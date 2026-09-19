//! Filesystem broker (Layer A): race-aware filesystem operations whose policy
//! checks are bound to the objects actually accessed (plan sections 8 and 45).
//!
//! Every operation works on a [`Canonical`] target that policy has already
//! evaluated, then:
//! - opens parent directories *pinned* (no `FILE_SHARE_DELETE`) and verifies
//!   their final path, so they cannot be swapped for a junction mid-operation;
//! - creates, opens, renames and deletes children relative to that handle with
//!   `FILE_OPEN_REPARSE_POINT`, so a planted link is never followed;
//! - compares file identity (volume + 128-bit file ID) with the evaluated one;
//! - checks every hard-link name of multi-link files against protected and
//!   control-data rules;
//! - verifies the final path of the handle after the operation.
//!
//! If a target cannot be established safely the operation is rejected; there
//! is no unchecked path-based fallback.

use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::io::OwnedHandle;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use workstation_core::paths::eq_ci;
use workstation_core::{ErrorCode, LpError, LpResult};

use crate::classify::PathClass;
use crate::evaluator::PolicyEngine;
use crate::winfs::{self, FileIdentity, FinalPath};
use crate::winpath::{self, Canonical, ExpandEnv, PathError};

const MAX_TREE_ENTRIES: usize = 200_000;

pub fn path_error(e: PathError) -> LpError {
    match e {
        PathError::AccessDenied => LpError::new(ErrorCode::PermissionDenied, e.to_string()),
        PathError::Io(ref m) if m.contains("does not exist") => {
            LpError::new(ErrorCode::PathNotFound, e.to_string())
        }
        PathError::Io(_) => LpError::new(ErrorCode::InvalidArguments, e.to_string()),
        PathError::Empty | PathError::TooLong => LpError::invalid(e.to_string()),
        _ => LpError::new(ErrorCode::PathOutsidePolicy, e.to_string()),
    }
}

fn io_error(context: &str, e: std::io::Error) -> LpError {
    match e.raw_os_error() {
        Some(2) | Some(3) => LpError::new(ErrorCode::PathNotFound, format!("{context}: not found")),
        Some(5) => LpError::new(
            ErrorCode::PermissionDenied,
            format!("{context}: access denied by Windows"),
        ),
        Some(32) | Some(33) => LpError::new(
            ErrorCode::CommandFailed,
            format!("{context}: the file is in use by another process"),
        ),
        Some(80) | Some(183) => LpError::new(
            ErrorCode::AlreadyExists,
            format!("{context}: already exists"),
        ),
        Some(145) => LpError::new(
            ErrorCode::CommandFailed,
            format!("{context}: directory is not empty"),
        ),
        Some(17) => LpError::new(
            ErrorCode::Unsupported,
            format!("{context}: cannot move across volumes; copy then delete instead"),
        ),
        Some(112) => LpError::new(ErrorCode::CommandFailed, format!("{context}: disk is full")),
        _ => LpError::new(ErrorCode::CommandFailed, format!("{context} failed")).with_internal(e),
    }
}

fn changed() -> LpError {
    LpError::new(
        ErrorCode::PermissionDenied,
        "The target changed while the operation was being validated (link, identity or location mismatch); nothing was modified.",
    )
}

/// Resolve user input into a canonical target.
pub fn resolve(
    input: &str,
    base: &Path,
    env: &ExpandEnv,
    follow_final: bool,
) -> LpResult<Canonical> {
    winpath::resolve(input, base, env, follow_final).map_err(path_error)
}

fn dos(fp: FinalPath) -> LpResult<PathBuf> {
    match fp {
        FinalPath::Dos(p) => Ok(p),
        _ => Err(LpError::new(
            ErrorCode::PathOutsidePolicy,
            "target resolved to a non-local location",
        )),
    }
}

fn verify_final(h: &OwnedHandle, expected: &Path) -> LpResult<()> {
    let actual = dos(winfs::final_path(h).map_err(|e| io_error("resolve handle", e))?)?;
    if eq_ci(&actual, expected) {
        Ok(())
    } else {
        tracing::warn!(expected = %expected.display(), actual = %actual.display(), "broker final-path mismatch");
        Err(changed())
    }
}

fn open_parent(parent: &Path) -> LpResult<OwnedHandle> {
    let h = winfs::open_dir_pinned(parent).map_err(|e| io_error("open parent directory", e))?;
    verify_final(&h, parent)?;
    Ok(h)
}

fn split_parent(path: &Path) -> LpResult<(&Path, &OsStr)> {
    match (path.parent(), path.file_name()) {
        (Some(p), Some(n)) => Ok((p, n)),
        _ => Err(LpError::invalid(
            "the operation needs a path below a drive root",
        )),
    }
}

/// Deny if any hard-link alias of a file is protected or control data, or (for
/// mutations) if aliases fall into different policy classes.
fn check_links(engine: &PolicyEngine, path: &Path, links: u32, mutation: bool) -> LpResult<()> {
    if links <= 1 {
        return Ok(());
    }
    let names = winfs::hard_link_names(path).map_err(|_| {
        LpError::new(
            ErrorCode::ProtectedResource,
            "This file has multiple hard links that could not be verified.",
        )
    })?;
    let base_class = engine.roots.classify_class(path);
    for n in &names {
        if engine.protected.check(n, !mutation).is_some() {
            return Err(LpError::new(
                ErrorCode::ProtectedResource,
                "This file is also linked from a protected location.",
            ));
        }
        let class = engine.roots.classify_class(n);
        if class == PathClass::ControlData {
            return Err(LpError::new(
                ErrorCode::PermissionDenied,
                "This file is also linked from Local Pilot control data.",
            ));
        }
        if mutation && class != base_class {
            return Err(LpError::new(
                ErrorCode::PermissionDenied,
                "Ambiguous hard link: the file is also reachable from a location with a different policy, so it cannot be modified.",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub path: String,
    pub exists: bool,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub modified_ms: i64,
    pub created_ms: i64,
    pub readonly: bool,
    pub hard_links: u32,
    pub identity: Option<String>,
}

pub fn stat(c: &Canonical, follow: bool) -> LpResult<Metadata> {
    if !c.exists {
        return Ok(Metadata {
            path: c.path.display().to_string(),
            exists: false,
            is_dir: false,
            is_link: false,
            size: 0,
            modified_ms: 0,
            created_ms: 0,
            readonly: false,
            hard_links: 0,
            identity: None,
        });
    }
    let h = winfs::open_path(
        &c.path,
        winfs::FILE_READ_ATTRIBUTES,
        winfs::SHARE_ALL,
        !follow,
    )
    .map_err(|e| io_error("stat", e))?;
    verify_final(&h, &c.path)?;
    let info = winfs::file_info(&h).map_err(|e| io_error("stat", e))?;
    Ok(Metadata {
        path: c.path.display().to_string(),
        exists: true,
        is_dir: info.is_dir(),
        is_link: info.is_reparse(),
        size: info.size,
        modified_ms: info.modified_ms,
        created_ms: info.created_ms,
        readonly: info.is_readonly(),
        hard_links: info.links,
        identity: Some(info.identity.to_string_id()),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResult {
    pub bytes: Vec<u8>,
    pub total_size: u64,
    pub offset: u64,
    pub truncated: bool,
}

/// Read a byte range from a file, bound to the verified handle.
pub fn read(
    engine: &PolicyEngine,
    c: &Canonical,
    offset: u64,
    max_len: u64,
) -> LpResult<ReadResult> {
    if !c.exists {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("{} does not exist", c.path.display()),
        ));
    }
    let h = winfs::open_path(
        &c.path,
        winfs::FILE_READ_DATA | winfs::FILE_READ_ATTRIBUTES | winfs::SYNCHRONIZE,
        winfs::SHARE_ALL,
        false,
    )
    .map_err(|e| io_error("open for read", e))?;
    verify_final(&h, &c.path)?;
    let info = winfs::file_info(&h).map_err(|e| io_error("read", e))?;
    if info.is_dir() {
        return Err(LpError::invalid("the path is a directory; use fs_list"));
    }
    if Some(info.identity) != c.identity {
        return Err(changed());
    }
    check_links(engine, &c.path, info.links, false)?;
    let mut f = winfs::into_file(h);
    let total = info.size;
    if offset > total {
        return Ok(ReadResult {
            bytes: Vec::new(),
            total_size: total,
            offset,
            truncated: false,
        });
    }
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| io_error("seek", e))?;
    let want = max_len.min(total - offset);
    let mut buf = Vec::with_capacity(want as usize);
    (&mut f)
        .take(want)
        .read_to_end(&mut buf)
        .map_err(|e| io_error("read", e))?;
    Ok(ReadResult {
        truncated: offset + (buf.len() as u64) < total,
        bytes: buf,
        total_size: total,
        offset,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub modified_ms: i64,
    /// Content is protected (the name is visible, the content is not).
    pub protected: bool,
}

pub fn list(engine: &PolicyEngine, c: &Canonical, limit: usize) -> LpResult<(Vec<DirEntry>, bool)> {
    if !c.exists {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("{} does not exist", c.path.display()),
        ));
    }
    let h = winfs::open_path(
        &c.path,
        winfs::FILE_LIST_DIRECTORY
            | winfs::FILE_TRAVERSE
            | winfs::FILE_READ_ATTRIBUTES
            | winfs::SYNCHRONIZE,
        winfs::SHARE_ALL,
        false,
    )
    .map_err(|e| io_error("open directory", e))?;
    verify_final(&h, &c.path)?;
    let info = winfs::file_info(&h).map_err(|e| io_error("list", e))?;
    if !info.is_dir() {
        return Err(LpError::invalid("the path is not a directory"));
    }
    let (entries, truncated) =
        winfs::read_dir_handle(&h, limit).map_err(|e| io_error("list", e))?;
    let mut out: Vec<DirEntry> = entries
        .into_iter()
        .map(|e| {
            let name = e.name.to_string_lossy().into_owned();
            let path = c.path.join(&name);
            let protected = engine.protected.check(&path, true).is_some()
                || engine.roots.classify_class(&path) == PathClass::ControlData;
            DirEntry {
                path: path.display().to_string(),
                is_dir: e.is_dir(),
                is_link: e.is_reparse(),
                size: if e.is_dir() { 0 } else { e.size },
                modified_ms: e.modified_ms,
                protected,
                name,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok((out, truncated))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode {
    /// Fail if the file exists.
    CreateNew,
    /// Create or replace the content.
    Overwrite,
    /// Create or append.
    Append,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteOutcome {
    pub path: String,
    pub created: bool,
    pub bytes_written: u64,
    pub size: u64,
    pub identity: String,
}

/// Create the missing directory chain `c.tail[..upto]` below `c.existing`,
/// returning a pinned handle to the deepest directory.
fn ensure_dirs(c: &Canonical, upto: usize) -> LpResult<(OwnedHandle, PathBuf)> {
    let mut cur_path = c.existing.clone();
    let mut cur = open_parent(&cur_path)?;
    for comp in &c.tail[..upto] {
        let h = winfs::nt_create_relative(
            &cur,
            OsStr::new(comp),
            winfs::FILE_LIST_DIRECTORY
                | winfs::FILE_TRAVERSE
                | winfs::FILE_READ_ATTRIBUTES
                | winfs::FILE_ADD_FILE
                | winfs::FILE_ADD_SUBDIRECTORY,
            0,
            winfs::SHARE_PIN,
            winfs::FILE_OPEN_IF,
            winfs::FILE_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
        )
        .map_err(|e| io_error("create directory", e))?;
        let info = winfs::file_info(&h).map_err(|e| io_error("create directory", e))?;
        if info.is_reparse() || !info.is_dir() {
            return Err(changed());
        }
        cur_path.push(comp);
        cur = h;
    }
    verify_final(&cur, &cur_path)?;
    Ok((cur, cur_path))
}

/// Open (or create) the target file for writing, bound to the evaluated object.
fn open_for_write(
    engine: &PolicyEngine,
    c: &Canonical,
    mode: WriteMode,
    create_parents: bool,
) -> LpResult<(std::fs::File, bool)> {
    let (parent, name) = if c.exists {
        if c.is_dir {
            return Err(LpError::invalid("the path is a directory"));
        }
        if mode == WriteMode::CreateNew {
            return Err(LpError::new(
                ErrorCode::AlreadyExists,
                format!("{} already exists", c.path.display()),
            ));
        }
        let (p, n) = split_parent(&c.path)?;
        (open_parent(p)?, n.to_os_string())
    } else {
        if c.tail.len() > 1 && !create_parents {
            return Err(LpError::new(
                ErrorCode::PathNotFound,
                "The parent directory does not exist (set create_parents to create it).",
            ));
        }
        let (h, _) = ensure_dirs(c, c.tail.len() - 1)?;
        (
            h,
            OsStr::new(c.tail.last().expect("non-empty tail")).to_os_string(),
        )
    };
    let access = winfs::GENERIC_READ_ACCESS | winfs::GENERIC_WRITE_ACCESS;
    if c.exists {
        let h = winfs::nt_create_relative(
            &parent,
            &name,
            access,
            0,
            winfs::SHARE_ALL & !0x4, // read|write sharing, no delete while we write
            winfs::FILE_OPEN,
            winfs::FILE_NON_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
        )
        .map_err(|e| io_error("open for write", e))?;
        let info = winfs::file_info(&h).map_err(|e| io_error("open for write", e))?;
        if info.is_reparse() || Some(info.identity) != c.identity {
            return Err(changed());
        }
        check_links(engine, &c.path, info.links, true)?;
        verify_final(&h, &c.path)?;
        Ok((winfs::into_file(h), false))
    } else {
        let h = winfs::nt_create_relative(
            &parent,
            &name,
            access,
            0,
            winfs::SHARE_ALL & !0x4,
            winfs::FILE_CREATE,
            winfs::FILE_NON_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
        )
        .map_err(|e| {
            if matches!(e.raw_os_error(), Some(80) | Some(183)) {
                changed()
            } else {
                io_error("create file", e)
            }
        })?;
        verify_final(&h, &c.path)?;
        Ok((winfs::into_file(h), true))
    }
}

pub fn write(
    engine: &PolicyEngine,
    c: &Canonical,
    content: &[u8],
    mode: WriteMode,
    create_parents: bool,
) -> LpResult<WriteOutcome> {
    let (mut f, created) = open_for_write(engine, c, mode, create_parents)?;
    match mode {
        WriteMode::Append => {
            f.seek(SeekFrom::End(0)).map_err(|e| io_error("seek", e))?;
        }
        _ => {
            f.set_len(0).map_err(|e| io_error("truncate", e))?;
        }
    }
    f.write_all(content).map_err(|e| io_error("write", e))?;
    f.flush().map_err(|e| io_error("flush", e))?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let h: OwnedHandle = f.into();
    let info = winfs::file_info(&h).map_err(|e| io_error("write", e))?;
    Ok(WriteOutcome {
        path: c.path.display().to_string(),
        created,
        bytes_written: content.len() as u64,
        size,
        identity: info.identity.to_string_id(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
}

pub fn decode_text(bytes: &[u8]) -> Option<(String, TextEncoding)> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(rest.to_vec())
            .ok()
            .map(|s| (s, TextEncoding::Utf8Bom));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let u: Vec<u16> = rest
            .as_chunks::<2>().0.iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&u)
            .ok()
            .map(|s| (s, TextEncoding::Utf16Le));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let u: Vec<u16> = rest
            .as_chunks::<2>().0.iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&u)
            .ok()
            .map(|s| (s, TextEncoding::Utf16Be));
    }
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes.to_vec())
        .ok()
        .map(|s| (s, TextEncoding::Utf8))
}

pub fn encode_text(text: &str, enc: TextEncoding) -> Vec<u8> {
    match enc {
        TextEncoding::Utf8 => text.as_bytes().to_vec(),
        TextEncoding::Utf8Bom => [&[0xEF, 0xBB, 0xBF][..], text.as_bytes()].concat(),
        TextEncoding::Utf16Le => {
            let mut v = vec![0xFF, 0xFE];
            v.extend(text.encode_utf16().flat_map(|u| u.to_le_bytes()));
            v
        }
        TextEncoding::Utf16Be => {
            let mut v = vec![0xFE, 0xFF];
            v.extend(text.encode_utf16().flat_map(|u| u.to_be_bytes()));
            v
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edit {
    pub old_text: String,
    pub new_text: String,
    /// Required number of occurrences (default 1). Use 0 to replace all.
    #[serde(default)]
    pub expected_replacements: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOutcome {
    pub path: String,
    pub replacements: usize,
    pub size: u64,
    pub encoding: TextEncoding,
}

/// Apply exact-text edits to a file through one verified handle.
pub fn patch(
    engine: &PolicyEngine,
    c: &Canonical,
    edits: &[Edit],
    max_bytes: u64,
) -> LpResult<PatchOutcome> {
    if !c.exists {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("{} does not exist", c.path.display()),
        ));
    }
    if c.size > max_bytes {
        return Err(LpError::new(
            ErrorCode::TooLarge,
            "file is too large to patch",
        ));
    }
    let (mut f, _) = open_for_write(engine, c, WriteMode::Overwrite, false)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|e| io_error("read", e))?;
    let (mut text, enc) = decode_text(&bytes)
        .ok_or_else(|| LpError::invalid("the file is not valid text (UTF-8/UTF-16)"))?;
    let mut total = 0;
    for (i, e) in edits.iter().enumerate() {
        if e.old_text.is_empty() {
            return Err(LpError::invalid(format!(
                "edit {i}: old_text must not be empty"
            )));
        }
        let count = text.matches(e.old_text.as_str()).count();
        let expected = e.expected_replacements.unwrap_or(1);
        if count == 0 {
            return Err(LpError::invalid(format!(
                "edit {i}: old_text was not found; no changes were written"
            )));
        }
        if expected != 0 && count != expected {
            return Err(LpError::invalid(format!(
                "edit {i}: old_text occurs {count} times but expected_replacements is {expected}; no changes were written"
            )));
        }
        text = text.replace(e.old_text.as_str(), &e.new_text);
        total += count;
    }
    let out = encode_text(&text, enc);
    f.seek(SeekFrom::Start(0))
        .map_err(|e| io_error("seek", e))?;
    f.set_len(0).map_err(|e| io_error("truncate", e))?;
    f.write_all(&out).map_err(|e| io_error("write", e))?;
    f.flush().map_err(|e| io_error("flush", e))?;
    Ok(PatchOutcome {
        path: c.path.display().to_string(),
        replacements: total,
        size: out.len() as u64,
        encoding: enc,
    })
}

pub fn mkdir(c: &Canonical, recursive: bool) -> LpResult<bool> {
    if c.exists {
        if c.is_dir {
            return Ok(false);
        }
        return Err(LpError::new(
            ErrorCode::AlreadyExists,
            "a file with that name exists",
        ));
    }
    if c.tail.len() > 1 && !recursive {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            "the parent directory does not exist (set recursive to create it)",
        ));
    }
    ensure_dirs(c, c.tail.len())?;
    Ok(true)
}

/// Walk a subtree through handles, reporting every entry path.
fn scan_tree(
    dir: &OwnedHandle,
    path: &Path,
    visit: &mut dyn FnMut(&Path, &winfs::DirEntryInfo) -> LpResult<()>,
    count: &mut usize,
) -> LpResult<()> {
    let (entries, truncated) =
        winfs::read_dir_handle(dir, MAX_TREE_ENTRIES).map_err(|e| io_error("scan", e))?;
    if truncated {
        return Err(LpError::new(
            ErrorCode::TooLarge,
            "directory tree is too large to verify",
        ));
    }
    for e in entries {
        *count += 1;
        if *count > MAX_TREE_ENTRIES {
            return Err(LpError::new(
                ErrorCode::TooLarge,
                "directory tree is too large to verify",
            ));
        }
        let p = path.join(&e.name);
        visit(&p, &e)?;
        if e.is_dir() && !e.is_reparse() {
            let child = winfs::nt_create_relative(
                dir,
                &e.name,
                winfs::FILE_LIST_DIRECTORY | winfs::FILE_TRAVERSE | winfs::FILE_READ_ATTRIBUTES,
                0,
                winfs::SHARE_ALL,
                winfs::FILE_OPEN,
                winfs::FILE_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
            )
            .map_err(|er| io_error("scan", er))?;
            scan_tree(&child, &p, visit, count)?;
        }
    }
    Ok(())
}

fn deny_protected_in_tree(
    engine: &PolicyEngine,
    dir: &OwnedHandle,
    path: &Path,
) -> LpResult<usize> {
    let mut count = 0;
    scan_tree(
        dir,
        path,
        &mut |p, _| {
            if engine.protected.check(p, false).is_some() && !engine.protected.mutation_excepted(p)
            {
                return Err(LpError::new(
                    ErrorCode::ProtectedResource,
                    format!(
                        "The directory contains a protected file ({}); recursive operations on it are not permitted.",
                        p.display()
                    ),
                ));
            }
            Ok(())
        },
        &mut count,
    )?;
    Ok(count)
}

fn delete_tree(dir: &OwnedHandle, stats: &mut DeleteOutcome) -> LpResult<()> {
    loop {
        let (entries, _) = winfs::read_dir_handle(dir, 4096).map_err(|e| io_error("delete", e))?;
        if entries.is_empty() {
            return Ok(());
        }
        for e in entries {
            let child = winfs::nt_create_relative(
                dir,
                &e.name,
                winfs::DELETE
                    | winfs::FILE_READ_ATTRIBUTES
                    | winfs::FILE_LIST_DIRECTORY
                    | winfs::FILE_TRAVERSE,
                0,
                winfs::SHARE_ALL,
                winfs::FILE_OPEN,
                winfs::FILE_OPEN_REPARSE_POINT,
            )
            .map_err(|er| io_error("delete", er))?;
            let info = winfs::file_info(&child).map_err(|er| io_error("delete", er))?;
            if info.is_dir() && !info.is_reparse() {
                delete_tree(&child, stats)?;
                stats.directories += 1;
            } else if info.is_reparse() {
                stats.links += 1;
            } else {
                stats.files += 1;
            }
            winfs::delete_by_handle(&child).map_err(|er| io_error("delete", er))?;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeleteOutcome {
    pub path: String,
    pub files: u64,
    pub directories: u64,
    /// Links/junctions removed without following them.
    pub links: u64,
}

/// Delete an entry. `c` must be resolved without following the final
/// component, so a link is removed rather than its target.
pub fn delete(engine: &PolicyEngine, c: &Canonical, recursive: bool) -> LpResult<DeleteOutcome> {
    if !c.exists {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("{} does not exist", c.path.display()),
        ));
    }
    let (parent_path, name) = split_parent(&c.path)?;
    let parent = open_parent(parent_path)?;
    let h = winfs::nt_create_relative(
        &parent,
        name,
        winfs::DELETE
            | winfs::FILE_READ_ATTRIBUTES
            | winfs::FILE_LIST_DIRECTORY
            | winfs::FILE_TRAVERSE,
        0,
        winfs::SHARE_ALL,
        winfs::FILE_OPEN,
        winfs::FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|e| io_error("open for delete", e))?;
    let info = winfs::file_info(&h).map_err(|e| io_error("delete", e))?;
    if Some(info.identity) != c.identity {
        return Err(changed());
    }
    let mut out = DeleteOutcome {
        path: c.path.display().to_string(),
        ..Default::default()
    };
    if info.is_dir() && !info.is_reparse() {
        let (entries, _) = winfs::read_dir_handle(&h, 1).map_err(|e| io_error("delete", e))?;
        if !entries.is_empty() {
            if !recursive {
                return Err(LpError::new(
                    ErrorCode::CommandFailed,
                    "the directory is not empty (set recursive to delete its contents)",
                ));
            }
            deny_protected_in_tree(engine, &h, &c.path)?;
            delete_tree(&h, &mut out)?;
        }
        out.directories += 1;
    } else if info.is_reparse() {
        out.links += 1;
    } else {
        out.files += 1;
    }
    winfs::delete_by_handle(&h).map_err(|e| io_error("delete", e))?;
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveOutcome {
    pub from: String,
    pub to: String,
}

/// Move/rename `src` (resolved without following its final component) to `dst`.
pub fn rename(
    engine: &PolicyEngine,
    src: &Canonical,
    dst: &Canonical,
    overwrite: bool,
    create_parents: bool,
) -> LpResult<MoveOutcome> {
    if !src.exists {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("{} does not exist", src.path.display()),
        ));
    }
    if dst.exists && !overwrite {
        return Err(LpError::new(
            ErrorCode::AlreadyExists,
            format!(
                "{} already exists (set overwrite to replace it)",
                dst.path.display()
            ),
        ));
    }
    if dst.exists && dst.is_dir {
        return Err(LpError::invalid(
            "the destination is an existing directory; give the full new path",
        ));
    }
    let (sp, sn) = split_parent(&src.path)?;
    let src_parent = open_parent(sp)?;
    let h = winfs::nt_create_relative(
        &src_parent,
        sn,
        winfs::DELETE
            | winfs::FILE_READ_ATTRIBUTES
            | winfs::FILE_LIST_DIRECTORY
            | winfs::FILE_TRAVERSE,
        0,
        winfs::SHARE_ALL,
        winfs::FILE_OPEN,
        winfs::FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|e| io_error("open source", e))?;
    let info = winfs::file_info(&h).map_err(|e| io_error("move", e))?;
    if Some(info.identity) != src.identity {
        return Err(changed());
    }
    if info.is_dir() && !info.is_reparse() {
        deny_protected_in_tree(engine, &h, &src.path)?;
    } else if !info.is_reparse() {
        check_links(engine, &src.path, info.links, true)?;
    }
    let (dst_parent, name) = if dst.exists {
        let (dp, dn) = split_parent(&dst.path)?;
        (open_parent(dp)?, dn.to_os_string())
    } else {
        if dst.tail.len() > 1 && !create_parents {
            return Err(LpError::new(
                ErrorCode::PathNotFound,
                "the destination directory does not exist (set create_parents)",
            ));
        }
        let (hd, _) = ensure_dirs(dst, dst.tail.len() - 1)?;
        (
            hd,
            OsStr::new(dst.tail.last().expect("tail")).to_os_string(),
        )
    };
    winfs::rename_relative(&h, &dst_parent, &name, overwrite).map_err(|e| io_error("move", e))?;
    verify_final(&h, &dst.path).map_err(|_| {
        LpError::new(
            ErrorCode::OutcomeUnknown,
            "The move completed but the destination could not be re-verified.",
        )
    })?;
    Ok(MoveOutcome {
        from: src.path.display().to_string(),
        to: dst.path.display().to_string(),
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CopyOutcome {
    pub from: String,
    pub to: String,
    pub files: u64,
    pub directories: u64,
    pub bytes: u64,
    /// Links/junctions inside the source tree that were skipped, not followed.
    pub skipped_links: Vec<String>,
}

fn copy_stream(
    src: &mut std::fs::File,
    dst: &mut std::fs::File,
    max_bytes: u64,
    total: &mut u64,
) -> LpResult<()> {
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = src.read(&mut buf).map_err(|e| io_error("copy read", e))?;
        if n == 0 {
            break;
        }
        *total += n as u64;
        if *total > max_bytes {
            return Err(LpError::new(
                ErrorCode::TooLarge,
                "copy exceeds the configured size limit",
            ));
        }
        dst.write_all(&buf[..n])
            .map_err(|e| io_error("copy write", e))?;
    }
    dst.flush().map_err(|e| io_error("copy flush", e))
}

/// Copy a file or (with `recursive`) a directory tree.
pub fn copy(
    engine: &PolicyEngine,
    src: &Canonical,
    dst: &Canonical,
    overwrite: bool,
    recursive: bool,
    create_parents: bool,
    max_bytes: u64,
) -> LpResult<CopyOutcome> {
    if !src.exists {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("{} does not exist", src.path.display()),
        ));
    }
    let mut out = CopyOutcome {
        from: src.path.display().to_string(),
        to: dst.path.display().to_string(),
        ..Default::default()
    };
    if !src.is_dir {
        let h = winfs::open_path(
            &src.path,
            winfs::FILE_READ_DATA | winfs::FILE_READ_ATTRIBUTES | winfs::SYNCHRONIZE,
            winfs::SHARE_ALL,
            false,
        )
        .map_err(|e| io_error("open source", e))?;
        verify_final(&h, &src.path)?;
        let info = winfs::file_info(&h).map_err(|e| io_error("copy", e))?;
        if Some(info.identity) != src.identity {
            return Err(changed());
        }
        check_links(engine, &src.path, info.links, false)?;
        let mode = if overwrite {
            WriteMode::Overwrite
        } else {
            WriteMode::CreateNew
        };
        let (mut df, _) = open_for_write(engine, dst, mode, create_parents)?;
        df.set_len(0).map_err(|e| io_error("truncate", e))?;
        let mut sf = winfs::into_file(h);
        copy_stream(&mut sf, &mut df, max_bytes, &mut out.bytes)?;
        out.files = 1;
        return Ok(out);
    }
    if !recursive {
        return Err(LpError::invalid(
            "the source is a directory (set recursive to copy it)",
        ));
    }
    if dst.exists {
        return Err(LpError::new(
            ErrorCode::AlreadyExists,
            "the destination directory already exists",
        ));
    }
    if workstation_core::paths::starts_with_ci(&dst.path, &src.path) {
        return Err(LpError::invalid("cannot copy a directory into itself"));
    }
    let sh = winfs::open_path(
        &src.path,
        winfs::FILE_LIST_DIRECTORY
            | winfs::FILE_TRAVERSE
            | winfs::FILE_READ_ATTRIBUTES
            | winfs::SYNCHRONIZE,
        winfs::SHARE_PIN,
        false,
    )
    .map_err(|e| io_error("open source", e))?;
    verify_final(&sh, &src.path)?;
    // Source protection: deny before copying anything.
    let mut count = 0;
    scan_tree(
        &sh,
        &src.path,
        &mut |p, e| {
            if !e.is_reparse()
                && (engine.protected.check(p, true).is_some()
                    || engine.roots.classify_class(p) == PathClass::ControlData)
            {
                return Err(LpError::new(
                    ErrorCode::ProtectedResource,
                    format!(
                        "The source contains a protected file ({}); it cannot be copied.",
                        p.display()
                    ),
                ));
            }
            Ok(())
        },
        &mut count,
    )?;
    if dst.tail.len() > 1 && !create_parents {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            "the destination parent does not exist (set create_parents)",
        ));
    }
    let (dh, dpath) = ensure_dirs(dst, dst.tail.len())?;
    out.directories += 1;
    copy_tree(engine, &sh, &src.path, &dh, &dpath, max_bytes, &mut out)?;
    Ok(out)
}

fn copy_tree(
    engine: &PolicyEngine,
    sdir: &OwnedHandle,
    spath: &Path,
    ddir: &OwnedHandle,
    dpath: &Path,
    max_bytes: u64,
    out: &mut CopyOutcome,
) -> LpResult<()> {
    let (entries, truncated) =
        winfs::read_dir_handle(sdir, MAX_TREE_ENTRIES).map_err(|e| io_error("copy", e))?;
    if truncated {
        return Err(LpError::new(
            ErrorCode::TooLarge,
            "directory tree is too large to copy",
        ));
    }
    for e in entries {
        let sp = spath.join(&e.name);
        let dp = dpath.join(&e.name);
        if e.is_reparse() {
            out.skipped_links.push(sp.display().to_string());
            continue;
        }
        if e.is_dir() {
            let sc = winfs::nt_create_relative(
                sdir,
                &e.name,
                winfs::FILE_LIST_DIRECTORY | winfs::FILE_TRAVERSE | winfs::FILE_READ_ATTRIBUTES,
                0,
                winfs::SHARE_ALL,
                winfs::FILE_OPEN,
                winfs::FILE_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
            )
            .map_err(|er| io_error("copy", er))?;
            let dc = winfs::nt_create_relative(
                ddir,
                &e.name,
                winfs::FILE_LIST_DIRECTORY
                    | winfs::FILE_TRAVERSE
                    | winfs::FILE_READ_ATTRIBUTES
                    | winfs::FILE_ADD_FILE
                    | winfs::FILE_ADD_SUBDIRECTORY,
                0,
                winfs::SHARE_PIN,
                winfs::FILE_CREATE,
                winfs::FILE_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
            )
            .map_err(|er| io_error("copy", er))?;
            out.directories += 1;
            copy_tree(engine, &sc, &sp, &dc, &dp, max_bytes, out)?;
        } else {
            let sf = winfs::nt_create_relative(
                sdir,
                &e.name,
                winfs::GENERIC_READ_ACCESS,
                0,
                winfs::SHARE_ALL,
                winfs::FILE_OPEN,
                winfs::FILE_NON_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
            )
            .map_err(|er| io_error("copy", er))?;
            let info = winfs::file_info(&sf).map_err(|er| io_error("copy", er))?;
            if info.is_reparse() {
                out.skipped_links.push(sp.display().to_string());
                continue;
            }
            check_links(engine, &sp, info.links, false)?;
            let df = winfs::nt_create_relative(
                ddir,
                &e.name,
                winfs::GENERIC_WRITE_ACCESS | winfs::GENERIC_READ_ACCESS,
                0,
                0,
                winfs::FILE_CREATE,
                winfs::FILE_NON_DIRECTORY_FILE | winfs::FILE_OPEN_REPARSE_POINT,
            )
            .map_err(|er| io_error("copy", er))?;
            let mut sfile = winfs::into_file(sf);
            let mut dfile = winfs::into_file(df);
            copy_stream(&mut sfile, &mut dfile, max_bytes, &mut out.bytes)?;
            out.files += 1;
        }
    }
    Ok(())
}

/// File identity string of the existing object (for approval snapshots).
pub fn identity_string(c: &Canonical) -> String {
    match (c.exists, c.identity) {
        (true, Some(id)) => id.to_string_id(),
        (false, Some(parent)) => format!("absent-under:{}", parent.to_string_id()),
        _ => "unknown".into(),
    }
}

pub fn identity_of(c: &Canonical) -> Option<FileIdentity> {
    if c.exists { c.identity } else { None }
}
