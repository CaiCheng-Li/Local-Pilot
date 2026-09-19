//! Windows path normalization and handle-based canonicalization.
//!
//! Steps (plan section 8): expand safely, make absolute, normalize with Win32
//! semantics, then canonicalize the longest existing prefix through an opened
//! handle (`GetFinalPathNameByHandleW`), which resolves junctions, symbolic
//! links, 8.3 short names and letter case. Remaining (not yet existing)
//! components are validated and appended.
//!
//! Rejected up front: UNC paths (including `\\localhost\C$`), device namespace
//! paths (`\\.\`, `\\?\GLOBALROOT`, volume GUID paths), drive-relative and
//! root-relative paths, alternate data streams, reserved DOS device names and
//! invalid characters. `\\?\C:\...` is accepted only as an alias for `C:\...`
//! and is classified by its resolved destination, never used to bypass policy.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf, Prefix};

use serde::{Deserialize, Serialize};

use crate::winfs::{self, FileIdentity, FinalPath};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PathError {
    #[error("path is empty")]
    Empty,
    #[error("path is too long")]
    TooLong,
    #[error("network (UNC) paths are not permitted")]
    Unc,
    #[error("device namespace paths are not permitted")]
    Device,
    #[error("drive-relative or root-relative paths are not permitted; use an absolute path")]
    Relative,
    #[error("alternate data streams are not permitted")]
    AlternateStream,
    #[error("reserved device names are not permitted")]
    ReservedName,
    #[error("path contains invalid characters")]
    InvalidCharacters,
    #[error("path traverses a dangling link")]
    DanglingLink,
    #[error("path resolves to an unsupported location")]
    UnsupportedTarget,
    #[error("access to the path was denied by Windows")]
    AccessDenied,
    #[error("the path could not be resolved: {0}")]
    Io(String),
}

/// Environment used for safe expansion of `~` and a small set of `%VAR%`s.
#[derive(Debug, Clone, Default)]
pub struct ExpandEnv {
    pub profile: Option<PathBuf>,
    pub vars: Vec<(String, PathBuf)>,
}

impl ExpandEnv {
    pub fn from_system() -> Self {
        let profile = workstation_core::known_folders::profile().ok();
        let mut vars = Vec::new();
        let mut add = |name: &str, p: Option<PathBuf>| {
            if let Some(p) = p {
                vars.push((name.to_ascii_uppercase(), p));
            }
        };
        add("USERPROFILE", profile.clone());
        add(
            "LOCALAPPDATA",
            workstation_core::known_folders::local_app_data().ok(),
        );
        add(
            "APPDATA",
            workstation_core::known_folders::roaming_app_data().ok(),
        );
        add(
            "PROGRAMDATA",
            workstation_core::known_folders::program_data().ok(),
        );
        for name in [
            "TEMP",
            "TMP",
            "SYSTEMROOT",
            "WINDIR",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "PUBLIC",
            "ONEDRIVE",
        ] {
            add(name, std::env::var_os(name).map(PathBuf::from));
        }
        Self { profile, vars }
    }

    fn lookup(&self, name: &str) -> Option<&Path> {
        let upper = name.to_ascii_uppercase();
        self.vars
            .iter()
            .find(|(n, _)| *n == upper)
            .map(|(_, p)| p.as_path())
    }
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9", "LPT¹", "LPT²", "LPT³", "CONIN$", "CONOUT$",
];

/// Validate and normalize a single component with Win32 semantics
/// (trailing dots and spaces are stripped, as `GetFullPathNameW` does).
pub fn normalize_component(comp: &str) -> Result<String, PathError> {
    if comp
        .chars()
        .any(|c| (c as u32) < 0x20 || "<>\"|?*".contains(c))
    {
        return Err(PathError::InvalidCharacters);
    }
    if comp.contains(':') {
        return Err(PathError::AlternateStream);
    }
    let trimmed = comp.trim_end_matches(['.', ' ']);
    if trimmed.is_empty() {
        return Err(PathError::InvalidCharacters);
    }
    let stem = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches(' ')
        .to_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return Err(PathError::ReservedName);
    }
    Ok(trimmed.to_string())
}

/// Lexically normalize user input into an absolute `X:\...` path.
/// Relative input is resolved against `base` (normally the trusted root).
pub fn normalize(input: &str, base: &Path, env: &ExpandEnv) -> Result<PathBuf, PathError> {
    if input.trim().is_empty() {
        return Err(PathError::Empty);
    }
    if input.len() > 32_000 {
        return Err(PathError::TooLong);
    }
    if input.contains('\0') {
        return Err(PathError::InvalidCharacters);
    }
    let mut s = input.trim().replace('/', "\\");

    // Safe expansion: leading `~` and a closed set of %VARS%.
    if s == "~" || s.starts_with("~\\") {
        match &env.profile {
            Some(p) => s = format!("{}{}", p.display(), &s[1..]),
            None => return Err(PathError::Relative),
        }
    }
    if s.contains('%') {
        let mut out = String::new();
        let mut rest = s.as_str();
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            match after.find('%') {
                Some(end) => {
                    let name = &after[..end];
                    match env.lookup(name) {
                        Some(p) if !name.is_empty() => {
                            out.push_str(&p.display().to_string());
                            rest = &after[end + 1..];
                        }
                        _ => {
                            out.push('%');
                            rest = after;
                        }
                    }
                }
                None => {
                    out.push('%');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        s = out;
    }

    // Namespace prefixes.
    let mut verbatim = false;
    if let Some(rest) = s.strip_prefix(r"\\?\").or_else(|| s.strip_prefix(r"\??\")) {
        let upper = rest.to_ascii_uppercase();
        if upper.starts_with("UNC\\") {
            return Err(PathError::Unc);
        }
        let b = rest.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
            s = rest.to_string();
            verbatim = true;
        } else {
            return Err(PathError::Device);
        }
    } else if s.starts_with(r"\\.\") || s.starts_with(r"\\?") {
        return Err(PathError::Device);
    } else if s.starts_with(r"\\") {
        return Err(PathError::Unc);
    }

    let b = s.as_bytes();
    let absolute: PathBuf = if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        if b.len() == 2 || b[2] != b'\\' {
            return Err(PathError::Relative);
        }
        PathBuf::from(&s)
    } else if s.starts_with('\\') {
        return Err(PathError::Relative);
    } else {
        base.join(&s)
    };

    // Component-wise normalization.
    let mut drive: Option<String> = None;
    let mut parts: Vec<String> = Vec::new();
    for c in absolute.components() {
        match c {
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                    drive = Some(format!("{}:", (d as char).to_ascii_uppercase()))
                }
                Prefix::UNC(..) | Prefix::VerbatimUNC(..) => return Err(PathError::Unc),
                _ => return Err(PathError::Device),
            },
            Component::RootDir => {}
            Component::CurDir => {
                if verbatim {
                    return Err(PathError::InvalidCharacters);
                }
            }
            Component::ParentDir => {
                if verbatim {
                    return Err(PathError::InvalidCharacters);
                }
                parts.pop();
            }
            Component::Normal(os) => {
                let text = os.to_string_lossy();
                if text == "." || text == ".." {
                    if verbatim {
                        return Err(PathError::InvalidCharacters);
                    }
                    if text == ".." {
                        parts.pop();
                    }
                    continue;
                }
                parts.push(normalize_component(&text)?);
            }
        }
    }
    let drive = drive.ok_or(PathError::Relative)?;
    let mut out = PathBuf::from(format!("{drive}\\"));
    for p in parts {
        out.push(p);
    }
    Ok(out)
}

/// The canonical form of a path plus facts about the existing object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canonical {
    /// Canonical absolute DOS path (existing prefix resolved + tail appended).
    pub path: PathBuf,
    /// Canonical path of the longest existing prefix.
    pub existing: PathBuf,
    /// Components below `existing` that do not exist yet.
    pub tail: Vec<String>,
    /// Identity of the existing prefix object (the target itself if `exists`).
    pub identity: Option<FileIdentity>,
    pub exists: bool,
    pub is_dir: bool,
    pub is_reparse: bool,
    pub links: u32,
    pub size: u64,
    pub modified_ms: i64,
}

fn map_io(err: io::Error) -> PathError {
    match err.raw_os_error() {
        Some(5) => PathError::AccessDenied,
        _ => PathError::Io(err.to_string()),
    }
}

fn is_not_found(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(2) | Some(3) | Some(123) | Some(161) | Some(1920)
    ) || err.kind() == io::ErrorKind::NotFound
}

/// Canonicalize a normalized absolute path. If `follow_final` is false and the
/// final component exists as a reparse point, the link itself is described.
pub fn canonicalize(normalized: &Path, follow_final: bool) -> Result<Canonical, PathError> {
    let comps: Vec<OsString> = normalized
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            _ => None,
        })
        .collect();
    let root: PathBuf = normalized
        .components()
        .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        .collect();

    // Find the longest existing prefix, walking up from the full path.
    let mut n = comps.len();
    loop {
        let mut candidate = root.clone();
        for c in &comps[..n] {
            candidate.push(c);
        }
        let is_final = n == comps.len();
        let no_follow = is_final && !follow_final;
        match winfs::open_path(
            &candidate,
            winfs::FILE_READ_ATTRIBUTES,
            winfs::SHARE_ALL,
            no_follow,
        ) {
            Ok(h) => {
                let info = winfs::file_info(&h).map_err(map_io)?;
                let fp = winfs::final_path(&h).map_err(map_io)?;
                let existing = match fp {
                    FinalPath::Dos(p) => p,
                    FinalPath::Unc(_) => return Err(PathError::Unc),
                    FinalPath::Other(_) => return Err(PathError::UnsupportedTarget),
                };
                let tail: Vec<String> = comps[n..]
                    .iter()
                    .map(|c| c.to_string_lossy().into_owned())
                    .collect();
                let mut path = existing.clone();
                for t in &tail {
                    path.push(t);
                }
                let exists = tail.is_empty();
                if !exists && !info.is_dir() {
                    // A file cannot have children.
                    return Err(PathError::Io("a parent path component is a file".into()));
                }
                return Ok(Canonical {
                    path,
                    existing,
                    tail,
                    identity: Some(info.identity),
                    exists,
                    is_dir: exists && info.is_dir(),
                    is_reparse: exists && info.is_reparse(),
                    links: if exists { info.links } else { 0 },
                    size: if exists { info.size } else { 0 },
                    modified_ms: if exists { info.modified_ms } else { 0 },
                });
            }
            Err(e) if is_not_found(&e) => {
                // Detect a dangling reparse point at this position: following it
                // fails but the link object itself exists.
                if n > 0
                    && !no_follow
                    && winfs::open_path(
                        &candidate,
                        winfs::FILE_READ_ATTRIBUTES,
                        winfs::SHARE_ALL,
                        true,
                    )
                    .is_ok()
                {
                    return Err(PathError::DanglingLink);
                }
                if n == 0 {
                    return Err(PathError::Io("the drive does not exist".into()));
                }
                n -= 1;
            }
            Err(e) => return Err(map_io(e)),
        }
    }
}

/// Convenience: normalize then canonicalize.
pub fn resolve(
    input: &str,
    base: &Path,
    env: &ExpandEnv,
    follow_final: bool,
) -> Result<Canonical, PathError> {
    let normalized = normalize(input, base, env)?;
    canonicalize(&normalized, follow_final)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> ExpandEnv {
        ExpandEnv {
            profile: Some(PathBuf::from(r"C:\Users\Alice")),
            vars: vec![("USERPROFILE".into(), PathBuf::from(r"C:\Users\Alice"))],
        }
    }

    #[test]
    fn normalizes_traversal_and_case() {
        let base = Path::new(r"C:\Users\Alice\Documents\Projects");
        let p = normalize(r"Clippy\..\..\secret.txt", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\Users\Alice\Documents\secret.txt"));
        let p = normalize(r"c:/users/alice/x", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\users\alice\x"));
        let p = normalize(r"C:\..\..\Windows", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\Windows"));
    }

    #[test]
    fn rejects_unc_device_and_streams() {
        let base = Path::new(r"C:\P");
        let e = env();
        assert_eq!(
            normalize(r"\\localhost\C$\Users", base, &e),
            Err(PathError::Unc)
        );
        assert_eq!(
            normalize(r"\\server\share\x", base, &e),
            Err(PathError::Unc)
        );
        assert_eq!(
            normalize(r"\\?\UNC\server\share", base, &e),
            Err(PathError::Unc)
        );
        assert_eq!(normalize(r"\\.\C:\x", base, &e), Err(PathError::Device));
        assert_eq!(
            normalize(r"\\.\PhysicalDrive0", base, &e),
            Err(PathError::Device)
        );
        assert_eq!(
            normalize(r"\\?\GLOBALROOT\Device\x", base, &e),
            Err(PathError::Device)
        );
        assert_eq!(
            normalize(r"C:\P\file.txt:hidden", base, &e),
            Err(PathError::AlternateStream)
        );
        assert_eq!(
            normalize(r"C:\P\file.txt::$DATA", base, &e),
            Err(PathError::AlternateStream)
        );
        assert_eq!(normalize(r"C:relative", base, &e), Err(PathError::Relative));
        assert_eq!(normalize(r"\rooted", base, &e), Err(PathError::Relative));
        assert_eq!(
            normalize(r"C:\P\nul", base, &e),
            Err(PathError::ReservedName)
        );
        assert_eq!(
            normalize(r"C:\P\COM1.txt", base, &e),
            Err(PathError::ReservedName)
        );
        assert_eq!(
            normalize(r"C:\P\a|b", base, &e),
            Err(PathError::InvalidCharacters)
        );
    }

    #[test]
    fn verbatim_drive_paths_are_aliases_not_bypasses() {
        let base = Path::new(r"C:\P");
        let p = normalize(r"\\?\C:\Users\Alice\.ssh\id_rsa", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\Users\Alice\.ssh\id_rsa"));
        assert!(normalize(r"\\?\C:\Users\..\x", base, &env()).is_err());
    }

    #[test]
    fn trailing_dots_and_spaces_are_stripped() {
        let base = Path::new(r"C:\P");
        let p = normalize(r"C:\Users\Alice\.ssh.\id_rsa. ", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\Users\Alice\.ssh\id_rsa"));
    }

    #[test]
    fn expansion_is_limited() {
        let base = Path::new(r"C:\P");
        let p = normalize(r"~\.ssh", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\Users\Alice\.ssh"));
        let p = normalize(r"%USERPROFILE%\x", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\Users\Alice\x"));
        // Unknown variables stay literal.
        let p = normalize(r"C:\P\%NOPE%\x", base, &env()).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\P\%NOPE%\x"));
    }

    #[test]
    fn canonicalizes_existing_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Sub")).unwrap();
        std::fs::write(dir.path().join("Sub").join("File.txt"), "x").unwrap();
        let lower = dir.path().join("sub").join("file.txt");
        let c = canonicalize(
            &normalize(&lower.to_string_lossy(), dir.path(), &env()).unwrap(),
            true,
        )
        .unwrap();
        assert!(c.exists);
        assert!(c.path.ends_with(r"Sub\File.txt"), "{:?}", c.path);
        let missing = dir.path().join("sub").join("new").join("deep.txt");
        let c = canonicalize(
            &normalize(&missing.to_string_lossy(), dir.path(), &env()).unwrap(),
            true,
        )
        .unwrap();
        assert!(!c.exists);
        assert_eq!(c.tail, vec!["new".to_string(), "deep.txt".to_string()]);
        assert!(c.path.ends_with(r"Sub\new\deep.txt"));
    }

    #[test]
    fn junction_is_resolved_to_destination() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        let inside = dir.path().join("inside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::write(outside.join("secret.txt"), "s").unwrap();
        let link = inside.join("link");
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(status.status.success(), "{status:?}");
        let c = canonicalize(&link.join("secret.txt"), true).unwrap();
        assert!(
            c.path
                .to_string_lossy()
                .to_lowercase()
                .contains(r"\outside\secret.txt"),
            "{:?}",
            c.path
        );
        // Not following the final component describes the junction itself.
        let c = canonicalize(&link, false).unwrap();
        assert!(c.is_reparse);
        assert!(c.path.ends_with(r"inside\link"));
    }
}
