//! Thin, handle-based wrappers over Win32/NT file APIs.
//!
//! These are the primitives that let the broker bind a policy decision to the
//! object actually accessed: final-path resolution from an open handle, file
//! identity and link counts, parent-relative create/open (`NtCreateFile` with a
//! `RootDirectory`), handle-based rename and delete, and directory enumeration
//! through an already-verified directory handle.

#![allow(clippy::upper_case_acronyms)]

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_RENAME_INFORMATION, FileDispositionInformationEx, FileRenameInformationEx, NtCreateFile,
    NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_HANDLE_EOF, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO, FILE_NAME_NORMALIZED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, FileIdInfo, FindClose, FindFirstFileNameW, FindNextFileNameW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    OPEN_EXISTING, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

// Access rights (winnt.h)
pub const DELETE: u32 = 0x0001_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_LIST_DIRECTORY: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_ADD_FILE: u32 = 0x0002;
pub const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
pub const FILE_TRAVERSE: u32 = 0x0020;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
pub const READ_CONTROL: u32 = 0x0002_0000;

// NtCreateFile dispositions/options (ntifs.h)
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
pub const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;

pub const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
/// Share mode used to pin a directory: others may read/write inside it but
/// cannot rename, replace or delete it while we hold the handle.
pub const SHARE_PIN: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

pub fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_no_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().collect()
}

fn owned(h: HANDLE) -> OwnedHandle {
    // SAFETY: caller passes a valid handle we own.
    unsafe { OwnedHandle::from_raw_handle(h as RawHandle) }
}

fn raw(h: &OwnedHandle) -> HANDLE {
    h.as_raw_handle() as HANDLE
}

fn nt_err(status: i32) -> io::Error {
    // SAFETY: pure conversion function.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(code as i32)
}

/// Open a path with `CreateFileW` (`OPEN_EXISTING`, backup semantics so
/// directories can be opened). `no_follow` opens a reparse point itself.
pub fn open_path(path: &Path, access: u32, share: u32, no_follow: bool) -> io::Result<OwnedHandle> {
    let w = wide(path.as_os_str());
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
    if no_follow {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    // SAFETY: `w` is NUL-terminated and outlives the call.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            share,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(owned(h))
}

/// Result of `GetFinalPathNameByHandleW`, classified by namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalPath {
    /// `C:\...`
    Dos(PathBuf),
    /// `\\server\share\...` (a network location)
    Unc(PathBuf),
    /// Anything else (volume GUID paths etc.)
    Other(PathBuf),
}

pub fn final_path(h: &OwnedHandle) -> io::Result<FinalPath> {
    let mut buf: Vec<u16> = vec![0; 512];
    loop {
        // SAFETY: buffer length passed matches allocation.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                raw(h),
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n >= buf.len() {
            buf.resize(n + 1, 0);
            continue;
        }
        let s = OsString::from_wide(&buf[..n]);
        let text = s.to_string_lossy().into_owned();
        return Ok(if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            FinalPath::Unc(PathBuf::from(format!(r"\\{rest}")))
        } else if let Some(rest) = text.strip_prefix(r"\\?\") {
            let b = rest.as_bytes();
            if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                let mut p = rest.to_string();
                p.replace_range(0..1, &rest[0..1].to_ascii_uppercase());
                FinalPath::Dos(PathBuf::from(p))
            } else {
                FinalPath::Other(PathBuf::from(text))
            }
        } else {
            FinalPath::Other(PathBuf::from(text))
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileIdentity {
    pub volume: u64,
    pub id: u128,
}

impl FileIdentity {
    pub fn to_string_id(&self) -> String {
        format!("{:016x}:{:032x}", self.volume, self.id)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FileInfo {
    pub attributes: u32,
    pub size: u64,
    pub links: u32,
    pub identity: FileIdentity,
    pub modified_ms: i64,
    pub created_ms: i64,
}

impl FileInfo {
    pub fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }
    pub fn is_reparse(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    pub fn is_readonly(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_READONLY != 0
    }
}

pub fn filetime_to_ms(ft: i64) -> i64 {
    // FILETIME: 100ns ticks since 1601-01-01.
    if ft <= 0 {
        return 0;
    }
    (ft - 116_444_736_000_000_000) / 10_000
}

pub fn file_info(h: &OwnedHandle) -> io::Result<FileInfo> {
    let mut bhfi: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle and out-pointer.
    if unsafe { GetFileInformationByHandle(raw(h), &mut bhfi) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut idinfo: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            raw(h),
            FileIdInfo,
            &mut idinfo as *mut _ as *mut _,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    let identity = if ok != 0 {
        FileIdentity {
            volume: idinfo.VolumeSerialNumber,
            id: u128::from_le_bytes(idinfo.FileId.Identifier),
        }
    } else {
        FileIdentity {
            volume: bhfi.dwVolumeSerialNumber as u64,
            id: ((bhfi.nFileIndexHigh as u128) << 32) | bhfi.nFileIndexLow as u128,
        }
    };
    let ft = |f: windows_sys::Win32::Foundation::FILETIME| {
        filetime_to_ms(((f.dwHighDateTime as i64) << 32) | f.dwLowDateTime as i64)
    };
    Ok(FileInfo {
        attributes: bhfi.dwFileAttributes,
        size: ((bhfi.nFileSizeHigh as u64) << 32) | bhfi.nFileSizeLow as u64,
        links: bhfi.nNumberOfLinks,
        identity,
        modified_ms: ft(bhfi.ftLastWriteTime),
        created_ms: ft(bhfi.ftCreationTime),
    })
}

/// All hard-link names of a file, as absolute DOS paths on the same volume.
pub fn hard_link_names(path: &Path) -> io::Result<Vec<PathBuf>> {
    let text = path.to_string_lossy();
    let drive = text.get(0..2).unwrap_or("").to_string();
    let w = wide(path.as_os_str());
    let mut out = Vec::new();
    let mut buf: Vec<u16> = vec![0; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: buffers sized per `len`.
    let h = unsafe { FindFirstFileNameW(w.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
    if h == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
            buf.resize(len as usize + 1, 0);
            return hard_link_names_retry(path, buf.len());
        }
        return Err(err);
    }
    let push = |out: &mut Vec<PathBuf>, buf: &[u16], len: u32| {
        let n = (len as usize).saturating_sub(1).min(buf.len());
        let name = OsString::from_wide(&buf[..n]);
        out.push(PathBuf::from(format!("{drive}{}", name.to_string_lossy())));
    };
    push(&mut out, &buf, len);
    loop {
        len = buf.len() as u32;
        let ok = unsafe { FindNextFileNameW(h, &mut len, buf.as_mut_ptr()) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
                buf.resize(len as usize + 1, 0);
                continue;
            }
            break;
        }
        push(&mut out, &buf, len);
        if out.len() > 1024 {
            break;
        }
    }
    unsafe { FindClose(h) };
    Ok(out)
}

fn hard_link_names_retry(path: &Path, size: usize) -> io::Result<Vec<PathBuf>> {
    let text = path.to_string_lossy();
    let drive = text.get(0..2).unwrap_or("").to_string();
    let w = wide(path.as_os_str());
    let mut buf: Vec<u16> = vec![0; size.max(32768)];
    let mut len = buf.len() as u32;
    let h = unsafe { FindFirstFileNameW(w.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    loop {
        let n = (len as usize).saturating_sub(1).min(buf.len());
        out.push(PathBuf::from(format!(
            "{drive}{}",
            OsString::from_wide(&buf[..n]).to_string_lossy()
        )));
        len = buf.len() as u32;
        if unsafe { FindNextFileNameW(h, &mut len, buf.as_mut_ptr()) } == 0 || out.len() > 1024 {
            break;
        }
    }
    unsafe { FindClose(h) };
    Ok(out)
}

/// Create or open `name` (a single path component) relative to `parent`
/// using `NtCreateFile`. With `FILE_OPEN_REPARSE_POINT` in `options` a
/// reparse point at `name` is opened itself rather than followed.
pub fn nt_create_relative(
    parent: &OwnedHandle,
    name: &OsStr,
    access: u32,
    attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> io::Result<OwnedHandle> {
    let w = wide_no_nul(name);
    if w.is_empty()
        || w.iter()
            .any(|&c| c == b'\\' as u16 || c == b'/' as u16 || c == 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative name must be a single component",
        ));
    }
    let byte_len = (w.len() * 2) as u16;
    let us = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: w.as_ptr() as *mut u16,
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw(parent),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut h: HANDLE = std::ptr::null_mut();
    let attrs = if attributes == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        attributes
    };
    // SAFETY: all pointers reference live locals for the duration of the call.
    let status = unsafe {
        NtCreateFile(
            &mut h,
            access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            attrs,
            share,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_err(status));
    }
    Ok(owned(h))
}

/// Rename/move the object behind `src` to `dest_parent\dest_name`.
pub fn rename_relative(
    src: &OwnedHandle,
    dest_parent: &OwnedHandle,
    dest_name: &OsStr,
    replace: bool,
) -> io::Result<()> {
    let name = wide_no_nul(dest_name);
    if name.is_empty() || name.iter().any(|&c| c == b'\\' as u16 || c == b'/' as u16) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad destination name",
        ));
    }
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let total = header + name.len() * 2 + 2;
    let mut buf = vec![0u8; total.max(std::mem::size_of::<FILE_RENAME_INFORMATION>())];
    // SAFETY: buffer is large enough for the header plus the name.
    unsafe {
        let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        let flags: u32 = 0x2 /* POSIX_SEMANTICS */ | if replace { 0x1 } else { 0 };
        (*info).Anonymous.Flags = flags;
        (*info).RootDirectory = raw(dest_parent);
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (buf.as_mut_ptr().add(header)) as *mut u16,
            name.len(),
        );
    }
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtSetInformationFile(
            raw(src),
            &mut iosb,
            buf.as_ptr() as *const _,
            buf.len() as u32,
            FileRenameInformationEx,
        )
    };
    if status < 0 {
        return Err(nt_err(status));
    }
    Ok(())
}

/// Delete the object behind `h` (POSIX semantics, ignoring read-only).
/// The handle must have been opened with `DELETE` access.
pub fn delete_by_handle(h: &OwnedHandle) -> io::Result<()> {
    #[repr(C)]
    struct DispositionEx {
        flags: u32,
    }
    let info = DispositionEx {
        flags: 0x1 /* DELETE */ | 0x2 /* POSIX_SEMANTICS */ | 0x10, /* IGNORE_READONLY_ATTRIBUTE */
    };
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtSetInformationFile(
            raw(h),
            &mut iosb,
            &info as *const _ as *const _,
            std::mem::size_of::<DispositionEx>() as u32,
            FileDispositionInformationEx,
        )
    };
    if status < 0 {
        return Err(nt_err(status));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub name: OsString,
    pub attributes: u32,
    pub size: u64,
    pub modified_ms: i64,
    pub file_id: i64,
}

impl DirEntryInfo {
    pub fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }
    pub fn is_reparse(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

/// Enumerate a directory through an open handle (opened with
/// `FILE_LIST_DIRECTORY`). `.` and `..` are omitted. Stops after `limit` entries.
pub fn read_dir_handle(h: &OwnedHandle, limit: usize) -> io::Result<(Vec<DirEntryInfo>, bool)> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut class = FileIdBothDirectoryRestartInfo;
    let mut truncated = false;
    loop {
        // SAFETY: buffer size passed matches allocation; alignment of Vec<u8>
        // allocation is sufficient for the 8-byte-aligned records in practice,
        // but we read fields with unaligned reads to be safe.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                raw(h),
                class,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
            )
        };
        class = FileIdBothDirectoryInfo;
        if ok == 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(c) if c == ERROR_NO_MORE_FILES as i32 || c == ERROR_HANDLE_EOF as i32 => break,
                _ => return Err(err),
            }
        }
        let mut offset = 0usize;
        loop {
            let base = unsafe { buf.as_ptr().add(offset) } as *const FILE_ID_BOTH_DIR_INFO;
            let rec: FILE_ID_BOTH_DIR_INFO = unsafe { std::ptr::read_unaligned(base) };
            let name_off = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            let name_len = rec.FileNameLength as usize / 2;
            let mut name_w = vec![0u16; name_len];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    buf.as_ptr().add(offset + name_off),
                    name_w.as_mut_ptr() as *mut u8,
                    name_len * 2,
                );
            }
            let name = OsString::from_wide(&name_w);
            if name != "." && name != ".." {
                if out.len() >= limit {
                    truncated = true;
                    return Ok((out, truncated));
                }
                out.push(DirEntryInfo {
                    name,
                    attributes: rec.FileAttributes,
                    size: rec.EndOfFile as u64,
                    modified_ms: filetime_to_ms(rec.LastWriteTime),
                    file_id: rec.FileId,
                });
            }
            if rec.NextEntryOffset == 0 {
                break;
            }
            offset += rec.NextEntryOffset as usize;
        }
    }
    Ok((out, truncated))
}

/// Convert an owned handle into a `File` for buffered reads/writes.
pub fn into_file(h: OwnedHandle) -> std::fs::File {
    std::fs::File::from(h)
}

/// Open a directory for use as a parent in relative operations, pinned
/// against rename/delete while held.
pub fn open_dir_pinned(path: &Path) -> io::Result<OwnedHandle> {
    open_path(
        path,
        FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | SYNCHRONIZE,
        SHARE_PIN,
        false,
    )
    .or_else(|_| {
        // Fall back to read-only directory access (e.g. for read-only parents);
        // relative create will then fail with an access error if not permitted.
        open_path(
            path,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            SHARE_PIN,
            false,
        )
    })
}

pub const GENERIC_READ_ACCESS: u32 = GENERIC_READ;
pub const GENERIC_WRITE_ACCESS: u32 = GENERIC_WRITE;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn relative_create_rename_delete() {
        let dir = tempfile::tempdir().unwrap();
        let parent = open_dir_pinned(dir.path()).unwrap();
        let fp = final_path(&parent).unwrap();
        assert!(matches!(fp, FinalPath::Dos(_)));

        let h = nt_create_relative(
            &parent,
            OsStr::new("a.txt"),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            0,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        )
        .unwrap();
        let info = file_info(&h).unwrap();
        assert_eq!(info.links, 1);
        let mut f = into_file(h);
        f.write_all(b"hello").unwrap();
        drop(f);

        // FILE_CREATE on an existing name fails.
        assert!(
            nt_create_relative(
                &parent,
                OsStr::new("a.txt"),
                GENERIC_READ,
                0,
                SHARE_ALL,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
            )
            .is_err()
        );

        let h = nt_create_relative(
            &parent,
            OsStr::new("a.txt"),
            DELETE | FILE_READ_ATTRIBUTES,
            0,
            SHARE_ALL,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT,
        )
        .unwrap();
        rename_relative(&h, &parent, OsStr::new("b.txt"), false).unwrap();
        drop(h);
        let mut s = String::new();
        std::fs::File::open(dir.path().join("b.txt"))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello");

        let (entries, truncated) = read_dir_handle(&parent, 100).unwrap();
        assert!(!truncated);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "b.txt");

        let h = nt_create_relative(
            &parent,
            OsStr::new("b.txt"),
            DELETE | FILE_READ_ATTRIBUTES,
            0,
            SHARE_ALL,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT,
        )
        .unwrap();
        delete_by_handle(&h).unwrap();
        drop(h);
        assert!(!dir.path().join("b.txt").exists());
    }

    #[test]
    fn hard_links_are_enumerated() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        std::fs::write(&a, "x").unwrap();
        std::fs::hard_link(&a, dir.path().join("b.txt")).unwrap();
        let h = open_path(&a, FILE_READ_ATTRIBUTES, SHARE_ALL, false).unwrap();
        assert_eq!(file_info(&h).unwrap().links, 2);
        let names = hard_link_names(&a).unwrap();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[test]
    fn pinned_directory_cannot_be_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let pinned = open_dir_pinned(&sub).unwrap();
        assert!(std::fs::rename(&sub, dir.path().join("moved")).is_err());
        drop(pinned);
        std::fs::rename(&sub, dir.path().join("moved")).unwrap();
    }
}
