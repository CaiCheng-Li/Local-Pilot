//! Windows Known Folder resolution. The Documents folder may be redirected (for
//! example to OneDrive), so it is always resolved through `SHGetKnownFolderPath`
//! instead of being derived from the user name or profile path.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_Documents, FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_ProgramData,
    FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows_sys::core::GUID;

use crate::error::{LpError, LpResult};

fn known_folder(id: &GUID, name: &str) -> LpResult<PathBuf> {
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: SHGetKnownFolderPath writes a CoTaskMem-allocated, NUL-terminated
    // wide string into `raw` on success; we free it with CoTaskMemFree.
    let hr =
        unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, std::ptr::null_mut(), &mut raw) };
    if hr < 0 || raw.is_null() {
        if !raw.is_null() {
            unsafe { CoTaskMemFree(raw as *const _) };
        }
        return Err(LpError::internal(format!(
            "SHGetKnownFolderPath({name}) failed: 0x{hr:08x}"
        )));
    }
    let path = unsafe {
        let mut len = 0usize;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(raw, len);
        let os = OsString::from_wide(slice);
        CoTaskMemFree(raw as *const _);
        PathBuf::from(os)
    };
    Ok(path)
}

pub fn documents() -> LpResult<PathBuf> {
    known_folder(&FOLDERID_Documents, "Documents")
}

pub fn local_app_data() -> LpResult<PathBuf> {
    known_folder(&FOLDERID_LocalAppData, "LocalAppData")
}

pub fn roaming_app_data() -> LpResult<PathBuf> {
    known_folder(&FOLDERID_RoamingAppData, "RoamingAppData")
}

pub fn profile() -> LpResult<PathBuf> {
    known_folder(&FOLDERID_Profile, "Profile")
}

pub fn program_data() -> LpResult<PathBuf> {
    known_folder(&FOLDERID_ProgramData, "ProgramData")
}

/// The default trusted workspace: `<Documents>\Projects`.
pub fn default_projects_root() -> LpResult<PathBuf> {
    Ok(documents()?.join("Projects"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_folders() {
        let docs = documents().unwrap();
        assert!(docs.is_absolute());
        let lad = local_app_data().unwrap();
        assert!(lad.is_absolute());
        assert!(profile().unwrap().is_absolute());
    }
}
