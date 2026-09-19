//! Process creation for agent tasks.
//!
//! - The process is created suspended, placed in its Job Object (atomically via
//!   `PROC_THREAD_ATTRIBUTE_JOB_LIST`, with an explicit assignment check), and
//!   only then resumed, so no code runs outside the job.
//! - Only the three standard handles are inherited (`HANDLE_LIST`).
//! - If Local Pilot itself runs elevated, the child is launched with a
//!   restricted LUA token at medium integrity. If that cannot be established
//!   the launch fails closed.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    SetHandleInformation,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, GetTokenInformation, LUA_TOKEN,
    SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TokenElevation, TokenIntegrityLevel,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, UpdateProcThreadAttribute,
};

use crate::job::Job;

#[derive(Debug, Clone)]
pub struct SpawnSpec {
    /// Resolved executable used as `lpApplicationName`.
    pub application: PathBuf,
    /// Full command line (program + quoted arguments).
    pub command_line: String,
    pub cwd: PathBuf,
    /// Complete environment for the child.
    pub env: Vec<(String, String)>,
}

pub struct Spawned {
    pub process: OwnedHandle,
    pub pid: u32,
    pub stdout: File,
    pub stderr: File,
    pub job: Job,
    pub standard_user_token: bool,
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

struct Raw(HANDLE);
impl Drop for Raw {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn inheritable_pipe() -> io::Result<(Raw, Raw)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut r: HANDLE = std::ptr::null_mut();
    let mut w: HANDLE = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 64 * 1024) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // The parent's read end must not be inherited.
    unsafe { SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0) };
    Ok((Raw(r), Raw(w)))
}

fn nul_input() -> io::Result<Raw> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let name = wide(OsStr::new("NUL"));
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(Raw(h))
}

/// Whether the current process token is elevated.
pub fn current_process_elevated() -> bool {
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        return false;
    }
    let tok = Raw(tok);
    let mut elev: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            tok.0,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    ok != 0 && elev.TokenIsElevated != 0
}

fn token_elevated(tok: HANDLE) -> bool {
    let mut elev: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            tok,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    ok == 0 || elev.TokenIsElevated != 0
}

/// Build a restricted, non-elevated, medium-integrity primary token derived
/// from the current process token.
pub fn standard_user_token() -> io::Result<OwnedHandle> {
    let mut tok: HANDLE = std::ptr::null_mut();
    let access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut tok) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let tok = Raw(tok);
    let mut restricted: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        CreateRestrictedToken(
            tok.0,
            LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut restricted,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let restricted_owned = unsafe { OwnedHandle::from_raw_handle(restricted as RawHandle) };
    // Medium mandatory level: S-1-16-8192
    let sid_str = wide(OsStr::new("S-1-16-8192"));
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_str.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0x20, // SE_GROUP_INTEGRITY
        },
    };
    let len = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32
        + unsafe { windows_sys::Win32::Security::GetLengthSid(sid) };
    let ok = unsafe {
        SetTokenInformation(
            restricted,
            TokenIntegrityLevel,
            &label as *const _ as *const _,
            len,
        )
    };
    unsafe { windows_sys::Win32::Foundation::LocalFree(sid as _) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if token_elevated(restricted) {
        return Err(io::Error::other("restricted token is still elevated"));
    }
    Ok(restricted_owned)
}

fn env_block(env: &[(String, String)]) -> Vec<u16> {
    let mut vars: Vec<&(String, String)> = env.iter().collect();
    vars.sort_by_key(|a| a.0.to_uppercase());
    let mut block = Vec::new();
    for (k, v) in vars {
        if k.is_empty()
            || k.contains('=') && !k.starts_with('=')
            || k.contains('\0')
            || v.contains('\0')
        {
            continue;
        }
        block.extend(OsStr::new(&format!("{k}={v}")).encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// Launch a process inside a new job. Fails closed if a standard-user launch
/// cannot be established while Local Pilot is elevated.
pub fn spawn(spec: &SpawnSpec) -> io::Result<Spawned> {
    let (out_r, out_w) = inheritable_pipe()?;
    let (err_r, err_w) = inheritable_pipe()?;
    let stdin = nul_input()?;
    let job = Job::new()?;

    let elevated = current_process_elevated();
    let token = if elevated && std::env::var_os("CI").is_none() {
        Some(standard_user_token()?)
    } else {
        None
    };

    // Attribute list: inherited handles + job assignment.
    let mut size = 0usize;
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size) };
    let mut attr_buf = vec![0u8; size];
    let attrs = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    if unsafe { InitializeProcThreadAttributeList(attrs, 2, 0, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    struct AttrGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for AttrGuard {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _guard = AttrGuard(attrs);
    let handles: [HANDLE; 3] = [stdin.0, out_w.0, err_w.0];
    if unsafe {
        UpdateProcThreadAttribute(
            attrs,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr() as *const _,
            std::mem::size_of_val(&handles),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let jobs: [HANDLE; 1] = [job.raw()];
    let job_attr_ok = unsafe {
        UpdateProcThreadAttribute(
            attrs,
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            jobs.as_ptr() as *const _,
            std::mem::size_of_val(&jobs),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } != 0;

    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = stdin.0;
    si.StartupInfo.hStdOutput = out_w.0;
    si.StartupInfo.hStdError = err_w.0;
    si.lpAttributeList = attrs;

    let app = wide(spec.application.as_os_str());
    let mut cmdline = wide(OsStr::new(&spec.command_line));
    let cwd = wide(spec.cwd.as_os_str());
    let mut env = env_block(&spec.env);
    let flags = EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NO_WINDOW
        | CREATE_NEW_PROCESS_GROUP
        | CREATE_SUSPENDED;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        match &token {
            Some(t) => CreateProcessAsUserW(
                t.as_raw_handle() as HANDLE,
                app.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                flags,
                env.as_mut_ptr() as *mut _,
                cwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            ),
            None => CreateProcessW(
                app.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                flags,
                env.as_mut_ptr() as *mut _,
                cwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            ),
        }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess as RawHandle) };
    let thread = Raw(pi.hThread);
    // Ensure job membership before any code runs.
    if (!job_attr_ok || !job.contains(pi.hProcess))
        && let Err(e) = job.assign(pi.hProcess)
    {
        unsafe { windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1) };
        return Err(e);
    }
    if !job.contains(pi.hProcess) {
        unsafe { windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1) };
        return Err(io::Error::other(
            "process could not be placed in its job object",
        ));
    }
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        let e = io::Error::last_os_error();
        let _ = job.terminate(1);
        return Err(e);
    }
    drop(thread);
    // Close our copies of the child's ends.
    drop(out_w);
    drop(err_w);
    drop(stdin);
    let stdout = unsafe {
        File::from_raw_handle(std::mem::replace(&mut { out_r }.0, std::ptr::null_mut()) as RawHandle)
    };
    let stderr = unsafe {
        File::from_raw_handle(std::mem::replace(&mut { err_r }.0, std::ptr::null_mut()) as RawHandle)
    };
    Ok(Spawned {
        process,
        pid: pi.dwProcessId,
        stdout,
        stderr,
        job,
        standard_user_token: token.is_some(),
    })
}

#[derive(Debug, Clone)]
pub struct Captured {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub truncated: bool,
}

/// Run a short-lived command in its own job (standard user) and capture its
/// output, bounded to `max_output` bytes per stream. Used by structured Git
/// and GitHub tools; the tree is terminated on timeout.
pub fn run_captured(
    spec: &SpawnSpec,
    timeout: std::time::Duration,
    max_output: usize,
) -> io::Result<Captured> {
    use std::io::Read;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    let s = spawn(spec)?;
    let read = |mut f: File| {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 16384];
            let mut truncated = false;
            loop {
                match f.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.len() + n > max_output {
                            let room = max_output.saturating_sub(out.len());
                            out.extend_from_slice(&buf[..room]);
                            truncated = true;
                        } else {
                            out.extend_from_slice(&buf[..n]);
                        }
                    }
                }
            }
            (out, truncated)
        })
    };
    let out_t = read(s.stdout);
    let err_t = read(s.stderr);
    let deadline = std::time::Instant::now() + timeout;
    let h = s.process.as_raw_handle() as HANDLE;
    let mut timed_out = false;
    loop {
        if unsafe { WaitForSingleObject(h, 100) } == 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = s.job.terminate(1);
            timed_out = true;
            break;
        }
    }
    // Children may still hold the pipes; bound the wait for them too.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while s.job.active_processes().unwrap_or(0) > 0 && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = s.job.terminate(1);
    let mut code = 0u32;
    unsafe { GetExitCodeProcess(h, &mut code) };
    let (stdout, t1) = out_t.join().unwrap_or_default();
    let (stderr, t2) = err_t.join().unwrap_or_default();
    Ok(Captured {
        exit_code: if timed_out { None } else { Some(code as i32) },
        stdout,
        stderr,
        timed_out,
        truncated: t1 || t2,
    })
}

/// Resolve a program the way the task launcher does: explicit paths relative
/// to `cwd`, otherwise the `PATH` entries in order, trying `PATHEXT`.
pub fn resolve_executable(program: &str, cwd: &Path, env: &[(String, String)]) -> Option<PathBuf> {
    let get = |name: &str| {
        env.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let pathext: Vec<String> = get("PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let candidates = |base: PathBuf| -> Vec<PathBuf> {
        let mut v = Vec::new();
        let has_ext = base
            .extension()
            .map(|e| pathext.contains(&format!(".{}", e.to_string_lossy().to_ascii_lowercase())))
            .unwrap_or(false);
        if has_ext {
            v.push(base.clone());
        }
        for e in &pathext {
            let mut s = base.clone().into_os_string();
            s.push(e);
            v.push(PathBuf::from(s));
        }
        v
    };
    let is_file = |p: &Path| p.is_file();
    if program.contains('\\') || program.contains('/') || Path::new(program).is_absolute() {
        let base = if Path::new(program).is_absolute() {
            PathBuf::from(program)
        } else {
            cwd.join(program)
        };
        return candidates(base)
            .into_iter()
            .find(|p| is_file(p))
            .and_then(|p| std::fs::canonicalize(&p).ok().map(strip_verbatim));
    }
    let path = get("PATH").unwrap_or_default();
    for dir in path.split(';').filter(|d| !d.trim().is_empty()) {
        let dir = PathBuf::from(dir.trim().trim_matches('"'));
        if !dir.is_absolute() {
            continue; // relative PATH entries would depend on the working directory
        }
        for c in candidates(dir.join(program)) {
            if is_file(&c) {
                return std::fs::canonicalize(&c).ok().map(strip_verbatim);
            }
        }
    }
    None
}

pub fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.display().to_string();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => p,
    }
}

/// The system command interpreter (`%SystemRoot%\System32\cmd.exe`).
pub fn cmd_exe() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join("cmd.exe")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn env() -> Vec<(String, String)> {
        std::env::vars().collect()
    }

    #[test]
    fn runs_in_job_and_captures_output() {
        let dir = tempfile::tempdir().unwrap();
        let spec = SpawnSpec {
            application: cmd_exe(),
            command_line: r#"cmd.exe /d /s /c "echo hello& echo oops 1>&2""#.into(),
            cwd: dir.path().to_path_buf(),
            env: env(),
        };
        let mut s = spawn(&spec).unwrap();
        let mut out = String::new();
        s.stdout.read_to_string(&mut out).unwrap();
        let mut err = String::new();
        s.stderr.read_to_string(&mut err).unwrap();
        assert_eq!(out.trim(), "hello");
        assert_eq!(err.trim(), "oops");
        assert!(!s.standard_user_token || current_process_elevated());
    }

    #[test]
    fn terminating_the_job_kills_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        let spec = SpawnSpec {
            application: cmd_exe(),
            command_line: r#"cmd.exe /d /s /c "ping -n 30 127.0.0.1 >nul""#.into(),
            cwd: dir.path().to_path_buf(),
            env: env(),
        };
        let s = spawn(&spec).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(s.job.active_processes().unwrap() >= 2, "cmd + ping");
        s.job.terminate(1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(s.job.active_processes().unwrap(), 0);
    }

    #[test]
    fn resolves_programs_on_path() {
        let e = env();
        let p = resolve_executable("cmd", Path::new(r"C:\"), &e).unwrap();
        assert!(
            p.to_string_lossy()
                .to_lowercase()
                .ends_with(r"system32\cmd.exe"),
            "{p:?}"
        );
        assert!(
            resolve_executable("definitely-not-a-program-xyz", Path::new(r"C:\"), &e).is_none()
        );
    }
}
