//! Launcher for the short-lived elevated helper (plan sections 16 and 43).
//!
//! For each approved administrative operation:
//! 1. create a uniquely named, local-only pipe (first instance, remote clients
//!    rejected);
//! 2. launch `local-pilot-elevated-helper.exe` with `runas` — Windows shows the
//!    UAC prompt, which is itself a local consent step;
//! 3. accept exactly one connection and verify the client process is the
//!    helper we launched;
//! 4. send one request (request ID, nonce, operation, digest), read one
//!    response, close the pipe. The helper exits after the operation, on pipe
//!    closure (Emergency Stop) or after an idle timeout.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_NOWAIT,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
    SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{GetProcessId, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use workstation_core::helper_ipc::{
    AdminOperation, HelperRequest, HelperResponse, PIPE_PREFIX, operation_digest,
};
use workstation_core::{ErrorCode, LpError, LpResult, hashing, ids};

struct Active {
    abort: Arc<AtomicBool>,
}

pub struct HelperManager {
    exe: Option<PathBuf>,
    active: Mutex<Vec<Active>>,
}

struct H(HANDLE);
unsafe impl Send for H {}
impl Drop for H {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

impl HelperManager {
    pub fn new(exe: Option<PathBuf>) -> Self {
        Self {
            exe,
            active: Mutex::new(Vec::new()),
        }
    }

    pub fn available(&self) -> bool {
        self.exe.as_ref().map(|p| p.is_file()).unwrap_or(false)
    }

    /// Emergency Stop: abort every helper exchange; helpers exit when their
    /// pipe breaks and terminate their own job.
    pub fn abort_all(&self) {
        for a in self.active.lock().iter() {
            a.abort.store(true, Ordering::SeqCst);
        }
    }

    pub async fn run(&self, op: AdminOperation) -> LpResult<HelperResponse> {
        op.validate()?;
        let exe = self.exe.clone().filter(|p| p.is_file()).ok_or_else(|| {
            LpError::new(
                ErrorCode::Unsupported,
                "The elevated helper is not installed with this build.",
            )
        })?;
        let abort = Arc::new(AtomicBool::new(false));
        self.active.lock().push(Active {
            abort: abort.clone(),
        });
        let a2 = abort.clone();
        let result = tokio::task::spawn_blocking(move || exchange(&exe, op, &a2))
            .await
            .map_err(LpError::internal)?;
        self.active
            .lock()
            .retain(|a| !Arc::ptr_eq(&a.abort, &abort));
        result
    }
}

fn exchange(
    exe: &std::path::Path,
    op: AdminOperation,
    abort: &AtomicBool,
) -> LpResult<HelperResponse> {
    let request_id = ids::request_id();
    let nonce = hashing::random_token("n");
    let pipe_name = format!("{PIPE_PREFIX}{}", hashing::random_token("p"));
    let wname = wide(&pipe_name);
    // SAFETY: valid NUL-terminated name; default security (current user).
    let pipe = unsafe {
        CreateNamedPipeW(
            wname.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            std::ptr::null(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(LpError::internal(format!(
            "CreateNamedPipe failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let pipe = H(pipe);

    // Launch with UAC elevation.
    let file = wide(&exe.display().to_string());
    let verb = wide("runas");
    let params = wide(&format!(
        "--pipe \"{pipe_name}\" --request {request_id} --nonce {nonce} --parent {}",
        std::process::id()
    ));
    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    sei.lpVerb = verb.as_ptr();
    sei.lpFile = file.as_ptr();
    sei.lpParameters = params.as_ptr();
    sei.nShow = 0; // SW_HIDE
    if unsafe { ShellExecuteExW(&mut sei) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(1223) {
            return Err(LpError::new(
                ErrorCode::ApprovalDenied,
                "Windows elevation was declined; nothing was executed.",
            ));
        }
        return Err(LpError::new(
            ErrorCode::CommandFailed,
            format!("could not start the elevated helper: {e}"),
        ));
    }
    let process = H(sei.hProcess);
    let helper_pid = unsafe { GetProcessId(process.0) };

    // Accept one connection (non-blocking polling so abort/timeouts work).
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if abort.load(Ordering::SeqCst) {
            return Err(LpError::new(ErrorCode::EmergencyStopActive, "aborted"));
        }
        let ok = unsafe { ConnectNamedPipe(pipe.0, std::ptr::null_mut()) };
        let err = unsafe { GetLastError() };
        if ok != 0 || err == 535 {
            break; // ERROR_PIPE_CONNECTED
        }
        if err != 536 && err != 232 {
            return Err(LpError::internal(format!("ConnectNamedPipe failed: {err}")));
        }
        if unsafe { WaitForSingleObject(process.0, 0) } == 0 {
            return Err(LpError::new(
                ErrorCode::CommandFailed,
                "the elevated helper exited before connecting",
            ));
        }
        if Instant::now() > deadline {
            return Err(LpError::new(
                ErrorCode::Timeout,
                "the elevated helper did not connect in time",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    unsafe { SetNamedPipeHandleState(pipe.0, &mode, std::ptr::null(), std::ptr::null()) };
    // Authenticate the peer: it must be the process we launched.
    let mut client_pid = 0u32;
    if unsafe { GetNamedPipeClientProcessId(pipe.0, &mut client_pid) } == 0
        || client_pid != helper_pid
    {
        return Err(LpError::new(
            ErrorCode::PermissionDenied,
            "unexpected process connected to the helper pipe",
        ));
    }
    let req = HelperRequest {
        request_id: request_id.clone(),
        nonce,
        digest: operation_digest(&op),
        operation: op,
    };
    let bytes = serde_json::to_vec(&req).map_err(LpError::internal)?;
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend(bytes);
    write_all(&pipe, &frame)?;
    let resp_len = read_exact(&pipe, 4, abort, Duration::from_secs(30 * 60))?;
    let n = u32::from_le_bytes([resp_len[0], resp_len[1], resp_len[2], resp_len[3]]) as usize;
    if n > workstation_core::helper_ipc::MAX_FRAME {
        return Err(LpError::invalid("oversized helper response"));
    }
    let body = read_exact(&pipe, n, abort, Duration::from_secs(60))?;
    let resp: HelperResponse = serde_json::from_slice(&body)
        .map_err(|e| LpError::internal(format!("bad helper response: {e}")))?;
    if resp.request_id != request_id {
        return Err(LpError::new(
            ErrorCode::PermissionDenied,
            "helper response does not match the request",
        ));
    }
    drop(pipe);
    unsafe { WaitForSingleObject(process.0, 5000) };
    Ok(resp)
}

fn write_all(pipe: &H, mut data: &[u8]) -> LpResult<()> {
    while !data.is_empty() {
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                pipe.0,
                data.as_ptr(),
                data.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(LpError::internal(format!(
                "pipe write failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        data = &data[written as usize..];
    }
    Ok(())
}

fn read_exact(pipe: &H, n: usize, abort: &AtomicBool, timeout: Duration) -> LpResult<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    let deadline = Instant::now() + timeout;
    while out.len() < n {
        if abort.load(Ordering::SeqCst) {
            return Err(LpError::new(
                ErrorCode::EmergencyStopActive,
                "aborted; the elevated helper was told to stop",
            ));
        }
        let mut avail = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                pipe.0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut avail,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(LpError::new(
                ErrorCode::OutcomeUnknown,
                "the elevated helper disconnected before reporting a result",
            ));
        }
        if avail == 0 {
            if Instant::now() > deadline {
                return Err(LpError::new(
                    ErrorCode::OutcomeUnknown,
                    "the elevated operation did not report in time; its outcome is unknown",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let want = (n - out.len()).min(avail as usize);
        let mut buf = vec![0u8; want];
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                pipe.0,
                buf.as_mut_ptr(),
                want as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(LpError::new(ErrorCode::OutcomeUnknown, "pipe read failed"));
        }
        out.extend_from_slice(&buf[..read as usize]);
    }
    Ok(out)
}
