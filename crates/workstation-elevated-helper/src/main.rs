//! Short-lived elevated helper for Local Pilot.
//!
//! The desktop process creates a one-use named pipe and starts this executable
//! through `runas`. The helper authenticates that pipe's server process,
//! validates the request against command-line bindings, executes exactly one
//! structured operation, returns a bounded response, and exits.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::{Command, Output};

use base64::Engine;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    RegSetValueExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};
use workstation_core::helper_ipc::{
    AdminOperation, HelperRequest, HelperResponse, PIPE_PREFIX, ServiceAction, operation_digest,
    read_frame, write_frame,
};

const MAX_OUTPUT: usize = 64 * 1024;

#[derive(Debug)]
struct Args {
    pipe: String,
    request: String,
    nonce: String,
    parent: u32,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(message) => {
            // The parent receives operational errors through the pipe whenever
            // possible. Startup failures contain no operation payload.
            eprintln!("Local Pilot elevated helper: {message}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args_os().skip(1))?;
    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.pipe)
        .map_err(|e| format!("could not connect to the one-use pipe: {e}"))?;

    let mut server_pid = 0u32;
    let handle = pipe.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    if unsafe { GetNamedPipeServerProcessId(handle, &mut server_pid) } == 0
        || server_pid != args.parent
    {
        return Err("the pipe was not created by the expected Local Pilot process".into());
    }

    let request: HelperRequest = read_frame(&mut pipe).map_err(|e| e.message)?;
    let response = if request.request_id != args.request
        || request.nonce != args.nonce
        || request.digest != operation_digest(&request.operation)
    {
        HelperResponse {
            request_id: args.request,
            ok: false,
            exit_code: None,
            output: String::new(),
            error: Some("request binding verification failed".into()),
        }
    } else {
        execute(request)
    };
    write_frame(&mut pipe, &response).map_err(|e| e.message)
}

fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator,
    I::Item: Into<std::ffi::OsString>,
{
    let values = args
        .into_iter()
        .map(|value| value.into())
        .collect::<Vec<_>>();
    if values.len() != 8 {
        return Err("expected --pipe, --request, --nonce, and --parent".into());
    }
    let mut parsed = HashMap::new();
    for pair in values.as_chunks::<2>().0 {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| "argument names must be Unicode".to_string())?;
        let value = pair[1]
            .to_str()
            .ok_or_else(|| format!("{key} must be Unicode"))?;
        if !matches!(key, "--pipe" | "--request" | "--nonce" | "--parent")
            || parsed.insert(key.to_string(), value.to_string()).is_some()
        {
            return Err(format!("unexpected or duplicate argument: {key}"));
        }
    }
    let pipe = parsed.remove("--pipe").unwrap_or_default();
    let suffix = pipe
        .strip_prefix(PIPE_PREFIX)
        .filter(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 160
                && suffix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
        .ok_or_else(|| "invalid pipe name".to_string())?;
    let _ = suffix;
    let request = bound_token(parsed.remove("--request"), "request")?;
    let nonce = bound_token(parsed.remove("--nonce"), "nonce")?;
    let parent = parsed
        .remove("--parent")
        .ok_or_else(|| "missing parent".to_string())?
        .parse::<u32>()
        .map_err(|_| "invalid parent process ID".to_string())?;
    if parent == 0 {
        return Err("invalid parent process ID".into());
    }
    Ok(Args {
        pipe,
        request,
        nonce,
        parent,
    })
}

fn bound_token(value: Option<String>, name: &str) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("missing {name}"))?;
    if value.len() < 8
        || value.len() > 200
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!("invalid {name}"));
    }
    Ok(value)
}

fn execute(request: HelperRequest) -> HelperResponse {
    let result = request.operation.validate().and_then(|()| {
        execute_operation(&request.operation)
            .map_err(|e| workstation_core::LpError::internal(e.to_string()))
    });
    match result {
        Ok((exit_code, output)) => HelperResponse {
            request_id: request.request_id,
            ok: true,
            exit_code,
            output: truncate(output),
            error: None,
        },
        Err(error) => HelperResponse {
            request_id: request.request_id,
            ok: false,
            exit_code: None,
            output: String::new(),
            error: Some(error.message),
        },
    }
}

fn execute_operation(operation: &AdminOperation) -> io::Result<(Option<i32>, String)> {
    match operation {
        AdminOperation::ServiceControl { service, action } => match action {
            ServiceAction::Start => command("sc.exe", &["start", service]),
            ServiceAction::Stop => command("sc.exe", &["stop", service]),
            ServiceAction::Restart => {
                let (_, stopped) = command("sc.exe", &["stop", service])?;
                let (code, started) = command("sc.exe", &["start", service])?;
                Ok((code, format!("{stopped}\n{started}")))
            }
        },
        AdminOperation::WingetInstall {
            package_id,
            version,
        } => {
            let mut args = vec![
                "install".to_string(),
                "--id".into(),
                package_id.clone(),
                "--exact".into(),
                "--scope".into(),
                "machine".into(),
                "--disable-interactivity".into(),
                "--accept-package-agreements".into(),
                "--accept-source-agreements".into(),
            ];
            if let Some(version) = version {
                args.extend(["--version".into(), version.clone()]);
            }
            command_owned("winget.exe", &args)
        }
        AdminOperation::WingetUninstall { package_id } => command(
            "winget.exe",
            &[
                "uninstall",
                "--id",
                package_id,
                "--exact",
                "--scope",
                "machine",
                "--disable-interactivity",
            ],
        ),
        AdminOperation::SetMachineEnvironment { name, value } => {
            set_machine_environment(name, value.as_deref())?;
            Ok((
                Some(0),
                format!("machine environment variable {name} updated"),
            ))
        }
        AdminOperation::WriteSystemFile {
            path,
            content_base64,
        } => {
            let content = base64::engine::general_purpose::STANDARD
                .decode(content_base64)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid base64 content")
                })?;
            write_system_file(Path::new(path), &content)?;
            Ok((Some(0), format!("wrote {} bytes", content.len())))
        }
    }
}

fn command(program: &str, args: &[&str]) -> io::Result<(Option<i32>, String)> {
    let args = args
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    command_owned(program, &args)
}

fn command_owned(program: &str, args: &[String]) -> io::Result<(Option<i32>, String)> {
    let output = Command::new(program)
        .args(args)
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GIT_ASKPASS")
        .env_remove("SSH_ASKPASS")
        .output()?;
    command_result(output)
}

fn command_result(output: Output) -> io::Result<(Option<i32>, String)> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = truncate(format!("{stdout}{stderr}"));
    if output.status.success() {
        Ok((output.status.code(), combined))
    } else {
        Err(io::Error::other(format!(
            "operation failed with exit code {:?}: {combined}",
            output.status.code()
        )))
    }
}

fn set_machine_environment(name: &str, value: Option<&str>) -> io::Result<()> {
    let subkey = wide(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
    let name = wide(name);
    let mut key = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let status = match value {
        Some(value) => {
            let value = wide(value);
            unsafe {
                RegSetValueExW(
                    key,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    value.as_ptr() as *const u8,
                    (value.len() * size_of::<u16>()) as u32,
                )
            }
        }
        None => unsafe { RegDeleteValueW(key, name.as_ptr()) },
    };
    unsafe { RegCloseKey(key) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let environment = wide("Environment");
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            environment.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            2000,
            std::ptr::null_mut(),
        )
    };
    Ok(())
}

fn write_system_file(path: &Path, content: &[u8]) -> io::Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to replace a symbolic link",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let canonical_parent = parent.canonicalize()?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let destination = canonical_parent.join(file_name);
    let temp = canonical_parent.join(format!(
        ".{}.local-pilot-{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&temp)?;
    io::Write::write_all(&mut file, content)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = replace_file(&temp, &destination) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source = wide(source.as_os_str());
    let destination = wide(destination.as_os_str());
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn truncate(mut value: String) -> String {
    if value.len() <= MAX_OUTPUT {
        return value;
    }
    let end = (0..=MAX_OUTPUT)
        .rev()
        .find(|&index| value.is_char_boundary(index))
        .unwrap_or(0);
    value.truncate(end);
    value.push_str("\n[output truncated]");
    value
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_exact_and_bound() {
        let args = parse_args([
            "--nonce",
            "n_12345678",
            "--parent",
            "42",
            "--request",
            "req_12345678",
            "--pipe",
            r"\\.\pipe\LocalPilot-helper-p_12345678",
        ])
        .unwrap();
        assert_eq!(args.parent, 42);
        assert!(parse_args(["--pipe", "bad"]).is_err());
    }

    #[test]
    fn output_truncation_preserves_utf8() {
        let value = "é".repeat(MAX_OUTPUT);
        let result = truncate(value);
        assert!(result.is_char_boundary(result.len()));
        assert!(result.ends_with("[output truncated]"));
    }
}
