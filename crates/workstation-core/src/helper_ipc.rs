//! Wire protocol between Local Pilot and the short-lived elevated helper.
//!
//! The helper only understands this closed set of structured operations; there
//! is intentionally no "run this string as admin" request.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::error::{LpError, LpResult};

pub const PIPE_PREFIX: &str = r"\\.\pipe\LocalPilot-helper-";
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
pub const HELPER_IDLE_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AdminOperation {
    ServiceControl {
        service: String,
        action: ServiceAction,
    },
    WingetInstall {
        package_id: String,
        version: Option<String>,
    },
    WingetUninstall {
        package_id: String,
    },
    SetMachineEnvironment {
        name: String,
        /// `None` removes the variable.
        value: Option<String>,
    },
    WriteSystemFile {
        path: String,
        content_base64: String,
    },
}

impl AdminOperation {
    pub fn summary(&self) -> String {
        match self {
            AdminOperation::ServiceControl { service, action } => {
                format!("{action:?} Windows service '{service}'")
            }
            AdminOperation::WingetInstall {
                package_id,
                version,
            } => format!(
                "Install '{package_id}'{} machine-wide with winget",
                version
                    .as_deref()
                    .map(|v| format!(" version {v}"))
                    .unwrap_or_default()
            ),
            AdminOperation::WingetUninstall { package_id } => {
                format!("Uninstall '{package_id}' with winget")
            }
            AdminOperation::SetMachineEnvironment { name, value } => match value {
                Some(_) => format!("Set machine environment variable {name}"),
                None => format!("Remove machine environment variable {name}"),
            },
            AdminOperation::WriteSystemFile {
                path,
                content_base64,
            } => format!("Write {} bytes (base64) to {path}", content_base64.len()),
        }
    }

    /// Strict argument validation shared by the requester and the helper.
    pub fn validate(&self) -> LpResult<()> {
        fn ident(s: &str, what: &str, extra: &[char]) -> LpResult<()> {
            if s.is_empty()
                || s.len() > 128
                || !s.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || c == '_'
                        || c == '-'
                        || c == '.'
                        || extra.contains(&c)
                })
            {
                return Err(LpError::invalid(format!("invalid {what}: {s:?}")));
            }
            Ok(())
        }
        match self {
            AdminOperation::ServiceControl { service, .. } => ident(service, "service name", &[]),
            AdminOperation::WingetInstall {
                package_id,
                version,
            } => {
                ident(package_id, "package id", &[])?;
                if let Some(v) = version {
                    ident(v, "version", &['+'])?;
                }
                Ok(())
            }
            AdminOperation::WingetUninstall { package_id } => ident(package_id, "package id", &[]),
            AdminOperation::SetMachineEnvironment { name, value } => {
                ident(name, "variable name", &[])?;
                if let Some(v) = value
                    && (v.len() > 32 * 1024 || v.contains('\0'))
                {
                    return Err(LpError::invalid("invalid variable value"));
                }
                Ok(())
            }
            AdminOperation::WriteSystemFile {
                path,
                content_base64,
            } => {
                let b = path.as_bytes();
                let drive_absolute = b.len() > 3
                    && b[0].is_ascii_alphabetic()
                    && b[1] == b':'
                    && b[2] == b'\\'
                    && !path[2..].contains(':')
                    && !path.split('\\').any(|c| c == "..");
                if !drive_absolute {
                    return Err(LpError::invalid(
                        "system file path must be an absolute drive path",
                    ));
                }
                if content_base64.len() > MAX_FRAME / 2 {
                    return Err(LpError::invalid("content too large"));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperRequest {
    pub request_id: String,
    /// Random per-request nonce, also passed on the helper command line.
    pub nonce: String,
    pub operation: AdminOperation,
    /// SHA-256 of the canonical JSON of `operation`, bound to the local approval.
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperResponse {
    pub request_id: String,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub output: String,
    pub error: Option<String>,
}

pub fn operation_digest(op: &AdminOperation) -> String {
    crate::hashing::json_digest(&serde_json::to_value(op).unwrap_or_default())
}

pub fn write_frame(w: &mut impl Write, value: &impl Serialize) -> LpResult<()> {
    let bytes = serde_json::to_vec(value).map_err(LpError::internal)?;
    if bytes.len() > MAX_FRAME {
        return Err(LpError::invalid("frame too large"));
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|_| w.write_all(&bytes))
        .and_then(|_| w.flush())
        .map_err(|e| LpError::internal(format!("pipe write: {e}")))
}

pub fn read_frame<T: for<'de> Deserialize<'de>>(r: &mut impl Read) -> LpResult<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .map_err(|e| LpError::internal(format!("pipe read: {e}")))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(LpError::invalid("frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|e| LpError::internal(format!("pipe read: {e}")))?;
    serde_json::from_slice(&buf).map_err(|e| LpError::invalid(format!("bad frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_injection() {
        assert!(
            AdminOperation::ServiceControl {
                service: "Spooler".into(),
                action: ServiceAction::Restart
            }
            .validate()
            .is_ok()
        );
        assert!(
            AdminOperation::ServiceControl {
                service: "x & calc".into(),
                action: ServiceAction::Start
            }
            .validate()
            .is_err()
        );
        assert!(
            AdminOperation::WingetInstall {
                package_id: "Git.Git".into(),
                version: None
            }
            .validate()
            .is_ok()
        );
        assert!(
            AdminOperation::WingetInstall {
                package_id: "Git.Git --override".into(),
                version: None
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn frames_roundtrip() {
        let req = HelperRequest {
            request_id: "r".into(),
            nonce: "n".into(),
            operation: AdminOperation::WingetUninstall {
                package_id: "A.B".into(),
            },
            digest: "d".into(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let back: HelperRequest = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(back.operation, req.operation);
    }
}
