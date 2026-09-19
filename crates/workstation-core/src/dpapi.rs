//! DPAPI (CurrentUser scope) protection for local key material such as the
//! token-hashing pepper and helper IPC keys. Plaintext tokens are never stored.

use std::path::Path;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

use crate::error::{LpError, LpResult};

const ENTROPY: &[u8] = b"LocalPilot/v1/local-secrets";

pub fn protect(plain: &[u8]) -> LpResult<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: ENTROPY.len() as u32,
        pbData: ENTROPY.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: all blobs point to valid memory for the duration of the call; the
    // output buffer is LocalAlloc'd by DPAPI and released with LocalFree.
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(LpError::internal(format!(
            "CryptProtectData failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let data = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { LocalFree(out.pbData as _) };
    Ok(data)
}

pub fn unprotect(blob: &[u8]) -> LpResult<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: ENTROPY.len() as u32,
        pbData: ENTROPY.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(LpError::internal(format!(
            "CryptUnprotectData failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let data = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { LocalFree(out.pbData as _) };
    Ok(data)
}

/// Local secrets kept in `config\secrets.bin` under DPAPI.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalSecrets {
    /// Pepper mixed into token hashes (HMAC-SHA256 key).
    pub token_pepper: Vec<u8>,
}

impl LocalSecrets {
    pub fn load_or_create(path: &Path) -> LpResult<Self> {
        match std::fs::read(path) {
            Ok(blob) => {
                let plain = unprotect(&blob)?;
                serde_json::from_slice(&plain)
                    .map_err(|e| LpError::internal(format!("secrets: {e}")))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let secrets = LocalSecrets {
                    token_pepper: crate::hashing::random_bytes(32),
                };
                let plain = serde_json::to_vec(&secrets).map_err(LpError::internal)?;
                let blob = protect(&plain)?;
                crate::config::write_atomic(path, &blob)?;
                Ok(secrets)
            }
            Err(e) => Err(LpError::internal(format!("read secrets: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let blob = protect(b"hello").unwrap();
        assert_ne!(blob, b"hello");
        assert_eq!(unprotect(&blob).unwrap(), b"hello");
    }

    #[test]
    fn load_or_create_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.bin");
        let a = LocalSecrets::load_or_create(&p).unwrap();
        let b = LocalSecrets::load_or_create(&p).unwrap();
        assert_eq!(a.token_pepper, b.token_pepper);
        assert_eq!(a.token_pepper.len(), 32);
    }
}
