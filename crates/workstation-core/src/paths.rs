//! Application-data layout under `%LOCALAPPDATA%\LocalPilot`.
//!
//! Everything here is application control data except the `cache\temp`
//! subtree, which is the single narrowly scoped external-write allowance for
//! agent-launched tools (see plan section 14).

use std::path::{Path, PathBuf};

use crate::error::{LpError, LpResult};
use crate::known_folders;

#[derive(Debug, Clone)]
pub struct AppPaths {
    /// `%LOCALAPPDATA%\LocalPilot`
    pub root: PathBuf,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub state_dir: PathBuf,
    pub update_dir: PathBuf,
    pub cache_dir: PathBuf,
    /// `%LOCALAPPDATA%\LocalPilot\cache\temp` (agent cache/temp allowance)
    pub cache_temp_dir: PathBuf,
}

impl AppPaths {
    /// Resolve the default layout using the LocalAppData known folder.
    pub fn resolve_default() -> LpResult<Self> {
        let lad = known_folders::local_app_data()?;
        Ok(Self::with_root(lad.join(crate::APP_DIR_NAME)))
    }

    /// Build the layout under an explicit root (used by tests and portable runs).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let cache_dir = root.join("cache");
        Self {
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            logs_dir: root.join("logs"),
            state_dir: root.join("state"),
            update_dir: root.join("update"),
            cache_temp_dir: cache_dir.join("temp"),
            cache_dir,
            root,
        }
    }

    pub fn ensure(&self) -> LpResult<()> {
        for dir in [
            &self.root,
            &self.config_dir,
            &self.data_dir,
            &self.logs_dir,
            &self.state_dir,
            &self.update_dir,
            &self.cache_dir,
            &self.cache_temp_dir,
            &self.cache_temp_dir.join("tools"),
            &self.cache_temp_dir.join("tasks"),
        ] {
            std::fs::create_dir_all(dir)
                .map_err(|e| LpError::internal(format!("create {}: {e}", dir.display())))?;
        }
        Ok(())
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }
    pub fn secrets_file(&self) -> PathBuf {
        self.config_dir.join("secrets.bin")
    }
    pub fn control_db(&self) -> PathBuf {
        self.data_dir.join("local-pilot.db")
    }
    pub fn audit_db(&self) -> PathBuf {
        self.data_dir.join("audit.db")
    }
    pub fn index_db(&self) -> PathBuf {
        self.data_dir.join("index.db")
    }
    pub fn remote_access_gate(&self) -> PathBuf {
        self.state_dir.join("remote-access.gate")
    }
    pub fn task_cache_dir(&self, task_id: &str) -> PathBuf {
        self.cache_temp_dir.join("tasks").join(task_id)
    }
    pub fn tool_cache_dir(&self, tool_profile: &str, scope: &str) -> PathBuf {
        self.cache_temp_dir
            .join("tools")
            .join(tool_profile)
            .join(scope)
    }

    pub fn is_under(&self, path: &Path) -> bool {
        crate::paths::starts_with_ci(path, &self.root)
    }
}

/// Case-insensitive, component-wise prefix test for already-canonical Windows
/// paths. Never use raw string prefix matching for policy decisions.
pub fn starts_with_ci(path: &Path, prefix: &Path) -> bool {
    let mut p = path.components();
    for pc in prefix.components() {
        match p.next() {
            Some(c) => {
                let a = c.as_os_str().to_string_lossy().to_lowercase();
                let b = pc.as_os_str().to_string_lossy().to_lowercase();
                if a != b {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

/// Case-insensitive equality for canonical Windows paths.
pub fn eq_ci(a: &Path, b: &Path) -> bool {
    starts_with_ci(a, b) && starts_with_ci(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_component_wise() {
        let root = Path::new(r"C:\Users\Alice\Documents\Projects");
        assert!(starts_with_ci(
            Path::new(r"C:\Users\Alice\Documents\Projects\Clippy"),
            root
        ));
        assert!(starts_with_ci(
            Path::new(r"c:\users\alice\documents\projects\clippy"),
            root
        ));
        assert!(!starts_with_ci(
            Path::new(r"C:\Users\Alice\Documents\Projects-Backup"),
            root
        ));
        assert!(!starts_with_ci(
            Path::new(r"C:\Users\Alice\Documents\Projects2\x"),
            root
        ));
        assert!(starts_with_ci(root, root));
    }
}
