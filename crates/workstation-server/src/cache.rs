//! Managed cache/temp allowance (plan section 14):
//! `%LOCALAPPDATA%\LocalPilot\cache\temp\tools\<profile>\<principal>\` and
//! `...\tasks\<task-id>\`. Quotas are enforced before allocation; cleanup
//! never touches active task directories.

use std::path::{Path, PathBuf};

use workstation_core::paths::AppPaths;
use workstation_core::{ErrorCode, LpError, LpResult};

pub struct CacheManager {
    paths: AppPaths,
}

fn dir_size(p: &Path, budget: &mut usize) -> u64 {
    let mut total = 0;
    let Ok(rd) = std::fs::read_dir(p) else {
        return 0;
    };
    for e in rd.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            total += dir_size(&e.path(), budget);
        } else if let Ok(m) = e.metadata() {
            total += m.len();
        }
    }
    total
}

fn safe_component(s: &str) -> String {
    let c: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect();
    if c.is_empty() { "x".into() } else { c }
}

impl CacheManager {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn usage_bytes(&self) -> u64 {
        let mut budget = 500_000;
        dir_size(&self.paths.cache_temp_dir, &mut budget)
    }

    /// Allocate the task's temp directory and the tool cache for its principal.
    pub fn allocate(
        &self,
        task_id: &str,
        tool_profile: &str,
        principal: &str,
        quota_mb: u64,
    ) -> LpResult<(PathBuf, PathBuf)> {
        let quota = quota_mb * 1024 * 1024;
        let used = self.usage_bytes();
        if used >= quota {
            return Err(LpError::new(
                ErrorCode::CacheQuotaExceeded,
                format!(
                    "The Local Pilot cache/temp quota is exhausted ({} MB used of {} MB); ask the user to clean up or raise the quota.",
                    used / (1024 * 1024),
                    quota_mb
                ),
            ));
        }
        let task_dir = self
            .paths
            .cache_temp_dir
            .join("tasks")
            .join(safe_component(task_id));
        let tool_dir = self
            .paths
            .cache_temp_dir
            .join("tools")
            .join(safe_component(tool_profile))
            .join(safe_component(principal));
        std::fs::create_dir_all(&task_dir).map_err(LpError::internal)?;
        std::fs::create_dir_all(&tool_dir).map_err(LpError::internal)?;
        Ok((task_dir, tool_dir))
    }

    /// Remove finished task directories older than `max_age`, never active ones.
    pub fn cleanup(&self, active_task_ids: &[String], max_age: std::time::Duration) -> usize {
        let dir = self.paths.cache_temp_dir.join("tasks");
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return 0;
        };
        let mut removed = 0;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if active_task_ids.iter().any(|a| safe_component(a) == name) {
                continue;
            }
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|age| age > max_age)
                .unwrap_or(false);
            if old
                && e.file_type()
                    .map(|t| t.is_dir() && !t.is_symlink())
                    .unwrap_or(false)
                && std::fs::remove_dir_all(e.path()).is_ok()
            {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_and_quota() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_root(dir.path());
        paths.ensure().unwrap();
        let m = CacheManager::new(paths.clone());
        let (t, tool) = m.allocate("task_1", "npm", "cl_1", 10).unwrap();
        assert!(t.starts_with(&paths.cache_temp_dir));
        assert!(tool.ends_with(r"tools\npm\cl_1"));
        std::fs::write(t.join("big"), vec![0u8; 2 * 1024 * 1024]).unwrap();
        assert!(
            matches!(m.allocate("task_2", "npm", "cl_1", 1), Err(e) if e.code == ErrorCode::CacheQuotaExceeded)
        );
        // Active task directories survive cleanup.
        assert_eq!(
            m.cleanup(&["task_1".into()], std::time::Duration::from_secs(0)),
            0
        );
        assert!(t.exists());
    }
}
