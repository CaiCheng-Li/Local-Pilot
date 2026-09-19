//! Project writer leases (plan section 20).
//!
//! By default one client holds the writer lease of a project at a time.
//! Leases expire unless renewed, so a crashed client cannot lock a project
//! forever. Leases coordinate agents; they are not filesystem isolation.

use std::collections::HashMap;

use parking_lot::Mutex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use workstation_core::db::Db;
use workstation_core::{ErrorCode, LpError, LpResult, time};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub project_id: String,
    pub holder_client_id: String,
    /// Task holding the lease (renewed while it runs), if any.
    pub holder_task_id: Option<String>,
    pub acquired_at: i64,
    pub expires_at: i64,
}

pub struct LeaseManager {
    db: Db,
    leases: Mutex<HashMap<String, Vec<Lease>>>,
}

impl LeaseManager {
    pub fn new(db: Db) -> Self {
        let _ = db.write_sync(|c| {
            c.execute("DELETE FROM project_locks", [])?;
            Ok(())
        });
        Self {
            db,
            leases: Mutex::new(HashMap::new()),
        }
    }

    /// Acquire or renew a writer lease for `client_id`.
    pub fn acquire(
        &self,
        project_id: &str,
        client_id: &str,
        task_id: Option<&str>,
        ttl_ms: i64,
        allow_multiple: bool,
    ) -> LpResult<()> {
        let now = time::now_ms();
        let mut map = self.leases.lock();
        let list = map.entry(project_id.to_string()).or_default();
        list.retain(|l| l.expires_at > now);
        if !allow_multiple
            && let Some(other) = list.iter().find(|l| l.holder_client_id != client_id)
        {
            return Err(LpError::new(
                ErrorCode::ProjectLocked,
                format!(
                    "Another agent ({}) currently holds the writer lease for this project; retry later or ask the user to allow multiple writers.",
                    other.holder_client_id
                ),
            ));
        }
        match list
            .iter_mut()
            .find(|l| l.holder_client_id == client_id && l.holder_task_id.as_deref() == task_id)
        {
            Some(l) => l.expires_at = l.expires_at.max(now + ttl_ms),
            None => list.push(Lease {
                project_id: project_id.to_string(),
                holder_client_id: client_id.to_string(),
                holder_task_id: task_id.map(|s| s.to_string()),
                acquired_at: now,
                expires_at: now + ttl_ms,
            }),
        }
        let first = list.first().cloned();
        drop(map);
        if let Some(l) = first {
            let _ = self.db.write_sync(move |c| {
                c.execute(
                    "INSERT INTO project_locks (project_id, holder_client_id, holder_task_id, acquired_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(project_id) DO UPDATE SET holder_client_id = excluded.holder_client_id, holder_task_id = excluded.holder_task_id, expires_at = excluded.expires_at",
                    params![l.project_id, l.holder_client_id, l.holder_task_id, l.acquired_at, l.expires_at],
                )?;
                Ok(())
            });
        }
        Ok(())
    }

    /// Release a task's lease when it finishes.
    pub fn release_task(&self, task_id: &str) {
        let mut map = self.leases.lock();
        for list in map.values_mut() {
            list.retain(|l| l.holder_task_id.as_deref() != Some(task_id));
        }
        map.retain(|_, v| !v.is_empty());
        self.sync(&map);
    }

    pub fn release_client(&self, client_id: &str) {
        let mut map = self.leases.lock();
        for list in map.values_mut() {
            list.retain(|l| l.holder_client_id != client_id);
        }
        map.retain(|_, v| !v.is_empty());
        self.sync(&map);
    }

    pub fn clear(&self) {
        let mut map = self.leases.lock();
        map.clear();
        self.sync(&map);
    }

    /// Extend leases held by running tasks (heartbeat).
    pub fn renew_task(&self, task_id: &str, ttl_ms: i64) {
        let now = time::now_ms();
        for list in self.leases.lock().values_mut() {
            for l in list
                .iter_mut()
                .filter(|l| l.holder_task_id.as_deref() == Some(task_id))
            {
                l.expires_at = now + ttl_ms;
            }
        }
    }

    pub fn list(&self) -> Vec<Lease> {
        let now = time::now_ms();
        let mut map = self.leases.lock();
        for list in map.values_mut() {
            list.retain(|l| l.expires_at > now);
        }
        map.retain(|_, v| !v.is_empty());
        map.values().flatten().cloned().collect()
    }

    fn sync(&self, map: &HashMap<String, Vec<Lease>>) {
        let rows: Vec<Lease> = map.values().filter_map(|v| v.first().cloned()).collect();
        let _ = self.db.write_sync(move |c| {
            c.execute("DELETE FROM project_locks", [])?;
            for l in &rows {
                c.execute(
                    "INSERT INTO project_locks (project_id, holder_client_id, holder_task_id, acquired_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![l.project_id, l.holder_client_id, l.holder_task_id, l.acquired_at, l.expires_at],
                )?;
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_writer_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("c.db"), crate::control_db::MIGRATIONS).unwrap();
        let m = LeaseManager::new(db);
        m.acquire("prj_1", "cl_a", None, 60_000, false).unwrap();
        m.acquire("prj_1", "cl_a", None, 60_000, false).unwrap();
        assert!(m.acquire("prj_1", "cl_b", None, 60_000, false).is_err());
        assert!(m.acquire("prj_2", "cl_b", None, 60_000, false).is_ok());
        assert!(m.acquire("prj_1", "cl_b", None, 60_000, true).is_ok());
        m.release_client("cl_a");
        m.release_client("cl_b");
        assert!(m.acquire("prj_1", "cl_c", None, 60_000, false).is_ok());
        // Expired leases do not block.
        m.acquire("prj_3", "cl_a", None, -1, false).unwrap();
        assert!(m.acquire("prj_3", "cl_b", None, 60_000, false).is_ok());
    }
}
