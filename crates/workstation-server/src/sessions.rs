//! Application sessions (plan section 17, "Application sessions").
//!
//! A session is distinct from HTTP connections, OAuth access tokens and MCP
//! transport sessions. There is one active session per principal + credential
//! grant; chats sharing a grant share its scoped permissions. Idle and absolute
//! expiry are enforced here; restarts end every session.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use workstation_core::config::Settings;
use workstation_core::db::Db;
use workstation_core::{LpResult, ids, time};
use workstation_policy::SessionScope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrant {
    pub scope: SessionScope,
    pub label: String,
    pub approval_id: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub client_id: String,
    pub credential_id: String,
    pub created_at: i64,
    pub last_activity_at: i64,
    pub absolute_expires_at: i64,
    pub idle_timeout_ms: i64,
    pub grants: Vec<SessionGrant>,
}

impl Session {
    pub fn idle_expires_at(&self) -> i64 {
        self.last_activity_at + self.idle_timeout_ms
    }
    pub fn expired(&self, now: i64) -> Option<&'static str> {
        if now >= self.absolute_expires_at {
            Some("absolute_expiry")
        } else if now >= self.idle_expires_at() {
            Some("idle_expiry")
        } else {
            None
        }
    }
    pub fn scopes(&self) -> Vec<SessionScope> {
        self.grants.iter().map(|g| g.scope.clone()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct EndedSession {
    pub session: Session,
    pub reason: String,
}

pub struct SessionService {
    db: Db,
    active: Mutex<HashMap<(String, String), Session>>,
}

impl SessionService {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Startup: sessions never survive a restart.
    pub fn end_all_persisted(&self, reason: &str) -> LpResult<usize> {
        let r = reason.to_string();
        self.db.write_sync(move |c| {
            let now = time::now_ms();
            c.execute("UPDATE session_permissions SET revoked_at = ?1 WHERE revoked_at IS NULL", [now])?;
            Ok(c.execute(
                "UPDATE application_sessions SET ended_at = ?1, end_reason = ?2 WHERE ended_at IS NULL",
                params![now, r],
            )?)
        })
    }

    /// Current session for a principal/grant, creating one if none is active.
    /// Returns the session and any session that just expired.
    pub fn resolve(
        &self,
        client_id: &str,
        credential_id: &str,
        settings: &Settings,
    ) -> LpResult<(Session, Option<EndedSession>)> {
        let now = time::now_ms();
        let key = (client_id.to_string(), credential_id.to_string());
        let mut active = self.active.lock();
        let mut ended = None;
        if let Some(s) = active.get(&key) {
            match s.expired(now) {
                None => return Ok((s.clone(), None)),
                Some(reason) => {
                    let s = active.remove(&key).expect("present");
                    self.persist_end(&s.session_id, reason);
                    ended = Some(EndedSession {
                        session: s,
                        reason: reason.to_string(),
                    });
                }
            }
        }
        let s = Session {
            session_id: ids::session_id(),
            client_id: client_id.to_string(),
            credential_id: credential_id.to_string(),
            created_at: now,
            last_activity_at: now,
            absolute_expires_at: now
                + settings.sessions.absolute_lifetime_hours as i64 * time::HOUR_MS,
            idle_timeout_ms: settings.sessions.idle_timeout_minutes as i64 * time::MINUTE_MS,
            grants: Vec::new(),
        };
        let s2 = s.clone();
        self.db.write_sync(move |c| {
            c.execute(
                "INSERT INTO application_sessions (session_id, client_id, credential_id, created_at, last_activity_at, absolute_expires_at) VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
                params![s2.session_id, s2.client_id, s2.credential_id, s2.created_at, s2.absolute_expires_at],
            )?;
            Ok(())
        })?;
        active.insert(key, s.clone());
        Ok((s, ended))
    }

    pub fn get(&self, session_id: &str) -> Option<Session> {
        self.active
            .lock()
            .values()
            .find(|s| s.session_id == session_id)
            .cloned()
    }

    pub fn list(&self) -> Vec<Session> {
        let mut v: Vec<Session> = self.active.lock().values().cloned().collect();
        v.sort_by_key(|s| s.created_at);
        v
    }

    pub fn active_client_ids(&self) -> Vec<String> {
        let now = time::now_ms();
        let mut v: Vec<String> = self
            .active
            .lock()
            .values()
            .filter(|s| s.expired(now).is_none())
            .map(|s| s.client_id.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Record authenticated work (not status polling) as activity.
    pub fn touch(&self, session_id: &str) {
        let now = time::now_ms();
        let mut active = self.active.lock();
        if let Some(s) = active.values_mut().find(|s| s.session_id == session_id)
            && s.expired(now).is_none()
        {
            s.last_activity_at = now;
        }
    }

    /// Heartbeat from an owned running task keeps its client's session alive.
    pub fn touch_client(&self, client_id: &str) {
        let now = time::now_ms();
        for s in self
            .active
            .lock()
            .values_mut()
            .filter(|s| s.client_id == client_id)
        {
            if s.expired(now).is_none() {
                s.last_activity_at = now;
            }
        }
    }

    pub fn add_grant(&self, session_id: &str, grant: SessionGrant) -> LpResult<()> {
        let (sid, client) = {
            let mut active = self.active.lock();
            let s = active
                .values_mut()
                .find(|s| s.session_id == session_id)
                .ok_or_else(|| {
                    workstation_core::LpError::new(
                        workstation_core::ErrorCode::SessionExpired,
                        "the session has ended",
                    )
                })?;
            s.grants.push(grant.clone());
            (s.session_id.clone(), s.client_id.clone())
        };
        let scope = serde_json::to_string(&grant.scope).unwrap_or_default();
        self.db.write_sync(move |c| {
            c.execute(
                "INSERT INTO session_permissions (session_id, client_id, scope, label, approval_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![sid, client, scope, grant.label, grant.approval_id, grant.created_at],
            )?;
            Ok(())
        })
    }

    /// Revoke all session grants (used when policy tightens).
    pub fn clear_grants(&self) {
        for s in self.active.lock().values_mut() {
            s.grants.clear();
        }
        let _ = self.db.write_sync(|c| {
            c.execute(
                "UPDATE session_permissions SET revoked_at = ?1 WHERE revoked_at IS NULL",
                [time::now_ms()],
            )?;
            Ok(())
        });
    }

    fn persist_end(&self, session_id: &str, reason: &str) {
        let (sid, r) = (session_id.to_string(), reason.to_string());
        let _ = self.db.write_sync(move |c| {
            let now = time::now_ms();
            c.execute(
                "UPDATE application_sessions SET ended_at = ?2, end_reason = ?3, last_activity_at = last_activity_at WHERE session_id = ?1 AND ended_at IS NULL",
                params![sid, now, r],
            )?;
            c.execute("UPDATE session_permissions SET revoked_at = ?2 WHERE session_id = ?1 AND revoked_at IS NULL", params![sid, now])?;
            Ok(())
        });
    }

    /// End one session by ID.
    pub fn end(&self, session_id: &str, reason: &str) -> Option<EndedSession> {
        let mut active = self.active.lock();
        let key = active
            .iter()
            .find(|(_, s)| s.session_id == session_id)
            .map(|(k, _)| k.clone())?;
        let s = active.remove(&key)?;
        drop(active);
        self.persist_end(&s.session_id, reason);
        Some(EndedSession {
            session: s,
            reason: reason.to_string(),
        })
    }

    pub fn end_where(&self, pred: impl Fn(&Session) -> bool, reason: &str) -> Vec<EndedSession> {
        let mut active = self.active.lock();
        let keys: Vec<_> = active
            .iter()
            .filter(|(_, s)| pred(s))
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::new();
        for k in keys {
            if let Some(s) = active.remove(&k) {
                out.push(s);
            }
        }
        drop(active);
        out.into_iter()
            .map(|s| {
                self.persist_end(&s.session_id, reason);
                EndedSession {
                    session: s,
                    reason: reason.to_string(),
                }
            })
            .collect()
    }

    pub fn end_client(&self, client_id: &str, reason: &str) -> Vec<EndedSession> {
        self.end_where(|s| s.client_id == client_id, reason)
    }

    pub fn end_credential(&self, credential_id: &str, reason: &str) -> Vec<EndedSession> {
        self.end_where(|s| s.credential_id == credential_id, reason)
    }

    pub fn end_all(&self, reason: &str) -> Vec<EndedSession> {
        self.end_where(|_| true, reason)
    }

    /// Periodic expiry sweep.
    pub fn sweep(&self) -> Vec<EndedSession> {
        let now = time::now_ms();
        let expired: Vec<(String, &'static str)> = self
            .active
            .lock()
            .values()
            .filter_map(|s| s.expired(now).map(|r| (s.session_id.clone(), r)))
            .collect();
        expired
            .into_iter()
            .filter_map(|(id, r)| self.end(&id, r))
            .collect()
    }

    /// Settings changed: new limits apply to existing sessions (never revive).
    pub fn apply_limits(&self, settings: &Settings) {
        let idle = settings.sessions.idle_timeout_minutes as i64 * time::MINUTE_MS;
        let abs = settings.sessions.absolute_lifetime_hours as i64 * time::HOUR_MS;
        for s in self.active.lock().values_mut() {
            s.idle_timeout_ms = idle;
            s.absolute_expires_at = s.absolute_expires_at.min(s.created_at + abs);
        }
    }
}

pub type SharedSessions = Arc<SessionService>;

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> (tempfile::TempDir, SessionService) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("c.db"), crate::control_db::MIGRATIONS).unwrap();
        (dir, SessionService::new(db))
    }

    #[test]
    fn one_session_per_grant_and_expiry() {
        let (_d, s) = svc();
        let settings = Settings::default();
        let (a, _) = s.resolve("cl_1", "cred_1", &settings).unwrap();
        let (b, _) = s.resolve("cl_1", "cred_1", &settings).unwrap();
        assert_eq!(a.session_id, b.session_id);
        let (c, _) = s.resolve("cl_1", "cred_2", &settings).unwrap();
        assert_ne!(a.session_id, c.session_id);
        // Force idle expiry.
        {
            let mut active = s.active.lock();
            let sess = active
                .get_mut(&("cl_1".to_string(), "cred_1".to_string()))
                .unwrap();
            sess.last_activity_at -= 31 * time::MINUTE_MS;
        }
        let (d, ended) = s.resolve("cl_1", "cred_1", &settings).unwrap();
        assert_ne!(d.session_id, a.session_id);
        assert_eq!(ended.unwrap().reason, "idle_expiry");
    }

    #[test]
    fn grants_do_not_survive_end() {
        let (_d, s) = svc();
        let settings = Settings::default();
        let (a, _) = s.resolve("cl_1", "cred_1", &settings).unwrap();
        s.add_grant(
            &a.session_id,
            SessionGrant {
                scope: SessionScope::Exact {
                    key: "k".into(),
                    label: "x".into(),
                },
                label: "x".into(),
                approval_id: None,
                created_at: 0,
            },
        )
        .unwrap();
        assert_eq!(s.get(&a.session_id).unwrap().grants.len(), 1);
        s.end(&a.session_id, "explicit");
        let (b, _) = s.resolve("cl_1", "cred_1", &settings).unwrap();
        assert!(b.grants.is_empty());
    }
}
