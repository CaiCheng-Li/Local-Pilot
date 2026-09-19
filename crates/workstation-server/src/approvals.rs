//! Approval engine (plan section 17).
//!
//! Local approval only changes permission state; it never executes anything.
//! The originating client calls `approval_resume` to run the stored operation.
//! The immutable operation snapshot (tool, exact arguments, descriptor digest
//! of resolved targets/identities, required scopes, policy revision) is kept in
//! memory only and discarded on restart. Resume atomically assigns an
//! execution ID; concurrent or repeated resumes observe the same execution and
//! never dispatch again. A crash after dispatch leaves an explicit
//! `outcome_unknown` record instead of replaying the side effect.

use std::collections::HashMap;

use parking_lot::Mutex;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use workstation_core::db::Db;
use workstation_core::{ErrorCode, LpError, LpResult, ids, time};
use workstation_policy::{ApprovalRequirement, SessionScope};

use crate::auth::Principal;
use crate::sessions::Session;

#[derive(Debug, Clone)]
pub struct PendingOperation {
    pub tool_name: String,
    /// Exact arguments of the original call (memory only).
    pub arguments: Value,
    /// Digest of resolved targets/identities/command bound at request time.
    pub descriptor_digest: String,
    pub required_scopes: Vec<String>,
    pub session_scope: SessionScope,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub paths: Vec<String>,
    pub command: Option<String>,
    pub cwd: Option<String>,
    /// Redacted arguments for display.
    pub arguments: Option<Value>,
    pub impact: String,
    pub session_scope_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalView {
    pub approval_id: String,
    pub client_id: String,
    pub client_display_name: Option<String>,
    pub session_id: String,
    pub tool_name: String,
    pub category: String,
    pub summary: ApprovalSummary,
    pub reason: String,
    pub risk: String,
    pub requires_admin: bool,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    pub execution_id: Option<String>,
    pub policy_revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionView {
    pub execution_id: String,
    pub approval_id: Option<String>,
    pub status: String,
    pub result: Option<Value>,
    pub task_id: Option<String>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalDecision {
    AllowOnce,
    AllowSession,
    Deny,
}

pub enum ResumeStart {
    Dispatch {
        op: PendingOperation,
        execution_id: String,
        approval: Box<ApprovalView>,
    },
    Existing(ExecutionView),
}

type ApprovalResumeRow = (String, String, String, i64, Option<String>, i64, String);

pub enum IdemOutcome {
    Proceed,
    Replay(Value),
    InProgress,
    Conflict,
}

pub struct ApprovalService {
    db: Db,
    ops: Mutex<HashMap<String, PendingOperation>>,
}

const COLS: &str = "approval_id, client_id, client_display_name, session_id, tool_name, category, summary, reason, risk, requires_admin, status, created_at, expires_at, decided_at, execution_id, policy_revision";

fn row_to_view(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalView> {
    let summary: String = r.get(6)?;
    Ok(ApprovalView {
        approval_id: r.get(0)?,
        client_id: r.get(1)?,
        client_display_name: r.get(2)?,
        session_id: r.get(3)?,
        tool_name: r.get(4)?,
        category: r.get(5)?,
        summary: serde_json::from_str(&summary).unwrap_or_default(),
        reason: r.get(7)?,
        risk: r.get(8)?,
        requires_admin: r.get(9)?,
        status: r.get(10)?,
        created_at: r.get(11)?,
        expires_at: r.get(12)?,
        decided_at: r.get(13)?,
        execution_id: r.get(14)?,
        policy_revision: r.get(15)?,
    })
}

fn row_to_exec(r: &rusqlite::Row<'_>) -> rusqlite::Result<ExecutionView> {
    let result: Option<String> = r.get(3)?;
    Ok(ExecutionView {
        execution_id: r.get(0)?,
        approval_id: r.get(1)?,
        status: r.get(2)?,
        result: result.and_then(|s| serde_json::from_str(&s).ok()),
        task_id: r.get(4)?,
        created_at: r.get(5)?,
        completed_at: r.get(6)?,
    })
}

impl ApprovalService {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            ops: Mutex::new(HashMap::new()),
        }
    }

    /// Startup recovery: approvals never survive a restart; executions that
    /// were dispatched without a recorded outcome become `outcome_unknown`.
    pub fn startup_recovery(&self) -> LpResult<(usize, usize)> {
        self.db.write_sync(|c| {
            let a = c.execute(
                "UPDATE approvals SET status = 'invalidated', decision_note = 'Local Pilot restarted' WHERE status IN ('pending', 'allowed_once', 'allowed_session')",
                [],
            )?;
            let e = c.execute(
                "UPDATE operation_executions SET status = 'outcome_unknown', completed_at = ?1 WHERE status = 'dispatched'",
                [time::now_ms()],
            )?;
            c.execute("UPDATE idempotency_keys SET status = 'outcome_unknown' WHERE status = 'in_progress'", [])?;
            Ok((a, e))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        principal: &Principal,
        session: &Session,
        tool_name: &str,
        req: &ApprovalRequirement,
        summary: ApprovalSummary,
        op: PendingOperation,
        policy_revision: u64,
        lifetime_minutes: u64,
    ) -> LpResult<ApprovalView> {
        let id = ids::approval_id();
        let now = time::now_ms();
        let expires = now + lifetime_minutes as i64 * time::MINUTE_MS;
        let digest = workstation_core::hashing::json_digest(&serde_json::json!({
            "tool": op.tool_name,
            "arguments": op.arguments,
            "descriptor": op.descriptor_digest,
            "policy_revision": policy_revision,
            "client": principal.client_id,
            "session": session.session_id,
        }));
        let summary_json = serde_json::to_string(&summary).map_err(LpError::internal)?;
        let risk = serde_json::to_value(req.risk)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let (id2, p, s, t, r) = (
            id.clone(),
            principal.clone(),
            session.session_id.clone(),
            tool_name.to_string(),
            req.clone(),
        );
        let scopes = op.required_scopes.join(" ");
        let scope_json = serde_json::to_string(&op.session_scope).unwrap_or_default();
        self.db.write_sync(move |c| {
            c.execute(
                "INSERT INTO approvals (approval_id, client_id, client_display_name, session_id, credential_id, tool_name, category, summary, reason, risk, requires_admin, status, created_at, expires_at, policy_revision, operation_digest, required_scopes, session_scope)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    id2, p.client_id, p.display_name, s, p.credential_id, t, r.category, summary_json, r.reason, risk,
                    r.requires_admin, now, expires, policy_revision as i64, digest, scopes, scope_json
                ],
            )?;
            Ok(())
        })?;
        self.ops.lock().insert(id.clone(), op);
        self.get(&id)
            .ok_or_else(|| LpError::internal("approval vanished"))
    }

    pub fn get(&self, id: &str) -> Option<ApprovalView> {
        let id = id.to_string();
        self.db
            .read_sync(|c| {
                Ok(c.query_row(
                    &format!("SELECT {COLS} FROM approvals WHERE approval_id = ?1"),
                    [&id],
                    row_to_view,
                )
                .optional()?)
            })
            .ok()
            .flatten()
    }

    pub fn list(
        &self,
        status: Option<&str>,
        client_id: Option<&str>,
        limit: usize,
    ) -> Vec<ApprovalView> {
        let (st, cid) = (
            status.map(|s| s.to_string()),
            client_id.map(|s| s.to_string()),
        );
        let limit = limit.clamp(1, 1000) as i64;
        self.db
            .read_sync(move |c| {
                let mut sql = format!("SELECT {COLS} FROM approvals WHERE 1=1");
                let mut args: Vec<rusqlite::types::Value> = Vec::new();
                if let Some(s) = st {
                    sql.push_str(" AND status = ?");
                    args.push(s.into());
                }
                if let Some(c2) = cid {
                    sql.push_str(" AND client_id = ?");
                    args.push(c2.into());
                }
                sql.push_str(" ORDER BY created_at DESC LIMIT ?");
                args.push(limit.into());
                let mut stmt = c.prepare(&sql)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(args), row_to_view)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .unwrap_or_default()
    }

    pub fn session_scope(&self, id: &str) -> Option<SessionScope> {
        if let Some(op) = self.ops.lock().get(id) {
            return Some(op.session_scope.clone());
        }
        let id = id.to_string();
        self.db
            .read_sync(|c| {
                Ok(c.query_row(
                    "SELECT session_scope FROM approvals WHERE approval_id = ?1",
                    [&id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?)
            })
            .ok()
            .flatten()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    /// Local UI decision. Only pending, unexpired approvals can be decided;
    /// an allow opens a fresh resume window of the configured lifetime.
    pub fn decide(
        &self,
        id: &str,
        decision: LocalDecision,
        lifetime_minutes: u64,
    ) -> LpResult<ApprovalView> {
        let (id2, now) = (id.to_string(), time::now_ms());
        let status = match decision {
            LocalDecision::AllowOnce => "allowed_once",
            LocalDecision::AllowSession => "allowed_session",
            LocalDecision::Deny => "denied",
        };
        let new_expiry = now + lifetime_minutes as i64 * time::MINUTE_MS;
        self.db.write_sync(move |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<(String, i64)> = tx
                .query_row("SELECT status, expires_at FROM approvals WHERE approval_id = ?1", [&id2], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let (cur, expires) = row.ok_or_else(|| LpError::not_found("unknown approval"))?;
            if cur != "pending" {
                return Err(LpError::invalid(format!("approval is already {cur}")));
            }
            if expires < now {
                tx.execute("UPDATE approvals SET status = 'expired' WHERE approval_id = ?1", [&id2])?;
                tx.commit()?;
                return Err(LpError::new(ErrorCode::ApprovalExpired, "the approval request expired"));
            }
            tx.execute(
                "UPDATE approvals SET status = ?2, decided_at = ?3, expires_at = CASE WHEN ?2 = 'denied' THEN expires_at ELSE ?4 END WHERE approval_id = ?1",
                params![id2, status, now, new_expiry],
            )?;
            tx.commit()?;
            Ok(())
        })?;
        if decision == LocalDecision::Deny {
            self.ops.lock().remove(id);
        }
        self.get(id)
            .ok_or_else(|| LpError::internal("approval vanished"))
    }

    /// Begin resuming an approved operation (see module docs).
    pub fn begin_resume(
        &self,
        id: &str,
        principal: &Principal,
        session: &Session,
        policy_revision: u64,
    ) -> LpResult<ResumeStart> {
        let now = time::now_ms();
        let op = self.ops.lock().get(id).cloned();
        let op_present = op.is_some();
        let (id2, client, sid) = (
            id.to_string(),
            principal.client_id.clone(),
            session.session_id.clone(),
        );
        let scopes = principal.scopes.clone();
        let outcome = self.db.write_sync(move |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<ApprovalResumeRow> = tx
                .query_row(
                    "SELECT client_id, session_id, status, expires_at, execution_id, policy_revision, required_scopes FROM approvals WHERE approval_id = ?1",
                    [&id2],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
                )
                .optional()?;
            let Some((owner, session_id, status, expires, execution_id, revision, required)) = row else {
                return Err(LpError::not_found("unknown approval"));
            };
            // Opaque IDs are not authorization: only the owner may resume.
            if owner != client {
                return Err(LpError::not_found("unknown approval"));
            }
            if let Some(exec) = execution_id {
                let e = tx
                    .query_row(
                        "SELECT execution_id, approval_id, status, result, task_id, created_at, completed_at FROM operation_executions WHERE execution_id = ?1",
                        [&exec],
                        row_to_exec,
                    )
                    .optional()?;
                tx.commit()?;
                return e.map(Err).ok_or_else(|| LpError::internal("execution record missing"));
            }
            match status.as_str() {
                "pending" => return Err(LpError::new(ErrorCode::ApprovalPending, "the request is still waiting for local approval")),
                "denied" => return Err(LpError::new(ErrorCode::ApprovalDenied, "the workstation owner denied this request")),
                "expired" => return Err(LpError::new(ErrorCode::ApprovalExpired, "the approval expired")),
                "allowed_once" | "allowed_session" => {}
                _ => return Err(LpError::new(ErrorCode::ApprovalInvalidated, "the approval is no longer valid")),
            }
            let invalidate = |tx: &rusqlite::Transaction<'_>, why: &str| -> rusqlite::Result<()> {
                tx.execute("UPDATE approvals SET status = 'invalidated', decision_note = ?2 WHERE approval_id = ?1", params![id2, why])?;
                Ok(())
            };
            if expires < now {
                tx.execute("UPDATE approvals SET status = 'expired' WHERE approval_id = ?1", [&id2])?;
                tx.commit()?;
                return Err(LpError::new(ErrorCode::ApprovalExpired, "the approval expired before it was resumed"));
            }
            if session_id != sid {
                invalidate(&tx, "session ended")?;
                tx.commit()?;
                return Err(LpError::new(ErrorCode::ApprovalInvalidated, "the approval belonged to an application session that has ended"));
            }
            if revision as u64 != policy_revision {
                invalidate(&tx, "policy changed")?;
                tx.commit()?;
                return Err(LpError::new(ErrorCode::ApprovalInvalidated, "local policy changed after approval; request the operation again"));
            }
            if required.split_whitespace().any(|s| !scopes.iter().any(|x| x == s)) {
                return Err(LpError::new(ErrorCode::InsufficientScope, "the current credential lacks the scopes of the original operation"));
            }
            if !op_present {
                invalidate(&tx, "operation snapshot unavailable")?;
                tx.commit()?;
                return Err(LpError::new(ErrorCode::ApprovalInvalidated, "the stored operation is no longer available"));
            }
            let exec = ids::execution_id();
            let consumed = if status == "allowed_once" { "consumed" } else { "allowed_session" };
            tx.execute(
                "UPDATE approvals SET execution_id = ?2, status = ?3 WHERE approval_id = ?1",
                params![id2, exec, consumed],
            )?;
            tx.execute(
                "INSERT INTO operation_executions (execution_id, approval_id, client_id, tool_name, status, created_at) VALUES (?1, ?2, ?3, (SELECT tool_name FROM approvals WHERE approval_id = ?2), 'dispatched', ?4)",
                params![exec, id2, client, now],
            )?;
            tx.commit()?;
            Ok(Ok(exec))
        });
        match outcome {
            Err(e) => Err(e),
            Ok(Err(existing)) => Ok(ResumeStart::Existing(existing)),
            Ok(Ok(execution_id)) => {
                let op = op.expect("checked above");
                if self
                    .get(id)
                    .map(|a| a.status == "consumed")
                    .unwrap_or(false)
                {
                    self.ops.lock().remove(id);
                }
                let approval = self
                    .get(id)
                    .ok_or_else(|| LpError::internal("approval vanished"))?;
                Ok(ResumeStart::Dispatch {
                    op,
                    execution_id,
                    approval: Box::new(approval),
                })
            }
        }
    }

    pub fn complete_execution(
        &self,
        execution_id: &str,
        status: &str,
        result: Option<&Value>,
        task_id: Option<&str>,
    ) {
        let (id, st, res, tid) = (
            execution_id.to_string(),
            status.to_string(),
            result.map(|v| v.to_string()),
            task_id.map(|s| s.to_string()),
        );
        let _ = self.db.write_sync(move |c| {
            c.execute(
                "UPDATE operation_executions SET status = ?2, result = ?3, task_id = COALESCE(?4, task_id), completed_at = ?5 WHERE execution_id = ?1",
                params![id, st, res, tid, time::now_ms()],
            )?;
            Ok(())
        });
    }

    pub fn execution(&self, execution_id: &str) -> Option<ExecutionView> {
        let id = execution_id.to_string();
        self.db
            .read_sync(|c| {
                Ok(c.query_row(
                    "SELECT execution_id, approval_id, status, result, task_id, created_at, completed_at FROM operation_executions WHERE execution_id = ?1",
                    [&id],
                    row_to_exec,
                )
                .optional()?)
            })
            .ok()
            .flatten()
    }

    pub fn list_unknown_outcomes(&self) -> Vec<ExecutionView> {
        self.db
            .read_sync(|c| {
                let mut stmt = c.prepare(
                    "SELECT execution_id, approval_id, status, result, task_id, created_at, completed_at FROM operation_executions WHERE status = 'outcome_unknown' ORDER BY created_at DESC LIMIT 200",
                )?;
                Ok(stmt.query_map([], row_to_exec)?.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap_or_default()
    }

    /// Mark an unknown outcome as reconciled by the owner.
    pub fn reconcile(&self, execution_id: &str, note: &str) -> LpResult<()> {
        let (id, n) = (execution_id.to_string(), note.to_string());
        self.db.write_sync(move |c| {
            c.execute(
                "UPDATE operation_executions SET status = 'reconciled', result = COALESCE(result, json_object('note', ?2)) WHERE execution_id = ?1 AND status = 'outcome_unknown'",
                params![id, n],
            )?;
            Ok(())
        })
    }

    /// Cancel/invalidate open approvals matching a predicate on (client, session).
    pub fn invalidate(
        &self,
        client_id: Option<&str>,
        session_id: Option<&str>,
        status: &str,
        note: &str,
    ) -> Vec<String> {
        let (cid, sid, st, n) = (
            client_id.map(|s| s.to_string()),
            session_id.map(|s| s.to_string()),
            status.to_string(),
            note.to_string(),
        );
        let ids: Vec<String> = self
            .db
            .write_sync(move |c| {
                let mut sql = String::from("SELECT approval_id FROM approvals WHERE status IN ('pending', 'allowed_once', 'allowed_session')");
                let mut args: Vec<rusqlite::types::Value> = Vec::new();
                if let Some(x) = &cid {
                    sql.push_str(" AND client_id = ?");
                    args.push(x.clone().into());
                }
                if let Some(x) = &sid {
                    sql.push_str(" AND session_id = ?");
                    args.push(x.clone().into());
                }
                let ids: Vec<String> = {
                    let mut stmt = c.prepare(&sql)?;
                    stmt.query_map(rusqlite::params_from_iter(args), |r| r.get(0))?.collect::<Result<_, _>>()?
                };
                for id in &ids {
                    c.execute(
                        "UPDATE approvals SET status = ?2, decision_note = ?3 WHERE approval_id = ?1",
                        params![id, st, n],
                    )?;
                }
                Ok(ids)
            })
            .unwrap_or_default();
        let mut ops = self.ops.lock();
        for id in &ids {
            ops.remove(id);
        }
        ids
    }

    /// Expire pending/allowed approvals past their lifetime.
    pub fn expire_sweep(&self) -> Vec<String> {
        let now = time::now_ms();
        let ids: Vec<String> = self
            .db
            .write_sync(move |c| {
                let ids: Vec<String> = {
                    let mut stmt = c.prepare("SELECT approval_id FROM approvals WHERE status IN ('pending', 'allowed_once') AND expires_at < ?1")?;
                    stmt.query_map([now], |r| r.get(0))?.collect::<Result<_, _>>()?
                };
                for id in &ids {
                    c.execute("UPDATE approvals SET status = 'expired' WHERE approval_id = ?1", [id])?;
                }
                Ok(ids)
            })
            .unwrap_or_default();
        let mut ops = self.ops.lock();
        for id in &ids {
            ops.remove(id);
        }
        ids
    }

    // ---------------------------------------------------------- idempotency

    pub fn idem_begin(
        &self,
        client_id: &str,
        key: &str,
        tool: &str,
        digest: &str,
    ) -> LpResult<IdemOutcome> {
        if key.is_empty() || key.len() > 200 {
            return Err(LpError::invalid("idempotency_key must be 1-200 characters"));
        }
        let (c1, k, t, d) = (
            client_id.to_string(),
            key.to_string(),
            tool.to_string(),
            digest.to_string(),
        );
        self.db.write_sync(move |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("DELETE FROM idempotency_keys WHERE created_at < ?1", [time::now_ms() - time::DAY_MS])?;
            let row: Option<(String, String, String, Option<String>)> = tx
                .query_row(
                    "SELECT tool_name, args_digest, status, result FROM idempotency_keys WHERE client_id = ?1 AND idem_key = ?2",
                    params![c1, k],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let out = match row {
                Some((tool, dg, status, result)) => {
                    if tool != t || dg != d {
                        IdemOutcome::Conflict
                    } else if status == "done" {
                        IdemOutcome::Replay(result.and_then(|r| serde_json::from_str(&r).ok()).unwrap_or(Value::Null))
                    } else {
                        IdemOutcome::InProgress
                    }
                }
                None => {
                    tx.execute(
                        "INSERT INTO idempotency_keys (client_id, idem_key, tool_name, args_digest, status, created_at) VALUES (?1, ?2, ?3, ?4, 'in_progress', ?5)",
                        params![c1, k, t, d, time::now_ms()],
                    )?;
                    IdemOutcome::Proceed
                }
            };
            tx.commit()?;
            Ok(out)
        })
    }

    pub fn idem_finish(&self, client_id: &str, key: &str, result: &Value) {
        let (c1, k, r) = (client_id.to_string(), key.to_string(), result.to_string());
        let _ = self.db.write_sync(move |c| {
            c.execute(
                "UPDATE idempotency_keys SET status = 'done', result = ?3 WHERE client_id = ?1 AND idem_key = ?2",
                params![c1, k, r],
            )?;
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMethod;
    use workstation_policy::Risk;

    fn setup() -> (tempfile::TempDir, ApprovalService, Principal, Session) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("c.db"), crate::control_db::MIGRATIONS).unwrap();
        let p = Principal {
            client_id: "cl_1".into(),
            display_name: "A".into(),
            credential_id: "cred_1".into(),
            auth_method: AuthMethod::ManualToken,
            scopes: vec!["workstation:write".into()],
            oauth_client_id: None,
        };
        let s = Session {
            session_id: "ses_1".into(),
            client_id: "cl_1".into(),
            credential_id: "cred_1".into(),
            created_at: 0,
            last_activity_at: time::now_ms(),
            absolute_expires_at: i64::MAX,
            idle_timeout_ms: i64::MAX / 4,
            grants: vec![],
        };
        (dir, ApprovalService::new(db), p, s)
    }

    fn req() -> ApprovalRequirement {
        ApprovalRequirement {
            category: "external_write".into(),
            reason: "r".into(),
            impact: "i".into(),
            risk: Risk::Medium,
            requires_admin: false,
            paths: vec![r"C:\x".into()],
            command: None,
            session_scope: SessionScope::PathPrefix {
                operation: "write".into(),
                prefix: r"C:\".into(),
            },
        }
    }

    fn op() -> PendingOperation {
        PendingOperation {
            tool_name: "fs_write_text".into(),
            arguments: serde_json::json!({"path": "C:\\x"}),
            descriptor_digest: "d".into(),
            required_scopes: vec!["workstation:write".into()],
            session_scope: SessionScope::PathPrefix {
                operation: "write".into(),
                prefix: r"C:\".into(),
            },
        }
    }

    #[test]
    fn allow_once_resume_is_idempotent() {
        let (_d, svc, p, s) = setup();
        let a = svc
            .create(
                &p,
                &s,
                "fs_write_text",
                &req(),
                ApprovalSummary::default(),
                op(),
                1,
                10,
            )
            .unwrap();
        assert!(
            matches!(svc.begin_resume(&a.approval_id, &p, &s, 1), Err(e) if e.code == ErrorCode::ApprovalPending)
        );
        svc.decide(&a.approval_id, LocalDecision::AllowOnce, 10)
            .unwrap();
        let first = svc.begin_resume(&a.approval_id, &p, &s, 1).unwrap();
        let exec = match first {
            ResumeStart::Dispatch { execution_id, .. } => execution_id,
            _ => panic!("expected dispatch"),
        };
        // A second resume never dispatches again.
        match svc.begin_resume(&a.approval_id, &p, &s, 1).unwrap() {
            ResumeStart::Existing(e) => assert_eq!(e.execution_id, exec),
            _ => panic!("expected existing"),
        }
        svc.complete_execution(
            &exec,
            "completed",
            Some(&serde_json::json!({"ok": true})),
            None,
        );
        match svc.begin_resume(&a.approval_id, &p, &s, 1).unwrap() {
            ResumeStart::Existing(e) => assert_eq!(e.result.unwrap()["ok"], true),
            _ => panic!(),
        }
    }

    #[test]
    fn resume_rules() {
        let (_d, svc, p, s) = setup();
        let a = svc
            .create(
                &p,
                &s,
                "fs_write_text",
                &req(),
                ApprovalSummary::default(),
                op(),
                1,
                10,
            )
            .unwrap();
        svc.decide(&a.approval_id, LocalDecision::AllowOnce, 10)
            .unwrap();
        // Another client cannot see or resume it.
        let mut other = p.clone();
        other.client_id = "cl_2".into();
        assert!(
            matches!(svc.begin_resume(&a.approval_id, &other, &s, 1), Err(e) if e.code == ErrorCode::NotFound)
        );
        // Policy revision change invalidates.
        assert!(
            matches!(svc.begin_resume(&a.approval_id, &p, &s, 2), Err(e) if e.code == ErrorCode::ApprovalInvalidated)
        );

        let b = svc
            .create(
                &p,
                &s,
                "fs_write_text",
                &req(),
                ApprovalSummary::default(),
                op(),
                1,
                10,
            )
            .unwrap();
        svc.decide(&b.approval_id, LocalDecision::Deny, 10).unwrap();
        assert!(
            matches!(svc.begin_resume(&b.approval_id, &p, &s, 1), Err(e) if e.code == ErrorCode::ApprovalDenied)
        );
        assert!(
            svc.decide(&b.approval_id, LocalDecision::AllowOnce, 10)
                .is_err()
        );

        let c = svc
            .create(
                &p,
                &s,
                "fs_write_text",
                &req(),
                ApprovalSummary::default(),
                op(),
                1,
                10,
            )
            .unwrap();
        svc.decide(&c.approval_id, LocalDecision::AllowOnce, 10)
            .unwrap();
        let mut s2 = s.clone();
        s2.session_id = "ses_2".into();
        assert!(
            matches!(svc.begin_resume(&c.approval_id, &p, &s2, 1), Err(e) if e.code == ErrorCode::ApprovalInvalidated)
        );
    }

    #[test]
    fn restart_invalidates_and_marks_unknown() {
        let (_d, svc, p, s) = setup();
        let a = svc
            .create(
                &p,
                &s,
                "fs_write_text",
                &req(),
                ApprovalSummary::default(),
                op(),
                1,
                10,
            )
            .unwrap();
        svc.decide(&a.approval_id, LocalDecision::AllowOnce, 10)
            .unwrap();
        let ResumeStart::Dispatch { execution_id, .. } =
            svc.begin_resume(&a.approval_id, &p, &s, 1).unwrap()
        else {
            panic!()
        };
        let b = svc
            .create(
                &p,
                &s,
                "fs_write_text",
                &req(),
                ApprovalSummary::default(),
                op(),
                1,
                10,
            )
            .unwrap();
        let (inv, unknown) = svc.startup_recovery().unwrap();
        assert_eq!(inv, 1);
        assert_eq!(unknown, 1);
        assert_eq!(svc.get(&b.approval_id).unwrap().status, "invalidated");
        assert_eq!(
            svc.execution(&execution_id).unwrap().status,
            "outcome_unknown"
        );
    }

    #[test]
    fn idempotency_keys() {
        let (_d, svc, _, _) = setup();
        assert!(matches!(
            svc.idem_begin("cl_1", "k1", "fs_write_text", "d1").unwrap(),
            IdemOutcome::Proceed
        ));
        assert!(matches!(
            svc.idem_begin("cl_1", "k1", "fs_write_text", "d1").unwrap(),
            IdemOutcome::InProgress
        ));
        assert!(matches!(
            svc.idem_begin("cl_1", "k1", "fs_write_text", "d2").unwrap(),
            IdemOutcome::Conflict
        ));
        svc.idem_finish("cl_1", "k1", &serde_json::json!({"done": 1}));
        assert!(matches!(
            svc.idem_begin("cl_1", "k1", "fs_write_text", "d1").unwrap(),
            IdemOutcome::Replay(_)
        ));
        assert!(matches!(
            svc.idem_begin("cl_2", "k1", "fs_write_text", "d2").unwrap(),
            IdemOutcome::Proceed
        ));
    }
}
