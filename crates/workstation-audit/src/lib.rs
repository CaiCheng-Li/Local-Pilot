//! Audit history and the Data Shared log (plan sections 32-33).
//!
//! - Mutations persist a minimal *intent* record synchronously before
//!   dispatch. If that write fails the caller must refuse the operation with
//!   `AUDIT_UNAVAILABLE`; the store enters a visible fault state.
//! - Other records go through a bounded queue drained by a writer task, which
//!   applies backpressure instead of growing without bound.
//! - Data Shared records hold the exact post-redaction bytes (and their
//!   SHA-256) that are emitted to a client, written durably before emission.
//! - Retention is finite; removed ranges are recorded as explicit boundaries.
//!
//! Neither log is tamper-proof against other processes running as the same
//! Windows user.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use workstation_core::db::{Db, Migration};
use workstation_core::{LpError, LpResult, ids, time};

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "audit_init",
    sql: r#"
CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    timestamp_start INTEGER NOT NULL,
    timestamp_end INTEGER,
    client_id TEXT,
    client_display_name TEXT,
    session_id TEXT,
    mcp_protocol_version TEXT,
    tool_name TEXT,
    operation_category TEXT,
    project_id TEXT,
    cwd TEXT,
    command TEXT,
    arguments TEXT,
    paths TEXT,
    entry_point TEXT,
    shell_checks INTEGER,
    policy_decision TEXT,
    policy_detail TEXT,
    approval_id TEXT,
    approval_result TEXT,
    task_id TEXT,
    pid INTEGER,
    exit_code INTEGER,
    stdout_bytes INTEGER,
    stderr_bytes INTEGER,
    result_status TEXT NOT NULL,
    duration_ms INTEGER,
    error TEXT
);
CREATE INDEX idx_audit_ts ON audit_events(timestamp_start);
CREATE INDEX idx_audit_client ON audit_events(client_id, timestamp_start);
CREATE INDEX idx_audit_project ON audit_events(project_id, timestamp_start);
CREATE INDEX idx_audit_task ON audit_events(task_id);
CREATE INDEX idx_audit_status ON audit_events(result_status);

CREATE TABLE data_shared (
    share_event_id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    client_id TEXT,
    session_id TEXT,
    tool_name TEXT,
    request_id TEXT,
    audit_event_id TEXT,
    source_path TEXT,
    mime_type TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    payload BLOB NOT NULL,
    redaction TEXT,
    transmission TEXT NOT NULL
);
CREATE INDEX idx_ds_ts ON data_shared(timestamp);
CREATE INDEX idx_ds_client ON data_shared(client_id, timestamp);
CREATE INDEX idx_ds_session ON data_shared(session_id, timestamp);

CREATE TABLE retention_boundaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    removed_before INTEGER NOT NULL,
    removed_count INTEGER NOT NULL,
    reason TEXT NOT NULL,
    session_id TEXT
);
CREATE INDEX idx_rb_log ON retention_boundaries(log, timestamp);
"#,
}];

/// Fields known when an audited action starts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditEvent {
    pub kind: String,
    pub client_id: Option<String>,
    pub client_display_name: Option<String>,
    pub session_id: Option<String>,
    pub mcp_protocol_version: Option<String>,
    pub tool_name: Option<String>,
    pub operation_category: Option<String>,
    pub project_id: Option<String>,
    pub cwd: Option<String>,
    pub command: Option<String>,
    /// Already-redacted JSON arguments.
    pub arguments: Option<serde_json::Value>,
    pub paths: Vec<String>,
    pub entry_point: Option<String>,
    pub shell_checks: Option<bool>,
    pub policy_decision: Option<String>,
    pub policy_detail: Option<String>,
    pub approval_id: Option<String>,
    pub approval_result: Option<String>,
    pub task_id: Option<String>,
    pub result_status: String,
    pub error: Option<String>,
}

/// Fields known when an audited action ends.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditCompletion {
    pub result_status: String,
    pub policy_decision: Option<String>,
    pub policy_detail: Option<String>,
    pub approval_id: Option<String>,
    pub approval_result: Option<String>,
    pub task_id: Option<String>,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub stdout_bytes: Option<u64>,
    pub stderr_bytes: Option<u64>,
    pub error: Option<String>,
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRow {
    pub event_id: String,
    pub kind: String,
    pub timestamp_start: i64,
    pub timestamp_end: Option<i64>,
    pub client_id: Option<String>,
    pub client_display_name: Option<String>,
    pub session_id: Option<String>,
    pub mcp_protocol_version: Option<String>,
    pub tool_name: Option<String>,
    pub operation_category: Option<String>,
    pub project_id: Option<String>,
    pub cwd: Option<String>,
    pub command: Option<String>,
    pub arguments: Option<String>,
    pub paths: Option<String>,
    pub entry_point: Option<String>,
    pub shell_checks: Option<bool>,
    pub policy_decision: Option<String>,
    pub policy_detail: Option<String>,
    pub approval_id: Option<String>,
    pub approval_result: Option<String>,
    pub task_id: Option<String>,
    pub pid: Option<i64>,
    pub exit_code: Option<i64>,
    pub stdout_bytes: Option<i64>,
    pub stderr_bytes: Option<i64>,
    pub result_status: String,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub client_id: Option<String>,
    pub tool_name: Option<String>,
    pub project_id: Option<String>,
    pub result_status: Option<String>,
    pub kind: Option<String>,
    pub text: Option<String>,
    pub limit: Option<u32>,
    pub before_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    pub client_id: Option<String>,
    pub session_id: Option<String>,
    pub tool_name: Option<String>,
    pub request_id: Option<String>,
    pub audit_event_id: Option<String>,
    pub source_path: Option<String>,
    pub mime_type: String,
    /// Exact post-redaction bytes that will be emitted.
    pub payload: Vec<u8>,
    pub redaction: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRow {
    pub share_event_id: String,
    pub timestamp: i64,
    pub client_id: Option<String>,
    pub session_id: Option<String>,
    pub tool_name: Option<String>,
    pub request_id: Option<String>,
    pub audit_event_id: Option<String>,
    pub source_path: Option<String>,
    pub mime_type: String,
    pub byte_count: i64,
    pub sha256: String,
    pub redaction: Option<String>,
    pub transmission: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShareFilter {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub client_id: Option<String>,
    pub session_id: Option<String>,
    pub tool_name: Option<String>,
    pub limit: Option<u32>,
    pub before_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionBoundary {
    pub log: String,
    pub timestamp: i64,
    pub removed_before: i64,
    pub removed_count: i64,
    pub reason: String,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionSummary {
    pub audit_oldest_ms: Option<i64>,
    pub audit_newest_ms: Option<i64>,
    pub audit_events: i64,
    pub audit_bytes: u64,
    pub shared_oldest_ms: Option<i64>,
    pub shared_newest_ms: Option<i64>,
    pub shared_events: i64,
    pub shared_bytes: i64,
    pub boundaries: Vec<RetentionBoundary>,
    /// Sessions whose older Data Shared records were rotated while active.
    pub truncated_sessions: Vec<String>,
    pub fault: Option<String>,
    pub admission_blocked: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    pub audit_retention_days: u64,
    pub audit_max_bytes: u64,
    pub shared_retention_days: u64,
    pub shared_max_bytes: u64,
    pub reserved_events_per_session: u64,
}

enum QueueOp {
    Insert(String, i64, Box<AuditEvent>),
    Complete(String, i64, Box<AuditCompletion>),
    Transmission(Vec<String>, String),
}

struct Inner {
    db: Db,
    fault: RwLock<Option<String>>,
    admission_blocked: AtomicBool,
    queue: mpsc::Sender<QueueOp>,
}

#[derive(Clone)]
pub struct AuditStore {
    inner: Arc<Inner>,
}

fn opt_json(v: &Option<serde_json::Value>) -> Option<String> {
    v.as_ref().map(|x| x.to_string())
}

fn insert_event(
    conn: &rusqlite::Connection,
    id: &str,
    ts: i64,
    e: &AuditEvent,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO audit_events (event_id, kind, timestamp_start, client_id, client_display_name, session_id,
            mcp_protocol_version, tool_name, operation_category, project_id, cwd, command, arguments, paths,
            entry_point, shell_checks, policy_decision, policy_detail, approval_id, approval_result, task_id,
            result_status, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        params![
            id,
            e.kind,
            ts,
            e.client_id,
            e.client_display_name,
            e.session_id,
            e.mcp_protocol_version,
            e.tool_name,
            e.operation_category,
            e.project_id,
            e.cwd,
            e.command,
            opt_json(&e.arguments),
            serde_json::to_string(&e.paths).ok(),
            e.entry_point,
            e.shell_checks,
            e.policy_decision,
            e.policy_detail,
            e.approval_id,
            e.approval_result,
            e.task_id,
            e.result_status,
            e.error,
        ],
    )
}

fn complete_event(
    conn: &rusqlite::Connection,
    id: &str,
    ts: i64,
    c: &AuditCompletion,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE audit_events SET timestamp_end = ?2, result_status = ?3,
            policy_decision = COALESCE(?4, policy_decision), policy_detail = COALESCE(?5, policy_detail),
            approval_id = COALESCE(?6, approval_id), approval_result = COALESCE(?7, approval_result),
            task_id = COALESCE(?8, task_id), pid = COALESCE(?9, pid), exit_code = COALESCE(?10, exit_code),
            stdout_bytes = COALESCE(?11, stdout_bytes), stderr_bytes = COALESCE(?12, stderr_bytes),
            error = COALESCE(?13, error), paths = COALESCE(?14, paths),
            duration_ms = ?2 - timestamp_start
         WHERE event_id = ?1",
        params![
            id,
            ts,
            c.result_status,
            c.policy_decision,
            c.policy_detail,
            c.approval_id,
            c.approval_result,
            c.task_id,
            c.pid,
            c.exit_code,
            c.stdout_bytes.map(|v| v as i64),
            c.stderr_bytes.map(|v| v as i64),
            c.error,
            c.paths.as_ref().and_then(|p| serde_json::to_string(p).ok()),
        ],
    )
}

impl AuditStore {
    pub fn open(path: &Path) -> LpResult<Self> {
        let db = Db::open(path, MIGRATIONS)?;
        db.write_sync(|c| {
            c.pragma_update(None, "synchronous", "FULL")?;
            Ok(())
        })?;
        let (tx, mut rx) = mpsc::channel::<QueueOp>(2048);
        let inner = Arc::new(Inner {
            db,
            fault: RwLock::new(None),
            admission_blocked: AtomicBool::new(false),
            queue: tx,
        });
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                let mut batch = vec![first];
                while batch.len() < 256 {
                    match rx.try_recv() {
                        Ok(op) => batch.push(op),
                        Err(_) => break,
                    }
                }
                let Some(inner) = weak.upgrade() else { break };
                let res = inner
                    .db
                    .write(move |conn| {
                        let tx = conn.transaction()?;
                        for op in &batch {
                            match op {
                                QueueOp::Insert(id, ts, e) => {
                                    insert_event(&tx, id, *ts, e)?;
                                }
                                QueueOp::Complete(id, ts, c) => {
                                    complete_event(&tx, id, *ts, c)?;
                                }
                                QueueOp::Transmission(ids, status) => {
                                    for id in ids {
                                        tx.execute(
                                            "UPDATE data_shared SET transmission = ?2 WHERE share_event_id = ?1",
                                            params![id, status],
                                        )?;
                                    }
                                }
                            }
                        }
                        tx.commit()?;
                        Ok(())
                    })
                    .await;
                if let Err(e) = res {
                    tracing::error!(error = %e, "audit queue write failed");
                    *inner.fault.write() =
                        Some("Audit storage write failed; see the diagnostic log.".into());
                }
            }
        });
        Ok(Self { inner })
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    pub fn fault(&self) -> Option<String> {
        self.inner.fault.read().clone()
    }

    pub fn clear_fault(&self) {
        *self.inner.fault.write() = None;
    }

    fn set_fault(&self, msg: &str) {
        tracing::error!(msg, "audit fault");
        *self.inner.fault.write() = Some(msg.to_string());
    }

    /// Durably record the intent of a mutation/launch before dispatch.
    /// Returns `AUDIT_UNAVAILABLE` if it cannot be persisted.
    pub async fn intent(&self, mut event: AuditEvent) -> LpResult<String> {
        if self.fault().is_some() {
            return Err(LpError::audit_unavailable());
        }
        let id = ids::event_id();
        event.result_status = "intent".into();
        let (id2, ts) = (id.clone(), time::now_ms());
        match self
            .inner
            .db
            .write(move |c| {
                insert_event(c, &id2, ts, &event)?;
                Ok(())
            })
            .await
        {
            Ok(()) => Ok(id),
            Err(e) => {
                self.set_fault(&format!(
                    "Audit intent could not be persisted: {}",
                    e.message
                ));
                Err(LpError::audit_unavailable().with_internal(e))
            }
        }
    }

    /// Queue completion of an event (bounded queue; awaits under backpressure).
    pub async fn complete(&self, event_id: &str, completion: AuditCompletion) {
        let op = QueueOp::Complete(event_id.to_string(), time::now_ms(), Box::new(completion));
        if self.inner.queue.send(op).await.is_err() {
            self.set_fault("Audit queue is closed");
        }
    }

    /// Queue a standalone event (reads, decisions, lifecycle).
    pub async fn record(&self, event: AuditEvent) -> String {
        let id = ids::event_id();
        let op = QueueOp::Insert(id.clone(), time::now_ms(), Box::new(event));
        if self.inner.queue.send(op).await.is_err() {
            self.set_fault("Audit queue is closed");
        }
        id
    }

    /// Record a standalone event synchronously (used for security-critical
    /// local actions such as settings changes and Emergency Stop).
    pub fn record_sync(&self, event: AuditEvent) -> LpResult<String> {
        let id = ids::event_id();
        let ts = time::now_ms();
        let id2 = id.clone();
        self.inner.db.write_sync(|c| {
            insert_event(c, &id2, ts, &event)?;
            Ok(())
        })?;
        Ok(id)
    }

    /// Durably record outbound MCP data before it is emitted. The payload must
    /// already be redacted; its hash is computed over exactly these bytes.
    pub async fn record_share(&self, rec: ShareRecord) -> LpResult<(String, String)> {
        if self.fault().is_some() || self.inner.admission_blocked.load(Ordering::SeqCst) {
            return Err(LpError::audit_unavailable());
        }
        let id = ids::share_id();
        let sha = hex::encode(Sha256::digest(&rec.payload));
        let (id2, sha2, ts) = (id.clone(), sha.clone(), time::now_ms());
        let res = self
            .inner
            .db
            .write(move |c| {
                c.execute(
                    "INSERT INTO data_shared (share_event_id, timestamp, client_id, session_id, tool_name, request_id,
                        audit_event_id, source_path, mime_type, byte_count, sha256, payload, redaction, transmission)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'prepared')",
                    params![
                        id2,
                        ts,
                        rec.client_id,
                        rec.session_id,
                        rec.tool_name,
                        rec.request_id,
                        rec.audit_event_id,
                        rec.source_path,
                        rec.mime_type,
                        rec.payload.len() as i64,
                        sha2,
                        rec.payload,
                        opt_json(&rec.redaction),
                    ],
                )?;
                Ok(())
            })
            .await;
        match res {
            Ok(()) => Ok((id, sha)),
            Err(e) => {
                self.set_fault(&format!(
                    "Data Shared record could not be persisted: {}",
                    e.message
                ));
                Err(LpError::audit_unavailable().with_internal(e))
            }
        }
    }

    /// Update transmission state (`sent`, `interrupted`, `failed`).
    pub fn mark_transmission(&self, ids: Vec<String>, status: &str) {
        if ids.is_empty() {
            return;
        }
        let _ = self
            .inner
            .queue
            .try_send(QueueOp::Transmission(ids, status.to_string()));
    }

    pub async fn query_events(&self, f: AuditFilter) -> LpResult<Vec<AuditRow>> {
        self.inner
            .db
            .read(move |c| {
                let mut sql = String::from("SELECT event_id, kind, timestamp_start, timestamp_end, client_id, client_display_name, session_id, mcp_protocol_version, tool_name, operation_category, project_id, cwd, command, arguments, paths, entry_point, shell_checks, policy_decision, policy_detail, approval_id, approval_result, task_id, pid, exit_code, stdout_bytes, stderr_bytes, result_status, duration_ms, error FROM audit_events WHERE 1=1");
                let mut args: Vec<rusqlite::types::Value> = Vec::new();
                let mut push = |cond: &str, v: rusqlite::types::Value, sql: &mut String| {
                    sql.push_str(cond);
                    args.push(v);
                };
                if let Some(v) = f.since_ms { push(" AND timestamp_start >= ?", v.into(), &mut sql); }
                if let Some(v) = f.until_ms { push(" AND timestamp_start <= ?", v.into(), &mut sql); }
                if let Some(v) = f.before_ms { push(" AND timestamp_start < ?", v.into(), &mut sql); }
                if let Some(v) = &f.client_id { push(" AND client_id = ?", v.clone().into(), &mut sql); }
                if let Some(v) = &f.tool_name { push(" AND tool_name = ?", v.clone().into(), &mut sql); }
                if let Some(v) = &f.project_id { push(" AND project_id = ?", v.clone().into(), &mut sql); }
                if let Some(v) = &f.result_status { push(" AND result_status = ?", v.clone().into(), &mut sql); }
                if let Some(v) = &f.kind { push(" AND kind = ?", v.clone().into(), &mut sql); }
                if let Some(v) = &f.text {
                    let like = format!("%{}%", v.replace('%', "\\%").replace('_', "\\_"));
                    sql.push_str(" AND (command LIKE ? ESCAPE '\\' OR arguments LIKE ? ESCAPE '\\' OR paths LIKE ? ESCAPE '\\' OR tool_name LIKE ? ESCAPE '\\')");
                    for _ in 0..4 {
                        args.push(like.clone().into());
                    }
                }
                sql.push_str(" ORDER BY timestamp_start DESC LIMIT ?");
                args.push((f.limit.unwrap_or(200).min(2000) as i64).into());
                let mut stmt = c.prepare(&sql)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(args), |r| {
                        Ok(AuditRow {
                            event_id: r.get(0)?,
                            kind: r.get(1)?,
                            timestamp_start: r.get(2)?,
                            timestamp_end: r.get(3)?,
                            client_id: r.get(4)?,
                            client_display_name: r.get(5)?,
                            session_id: r.get(6)?,
                            mcp_protocol_version: r.get(7)?,
                            tool_name: r.get(8)?,
                            operation_category: r.get(9)?,
                            project_id: r.get(10)?,
                            cwd: r.get(11)?,
                            command: r.get(12)?,
                            arguments: r.get(13)?,
                            paths: r.get(14)?,
                            entry_point: r.get(15)?,
                            shell_checks: r.get(16)?,
                            policy_decision: r.get(17)?,
                            policy_detail: r.get(18)?,
                            approval_id: r.get(19)?,
                            approval_result: r.get(20)?,
                            task_id: r.get(21)?,
                            pid: r.get(22)?,
                            exit_code: r.get(23)?,
                            stdout_bytes: r.get(24)?,
                            stderr_bytes: r.get(25)?,
                            result_status: r.get(26)?,
                            duration_ms: r.get(27)?,
                            error: r.get(28)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    pub async fn query_shares(&self, f: ShareFilter) -> LpResult<Vec<ShareRow>> {
        self.inner
            .db
            .read(move |c| {
                let mut sql = String::from("SELECT share_event_id, timestamp, client_id, session_id, tool_name, request_id, audit_event_id, source_path, mime_type, byte_count, sha256, redaction, transmission FROM data_shared WHERE 1=1");
                let mut args: Vec<rusqlite::types::Value> = Vec::new();
                if let Some(v) = f.since_ms { sql.push_str(" AND timestamp >= ?"); args.push(v.into()); }
                if let Some(v) = f.until_ms { sql.push_str(" AND timestamp <= ?"); args.push(v.into()); }
                if let Some(v) = f.before_ms { sql.push_str(" AND timestamp < ?"); args.push(v.into()); }
                if let Some(v) = &f.client_id { sql.push_str(" AND client_id = ?"); args.push(v.clone().into()); }
                if let Some(v) = &f.session_id { sql.push_str(" AND session_id = ?"); args.push(v.clone().into()); }
                if let Some(v) = &f.tool_name { sql.push_str(" AND tool_name = ?"); args.push(v.clone().into()); }
                sql.push_str(" ORDER BY timestamp DESC LIMIT ?");
                args.push((f.limit.unwrap_or(200).min(2000) as i64).into());
                let mut stmt = c.prepare(&sql)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(args), |r| {
                        Ok(ShareRow {
                            share_event_id: r.get(0)?,
                            timestamp: r.get(1)?,
                            client_id: r.get(2)?,
                            session_id: r.get(3)?,
                            tool_name: r.get(4)?,
                            request_id: r.get(5)?,
                            audit_event_id: r.get(6)?,
                            source_path: r.get(7)?,
                            mime_type: r.get(8)?,
                            byte_count: r.get(9)?,
                            sha256: r.get(10)?,
                            redaction: r.get(11)?,
                            transmission: r.get(12)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    pub async fn share_payload(&self, id: String) -> LpResult<Option<Vec<u8>>> {
        self.inner
            .db
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT payload FROM data_shared WHERE share_event_id = ?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()?)
            })
            .await
    }

    /// Crash recovery: events left in `intent` are marked `unknown` (the
    /// outcome was not recorded); nothing is replayed.
    pub async fn mark_incomplete_unknown(&self) -> LpResult<usize> {
        self.inner
            .db
            .write(|c| {
                let n = c.execute(
                    "UPDATE audit_events SET result_status = 'outcome_unknown', error = COALESCE(error, 'Local Pilot stopped before the outcome was recorded; reconcile manually.') WHERE result_status IN ('intent', 'running')",
                    [],
                )?;
                c.execute("UPDATE data_shared SET transmission = 'interrupted' WHERE transmission = 'prepared'", [])?;
                Ok(n)
            })
            .await
    }

    /// Apply retention limits. `active_sessions` keeps their latest reserved
    /// Data Shared events under size pressure.
    pub async fn run_retention(
        &self,
        p: RetentionPolicy,
        active_sessions: Vec<String>,
    ) -> LpResult<RetentionSummary> {
        let blocked = self
            .inner
            .db
            .write(move |c| {
                let now = time::now_ms();
                let mut blocked = false;
                // --- audit: age
                let cutoff = now - (p.audit_retention_days as i64) * time::DAY_MS;
                let n = c.execute("DELETE FROM audit_events WHERE timestamp_start < ?1", [cutoff])?;
                if n > 0 {
                    c.execute(
                        "INSERT INTO retention_boundaries (log, timestamp, removed_before, removed_count, reason) VALUES ('audit', ?1, ?2, ?3, 'age')",
                        params![now, cutoff, n as i64],
                    )?;
                }
                // --- audit: size
                loop {
                    // Audit events and Data Shared share this file; the audit
                    // budget applies to the part not used by Data Shared payloads.
                    let audit_part = used_bytes(c)?.saturating_sub(shared_bytes(c)? as u64);
                    if audit_part <= p.audit_max_bytes {
                        break;
                    }
                    let oldest: Option<i64> = c
                        .query_row("SELECT timestamp_start FROM audit_events ORDER BY timestamp_start LIMIT 1 OFFSET 1000", [], |r| r.get(0))
                        .optional()?;
                    let Some(before) = oldest else { break };
                    let n = c.execute("DELETE FROM audit_events WHERE timestamp_start < ?1", [before])?;
                    c.execute(
                        "INSERT INTO retention_boundaries (log, timestamp, removed_before, removed_count, reason) VALUES ('audit', ?1, ?2, ?3, 'size')",
                        params![now, before, n as i64],
                    )?;
                    if n == 0 {
                        break;
                    }
                }
                // --- data shared: age
                let cutoff = now - (p.shared_retention_days as i64) * time::DAY_MS;
                let n = c.execute("DELETE FROM data_shared WHERE timestamp < ?1", [cutoff])?;
                if n > 0 {
                    c.execute(
                        "INSERT INTO retention_boundaries (log, timestamp, removed_before, removed_count, reason) VALUES ('data_shared', ?1, ?2, ?3, 'age')",
                        params![now, cutoff, n as i64],
                    )?;
                }
                // --- data shared: size with per-active-session reservations
                c.execute("CREATE TEMP TABLE IF NOT EXISTS reserved (share_event_id TEXT PRIMARY KEY)", [])?;
                c.execute("DELETE FROM temp.reserved", [])?;
                for s in &active_sessions {
                    c.execute(
                        "INSERT OR IGNORE INTO temp.reserved SELECT share_event_id FROM data_shared WHERE session_id = ?1 ORDER BY timestamp DESC LIMIT ?2",
                        params![s, p.reserved_events_per_session as i64],
                    )?;
                }
                loop {
                    let total = shared_bytes(c)?;
                    if total as u64 <= p.shared_max_bytes {
                        break;
                    }
                    let victim: Option<(String, i64, Option<String>)> = c
                        .query_row(
                            "SELECT share_event_id, timestamp, session_id FROM data_shared WHERE share_event_id NOT IN (SELECT share_event_id FROM temp.reserved) ORDER BY timestamp LIMIT 1",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .optional()?;
                    let Some((_, ts, _)) = victim else {
                        // Only reserved evidence remains and it does not fit.
                        blocked = true;
                        break;
                    };
                    // Delete a batch of the oldest non-reserved rows up to this timestamp window.
                    let rows: Vec<(String, Option<String>)> = {
                        let mut stmt = c.prepare(
                            "SELECT share_event_id, session_id FROM data_shared WHERE share_event_id NOT IN (SELECT share_event_id FROM temp.reserved) ORDER BY timestamp LIMIT 200",
                        )?;
                        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
                    };
                    let mut truncated_sessions = std::collections::BTreeSet::new();
                    for (id, sess) in &rows {
                        c.execute("DELETE FROM data_shared WHERE share_event_id = ?1", [id])?;
                        if let Some(s) = sess
                            && active_sessions.contains(s)
                        {
                            truncated_sessions.insert(s.clone());
                        }
                    }
                    c.execute(
                        "INSERT INTO retention_boundaries (log, timestamp, removed_before, removed_count, reason) VALUES ('data_shared', ?1, ?2, ?3, 'size')",
                        params![now, ts + 1, rows.len() as i64],
                    )?;
                    for s in truncated_sessions {
                        c.execute(
                            "INSERT INTO retention_boundaries (log, timestamp, removed_before, removed_count, reason, session_id) VALUES ('data_shared', ?1, ?2, 0, 'active_session_truncated', ?3)",
                            params![now, ts + 1, s],
                        )?;
                    }
                }
                c.execute_batch("PRAGMA incremental_vacuum(2000);")?;
                Ok(blocked)
            })
            .await?;
        self.inner
            .admission_blocked
            .store(blocked, Ordering::SeqCst);
        if blocked {
            self.set_fault("Data Shared reserved evidence exceeds the configured size; data delivery is paused until limits are raised or sessions end.");
        }
        self.summary().await
    }

    pub async fn summary(&self) -> LpResult<RetentionSummary> {
        let fault = self.fault();
        let blocked = self.inner.admission_blocked.load(Ordering::SeqCst);
        let db_bytes = self.inner.db.size_bytes();
        self.inner
            .db
            .read(move |c| {
                let (ao, an, ac): (Option<i64>, Option<i64>, i64) = c.query_row(
                    "SELECT MIN(timestamp_start), MAX(timestamp_start), COUNT(*) FROM audit_events",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                let (so, sn, sc, sb): (Option<i64>, Option<i64>, i64, Option<i64>) = c.query_row(
                    "SELECT MIN(timestamp), MAX(timestamp), COUNT(*), SUM(byte_count) FROM data_shared",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;
                let mut stmt = c.prepare(
                    "SELECT log, timestamp, removed_before, removed_count, reason, session_id FROM retention_boundaries ORDER BY timestamp DESC LIMIT 100",
                )?;
                let boundaries = stmt
                    .query_map([], |r| {
                        Ok(RetentionBoundary {
                            log: r.get(0)?,
                            timestamp: r.get(1)?,
                            removed_before: r.get(2)?,
                            removed_count: r.get(3)?,
                            reason: r.get(4)?,
                            session_id: r.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let truncated_sessions = boundaries
                    .iter()
                    .filter(|b| b.reason == "active_session_truncated")
                    .filter_map(|b| b.session_id.clone())
                    .collect();
                Ok(RetentionSummary {
                    audit_oldest_ms: ao,
                    audit_newest_ms: an,
                    audit_events: ac,
                    audit_bytes: db_bytes,
                    shared_oldest_ms: so,
                    shared_newest_ms: sn,
                    shared_events: sc,
                    shared_bytes: sb.unwrap_or(0),
                    boundaries,
                    truncated_sessions,
                    fault,
                    admission_blocked: blocked,
                })
            })
            .await
    }

    /// Export audit events as JSON lines to `path` (local UI action).
    pub async fn export_events(
        &self,
        path: std::path::PathBuf,
        filter: AuditFilter,
    ) -> LpResult<usize> {
        let mut f = filter;
        f.limit = Some(2000);
        let mut total = 0usize;
        let mut out = Vec::new();
        let mut before: Option<i64> = None;
        loop {
            let mut page = f.clone();
            page.before_ms = before;
            let rows = self.query_events(page).await?;
            if rows.is_empty() {
                break;
            }
            before = rows.last().map(|r| r.timestamp_start);
            for r in &rows {
                out.extend(serde_json::to_vec(r).map_err(LpError::internal)?);
                out.push(b'\n');
            }
            total += rows.len();
            if rows.len() < 2000 || total > 1_000_000 {
                break;
            }
        }
        std::fs::write(&path, out).map_err(LpError::internal)?;
        Ok(total)
    }
}

fn used_bytes(c: &rusqlite::Connection) -> rusqlite::Result<u64> {
    let page_size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    let page_count: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    Ok(((page_count - free).max(0) * page_size) as u64)
}

fn shared_bytes(c: &rusqlite::Connection) -> rusqlite::Result<i64> {
    Ok(c.query_row(
        "SELECT COALESCE(SUM(byte_count), 0) FROM data_shared",
        [],
        |r| r.get(0),
    )
    .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, AuditStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        (dir, s)
    }

    #[tokio::test]
    async fn intent_then_complete() {
        let (_d, s) = store().await;
        let id = s
            .intent(AuditEvent {
                kind: "tool_call".into(),
                tool_name: Some("fs_write_text".into()),
                client_id: Some("cl_1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        s.complete(
            &id,
            AuditCompletion {
                result_status: "ok".into(),
                ..Default::default()
            },
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let rows = s.query_events(AuditFilter::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].result_status, "ok");
        assert!(rows[0].duration_ms.is_some());
    }

    #[tokio::test]
    async fn share_hash_matches_payload() {
        let (_d, s) = store().await;
        let payload = b"{\"x\":\"<redacted>\"}".to_vec();
        let (id, sha) = s
            .record_share(ShareRecord {
                client_id: Some("cl_1".into()),
                session_id: Some("ses_1".into()),
                tool_name: Some("fs_read_text".into()),
                request_id: None,
                audit_event_id: None,
                source_path: None,
                mime_type: "application/json".into(),
                payload: payload.clone(),
                redaction: None,
            })
            .await
            .unwrap();
        assert_eq!(sha, hex::encode(Sha256::digest(&payload)));
        assert_eq!(s.share_payload(id).await.unwrap().unwrap(), payload);
    }

    #[tokio::test]
    async fn size_rotation_keeps_reserved_session_events() {
        let (_d, s) = store().await;
        for i in 0..30 {
            s.record_share(ShareRecord {
                client_id: Some("cl".into()),
                session_id: Some(if i % 2 == 0 {
                    "active".into()
                } else {
                    "old".into()
                }),
                tool_name: None,
                request_id: None,
                audit_event_id: None,
                source_path: None,
                mime_type: "text/plain".into(),
                payload: vec![b'x'; 1000],
                redaction: None,
            })
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let summary = s
            .run_retention(
                RetentionPolicy {
                    audit_retention_days: 30,
                    audit_max_bytes: 512 * 1024 * 1024,
                    shared_retention_days: 30,
                    shared_max_bytes: 10_000,
                    reserved_events_per_session: 5,
                },
                vec!["active".into()],
            )
            .await
            .unwrap();
        assert!(summary.shared_bytes <= 10_000);
        let active = s
            .query_shares(ShareFilter {
                session_id: Some("active".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(active.len() >= 5);
        assert!(
            summary
                .boundaries
                .iter()
                .any(|b| b.log == "data_shared" && b.reason == "size")
        );
        assert!(summary.truncated_sessions.contains(&"active".to_string()));
        assert!(!summary.admission_blocked);
    }

    #[tokio::test]
    async fn reserved_overflow_blocks_admission() {
        let (_d, s) = store().await;
        for _ in 0..5 {
            s.record_share(ShareRecord {
                client_id: None,
                session_id: Some("a".into()),
                tool_name: None,
                request_id: None,
                audit_event_id: None,
                source_path: None,
                mime_type: "text/plain".into(),
                payload: vec![b'x'; 4000],
                redaction: None,
            })
            .await
            .unwrap();
        }
        let summary = s
            .run_retention(
                RetentionPolicy {
                    audit_retention_days: 30,
                    audit_max_bytes: 1 << 30,
                    shared_retention_days: 30,
                    shared_max_bytes: 1000,
                    reserved_events_per_session: 10,
                },
                vec!["a".into()],
            )
            .await
            .unwrap();
        assert!(summary.admission_blocked);
        assert!(
            s.record_share(ShareRecord {
                client_id: None,
                session_id: None,
                tool_name: None,
                request_id: None,
                audit_event_id: None,
                source_path: None,
                mime_type: "text/plain".into(),
                payload: vec![1],
                redaction: None,
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn recovery_marks_unknown() {
        let (_d, s) = store().await;
        s.intent(AuditEvent {
            kind: "tool_call".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(s.mark_incomplete_unknown().await.unwrap(), 1);
        let rows = s.query_events(AuditFilter::default()).await.unwrap();
        assert_eq!(rows[0].result_status, "outcome_unknown");
    }
}
