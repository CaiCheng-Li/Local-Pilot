//! Task manager: every launch gets a task ID, runs in its own job, streams
//! redacted output into bounded storage, and can be polled, cancelled or
//! killed without an HTTP request staying open.

use std::collections::HashMap;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use workstation_core::db::{Db, Migration};
use workstation_core::redaction::{Redactor, StreamRedactor};
use workstation_core::{ErrorCode, LpError, LpResult, time};

use crate::job::Job;
use crate::spawn::{SpawnSpec, spawn};

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "tasks_init",
    sql: r#"
CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    session_id TEXT,
    tool_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    command TEXT NOT NULL,
    cwd TEXT NOT NULL,
    project_id TEXT,
    pid INTEGER,
    status TEXT NOT NULL,
    exit_code INTEGER,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    ended_at INTEGER,
    timeout_ms INTEGER,
    stdout_bytes INTEGER NOT NULL DEFAULT 0,
    stderr_bytes INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    truncated_before INTEGER NOT NULL DEFAULT 0,
    last_output_at INTEGER,
    error TEXT,
    audit_event_id TEXT,
    approval_id TEXT,
    execution_id TEXT,
    warnings TEXT,
    cache_dir TEXT,
    standard_user_token INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_tasks_client ON tasks(client_id, created_at);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE TABLE task_output_chunks (
    task_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    stream TEXT NOT NULL,
    offset INTEGER NOT NULL,
    data BLOB NOT NULL,
    ts INTEGER NOT NULL,
    PRIMARY KEY (task_id, seq)
);
"#,
}];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
    Killed,
    TimedOut,
    Interrupted,
    LaunchFailed,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Running => "running",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
            TaskStatus::Killed => "killed",
            TaskStatus::TimedOut => "timed_out",
            TaskStatus::Interrupted => "interrupted",
            TaskStatus::LaunchFailed => "launch_failed",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "running" => TaskStatus::Running,
            "completed" => TaskStatus::Completed,
            "failed" => TaskStatus::Failed,
            "cancelled" => TaskStatus::Cancelled,
            "killed" => TaskStatus::Killed,
            "timed_out" => TaskStatus::TimedOut,
            "launch_failed" => TaskStatus::LaunchFailed,
            _ => TaskStatus::Interrupted,
        }
    }
    pub fn is_terminal(&self) -> bool {
        !matches!(self, TaskStatus::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub task_id: String,
    pub client_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub kind: String,
    pub command: String,
    pub cwd: String,
    pub project_id: Option<String>,
    pub pid: Option<u32>,
    pub status: TaskStatus,
    pub exit_code: Option<i64>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub timeout_ms: Option<i64>,
    pub stdout_bytes: i64,
    pub stderr_bytes: i64,
    pub total_bytes: i64,
    pub truncated_before: i64,
    pub last_output_at: Option<i64>,
    pub error: Option<String>,
    pub approval_id: Option<String>,
    pub execution_id: Option<String>,
    pub warnings: Vec<String>,
    pub standard_user_token: bool,
    pub active_processes: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TaskSpec {
    pub client_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub kind: String,
    /// Redacted display form of the command.
    pub display_command: String,
    pub project_id: Option<String>,
    pub spawn: SpawnSpec,
    pub timeout: Duration,
    pub audit_event_id: Option<String>,
    pub approval_id: Option<String>,
    pub execution_id: Option<String>,
    pub warnings: Vec<String>,
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputChunk {
    pub stream: String,
    pub offset: i64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSlice {
    pub task_id: String,
    pub chunks: Vec<OutputChunk>,
    /// Offset to pass next time.
    pub next_offset: i64,
    /// Output before this offset was dropped by the per-task retention cap.
    pub truncated_before: i64,
    pub total_bytes: i64,
    pub status: TaskStatus,
    pub more_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TaskEvent {
    Started {
        task_id: String,
        client_id: String,
    },
    Finished {
        task_id: String,
        client_id: String,
        status: TaskStatus,
        exit_code: Option<i64>,
    },
}

struct Running {
    client_id: String,
    job: Job,
    process: OwnedHandle,
    cancel_requested: AtomicBool,
    kill_status: Mutex<Option<TaskStatus>>,
    readers_done: Arc<(AtomicBool, AtomicBool)>,
}

struct OutputState {
    next_offset: i64,
    seq: i64,
    stdout: i64,
    stderr: i64,
}

struct Inner {
    db: Db,
    redactor: Redactor,
    running: Mutex<HashMap<String, Arc<Running>>>,
    events: broadcast::Sender<TaskEvent>,
    max_output_bytes: AtomicU64,
}

#[derive(Clone)]
pub struct TaskManager {
    inner: Arc<Inner>,
}

const TASK_COLS: &str = "task_id, client_id, session_id, tool_name, kind, command, cwd, project_id, pid, status, exit_code, created_at, started_at, ended_at, timeout_ms, stdout_bytes, stderr_bytes, total_bytes, truncated_before, last_output_at, error, approval_id, execution_id, warnings, standard_user_token";

fn row_to_task(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskInfo> {
    let status: String = r.get(9)?;
    let warnings: Option<String> = r.get(23)?;
    Ok(TaskInfo {
        task_id: r.get(0)?,
        client_id: r.get(1)?,
        session_id: r.get(2)?,
        tool_name: r.get(3)?,
        kind: r.get(4)?,
        command: r.get(5)?,
        cwd: r.get(6)?,
        project_id: r.get(7)?,
        pid: r.get::<_, Option<i64>>(8)?.map(|p| p as u32),
        status: TaskStatus::parse(&status),
        exit_code: r.get(10)?,
        created_at: r.get(11)?,
        started_at: r.get(12)?,
        ended_at: r.get(13)?,
        timeout_ms: r.get(14)?,
        stdout_bytes: r.get(15)?,
        stderr_bytes: r.get(16)?,
        total_bytes: r.get(17)?,
        truncated_before: r.get(18)?,
        last_output_at: r.get(19)?,
        error: r.get(20)?,
        approval_id: r.get(21)?,
        execution_id: r.get(22)?,
        warnings: warnings
            .and_then(|w| serde_json::from_str(&w).ok())
            .unwrap_or_default(),
        standard_user_token: r.get(24)?,
        active_processes: None,
    })
}

impl TaskManager {
    pub fn open(db_path: &Path, redactor: Redactor, max_output_bytes: u64) -> LpResult<Self> {
        let db = Db::open(db_path, MIGRATIONS)?;
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(Inner {
                db,
                redactor,
                running: Mutex::new(HashMap::new()),
                events,
                max_output_bytes: AtomicU64::new(max_output_bytes.max(64 * 1024)),
            }),
        })
    }

    pub fn set_max_output_bytes(&self, v: u64) {
        self.inner
            .max_output_bytes
            .store(v.max(64 * 1024), Ordering::SeqCst);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TaskEvent> {
        self.inner.events.subscribe()
    }

    /// Crash recovery: tasks recorded as running cannot be reattached (their
    /// job was closed with the previous process), so they are interrupted.
    pub fn recover_on_startup(&self) -> LpResult<usize> {
        self.inner.db.write_sync(|c| {
            Ok(c.execute(
                "UPDATE tasks SET status = 'interrupted', ended_at = ?1, error = COALESCE(error, 'Local Pilot stopped while the task was running; its process tree was terminated with the job.') WHERE status = 'running'",
                [time::now_ms()],
            )?)
        })
    }

    pub fn running_count(&self, client_id: &str) -> usize {
        self.inner
            .running
            .lock()
            .values()
            .filter(|r| r.client_id == client_id)
            .count()
    }

    pub fn running_ids(&self) -> Vec<(String, String)> {
        self.inner
            .running
            .lock()
            .iter()
            .map(|(id, r)| (id.clone(), r.client_id.clone()))
            .collect()
    }

    /// Launch a task. Returns once the process is running inside its job.
    pub fn launch(&self, task_id: &str, spec: TaskSpec) -> LpResult<TaskInfo> {
        let now = time::now_ms();
        let tid = task_id.to_string();
        {
            let spec = spec.clone();
            let tid = tid.clone();
            self.inner.db.write_sync(move |c| {
                c.execute(
                    "INSERT INTO tasks (task_id, client_id, session_id, tool_name, kind, command, cwd, project_id, status, created_at, timeout_ms, audit_event_id, approval_id, execution_id, warnings, cache_dir)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'running', ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        tid,
                        spec.client_id,
                        spec.session_id,
                        spec.tool_name,
                        spec.kind,
                        spec.display_command,
                        spec.spawn.cwd.display().to_string(),
                        spec.project_id,
                        now,
                        spec.timeout.as_millis() as i64,
                        spec.audit_event_id,
                        spec.approval_id,
                        spec.execution_id,
                        serde_json::to_string(&spec.warnings).ok(),
                        spec.cache_dir.as_ref().map(|p| p.display().to_string()),
                    ],
                )?;
                Ok(())
            })?;
        }
        let spawned = match spawn(&spec.spawn) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("launch failed: {e}");
                let tid2 = tid.clone();
                let m2 = msg.clone();
                let _ = self.inner.db.write_sync(move |c| {
                    c.execute(
                        "UPDATE tasks SET status = 'launch_failed', ended_at = ?2, error = ?3 WHERE task_id = ?1",
                        params![tid2, time::now_ms(), m2],
                    )?;
                    Ok(())
                });
                return Err(LpError::new(ErrorCode::CommandFailed, msg));
            }
        };
        let pid = spawned.pid;
        let standard_user = spawned.standard_user_token;
        {
            let tid2 = tid.clone();
            self.inner.db.write_sync(move |c| {
                c.execute(
                    "UPDATE tasks SET pid = ?2, started_at = ?3, standard_user_token = ?4 WHERE task_id = ?1",
                    params![tid2, pid, time::now_ms(), standard_user],
                )?;
                Ok(())
            })?;
        }
        let readers_done = Arc::new((AtomicBool::new(false), AtomicBool::new(false)));
        let running = Arc::new(Running {
            client_id: spec.client_id.clone(),
            job: spawned.job,
            process: spawned.process,
            cancel_requested: AtomicBool::new(false),
            kill_status: Mutex::new(None),
            readers_done: readers_done.clone(),
        });
        self.inner
            .running
            .lock()
            .insert(tid.clone(), running.clone());

        let state = Arc::new(Mutex::new(OutputState {
            next_offset: 0,
            seq: 0,
            stdout: 0,
            stderr: 0,
        }));
        for (stream, file) in [("stdout", spawned.stdout), ("stderr", spawned.stderr)] {
            let this = self.clone();
            let tid = tid.clone();
            let state = state.clone();
            let done = readers_done.clone();
            let redactor = self.inner.redactor.stream();
            std::thread::Builder::new()
                .name(format!("lp-out-{stream}"))
                .spawn(move || {
                    this.reader_loop(&tid, stream, file, redactor, &state);
                    if stream == "stdout" {
                        done.0.store(true, Ordering::SeqCst);
                    } else {
                        done.1.store(true, Ordering::SeqCst);
                    }
                })
                .map_err(LpError::internal)?;
        }
        {
            let this = self.clone();
            let tid = tid.clone();
            let deadline = Instant::now() + spec.timeout;
            std::thread::Builder::new()
                .name("lp-task-wait".into())
                .spawn(move || this.wait_loop(&tid, running, deadline))
                .map_err(LpError::internal)?;
        }
        let _ = self.inner.events.send(TaskEvent::Started {
            task_id: tid.clone(),
            client_id: spec.client_id.clone(),
        });
        self.get(&tid)
            .ok_or_else(|| LpError::internal("task vanished"))
    }

    fn reader_loop(
        &self,
        task_id: &str,
        stream: &str,
        mut file: std::fs::File,
        mut redactor: StreamRedactor,
        state: &Mutex<OutputState>,
    ) {
        let mut buf = vec![0u8; 32 * 1024];
        let mut pending: Vec<u8> = Vec::new();
        let mut last_flush = Instant::now();
        loop {
            let n = match file.read(&mut buf) {
                Ok(0) | Err(_) => 0,
                Ok(n) => n,
            };
            if n > 0 {
                pending.extend(redactor.push(&buf[..n]));
            } else {
                pending.extend(redactor.finish());
            }
            if !pending.is_empty()
                && (n == 0
                    || pending.len() >= 16 * 1024
                    || last_flush.elapsed() > Duration::from_millis(200))
            {
                self.store_chunk(task_id, stream, std::mem::take(&mut pending), state);
                last_flush = Instant::now();
            }
            if n == 0 {
                break;
            }
        }
    }

    fn store_chunk(&self, task_id: &str, stream: &str, data: Vec<u8>, state: &Mutex<OutputState>) {
        let (seq, offset, len) = {
            let mut s = state.lock();
            let seq = s.seq;
            let offset = s.next_offset;
            s.seq += 1;
            s.next_offset += data.len() as i64;
            if stream == "stdout" {
                s.stdout += data.len() as i64;
            } else {
                s.stderr += data.len() as i64;
            }
            (seq, offset, data.len() as i64)
        };
        let cap = self.inner.max_output_bytes.load(Ordering::SeqCst) as i64;
        let tid = task_id.to_string();
        let stream = stream.to_string();
        let res = self.inner.db.write_sync(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO task_output_chunks (task_id, seq, stream, offset, data, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![tid, seq, stream, offset, data, time::now_ms()],
            )?;
            let col = if stream == "stdout" { "stdout_bytes" } else { "stderr_bytes" };
            tx.execute(
                &format!("UPDATE tasks SET {col} = {col} + ?2, total_bytes = total_bytes + ?2, last_output_at = ?3 WHERE task_id = ?1"),
                params![tid, len, time::now_ms()],
            )?;
            // Enforce the per-task retention cap by dropping the oldest chunks.
            let retained: i64 = tx.query_row(
                "SELECT COALESCE(SUM(length(data)), 0) FROM task_output_chunks WHERE task_id = ?1",
                [&tid],
                |r| r.get(0),
            )?;
            if retained > cap {
                let mut excess = retained - cap;
                let mut stmt = tx.prepare("SELECT seq, offset, length(data) FROM task_output_chunks WHERE task_id = ?1 ORDER BY seq")?;
                let rows: Vec<(i64, i64, i64)> = stmt.query_map([&tid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
                drop(stmt);
                let mut new_trunc = 0;
                for (s, off, l) in rows {
                    if excess <= 0 {
                        break;
                    }
                    tx.execute("DELETE FROM task_output_chunks WHERE task_id = ?1 AND seq = ?2", params![tid, s])?;
                    excess -= l;
                    new_trunc = off + l;
                }
                tx.execute("UPDATE tasks SET truncated_before = MAX(truncated_before, ?2) WHERE task_id = ?1", params![tid, new_trunc])?;
            }
            tx.commit()?;
            Ok(())
        });
        if let Err(e) = res {
            tracing::error!(error = %e, "storing task output failed");
        }
    }

    fn wait_loop(&self, task_id: &str, running: Arc<Running>, deadline: Instant) {
        let h = running.process.as_raw_handle() as HANDLE;
        let mut root_exit: Option<u32> = None;
        let mut timed_out = false;
        loop {
            if root_exit.is_none() && unsafe { WaitForSingleObject(h, 200) } == WAIT_OBJECT_0 {
                let mut code = 0u32;
                unsafe { GetExitCodeProcess(h, &mut code) };
                root_exit = Some(code);
            } else if root_exit.is_some() {
                std::thread::sleep(Duration::from_millis(200));
            }
            let active = running.job.active_processes().unwrap_or(0);
            if root_exit.is_some() && active == 0 {
                break;
            }
            if running.kill_status.lock().is_some() {
                let _ = running.job.terminate(1);
            }
            if Instant::now() > deadline && !timed_out {
                timed_out = true;
                let _ = running.job.terminate(0x5000_0001);
                *running.kill_status.lock() = Some(TaskStatus::TimedOut);
            }
        }
        // Give readers a moment to drain after the tree exits.
        let wait_until = Instant::now() + Duration::from_secs(5);
        while !(running.readers_done.0.load(Ordering::SeqCst)
            && running.readers_done.1.load(Ordering::SeqCst))
            && Instant::now() < wait_until
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let code = root_exit.unwrap_or(1);
        let status = match *running.kill_status.lock() {
            Some(s) => s,
            None if running.cancel_requested.load(Ordering::SeqCst) => TaskStatus::Cancelled,
            None if code == 0 => TaskStatus::Completed,
            None => TaskStatus::Failed,
        };
        let tid = task_id.to_string();
        let st = status.as_str().to_string();
        let _ = self.inner.db.write_sync(move |c| {
            c.execute(
                "UPDATE tasks SET status = ?2, exit_code = ?3, ended_at = ?4 WHERE task_id = ?1",
                params![tid, st, code as i64 as i32 as i64, time::now_ms()],
            )?;
            Ok(())
        });
        self.inner.running.lock().remove(task_id);
        let _ = self.inner.events.send(TaskEvent::Finished {
            task_id: task_id.to_string(),
            client_id: running.client_id.clone(),
            status,
            exit_code: Some(code as i32 as i64),
        });
    }

    pub fn get(&self, task_id: &str) -> Option<TaskInfo> {
        let tid = task_id.to_string();
        let mut info = self
            .inner
            .db
            .read_sync(move |c| {
                Ok(c.query_row(
                    &format!("SELECT {TASK_COLS} FROM tasks WHERE task_id = ?1"),
                    [tid],
                    row_to_task,
                )
                .optional()?)
            })
            .ok()
            .flatten()?;
        if let Some(r) = self.inner.running.lock().get(task_id) {
            info.active_processes = r.job.active_processes().ok();
        }
        Some(info)
    }

    pub fn list(&self, client_id: Option<&str>, active_only: bool, limit: usize) -> Vec<TaskInfo> {
        let cid = client_id.map(|s| s.to_string());
        let limit = limit.clamp(1, 1000) as i64;
        self.inner
            .db
            .read_sync(move |c| {
                let mut sql = format!("SELECT {TASK_COLS} FROM tasks WHERE 1=1");
                if cid.is_some() {
                    sql.push_str(" AND client_id = ?2");
                }
                if active_only {
                    sql.push_str(" AND status = 'running'");
                }
                sql.push_str(" ORDER BY created_at DESC LIMIT ?1");
                let mut stmt = c.prepare(&sql)?;
                let rows = match &cid {
                    Some(id) => stmt
                        .query_map(params![limit, id], row_to_task)?
                        .collect::<Result<Vec<_>, _>>()?,
                    None => stmt
                        .query_map(params![limit], row_to_task)?
                        .collect::<Result<Vec<_>, _>>()?,
                };
                Ok(rows)
            })
            .unwrap_or_default()
    }

    /// Bounded output retrieval from `offset`.
    pub fn output(
        &self,
        task_id: &str,
        offset: Option<i64>,
        max_bytes: u64,
    ) -> LpResult<OutputSlice> {
        let info = self
            .get(task_id)
            .ok_or_else(|| LpError::new(ErrorCode::TaskNotFound, "unknown task"))?;
        let start = offset
            .unwrap_or(info.truncated_before)
            .max(info.truncated_before)
            .max(0);
        let tid = task_id.to_string();
        let max = max_bytes.clamp(1, 4 * 1024 * 1024) as i64;
        let (chunks, next, more) = self.inner.db.read_sync(move |c| {
            let mut stmt = c.prepare(
                "SELECT stream, offset, data FROM task_output_chunks WHERE task_id = ?1 AND offset + length(data) > ?2 ORDER BY seq",
            )?;
            let rows: Vec<(String, i64, Vec<u8>)> = stmt
                .query_map(params![tid, start], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            let mut out = Vec::new();
            let mut used = 0i64;
            let mut next = start;
            let mut more = false;
            for (stream, off, data) in rows {
                let skip = (start - off).max(0) as usize;
                let slice = &data[skip.min(data.len())..];
                if slice.is_empty() {
                    continue;
                }
                let room = (max - used) as usize;
                if room == 0 {
                    more = true;
                    break;
                }
                let mut take = slice.len().min(room);
                // Do not split a UTF-8 sequence.
                while take < slice.len() && take > 0 && (slice[take] & 0b1100_0000) == 0b1000_0000 {
                    take -= 1;
                }
                if take == 0 {
                    more = true;
                    break;
                }
                out.push(OutputChunk {
                    stream,
                    offset: off + skip as i64,
                    text: String::from_utf8_lossy(&slice[..take]).into_owned(),
                });
                used += take as i64;
                next = off + skip as i64 + take as i64;
                if take < slice.len() {
                    more = true;
                    break;
                }
            }
            Ok((out, next, more))
        })?;
        Ok(OutputSlice {
            task_id: task_id.to_string(),
            chunks,
            next_offset: next,
            truncated_before: info.truncated_before,
            total_bytes: info.total_bytes,
            status: info.status,
            more_available: more || next < info.total_bytes,
        })
    }

    fn terminate(&self, task_id: &str, status: TaskStatus) -> LpResult<TaskInfo> {
        let running = self.inner.running.lock().get(task_id).cloned();
        match running {
            Some(r) => {
                *r.kill_status.lock() = Some(status);
                let _ = r.job.terminate(1);
            }
            None => {
                return self
                    .get(task_id)
                    .ok_or_else(|| LpError::new(ErrorCode::TaskNotFound, "unknown task"));
            }
        }
        self.get(task_id)
            .ok_or_else(|| LpError::new(ErrorCode::TaskNotFound, "unknown task"))
    }

    /// Request cancellation. Windows offers no reliable graceful signal for
    /// console-less children, so a Ctrl+Break is attempted and the job is
    /// terminated after a short grace period.
    pub fn cancel(&self, task_id: &str) -> LpResult<TaskInfo> {
        let running = self.inner.running.lock().get(task_id).cloned();
        let Some(r) = running else {
            return self
                .get(task_id)
                .ok_or_else(|| LpError::new(ErrorCode::TaskNotFound, "unknown task"));
        };
        if r.cancel_requested.swap(true, Ordering::SeqCst) {
            return self.terminate(task_id, TaskStatus::Cancelled);
        }
        let pid = self.get(task_id).and_then(|t| t.pid);
        if let Some(pid) = pid {
            send_ctrl_break(pid);
        }
        let this = self.clone();
        let tid = task_id.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            let _ = this.terminate(&tid, TaskStatus::Cancelled);
        });
        let mut info = self
            .get(task_id)
            .ok_or_else(|| LpError::new(ErrorCode::TaskNotFound, "unknown task"))?;
        info.warnings.push(
            "cancellation requested; the process tree is terminated after a 3 second grace period"
                .into(),
        );
        Ok(info)
    }

    pub fn kill(&self, task_id: &str) -> LpResult<TaskInfo> {
        self.terminate(task_id, TaskStatus::Killed)
    }

    /// Terminate every managed task (Emergency Stop / full stop).
    pub fn kill_all(&self) -> usize {
        let all: Vec<Arc<Running>> = self.inner.running.lock().values().cloned().collect();
        for r in &all {
            *r.kill_status.lock() = Some(TaskStatus::Killed);
            let _ = r.job.terminate(1);
        }
        all.len()
    }

    /// Terminate tasks owned by one client (revoke/disable/disconnect).
    pub fn kill_client(&self, client_id: &str) -> usize {
        let owned: Vec<Arc<Running>> = self
            .inner
            .running
            .lock()
            .values()
            .filter(|r| r.client_id == client_id)
            .cloned()
            .collect();
        for r in &owned {
            *r.kill_status.lock() = Some(TaskStatus::Killed);
            let _ = r.job.terminate(1);
        }
        owned.len()
    }

    /// Wait (async) until the task finishes or `max` elapses.
    pub async fn wait(&self, task_id: &str, max: Duration) -> Option<TaskInfo> {
        let mut rx = self.subscribe();
        let deadline = tokio::time::Instant::now() + max;
        loop {
            let info = self.get(task_id)?;
            if info.status.is_terminal() {
                return Some(info);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Some(info);
            }
            let step = remaining.min(Duration::from_millis(500));
            match tokio::time::timeout(step, rx.recv()).await {
                Ok(Ok(TaskEvent::Finished { task_id: t, .. })) if t == task_id => {}
                _ => {}
            }
        }
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    /// Delete output of finished tasks older than `max_age_ms`.
    pub fn prune(&self, max_age_ms: i64) -> LpResult<usize> {
        let cutoff = time::now_ms() - max_age_ms;
        self.inner.db.write_sync(move |c| {
            let n = c.execute(
                "DELETE FROM task_output_chunks WHERE task_id IN (SELECT task_id FROM tasks WHERE status != 'running' AND ended_at < ?1)",
                [cutoff],
            )?;
            c.execute("DELETE FROM tasks WHERE status != 'running' AND ended_at < ?1", [cutoff])?;
            Ok(n)
        })
    }
}

static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

/// Best-effort Ctrl+Break to a console-less child's process group. Only done
/// when Local Pilot has no console of its own (attaching would disturb it).
fn send_ctrl_break(pid: u32) {
    use windows_sys::Win32::System::Console::{
        AttachConsole, CTRL_BREAK_EVENT, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleWindow,
        SetConsoleCtrlHandler,
    };
    let _g = CONSOLE_LOCK.lock();
    unsafe {
        if !GetConsoleWindow().is_null() {
            return;
        }
        if AttachConsole(pid) == 0 {
            return;
        }
        SetConsoleCtrlHandler(None, 1);
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
        FreeConsole();
        std::thread::sleep(Duration::from_millis(50));
        SetConsoleCtrlHandler(None, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spawn::cmd_exe;

    fn spec(dir: &Path, command: &str, timeout: Duration) -> TaskSpec {
        TaskSpec {
            client_id: "cl_1".into(),
            session_id: None,
            tool_name: "shell_cmd".into(),
            kind: "cmd".into(),
            display_command: command.into(),
            project_id: None,
            spawn: SpawnSpec {
                application: cmd_exe(),
                command_line: format!("cmd.exe /d /s /c \"{command}\""),
                cwd: dir.to_path_buf(),
                env: std::env::vars().collect(),
            },
            timeout,
            audit_event_id: None,
            approval_id: None,
            execution_id: None,
            warnings: Vec::new(),
            cache_dir: None,
        }
    }

    #[tokio::test]
    async fn runs_captures_and_redacts() {
        let dir = tempfile::tempdir().unwrap();
        let tm = TaskManager::open(&dir.path().join("tasks.db"), Redactor::new(), 1 << 20).unwrap();
        tm.launch(
            "task_a",
            spec(
                dir.path(),
                "echo token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD & exit 3",
                Duration::from_secs(30),
            ),
        )
        .unwrap();
        let info = tm.wait("task_a", Duration::from_secs(20)).await.unwrap();
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.exit_code, Some(3));
        let out = tm.output("task_a", None, 4096).unwrap();
        let text: String = out.chunks.iter().map(|c| c.text.clone()).collect();
        assert!(text.contains("token ghp_<redacted>"), "{text}");
        assert!(!text.contains("abcdefghijklmnop"));
    }

    #[tokio::test]
    async fn kill_and_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let tm = TaskManager::open(&dir.path().join("tasks.db"), Redactor::new(), 1 << 20).unwrap();
        tm.launch(
            "task_k",
            spec(dir.path(), "ping -n 60 127.0.0.1", Duration::from_secs(120)),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(tm.running_count("cl_1"), 1);
        tm.kill("task_k").unwrap();
        let info = tm.wait("task_k", Duration::from_secs(10)).await.unwrap();
        assert_eq!(info.status, TaskStatus::Killed);

        tm.launch(
            "task_t",
            spec(
                dir.path(),
                "ping -n 60 127.0.0.1",
                Duration::from_millis(800),
            ),
        )
        .unwrap();
        let info = tm.wait("task_t", Duration::from_secs(10)).await.unwrap();
        assert_eq!(info.status, TaskStatus::TimedOut);
    }

    #[tokio::test]
    async fn output_is_bounded_and_paged() {
        let dir = tempfile::tempdir().unwrap();
        let tm =
            TaskManager::open(&dir.path().join("tasks.db"), Redactor::new(), 64 * 1024).unwrap();
        tm.launch(
            "task_o",
            spec(
                dir.path(),
                "for /L %i in (1,1,4000) do @echo line %i with some padding text",
                Duration::from_secs(60),
            ),
        )
        .unwrap();
        let info = tm.wait("task_o", Duration::from_secs(60)).await.unwrap();
        assert_eq!(info.status, TaskStatus::Completed);
        assert!(info.total_bytes > 64 * 1024);
        assert!(
            info.truncated_before > 0,
            "retention cap should drop old output"
        );
        let first = tm.output("task_o", Some(0), 1000).unwrap();
        assert!(
            first
                .chunks
                .iter()
                .all(|c| c.offset >= info.truncated_before)
        );
        let used: usize = first.chunks.iter().map(|c| c.text.len()).sum();
        assert!(used <= 1000);
        assert!(first.more_available);
        let next = tm
            .output("task_o", Some(first.next_offset), 1_000_000)
            .unwrap();
        let tail: String = next.chunks.iter().map(|c| c.text.clone()).collect();
        assert!(tail.contains("line 4000"));
    }
}
