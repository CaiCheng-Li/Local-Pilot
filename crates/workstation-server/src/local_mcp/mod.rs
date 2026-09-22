//! Generic downstream MCP gateway. Configuration is desktop-owned, never agent-writable.
pub mod policy;
mod transport;
mod ui;

use parking_lot::{Mutex, RwLock};
use rmcp::{
    RoleClient,
    model::{CallToolRequestParams, Tool},
    service::RunningService,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use workstation_core::{
    ErrorCode, LpError, LpResult,
    db::{Db, Migration},
    dpapi,
    redaction::Redactor,
    time,
};
use workstation_executor::job::Job;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClass {
    ReadOnly,
    ProjectWrite,
    FilesystemWrite,
    ProcessExecution,
    Network,
    ApplicationControl,
    ArbitraryCode,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolPermission {
    Allow,
    Deny,
    #[default]
    Ask,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolPolicy {
    pub risk: RiskClass,
    pub permission: ToolPermission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerConfig {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub transport: Transport,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub url: String,
    pub auto_start: bool,
    pub auto_connect: bool,
    pub trusted: bool,
    pub connection_timeout_seconds: u64,
    pub tool_timeout_seconds: u64,
    pub reconnect_attempts: u32,
    pub tool_policies: BTreeMap<String, ToolPolicy>,
    pub logging: bool,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            transport: Transport::Stdio,
            command: String::new(),
            args: vec![],
            cwd: String::new(),
            env: BTreeMap::new(),
            url: String::new(),
            auto_start: false,
            auto_connect: false,
            trusted: false,
            connection_timeout_seconds: 10,
            tool_timeout_seconds: 60,
            reconnect_attempts: 0,
            tool_policies: BTreeMap::new(),
            logging: true,
        }
    }
}
impl ServerConfig {
    pub fn validate(&mut self) -> LpResult<()> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
        {
            return Err(LpError::invalid(
                "Server ID must contain 1–64 lowercase letters, digits, underscores or hyphens",
            ));
        }
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.len() > 128 {
            return Err(LpError::invalid(
                "A server name of at most 128 bytes is required",
            ));
        }
        if !(1..=120).contains(&self.connection_timeout_seconds)
            || !(1..=3600).contains(&self.tool_timeout_seconds)
            || self.reconnect_attempts > 5
        {
            return Err(LpError::invalid(
                "Timeouts must be 1–120 seconds for connection and 1–3600 for calls; at most 5 reconnect attempts",
            ));
        }
        if self.args.len() > 128
            || self.env.len() > 128
            || self.tool_policies.len() > 2000
            || serde_json::to_vec(self).map_err(LpError::internal)?.len() > 256 * 1024
        {
            return Err(LpError::invalid("Server configuration exceeds limits"));
        }
        if self.command.contains('\0')
            || self.cwd.contains('\0')
            || self.args.iter().any(|v| v.contains('\0'))
            || self
                .env
                .iter()
                .any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0'))
        {
            return Err(LpError::invalid(
                "Invalid command, argument or environment value",
            ));
        }
        match self.transport {
            Transport::Stdio => {
                if self.command.trim().is_empty()
                    || !Path::new(&self.cwd).is_absolute()
                    || !Path::new(&self.cwd).is_dir()
                {
                    return Err(LpError::invalid(
                        "stdio requires a command and an existing absolute working directory",
                    ));
                }
            }
            Transport::StreamableHttp => {
                local_url(&self.url)?;
            }
        }
        Ok(())
    }
    /// Upstream metadata intentionally excludes launch arguments and all environment values.
    pub fn public(&self) -> Value {
        json!({"id":self.id,"name":self.name,"enabled":self.enabled,"transport":self.transport,"trusted":self.trusted})
    }
}

pub fn local_url(value: &str) -> LpResult<url::Url> {
    let mut u = url::Url::parse(value).map_err(|_| LpError::invalid("Invalid MCP URL"))?;
    if u.scheme() != "http"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(LpError::invalid(
            "Use a local http URL without credentials, query or fragment",
        ));
    }
    match u.host_str() {
        Some("localhost") => {
            u.set_host(Some("127.0.0.1")).map_err(LpError::internal)?;
        }
        Some("127.0.0.1" | "[::1]") => (),
        _ => {
            return Err(LpError::new(
                ErrorCode::McpPermissionDenied,
                "Only localhost, 127.0.0.1 and ::1 MCP endpoints are allowed",
            ));
        }
    }
    Ok(u)
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Runtime {
    pub status: String,
    pub last_connected: Option<i64>,
    pub last_error: Option<String>,
    pub pid: Option<u32>,
    pub started_at: Option<i64>,
    pub exit_code: Option<u32>,
    pub restart_count: u32,
    pub next_retry_at: Option<i64>,
    pub tool_count: usize,
    pub server_info: Option<Value>,
    pub discovered_at: Option<i64>,
    pub logs: Vec<String>,
}
pub(super) struct Connection {
    pub service: RunningService<RoleClient, ()>,
    pub job: Option<Job>,
    pub pid: Option<u32>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(job) = &self.job {
            let _ = job.terminate(1);
        }
        self.service.cancellation_token().cancel();
    }
}
pub(super) struct Entry {
    config: RwLock<ServerConfig>,
    pub runtime: Mutex<Runtime>,
    connection: Mutex<Option<Arc<Connection>>>,
    tools: RwLock<Vec<Tool>>,
    operation: tokio::sync::Mutex<()>,
    stop: Mutex<CancellationToken>,
}
impl Entry {
    fn new(config: ServerConfig) -> Self {
        let status = if config.enabled {
            "stopped"
        } else {
            "disabled"
        }
        .into();
        Self {
            config: RwLock::new(config),
            runtime: Mutex::new(Runtime {
                status,
                ..Default::default()
            }),
            connection: Mutex::new(None),
            tools: RwLock::new(vec![]),
            operation: tokio::sync::Mutex::new(()),
            stop: Mutex::new(CancellationToken::new()),
        }
    }
    fn stop(&self) {
        self.stop.lock().cancel();
        if let Some(c) = self.connection.lock().take() {
            if let Some(job) = &c.job {
                let _ = job.terminate(1);
            }
            c.service.cancellation_token().cancel();
        }
        self.tools.write().clear();
        let mut r = self.runtime.lock();
        r.status = if self.config.read().enabled {
            "stopped"
        } else {
            "disabled"
        }
        .into();
        r.pid = None;
        r.tool_count = 0;
        r.next_retry_at = None;
    }
}

pub struct Gateway {
    db: Db,
    entries: RwLock<BTreeMap<String, Arc<Entry>>>,
    blocked: AtomicBool,
    redactor: Redactor,
}
impl Gateway {
    pub fn open(path: &Path, redactor: Redactor) -> LpResult<Self> {
        let db = Db::open(
            path,
            &[Migration {
                version: 1,
                name: "local MCP registry",
                sql: "CREATE TABLE servers (id TEXT PRIMARY KEY, config BLOB NOT NULL);",
            }],
        )?;
        let configs = db.read_sync(|c| {
            let mut stmt = c.prepare("SELECT config FROM servers ORDER BY id")?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            let mut out = vec![];
            for row in rows {
                let raw = dpapi::unprotect(&row?)?;
                let config: ServerConfig =
                    serde_json::from_slice(&raw).map_err(LpError::internal)?;
                out.push(config);
            }
            Ok(out)
        })?;
        let entries = configs
            .into_iter()
            .map(|c| {
                for (k, v) in &c.env {
                    redactor.add_known_value(k, v);
                }
                (c.id.clone(), Arc::new(Entry::new(c)))
            })
            .collect();
        Ok(Self {
            db,
            entries: RwLock::new(entries),
            blocked: AtomicBool::new(true),
            redactor,
        })
    }
    fn entry(&self, id: &str) -> LpResult<Arc<Entry>> {
        self.entries
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| LpError::new(ErrorCode::McpServerNotFound, "MCP server not found"))
    }
    pub fn config(&self, id: &str) -> LpResult<ServerConfig> {
        Ok(self.entry(id)?.config.read().clone())
    }
    pub fn list(&self) -> Value {
        Value::Array(
            self.entries
                .read()
                .values()
                .map(|e| self.view(e, false))
                .collect(),
        )
    }
    fn view(&self, e: &Entry, local: bool) -> Value {
        let disconnected = e
            .connection
            .lock()
            .as_ref()
            .is_some_and(|c| c.service.is_closed());
        let config = e.config.read();
        let mut v = if local {
            serde_json::to_value(&*config).unwrap_or_default()
        } else {
            config.public()
        };
        let mut runtime = e.runtime.lock().clone();
        if disconnected && runtime.status == "connected" {
            runtime.status = "degraded".into();
        }
        if local {
            v["env"] = json!(
                config
                    .env
                    .keys()
                    .map(|k| (k.clone(), "<redacted>"))
                    .collect::<BTreeMap<_, _>>()
            );
        }
        v["runtime"] = serde_json::to_value(runtime).unwrap_or_default();
        if !local {
            v["runtime"].as_object_mut().unwrap().remove("logs");
        }
        self.redactor.redact_json(&v).0
    }
    pub fn get(&self, id: &str) -> LpResult<Value> {
        Ok(self.view(self.entry(id)?.as_ref(), false))
    }
    pub fn desktop_list(&self) -> Value {
        Value::Array(
            self.entries
                .read()
                .values()
                .map(|e| self.view(e, true))
                .collect(),
        )
    }
    pub async fn save(&self, mut config: ServerConfig, replace: bool) -> LpResult<()> {
        config.validate()?;
        // Environment is write-only in UI. Preserve masked values on edits.
        if replace {
            let old = self.config(&config.id)?;
            for (k, v) in &mut config.env {
                if v == "<redacted>" {
                    *v = old
                        .env
                        .get(k)
                        .cloned()
                        .ok_or_else(|| LpError::invalid("Enter the environment value"))?;
                }
            }
        }
        for (k, v) in &config.env {
            self.redactor.add_known_value(k, v);
        }
        let blob = dpapi::protect(&serde_json::to_vec(&config).map_err(LpError::internal)?)?;
        let old = self.entries.read().get(&config.id).cloned();
        if old.is_some() != replace {
            return Err(LpError::invalid(if replace {
                "Server does not exist"
            } else {
                "Duplicate server ID"
            }));
        }
        let _guard = match &old {
            Some(e) => Some(e.operation.lock().await),
            None => None,
        };
        let mut entries = self.entries.write();
        if entries.contains_key(&config.id) != replace {
            return Err(LpError::invalid("Registry changed; refresh and retry"));
        }
        self.db.write_sync(|c| {
            if replace {
                c.execute(
                    "UPDATE servers SET config=?2 WHERE id=?1",
                    rusqlite::params![config.id, blob],
                )?;
            } else {
                c.execute(
                    "INSERT INTO servers(id,config) VALUES(?1,?2)",
                    rusqlite::params![config.id, blob],
                )?;
            }
            Ok(())
        })?;
        if let Some(e) = old.as_ref() {
            e.stop();
        }
        if let Some(e) = old.as_ref() {
            *e.config.write() = config;
            e.stop();
        } else {
            entries.insert(config.id.clone(), Arc::new(Entry::new(config)));
        }
        Ok(())
    }
    pub async fn remove(&self, id: &str) -> LpResult<()> {
        let e = self.entry(id)?;
        let _guard = e.operation.lock().await;
        self.db.write_sync(|c| {
            c.execute("DELETE FROM servers WHERE id=?1", [id])?;
            Ok(())
        })?;
        e.stop();
        self.entries.write().remove(id);
        Ok(())
    }
    pub fn block(&self) {
        self.blocked.store(true, Ordering::SeqCst);
        for e in self.entries.read().values() {
            e.stop();
        }
    }
    pub fn resume(&self) {
        self.blocked.store(false, Ordering::SeqCst);
    }
    pub fn stop(&self, id: &str) -> LpResult<()> {
        self.entry(id)?.stop();
        Ok(())
    }
    pub async fn start(&self, id: &str) -> LpResult<()> {
        let e = self.entry(id)?;
        let _guard = e.operation.lock().await;
        if self.blocked.load(Ordering::SeqCst) {
            return Err(LpError::new(
                ErrorCode::EmergencyStopActive,
                "Resume Local Pilot before starting MCP services",
            ));
        }
        let c = e.config.read().clone();
        if !c.enabled {
            return Err(LpError::new(
                ErrorCode::McpServerDisabled,
                "MCP server is disabled",
            ));
        }
        if e.connection
            .lock()
            .as_ref()
            .is_some_and(|c| !c.service.is_closed())
        {
            return Ok(());
        }
        e.stop();
        let token = CancellationToken::new();
        *e.stop.lock() = token.clone();
        e.runtime.lock().status = if c.transport == Transport::Stdio {
            "starting"
        } else {
            "connecting"
        }
        .into();
        let result = tokio::select! {
            biased;
            _=token.cancelled()=>Err(LpError::new(ErrorCode::McpConnectionFailed,"Connection cancelled")),
            r=tokio::time::timeout(Duration::from_secs(c.connection_timeout_seconds),transport::connect(&c,e.clone(),self.redactor.clone()))=>r.unwrap_or_else(|_|Err(LpError::new(ErrorCode::McpConnectionFailed,"MCP connection timed out"))),
        };
        match result {
            Ok((connection, tools)) => {
                let mut live = e.connection.lock();
                if token.is_cancelled() || self.blocked.load(Ordering::SeqCst) {
                    drop(connection);
                    return Err(LpError::new(
                        ErrorCode::EmergencyStopActive,
                        "Connection stopped",
                    ));
                }
                let mut r = e.runtime.lock();
                r.status = "connected".into();
                r.last_error = None;
                r.last_connected = Some(time::now_ms());
                r.tool_count = tools.len();
                r.discovered_at = r.last_connected;
                r.pid = connection.pid;
                r.server_info = connection.service.peer_info().map(|i| {
                    self.redactor
                        .redact_json(&serde_json::to_value(i).unwrap_or_default())
                        .0
                });
                r.next_retry_at = None;
                r.restart_count = 0;
                *e.tools.write() = tools;
                *live = Some(Arc::new(connection));
                Ok(())
            }
            Err(err) => {
                let mut r = e.runtime.lock();
                if !token.is_cancelled() {
                    r.status = "error".into();
                    r.last_error = Some(err.message.clone());
                }
                r.pid = None;
                Err(err)
            }
        }
    }
    pub async fn test(&self, mut config: ServerConfig) -> LpResult<Value> {
        config.validate()?;
        config.id = format!(
            "test-{}",
            workstation_core::ids::new_id("test").to_ascii_lowercase()
        );
        let id = config.id.clone();
        self.entries
            .write()
            .insert(id.clone(), Arc::new(Entry::new(config)));
        let result = self.start(&id).await.and_then(|_| self.get(&id));
        let _ = self.stop(&id);
        self.entries.write().remove(&id);
        result
    }
    pub async fn restart(&self, id: &str) -> LpResult<()> {
        self.stop(id)?;
        self.start(id).await
    }
    pub fn tools(&self, id: &str) -> LpResult<Value> {
        let e = self.entry(id)?;
        let c = e.config.read();
        if !c.enabled {
            return Err(LpError::new(
                ErrorCode::McpServerDisabled,
                "MCP server is disabled",
            ));
        }
        let tools = e
            .tools
            .read()
            .iter()
            .map(|t| {
                let mut v = serde_json::to_value(t).unwrap_or_default();
                v["serverId"] = json!(id);
                v["policy"] = json!(
                    c.tool_policies
                        .get(t.name.as_ref())
                        .cloned()
                        .unwrap_or_default()
                );
                v
            })
            .collect::<Vec<_>>();
        Ok(self.redactor.redact_json(&json!(tools)).0)
    }
    pub fn descriptor(&self, id: &str, tool: Option<&str>) -> LpResult<Value> {
        let e = self.entry(id)?;
        let c = e.config.read();
        if !c.enabled {
            return Err(LpError::new(
                ErrorCode::McpServerDisabled,
                "MCP server is disabled",
            ));
        }
        let schema = if let Some(name) = tool {
            Some(
                e.tools
                    .read()
                    .iter()
                    .find(|t| t.name == name)
                    .cloned()
                    .ok_or_else(|| {
                        LpError::new(
                            ErrorCode::McpToolNotFound,
                            "Tool not discovered; connect and refresh first",
                        )
                    })?,
            )
        } else {
            None
        };
        Ok(json!({"configHash":workstation_core::hashing::json_digest(&json!(*c)),"tool":schema}))
    }
    pub async fn refresh(&self, id: &str) -> LpResult<Value> {
        let e = self.entry(id)?;
        let c = e.connection.lock().clone().ok_or_else(|| {
            LpError::new(ErrorCode::McpConnectionFailed, "Server is not connected")
        })?;
        let tools = transport::discover(&c.service).await?;
        let mut r = e.runtime.lock();
        r.tool_count = tools.len();
        r.discovered_at = Some(time::now_ms());
        *e.tools.write() = tools;
        drop(r);
        self.tools(id)
    }
    pub async fn call(
        &self,
        id: &str,
        tool: &str,
        args: Value,
        expected: &Value,
        cancel: CancellationToken,
    ) -> LpResult<Value> {
        let e = self.entry(id)?;
        if self.blocked.load(Ordering::SeqCst) {
            return Err(LpError::new(
                ErrorCode::EmergencyStopActive,
                "MCP gateway stopped",
            ));
        }
        if &self.descriptor(id, Some(tool))? != expected {
            return Err(LpError::new(
                ErrorCode::ApprovalInvalidated,
                "MCP configuration or tool schema changed",
            ));
        }
        let c = e.connection.lock().clone().ok_or_else(|| {
            LpError::new(
                ErrorCode::McpConnectionFailed,
                "MCP server is not connected",
            )
        })?;
        let token = e.stop.lock().clone();
        let timeout = e.config.read().tool_timeout_seconds;
        let args = args
            .as_object()
            .cloned()
            .ok_or_else(|| LpError::invalid("Tool arguments must be an object"))?;
        let params = CallToolRequestParams::new(tool.to_string()).with_arguments(args);
        transport::call(
            &c.service,
            params,
            Duration::from_secs(timeout),
            token,
            cancel,
        )
        .await
    }
    pub async fn auto_start(&self) {
        let ids: Vec<_> = self
            .entries
            .read()
            .values()
            .filter_map(|e| {
                let c = e.config.read();
                (c.enabled
                    && if c.transport == Transport::Stdio {
                        c.auto_start
                    } else {
                        c.auto_connect
                    })
                .then(|| c.id.clone())
            })
            .collect();
        for id in ids {
            let _ = self.start(&id).await;
        }
    }
    pub async fn maintain(&self) {
        if self.blocked.load(Ordering::SeqCst) {
            return;
        }
        let entries: Vec<_> = self.entries.read().values().cloned().collect();
        for e in entries {
            let config = e.config.read().clone();
            let broken = e
                .connection
                .lock()
                .as_ref()
                .is_some_and(|c| c.service.is_closed());
            if broken {
                e.stop();
                let mut r = e.runtime.lock();
                r.status = "degraded".into();
                r.last_error = Some("Downstream MCP disconnected".into());
            }
            let retry = {
                let mut r = e.runtime.lock();
                if matches!(r.status.as_str(), "degraded" | "error")
                    && config.enabled
                    && r.restart_count < config.reconnect_attempts
                {
                    let backoff = 1000 * (1i64 << r.restart_count.min(5));
                    let next = *r.next_retry_at.get_or_insert(time::now_ms() + backoff);
                    if time::now_ms() >= next {
                        r.restart_count += 1;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if retry {
                let _ = self.start(&config.id).await;
            }
        }
    }
}

#[cfg(test)]
mod tests;
