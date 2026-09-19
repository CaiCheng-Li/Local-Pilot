//! Local UI API. These operations are reachable only from the desktop app
//! process (Tauri IPC); remote MCP clients cannot call them. Every
//! security-relevant change is audited.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use workstation_audit::{
    AuditEvent, AuditFilter, AuditRow, RetentionSummary, ShareFilter, ShareRow,
};
use workstation_core::config::{Settings, ToolSecretGrant};
use workstation_core::{ErrorCode, LpError, LpResult, ids, known_folders, time};

use crate::Core;
use crate::approvals::{ApprovalView, ExecutionView, LocalDecision};
use crate::auth::ClientRow;
use crate::auth::oauth::PendingConnectionView;
use crate::environment::{self, EnvVarInfo};
use crate::leases::Lease;
use crate::sessions::Session;
use crate::state::ServerState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusView {
    pub version: String,
    pub state: String,
    pub remote_access: bool,
    pub emergency_latched: bool,
    pub fault: Option<String>,
    pub config_fault: Option<String>,
    pub audit_fault: Option<String>,
    pub listener: Option<String>,
    pub listener_error: Option<String>,
    pub public: crate::PublicUrls,
    pub setup_completed: bool,
    pub shell_checks_enabled: bool,
    pub trusted_root: String,
    pub trusted_root_exists: bool,
    pub sessions: Vec<SessionView>,
    pub running_tasks: usize,
    pub pending_approvals: usize,
    pub pending_connections: usize,
    pub projects: usize,
    pub app_elevated: bool,
    pub helper_available: bool,
    pub unknown_outcomes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub session_id: String,
    pub client_id: String,
    pub client_name: String,
    pub created_at: i64,
    pub last_activity_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
    pub grants: Vec<String>,
    pub running_tasks: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupRequest {
    pub port: Option<u16>,
    pub public_mcp_url: Option<String>,
    pub autostart: bool,
    pub create_projects_folder: bool,
    pub enable_remote_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectView {
    #[serde(flatten)]
    pub project: workstation_index::Project,
    pub lease: Option<Lease>,
    pub active_clients: Vec<String>,
}

pub fn pick_free_port() -> LpResult<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(LpError::internal)?;
    Ok(l.local_addr().map_err(LpError::internal)?.port())
}

impl Core {
    pub async fn ui_status(self: &Arc<Self>) -> StatusView {
        let s = self.settings.get();
        let clients = self.auth.list_clients().unwrap_or_default();
        let name_of = |id: &str| {
            clients
                .iter()
                .find(|c| c.client_id == id)
                .map(|c| c.display_name.clone())
                .unwrap_or_default()
        };
        let running = self.tasks.running_ids();
        let sessions = self
            .sessions
            .list()
            .into_iter()
            .map(|x| SessionView {
                client_name: name_of(&x.client_id),
                running_tasks: running.iter().filter(|(_, c)| c == &x.client_id).count(),
                idle_expires_at: x.idle_expires_at(),
                grants: x.grants.iter().map(|g| g.label.clone()).collect(),
                session_id: x.session_id,
                client_id: x.client_id,
                created_at: x.created_at,
                last_activity_at: x.last_activity_at,
                absolute_expires_at: x.absolute_expires_at,
            })
            .collect();
        let root = self.trusted_root();
        StatusView {
            version: workstation_core::VERSION.into(),
            state: self.state.get().as_str().into(),
            remote_access: self.state.accepting(),
            emergency_latched: crate::state::latch_get(&self.control).unwrap_or(true),
            fault: self.state.fault(),
            config_fault: self.settings.fault().map(|f| f.message),
            audit_fault: self.audit.fault(),
            listener: self.listener_addr().await.map(|a| a.to_string()),
            listener_error: self.last_http_error(),
            public: self.public_urls(),
            setup_completed: s.setup_completed,
            shell_checks_enabled: s.shell_protection.enabled,
            trusted_root_exists: root.is_dir(),
            trusted_root: root.display().to_string(),
            sessions,
            running_tasks: running.len(),
            pending_approvals: self.approvals.list(Some("pending"), None, 1000).len(),
            pending_connections: self.auth.oauth_pending().len(),
            projects: self
                .index
                .list()
                .iter()
                .filter(|p| p.parent_project_id.is_none())
                .count(),
            app_elevated: workstation_executor::current_process_elevated(),
            helper_available: self.helper.available(),
            unknown_outcomes: self.approvals.list_unknown_outcomes().len(),
        }
    }

    fn ui_audit(&self, kind: &str, detail: String, client: Option<&str>) {
        let _ = self.audit.record_sync(AuditEvent {
            kind: kind.into(),
            client_id: client.map(|s| s.to_string()),
            result_status: "ok".into(),
            policy_detail: Some(detail),
            ..Default::default()
        });
    }

    // ---------------------------------------------------------- setup

    pub fn ui_default_projects_root(&self) -> LpResult<String> {
        Ok(known_folders::default_projects_root()?
            .display()
            .to_string())
    }

    pub async fn ui_complete_setup(self: &Arc<Self>, req: SetupRequest) -> LpResult<StatusView> {
        let mut s = (*self.settings.get()).clone();
        if req.create_projects_folder {
            let root = match &s.trusted_workspace.root_override {
                Some(p) => p.clone(),
                None => known_folders::default_projects_root()?,
            };
            std::fs::create_dir_all(&root)
                .map_err(|e| LpError::internal(format!("create {}: {e}", root.display())))?;
        }
        s.network.port = match req.port {
            Some(p) if p != 0 => p,
            _ if s.network.port != 0 => s.network.port,
            _ => pick_free_port()?,
        };
        s.network.public_mcp_url = match req.public_mcp_url.as_deref().map(str::trim) {
            Some(u) if !u.is_empty() => {
                workstation_core::config::validate_public_url(u)?;
                Some(u.trim_end_matches('/').to_string())
            }
            _ => None,
        };
        s.general.autostart = req.autostart;
        s.setup_completed = true;
        self.update_settings(s).await?;
        self.rebuild_policy_after_setup();
        self.ui_audit("setup_completed", "first-run setup completed".into(), None);
        if req.enable_remote_access {
            self.enable_remote_access().await?;
        }
        Ok(self.ui_status().await)
    }

    fn rebuild_policy_after_setup(self: &Arc<Self>) {
        self.schedule_index_refresh();
        let index = self.index.clone();
        tokio::task::spawn_blocking(move || {
            let _ = index.start_watcher();
        });
    }

    // -------------------------------------------------------- clients

    pub fn ui_clients(&self) -> LpResult<Vec<ClientRow>> {
        self.auth.list_clients()
    }

    pub fn ui_create_client(&self, name: &str) -> LpResult<String> {
        let id = self.auth.create_client(name, Some("manual"))?;
        self.ui_audit("client_created", format!("{id} ({name})"), Some(&id));
        Ok(id)
    }

    /// Returns the plaintext token once.
    pub fn ui_create_manual_token(
        &self,
        client_id: &str,
        scopes: Vec<String>,
        label: Option<String>,
        expires_in_days: Option<u64>,
    ) -> LpResult<Value> {
        let (cred, token) =
            self.auth
                .create_manual_token(client_id, &scopes, label.as_deref(), expires_in_days)?;
        self.ui_audit(
            "manual_token_created",
            format!("credential {cred}"),
            Some(client_id),
        );
        Ok(json!({ "credential_id": cred, "token": token, "shown_once": true }))
    }

    pub fn ui_rotate_token(&self, credential_id: &str) -> LpResult<Value> {
        let (cred, token) = self.auth.rotate_manual_token(credential_id)?;
        self.sessions
            .end_credential(credential_id, "credential rotated");
        self.ui_audit(
            "manual_token_rotated",
            format!("{credential_id} -> {cred}"),
            None,
        );
        Ok(json!({ "credential_id": cred, "token": token, "shown_once": true }))
    }

    pub fn ui_revoke_credential(&self, credential_id: &str) -> LpResult<()> {
        let client = self.auth.revoke_credential(credential_id)?;
        self.sessions
            .end_credential(credential_id, "credential revoked");
        let remaining_active = self
            .auth
            .list_clients()?
            .into_iter()
            .find(|c| c.client_id == client)
            .map(|c| {
                c.credentials
                    .iter()
                    .any(|cr| cr.revoked_at.is_none() && cr.enabled)
            })
            .unwrap_or(false);
        if !remaining_active {
            self.client_access_removed(&client, "credential revoked");
        } else {
            self.approvals
                .invalidate(Some(&client), None, "cancelled", "credential revoked");
        }
        self.ui_audit(
            "credential_revoked",
            credential_id.to_string(),
            Some(&client),
        );
        Ok(())
    }

    pub fn ui_set_credential_enabled(&self, credential_id: &str, enabled: bool) -> LpResult<()> {
        let client = self.auth.set_credential_enabled(credential_id, enabled)?;
        if !enabled {
            self.sessions
                .end_credential(credential_id, "credential disabled");
            self.client_access_removed(&client, "credential disabled");
        }
        self.ui_audit(
            "credential_enabled_changed",
            format!("{credential_id} enabled={enabled}"),
            Some(&client),
        );
        Ok(())
    }

    pub fn ui_set_client_enabled(&self, client_id: &str, enabled: bool) -> LpResult<()> {
        self.auth.set_client_enabled(client_id, enabled)?;
        if !enabled {
            self.client_access_removed(client_id, "client disabled");
        }
        self.ui_audit(
            "client_enabled_changed",
            format!("enabled={enabled}"),
            Some(client_id),
        );
        Ok(())
    }

    pub fn ui_rename_client(&self, client_id: &str, name: &str) -> LpResult<()> {
        self.auth.rename_client(client_id, name)?;
        self.ui_audit("client_renamed", name.to_string(), Some(client_id));
        Ok(())
    }

    /// Disconnect: end the client's sessions (grants and approvals cancelled).
    pub fn ui_disconnect_client(&self, client_id: &str) -> usize {
        let n = self.client_access_removed(client_id, "disconnected locally");
        self.ui_audit(
            "client_disconnected",
            format!("terminated {n} task(s)"),
            Some(client_id),
        );
        n
    }

    pub async fn ui_allow_only_client(self: &Arc<Self>, client_id: &str) -> LpResult<()> {
        let mut s = (*self.settings.get()).clone();
        s.concurrency.allow_any_authenticated_client = false;
        s.concurrency.allowed_client_ids = vec![client_id.to_string()];
        self.update_settings(s).await?;
        for c in self.auth.list_clients()? {
            if c.client_id != client_id {
                self.client_access_removed(&c.client_id, "not in allow list");
            }
        }
        Ok(())
    }

    pub fn ui_sessions(&self) -> Vec<Session> {
        self.sessions.list()
    }

    pub fn ui_end_session(&self, session_id: &str) {
        self.end_session(session_id, "ended locally");
        self.ui_audit("session_ended_locally", session_id.to_string(), None);
    }

    // ---------------------------------------------------- connections

    pub fn ui_pending_connections(&self) -> Vec<PendingConnectionView> {
        self.auth.oauth_pending()
    }

    pub fn ui_decide_connection(
        &self,
        request_id: &str,
        approve: bool,
        bind_client_id: Option<String>,
        display_name: Option<String>,
    ) -> LpResult<()> {
        self.auth
            .oauth_decide(request_id, approve, bind_client_id.clone(), display_name)?;
        self.ui_audit(
            "connection_decision",
            format!(
                "{request_id} approve={approve} bind={}",
                bind_client_id.unwrap_or_else(|| "-".into())
            ),
            None,
        );
        self.events.emit(crate::events::UiEvent::ConnectionChanged {
            request_id: request_id.to_string(),
            status: if approve {
                "approved".into()
            } else {
                "denied".into()
            },
        });
        Ok(())
    }

    // ------------------------------------------------------ approvals

    pub fn ui_approvals(&self, status: Option<String>, limit: usize) -> Vec<ApprovalView> {
        self.approvals.list(status.as_deref(), None, limit)
    }

    pub fn ui_decide_approval(
        &self,
        approval_id: &str,
        decision: LocalDecision,
    ) -> LpResult<ApprovalView> {
        self.decide_approval(approval_id, decision)
    }

    pub fn ui_unknown_outcomes(&self) -> Vec<ExecutionView> {
        self.approvals.list_unknown_outcomes()
    }

    pub fn ui_reconcile(&self, execution_id: &str, note: &str) -> LpResult<()> {
        self.approvals.reconcile(execution_id, note)?;
        self.ui_audit(
            "outcome_reconciled",
            format!("{execution_id}: {note}"),
            None,
        );
        Ok(())
    }

    // ---------------------------------------------------------- tasks

    pub fn ui_tasks(&self, active_only: bool, limit: usize) -> Vec<workstation_executor::TaskInfo> {
        self.tasks.list(None, active_only, limit)
    }

    pub fn ui_task_output(
        &self,
        task_id: &str,
        offset: Option<i64>,
        max_bytes: u64,
    ) -> LpResult<workstation_executor::OutputSlice> {
        self.tasks.output(task_id, offset, max_bytes)
    }

    pub fn ui_kill_task(&self, task_id: &str) -> LpResult<workstation_executor::TaskInfo> {
        let t = self.tasks.kill(task_id)?;
        self.ui_audit(
            "task_killed_locally",
            task_id.to_string(),
            Some(&t.client_id),
        );
        Ok(t)
    }

    pub fn ui_cancel_task(&self, task_id: &str) -> LpResult<workstation_executor::TaskInfo> {
        let t = self.tasks.cancel(task_id)?;
        self.ui_audit(
            "task_cancelled_locally",
            task_id.to_string(),
            Some(&t.client_id),
        );
        Ok(t)
    }

    // ------------------------------------------------------- projects

    pub fn ui_projects(&self) -> Vec<ProjectView> {
        let leases = self.leases.list();
        let running = self.tasks.list(None, true, 1000);
        self.index
            .list()
            .into_iter()
            .map(|p| ProjectView {
                lease: leases
                    .iter()
                    .find(|l| l.project_id == p.project_id)
                    .cloned(),
                active_clients: {
                    let mut v: Vec<String> = running
                        .iter()
                        .filter(|t| t.project_id.as_deref() == Some(&p.project_id))
                        .map(|t| t.client_id.clone())
                        .collect();
                    v.dedup();
                    v
                },
                project: p,
            })
            .collect()
    }

    pub async fn ui_refresh_projects(&self, project_id: Option<String>) -> LpResult<usize> {
        let index = self.index.clone();
        tokio::task::spawn_blocking(move || index.refresh(project_id.as_deref()))
            .await
            .map_err(LpError::internal)?
    }

    pub fn ui_set_project_locked(&self, project_id: &str, locked: bool) -> LpResult<()> {
        self.index.set_locked(project_id, locked)?;
        self.ui_audit(
            "project_lock_changed",
            format!("{project_id} locked={locked}"),
            None,
        );
        Ok(())
    }

    pub fn ui_set_project_aliases(&self, project_id: &str, aliases: Vec<String>) -> LpResult<()> {
        self.index.set_aliases(project_id, &aliases)
    }

    // ---------------------------------------------------- audit/share

    pub async fn ui_audit_events(&self, filter: AuditFilter) -> LpResult<Vec<AuditRow>> {
        self.audit.query_events(filter).await
    }

    pub async fn ui_export_audit(&self, path: PathBuf, filter: AuditFilter) -> LpResult<usize> {
        let n = self.audit.export_events(path.clone(), filter).await?;
        self.ui_audit(
            "audit_exported",
            format!("{n} events to {}", path.display()),
            None,
        );
        Ok(n)
    }

    pub async fn ui_retention(&self) -> LpResult<RetentionSummary> {
        self.audit.summary().await
    }

    pub async fn ui_shares(&self, filter: ShareFilter) -> LpResult<Vec<ShareRow>> {
        self.audit.query_shares(filter).await
    }

    pub async fn ui_share_payload(&self, id: String) -> LpResult<Option<String>> {
        Ok(self
            .audit
            .share_payload(id)
            .await?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }

    pub fn ui_clear_audit_fault(&self) {
        self.audit.clear_fault();
        self.ui_audit("audit_fault_cleared", "cleared by user".into(), None);
    }

    // ------------------------------------------------------- settings

    pub fn ui_settings(&self) -> Settings {
        (*self.settings.get()).clone()
    }

    pub fn ui_environment(&self) -> Vec<EnvVarInfo> {
        environment::inspect(&self.settings.get())
    }

    /// Grant a configured tool (identified executable) inheritance of secret variables.
    pub async fn ui_add_tool_grant(
        self: &Arc<Self>,
        executable_path: String,
        variables: Vec<String>,
        project_scope: Option<String>,
    ) -> LpResult<()> {
        let exe = std::fs::canonicalize(&executable_path)
            .map_err(|_| LpError::invalid("executable not found"))?;
        let exe = workstation_executor::spawn::strip_verbatim(exe);
        let bytes = std::fs::read(&exe).map_err(LpError::internal)?;
        let mut s = (*self.settings.get()).clone();
        s.environment.tool_grants.push(ToolSecretGrant {
            id: ids::new_id("grant"),
            variables,
            executable_path: exe.display().to_string(),
            executable_sha256: workstation_core::hashing::sha256_hex(&bytes),
            project_scope,
            created_at: time::now_ms(),
        });
        self.update_settings(s).await?;
        Ok(())
    }

    // -------------------------------------------------------- network

    pub async fn ui_external_health(&self) -> LpResult<Value> {
        let urls = self.public_urls();
        if !urls.configured {
            return Err(LpError::new(
                ErrorCode::ConfigFault,
                "No public MCP URL is configured.",
            ));
        }
        let health = format!("{}{}/health", urls.origin, urls.prefix);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(LpError::internal)?;
        let started = std::time::Instant::now();
        match client.get(&health).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let body: Value = r.json().await.unwrap_or(Value::Null);
                let ok = status == 200 && body.get("status").and_then(|s| s.as_str()) == Some("ok");
                let v = json!({ "url": health, "ok": ok, "status": status, "latency_ms": started.elapsed().as_millis() as u64, "checked_at": time::now_ms() });
                let _ = self.control.write_sync(|c| {
                    c.execute(
                        "INSERT INTO settings_kv (key, value, updated_at) VALUES ('external_health', ?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                        rusqlite::params![v.to_string(), time::now_ms()],
                    )?;
                    Ok(())
                });
                Ok(v)
            }
            Err(e) => Ok(
                json!({ "url": health, "ok": false, "error": e.to_string(), "checked_at": time::now_ms() }),
            ),
        }
    }

    pub fn ui_last_external_health(&self) -> Option<Value> {
        self.control
            .read_sync(|c| {
                use rusqlite::OptionalExtension;
                Ok(c.query_row(
                    "SELECT value FROM settings_kv WHERE key = 'external_health'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
            })
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    /// Best-effort detection of a local cloudflared process/service.
    pub fn ui_tunnel_status(&self) -> Value {
        let run = |exe: &str, args: &[&str]| -> Option<String> {
            use std::os::windows::process::CommandExt;
            std::process::Command::new(exe)
                .args(args)
                .creation_flags(0x0800_0000)
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        };
        let process = run("tasklist", &["/FI", "IMAGENAME eq cloudflared.exe", "/NH"])
            .map(|s| s.to_lowercase().contains("cloudflared.exe"))
            .unwrap_or(false);
        let service = run("sc", &["query", "cloudflared"]).map(|s| {
            if s.contains("RUNNING") {
                "running"
            } else if s.contains("STOPPED") {
                "stopped"
            } else {
                "not_installed"
            }
        });
        json!({ "cloudflared_process": process, "cloudflared_service": service.unwrap_or("unknown") })
    }

    /// Redacted diagnostic bundle (settings, status, recent diagnostic log).
    pub async fn ui_support_bundle(self: &Arc<Self>, dest: PathBuf) -> LpResult<PathBuf> {
        let status = serde_json::to_value(self.ui_status().await).unwrap_or_default();
        let mut settings = serde_json::to_value(self.ui_settings()).unwrap_or_default();
        if let Some(n) = settings.get_mut("network") {
            n["public_mcp_url"] = json!("<omitted>");
        }
        let mut log = String::new();
        if let Ok(rd) = std::fs::read_dir(&self.paths.logs_dir) {
            let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
            files.sort();
            if let Some(last) = files.last()
                && let Ok(t) = std::fs::read_to_string(last)
            {
                let tail: String = t
                    .lines()
                    .rev()
                    .take(2000)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n");
                log = self.redactor.redact_string(&tail);
            }
        }
        let bundle = json!({
            "generated_at": time::ms_to_rfc3339(time::now_ms()),
            "status": self.redactor.redact_json(&status).0,
            "settings": settings,
            "diagnostic_log_tail": log,
            "note": "Tokens, credentials, databases and Data Shared payloads are never included.",
        });
        let text = serde_json::to_string_pretty(&bundle).map_err(LpError::internal)?;
        std::fs::write(&dest, text).map_err(LpError::internal)?;
        Ok(dest)
    }

    pub fn ui_server_state(&self) -> ServerState {
        self.state.get()
    }
}
