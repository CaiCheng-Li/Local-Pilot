//! Local Pilot core service.
//!
//! [`Core`] owns every subsystem (settings, state machine, auth, sessions,
//! approvals, policy, index, tasks, audit) and exposes the operations used by
//! both the MCP tool pipeline and the local desktop UI. Security logic lives
//! here and in the policy crate, never in UI command handlers.

pub mod approvals;
pub mod auth;
pub mod cache;
pub mod control_db;
pub mod environment;
pub mod events;
pub mod helper;
pub mod http;
pub mod leases;
pub mod local_mcp;
pub mod mcp;
pub mod ratelimit;
pub mod sessions;
pub mod settings_store;
pub mod state;
pub mod tools;
pub mod ui_api;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use workstation_audit::{AuditEvent, AuditStore, RetentionPolicy};
use workstation_core::config::Settings;
use workstation_core::db::Db;
use workstation_core::dpapi::LocalSecrets;
use workstation_core::paths::{AppPaths, starts_with_ci};
use workstation_core::redaction::Redactor;
use workstation_core::{ErrorCode, LpError, LpResult, known_folders, time};
use workstation_executor::TaskManager;
use workstation_index::ProjectIndex;
use workstation_policy::{ApprovalRequirement, ExpandEnv, PolicyEngine, Roots, winpath};

use crate::approvals::{
    ApprovalService, ApprovalSummary, ApprovalView, LocalDecision, PendingOperation,
};
use crate::auth::{AuthService, Principal};
use crate::cache::CacheManager;
use crate::events::{EventBus, UiEvent};
use crate::leases::LeaseManager;
use crate::ratelimit::RateLimiter;
use crate::sessions::{EndedSession, Session, SessionGrant, SessionService};
use crate::settings_store::SettingsStore;
use crate::state::{ServerState, StateMachine};
use crate::tools::{ToolCtx, ToolRegistry};

pub use workstation_core;
pub use workstation_policy;

#[derive(Debug, Clone)]
pub struct CoreOptions {
    pub paths: AppPaths,
    /// Directory of the installed application binaries (control data).
    pub install_dir: Option<PathBuf>,
    /// Use these settings instead of loading `settings.json` (tests).
    pub settings_override: Option<Settings>,
    /// Start the index watcher and maintenance loops.
    pub background: bool,
    /// Path of `local-pilot-elevated-helper.exe`.
    pub helper_exe: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicUrls {
    pub origin: String,
    /// Path prefix before `/mcp`, e.g. `/workstation` (empty for none).
    pub prefix: String,
    pub mcp_url: String,
    /// RFC 8707 resource identifier (the MCP URL).
    pub resource: String,
    /// OAuth issuer (`origin + prefix`).
    pub issuer: String,
    /// RFC 9728 protected resource metadata URL.
    pub resource_metadata: String,
    pub authorization_server_metadata: String,
    pub public_host: Option<String>,
    pub configured: bool,
}

pub struct HttpHandle {
    pub cancel: CancellationToken,
    pub addr: SocketAddr,
    pub join: tokio::task::JoinHandle<()>,
}

pub struct Core {
    pub paths: AppPaths,
    pub settings: SettingsStore,
    pub state: StateMachine,
    pub control: Db,
    pub audit: AuditStore,
    pub index: ProjectIndex,
    pub tasks: TaskManager,
    pub redactor: Redactor,
    pub auth: AuthService,
    pub sessions: SessionService,
    pub approvals: ApprovalService,
    pub leases: LeaseManager,
    pub limiter: RateLimiter,
    pub cache: CacheManager,
    pub events: EventBus,
    pub env: ExpandEnv,
    pub tools: ToolRegistry,
    pub local_mcp: local_mcp::Gateway,
    pub helper: helper::HelperManager,
    roots: RwLock<Roots>,
    policy: RwLock<Arc<PolicyEngine>>,
    http: tokio::sync::Mutex<Option<HttpHandle>>,
    refresh_pending: AtomicBool,
    shutdown: CancellationToken,
    install_dir: Option<PathBuf>,
    last_http_error: Mutex<Option<String>>,
}

fn canonical_or(p: &Path) -> PathBuf {
    winpath::canonicalize(p, true)
        .map(|c| c.path)
        .unwrap_or_else(|_| p.to_path_buf())
}

impl Core {
    /// Start the core: open storage, recover from any previous run, and
    /// bring remote access up only if the crash-safe gate allows it.
    pub async fn start(opts: CoreOptions) -> LpResult<Arc<Core>> {
        opts.paths.ensure()?;
        let settings = match opts.settings_override.clone() {
            Some(s) => SettingsStore::from_settings(opts.paths.settings_file(), s),
            None => SettingsStore::load(opts.paths.settings_file()),
        };
        let s = settings.get();
        let secrets = LocalSecrets::load_or_create(&opts.paths.secrets_file())?;
        let redactor = Redactor::new();
        redactor.register_process_environment();

        let control = Db::open(&opts.paths.control_db(), control_db::MIGRATIONS)?;
        let audit = AuditStore::open(&opts.paths.audit_db())?;
        let env = ExpandEnv::from_system();
        let trusted = match &s.trusted_workspace.root_override {
            Some(p) => p.clone(),
            None => known_folders::default_projects_root()?,
        };
        let roots = Roots {
            trusted: canonical_or(&trusted),
            app_data: canonical_or(&opts.paths.root),
            cache_temp: canonical_or(&opts.paths.cache_temp_dir),
            install_dir: opts
                .install_dir
                .as_ref()
                .map(|p| canonical_or(p))
                .filter(|p| !starts_with_ci(p, &canonical_or(&trusted))),
        };
        let index = ProjectIndex::open(
            &opts.paths.index_db(),
            roots.trusted.clone(),
            redactor.clone(),
        )?;
        let tasks = TaskManager::open(
            &opts.paths.data_dir.join("tasks.db"),
            redactor.clone(),
            s.process.max_output_bytes_per_task,
        )?;
        let policy = PolicyEngine::new(
            s.clone(),
            roots.clone(),
            env.clone(),
            settings.fault().is_some(),
        );
        let state = StateMachine::new(opts.paths.remote_access_gate());
        let local_mcp = local_mcp::Gateway::open(
            &opts.paths.control_db().with_file_name("mcp.db"),
            redactor.clone(),
        )?;
        let core = Arc::new(Core {
            paths: opts.paths.clone(),
            auth: AuthService::new(control.clone(), secrets.token_pepper.clone()),
            sessions: SessionService::new(control.clone()),
            approvals: ApprovalService::new(control.clone()),
            leases: LeaseManager::new(control.clone()),
            limiter: RateLimiter::default(),
            cache: CacheManager::new(opts.paths.clone()),
            events: EventBus::default(),
            tools: ToolRegistry::build(),
            local_mcp,
            helper: helper::HelperManager::new(opts.helper_exe.clone()),
            settings,
            state,
            control,
            audit,
            index,
            tasks,
            redactor,
            env,
            roots: RwLock::new(roots),
            policy: RwLock::new(Arc::new(policy)),
            http: tokio::sync::Mutex::new(None),
            refresh_pending: AtomicBool::new(false),
            shutdown: CancellationToken::new(),
            install_dir: opts.install_dir.clone(),
            last_http_error: Mutex::new(None),
        });
        core.recover().await?;
        if opts.background {
            core.spawn_background();
        }
        // Remote access gate.
        let latched = state::latch_get(&core.control).unwrap_or(true);
        let fault = core.settings.fault();
        if latched {
            core.state.set(ServerState::EmergencyStopped);
        } else if fault.is_some() {
            core.state.set(ServerState::Faulted);
            core.state.set_fault(fault.map(|f| f.message));
        } else if core.settings.get().setup_completed && core.state.gate_enabled() {
            if let Err(e) = core.start_http().await {
                tracing::error!(error = %e, "MCP listener failed to start");
                core.state.set(ServerState::Faulted);
                core.state.set_fault(Some(e.message.clone()));
            }
        } else {
            core.state.set(ServerState::Paused);
        }
        core.emit_state();
        Ok(core)
    }

    /// Startup recovery (plan section 55).
    async fn recover(&self) -> LpResult<()> {
        let interrupted = self.tasks.recover_on_startup()?;
        let unknown = self.audit.mark_incomplete_unknown().await?;
        let (approvals, executions) = self.approvals.startup_recovery()?;
        let sessions = self.sessions.end_all_persisted("restart")?;
        if !self.index.verify() {
            tracing::error!(
                "project index failed its integrity check; it will be rebuilt by the next scan"
            );
        }
        self.audit.record(AuditEvent {
            kind: "startup".into(),
            result_status: "ok".into(),
            policy_detail: Some(format!(
                "recovered: {interrupted} interrupted tasks, {unknown} audit events with unknown outcome, {approvals} approvals invalidated, {executions} executions with unknown outcome, {sessions} sessions ended"
            )),
            ..Default::default()
        })
        .await;
        Ok(())
    }

    pub fn policy(&self) -> Arc<PolicyEngine> {
        self.policy.read().clone()
    }

    pub fn roots(&self) -> Roots {
        self.roots.read().clone()
    }

    pub fn trusted_root(&self) -> PathBuf {
        self.roots.read().trusted.clone()
    }

    pub fn install_dir(&self) -> Option<PathBuf> {
        self.install_dir.clone()
    }

    fn rebuild_policy(&self) {
        let s = self.settings.get();
        let trusted = match &s.trusted_workspace.root_override {
            Some(p) => p.clone(),
            None => known_folders::default_projects_root().unwrap_or_else(|_| self.trusted_root()),
        };
        {
            let mut r = self.roots.write();
            r.trusted = canonical_or(&trusted);
        }
        let engine = PolicyEngine::new(
            s,
            self.roots(),
            self.env.clone(),
            self.settings.fault().is_some(),
        );
        *self.policy.write() = Arc::new(engine);
    }

    pub fn public_urls(&self) -> PublicUrls {
        let s = self.settings.get();
        if let Some(u) = s
            .network
            .public_mcp_url
            .as_ref()
            .and_then(|u| url::Url::parse(u).ok())
        {
            let origin = u.origin().ascii_serialization();
            let path = u.path().trim_end_matches('/').to_string();
            let prefix = path.strip_suffix("/mcp").unwrap_or("").to_string();
            let mcp = format!("{origin}{path}");
            PublicUrls {
                resource_metadata: format!("{origin}/.well-known/oauth-protected-resource{path}"),
                authorization_server_metadata: format!(
                    "{origin}/.well-known/oauth-authorization-server{prefix}"
                ),
                issuer: format!("{origin}{prefix}"),
                resource: mcp.clone(),
                mcp_url: mcp,
                public_host: u.host_str().map(|h| match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                }),
                prefix,
                origin,
                configured: true,
            }
        } else {
            let origin = format!("http://127.0.0.1:{}", s.network.port);
            PublicUrls {
                resource_metadata: format!("{origin}/.well-known/oauth-protected-resource/mcp"),
                authorization_server_metadata: format!(
                    "{origin}/.well-known/oauth-authorization-server"
                ),
                issuer: origin.clone(),
                resource: format!("{origin}/mcp"),
                mcp_url: format!("{origin}/mcp"),
                public_host: None,
                prefix: String::new(),
                origin,
                configured: false,
            }
        }
    }

    // ----------------------------------------------------------- state

    pub fn emit_state(&self) {
        self.events.emit(UiEvent::StateChanged {
            state: self.state.get().as_str().into(),
            remote_access: self.state.accepting(),
        });
    }

    pub async fn start_http(self: &Arc<Self>) -> LpResult<SocketAddr> {
        let mut guard = self.http.lock().await;
        if let Some(h) = guard.as_ref() {
            return Ok(h.addr);
        }
        let s = self.settings.get();
        if s.network.port == 0 {
            return Err(LpError::new(
                ErrorCode::ConfigFault,
                "No listener port is configured; finish setup first.",
            ));
        }
        let handle = http::serve(self.clone()).await.inspect_err(|e| {
            *self.last_http_error.lock() = Some(e.message.clone());
        })?;
        let addr = handle.addr;
        *guard = Some(handle);
        *self.last_http_error.lock() = None;
        self.state.set(ServerState::Ready);
        self.state.set_fault(None);
        Ok(addr)
    }

    pub async fn stop_http(&self) {
        let h = self.http.lock().await.take();
        if let Some(h) = h {
            h.cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), h.join).await;
        }
    }

    pub async fn listener_addr(&self) -> Option<SocketAddr> {
        self.http.lock().await.as_ref().map(|h| h.addr)
    }

    pub fn last_http_error(&self) -> Option<String> {
        self.last_http_error.lock().clone()
    }

    /// Invalidate every session, session grant and pending approval.
    fn invalidate_all(&self, reason: &str, status: &str) {
        for e in self.sessions.end_all(reason) {
            self.events.emit(UiEvent::ClientDisconnected {
                client_id: e.session.client_id.clone(),
                display_name: String::new(),
                reason: reason.into(),
            });
        }
        let ids = self.approvals.invalidate(None, None, status, reason);
        for id in ids {
            self.events.emit(UiEvent::ApprovalChanged {
                approval_id: id,
                status: status.into(),
            });
        }
        self.auth.oauth_reset();
    }

    /// Emergency Stop (plan section 18). Stops work immediately; the latch is
    /// persisted as part of the stop and never cleared automatically.
    pub async fn emergency_stop(self: &Arc<Self>, source: &str) -> LpResult<usize> {
        // 1-2: stop accepting and reject queued calls.
        self.state.set(ServerState::EmergencyStopped);
        self.local_mcp.block();
        // 5-6: terminate managed process trees and elevated helpers first.
        let killed = self.tasks.kill_all();
        self.helper.abort_all();
        // 3-4: revoke session approvals, cancel pending approvals.
        self.invalidate_all("emergency stop", "cancelled");
        self.leases.clear();
        // Persist the latch and the gate (failure leaves a visible fault but
        // does not delay the stop).
        let latch = state::latch_set(&self.control, true, source);
        let gate = self.state.write_gate(false);
        if let Err(e) = latch.and(gate) {
            self.state.set_fault(Some(format!(
                "Emergency Stop latch could not be persisted: {}",
                e.message
            )));
        }
        // 7-8: close connections and suspend remote access.
        self.stop_http().await;
        let _ = self.audit.record_sync(AuditEvent {
            kind: "emergency_stop".into(),
            result_status: "ok".into(),
            policy_detail: Some(format!("source: {source}; terminated {killed} task(s)")),
            ..Default::default()
        });
        self.events.emit(UiEvent::EmergencyStop);
        self.emit_state();
        Ok(killed)
    }

    /// Explicit local Resume after Emergency Stop.
    pub async fn resume_remote_access(self: &Arc<Self>) -> LpResult<()> {
        if self.settings.fault().is_some() {
            return Err(LpError::new(
                ErrorCode::ConfigFault,
                "Repair or reset the damaged settings before enabling remote access.",
            ));
        }
        state::latch_set(&self.control, false, "local resume")?;
        self.state.write_gate(true)?;
        self.audit.record_sync(AuditEvent {
            kind: "remote_access_resumed".into(),
            result_status: "ok".into(),
            ..Default::default()
        })?;
        self.local_mcp.resume();
        self.start_http().await?;
        self.emit_state();
        Ok(())
    }

    /// Disable remote access without the Emergency Stop latch (local pause).
    pub async fn pause_remote_access(self: &Arc<Self>) -> LpResult<()> {
        self.state.write_gate(false)?;
        self.state.set(ServerState::Paused);
        self.stop_http().await;
        self.invalidate_all("remote access paused", "cancelled");
        self.audit.record_sync(AuditEvent {
            kind: "remote_access_paused".into(),
            result_status: "ok".into(),
            ..Default::default()
        })?;
        self.emit_state();
        Ok(())
    }

    /// Enable remote access (setup completion or local toggle). Refuses while
    /// the Emergency Stop latch is set.
    pub async fn enable_remote_access(self: &Arc<Self>) -> LpResult<()> {
        if state::latch_get(&self.control).unwrap_or(true) {
            return Err(LpError::new(
                ErrorCode::EmergencyStopActive,
                "Emergency Stop is latched; use Resume to re-enable remote access.",
            ));
        }
        self.resume_remote_access().await
    }

    /// Restart the MCP listener/control subsystem (plan section 19).
    pub async fn restart_mcp(self: &Arc<Self>, terminate_tasks: bool) -> LpResult<()> {
        let prev = self.state.get();
        self.state.set(ServerState::Restarting);
        self.emit_state();
        self.stop_http().await;
        if terminate_tasks {
            self.tasks.kill_all();
        }
        self.invalidate_all("MCP restart", "invalidated");
        let _ = self.audit.record_sync(AuditEvent {
            kind: "mcp_restart".into(),
            result_status: "ok".into(),
            policy_detail: Some(format!("terminate_tasks={terminate_tasks}")),
            ..Default::default()
        });
        // Restart never clears Emergency Stop.
        if prev == ServerState::EmergencyStopped || state::latch_get(&self.control).unwrap_or(true)
        {
            self.state.set(ServerState::EmergencyStopped);
        } else if prev == ServerState::Ready
            || (self.state.gate_enabled() && self.settings.get().setup_completed)
        {
            if let Err(e) = self.start_http().await {
                self.state.set(ServerState::Faulted);
                self.state.set_fault(Some(e.message));
            }
        } else {
            self.state.set(ServerState::Paused);
        }
        self.emit_state();
        Ok(())
    }

    /// Full stop: terminate tasks, stop MCP, flush.
    pub async fn shutdown(self: &Arc<Self>) {
        self.state.set(ServerState::Stopping);
        self.shutdown.cancel();
        self.stop_http().await;
        self.tasks.kill_all();
        self.helper.abort_all();
        self.index.stop_watcher();
        let _ = self.audit.record_sync(AuditEvent {
            kind: "shutdown".into(),
            result_status: "ok".into(),
            ..Default::default()
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // -------------------------------------------------------- sessions

    /// Connection policy + application session for an authenticated call.
    pub fn session_for(
        &self,
        p: &Principal,
        client_info: Option<String>,
        protocol: Option<String>,
        remote: Option<String>,
    ) -> LpResult<Session> {
        let s = self.settings.get();
        if !s.concurrency.allow_any_authenticated_client
            && !s
                .concurrency
                .allowed_client_ids
                .iter()
                .any(|c| c == &p.client_id)
        {
            return Err(LpError::new(
                ErrorCode::ClientDisabled,
                "This client is not in the local allow list.",
            ));
        }
        let active = self.sessions.active_client_ids();
        if !active.contains(&p.client_id) {
            let max = if s.concurrency.allow_multiple_agents {
                s.concurrency.max_simultaneous_clients
            } else {
                1
            };
            if active.len() >= max {
                return Err(LpError::new(
                    ErrorCode::ClientLimitReached,
                    "The maximum number of simultaneous clients is connected.",
                ));
            }
        }
        let (session, ended) = self.sessions.resolve(&p.client_id, &p.credential_id, &s)?;
        if let Some(e) = ended {
            self.on_session_ended(e);
        }
        let is_new = session.created_at == session.last_activity_at
            && time::now_ms() - session.created_at < 2000;
        self.auth
            .record_seen(&p.client_id, client_info, protocol, remote.clone());
        if is_new {
            self.auth.log_connection_event(
                Some(&p.client_id),
                Some(&p.credential_id),
                "session_started",
                None,
                remote.as_deref(),
            );
            self.events.emit(UiEvent::ClientConnected {
                client_id: p.client_id.clone(),
                display_name: p.display_name.clone(),
            });
        }
        Ok(session)
    }

    fn on_session_ended(&self, e: EndedSession) {
        let ids = self.approvals.invalidate(
            None,
            Some(&e.session.session_id),
            "invalidated",
            &format!("session {}", e.reason),
        );
        for id in ids {
            self.events.emit(UiEvent::ApprovalChanged {
                approval_id: id,
                status: "invalidated".into(),
            });
        }
        let s = self.settings.get();
        if s.sessions.terminate_tasks_on_expiry && e.reason.contains("expiry") {
            for t in self.tasks.list(Some(&e.session.client_id), true, 1000) {
                if t.session_id.as_deref() == Some(&e.session.session_id) {
                    let _ = self.tasks.kill(&t.task_id);
                }
            }
        }
        self.auth.log_connection_event(
            Some(&e.session.client_id),
            Some(&e.session.credential_id),
            "session_ended",
            Some(&e.reason),
            None,
        );
    }

    pub fn end_session(&self, session_id: &str, reason: &str) {
        if let Some(e) = self.sessions.end(session_id, reason) {
            let ids = self
                .approvals
                .invalidate(None, Some(session_id), "cancelled", reason);
            for id in ids {
                self.events.emit(UiEvent::ApprovalChanged {
                    approval_id: id,
                    status: "cancelled".into(),
                });
            }
            self.auth.log_connection_event(
                Some(&e.session.client_id),
                Some(&e.session.credential_id),
                "session_ended",
                Some(reason),
                None,
            );
        }
    }

    /// Revoke/disable consequences for a client (plan sections 17 and 21).
    pub fn client_access_removed(&self, client_id: &str, reason: &str) -> usize {
        for e in self.sessions.end_client(client_id, reason) {
            let _ = e;
        }
        let ids = self
            .approvals
            .invalidate(Some(client_id), None, "cancelled", reason);
        for id in ids {
            self.events.emit(UiEvent::ApprovalChanged {
                approval_id: id,
                status: "cancelled".into(),
            });
        }
        let killed = if self.settings.get().sessions.terminate_tasks_on_revoke {
            self.tasks.kill_client(client_id)
        } else {
            0
        };
        self.leases.release_client(client_id);
        self.events.emit(UiEvent::ClientDisconnected {
            client_id: client_id.to_string(),
            display_name: String::new(),
            reason: reason.to_string(),
        });
        killed
    }

    // ------------------------------------------------------- approvals

    pub fn request_approval(
        &self,
        ctx: &ToolCtx,
        req: &ApprovalRequirement,
        digest: String,
        mut summary: ApprovalSummary,
    ) -> LpResult<ApprovalView> {
        let s = self.settings.get();
        summary.session_scope_label = req.session_scope.describe();
        if summary.paths.is_empty() {
            summary.paths = req.paths.clone();
        }
        if summary.command.is_none() {
            summary.command = req.command.as_ref().map(|c| self.redactor.redact_string(c));
        }
        if summary.impact.is_empty() {
            summary.impact = req.impact.clone();
        }
        let def = self.tools.get(ctx.tool);
        let op = PendingOperation {
            tool_name: ctx.tool.to_string(),
            arguments: ctx.raw_args.clone(),
            descriptor_digest: digest,
            required_scopes: def
                .map(|d| d.scopes.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
            session_scope: req.session_scope.clone(),
        };
        let view = self.approvals.create(
            &ctx.principal,
            &ctx.session,
            ctx.tool,
            req,
            summary,
            op,
            s.policy_revision,
            s.sessions.pending_approval_minutes,
        )?;
        self.events.emit(UiEvent::ApprovalRequested {
            approval_id: view.approval_id.clone(),
            client: ctx.principal.display_name.clone(),
            summary: view
                .summary
                .command
                .clone()
                .unwrap_or_else(|| view.summary.paths.join(", ")),
            requires_admin: view.requires_admin,
        });
        Ok(view)
    }

    /// Local UI decision on an approval (the remote agent can never do this).
    pub fn decide_approval(
        &self,
        approval_id: &str,
        decision: LocalDecision,
    ) -> LpResult<ApprovalView> {
        let s = self.settings.get();
        let view =
            self.approvals
                .decide(approval_id, decision, s.sessions.pending_approval_minutes)?;
        if decision == LocalDecision::AllowSession
            && let Some(scope) = self.approvals.session_scope(approval_id)
        {
            let label = scope.describe();
            if let Err(e) = self.sessions.add_grant(
                &view.session_id,
                SessionGrant {
                    scope,
                    label,
                    approval_id: Some(approval_id.to_string()),
                    created_at: time::now_ms(),
                },
            ) {
                tracing::warn!(error = %e, "session grant not recorded (session ended)");
            }
        }
        let _ = self.audit.record_sync(AuditEvent {
            kind: "approval_decision".into(),
            client_id: Some(view.client_id.clone()),
            client_display_name: view.client_display_name.clone(),
            session_id: Some(view.session_id.clone()),
            tool_name: Some(view.tool_name.clone()),
            operation_category: Some(view.category.clone()),
            approval_id: Some(view.approval_id.clone()),
            approval_result: Some(view.status.clone()),
            paths: view.summary.paths.clone(),
            command: view.summary.command.clone(),
            result_status: "ok".into(),
            ..Default::default()
        });
        self.events.emit(UiEvent::ApprovalChanged {
            approval_id: approval_id.to_string(),
            status: view.status.clone(),
        });
        Ok(view)
    }

    // ----------------------------------------------------------- tasks

    pub fn task_owned_by(&self, task_id: &str, client_id: &str) -> bool {
        self.tasks
            .get(task_id)
            .map(|t| t.client_id == client_id)
            .unwrap_or(false)
    }

    /// Lock/lease check before mutating inside a trusted project.
    pub fn project_write_guard(
        &self,
        client_id: &str,
        path: &Path,
        task_id: Option<&str>,
    ) -> LpResult<()> {
        if !self.policy().roots.is_trusted(path) {
            return Ok(());
        }
        let Some(project) = self.index.top_project_for_path(path) else {
            return Ok(());
        };
        if project.locked {
            return Err(LpError::new(
                ErrorCode::ProjectLocked,
                format!("The user has locked '{}' for agents.", project.display_name),
            ));
        }
        let s = self.settings.get();
        self.leases.acquire(
            &project.project_id,
            client_id,
            task_id,
            s.concurrency.writer_lease_seconds as i64 * 1000,
            s.concurrency.allow_multiple_writers_per_project,
        )
    }

    pub fn schedule_index_refresh(self: &Arc<Self>) {
        if self.refresh_pending.swap(true, Ordering::SeqCst) {
            return;
        }
        let core = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            core.refresh_pending.store(false, Ordering::SeqCst);
            let index = core.index.clone();
            let _ = tokio::task::spawn_blocking(move || index.full_scan()).await;
            core.events.emit(UiEvent::ProjectsChanged);
        });
    }

    pub async fn run_elevated(
        &self,
        op: workstation_core::helper_ipc::AdminOperation,
    ) -> LpResult<workstation_core::helper_ipc::HelperResponse> {
        self.helper.run(op).await
    }

    // ------------------------------------------------------- settings

    /// Apply new settings from the local UI (validated, audited).
    pub async fn update_settings(self: &Arc<Self>, next: Settings) -> LpResult<Arc<Settings>> {
        let (prev, next) = self.settings.update(next)?;
        let shell_changed = prev.shell_protection.enabled != next.shell_protection.enabled;
        let network_changed = prev.network != next.network;
        self.rebuild_policy();
        self.tasks
            .set_max_output_bytes(next.process.max_output_bytes_per_task);
        self.sessions.apply_limits(&next);
        if prev.policy_revision != next.policy_revision {
            // Tightening must never be undermined by earlier grants: revoke
            // session grants and invalidate open approvals.
            self.sessions.clear_grants();
            let ids =
                self.approvals
                    .invalidate(None, None, "invalidated", "security settings changed");
            for id in ids {
                self.events.emit(UiEvent::ApprovalChanged {
                    approval_id: id,
                    status: "invalidated".into(),
                });
            }
        }
        let _ = self.audit.record_sync(AuditEvent {
            kind: "settings_change".into(),
            result_status: "ok".into(),
            policy_detail: Some(settings_diff(&prev, &next)),
            shell_checks: Some(next.shell_protection.enabled),
            ..Default::default()
        });
        if shell_changed {
            tracing::warn!(
                enabled = next.shell_protection.enabled,
                "shell protection checks changed"
            );
        }
        if network_changed && self.state.get() == ServerState::Ready {
            self.restart_mcp(false).await?;
        }
        self.events.emit(UiEvent::SettingsChanged {
            revision: next.policy_revision,
        });
        Ok(next)
    }

    pub async fn reset_settings(self: &Arc<Self>) -> LpResult<Arc<Settings>> {
        let s = self.settings.reset_to_defaults()?;
        self.rebuild_policy();
        let _ = self.audit.record_sync(AuditEvent {
            kind: "settings_reset".into(),
            result_status: "ok".into(),
            ..Default::default()
        });
        if self.state.get() == ServerState::Faulted {
            self.state.set(ServerState::Paused);
            self.state.set_fault(None);
        }
        self.emit_state();
        Ok(s)
    }

    // ---------------------------------------------------- background

    fn spawn_background(self: &Arc<Self>) {
        // Initial index scan + watcher.
        {
            let core = self.clone();
            tokio::spawn(async move {
                let index = core.index.clone();
                let root = core.trusted_root();
                if root.is_dir() {
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = index.full_scan();
                        let _ = index.start_watcher();
                    })
                    .await;
                    core.events.emit(UiEvent::ProjectsChanged);
                }
            });
        }
        // Task events: leases, notifications.
        {
            let core = self.clone();
            let mut rx = self.tasks.subscribe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = core.shutdown.cancelled() => break,
                        ev = rx.recv() => match ev {
                            Ok(workstation_executor::TaskEvent::Finished { task_id, client_id, status, .. }) => {
                                core.leases.release_task(&task_id);
                                core.events.emit(UiEvent::TaskChanged { task_id: task_id.clone(), status: status.as_str().into(), client_id: client_id.clone() });
                                if matches!(status, workstation_executor::TaskStatus::Failed | workstation_executor::TaskStatus::TimedOut) {
                                    let command = core.tasks.get(&task_id).map(|t| t.command).unwrap_or_default();
                                    core.events.emit(UiEvent::TaskFailed { task_id, client_id, command });
                                }
                            }
                            Ok(workstation_executor::TaskEvent::Started { task_id, client_id }) => {
                                core.events.emit(UiEvent::TaskChanged { task_id, status: "running".into(), client_id });
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(_) => break,
                        }
                    }
                }
            });
        }
        // Maintenance.
        {
            let core = self.clone();
            tokio::spawn(async move {
                core.local_mcp.auto_start().await;
                let mut tick: u64 = 0;
                loop {
                    tokio::select! {
                        _ = core.shutdown.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(15)) => {}
                    }
                    tick += 1;
                    core.maintenance_fast();
                    core.local_mcp.maintain().await;
                    if tick % 40 == 1 {
                        core.maintenance_slow().await;
                    }
                }
            });
        }
    }

    /// Session/approval expiry, task heartbeats, OAuth cleanup.
    pub fn maintenance_fast(&self) {
        for e in self.sessions.sweep() {
            self.on_session_ended(e);
        }
        for id in self.approvals.expire_sweep() {
            self.events.emit(UiEvent::ApprovalChanged {
                approval_id: id,
                status: "expired".into(),
            });
        }
        let s = self.settings.get();
        for (task_id, client_id) in self.tasks.running_ids() {
            self.sessions.touch_client(&client_id);
            self.leases
                .renew_task(&task_id, s.concurrency.writer_lease_seconds as i64 * 1000);
        }
        self.auth.oauth_cleanup();
        if let Some(f) = self.audit.fault() {
            self.events.emit(UiEvent::AuditFault { message: f });
        }
    }

    /// Retention, cache cleanup, task pruning (never blocks the UI).
    pub async fn maintenance_slow(&self) {
        let s = self.settings.get();
        let active: Vec<String> = self
            .sessions
            .list()
            .into_iter()
            .map(|x| x.session_id)
            .collect();
        let r = self
            .audit
            .run_retention(
                RetentionPolicy {
                    audit_retention_days: s.audit.retention_days,
                    audit_max_bytes: s.audit.max_size_mb * 1024 * 1024,
                    shared_retention_days: s.data_shared.retention_days,
                    shared_max_bytes: s.data_shared.max_size_mb * 1024 * 1024,
                    reserved_events_per_session: s.data_shared.reserved_events_per_session,
                },
                active,
            )
            .await;
        if let Err(e) = r {
            tracing::error!(error = %e, "retention failed");
        }
        let running: Vec<String> = self
            .tasks
            .running_ids()
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        self.cache.cleanup(
            &running,
            Duration::from_secs(s.cache_temp.finished_task_retention_hours * 3600),
        );
        let _ = self
            .tasks
            .prune(s.audit.retention_days as i64 * time::DAY_MS);
    }
}

fn settings_diff(a: &Settings, b: &Settings) -> String {
    let va = serde_json::to_value(a).unwrap_or_default();
    let vb = serde_json::to_value(b).unwrap_or_default();
    let mut changes = Vec::new();
    fn walk(prefix: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
        match (a, b) {
            (serde_json::Value::Object(ma), serde_json::Value::Object(mb)) => {
                for (k, vb) in mb {
                    let va = ma.get(k).unwrap_or(&serde_json::Value::Null);
                    walk(&format!("{prefix}{k}."), va, vb, out);
                }
            }
            _ if a != b => out.push(format!("{}: {} -> {}", prefix.trim_end_matches('.'), a, b)),
            _ => {}
        }
    }
    walk("", &va, &vb, &mut changes);
    changes.retain(|c| !c.starts_with("policy_revision"));
    let text = changes.join("; ");
    if text.len() > 4000 {
        let end = (0..=4000)
            .rev()
            .find(|&index| text.is_char_boundary(index))
            .unwrap_or(0);
        format!("{}…", &text[..end])
    } else {
        text
    }
}
