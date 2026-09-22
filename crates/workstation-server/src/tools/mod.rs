//! MCP tool registry and the shared call pipeline.
//!
//! Every tool call goes through [`dispatch`]:
//! state gate → scope check → application session → audit intent (mutations)
//! → idempotency → handler (which consults the central policy evaluator) →
//! single redaction pass → size bound → durable Data Shared record → result.
//! Authorization never depends on tool annotations or model compliance.

pub mod admin;
pub mod approval;
pub mod fs;
pub mod git;
pub mod github;
pub mod local_mcp;
pub mod process;
pub mod projects;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;
use parking_lot::Mutex;
use rmcp::model::{CallToolResult, JsonObject, MetaObject, Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use workstation_audit::{AuditCompletion, AuditEvent, ShareRecord};
use workstation_core::{ErrorCode, LpError, LpResult};
use workstation_policy::{ApprovalRequirement, Decision, EntryPoint, PolicyContext, SessionScope};

use crate::Core;
use crate::approvals::{ApprovalSummary, IdemOutcome};
use crate::auth::{Principal, SCOPE_EXECUTE, SCOPE_READ, SCOPE_WRITE};
use crate::events::UiEvent;
use crate::sessions::Session;

pub type Handler =
    Arc<dyn Fn(Arc<ToolCtx>, Value) -> BoxFuture<'static, LpResult<Value>> + Send + Sync>;

pub struct ToolDef {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub schema: Arc<JsonObject>,
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
    pub scopes: &'static [&'static str],
    /// Durable audit intent before dispatch.
    pub mutating: bool,
    /// Status polling: does not count as session activity.
    pub poll: bool,
    pub handler: Handler,
}

#[derive(Clone, Copy)]
pub struct ToolMeta {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Read-only; `workstation:read`.
    Read,
    /// Read-only status polling; `workstation:read`.
    Poll,
    /// Filesystem/Git/GitHub mutation; `workstation:write`.
    Write,
    /// Destructive mutation; `workstation:write`.
    Destructive,
    /// Process execution; `workstation:execute`.
    Execute,
    /// Session/approval control; `workstation:read` (resume re-checks the original scopes).
    Control,
}

#[derive(Default)]
pub struct ToolRegistry {
    defs: Vec<Arc<ToolDef>>,
    by_name: HashMap<&'static str, Arc<ToolDef>>,
}

impl ToolRegistry {
    pub fn build() -> Self {
        let mut r = ToolRegistry::default();
        projects::register(&mut r);
        fs::register(&mut r);
        process::register(&mut r);
        git::register(&mut r);
        github::register(&mut r);
        approval::register(&mut r);
        admin::register(&mut r);
        local_mcp::register(&mut r);
        r
    }

    pub fn get(&self, name: &str) -> Option<Arc<ToolDef>> {
        self.by_name.get(name).cloned()
    }

    pub fn all(&self) -> &[Arc<ToolDef>] {
        &self.defs
    }

    /// Register a typed tool. Arguments are deserialized strictly into `A`.
    pub fn add<A, F, Fut>(&mut self, meta: ToolMeta, f: F)
    where
        A: DeserializeOwned + JsonSchema + Send + 'static,
        F: Fn(Arc<ToolCtx>, A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = LpResult<Value>> + Send + 'static,
    {
        let schema = rmcp::handler::server::common::schema_for_input::<A>()
            .unwrap_or_else(|e| panic!("invalid schema for {}: {e}", meta.name));
        let f = Arc::new(f);
        let handler: Handler = Arc::new(move |ctx, args| {
            let f = f.clone();
            Box::pin(async move {
                let a: A = serde_json::from_value(args)
                    .map_err(|e| LpError::invalid(format!("invalid arguments: {e}")))?;
                f(ctx, a).await
            })
        });
        let (read_only, destructive, scopes, mutating, poll): (
            bool,
            bool,
            &'static [&'static str],
            bool,
            bool,
        ) = match meta.kind {
            Kind::Read => (true, false, &[SCOPE_READ], false, false),
            Kind::Poll => (true, false, &[SCOPE_READ], false, true),
            Kind::Write => (false, false, &[SCOPE_WRITE], true, false),
            Kind::Destructive => (false, true, &[SCOPE_WRITE], true, false),
            Kind::Execute => (false, true, &[SCOPE_EXECUTE], true, false),
            Kind::Control => (false, false, &[SCOPE_READ], false, false),
        };
        let def = Arc::new(ToolDef {
            name: meta.name,
            title: meta.title,
            description: meta.description,
            schema,
            read_only,
            destructive,
            idempotent: read_only,
            open_world: false,
            scopes,
            mutating,
            poll,
            handler,
        });
        self.by_name.insert(meta.name, def.clone());
        self.defs.push(def);
    }

    /// MCP tool descriptors with annotations and security schemes.
    pub fn mcp_tools(&self) -> Vec<Tool> {
        self.defs
            .iter()
            .map(|d| {
                let schemes = security_schemes(d);
                let mut meta = JsonObject::new();
                meta.insert("securitySchemes".into(), schemes);
                let annotations = ToolAnnotations::with_title(d.title)
                    .read_only(d.read_only)
                    .destructive(d.destructive)
                    .idempotent(d.idempotent)
                    .open_world(d.open_world);
                Tool::new(d.name, d.description, d.schema.clone())
                    .with_title(d.title)
                    .with_annotations(annotations)
                    .with_meta(MetaObject(meta))
            })
            .collect()
    }
}

pub fn security_schemes(d: &ToolDef) -> Value {
    json!([{ "type": "oauth2", "scopes": d.scopes }])
}

// ----------------------------------------------------------------- context

#[derive(Debug, Clone, Default)]
pub struct CallNotes {
    pub paths: Vec<String>,
    pub cwd: Option<String>,
    pub command: Option<String>,
    pub project_id: Option<String>,
    pub task_id: Option<String>,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub decision: Option<String>,
    pub decision_detail: Option<String>,
    pub approval_id: Option<String>,
    pub approval_result: Option<String>,
    pub entry_point: Option<EntryPoint>,
    pub category: Option<String>,
    pub warnings: Vec<String>,
    pub source_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResumeGrant {
    pub approval_id: String,
    pub execution_id: String,
    pub descriptor_digest: String,
}

pub struct ToolCtx {
    pub cancel: tokio_util::sync::CancellationToken,
    pub core: Arc<Core>,
    pub principal: Principal,
    pub session: Session,
    pub tool: &'static str,
    pub request_id: String,
    pub raw_args: Value,
    pub resume: Option<ResumeGrant>,
    pub notes: Mutex<CallNotes>,
    pub audit_event_id: Mutex<Option<String>>,
}

impl ToolCtx {
    pub fn note(&self, f: impl FnOnce(&mut CallNotes)) {
        f(&mut self.notes.lock());
    }

    pub fn owns_task(&self, task_id: &str) -> bool {
        self.core.task_owned_by(task_id, &self.principal.client_id)
    }

    /// Evaluate with a policy context built from the caller's session.
    pub fn with_policy<T>(
        &self,
        entry: EntryPoint,
        f: impl FnOnce(&workstation_policy::PolicyEngine, &PolicyContext<'_>) -> T,
    ) -> T {
        let grants = self
            .core
            .sessions
            .get(&self.session.session_id)
            .map(|s| s.scopes())
            .unwrap_or_default();
        let owns = |t: &str| self.owns_task(t);
        let pc = PolicyContext {
            principal_id: &self.principal.client_id,
            entry,
            session_grants: &grants,
            owns_task: &owns,
        };
        let engine = self.core.policy();
        f(&engine, &pc)
    }

    /// Act on one or more policy decisions for this call. On
    /// `RequireApproval`, an approval is created (or, when resuming, the
    /// stored descriptor is checked) — see [`crate::approvals`].
    pub fn authorize(
        &self,
        decisions: Vec<Decision>,
        descriptor: Value,
        summary: ApprovalSummary,
    ) -> LpResult<()> {
        let mut reqs: Vec<ApprovalRequirement> = Vec::new();
        for d in decisions {
            self.note(|n| n.decision = Some(d.label().to_string()));
            match d {
                Decision::Allow { warnings } => self.note(|n| n.warnings.extend(warnings)),
                Decision::Deny { code, reason } => {
                    self.note(|n| {
                        n.decision = Some("deny".into());
                        n.decision_detail = Some(reason.clone());
                    });
                    return Err(LpError::new(code, reason));
                }
                Decision::RequireApproval(r) => reqs.push(r),
            }
        }
        if reqs.is_empty() {
            self.note(|n| {
                if n.decision.is_none() || n.decision.as_deref() == Some("allow") {
                    n.decision = Some("allow".into());
                }
            });
            return Ok(());
        }
        let digest = workstation_core::hashing::json_digest(&json!({
            "tool": self.tool,
            "arguments": self.raw_args,
            "descriptor": descriptor,
        }));
        if let Some(g) = &self.resume {
            if g.descriptor_digest == digest {
                self.note(|n| {
                    n.decision = Some("allow_by_approval".into());
                    n.approval_id = Some(g.approval_id.clone());
                    n.approval_result = Some("resumed".into());
                });
                return Ok(());
            }
            return Err(LpError::new(
                ErrorCode::ApprovalInvalidated,
                "The target, command or policy inputs changed since approval (for example a path now resolves elsewhere). Nothing was executed; request the operation again.",
            ));
        }
        let mut req = reqs[0].clone();
        if reqs.len() > 1 {
            req.reason = reqs
                .iter()
                .map(|r| r.reason.clone())
                .collect::<Vec<_>>()
                .join(" ");
            req.paths = reqs.iter().flat_map(|r| r.paths.clone()).collect();
            req.requires_admin = reqs.iter().any(|r| r.requires_admin);
            req.risk = reqs.iter().map(|r| r.risk).max().unwrap_or(req.risk);
            req.session_scope = SessionScope::Exact {
                key: digest.clone(),
                label: format!("repeat this exact {} call", self.tool),
            };
        }
        let view = self.core.request_approval(self, &req, digest, summary)?;
        self.note(|n| {
            n.decision = Some("require_approval".into());
            n.approval_id = Some(view.approval_id.clone());
            n.category = Some(req.category.clone());
        });
        Err(LpError::new(ErrorCode::ApprovalRequired, "Local user approval is required before this operation can run.").with_details(json!({
            "status": "approval_required",
            "approval_id": view.approval_id,
            "message": "Local user approval is required before this operation can run. Approval does not run it: after the user approves, call approval_resume with this approval_id (poll approval_status meanwhile).",
            "reason": req.reason,
            "category": req.category,
            "risk": req.risk,
            "requires_admin": req.requires_admin,
            "paths": req.paths,
            "session_scope": req.session_scope.describe(),
            "expires_at": workstation_core::time::ms_to_rfc3339(view.expires_at),
        })))
    }

    pub fn settings(&self) -> Arc<workstation_core::config::Settings> {
        self.core.settings.get()
    }
}

// --------------------------------------------------------------- dispatch

pub struct CallInput {
    pub cancel: tokio_util::sync::CancellationToken,
    pub name: String,
    pub arguments: Value,
    pub principal: Principal,
    pub protocol_version: Option<String>,
    pub client_info: Option<String>,
    pub remote_addr: Option<String>,
    pub request_id: String,
    /// Data Shared record IDs emitted in this HTTP response.
    pub share_ids: Option<Arc<Mutex<Vec<String>>>>,
}

fn error_value(e: &LpError) -> Value {
    let mut err = json!({ "code": e.code.as_str(), "message": e.message });
    if let Some(d) = &e.details {
        err["details"] = d.clone();
    }
    json!({ "error": err })
}

/// Shorten long strings/arrays for audit records and approval summaries.
pub fn truncate_args(v: &Value) -> Value {
    match v {
        Value::String(s) if s.len() > 2000 => {
            let end = (0..=2000)
                .rev()
                .find(|&index| s.is_char_boundary(index))
                .unwrap_or(0);
            Value::String(format!("{}…({} bytes)", &s[..end], s.len()))
        }
        Value::Array(a) => Value::Array(a.iter().take(100).map(truncate_args).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), truncate_args(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn www_authenticate_meta(core: &Core, scopes: &[&str]) -> MetaObject {
    let urls = core.public_urls();
    let mut m = JsonObject::new();
    m.insert(
        "mcp/www_authenticate".into(),
        json!([format!(
            "Bearer resource_metadata=\"{}\", error=\"insufficient_scope\", error_description=\"This tool needs the {} scope; reconnect to grant it\", scope=\"{}\"",
            urls.resource_metadata,
            scopes.join(" "),
            scopes.join(" ")
        )]),
    );
    MetaObject(m)
}

/// Run one tool call end to end.
pub async fn dispatch(core: Arc<Core>, input: CallInput) -> CallToolResult {
    let settings = core.settings.get();
    // 1. Availability gate.
    if !core.state.accepting() {
        let code = if core.state.get() == crate::state::ServerState::EmergencyStopped {
            ErrorCode::EmergencyStopActive
        } else {
            ErrorCode::ServiceUnavailable
        };
        return CallToolResult::structured_error(error_value(&LpError::new(
            code,
            "Remote access is currently disabled on this workstation.",
        )));
    }
    let Some(def) = core.tools.get(&input.name) else {
        return CallToolResult::structured_error(error_value(&LpError::not_found(format!(
            "unknown tool '{}'",
            input.name
        ))));
    };
    // 2. Scopes.
    if !def.scopes.iter().all(|s| input.principal.has_scope(s)) {
        let e = LpError::new(
            ErrorCode::InsufficientScope,
            format!("This tool requires the {} scope.", def.scopes.join(" ")),
        );
        return CallToolResult::structured_error(error_value(&e))
            .with_meta(Some(www_authenticate_meta(&core, def.scopes)));
    }
    // 3. Session.
    let session = match core.session_for(
        &input.principal,
        input.client_info.clone(),
        input.protocol_version.clone(),
        input.remote_addr.clone(),
    ) {
        Ok(s) => s,
        Err(e) => return CallToolResult::structured_error(error_value(&e)),
    };
    if !def.poll {
        core.sessions.touch(&session.session_id);
    }
    let redacted_args = core.redactor.redact_json(&input.arguments).0;
    let ctx = Arc::new(ToolCtx {
        cancel: input.cancel.clone(),
        core: core.clone(),
        principal: input.principal.clone(),
        session: session.clone(),
        tool: def.name,
        request_id: input.request_id.clone(),
        raw_args: input.arguments.clone(),
        resume: None,
        notes: Mutex::new(CallNotes::default()),
        audit_event_id: Mutex::new(None),
    });
    let base_event = AuditEvent {
        kind: "tool_call".into(),
        client_id: Some(input.principal.client_id.clone()),
        client_display_name: Some(input.principal.display_name.clone()),
        session_id: Some(session.session_id.clone()),
        mcp_protocol_version: input.protocol_version.clone(),
        tool_name: Some(def.name.to_string()),
        arguments: Some(truncate_args(&redacted_args)),
        shell_checks: Some(settings.shell_protection.enabled),
        result_status: "ok".into(),
        ..Default::default()
    };
    // 4. Durable intent for mutations.
    if def.mutating {
        match core.audit.intent(base_event.clone()).await {
            Ok(id) => *ctx.audit_event_id.lock() = Some(id),
            Err(e) => {
                core.events.emit(UiEvent::AuditFault {
                    message: e.message.clone(),
                });
                return CallToolResult::structured_error(
                    error_value(&LpError::audit_unavailable()),
                );
            }
        }
    }
    // 5. Idempotency.
    let idem_key = if def.mutating {
        input
            .arguments
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    };
    let mut replay: Option<Value> = None;
    if let Some(k) = &idem_key {
        let digest = workstation_core::hashing::json_digest(&input.arguments);
        match core
            .approvals
            .idem_begin(&input.principal.client_id, k, def.name, &digest)
        {
            Ok(IdemOutcome::Proceed) => {}
            Ok(IdemOutcome::Replay(v)) => replay = Some(v),
            Ok(IdemOutcome::InProgress) => {
                return finish(&core, &ctx, &def, base_event, Err(LpError::new(ErrorCode::IdempotencyConflict, "A call with this idempotency_key is still in progress or its outcome is unknown.")), input.share_ids, None).await;
            }
            Ok(IdemOutcome::Conflict) => {
                return finish(
                    &core,
                    &ctx,
                    &def,
                    base_event,
                    Err(LpError::new(
                        ErrorCode::IdempotencyConflict,
                        "This idempotency_key was already used with different arguments.",
                    )),
                    input.share_ids,
                    None,
                )
                .await;
            }
            Err(e) => {
                return finish(&core, &ctx, &def, base_event, Err(e), input.share_ids, None).await;
            }
        }
    }
    // 6. Handler.
    let result = match replay {
        Some(v) => Ok(v),
        None => run_handler(&def, ctx.clone(), input.arguments.clone()).await,
    };
    finish(
        &core,
        &ctx,
        &def,
        base_event,
        result,
        input.share_ids,
        idem_key,
    )
    .await
}

pub async fn run_handler(def: &ToolDef, ctx: Arc<ToolCtx>, args: Value) -> LpResult<Value> {
    let fut = (def.handler)(ctx, args);
    match tokio::spawn(fut).await {
        Ok(r) => r,
        Err(e) => Err(LpError::internal(format!("tool task failed: {e}"))),
    }
}

/// Map a handler result to the MCP result, record Data Shared and audit.
pub async fn finish(
    core: &Arc<Core>,
    ctx: &Arc<ToolCtx>,
    def: &ToolDef,
    base_event: AuditEvent,
    result: LpResult<Value>,
    share_ids: Option<Arc<Mutex<Vec<String>>>>,
    idem_key: Option<String>,
) -> CallToolResult {
    let settings = core.settings.get();
    let (value, is_error, status, err_code) = match &result {
        Ok(v) => (v.clone(), false, "ok".to_string(), None),
        Err(e) if e.code == ErrorCode::ApprovalRequired => (
            e.details
                .clone()
                .unwrap_or_else(|| json!({"status": "approval_required"})),
            false,
            "approval_required".to_string(),
            None,
        ),
        Err(e) => {
            if let Some(i) = &e.internal {
                tracing::warn!(tool = def.name, code = %e.code, internal = %i, "tool error");
            }
            let st = match e.code {
                ErrorCode::PermissionDenied
                | ErrorCode::ProtectedResource
                | ErrorCode::AttributionBlocked
                | ErrorCode::PathOutsidePolicy => "denied",
                _ => "error",
            };
            (error_value(e), true, st.to_string(), Some(e.code))
        }
    };
    // Single redaction pass over the outbound payload.
    let (redacted, report) = core.redactor.redact_json(&value);
    let mut call_result = if is_error {
        CallToolResult::structured_error(redacted.clone())
    } else {
        CallToolResult::structured(redacted.clone())
    };
    let mut bytes = serde_json::to_vec(&call_result).unwrap_or_default();
    if bytes.len() as u64 > settings.limits.max_result_bytes {
        let e = LpError::new(
            ErrorCode::OutputLimitReached,
            format!(
                "The result ({} bytes) exceeds the {} byte limit. Request a smaller range (offset/length, line ranges, max_results).",
                bytes.len(),
                settings.limits.max_result_bytes
            ),
        );
        call_result = CallToolResult::structured_error(error_value(&e));
        bytes = serde_json::to_vec(&call_result).unwrap_or_default();
    }
    let notes = ctx.notes.lock().clone();
    let audit_event_id = ctx.audit_event_id.lock().clone();
    // Durable Data Shared record before emission.
    let share = core
        .audit
        .record_share(ShareRecord {
            client_id: Some(ctx.principal.client_id.clone()),
            session_id: Some(ctx.session.session_id.clone()),
            tool_name: Some(def.name.to_string()),
            request_id: Some(ctx.request_id.clone()),
            audit_event_id: audit_event_id.clone(),
            source_path: notes.source_path.clone(),
            mime_type: "application/json".into(),
            payload: bytes,
            redaction: if report.is_empty() {
                None
            } else {
                serde_json::to_value(&report).ok()
            },
        })
        .await;
    let final_result = match share {
        Ok((id, _)) => {
            if let Some(t) = &share_ids {
                t.lock().push(id);
            }
            call_result
        }
        Err(_) => {
            core.events.emit(UiEvent::AuditFault {
                message: "Data Shared storage failed; data delivery is paused.".into(),
            });
            CallToolResult::structured_error(error_value(&LpError::audit_unavailable()))
        }
    };
    // Audit completion (queued with backpressure).
    let completion = AuditCompletion {
        result_status: status.clone(),
        policy_decision: notes.decision.clone(),
        policy_detail: notes
            .decision_detail
            .clone()
            .or_else(|| (!notes.warnings.is_empty()).then(|| notes.warnings.join("; "))),
        approval_id: notes.approval_id.clone(),
        approval_result: notes.approval_result.clone(),
        task_id: notes.task_id.clone(),
        pid: notes.pid,
        exit_code: notes.exit_code,
        stdout_bytes: None,
        stderr_bytes: None,
        error: err_code.map(|c| c.as_str().to_string()),
        paths: (!notes.paths.is_empty()).then(|| notes.paths.clone()),
    };
    match audit_event_id {
        Some(id) => core.audit.complete(&id, completion).await,
        None => {
            let mut ev = base_event;
            ev.result_status = status;
            ev.paths = notes.paths.clone();
            ev.cwd = notes.cwd.clone();
            ev.command = notes.command.clone();
            ev.project_id = notes.project_id.clone();
            ev.task_id = notes.task_id.clone();
            ev.policy_decision = notes.decision.clone();
            ev.policy_detail = completion.policy_detail.clone();
            ev.approval_id = notes.approval_id.clone();
            ev.error = completion.error.clone();
            ev.entry_point = notes.entry_point.map(|e| format!("{e:?}").to_lowercase());
            ev.operation_category = notes.category.clone();
            core.audit.record(ev).await;
        }
    }
    if let Some(k) = idem_key
        && !is_error
    {
        core.approvals
            .idem_finish(&ctx.principal.client_id, &k, &value);
    }
    final_result
}

/// Helper for handlers: serialize any serializable result.
pub fn ok<T: serde::Serialize>(v: T) -> LpResult<Value> {
    serde_json::to_value(v).map_err(LpError::internal)
}
