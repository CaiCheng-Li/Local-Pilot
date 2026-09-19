//! Approval polling/resume and application-session tools (plan section 17).

use std::sync::Arc;

use parking_lot::Mutex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use workstation_audit::{AuditCompletion, AuditEvent};
use workstation_core::{ErrorCode, LpError, LpResult, time};

use super::{CallNotes, Kind, ResumeGrant, ToolCtx, ToolMeta, ToolRegistry, ok, run_handler};
use crate::approvals::ResumeStart;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalArgs {
    pub approval_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

pub fn register(r: &mut ToolRegistry) {
    use Kind::*;
    let m = |name, title, description, kind| ToolMeta {
        name,
        title,
        description,
        kind,
    };
    r.add(m("approval_status", "Approval status", "Check a pending approval (pending, allowed_once, allowed_session, denied, expired, cancelled, consumed, invalidated). Never executes anything.", Poll), status);
    r.add(
        m(
            "approval_resume",
            "Resume approved operation",
            "Run the exact operation stored with an approval after the user allowed it. Arguments cannot be changed; targets are re-validated. Repeated or concurrent calls return the same execution instead of running it again.",
            Control,
        ),
        resume,
    );
    r.add(
        m(
            "session_current",
            "Current session",
            "Your application session: expiry times and scoped session approvals.",
            Poll,
        ),
        current,
    );
    r.add(
        m(
            "session_end",
            "End session",
            "End your application session; session approvals and pending requests are cancelled.",
            Control,
        ),
        end,
    );
}

fn owned(ctx: &ToolCtx, id: &str) -> LpResult<crate::approvals::ApprovalView> {
    match ctx.core.approvals.get(id) {
        Some(a) if a.client_id == ctx.principal.client_id => Ok(a),
        _ => Err(LpError::not_found("unknown approval")),
    }
}

async fn status(ctx: Arc<ToolCtx>, a: ApprovalArgs) -> LpResult<Value> {
    let v = owned(&ctx, &a.approval_id)?;
    let exec = v
        .execution_id
        .as_ref()
        .and_then(|e| ctx.core.approvals.execution(e));
    let next = match v.status.as_str() {
        "pending" => "Wait for the user to decide in Local Pilot, then call approval_resume.",
        "allowed_once" | "allowed_session" if exec.is_none() => {
            "Approved: call approval_resume with this approval_id to run the operation."
        }
        "consumed" | "allowed_session" => {
            "Already executed; approval_resume returns the recorded result."
        }
        _ => "This approval cannot be used; request the operation again if still needed.",
    };
    ok(json!({
        "approval_id": v.approval_id,
        "status": v.status,
        "tool": v.tool_name,
        "reason": v.reason,
        "expires_at": time::ms_to_rfc3339(v.expires_at),
        "execution": exec.map(|e| json!({ "execution_id": e.execution_id, "status": e.status })),
        "next_step": next,
    }))
}

async fn resume(ctx: Arc<ToolCtx>, a: ApprovalArgs) -> LpResult<Value> {
    let core = ctx.core.clone();
    let policy_revision = core.settings.get().policy_revision;
    match core.approvals.begin_resume(
        &a.approval_id,
        &ctx.principal,
        &ctx.session,
        policy_revision,
    )? {
        ResumeStart::Existing(e) => {
            if e.status == "dispatched" {
                return ok(
                    json!({ "status": "executing", "execution_id": e.execution_id, "message": "The approved operation is running; call approval_resume again later for its result." }),
                );
            }
            if e.status == "outcome_unknown" {
                return Err(LpError::new(
                    ErrorCode::OutcomeUnknown,
                    "Local Pilot stopped after dispatching this operation; its outcome is unknown and it will not be replayed. Check the target state before retrying.",
                ));
            }
            ok(
                json!({ "status": e.status, "execution_id": e.execution_id, "already_executed": true, "result": e.result }),
            )
        }
        ResumeStart::Dispatch {
            op,
            execution_id,
            approval,
        } => {
            let Some(def) = core.tools.get(&op.tool_name) else {
                core.approvals
                    .complete_execution(&execution_id, "failed", None, None);
                return Err(LpError::internal("approved tool no longer exists"));
            };
            let inner = Arc::new(ToolCtx {
                core: core.clone(),
                principal: ctx.principal.clone(),
                session: ctx.session.clone(),
                tool: def.name,
                request_id: ctx.request_id.clone(),
                raw_args: op.arguments.clone(),
                resume: Some(ResumeGrant {
                    approval_id: approval.approval_id.clone(),
                    execution_id: execution_id.clone(),
                    descriptor_digest: op.descriptor_digest.clone(),
                }),
                notes: Mutex::new(CallNotes::default()),
                audit_event_id: Mutex::new(None),
            });
            // Execution is logged separately from the permission decision.
            let intent = core
                .audit
                .intent(AuditEvent {
                    kind: "approved_execution".into(),
                    client_id: Some(ctx.principal.client_id.clone()),
                    client_display_name: Some(ctx.principal.display_name.clone()),
                    session_id: Some(ctx.session.session_id.clone()),
                    tool_name: Some(def.name.to_string()),
                    arguments: Some(super::truncate_args(
                        &core.redactor.redact_json(&op.arguments).0,
                    )),
                    approval_id: Some(approval.approval_id.clone()),
                    approval_result: Some(approval.status.clone()),
                    shell_checks: Some(core.settings.get().shell_protection.enabled),
                    result_status: "intent".into(),
                    ..Default::default()
                })
                .await;
            let event_id = match intent {
                Ok(id) => id,
                Err(e) => {
                    core.approvals
                        .complete_execution(&execution_id, "failed", None, None);
                    return Err(e);
                }
            };
            *inner.audit_event_id.lock() = Some(event_id.clone());
            let result = run_handler(&def, inner.clone(), op.arguments.clone()).await;
            let notes = inner.notes.lock().clone();
            let (status, value) = match &result {
                Ok(v) => ("completed", core.redactor.redact_json(v).0),
                Err(e) => (
                    "failed",
                    json!({ "error": { "code": e.code.as_str(), "message": e.message } }),
                ),
            };
            core.approvals.complete_execution(
                &execution_id,
                status,
                Some(&value),
                notes.task_id.as_deref(),
            );
            core.audit
                .complete(
                    &event_id,
                    AuditCompletion {
                        result_status: if status == "completed" {
                            "ok".into()
                        } else {
                            "error".into()
                        },
                        policy_decision: notes.decision.clone(),
                        task_id: notes.task_id.clone(),
                        pid: notes.pid,
                        exit_code: notes.exit_code,
                        paths: (!notes.paths.is_empty()).then(|| notes.paths.clone()),
                        error: result.as_ref().err().map(|e| e.code.as_str().to_string()),
                        approval_id: Some(approval.approval_id.clone()),
                        ..Default::default()
                    },
                )
                .await;
            ctx.note(|n| {
                n.approval_id = Some(approval.approval_id.clone());
                n.approval_result = Some("resumed".into());
                n.paths = notes.paths.clone();
                n.task_id = notes.task_id.clone();
                n.source_path = notes.source_path.clone();
            });
            core.events.emit(crate::events::UiEvent::ApprovalChanged {
                approval_id: approval.approval_id.clone(),
                status: "executed".into(),
            });
            match result {
                Ok(v) => ok(
                    json!({ "status": "executed", "execution_id": execution_id, "approval_id": approval.approval_id, "result": v }),
                ),
                Err(e) => Err(e),
            }
        }
    }
}

async fn current(ctx: Arc<ToolCtx>, _a: Empty) -> LpResult<Value> {
    let s = ctx
        .core
        .sessions
        .get(&ctx.session.session_id)
        .unwrap_or_else(|| ctx.session.clone());
    ok(json!({
        "session_id": s.session_id,
        "client_id": ctx.principal.client_id,
        "client_name": ctx.principal.display_name,
        "auth_method": ctx.principal.auth_method,
        "scopes": ctx.principal.scopes,
        "created_at": time::ms_to_rfc3339(s.created_at),
        "idle_expires_at": time::ms_to_rfc3339(s.idle_expires_at()),
        "absolute_expires_at": time::ms_to_rfc3339(s.absolute_expires_at),
        "session_approvals": s.grants.iter().map(|g| g.label.clone()).collect::<Vec<_>>(),
        "trusted_workspace": ctx.core.trusted_root().display().to_string(),
        "shell_protection_checks": ctx.settings().shell_protection.enabled,
    }))
}

async fn end(ctx: Arc<ToolCtx>, _a: Empty) -> LpResult<Value> {
    ctx.core
        .end_session(&ctx.session.session_id, "ended by client");
    ok(json!({ "ended": true, "session_id": ctx.session.session_id }))
}
