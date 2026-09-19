//! Structured administrative requests (plan sections 16 and 43).
//!
//! Agents never get a generic elevated shell. A closed set of structured
//! operations can be requested; each always requires local approval, and only
//! runs (after `approval_resume`) in a short-lived elevated helper that the
//! user confirms through the Windows UAC prompt.

use std::sync::Arc;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use workstation_core::LpResult;
use workstation_core::helper_ipc::{AdminOperation, ServiceAction, operation_digest};
use workstation_policy::EntryPoint;

use super::{Kind, ToolCtx, ToolMeta, ToolRegistry, ok};
use crate::approvals::ApprovalSummary;

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ServiceActionArg {
    Start,
    Stop,
    Restart,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum AdminKind {
    /// Start/stop/restart a Windows service (`service`, `action`).
    ServiceControl,
    /// Install a package machine-wide with winget (`package_id`, optional `version`).
    WingetInstall,
    /// Uninstall a winget package (`package_id`).
    WingetUninstall,
    /// Set a machine-level environment variable (`name`, `value`; omit `value` to remove).
    SetMachineEnvironment,
    /// Write a file that needs administrator rights, e.g. the hosts file (`path`, `content_base64`).
    WriteSystemFile,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminArgs {
    pub operation: AdminKind,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub action: Option<ServiceActionArg>,
    #[serde(default)]
    pub package_id: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub content_base64: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

pub fn register(r: &mut ToolRegistry) {
    r.add(
        ToolMeta {
            name: "admin_request",
            title: "Request administrative operation",
            description: "Request one structured administrative operation (service control, machine-wide winget install/uninstall, machine environment variable, protected system file write). Always requires local approval; after approval call approval_resume, and the user confirms elevation in Windows.",
            kind: Kind::Execute,
        },
        request,
    );
}

async fn request(ctx: Arc<ToolCtx>, a: AdminArgs) -> LpResult<Value> {
    let need = |v: Option<String>, what: &str| {
        v.ok_or_else(|| {
            workstation_core::LpError::invalid(format!("{what} is required for this operation"))
        })
    };
    let op = match a.operation {
        AdminKind::ServiceControl => AdminOperation::ServiceControl {
            service: need(a.service, "service")?,
            action: match a
                .action
                .ok_or_else(|| workstation_core::LpError::invalid("action is required"))?
            {
                ServiceActionArg::Start => ServiceAction::Start,
                ServiceActionArg::Stop => ServiceAction::Stop,
                ServiceActionArg::Restart => ServiceAction::Restart,
            },
        },
        AdminKind::WingetInstall => AdminOperation::WingetInstall {
            package_id: need(a.package_id, "package_id")?,
            version: a.version,
        },
        AdminKind::WingetUninstall => AdminOperation::WingetUninstall {
            package_id: need(a.package_id, "package_id")?,
        },
        AdminKind::SetMachineEnvironment => AdminOperation::SetMachineEnvironment {
            name: need(a.name, "name")?,
            value: a.value,
        },
        AdminKind::WriteSystemFile => AdminOperation::WriteSystemFile {
            path: need(a.path, "path")?,
            content_base64: need(a.content_base64, "content_base64")?,
        },
    };
    op.validate()?;
    let summary = op.summary();
    let digest = operation_digest(&op);
    ctx.note(|n| {
        n.command = Some(summary.clone());
        n.category = Some("admin".into());
        n.entry_point = Some(EntryPoint::Structured);
    });
    if let AdminOperation::WriteSystemFile { path, .. } = &op {
        // Protected and control-data rules still apply to elevated writes.
        let engine = ctx.core.policy();
        let p = std::path::Path::new(path);
        if engine.protected.check(p, false).is_some()
            || engine.roots.classify_class(p) == workstation_policy::PathClass::ControlData
        {
            return Err(workstation_core::LpError::protected());
        }
    }
    let d = ctx.with_policy(EntryPoint::Structured, |e, pc| {
        e.evaluate_admin(&summary, &digest, pc)
    });
    ctx.authorize(
        vec![d],
        json!({ "op": "admin", "digest": digest }),
        ApprovalSummary {
            paths: Vec::new(),
            command: Some(summary.clone()),
            cwd: None,
            arguments: Some(serde_json::to_value(&op).unwrap_or_default()),
            impact: format!("Runs with administrator rights after Windows elevation: {summary}"),
            session_scope_label: String::new(),
        },
    )?;
    let resp = ctx.core.run_elevated(op).await?;
    ok(
        json!({ "ok": resp.ok, "exit_code": resp.exit_code, "output": resp.output, "error": resp.error }),
    )
}
