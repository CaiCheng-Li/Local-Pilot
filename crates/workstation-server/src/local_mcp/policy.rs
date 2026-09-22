//! Downstream permission adapter. Names/annotations can raise risk, never lower it.
use super::*;
use crate::{approvals::ApprovalSummary, tools::ToolCtx};
use workstation_policy::{
    ApprovalRequirement, Decision, EntryPoint, FsAccess, Risk, SessionScope, broker,
};

pub fn effective_risk(name: &str, args: &Value, configured: RiskClass) -> RiskClass {
    let name = name.to_ascii_lowercase();
    fn has_code(v: &Value) -> bool {
        match v {
            Value::Object(m) => m.iter().any(|(k, v)| {
                matches!(
                    k.to_ascii_lowercase().as_str(),
                    "code" | "script" | "python" | "command" | "shell" | "expression"
                ) || has_code(v)
            }),
            Value::Array(a) => a.iter().any(has_code),
            _ => false,
        }
    }
    if ["execute", "eval", "python", "script", "command", "shell"]
        .iter()
        .any(|x| name.contains(x))
        || has_code(args)
    {
        RiskClass::ArbitraryCode
    } else {
        configured
    }
}

pub fn authorize(
    ctx: &ToolCtx,
    config: &ServerConfig,
    tool: &str,
    args: &Value,
    descriptor: Value,
    lifecycle: bool,
) -> LpResult<()> {
    if ctx.core.settings.fault().is_some() {
        return Err(LpError::new(
            ErrorCode::ConfigFault,
            "Repair configuration before invoking MCP services",
        ));
    }
    let policy = config.tool_policies.get(tool).cloned().unwrap_or_default();
    if policy.permission == ToolPermission::Deny {
        return Err(LpError::new(
            ErrorCode::McpPermissionDenied,
            "Downstream tool is denied by local policy",
        ));
    }
    let risk = if lifecycle {
        RiskClass::ProcessExecution
    } else {
        effective_risk(tool, args, policy.risk)
    };
    let mut decisions = vec![];
    fn paths(
        ctx: &ToolCtx,
        value: &Value,
        key: &str,
        read: bool,
        out: &mut Vec<Decision>,
    ) -> LpResult<()> {
        match value {
            Value::Object(m) => {
                for (k, v) in m {
                    paths(ctx, v, k, read, out)?;
                }
            }
            Value::Array(a) => {
                for v in a {
                    paths(ctx, v, key, read, out)?;
                }
            }
            Value::String(s) => {
                let key = key.to_ascii_lowercase();
                if s.len() < 32768
                    && !s.is_empty()
                    && (Path::new(s).is_absolute()
                        || key.contains("path")
                        || key.contains("directory")
                        || matches!(key.as_str(), "file" | "filename" | "folder" | "cwd"))
                {
                    let canonical =
                        broker::resolve(s, &ctx.core.trusted_root(), &ctx.core.env, true)?;
                    let d = ctx.with_policy(EntryPoint::Structured, |e, pc| {
                        e.evaluate_fs(
                            &canonical.path,
                            if read {
                                FsAccess::Read
                            } else {
                                FsAccess::Write
                            },
                            pc,
                        )
                    });
                    out.push(d);
                }
            }
            _ => (),
        }
        Ok(())
    }
    paths(ctx, args, "", risk == RiskClass::ReadOnly, &mut decisions)?;
    let high = matches!(
        risk,
        RiskClass::ArbitraryCode
            | RiskClass::Unknown
            | RiskClass::ProcessExecution
            | RiskClass::FilesystemWrite
            | RiskClass::Network
    );
    let auto =
        !lifecycle && !high && (policy.permission == ToolPermission::Allow || config.trusted);
    let key = workstation_core::hashing::json_digest(
        &json!({"descriptor":descriptor,"arguments":args,"operation":tool}),
    );
    let scope = SessionScope::Exact {
        key,
        label: format!("Repeat this exact MCP operation on {}", config.name),
    };
    let grant = ctx
        .core
        .sessions
        .get(&ctx.session.session_id)
        .is_some_and(|s| s.scopes().iter().any(|g| g.covers(&scope)));
    if !auto && !grant {
        decisions.push(Decision::RequireApproval(ApprovalRequirement{
        category:"local_mcp".into(),reason:format!("{} / {}: {:?}. Downstream code runs with local user access.",config.name,tool,risk),
        impact:"Invoke the configured local MCP service; arbitrary code may access the host filesystem or network".into(),
        risk:if high{Risk::High}else{Risk::Medium},requires_admin:false,paths:vec![],command:Some(format!("{} / {}",config.id,tool)),session_scope:scope,
    }));
    }
    if decisions.is_empty() {
        decisions.push(Decision::allow());
    }
    ctx.note(|n| {
        n.category = Some("local_mcp".into());
        n.command = Some(format!("{} / {}", config.id, tool));
        n.source_path = Some(format!("mcp://{}/{}", config.id, tool));
    });
    ctx.authorize(
        decisions,
        descriptor,
        ApprovalSummary {
            paths: vec![],
            command: Some(format!("{} / {}", config.id, tool)),
            cwd: None,
            arguments: Some(ctx.core.redactor.redact_json(args).0),
            impact: format!("Downstream MCP action ({risk:?}); not an OS sandbox"),
            session_scope_label: String::new(),
        },
    )
}
