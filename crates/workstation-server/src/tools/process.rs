//! Process, shell and task tools (plan section 5).
//!
//! Raw PowerShell/cmd are first-class features. Layer B checks (command
//! classification, PowerShell AST inspection, path extraction) run when shell
//! protection checks are ON; they are best effort. Every launch runs as a
//! standard user inside its own Job Object with redirected TEMP/caches, a task
//! ID, bounded output and a timeout.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use workstation_core::{ErrorCode, LpError, LpResult, ids};
use workstation_executor::{SpawnSpec, TaskSpec, cmd_exe, resolve_executable};
use workstation_policy::command::Analyzer;
use workstation_policy::command::tokenize::quote_arg;
use workstation_policy::{EntryPoint, FsAccess, broker};

use super::{Kind, ToolCtx, ToolMeta, ToolRegistry, ok};
use crate::approvals::ApprovalSummary;
use crate::environment;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunArgs {
    /// Program name (resolved on PATH) or path, e.g. `npm`, `cargo`, `.\\tools\\gen.exe`.
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory (default: the project, or Documents\Projects).
    #[serde(default)]
    pub cwd: Option<String>,
    /// Project ID or name used as the default working directory.
    #[serde(default)]
    pub project: Option<String>,
    /// Extra environment variables for this process (identity/credential variables cannot be set).
    #[serde(default)]
    pub env_overrides: Option<std::collections::BTreeMap<String, String>>,
    /// Kill the process tree after this many seconds.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Return immediately with a task ID instead of waiting.
    #[serde(default)]
    pub background: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PowerShellArgs {
    /// PowerShell script text.
    pub script: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub background: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CmdArgs {
    /// Command line for cmd.exe.
    pub command: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub background: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskIdArgs {
    pub task_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskListArgs {
    /// Only running tasks.
    #[serde(default)]
    pub active_only: Option<bool>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskOutputArgs {
    pub task_id: String,
    /// Offset returned as `next_offset` by the previous call (default: oldest retained output).
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

pub fn register(r: &mut ToolRegistry) {
    use Kind::*;
    let m = |name, title, description, kind| ToolMeta {
        name,
        title,
        description,
        kind,
    };
    r.add(m("process_run", "Run program", "Run an executable with an argument list (no shell). Runs as a standard user in a Job Object; returns output when it finishes within the wait window, otherwise a task_id to poll with task_output.", Execute), run);
    r.add(m("shell_powershell", "Run PowerShell", "Run a PowerShell script. Output is captured and redacted; long work continues as a task (poll task_output, stop with task_cancel/task_kill).", Execute), powershell);
    r.add(
        m(
            "shell_cmd",
            "Run cmd",
            "Run a Command Prompt command line.",
            Execute,
        ),
        cmd,
    );
    r.add(
        m("task_get", "Get task", "Status of one of your tasks.", Poll),
        task_get,
    );
    r.add(
        m("task_list", "List tasks", "List your tasks.", Poll),
        task_list,
    );
    r.add(
        m(
            "task_output",
            "Task output",
            "Read task output incrementally from an offset (bounded).",
            Poll,
        ),
        task_output,
    );
    r.add(m("task_cancel", "Cancel task", "Request cancellation (Ctrl+Break, then terminate the tree after a short grace period).", Execute), task_cancel);
    r.add(
        m(
            "task_kill",
            "Kill task",
            "Terminate the task's whole process tree immediately.",
            Execute,
        ),
        task_kill,
    );
}

enum Launch {
    Process { exe: PathBuf, args: Vec<String> },
    PowerShell { script: String },
    Cmd { command: String },
}

fn resolve_cwd(ctx: &ToolCtx, cwd: Option<&str>, project: Option<&str>) -> LpResult<PathBuf> {
    let root = ctx.core.trusted_root();
    let input = match (cwd, project) {
        (Some(c), _) => c.to_string(),
        (None, Some(p)) => ctx
            .core
            .index
            .get(p)
            .map(|x| x.canonical_path)
            .ok_or_else(|| {
                LpError::new(ErrorCode::ProjectNotFound, format!("unknown project '{p}'"))
            })?,
        (None, None) => root.display().to_string(),
    };
    let c = broker::resolve(&input, &root, &ctx.core.env, true)?;
    if !c.exists || !c.is_dir {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("working directory {} does not exist", c.path.display()),
        ));
    }
    let d = ctx.with_policy(EntryPoint::RawShell, |e, pc| {
        e.evaluate_fs(&c.path, FsAccess::List, pc)
    });
    if let workstation_policy::Decision::Deny { code, reason } = d {
        return Err(LpError::new(code, reason));
    }
    Ok(c.path)
}

fn exe_identity(p: &Path) -> Value {
    let md = std::fs::metadata(p).ok();
    json!({
        "path": p.display().to_string(),
        "size": md.as_ref().map(|m| m.len()),
        "modified": md.and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64),
    })
}

fn batch_command_line(exe: &Path, args: &[String]) -> LpResult<String> {
    let mut s = format!("\"{}\"", exe.display());
    for a in args {
        if a.chars()
            .any(|c| matches!(c, '"' | '%' | '!' | '\r' | '\n' | '\0'))
        {
            return Err(LpError::invalid(
                "Arguments to .cmd/.bat programs may not contain quotes, %, ! or line breaks; use shell_cmd for full cmd syntax.",
            ));
        }
        if a.is_empty() || a.chars().any(|c| " \t&|<>^(),;=".contains(c)) {
            s.push_str(&format!(" \"{a}\""));
        } else {
            s.push(' ');
            s.push_str(a);
        }
    }
    Ok(format!("cmd.exe /d /s /c \"{s}\""))
}

fn powershell_exe(ctx: &ToolCtx, env: &[(String, String)]) -> LpResult<PathBuf> {
    let configured = ctx.settings().process.powershell_executable.clone();
    resolve_executable(&configured, &ctx.core.trusted_root(), env).ok_or_else(|| {
        LpError::new(
            ErrorCode::CommandFailed,
            format!("PowerShell executable '{configured}' was not found"),
        )
    })
}

async fn launch(
    ctx: Arc<ToolCtx>,
    launch: Launch,
    cwd: PathBuf,
    overrides: Vec<(String, String)>,
    timeout: Option<u64>,
    background: bool,
) -> LpResult<Value> {
    let settings = ctx.settings();
    let core = ctx.core.clone();
    let principal = ctx.principal.clone();
    // Per-client task limit.
    if core.tasks.running_count(&principal.client_id) >= settings.concurrency.max_tasks_per_client {
        return Err(LpError::new(
            ErrorCode::RateLimited,
            "You already have the maximum number of running tasks; wait for one to finish or kill one.",
        ));
    }
    let timeout_s = timeout
        .unwrap_or(settings.process.default_timeout_seconds)
        .clamp(1, settings.process.max_timeout_seconds);
    let task_id = ids::task_id();

    // Environment used for executable resolution (PATH) and the child.
    let base_env = environment::build(
        &settings,
        None,
        &cwd,
        &overrides,
        &std::env::temp_dir(),
        None,
    )?;
    let (exe, command_line, display, kind, analysis) = {
        let program_in_trusted = |tok: &str| -> bool {
            resolve_executable(tok, &cwd, &base_env.vars)
                .map(|p| core.policy().roots.is_trusted(&p))
                .unwrap_or(false)
        };
        let ps_parser = settings.process.powershell_executable.clone();
        let analyzer = Analyzer {
            powershell_exe: &ps_parser,
            program_in_trusted: &program_in_trusted,
        };
        let checks = settings.shell_protection.enabled;
        match &launch {
            Launch::Process { exe, args } => {
                let ext = exe
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                let cl = if ext == "cmd" || ext == "bat" {
                    batch_command_line(exe, args)?
                } else {
                    std::iter::once(quote_arg(&exe.display().to_string()))
                        .chain(args.iter().map(|a| quote_arg(a)))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                let app = if ext == "cmd" || ext == "bat" {
                    cmd_exe()
                } else {
                    exe.clone()
                };
                let display = std::iter::once(exe.display().to_string())
                    .chain(args.iter().map(|a| quote_arg(a)))
                    .collect::<Vec<_>>()
                    .join(" ");
                let analysis =
                    checks.then(|| analyzer.analyze_process(&exe.display().to_string(), args));
                (app, cl, display, "process", analysis)
            }
            Launch::Cmd { command } => {
                if command.len() > settings.process.max_command_length {
                    return Err(LpError::new(ErrorCode::TooLarge, "command is too long"));
                }
                let cl = format!("cmd.exe /d /s /c \"chcp 65001>nul & {command}\"");
                let analysis = checks.then(|| analyzer.analyze_cmd(command));
                (cmd_exe(), cl, command.clone(), "cmd", analysis)
            }
            Launch::PowerShell { script } => {
                if script.len() > settings.process.max_command_length * 4 {
                    return Err(LpError::new(
                        ErrorCode::TooLarge,
                        "script is too long; write it to a .ps1 file in the project and run that",
                    ));
                }
                let ps = powershell_exe(&ctx, &base_env.vars)?;
                let analysis = checks.then(|| analyzer.analyze_powershell(script));
                (
                    ps.clone(),
                    String::new(),
                    script.clone(),
                    "powershell",
                    analysis,
                )
            }
        }
    };
    let display_redacted = core.redactor.redact_string(&display);
    ctx.note(|n| {
        n.cwd = Some(cwd.display().to_string());
        n.command = Some(display_redacted.clone());
        n.entry_point = Some(EntryPoint::RawShell);
        n.task_id = Some(task_id.clone());
    });

    // Policy (Layer B preflight when checks are ON; structured cwd rules always).
    let decision = {
        let git_facts = |g: &workstation_policy::command::git::GitCommand| {
            super::git::facts_for_command(&cwd, g)
        };
        let read_file = |p: &Path| -> Option<String> {
            let engine = core.policy();
            if engine.protected.check(p, true).is_some() {
                return None;
            }
            std::fs::read_to_string(p)
                .ok()
                .filter(|s| s.len() < 1_000_000)
        };
        let empty = workstation_policy::command::CommandAnalysis {
            kind: workstation_policy::command::ShellKind::Process,
            findings: Vec::new(),
            parse_errors: Vec::new(),
        };
        let a = analysis.as_ref().unwrap_or(&empty);
        ctx.with_policy(EntryPoint::RawShell, |e, pc| {
            e.evaluate_command(a, &cwd, &display, &git_facts, &read_file, pc)
        })
    };
    let descriptor = json!({
        "kind": kind,
        "executable": exe_identity(&exe),
        "command_digest": workstation_core::hashing::sha256_hex(display.as_bytes()),
        "cwd": cwd.display().to_string(),
        "cwd_identity": broker::resolve(&cwd.display().to_string(), &cwd, &core.env, true).map(|c| broker::identity_string(&c)).unwrap_or_default(),
        "env_overrides": overrides,
        "timeout": timeout_s,
    });
    ctx.authorize(
        vec![decision],
        descriptor,
        ApprovalSummary {
            paths: Vec::new(),
            command: Some(display_redacted.clone()),
            cwd: Some(cwd.display().to_string()),
            arguments: None,
            impact: format!(
                "Runs a {kind} command as a standard user in {}",
                cwd.display()
            ),
            session_scope_label: String::new(),
        },
    )?;

    // Project lock / writer lease (unknown commands are potential writers).
    let read_only = analysis.as_ref().map(|a| a.is_read_only()).unwrap_or(false);
    let project = core.index.top_project_for_path(&cwd);
    if let Some(p) = &project {
        ctx.note(|n| n.project_id = Some(p.project_id.clone()));
        if !read_only {
            core.project_write_guard(&principal.client_id, &cwd, Some(&task_id))?;
        } else if p.locked {
            return Err(LpError::new(
                ErrorCode::ProjectLocked,
                "The user has locked this project for agents.",
            ));
        }
    }

    // Cache/temp allocation and the final environment.
    let profile = environment::tool_profile_for(&exe);
    let (task_dir, tool_dir) = core.cache.allocate(
        &task_id,
        &profile,
        &principal.client_id,
        settings.cache_temp.quota_mb,
    )?;
    let env = environment::build(
        &settings,
        Some(&exe),
        &cwd,
        &overrides,
        &task_dir,
        Some(&tool_dir),
    )?;
    let (application, command_line) = match &launch {
        Launch::PowerShell { script } => {
            let preamble = "$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8\n";
            let full = format!("{preamble}{script}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(
                full.encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<u8>>(),
            );
            let ps = exe.clone();
            if encoded.len() < 30_000 {
                (
                    ps.clone(),
                    format!(
                        "{} -NoProfile -NonInteractive -NoLogo -EncodedCommand {encoded}",
                        quote_arg(&ps.display().to_string())
                    ),
                )
            } else {
                // Too long for a command line: run from the task's temp directory.
                let file = task_dir.join("script.ps1");
                let mut bytes = vec![0xEF, 0xBB, 0xBF];
                bytes.extend(full.as_bytes());
                std::fs::write(&file, bytes).map_err(LpError::internal)?;
                (
                    ps.clone(),
                    format!(
                        "{} -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass -File {}",
                        quote_arg(&ps.display().to_string()),
                        quote_arg(&file.display().to_string())
                    ),
                )
            }
        }
        _ => (exe.clone(), command_line),
    };
    let spec = TaskSpec {
        client_id: principal.client_id.clone(),
        session_id: Some(ctx.session.session_id.clone()),
        tool_name: ctx.tool.to_string(),
        kind: kind.to_string(),
        display_command: display_redacted.clone(),
        project_id: project.as_ref().map(|p| p.project_id.clone()),
        spawn: SpawnSpec {
            application,
            command_line,
            cwd: cwd.clone(),
            env: env.vars,
        },
        timeout: Duration::from_secs(timeout_s),
        audit_event_id: ctx.audit_event_id.lock().clone(),
        approval_id: ctx.resume.as_ref().map(|r| r.approval_id.clone()),
        execution_id: ctx.resume.as_ref().map(|r| r.execution_id.clone()),
        warnings: ctx.notes.lock().warnings.clone(),
        cache_dir: Some(task_dir),
    };
    let tasks = core.tasks.clone();
    let tid = task_id.clone();
    let info = tokio::task::spawn_blocking(move || tasks.launch(&tid, spec))
        .await
        .map_err(LpError::internal)??;
    ctx.note(|n| n.pid = info.pid);
    let wait = if background {
        Duration::ZERO
    } else {
        Duration::from_secs(settings.process.foreground_wait_seconds.min(timeout_s))
    };
    let info = if wait.is_zero() {
        info
    } else {
        core.tasks.wait(&task_id, wait).await.unwrap_or(info)
    };
    if let Some(code) = info.exit_code {
        ctx.note(|n| n.exit_code = Some(code as i32));
    }
    let max_out = settings.limits.max_task_output_bytes_per_call;
    let output = if background {
        None
    } else {
        core.tasks.output(&task_id, None, max_out).ok()
    };
    let text: Option<String> = output
        .as_ref()
        .map(|o| o.chunks.iter().map(|c| c.text.as_str()).collect());
    ok(json!({
        "task_id": task_id,
        "status": info.status,
        "pid": info.pid,
        "exit_code": info.exit_code,
        "cwd": cwd.display().to_string(),
        "standard_user_token": info.standard_user_token,
        "warnings": ctx.notes.lock().warnings,
        "output": text,
        "output_next_offset": output.as_ref().map(|o| o.next_offset),
        "output_more_available": output.as_ref().map(|o| o.more_available),
        "hint": if info.status.is_terminal() { None } else { Some("Still running: poll task_output with output_next_offset, or task_cancel/task_kill.") },
    }))
}

fn overrides_of(m: Option<std::collections::BTreeMap<String, String>>) -> Vec<(String, String)> {
    m.map(|m| m.into_iter().collect()).unwrap_or_default()
}

async fn run(ctx: Arc<ToolCtx>, a: RunArgs) -> LpResult<Value> {
    let cwd = resolve_cwd(&ctx, a.cwd.as_deref(), a.project.as_deref())?;
    let overrides = overrides_of(a.env_overrides);
    let settings = ctx.settings();
    let env = environment::build(
        &settings,
        None,
        &cwd,
        &overrides,
        &std::env::temp_dir(),
        None,
    )?;
    let exe = resolve_executable(&a.executable, &cwd, &env.vars).ok_or_else(|| {
        LpError::new(
            ErrorCode::PathNotFound,
            format!(
                "executable '{}' was not found on PATH or relative to the working directory",
                a.executable
            ),
        )
    })?;
    // The executable itself must not be control data or protected.
    let d = ctx.with_policy(EntryPoint::RawShell, |e, pc| {
        e.evaluate_fs(&exe, FsAccess::Metadata, pc)
    });
    if let workstation_policy::Decision::Deny { code, reason } = d {
        return Err(LpError::new(code, reason));
    }
    if ctx.core.policy().roots.classify_class(&exe) == workstation_policy::PathClass::ControlData {
        return Err(LpError::denied(
            "Local Pilot's own executables cannot be launched by agents.",
        ));
    }
    launch(
        ctx,
        Launch::Process { exe, args: a.args },
        cwd,
        overrides,
        a.timeout_seconds,
        a.background.unwrap_or(false),
    )
    .await
}

async fn powershell(ctx: Arc<ToolCtx>, a: PowerShellArgs) -> LpResult<Value> {
    let cwd = resolve_cwd(&ctx, a.cwd.as_deref(), a.project.as_deref())?;
    launch(
        ctx,
        Launch::PowerShell { script: a.script },
        cwd,
        Vec::new(),
        a.timeout_seconds,
        a.background.unwrap_or(false),
    )
    .await
}

async fn cmd(ctx: Arc<ToolCtx>, a: CmdArgs) -> LpResult<Value> {
    let cwd = resolve_cwd(&ctx, a.cwd.as_deref(), a.project.as_deref())?;
    launch(
        ctx,
        Launch::Cmd { command: a.command },
        cwd,
        Vec::new(),
        a.timeout_seconds,
        a.background.unwrap_or(false),
    )
    .await
}

fn owned_task(ctx: &ToolCtx, task_id: &str) -> LpResult<workstation_executor::TaskInfo> {
    match ctx.core.tasks.get(task_id) {
        Some(t) if t.client_id == ctx.principal.client_id => Ok(t),
        _ => Err(LpError::new(ErrorCode::TaskNotFound, "unknown task")),
    }
}

async fn task_get(ctx: Arc<ToolCtx>, a: TaskIdArgs) -> LpResult<Value> {
    ok(owned_task(&ctx, &a.task_id)?)
}

async fn task_list(ctx: Arc<ToolCtx>, a: TaskListArgs) -> LpResult<Value> {
    let tasks = ctx.core.tasks.list(
        Some(&ctx.principal.client_id),
        a.active_only.unwrap_or(false),
        a.limit.unwrap_or(50).min(200),
    );
    ok(json!({ "count": tasks.len(), "tasks": tasks }))
}

async fn task_output(ctx: Arc<ToolCtx>, a: TaskOutputArgs) -> LpResult<Value> {
    owned_task(&ctx, &a.task_id)?;
    let max = a
        .max_bytes
        .unwrap_or(64 * 1024)
        .min(ctx.settings().limits.max_task_output_bytes_per_call);
    let slice = ctx.core.tasks.output(&a.task_id, a.offset, max)?;
    let text: String = slice.chunks.iter().map(|c| c.text.as_str()).collect();
    ok(json!({
        "task_id": slice.task_id,
        "status": slice.status,
        "output": text,
        "chunks": slice.chunks.iter().map(|c| json!({"stream": c.stream, "offset": c.offset, "bytes": c.text.len()})).collect::<Vec<_>>(),
        "next_offset": slice.next_offset,
        "more_available": slice.more_available,
        "truncated_before": slice.truncated_before,
        "total_bytes": slice.total_bytes,
    }))
}

async fn task_cancel(ctx: Arc<ToolCtx>, a: TaskIdArgs) -> LpResult<Value> {
    owned_task(&ctx, &a.task_id)?;
    ctx.note(|n| n.task_id = Some(a.task_id.clone()));
    ok(ctx.core.tasks.cancel(&a.task_id)?)
}

async fn task_kill(ctx: Arc<ToolCtx>, a: TaskIdArgs) -> LpResult<Value> {
    owned_task(&ctx, &a.task_id)?;
    ctx.note(|n| n.task_id = Some(a.task_id.clone()));
    ok(ctx.core.tasks.kill(&a.task_id)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_quoting() {
        let exe = Path::new(r"C:\Program Files\nodejs\npm.cmd");
        let cl = batch_command_line(exe, &["install".into(), "a b".into(), "x&y".into()]).unwrap();
        assert_eq!(
            cl,
            r#"cmd.exe /d /s /c ""C:\Program Files\nodejs\npm.cmd" install "a b" "x&y"""#
        );
        assert!(batch_command_line(exe, &["%PATH%".into()]).is_err());
        assert!(batch_command_line(exe, &["a\"b".into()]).is_err());
    }
}
