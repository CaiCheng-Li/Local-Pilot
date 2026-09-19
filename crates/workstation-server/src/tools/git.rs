//! Structured Git tools (plan sections 10-12). They preserve the configured
//! identity (never pass `--author` or identity overrides), apply the
//! attribution guard, branch-first push policy and destructive-operation
//! approval regardless of the shell-check switch.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use workstation_core::{ErrorCode, LpError, LpResult};
use workstation_executor::{SpawnSpec, resolve_executable, run_captured};
use workstation_policy::command::git::{self as gitparse, GitCommand, GitKind};
use workstation_policy::command::tokenize::quote_arg;
use workstation_policy::{EntryPoint, FsAccess, GitFacts, broker};

use super::{Kind, ToolCtx, ToolMeta, ToolRegistry, ok};
use crate::approvals::ApprovalSummary;
use crate::environment;

pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

/// Run a program (git/gh) for a structured tool: standard user, own job,
/// redirected temp, bounded output. Fact queries use a minimal hardened call.
pub fn run_program(
    ctx: Option<&ToolCtx>,
    program: &str,
    args: &[String],
    dir: &Path,
    timeout: Duration,
) -> LpResult<Output> {
    let settings = ctx.map(|c| c.settings()).unwrap_or_default();
    let temp = std::env::temp_dir();
    let env = environment::build(&settings, None, dir, &[], &temp, None)?;
    let exe = resolve_executable(program, dir, &env.vars).ok_or_else(|| {
        LpError::new(
            ErrorCode::CommandFailed,
            format!("'{program}' is not installed or not on PATH"),
        )
    })?;
    let env = environment::build(&settings, Some(&exe), dir, &[], &temp, None)?;
    let cl = std::iter::once(quote_arg(&exe.display().to_string()))
        .chain(args.iter().map(|a| quote_arg(a)))
        .collect::<Vec<_>>()
        .join(" ");
    let spec = SpawnSpec {
        application: exe,
        command_line: cl,
        cwd: dir.to_path_buf(),
        env: env.vars,
    };
    let cap = run_captured(&spec, timeout, 4 * 1024 * 1024).map_err(|e| {
        LpError::new(
            ErrorCode::CommandFailed,
            format!("{program} failed to start: {e}"),
        )
    })?;
    if cap.timed_out {
        return Err(LpError::new(
            ErrorCode::Timeout,
            format!("{program} did not finish within {}s", timeout.as_secs()),
        ));
    }
    Ok(Output {
        code: cap.exit_code,
        stdout: String::from_utf8_lossy(&cap.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&cap.stderr).into_owned(),
        truncated: cap.truncated,
    })
}

fn git_query(dir: &Path, args: &[&str]) -> Option<String> {
    let mut full: Vec<String> = vec![
        "-c".into(),
        "core.fsmonitor=false".into(),
        "-c".into(),
        "core.untrackedCache=false".into(),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    let out = run_program(None, "git", &full, dir, Duration::from_secs(20)).ok()?;
    if out.code == Some(0) {
        Some(out.stdout.trim().to_string())
    } else {
        None
    }
}

/// Repository facts for Git policy decisions (read-only, hardened queries).
pub fn facts(dir: &Path, remote: Option<&str>) -> GitFacts {
    let repo_root = git_query(dir, &["rev-parse", "--show-toplevel"])
        .map(|s| PathBuf::from(s.replace('/', "\\")));
    let current = git_query(dir, &["symbolic-ref", "--quiet", "--short", "HEAD"]);
    let upstream_full = git_query(
        dir,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    );
    let upstream_remote = upstream_full
        .as_ref()
        .and_then(|u| u.split_once('/').map(|(r, _)| r.to_string()));
    let upstream_branch = upstream_full
        .as_ref()
        .and_then(|u| u.split_once('/').map(|(_, b)| b.to_string()));
    let remote = remote
        .map(|s| s.to_string())
        .or(upstream_remote)
        .unwrap_or_else(|| "origin".into());
    let mut defaults = Vec::new();
    if let Some(h) = git_query(
        dir,
        &[
            "symbolic-ref",
            "--quiet",
            "--short",
            &format!("refs/remotes/{remote}/HEAD"),
        ],
    ) && let Some((_, b)) = h.split_once('/')
    {
        defaults.push(b.to_string());
    }
    if defaults.is_empty() {
        for b in ["main", "master"] {
            if git_query(
                dir,
                &[
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    &format!("refs/remotes/{remote}/{b}"),
                ],
            )
            .is_some()
            {
                defaults.push(b.to_string());
            }
        }
    }
    GitFacts {
        repo_root,
        current_branch: current,
        upstream_branch,
        default_branches: defaults,
        rewrites_published_history: false,
    }
}

/// Facts for a parsed shell Git command (used by shell preflight).
pub fn facts_for_command(cwd: &Path, g: &GitCommand) -> GitFacts {
    let dir = g
        .cwd_override
        .as_ref()
        .map(|o| cwd.join(o))
        .unwrap_or_else(|| cwd.to_path_buf());
    let remote = match &g.kind {
        GitKind::Push(s) => s.remote.clone(),
        _ => None,
    };
    let mut f = facts(&dir, remote.as_deref());
    f.rewrites_published_history = match &g.kind {
        GitKind::Rebase { upstream } => rewrites_published(&dir, upstream.as_deref()),
        GitKind::CommitAmend => head_published(&dir),
        _ => false,
    };
    f
}

fn head_published(dir: &Path) -> bool {
    git_query(dir, &["branch", "-r", "--contains", "HEAD"])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

fn rewrites_published(dir: &Path, upstream: Option<&str>) -> bool {
    let base = upstream.unwrap_or("@{u}");
    let Some(list) = git_query(dir, &["rev-list", "--reverse", &format!("{base}..HEAD")]) else {
        return false;
    };
    let Some(oldest) = list.lines().next() else {
        return false;
    };
    git_query(dir, &["branch", "-r", "--contains", oldest])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoArgs {
    /// Repository directory, project ID or project name.
    pub repo: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffArgs {
    pub repo: String,
    /// Diff the index instead of the working tree.
    #[serde(default)]
    pub staged: Option<bool>,
    /// Compare against a commit/branch (e.g. `main`, `HEAD~1`).
    #[serde(default)]
    pub against: Option<String>,
    /// Limit to these paths (relative to the repository).
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub stat_only: Option<bool>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogArgs {
    pub repo: String,
    #[serde(default)]
    pub max_count: Option<u32>,
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BranchListArgs {
    pub repo: String,
    /// Include remote-tracking branches.
    #[serde(default)]
    pub all: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BranchCreateArgs {
    pub repo: String,
    pub name: String,
    #[serde(default)]
    pub start_point: Option<String>,
    /// Switch to the new branch (default true).
    #[serde(default)]
    pub checkout: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutArgs {
    pub repo: String,
    /// Branch, tag or commit to switch to.
    pub target: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FetchArgs {
    pub repo: String,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub prune: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PullArgs {
    pub repo: String,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub rebase: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddArgs {
    pub repo: String,
    /// Paths to stage (relative to the repository). Use ["."] for everything.
    pub paths: Vec<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitArgs {
    pub repo: String,
    /// Commit message written in the project's normal voice. Agent/vendor attribution is rejected.
    pub message: String,
    /// Stage tracked modifications first (`git commit -a`).
    #[serde(default)]
    pub all: Option<bool>,
    /// Amend the last commit (requires approval if it was already pushed).
    #[serde(default)]
    pub amend: Option<bool>,
    #[serde(default)]
    pub allow_empty: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushArgs {
    pub repo: String,
    #[serde(default)]
    pub remote: Option<String>,
    /// Branch to push (default: current branch).
    #[serde(default)]
    pub branch: Option<String>,
    /// Set upstream (`-u`).
    #[serde(default)]
    pub set_upstream: Option<bool>,
    /// Use `--force-with-lease` (requires approval unless enabled in settings).
    #[serde(default)]
    pub force_with_lease: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StashAction {
    Push,
    Pop,
    Apply,
    List,
    Drop,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StashArgs {
    pub repo: String,
    pub action: StashAction,
    #[serde(default)]
    pub message: Option<String>,
    /// Stash reference for pop/apply/drop (default the latest).
    #[serde(default)]
    pub stash: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

pub fn register(r: &mut ToolRegistry) {
    use Kind::*;
    let m = |name, title, description, kind| ToolMeta {
        name,
        title,
        description,
        kind,
    };
    r.add(
        m(
            "git_status",
            "Git status",
            "Branch, upstream, ahead/behind and changed files for a repository.",
            Read,
        ),
        status,
    );
    r.add(m("git_diff", "Git diff", "Diff of the working tree, index or against a revision (bounded; protected files are excluded; output is redacted).", Read), diff);
    r.add(m("git_log", "Git log", "Recent commits.", Read), log);
    r.add(
        m(
            "git_branch_list",
            "List branches",
            "Local (and optionally remote) branches.",
            Read,
        ),
        branch_list,
    );
    r.add(
        m(
            "git_remote_list",
            "List remotes",
            "Configured remotes (credentials in URLs are redacted).",
            Read,
        ),
        remote_list,
    );
    r.add(m("git_branch_create", "Create branch", "Create (and by default switch to) a branch. Work branch-first: pushes to the default branch need approval.", Write), branch_create);
    r.add(
        m(
            "git_checkout",
            "Switch branch",
            "Switch to a branch/tag/commit (fails rather than discarding local changes).",
            Write,
        ),
        checkout,
    );
    r.add(
        m(
            "git_fetch",
            "Fetch",
            "Fetch from a remote using the user's existing Git credentials.",
            Write,
        ),
        fetch,
    );
    r.add(m("git_pull", "Pull", "Pull from a remote.", Write), pull);
    r.add(
        m(
            "git_add",
            "Stage files",
            "Stage paths. Protected files (e.g. .env, keys) are refused.",
            Write,
        ),
        add,
    );
    r.add(m("git_commit", "Commit", "Commit with the repository's configured identity. Messages containing agent/vendor attribution are rejected.", Write), commit);
    r.add(m("git_push", "Push", "Push a branch. Non-default branches push freely; the default branch and force pushes require local approval by default.", Write), push);
    r.add(
        m(
            "git_stash",
            "Stash",
            "Stash push/pop/apply/list/drop.",
            Write,
        ),
        stash,
    );
}

struct Repo {
    dir: PathBuf,
    identity: String,
    decision: workstation_policy::Decision,
    mutation: bool,
}

/// Resolve the repository directory and evaluate filesystem policy. The
/// decision is authorized together with the Git decision in one request.
fn repo(ctx: &ToolCtx, repo: &str, mutation: bool) -> LpResult<Repo> {
    let root = ctx.core.trusted_root();
    let input = ctx
        .core
        .index
        .get(repo)
        .map(|p| p.canonical_path)
        .unwrap_or_else(|| repo.to_string());
    let c = broker::resolve(&input, &root, &ctx.core.env, true)?;
    if !c.exists || !c.is_dir {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("repository directory {} does not exist", c.path.display()),
        ));
    }
    let access = if mutation {
        FsAccess::Write
    } else {
        FsAccess::List
    };
    let decision = ctx.with_policy(EntryPoint::Structured, |e, pc| {
        e.evaluate_fs(&c.path, access, pc)
    });
    ctx.note(|n| {
        n.cwd = Some(c.path.display().to_string());
        n.paths.push(c.path.display().to_string());
        n.entry_point = Some(EntryPoint::Structured);
    });
    Ok(Repo {
        identity: broker::identity_string(&c),
        dir: c.path,
        decision,
        mutation,
    })
}

/// Read-only tools: authorize the repository access alone.
fn repo_dir(ctx: &ToolCtx, name: &str, mutation: bool) -> LpResult<PathBuf> {
    let r = repo(ctx, name, mutation)?;
    ctx.authorize(
        vec![r.decision.clone()],
        json!({ "op": "git_repo", "path": r.dir.display().to_string(), "identity": r.identity }),
        summary(ctx, &r.dir, format!("{} in {}", ctx.tool, r.dir.display())),
    )?;
    Ok(r.dir)
}

fn summary(ctx: &ToolCtx, dir: &Path, command: String) -> ApprovalSummary {
    ApprovalSummary {
        paths: vec![dir.display().to_string()],
        command: Some(ctx.core.redactor.redact_string(&command)),
        cwd: Some(dir.display().to_string()),
        arguments: Some(super::truncate_args(
            &ctx.core.redactor.redact_json(&ctx.raw_args).0,
        )),
        impact: "Git operation that needs local approval".into(),
        session_scope_label: String::new(),
    }
}

fn git(ctx: &ToolCtx, dir: &Path, args: &[&str], timeout_s: u64) -> LpResult<Output> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    ctx.note(|n| n.command = Some(format!("git {}", args.join(" "))));
    run_program(Some(ctx), "git", &args, dir, Duration::from_secs(timeout_s))
}

fn result(out: Output) -> LpResult<Value> {
    let success = out.code == Some(0);
    if !success {
        return Err(LpError::new(
            ErrorCode::CommandFailed,
            format!("git exited with {:?}", out.code),
        )
        .with_details(json!({
            "stdout": out.stdout,
            "stderr": out.stderr,
        })));
    }
    ok(
        json!({ "ok": true, "stdout": out.stdout, "stderr": out.stderr, "truncated": out.truncated }),
    )
}

/// Structured Git policy (always enforced, independent of the shell switch),
/// combined with the repository filesystem decision into one authorization.
fn authorize_git(
    ctx: &ToolCtx,
    r: &Repo,
    args: &[&str],
    remote: Option<&str>,
) -> LpResult<GitCommand> {
    let dir = &r.dir;
    let parsed = gitparse::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let mut facts = facts(dir, remote);
    facts.rewrites_published_history = match &parsed.kind {
        GitKind::Rebase { upstream } => rewrites_published(dir, upstream.as_deref()),
        GitKind::CommitAmend => head_published(dir),
        _ => false,
    };
    let d = ctx.with_policy(EntryPoint::Structured, |e, pc| {
        e.evaluate_git_structured(&parsed, &facts, pc)
    });
    ctx.authorize(
        vec![r.decision.clone(), d],
        json!({ "op": "git", "repo": dir.display().to_string(), "identity": r.identity, "args": args, "facts": {
            "current_branch": facts.current_branch, "upstream": facts.upstream_branch, "defaults": facts.default_branches,
        }}),
        summary(ctx, dir, format!("git {}", args.join(" "))),
    )?;
    if r.mutation {
        ctx.core
            .project_write_guard(&ctx.principal.client_id, dir, None)?;
    }
    Ok(parsed)
}

async fn status(ctx: Arc<ToolCtx>, a: RepoArgs) -> LpResult<Value> {
    let dir = repo_dir(&ctx, &a.repo, false)?;
    let out = git(
        &ctx,
        &dir,
        &[
            "-c",
            "core.fsmonitor=false",
            "status",
            "--porcelain=v2",
            "--branch",
            "-z",
        ],
        60,
    )?;
    if out.code != Some(0) {
        return result(out);
    }
    let engine = ctx.core.policy();
    let mut branch = json!({});
    let mut changes = Vec::new();
    let mut entries = out.stdout.split('\0').peekable();
    while let Some(e) = entries.next() {
        if let Some(rest) = e.strip_prefix("# ") {
            let (k, v) = rest.split_once(' ').unwrap_or((rest, ""));
            branch[k.replace('.', "_")] = json!(v);
        } else if let Some(rest) = e.strip_prefix("1 ") {
            let parts: Vec<&str> = rest.splitn(8, ' ').collect();
            if let (Some(xy), Some(path)) = (parts.first(), parts.get(7)) {
                changes.push(json!({ "status": xy, "path": path, "protected": engine.protected.check(&dir.join(path), true).is_some() }));
            }
        } else if let Some(rest) = e.strip_prefix("2 ") {
            let parts: Vec<&str> = rest.splitn(9, ' ').collect();
            let orig = entries.next().unwrap_or("");
            if let (Some(xy), Some(path)) = (parts.first(), parts.get(8)) {
                changes.push(json!({ "status": xy, "path": path, "renamed_from": orig }));
            }
        } else if let Some(path) = e.strip_prefix("? ") {
            changes.push(json!({ "status": "untracked", "path": path, "protected": engine.protected.check(&dir.join(path), true).is_some() }));
        } else if let Some(rest) = e.strip_prefix("u ") {
            let parts: Vec<&str> = rest.splitn(10, ' ').collect();
            if let Some(path) = parts.get(9) {
                changes.push(json!({ "status": "conflict", "path": path }));
            }
        }
    }
    ok(
        json!({ "repo": dir.display().to_string(), "branch": branch, "changes": changes, "clean": changes.is_empty() }),
    )
}

async fn diff(ctx: Arc<ToolCtx>, a: DiffArgs) -> LpResult<Value> {
    let dir = repo_dir(&ctx, &a.repo, false)?;
    let mut base: Vec<String> = vec![
        "-c".into(),
        "core.fsmonitor=false".into(),
        "diff".into(),
        "--no-color".into(),
        "--no-ext-diff".into(),
    ];
    if a.staged.unwrap_or(false) {
        base.push("--staged".into());
    }
    if let Some(r) = &a.against {
        if r.starts_with('-') {
            return Err(LpError::invalid("invalid revision"));
        }
        base.push(r.clone());
    }
    // Exclude protected files from any diff output.
    let mut names_args = base.clone();
    names_args.push("--name-only".into());
    names_args.push("-z".into());
    let names_ref: Vec<&str> = names_args.iter().map(|s| s.as_str()).collect();
    let names = git(&ctx, &dir, &names_ref, 60)?;
    let engine = ctx.core.policy();
    let excluded: Vec<String> = names
        .stdout
        .split('\0')
        .filter(|n| !n.is_empty() && engine.protected.check(&dir.join(n), true).is_some())
        .map(|s| s.to_string())
        .collect();
    let mut args = base;
    if a.stat_only.unwrap_or(false) {
        args.push("--stat".into());
    }
    args.push("--".into());
    match &a.paths {
        Some(p) if !p.is_empty() => args.extend(p.iter().map(|x| format!(":(literal){x}"))),
        _ => args.push(".".into()),
    }
    for e in &excluded {
        args.push(format!(":(exclude,literal){e}"));
    }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = git(&ctx, &dir, &refs, 120)?;
    if out.code != Some(0) {
        return result(out);
    }
    let max = a
        .max_bytes
        .unwrap_or(256 * 1024)
        .min(ctx.settings().limits.max_read_bytes) as usize;
    let truncated = out.stdout.len() > max;
    let text = if truncated {
        let end = (0..=max)
            .rev()
            .find(|&index| out.stdout.is_char_boundary(index))
            .unwrap_or(0);
        out.stdout[..end].to_string()
    } else {
        out.stdout
    };
    ok(json!({ "diff": text, "truncated": truncated, "excluded_protected_files": excluded }))
}

async fn log(ctx: Arc<ToolCtx>, a: LogArgs) -> LpResult<Value> {
    let dir = repo_dir(&ctx, &a.repo, false)?;
    let n = a.max_count.unwrap_or(20).clamp(1, 500).to_string();
    let mut args = vec![
        "log",
        "--no-color",
        "-n",
        &n,
        "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%s%x1e",
    ];
    if let Some(r) = &a.revision {
        if r.starts_with('-') {
            return Err(LpError::invalid("invalid revision"));
        }
        args.push(r);
    }
    if let Some(p) = &a.path {
        args.push("--");
        args.push(p);
    }
    let out = git(&ctx, &dir, &args, 60)?;
    if out.code != Some(0) {
        return result(out);
    }
    let commits: Vec<Value> = out
        .stdout
        .split('\u{1e}')
        .filter(|r| !r.trim().is_empty())
        .map(|r| {
            let f: Vec<&str> = r.trim().split('\u{1f}').collect();
            json!({ "sha": f.first(), "author": f.get(1), "email": f.get(2), "date": f.get(3), "subject": f.get(4) })
        })
        .collect();
    ok(json!({ "commits": commits }))
}

async fn branch_list(ctx: Arc<ToolCtx>, a: BranchListArgs) -> LpResult<Value> {
    let dir = repo_dir(&ctx, &a.repo, false)?;
    let mut args = vec![
        "branch",
        "--no-color",
        "--format=%(HEAD)%1f%(refname:short)%1f%(upstream:short)%1f%(objectname:short)",
    ];
    if a.all.unwrap_or(false) {
        args.push("--all");
    }
    let out = git(&ctx, &dir, &args, 60)?;
    if out.code != Some(0) {
        return result(out);
    }
    let branches: Vec<Value> = out
        .stdout
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\u{1f}').collect();
            json!({ "current": f.first() == Some(&"*"), "name": f.get(1), "upstream": f.get(2).filter(|s| !s.is_empty()), "commit": f.get(3) })
        })
        .collect();
    let facts = facts(&dir, None);
    ok(json!({ "branches": branches, "default_branches": facts.default_branches }))
}

async fn remote_list(ctx: Arc<ToolCtx>, a: RepoArgs) -> LpResult<Value> {
    let dir = repo_dir(&ctx, &a.repo, false)?;
    let out = git(&ctx, &dir, &["remote", "-v"], 30)?;
    if out.code != Some(0) {
        return result(out);
    }
    let remotes: Vec<Value> = out
        .stdout
        .lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            Some(json!({ "name": p.next()?, "url": ctx.core.redactor.redact_string(p.next()?), "kind": p.next().unwrap_or("").trim_matches(|c| c == '(' || c == ')') }))
        })
        .collect();
    ok(json!({ "remotes": remotes }))
}

fn check_ref_name(name: &str) -> LpResult<()> {
    if name.is_empty()
        || name.starts_with('-')
        || name.len() > 250
        || name.contains("..")
        || name
            .chars()
            .any(|c| c.is_whitespace() || "~^:?*[\\".contains(c))
    {
        return Err(LpError::invalid("invalid branch name"));
    }
    Ok(())
}

async fn branch_create(ctx: Arc<ToolCtx>, a: BranchCreateArgs) -> LpResult<Value> {
    check_ref_name(&a.name)?;
    let r = repo(&ctx, &a.repo, true)?;
    let dir = r.dir.clone();
    let checkout = a.checkout.unwrap_or(true);
    let mut args: Vec<&str> = if checkout {
        vec!["switch", "-c", &a.name]
    } else {
        vec!["branch", &a.name]
    };
    if let Some(s) = &a.start_point {
        if s.starts_with('-') {
            return Err(LpError::invalid("invalid start point"));
        }
        args.push(s);
    }
    authorize_git(&ctx, &r, &args, None)?;
    result(git(&ctx, &dir, &args, 60)?)
}

async fn checkout(ctx: Arc<ToolCtx>, a: CheckoutArgs) -> LpResult<Value> {
    if a.target.starts_with('-') {
        return Err(LpError::invalid("invalid target"));
    }
    let r = repo(&ctx, &a.repo, true)?;
    let dir = r.dir.clone();
    let args = ["checkout", a.target.as_str()];
    authorize_git(&ctx, &r, &args, None)?;
    result(git(&ctx, &dir, &args, 60)?)
}

async fn fetch(ctx: Arc<ToolCtx>, a: FetchArgs) -> LpResult<Value> {
    let r = repo(&ctx, &a.repo, true)?;
    let dir = r.dir.clone();
    let mut args = vec!["fetch"];
    if a.prune.unwrap_or(false) {
        args.push("--prune");
    }
    if let Some(r) = &a.remote {
        if r.starts_with('-') {
            return Err(LpError::invalid("invalid remote"));
        }
        args.push(r);
    }
    authorize_git(&ctx, &r, &args, a.remote.as_deref())?;
    result(git(&ctx, &dir, &args, 300)?)
}

async fn pull(ctx: Arc<ToolCtx>, a: PullArgs) -> LpResult<Value> {
    let r = repo(&ctx, &a.repo, true)?;
    let dir = r.dir.clone();
    let mut args = vec!["pull", "--no-edit"];
    args.push(if a.rebase.unwrap_or(false) {
        "--rebase"
    } else {
        "--no-rebase"
    });
    if let Some(r) = &a.remote {
        if r.starts_with('-') {
            return Err(LpError::invalid("invalid remote"));
        }
        args.push(r);
        if let Some(b) = &a.branch {
            check_ref_name(b)?;
            args.push(b);
        }
    }
    authorize_git(&ctx, &r, &args, a.remote.as_deref())?;
    result(git(&ctx, &dir, &args, 300)?)
}

async fn add(ctx: Arc<ToolCtx>, a: AddArgs) -> LpResult<Value> {
    if a.paths.is_empty() {
        return Err(LpError::invalid("paths must not be empty"));
    }
    let r = repo(&ctx, &a.repo, true)?;
    let dir = r.dir.clone();
    // Dry run first: refuse if a protected file would be staged.
    let mut dry: Vec<String> = vec!["add".into(), "--dry-run".into(), "--".into()];
    dry.extend(a.paths.iter().cloned());
    let dry_ref: Vec<&str> = dry.iter().map(|s| s.as_str()).collect();
    let out = git(&ctx, &dir, &dry_ref, 60)?;
    if out.code != Some(0) {
        return result(out);
    }
    let engine = ctx.core.policy();
    let protected: Vec<String> = out
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("add '").and_then(|r| r.strip_suffix('\'')))
        .filter(|p| engine.protected.check(&dir.join(p), false).is_some())
        .map(|s| s.to_string())
        .collect();
    if !protected.is_empty() {
        return Err(LpError::new(
            ErrorCode::ProtectedResource,
            format!(
                "Refusing to stage protected files: {}. Add them to .gitignore or stage specific paths.",
                protected.join(", ")
            ),
        ));
    }
    let mut args: Vec<String> = vec!["add".into(), "--".into()];
    args.extend(a.paths.iter().cloned());
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    authorize_git(&ctx, &r, &refs, None)?;
    result(git(&ctx, &dir, &refs, 120)?)
}

async fn commit(ctx: Arc<ToolCtx>, a: CommitArgs) -> LpResult<Value> {
    if a.message.trim().is_empty() {
        return Err(LpError::invalid("commit message must not be empty"));
    }
    let r = repo(&ctx, &a.repo, true)?;
    let dir = r.dir.clone();
    let mut args = vec!["commit", "-m", a.message.as_str()];
    if a.all.unwrap_or(false) {
        args.push("-a");
    }
    if a.amend.unwrap_or(false) {
        args.push("--amend");
    }
    if a.allow_empty.unwrap_or(false) {
        args.push("--allow-empty");
    }
    authorize_git(&ctx, &r, &args, None)?;
    let out = git(&ctx, &dir, &args, 120)?;
    let r = result(out)?;
    let head = git(&ctx, &dir, &["log", "-1", "--format=%H%x1f%an%x1f%ae"], 30)?;
    let f: Vec<String> = head
        .stdout
        .trim()
        .split('\u{1f}')
        .map(|s| s.to_string())
        .collect();
    ok(json!({ "result": r, "commit": f.first(), "author": f.get(1), "email": f.get(2) }))
}

async fn push(ctx: Arc<ToolCtx>, a: PushArgs) -> LpResult<Value> {
    let r = repo(&ctx, &a.repo, true)?;
    let dir = r.dir.clone();
    let facts = facts(&dir, a.remote.as_deref());
    let remote = a.remote.clone().unwrap_or_else(|| "origin".into());
    if remote.starts_with('-') {
        return Err(LpError::invalid("invalid remote"));
    }
    let branch = match &a.branch {
        Some(b) => b.clone(),
        None => facts
            .current_branch
            .clone()
            .ok_or_else(|| LpError::invalid("HEAD is detached; specify the branch to push"))?,
    };
    check_ref_name(&branch)?;
    let mut args: Vec<&str> = vec!["push"];
    if a.set_upstream.unwrap_or(false) {
        args.push("-u");
    }
    if a.force_with_lease.unwrap_or(false) {
        args.push("--force-with-lease");
    }
    args.push(&remote);
    args.push(&branch);
    authorize_git(&ctx, &r, &args, Some(&remote))?;
    result(git(&ctx, &dir, &args, 300)?)
}

async fn stash(ctx: Arc<ToolCtx>, a: StashArgs) -> LpResult<Value> {
    let r = repo(&ctx, &a.repo, a.action != StashAction::List)?;
    let dir = r.dir.clone();
    let mut args: Vec<&str> = vec!["stash"];
    match a.action {
        StashAction::Push => {
            args.push("push");
            if let Some(m) = &a.message {
                args.push("-m");
                args.push(m);
            }
        }
        StashAction::Pop => args.push("pop"),
        StashAction::Apply => args.push("apply"),
        StashAction::List => args.push("list"),
        StashAction::Drop => args.push("drop"),
    }
    if let Some(s) = &a.stash
        && matches!(
            a.action,
            StashAction::Pop | StashAction::Apply | StashAction::Drop
        )
    {
        if s.starts_with('-') {
            return Err(LpError::invalid("invalid stash reference"));
        }
        args.push(s);
    }
    authorize_git(&ctx, &r, &args, None)?;
    result(git(&ctx, &dir, &args, 60)?)
}
