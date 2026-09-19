//! Structured GitHub tools via the user's authenticated `gh` (plan section
//! 13). Tokens are never exposed; every content-writing tool passes the
//! attribution guard. Raw `gh` remains available through the shell tools.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use workstation_core::{ErrorCode, LpError, LpResult};
use workstation_policy::{EntryPoint, FsAccess, broker};

use super::git::run_program;
use super::{Kind, ToolCtx, ToolMeta, ToolRegistry, ok};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Local repository directory or project (used to infer the GitHub repository).
    #[serde(default)]
    pub repo: Option<String>,
    /// Explicit GitHub repository as OWNER/NAME.
    #[serde(default)]
    pub github_repo: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    /// open, closed, merged or all.
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NumberArgs {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    /// Issue or pull request number.
    pub number: u64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssueCreateArgs {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub labels: Option<Vec<String>>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentArgs {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    pub number: u64,
    pub body: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrCreateArgs {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    pub title: String,
    pub body: String,
    /// Branch with the changes (default: current branch).
    #[serde(default)]
    pub head: Option<String>,
    /// Target branch (default: repository default branch).
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub draft: Option<bool>,
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
            "github_repo_view",
            "View GitHub repository",
            "Repository details via the locally authenticated GitHub CLI.",
            Read,
        ),
        repo_view,
    );
    r.add(
        m("github_issue_list", "List issues", "List issues.", Read),
        issue_list,
    );
    r.add(m("github_issue_create", "Create issue", "Create an issue. Text must read as the user's own; agent/vendor attribution is rejected.", Write), issue_create);
    r.add(
        m(
            "github_issue_comment",
            "Comment on issue",
            "Comment on an issue (attribution guard applies).",
            Write,
        ),
        issue_comment,
    );
    r.add(
        m(
            "github_pr_list",
            "List pull requests",
            "List pull requests.",
            Read,
        ),
        pr_list,
    );
    r.add(
        m(
            "github_pr_view",
            "View pull request",
            "Pull request details.",
            Read,
        ),
        pr_view,
    );
    r.add(
        m(
            "github_pr_create",
            "Create pull request",
            "Open a pull request from a pushed branch (attribution guard applies).",
            Write,
        ),
        pr_create,
    );
    r.add(
        m(
            "github_pr_comment",
            "Comment on pull request",
            "Comment on a pull request (attribution guard applies).",
            Write,
        ),
        pr_comment,
    );
    r.add(
        m(
            "github_pr_checks",
            "Pull request checks",
            "CI check status of a pull request.",
            Read,
        ),
        pr_checks,
    );
    r.add(
        m(
            "github_release_list",
            "List releases",
            "List releases.",
            Read,
        ),
        release_list,
    );
}

fn repo_flag(v: &Option<String>) -> LpResult<Vec<String>> {
    match v {
        Some(r) => {
            let ok = r.split('/').count() == 2
                && r.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
                && !r.starts_with('-');
            if !ok {
                return Err(LpError::invalid("github_repo must look like OWNER/NAME"));
            }
            Ok(vec!["-R".into(), r.clone()])
        }
        None => Ok(Vec::new()),
    }
}

fn workdir(ctx: &ToolCtx, repo: &Option<String>) -> LpResult<PathBuf> {
    let root = ctx.core.trusted_root();
    let input = match repo {
        Some(r) => ctx
            .core
            .index
            .get(r)
            .map(|p| p.canonical_path)
            .unwrap_or_else(|| r.clone()),
        None => root.display().to_string(),
    };
    let c = broker::resolve(&input, &root, &ctx.core.env, true)?;
    if !c.exists || !c.is_dir {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            "repository directory does not exist",
        ));
    }
    let d = ctx.with_policy(EntryPoint::Structured, |e, pc| {
        e.evaluate_fs(&c.path, FsAccess::List, pc)
    });
    ctx.authorize(vec![d], json!(null), Default::default())?;
    ctx.note(|n| {
        n.cwd = Some(c.path.display().to_string());
        n.entry_point = Some(EntryPoint::Structured);
    });
    Ok(c.path)
}

fn gh(ctx: &ToolCtx, dir: &Path, args: Vec<String>, parse_json: bool) -> LpResult<Value> {
    ctx.note(|n| {
        n.command = Some(format!(
            "gh {}",
            args.iter()
                .map(|a| if a.len() > 80 {
                    "<text>".to_string()
                } else {
                    a.clone()
                })
                .collect::<Vec<_>>()
                .join(" ")
        ))
    });
    let out = run_program(Some(ctx), "gh", &args, dir, Duration::from_secs(120))?;
    if out.code != Some(0) {
        return Err(
            LpError::new(ErrorCode::CommandFailed, "gh reported an error")
                .with_details(json!({ "stderr": out.stderr, "stdout": out.stdout })),
        );
    }
    if parse_json {
        serde_json::from_str(&out.stdout).or_else(|_| Ok(json!({ "output": out.stdout })))
    } else {
        ok(json!({ "ok": true, "output": out.stdout.trim() }))
    }
}

fn guard(ctx: &ToolCtx, texts: &[&str], refs: &[&str]) -> LpResult<()> {
    let engine = ctx.core.policy();
    if let Err((code, msg)) = engine.check_github_text(texts, refs) {
        ctx.note(|n| {
            n.decision = Some("deny".into());
            n.decision_detail = Some(msg.clone());
        });
        return Err(LpError::new(code, msg));
    }
    ctx.note(|n| n.decision = Some("allow".into()));
    Ok(())
}

fn state_arg(s: &Option<String>) -> LpResult<String> {
    let s = s.clone().unwrap_or_else(|| "open".into());
    if !matches!(s.as_str(), "open" | "closed" | "merged" | "all") {
        return Err(LpError::invalid(
            "state must be open, closed, merged or all",
        ));
    }
    Ok(s)
}

async fn repo_view(ctx: Arc<ToolCtx>, a: Target) -> LpResult<Value> {
    let dir = workdir(&ctx, &a.repo)?;
    let mut args = vec!["repo".into(), "view".into()];
    if let Some(r) = &a.github_repo {
        repo_flag(&Some(r.clone()))?;
        args.push(r.clone());
    }
    args.extend([
        "--json".into(),
        "nameWithOwner,description,defaultBranchRef,url,visibility,isFork,stargazerCount,updatedAt"
            .into(),
    ]);
    gh(&ctx, &dir, args, true)
}

async fn issue_list(ctx: Arc<ToolCtx>, a: ListArgs) -> LpResult<Value> {
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "issue".into(),
        "list".into(),
        "--state".into(),
        state_arg(&a.state)?,
        "--limit".into(),
        a.limit.unwrap_or(30).min(200).to_string(),
    ];
    args.extend(repo_flag(&a.github_repo)?);
    args.extend([
        "--json".into(),
        "number,title,state,author,labels,url,updatedAt".into(),
    ]);
    gh(&ctx, &dir, args, true)
}

async fn issue_create(ctx: Arc<ToolCtx>, a: IssueCreateArgs) -> LpResult<Value> {
    guard(&ctx, &[&a.title, &a.body], &[])?;
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "issue".into(),
        "create".into(),
        "--title".into(),
        a.title.clone(),
        "--body".into(),
        a.body.clone(),
    ];
    for l in a.labels.unwrap_or_default() {
        args.push("--label".into());
        args.push(l);
    }
    args.extend(repo_flag(&a.github_repo)?);
    gh(&ctx, &dir, args, false)
}

async fn issue_comment(ctx: Arc<ToolCtx>, a: CommentArgs) -> LpResult<Value> {
    guard(&ctx, &[&a.body], &[])?;
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "issue".into(),
        "comment".into(),
        a.number.to_string(),
        "--body".into(),
        a.body.clone(),
    ];
    args.extend(repo_flag(&a.github_repo)?);
    gh(&ctx, &dir, args, false)
}

async fn pr_list(ctx: Arc<ToolCtx>, a: ListArgs) -> LpResult<Value> {
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "pr".into(),
        "list".into(),
        "--state".into(),
        state_arg(&a.state)?,
        "--limit".into(),
        a.limit.unwrap_or(30).min(200).to_string(),
    ];
    args.extend(repo_flag(&a.github_repo)?);
    args.extend([
        "--json".into(),
        "number,title,state,author,headRefName,baseRefName,isDraft,url,updatedAt".into(),
    ]);
    gh(&ctx, &dir, args, true)
}

async fn pr_view(ctx: Arc<ToolCtx>, a: NumberArgs) -> LpResult<Value> {
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec!["pr".into(), "view".into(), a.number.to_string()];
    args.extend(repo_flag(&a.github_repo)?);
    args.extend(["--json".into(), "number,title,state,author,body,headRefName,baseRefName,isDraft,mergeable,reviewDecision,url,commits,files".into()]);
    gh(&ctx, &dir, args, true)
}

async fn pr_create(ctx: Arc<ToolCtx>, a: PrCreateArgs) -> LpResult<Value> {
    let refs: Vec<&str> = a.head.iter().map(|s| s.as_str()).collect();
    guard(&ctx, &[&a.title, &a.body], &refs)?;
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "pr".into(),
        "create".into(),
        "--title".into(),
        a.title.clone(),
        "--body".into(),
        a.body.clone(),
    ];
    if let Some(h) = &a.head {
        args.push("--head".into());
        args.push(h.clone());
    }
    if let Some(b) = &a.base {
        args.push("--base".into());
        args.push(b.clone());
    }
    if a.draft.unwrap_or(false) {
        args.push("--draft".into());
    }
    args.extend(repo_flag(&a.github_repo)?);
    gh(&ctx, &dir, args, false)
}

async fn pr_comment(ctx: Arc<ToolCtx>, a: CommentArgs) -> LpResult<Value> {
    guard(&ctx, &[&a.body], &[])?;
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "pr".into(),
        "comment".into(),
        a.number.to_string(),
        "--body".into(),
        a.body.clone(),
    ];
    args.extend(repo_flag(&a.github_repo)?);
    gh(&ctx, &dir, args, false)
}

async fn pr_checks(ctx: Arc<ToolCtx>, a: NumberArgs) -> LpResult<Value> {
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "pr".into(),
        "checks".into(),
        a.number.to_string(),
        "--json".into(),
        "name,state,bucket,link,workflow".into(),
    ];
    args.extend(repo_flag(&a.github_repo)?);
    gh(&ctx, &dir, args, true)
}

async fn release_list(ctx: Arc<ToolCtx>, a: ListArgs) -> LpResult<Value> {
    let dir = workdir(&ctx, &a.repo)?;
    let mut args: Vec<String> = vec![
        "release".into(),
        "list".into(),
        "--limit".into(),
        a.limit.unwrap_or(20).min(100).to_string(),
    ];
    args.extend(repo_flag(&a.github_repo)?);
    args.extend([
        "--json".into(),
        "name,tagName,isLatest,isDraft,isPrerelease,publishedAt".into(),
    ]);
    gh(&ctx, &dir, args, true)
}
