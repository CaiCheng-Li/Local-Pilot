//! Project discovery and search tools (plan section 7).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use workstation_core::{ErrorCode, LpError, LpResult};
use workstation_index::search::{self, TextSearchOptions};
use workstation_policy::{EntryPoint, FsAccess, broker};

use super::{Kind, ToolCtx, ToolMeta, ToolRegistry, ok};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Include nested projects (repositories/workspace members inside a project folder).
    #[serde(default)]
    pub include_nested: Option<bool>,
    /// Maximum number of projects to return (default 200).
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveArgs {
    /// Project name or alias, e.g. "Clippy".
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    /// Project ID (prj_...) or exact name.
    pub project: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefreshArgs {
    /// Project ID or name to rescan; omit to rescan everything.
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchNamesArgs {
    /// Substring of a file or directory name (case-insensitive).
    pub query: String,
    /// Restrict to one project (ID or name).
    #[serde(default)]
    pub project: Option<String>,
    /// Only directories.
    #[serde(default)]
    pub directories_only: Option<bool>,
    #[serde(default)]
    pub max_results: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindArgs {
    /// Glob pattern such as `**/*.rs` or `package.json`.
    pub pattern: String,
    /// Project ID/name or a directory path to search under (default: all projects).
    #[serde(default)]
    pub scope: Option<String>,
    /// Include dependency/build directories and .gitignored files.
    #[serde(default)]
    pub include_ignored: Option<bool>,
    #[serde(default)]
    pub max_results: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchTextArgs {
    /// Text or regular expression to search for.
    pub query: String,
    /// Project ID/name or a directory path (default: all projects).
    #[serde(default)]
    pub scope: Option<String>,
    /// Treat `query` as a regular expression (default false: literal).
    #[serde(default)]
    pub regex: Option<bool>,
    #[serde(default)]
    pub case_sensitive: Option<bool>,
    /// Comma-separated globs to include, e.g. `*.ts,*.tsx`; prefix with `!` to exclude.
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub max_results: Option<usize>,
    /// Lines of context before/after each match (0-10).
    #[serde(default)]
    pub context_lines: Option<usize>,
    /// Include dependency/build directories and .gitignored files.
    #[serde(default)]
    pub include_ignored: Option<bool>,
}

pub fn register(r: &mut ToolRegistry) {
    r.add(
        ToolMeta {
            name: "projects_list",
            title: "List projects",
            description: "List projects in the trusted workspace (Documents\\Projects) with detected types, languages and Git remotes. Returns a bounded list; use projects_resolve to find one project by name.",
            kind: Kind::Read,
        },
        list,
    );
    r.add(
        ToolMeta {
            name: "projects_resolve",
            title: "Resolve project",
            description: "Find a project by name or alias (e.g. 'Where is my Clippy project?'). Returns matching projects with confidence scores; if none match, falls back to directories whose names match.",
            kind: Kind::Read,
        },
        resolve,
    );
    r.add(
        ToolMeta {
            name: "projects_get",
            title: "Get project",
            description: "Get indexed details for one project by ID or exact name.",
            kind: Kind::Read,
        },
        get,
    );
    r.add(
        ToolMeta {
            name: "projects_refresh",
            title: "Refresh project index",
            description: "Rescan one project (or all projects) to update the folder map after large changes.",
            kind: Kind::Read,
        },
        refresh,
    );
    r.add(
        ToolMeta {
            name: "files_search_names",
            title: "Search file names",
            description: "Fast indexed search for files/directories by name across projects. Dependency and build folders are not indexed.",
            kind: Kind::Read,
        },
        search_names,
    );
    r.add(
        ToolMeta {
            name: "files_find",
            title: "Find files by glob",
            description: "Find files matching a glob pattern under a project or directory (respects .gitignore unless include_ignored is set).",
            kind: Kind::Read,
        },
        find,
    );
    r.add(
        ToolMeta {
            name: "files_search_text",
            title: "Search file contents",
            description: "Search file contents (literal or regex) under a project or directory with bounded results and optional context lines. Protected files (credentials, .env, keys) are never searched; results are redacted.",
            kind: Kind::Read,
        },
        search_text,
    );
}

fn project_json(p: &workstation_index::Project) -> Value {
    json!({
        "project_id": p.project_id,
        "name": p.display_name,
        "path": p.canonical_path,
        "types": p.detected_project_types,
        "languages": p.detected_languages,
        "git_repository": p.git_repository,
        "git_remote_urls": p.git_remote_urls,
        "default_branch": p.default_branch,
        "parent_project_id": p.parent_project_id,
        "aliases": p.aliases,
        "locked_by_user": p.locked,
        "last_modified": p.last_modified_time.map(workstation_core::time::ms_to_rfc3339),
        "indexed_files": p.file_count,
    })
}

async fn list(ctx: Arc<ToolCtx>, a: ListArgs) -> LpResult<Value> {
    let nested = a.include_nested.unwrap_or(false);
    let limit = a.limit.unwrap_or(200).clamp(1, 1000);
    let projects: Vec<Value> = ctx
        .core
        .index
        .list()
        .iter()
        .filter(|p| nested || p.parent_project_id.is_none())
        .take(limit)
        .map(project_json)
        .collect();
    ok(
        json!({ "root": ctx.core.trusted_root().display().to_string(), "count": projects.len(), "projects": projects }),
    )
}

async fn resolve(ctx: Arc<ToolCtx>, a: ResolveArgs) -> LpResult<Value> {
    let r = ctx.core.index.resolve(&a.name, 10)?;
    if r.matches.is_empty() && r.fallback.is_empty() {
        return Err(LpError::new(
            ErrorCode::ProjectNotFound,
            format!("No project or directory named like '{}' was found.", a.name),
        ));
    }
    let best = r.matches.first().cloned();
    ok(json!({
        "name": best.as_ref().map(|b| b.name.clone()),
        "path": best.as_ref().map(|b| b.path.clone()),
        "confidence": best.as_ref().map(|b| b.confidence),
        "matches": r.matches,
        "fallback_directories": r.fallback,
    }))
}

fn find_project(ctx: &ToolCtx, key: &str) -> LpResult<workstation_index::Project> {
    ctx.core.index.get(key).ok_or_else(|| {
        LpError::new(
            ErrorCode::ProjectNotFound,
            format!("unknown project '{key}'"),
        )
    })
}

async fn get(ctx: Arc<ToolCtx>, a: GetArgs) -> LpResult<Value> {
    let p = find_project(&ctx, &a.project)?;
    ok(project_json(&p))
}

async fn refresh(ctx: Arc<ToolCtx>, a: RefreshArgs) -> LpResult<Value> {
    let index = ctx.core.index.clone();
    let id = match &a.project {
        Some(k) => Some(find_project(&ctx, k)?.project_id),
        None => None,
    };
    let n = tokio::task::spawn_blocking(move || index.refresh(id.as_deref()))
        .await
        .map_err(LpError::internal)??;
    ok(json!({ "rescanned": n }))
}

async fn search_names(ctx: Arc<ToolCtx>, a: SearchNamesArgs) -> LpResult<Value> {
    let pid = match &a.project {
        Some(k) => Some(find_project(&ctx, k)?.project_id),
        None => None,
    };
    let max = a
        .max_results
        .unwrap_or(50)
        .clamp(1, ctx.settings().limits.max_search_results);
    let hits = ctx.core.index.search_names(
        &a.query,
        pid.as_deref(),
        max,
        a.directories_only.unwrap_or(false),
    )?;
    ok(json!({ "count": hits.len(), "results": hits }))
}

/// Resolve a search scope (project or directory) and check it is readable.
fn scope_dir(ctx: &ToolCtx, scope: Option<&str>) -> LpResult<PathBuf> {
    let root = ctx.core.trusted_root();
    let Some(s) = scope else { return Ok(root) };
    if let Some(p) = ctx.core.index.get(s) {
        return Ok(PathBuf::from(p.canonical_path));
    }
    let c = broker::resolve(s, &root, &ctx.core.env, true)?;
    if !c.exists || !c.is_dir {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("'{s}' is not a project or existing directory"),
        ));
    }
    let d = ctx.with_policy(EntryPoint::Structured, |e, pc| {
        e.evaluate_fs(&c.path, FsAccess::List, pc)
    });
    ctx.authorize(vec![d], json!(null), Default::default())?;
    Ok(c.path)
}

async fn find(ctx: Arc<ToolCtx>, a: FindArgs) -> LpResult<Value> {
    let dir = scope_dir(&ctx, a.scope.as_deref())?;
    ctx.note(|n| n.paths.push(dir.display().to_string()));
    let max = a
        .max_results
        .unwrap_or(200)
        .clamp(1, ctx.settings().limits.max_search_results);
    let include = a.include_ignored.unwrap_or(false);
    let pattern = a.pattern.clone();
    let engine = ctx.core.policy();
    let (hits, truncated) =
        tokio::task::spawn_blocking(move || search::find(&dir, &pattern, include, max))
            .await
            .map_err(LpError::internal)??;
    let hits: Vec<Value> = hits
        .into_iter()
        .filter(|h| engine.roots.classify_class(Path::new(&h.path)) != workstation_policy::PathClass::ControlData)
        .map(|h| {
            let protected = engine.protected.check(Path::new(&h.path), true).is_some();
            json!({ "path": h.path, "is_dir": h.is_dir, "size": h.size, "modified": workstation_core::time::ms_to_rfc3339(h.modified_ms), "protected": protected })
        })
        .collect();
    ok(json!({ "count": hits.len(), "truncated": truncated, "results": hits }))
}

async fn search_text(ctx: Arc<ToolCtx>, a: SearchTextArgs) -> LpResult<Value> {
    let dir = scope_dir(&ctx, a.scope.as_deref())?;
    ctx.note(|n| n.paths.push(dir.display().to_string()));
    let settings = ctx.settings();
    let opts = TextSearchOptions {
        query: a.query,
        regex: a.regex.unwrap_or(false),
        case_sensitive: a.case_sensitive.unwrap_or(false),
        glob: a.glob,
        max_results: a
            .max_results
            .unwrap_or(100)
            .clamp(1, settings.limits.max_search_results),
        context_lines: a.context_lines.unwrap_or(0).min(10),
        include_ignored: a.include_ignored.unwrap_or(false),
        max_file_bytes: 8 * 1024 * 1024,
    };
    let engine = ctx.core.policy();
    let result = tokio::task::spawn_blocking(move || {
        search::search_text(&dir, &opts, &|p| {
            engine.protected.check(p, true).is_some()
                || engine.roots.classify_class(p) == workstation_policy::PathClass::ControlData
        })
    })
    .await
    .map_err(LpError::internal)??;
    ok(result)
}
