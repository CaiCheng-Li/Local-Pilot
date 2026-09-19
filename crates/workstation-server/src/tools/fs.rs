//! Filesystem tools (plan section 8). All paths go through the broker:
//! canonicalization, classification, the central policy evaluator, and
//! handle-bound execution. Relative paths resolve against the trusted
//! Projects root.

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use workstation_core::{ErrorCode, LpError, LpResult};
use workstation_index::search;
use workstation_policy::broker::{self, Edit, TextEncoding, WriteMode};
use workstation_policy::{Canonical, EntryPoint, FsAccess, PathClass};

use super::{Kind, ToolCtx, ToolMeta, ToolRegistry, ok};
use crate::approvals::ApprovalSummary;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathArgs {
    /// Absolute path, or a path relative to Documents\Projects.
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatArgs {
    /// Absolute path, or a path relative to Documents\Projects.
    pub path: String,
    /// Follow a final symlink/junction (default true).
    #[serde(default)]
    pub follow_links: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Directory path (absolute or relative to Documents\Projects).
    pub path: String,
    #[serde(default)]
    pub max_entries: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindArgs {
    /// Directory to search under.
    pub path: String,
    /// Glob such as `**/*.json`.
    pub pattern: String,
    #[serde(default)]
    pub include_ignored: Option<bool>,
    #[serde(default)]
    pub max_results: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManyArgs {
    /// Up to the configured maximum number of paths.
    pub paths: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadTextArgs {
    /// File path (absolute or relative to Documents\Projects).
    pub path: String,
    /// Byte offset to start reading from.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Maximum bytes to return (bounded by the server limit).
    #[serde(default)]
    pub length: Option<u64>,
    /// First line to return (1-based). Use with end_line for line ranges.
    #[serde(default)]
    pub start_line: Option<usize>,
    /// Last line to return (inclusive).
    #[serde(default)]
    pub end_line: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadBytesArgs {
    pub path: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub length: Option<u64>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ModeArg {
    Overwrite,
    CreateNew,
    Append,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum EncodingArg {
    Utf8,
    Utf8Bom,
    Utf16le,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteTextArgs {
    pub path: String,
    pub content: String,
    /// overwrite (default), create_new (fail if it exists) or append.
    #[serde(default)]
    pub mode: Option<ModeArg>,
    /// Create missing parent directories (default true).
    #[serde(default)]
    pub create_parents: Option<bool>,
    #[serde(default)]
    pub encoding: Option<EncodingArg>,
    /// Client-chosen key; retries with the same key and arguments return the first result.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteBytesArgs {
    pub path: String,
    /// Base64-encoded content.
    pub content_base64: String,
    #[serde(default)]
    pub mode: Option<ModeArg>,
    #[serde(default)]
    pub create_parents: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditArg {
    /// Exact text to replace (must occur exactly `expected_replacements` times).
    pub old_text: String,
    pub new_text: String,
    /// Required occurrence count (default 1; 0 means replace all occurrences).
    #[serde(default)]
    pub expected_replacements: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchArgs {
    pub path: String,
    /// Exact-text replacements applied in order; nothing is written if any edit fails.
    pub edits: Vec<EditArg>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MkdirArgs {
    pub path: String,
    /// Create missing parents (default true).
    #[serde(default)]
    pub recursive: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopyArgs {
    pub source: String,
    /// Full destination path (not a directory to copy into).
    pub destination: String,
    #[serde(default)]
    pub overwrite: Option<bool>,
    /// Required to copy a directory tree.
    #[serde(default)]
    pub recursive: Option<bool>,
    #[serde(default)]
    pub create_parents: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveArgs {
    pub source: String,
    /// Full new path.
    pub destination: String,
    #[serde(default)]
    pub overwrite: Option<bool>,
    #[serde(default)]
    pub create_parents: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteArgs {
    pub path: String,
    /// Required to delete a non-empty directory. Links are removed, never followed.
    #[serde(default)]
    pub recursive: Option<bool>,
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
    r.add(m("fs_stat", "Stat path", "Metadata for a file or directory (size, times, link status). Works for protected files without revealing content.", Read), stat);
    r.add(
        m(
            "fs_exists",
            "Path exists",
            "Check whether a path exists.",
            Read,
        ),
        exists,
    );
    r.add(
        m(
            "fs_list",
            "List directory",
            "List a directory. Protected entries are flagged; their content is never returned.",
            Read,
        ),
        list,
    );
    r.add(
        m(
            "fs_find",
            "Find in directory",
            "Find files under a directory by glob pattern.",
            Read,
        ),
        find,
    );
    r.add(
        m(
            "fs_get_many_metadata",
            "Metadata for many paths",
            "Metadata for several paths in one call (bounded).",
            Read,
        ),
        get_many,
    );
    r.add(m("fs_read_text", "Read text file", "Read a text file (UTF-8/UTF-16). Large files return metadata and must be read in ranges (offset/length or start_line/end_line). Content is redacted; protected files are denied.", Read), read_text);
    r.add(m("fs_read_bytes", "Read bytes", "Read a byte range as base64. Protected files and binaries containing credential-like data are denied.", Read), read_bytes);
    r.add(m("fs_write_text", "Write text file", "Create or replace a text file. Free inside Documents\\Projects; elsewhere local approval is required (the result will say approval_required).", Write), write_text);
    r.add(
        m(
            "fs_write_bytes",
            "Write bytes",
            "Write base64 content to a file (same policy as fs_write_text).",
            Write,
        ),
        write_bytes,
    );
    r.add(
        m(
            "fs_patch",
            "Patch text file",
            "Apply exact-text replacements to a file atomically through one verified handle.",
            Write,
        ),
        patch,
    );
    r.add(
        m(
            "fs_mkdir",
            "Create directory",
            "Create a directory (and parents).",
            Write,
        ),
        mkdir,
    );
    r.add(m("fs_copy", "Copy", "Copy a file or directory tree. Links inside a copied tree are skipped, and protected sources cannot be copied.", Write), copy);
    r.add(
        m(
            "fs_move",
            "Move/rename",
            "Move or rename a file or directory.",
            Destructive,
        ),
        move_,
    );
    r.add(
        m(
            "fs_delete",
            "Delete",
            "Delete a file, link or (with recursive) directory tree.",
            Destructive,
        ),
        delete,
    );
}

fn resolve(ctx: &ToolCtx, input: &str, follow: bool) -> LpResult<Canonical> {
    broker::resolve(input, &ctx.core.trusted_root(), &ctx.core.env, follow)
}

fn fs_decision(ctx: &ToolCtx, c: &Canonical, access: FsAccess) -> workstation_policy::Decision {
    ctx.with_policy(EntryPoint::Structured, |e, pc| {
        e.evaluate_fs(&c.path, access, pc)
    })
}

fn summary(ctx: &ToolCtx, paths: Vec<String>, impact: &str) -> ApprovalSummary {
    ApprovalSummary {
        paths,
        command: None,
        cwd: None,
        arguments: Some(super::truncate_args(
            &ctx.core.redactor.redact_json(&ctx.raw_args).0,
        )),
        impact: impact.to_string(),
        session_scope_label: String::new(),
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> LpResult<T> + Send + 'static,
) -> LpResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(LpError::internal)?
}

async fn stat(ctx: Arc<ToolCtx>, a: StatArgs) -> LpResult<Value> {
    let follow = a.follow_links.unwrap_or(true);
    let c = resolve(&ctx, &a.path, follow)?;
    ctx.note(|n| n.paths.push(c.path.display().to_string()));
    ctx.authorize(
        vec![fs_decision(&ctx, &c, FsAccess::Metadata)],
        json!(null),
        Default::default(),
    )?;
    let engine = ctx.core.policy();
    let md = blocking(move || broker::stat(&c, follow)).await?;
    let protected = engine
        .protected
        .check(std::path::Path::new(&md.path), true)
        .is_some();
    ok(json!({ "metadata": md, "protected": protected }))
}

async fn exists(ctx: Arc<ToolCtx>, a: PathArgs) -> LpResult<Value> {
    let c = resolve(&ctx, &a.path, true)?;
    ctx.authorize(
        vec![fs_decision(&ctx, &c, FsAccess::Metadata)],
        json!(null),
        Default::default(),
    )?;
    ok(json!({ "path": c.path.display().to_string(), "exists": c.exists, "is_dir": c.is_dir }))
}

async fn list(ctx: Arc<ToolCtx>, a: ListArgs) -> LpResult<Value> {
    let c = resolve(&ctx, &a.path, true)?;
    ctx.note(|n| n.paths.push(c.path.display().to_string()));
    ctx.authorize(
        vec![fs_decision(&ctx, &c, FsAccess::List)],
        json!(null),
        Default::default(),
    )?;
    let limit = a
        .max_entries
        .unwrap_or(500)
        .clamp(1, ctx.settings().limits.max_list_entries);
    let engine = ctx.core.policy();
    let path = c.path.display().to_string();
    let (entries, truncated) = blocking(move || broker::list(&engine, &c, limit)).await?;
    ok(json!({ "path": path, "count": entries.len(), "truncated": truncated, "entries": entries }))
}

async fn find(ctx: Arc<ToolCtx>, a: FindArgs) -> LpResult<Value> {
    let c = resolve(&ctx, &a.path, true)?;
    if !c.exists || !c.is_dir {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            "path is not an existing directory",
        ));
    }
    ctx.note(|n| n.paths.push(c.path.display().to_string()));
    ctx.authorize(
        vec![fs_decision(&ctx, &c, FsAccess::List)],
        json!(null),
        Default::default(),
    )?;
    let max = a
        .max_results
        .unwrap_or(200)
        .clamp(1, ctx.settings().limits.max_search_results);
    let include = a.include_ignored.unwrap_or(false);
    let engine = ctx.core.policy();
    let dir = c.path.clone();
    let pattern = a.pattern;
    let (hits, truncated) = blocking(move || search::find(&dir, &pattern, include, max)).await?;
    let results: Vec<Value> = hits
        .into_iter()
        .filter(|h| {
            engine.roots.classify_class(std::path::Path::new(&h.path)) != PathClass::ControlData
        })
        .map(|h| {
            let protected = engine
                .protected
                .check(std::path::Path::new(&h.path), true)
                .is_some();
            json!({ "path": h.path, "is_dir": h.is_dir, "size": h.size, "protected": protected })
        })
        .collect();
    ok(json!({ "count": results.len(), "truncated": truncated, "results": results }))
}

async fn get_many(ctx: Arc<ToolCtx>, a: ManyArgs) -> LpResult<Value> {
    let max = ctx.settings().limits.max_get_many_items;
    if a.paths.len() > max {
        return Err(LpError::new(
            ErrorCode::TooLarge,
            format!("at most {max} paths per call"),
        ));
    }
    let mut out = Vec::new();
    for p in a.paths {
        let item = match resolve(&ctx, &p, true) {
            Ok(c) => match fs_decision(&ctx, &c, FsAccess::Metadata) {
                workstation_policy::Decision::Allow { .. } => {
                    let c2 = c.clone();
                    match blocking(move || broker::stat(&c2, true)).await {
                        Ok(md) => json!({ "input": p, "metadata": md }),
                        Err(e) => {
                            json!({ "input": p, "error": { "code": e.code.as_str(), "message": e.message } })
                        }
                    }
                }
                workstation_policy::Decision::Deny { code, reason } => {
                    json!({ "input": p, "error": { "code": code.as_str(), "message": reason } })
                }
                workstation_policy::Decision::RequireApproval(_) => {
                    json!({ "input": p, "error": { "code": "PERMISSION_DENIED" } })
                }
            },
            Err(e) => {
                json!({ "input": p, "error": { "code": e.code.as_str(), "message": e.message } })
            }
        };
        out.push(item);
    }
    ok(json!({ "items": out }))
}

fn guard_writes(ctx: &ToolCtx, paths: &[&std::path::Path]) -> LpResult<()> {
    for p in paths {
        ctx.core
            .project_write_guard(&ctx.principal.client_id, p, None)?;
    }
    Ok(())
}

async fn read_text(ctx: Arc<ToolCtx>, a: ReadTextArgs) -> LpResult<Value> {
    let c = resolve(&ctx, &a.path, true)?;
    let path_s = c.path.display().to_string();
    ctx.note(|n| {
        n.paths.push(path_s.clone());
        n.source_path = Some(path_s.clone());
    });
    ctx.authorize(
        vec![fs_decision(&ctx, &c, FsAccess::Read)],
        json!(null),
        Default::default(),
    )?;
    if !c.exists {
        return Err(LpError::new(
            ErrorCode::PathNotFound,
            format!("{path_s} does not exist"),
        ));
    }
    if c.is_dir {
        return Err(LpError::invalid("the path is a directory; use fs_list"));
    }
    let max = ctx.settings().limits.max_read_bytes;
    let engine = ctx.core.policy();
    let line_mode = a.start_line.is_some() || a.end_line.is_some();
    if !line_mode && a.offset.is_none() && a.length.is_none() && c.size > max {
        return ok(json!({
            "path": path_s,
            "size": c.size,
            "content": null,
            "truncated": true,
            "message": format!("The file is {} bytes, larger than the {} byte read limit. Request a range with offset/length or start_line/end_line.", c.size, max),
        }));
    }
    if line_mode {
        if c.size > 64 * 1024 * 1024 {
            return Err(LpError::new(
                ErrorCode::TooLarge,
                "line ranges are supported for files up to 64 MiB; use offset/length",
            ));
        }
        let size = c.size;
        let r = blocking(move || broker::read(&engine, &c, 0, size)).await?;
        let (text, enc) = broker::decode_text(&r.bytes)
            .ok_or_else(|| LpError::invalid("the file is not text; use fs_read_bytes"))?;
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let total = lines.len();
        let start = a.start_line.unwrap_or(1).max(1);
        let end = a.end_line.unwrap_or(total).min(total);
        let mut content = String::new();
        let mut last = start.saturating_sub(1);
        for (i, l) in lines.iter().enumerate().take(end).skip(start - 1) {
            if (content.len() + l.len()) as u64 > max {
                break;
            }
            content.push_str(l);
            last = i + 1;
        }
        return ok(json!({
            "path": path_s,
            "encoding": enc,
            "size": size,
            "total_lines": total,
            "start_line": start,
            "end_line": last,
            "truncated": last < end,
            "content": content,
        }));
    }
    let offset = a.offset.unwrap_or(0);
    let length = a.length.unwrap_or(max).min(max);
    let r = blocking(move || broker::read(&engine, &c, offset, length)).await?;
    let (content, enc) = match broker::decode_text(&r.bytes) {
        Some(x) => x,
        None if offset > 0 || r.truncated => (
            String::from_utf8_lossy(&r.bytes).into_owned(),
            TextEncoding::Utf8,
        ),
        None => {
            return Err(LpError::invalid(
                "the file is not valid UTF-8/UTF-16 text; use fs_read_bytes",
            ));
        }
    };
    ok(json!({
        "path": path_s,
        "encoding": enc,
        "size": r.total_size,
        "offset": r.offset,
        "returned_bytes": r.bytes.len(),
        "truncated": r.truncated,
        "next_offset": if r.truncated { Some(r.offset + r.bytes.len() as u64) } else { None },
        "content": content,
    }))
}

async fn read_bytes(ctx: Arc<ToolCtx>, a: ReadBytesArgs) -> LpResult<Value> {
    let c = resolve(&ctx, &a.path, true)?;
    let path_s = c.path.display().to_string();
    ctx.note(|n| {
        n.paths.push(path_s.clone());
        n.source_path = Some(path_s.clone());
    });
    ctx.authorize(
        vec![fs_decision(&ctx, &c, FsAccess::Read)],
        json!(null),
        Default::default(),
    )?;
    let max = ctx.settings().limits.max_read_bytes;
    let offset = a.offset.unwrap_or(0);
    let length = a.length.unwrap_or(max).min(max);
    let engine = ctx.core.policy();
    let r = blocking(move || broker::read(&engine, &c, offset, length)).await?;
    // Never corrupt binaries with text replacement: deny instead when the
    // bytes contain credential-like data.
    if ctx
        .core
        .redactor
        .contains_secret(&String::from_utf8_lossy(&r.bytes))
    {
        return Err(LpError::new(
            ErrorCode::ProtectedResource,
            "This byte range contains credential-like data and cannot be returned.",
        ));
    }
    ok(json!({
        "path": path_s,
        "size": r.total_size,
        "offset": r.offset,
        "returned_bytes": r.bytes.len(),
        "truncated": r.truncated,
        "content_base64": base64::engine::general_purpose::STANDARD.encode(&r.bytes),
    }))
}

fn mode_of(m: Option<ModeArg>) -> WriteMode {
    match m {
        Some(ModeArg::CreateNew) => WriteMode::CreateNew,
        Some(ModeArg::Append) => WriteMode::Append,
        _ => WriteMode::Overwrite,
    }
}

async fn write_common(
    ctx: Arc<ToolCtx>,
    path: String,
    bytes: Vec<u8>,
    mode: WriteMode,
    create_parents: bool,
) -> LpResult<Value> {
    let limits = ctx.settings().limits.clone();
    if bytes.len() as u64 > limits.max_write_bytes {
        return Err(LpError::new(
            ErrorCode::TooLarge,
            format!(
                "content exceeds the {} byte write limit",
                limits.max_write_bytes
            ),
        ));
    }
    let c = resolve(&ctx, &path, true)?;
    let p = c.path.display().to_string();
    ctx.note(|n| n.paths.push(p.clone()));
    let access = if c.exists {
        FsAccess::Write
    } else {
        FsAccess::Create
    };
    let d = fs_decision(&ctx, &c, access);
    ctx.authorize(
        vec![d],
        json!({ "op": "write", "path": p, "identity": broker::identity_string(&c), "mode": format!("{mode:?}") }),
        summary(&ctx, vec![p.clone()], &format!("Writes {} bytes to {p}", bytes.len())),
    )?;
    guard_writes(&ctx, &[&c.path])?;
    let engine = ctx.core.policy();
    let out = blocking(move || broker::write(&engine, &c, &bytes, mode, create_parents)).await?;
    ok(out)
}

async fn write_text(ctx: Arc<ToolCtx>, a: WriteTextArgs) -> LpResult<Value> {
    let enc = match a.encoding {
        Some(EncodingArg::Utf8Bom) => TextEncoding::Utf8Bom,
        Some(EncodingArg::Utf16le) => TextEncoding::Utf16Le,
        _ => TextEncoding::Utf8,
    };
    let bytes = broker::encode_text(&a.content, enc);
    write_common(
        ctx,
        a.path,
        bytes,
        mode_of(a.mode),
        a.create_parents.unwrap_or(true),
    )
    .await
}

async fn write_bytes(ctx: Arc<ToolCtx>, a: WriteBytesArgs) -> LpResult<Value> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(a.content_base64.trim())
        .map_err(|_| LpError::invalid("content_base64 is not valid base64"))?;
    write_common(
        ctx,
        a.path,
        bytes,
        mode_of(a.mode),
        a.create_parents.unwrap_or(true),
    )
    .await
}

async fn patch(ctx: Arc<ToolCtx>, a: PatchArgs) -> LpResult<Value> {
    if a.edits.is_empty() || a.edits.len() > 200 {
        return Err(LpError::invalid("provide 1-200 edits"));
    }
    let c = resolve(&ctx, &a.path, true)?;
    let p = c.path.display().to_string();
    ctx.note(|n| n.paths.push(p.clone()));
    let d = fs_decision(&ctx, &c, FsAccess::Write);
    ctx.authorize(
        vec![d],
        json!({ "op": "patch", "path": p, "identity": broker::identity_string(&c) }),
        summary(&ctx, vec![p.clone()], &format!("Edits {p}")),
    )?;
    guard_writes(&ctx, &[&c.path])?;
    let edits: Vec<Edit> = a
        .edits
        .into_iter()
        .map(|e| Edit {
            old_text: e.old_text,
            new_text: e.new_text,
            expected_replacements: e.expected_replacements,
        })
        .collect();
    let max = ctx.settings().limits.max_write_bytes.max(16 * 1024 * 1024);
    let engine = ctx.core.policy();
    ok(blocking(move || broker::patch(&engine, &c, &edits, max)).await?)
}

async fn mkdir(ctx: Arc<ToolCtx>, a: MkdirArgs) -> LpResult<Value> {
    let c = resolve(&ctx, &a.path, true)?;
    let p = c.path.display().to_string();
    ctx.note(|n| n.paths.push(p.clone()));
    let d = fs_decision(&ctx, &c, FsAccess::Mkdir);
    ctx.authorize(
        vec![d],
        json!({ "op": "mkdir", "path": p, "identity": broker::identity_string(&c) }),
        summary(&ctx, vec![p.clone()], &format!("Creates directory {p}")),
    )?;
    guard_writes(&ctx, &[&c.path])?;
    let recursive = a.recursive.unwrap_or(true);
    let created = blocking(move || broker::mkdir(&c, recursive)).await?;
    // A new top-level folder is a new project.
    if created && ctx.core.policy().roots.is_trusted(&PathBuf::from(&p)) {
        ctx.core.schedule_index_refresh();
    }
    ok(json!({ "path": p, "created": created }))
}

async fn copy(ctx: Arc<ToolCtx>, a: CopyArgs) -> LpResult<Value> {
    let src = resolve(&ctx, &a.source, true)?;
    let dst = resolve(&ctx, &a.destination, true)?;
    let (sp, dp) = (
        src.path.display().to_string(),
        dst.path.display().to_string(),
    );
    ctx.note(|n| {
        n.paths.push(sp.clone());
        n.paths.push(dp.clone());
        n.source_path = Some(sp.clone());
    });
    let d1 = fs_decision(&ctx, &src, FsAccess::Read);
    let d2 = fs_decision(&ctx, &dst, FsAccess::CopyDestination);
    ctx.authorize(
        vec![d1, d2],
        json!({ "op": "copy", "source": sp, "source_identity": broker::identity_string(&src), "destination": dp, "destination_identity": broker::identity_string(&dst) }),
        summary(&ctx, vec![sp.clone(), dp.clone()], &format!("Copies {sp} to {dp}")),
    )?;
    guard_writes(&ctx, &[&dst.path])?;
    let engine = ctx.core.policy();
    let max = 4 * 1024 * 1024 * 1024u64;
    let (overwrite, recursive, parents) = (
        a.overwrite.unwrap_or(false),
        a.recursive.unwrap_or(false),
        a.create_parents.unwrap_or(true),
    );
    ok(
        blocking(move || broker::copy(&engine, &src, &dst, overwrite, recursive, parents, max))
            .await?,
    )
}

async fn move_(ctx: Arc<ToolCtx>, a: MoveArgs) -> LpResult<Value> {
    let src = resolve(&ctx, &a.source, false)?;
    let dst = resolve(&ctx, &a.destination, false)?;
    let (sp, dp) = (
        src.path.display().to_string(),
        dst.path.display().to_string(),
    );
    ctx.note(|n| {
        n.paths.push(sp.clone());
        n.paths.push(dp.clone());
    });
    let d1 = fs_decision(&ctx, &src, FsAccess::MoveSource);
    let d2 = fs_decision(&ctx, &dst, FsAccess::MoveDestination);
    ctx.authorize(
        vec![d1, d2],
        json!({ "op": "move", "source": sp, "source_identity": broker::identity_string(&src), "destination": dp, "destination_identity": broker::identity_string(&dst) }),
        summary(&ctx, vec![sp.clone(), dp.clone()], &format!("Moves {sp} to {dp}")),
    )?;
    guard_writes(&ctx, &[&src.path, &dst.path])?;
    let engine = ctx.core.policy();
    let (overwrite, parents) = (
        a.overwrite.unwrap_or(false),
        a.create_parents.unwrap_or(false),
    );
    let out = blocking(move || broker::rename(&engine, &src, &dst, overwrite, parents)).await?;
    ctx.core.schedule_index_refresh();
    ok(out)
}

async fn delete(ctx: Arc<ToolCtx>, a: DeleteArgs) -> LpResult<Value> {
    let c = resolve(&ctx, &a.path, false)?;
    let p = c.path.display().to_string();
    ctx.note(|n| n.paths.push(p.clone()));
    if c.path.parent().is_none()
        || workstation_core::paths::eq_ci(&c.path, &ctx.core.trusted_root())
    {
        return Err(LpError::denied(
            "Deleting a drive root or the trusted workspace root is not permitted.",
        ));
    }
    let d = fs_decision(&ctx, &c, FsAccess::Delete);
    ctx.authorize(
        vec![d],
        json!({ "op": "delete", "path": p, "identity": broker::identity_string(&c), "recursive": a.recursive.unwrap_or(false) }),
        summary(&ctx, vec![p.clone()], &format!("Deletes {p}{}", if a.recursive.unwrap_or(false) { " and everything inside it" } else { "" })),
    )?;
    guard_writes(&ctx, &[&c.path])?;
    let engine = ctx.core.policy();
    let recursive = a.recursive.unwrap_or(false);
    let out = blocking(move || broker::delete(&engine, &c, recursive)).await?;
    ctx.core.schedule_index_refresh();
    ok(out)
}
