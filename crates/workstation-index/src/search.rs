//! Bounded content and glob search using ripgrep's libraries.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use grep_regex::RegexMatcherBuilder;
use grep_searcher::sinks::UTF8;
use grep_searcher::{BinaryDetection, SearcherBuilder};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use workstation_core::{LpError, LpResult};

use crate::is_ignored_component;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSearchOptions {
    pub query: String,
    pub regex: bool,
    pub case_sensitive: bool,
    pub glob: Option<String>,
    pub max_results: usize,
    pub context_lines: usize,
    pub include_ignored: bool,
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextHit {
    pub path: String,
    pub line: u64,
    pub text: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSearchResult {
    pub hits: Vec<TextHit>,
    pub truncated: bool,
    pub files_searched: usize,
    /// Files skipped because they are protected (content never searched).
    pub protected_skipped: usize,
}

fn walker(scope: &Path, include_ignored: bool, glob: Option<&str>) -> LpResult<ignore::Walk> {
    let mut b = ignore::WalkBuilder::new(scope);
    b.hidden(false)
        .follow_links(false)
        .git_ignore(!include_ignored)
        .git_global(false)
        .git_exclude(false)
        .parents(!include_ignored)
        .add_custom_ignore_filename(".localpilotignore")
        .max_depth(Some(64));
    if !include_ignored {
        b.filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !(e.file_type().map(|t| t.is_dir()).unwrap_or(false) && is_ignored_component(&name))
        });
    }
    if let Some(g) = glob {
        let mut ob = ignore::overrides::OverrideBuilder::new(scope);
        for part in g.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            ob.add(part)
                .map_err(|e| LpError::invalid(format!("invalid glob '{part}': {e}")))?;
        }
        b.overrides(
            ob.build()
                .map_err(|e| LpError::invalid(format!("invalid glob: {e}")))?,
        );
    }
    Ok(b.build())
}

/// Search file contents under `scope`. `is_protected` is consulted for every
/// file before it is opened; protected files are never searched.
pub fn search_text(
    scope: &Path,
    opts: &TextSearchOptions,
    is_protected: &dyn Fn(&Path) -> bool,
) -> LpResult<TextSearchResult> {
    if opts.query.is_empty() {
        return Err(LpError::invalid("query must not be empty"));
    }
    let pattern = if opts.regex {
        opts.query.clone()
    } else {
        regex::escape(&opts.query)
    };
    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(!opts.case_sensitive)
        .line_terminator(Some(b'\n'))
        .build(&pattern)
        .map_err(|e| LpError::invalid(format!("invalid pattern: {e}")))?;
    let mut searcher = SearcherBuilder::new()
        .binary_detection(BinaryDetection::quit(b'\x00'))
        .line_number(true)
        .build();
    let hits: Arc<Mutex<Vec<TextHit>>> = Arc::new(Mutex::new(Vec::new()));
    let mut files = 0usize;
    let mut protected_skipped = 0usize;
    let mut truncated = false;
    let max = opts.max_results.clamp(1, 5000);
    for entry in walker(scope, opts.include_ignored, opts.glob.as_deref())?.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        if is_protected(path) {
            protected_skipped += 1;
            continue;
        }
        if entry
            .metadata()
            .map(|m| m.len() > opts.max_file_bytes)
            .unwrap_or(true)
        {
            continue;
        }
        files += 1;
        let before_len = hits.lock().len();
        if before_len >= max {
            truncated = true;
            break;
        }
        let path_s = path.display().to_string();
        let sink_hits = hits.clone();
        let count = AtomicUsize::new(before_len);
        let _ = searcher.search_path(
            &matcher,
            path,
            UTF8(|line_no, line| {
                if count.fetch_add(1, Ordering::SeqCst) >= max {
                    return Ok(false);
                }
                sink_hits.lock().push(TextHit {
                    path: path_s.clone(),
                    line: line_no,
                    text: truncate_line(line),
                    before: Vec::new(),
                    after: Vec::new(),
                });
                Ok(true)
            }),
        );
        if count.load(Ordering::SeqCst) > max {
            truncated = true;
        }
    }
    let mut hits = Arc::try_unwrap(hits)
        .map(|m| m.into_inner())
        .unwrap_or_default();
    hits.truncate(max);
    if opts.context_lines > 0 {
        add_context(&mut hits, opts.context_lines.min(10));
    }
    Ok(TextSearchResult {
        hits,
        truncated,
        files_searched: files,
        protected_skipped,
    })
}

fn truncate_line(line: &str) -> String {
    let l = line.trim_end_matches(['\r', '\n']);
    if l.chars().count() > 400 {
        l.chars().take(400).collect::<String>() + "…"
    } else {
        l.to_string()
    }
}

fn add_context(hits: &mut [TextHit], n: usize) {
    let mut cache: Option<(String, Vec<String>)> = None;
    for h in hits.iter_mut() {
        if cache.as_ref().map(|(p, _)| p != &h.path).unwrap_or(true) {
            let lines = std::fs::read_to_string(&h.path)
                .map(|t| t.lines().map(truncate_line).collect())
                .unwrap_or_default();
            cache = Some((h.path.clone(), lines));
        }
        let lines = &cache.as_ref().unwrap().1;
        let idx = (h.line as usize).saturating_sub(1);
        let start = idx.saturating_sub(n);
        h.before = lines
            .get(start..idx)
            .map(|s| s.to_vec())
            .unwrap_or_default();
        h.after = lines
            .get(idx + 1..(idx + 1 + n).min(lines.len()))
            .map(|s| s.to_vec())
            .unwrap_or_default();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindHit {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ms: i64,
}

/// Glob search (e.g. `**/*.rs`) below `scope`.
pub fn find(
    scope: &Path,
    pattern: &str,
    include_ignored: bool,
    max: usize,
) -> LpResult<(Vec<FindHit>, bool)> {
    let glob = globset::GlobBuilder::new(pattern)
        .case_insensitive(true)
        .literal_separator(false)
        .build()
        .map_err(|e| LpError::invalid(format!("invalid glob: {e}")))?
        .compile_matcher();
    let mut out = Vec::new();
    let mut truncated = false;
    for entry in walker(scope, include_ignored, None)?.flatten() {
        if entry.depth() == 0 {
            continue;
        }
        let path: PathBuf = entry.path().to_path_buf();
        let rel = path.strip_prefix(scope).unwrap_or(&path);
        let name_match = rel.file_name().map(|n| glob.is_match(n)).unwrap_or(false);
        let name_only_pattern = !pattern.contains('/') && !pattern.contains('\\');
        if !(glob.is_match(rel) || name_only_pattern && name_match) {
            continue;
        }
        if out.len() >= max {
            truncated = true;
            break;
        }
        let meta = entry.metadata().ok();
        out.push(FindHit {
            path: path.display().to_string(),
            is_dir: entry.file_type().map(|t| t.is_dir()).unwrap_or(false),
            size: meta.as_ref().map(|m| m.len()).unwrap_or(0),
            modified_ms: meta
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        });
    }
    Ok((out, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_search_with_protection_and_context() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src").join("a.rs"),
            "one\nfn needle() {}\nthree\n",
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), "NEEDLE=secret\n").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules").join("x.js"), "needle").unwrap();
        let opts = TextSearchOptions {
            query: "needle".into(),
            regex: false,
            case_sensitive: false,
            glob: None,
            max_results: 50,
            context_lines: 1,
            include_ignored: false,
            max_file_bytes: 1 << 20,
        };
        let r = search_text(dir.path(), &opts, &|p| {
            p.file_name().map(|n| n == ".env").unwrap_or(false)
        })
        .unwrap();
        assert_eq!(r.hits.len(), 1, "{:?}", r.hits);
        assert_eq!(r.hits[0].line, 2);
        assert_eq!(r.hits[0].before, vec!["one"]);
        assert_eq!(r.hits[0].after, vec!["three"]);
        assert_eq!(r.protected_skipped, 1);
    }

    #[test]
    fn glob_find() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a").join("b")).unwrap();
        std::fs::write(dir.path().join("a").join("b").join("x.rs"), "").unwrap();
        std::fs::write(dir.path().join("a").join("y.txt"), "").unwrap();
        let (hits, _) = find(dir.path(), "*.rs", false, 10).unwrap();
        assert_eq!(hits.len(), 1);
        let (hits, _) = find(dir.path(), "a/**/*.rs", false, 10).unwrap();
        assert_eq!(hits.len(), 1);
    }
}
