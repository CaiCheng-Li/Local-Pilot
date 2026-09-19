//! Project discovery and the folder map (plan section 7).
//!
//! Every direct child directory of the trusted Projects root is a project;
//! nested directories with project markers (a repository inside a folder, a
//! workspace member) are indexed as nested projects. Metadata and file names
//! live in SQLite with FTS5 (trigram) tables; a filesystem watcher keeps the
//! index current without rescanning the whole tree.

pub mod search;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher};
use parking_lot::{Mutex, RwLock};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use workstation_core::db::{Db, Migration};
use workstation_core::paths::starts_with_ci;
use workstation_core::redaction::Redactor;
use workstation_core::{ErrorCode, LpError, LpResult, ids, time};

/// Directories skipped by indexing and search unless explicitly requested.
pub const DEFAULT_IGNORED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "bin",
    "obj",
    ".next",
    "__pycache__",
    ".gradle",
    ".turbo",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    "coverage",
];

const MAX_FILES_PER_PROJECT: usize = 50_000;
const NESTED_DEPTH: usize = 3;

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "index_init",
    sql: r#"
CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    canonical_path TEXT NOT NULL UNIQUE COLLATE NOCASE,
    detected_project_types TEXT NOT NULL,
    detected_languages TEXT NOT NULL,
    git_repository INTEGER NOT NULL,
    git_remote_urls TEXT NOT NULL,
    default_branch TEXT,
    last_scan_time INTEGER NOT NULL,
    last_modified_time INTEGER,
    parent_project_id TEXT,
    locked INTEGER NOT NULL DEFAULT 0,
    file_count INTEGER NOT NULL DEFAULT 0,
    files_truncated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE project_aliases (
    project_id TEXT NOT NULL,
    alias TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (project_id, alias)
);
CREATE VIRTUAL TABLE project_fts USING fts5(project_id UNINDEXED, name, aliases, path, tokenize = 'trigram');
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    rel_path TEXT NOT NULL COLLATE NOCASE,
    name TEXT NOT NULL,
    is_dir INTEGER NOT NULL,
    size INTEGER NOT NULL,
    modified INTEGER NOT NULL,
    UNIQUE(project_id, rel_path)
);
CREATE INDEX idx_files_project ON files(project_id);
CREATE VIRTUAL TABLE files_fts USING fts5(name, rel_path, content = 'files', content_rowid = 'id', tokenize = 'trigram');
CREATE TRIGGER files_ai AFTER INSERT ON files BEGIN
  INSERT INTO files_fts(rowid, name, rel_path) VALUES (new.id, new.name, new.rel_path);
END;
CREATE TRIGGER files_ad AFTER DELETE ON files BEGIN
  INSERT INTO files_fts(files_fts, rowid, name, rel_path) VALUES ('delete', old.id, old.name, old.rel_path);
END;
CREATE TRIGGER files_au AFTER UPDATE ON files BEGIN
  INSERT INTO files_fts(files_fts, rowid, name, rel_path) VALUES ('delete', old.id, old.name, old.rel_path);
  INSERT INTO files_fts(rowid, name, rel_path) VALUES (new.id, new.name, new.rel_path);
END;
"#,
}];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub project_id: String,
    pub display_name: String,
    pub canonical_path: String,
    pub detected_project_types: Vec<String>,
    pub detected_languages: Vec<String>,
    pub git_repository: bool,
    pub git_remote_urls: Vec<String>,
    pub default_branch: Option<String>,
    pub last_scan_time: i64,
    pub last_modified_time: Option<i64>,
    pub aliases: Vec<String>,
    pub parent_project_id: Option<String>,
    pub locked: bool,
    pub file_count: i64,
    pub files_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMatch {
    pub name: String,
    pub path: String,
    pub project_id: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHit {
    pub project_id: String,
    pub project_name: String,
    pub path: String,
    pub rel_path: String,
    pub is_dir: bool,
    pub size: i64,
    pub modified: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResult {
    pub matches: Vec<ProjectMatch>,
    /// When no project matched, directories/files whose names match.
    pub fallback: Vec<FileHit>,
}

struct Markers {
    types: BTreeSet<String>,
    languages: BTreeSet<String>,
}

fn detect_markers(dir: &Path) -> Option<Markers> {
    let mut types = BTreeSet::new();
    let mut langs = BTreeSet::new();
    let rd = std::fs::read_dir(dir).ok()?;
    let mut any = false;
    for e in rd.flatten().take(500) {
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        let mut hit = |t: &str, l: &[&str]| {
            types.insert(t.to_string());
            for x in l {
                langs.insert(x.to_string());
            }
            any = true;
        };
        match name.as_str() {
            ".git" => hit("git", &[]),
            "package.json" => hit("node", &["JavaScript"]),
            "tsconfig.json" => hit("typescript", &["TypeScript"]),
            "cargo.toml" => hit("cargo", &["Rust"]),
            "pyproject.toml" | "requirements.txt" | "pipfile" | "poetry.lock" | "setup.py"
            | "setup.cfg" => hit("python", &["Python"]),
            "go.mod" => hit("go", &["Go"]),
            "cmakelists.txt" => hit("cmake", &["C", "C++"]),
            "pom.xml" => hit("maven", &["Java"]),
            "build.gradle"
            | "build.gradle.kts"
            | "gradlew"
            | "settings.gradle"
            | "settings.gradle.kts" => hit("gradle", &["Java", "Kotlin"]),
            "composer.json" => hit("composer", &["PHP"]),
            "gemfile" => hit("ruby", &["Ruby"]),
            "pubspec.yaml" => hit("flutter", &["Dart"]),
            "deno.json" | "deno.jsonc" => hit("deno", &["TypeScript"]),
            "makefile" => hit("make", &[]),
            _ => {
                if name.ends_with(".sln") {
                    hit("dotnet-solution", &["C#"]);
                } else if name.ends_with(".csproj") {
                    hit("dotnet", &["C#"]);
                } else if name.ends_with(".fsproj") {
                    hit("dotnet", &["F#"]);
                } else if name.ends_with(".vcxproj") {
                    hit("msbuild-cpp", &["C++"]);
                }
            }
        }
    }
    if any {
        Some(Markers {
            types,
            languages: langs,
        })
    } else {
        None
    }
}

/// Read remotes and default branch from `.git` without launching git.
fn git_info(dir: &Path, redactor: &Redactor) -> (bool, Vec<String>, Option<String>) {
    let dot = dir.join(".git");
    let git_dir = if dot.is_dir() {
        dot
    } else if dot.is_file() {
        match std::fs::read_to_string(&dot) {
            Ok(t) => match t.trim().strip_prefix("gitdir:") {
                Some(p) => {
                    let p = PathBuf::from(p.trim());
                    if p.is_absolute() { p } else { dir.join(p) }
                }
                None => return (true, Vec::new(), None),
            },
            Err(_) => return (true, Vec::new(), None),
        }
    } else {
        return (false, Vec::new(), None);
    };
    let mut remotes = Vec::new();
    // Worktrees keep config in the common dir.
    let common = std::fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .map(|c| git_dir.join(c.trim()))
        .unwrap_or_else(|| git_dir.clone());
    if let Ok(cfg) = std::fs::read_to_string(common.join("config")) {
        let mut in_remote = false;
        for line in cfg.lines() {
            let l = line.trim();
            if l.starts_with('[') {
                in_remote = l.starts_with("[remote ");
            } else if in_remote
                && let Some(v) = l.strip_prefix("url").map(|r| r.trim_start())
                && let Some(v) = v.strip_prefix('=')
            {
                remotes.push(redactor.redact_string(v.trim()));
            }
        }
    }
    let default_branch = std::fs::read_to_string(
        common
            .join("refs")
            .join("remotes")
            .join("origin")
            .join("HEAD"),
    )
    .ok()
    .and_then(|t| {
        t.trim()
            .strip_prefix("ref: refs/remotes/origin/")
            .map(|s| s.to_string())
    });
    (true, remotes, default_branch)
}

fn row_to_project(r: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    let parse = |s: String| serde_json::from_str::<Vec<String>>(&s).unwrap_or_default();
    Ok(Project {
        project_id: r.get(0)?,
        display_name: r.get(1)?,
        canonical_path: r.get(2)?,
        detected_project_types: parse(r.get(3)?),
        detected_languages: parse(r.get(4)?),
        git_repository: r.get(5)?,
        git_remote_urls: parse(r.get(6)?),
        default_branch: r.get(7)?,
        last_scan_time: r.get(8)?,
        last_modified_time: r.get(9)?,
        parent_project_id: r.get(10)?,
        locked: r.get(11)?,
        file_count: r.get(12)?,
        files_truncated: r.get(13)?,
        aliases: Vec::new(),
    })
}

const PROJECT_COLS: &str = "project_id, display_name, canonical_path, detected_project_types, detected_languages, git_repository, git_remote_urls, default_branch, last_scan_time, last_modified_time, parent_project_id, locked, file_count, files_truncated";

struct Inner {
    db: Db,
    root: PathBuf,
    redactor: Redactor,
    cache: RwLock<Vec<Project>>,
    watcher: Mutex<Option<notify::RecommendedWatcher>>,
    scanning: Mutex<()>,
}

#[derive(Clone)]
pub struct ProjectIndex {
    inner: Arc<Inner>,
}

pub fn is_ignored_component(name: &str) -> bool {
    DEFAULT_IGNORED_DIRS
        .iter()
        .any(|d| d.eq_ignore_ascii_case(name))
}

impl ProjectIndex {
    pub fn open(db_path: &Path, root: PathBuf, redactor: Redactor) -> LpResult<Self> {
        let db = Db::open(db_path, MIGRATIONS)?;
        let s = Self {
            inner: Arc::new(Inner {
                db,
                root,
                redactor,
                cache: RwLock::new(Vec::new()),
                watcher: Mutex::new(None),
                scanning: Mutex::new(()),
            }),
        };
        s.reload_cache()?;
        Ok(s)
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    fn reload_cache(&self) -> LpResult<()> {
        let projects = self.inner.db.read_sync(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {PROJECT_COLS} FROM projects ORDER BY display_name COLLATE NOCASE"
            ))?;
            let mut list: Vec<Project> = stmt
                .query_map([], row_to_project)?
                .collect::<Result<_, _>>()?;
            let mut stmt = c.prepare("SELECT project_id, alias FROM project_aliases")?;
            let aliases: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            let mut map: HashMap<String, Vec<String>> = HashMap::new();
            for (id, a) in aliases {
                map.entry(id).or_default().push(a);
            }
            for p in &mut list {
                p.aliases = map.remove(&p.project_id).unwrap_or_default();
            }
            Ok(list)
        })?;
        *self.inner.cache.write() = projects;
        Ok(())
    }

    pub fn list(&self) -> Vec<Project> {
        self.inner.cache.read().clone()
    }

    pub fn get(&self, id_or_name: &str) -> Option<Project> {
        let cache = self.inner.cache.read();
        cache
            .iter()
            .find(|p| p.project_id == id_or_name)
            .or_else(|| {
                cache.iter().find(|p| {
                    p.display_name.eq_ignore_ascii_case(id_or_name) && p.parent_project_id.is_none()
                })
            })
            .or_else(|| {
                cache
                    .iter()
                    .find(|p| p.display_name.eq_ignore_ascii_case(id_or_name))
            })
            .cloned()
    }

    /// The deepest indexed project containing `path`.
    pub fn project_for_path(&self, path: &Path) -> Option<Project> {
        let cache = self.inner.cache.read();
        cache
            .iter()
            .filter(|p| starts_with_ci(path, Path::new(&p.canonical_path)))
            .max_by_key(|p| p.canonical_path.len())
            .cloned()
    }

    /// Top-level project (direct child of the root) containing `path`.
    pub fn top_project_for_path(&self, path: &Path) -> Option<Project> {
        let mut p = self.project_for_path(path)?;
        let cache = self.inner.cache.read();
        while let Some(parent) = p
            .parent_project_id
            .as_ref()
            .and_then(|id| cache.iter().find(|x| &x.project_id == id))
        {
            p = parent.clone();
        }
        Some(p)
    }

    /// Full discovery scan of the root (initial scan / explicit refresh).
    pub fn full_scan(&self) -> LpResult<usize> {
        let _guard = self.inner.scanning.lock();
        let root = self.inner.root.clone();
        std::fs::create_dir_all(&root).ok();
        let mut found: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
        let rd = std::fs::read_dir(&root)
            .map_err(|e| LpError::internal(format!("scan projects root: {e}")))?;
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let path = e.path();
            found.push((path.clone(), None));
            collect_nested(&path, &path, 1, &mut found);
        }
        let seen: BTreeSet<String> = found
            .iter()
            .map(|(p, _)| p.display().to_string().to_lowercase())
            .collect();
        // Drop projects that no longer exist.
        self.inner.db.write_sync(|c| {
            let mut stmt = c.prepare("SELECT project_id, canonical_path FROM projects")?;
            let existing: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            for (id, path) in existing {
                if !seen.contains(&path.to_lowercase()) {
                    c.execute("DELETE FROM projects WHERE project_id = ?1", [&id])?;
                    c.execute("DELETE FROM files WHERE project_id = ?1", [&id])?;
                    c.execute("DELETE FROM project_fts WHERE project_id = ?1", [&id])?;
                    c.execute("DELETE FROM project_aliases WHERE project_id = ?1", [&id])?;
                }
            }
            Ok(())
        })?;
        let mut ids: HashMap<String, String> = HashMap::new();
        for (path, parent) in &found {
            let parent_id = parent
                .as_ref()
                .and_then(|p| ids.get(&p.display().to_string().to_lowercase()).cloned());
            let id = self.upsert_project(path, parent_id)?;
            ids.insert(path.display().to_string().to_lowercase(), id);
        }
        self.reload_cache()?;
        for (path, _) in &found {
            if let Some(id) = ids.get(&path.display().to_string().to_lowercase()) {
                self.index_files(id, path)?;
            }
        }
        self.reload_cache()?;
        Ok(found.len())
    }

    fn upsert_project(&self, path: &Path, parent_id: Option<String>) -> LpResult<String> {
        let markers = detect_markers(path);
        let (is_git, remotes, default_branch) = git_info(path, &self.inner.redactor);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let modified = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64);
        let types: Vec<String> = markers
            .as_ref()
            .map(|m| m.types.iter().cloned().collect())
            .unwrap_or_default();
        let langs: Vec<String> = markers
            .as_ref()
            .map(|m| m.languages.iter().cloned().collect())
            .unwrap_or_default();
        let path_s = path.display().to_string();
        self.inner.db.write_sync(|c| {
            let existing: Option<String> = c
                .query_row("SELECT project_id FROM projects WHERE canonical_path = ?1", [&path_s], |r| r.get(0))
                .optional()?;
            let id = existing.clone().unwrap_or_else(ids::project_id);
            let now = time::now_ms();
            if existing.is_some() {
                c.execute(
                    "UPDATE projects SET display_name=?2, detected_project_types=?3, detected_languages=?4, git_repository=?5, git_remote_urls=?6, default_branch=?7, last_scan_time=?8, last_modified_time=?9, parent_project_id=?10 WHERE project_id=?1",
                    params![id, name, serde_json::to_string(&types).unwrap(), serde_json::to_string(&langs).unwrap(), is_git, serde_json::to_string(&remotes).unwrap(), default_branch, now, modified, parent_id],
                )?;
            } else {
                c.execute(
                    &format!("INSERT INTO projects ({PROJECT_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,0,0)"),
                    params![id, name, path_s, serde_json::to_string(&types).unwrap(), serde_json::to_string(&langs).unwrap(), is_git, serde_json::to_string(&remotes).unwrap(), default_branch, now, modified, parent_id],
                )?;
            }
            let aliases: Vec<String> = {
                let mut stmt = c.prepare("SELECT alias FROM project_aliases WHERE project_id = ?1")?;
                stmt.query_map([&id], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            c.execute("DELETE FROM project_fts WHERE project_id = ?1", [&id])?;
            c.execute(
                "INSERT INTO project_fts (project_id, name, aliases, path) VALUES (?1, ?2, ?3, ?4)",
                params![id, name, aliases.join(" "), path_s],
            )?;
            Ok(id)
        })
    }

    fn index_files(&self, project_id: &str, dir: &Path) -> LpResult<()> {
        let mut rows: Vec<(String, String, bool, i64, i64)> = Vec::new();
        let mut truncated = false;
        let nested: Vec<PathBuf> = self
            .list()
            .into_iter()
            .filter(|p| p.parent_project_id.as_deref() == Some(project_id))
            .map(|p| PathBuf::from(p.canonical_path))
            .collect();
        let walker = ignore::WalkBuilder::new(dir)
            .hidden(false)
            .git_ignore(true)
            .git_exclude(false)
            .git_global(false)
            .parents(false)
            .follow_links(false)
            .add_custom_ignore_filename(".localpilotignore")
            .max_depth(Some(32))
            .filter_entry(move |e| {
                let name = e.file_name().to_string_lossy();
                !(e.file_type().map(|t| t.is_dir()).unwrap_or(false) && is_ignored_component(&name))
            })
            .build();
        for entry in walker.flatten() {
            if entry.depth() == 0 {
                continue;
            }
            let p = entry.path();
            if nested.iter().any(|n| starts_with_ci(p, n)) {
                continue; // indexed under the nested project
            }
            if rows.len() >= MAX_FILES_PER_PROJECT {
                truncated = true;
                break;
            }
            let Ok(rel) = p.strip_prefix(dir) else {
                continue;
            };
            let meta = entry.metadata().ok();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len() as i64).unwrap_or(0);
            let modified = meta
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            rows.push((
                rel.display().to_string(),
                entry.file_name().to_string_lossy().into_owned(),
                is_dir,
                if is_dir { 0 } else { size },
                modified,
            ));
        }
        let pid = project_id.to_string();
        let count = rows.len() as i64;
        self.inner.db.write_sync(move |c| {
            let tx = c.transaction()?;
            tx.execute("DELETE FROM files WHERE project_id = ?1", [&pid])?;
            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO files (project_id, rel_path, name, is_dir, size, modified) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )?;
                for (rel, name, is_dir, size, modified) in &rows {
                    stmt.execute(params![pid, rel, name, is_dir, size, modified])?;
                }
            }
            tx.execute(
                "UPDATE projects SET file_count = ?2, files_truncated = ?3, last_scan_time = ?4 WHERE project_id = ?1",
                params![pid, count, truncated, time::now_ms()],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Rescan one project (metadata + files) or everything.
    pub fn refresh(&self, project_id: Option<&str>) -> LpResult<usize> {
        match project_id {
            None => self.full_scan(),
            Some(id) => {
                let p = self
                    .get(id)
                    .ok_or_else(|| LpError::new(ErrorCode::ProjectNotFound, "unknown project"))?;
                let path = PathBuf::from(&p.canonical_path);
                if !path.is_dir() {
                    return self.full_scan();
                }
                self.upsert_project(&path, p.parent_project_id.clone())?;
                self.index_files(&p.project_id, &path)?;
                self.reload_cache()?;
                Ok(1)
            }
        }
    }

    pub fn set_locked(&self, project_id: &str, locked: bool) -> LpResult<()> {
        let id = project_id.to_string();
        self.inner.db.write_sync(|c| {
            c.execute(
                "UPDATE projects SET locked = ?2 WHERE project_id = ?1",
                params![id, locked],
            )?;
            Ok(())
        })?;
        self.reload_cache()
    }

    pub fn set_aliases(&self, project_id: &str, aliases: &[String]) -> LpResult<()> {
        let id = project_id.to_string();
        let aliases: Vec<String> = aliases
            .iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        self.inner.db.write_sync(|c| {
            c.execute("DELETE FROM project_aliases WHERE project_id = ?1", [&id])?;
            for a in &aliases {
                c.execute(
                    "INSERT OR IGNORE INTO project_aliases (project_id, alias) VALUES (?1, ?2)",
                    params![id, a],
                )?;
            }
            c.execute(
                "UPDATE project_fts SET aliases = ?2 WHERE project_id = ?1",
                params![id, aliases.join(" ")],
            )?;
            Ok(())
        })?;
        self.reload_cache()
    }

    /// Resolve a project by name, alias or fuzzy match; falls back to
    /// directory/file name search.
    pub fn resolve(&self, query: &str, limit: usize) -> LpResult<ResolveResult> {
        let q = query.trim();
        if q.is_empty() {
            return Err(LpError::invalid("query must not be empty"));
        }
        let ql = q.to_lowercase();
        let mut scored: Vec<(f32, Project)> = Vec::new();
        for p in self.list() {
            let name = p.display_name.to_lowercase();
            let score = if name == ql {
                if p.parent_project_id.is_none() {
                    1.0
                } else {
                    0.97
                }
            } else if p.aliases.iter().any(|a| a.to_lowercase() == ql) {
                0.95
            } else if normalize_name(&name) == normalize_name(&ql) {
                0.92
            } else if name.starts_with(&ql) {
                0.8
            } else if name.contains(&ql) {
                0.7
            } else {
                let d = levenshtein(&name, &ql);
                if d <= 2 && ql.len() >= 4 {
                    0.6 - 0.1 * d as f32
                } else {
                    0.0
                }
            };
            if score > 0.0 {
                scored.push((score, p));
            }
        }
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.canonical_path.len().cmp(&b.1.canonical_path.len()))
        });
        let matches: Vec<ProjectMatch> = scored
            .into_iter()
            .take(limit)
            .map(|(s, p)| ProjectMatch {
                name: p.display_name,
                path: p.canonical_path,
                project_id: p.project_id,
                confidence: s,
            })
            .collect();
        let fallback = if matches.is_empty() {
            self.search_names(q, None, limit, true)?
        } else {
            Vec::new()
        };
        Ok(ResolveResult { matches, fallback })
    }

    /// Filename search through the FTS index.
    pub fn search_names(
        &self,
        query: &str,
        project_id: Option<&str>,
        limit: usize,
        dirs_only: bool,
    ) -> LpResult<Vec<FileHit>> {
        let q = query.trim().to_string();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pid = project_id.map(|s| s.to_string());
        let cache = self.list();
        let rows: Vec<(String, String, bool, i64, i64)> = self.inner.db.read_sync(move |c| {
            let limit = limit.min(1000) as i64;
            // Trigram FTS needs 3+ characters; shorter queries use LIKE.
            let out = if q.chars().count() >= 3 {
                let fts_q = format!("\"{}\"", q.replace('"', "\"\""));
                let mut sql = String::from("SELECT f.project_id, f.rel_path, f.is_dir, f.size, f.modified FROM files_fts JOIN files f ON f.id = files_fts.rowid WHERE files_fts MATCH ?1");
                if pid.is_some() {
                    sql.push_str(" AND f.project_id = ?3");
                }
                if dirs_only {
                    sql.push_str(" AND f.is_dir = 1");
                }
                sql.push_str(" ORDER BY (lower(f.name) = lower(?4)) DESC, length(f.rel_path) LIMIT ?2");
                let mut stmt = c.prepare(&sql)?;
                let map = |r: &rusqlite::Row<'_>| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?));
                let rows: Vec<_> = match &pid {
                    Some(p) => stmt.query_map(params![fts_q, limit, p, q], map)?.collect::<Result<_, _>>()?,
                    None => stmt.query_map(rusqlite::params![fts_q, limit, rusqlite::types::Null, q], map)?.collect::<Result<_, _>>()?,
                };
                rows
            } else {
                let like = format!("%{}%", q.replace(['%', '_'], ""));
                let mut sql = String::from("SELECT project_id, rel_path, is_dir, size, modified FROM files WHERE name LIKE ?1");
                if dirs_only {
                    sql.push_str(" AND is_dir = 1");
                }
                if pid.is_some() {
                    sql.push_str(" AND project_id = ?3");
                }
                sql.push_str(" LIMIT ?2");
                let mut stmt = c.prepare(&sql)?;
                let map = |r: &rusqlite::Row<'_>| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?));
                match &pid {
                    Some(p) => stmt.query_map(params![like, limit, p], map)?.collect::<Result<_, _>>()?,
                    None => stmt.query_map(params![like, limit], map)?.collect::<Result<_, _>>()?,
                }
            };
            Ok(out)
        })?;
        Ok(rows
            .into_iter()
            .filter_map(|(pid, rel, is_dir, size, modified)| {
                let p = cache.iter().find(|p| p.project_id == pid)?;
                Some(FileHit {
                    project_id: pid.clone(),
                    project_name: p.display_name.clone(),
                    path: Path::new(&p.canonical_path)
                        .join(&rel)
                        .display()
                        .to_string(),
                    rel_path: rel,
                    is_dir,
                    size,
                    modified,
                })
            })
            .collect())
    }

    /// Start watching the root. Events are debounced and applied
    /// incrementally; ignored directories are filtered before processing.
    pub fn start_watcher(&self) -> LpResult<()> {
        let (tx, rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(tx)
            .map_err(|e| LpError::internal(format!("watcher: {e}")))?;
        watcher
            .watch(&self.inner.root, RecursiveMode::Recursive)
            .map_err(|e| LpError::internal(format!("watch: {e}")))?;
        *self.inner.watcher.lock() = Some(watcher);
        let this = self.clone();
        std::thread::Builder::new()
            .name("lp-index-watch".into())
            .spawn(move || this.watch_loop(rx))
            .map_err(LpError::internal)?;
        Ok(())
    }

    pub fn stop_watcher(&self) {
        *self.inner.watcher.lock() = None;
    }

    fn watch_loop(&self, rx: std::sync::mpsc::Receiver<notify::Result<notify::Event>>) {
        loop {
            let first = match rx.recv() {
                Ok(e) => e,
                Err(_) => return,
            };
            let mut batch = vec![first];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
                match rx.recv_timeout(left) {
                    Ok(e) => batch.push(e),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(_) => return,
                }
                if batch.len() > 20_000 {
                    break;
                }
            }
            if let Err(e) = self.apply_events(batch) {
                tracing::warn!(error = %e, "index update failed");
            }
        }
    }

    fn apply_events(&self, batch: Vec<notify::Result<notify::Event>>) -> LpResult<()> {
        let root = self.inner.root.clone();
        let mut touched: BTreeSet<PathBuf> = BTreeSet::new();
        let mut rescan_projects: BTreeSet<String> = BTreeSet::new();
        let mut full = false;
        for ev in batch.into_iter().flatten() {
            if matches!(ev.kind, EventKind::Access(_)) {
                continue;
            }
            for p in ev.paths {
                let Ok(rel) = p.strip_prefix(&root) else {
                    continue;
                };
                let comps: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                if comps.iter().any(|c| is_ignored_component(c)) {
                    continue;
                }
                if comps.len() <= 1 {
                    full = true; // project created/removed/renamed
                    continue;
                }
                let name = comps
                    .last()
                    .cloned()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if (matches!(
                    name.as_str(),
                    "package.json"
                        | "cargo.toml"
                        | "pyproject.toml"
                        | "go.mod"
                        | ".git"
                        | "config"
                        | "tsconfig.json"
                        | "head"
                ) || name.ends_with(".sln")
                    || name.ends_with(".csproj"))
                    && let Some(pr) = self.project_for_path(&p)
                {
                    rescan_projects.insert(pr.project_id);
                }
                touched.insert(p);
            }
        }
        if full {
            self.full_scan()?;
            return Ok(());
        }
        for id in &rescan_projects {
            if let Some(p) = self.get(id) {
                self.upsert_project(Path::new(&p.canonical_path), p.parent_project_id.clone())?;
            }
        }
        let mut upserts = Vec::new();
        let mut deletes = Vec::new();
        for p in touched {
            let Some(project) = self.project_for_path(&p) else {
                continue;
            };
            let base = PathBuf::from(&project.canonical_path);
            let Ok(rel) = p.strip_prefix(&base) else {
                continue;
            };
            let rel = rel.display().to_string();
            if rel.is_empty() {
                continue;
            }
            match std::fs::symlink_metadata(&p) {
                Ok(m) => {
                    let modified = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    upserts.push((
                        project.project_id.clone(),
                        rel,
                        name,
                        m.is_dir(),
                        if m.is_dir() { 0 } else { m.len() as i64 },
                        modified,
                    ));
                }
                Err(_) => deletes.push((project.project_id.clone(), rel)),
            }
        }
        if !upserts.is_empty() || !deletes.is_empty() {
            self.inner.db.write_sync(move |c| {
                let tx = c.transaction()?;
                for (pid, rel, name, is_dir, size, modified) in &upserts {
                    tx.execute(
                        "INSERT INTO files (project_id, rel_path, name, is_dir, size, modified) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(project_id, rel_path) DO UPDATE SET size = excluded.size, modified = excluded.modified, is_dir = excluded.is_dir",
                        params![pid, rel, name, is_dir, size, modified],
                    )?;
                }
                for (pid, rel) in &deletes {
                    let prefix = format!("{}\\%", rel.replace('%', "\\%").replace('_', "\\_"));
                    tx.execute(
                        "DELETE FROM files WHERE project_id = ?1 AND (rel_path = ?2 OR rel_path LIKE ?3 ESCAPE '\\')",
                        params![pid, rel, prefix],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })?;
        }
        if !rescan_projects.is_empty() {
            self.reload_cache()?;
        }
        Ok(())
    }

    /// Integrity check for crash recovery.
    pub fn verify(&self) -> bool {
        self.inner.db.quick_check().unwrap_or(false)
    }
}

fn collect_nested(top: &Path, dir: &Path, depth: usize, out: &mut Vec<(PathBuf, Option<PathBuf>)>) {
    if depth > NESTED_DEPTH {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_dir() || ft.is_symlink() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if is_ignored_component(&name) || name.starts_with('.') {
            continue;
        }
        let p = e.path();
        if detect_markers(&p).is_some() {
            // Parent is the nearest already-collected ancestor.
            let parent = out
                .iter()
                .filter(|(q, _)| starts_with_ci(&p, q) && q != &p)
                .max_by_key(|(q, _)| q.as_os_str().len())
                .map(|(q, _)| q.clone())
                .unwrap_or_else(|| top.to_path_buf());
            out.push((p.clone(), Some(parent)));
        }
        collect_nested(top, &p, depth + 1, out);
    }
}

fn normalize_name(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, ProjectIndex) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Projects");
        std::fs::create_dir_all(root.join("Clippy").join("src")).unwrap();
        std::fs::write(root.join("Clippy").join("Cargo.toml"), "[package]").unwrap();
        std::fs::write(
            root.join("Clippy").join("src").join("main.rs"),
            "fn main(){}",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("Clippy").join("target").join("debug")).unwrap();
        std::fs::write(
            root.join("Clippy")
                .join("target")
                .join("debug")
                .join("junk.o"),
            "x",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("web-app").join("packages").join("ui")).unwrap();
        std::fs::write(root.join("web-app").join("package.json"), "{}").unwrap();
        std::fs::write(
            root.join("web-app")
                .join("packages")
                .join("ui")
                .join("package.json"),
            "{}",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("notes")).unwrap();
        let idx = ProjectIndex::open(&dir.path().join("index.db"), root, Redactor::new()).unwrap();
        idx.full_scan().unwrap();
        (dir, idx)
    }

    #[test]
    fn discovers_and_resolves() {
        let (_d, idx) = setup();
        let names: Vec<String> = idx.list().iter().map(|p| p.display_name.clone()).collect();
        assert!(names.contains(&"Clippy".to_string()));
        assert!(names.contains(&"web-app".to_string()));
        assert!(
            names.contains(&"ui".to_string()),
            "nested project missing: {names:?}"
        );
        assert!(names.contains(&"notes".to_string()));
        let r = idx.resolve("clippy", 5).unwrap();
        assert_eq!(r.matches[0].name, "Clippy");
        assert_eq!(r.matches[0].confidence, 1.0);
        let r = idx.resolve("webapp", 5).unwrap();
        assert_eq!(r.matches[0].name, "web-app");
        let clippy = idx.get("Clippy").unwrap();
        assert!(clippy.detected_languages.contains(&"Rust".to_string()));
    }

    #[test]
    fn filename_search_skips_ignored_dirs() {
        let (_d, idx) = setup();
        let hits = idx.search_names("main.rs", None, 10, false).unwrap();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].path.ends_with(r"Clippy\src\main.rs"));
        assert!(
            idx.search_names("junk", None, 10, false)
                .unwrap()
                .is_empty()
        );
        let r = idx.resolve("src", 5).unwrap();
        assert!(r.matches.is_empty());
        assert!(!r.fallback.is_empty());
    }
}
