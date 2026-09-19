//! The central policy evaluator (plan section 46).
//!
//! Every filesystem mutation, process request, Git/GitHub operation, package
//! installation and privileged request is decided here. Tools never duplicate
//! authorization logic; they describe the operation and act on the decision.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use workstation_core::ErrorCode;
use workstation_core::config::{InstallPolicy, Settings};
use workstation_core::paths::starts_with_ci;

use crate::attribution;
use crate::classify::{CacheArea, PathClass, Roots};
use crate::command::gh::GhKind;
use crate::command::git::{GitCommand, GitKind};
use crate::command::{Category, CommandAnalysis, RefAccess};
use crate::protected::ProtectedRules;
use crate::winpath::{self, ExpandEnv};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryPoint {
    /// Application-mediated structured tool (strict enforcement).
    Structured,
    /// Raw process/shell execution (best-effort checks).
    RawShell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    Metadata,
    List,
    Read,
    Write,
    Create,
    Delete,
    MoveSource,
    MoveDestination,
    CopyDestination,
    Mkdir,
}

impl FsAccess {
    pub fn is_mutation(&self) -> bool {
        !matches!(self, FsAccess::Metadata | FsAccess::List | FsAccess::Read)
    }
    fn op_class(&self) -> &'static str {
        match self {
            FsAccess::Delete | FsAccess::MoveSource => "delete",
            _ => "write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

/// The scope a "Allow for this session" decision grants. Scopes are exact:
/// a path prefix for one operation class, or an exact operation key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionScope {
    PathPrefix { operation: String, prefix: String },
    Exact { key: String, label: String },
}

impl SessionScope {
    pub fn covers(&self, other: &SessionScope) -> bool {
        match (self, other) {
            (
                SessionScope::PathPrefix {
                    operation: a,
                    prefix: pa,
                },
                SessionScope::PathPrefix {
                    operation: b,
                    prefix: pb,
                },
            ) => a == b && starts_with_ci(Path::new(pb), Path::new(pa)),
            (SessionScope::Exact { key: a, .. }, SessionScope::Exact { key: b, .. }) => a == b,
            _ => false,
        }
    }
    pub fn describe(&self) -> String {
        match self {
            SessionScope::PathPrefix { operation, prefix } => {
                format!("{operation} under {prefix}\\")
            }
            SessionScope::Exact { label, .. } => label.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    pub category: String,
    pub reason: String,
    pub impact: String,
    pub risk: Risk,
    pub requires_admin: bool,
    pub paths: Vec<String>,
    pub command: Option<String>,
    pub session_scope: SessionScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow { warnings: Vec<String> },
    Deny { code: ErrorCode, reason: String },
    RequireApproval(ApprovalRequirement),
}

impl Decision {
    pub fn allow() -> Self {
        Decision::Allow {
            warnings: Vec::new(),
        }
    }
    fn deny(code: ErrorCode, reason: impl Into<String>) -> Self {
        Decision::Deny {
            code,
            reason: reason.into(),
        }
    }
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
    pub fn label(&self) -> &'static str {
        match self {
            Decision::Allow { .. } => "allow",
            Decision::Deny { .. } => "deny",
            Decision::RequireApproval(_) => "require_approval",
        }
    }
}

/// Per-call context supplied by the server.
pub struct PolicyContext<'a> {
    pub principal_id: &'a str,
    pub entry: EntryPoint,
    /// Scoped session grants currently held by the caller's application session.
    pub session_grants: &'a [SessionScope],
    /// Whether a task ID belongs to the caller (cache/temp ownership).
    pub owns_task: &'a dyn Fn(&str) -> bool,
}

/// Repository facts used for Git decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitFacts {
    pub repo_root: Option<PathBuf>,
    pub current_branch: Option<String>,
    pub upstream_branch: Option<String>,
    /// Default branch names of the target remote (e.g. `main`).
    pub default_branches: Vec<String>,
    /// For rebase/amend: whether commits being rewritten are already published.
    pub rewrites_published_history: bool,
}

pub struct PolicyEngine {
    pub settings: Arc<Settings>,
    pub roots: Roots,
    pub protected: ProtectedRules,
    pub env: ExpandEnv,
    /// Settings could not be loaded: fail closed for write/admin operations.
    pub config_fault: bool,
    extra_attribution: Vec<regex::Regex>,
}

impl PolicyEngine {
    pub fn new(settings: Arc<Settings>, roots: Roots, env: ExpandEnv, config_fault: bool) -> Self {
        let protected = ProtectedRules::new(&settings.protected_paths, &env);
        let extra_attribution =
            attribution::compile_extra(&settings.github.extra_blocked_attribution_patterns);
        Self {
            settings,
            roots,
            protected,
            env,
            config_fault,
            extra_attribution,
        }
    }

    pub fn shell_checks_enabled(&self) -> bool {
        self.settings.shell_protection.enabled
    }

    // ------------------------------------------------------------------ fs

    /// Decide a structured filesystem access to an already-canonical path.
    pub fn evaluate_fs(
        &self,
        canonical: &Path,
        access: FsAccess,
        ctx: &PolicyContext<'_>,
    ) -> Decision {
        if self.config_fault && access.is_mutation() {
            return Decision::deny(
                ErrorCode::ConfigFault,
                "Settings are damaged; mutations are disabled until they are repaired locally.",
            );
        }
        let class = self.roots.classify_class(canonical);
        if class == PathClass::ControlData {
            return Decision::deny(
                ErrorCode::PermissionDenied,
                "Local Pilot application control data is not accessible to agents.",
            );
        }
        if let Some(m) = self.protected.check(canonical, !access.is_mutation()) {
            let allowed = match access {
                FsAccess::Metadata => true,
                a if a.is_mutation() => self.protected.mutation_excepted(canonical),
                _ => false,
            };
            if !allowed {
                return Decision::deny(
                    ErrorCode::ProtectedResource,
                    format!(
                        "Protected resource ({}). Ask the user directly if secret or credential information is needed.",
                        m.rule
                    ),
                );
            }
        }
        match class {
            PathClass::Trusted => Decision::allow(),
            PathClass::CacheTemp(area) => match area {
                CacheArea::Task { task_id } if (ctx.owns_task)(&task_id) => Decision::allow(),
                CacheArea::Tool { scope, .. } if scope == ctx.principal_id => Decision::allow(),
                _ => Decision::deny(
                    ErrorCode::PermissionDenied,
                    "This cache/temp location belongs to another task or client.",
                ),
            },
            PathClass::External => {
                if !access.is_mutation() {
                    return Decision::allow();
                }
                for g in &self.settings.external_writes.grants {
                    if starts_with_ci(canonical, Path::new(&g.path_prefix))
                        && (g.allow_delete || access.op_class() == "write")
                    {
                        return Decision::Allow {
                            warnings: vec![format!("allowed by local policy grant {}", g.id)],
                        };
                    }
                }
                let prefix = canonical
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| canonical.display().to_string());
                let scope = SessionScope::PathPrefix {
                    operation: access.op_class().to_string(),
                    prefix: prefix.clone(),
                };
                if ctx.session_grants.iter().any(|g| g.covers(&scope)) {
                    return Decision::Allow {
                        warnings: vec!["allowed by session approval".into()],
                    };
                }
                Decision::RequireApproval(ApprovalRequirement {
                    category: format!("external_{}", access.op_class()),
                    reason: format!(
                        "{access:?} outside the trusted workspace requires local approval."
                    ),
                    impact: format!(
                        "Changes {} outside Documents\\Projects.",
                        canonical.display()
                    ),
                    risk: if access.op_class() == "delete" {
                        Risk::High
                    } else {
                        Risk::Medium
                    },
                    requires_admin: false,
                    paths: vec![canonical.display().to_string()],
                    command: None,
                    session_scope: scope,
                })
            }
            PathClass::ControlData => unreachable!(),
        }
    }

    // ------------------------------------------------------------ commands

    /// Resolve a path reference from a command relative to `cwd`.
    pub fn resolve_command_path(&self, raw: &str, cwd: &Path) -> Option<PathBuf> {
        let mut s = raw.trim().trim_matches('"').trim_matches('\'').to_string();
        // PowerShell-style environment references.
        let lower = s.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("$env:") {
            let name_len = rest.find(['\\', '/']).unwrap_or(rest.len());
            let name = &s[5..5 + name_len];
            let value = self
                .env
                .vars
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, p)| p.display().to_string())
                .or_else(|| std::env::var(name).ok())?;
            s = format!("{value}{}", &s[5 + name_len..]);
        } else if lower.starts_with("$home") {
            let p = self.env.profile.as_ref()?.display().to_string();
            s = format!("{p}{}", &s[5..]);
        }
        if s.contains('$') || s.contains('*') || s.contains('?') {
            // Wildcards: evaluate the directory part.
            let cut = s.find(['*', '?', '$']).unwrap_or(s.len());
            let dir = s[..cut]
                .rsplit_once(['\\', '/'])
                .map(|(d, _)| d.to_string())
                .unwrap_or_default();
            if dir.is_empty() || s[..cut].contains('$') {
                return None;
            }
            s = dir;
        }
        let normalized = winpath::normalize(&s, cwd, &self.env).ok()?;
        match winpath::canonicalize(&normalized, true) {
            Ok(c) => Some(c.path),
            Err(_) => Some(normalized),
        }
    }

    /// Decide a raw process/shell request (Layer B, best effort).
    pub fn evaluate_command(
        &self,
        analysis: &CommandAnalysis,
        cwd: &Path,
        command_text: &str,
        git_facts: &dyn Fn(&GitCommand) -> GitFacts,
        read_text_file: &dyn Fn(&Path) -> Option<String>,
        ctx: &PolicyContext<'_>,
    ) -> Decision {
        // The working directory is a structured parameter: always enforced.
        let cwd_class = self.roots.classify_class(cwd);
        if cwd_class == PathClass::ControlData {
            return Decision::deny(
                ErrorCode::PermissionDenied,
                "The working directory is Local Pilot control data.",
            );
        }
        if self.protected.check(cwd, true).is_some() {
            return Decision::deny(
                ErrorCode::ProtectedResource,
                "The working directory is a protected location.",
            );
        }
        if self.config_fault {
            return Decision::deny(
                ErrorCode::ConfigFault,
                "Settings are damaged; process launches are disabled until they are repaired locally.",
            );
        }
        if !self.shell_checks_enabled() {
            return Decision::Allow {
                warnings: vec![
                    "shell protection checks are OFF: command/path preflight was bypassed".into(),
                ],
            };
        }

        let cwd_trusted = cwd_class == PathClass::Trusted
            || matches!(&cwd_class, PathClass::CacheTemp(CacheArea::Task { task_id }) if (ctx.owns_task)(task_id));
        let mut warnings: Vec<String> = Vec::new();
        let mut approvals: Vec<ApprovalRequirement> = Vec::new();
        let command_key = workstation_core::hashing::sha256_hex(
            format!("{}\n{}", cwd.display(), command_text).as_bytes(),
        );
        let exact_scope = |label: &str| SessionScope::Exact {
            key: command_key.clone(),
            label: format!("{label}: {}", truncate(command_text, 120)),
        };

        for f in &analysis.findings {
            match f.category {
                Category::CredentialAccess => {
                    return Decision::deny(
                        ErrorCode::ProtectedResource,
                        format!(
                            "Credential access/export is blocked ({}). Ask the user directly for any secret you need.",
                            f.detail
                        ),
                    );
                }
                Category::Admin => {
                    return Decision::deny(
                        ErrorCode::PermissionDenied,
                        format!(
                            "'{}' needs administrative rights. Agent processes run as a standard user; use the admin_request tool for a locally approved, structured elevated operation.",
                            f.detail
                        ),
                    );
                }
                Category::SystemChange => approvals.push(ApprovalRequirement {
                    category: "system_change".into(),
                    reason: format!("{} changes user or system configuration.", f.detail),
                    impact: "Modifies configuration outside the trusted workspace.".into(),
                    risk: Risk::High,
                    requires_admin: false,
                    paths: Vec::new(),
                    command: Some(command_text.to_string()),
                    session_scope: exact_scope("run this exact command"),
                }),
                Category::PackageGlobal => match self.settings.packages.system_install_policy {
                    InstallPolicy::Allow => {
                        warnings.push(format!("global install allowed by policy: {}", f.detail))
                    }
                    InstallPolicy::Deny => {
                        return Decision::deny(
                            ErrorCode::PermissionDenied,
                            format!(
                                "System-wide/user-global installs are disabled by local policy ({}).",
                                f.detail
                            ),
                        );
                    }
                    InstallPolicy::RequireApproval => approvals.push(ApprovalRequirement {
                        category: "package_global".into(),
                        reason: format!("{} installs software outside the project.", f.detail),
                        impact: "Installs or changes tools in the user profile or system.".into(),
                        risk: Risk::Medium,
                        requires_admin: false,
                        paths: Vec::new(),
                        command: Some(command_text.to_string()),
                        session_scope: exact_scope("run this exact install command"),
                    }),
                },
                Category::PackageLocal if !cwd_trusted => approvals.push(ApprovalRequirement {
                    category: "external_write".into(),
                    reason: "Dependency installation outside the trusted workspace.".into(),
                    impact: format!("Writes dependencies under {}.", cwd.display()),
                    risk: Risk::Medium,
                    requires_admin: false,
                    paths: vec![cwd.display().to_string()],
                    command: Some(command_text.to_string()),
                    session_scope: exact_scope("run this exact command"),
                }),
                Category::Dynamic => warnings.push(format!(
                    "dynamic behaviour cannot be fully analyzed: {}",
                    f.detail
                )),
                Category::Unknown if !cwd_trusted && !has_only_reads(f) => {
                    approvals.push(ApprovalRequirement {
                        category: "unknown_external".into(),
                        reason: format!(
                            "'{}' may modify files and runs outside the trusted workspace.",
                            f.program
                        ),
                        impact: format!("Runs with working directory {}.", cwd.display()),
                        risk: Risk::Medium,
                        requires_admin: false,
                        paths: vec![cwd.display().to_string()],
                        command: Some(command_text.to_string()),
                        session_scope: exact_scope("run this exact command"),
                    })
                }
                Category::Unknown => warnings.push(format!("unclassified command '{}'", f.program)),
                _ => {}
            }

            // Official GitHub text: attribution guard.
            let mut texts = f.official_texts.clone();
            for file in &f.official_text_files {
                if let Some(p) = self.resolve_command_path(file, cwd)
                    && let Some(t) = read_text_file(&p)
                {
                    texts.push(t);
                }
            }
            for t in &texts {
                if let Some(hit) = attribution::find_attribution(t, &self.extra_attribution) {
                    return Decision::deny(
                        ErrorCode::AttributionBlocked,
                        format!(
                            "Agent/vendor attribution is not allowed in official Git/GitHub content ({hit})."
                        ),
                    );
                }
            }
            for r in &f.official_refs {
                if attribution::ref_name_discloses_agent(r) {
                    return Decision::deny(
                        ErrorCode::AttributionBlocked,
                        format!("Branch/tag name '{r}' discloses agent attribution."),
                    );
                }
            }
            for v in &f.identity_values {
                if attribution::identity_discloses_agent(v) {
                    return Decision::deny(
                        ErrorCode::AttributionBlocked,
                        "Git identity overrides may not name an agent or vendor.",
                    );
                }
            }

            if let Some(g) = &f.git {
                match self.evaluate_git_kind(g, &git_facts(g), command_text, &command_key) {
                    Decision::Allow { warnings: w } => warnings.extend(w),
                    Decision::RequireApproval(r) => approvals.push(r),
                    deny => return deny,
                }
            }
            if let Some(gh) = &f.gh
                && gh.kind == GhKind::DestructiveWrite
            {
                approvals.push(ApprovalRequirement {
                    category: "github_destructive".into(),
                    reason: format!(
                        "gh {} {} makes an irreversible remote change.",
                        gh.group, gh.action
                    ),
                    impact: "Deletes, archives or renames GitHub resources.".into(),
                    risk: Risk::High,
                    requires_admin: false,
                    paths: Vec::new(),
                    command: Some(command_text.to_string()),
                    session_scope: exact_scope("run this exact command"),
                });
            }

            // Paths referenced by the command.
            for p in &f.paths {
                let Some(resolved) = self.resolve_command_path(&p.raw, cwd) else {
                    if matches!(p.access, RefAccess::Write | RefAccess::Delete) {
                        warnings.push(format!("could not resolve path '{}'", p.raw));
                    }
                    continue;
                };
                let class = self.roots.classify_class(&resolved);
                let protected = self.protected.check(
                    &resolved,
                    matches!(p.access, RefAccess::Read | RefAccess::ReadDisclose),
                );
                if class == PathClass::ControlData && p.access != RefAccess::Read {
                    return Decision::deny(
                        ErrorCode::PermissionDenied,
                        format!("'{}' refers to Local Pilot control data.", p.raw),
                    );
                }
                if let Some(m) = &protected {
                    match p.access {
                        RefAccess::ReadDisclose | RefAccess::Write | RefAccess::Delete => {
                            return Decision::deny(
                                ErrorCode::ProtectedResource,
                                format!(
                                    "'{}' is a protected resource ({}); it cannot be printed, copied or modified by agent commands.",
                                    p.raw, m.rule
                                ),
                            );
                        }
                        RefAccess::Unknown => warnings.push(format!(
                            "command references protected resource '{}' (use, not disclosure)",
                            p.raw
                        )),
                        RefAccess::Read => {}
                    }
                }
                if matches!(p.access, RefAccess::Write | RefAccess::Delete) {
                    let op = if p.access == RefAccess::Delete {
                        FsAccess::Delete
                    } else {
                        FsAccess::Write
                    };
                    match self.evaluate_fs(&resolved, op, ctx) {
                        Decision::Allow { warnings: w } => warnings.extend(w),
                        Decision::RequireApproval(mut r) => {
                            r.category = format!("shell_{}", r.category);
                            r.command = Some(command_text.to_string());
                            r.reason = format!(
                                "The command {} {} outside the trusted workspace.",
                                if op == FsAccess::Delete {
                                    "deletes"
                                } else {
                                    "writes"
                                },
                                resolved.display()
                            );
                            approvals.push(r)
                        }
                        deny => return deny,
                    }
                }
            }
        }
        if !analysis.parse_errors.is_empty() {
            warnings.push("command could not be fully parsed".into());
            if !cwd_trusted {
                approvals.push(ApprovalRequirement {
                    category: "unknown_external".into(),
                    reason:
                        "The command could not be parsed and runs outside the trusted workspace."
                            .into(),
                    impact: format!("Runs with working directory {}.", cwd.display()),
                    risk: Risk::Medium,
                    requires_admin: false,
                    paths: vec![cwd.display().to_string()],
                    command: Some(command_text.to_string()),
                    session_scope: exact_scope("run this exact command"),
                });
            }
        }
        if analysis.categories().contains(&Category::Dynamic) && !cwd_trusted {
            approvals.push(ApprovalRequirement {
                category: "unknown_external".into(),
                reason: "The command uses dynamic execution outside the trusted workspace.".into(),
                impact: format!("Runs with working directory {}.", cwd.display()),
                risk: Risk::Medium,
                requires_admin: false,
                paths: vec![cwd.display().to_string()],
                command: Some(command_text.to_string()),
                session_scope: exact_scope("run this exact command"),
            });
        }

        if approvals.is_empty() {
            return Decision::Allow { warnings };
        }
        // Combine into one approval request bound to the exact command.
        approvals.sort_by_key(|approval| std::cmp::Reverse(approval.risk));
        let mut combined = approvals[0].clone();
        if approvals.len() > 1 {
            combined.reason = approvals
                .iter()
                .map(|a| a.reason.clone())
                .collect::<Vec<_>>()
                .join(" ");
            combined.paths = approvals.iter().flat_map(|a| a.paths.clone()).collect();
            combined.paths.dedup();
        }
        // A single approval for a multi-part command is scoped to the exact command.
        if approvals.len() > 1 || !matches!(combined.session_scope, SessionScope::Exact { .. }) {
            combined.session_scope = exact_scope("run this exact command");
        }
        if ctx
            .session_grants
            .iter()
            .any(|g| g.covers(&combined.session_scope))
            || approvals.iter().all(|a| {
                ctx.session_grants
                    .iter()
                    .any(|g| g.covers(&a.session_scope))
            })
        {
            warnings.push("allowed by session approval".into());
            return Decision::Allow { warnings };
        }
        combined.command = Some(command_text.to_string());
        Decision::RequireApproval(combined)
    }

    // ----------------------------------------------------------------- git

    fn evaluate_git_kind(
        &self,
        g: &GitCommand,
        facts: &GitFacts,
        command_text: &str,
        key: &str,
    ) -> Decision {
        let exact = |label: &str| SessionScope::Exact {
            key: key.to_string(),
            label: format!("{label}: {}", truncate(command_text, 120)),
        };
        let repo = facts
            .repo_root
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let destructive = |what: &str| {
            if self.settings.git.allow_destructive {
                Decision::Allow {
                    warnings: vec![format!(
                        "destructive Git operation allowed by settings: {what}"
                    )],
                }
            } else {
                Decision::RequireApproval(ApprovalRequirement {
                    category: "git_destructive".into(),
                    reason: format!("{what} is a destructive Git operation."),
                    impact: "May discard work or rewrite shared history.".into(),
                    risk: Risk::High,
                    requires_admin: false,
                    paths: if repo.is_empty() {
                        Vec::new()
                    } else {
                        vec![repo.clone()]
                    },
                    command: Some(command_text.to_string()),
                    session_scope: exact("run this exact Git command"),
                })
            }
        };
        match &g.kind {
            GitKind::ResetHard => destructive("git reset --hard"),
            GitKind::Clean => destructive("git clean -f"),
            GitKind::HistoryRewrite => destructive("History filtering"),
            GitKind::Rebase { .. } if facts.rewrites_published_history => {
                destructive("Rebase of published commits")
            }
            GitKind::CommitAmend if facts.rewrites_published_history => {
                destructive("Amending a published commit")
            }
            GitKind::CredentialAccess => Decision::deny(
                ErrorCode::ProtectedResource,
                "Git credential access is blocked.",
            ),
            GitKind::IdentityChange => Decision::RequireApproval(ApprovalRequirement {
                category: "git_identity_change".into(),
                reason: "The command changes the configured Git identity.".into(),
                impact: "Commits would be attributed to a different author.".into(),
                risk: Risk::High,
                requires_admin: false,
                paths: Vec::new(),
                command: Some(command_text.to_string()),
                session_scope: exact("run this exact Git command"),
            }),
            GitKind::Push(spec) => {
                if spec.force || spec.mirror {
                    return destructive("Force push");
                }
                if spec.delete {
                    return destructive(if spec.deletes_tags {
                        "Deleting remote tags"
                    } else {
                        "Deleting a remote branch"
                    });
                }
                if spec.deletes_tags {
                    return destructive("Deleting remote tags");
                }
                let mut targets: Vec<String> = spec
                    .destinations
                    .iter()
                    .map(|d| {
                        if d == "HEAD" {
                            facts.current_branch.clone().unwrap_or_default()
                        } else {
                            d.clone()
                        }
                    })
                    .collect();
                if targets.is_empty()
                    && let Some(u) = facts
                        .upstream_branch
                        .clone()
                        .or_else(|| facts.current_branch.clone())
                {
                    targets.push(u);
                }
                let defaults: Vec<String> = if facts.default_branches.is_empty() {
                    vec!["main".into(), "master".into()]
                } else {
                    facts.default_branches.clone()
                };
                let hits_default = spec.all
                    || targets
                        .iter()
                        .any(|t| defaults.iter().any(|d| d.eq_ignore_ascii_case(t)));
                if hits_default && !self.settings.git.allow_auto_push_default_branch {
                    let branch = targets
                        .iter()
                        .find(|t| defaults.iter().any(|d| d.eq_ignore_ascii_case(t)))
                        .cloned()
                        .unwrap_or_else(|| "default branch".into());
                    return Decision::RequireApproval(ApprovalRequirement {
                        category: "git_default_branch_push".into(),
                        reason: format!(
                            "Direct push to the default branch '{branch}' requires local approval (branch-first workflow)."
                        ),
                        impact: format!(
                            "Publishes commits directly to {} on {}.",
                            branch,
                            spec.remote
                                .clone()
                                .unwrap_or_else(|| "the upstream remote".into())
                        ),
                        risk: Risk::Medium,
                        requires_admin: false,
                        paths: if repo.is_empty() {
                            Vec::new()
                        } else {
                            vec![repo.clone()]
                        },
                        command: Some(command_text.to_string()),
                        session_scope: SessionScope::Exact {
                            key: format!(
                                "git_push_default:{}:{}:{}",
                                repo.to_ascii_lowercase(),
                                spec.remote.clone().unwrap_or_default(),
                                branch
                            ),
                            label: format!("push to {branch} in {repo}"),
                        },
                    });
                }
                Decision::allow()
            }
            GitKind::GlobalConfigChange => Decision::RequireApproval(ApprovalRequirement {
                category: "external_write".into(),
                reason: "The command changes global Git configuration.".into(),
                impact: "Modifies the user's global .gitconfig.".into(),
                risk: Risk::Medium,
                requires_admin: false,
                paths: Vec::new(),
                command: Some(command_text.to_string()),
                session_scope: exact("run this exact Git command"),
            }),
            _ => Decision::allow(),
        }
    }

    /// Git decision for structured Git tools (not subject to the shell switch).
    pub fn evaluate_git_structured(
        &self,
        g: &GitCommand,
        facts: &GitFacts,
        ctx: &PolicyContext<'_>,
    ) -> Decision {
        if self.config_fault && g.kind != GitKind::ReadOnly {
            return Decision::deny(
                ErrorCode::ConfigFault,
                "Settings are damaged; Git mutations are disabled until they are repaired locally.",
            );
        }
        for t in &g.messages {
            if let Some(hit) = attribution::find_attribution(t, &self.extra_attribution) {
                return Decision::deny(
                    ErrorCode::AttributionBlocked,
                    format!(
                        "Agent/vendor attribution is not allowed in commit/tag messages ({hit})."
                    ),
                );
            }
        }
        for r in &g.created_refs {
            if attribution::ref_name_discloses_agent(r) {
                return Decision::deny(
                    ErrorCode::AttributionBlocked,
                    format!("Branch/tag name '{r}' discloses agent attribution."),
                );
            }
        }
        if !g.identity_overrides.is_empty() {
            return Decision::deny(
                ErrorCode::PermissionDenied,
                "Structured Git tools never override the configured Git identity.",
            );
        }
        let text = format!("git {} {}", g.subcommand, g.args.join(" "));
        let key = workstation_core::hashing::sha256_hex(
            format!(
                "{}\n{}",
                facts
                    .repo_root
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                text
            )
            .as_bytes(),
        );
        let d = self.evaluate_git_kind(g, facts, &text, &key);
        if let Decision::RequireApproval(r) = &d
            && ctx
                .session_grants
                .iter()
                .any(|s| s.covers(&r.session_scope))
        {
            return Decision::Allow {
                warnings: vec!["allowed by session approval".into()],
            };
        }
        d
    }

    /// Attribution check for structured GitHub content.
    pub fn check_github_text(
        &self,
        texts: &[&str],
        refs: &[&str],
    ) -> Result<(), (ErrorCode, String)> {
        for t in texts {
            if let Some(hit) = attribution::find_attribution(t, &self.extra_attribution) {
                return Err((
                    ErrorCode::AttributionBlocked,
                    format!(
                        "Agent/vendor attribution is not allowed in official GitHub content ({hit})."
                    ),
                ));
            }
        }
        for r in refs {
            if attribution::ref_name_discloses_agent(r) {
                return Err((
                    ErrorCode::AttributionBlocked,
                    format!("Branch/tag name '{r}' discloses agent attribution."),
                ));
            }
        }
        Ok(())
    }

    /// Decision for a structured administrative request: always local approval.
    pub fn evaluate_admin(&self, summary: &str, digest: &str, ctx: &PolicyContext<'_>) -> Decision {
        if self.config_fault {
            return Decision::deny(
                ErrorCode::ConfigFault,
                "Settings are damaged; administrative operations are disabled.",
            );
        }
        let scope = SessionScope::Exact {
            key: format!("admin:{digest}"),
            label: format!("administrative operation: {summary}"),
        };
        // Administrative approvals are never satisfied by an earlier grant for a
        // different operation; an identical operation may reuse a session grant.
        if ctx.session_grants.iter().any(|g| g.covers(&scope)) {
            return Decision::Allow {
                warnings: vec!["allowed by session approval".into()],
            };
        }
        Decision::RequireApproval(ApprovalRequirement {
            category: "admin".into(),
            reason: "Administrative operations always require local approval.".into(),
            impact: summary.to_string(),
            risk: Risk::Critical,
            requires_admin: true,
            paths: Vec::new(),
            command: Some(summary.to_string()),
            session_scope: scope,
        })
    }
}

fn has_only_reads(f: &crate::command::Finding) -> bool {
    f.paths
        .iter()
        .all(|p| matches!(p.access, RefAccess::Read | RefAccess::ReadDisclose))
        && !f.paths.is_empty()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Analyzer;

    fn engine(settings: Settings) -> PolicyEngine {
        let roots = Roots {
            trusted: PathBuf::from(r"C:\Users\Alice\Documents\Projects"),
            app_data: PathBuf::from(r"C:\Users\Alice\AppData\Local\LocalPilot"),
            cache_temp: PathBuf::from(r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp"),
            install_dir: None,
        };
        let env = ExpandEnv {
            profile: Some(PathBuf::from(r"C:\Users\Alice")),
            vars: vec![("USERPROFILE".into(), PathBuf::from(r"C:\Users\Alice"))],
        };
        PolicyEngine::new(Arc::new(settings), roots, env, false)
    }

    fn ctx<'a>(grants: &'a [SessionScope]) -> PolicyContext<'a> {
        PolicyContext {
            principal_id: "cl_1",
            entry: EntryPoint::Structured,
            session_grants: grants,
            owns_task: &|t: &str| t == "task_mine",
        }
    }

    #[test]
    fn fs_rules() {
        let e = engine(Settings::default());
        let c = ctx(&[]);
        let p = |s: &str| PathBuf::from(s);
        assert!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\Documents\Projects\X\a.rs"),
                FsAccess::Write,
                &c
            )
            .is_allow()
        );
        assert!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\Documents\Projects\X\a.rs"),
                FsAccess::Delete,
                &c
            )
            .is_allow()
        );
        assert!(
            e.evaluate_fs(&p(r"C:\Temp\notes.txt"), FsAccess::Read, &c)
                .is_allow()
        );
        assert!(matches!(
            e.evaluate_fs(&p(r"C:\Temp\notes.txt"), FsAccess::Write, &c),
            Decision::RequireApproval(_)
        ));
        assert!(matches!(
            e.evaluate_fs(&p(r"C:\Users\Alice\.ssh\id_rsa"), FsAccess::Read, &c),
            Decision::Deny {
                code: ErrorCode::ProtectedResource,
                ..
            }
        ));
        assert!(matches!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\Documents\Projects\X\.env"),
                FsAccess::Read,
                &c
            ),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\Documents\Projects\X\.env"),
                FsAccess::Write,
                &c
            ),
            Decision::Deny { .. }
        ));
        assert!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\Documents\Projects\X\.env"),
                FsAccess::Metadata,
                &c
            )
            .is_allow()
        );
        assert!(matches!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\AppData\Local\LocalPilot\data\x.db"),
                FsAccess::Read,
                &c
            ),
            Decision::Deny { .. }
        ));
        assert!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp\tasks\task_mine\a"),
                FsAccess::Write,
                &c
            )
            .is_allow()
        );
        assert!(matches!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp\tasks\task_other\a"),
                FsAccess::Write,
                &c
            ),
            Decision::Deny { .. }
        ));
        assert!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp\tools\npm\cl_1\x"),
                FsAccess::Write,
                &c
            )
            .is_allow()
        );
        assert!(matches!(
            e.evaluate_fs(
                &p(r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp\tools\npm\cl_2\x"),
                FsAccess::Read,
                &c
            ),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn session_grants_are_scoped() {
        let e = engine(Settings::default());
        let grant = [SessionScope::PathPrefix {
            operation: "write".into(),
            prefix: r"C:\SomeFolder".into(),
        }];
        let c = ctx(&grant);
        assert!(
            e.evaluate_fs(Path::new(r"C:\SomeFolder\a.txt"), FsAccess::Write, &c)
                .is_allow()
        );
        assert!(
            e.evaluate_fs(Path::new(r"C:\SomeFolder\sub\a.txt"), FsAccess::Write, &c)
                .is_allow()
        );
        assert!(matches!(
            e.evaluate_fs(Path::new(r"C:\SomeFolder\a.txt"), FsAccess::Delete, &c),
            Decision::RequireApproval(_)
        ));
        assert!(matches!(
            e.evaluate_fs(Path::new(r"C:\SomeFolder2\a.txt"), FsAccess::Write, &c),
            Decision::RequireApproval(_)
        ));
    }

    #[test]
    fn corrupt_config_fails_closed() {
        let roots = Roots {
            trusted: PathBuf::from(r"C:\P"),
            app_data: PathBuf::from(r"C:\A"),
            cache_temp: PathBuf::from(r"C:\A\cache\temp"),
            install_dir: None,
        };
        let e = PolicyEngine::new(
            Arc::new(Settings::default()),
            roots,
            ExpandEnv::default(),
            true,
        );
        let c = ctx(&[]);
        assert!(matches!(
            e.evaluate_fs(Path::new(r"C:\P\a"), FsAccess::Write, &c),
            Decision::Deny {
                code: ErrorCode::ConfigFault,
                ..
            }
        ));
        assert!(
            e.evaluate_fs(Path::new(r"C:\P\a"), FsAccess::Read, &c)
                .is_allow()
        );
    }

    fn cmd_decision(e: &PolicyEngine, line: &str, cwd: &str, facts: GitFacts) -> Decision {
        let f = |_: &str| false;
        let a = Analyzer {
            powershell_exe: "powershell.exe",
            program_in_trusted: &f,
        };
        let analysis = a.analyze_cmd(line);
        e.evaluate_command(
            &analysis,
            Path::new(cwd),
            line,
            &|_| facts.clone(),
            &|_| None,
            &ctx(&[]),
        )
    }

    #[test]
    fn shell_preflight() {
        let e = engine(Settings::default());
        let cwd = r"C:\Users\Alice\Documents\Projects\X";
        assert!(cmd_decision(&e, "npm install", cwd, GitFacts::default()).is_allow());
        assert!(matches!(
            cmd_decision(&e, "npm install -g x", cwd, GitFacts::default()),
            Decision::RequireApproval(_)
        ));
        assert!(matches!(
            cmd_decision(&e, r"echo x > C:\Windows\x.txt", cwd, GitFacts::default()),
            Decision::RequireApproval(_)
        ));
        assert!(matches!(
            cmd_decision(
                &e,
                r"type C:\Users\Alice\.ssh\id_rsa",
                cwd,
                GitFacts::default()
            ),
            Decision::Deny {
                code: ErrorCode::ProtectedResource,
                ..
            }
        ));
        assert!(matches!(
            cmd_decision(&e, "gh auth token", cwd, GitFacts::default()),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            cmd_decision(&e, "sc stop Spooler", cwd, GitFacts::default()),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            cmd_decision(&e, "somethingunknown.exe", r"C:\Temp", GitFacts::default()),
            Decision::RequireApproval(_)
        ));
        assert!(cmd_decision(&e, "somethingunknown.exe", cwd, GitFacts::default()).is_allow());
        assert!(matches!(
            cmd_decision(
                &e,
                r#"gh pr create --title x --body "Generated with Claude Code""#,
                cwd,
                GitFacts::default()
            ),
            Decision::Deny {
                code: ErrorCode::AttributionBlocked,
                ..
            }
        ));
    }

    #[test]
    fn git_push_policy() {
        let e = engine(Settings::default());
        let cwd = r"C:\Users\Alice\Documents\Projects\X";
        let facts = GitFacts {
            current_branch: Some("feature".into()),
            default_branches: vec!["main".into()],
            ..Default::default()
        };
        assert!(cmd_decision(&e, "git push origin feature", cwd, facts.clone()).is_allow());
        assert!(
            matches!(cmd_decision(&e, "git push origin main", cwd, facts.clone()), Decision::RequireApproval(ref r) if r.category == "git_default_branch_push")
        );
        assert!(
            matches!(cmd_decision(&e, "git push --force origin feature", cwd, facts.clone()), Decision::RequireApproval(ref r) if r.category == "git_destructive")
        );
        assert!(matches!(
            cmd_decision(&e, "git reset --hard", cwd, facts.clone()),
            Decision::RequireApproval(_)
        ));
        let on_main = GitFacts {
            current_branch: Some("main".into()),
            default_branches: vec!["main".into()],
            ..Default::default()
        };
        assert!(matches!(
            cmd_decision(&e, "git push", cwd, on_main),
            Decision::RequireApproval(_)
        ));

        let mut s = Settings::default();
        s.git.allow_auto_push_default_branch = true;
        s.git.allow_destructive = true;
        let e = engine(s);
        assert!(cmd_decision(&e, "git push origin main", cwd, facts.clone()).is_allow());
        assert!(cmd_decision(&e, "git push -f origin feature", cwd, facts).is_allow());
    }

    #[test]
    fn shell_switch_off_bypasses_preflight_only() {
        let mut s = Settings::default();
        s.shell_protection.enabled = false;
        let e = engine(s);
        let cwd = r"C:\Users\Alice\Documents\Projects\X";
        assert!(cmd_decision(&e, "npm install -g x", cwd, GitFacts::default()).is_allow());
        assert!(cmd_decision(&e, "gh auth token", cwd, GitFacts::default()).is_allow());
        // Structured tools keep their policy.
        assert!(matches!(
            e.evaluate_fs(Path::new(r"C:\Temp\x"), FsAccess::Write, &ctx(&[])),
            Decision::RequireApproval(_)
        ));
        assert!(matches!(
            e.evaluate_fs(
                Path::new(r"C:\Users\Alice\.ssh\id_rsa"),
                FsAccess::Read,
                &ctx(&[])
            ),
            Decision::Deny { .. }
        ));
        // Control-data working directories stay blocked.
        assert!(matches!(
            cmd_decision(
                &e,
                "dir",
                r"C:\Users\Alice\AppData\Local\LocalPilot\data",
                GitFacts::default()
            ),
            Decision::Deny { .. }
        ));
    }
}
