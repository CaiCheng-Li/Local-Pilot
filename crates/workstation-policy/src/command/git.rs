//! Git command parsing and argument-aware classification (plan sections 10-11).
//!
//! Classification considers actual arguments: `checkout`, `restore` and
//! `rebase` are not destructive by name alone. Push targets, force flags,
//! deletes and history rewrites are extracted so policy can decide with
//! repository facts (default branch, published commits).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSpec {
    pub remote: Option<String>,
    /// Destination branch names (without `refs/heads/`), empty = implicit upstream.
    pub destinations: Vec<String>,
    pub force: bool,
    pub delete: bool,
    pub all: bool,
    pub mirror: bool,
    pub tags: bool,
    pub deletes_tags: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GitKind {
    ReadOnly,
    LocalMutation,
    Fetch,
    Pull,
    Clone { destination: Option<String> },
    Push(PushSpec),
    ResetHard,
    Clean,
    HistoryRewrite,
    Rebase { upstream: Option<String> },
    CommitAmend,
    IdentityChange,
    CredentialAccess,
    GlobalConfigChange,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCommand {
    /// `-C <dir>` override of the working directory.
    pub cwd_override: Option<String>,
    pub subcommand: String,
    pub args: Vec<String>,
    pub kind: GitKind,
    /// Commit/tag/merge messages and trailers supplied inline.
    pub messages: Vec<String>,
    /// Files supplying messages (`-F`).
    pub message_files: Vec<String>,
    /// Author/committer identity overrides.
    pub identity_overrides: Vec<String>,
    /// Branch/tag names being created (local or remote).
    pub created_refs: Vec<String>,
    /// Paths written by the command outside the repository (clone dest, archive output...).
    pub output_paths: Vec<String>,
}

const IDENTITY_KEYS: &[&str] = &[
    "user.name",
    "user.email",
    "author.name",
    "author.email",
    "committer.name",
    "committer.email",
];

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Option<String> {
    let a = &args[*i];
    if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
        return Some(v.to_string());
    }
    if a == flag && *i + 1 < args.len() {
        *i += 1;
        return Some(args[*i].clone());
    }
    // Short flags with attached values: -mMessage
    if flag.len() == 2 && a.starts_with(flag) && a.len() > 2 && !a.starts_with("--") {
        return Some(a[2..].to_string());
    }
    None
}

/// Parse `git` arguments (excluding the program itself).
pub fn parse(args: &[String]) -> GitCommand {
    let mut i = 0;
    let mut cwd_override = None;
    let mut identity_overrides = Vec::new();
    let mut config_credential = false;
    // Global options.
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-C" && i + 1 < args.len() {
            cwd_override = Some(args[i + 1].clone());
            i += 2;
        } else if a == "-c" && i + 1 < args.len() {
            let kv = &args[i + 1];
            let key = kv.split('=').next().unwrap_or("").to_ascii_lowercase();
            if IDENTITY_KEYS.contains(&key.as_str()) {
                identity_overrides.push(kv.clone());
            }
            if key.starts_with("credential.") {
                config_credential = true;
            }
            i += 2;
        } else if a.starts_with("--git-dir=")
            || a.starts_with("--work-tree=")
            || a.starts_with("--namespace=")
        {
            i += 1;
        } else if matches!(
            a,
            "--git-dir" | "--work-tree" | "--namespace" | "--exec-path"
        ) && i + 1 < args.len()
        {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            break;
        }
    }
    let sub = args
        .get(i)
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rest: Vec<String> = args.iter().skip(i + 1).cloned().collect();
    let mut cmd = GitCommand {
        cwd_override,
        subcommand: sub.clone(),
        args: rest.clone(),
        kind: GitKind::Unknown,
        messages: Vec::new(),
        message_files: Vec::new(),
        identity_overrides,
        created_refs: Vec::new(),
        output_paths: Vec::new(),
    };
    let has = |f: &str| rest.iter().any(|a| a == f);
    let has_prefix = |f: &str| rest.iter().any(|a| a.starts_with(f));
    let positional: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();

    cmd.kind = match sub.as_str() {
        "" | "help" | "version" | "--version" | "status" | "diff" | "log" | "show"
        | "rev-parse" | "rev-list" | "ls-files" | "ls-remote" | "ls-tree" | "cat-file"
        | "blame" | "describe" | "shortlog" | "grep" | "whatchanged" | "merge-base"
        | "name-rev" | "for-each-ref" | "show-ref" | "count-objects" | "fsck" | "check-ignore"
        | "check-attr" | "var" | "diff-tree" | "diff-files" | "diff-index" | "range-diff"
        | "cherry" | "annotate" | "show-branch" | "verify-commit" | "verify-tag" => {
            GitKind::ReadOnly
        }
        "reflog" => {
            if positional.first().map(|s| s.as_str()) == Some("expire")
                || positional.first().map(|s| s.as_str()) == Some("delete")
            {
                GitKind::LocalMutation
            } else {
                GitKind::ReadOnly
            }
        }
        "fetch" => GitKind::Fetch,
        "pull" => GitKind::Pull,
        "clone" => {
            let dest = positional.get(1).map(|s| s.to_string());
            if let Some(d) = &dest {
                cmd.output_paths.push(d.clone());
            }
            GitKind::Clone { destination: dest }
        }
        "archive" => {
            let mut j = 0;
            while j < rest.len() {
                if let Some(v) = take_value(&rest, &mut j, "--output")
                    .or_else(|| take_value(&rest, &mut j, "-o"))
                {
                    cmd.output_paths.push(v);
                }
                j += 1;
            }
            GitKind::ReadOnly
        }
        "branch" => {
            let listing = positional.is_empty()
                || has("--list")
                || has("-l")
                || has("--show-current")
                || has_prefix("--contains")
                || has_prefix("--merged")
                || has_prefix("--no-merged")
                || has_prefix("--points-at");
            let modifying = has("-d")
                || has("-D")
                || has("--delete")
                || has("-m")
                || has("-M")
                || has("-c")
                || has("-C")
                || has("--set-upstream-to")
                || has("-u")
                || has("--unset-upstream")
                || has("-f")
                || has("--force");
            if listing && !modifying {
                GitKind::ReadOnly
            } else {
                if !(has("-d") || has("-D") || has("--delete")) {
                    if let Some(name) = positional.last().filter(|_| !has("-m") && !has("-M")) {
                        cmd.created_refs.push(name.to_string());
                    } else if (has("-m") || has("-M")) && positional.len() >= 2 {
                        cmd.created_refs
                            .push(positional[positional.len() - 1].to_string());
                    } else if (has("-m") || has("-M")) && positional.len() == 1 {
                        cmd.created_refs.push(positional[0].to_string());
                    }
                }
                GitKind::LocalMutation
            }
        }
        "tag" => {
            let listing = positional.is_empty()
                || has("-l")
                || has("--list")
                || has_prefix("--contains")
                || has_prefix("--points-at")
                || has("-v")
                || has("--verify");
            let deleting = has("-d") || has("--delete");
            let mut j = 0;
            while j < rest.len() {
                if let Some(m) = take_value(&rest, &mut j, "-m")
                    .or_else(|| take_value(&rest, &mut j, "--message"))
                {
                    cmd.messages.push(m);
                } else if let Some(f) =
                    take_value(&rest, &mut j, "-F").or_else(|| take_value(&rest, &mut j, "--file"))
                {
                    cmd.message_files.push(f);
                }
                j += 1;
            }
            if listing && !deleting && cmd.messages.is_empty() {
                GitKind::ReadOnly
            } else {
                if !deleting && let Some(name) = positional.first() {
                    cmd.created_refs.push(name.to_string());
                }
                GitKind::LocalMutation
            }
        }
        "remote" => match positional.first().map(|s| s.as_str()) {
            None | Some("show") | Some("get-url") => GitKind::ReadOnly,
            _ => GitKind::LocalMutation,
        },
        "stash" => match positional.first().map(|s| s.as_str()) {
            Some("list") | Some("show") => GitKind::ReadOnly,
            _ => GitKind::LocalMutation,
        },
        "worktree" => match positional.first().map(|s| s.as_str()) {
            Some("list") => GitKind::ReadOnly,
            Some("add") => {
                if let Some(p) = positional.get(1) {
                    cmd.output_paths.push(p.to_string());
                }
                GitKind::LocalMutation
            }
            _ => GitKind::LocalMutation,
        },
        "submodule" => match positional.first().map(|s| s.as_str()) {
            None | Some("status") | Some("summary") => GitKind::ReadOnly,
            _ => GitKind::LocalMutation,
        },
        "checkout" | "switch" => {
            let mut j = 0;
            while j < rest.len() {
                if let Some(b) = take_value(&rest, &mut j, "-b")
                    .or_else(|| take_value(&rest, &mut j, "-B"))
                    .or_else(|| take_value(&rest, &mut j, "-c"))
                    .or_else(|| take_value(&rest, &mut j, "-C"))
                    .or_else(|| take_value(&rest, &mut j, "--orphan"))
                {
                    cmd.created_refs.push(b);
                }
                j += 1;
            }
            GitKind::LocalMutation
        }
        "add" | "rm" | "mv" | "restore" | "merge" | "cherry-pick" | "revert" | "init" | "am"
        | "apply" | "gc" | "prune" | "notes" | "sparse-checkout" | "update-index" | "bisect"
        | "mergetool" | "repack" | "maintenance" | "lfs" | "update-ref" | "symbolic-ref"
        | "replace" => {
            if sub == "notes" {
                let mut j = 0;
                while j < rest.len() {
                    if let Some(m) = take_value(&rest, &mut j, "-m") {
                        cmd.messages.push(m);
                    }
                    j += 1;
                }
            }
            if sub == "merge" {
                let mut j = 0;
                while j < rest.len() {
                    if let Some(m) = take_value(&rest, &mut j, "-m")
                        .or_else(|| take_value(&rest, &mut j, "--message"))
                    {
                        cmd.messages.push(m);
                    }
                    j += 1;
                }
            }
            GitKind::LocalMutation
        }
        "commit" => {
            let mut j = 0;
            let mut amend = false;
            while j < rest.len() {
                let a = rest[j].clone();
                if a == "--amend" {
                    amend = true;
                } else if let Some(m) = take_value(&rest, &mut j, "-m")
                    .or_else(|| take_value(&rest, &mut j, "--message"))
                {
                    cmd.messages.push(m);
                } else if let Some(f) =
                    take_value(&rest, &mut j, "-F").or_else(|| take_value(&rest, &mut j, "--file"))
                {
                    cmd.message_files.push(f);
                } else if let Some(t) = take_value(&rest, &mut j, "--trailer") {
                    cmd.messages.push(t);
                } else if let Some(au) = take_value(&rest, &mut j, "--author") {
                    cmd.identity_overrides.push(format!("author={au}"));
                }
                j += 1;
            }
            if amend {
                GitKind::CommitAmend
            } else {
                GitKind::LocalMutation
            }
        }
        "reset" => {
            if has("--hard") || has("--merge") || has("--keep") {
                GitKind::ResetHard
            } else {
                GitKind::LocalMutation
            }
        }
        "clean" => {
            let dry = has("-n") || has("--dry-run");
            let force = rest.iter().any(|a| {
                a == "--force" || (a.starts_with('-') && !a.starts_with("--") && a.contains('f'))
            });
            if dry || !force {
                GitKind::ReadOnly
            } else {
                GitKind::Clean
            }
        }
        "filter-branch" | "filter-repo" => GitKind::HistoryRewrite,
        "rebase" => {
            if has("--abort")
                || has("--quit")
                || has("--show-current-patch")
                || has("--continue")
                || has("--skip")
            {
                GitKind::LocalMutation
            } else {
                let upstream = positional.first().map(|s| s.to_string());
                GitKind::Rebase { upstream }
            }
        }
        "push" => GitKind::Push(parse_push(&rest, &mut cmd.created_refs)),
        "credential"
        | "credential-manager"
        | "credential-manager-core"
        | "credential-store"
        | "credential-cache"
        | "credential-wincred" => GitKind::CredentialAccess,
        "config" => classify_config(&rest, &mut cmd),
        _ => GitKind::Unknown,
    };
    if config_credential && matches!(cmd.kind, GitKind::ReadOnly | GitKind::Unknown) {
        // `-c credential.helper=...` with read commands is harmless; keep kind.
    }
    if !cmd.identity_overrides.is_empty() && !matches!(cmd.kind, GitKind::IdentityChange) {
        // Identity overrides on an otherwise ordinary command are flagged by policy.
    }
    cmd
}

fn classify_config(rest: &[String], cmd: &mut GitCommand) -> GitKind {
    let read_flags = [
        "--get",
        "--get-all",
        "--get-regexp",
        "--list",
        "-l",
        "--get-urlmatch",
        "--show-origin",
        "--show-scope",
        "--name-only",
    ];
    let is_read = rest.iter().any(|a| read_flags.contains(&a.as_str()));
    let global = rest.iter().any(|a| a == "--global" || a == "--system");
    let positional: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
    if is_read
        || positional.len() < 2
            && !rest.iter().any(|a| {
                a == "--unset"
                    || a == "--unset-all"
                    || a == "--add"
                    || a == "--replace-all"
                    || a.starts_with("--remove-section")
                    || a.starts_with("--rename-section")
            })
    {
        return GitKind::ReadOnly;
    }
    let key = positional
        .first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if IDENTITY_KEYS.contains(&key.as_str()) {
        if let Some(v) = positional.get(1) {
            cmd.identity_overrides.push(format!("{key}={v}"));
        }
        return GitKind::IdentityChange;
    }
    if key.starts_with("credential") {
        return GitKind::GlobalConfigChange;
    }
    if global {
        GitKind::GlobalConfigChange
    } else {
        GitKind::LocalMutation
    }
}

fn parse_push(rest: &[String], created: &mut Vec<String>) -> PushSpec {
    let mut spec = PushSpec {
        remote: None,
        destinations: Vec::new(),
        force: false,
        delete: false,
        all: false,
        mirror: false,
        tags: false,
        deletes_tags: false,
    };
    let mut positional = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "-f" | "--force" => spec.force = true,
            "-d" | "--delete" => spec.delete = true,
            "--all" | "--branches" => spec.all = true,
            "--mirror" => {
                spec.mirror = true;
                spec.force = true;
            }
            "--tags" => spec.tags = true,
            "--prune" => spec.delete = true,
            "-o" | "--push-option" | "--repo" | "--receive-pack" | "--exec" => {
                if a == "--repo" && i + 1 < rest.len() {
                    spec.remote = Some(rest[i + 1].clone());
                }
                i += 1;
            }
            _ if a.starts_with("--force-with-lease") || a.starts_with("--force-if-includes") => {
                spec.force = true
            }
            _ if a.starts_with("--repo=") => spec.remote = Some(a[7..].to_string()),
            _ if a.starts_with('-') && !a.starts_with("--") && a.len() > 2 => {
                // Combined short flags like -fu
                if a.contains('f') {
                    spec.force = true;
                }
                if a.contains('d') {
                    spec.delete = true;
                }
            }
            _ if a.starts_with('-') => {}
            _ => positional.push(a.to_string()),
        }
        i += 1;
    }
    let mut iter = positional.into_iter();
    if spec.remote.is_none() {
        spec.remote = iter.next();
    }
    for refspec in iter {
        let (force, body) = match refspec.strip_prefix('+') {
            Some(b) => (true, b.to_string()),
            None => (false, refspec.clone()),
        };
        if force {
            spec.force = true;
        }
        let (src, dst) = match body.split_once(':') {
            Some((s, d)) => (s.to_string(), d.to_string()),
            None => (body.clone(), body.clone()),
        };
        if src.is_empty() {
            spec.delete = true;
        }
        let dst_clean = dst.trim_start_matches("refs/heads/").to_string();
        if dst.starts_with("refs/tags/") {
            if src.is_empty() || spec.delete {
                spec.deletes_tags = true;
            }
            created.push(dst.clone());
            continue;
        }
        if !dst_clean.is_empty() && dst_clean != "HEAD" {
            created.push(dst_clean.clone());
        }
        spec.destinations.push(dst_clean);
    }
    if spec.delete && spec.tags {
        spec.deletes_tags = true;
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> GitCommand {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn read_only_commands() {
        for c in [
            "status",
            "log --oneline -5",
            "diff HEAD",
            "branch",
            "branch -a",
            "tag",
            "remote -v",
            "config --get user.name",
            "stash list",
            "clean -n -fd",
        ] {
            assert_eq!(p(c).kind, GitKind::ReadOnly, "{c}");
        }
    }

    #[test]
    fn destructive_commands() {
        assert_eq!(p("reset --hard HEAD~1").kind, GitKind::ResetHard);
        assert_eq!(p("clean -fdx").kind, GitKind::Clean);
        assert_eq!(p("clean -f").kind, GitKind::Clean);
        assert_eq!(
            p("filter-branch --tree-filter x").kind,
            GitKind::HistoryRewrite
        );
        assert_eq!(p("commit --amend -m x").kind, GitKind::CommitAmend);
        assert!(matches!(
            p("rebase main").kind,
            GitKind::Rebase { upstream: Some(_) }
        ));
        assert_eq!(p("rebase --continue").kind, GitKind::LocalMutation);
    }

    #[test]
    fn ordinary_checkout_and_restore_are_not_destructive() {
        assert_eq!(p("checkout feature").kind, GitKind::LocalMutation);
        assert_eq!(p("restore --staged file").kind, GitKind::LocalMutation);
        assert_eq!(p("reset HEAD file").kind, GitKind::LocalMutation);
    }

    #[test]
    fn push_parsing() {
        let GitKind::Push(s) = p("push origin feature").kind else {
            panic!()
        };
        assert_eq!(s.remote.as_deref(), Some("origin"));
        assert_eq!(s.destinations, vec!["feature"]);
        assert!(!s.force && !s.delete);

        let GitKind::Push(s) = p("push --force-with-lease origin main").kind else {
            panic!()
        };
        assert!(s.force);
        let GitKind::Push(s) = p("push origin +main").kind else {
            panic!()
        };
        assert!(s.force);
        let GitKind::Push(s) = p("push origin :old-branch").kind else {
            panic!()
        };
        assert!(s.delete);
        let GitKind::Push(s) = p("push origin --delete old").kind else {
            panic!()
        };
        assert!(s.delete);
        let GitKind::Push(s) = p("push origin HEAD:main").kind else {
            panic!()
        };
        assert_eq!(s.destinations, vec!["main"]);
        let GitKind::Push(s) = p("push").kind else {
            panic!()
        };
        assert!(s.remote.is_none() && s.destinations.is_empty());
        let GitKind::Push(s) = p("push origin :refs/tags/v1").kind else {
            panic!()
        };
        assert!(s.deletes_tags);
    }

    #[test]
    fn identity_and_messages() {
        let c = p("config user.email bot@example.com");
        assert_eq!(c.kind, GitKind::IdentityChange);
        let c = p("-c user.name=Bot commit -m hi");
        assert_eq!(c.identity_overrides.len(), 1);
        let c = parse(&[
            "commit".into(),
            "-m".into(),
            "Fix it".into(),
            "--trailer".into(),
            "Co-authored-by: X".into(),
        ]);
        assert_eq!(c.messages, vec!["Fix it", "Co-authored-by: X"]);
        let c = p("checkout -b claude/fix");
        assert_eq!(c.created_refs, vec!["claude/fix"]);
        assert_eq!(p("credential fill").kind, GitKind::CredentialAccess);
        assert_eq!(
            p("config --global core.autocrlf true").kind,
            GitKind::GlobalConfigChange
        );
        assert_eq!(p("-C sub status").cwd_override.as_deref(), Some("sub"));
    }
}
