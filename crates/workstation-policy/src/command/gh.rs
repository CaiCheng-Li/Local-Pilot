//! GitHub CLI (`gh`) classification.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GhKind {
    Read,
    Write,
    /// Irreversible remote changes (repo/release deletion, archival, DELETE API calls).
    DestructiveWrite,
    CredentialAccess,
    CredentialChange,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhCommand {
    pub group: String,
    pub action: String,
    pub kind: GhKind,
    /// User-visible text fields (titles, bodies, notes, API field values).
    pub texts: Vec<String>,
    /// Files supplying body text (`--body-file`, `-F`).
    pub text_files: Vec<String>,
    /// Branch/tag names created remotely (e.g. `--head`, release tag).
    pub created_refs: Vec<String>,
}

fn value_of(args: &[String], names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        for n in names {
            if a == n && i + 1 < args.len() {
                out.push(args[i + 1].clone());
            } else if let Some(v) = a.strip_prefix(&format!("{n}=")) {
                out.push(v.to_string());
            }
        }
        i += 1;
    }
    out
}

pub fn parse(args: &[String]) -> GhCommand {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let group = positional
        .first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let action = positional
        .get(1)
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let has = |f: &str| args.iter().any(|a| a == f);
    let mut cmd = GhCommand {
        group: group.clone(),
        action: action.clone(),
        kind: GhKind::Unknown,
        texts: value_of(
            args,
            &[
                "--title",
                "-t",
                "--body",
                "-b",
                "--notes",
                "-n",
                "--message",
                "--subject",
                "--description",
                "-d",
            ],
        ),
        text_files: value_of(args, &["--body-file", "-F", "--notes-file"]),
        created_refs: value_of(args, &["--head", "-H"]),
    };
    cmd.kind = match group.as_str() {
        "auth" => match action.as_str() {
            "token" => GhKind::CredentialAccess,
            "status" if has("-t") || has("--show-token") => GhKind::CredentialAccess,
            "status" => GhKind::Read,
            "login" | "logout" | "refresh" | "setup-git" | "switch" => GhKind::CredentialChange,
            _ => GhKind::Unknown,
        },
        "secret" | "variable" | "ssh-key" | "gpg-key" => match action.as_str() {
            "list" | "get" => GhKind::Read,
            _ => GhKind::CredentialChange,
        },
        "pr" | "issue" => match action.as_str() {
            "list" | "view" | "status" | "checks" | "diff" => GhKind::Read,
            "delete" => GhKind::DestructiveWrite,
            "checkout" => GhKind::Read,
            _ => GhKind::Write,
        },
        "release" => match action.as_str() {
            "list" | "view" | "download" => GhKind::Read,
            "delete" | "delete-asset" => GhKind::DestructiveWrite,
            _ => {
                if action == "create"
                    && let Some(tag) = positional.get(2)
                {
                    cmd.created_refs.push(tag.to_string());
                    cmd.texts.push(tag.to_string());
                }
                GhKind::Write
            }
        },
        "repo" => match action.as_str() {
            "view" | "list" | "clone" => GhKind::Read,
            "delete" | "archive" | "rename" => GhKind::DestructiveWrite,
            _ => GhKind::Write,
        },
        "gist" | "label" | "project" | "cache" | "ruleset" => match action.as_str() {
            "list" | "view" => GhKind::Read,
            "delete" => GhKind::DestructiveWrite,
            _ => GhKind::Write,
        },
        "workflow" | "run" => match action.as_str() {
            "list" | "view" | "watch" | "download" => GhKind::Read,
            _ => GhKind::Write,
        },
        "api" => {
            let method = value_of(args, &["-X", "--method"])
                .first()
                .map(|m| m.to_ascii_uppercase());
            let fields = value_of(args, &["-f", "--raw-field", "-F", "--field"]);
            cmd.texts.extend(fields.iter().map(|f| {
                f.split_once('=')
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default()
            }));
            match method.as_deref() {
                Some("DELETE") => GhKind::DestructiveWrite,
                Some("GET") | Some("HEAD") => GhKind::Read,
                Some(_) => GhKind::Write,
                None if fields.is_empty() && !has("--input") => GhKind::Read,
                None => GhKind::Write,
            }
        }
        "browse" | "search" | "status" | "help" | "version" | "--version" | "extension"
        | "alias" | "config" | "codespace" | "org" | "completion" => GhKind::Read,
        _ => GhKind::Unknown,
    };
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &[&str]) -> GhCommand {
        parse(&s.iter().map(|x| x.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn classifies() {
        assert_eq!(p(&["auth", "token"]).kind, GhKind::CredentialAccess);
        assert_eq!(
            p(&["auth", "status", "--show-token"]).kind,
            GhKind::CredentialAccess
        );
        assert_eq!(p(&["auth", "status"]).kind, GhKind::Read);
        assert_eq!(p(&["pr", "list"]).kind, GhKind::Read);
        let c = p(&[
            "pr",
            "create",
            "--title",
            "Fix",
            "--body",
            "Generated with ChatGPT",
        ]);
        assert_eq!(c.kind, GhKind::Write);
        assert_eq!(c.texts, vec!["Fix", "Generated with ChatGPT"]);
        assert_eq!(p(&["repo", "delete", "x/y"]).kind, GhKind::DestructiveWrite);
        assert_eq!(p(&["api", "repos/x/y"]).kind, GhKind::Read);
        assert_eq!(
            p(&["api", "-X", "POST", "repos/x/y/issues", "-f", "title=hi"]).kind,
            GhKind::Write
        );
        assert_eq!(p(&["secret", "set", "X"]).kind, GhKind::CredentialChange);
    }
}
