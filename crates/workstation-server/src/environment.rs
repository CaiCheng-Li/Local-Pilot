//! Child-process environment (plan section 6).
//!
//! Agent-launched processes inherit the user's normal environment so installed
//! tools work, except secret-looking variables, which are excluded unless a
//! locally created tool grant maps them to an identified executable. Agents
//! cannot grant themselves inheritance via `env_overrides`. `TEMP`/`TMP` and
//! supported package caches point into the task's cache/temp directory.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use workstation_core::config::Settings;
use workstation_core::paths::{eq_ci, starts_with_ci};
use workstation_core::redaction::is_secret_env_name;
use workstation_core::{ErrorCode, LpError, LpResult};

/// Variables an agent may never set through `env_overrides`.
const PROTECTED_OVERRIDES: &[&str] = &[
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_SSH_COMMAND",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_CONFIG_DIR",
    "USERPROFILE",
    "HOME",
    "APPDATA",
    "LOCALAPPDATA",
    "SYSTEMROOT",
    "COMSPEC",
];

/// Package-manager cache variables redirected to the tool cache.
const CACHE_VARS: &[(&str, &str)] = &[
    ("npm_config_cache", "npm"),
    ("YARN_CACHE_FOLDER", "yarn"),
    ("PIP_CACHE_DIR", "pip"),
    ("UV_CACHE_DIR", "uv"),
    ("POETRY_CACHE_DIR", "poetry"),
    ("GOCACHE", "go-build"),
    ("NUGET_HTTP_CACHE_PATH", "nuget-http"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarInfo {
    pub name: String,
    /// Whether an agent-launched process inherits it.
    pub inherited: bool,
    pub secret_like: bool,
    pub explicitly_allowed: bool,
    pub explicitly_denied: bool,
    /// Value shown only for non-secret variables or disclosable allowed ones.
    pub value: Option<String>,
    pub granted_to_tools: Vec<String>,
}

fn is_denied(settings: &Settings, name: &str) -> bool {
    settings
        .environment
        .denied
        .iter()
        .any(|d| d.eq_ignore_ascii_case(name))
}

fn is_allowed(settings: &Settings, name: &str) -> bool {
    settings
        .environment
        .allowed
        .iter()
        .any(|d| d.eq_ignore_ascii_case(name))
}

/// Whether `name` from the parent environment is inherited by a child that
/// runs `executable` in `cwd`.
pub fn inherits(settings: &Settings, name: &str, executable: Option<&Path>, cwd: &Path) -> bool {
    if is_denied(settings, name) {
        return false;
    }
    if !is_secret_env_name(name) || is_allowed(settings, name) {
        return true;
    }
    // Secret-like: only through a configured tool grant bound to this executable.
    let Some(exe) = executable else { return false };
    settings.environment.tool_grants.iter().any(|g| {
        g.variables.iter().any(|v| v.eq_ignore_ascii_case(name))
            && eq_ci(Path::new(&g.executable_path), exe)
            && g.project_scope
                .as_ref()
                .map(|p| starts_with_ci(cwd, Path::new(p)))
                .unwrap_or(true)
            && grant_identity_matches(&g.executable_path, &g.executable_sha256)
    })
}

/// Executable identity check for tool grants: the recorded SHA-256 must still
/// match (a changed binary requires the user to review the grant again).
pub fn grant_identity_matches(path: &str, sha: &str) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => workstation_core::hashing::sha256_hex(&bytes) == sha,
        Err(_) => false,
    }
}

pub struct ChildEnv {
    pub vars: Vec<(String, String)>,
    pub withheld: Vec<String>,
}

/// Build the environment for an agent-launched process.
pub fn build(
    settings: &Settings,
    executable: Option<&Path>,
    cwd: &Path,
    overrides: &[(String, String)],
    task_temp: &Path,
    tool_cache: Option<&Path>,
) -> LpResult<ChildEnv> {
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut withheld = Vec::new();
    for (k, v) in std::env::vars() {
        if inherits(settings, &k, executable, cwd) {
            vars.push((k, v));
        } else {
            withheld.push(k);
        }
    }
    let set = |vars: &mut Vec<(String, String)>, k: &str, v: String| {
        vars.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
        vars.push((k.to_string(), v));
    };
    for (k, v) in overrides {
        if k.is_empty()
            || k.contains('=')
            || k.contains('\0')
            || v.contains('\0')
            || k.len() > 256
            || v.len() > 32 * 1024
        {
            return Err(LpError::invalid(format!(
                "invalid environment override {k:?}"
            )));
        }
        if PROTECTED_OVERRIDES
            .iter()
            .any(|p| p.eq_ignore_ascii_case(k))
        {
            return Err(LpError::new(
                ErrorCode::PermissionDenied,
                format!(
                    "{k} cannot be overridden by agents (identity, credential or profile variable)"
                ),
            ));
        }
        if withheld.iter().any(|w| w.eq_ignore_ascii_case(k)) && is_secret_env_name(k) {
            // Setting a new literal value is allowed; referencing the withheld
            // secret is not possible because its value never reaches the agent.
        }
        if v.contains('%')
            && withheld.iter().any(|w| {
                v.to_ascii_lowercase()
                    .contains(&format!("%{}%", w.to_ascii_lowercase()))
            })
        {
            return Err(LpError::new(
                ErrorCode::ProtectedResource,
                format!("{k} references a withheld secret variable"),
            ));
        }
        set(&mut vars, k, v.clone());
    }
    let tmp = task_temp.display().to_string();
    set(&mut vars, "TEMP", tmp.clone());
    set(&mut vars, "TMP", tmp);
    // Avoid interactive prompts hanging a task.
    set(&mut vars, "GIT_TERMINAL_PROMPT", "0".into());
    set(&mut vars, "GCM_INTERACTIVE", "never".into());
    if settings.cache_temp.redirect_package_caches
        && let Some(cache) = tool_cache
    {
        for (var, sub) in CACHE_VARS {
            let user_set = overrides.iter().any(|(k, _)| k.eq_ignore_ascii_case(var));
            if !user_set {
                set(&mut vars, var, cache.join(sub).display().to_string());
            }
        }
    }
    Ok(ChildEnv { vars, withheld })
}

/// Environment inspection for the local UI.
pub fn inspect(settings: &Settings) -> Vec<EnvVarInfo> {
    let mut out: Vec<EnvVarInfo> = std::env::vars()
        .map(|(k, v)| {
            let secret = is_secret_env_name(&k);
            let allowed = is_allowed(settings, &k);
            let denied = is_denied(settings, &k);
            let disclosable = settings
                .environment
                .disclosable
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&k));
            let inherited = !denied && (!secret || allowed);
            let grants = settings
                .environment
                .tool_grants
                .iter()
                .filter(|g| g.variables.iter().any(|x| x.eq_ignore_ascii_case(&k)))
                .map(|g| g.executable_path.clone())
                .collect();
            EnvVarInfo {
                value: if !secret || (allowed && disclosable) {
                    Some(v)
                } else {
                    None
                },
                name: k,
                inherited,
                secret_like: secret,
                explicitly_allowed: allowed,
                explicitly_denied: denied,
                granted_to_tools: grants,
            }
        })
        .collect();
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

/// Names of variables whose values may be shown to agents.
pub fn disclosable_to_agents(settings: &Settings, name: &str) -> bool {
    if is_denied(settings, name) {
        return false;
    }
    !is_secret_env_name(name)
        || (is_allowed(settings, name)
            && settings
                .environment
                .disclosable
                .iter()
                .any(|d| d.eq_ignore_ascii_case(name)))
}

pub fn tool_profile_for(executable: &Path) -> String {
    let name = executable
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| "tool".into());
    let clean: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if clean.is_empty() {
        "tool".into()
    } else {
        clean
    }
}

pub fn exe_path(p: &Path) -> PathBuf {
    p.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_withheld_and_overrides_checked() {
        // SAFETY: test-only environment mutation.
        unsafe { std::env::set_var("LP_TEST_API_TOKEN", "abc123secretvalue") };
        let s = Settings::default();
        let dir = tempfile::tempdir().unwrap();
        let env = build(
            &s,
            None,
            dir.path(),
            &[("FOO".into(), "bar".into())],
            dir.path(),
            None,
        )
        .unwrap();
        assert!(!env.vars.iter().any(|(k, _)| k == "LP_TEST_API_TOKEN"));
        assert!(env.withheld.iter().any(|k| k == "LP_TEST_API_TOKEN"));
        assert!(env.vars.iter().any(|(k, v)| k == "FOO" && v == "bar"));
        assert!(env.vars.iter().any(|(k, _)| k == "TEMP"));
        assert!(
            build(
                &s,
                None,
                dir.path(),
                &[("GIT_AUTHOR_NAME".into(), "x".into())],
                dir.path(),
                None
            )
            .is_err()
        );
        assert!(
            build(
                &s,
                None,
                dir.path(),
                &[("X".into(), "%LP_TEST_API_TOKEN%".into())],
                dir.path(),
                None
            )
            .is_err()
        );
        let mut s2 = Settings::default();
        s2.environment.allowed.push("LP_TEST_API_TOKEN".into());
        let env = build(&s2, None, dir.path(), &[], dir.path(), None).unwrap();
        assert!(env.vars.iter().any(|(k, _)| k == "LP_TEST_API_TOKEN"));
    }
}
