//! Package-manager classification (plan section 14).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageScope {
    /// Project-local dependency install/build (allowed inside trusted projects).
    Local,
    /// User-global or system-wide install (approval by default).
    Global,
    /// Machine-wide install that needs elevation.
    Admin,
    /// Not an install-type action.
    NotInstall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageAction {
    pub manager: String,
    pub scope: PackageScope,
    pub detail: String,
}

/// Classify a package-manager invocation. `program_in_trusted` says whether
/// the resolved executable lives inside the trusted workspace (e.g. a project
/// virtual environment's `pip`).
pub fn classify(program: &str, args: &[String], program_in_trusted: bool) -> Option<PackageAction> {
    let lower: Vec<String> = args.iter().map(|a| a.to_ascii_lowercase()).collect();
    let has = |f: &str| lower.iter().any(|a| a == f);
    let first = lower
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_default();
    let mk = |scope, detail: &str| {
        Some(PackageAction {
            manager: program.to_string(),
            scope,
            detail: detail.to_string(),
        })
    };
    match program {
        "npm" | "pnpm" | "yarn" | "bun" | "cnpm" => {
            let global = has("-g")
                || has("--global")
                || lower.iter().any(|a| a == "--location=global")
                || (program == "yarn" && first == "global");
            let install_like = matches!(
                first.as_str(),
                "install"
                    | "i"
                    | "add"
                    | "ci"
                    | "update"
                    | "up"
                    | "upgrade"
                    | "remove"
                    | "rm"
                    | "uninstall"
                    | "un"
                    | "link"
                    | "global"
                    | ""
            );
            if program == "npm"
                && first == "install"
                && lower.iter().any(|a| a.contains("playwright"))
                && global
            {
                return mk(PackageScope::Global, "global Playwright install");
            }
            if global && install_like {
                mk(PackageScope::Global, &format!("{program} global install"))
            } else if install_like {
                mk(
                    PackageScope::Local,
                    &format!("{program} project dependency operation"),
                )
            } else if (first == "exec" || first == "x" || first == "dlx")
                && lower.iter().any(|a| a == "playwright")
                && lower.iter().any(|a| a == "install")
            {
                mk(
                    PackageScope::Global,
                    "Playwright browser download into the user profile",
                )
            } else {
                mk(PackageScope::NotInstall, "package script")
            }
        }
        "npx" => {
            if lower.iter().any(|a| a == "playwright") && lower.iter().any(|a| a == "install") {
                mk(
                    PackageScope::Global,
                    "Playwright browser download into the user profile",
                )
            } else {
                mk(PackageScope::NotInstall, "npx package execution")
            }
        }
        "pip" | "pip3" => classify_pip(&lower, program_in_trusted),
        "python" | "python3" | "py" => {
            if let Some(pos) = lower.iter().position(|a| a == "-m") {
                let module = lower.get(pos + 1).map(|s| s.as_str()).unwrap_or("");
                if module == "pip" {
                    return classify_pip(&lower[pos + 2..], program_in_trusted);
                }
                if module == "venv" || module == "virtualenv" {
                    return mk(PackageScope::Local, "create virtual environment");
                }
            }
            None
        }
        "uv" => {
            if first == "tool" && lower.get(1).map(|s| s == "install").unwrap_or(false) {
                mk(PackageScope::Global, "uv tool install")
            } else if first == "pip" && has("--system") {
                mk(PackageScope::Global, "uv pip install --system")
            } else {
                mk(PackageScope::Local, "uv project operation")
            }
        }
        "poetry" | "pipenv" | "pdm" | "hatch" | "bundle" => mk(
            PackageScope::Local,
            &format!("{program} project dependency operation"),
        ),
        "pipx" => match first.as_str() {
            "install" | "upgrade" | "uninstall" | "inject" | "ensurepath" => {
                mk(PackageScope::Global, "pipx user-global install")
            }
            _ => mk(PackageScope::NotInstall, "pipx"),
        },
        "cargo" => match first.as_str() {
            "install" | "uninstall" => mk(PackageScope::Global, "cargo install into ~/.cargo/bin"),
            _ => mk(PackageScope::Local, "cargo project operation"),
        },
        "rustup" => match first.as_str() {
            "show" | "which" | "--version" | "doc" => mk(PackageScope::NotInstall, "rustup query"),
            _ => mk(PackageScope::Global, "rustup toolchain change"),
        },
        "go" => match first.as_str() {
            "install" => mk(PackageScope::Global, "go install into GOBIN"),
            _ => mk(PackageScope::Local, "go project operation"),
        },
        "dotnet" => {
            if (first == "tool" && (has("-g") || has("--global") || has("--tool-path")))
                || (first == "new"
                    && (has("--install") || lower.get(1).map(|s| s == "install").unwrap_or(false)))
            {
                mk(PackageScope::Global, "dotnet global tool/template install")
            } else if first == "workload"
                && matches!(
                    lower.get(1).map(|s| s.as_str()),
                    Some("install" | "update" | "repair" | "uninstall")
                )
            {
                mk(PackageScope::Admin, "dotnet workload change")
            } else {
                mk(PackageScope::Local, "dotnet project operation")
            }
        }
        "winget" => match first.as_str() {
            "install" | "upgrade" | "uninstall" | "remove" | "import" | "update" | "add" => {
                if lower.iter().any(|a| a == "machine") && has("--scope") {
                    mk(PackageScope::Admin, "winget machine-wide install")
                } else {
                    mk(PackageScope::Global, "winget install")
                }
            }
            _ => mk(PackageScope::NotInstall, "winget query"),
        },
        "choco" | "chocolatey" => match first.as_str() {
            "install" | "upgrade" | "uninstall" | "update" | "feature" | "source" | "config" => {
                mk(PackageScope::Admin, "Chocolatey system install")
            }
            _ => mk(PackageScope::NotInstall, "choco query"),
        },
        "scoop" => match first.as_str() {
            "install" | "update" | "uninstall" | "bucket" | "reset" => {
                if has("--global") || has("-g") {
                    mk(PackageScope::Admin, "scoop global install")
                } else {
                    mk(PackageScope::Global, "scoop user install")
                }
            }
            _ => mk(PackageScope::NotInstall, "scoop query"),
        },
        "gem" => match first.as_str() {
            "install" | "uninstall" | "update" => mk(PackageScope::Global, "gem install"),
            _ => mk(PackageScope::NotInstall, "gem query"),
        },
        "composer" => {
            if first == "global" {
                mk(PackageScope::Global, "composer global install")
            } else {
                mk(PackageScope::Local, "composer project operation")
            }
        }
        "nvm" | "volta" | "fnm" | "corepack" | "sdkmanager" => match first.as_str() {
            "list" | "ls" | "current" | "version" | "--version" => {
                mk(PackageScope::NotInstall, "version manager query")
            }
            _ => mk(PackageScope::Global, "runtime/version manager change"),
        },
        _ => None,
    }
}

fn classify_pip(lower: &[String], program_in_trusted: bool) -> Option<PackageAction> {
    let first = lower
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_default();
    let mk = |scope, detail: &str| {
        Some(PackageAction {
            manager: "pip".into(),
            scope,
            detail: detail.to_string(),
        })
    };
    if !matches!(
        first.as_str(),
        "install" | "uninstall" | "download" | "wheel"
    ) {
        return mk(PackageScope::NotInstall, "pip query");
    }
    if lower.iter().any(|a| a == "--user") {
        return mk(PackageScope::Global, "pip install --user");
    }
    if lower.iter().any(|a| {
        a == "--target"
            || a == "-t"
            || a.starts_with("--target=")
            || a == "--prefix"
            || a == "--root"
    }) {
        return mk(
            PackageScope::Local,
            "pip install into an explicit directory (checked separately)",
        );
    }
    if first == "download" || first == "wheel" {
        return mk(PackageScope::Local, "pip download");
    }
    if program_in_trusted {
        mk(
            PackageScope::Local,
            "pip install inside a project virtual environment",
        )
    } else {
        mk(
            PackageScope::Global,
            "pip install into a global interpreter",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(p: &str, a: &str, t: bool) -> PackageScope {
        classify(
            p,
            &a.split_whitespace().map(String::from).collect::<Vec<_>>(),
            t,
        )
        .map(|x| x.scope)
        .unwrap_or(PackageScope::NotInstall)
    }

    #[test]
    fn local_vs_global() {
        assert_eq!(c("npm", "install", false), PackageScope::Local);
        assert_eq!(
            c("npm", "install -g typescript", false),
            PackageScope::Global
        );
        assert_eq!(c("pnpm", "add -D vitest", false), PackageScope::Local);
        assert_eq!(c("yarn", "global add x", false), PackageScope::Global);
        assert_eq!(
            c("pip", "install -r requirements.txt", true),
            PackageScope::Local
        );
        assert_eq!(c("pip", "install requests", false), PackageScope::Global);
        assert_eq!(
            c("python", "-m pip install --user x", true),
            PackageScope::Global
        );
        assert_eq!(c("poetry", "install", false), PackageScope::Local);
        assert_eq!(c("cargo", "build", false), PackageScope::Local);
        assert_eq!(c("cargo", "install ripgrep", false), PackageScope::Global);
        assert_eq!(c("go", "mod download", false), PackageScope::Local);
        assert_eq!(c("dotnet", "restore", false), PackageScope::Local);
        assert_eq!(
            c("dotnet", "tool install -g x", false),
            PackageScope::Global
        );
        assert_eq!(c("winget", "install Git.Git", false), PackageScope::Global);
        assert_eq!(
            c("winget", "install --scope machine Git.Git", false),
            PackageScope::Admin
        );
        assert_eq!(c("choco", "install git", false), PackageScope::Admin);
        assert_eq!(c("npm", "test", false), PackageScope::NotInstall);
    }
}
