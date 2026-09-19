//! Protected secret and credential locations (plan section 3).
//!
//! Rules are deterministic: a set of protected directories (resolved from the
//! user's known folders and canonicalized where they exist), file-name
//! patterns, and explicit exceptions. Generic-word patterns (`*token*`,
//! `credentials*`, `secrets*`) skip configured source-code extensions so that
//! normal development (e.g. `tokenizer.rs`) keeps working.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use workstation_core::config::ProtectedPathSettings;
use workstation_core::paths::starts_with_ci;

use crate::winpath::{self, ExpandEnv};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedMatch {
    pub rule: String,
    pub kind: ProtectedKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedKind {
    Directory,
    FilePattern,
    EnvFile,
}

/// Protected directories relative to known folders.
fn default_directories(env: &ExpandEnv) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let profile = env.profile.clone();
    let lookup = |name: &str| {
        env.vars
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.clone())
    };
    if let Some(p) = &profile {
        for d in [
            ".ssh",
            ".aws",
            ".azure",
            ".gnupg",
            ".kube",
            ".docker",
            ".cloudflared",
            ".wrangler",
            ".config\\gh",
            ".config\\gcloud",
            ".config\\git\\credentials",
            ".git-credentials",
            ".netrc",
            "_netrc",
            ".npmrc",
            ".pypirc",
            ".terraform.d\\credentials.tfrc.json",
            ".cargo\\credentials",
            ".cargo\\credentials.toml",
            ".vault-token",
            ".password-store",
            ".m2\\settings-security.xml",
        ] {
            out.push((format!("%USERPROFILE%\\{d}"), p.join(d)));
        }
    }
    if let Some(a) = lookup("APPDATA") {
        for d in [
            "Microsoft\\Credentials",
            "Microsoft\\Protect",
            "Microsoft\\Vault",
            "Microsoft\\SystemCertificates\\My",
            "GitHub CLI",
            "gcloud",
            "Mozilla\\Firefox\\Profiles",
            "Bitwarden",
            "KeePass",
            "KeePassXC",
            "1Password",
            "xdg.config\\.wrangler",
            "Docker\\config.json",
        ] {
            out.push((format!("%APPDATA%\\{d}"), a.join(d)));
        }
    }
    if let Some(l) = lookup("LOCALAPPDATA") {
        for d in [
            "Microsoft\\Credentials",
            "Microsoft\\Vault",
            "Google\\Chrome\\User Data",
            "Microsoft\\Edge\\User Data",
            "BraveSoftware\\Brave-Browser\\User Data",
            "Vivaldi\\User Data",
            "Opera Software",
            "1Password",
            "Bitwarden",
            "GitCredentialManager",
            "gcloud",
        ] {
            out.push((format!("%LOCALAPPDATA%\\{d}"), l.join(d)));
        }
    }
    if let Some(s) = lookup("SYSTEMROOT") {
        out.push((
            "%SYSTEMROOT%\\System32\\config".into(),
            s.join("System32").join("config"),
        ));
    }
    out
}

const FILE_PATTERNS: &[&str] = &[
    "*.pem",
    "*.pfx",
    "*.p12",
    "*.key",
    "*.ppk",
    "*.kdbx",
    "*.keystore",
    "*.jks",
    "id_rsa",
    "id_rsa.*",
    "id_dsa",
    "id_dsa.*",
    "id_ecdsa",
    "id_ecdsa.*",
    "id_ed25519",
    "id_ed25519.*",
    ".git-credentials",
    ".netrc",
    "_netrc",
    ".pgpass",
    "*.tfstate",
    "*.tfstate.backup",
];

/// Generic-word patterns that skip source-code extensions.
const GENERIC_PATTERNS: &[&str] = &["credentials*", "secrets*", "*token*"];

pub struct ProtectedRules {
    directories: Vec<(String, PathBuf)>,
    files: GlobSet,
    file_names: Vec<String>,
    generic: GlobSet,
    generic_names: Vec<String>,
    exceptions: GlobSet,
    source_exts: Vec<String>,
    allow_env_reads: bool,
    mutation_exceptions: Vec<PathBuf>,
}

fn glob(p: &str) -> Option<Glob> {
    GlobBuilder::new(p)
        .case_insensitive(true)
        .literal_separator(true)
        .build()
        .ok()
}

impl ProtectedRules {
    pub fn new(settings: &ProtectedPathSettings, env: &ExpandEnv) -> Self {
        let mut directories = default_directories(env);
        for extra in &settings.extra_directories {
            if let Ok(p) = winpath::normalize(extra, Path::new("C:\\"), env) {
                directories.push((extra.clone(), p));
            }
        }
        // Canonicalize existing protected locations so junction/redirected
        // folders are matched by their real destination as well.
        let mut resolved = Vec::new();
        for (label, p) in &directories {
            resolved.push((label.clone(), p.clone()));
            if let Ok(c) = winpath::canonicalize(p, true)
                && !workstation_core::paths::eq_ci(&c.path, p)
            {
                resolved.push((label.clone(), c.path));
            }
        }

        let mut files = GlobSetBuilder::new();
        let mut file_names = Vec::new();
        for p in FILE_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .chain(settings.extra_file_patterns.iter().cloned())
        {
            if let Some(g) = glob(&p) {
                files.add(g);
                file_names.push(p);
            }
        }
        let mut generic = GlobSetBuilder::new();
        let mut generic_names = Vec::new();
        for p in GENERIC_PATTERNS {
            if let Some(g) = glob(p) {
                generic.add(g);
                generic_names.push(p.to_string());
            }
        }
        let mut exceptions = GlobSetBuilder::new();
        for p in &settings.exceptions {
            if let Some(g) = glob(p) {
                exceptions.add(g);
            }
        }
        Self {
            directories: resolved,
            files: files.build().unwrap_or_else(|_| GlobSet::empty()),
            file_names,
            generic: generic.build().unwrap_or_else(|_| GlobSet::empty()),
            generic_names,
            exceptions: exceptions.build().unwrap_or_else(|_| GlobSet::empty()),
            source_exts: settings
                .generic_pattern_source_extensions
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            allow_env_reads: settings.allow_env_file_reads,
            mutation_exceptions: settings
                .mutation_exceptions
                .iter()
                .map(PathBuf::from)
                .collect(),
        }
    }

    pub fn directories(&self) -> impl Iterator<Item = (&str, &Path)> {
        self.directories
            .iter()
            .map(|(l, p)| (l.as_str(), p.as_path()))
    }

    /// Check a canonical path. `for_read` distinguishes `.env` read policy.
    pub fn check(&self, path: &Path, for_read: bool) -> Option<ProtectedMatch> {
        for (label, dir) in &self.directories {
            if starts_with_ci(path, dir) {
                return Some(ProtectedMatch {
                    rule: label.clone(),
                    kind: ProtectedKind::Directory,
                });
            }
        }
        // Any `.ssh` or `.gnupg` directory component protects its contents.
        for c in path.components() {
            let s = c.as_os_str().to_string_lossy().to_ascii_lowercase();
            if s == ".ssh" || s == ".gnupg" {
                return Some(ProtectedMatch {
                    rule: format!("{s} directory"),
                    kind: ProtectedKind::Directory,
                });
            }
        }
        let name = path.file_name()?.to_string_lossy().to_string();
        self.check_name(&name, for_read)
    }

    /// Check a bare file name against file patterns.
    pub fn check_name(&self, name: &str, for_read: bool) -> Option<ProtectedMatch> {
        if self.exceptions.is_match(name) {
            return None;
        }
        let lower = name.to_ascii_lowercase();
        if lower == ".env" || lower.starts_with(".env.") || lower.ends_with(".env") {
            if for_read && self.allow_env_reads {
                return None;
            }
            return Some(ProtectedMatch {
                rule: ".env / .env.*".into(),
                kind: ProtectedKind::EnvFile,
            });
        }
        let hits = self.files.matches(name);
        if let Some(i) = hits.first() {
            return Some(ProtectedMatch {
                rule: self.file_names[*i].clone(),
                kind: ProtectedKind::FilePattern,
            });
        }
        let hits = self.generic.matches(name);
        if let Some(i) = hits.first() {
            let ext = Path::new(name)
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !self.source_exts.contains(&ext) {
                return Some(ProtectedMatch {
                    rule: self.generic_names[*i].clone(),
                    kind: ProtectedKind::FilePattern,
                });
            }
        }
        None
    }

    /// Whether a protected path has a local mutation exception.
    pub fn mutation_excepted(&self, path: &Path) -> bool {
        self.mutation_exceptions
            .iter()
            .any(|p| workstation_core::paths::eq_ci(p, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> ProtectedRules {
        let env = ExpandEnv {
            profile: Some(PathBuf::from(r"C:\Users\Alice")),
            vars: vec![
                ("USERPROFILE".into(), PathBuf::from(r"C:\Users\Alice")),
                (
                    "APPDATA".into(),
                    PathBuf::from(r"C:\Users\Alice\AppData\Roaming"),
                ),
                (
                    "LOCALAPPDATA".into(),
                    PathBuf::from(r"C:\Users\Alice\AppData\Local"),
                ),
            ],
        };
        ProtectedRules::new(&ProtectedPathSettings::default(), &env)
    }

    #[test]
    fn protects_credential_directories() {
        let r = rules();
        for p in [
            r"C:\Users\Alice\.ssh\id_rsa",
            r"C:\Users\Alice\.ssh\config",
            r"c:\users\alice\.AWS\credentials",
            r"C:\Users\Alice\AppData\Roaming\Microsoft\Credentials\x",
            r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"C:\Users\Alice\AppData\Roaming\GitHub CLI\hosts.yml",
            r"C:\Users\Alice\.config\gh\hosts.yml",
            r"C:\Users\Alice\.git-credentials",
            r"C:\Users\Alice\.cloudflared\cert.pem",
        ] {
            assert!(r.check(Path::new(p), true).is_some(), "{p}");
        }
    }

    #[test]
    fn protects_secret_file_patterns() {
        let r = rules();
        for p in [
            r"C:\P\app\.env",
            r"C:\P\app\.env.local",
            r"C:\P\app\server.pem",
            r"C:\P\app\cert.PFX",
            r"C:\P\app\id_ed25519",
            r"C:\P\app\credentials.json",
            r"C:\P\app\secrets.yaml",
            r"C:\P\app\github_token.txt",
            r"C:\P\app\deploy\.ssh\known_hosts",
        ] {
            assert!(r.check(Path::new(p), true).is_some(), "{p}");
        }
    }

    #[test]
    fn leaves_normal_development_files_alone() {
        let r = rules();
        for p in [
            r"C:\P\app\.env.example",
            r"C:\P\app\src\tokenizer.rs",
            r"C:\P\app\src\token.ts",
            r"C:\P\app\src\credentials.ts",
            r"C:\P\app\README.md",
            r"C:\P\app\package.json",
            r"C:\P\app\src\environment.ts",
            r"C:\Users\Alice\Documents\notes.txt",
        ] {
            assert!(r.check(Path::new(p), true).is_none(), "{p}");
        }
    }

    #[test]
    fn env_reads_can_be_allowed_locally() {
        let env = ExpandEnv::default();
        let settings = ProtectedPathSettings {
            allow_env_file_reads: true,
            ..Default::default()
        };
        let r = ProtectedRules::new(&settings, &env);
        assert!(r.check(Path::new(r"C:\P\.env"), true).is_none());
        // Mutation still protected.
        assert!(r.check(Path::new(r"C:\P\.env"), false).is_some());
    }
}
