//! Best-effort command classification for raw process/shell execution
//! (plan sections 4 and 47). This is Layer B: it detects explicit paths and
//! known actions so policy can block or prompt, but it cannot observe what an
//! arbitrary program does at run time.

pub mod gh;
pub mod git;
pub mod packages;
pub mod powershell;
pub mod tokenize;

use std::collections::BTreeSet;

use base64::Engine;
use serde::{Deserialize, Serialize};

use self::gh::{GhCommand, GhKind};
use self::git::{GitCommand, GitKind};
use self::packages::{PackageAction, PackageScope};
use self::tokenize::program_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ReadOnly,
    PackageLocal,
    PackageGlobal,
    GitSafe,
    GitDestructive,
    GithubRead,
    GithubWrite,
    CredentialAccess,
    SystemChange,
    Admin,
    Network,
    Dynamic,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefAccess {
    /// Content is read and may be disclosed (printed, copied, uploaded).
    ReadDisclose,
    /// Content/metadata read without disclosure (hashing, listing, existence).
    Read,
    Write,
    Delete,
    /// Referenced by a program whose behaviour is unknown.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRef {
    pub raw: String,
    pub access: RefAccess,
    pub via: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: Category,
    pub program: String,
    pub detail: String,
    pub paths: Vec<PathRef>,
    pub git: Option<GitCommand>,
    pub gh: Option<GhCommand>,
    pub package: Option<PackageAction>,
    /// Text that will appear in an official GitHub action (checked for attribution).
    pub official_texts: Vec<String>,
    pub official_text_files: Vec<String>,
    pub official_refs: Vec<String>,
    pub identity_values: Vec<String>,
}

impl Finding {
    fn new(category: Category, program: &str, detail: impl Into<String>) -> Self {
        Self {
            category,
            program: program.to_string(),
            detail: detail.into(),
            paths: Vec::new(),
            git: None,
            gh: None,
            package: None,
            official_texts: Vec::new(),
            official_text_files: Vec::new(),
            official_refs: Vec::new(),
            identity_values: Vec::new(),
        }
    }
    fn with_paths(mut self, paths: Vec<PathRef>) -> Self {
        self.paths = paths;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    Process,
    Cmd,
    PowerShell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAnalysis {
    pub kind: ShellKind,
    pub findings: Vec<Finding>,
    pub parse_errors: Vec<String>,
}

impl CommandAnalysis {
    pub fn categories(&self) -> BTreeSet<Category> {
        self.findings.iter().map(|f| f.category).collect()
    }
    pub fn all_paths(&self) -> impl Iterator<Item = &PathRef> {
        self.findings.iter().flat_map(|f| f.paths.iter())
    }
    pub fn is_read_only(&self) -> bool {
        self.parse_errors.is_empty()
            && !self.findings.is_empty()
            && self.findings.iter().all(|f| {
                matches!(
                    f.category,
                    Category::ReadOnly | Category::GithubRead | Category::Network
                ) || (f.category == Category::GitSafe
                    && f.git
                        .as_ref()
                        .map(|g| g.kind == GitKind::ReadOnly)
                        .unwrap_or(false))
            })
            && self
                .all_paths()
                .all(|p| matches!(p.access, RefAccess::Read | RefAccess::ReadDisclose))
    }
}

/// Inputs the analyzer needs from its environment.
pub struct Analyzer<'a> {
    pub powershell_exe: &'a str,
    /// Whether a program token resolves (via PATH/cwd) to an executable inside
    /// the trusted workspace, e.g. a project's virtual-environment `pip`.
    pub program_in_trusted: &'a dyn Fn(&str) -> bool,
}

const MAX_DEPTH: usize = 4;

fn looks_like_path(arg: &str) -> bool {
    if arg.is_empty() || arg.contains("://") || arg.starts_with('-') {
        return false;
    }
    let b = arg.as_bytes();
    arg.contains('\\')
        || arg.contains('/')
        || arg.starts_with('.')
        || arg.starts_with('~')
        || arg.starts_with('%')
        || arg.to_ascii_lowercase().starts_with("$env:")
        || arg.starts_with("$HOME")
        || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
}

fn is_switch(arg: &str, cmd_builtin: bool) -> bool {
    arg.starts_with('-')
        || (cmd_builtin && arg.starts_with('/') && arg.len() <= 12 && !arg[1..].contains('/'))
}

fn positional(args: &[String], cmd_builtin: bool) -> Vec<String> {
    args.iter()
        .filter(|a| !is_switch(a, cmd_builtin))
        .cloned()
        .collect()
}

fn refs(values: &[String], access: RefAccess, via: &str) -> Vec<PathRef> {
    values
        .iter()
        .filter(|v| !v.is_empty() && !v.contains("://"))
        .map(|v| PathRef {
            raw: v.clone(),
            access,
            via: via.to_string(),
        })
        .collect()
}

fn path_like_refs(args: &[String], access: RefAccess, via: &str) -> Vec<PathRef> {
    let v: Vec<String> = args
        .iter()
        .filter(|a| looks_like_path(a))
        .cloned()
        .collect();
    refs(&v, access, via)
}

fn flag_values(args: &[String], names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let lower = a.to_ascii_lowercase();
        for n in names {
            if lower == *n {
                if let Some(v) = args.get(i + 1) {
                    out.push(v.clone());
                }
            } else if let Some(v) = lower.strip_prefix(&format!("{n}=")) {
                out.push(a[a.len() - v.len()..].to_string());
            }
        }
    }
    out
}

impl<'a> Analyzer<'a> {
    /// `process.run(executable, args)`
    pub fn analyze_process(&self, executable: &str, args: &[String]) -> CommandAnalysis {
        let mut a = CommandAnalysis {
            kind: ShellKind::Process,
            findings: Vec::new(),
            parse_errors: Vec::new(),
        };
        a.findings = self.classify_program(executable, args, &[], 0, &mut a.parse_errors);
        a
    }

    /// `shell.cmd(command)`
    pub fn analyze_cmd(&self, line: &str) -> CommandAnalysis {
        let mut a = CommandAnalysis {
            kind: ShellKind::Cmd,
            findings: Vec::new(),
            parse_errors: Vec::new(),
        };
        a.findings = self.cmd_findings(line, 0, &mut a.parse_errors);
        a
    }

    /// `shell.powershell(script)`
    pub fn analyze_powershell(&self, script: &str) -> CommandAnalysis {
        let mut a = CommandAnalysis {
            kind: ShellKind::PowerShell,
            findings: Vec::new(),
            parse_errors: Vec::new(),
        };
        a.findings = self.ps_findings(script, 0, &mut a.parse_errors);
        a
    }

    fn cmd_findings(&self, line: &str, depth: usize, errors: &mut Vec<String>) -> Vec<Finding> {
        if depth > MAX_DEPTH {
            return vec![Finding::new(
                Category::Dynamic,
                "cmd",
                "command nesting too deep to analyze",
            )];
        }
        let mut out = Vec::new();
        for seg in tokenize::split_cmd(line) {
            let redirect_refs: Vec<PathRef> = seg
                .redirects
                .iter()
                .filter(|r| !r.target.eq_ignore_ascii_case("nul"))
                .map(|r| PathRef {
                    raw: r.target.clone(),
                    access: if r.input {
                        RefAccess::ReadDisclose
                    } else {
                        RefAccess::Write
                    },
                    via: "redirection".into(),
                })
                .collect();
            let Some(first) = seg.tokens.first() else {
                if !redirect_refs.is_empty() {
                    out.push(
                        Finding::new(Category::Unknown, "cmd", "redirection")
                            .with_paths(redirect_refs),
                    );
                }
                continue;
            };
            let mut tokens = seg.tokens.clone();
            let mut prog = program_name(first);
            // Unwrap `call`, `start`, `if`, `for ... do`.
            loop {
                match prog.as_str() {
                    "call" if tokens.len() > 1 => {
                        tokens.remove(0);
                    }
                    "start" if tokens.len() > 1 => {
                        tokens.remove(0);
                        while let Some(t) = tokens.first() {
                            if t.starts_with('/') || t.is_empty() {
                                let takes = t.eq_ignore_ascii_case("/d");
                                tokens.remove(0);
                                if takes && !tokens.is_empty() {
                                    tokens.remove(0);
                                }
                            } else {
                                break;
                            }
                        }
                        if tokens.len() > 1 && tokens[0].contains(' ') {
                            tokens.remove(0); // window title
                        }
                    }
                    "if" => {
                        tokens.remove(0);
                        if tokens
                            .first()
                            .map(|t| t.eq_ignore_ascii_case("not"))
                            .unwrap_or(false)
                        {
                            tokens.remove(0);
                        }
                        if let Some(t) = tokens.first() {
                            let lt = t.to_ascii_lowercase();
                            if lt == "exist" || lt == "defined" || lt == "errorlevel" {
                                tokens.drain(..2.min(tokens.len()));
                            } else if t.contains("==") {
                                tokens.remove(0);
                            } else if tokens.len() >= 3 {
                                tokens.drain(..3);
                            }
                        }
                        out.push(Finding::new(
                            Category::Dynamic,
                            "if",
                            "conditional execution",
                        ));
                    }
                    "for" => {
                        match tokens.iter().position(|t| t.eq_ignore_ascii_case("do")) {
                            Some(p) => {
                                tokens.drain(..=p);
                            }
                            None => tokens.clear(),
                        }
                        out.push(Finding::new(
                            Category::Dynamic,
                            "for",
                            "loop with variable expansion",
                        ));
                    }
                    _ => break,
                }
                match tokens.first() {
                    Some(t) => prog = program_name(t),
                    None => break,
                }
            }
            if tokens.is_empty() {
                continue;
            }
            let args: Vec<String> = tokens[1..].to_vec();
            let mut f = self.classify_program(&tokens[0], &args, &redirect_refs, depth, errors);
            if tokens[0].contains('%') || tokens[0].contains('!') {
                f.push(Finding::new(
                    Category::Dynamic,
                    &prog,
                    "program name uses variable expansion",
                ));
            }
            out.extend(f);
        }
        out
    }

    fn ps_findings(&self, script: &str, depth: usize, errors: &mut Vec<String>) -> Vec<Finding> {
        if depth > MAX_DEPTH {
            return vec![Finding::new(
                Category::Dynamic,
                "powershell",
                "command nesting too deep to analyze",
            )];
        }
        let ast = match powershell::parse(script, self.powershell_exe) {
            Ok(a) => a,
            Err(e) => {
                errors.push(e);
                return vec![Finding::new(
                    Category::Unknown,
                    "powershell",
                    "script could not be parsed",
                )];
            }
        };
        errors.extend(ast.errors.iter().cloned());
        let mut out = Vec::new();
        for c in &ast.commands {
            let redirect_refs: Vec<PathRef> = c
                .redirects
                .iter()
                .filter(|r| {
                    !r.target.eq_ignore_ascii_case("$null") && !r.target.eq_ignore_ascii_case("nul")
                })
                .map(|r| PathRef {
                    raw: unquote(&r.target),
                    access: RefAccess::Write,
                    via: "redirection".into(),
                })
                .collect();
            if c.is_dynamic_name() {
                let mut f = Finding::new(
                    Category::Dynamic,
                    "&",
                    "invokes a command chosen at run time",
                );
                f.paths = redirect_refs;
                out.push(f);
                continue;
            }
            let name = c.name.clone().unwrap_or_default();
            let args = c.args();
            out.extend(self.classify_ps_command(&name, &args, &redirect_refs, depth, errors));
        }
        for m in &ast.members {
            out.extend(classify_member(m));
        }
        out
    }

    fn classify_ps_command(
        &self,
        name: &str,
        args: &[String],
        redirects: &[PathRef],
        depth: usize,
        errors: &mut Vec<String>,
    ) -> Vec<Finding> {
        let lower = name.to_ascii_lowercase();
        let (named, pos) = split_ps_params(args);
        let get = |keys: &[&str]| -> Vec<String> {
            let mut v: Vec<String> = named
                .iter()
                .filter(|(k, _)| keys.iter().any(|x| x.eq_ignore_ascii_case(k)))
                .map(|(_, v)| v.clone())
                .collect();
            v.retain(|s| !s.is_empty());
            v
        };
        let path_params = [
            "path",
            "literalpath",
            "lp",
            "pspath",
            "filepath",
            "fullname",
        ];
        let paths_or_pos = |keys: &[&str]| -> Vec<String> {
            let v = get(keys);
            if v.is_empty() {
                pos.first().cloned().into_iter().collect()
            } else {
                v
            }
        };
        let with_redirects = |mut f: Finding| {
            f.paths.extend(redirects.iter().cloned());
            vec![f]
        };
        let provider_category = |p: &str| -> Option<Category> {
            let l = p.to_ascii_lowercase();
            if l.starts_with("hklm:")
                || l.starts_with("registry::hkey_local_machine")
                || l.starts_with("hkcr:")
                || l.starts_with("registry::hkey_classes_root")
            {
                Some(Category::Admin)
            } else if l.starts_with("hkcu:") || l.starts_with("registry::hkey_current_user") {
                Some(Category::SystemChange)
            } else if l.starts_with("env:")
                || l.starts_with("variable:")
                || l.starts_with("function:")
                || l.starts_with("alias:")
            {
                Some(Category::ReadOnly)
            } else if l.starts_with("cert:") {
                Some(Category::CredentialAccess)
            } else {
                None
            }
        };
        match lower.as_str() {
            "get-content"
            | "gc"
            | "cat"
            | "type"
            | "import-csv"
            | "import-clixml"
            | "format-hex"
            | "fhx"
            | "get-filehash"
            | "select-string"
            | "sls"
            | "import-powershelldatafile" => {
                let p = paths_or_pos(&path_params);
                let access = if lower == "get-filehash" {
                    RefAccess::Read
                } else {
                    RefAccess::ReadDisclose
                };
                if lower == "select-string" || lower == "sls" {
                    let p = get(&path_params);
                    return with_redirects(
                        Finding::new(Category::ReadOnly, name, "search file content")
                            .with_paths(refs(&p, access, name)),
                    );
                }
                with_redirects(
                    Finding::new(Category::ReadOnly, name, "read file content")
                        .with_paths(refs(&p, access, name)),
                )
            }
            "get-item" | "gi" | "get-childitem" | "gci" | "ls" | "dir" | "test-path"
            | "resolve-path" | "rvpa" | "get-acl" | "get-itemproperty" | "gp" | "split-path"
            | "join-path" | "get-location" | "gl" | "pwd" | "set-location" | "sl" | "cd"
            | "chdir" | "push-location" | "pushd" | "pop-location" | "popd" | "measure-object"
            | "measure" => {
                let p = get(&path_params);
                let p = if p.is_empty()
                    && !matches!(
                        lower.as_str(),
                        "split-path" | "join-path" | "measure-object" | "measure"
                    ) {
                    pos.first().cloned().into_iter().collect()
                } else {
                    p
                };
                if let Some(cat) = p.first().and_then(|x| provider_category(x)) {
                    if cat == Category::CredentialAccess {
                        return with_redirects(Finding::new(
                            Category::ReadOnly,
                            name,
                            "certificate store listing",
                        ));
                    }
                    return with_redirects(Finding::new(Category::ReadOnly, name, "provider read"));
                }
                with_redirects(
                    Finding::new(Category::ReadOnly, name, "inspect items").with_paths(refs(
                        &p,
                        RefAccess::Read,
                        name,
                    )),
                )
            }
            "set-content" | "sc" | "add-content" | "ac" | "out-file" | "clear-content" | "clc"
            | "export-csv" | "epcsv" | "export-clixml" | "set-acl" => {
                let p = paths_or_pos(&path_params);
                with_redirects(
                    Finding::new(Category::Unknown, name, "write file").with_paths(refs(
                        &p,
                        RefAccess::Write,
                        name,
                    )),
                )
            }
            "tee-object" | "tee" => {
                let p = get(&["filepath", "literalpath", "path"]);
                let p = if p.is_empty() { pos.clone() } else { p };
                with_redirects(
                    Finding::new(Category::Unknown, name, "write file").with_paths(refs(
                        &p,
                        RefAccess::Write,
                        name,
                    )),
                )
            }
            "new-item" | "ni" | "md" | "mkdir" => {
                let mut p = get(&["path"]);
                if p.is_empty() {
                    p = pos.first().cloned().into_iter().collect();
                }
                let item_names = get(&["name"]);
                if let (Some(base), Some(n)) = (p.first().cloned(), item_names.first()) {
                    p = vec![format!("{base}\\{n}")];
                } else if p.is_empty() {
                    p = item_names;
                }
                if let Some(cat) = p.first().and_then(|x| provider_category(x)) {
                    return with_redirects(Finding::new(cat, name, "create provider item"));
                }
                let mut f = Finding::new(Category::Unknown, name, "create item").with_paths(refs(
                    &p,
                    RefAccess::Write,
                    name,
                ));
                f.paths
                    .extend(refs(&get(&["value", "target"]), RefAccess::Read, name));
                with_redirects(f)
            }
            "remove-item" | "ri" | "rm" | "rmdir" | "del" | "erase" | "rd" => {
                let p = paths_or_pos(&path_params);
                if let Some(cat) = p.first().and_then(|x| provider_category(x)) {
                    return with_redirects(Finding::new(cat, name, "remove provider item"));
                }
                with_redirects(
                    Finding::new(Category::Unknown, name, "delete items").with_paths(refs(
                        &p,
                        RefAccess::Delete,
                        name,
                    )),
                )
            }
            "copy-item" | "copy" | "cp" | "cpi" => {
                let src = paths_or_pos(&path_params);
                let mut dst = get(&["destination"]);
                if dst.is_empty() && pos.len() >= 2 {
                    dst = vec![pos[1].clone()];
                }
                let mut f = Finding::new(Category::Unknown, name, "copy items").with_paths(refs(
                    &src,
                    RefAccess::ReadDisclose,
                    name,
                ));
                f.paths.extend(refs(&dst, RefAccess::Write, name));
                with_redirects(f)
            }
            "move-item" | "move" | "mv" | "mi" | "rename-item" | "ren" | "rni" => {
                let src = paths_or_pos(&path_params);
                let mut dst = get(&["destination", "newname"]);
                if dst.is_empty() && pos.len() >= 2 {
                    dst = vec![pos[1].clone()];
                }
                if (lower.starts_with("ren") || lower == "rni")
                    && let (Some(s), Some(n)) = (src.first(), dst.first())
                    && !n.contains('\\')
                    && !n.contains('/')
                {
                    let parent = s
                        .rsplit_once(['\\', '/'])
                        .map(|(p, _)| p.to_string())
                        .unwrap_or_default();
                    dst = vec![if parent.is_empty() {
                        n.clone()
                    } else {
                        format!("{parent}\\{n}")
                    }];
                }
                let mut f = Finding::new(Category::Unknown, name, "move items").with_paths(refs(
                    &src,
                    RefAccess::Delete,
                    name,
                ));
                f.paths.extend(refs(&dst, RefAccess::Write, name));
                with_redirects(f)
            }
            "set-item"
            | "si"
            | "new-itemproperty"
            | "set-itemproperty"
            | "sp"
            | "remove-itemproperty"
            | "rp"
            | "clear-itemproperty"
            | "rename-itemproperty" => {
                let p = paths_or_pos(&path_params);
                let cat = p
                    .first()
                    .and_then(|x| provider_category(x))
                    .unwrap_or(Category::SystemChange);
                with_redirects(Finding::new(cat, name, "change provider item/property"))
            }
            "expand-archive" => {
                let src = paths_or_pos(&path_params);
                let dst = get(&["destinationpath"]);
                let mut f = Finding::new(Category::Unknown, name, "extract archive")
                    .with_paths(refs(&src, RefAccess::Read, name));
                f.paths.extend(refs(
                    &if dst.is_empty() {
                        vec![".".into()]
                    } else {
                        dst
                    },
                    RefAccess::Write,
                    name,
                ));
                with_redirects(f)
            }
            "compress-archive" => {
                let src = get(&["path", "literalpath"]);
                let dst = get(&["destinationpath"]);
                let mut f = Finding::new(Category::Unknown, name, "create archive")
                    .with_paths(refs(&src, RefAccess::ReadDisclose, name));
                f.paths.extend(refs(&dst, RefAccess::Write, name));
                with_redirects(f)
            }
            "invoke-webrequest" | "iwr" | "invoke-restmethod" | "irm" | "curl" | "wget"
            | "start-bitstransfer" => {
                let mut f = Finding::new(Category::Network, name, "network request");
                f.paths.extend(refs(
                    &get(&["outfile", "destination"]),
                    RefAccess::Write,
                    name,
                ));
                f.paths.extend(refs(
                    &get(&["infile", "source"])
                        .into_iter()
                        .filter(|s| !s.contains("://"))
                        .collect::<Vec<_>>(),
                    RefAccess::ReadDisclose,
                    name,
                ));
                with_redirects(f)
            }
            "get-storedcredential"
            | "convertfrom-securestring"
            | "export-pfxcertificate"
            | "get-credential"
            | "export-certificate" => with_redirects(Finding::new(
                Category::CredentialAccess,
                name,
                "credential export or prompt",
            )),
            "new-service"
            | "set-service"
            | "remove-service"
            | "start-service"
            | "stop-service"
            | "restart-service"
            | "suspend-service"
            | "resume-service"
            | "install-windowsfeature"
            | "enable-windowsoptionalfeature"
            | "disable-windowsoptionalfeature"
            | "add-windowscapability"
            | "remove-windowscapability"
            | "add-mppreference"
            | "set-mppreference"
            | "remove-mppreference"
            | "new-netfirewallrule"
            | "set-netfirewallrule"
            | "remove-netfirewallrule"
            | "set-netfirewallprofile"
            | "new-localuser"
            | "set-localuser"
            | "remove-localuser"
            | "add-localgroupmember"
            | "remove-localgroupmember"
            | "set-timezone"
            | "set-date"
            | "enable-psremoting"
            | "set-netipaddress"
            | "new-netipaddress"
            | "set-dnsclientserveraddress"
            | "bcdedit" => with_redirects(Finding::new(
                Category::Admin,
                name,
                "administrative system change",
            )),
            "set-executionpolicy" => {
                let scope = get(&["scope"])
                    .first()
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_else(|| "localmachine".into());
                let cat = match scope.as_str() {
                    "process" => Category::ReadOnly,
                    "currentuser" => Category::SystemChange,
                    _ => Category::Admin,
                };
                with_redirects(Finding::new(
                    cat,
                    name,
                    format!("execution policy change ({scope})"),
                ))
            }
            "register-scheduledtask"
            | "unregister-scheduledtask"
            | "set-scheduledtask"
            | "restart-computer"
            | "stop-computer"
            | "register-psrepository"
            | "set-psrepository"
            | "set-itempropertyvalue" => with_redirects(Finding::new(
                Category::SystemChange,
                name,
                "user/system configuration change",
            )),
            "install-module" | "install-package" | "install-script" | "update-module"
            | "update-script" | "uninstall-module" | "install-psresource" | "update-psresource" => {
                let scope = get(&["scope"])
                    .first()
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                let cat = if scope == "allusers" {
                    Category::Admin
                } else {
                    Category::PackageGlobal
                };
                let mut f = Finding::new(cat, name, "PowerShell module install");
                f.package = Some(PackageAction {
                    manager: "powershellget".into(),
                    scope: if cat == Category::Admin {
                        PackageScope::Admin
                    } else {
                        PackageScope::Global
                    },
                    detail: "PowerShell module install into a user/system module path".into(),
                });
                with_redirects(f)
            }
            "invoke-expression" | "iex" | "add-type" | "invoke-command" | "icm" | "start-job"
            | "sajb" | "invoke-item" | "ii" => with_redirects(Finding::new(
                Category::Dynamic,
                name,
                "dynamic code execution",
            )),
            "start-process" | "saps" | "start" => {
                let file = get(&["filepath"])
                    .into_iter()
                    .next()
                    .or_else(|| pos.first().cloned());
                let verb = get(&["verb"]).first().map(|s| s.to_ascii_lowercase());
                if verb.as_deref() == Some("runas") {
                    return with_redirects(Finding::new(
                        Category::Admin,
                        name,
                        "elevated process launch (RunAs)",
                    ));
                }
                let arglist = get(&["argumentlist", "args"]);
                let args: Vec<String> = arglist
                    .iter()
                    .flat_map(|a| tokenize::split_windows_args(&a.replace(['\'', ','], " ")))
                    .collect();
                match file {
                    Some(f) => {
                        let mut r = self.classify_program(&f, &args, redirects, depth + 1, errors);
                        r.push(Finding::new(
                            Category::Dynamic,
                            name,
                            "starts a separate process",
                        ));
                        r
                    }
                    None => {
                        with_redirects(Finding::new(Category::Dynamic, name, "starts a process"))
                    }
                }
            }
            "write-output"
            | "write-host"
            | "echo"
            | "write"
            | "out-host"
            | "out-null"
            | "out-string"
            | "format-table"
            | "ft"
            | "format-list"
            | "fl"
            | "select-object"
            | "select"
            | "where-object"
            | "where"
            | "?"
            | "foreach-object"
            | "foreach"
            | "%"
            | "sort-object"
            | "sort"
            | "group-object"
            | "get-date"
            | "get-process"
            | "gps"
            | "ps"
            | "get-service"
            | "gsv"
            | "get-command"
            | "gcm"
            | "get-help"
            | "get-member"
            | "gm"
            | "convertto-json"
            | "convertfrom-json"
            | "get-variable"
            | "gv"
            | "set-variable"
            | "set"
            | "sv"
            | "new-object"
            | "start-sleep"
            | "sleep"
            | "write-error"
            | "write-warning"
            | "write-verbose"
            | "write-debug"
            | "write-progress"
            | "get-host"
            | "get-culture"
            | "get-uptime"
            | "get-computerinfo"
            | "get-psdrive"
            | "get-module"
            | "import-module"
            | "ipmo"
            | "test-connection"
            | "resolve-dnsname"
            | "get-netipaddress"
            | "get-ciminstance"
            | "get-wmiobject"
            | "compare-object"
            | "get-random"
            | "convertto-csv"
            | "convertfrom-csv"
            | "get-unique"
            | "tee-variable"
            | "clear-host"
            | "cls"
            | "exit"
            | "return"
            | "wait-process"
            | "get-job"
            | "receive-job"
            | "wait-job"
            | "remove-job"
            | "get-alias"
            | "get-psreadlineoption"
            | "get-executionpolicy"
            | "get-winevent"
            | "get-eventlog"
            | "measure-command"
            | "get-hotfix"
            | "stop-process"
            | "kill"
            | "spps" => {
                if lower == "import-module" || lower == "ipmo" {
                    let p = paths_or_pos(&["name"]);
                    return with_redirects(
                        Finding::new(Category::ReadOnly, name, "load module")
                            .with_paths(path_like_refs(&p, RefAccess::Read, name)),
                    );
                }
                with_redirects(Finding::new(
                    Category::ReadOnly,
                    name,
                    "read-only/pipeline cmdlet",
                ))
            }
            _ => {
                // Native program (git, npm, cmd, ...) or an unknown cmdlet/function.
                if lower.contains('-')
                    && !lower.contains('.')
                    && !lower.contains('\\')
                    && !lower.contains('/')
                {
                    let mut f =
                        Finding::new(Category::Unknown, name, "unrecognized cmdlet or function");
                    f.paths = path_like_refs(args, RefAccess::Unknown, name);
                    f.paths.extend(redirects.iter().cloned());
                    return vec![f];
                }
                self.classify_program(name, args, redirects, depth + 1, errors)
            }
        }
    }

    /// Classify a native program invocation (shared by all entry points).
    pub fn classify_program(
        &self,
        program_token: &str,
        args: &[String],
        redirects: &[PathRef],
        depth: usize,
        errors: &mut Vec<String>,
    ) -> Vec<Finding> {
        let prog = program_name(program_token);
        let mut findings = self.classify_program_inner(&prog, program_token, args, depth, errors);
        if !redirects.is_empty() {
            if let Some(f) = findings.first_mut() {
                f.paths.extend(redirects.iter().cloned());
            } else {
                findings.push(
                    Finding::new(Category::Unknown, &prog, "redirection")
                        .with_paths(redirects.to_vec()),
                );
            }
        }
        findings
    }

    fn classify_program_inner(
        &self,
        prog: &str,
        program_token: &str,
        args: &[String],
        depth: usize,
        errors: &mut Vec<String>,
    ) -> Vec<Finding> {
        let lower_args: Vec<String> = args.iter().map(|a| a.to_ascii_lowercase()).collect();
        let has = |f: &str| lower_args.iter().any(|a| a == f);
        let pos_cmd = positional(args, true);
        let pos_unix = positional(args, false);
        let one = |f: Finding| vec![f];
        match prog {
            "cmd" => {
                let idx = lower_args
                    .iter()
                    .position(|a| a == "/c" || a == "/k" || a == "/r");
                match idx {
                    Some(i) => self.cmd_findings(&args[i + 1..].join(" "), depth + 1, errors),
                    None => one(Finding::new(
                        Category::Dynamic,
                        prog,
                        "interactive command interpreter",
                    )),
                }
            }
            "powershell" | "pwsh" => {
                let mut i = 0;
                while i < args.len() {
                    let a = lower_args[i].trim_start_matches('/').to_string();
                    let a = a.trim_start_matches('-');
                    if ["encodedcommand", "enc", "e", "ec", "en", "encoded"].contains(&a)
                        && let Some(b64) = args.get(i + 1)
                    {
                        match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                            Ok(bytes) => {
                                let units: Vec<u16> = bytes
                                    .as_chunks::<2>()
                                    .0
                                    .iter()
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                let script = String::from_utf16_lossy(&units);
                                let mut f = self.ps_findings(&script, depth + 1, errors);
                                f.push(Finding::new(
                                    Category::Dynamic,
                                    prog,
                                    "encoded command (decoded and analyzed)",
                                ));
                                return f;
                            }
                            Err(_) => {
                                return one(Finding::new(
                                    Category::Dynamic,
                                    prog,
                                    "undecodable encoded command",
                                ));
                            }
                        }
                    }
                    if ["command", "c"].contains(&a) {
                        let script = args[i + 1..].join(" ");
                        if script.trim() == "-" {
                            return one(Finding::new(
                                Category::Dynamic,
                                prog,
                                "script from standard input",
                            ));
                        }
                        return self.ps_findings(&script, depth + 1, errors);
                    }
                    if ["file", "f"].contains(&a) {
                        let f = args.get(i + 1).cloned().unwrap_or_default();
                        return one(Finding::new(Category::Unknown, prog, "runs a script file")
                            .with_paths(refs(&[f], RefAccess::Read, prog)));
                    }
                    i += 1;
                }
                if let Some(first) = pos_unix.first() {
                    return self
                        .ps_findings(&pos_unix.join(" "), depth + 1, errors)
                        .into_iter()
                        .chain(std::iter::once(Finding::new(
                            Category::Unknown,
                            prog,
                            format!("argument {first}"),
                        )))
                        .collect();
                }
                one(Finding::new(Category::Dynamic, prog, "interactive shell"))
            }
            "git" => {
                let g = git::parse(args);
                let category = match &g.kind {
                    GitKind::ResetHard | GitKind::Clean | GitKind::HistoryRewrite => {
                        Category::GitDestructive
                    }
                    GitKind::CredentialAccess => Category::CredentialAccess,
                    GitKind::IdentityChange | GitKind::GlobalConfigChange => Category::SystemChange,
                    GitKind::Unknown => Category::Unknown,
                    _ => Category::GitSafe,
                };
                let mut f = Finding::new(category, "git", format!("git {}", g.subcommand));
                f.paths = refs(&g.output_paths, RefAccess::Write, "git");
                f.official_texts = g.messages.clone();
                f.official_text_files = g.message_files.clone();
                f.official_refs = g.created_refs.clone();
                f.identity_values = g.identity_overrides.clone();
                f.git = Some(g);
                one(f)
            }
            "gh" => {
                let g = gh::parse(args);
                let category = match g.kind {
                    GhKind::Read => Category::GithubRead,
                    GhKind::Write | GhKind::DestructiveWrite => Category::GithubWrite,
                    GhKind::CredentialAccess => Category::CredentialAccess,
                    GhKind::CredentialChange => Category::SystemChange,
                    GhKind::Unknown => Category::Unknown,
                };
                let mut f = Finding::new(category, "gh", format!("gh {} {}", g.group, g.action));
                f.official_texts = g.texts.clone();
                f.official_text_files = g.text_files.clone();
                f.official_refs = g.created_refs.clone();
                f.paths = refs(&g.text_files, RefAccess::Read, "gh");
                f.gh = Some(g);
                one(f)
            }
            "type" | "more" | "cat" | "less" | "head" | "tail" | "strings" | "xxd" | "od"
            | "base64" | "hexdump" | "nl" | "tac" => {
                one(
                    Finding::new(Category::ReadOnly, prog, "print file content").with_paths(refs(
                        &pos_unix_or_cmd(prog, &pos_cmd, &pos_unix),
                        RefAccess::ReadDisclose,
                        prog,
                    )),
                )
            }
            "findstr" | "find" | "grep" | "rg" | "egrep" | "fgrep" | "ag" => {
                let files: Vec<String> = pos_unix_or_cmd(prog, &pos_cmd, &pos_unix)
                    .into_iter()
                    .skip(1)
                    .collect();
                one(
                    Finding::new(Category::ReadOnly, prog, "search file content").with_paths(refs(
                        &files,
                        RefAccess::ReadDisclose,
                        prog,
                    )),
                )
            }
            "certutil" => {
                if has("-encode")
                    || has("-decode")
                    || has("-dump")
                    || has("-encodehex")
                    || has("-decodehex")
                {
                    let files = pos_cmd.clone();
                    let mut f =
                        Finding::new(Category::ReadOnly, prog, "encode/decode file").with_paths(
                            refs(&files[..1.min(files.len())], RefAccess::ReadDisclose, prog),
                        );
                    f.paths.extend(refs(
                        &files.iter().skip(1).cloned().collect::<Vec<_>>(),
                        RefAccess::Write,
                        prog,
                    ));
                    one(f)
                } else if has("-exportpfx") || has("-exportsst") {
                    one(Finding::new(
                        Category::CredentialAccess,
                        prog,
                        "certificate export",
                    ))
                } else if has("-urlcache") {
                    one(Finding::new(Category::Network, prog, "download")
                        .with_paths(path_like_refs(args, RefAccess::Write, prog)))
                } else {
                    one(Finding::new(Category::Unknown, prog, "certutil")
                        .with_paths(path_like_refs(args, RefAccess::Unknown, prog)))
                }
            }
            "dir" | "ls" | "tree" | "where" | "echo" | "cd" | "chdir" | "ver" | "vol"
            | "hostname" | "whoami" | "systeminfo" | "tasklist" | "ipconfig" | "ping"
            | "nslookup" | "tracert" | "netstat" | "wc" | "diff" | "fc" | "comp" | "sort"
            | "uniq" | "cls" | "title" | "pause" | "timeout" | "exit" | "rem" | "pushd"
            | "popd" | "which" | "stat" | "file" | "du" | "df" | "pwd" | "true" | "false"
            | "date" | "whereis" | "chcp" | "getmac" | "arp" | "route" | "query" | "qprocess"
            | "driverquery" | "set" | "path" | "assoc" | "ftype" => {
                let access = if matches!(prog, "diff" | "fc" | "comp" | "sort" | "uniq" | "wc") {
                    RefAccess::ReadDisclose
                } else {
                    RefAccess::Read
                };
                let paths = if matches!(prog, "echo" | "set" | "rem" | "title") {
                    Vec::new()
                } else {
                    path_like_refs(&pos_unix_or_cmd(prog, &pos_cmd, &pos_unix), access, prog)
                };
                if prog == "route" && lower_args.first().map(|a| a != "print").unwrap_or(false) {
                    return one(Finding::new(Category::Admin, prog, "routing table change"));
                }
                if prog == "set" && args.iter().any(|a| a.contains('=')) {
                    return one(Finding::new(
                        Category::ReadOnly,
                        prog,
                        "set process environment variable",
                    ));
                }
                one(Finding::new(Category::ReadOnly, prog, "read-only command").with_paths(paths))
            }
            "del" | "erase" | "rd" | "rmdir" | "rm" | "unlink" | "shred" => {
                one(
                    Finding::new(Category::Unknown, prog, "delete").with_paths(refs(
                        &pos_unix_or_cmd(prog, &pos_cmd, &pos_unix),
                        RefAccess::Delete,
                        prog,
                    )),
                )
            }
            "copy" | "xcopy" | "robocopy" | "cp" | "scp" | "rsync" => {
                let p = pos_unix_or_cmd(prog, &pos_cmd, &pos_unix);
                let (src, dst) = split_last(&p);
                let mut f = Finding::new(
                    if matches!(prog, "scp" | "rsync") {
                        Category::Network
                    } else {
                        Category::Unknown
                    },
                    prog,
                    "copy",
                );
                let local_src: Vec<String> =
                    src.into_iter().filter(|s| !is_remote_spec(s)).collect();
                f.paths = refs(&local_src, RefAccess::ReadDisclose, prog);
                if let Some(d) = dst.filter(|d| !is_remote_spec(d)) {
                    f.paths.extend(refs(&[d], RefAccess::Write, prog));
                }
                one(f)
            }
            "move" | "ren" | "rename" | "mv" => {
                let p = pos_unix_or_cmd(prog, &pos_cmd, &pos_unix);
                let (src, dst) = split_last(&p);
                let mut f = Finding::new(Category::Unknown, prog, "move/rename").with_paths(refs(
                    &src,
                    RefAccess::Delete,
                    prog,
                ));
                if let Some(mut d) = dst {
                    if (prog == "ren" || prog == "rename")
                        && !d.contains('\\')
                        && let Some(s) = src.first()
                        && let Some((parent, _)) = s.rsplit_once(['\\', '/'])
                    {
                        d = format!("{parent}\\{d}");
                    }
                    f.paths.extend(refs(&[d], RefAccess::Write, prog));
                }
                one(f)
            }
            "md" | "mkdir" | "touch" | "attrib" | "icacls" | "cacls" | "takeown" | "chmod"
            | "chown" | "compact" | "tee" => {
                one(
                    Finding::new(Category::Unknown, prog, "create/modify").with_paths(refs(
                        &pos_unix_or_cmd(prog, &pos_cmd, &pos_unix),
                        RefAccess::Write,
                        prog,
                    )),
                )
            }
            "mklink" => {
                let p = pos_cmd.clone();
                let mut f = Finding::new(Category::Unknown, prog, "create link").with_paths(refs(
                    &p[..1.min(p.len())],
                    RefAccess::Write,
                    prog,
                ));
                f.paths.extend(refs(
                    &p.iter().skip(1).cloned().collect::<Vec<_>>(),
                    RefAccess::Read,
                    prog,
                ));
                one(f)
            }
            "sed" | "perl" => {
                if lower_args.iter().any(|a| {
                    a == "-i"
                        || (a.starts_with("-i") && a.len() <= 6)
                        || a.starts_with("--in-place")
                }) {
                    let files: Vec<String> = pos_unix.iter().skip(1).cloned().collect();
                    one(
                        Finding::new(Category::Unknown, prog, "in-place edit").with_paths(refs(
                            &files,
                            RefAccess::Write,
                            prog,
                        )),
                    )
                } else if prog == "perl" && (has("-e") || has("-E")) {
                    one(Finding::new(Category::Dynamic, prog, "inline script"))
                } else {
                    let files: Vec<String> = pos_unix.iter().skip(1).cloned().collect();
                    one(
                        Finding::new(Category::ReadOnly, prog, "stream edit").with_paths(refs(
                            &files,
                            RefAccess::ReadDisclose,
                            prog,
                        )),
                    )
                }
            }
            "curl" | "wget" => {
                let mut f = Finding::new(Category::Network, prog, "network request");
                f.paths = refs(
                    &flag_values(
                        args,
                        &[
                            "-o",
                            "--output",
                            "-O",
                            "--output-document",
                            "-P",
                            "--directory-prefix",
                        ],
                    )
                    .into_iter()
                    .filter(|v| v != "-")
                    .collect::<Vec<_>>(),
                    RefAccess::Write,
                    prog,
                );
                let uploads: Vec<String> = flag_values(args, &["-t", "--upload-file"])
                    .into_iter()
                    .chain(
                        flag_values(
                            args,
                            &[
                                "-d",
                                "--data",
                                "--data-binary",
                                "--data-raw",
                                "--data-urlencode",
                                "-f",
                                "--form",
                            ],
                        )
                        .into_iter()
                        .filter_map(|v| {
                            v.split_once('@')
                                .map(|(_, p)| p.split(';').next().unwrap_or("").to_string())
                        }),
                    )
                    .collect();
                f.paths
                    .extend(refs(&uploads, RefAccess::ReadDisclose, prog));
                one(f)
            }
            "ssh" | "sftp" | "ftp" | "telnet" | "nc" | "ncat" => {
                one(Finding::new(Category::Network, prog, "remote connection"))
            }
            "tar" | "7z" | "zip" | "unzip" | "expand" | "gzip" | "gunzip" | "bzip2" | "xz"
            | "extrac32" | "makecab" => {
                one(Finding::new(Category::Unknown, prog, "archive operation")
                    .with_paths(path_like_refs(args, RefAccess::Unknown, prog)))
            }
            "reg" => {
                let sub = lower_args.first().cloned().unwrap_or_default();
                let key = lower_args.get(1).cloned().unwrap_or_default();
                let machine = key.starts_with("hklm")
                    || key.starts_with("hkey_local_machine")
                    || key.starts_with("hkcr")
                    || key.starts_with("hkey_classes_root")
                    || key.starts_with("hku")
                    || key.starts_with("hkey_users")
                    || key.starts_with("hkcc");
                match sub.as_str() {
                    "query" | "compare" => {
                        one(Finding::new(Category::ReadOnly, prog, "registry query"))
                    }
                    "save" | "export" => {
                        let hive_secret = ["\\sam", "\\security", "\\system"]
                            .iter()
                            .any(|h| key.ends_with(h));
                        if hive_secret {
                            one(Finding::new(
                                Category::CredentialAccess,
                                prog,
                                "registry hive export",
                            ))
                        } else {
                            one(Finding::new(Category::ReadOnly, prog, "registry export")
                                .with_paths(refs(
                                    &pos_cmd.iter().skip(2).take(1).cloned().collect::<Vec<_>>(),
                                    RefAccess::Write,
                                    prog,
                                )))
                        }
                    }
                    _ => one(Finding::new(
                        if machine {
                            Category::Admin
                        } else {
                            Category::SystemChange
                        },
                        prog,
                        format!("registry {sub}"),
                    )),
                }
            }
            "sc" => {
                let sub = lower_args
                    .iter()
                    .find(|a| !a.starts_with("\\\\"))
                    .cloned()
                    .unwrap_or_default();
                if matches!(
                    sub.as_str(),
                    "query"
                        | "queryex"
                        | "qc"
                        | "qdescription"
                        | "qfailure"
                        | "sdshow"
                        | "getdisplayname"
                        | "getkeyname"
                        | "enumdepend"
                ) {
                    one(Finding::new(Category::ReadOnly, prog, "service query"))
                } else {
                    one(Finding::new(
                        Category::Admin,
                        prog,
                        format!("service {sub}"),
                    ))
                }
            }
            "net" | "net1" => {
                let sub = lower_args.first().cloned().unwrap_or_default();
                let modifies = lower_args.iter().any(|a| {
                    a == "/add"
                        || a == "/delete"
                        || a.starts_with("/active")
                        || a.starts_with("/passwordreq")
                });
                match sub.as_str() {
                    "start" | "stop" | "pause" | "continue" if lower_args.len() > 1 => one(
                        Finding::new(Category::Admin, prog, format!("service {sub}")),
                    ),
                    "user" | "localgroup" | "group" | "accounts" | "share"
                        if modifies || (sub == "user" && lower_args.len() > 2) =>
                    {
                        one(Finding::new(
                            Category::Admin,
                            prog,
                            format!("net {sub} change"),
                        ))
                    }
                    "use" if lower_args.len() > 1 => one(Finding::new(
                        Category::SystemChange,
                        prog,
                        "network drive mapping",
                    )),
                    _ => one(Finding::new(Category::ReadOnly, prog, format!("net {sub}"))),
                }
            }
            "netsh" => {
                if lower_args.iter().any(|a| a == "show" || a == "dump")
                    && !lower_args
                        .iter()
                        .any(|a| a == "set" || a == "add" || a == "delete" || a == "reset")
                {
                    one(Finding::new(
                        Category::ReadOnly,
                        prog,
                        "network configuration query",
                    ))
                } else {
                    one(Finding::new(
                        Category::Admin,
                        prog,
                        "network/firewall configuration change",
                    ))
                }
            }
            "bcdedit" | "diskpart" | "format" | "dism" | "sfc" | "vssadmin" | "fsutil"
            | "bootrec" | "manage-bde" | "pnputil" | "runas" | "wusa" | "msiexec" | "bcdboot"
            | "auditpol" | "secedit" | "gpupdate" | "lodctr" | "dcomcnfg" => one(Finding::new(
                Category::Admin,
                prog,
                "administrative system tool",
            )),
            "chkdsk" | "cipher" | "wevtutil" => {
                if lower_args.iter().any(|a| {
                    a.starts_with("/f")
                        || a.starts_with("/r")
                        || a.starts_with("/w")
                        || a == "cl"
                        || a == "clear-log"
                }) {
                    one(Finding::new(
                        Category::Admin,
                        prog,
                        "administrative disk/log operation",
                    ))
                } else {
                    one(Finding::new(Category::ReadOnly, prog, "system query"))
                }
            }
            "shutdown" | "logoff" | "restart-computer" => one(Finding::new(
                Category::SystemChange,
                prog,
                "shutdown/logoff",
            )),
            "schtasks" => {
                if lower_args.iter().any(|a| a == "/query") {
                    one(Finding::new(
                        Category::ReadOnly,
                        prog,
                        "scheduled task query",
                    ))
                } else if lower_args
                    .windows(2)
                    .any(|w| w[0] == "/ru" && (w[1] == "system" || w[1].contains("administrator")))
                {
                    one(Finding::new(
                        Category::Admin,
                        prog,
                        "scheduled task as SYSTEM",
                    ))
                } else {
                    one(Finding::new(
                        Category::SystemChange,
                        prog,
                        "scheduled task change",
                    ))
                }
            }
            "setx" => {
                if has("/m") {
                    one(Finding::new(
                        Category::Admin,
                        prog,
                        "machine environment variable change",
                    ))
                } else {
                    one(Finding::new(
                        Category::SystemChange,
                        prog,
                        "user environment variable change",
                    ))
                }
            }
            "wmic" => {
                if lower_args
                    .iter()
                    .any(|a| a == "call" || a == "create" || a == "delete" || a == "set")
                {
                    one(Finding::new(
                        Category::Admin,
                        prog,
                        "WMI change or process creation",
                    ))
                } else {
                    one(Finding::new(Category::ReadOnly, prog, "WMI query"))
                }
            }
            "cmdkey" => {
                if has("/list") || lower_args.iter().any(|a| a.starts_with("/list:")) {
                    one(Finding::new(
                        Category::ReadOnly,
                        prog,
                        "list credential targets (no secrets)",
                    ))
                } else {
                    one(Finding::new(
                        Category::SystemChange,
                        prog,
                        "credential store change",
                    ))
                }
            }
            "vaultcmd" => {
                if lower_args
                    .iter()
                    .any(|a| a.starts_with("/listcreds") || a.starts_with("/listproperties"))
                {
                    one(Finding::new(
                        Category::CredentialAccess,
                        prog,
                        "credential vault listing",
                    ))
                } else {
                    one(Finding::new(
                        Category::SystemChange,
                        prog,
                        "credential vault change",
                    ))
                }
            }
            "rundll32" => {
                if lower_args.iter().any(|a| {
                    a.contains("keymgr") || a.contains("comsvcs") || a.contains("minidump")
                }) {
                    one(Finding::new(
                        Category::CredentialAccess,
                        prog,
                        "credential manager or memory dump",
                    ))
                } else {
                    one(Finding::new(
                        Category::Dynamic,
                        prog,
                        "rundll32 entry point",
                    ))
                }
            }
            "mimikatz" | "pypykatz" | "lazagne" | "secretsdump" | "ntdsutil" | "gsecdump"
            | "pwdump" | "wce" => one(Finding::new(
                Category::CredentialAccess,
                prog,
                "credential dumping tool",
            )),
            "procdump" | "procdump64" => {
                if lower_args.iter().any(|a| a.contains("lsass")) {
                    one(Finding::new(
                        Category::CredentialAccess,
                        prog,
                        "LSASS memory dump",
                    ))
                } else {
                    one(Finding::new(Category::Unknown, prog, "process dump")
                        .with_paths(path_like_refs(args, RefAccess::Write, prog)))
                }
            }
            "git-credential-manager"
            | "git-credential-manager-core"
            | "git-credential-wincred"
            | "git-credential-store" => one(Finding::new(
                Category::CredentialAccess,
                prog,
                "git credential helper",
            )),
            "bash" | "sh" | "zsh" | "wsl" | "node" | "deno" | "python" | "python3" | "py"
            | "ruby" | "php" | "lua" | "osascript" | "mshta" | "cscript" | "wscript" | "java"
            | "dotnet-script" => {
                if matches!(prog, "python" | "python3" | "py")
                    && let Some(p) =
                        packages::classify(prog, args, (self.program_in_trusted)(program_token))
                {
                    return one(package_finding(prog, p));
                }
                let inline = lower_args.iter().any(|a| {
                    matches!(
                        a.as_str(),
                        "-c" | "-e" | "--eval" | "-p" | "--print" | "-command"
                    )
                });
                let mut f = Finding::new(
                    if inline || matches!(prog, "mshta" | "wsl") {
                        Category::Dynamic
                    } else {
                        Category::Unknown
                    },
                    prog,
                    if inline {
                        "inline code"
                    } else {
                        "script interpreter"
                    },
                );
                f.paths = path_like_refs(args, RefAccess::Unknown, prog);
                one(f)
            }
            _ => {
                if let Some(p) =
                    packages::classify(prog, args, (self.program_in_trusted)(program_token))
                {
                    let mut f = package_finding(prog, p);
                    let target: Vec<String> = flag_values(
                        args,
                        &[
                            "--target",
                            "-t",
                            "--prefix",
                            "--root",
                            "--install-dir",
                            "--tool-path",
                        ],
                    );
                    f.paths.extend(refs(&target, RefAccess::Write, prog));
                    return one(f);
                }
                let mut f = Finding::new(Category::Unknown, prog, "unrecognized program");
                f.paths = path_like_refs(args, RefAccess::Unknown, prog);
                one(f)
            }
        }
    }
}

fn package_finding(prog: &str, p: PackageAction) -> Finding {
    let category = match p.scope {
        PackageScope::Local => Category::PackageLocal,
        PackageScope::Global => Category::PackageGlobal,
        PackageScope::Admin => Category::Admin,
        PackageScope::NotInstall => Category::Unknown,
    };
    let mut f = Finding::new(category, prog, p.detail.clone());
    f.package = Some(p);
    f
}

fn pos_unix_or_cmd(prog: &str, pos_cmd: &[String], pos_unix: &[String]) -> Vec<String> {
    let cmd_builtins = [
        "type", "more", "del", "erase", "rd", "rmdir", "copy", "xcopy", "robocopy", "move", "ren",
        "rename", "md", "mkdir", "dir", "tree", "attrib", "icacls", "cacls", "takeown", "find",
        "findstr", "fc", "comp", "where", "compact", "vol", "cd", "chdir", "pushd",
    ];
    if cmd_builtins.contains(&prog) {
        pos_cmd.to_vec()
    } else {
        pos_unix.to_vec()
    }
}

fn split_last(p: &[String]) -> (Vec<String>, Option<String>) {
    match p.split_last() {
        Some((last, rest)) if !rest.is_empty() => (rest.to_vec(), Some(last.clone())),
        Some((last, _)) => (vec![last.clone()], None),
        None => (Vec::new(), None),
    }
}

fn is_remote_spec(s: &str) -> bool {
    // user@host:path or host:path (but not C:\...)
    let b = s.as_bytes();
    let drive = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
    !drive && s.contains(':') && !s.contains('\\')
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Split PowerShell command arguments into named parameters and positionals.
fn split_ps_params(args: &[String]) -> (Vec<(String, String)>, Vec<String>) {
    let mut named = Vec::new();
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(p) = a.strip_prefix('-')
            && !p.is_empty()
            && p.chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
        {
            if let Some((k, v)) = p.split_once(':') {
                named.push((k.to_ascii_lowercase(), unquote(v)));
            } else {
                let key = p.to_ascii_lowercase();
                let is_switch_param = matches!(
                    key.as_str(),
                    "recurse"
                        | "force"
                        | "whatif"
                        | "confirm"
                        | "append"
                        | "nonewline"
                        | "passthru"
                        | "raw"
                        | "wait"
                        | "nonewwindow"
                        | "usebasicparsing"
                        | "noclobber"
                        | "asjob"
                        | "hidden"
                        | "file"
                        | "directory"
                );
                if !is_switch_param && i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    named.push((key, unquote(&args[i + 1])));
                    i += 1;
                } else {
                    named.push((key, String::new()));
                }
            }
        } else {
            pos.push(unquote(a));
        }
        i += 1;
    }
    (named, pos)
}

fn classify_member(m: &powershell::PsMember) -> Vec<Finding> {
    let target = m.target.to_ascii_lowercase().replace(' ', "");
    let member = m.member.to_ascii_lowercase();
    let literals: Vec<String> = extract_literals(&m.text);
    let f = |cat: Category, detail: &str, access: Option<RefAccess>| {
        let mut f = Finding::new(
            cat,
            "[.NET]",
            format!("{}::{} {detail}", m.target, m.member),
        );
        if let Some(a) = access {
            f.paths = refs(
                &literals.iter().take(1).cloned().collect::<Vec<_>>(),
                a,
                "[.NET]",
            );
        }
        vec![f]
    };
    let io_file = target.ends_with("io.file]") || target.ends_with("io.directory]");
    if target.contains("scriptblock]") && member == "create" {
        return f(Category::Dynamic, "creates a script block", None);
    }
    if target.ends_with("environment]") && member == "setenvironmentvariable" {
        let scope = literals
            .get(2)
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| m.text.to_ascii_lowercase());
        return if scope.contains("machine") {
            f(Category::Admin, "machine environment change", None)
        } else if scope.contains("user") {
            f(Category::SystemChange, "user environment change", None)
        } else {
            f(Category::ReadOnly, "process environment change", None)
        };
    }
    if target.contains("registry") {
        return f(Category::SystemChange, "registry access", None);
    }
    if io_file {
        if member.starts_with("read") || member == "openread" || member == "opentext" {
            return f(
                Category::ReadOnly,
                "file read",
                Some(RefAccess::ReadDisclose),
            );
        }
        if member == "exists" || member.starts_with("get") || member.starts_with("enumerate") {
            return f(Category::ReadOnly, "file query", Some(RefAccess::Read));
        }
        if member == "delete" {
            return f(Category::Unknown, "delete", Some(RefAccess::Delete));
        }
        if member == "copy" {
            let mut out = Finding::new(Category::Unknown, "[.NET]", "copy");
            out.paths = refs(
                &literals.iter().take(1).cloned().collect::<Vec<_>>(),
                RefAccess::ReadDisclose,
                "[.NET]",
            );
            out.paths.extend(refs(
                &literals.iter().skip(1).take(1).cloned().collect::<Vec<_>>(),
                RefAccess::Write,
                "[.NET]",
            ));
            return vec![out];
        }
        if member == "move" || member == "replace" {
            let mut out = Finding::new(Category::Unknown, "[.NET]", "move");
            out.paths = refs(
                &literals.iter().take(1).cloned().collect::<Vec<_>>(),
                RefAccess::Delete,
                "[.NET]",
            );
            out.paths.extend(refs(
                &literals.iter().skip(1).take(1).cloned().collect::<Vec<_>>(),
                RefAccess::Write,
                "[.NET]",
            ));
            return vec![out];
        }
        return f(Category::Unknown, "file write", Some(RefAccess::Write));
    }
    if member == "downloadfile" || member == "downloadfileasync" {
        let mut out = Finding::new(Category::Network, "[.NET]", "download to file");
        out.paths = refs(
            &literals.iter().skip(1).take(1).cloned().collect::<Vec<_>>(),
            RefAccess::Write,
            "[.NET]",
        );
        return vec![out];
    }
    if [
        "uploadfile",
        "uploaddata",
        "uploadstring",
        "sendasync",
        "getasync",
        "postasync",
        "downloadstring",
        "downloaddata",
        "openread",
    ]
    .contains(&member.as_str())
    {
        return f(Category::Network, "network I/O", None);
    }
    if [
        "invoke",
        "invokescript",
        "start",
        "loadfrom",
        "load",
        "loadfile",
        "createinstance",
    ]
    .contains(&member.as_str())
    {
        return f(Category::Dynamic, "dynamic invocation", None);
    }
    if [
        "writealltext",
        "writeallbytes",
        "writealllines",
        "appendalltext",
        "save",
        "create",
        "createdirectory",
    ]
    .contains(&member.as_str())
    {
        return f(Category::Unknown, "write", Some(RefAccess::Write));
    }
    Vec::new()
}

fn extract_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let q = chars[i];
        if q == '\'' || q == '"' {
            let mut j = i + 1;
            let mut s = String::new();
            while j < chars.len() && chars[j] != q {
                s.push(chars[j]);
                j += 1;
            }
            out.push(s);
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer() -> Analyzer<'static> {
        static F: fn(&str) -> bool = |p: &str| p.contains(".venv");
        Analyzer {
            powershell_exe: "powershell.exe",
            program_in_trusted: &F,
        }
    }

    fn paths(a: &CommandAnalysis, access: RefAccess) -> Vec<String> {
        a.all_paths()
            .filter(|p| p.access == access)
            .map(|p| p.raw.clone())
            .collect()
    }

    #[test]
    fn cmd_write_and_delete_detection() {
        let a = analyzer().analyze_cmd(r#"echo x > C:\Windows\x.txt & del /q "C:\Users\Alice\file.txt" && copy src.txt D:\out\"#);
        assert!(paths(&a, RefAccess::Write).contains(&r"C:\Windows\x.txt".to_string()));
        assert!(paths(&a, RefAccess::Delete).contains(&r"C:\Users\Alice\file.txt".to_string()));
        assert!(paths(&a, RefAccess::Write).contains(&r"D:\out\".to_string()));
        assert!(paths(&a, RefAccess::ReadDisclose).contains(&"src.txt".to_string()));
    }

    #[test]
    fn credential_commands() {
        let a = analyzer().analyze_process("gh", &["auth".into(), "token".into()]);
        assert!(a.categories().contains(&Category::CredentialAccess));
        let a = analyzer().analyze_cmd("git credential fill");
        assert!(a.categories().contains(&Category::CredentialAccess));
        let a = analyzer().analyze_cmd(r"reg save HKLM\SAM C:\x\sam");
        assert!(a.categories().contains(&Category::CredentialAccess));
        let a = analyzer().analyze_cmd(r"type %USERPROFILE%\.ssh\id_rsa");
        assert_eq!(
            paths(&a, RefAccess::ReadDisclose),
            vec![r"%USERPROFILE%\.ssh\id_rsa".to_string()]
        );
    }

    #[test]
    fn admin_and_system_changes() {
        assert!(
            analyzer()
                .analyze_cmd("sc stop Spooler")
                .categories()
                .contains(&Category::Admin)
        );
        assert!(
            analyzer()
                .analyze_cmd("sc query Spooler")
                .categories()
                .contains(&Category::ReadOnly)
        );
        assert!(
            analyzer()
                .analyze_cmd("setx FOO bar")
                .categories()
                .contains(&Category::SystemChange)
        );
        assert!(
            analyzer()
                .analyze_cmd(r"reg add HKLM\Software\X /v a /d b")
                .categories()
                .contains(&Category::Admin)
        );
        assert!(
            analyzer()
                .analyze_cmd("netsh advfirewall set allprofiles state off")
                .categories()
                .contains(&Category::Admin)
        );
    }

    #[test]
    fn packages() {
        assert!(
            analyzer()
                .analyze_cmd("npm install")
                .categories()
                .contains(&Category::PackageLocal)
        );
        assert!(
            analyzer()
                .analyze_cmd("npm i -g rimraf")
                .categories()
                .contains(&Category::PackageGlobal)
        );
        assert!(
            analyzer()
                .analyze_cmd("winget install Git.Git")
                .categories()
                .contains(&Category::PackageGlobal)
        );
        assert!(
            analyzer()
                .analyze_process(r".venv\Scripts\pip.exe", &["install".into(), "x".into()])
                .categories()
                .contains(&Category::PackageLocal)
        );
    }

    #[test]
    fn nested_shells_are_analyzed() {
        let a = analyzer().analyze_cmd(r#"cmd /c "del C:\Windows\temp\x.txt""#);
        assert!(
            paths(&a, RefAccess::Delete).contains(&r"C:\Windows\temp\x.txt".to_string()),
            "{a:?}"
        );
    }

    #[test]
    fn read_only_detection() {
        assert!(analyzer().analyze_cmd("dir").is_read_only());
        assert!(analyzer().analyze_cmd("git status").is_read_only());
        assert!(!analyzer().analyze_cmd("git commit -m x").is_read_only());
        assert!(!analyzer().analyze_cmd("cargo build").is_read_only());
    }

    #[test]
    fn powershell_classification() {
        let a = analyzer().analyze_powershell(
            r#"Set-Content -Path C:\outside\x.txt -Value hi
Remove-Item -Recurse -Force .\build
Copy-Item $env:USERPROFILE\.ssh\id_rsa .\key
Get-Content .\README.md
Start-Process powershell -Verb RunAs
[IO.File]::WriteAllText('C:\z\y.txt', 'x')
Invoke-Expression $s
git push --force origin main"#,
        );
        assert!(
            paths(&a, RefAccess::Write).contains(&r"C:\outside\x.txt".to_string()),
            "{a:#?}"
        );
        assert!(paths(&a, RefAccess::Delete).contains(&r".\build".to_string()));
        assert!(
            paths(&a, RefAccess::ReadDisclose)
                .iter()
                .any(|p| p.contains(".ssh"))
        );
        assert!(paths(&a, RefAccess::Write).contains(&r"C:\z\y.txt".to_string()));
        let cats = a.categories();
        assert!(cats.contains(&Category::Admin));
        assert!(cats.contains(&Category::Dynamic));
        let push = a.findings.iter().find(|f| f.program == "git").unwrap();
        assert!(matches!(push.git.as_ref().unwrap().kind, GitKind::Push(ref s) if s.force));
    }

    #[test]
    fn encoded_powershell_is_decoded() {
        let script = "Remove-Item C:\\Windows\\x.txt";
        let bytes: Vec<u8> = script
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let a = analyzer().analyze_process("powershell.exe", &["-EncodedCommand".into(), b64]);
        assert!(
            paths(&a, RefAccess::Delete).contains(&r"C:\Windows\x.txt".to_string()),
            "{a:#?}"
        );
    }
}
