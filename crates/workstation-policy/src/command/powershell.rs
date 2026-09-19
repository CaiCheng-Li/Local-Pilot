//! PowerShell AST inspection.
//!
//! Scripts are parsed (never executed) with
//! `System.Management.Automation.Language.Parser::ParseInput` in a separate,
//! short-lived `powershell.exe -NoProfile` process. The script text is passed
//! as base64 on stdin, so nothing in it is interpreted by the parent shell.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Deserializer};

const PARSER_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$b64 = [Console]::In.ReadToEnd()
$src = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64.Trim()))
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
$cmds = New-Object System.Collections.ArrayList
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
  $elems = New-Object System.Collections.ArrayList
  foreach ($e in $c.CommandElements) {
    $v = $null
    $k = $e.GetType().Name
    if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $v = $e.Value }
    elseif ($e -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $v = $e.Value }
    elseif ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
      $v = '-' + $e.ParameterName
      if ($e.Argument -ne $null) { $v = $v + ':' + $e.Argument.Extent.Text }
    }
    [void]$elems.Add(@{ k = $k; t = $e.Extent.Text; v = $v })
  }
  $redirs = New-Object System.Collections.ArrayList
  foreach ($r in $c.Redirections) {
    if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) {
      [void]$redirs.Add(@{ t = $r.Location.Extent.Text; a = $r.Append })
    }
  }
  $name = $c.GetCommandName()
  [void]$cmds.Add(@{ n = $name; op = $c.InvocationOperator.ToString(); e = $elems; r = $redirs })
}
$members = New-Object System.Collections.ArrayList
foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
  [void]$members.Add(@{ t = $m.Extent.Text; ty = $m.Expression.Extent.Text; m = $m.Member.Extent.Text })
}
$errs = New-Object System.Collections.ArrayList
foreach ($er in $errors) { [void]$errs.Add($er.Message) }
$out = @{ commands = $cmds; members = $members; errors = $errs }
[Console]::Out.Write(($out | ConvertTo-Json -Depth 10 -Compress))
"#;

fn one_or_many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
        Null(()),
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(d)? {
        Some(OneOrMany::One(t)) => vec![t],
        Some(OneOrMany::Many(v)) => v,
        _ => Vec::new(),
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct PsElement {
    #[serde(rename = "k", default)]
    pub kind: String,
    #[serde(rename = "t", default)]
    pub text: String,
    #[serde(rename = "v", default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PsRedirect {
    #[serde(rename = "t", default)]
    pub target: String,
    #[serde(rename = "a", default)]
    pub append: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PsCommand {
    #[serde(rename = "n", default)]
    pub name: Option<String>,
    #[serde(rename = "op", default)]
    pub invocation_operator: String,
    #[serde(rename = "e", default, deserialize_with = "one_or_many")]
    pub elements: Vec<PsElement>,
    #[serde(rename = "r", default, deserialize_with = "one_or_many")]
    pub redirects: Vec<PsRedirect>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PsMember {
    #[serde(rename = "t", default)]
    pub text: String,
    #[serde(rename = "ty", default)]
    pub target: String,
    #[serde(rename = "m", default)]
    pub member: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PsAst {
    #[serde(default, deserialize_with = "one_or_many")]
    pub commands: Vec<PsCommand>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub members: Vec<PsMember>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub errors: Vec<String>,
}

impl PsCommand {
    /// Element values after the command name, with string constants unquoted.
    pub fn args(&self) -> Vec<String> {
        self.elements
            .iter()
            .skip(1)
            .map(|e| e.value.clone().unwrap_or_else(|| e.text.clone()))
            .collect()
    }

    /// True when the command name is not a static string (e.g. `& $x`).
    pub fn is_dynamic_name(&self) -> bool {
        self.name.is_none()
            || self
                .elements
                .first()
                .map(|e| e.kind != "StringConstantExpressionAst")
                .unwrap_or(true)
    }
}

/// Parse a PowerShell script into a simplified AST.
pub fn parse(script: &str, powershell_exe: &str) -> Result<PsAst, String> {
    let encoded_script = base64::engine::general_purpose::STANDARD.encode(
        PARSER_SCRIPT
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    let mut child = Command::new(powershell_exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-NoLogo",
            // Only our fixed parser script runs in this process; the inspected
            // script is data and is never executed.
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded_script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags_no_window()
        .spawn()
        .map_err(|e| format!("could not start PowerShell parser: {e}"))?;
    let payload = base64::engine::general_purpose::STANDARD.encode(script.as_bytes());
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.as_bytes());
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() > deadline => {
                let _ = child.kill();
                return Err("PowerShell parser timed out".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(e.to_string()),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err(format!(
            "PowerShell parser produced no output: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    serde_json::from_str(text).map_err(|e| format!("bad parser output: {e}"))
}

trait NoWindow {
    fn creation_flags_no_window(&mut self) -> &mut Self;
}

impl NoWindow for Command {
    fn creation_flags_no_window(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(0x0800_0000) // CREATE_NO_WINDOW
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands_redirects_and_members() {
        let ast = parse(
            r#"Get-Content 'C:\x\a.txt' | Set-Content -Path C:\out\b.txt; git status > log.txt
[IO.File]::WriteAllText("C:\z.txt", "hi")
& $cmd arg"#,
            "powershell.exe",
        )
        .unwrap();
        assert!(ast.errors.is_empty(), "{:?}", ast.errors);
        let names: Vec<_> = ast
            .commands
            .iter()
            .map(|c| c.name.clone().unwrap_or_default())
            .collect();
        assert!(names.contains(&"Get-Content".to_string()), "{names:?}");
        assert!(names.contains(&"Set-Content".to_string()));
        assert!(names.contains(&"git".to_string()));
        let gc = ast
            .commands
            .iter()
            .find(|c| c.name.as_deref() == Some("Get-Content"))
            .unwrap();
        assert_eq!(gc.args(), vec![r"C:\x\a.txt".to_string()]);
        let git = ast
            .commands
            .iter()
            .find(|c| c.name.as_deref() == Some("git"))
            .unwrap();
        assert_eq!(git.redirects[0].target, "log.txt");
        assert_eq!(ast.members.len(), 1);
        assert!(ast.commands.iter().any(|c| c.is_dynamic_name()));
    }
}
