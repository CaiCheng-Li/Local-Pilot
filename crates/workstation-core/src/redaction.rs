//! Central redaction engine.
//!
//! Every outbound or persisted data path (task output, audit arguments, Data
//! Shared payloads, environment inspection, error messages, Git remote URLs and
//! HTTP headers) goes through one [`Redactor`]. Redaction happens in the
//! backend before persistence, UI display or transmission.
//!
//! Pattern and known-value detection cannot recognise every transformed or
//! previously unknown secret; this is documented in SECURITY.md.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};

struct Rule {
    kind: &'static str,
    re: Regex,
    replacement: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |kind, pat: &str, replacement| Rule {
            kind,
            re: Regex::new(pat).expect("valid redaction regex"),
            replacement,
        };
        vec![
            r(
                "private_key",
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
                "<redacted private key>",
            ),
            r("local_pilot_token", r"\blp[amr]_[A-Za-z0-9_\-]{20,}", "<redacted>"),
            r("github_token", r"\b(gh[pousr])_[A-Za-z0-9]{30,255}\b", "${1}_<redacted>"),
            r("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b", "github_pat_<redacted>"),
            r(
                "authorization_header",
                r"(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)(?:(?:bearer|basic|token|digest)\s+)?[^\s\r\n,;]+",
                "${1}${2}<redacted>",
            ),
            r(
                "bearer",
                r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*",
                "Bearer <redacted>",
            ),
            r("aws_access_key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b", "<redacted aws key id>"),
            r(
                "aws_secret",
                r"(?i)(aws_?secret_?access_?key\s*[=:]\s*)[A-Za-z0-9/+=]{40}",
                "${1}<redacted>",
            ),
            r("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "<redacted api key>"),
            r(
                "openai_key",
                r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",
                "<redacted api key>",
            ),
            r("slack_token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", "<redacted>"),
            r("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "<redacted api key>"),
            r("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}", "<redacted api key>"),
            r("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", "<redacted>"),
            r(
                "cloudflare_tunnel_token",
                r"\beyJhIjoi[A-Za-z0-9+/=_\-]{40,}",
                "<redacted tunnel token>",
            ),
            r(
                "jwt",
                r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
                "<redacted jwt>",
            ),
            r(
                "url_credentials",
                r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^@\s/]+)(@)",
                "${1}<redacted>${3}",
            ),
            r(
                "connection_string_password",
                r"(?i)\b(password|pwd)(\s*=\s*)([^;\x22'\s()]{3,})(;|\s|$)",
                "${1}${2}<redacted>${4}",
            ),
            r(
                "secret_assignment",
                r#"(?i)\b([A-Z0-9_.\-]*(?:secret|token|passwd|password|api_?key|apikey|private_?key|access_?key|client_?secret|auth_?key)[A-Z0-9_.\-]*)(\s*[=:]\s*)("[A-Za-z0-9_\-+/=.~]{12,}"|'[A-Za-z0-9_\-+/=.~]{12,}'|[A-Za-z0-9_\-+/=.~]{16,})"#,
                "${1}${2}<redacted>",
            ),
        ]
    })
}

/// Values that look like placeholders are not treated as secrets by the
/// generic assignment rule.
fn is_placeholder(value: &str) -> bool {
    let v = value.trim_matches(|c| c == '"' || c == '\'');
    let lower = v.to_ascii_lowercase();
    lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("your_")
        || lower.contains("redacted")
        || lower.starts_with("process.env")
        || lower.starts_with("os.environ")
        || lower.starts_with("env.")
        || v.chars().all(|c| c == 'x' || c == 'X' || c == '*')
        || !(v.chars().any(|c| c.is_ascii_digit()) && v.chars().any(|c| c.is_ascii_alphabetic()))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionReport {
    /// Count of replacements by rule kind.
    pub counts: BTreeMap<String, u64>,
}

impl RedactionReport {
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
    pub fn merge(&mut self, other: &RedactionReport) {
        for (k, v) in &other.counts {
            *self.counts.entry(k.clone()).or_default() += v;
        }
    }
    fn add(&mut self, kind: &str, n: u64) {
        if n > 0 {
            *self.counts.entry(kind.to_string()).or_default() += n;
        }
    }
}

/// Known secret values (for example secret environment variable values present
/// in this process) that must never leave the machine verbatim.
#[derive(Default)]
struct KnownValues {
    values: Vec<(String, String)>, // (name, value) longest first
}

#[derive(Clone, Default)]
pub struct Redactor {
    known: Arc<RwLock<KnownValues>>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a secret value (minimum 8 characters) to be replaced wherever it appears.
    pub fn add_known_value(&self, name: &str, value: &str) {
        if value.len() < 8 {
            return;
        }
        let mut k = self.known.write();
        if k.values.iter().any(|(_, v)| v == value) {
            return;
        }
        k.values.push((name.to_string(), value.to_string()));
        k.values
            .sort_by_key(|value| std::cmp::Reverse(value.1.len()));
    }

    /// Register secret-looking variables of the current process environment.
    pub fn register_process_environment(&self) {
        for (name, value) in std::env::vars() {
            if crate::redaction::is_secret_env_name(&name) {
                self.add_known_value(&name, &value);
            }
        }
    }

    pub fn redact<'a>(&self, input: &'a str) -> (Cow<'a, str>, RedactionReport) {
        let mut report = RedactionReport::default();
        let mut text: Cow<'a, str> = Cow::Borrowed(input);
        {
            let known = self.known.read();
            for (name, value) in &known.values {
                if text.contains(value.as_str()) {
                    let n = text.matches(value.as_str()).count() as u64;
                    text = Cow::Owned(text.replace(value.as_str(), &format!("<redacted:{name}>")));
                    report.add("known_value", n);
                }
            }
        }
        for rule in rules() {
            if !rule.re.is_match(&text) {
                continue;
            }
            if rule.kind == "secret_assignment" {
                let mut n = 0u64;
                let replaced = rule
                    .re
                    .replace_all(&text, |caps: &regex::Captures<'_>| {
                        let value = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                        if is_placeholder(value) {
                            caps[0].to_string()
                        } else {
                            n += 1;
                            format!("{}{}<redacted>", &caps[1], &caps[2])
                        }
                    })
                    .into_owned();
                if n > 0 {
                    report.add(rule.kind, n);
                    text = Cow::Owned(replaced);
                }
                continue;
            }
            let n = rule.re.find_iter(&text).count() as u64;
            let replaced = rule.re.replace_all(&text, rule.replacement).into_owned();
            report.add(rule.kind, n);
            text = Cow::Owned(replaced);
        }
        (text, report)
    }

    pub fn redact_string(&self, input: &str) -> String {
        self.redact(input).0.into_owned()
    }

    /// Returns true if the text contains anything the redactor would replace.
    pub fn contains_secret(&self, input: &str) -> bool {
        !self.redact(input).1.is_empty()
    }

    /// Redact every string inside a JSON value (keys are preserved).
    pub fn redact_json(&self, value: &serde_json::Value) -> (serde_json::Value, RedactionReport) {
        let mut report = RedactionReport::default();
        let out = self.redact_json_inner(value, &mut report);
        (out, report)
    }

    fn redact_json_inner(
        &self,
        value: &serde_json::Value,
        report: &mut RedactionReport,
    ) -> serde_json::Value {
        use serde_json::Value;
        match value {
            Value::String(s) => {
                let (r, rep) = self.redact(s);
                report.merge(&rep);
                Value::String(r.into_owned())
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| self.redact_json_inner(v, report))
                    .collect(),
            ),
            Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    let lower = k.to_ascii_lowercase();
                    if matches!(v, Value::String(_))
                        && (lower == "authorization"
                            || lower == "password"
                            || lower == "client_secret"
                            || lower == "access_token"
                            || lower == "refresh_token"
                            || lower == "code_verifier")
                    {
                        report.add("sensitive_field", 1);
                        out.insert(k.clone(), Value::String("<redacted>".into()));
                    } else {
                        out.insert(k.clone(), self.redact_json_inner(v, report));
                    }
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    pub fn stream(&self) -> StreamRedactor {
        StreamRedactor {
            redactor: self.clone(),
            pending: Vec::new(),
            report: RedactionReport::default(),
        }
    }
}

/// Environment variable names treated as secret by default.
pub fn is_secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    const EXACT: &[&str] = &[
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_KEY",
        "CF_API_TOKEN",
        "CF_API_KEY",
        "TUNNEL_TOKEN",
        "NPM_TOKEN",
        "NODE_AUTH_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DATABASE_URL",
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
    ];
    if EXACT.contains(&upper.as_str()) {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASSWD",
        "_KEY",
        "_API_KEY",
        "_APIKEY",
        "_PAT",
        "_CREDENTIALS",
        "_PRIVATE_KEY",
        "_AUTH",
    ];
    if SUFFIXES.iter().any(|s| upper.ends_with(s)) {
        // Common non-secret variables that happen to match a suffix.
        const ALLOW: &[&str] = &["PSMODULEPATH_KEY", "PROCESSOR_ARCHITECTURE_KEY"];
        return !ALLOW.contains(&upper.as_str());
    }
    upper.contains("SECRET") || upper.contains("PASSWORD")
}

/// Streaming redaction with boundary state so a secret split across output
/// chunks is still redacted. Text is released at line boundaries; a private-key
/// block is held until it terminates (bounded).
pub struct StreamRedactor {
    redactor: Redactor,
    pending: Vec<u8>,
    report: RedactionReport,
}

const MAX_HOLD: usize = 64 * 1024;
const TAIL_HOLD: usize = 512;

impl StreamRedactor {
    /// Feed bytes; returns redacted bytes ready for storage.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        let cut = self.safe_cut();
        if cut == 0 {
            return Vec::new();
        }
        let ready: Vec<u8> = self.pending.drain(..cut).collect();
        self.redact_bytes(&ready)
    }

    /// Flush remaining bytes at end of stream.
    pub fn finish(&mut self) -> Vec<u8> {
        let rest = std::mem::take(&mut self.pending);
        if rest.is_empty() {
            return Vec::new();
        }
        self.redact_bytes(&rest)
    }

    pub fn report(&self) -> &RedactionReport {
        &self.report
    }

    fn redact_bytes(&mut self, bytes: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(bytes);
        let (out, rep) = self.redactor.redact(&text);
        self.report.merge(&rep);
        out.into_owned().into_bytes()
    }

    fn safe_cut(&self) -> usize {
        let buf = &self.pending;
        // Hold an unterminated private-key block (bounded).
        if let Some(begin) = find(buf, b"-----BEGIN ") {
            let after = &buf[begin..];
            if find(after, b"-----END ").is_none() && buf.len() < MAX_HOLD {
                return utf8_floor(
                    buf,
                    begin.min(last_newline(&buf[..begin]).map_or(0, |i| i + 1)),
                );
            }
        }
        match last_newline(buf) {
            Some(i) => utf8_floor(buf, i + 1),
            None if buf.len() > MAX_HOLD => utf8_floor(buf, buf.len() - TAIL_HOLD),
            None => 0,
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn last_newline(buf: &[u8]) -> Option<usize> {
    buf.iter().rposition(|&b| b == b'\n')
}

fn utf8_floor(buf: &[u8], mut idx: usize) -> usize {
    while idx > 0 && idx < buf.len() && (buf[idx] & 0b1100_0000) == 0b1000_0000 {
        idx -= 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secrets() {
        let r = Redactor::new();
        let cases = [
            "token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD here",
            "Authorization: Bearer abc.def.ghi123456",
            "AKIAABCDEFGHIJKLMNOP",
            "postgres://user:hunter2secret@db.example.com/x",
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
            "Server=x;User Id=sa;Password=Sup3rS3cret;",
            "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
            "lpa_abcdefghijklmnopqrstuvwxyz012345",
        ];
        for c in cases {
            let (out, rep) = r.redact(c);
            assert!(!rep.is_empty(), "not redacted: {c}");
            assert!(out.contains("redacted"), "{c} -> {out}");
        }
        let (out, _) = r.redact("token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert!(!out.contains("abcdefghijklmnop"));
    }

    #[test]
    fn leaves_ordinary_code_alone() {
        let r = Redactor::new();
        for c in [
            "let token = lexer.next_token();",
            "password = get_password()",
            "const API_KEY = process.env.API_KEY;",
            "fn tokenize(input: &str) -> Vec<Token>",
            "SECRET_KEY = 'your_secret_key_here_example'",
        ] {
            let (out, rep) = r.redact(c);
            assert!(rep.is_empty(), "false positive on {c}: {out}");
        }
    }

    #[test]
    fn known_values_are_redacted() {
        let r = Redactor::new();
        r.add_known_value("MY_SERVICE_TOKEN", "s3cr3t-value-123");
        let (out, _) = r.redact("value is s3cr3t-value-123!");
        assert_eq!(out, "value is <redacted:MY_SERVICE_TOKEN>!");
    }

    #[test]
    fn stream_redaction_handles_split_secrets() {
        let r = Redactor::new();
        let mut s = r.stream();
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        let (a, b) = secret.split_at(10);
        let mut out = Vec::new();
        out.extend(s.push(format!("line one\ntoken {a}").as_bytes()));
        out.extend(s.push(format!("{b} end\nnext").as_bytes()));
        out.extend(s.finish());
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("abcdefghijklmnop"), "{text}");
        assert!(text.contains("line one"));
        assert!(text.contains("next"));
    }

    #[test]
    fn stream_redaction_holds_private_key_blocks() {
        let r = Redactor::new();
        let mut s = r.stream();
        let mut out = Vec::new();
        out.extend(s.push(b"before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"));
        out.extend(s.push(b"BBBB\n-----END OPENSSH PRIVATE KEY-----\nafter\n"));
        out.extend(s.finish());
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("AAAA") && !text.contains("BBBB"), "{text}");
        assert!(text.contains("before") && text.contains("after"));
    }

    #[test]
    fn json_redaction_covers_nested_strings_and_sensitive_keys() {
        let r = Redactor::new();
        let v = serde_json::json!({
            "out": ["ok", "Bearer abcdefghijklmnop"],
            "client_secret": "whatever",
            "n": 3
        });
        let (red, rep) = r.redact_json(&v);
        assert!(rep.total() >= 2);
        assert_eq!(red["client_secret"], "<redacted>");
        assert_eq!(red["n"], 3);
        assert!(red["out"][1].as_str().unwrap().contains("<redacted>"));
    }

    #[test]
    fn secret_env_names() {
        for n in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "MY_API_KEY",
            "DB_PASSWORD",
            "CLOUDFLARE_API_TOKEN",
            "FOO_SECRET",
        ] {
            assert!(is_secret_env_name(n), "{n}");
        }
        for n in [
            "PATH",
            "USERPROFILE",
            "TEMP",
            "NUMBER_OF_PROCESSORS",
            "HOME",
        ] {
            assert!(!is_secret_env_name(n), "{n}");
        }
    }
}
