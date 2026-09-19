//! Shared test harness: boots a real `Core` (HTTP listener on loopback) with
//! an isolated trusted workspace, application-data directory and an
//! "outside" directory, and talks to it over MCP Streamable HTTP.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use workstation_core::config::Settings;
use workstation_core::paths::AppPaths;
use workstation_server::{Core, CoreOptions};

pub struct Harness {
    pub core: Arc<Core>,
    pub dir: tempfile::TempDir,
    pub projects: PathBuf,
    pub outside: PathBuf,
    pub app: AppPaths,
    pub base: String,
    pub token: String,
    pub client_id: String,
    pub http: reqwest::Client,
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn canonical(p: &Path) -> PathBuf {
    let c = std::fs::canonicalize(p).unwrap();
    PathBuf::from(c.display().to_string().trim_start_matches(r"\\?\"))
}

pub struct Options {
    pub settings: Settings,
    pub start_listener: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            start_listener: true,
        }
    }
}

impl Harness {
    pub async fn new() -> Harness {
        Self::with(Options::default()).await
    }

    pub async fn with(opts: Options) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let projects = dir.path().join("Documents").join("Projects");
        let outside = dir.path().join("Outside");
        std::fs::create_dir_all(&projects).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let app = AppPaths::with_root(dir.path().join("AppData").join("LocalPilot"));
        let mut s = opts.settings;
        s.trusted_workspace.root_override = Some(canonical(&projects));
        s.network.port = free_port();
        s.setup_completed = true;
        s.process.foreground_wait_seconds = 20;
        let core = Core::start(CoreOptions {
            paths: app.clone(),
            install_dir: None,
            settings_override: Some(s),
            background: false,
            helper_exe: None,
        })
        .await
        .unwrap();
        if opts.start_listener {
            core.enable_remote_access().await.unwrap();
        }
        let client_id = core.auth.create_client("Test Agent", None).unwrap();
        let (_, token) = core
            .auth
            .create_manual_token(&client_id, &[], None, None)
            .unwrap();
        let port = core.settings.get().network.port;
        Harness {
            core,
            projects: canonical(&projects),
            outside: canonical(&outside),
            dir,
            app,
            base: format!("http://127.0.0.1:{port}"),
            token,
            client_id,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    /// Another authenticated client (new principal + token).
    pub fn new_client(&self, name: &str) -> (String, String) {
        let id = self.core.auth.create_client(name, None).unwrap();
        let (_, token) = self
            .core
            .auth
            .create_manual_token(&id, &[], None, None)
            .unwrap();
        (id, token)
    }

    pub async fn rpc(&self, token: &str, method: &str, params: Value) -> reqwest::Response {
        self.http
            .post(format!("{}/mcp", self.base))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .unwrap()
    }

    /// Call a tool as `token`; returns (is_error, structured result).
    pub async fn call_as(&self, token: &str, tool: &str, args: Value) -> (bool, Value) {
        let resp = self
            .rpc(
                token,
                "tools/call",
                json!({ "name": tool, "arguments": args }),
            )
            .await;
        let status = resp.status();
        let text = resp.text().await.unwrap();
        assert!(status.is_success(), "HTTP {status} for {tool}: {text}");
        let body = parse_body(&text);
        if let Some(err) = body.get("error") {
            panic!("JSON-RPC error for {tool}: {err}");
        }
        let result = &body["result"];
        let is_error = result["isError"].as_bool().unwrap_or(false);
        let structured = result.get("structuredContent").cloned().unwrap_or_else(|| {
            result["content"][0]["text"]
                .as_str()
                .and_then(|t| serde_json::from_str(t).ok())
                .unwrap_or(Value::Null)
        });
        (is_error, structured)
    }

    pub async fn call(&self, tool: &str, args: Value) -> (bool, Value) {
        self.call_as(&self.token.clone(), tool, args).await
    }

    /// Call expecting success; returns the structured result.
    pub async fn ok(&self, tool: &str, args: Value) -> Value {
        let (err, v) = self.call(tool, args.clone()).await;
        assert!(!err, "{tool}({args}) failed: {v}");
        v
    }

    /// Call expecting a tool error; returns the error code.
    pub async fn err(&self, tool: &str, args: Value) -> String {
        let (err, v) = self.call(tool, args.clone()).await;
        assert!(err, "{tool}({args}) unexpectedly succeeded: {v}");
        v["error"]["code"].as_str().unwrap_or_default().to_string()
    }

    /// Call expecting `approval_required`; returns the approval ID.
    pub async fn needs_approval(&self, tool: &str, args: Value) -> String {
        let (err, v) = self.call(tool, args.clone()).await;
        assert!(
            !err,
            "{tool}({args}) errored instead of requiring approval: {v}"
        );
        assert_eq!(v["status"], "approval_required", "{tool}({args}) => {v}");
        v["approval_id"].as_str().unwrap().to_string()
    }

    pub fn path(&self, rel: &str) -> String {
        self.projects.join(rel).display().to_string()
    }
}

/// Responses are JSON (json_response mode) but tolerate SSE framing.
pub fn parse_body(text: &str) -> Value {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return v;
    }
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data:")
            && let Ok(v) = serde_json::from_str::<Value>(data.trim())
            && (v.get("result").is_some() || v.get("error").is_some())
        {
            return v;
        }
    }
    panic!("unparseable response: {text}");
}

/// Create a directory junction (no admin rights needed).
pub fn junction(link: &Path, target: &Path) {
    let out = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(out.status.success(), "mklink /J failed: {out:?}");
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}
