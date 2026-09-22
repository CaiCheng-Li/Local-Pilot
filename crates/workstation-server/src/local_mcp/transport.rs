//! SDK transports; no routing or approval decisions live here.
use super::*;
use rmcp::{
    ServiceExt,
    model::{CallToolRequest, CancelledNotificationParam, ClientRequest, ServerResult},
    service::PeerRequestOptions,
};
use workstation_executor::{
    SpawnSpec,
    spawn::{resolve_executable, spawn_interactive},
};

fn failure(code: ErrorCode, message: &str) -> LpError {
    LpError::new(code, message)
}

// Windows CommandLineToArgvW quoting. No shell is involved.
fn quote(arg: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in arg.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            out.push_str(&"\\".repeat(slashes));
        }
        slashes = 0;
        out.push(c);
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

pub(super) async fn connect(
    config: &ServerConfig,
    entry: Arc<Entry>,
    redactor: Redactor,
) -> LpResult<(Connection, Vec<Tool>)> {
    let connection = match config.transport {
        Transport::Stdio => {
            // Do not inherit tokens, API keys, credential-agent sockets or arbitrary user env.
            let mut env: BTreeMap<String, String> = [
                "SystemRoot",
                "WINDIR",
                "PATH",
                "PATHEXT",
                "TEMP",
                "TMP",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
            ]
            .into_iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_ascii_uppercase(), v)))
            .collect();
            for (k, v) in &config.env {
                env.insert(k.to_ascii_uppercase(), v.clone());
            }
            let env: Vec<_> = env.into_iter().collect();
            let cwd = Path::new(&config.cwd);
            let application = resolve_executable(&config.command, cwd, &env).ok_or_else(|| {
                failure(ErrorCode::McpConnectionFailed, "MCP executable not found")
            })?;
            if !application
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
            {
                return Err(LpError::invalid(
                    "Use an executable directly (for example node.exe with a script argument), not a shell batch file",
                ));
            }
            let command_line = std::iter::once(application.to_string_lossy().to_string())
                .chain(config.args.clone())
                .map(|s| quote(&s))
                .collect::<Vec<_>>()
                .join(" ");
            let spawned = spawn_interactive(&SpawnSpec {
                application,
                command_line,
                cwd: cwd.into(),
                env,
            })
            .map_err(|_| {
                failure(
                    ErrorCode::McpConnectionFailed,
                    "MCP process launch failed; check executable and working directory",
                )
            })?;
            {
                let mut r = entry.runtime.lock();
                r.pid = Some(spawned.pid);
                r.started_at = Some(time::now_ms());
                r.exit_code = None;
            }
            let mut stderr = spawned.stderr;
            let logging = config.logging;
            let log_entry = entry.clone();
            std::thread::spawn(move || {
                use std::io::Read;
                let mut stream = redactor.stream();
                let mut buf = [0; 4096];
                while let Ok(n) = stderr.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let data = stream.push(&buf[..n]);
                    if logging && !data.is_empty() {
                        let mut r = log_entry.runtime.lock();
                        r.logs.push(String::from_utf8_lossy(&data).into_owned());
                        if r.logs.len() > 64 {
                            r.logs.remove(0);
                        }
                    }
                }
                let tail = stream.finish();
                if logging && !tail.is_empty() {
                    log_entry
                        .runtime
                        .lock()
                        .logs
                        .push(String::from_utf8_lossy(&tail).into_owned());
                }
            });
            let process = spawned.process;
            std::thread::spawn(move || {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::System::Threading::{
                    GetExitCodeProcess, WaitForSingleObject,
                };
                unsafe {
                    WaitForSingleObject(process.as_raw_handle() as _, u32::MAX);
                    let mut code = 0;
                    GetExitCodeProcess(process.as_raw_handle() as _, &mut code);
                    entry.runtime.lock().exit_code = Some(code);
                }
            });
            // Keep job alive across handshake; any early return drops it and kills the tree.
            let job = spawned.job;
            let read = tokio::fs::File::from_std(spawned.stdout);
            let write = tokio::fs::File::from_std(spawned.stdin.expect("interactive stdin"));
            let service = ().serve((read, write)).await.map_err(|_| {
                failure(ErrorCode::McpConnectionFailed, "MCP initialization failed")
            })?;
            Connection {
                service,
                job: Some(job),
                pid: Some(spawned.pid),
            }
        }
        Transport::StreamableHttp => {
            let url = local_url(&config.url)?;
            let client = reqwest_mcp::Client::builder()
                .no_proxy()
                .redirect(reqwest_mcp::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(config.connection_timeout_seconds))
                .build()
                .map_err(LpError::internal)?;
            let transport=rmcp::transport::StreamableHttpClientTransport::with_client(client,rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(url.to_string()));
            let service = ().serve(transport).await.map_err(|_| {
                failure(
                    ErrorCode::McpConnectionFailed,
                    "Local HTTP MCP initialization failed",
                )
            })?;
            Connection {
                service,
                job: None,
                pid: None,
            }
        }
    };
    let tools = discover(&connection.service).await?;
    Ok((connection, tools))
}

pub(super) async fn discover(service: &RunningService<RoleClient, ()>) -> LpResult<Vec<Tool>> {
    if service
        .peer_info()
        .is_none_or(|i| i.capabilities.tools.is_none())
    {
        return Ok(vec![]);
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut tools = vec![];
        let mut cursor = None;
        let mut seen = std::collections::HashSet::new();
        loop {
            let page = service
                .list_tools(Some(
                    rmcp::model::PaginatedRequestParams::default().with_cursor(cursor),
                ))
                .await
                .map_err(|_| failure(ErrorCode::McpProtocolError, "MCP tools/list failed"))?;
            tools.extend(page.tools);
            if tools.len() > 2000
                || serde_json::to_vec(&tools).map_err(LpError::internal)?.len() > 4 * 1024 * 1024
            {
                return Err(failure(
                    ErrorCode::McpInvalidResponse,
                    "MCP tool catalog exceeds limits",
                ));
            }
            cursor = page.next_cursor;
            if let Some(c) = &cursor {
                if !seen.insert(c.clone()) {
                    return Err(failure(
                        ErrorCode::McpInvalidResponse,
                        "MCP returned a repeated tool cursor",
                    ));
                }
            } else {
                break;
            }
        }
        let mut names = std::collections::HashSet::new();
        if tools
            .iter()
            .any(|t| t.name.is_empty() || !names.insert(t.name.to_string()))
        {
            return Err(failure(
                ErrorCode::McpInvalidResponse,
                "MCP tool names must be unique and nonempty",
            ));
        }
        Ok(tools)
    })
    .await
    .unwrap_or_else(|_| {
        Err(failure(
            ErrorCode::McpToolTimeout,
            "MCP tool discovery timed out",
        ))
    })
}

pub(super) async fn call(
    service: &RunningService<RoleClient, ()>,
    params: CallToolRequestParams,
    timeout: Duration,
    stop: CancellationToken,
    cancel: CancellationToken,
) -> LpResult<Value> {
    let handle = service
        .send_request_with_option(
            ClientRequest::CallToolRequest(CallToolRequest::new(params)),
            PeerRequestOptions::no_options(),
        )
        .await
        .map_err(|_| {
            failure(
                ErrorCode::McpProcessExited,
                "MCP connection closed before dispatch",
            )
        })?;
    let id = handle.id.clone();
    let result = tokio::select! {
        biased;
        _=stop.cancelled()=>Err(failure(ErrorCode::McpPermissionDenied,"MCP service stopped; operation outcome may be unknown")),
        _=cancel.cancelled()=>Err(failure(ErrorCode::McpPermissionDenied,"MCP request cancelled; operation outcome may be unknown")),
        r=tokio::time::timeout(timeout,handle.await_response())=>match r {
            Err(_)=>Err(failure(ErrorCode::McpToolTimeout,"MCP tool timed out; operation outcome may be unknown")),
            Ok(Err(_))=>Err(failure(ErrorCode::McpProtocolError,"MCP call failed; operation outcome may be unknown")),
            Ok(Ok(ServerResult::CallToolResult(result)))=>serde_json::to_value(result).map_err(LpError::internal),
            Ok(Ok(_))=>Err(failure(ErrorCode::McpInvalidResponse,"Unsupported downstream tool response")),
        }
    };
    if result.is_err() {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            service.notify_cancelled(CancelledNotificationParam::new(
                Some(id),
                Some("Local Pilot cancelled or timed out".into()),
            )),
        )
        .await;
    }
    result
}
