//! HTTP listener (loopback by default): `/health`, the MCP Streamable HTTP
//! endpoint behind bearer authentication, RFC 9728/8414 discovery metadata and
//! the OAuth endpoints. Public URL path prefixes are served consistently.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use base64::Engine;
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use parking_lot::Mutex;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use workstation_audit::AuditEvent;
use workstation_core::config::TrustedProxy;
use workstation_core::{LpError, LpResult, ids};

use crate::auth::oauth::{
    AuthorizeError, AuthorizeParams, PollOutcome, RegistrationRequest, TokenRequest,
};
use crate::auth::{ALL_SCOPES, AuthFailure};
use crate::events::UiEvent;
use crate::mcp::{AuthContext, McpHandler};
use crate::ratelimit::Limit;
use crate::{Core, HttpHandle};

type AppState = Arc<Core>;

fn json_response(status: StatusCode, v: Value) -> Response {
    let mut r = (status, axum::Json(v)).into_response();
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

fn allowed_hosts(core: &Core) -> Vec<String> {
    let s = core.settings.get();
    let port = s.network.port;
    let mut hosts = vec![
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
    ];
    if let Some(h) = core.public_urls().public_host {
        hosts.push(h.clone());
        if let Some((host, _)) = h.split_once(':') {
            hosts.push(host.to_string());
        }
    }
    hosts.extend(s.network.extra_allowed_hosts.iter().cloned());
    hosts
}

fn host_allowed(core: &Core, headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    allowed_hosts(core)
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&host))
}

/// DNS-rebinding protection for every route (rmcp additionally validates
/// Host/Origin on the MCP endpoint).
async fn host_guard(State(core): State<AppState>, req: Request, next: Next) -> Response {
    if !host_allowed(&core, req.headers()) {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({ "error": "host_not_allowed" }),
        );
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    resp
}

fn remote_addr(core: &Core, headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<String> {
    let s = core.settings.get();
    if s.network.trusted_proxy == TrustedProxy::CloudflareTunnel
        && let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
    {
        // Display metadata only; never used for authentication.
        return Some(format!(
            "{} (via Cloudflare)",
            ip.chars().take(64).collect::<String>()
        ));
    }
    peer.map(|p| p.to_string())
}

fn challenge(core: &Core, failure: Option<&AuthFailure>) -> Response {
    let urls = core.public_urls();
    let mut value = format!(
        "Bearer resource_metadata=\"{}\", scope=\"{}\"",
        urls.resource_metadata,
        ALL_SCOPES.join(" ")
    );
    if let Some(f) = failure {
        value.push_str(&format!(
            ", error=\"{}\", error_description=\"{}\"",
            f.error,
            f.description.replace('"', "'")
        ));
    }
    let mut r = json_response(
        StatusCode::UNAUTHORIZED,
        json!({ "error": failure.map(|f| f.error).unwrap_or("unauthorized"), "error_description": failure.map(|f| f.description.clone()).unwrap_or_else(|| "authentication required".into()) }),
    );
    if let Ok(v) = HeaderValue::from_str(&value) {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    r
}

pin_project_lite::pin_project! {
    /// Response body that reports whether Data Shared payloads were fully
    /// written to the transport or interrupted.
    struct TrackedBody {
        #[pin]
        inner: Body,
        core: Arc<Core>,
        ids: Arc<Mutex<Vec<String>>>,
        done: bool,
    }
    impl PinnedDrop for TrackedBody {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            if !*this.done {
                let ids = std::mem::take(&mut *this.ids.lock());
                this.core.audit.mark_transmission(ids, "interrupted");
            }
        }
    }
}

impl http_body::Body for TrackedBody {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.project();
        let r = this.inner.poll_frame(cx);
        match &r {
            Poll::Ready(None) if !*this.done => {
                *this.done = true;
                let ids = std::mem::take(&mut *this.ids.lock());
                this.core.audit.mark_transmission(ids, "sent");
            }
            Poll::Ready(Some(Err(_))) => {
                *this.done = true;
                let ids = std::mem::take(&mut *this.ids.lock());
                this.core.audit.mark_transmission(ids, "failed");
            }
            _ => {}
        }
        r
    }
}

/// Mirror `_meta.securitySchemes` onto each tool descriptor as a top-level
/// field (ChatGPT reads it there; rmcp's `Tool` type has no such field).
fn inject_security_schemes(body: &[u8]) -> Option<Vec<u8>> {
    let mut v: Value = serde_json::from_slice(body).ok()?;
    let tools = v.get_mut("result")?.get_mut("tools")?.as_array_mut()?;
    for t in tools {
        if let Some(s) = t
            .get("_meta")
            .and_then(|m| m.get("securitySchemes"))
            .cloned()
        {
            t["securitySchemes"] = s;
        }
    }
    serde_json::to_vec(&v).ok()
}

async fn mcp_auth(
    State(core): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if !core.state.accepting() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "error": "remote_access_disabled" }),
        );
    }
    let urls = core.public_urls();
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(|s| s.trim().to_string());
    let Some(token) = token else {
        return challenge(&core, None);
    };
    let principal = match core.auth.authenticate_bearer(&token, &urls.resource) {
        Ok(p) => p,
        Err(f) => {
            core.auth.log_connection_event(
                None,
                None,
                "auth_failed",
                Some(&f.description),
                Some(&peer.to_string()),
            );
            return challenge(&core, Some(&f));
        }
    };
    let s = core.settings.get();
    let permit = match core.limiter.check(
        &principal.client_id,
        s.concurrency.requests_per_minute,
        s.concurrency.max_concurrent_calls_per_client,
    ) {
        Limit::Allowed(p) => p,
        Limit::RateLimited { retry_after_secs } => {
            let mut r = json_response(
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "rate_limited" }),
            );
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
            return r;
        }
        Limit::TooManyConcurrent => {
            let mut r = json_response(
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "too_many_concurrent_requests" }),
            );
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(1));
            return r;
        }
    };
    // Buffer the (bounded) request body to learn the JSON-RPC method and
    // validate standard routing headers against it.
    let (parts, body) = req.into_parts();
    let limit = s.network.max_request_body_bytes;
    let bytes = match http_body_util::Limited::new(body, limit).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({ "error": "request_too_large" }),
            );
        }
    };
    let rpc_method = serde_json::from_slice::<Value>(&bytes).ok().and_then(|v| {
        v.get("method")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
    });
    if let (Some(h), Some(m)) = (
        parts
            .headers
            .get("mcp-method")
            .and_then(|v| v.to_str().ok()),
        &rpc_method,
    ) && h != m
    {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "mcp_method_header_mismatch" }),
        );
    }
    let remote = remote_addr(&core, &parts.headers, Some(peer));
    if rpc_method.as_deref() == Some("initialize") {
        let info = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.pointer("/params/clientInfo").cloned())
            .map(|ci| {
                format!(
                    "{} {}",
                    ci["name"].as_str().unwrap_or("?"),
                    ci["version"].as_str().unwrap_or("")
                )
            });
        core.auth
            .record_seen(&principal.client_id, info.clone(), None, remote.clone());
        core.auth.log_connection_event(
            Some(&principal.client_id),
            Some(&principal.credential_id),
            "initialize",
            info.as_deref(),
            remote.as_deref(),
        );
    }
    let share_ids = Arc::new(Mutex::new(Vec::new()));
    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(AuthContext {
        principal,
        remote_addr: remote,
        request_id: ids::request_id(),
        share_ids: share_ids.clone(),
    });
    let resp = next.run(req).await;
    drop(permit);
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/json"))
        .unwrap_or(false);
    if rpc_method.as_deref() == Some("tools/list") && is_json {
        let (mut parts, body) = resp.into_parts();
        if let Ok(c) = body.collect().await {
            let bytes = c.to_bytes();
            let out = inject_security_schemes(&bytes).unwrap_or_else(|| bytes.to_vec());
            parts.headers.remove(header::CONTENT_LENGTH);
            return Response::from_parts(parts, Body::from(out));
        }
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": "response_failed" }),
        );
    }
    let (parts, body) = resp.into_parts();
    Response::from_parts(
        parts,
        Body::new(TrackedBody {
            inner: body,
            core: core.clone(),
            ids: share_ids,
            done: false,
        }),
    )
}

// ------------------------------------------------------------- discovery

fn protected_resource_metadata(core: &Core) -> Value {
    let u = core.public_urls();
    json!({
        "resource": u.resource,
        "authorization_servers": [u.issuer],
        "scopes_supported": ALL_SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_name": "Local Pilot",
    })
}

fn authorization_server_metadata(core: &Core) -> Value {
    let u = core.public_urls();
    let base = &u.issuer;
    let s = core.settings.get();
    let mut m = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "scopes_supported": ALL_SCOPES,
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": false,
    });
    if s.auth.allow_dynamic_client_registration {
        m["registration_endpoint"] = json!(format!("{base}/oauth/register"));
    }
    m
}

async fn prm(State(core): State<AppState>) -> Response {
    json_response(StatusCode::OK, protected_resource_metadata(&core))
}

async fn asm(State(core): State<AppState>) -> Response {
    json_response(StatusCode::OK, authorization_server_metadata(&core))
}

async fn health() -> Response {
    json_response(
        StatusCode::OK,
        json!({ "status": "ok", "version": workstation_core::VERSION }),
    )
}

// ----------------------------------------------------------------- OAuth

fn html_page(status: StatusCode, title: &str, body: &str, refresh: bool) -> Response {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let meta = if refresh {
        r#"<meta http-equiv="refresh" content="3">"#
    } else {
        ""
    };
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{meta}<title>{t}</title>
<style>body{{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1b1f24}}main{{max-width:520px;margin:10vh auto;background:#fff;border:1px solid #d8dde3;border-radius:10px;padding:28px}}h1{{font-size:20px;margin:0 0 12px}}.code{{font:600 28px Consolas,monospace;letter-spacing:4px;background:#eef2f7;border-radius:8px;padding:12px;text-align:center;margin:16px 0}}p{{line-height:1.5}}small{{color:#5b6570}}@media (prefers-color-scheme:dark){{body{{background:#15181c;color:#e6e9ed}}main{{background:#1d2126;border-color:#2c323a}}.code{{background:#262c33}}small{{color:#9aa4ae}}}}</style></head>
<body><main><h1>{t}</h1>{body}</main></body></html>"#,
        t = esc(title),
    );
    let mut r = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response();
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    r
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn register(
    State(core): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !core
        .limiter
        .check_anonymous(&format!("register:{}", peer.ip()), 10)
    {
        return json_response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "temporarily_unavailable" }),
        );
    }
    if body.len() > 16 * 1024 {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({ "error": "invalid_client_metadata", "error_description": "registration request too large" }),
        );
    }
    let req: RegistrationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_client_metadata", "error_description": e.to_string() }),
            );
        }
    };
    let remote = remote_addr(&core, &headers, Some(peer));
    match core
        .auth
        .oauth_register(req, remote.clone(), &core.settings.get())
    {
        Ok(resp) => {
            core.audit
                .record(AuditEvent {
                    kind: "oauth_client_registered".into(),
                    result_status: "ok".into(),
                    policy_detail: Some(format!(
                        "client {} ({})",
                        resp.client_id,
                        resp.client_name.clone().unwrap_or_default()
                    )),
                    ..Default::default()
                })
                .await;
            json_response(
                StatusCode::CREATED,
                serde_json::to_value(resp).unwrap_or_default(),
            )
        }
        Err(e) => json_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
            serde_json::to_value(e).unwrap_or_default(),
        ),
    }
}

fn cookie_name(request_id: &str) -> String {
    format!(
        "lp_auth_{}",
        request_id.trim_start_matches("req_").to_ascii_lowercase()
    )
}

async fn authorize(
    State(core): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    if !core
        .limiter
        .check_anonymous(&format!("authorize:{}", peer.ip()), 20)
    {
        return html_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            "<p>Please wait a minute and try again.</p>",
            false,
        );
    }
    let urls = core.public_urls();
    let remote = remote_addr(&core, &headers, Some(peer));
    match core
        .auth
        .oauth_begin(p, &urls.resource, remote, &core.settings.get())
    {
        Ok(out) => {
            core.events.emit(UiEvent::ConnectionRequested {
                request_id: out.request_id.clone(),
                client_name: out.view.client_name.clone(),
                pairing_code: out.view.pairing_code.clone(),
            });
            let secure = if urls.origin.starts_with("https://") {
                "; Secure"
            } else {
                ""
            };
            let cookie = format!(
                "{}={}; Path={}/oauth/; HttpOnly; SameSite=Lax; Max-Age=900{secure}",
                cookie_name(&out.request_id),
                out.binding_secret,
                urls.prefix
            );
            let mut r = (
                StatusCode::SEE_OTHER,
                [(
                    header::LOCATION,
                    format!("{}/oauth/consent/{}", urls.prefix, out.request_id),
                )],
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                r.headers_mut().insert(header::SET_COOKIE, v);
            }
            r.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Err(AuthorizeError::NoRedirect(msg)) => html_page(
            StatusCode::BAD_REQUEST,
            "Connection request rejected",
            &format!("<p>{}</p>", esc(&msg)),
            false,
        ),
        Err(AuthorizeError::Redirect {
            redirect_uri,
            state,
            error,
            description,
        }) => {
            let mut u = match url::Url::parse(&redirect_uri) {
                Ok(u) => u,
                Err(_) => return html_page(StatusCode::BAD_REQUEST, "Invalid redirect", "", false),
            };
            {
                let mut q = u.query_pairs_mut();
                q.append_pair("error", error);
                q.append_pair("error_description", &description);
                if let Some(s) = &state {
                    q.append_pair("state", s);
                }
                q.append_pair("iss", &urls.issuer);
            }
            (StatusCode::FOUND, [(header::LOCATION, u.to_string())]).into_response()
        }
    }
}

async fn consent(
    State(core): State<AppState>,
    AxPath(request_id): AxPath<String>,
    headers: HeaderMap,
) -> Response {
    let name = cookie_name(&request_id);
    let secret = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string());
    let urls = core.public_urls();
    match core.auth.oauth_poll(
        &request_id,
        secret.as_deref(),
        &urls.issuer,
        &core.settings.get(),
    ) {
        PollOutcome::Waiting(v) => {
            let scopes = v
                .scopes
                .iter()
                .map(|s| format!("<li>{}</li>", esc(s)))
                .collect::<String>();
            let body = format!(
                "<p><b>{}</b> wants to connect to Local Pilot on this workstation.</p>\
                 <p>Open the Local Pilot window on your computer and confirm that it shows this pairing code:</p>\
                 <div class=\"code\">{}</div>\
                 <p>Requested access:</p><ul>{scopes}</ul>\
                 <p><small>After you approve in Local Pilot, this page continues automatically. Only approve requests you started yourself. Redirect: {}</small></p>",
                esc(&v.client_name),
                esc(&v.pairing_code),
                esc(&v.redirect_uri)
            );
            html_page(
                StatusCode::OK,
                "Waiting for approval on your workstation",
                &body,
                true,
            )
        }
        PollOutcome::Redirect(url) => {
            let mut r = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
            if let Ok(v) =
                HeaderValue::from_str(&format!("{name}=; Path={}/oauth/; Max-Age=0", urls.prefix))
            {
                r.headers_mut().insert(header::SET_COOKIE, v);
            }
            r.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            core.events.emit(UiEvent::ConnectionChanged {
                request_id,
                status: "completed".into(),
            });
            r
        }
        PollOutcome::Expired | PollOutcome::NotFound => html_page(
            StatusCode::NOT_FOUND,
            "Connection request not found",
            "<p>This request expired or was started in another browser. Start the connection again from your MCP client.</p>",
            false,
        ),
    }
}

fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = v
        .strip_prefix("Basic ")
        .or_else(|| v.strip_prefix("basic "))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (id, secret) = s.split_once(':')?;
    let dec = |x: &str| {
        percent_encoding::percent_decode_str(x)
            .decode_utf8_lossy()
            .into_owned()
    };
    Some((dec(id), dec(secret)))
}

async fn token(
    State(core): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !core
        .limiter
        .check_anonymous(&format!("token:{}", peer.ip()), 60)
    {
        return json_response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "temporarily_unavailable" }),
        );
    }
    if body.len() > 16 * 1024 {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({ "error": "invalid_request" }),
        );
    }
    let req: TokenRequest = match serde_urlencoded_form(&body) {
        Some(r) => r,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request", "error_description": "expected a form-encoded body" }),
            );
        }
    };
    let grant = req.grant_type.clone().unwrap_or_default();
    let urls = core.public_urls();
    let result = core.auth.oauth_token(
        req,
        basic_auth(&headers),
        &urls.resource,
        &core.settings.get(),
    );
    match result {
        Ok((resp, client_id, credential_id)) => {
            // Authentication exchange: metadata only, never the issued secrets.
            core.audit
                .record(AuditEvent {
                    kind: "oauth_token".into(),
                    client_id: Some(client_id.clone()),
                    result_status: "ok".into(),
                    policy_detail: Some(format!(
                        "grant_type={grant} credential={credential_id} scope={}",
                        resp.scope
                    )),
                    ..Default::default()
                })
                .await;
            core.auth.log_connection_event(
                Some(&client_id),
                Some(&credential_id),
                &format!("token_{grant}"),
                None,
                remote_addr(&core, &headers, Some(peer)).as_deref(),
            );
            json_response(
                StatusCode::OK,
                serde_json::to_value(resp).unwrap_or_default(),
            )
        }
        Err(e) => {
            core.audit
                .record(AuditEvent {
                    kind: "oauth_token".into(),
                    result_status: "error".into(),
                    error: Some(e.error.to_string()),
                    policy_detail: Some(format!("grant_type={grant}")),
                    ..Default::default()
                })
                .await;
            json_response(
                StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
                serde_json::to_value(e).unwrap_or_default(),
            )
        }
    }
}

fn serde_urlencoded_form<T: serde::de::DeserializeOwned>(body: &[u8]) -> Option<T> {
    let pairs: serde_json::Map<String, Value> = url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), Value::String(v.into_owned())))
        .collect();
    serde_json::from_value(Value::Object(pairs)).ok()
}

async fn revoke(State(core): State<AppState>, body: Bytes) -> Response {
    #[derive(serde::Deserialize)]
    struct R {
        token: Option<String>,
    }
    if let Some(R { token: Some(t) }) = serde_urlencoded_form::<R>(&body)
        && let Some(cred) = core.auth.oauth_revoke(&t)
        && let Ok(Some(c)) = core.auth.db().read_sync(|c| {
            use rusqlite::OptionalExtension;
            Ok(c.query_row(
                "SELECT client_id FROM credentials WHERE credential_id = ?1",
                [&cred],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
        })
    {
        core.sessions.end_credential(&cred, "token revoked");
        let _ = c;
    }
    StatusCode::OK.into_response()
}

// ------------------------------------------------------------------ serve

fn oauth_routes() -> Router<AppState> {
    Router::new()
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/consent/{request_id}", get(consent))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/health", get(health))
        .route("/.well-known/oauth-protected-resource", get(prm))
        .route("/.well-known/oauth-protected-resource/{*rest}", get(prm))
        .route("/.well-known/oauth-authorization-server", get(asm))
        .route("/.well-known/oauth-authorization-server/{*rest}", get(asm))
        .route("/mcp/.well-known/oauth-protected-resource", get(prm))
}

pub async fn serve(core: Arc<Core>) -> LpResult<HttpHandle> {
    let s = core.settings.get();
    let urls = core.public_urls();
    let cancel = CancellationToken::new();
    let mut origins = vec![
        format!("http://127.0.0.1:{}", s.network.port),
        format!("http://localhost:{}", s.network.port),
    ];
    if urls.configured {
        origins.push(urls.origin.clone());
    }
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(allowed_hosts(&core))
        .with_allowed_origins(origins)
        .enforce_origin_validation()
        .with_max_request_body_bytes(s.network.max_request_body_bytes)
        .with_cancellation_token(cancel.child_token());
    let handler_core = core.clone();
    let service: StreamableHttpService<McpHandler, LocalSessionManager> =
        StreamableHttpService::new(
            move || {
                Ok(McpHandler {
                    core: handler_core.clone(),
                })
            },
            Default::default(),
            config,
        );

    let mcp_router = Router::new()
        .route_service("/mcp", service)
        .route_layer(middleware::from_fn_with_state(core.clone(), mcp_auth));
    let mut app: Router<AppState> = Router::new()
        .merge(oauth_routes())
        .merge(mcp_router.clone());
    if !urls.prefix.is_empty() {
        let prefixed: Router<AppState> = Router::new().merge(oauth_routes()).merge(mcp_router);
        app = app.nest(&urls.prefix, prefixed);
    }
    let app = app
        .fallback(any(|| async {
            json_response(StatusCode::NOT_FOUND, json!({ "error": "not_found" }))
        }))
        .layer(middleware::from_fn_with_state(core.clone(), host_guard))
        .with_state(core.clone());

    let ip: std::net::IpAddr = s.network.bind_address.parse().map_err(|_| {
        LpError::new(
            workstation_core::ErrorCode::ConfigFault,
            "invalid bind address",
        )
    })?;
    let addr = SocketAddr::new(ip, s.network.port);
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        LpError::new(
            workstation_core::ErrorCode::ConfigFault,
            format!("Cannot listen on {addr}: {e}. The configured port is unavailable; choose another port in Settings (the tunnel mapping must match)."),
        )
    })?;
    let bound = listener.local_addr().map_err(LpError::internal)?;
    let c2 = cancel.clone();
    let join = tokio::spawn(async move {
        let r = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { c2.cancelled().await })
        .await;
        if let Err(e) = r {
            tracing::error!(error = %e, "HTTP server stopped with an error");
        }
    });
    tracing::info!(%bound, "MCP listener started");
    Ok(HttpHandle {
        cancel,
        addr: bound,
        join,
    })
}

#[allow(dead_code)]
fn _assert_infallible(_: Infallible) {}
