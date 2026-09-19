//! Bundled OAuth 2.1 authorization server with local desktop consent.
//!
//! - Client registration: RFC 7591 Dynamic Client Registration (the method
//!   advertised; CIMD is not advertised because it is not implemented).
//! - Authorization code + PKCE S256 only; exact redirect URI matching;
//!   RFC 8707 resource binding; RFC 9207 `iss` in every authorization response.
//! - The public authorization page only creates a short-lived pending
//!   request. It cannot approve itself: an authenticated local UI action
//!   grants it, after the owner compares a request-specific pairing code with
//!   the one shown in the initiating browser. The code is released only to the
//!   browser holding the request-bound cookie, and only through the validated
//!   redirect.
//! - Opaque access tokens (short-lived) and rotating refresh tokens, stored as
//!   keyed hashes. Refresh-token reuse revokes the whole grant.

use std::collections::HashMap;

use parking_lot::Mutex;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use workstation_core::config::Settings;
use workstation_core::hashing::{constant_time_eq, pairing_code, random_token, sha256_b64url};
use workstation_core::{LpError, LpResult, ids, time};

use super::{ALL_SCOPES, AuthService, normalize_scopes};

pub const KNOWN_CHATGPT_REDIRECTS: &[&str] = &[
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/connector/oauth/",
    "https://platform.openai.com/apps-manage/oauth",
];

#[derive(Debug, Clone, Serialize)]
pub struct OAuthError {
    pub error: &'static str,
    pub error_description: String,
    #[serde(skip)]
    pub status: u16,
}

impl OAuthError {
    pub fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: description.into(),
            status: 400,
        }
    }
    fn unauthorized_client(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_client",
            error_description: description.into(),
            status: 401,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub software_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub client_id_issued_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub scope: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingAuthorization {
    request_id: String,
    created_at: i64,
    expires_at: i64,
    oauth_client_id: String,
    client_name: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    scopes: Vec<String>,
    resource: String,
    pairing_code: String,
    binding_hash: String,
    remote_addr: Option<String>,
    suggested_client_id: Option<String>,
    decision: Option<Decision>,
    released: bool,
}

#[derive(Debug, Clone)]
struct Decision {
    approve: bool,
    bind_client_id: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Clone)]
struct AuthCode {
    oauth_client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scopes: Vec<String>,
    resource: String,
    bind_client_id: Option<String>,
    display_name: String,
    expires_at: i64,
    used: bool,
    issued_credential: Option<String>,
}

#[derive(Default)]
pub struct OAuthState {
    pending: Mutex<HashMap<String, PendingAuthorization>>,
    codes: Mutex<HashMap<String, AuthCode>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConnectionView {
    pub request_id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub oauth_client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub redirect_is_known_chatgpt: bool,
    pub scopes: Vec<String>,
    pub resource: String,
    pub pairing_code: String,
    pub remote_addr: Option<String>,
    /// Existing local principal this OAuth client was previously bound to.
    pub suggested_client_id: Option<String>,
    pub status: String,
}

pub struct BeginOutcome {
    pub request_id: String,
    pub binding_secret: String,
    pub view: PendingConnectionView,
}

/// Errors from `/authorize`: some must not redirect (unknown client or bad
/// redirect URI), the rest are returned to the validated redirect URI.
pub enum AuthorizeError {
    NoRedirect(String),
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        error: &'static str,
        description: String,
    },
}

pub enum PollOutcome {
    Waiting(Box<PendingConnectionView>),
    Redirect(String),
    Expired,
    NotFound,
}

type OAuthClientRecord = (
    Option<String>,
    Vec<String>,
    String,
    Option<String>,
    Option<String>,
);

#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

/// Compare resource indicators, tolerating a trailing slash.
pub fn resource_matches(a: &str, b: &str) -> bool {
    a.trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim_end_matches('/'))
}

fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let u =
        url::Url::parse(uri).map_err(|_| "redirect URI is not a valid absolute URL".to_string())?;
    if u.fragment().is_some() {
        return Err("redirect URI must not contain a fragment".into());
    }
    match u.scheme() {
        "https" => Ok(()),
        "http"
            if matches!(
                u.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("[::1]")
            ) =>
        {
            Ok(())
        }
        _ => Err("redirect URI must use https (or http on loopback for local tools)".into()),
    }
}

fn append_query(uri: &str, pairs: &[(&str, &str)]) -> String {
    let mut u = match url::Url::parse(uri) {
        Ok(u) => u,
        Err(_) => return uri.to_string(),
    };
    {
        let mut q = u.query_pairs_mut();
        for (k, v) in pairs {
            q.append_pair(k, v);
        }
    }
    u.to_string()
}

fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
}

impl AuthService {
    // ------------------------------------------------------ registration

    pub fn oauth_register(
        &self,
        req: RegistrationRequest,
        remote: Option<String>,
        settings: &Settings,
    ) -> Result<RegistrationResponse, OAuthError> {
        if !settings.auth.allow_dynamic_client_registration {
            return Err(OAuthError::new(
                "invalid_client_metadata",
                "dynamic client registration is disabled",
            ));
        }
        if req.redirect_uris.is_empty() || req.redirect_uris.len() > 5 {
            return Err(OAuthError::new(
                "invalid_redirect_uri",
                "one to five redirect_uris are required",
            ));
        }
        for u in &req.redirect_uris {
            if u.len() > 512 {
                return Err(OAuthError::new(
                    "invalid_redirect_uri",
                    "redirect URI too long",
                ));
            }
            validate_redirect_uri(u).map_err(|e| OAuthError::new("invalid_redirect_uri", e))?;
        }
        let method = req
            .token_endpoint_auth_method
            .clone()
            .unwrap_or_else(|| "client_secret_basic".into());
        if !matches!(
            method.as_str(),
            "none" | "client_secret_post" | "client_secret_basic"
        ) {
            return Err(OAuthError::new(
                "invalid_client_metadata",
                "unsupported token_endpoint_auth_method",
            ));
        }
        if let Some(g) = &req.grant_types
            && g.iter()
                .any(|x| x != "authorization_code" && x != "refresh_token")
        {
            return Err(OAuthError::new(
                "invalid_client_metadata",
                "only authorization_code and refresh_token grants are supported",
            ));
        }
        if let Some(r) = &req.response_types
            && r.iter().any(|x| x != "code")
        {
            return Err(OAuthError::new(
                "invalid_client_metadata",
                "only the code response type is supported",
            ));
        }
        let name: Option<String> = req
            .client_name
            .as_ref()
            .map(|n| {
                n.chars()
                    .filter(|c| !c.is_control())
                    .take(100)
                    .collect::<String>()
            })
            .filter(|n| !n.trim().is_empty());
        let client_id = format!("lpoc_{}", ulid_like());
        let secret = if method == "none" {
            None
        } else {
            Some(random_token("lpcs"))
        };
        let secret_hash = secret.as_ref().map(|s| self.hash(s));
        let now = time::now_ms();
        let max = settings.auth.max_registered_clients as i64;
        let (cid, uris, m, n, sw) = (
            client_id.clone(),
            serde_json::to_string(&req.redirect_uris).unwrap_or_default(),
            method.clone(),
            name.clone(),
            req.software_id.clone(),
        );
        self.db()
            .write_sync(move |c| {
                // Keep the registry bounded: prune never-used registrations first.
                let count: i64 = c.query_row("SELECT COUNT(*) FROM oauth_clients", [], |r| r.get(0))?;
                if count >= max {
                    c.execute(
                        "DELETE FROM oauth_clients WHERE oauth_client_id IN (SELECT oauth_client_id FROM oauth_clients WHERE local_client_id IS NULL ORDER BY created_at LIMIT ?1)",
                        [count - max + 1],
                    )?;
                    let count: i64 = c.query_row("SELECT COUNT(*) FROM oauth_clients", [], |r| r.get(0))?;
                    if count >= max {
                        return Err(LpError::new(workstation_core::ErrorCode::ClientLimitReached, "registration limit reached"));
                    }
                }
                c.execute(
                    "INSERT INTO oauth_clients (oauth_client_id, client_name, redirect_uris, token_endpoint_auth_method, secret_hash, created_at, software_id, registration_addr) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![cid, n, uris, m, secret_hash, now, sw, remote],
                )?;
                Ok(())
            })
            .map_err(|e| OAuthError::new("invalid_client_metadata", e.message))?;
        Ok(RegistrationResponse {
            client_id,
            client_secret: secret,
            client_id_issued_at: now / 1000,
            client_secret_expires_at: if method == "none" { None } else { Some(0) },
            redirect_uris: req.redirect_uris,
            token_endpoint_auth_method: method,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            client_name: name,
            scope: ALL_SCOPES.join(" "),
        })
    }

    fn oauth_client(&self, client_id: &str) -> Option<OAuthClientRecord> {
        let id = client_id.to_string();
        self.db()
            .read_sync(|c| {
                Ok(c.query_row(
                    "SELECT client_name, redirect_uris, token_endpoint_auth_method, secret_hash, local_client_id FROM oauth_clients WHERE oauth_client_id = ?1",
                    [&id],
                    |r| {
                        let uris: String = r.get(1)?;
                        Ok((
                            r.get::<_, Option<String>>(0)?,
                            serde_json::from_str::<Vec<String>>(&uris).unwrap_or_default(),
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                        ))
                    },
                )
                .optional()?)
            })
            .ok()
            .flatten()
    }

    // ------------------------------------------------------ authorization

    pub fn oauth_begin(
        &self,
        p: AuthorizeParams,
        our_resource: &str,
        remote: Option<String>,
        settings: &Settings,
    ) -> Result<BeginOutcome, AuthorizeError> {
        let client_id = p
            .client_id
            .clone()
            .ok_or_else(|| AuthorizeError::NoRedirect("missing client_id".into()))?;
        let (name, uris, _, _, local_client) = self.oauth_client(&client_id).ok_or_else(|| {
            AuthorizeError::NoRedirect("unknown client_id; register the client first".into())
        })?;
        let redirect_uri = match (&p.redirect_uri, uris.len()) {
            (Some(r), _) => r.clone(),
            (None, 1) => uris[0].clone(),
            (None, _) => {
                return Err(AuthorizeError::NoRedirect(
                    "redirect_uri is required".into(),
                ));
            }
        };
        if !uris.iter().any(|u| u == &redirect_uri) {
            return Err(AuthorizeError::NoRedirect(
                "redirect_uri does not exactly match a registered URI".into(),
            ));
        }
        let redirect_err = |error: &'static str, description: &str| AuthorizeError::Redirect {
            redirect_uri: redirect_uri.clone(),
            state: p.state.clone(),
            error,
            description: description.to_string(),
        };
        if p.response_type.as_deref() != Some("code") {
            return Err(redirect_err(
                "unsupported_response_type",
                "response_type must be code",
            ));
        }
        let challenge = p.code_challenge.clone().unwrap_or_default();
        if challenge.len() < 43 || challenge.len() > 128 {
            return Err(redirect_err(
                "invalid_request",
                "a PKCE code_challenge is required",
            ));
        }
        if p.code_challenge_method.as_deref() != Some("S256") {
            return Err(redirect_err(
                "invalid_request",
                "code_challenge_method must be S256",
            ));
        }
        let resource = match &p.resource {
            Some(r) if !resource_matches(r, our_resource) => {
                return Err(redirect_err("invalid_target", "unknown resource"));
            }
            _ => our_resource.to_string(),
        };
        if let Some(s) = &p.scope
            && s.split_whitespace()
                .any(|x| !ALL_SCOPES.contains(&x) && !matches!(x, "openid" | "offline_access"))
        {
            return Err(redirect_err("invalid_scope", "unknown scope requested"));
        }
        if p.state.as_ref().map(|s| s.len() > 1024).unwrap_or(false) {
            return Err(redirect_err("invalid_request", "state too long"));
        }
        let scopes = normalize_scopes(p.scope.as_deref());
        let now = time::now_ms();
        let mut pending = self.oauth.pending.lock();
        pending.retain(|_, v| v.expires_at > now && !v.released);
        if pending.len() >= settings.auth.max_pending_connection_requests
            || pending
                .values()
                .filter(|v| v.oauth_client_id == client_id)
                .count()
                >= 3
        {
            return Err(redirect_err(
                "temporarily_unavailable",
                "too many pending connection requests",
            ));
        }
        let request_id = ids::request_id();
        let binding_secret = random_token("lpb");
        let pa = PendingAuthorization {
            request_id: request_id.clone(),
            created_at: now,
            expires_at: now + settings.auth.pending_connection_ttl_seconds as i64 * 1000,
            oauth_client_id: client_id,
            client_name: name.unwrap_or_else(|| "Unnamed MCP client".into()),
            redirect_uri,
            state: p.state,
            code_challenge: challenge,
            scopes,
            resource,
            pairing_code: pairing_code(),
            binding_hash: self.hash(&binding_secret),
            remote_addr: remote,
            suggested_client_id: local_client,
            decision: None,
            released: false,
        };
        let view = view_of(&pa);
        pending.insert(request_id.clone(), pa);
        Ok(BeginOutcome {
            request_id,
            binding_secret,
            view,
        })
    }

    pub fn oauth_pending(&self) -> Vec<PendingConnectionView> {
        let now = time::now_ms();
        let mut p = self.oauth.pending.lock();
        p.retain(|_, v| v.expires_at > now && !v.released);
        let mut v: Vec<_> = p.values().map(view_of).collect();
        v.sort_by_key(|x| x.created_at);
        v
    }

    /// Local UI decision (the only way a connection request is granted).
    pub fn oauth_decide(
        &self,
        request_id: &str,
        approve: bool,
        bind_client_id: Option<String>,
        display_name: Option<String>,
    ) -> LpResult<()> {
        let mut p = self.oauth.pending.lock();
        let pa = p
            .get_mut(request_id)
            .ok_or_else(|| LpError::not_found("unknown or expired connection request"))?;
        if pa.expires_at < time::now_ms() {
            return Err(LpError::not_found("connection request expired"));
        }
        if pa.decision.is_some() {
            return Err(LpError::invalid("connection request already decided"));
        }
        pa.decision = Some(Decision {
            approve,
            bind_client_id,
            display_name,
        });
        Ok(())
    }

    /// Browser polling: release the code only to the initiating browser.
    pub fn oauth_poll(
        &self,
        request_id: &str,
        binding_secret: Option<&str>,
        issuer: &str,
        settings: &Settings,
    ) -> PollOutcome {
        let now = time::now_ms();
        let mut p = self.oauth.pending.lock();
        let Some(pa) = p.get_mut(request_id) else {
            return PollOutcome::NotFound;
        };
        let bound = binding_secret
            .map(|s| constant_time_eq(&self.hash(s), &pa.binding_hash))
            .unwrap_or(false);
        if !bound {
            return PollOutcome::NotFound;
        }
        if pa.expires_at < now || pa.released {
            let r = append_query(
                &pa.redirect_uri,
                &[
                    ("error", "access_denied"),
                    ("error_description", "the connection request expired"),
                    ("iss", issuer),
                ]
                .into_iter()
                .chain(pa.state.as_deref().map(|s| ("state", s)))
                .collect::<Vec<_>>(),
            );
            p.remove(request_id);
            return if r.is_empty() {
                PollOutcome::Expired
            } else {
                PollOutcome::Redirect(r)
            };
        }
        let Some(decision) = pa.decision.clone() else {
            return PollOutcome::Waiting(Box::new(view_of(pa)));
        };
        pa.released = true;
        let state = pa.state.clone();
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if decision.approve {
            let code = random_token("lpc");
            let display_name = decision
                .display_name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| pa.client_name.clone());
            self.oauth.codes.lock().insert(
                self.hash(&code),
                AuthCode {
                    oauth_client_id: pa.oauth_client_id.clone(),
                    redirect_uri: pa.redirect_uri.clone(),
                    code_challenge: pa.code_challenge.clone(),
                    scopes: pa.scopes.clone(),
                    resource: pa.resource.clone(),
                    bind_client_id: decision
                        .bind_client_id
                        .clone()
                        .or_else(|| pa.suggested_client_id.clone()),
                    display_name,
                    expires_at: now + settings.auth.authorization_code_ttl_seconds as i64 * 1000,
                    used: false,
                    issued_credential: None,
                },
            );
            pairs.push(("code", code));
        } else {
            pairs.push(("error", "access_denied".into()));
            pairs.push((
                "error_description",
                "the workstation owner denied the request".into(),
            ));
        }
        if let Some(s) = state {
            pairs.push(("state", s));
        }
        pairs.push(("iss", issuer.to_string()));
        let redirect = pa.redirect_uri.clone();
        p.remove(request_id);
        let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        PollOutcome::Redirect(append_query(&redirect, &refs))
    }

    pub fn oauth_cleanup(&self) {
        let now = time::now_ms();
        self.oauth
            .pending
            .lock()
            .retain(|_, v| v.expires_at > now - 60_000);
        self.oauth
            .codes
            .lock()
            .retain(|_, v| v.expires_at > now - 600_000);
    }

    /// Discard pending requests and unexchanged codes (restart/Emergency Stop).
    pub fn oauth_reset(&self) {
        self.oauth.pending.lock().clear();
        self.oauth.codes.lock().clear();
    }

    // --------------------------------------------------------------- token

    fn authenticate_client(
        &self,
        client_id: &str,
        form_secret: Option<&str>,
        basic: Option<(String, String)>,
    ) -> Result<(String, Option<String>), OAuthError> {
        let (_, _, method, secret_hash, local) = self
            .oauth_client(client_id)
            .ok_or_else(|| OAuthError::unauthorized_client("unknown client"))?;
        match method.as_str() {
            "none" => Ok((method, local)),
            "client_secret_basic" | "client_secret_post" => {
                let presented = match (&basic, form_secret) {
                    (Some((id, s)), _) if id == client_id => Some(s.clone()),
                    (None, Some(s)) => Some(s.to_string()),
                    _ => None,
                };
                let ok = match (presented, secret_hash) {
                    (Some(p), Some(h)) => constant_time_eq(&self.hash(&p), &h),
                    _ => false,
                };
                if ok {
                    Ok((method, local))
                } else {
                    Err(OAuthError::unauthorized_client(
                        "client authentication failed",
                    ))
                }
            }
            _ => Err(OAuthError::unauthorized_client(
                "unsupported client authentication",
            )),
        }
    }

    pub fn oauth_token(
        &self,
        req: TokenRequest,
        basic: Option<(String, String)>,
        our_resource: &str,
        settings: &Settings,
    ) -> Result<(TokenResponse, String, String), OAuthError> {
        let client_id = match (&req.client_id, &basic) {
            (Some(c), _) => c.clone(),
            (None, Some((c, _))) => c.clone(),
            _ => return Err(OAuthError::unauthorized_client("client_id is required")),
        };
        if let Some(r) = &req.resource
            && !resource_matches(r, our_resource)
        {
            return Err(OAuthError::new("invalid_target", "unknown resource"));
        }
        let (_, local_client) =
            self.authenticate_client(&client_id, req.client_secret.as_deref(), basic)?;
        match req.grant_type.as_deref() {
            Some("authorization_code") => {
                self.exchange_code(req, &client_id, local_client, settings)
            }
            Some("refresh_token") => self.refresh(req, &client_id, our_resource, settings),
            _ => Err(OAuthError::new(
                "unsupported_grant_type",
                "grant_type must be authorization_code or refresh_token",
            )),
        }
    }

    fn exchange_code(
        &self,
        req: TokenRequest,
        client_id: &str,
        local_client: Option<String>,
        settings: &Settings,
    ) -> Result<(TokenResponse, String, String), OAuthError> {
        let code = req
            .code
            .clone()
            .ok_or_else(|| OAuthError::new("invalid_request", "code is required"))?;
        let verifier = req
            .code_verifier
            .clone()
            .ok_or_else(|| OAuthError::new("invalid_request", "code_verifier is required"))?;
        let code_hash = self.hash(&code);
        let ac = {
            let mut codes = self.oauth.codes.lock();
            let Some(ac) = codes.get_mut(&code_hash) else {
                return Err(OAuthError::new(
                    "invalid_grant",
                    "unknown or expired authorization code",
                ));
            };
            if ac.used {
                // Replay: revoke anything issued from this code.
                if let Some(cred) = ac.issued_credential.clone() {
                    let _ = self.revoke_credential(&cred);
                }
                return Err(OAuthError::new(
                    "invalid_grant",
                    "authorization code already used",
                ));
            }
            ac.used = true;
            ac.clone()
        };
        if ac.expires_at < time::now_ms() {
            return Err(OAuthError::new(
                "invalid_grant",
                "authorization code expired",
            ));
        }
        if ac.oauth_client_id != client_id {
            return Err(OAuthError::new(
                "invalid_grant",
                "code was issued to another client",
            ));
        }
        if req.redirect_uri.as_deref() != Some(ac.redirect_uri.as_str()) {
            return Err(OAuthError::new("invalid_grant", "redirect_uri mismatch"));
        }
        if !valid_verifier(&verifier) || sha256_b64url(verifier.as_bytes()) != ac.code_challenge {
            return Err(OAuthError::new("invalid_grant", "PKCE verification failed"));
        }
        if let Some(r) = &req.resource
            && !resource_matches(r, &ac.resource)
        {
            return Err(OAuthError::new(
                "invalid_target",
                "resource does not match the authorization",
            ));
        }
        // Resolve the local principal.
        let principal = match ac.bind_client_id.clone().or(local_client) {
            Some(existing) if self.client(&existing).ok().flatten().is_some() => existing,
            _ => self
                .create_client(&ac.display_name, Some("oauth"))
                .map_err(|e| OAuthError::new("server_error", e.message))?,
        };
        let cred = ids::credential_id();
        let (cred2, principal2, oc, scopes, resource) = (
            cred.clone(),
            principal.clone(),
            client_id.to_string(),
            ac.scopes.join(" "),
            ac.resource.clone(),
        );
        self.db()
            .write_sync(move |c| {
                c.execute(
                    "INSERT INTO credentials (credential_id, client_id, kind, scopes, created_at, enabled, oauth_client_id, resource, label) VALUES (?1, ?2, 'oauth_grant', ?3, ?4, 1, ?5, ?6, 'OAuth connection')",
                    params![cred2, principal2, scopes, time::now_ms(), oc, resource],
                )?;
                c.execute(
                    "UPDATE oauth_clients SET local_client_id = ?2, last_used_at = ?3 WHERE oauth_client_id = ?1",
                    params![oc, principal2, time::now_ms()],
                )?;
                Ok(())
            })
            .map_err(|e| OAuthError::new("server_error", e.message))?;
        if let Some(ac) = self.oauth.codes.lock().get_mut(&code_hash) {
            ac.issued_credential = Some(cred.clone());
        }
        let resp = self.issue_tokens(&cred, &ac.scopes, &ac.resource, settings)?;
        Ok((resp, principal, cred))
    }

    fn refresh(
        &self,
        req: TokenRequest,
        client_id: &str,
        our_resource: &str,
        settings: &Settings,
    ) -> Result<(TokenResponse, String, String), OAuthError> {
        let rt = req
            .refresh_token
            .clone()
            .ok_or_else(|| OAuthError::new("invalid_request", "refresh_token is required"))?;
        let hash = self.hash(&rt);
        let row = self
            .db()
            .read_sync(|c| {
                Ok(c.query_row(
                    "SELECT t.credential_id, t.expires_at, t.used_at, t.revoked_at, t.scopes, t.resource, cr.revoked_at, cr.enabled, cr.oauth_client_id, cr.client_id, cl.enabled
                     FROM oauth_grants_tokens t JOIN credentials cr ON cr.credential_id = t.credential_id JOIN clients cl ON cl.client_id = cr.client_id
                     WHERE t.token_hash = ?1 AND t.kind = 'refresh'",
                    [&hash],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Option<i64>>(2)?,
                            r.get::<_, Option<i64>>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, String>(5)?,
                            r.get::<_, Option<i64>>(6)?,
                            r.get::<_, bool>(7)?,
                            r.get::<_, Option<String>>(8)?,
                            r.get::<_, String>(9)?,
                            r.get::<_, bool>(10)?,
                        ))
                    },
                )
                .optional()?)
            })
            .map_err(|e| OAuthError::new("server_error", e.message))?;
        let Some((
            cred,
            expires,
            used,
            revoked,
            scopes,
            resource,
            cred_revoked,
            cred_enabled,
            oauth_client,
            principal,
            client_enabled,
        )) = row
        else {
            return Err(OAuthError::new("invalid_grant", "unknown refresh token"));
        };
        if oauth_client.as_deref() != Some(client_id) {
            return Err(OAuthError::new(
                "invalid_grant",
                "refresh token was issued to another client",
            ));
        }
        if used.is_some() {
            tracing::warn!(credential = %cred, "refresh token reuse detected; revoking grant");
            let _ = self.revoke_credential(&cred);
            return Err(OAuthError::new(
                "invalid_grant",
                "refresh token reuse detected; the grant was revoked",
            ));
        }
        if revoked.is_some() || cred_revoked.is_some() || !cred_enabled || !client_enabled {
            return Err(OAuthError::new(
                "invalid_grant",
                "the grant was revoked or disabled",
            ));
        }
        if expires < time::now_ms() {
            return Err(OAuthError::new("invalid_grant", "refresh token expired"));
        }
        if !resource_matches(&resource, our_resource) {
            return Err(OAuthError::new(
                "invalid_grant",
                "the grant is bound to a different resource; reconnect",
            ));
        }
        let granted: Vec<String> = scopes.split_whitespace().map(|s| s.to_string()).collect();
        let requested = match &req.scope {
            Some(s) => {
                let r: Vec<String> = s.split_whitespace().map(|x| x.to_string()).collect();
                if r.iter().any(|x| !granted.contains(x)) {
                    return Err(OAuthError::new(
                        "invalid_scope",
                        "requested scope exceeds the grant",
                    ));
                }
                r
            }
            None => granted,
        };
        let now = time::now_ms();
        let h2 = hash.clone();
        let consumed = self
            .db()
            .write_sync(move |c| Ok(c.execute("UPDATE oauth_grants_tokens SET used_at = ?2 WHERE token_hash = ?1 AND used_at IS NULL", params![h2, now])?))
            .map_err(|e| OAuthError::new("server_error", e.message))?;
        if consumed != 1 {
            let _ = self.revoke_credential(&cred);
            return Err(OAuthError::new(
                "invalid_grant",
                "refresh token reuse detected; the grant was revoked",
            ));
        }
        let resp = self.issue_tokens(&cred, &requested, &resource, settings)?;
        Ok((resp, principal, cred))
    }

    fn issue_tokens(
        &self,
        credential_id: &str,
        scopes: &[String],
        resource: &str,
        settings: &Settings,
    ) -> Result<TokenResponse, OAuthError> {
        let access = random_token("lpa");
        let refresh = random_token("lpr");
        let now = time::now_ms();
        let access_ttl = settings.auth.access_token_ttl_seconds.clamp(60, 24 * 3600);
        let refresh_ttl_ms =
            settings.auth.refresh_token_ttl_days.clamp(1, 365) as i64 * time::DAY_MS;
        let (ah, rh, cred, sc, res) = (
            self.hash(&access),
            self.hash(&refresh),
            credential_id.to_string(),
            scopes.join(" "),
            resource.to_string(),
        );
        self.db()
            .write_sync(move |c| {
                c.execute(
                    "INSERT INTO oauth_grants_tokens (token_hash, kind, credential_id, expires_at, created_at, scopes, resource) VALUES (?1, 'access', ?2, ?3, ?4, ?5, ?6)",
                    params![ah, cred, now + access_ttl as i64 * 1000, now, sc, res],
                )?;
                c.execute(
                    "INSERT INTO oauth_grants_tokens (token_hash, kind, credential_id, expires_at, created_at, scopes, resource) VALUES (?1, 'refresh', ?2, ?3, ?4, ?5, ?6)",
                    params![rh, cred, now + refresh_ttl_ms, now, sc, res],
                )?;
                c.execute("UPDATE credentials SET expires_at = ?2 WHERE credential_id = ?1", params![cred, now + refresh_ttl_ms])?;
                // Keep the token table small: drop long-expired rows for this grant.
                c.execute("DELETE FROM oauth_grants_tokens WHERE credential_id = ?1 AND expires_at < ?2", params![cred, now - time::DAY_MS])?;
                Ok(())
            })
            .map_err(|e| OAuthError::new("server_error", e.message))?;
        Ok(TokenResponse {
            access_token: access,
            token_type: "Bearer",
            expires_in: access_ttl,
            refresh_token: refresh,
            scope: scopes.join(" "),
        })
    }

    /// RFC 7009 revocation: revoking a refresh token revokes the grant.
    pub fn oauth_revoke(&self, token: &str) -> Option<String> {
        let hash = self.hash(token);
        let row: Option<(String, String)> = self
            .db()
            .read_sync(|c| {
                Ok(c.query_row(
                    "SELECT credential_id, kind FROM oauth_grants_tokens WHERE token_hash = ?1",
                    [&hash],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?)
            })
            .ok()
            .flatten();
        let (cred, kind) = row?;
        if kind == "refresh" {
            self.revoke_credential(&cred).ok()
        } else {
            let h = hash.clone();
            let _ = self.db().write_sync(move |c| {
                c.execute(
                    "UPDATE oauth_grants_tokens SET revoked_at = ?2 WHERE token_hash = ?1",
                    params![h, time::now_ms()],
                )?;
                Ok(())
            });
            None
        }
    }
}

fn view_of(pa: &PendingAuthorization) -> PendingConnectionView {
    PendingConnectionView {
        request_id: pa.request_id.clone(),
        created_at: pa.created_at,
        expires_at: pa.expires_at,
        oauth_client_id: pa.oauth_client_id.clone(),
        client_name: pa.client_name.clone(),
        redirect_uri: pa.redirect_uri.clone(),
        redirect_is_known_chatgpt: KNOWN_CHATGPT_REDIRECTS
            .iter()
            .any(|k| pa.redirect_uri.starts_with(k)),
        scopes: pa.scopes.clone(),
        resource: pa.resource.clone(),
        pairing_code: pa.pairing_code.clone(),
        remote_addr: pa.remote_addr.clone(),
        suggested_client_id: pa.suggested_client_id.clone(),
        status: match &pa.decision {
            None => "pending".into(),
            Some(d) if d.approve => "approved".into(),
            Some(_) => "denied".into(),
        },
    }
}

fn ulid_like() -> String {
    ids::new_id("x")
        .trim_start_matches("x_")
        .to_ascii_lowercase()
}
