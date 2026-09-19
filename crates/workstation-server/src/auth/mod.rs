//! Authentication: local principals, manual bearer tokens and OAuth grants.
//!
//! Local Pilot's `client_id` (principal identity, `cl_...`) is distinct from
//! an OAuth protocol `client_id`. Both authenticators resolve a request to a
//! [`Principal`] and then share the same policy, session, rate-limit and audit
//! paths. Tokens are stored only as keyed hashes.

pub mod oauth;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use workstation_core::db::Db;
use workstation_core::hashing::{random_token, token_hash};
use workstation_core::{ErrorCode, LpError, LpResult, ids, time};

pub const SCOPE_READ: &str = "workstation:read";
pub const SCOPE_WRITE: &str = "workstation:write";
pub const SCOPE_EXECUTE: &str = "workstation:execute";
pub const ALL_SCOPES: &[&str] = &[SCOPE_READ, SCOPE_WRITE, SCOPE_EXECUTE];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    OAuth,
    ManualToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// Local Pilot principal (`cl_...`).
    pub client_id: String,
    pub display_name: String,
    /// Manual token ID or OAuth grant ID (`cred_...`).
    pub credential_id: String,
    pub auth_method: AuthMethod,
    pub scopes: Vec<String>,
    pub oauth_client_id: Option<String>,
}

impl Principal {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRow {
    pub client_id: String,
    pub display_name: String,
    pub vendor_label: Option<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub last_client_info: Option<String>,
    pub last_protocol_version: Option<String>,
    pub last_remote_addr: Option<String>,
    pub credentials: Vec<CredentialRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRow {
    pub credential_id: String,
    pub client_id: String,
    pub kind: String,
    pub token_hint: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub enabled: bool,
    pub oauth_client_id: Option<String>,
    pub label: Option<String>,
    /// For OAuth grants: latest refresh-token expiry.
    pub refresh_expires_at: Option<i64>,
}

/// Why a bearer token was rejected (drives the `WWW-Authenticate` challenge).
#[derive(Debug, Clone)]
pub struct AuthFailure {
    pub error: &'static str,
    pub description: String,
    pub code: ErrorCode,
}

impl AuthFailure {
    fn invalid(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_token",
            description: description.into(),
            code: ErrorCode::AuthenticationFailed,
        }
    }
}

pub struct AuthService {
    db: Db,
    pepper: Vec<u8>,
    pub oauth: oauth::OAuthState,
}

fn parse_scopes(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

pub fn normalize_scopes(requested: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = match requested {
        Some(s) if !s.trim().is_empty() => s
            .split_whitespace()
            .filter(|x| ALL_SCOPES.contains(x))
            .map(|x| x.to_string())
            .collect(),
        _ => ALL_SCOPES.iter().map(|s| s.to_string()).collect(),
    };
    out.sort();
    out.dedup();
    out
}

impl AuthService {
    pub fn new(db: Db, pepper: Vec<u8>) -> Self {
        Self {
            db,
            pepper,
            oauth: oauth::OAuthState::default(),
        }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn hash(&self, token: &str) -> String {
        token_hash(&self.pepper, token)
    }

    // ------------------------------------------------------------ clients

    pub fn create_client(
        &self,
        display_name: &str,
        vendor_label: Option<&str>,
    ) -> LpResult<String> {
        let id = ids::client_id();
        let name = display_name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err(LpError::invalid("client name must be 1-100 characters"));
        }
        let (id2, name, vendor) = (
            id.clone(),
            name.to_string(),
            vendor_label.map(|s| s.to_string()),
        );
        self.db.write_sync(|c| {
            c.execute(
                "INSERT INTO clients (client_id, display_name, vendor_label, enabled, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
                params![id2, name, vendor, time::now_ms()],
            )?;
            Ok(())
        })?;
        Ok(id)
    }

    pub fn list_clients(&self) -> LpResult<Vec<ClientRow>> {
        self.db.read_sync(|c| {
            let mut stmt = c.prepare("SELECT client_id, display_name, vendor_label, enabled, created_at, last_seen_at, last_client_info, last_protocol_version, last_remote_addr FROM clients ORDER BY created_at")?;
            let mut clients: Vec<ClientRow> = stmt
                .query_map([], |r| {
                    Ok(ClientRow {
                        client_id: r.get(0)?,
                        display_name: r.get(1)?,
                        vendor_label: r.get(2)?,
                        enabled: r.get(3)?,
                        created_at: r.get(4)?,
                        last_seen_at: r.get(5)?,
                        last_client_info: r.get(6)?,
                        last_protocol_version: r.get(7)?,
                        last_remote_addr: r.get(8)?,
                        credentials: Vec::new(),
                    })
                })?
                .collect::<Result<_, _>>()?;
            let mut stmt = c.prepare(
                "SELECT credential_id, client_id, kind, token_hint, scopes, created_at, last_used_at, expires_at, revoked_at, enabled, oauth_client_id, label,
                   (SELECT MAX(expires_at) FROM oauth_grants_tokens t WHERE t.credential_id = credentials.credential_id AND t.kind = 'refresh' AND t.used_at IS NULL AND t.revoked_at IS NULL)
                 FROM credentials ORDER BY created_at",
            )?;
            let creds: Vec<CredentialRow> = stmt
                .query_map([], |r| {
                    Ok(CredentialRow {
                        credential_id: r.get(0)?,
                        client_id: r.get(1)?,
                        kind: r.get(2)?,
                        token_hint: r.get(3)?,
                        scopes: parse_scopes(&r.get::<_, String>(4)?),
                        created_at: r.get(5)?,
                        last_used_at: r.get(6)?,
                        expires_at: r.get(7)?,
                        revoked_at: r.get(8)?,
                        enabled: r.get(9)?,
                        oauth_client_id: r.get(10)?,
                        label: r.get(11)?,
                        refresh_expires_at: r.get(12)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            for cr in creds {
                if let Some(cl) = clients.iter_mut().find(|c| c.client_id == cr.client_id) {
                    cl.credentials.push(cr);
                }
            }
            Ok(clients)
        })
    }

    pub fn client(&self, client_id: &str) -> LpResult<Option<ClientRow>> {
        Ok(self
            .list_clients()?
            .into_iter()
            .find(|c| c.client_id == client_id))
    }

    pub fn set_client_enabled(&self, client_id: &str, enabled: bool) -> LpResult<()> {
        let id = client_id.to_string();
        let n = self.db.write_sync(|c| {
            Ok(c.execute(
                "UPDATE clients SET enabled = ?2 WHERE client_id = ?1",
                params![id, enabled],
            )?)
        })?;
        if n == 0 {
            return Err(LpError::not_found("unknown client"));
        }
        Ok(())
    }

    pub fn rename_client(&self, client_id: &str, name: &str) -> LpResult<()> {
        let name = name.trim().to_string();
        if name.is_empty() || name.len() > 100 {
            return Err(LpError::invalid("client name must be 1-100 characters"));
        }
        let id = client_id.to_string();
        self.db.write_sync(|c| {
            c.execute(
                "UPDATE clients SET display_name = ?2 WHERE client_id = ?1",
                params![id, name],
            )?;
            Ok(())
        })
    }

    pub fn record_seen(
        &self,
        client_id: &str,
        client_info: Option<String>,
        protocol: Option<String>,
        remote: Option<String>,
    ) {
        let id = client_id.to_string();
        let _ = self.db.write_sync(|c| {
            c.execute(
                "UPDATE clients SET last_seen_at = ?2, last_client_info = COALESCE(?3, last_client_info), last_protocol_version = COALESCE(?4, last_protocol_version), last_remote_addr = COALESCE(?5, last_remote_addr) WHERE client_id = ?1",
                params![id, time::now_ms(), client_info, protocol, remote],
            )?;
            Ok(())
        });
    }

    // ------------------------------------------------------ manual tokens

    /// Create a manual token. The plaintext is returned once and never stored.
    pub fn create_manual_token(
        &self,
        client_id: &str,
        scopes: &[String],
        label: Option<&str>,
        expires_in_days: Option<u64>,
    ) -> LpResult<(String, String)> {
        let token = random_token("lpm");
        let hash = self.hash(&token);
        let cred = ids::credential_id();
        let hint = format!("lpm_…{}", &token[token.len() - 4..]);
        let scopes = if scopes.is_empty() {
            normalize_scopes(None)
        } else {
            normalize_scopes(Some(&scopes.join(" ")))
        };
        let expires = expires_in_days.map(|d| time::now_ms() + d as i64 * time::DAY_MS);
        let (cred2, cid, label) = (
            cred.clone(),
            client_id.to_string(),
            label.map(|s| s.to_string()),
        );
        self.db.write_sync(|c| {
            let exists: Option<String> = c
                .query_row("SELECT client_id FROM clients WHERE client_id = ?1", [&cid], |r| r.get(0))
                .optional()?;
            if exists.is_none() {
                return Err(LpError::not_found("unknown client"));
            }
            c.execute(
                "INSERT INTO credentials (credential_id, client_id, kind, token_hash, token_hint, scopes, created_at, expires_at, enabled, label) VALUES (?1, ?2, 'manual_token', ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                params![cred2, cid, hash, hint, scopes.join(" "), time::now_ms(), expires, label],
            )?;
            Ok(())
        })?;
        Ok((cred, token))
    }

    /// Rotate a manual token: same principal, new secret, old one revoked.
    pub fn rotate_manual_token(&self, credential_id: &str) -> LpResult<(String, String)> {
        let id = credential_id.to_string();
        let row: Option<(String, String, Option<String>, Option<i64>)> = self.db.read_sync(|c| {
            Ok(c.query_row(
                "SELECT client_id, scopes, label, expires_at FROM credentials WHERE credential_id = ?1 AND kind = 'manual_token' AND revoked_at IS NULL",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?)
        })?;
        let (client_id, scopes, label, expires) =
            row.ok_or_else(|| LpError::not_found("unknown or revoked token"))?;
        let days = expires.map(|e| ((e - time::now_ms()).max(time::DAY_MS) / time::DAY_MS) as u64);
        let new =
            self.create_manual_token(&client_id, &parse_scopes(&scopes), label.as_deref(), days)?;
        self.revoke_credential(credential_id)?;
        Ok(new)
    }

    pub fn revoke_credential(&self, credential_id: &str) -> LpResult<String> {
        let id = credential_id.to_string();
        self.db.write_sync(|c| {
            let client: Option<String> = c
                .query_row("SELECT client_id FROM credentials WHERE credential_id = ?1", [&id], |r| r.get(0))
                .optional()?;
            let client = client.ok_or_else(|| LpError::not_found("unknown credential"))?;
            let now = time::now_ms();
            c.execute("UPDATE credentials SET revoked_at = COALESCE(revoked_at, ?2), enabled = 0 WHERE credential_id = ?1", params![id, now])?;
            c.execute("UPDATE oauth_grants_tokens SET revoked_at = COALESCE(revoked_at, ?2) WHERE credential_id = ?1", params![id, now])?;
            Ok(client)
        })
    }

    pub fn set_credential_enabled(&self, credential_id: &str, enabled: bool) -> LpResult<String> {
        let id = credential_id.to_string();
        self.db.write_sync(|c| {
            let client: Option<String> = c
                .query_row(
                    "SELECT client_id FROM credentials WHERE credential_id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?;
            let client = client.ok_or_else(|| LpError::not_found("unknown credential"))?;
            c.execute(
                "UPDATE credentials SET enabled = ?2 WHERE credential_id = ?1",
                params![id, enabled],
            )?;
            Ok(client)
        })
    }

    /// Revoke every credential of a client.
    pub fn revoke_client_credentials(&self, client_id: &str) -> LpResult<usize> {
        let id = client_id.to_string();
        self.db.write_sync(|c| {
            let now = time::now_ms();
            c.execute(
                "UPDATE oauth_grants_tokens SET revoked_at = COALESCE(revoked_at, ?2) WHERE credential_id IN (SELECT credential_id FROM credentials WHERE client_id = ?1)",
                params![id, now],
            )?;
            Ok(c.execute("UPDATE credentials SET revoked_at = COALESCE(revoked_at, ?2), enabled = 0 WHERE client_id = ?1 AND revoked_at IS NULL", params![id, now])?)
        })
    }

    // ----------------------------------------------------- authentication

    /// Validate a bearer token (manual or OAuth access token). Checks live
    /// revocation, expiry, enabled state and — for OAuth — resource binding.
    pub fn authenticate_bearer(
        &self,
        token: &str,
        expected_resource: &str,
    ) -> Result<Principal, AuthFailure> {
        let token = token.trim();
        if token.len() < 20 || token.len() > 512 {
            return Err(AuthFailure::invalid("malformed token"));
        }
        let hash = self.hash(token);
        let now = time::now_ms();
        if token.starts_with("lpm_") {
            let row = self
                .db
                .read_sync(|c| {
                    Ok(c.query_row(
                        "SELECT cr.credential_id, cr.client_id, cl.display_name, cr.scopes, cr.expires_at, cr.revoked_at, cr.enabled, cl.enabled
                         FROM credentials cr JOIN clients cl ON cl.client_id = cr.client_id
                         WHERE cr.token_hash = ?1 AND cr.kind = 'manual_token'",
                        [&hash],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, String>(2)?,
                                r.get::<_, String>(3)?,
                                r.get::<_, Option<i64>>(4)?,
                                r.get::<_, Option<i64>>(5)?,
                                r.get::<_, bool>(6)?,
                                r.get::<_, bool>(7)?,
                            ))
                        },
                    )
                    .optional()?)
                })
                .map_err(|_| AuthFailure::invalid("token lookup failed"))?;
            let Some((cred, client, name, scopes, expires, revoked, cred_enabled, client_enabled)) =
                row
            else {
                return Err(AuthFailure::invalid("unknown token"));
            };
            if revoked.is_some() {
                return Err(AuthFailure::invalid("token revoked"));
            }
            if expires.map(|e| e < now).unwrap_or(false) {
                return Err(AuthFailure::invalid("token expired"));
            }
            if !cred_enabled || !client_enabled {
                return Err(AuthFailure {
                    error: "invalid_token",
                    description: "client or credential disabled".into(),
                    code: ErrorCode::ClientDisabled,
                });
            }
            self.touch_credential(&cred);
            return Ok(Principal {
                client_id: client,
                display_name: name,
                credential_id: cred,
                auth_method: AuthMethod::ManualToken,
                scopes: parse_scopes(&scopes),
                oauth_client_id: None,
            });
        }
        if token.starts_with("lpa_") {
            let row = self
                .db
                .read_sync(|c| {
                    Ok(c.query_row(
                        "SELECT t.credential_id, t.expires_at, t.revoked_at, t.scopes, t.resource, cr.client_id, cl.display_name, cr.revoked_at, cr.enabled, cl.enabled, cr.oauth_client_id
                         FROM oauth_grants_tokens t JOIN credentials cr ON cr.credential_id = t.credential_id JOIN clients cl ON cl.client_id = cr.client_id
                         WHERE t.token_hash = ?1 AND t.kind = 'access'",
                        [&hash],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, i64>(1)?,
                                r.get::<_, Option<i64>>(2)?,
                                r.get::<_, String>(3)?,
                                r.get::<_, String>(4)?,
                                r.get::<_, String>(5)?,
                                r.get::<_, String>(6)?,
                                r.get::<_, Option<i64>>(7)?,
                                r.get::<_, bool>(8)?,
                                r.get::<_, bool>(9)?,
                                r.get::<_, Option<String>>(10)?,
                            ))
                        },
                    )
                    .optional()?)
                })
                .map_err(|_| AuthFailure::invalid("token lookup failed"))?;
            let Some((
                cred,
                expires,
                revoked,
                scopes,
                resource,
                client,
                name,
                cred_revoked,
                cred_enabled,
                client_enabled,
                oauth_client,
            )) = row
            else {
                return Err(AuthFailure::invalid("unknown token"));
            };
            if revoked.is_some() || cred_revoked.is_some() {
                return Err(AuthFailure::invalid("token revoked"));
            }
            if expires < now {
                return Err(AuthFailure::invalid("token expired"));
            }
            if !oauth::resource_matches(&resource, expected_resource) {
                return Err(AuthFailure::invalid(
                    "token audience does not match this server",
                ));
            }
            if !cred_enabled || !client_enabled {
                return Err(AuthFailure {
                    error: "invalid_token",
                    description: "client or credential disabled".into(),
                    code: ErrorCode::ClientDisabled,
                });
            }
            self.touch_credential(&cred);
            return Ok(Principal {
                client_id: client,
                display_name: name,
                credential_id: cred,
                auth_method: AuthMethod::OAuth,
                scopes: parse_scopes(&scopes),
                oauth_client_id: oauth_client,
            });
        }
        Err(AuthFailure::invalid("unrecognized token type"))
    }

    fn touch_credential(&self, credential_id: &str) {
        let id = credential_id.to_string();
        let now = time::now_ms();
        let _ = self.db.write_sync(|c| {
            c.execute(
                "UPDATE credentials SET last_used_at = ?2 WHERE credential_id = ?1 AND (last_used_at IS NULL OR last_used_at < ?2 - 30000)",
                params![id, now],
            )?;
            Ok(())
        });
    }

    pub fn log_connection_event(
        &self,
        client_id: Option<&str>,
        credential_id: Option<&str>,
        event: &str,
        detail: Option<&str>,
        remote: Option<&str>,
    ) {
        let (a, b, e, d, r) = (
            client_id.map(|s| s.to_string()),
            credential_id.map(|s| s.to_string()),
            event.to_string(),
            detail.map(|s| s.to_string()),
            remote.map(|s| s.to_string()),
        );
        let _ = self.db.write_sync(|c| {
            c.execute(
                "INSERT INTO connection_events (ts, client_id, credential_id, event, detail, remote_addr) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![time::now_ms(), a, b, e, d, r],
            )?;
            Ok(())
        });
    }
}
