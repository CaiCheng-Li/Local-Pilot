//! Schema of the control database (`data\local-pilot.db`). Plaintext tokens
//! and authorization codes are never stored; pending operation payloads live
//! in memory only and are discarded on restart.

use workstation_core::db::Migration;

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "control_init",
    sql: r#"
CREATE TABLE settings_kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE clients (
    client_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    vendor_label TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    last_client_info TEXT,
    last_protocol_version TEXT,
    last_remote_addr TEXT
);

CREATE TABLE credentials (
    credential_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    kind TEXT NOT NULL,
    token_hash TEXT UNIQUE,
    token_hint TEXT,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER,
    revoked_at INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    oauth_client_id TEXT,
    resource TEXT,
    label TEXT
);
CREATE INDEX idx_credentials_client ON credentials(client_id);

CREATE TABLE oauth_clients (
    oauth_client_id TEXT PRIMARY KEY,
    client_name TEXT,
    redirect_uris TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL,
    secret_hash TEXT,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    software_id TEXT,
    registration_addr TEXT,
    local_client_id TEXT
);

CREATE TABLE oauth_grants_tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    used_at INTEGER,
    revoked_at INTEGER,
    scopes TEXT NOT NULL,
    resource TEXT NOT NULL
);
CREATE INDEX idx_tokens_credential ON oauth_grants_tokens(credential_id);

CREATE TABLE application_sessions (
    session_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_activity_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    ended_at INTEGER,
    end_reason TEXT
);
CREATE INDEX idx_sessions_client ON application_sessions(client_id);

CREATE TABLE session_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    label TEXT NOT NULL,
    approval_id TEXT,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_display_name TEXT,
    session_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk TEXT NOT NULL,
    requires_admin INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    decided_at INTEGER,
    decision_note TEXT,
    execution_id TEXT,
    policy_revision INTEGER NOT NULL,
    operation_digest TEXT NOT NULL,
    required_scopes TEXT NOT NULL,
    session_scope TEXT
);
CREATE INDEX idx_approvals_status ON approvals(status, created_at);
CREATE INDEX idx_approvals_client ON approvals(client_id, created_at);

CREATE TABLE operation_executions (
    execution_id TEXT PRIMARY KEY,
    approval_id TEXT,
    client_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    task_id TEXT,
    created_at INTEGER NOT NULL,
    completed_at INTEGER
);

CREATE TABLE idempotency_keys (
    client_id TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (client_id, idem_key)
);

CREATE TABLE connection_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    client_id TEXT,
    credential_id TEXT,
    event TEXT NOT NULL,
    detail TEXT,
    remote_addr TEXT
);
CREATE INDEX idx_connection_events_ts ON connection_events(ts);

CREATE TABLE project_locks (
    project_id TEXT PRIMARY KEY,
    holder_client_id TEXT NOT NULL,
    holder_task_id TEXT,
    acquired_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
"#,
}];
