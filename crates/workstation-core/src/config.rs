//! Versioned settings schema with migrations.
//!
//! A missing file yields safe defaults. A corrupt or unknown-version file never
//! yields "allow everything": the loader returns safe defaults together with a
//! [`ConfigFault`], and callers must fail closed for write/admin operations and
//! keep remote access disabled until the user repairs or resets settings.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{LpError, LpResult};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub schema_version: u32,
    /// Incremented on every security-relevant change. Approvals are bound to it.
    pub policy_revision: u64,
    pub setup_completed: bool,
    pub general: GeneralSettings,
    pub network: NetworkSettings,
    pub trusted_workspace: TrustedWorkspaceSettings,
    pub protected_paths: ProtectedPathSettings,
    pub auth: AuthSettings,
    pub sessions: SessionSettings,
    pub concurrency: ConcurrencySettings,
    pub process: ProcessSettings,
    pub shell_protection: ShellProtectionSettings,
    pub git: GitSettings,
    pub github: GithubSettings,
    pub packages: PackageSettings,
    pub cache_temp: CacheTempSettings,
    pub environment: EnvironmentSettings,
    pub external_writes: ExternalWriteSettings,
    pub audit: AuditSettings,
    pub data_shared: DataSharedSettings,
    pub limits: LimitSettings,
    pub notifications: NotificationSettings,
    pub updates: UpdateSettings,
    pub advanced: AdvancedSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            policy_revision: 1,
            setup_completed: false,
            general: Default::default(),
            network: Default::default(),
            trusted_workspace: Default::default(),
            protected_paths: Default::default(),
            auth: Default::default(),
            sessions: Default::default(),
            concurrency: Default::default(),
            process: Default::default(),
            shell_protection: Default::default(),
            git: Default::default(),
            github: Default::default(),
            packages: Default::default(),
            cache_temp: Default::default(),
            environment: Default::default(),
            external_writes: Default::default(),
            audit: Default::default(),
            data_shared: Default::default(),
            limits: Default::default(),
            notifications: Default::default(),
            updates: Default::default(),
            advanced: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GeneralSettings {
    pub autostart: bool,
    pub close_to_tray: bool,
    pub start_minimized: bool,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            autostart: true,
            close_to_tray: true,
            start_minimized: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedProxy {
    /// No forwarded headers are trusted.
    None,
    /// `CF-Connecting-IP` is recorded as display metadata only.
    CloudflareTunnel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NetworkSettings {
    /// Loopback only by default. Changing this is an advanced, audited action.
    pub bind_address: String,
    /// 0 means "not chosen yet"; setup picks a free port once and persists it.
    pub port: u16,
    /// External URL of the MCP endpoint, e.g. `https://mcp.example.com/mcp`.
    pub public_mcp_url: Option<String>,
    pub trusted_proxy: TrustedProxy,
    pub max_request_body_bytes: usize,
    /// Additional Host header values accepted besides loopback and the public host.
    pub extra_allowed_hosts: Vec<String>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".into(),
            port: 0,
            public_mcp_url: None,
            trusted_proxy: TrustedProxy::None,
            max_request_body_bytes: 8 * 1024 * 1024,
            extra_allowed_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TrustedWorkspaceSettings {
    /// Test/advanced override. Normal installs resolve `<Documents>\Projects`.
    pub root_override: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProtectedPathSettings {
    /// Extra protected directories (environment variables like `%USERPROFILE%` are expanded).
    pub extra_directories: Vec<String>,
    /// Extra protected file-name glob patterns (case-insensitive).
    pub extra_file_patterns: Vec<String>,
    /// File-name patterns that are never protected (known non-secret templates).
    pub exceptions: Vec<String>,
    /// Allow direct reads of project `.env` files. Default OFF.
    pub allow_env_file_reads: bool,
    /// Exact canonical paths whose protected status is waived for structured
    /// mutation (not for reads). Default empty.
    pub mutation_exceptions: Vec<String>,
    /// Extensions treated as source code for the generic-word patterns
    /// (`*token*`, `credentials*`, `secrets*`) so that e.g. `tokenizer.rs` stays usable.
    pub generic_pattern_source_extensions: Vec<String>,
}

impl Default for ProtectedPathSettings {
    fn default() -> Self {
        Self {
            extra_directories: Vec::new(),
            extra_file_patterns: Vec::new(),
            exceptions: vec![
                ".env.example".into(),
                ".env.sample".into(),
                ".env.template".into(),
                ".env.dist".into(),
            ],
            allow_env_file_reads: false,
            mutation_exceptions: Vec::new(),
            generic_pattern_source_extensions: [
                "rs", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "go", "java", "kt", "c", "cc",
                "cpp", "h", "hpp", "cs", "rb", "php", "swift", "scala", "md", "mdx", "html", "css",
                "scss", "vue", "svelte", "dart", "lua", "sql", "snap", "proto", "graphql",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AuthSettings {
    pub access_token_ttl_seconds: u64,
    pub refresh_token_ttl_days: u64,
    pub authorization_code_ttl_seconds: u64,
    pub pending_connection_ttl_seconds: u64,
    pub allow_dynamic_client_registration: bool,
    pub max_registered_clients: usize,
    pub max_pending_connection_requests: usize,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_days: 30,
            authorization_code_ttl_seconds: 120,
            pending_connection_ttl_seconds: 600,
            allow_dynamic_client_registration: true,
            max_registered_clients: 50,
            max_pending_connection_requests: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SessionSettings {
    pub idle_timeout_minutes: u64,
    pub absolute_lifetime_hours: u64,
    pub pending_approval_minutes: u64,
    pub terminate_tasks_on_revoke: bool,
    pub terminate_tasks_on_expiry: bool,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            idle_timeout_minutes: 30,
            absolute_lifetime_hours: 8,
            pending_approval_minutes: 10,
            terminate_tasks_on_revoke: true,
            terminate_tasks_on_expiry: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ConcurrencySettings {
    pub allow_multiple_agents: bool,
    pub allow_any_authenticated_client: bool,
    /// Local principal IDs allowed when `allow_any_authenticated_client` is off.
    pub allowed_client_ids: Vec<String>,
    pub max_simultaneous_clients: usize,
    pub max_tasks_per_client: usize,
    pub max_concurrent_calls_per_client: usize,
    pub requests_per_minute: u32,
    pub allow_multiple_writers_per_project: bool,
    pub writer_lease_seconds: u64,
}

impl Default for ConcurrencySettings {
    fn default() -> Self {
        Self {
            allow_multiple_agents: true,
            allow_any_authenticated_client: true,
            allowed_client_ids: Vec::new(),
            max_simultaneous_clients: 8,
            max_tasks_per_client: 8,
            max_concurrent_calls_per_client: 16,
            requests_per_minute: 600,
            allow_multiple_writers_per_project: false,
            writer_lease_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProcessSettings {
    pub powershell_executable: String,
    pub default_timeout_seconds: u64,
    pub max_timeout_seconds: u64,
    pub foreground_wait_seconds: u64,
    pub max_output_bytes_per_task: u64,
    pub terminate_tasks_on_restart: bool,
    pub max_command_length: usize,
}

impl Default for ProcessSettings {
    fn default() -> Self {
        Self {
            powershell_executable: "powershell.exe".into(),
            default_timeout_seconds: 30 * 60,
            max_timeout_seconds: 24 * 60 * 60,
            foreground_wait_seconds: 60,
            max_output_bytes_per_task: 16 * 1024 * 1024,
            terminate_tasks_on_restart: true,
            max_command_length: 16 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ShellProtectionSettings {
    /// Best-effort shell preflight checks. Default ON. Local UI only.
    pub enabled: bool,
}

impl Default for ShellProtectionSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GitSettings {
    /// "Allow automatic pushes to default branch". Default OFF.
    pub allow_auto_push_default_branch: bool,
    /// "Automatically allow destructive Git operations". Default OFF.
    pub allow_destructive: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GithubSettings {
    /// Extra attribution phrases (regex, case-insensitive) to block.
    pub extra_blocked_attribution_patterns: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallPolicy {
    RequireApproval,
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PackageSettings {
    pub system_install_policy: InstallPolicy,
}

impl Default for PackageSettings {
    fn default() -> Self {
        Self {
            system_install_policy: InstallPolicy::RequireApproval,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CacheTempSettings {
    pub quota_mb: u64,
    pub finished_task_retention_hours: u64,
    /// Package-manager cache variables redirected into the tool cache.
    pub redirect_package_caches: bool,
}

impl Default for CacheTempSettings {
    fn default() -> Self {
        Self {
            quota_mb: 10 * 1024,
            finished_task_retention_hours: 24,
            redirect_package_caches: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSecretGrant {
    pub id: String,
    /// Variable names this tool may inherit.
    pub variables: Vec<String>,
    /// Canonical executable path the grant is bound to.
    pub executable_path: String,
    /// Executable identity recorded when the grant was created (size + mtime + sha256).
    pub executable_sha256: String,
    /// Optional canonical project directory scope.
    pub project_scope: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct EnvironmentSettings {
    /// Variable names explicitly allowed to be inherited (overrides secret-name detection).
    pub allowed: Vec<String>,
    /// Variable names never inherited.
    pub denied: Vec<String>,
    /// Allowed variables whose values may be shown to agents.
    pub disclosable: Vec<String>,
    pub tool_grants: Vec<ToolSecretGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalWriteGrant {
    pub id: String,
    /// Canonical directory prefix.
    pub path_prefix: String,
    pub allow_delete: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ExternalWriteSettings {
    /// Locally configured policy grants for structured external writes.
    pub grants: Vec<ExternalWriteGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AuditSettings {
    pub retention_days: u64,
    pub max_size_mb: u64,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            retention_days: 30,
            max_size_mb: 512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DataSharedSettings {
    pub retention_days: u64,
    pub max_size_mb: u64,
    /// Latest events always retained per active session under size pressure.
    pub reserved_events_per_session: u64,
    /// Maximum payload bytes stored for one reserved event.
    pub max_reserved_payload_bytes: u64,
}

impl Default for DataSharedSettings {
    fn default() -> Self {
        Self {
            retention_days: 30,
            max_size_mb: 250,
            reserved_events_per_session: 20,
            max_reserved_payload_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LimitSettings {
    pub max_read_bytes: u64,
    pub max_write_bytes: u64,
    pub max_get_many_items: usize,
    pub max_search_results: usize,
    pub max_list_entries: usize,
    pub max_task_output_bytes_per_call: u64,
    pub max_result_bytes: u64,
}

impl Default for LimitSettings {
    fn default() -> Self {
        Self {
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 8 * 1024 * 1024,
            max_get_many_items: 200,
            max_search_results: 500,
            max_list_entries: 2000,
            max_task_output_bytes_per_call: 256 * 1024,
            max_result_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub approvals: bool,
    pub connections: bool,
    pub task_failures: bool,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            approvals: true,
            connections: true,
            task_failures: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UpdateSettings {
    pub check_automatically: bool,
    pub install_automatically: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            check_automatically: true,
            install_automatically: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AdvancedSettings {
    pub advanced_mode: bool,
}

/// Why settings could not be loaded as written.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigFault {
    pub message: String,
    pub backup_path: Option<PathBuf>,
}

pub struct LoadedSettings {
    pub settings: Settings,
    pub fault: Option<ConfigFault>,
    pub existed: bool,
}

/// Apply stepwise migrations to a raw settings document.
pub fn migrate(mut value: serde_json::Value) -> LpResult<Settings> {
    let version = value
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    if version > SCHEMA_VERSION {
        return Err(LpError::new(
            crate::ErrorCode::ConfigFault,
            format!("settings schema version {version} is newer than supported {SCHEMA_VERSION}"),
        ));
    }
    if version == 0 {
        // Pre-release drafts had no version marker; fields map one-to-one.
        if let Some(obj) = value.as_object_mut() {
            obj.insert("schema_version".into(), serde_json::json!(1));
        }
    }
    // Future: `if version < 2 { ... }`
    let mut settings: Settings = serde_json::from_value(value)
        .map_err(|e| LpError::new(crate::ErrorCode::ConfigFault, format!("settings: {e}")))?;
    settings.schema_version = SCHEMA_VERSION;
    validate(&settings)?;
    Ok(settings)
}

/// Reject values that would silently weaken policy or break the service.
pub fn validate(s: &Settings) -> LpResult<()> {
    let bad = |m: &str| Err(LpError::new(crate::ErrorCode::ConfigFault, m.to_string()));
    if s.sessions.idle_timeout_minutes == 0 || s.sessions.idle_timeout_minutes > 7 * 24 * 60 {
        return bad("sessions.idle_timeout_minutes must be between 1 and 10080");
    }
    if s.sessions.absolute_lifetime_hours == 0 || s.sessions.absolute_lifetime_hours > 24 * 30 {
        return bad("sessions.absolute_lifetime_hours must be between 1 and 720");
    }
    if s.sessions.pending_approval_minutes == 0 || s.sessions.pending_approval_minutes > 24 * 60 {
        return bad("sessions.pending_approval_minutes must be between 1 and 1440");
    }
    if s.data_shared.max_size_mb < 16 {
        return bad("data_shared.max_size_mb must be at least 16");
    }
    if s.audit.max_size_mb < 16 {
        return bad("audit.max_size_mb must be at least 16");
    }
    if s.data_shared.retention_days == 0 || s.audit.retention_days == 0 {
        return bad("retention must be at least one day");
    }
    let reserved = s.data_shared.reserved_events_per_session
        * s.data_shared.max_reserved_payload_bytes
        * s.concurrency.max_simultaneous_clients as u64;
    if reserved > s.data_shared.max_size_mb * 1024 * 1024 / 2 {
        return bad(
            "data_shared reservations (events per session x payload size x max clients) must fit in half of the Data Shared size budget",
        );
    }
    if s.concurrency.max_simultaneous_clients == 0 || s.concurrency.max_tasks_per_client == 0 {
        return bad("concurrency limits must be at least 1");
    }
    if s.limits.max_read_bytes == 0 || s.limits.max_read_bytes > 64 * 1024 * 1024 {
        return bad("limits.max_read_bytes must be between 1 byte and 64 MiB");
    }
    if let Some(url) = &s.network.public_mcp_url {
        validate_public_url(url)?;
    }
    let ip: Result<std::net::IpAddr, _> = s.network.bind_address.parse();
    if ip.is_err() {
        return bad("network.bind_address must be an IP address");
    }
    Ok(())
}

pub fn validate_public_url(url: &str) -> LpResult<url::Url> {
    let parsed = url::Url::parse(url)
        .map_err(|e| LpError::invalid(format!("public MCP URL is not a valid URL: {e}")))?;
    if parsed.scheme() != "https" {
        let loopback = matches!(parsed.host_str(), Some("localhost") | Some("127.0.0.1"));
        if !(parsed.scheme() == "http" && loopback) {
            return Err(LpError::invalid("public MCP URL must use https"));
        }
    }
    if parsed.host_str().is_none() {
        return Err(LpError::invalid("public MCP URL must include a host"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpError::invalid(
            "public MCP URL must not include a query or fragment",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpError::invalid(
            "public MCP URL must not embed credentials",
        ));
    }
    if !parsed.path().ends_with("/mcp") {
        return Err(LpError::invalid("public MCP URL path must end with /mcp"));
    }
    Ok(parsed)
}

/// Load settings from disk, falling back to safe defaults plus a fault marker.
pub fn load(path: &Path) -> LoadedSettings {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return LoadedSettings {
                settings: Settings::default(),
                fault: None,
                existed: false,
            };
        }
        Err(e) => {
            return LoadedSettings {
                settings: Settings::default(),
                fault: Some(ConfigFault {
                    message: format!("settings could not be read: {e}"),
                    backup_path: None,
                }),
                existed: true,
            };
        }
    };
    let parsed = serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|e| LpError::new(crate::ErrorCode::ConfigFault, format!("settings JSON: {e}")))
        .and_then(migrate);
    match parsed {
        Ok(settings) => LoadedSettings {
            settings,
            fault: None,
            existed: true,
        },
        Err(err) => {
            let backup = path.with_extension(format!(
                "corrupt-{}.json",
                chrono::Utc::now().format("%Y%m%d%H%M%S")
            ));
            let backup_path = std::fs::copy(path, &backup).ok().map(|_| backup);
            LoadedSettings {
                settings: Settings::default(),
                fault: Some(ConfigFault {
                    message: err.message,
                    backup_path,
                }),
                existed: true,
            }
        }
    }
}

/// Atomically persist settings (write temp file, flush, rename).
pub fn save(path: &Path, settings: &Settings) -> LpResult<()> {
    validate(settings)?;
    let json = serde_json::to_vec_pretty(settings).map_err(LpError::internal)?;
    write_atomic(path, &json)
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> LpResult<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| LpError::internal("settings path has no parent"))?;
    std::fs::create_dir_all(dir).map_err(LpError::internal)?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).map_err(LpError::internal)?;
        f.write_all(bytes).map_err(LpError::internal)?;
        f.sync_all().map_err(LpError::internal)?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        LpError::internal(format!("rename settings: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let s = Settings::default();
        assert!(s.shell_protection.enabled);
        assert!(!s.git.allow_auto_push_default_branch);
        assert!(!s.git.allow_destructive);
        assert_eq!(
            s.packages.system_install_policy,
            InstallPolicy::RequireApproval
        );
        assert_eq!(s.network.bind_address, "127.0.0.1");
        assert_eq!(s.sessions.idle_timeout_minutes, 30);
        assert_eq!(s.sessions.absolute_lifetime_hours, 8);
        assert_eq!(s.sessions.pending_approval_minutes, 10);
        assert!(s.sessions.terminate_tasks_on_revoke);
        assert!(!s.sessions.terminate_tasks_on_expiry);
        assert_eq!(s.data_shared.max_size_mb, 250);
        assert_eq!(s.data_shared.retention_days, 30);
        assert_eq!(s.audit.retention_days, 30);
        assert!(!s.updates.install_automatically);
        assert!(s.updates.check_automatically);
        assert!(!s.protected_paths.allow_env_file_reads);
        validate(&s).unwrap();
    }

    #[test]
    fn corrupt_file_fails_closed_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        std::fs::write(&p, "{ not json").unwrap();
        let loaded = load(&p);
        assert!(loaded.fault.is_some());
        assert_eq!(loaded.settings, Settings::default());
        assert!(loaded.fault.unwrap().backup_path.is_some());
    }

    #[test]
    fn future_version_is_a_fault() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        std::fs::write(&p, r#"{"schema_version": 99}"#).unwrap();
        assert!(load(&p).fault.is_some());
    }

    #[test]
    fn unversioned_document_migrates() {
        let s = migrate(serde_json::json!({"git": {"allow_destructive": true}})).unwrap();
        assert_eq!(s.schema_version, SCHEMA_VERSION);
        assert!(s.git.allow_destructive);
    }

    #[test]
    fn invalid_limits_rejected() {
        let mut s = Settings::default();
        s.sessions.idle_timeout_minutes = 0;
        assert!(validate(&s).is_err());
    }

    #[test]
    fn roundtrip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        s.network.port = 41234;
        s.network.public_mcp_url = Some("https://mcp.example.com/mcp".into());
        save(&p, &s).unwrap();
        let loaded = load(&p);
        assert!(loaded.fault.is_none());
        assert_eq!(loaded.settings, s);
    }

    #[test]
    fn public_url_validation() {
        assert!(validate_public_url("https://mcp.example.com/mcp").is_ok());
        assert!(validate_public_url("https://example.com/workstation/mcp").is_ok());
        assert!(validate_public_url("http://mcp.example.com/mcp").is_err());
        assert!(validate_public_url("https://mcp.example.com/").is_err());
        assert!(validate_public_url("https://user:pw@mcp.example.com/mcp").is_err());
        assert!(validate_public_url("https://mcp.example.com/mcp?token=x").is_err());
    }
}
