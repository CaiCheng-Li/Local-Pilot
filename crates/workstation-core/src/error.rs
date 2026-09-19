use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable, client-visible error codes. Remote clients only ever see these codes
/// and a short message; internal details are logged locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    AuthenticationFailed,
    InsufficientScope,
    PermissionDenied,
    ProtectedResource,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalInvalidated,
    ApprovalPending,
    SessionExpired,
    IdempotencyConflict,
    OutcomeUnknown,
    PathOutsidePolicy,
    PathNotFound,
    AlreadyExists,
    ProjectNotFound,
    TaskNotFound,
    NotFound,
    CommandFailed,
    Timeout,
    OutputLimitReached,
    EmergencyStopActive,
    ServiceUnavailable,
    ClientDisabled,
    ClientLimitReached,
    RateLimited,
    ProjectLocked,
    AuditUnavailable,
    CacheQuotaExceeded,
    InvalidArguments,
    TooLarge,
    AttributionBlocked,
    ConfigFault,
    Unsupported,
    Internal,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::AuthenticationFailed => "AUTHENTICATION_FAILED",
            ErrorCode::InsufficientScope => "INSUFFICIENT_SCOPE",
            ErrorCode::PermissionDenied => "PERMISSION_DENIED",
            ErrorCode::ProtectedResource => "PROTECTED_RESOURCE",
            ErrorCode::ApprovalRequired => "APPROVAL_REQUIRED",
            ErrorCode::ApprovalDenied => "APPROVAL_DENIED",
            ErrorCode::ApprovalExpired => "APPROVAL_EXPIRED",
            ErrorCode::ApprovalInvalidated => "APPROVAL_INVALIDATED",
            ErrorCode::ApprovalPending => "APPROVAL_PENDING",
            ErrorCode::SessionExpired => "SESSION_EXPIRED",
            ErrorCode::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            ErrorCode::OutcomeUnknown => "OUTCOME_UNKNOWN",
            ErrorCode::PathOutsidePolicy => "PATH_OUTSIDE_POLICY",
            ErrorCode::PathNotFound => "PATH_NOT_FOUND",
            ErrorCode::AlreadyExists => "ALREADY_EXISTS",
            ErrorCode::ProjectNotFound => "PROJECT_NOT_FOUND",
            ErrorCode::TaskNotFound => "TASK_NOT_FOUND",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::CommandFailed => "COMMAND_FAILED",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::OutputLimitReached => "OUTPUT_LIMIT_REACHED",
            ErrorCode::EmergencyStopActive => "EMERGENCY_STOP_ACTIVE",
            ErrorCode::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            ErrorCode::ClientDisabled => "CLIENT_DISABLED",
            ErrorCode::ClientLimitReached => "CLIENT_LIMIT_REACHED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::ProjectLocked => "PROJECT_LOCKED",
            ErrorCode::AuditUnavailable => "AUDIT_UNAVAILABLE",
            ErrorCode::CacheQuotaExceeded => "CACHE_QUOTA_EXCEEDED",
            ErrorCode::InvalidArguments => "INVALID_ARGUMENTS",
            ErrorCode::TooLarge => "TOO_LARGE",
            ErrorCode::AttributionBlocked => "ATTRIBUTION_BLOCKED",
            ErrorCode::ConfigFault => "CONFIG_FAULT",
            ErrorCode::Unsupported => "UNSUPPORTED",
            ErrorCode::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error that can be shown to a remote client. `message` must never contain
/// secret material or internal debug output; `internal` is logged locally only.
#[derive(Debug, Clone)]
pub struct LpError {
    pub code: ErrorCode,
    pub message: String,
    pub internal: Option<String>,
    pub details: Option<serde_json::Value>,
}

impl LpError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            internal: None,
            details: None,
        }
    }

    pub fn with_internal(mut self, internal: impl fmt::Display) -> Self {
        self.internal = Some(internal.to_string());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn internal(err: impl fmt::Display) -> Self {
        Self::new(
            ErrorCode::Internal,
            "An internal error occurred; see the local diagnostic log.",
        )
        .with_internal(err)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArguments, message)
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, message)
    }

    pub fn protected() -> Self {
        Self::new(
            ErrorCode::ProtectedResource,
            "This resource is protected. Ask the user directly if secret or credential information is needed.",
        )
    }

    pub fn audit_unavailable() -> Self {
        Self::new(
            ErrorCode::AuditUnavailable,
            "Local audit storage is unavailable; the operation was not performed.",
        )
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
}

impl fmt::Display for LpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LpError {}

impl From<rusqlite::Error> for LpError {
    fn from(err: rusqlite::Error) -> Self {
        LpError::internal(format!("sqlite: {err}"))
    }
}

pub type LpResult<T> = Result<T, LpError>;
