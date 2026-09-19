//! Shared building blocks for Local Pilot: configuration, identifiers, error
//! codes, application paths, SQLite storage helpers, secret protection and the
//! central redaction engine.

pub mod config;
pub mod db;
pub mod dpapi;
pub mod error;
pub mod hashing;
pub mod helper_ipc;
pub mod ids;
pub mod known_folders;
pub mod paths;
pub mod redaction;
pub mod time;

pub use error::{ErrorCode, LpError, LpResult};

/// Product name shown in the UI.
pub const PRODUCT_NAME: &str = "Local Pilot";
/// Application-data directory name under `%LOCALAPPDATA%`.
pub const APP_DIR_NAME: &str = "LocalPilot";
/// Crate/package version, reported by `/health`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
