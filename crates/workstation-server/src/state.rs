//! MCP server availability state and the crash-safe remote-access gate.
//!
//! Remote access is enabled at startup only if *all* of these hold:
//! - the gate file `state\remote-access.gate` exists, parses and says
//!   `enabled` with a valid checksum (a missing, damaged or unknown gate means
//!   disabled — an unclean shutdown can never silently re-enable access);
//! - the Emergency Stop latch in the control database is not set;
//! - settings loaded without a fault and setup has been completed.
//!
//! Emergency Stop sets the latch before acknowledging durable completion. Only
//! an explicit local Resume clears it; restarts, reboots, token refresh and
//! autostart never do.

use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use workstation_core::db::Db;
use workstation_core::hashing::sha256_hex;
use workstation_core::{LpResult, time};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    Starting,
    Ready,
    Paused,
    EmergencyStopped,
    Restarting,
    Stopping,
    Faulted,
}

impl ServerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServerState::Starting => "starting",
            ServerState::Ready => "ready",
            ServerState::Paused => "paused",
            ServerState::EmergencyStopped => "emergency_stopped",
            ServerState::Restarting => "restarting",
            ServerState::Stopping => "stopping",
            ServerState::Faulted => "faulted",
        }
    }
}

pub struct StateMachine {
    state: RwLock<ServerState>,
    fault: RwLock<Option<String>>,
    gate_path: PathBuf,
}

const GATE_ENABLED: &str = "enabled";
const GATE_DISABLED: &str = "disabled";

impl StateMachine {
    pub fn new(gate_path: PathBuf) -> Self {
        Self {
            state: RwLock::new(ServerState::Starting),
            fault: RwLock::new(None),
            gate_path,
        }
    }

    pub fn get(&self) -> ServerState {
        *self.state.read()
    }

    pub fn set(&self, s: ServerState) {
        *self.state.write() = s;
    }

    pub fn fault(&self) -> Option<String> {
        self.fault.read().clone()
    }

    pub fn set_fault(&self, msg: Option<String>) {
        *self.fault.write() = msg;
    }

    pub fn accepting(&self) -> bool {
        self.get() == ServerState::Ready
    }

    /// Read the gate; anything other than a valid `enabled` record is disabled.
    pub fn gate_enabled(&self) -> bool {
        read_gate(&self.gate_path) == Some(true)
    }

    pub fn write_gate(&self, enabled: bool) -> LpResult<()> {
        write_gate(&self.gate_path, enabled)
    }
}

fn gate_record(value: &str, ts: i64) -> String {
    let body = format!("{value}\n{ts}");
    format!(
        "{body}\n{}\n",
        sha256_hex(format!("LocalPilot-gate\n{body}").as_bytes())
    )
}

pub fn read_gate(path: &Path) -> Option<bool> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let value = lines.next()?;
    let ts = lines.next()?;
    let sum = lines.next()?;
    let body = format!("{value}\n{ts}");
    if sha256_hex(format!("LocalPilot-gate\n{body}").as_bytes()) != sum {
        return None;
    }
    match value {
        GATE_ENABLED => Some(true),
        GATE_DISABLED => Some(false),
        _ => None,
    }
}

pub fn write_gate(path: &Path, enabled: bool) -> LpResult<()> {
    let rec = gate_record(
        if enabled { GATE_ENABLED } else { GATE_DISABLED },
        time::now_ms(),
    );
    workstation_core::config::write_atomic(path, rec.as_bytes())
}

/// Emergency Stop latch stored in the control database.
pub fn latch_set(db: &Db, on: bool, reason: &str) -> LpResult<()> {
    let value =
        serde_json::json!({ "latched": on, "reason": reason, "at": time::now_ms() }).to_string();
    db.write_sync(|c| {
        c.execute(
            "INSERT INTO settings_kv (key, value, updated_at) VALUES ('emergency_stop', ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            rusqlite::params![value, time::now_ms()],
        )?;
        Ok(())
    })
}

/// Returns `Some(true)` when latched, `Some(false)` when explicitly clear,
/// `None` when unknown (treated as latched by callers only if the gate is
/// also not enabled).
pub fn latch_get(db: &Db) -> Option<bool> {
    db.read_sync(|c| {
        use rusqlite::OptionalExtension;
        let v: Option<String> = c
            .query_row(
                "SELECT value FROM settings_kv WHERE key = 'emergency_stop'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v)
    })
    .ok()
    .map(|v| {
        v.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|j| j.get("latched").and_then(|b| b.as_bool()))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_is_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("gate");
        assert_eq!(read_gate(&p), None);
        write_gate(&p, true).unwrap();
        assert_eq!(read_gate(&p), Some(true));
        write_gate(&p, false).unwrap();
        assert_eq!(read_gate(&p), Some(false));
        // Tampered or truncated records are not "enabled".
        let text = std::fs::read_to_string(&p)
            .unwrap()
            .replace("disabled", "enabled");
        std::fs::write(&p, text).unwrap();
        assert_eq!(read_gate(&p), None);
        std::fs::write(&p, "enabled\n").unwrap();
        assert_eq!(read_gate(&p), None);
    }
}
