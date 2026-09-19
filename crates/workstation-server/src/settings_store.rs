//! Settings owned by the local UI. Remote tools can never change them.

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use workstation_core::LpResult;
use workstation_core::config::{self, ConfigFault, Settings};

pub struct SettingsStore {
    path: PathBuf,
    current: RwLock<Arc<Settings>>,
    fault: RwLock<Option<ConfigFault>>,
}

impl SettingsStore {
    pub fn load(path: PathBuf) -> Self {
        let loaded = config::load(&path);
        Self {
            path,
            current: RwLock::new(Arc::new(loaded.settings)),
            fault: RwLock::new(loaded.fault),
        }
    }

    pub fn from_settings(path: PathBuf, settings: Settings) -> Self {
        Self {
            path,
            current: RwLock::new(Arc::new(settings)),
            fault: RwLock::new(None),
        }
    }

    pub fn get(&self) -> Arc<Settings> {
        self.current.read().clone()
    }

    pub fn fault(&self) -> Option<ConfigFault> {
        self.fault.read().clone()
    }

    /// Replace settings (validated, persisted atomically). Security-relevant
    /// changes bump the policy revision.
    pub fn update(&self, mut next: Settings) -> LpResult<(Arc<Settings>, Arc<Settings>)> {
        let prev = self.get();
        next.schema_version = config::SCHEMA_VERSION;
        if security_relevant_change(&prev, &next) {
            next.policy_revision = prev.policy_revision + 1;
        } else {
            next.policy_revision = prev.policy_revision;
        }
        config::save(&self.path, &next)?;
        let next = Arc::new(next);
        *self.current.write() = next.clone();
        *self.fault.write() = None;
        Ok((prev, next))
    }

    /// Reset to defaults after a fault (explicit local action).
    pub fn reset_to_defaults(&self) -> LpResult<Arc<Settings>> {
        let prev = self.get();
        let s = Settings {
            policy_revision: prev.policy_revision + 1,
            ..Settings::default()
        };
        config::save(&self.path, &s)?;
        let s = Arc::new(s);
        *self.current.write() = s.clone();
        *self.fault.write() = None;
        Ok(s)
    }
}

/// Any change other than purely cosmetic/general settings is security relevant.
pub fn security_relevant_change(a: &Settings, b: &Settings) -> bool {
    let strip = |s: &Settings| {
        let mut s = s.clone();
        s.policy_revision = 0;
        s.general = Default::default();
        s.notifications = Default::default();
        s.updates = Default::default();
        s.setup_completed = false;
        s
    };
    strip(a) != strip(b)
}
