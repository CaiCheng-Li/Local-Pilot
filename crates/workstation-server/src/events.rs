//! Events pushed to the local UI (and used for Windows notifications).

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UiEvent {
    StateChanged {
        state: String,
        remote_access: bool,
    },
    ApprovalRequested {
        approval_id: String,
        client: String,
        summary: String,
        requires_admin: bool,
    },
    ApprovalChanged {
        approval_id: String,
        status: String,
    },
    ConnectionRequested {
        request_id: String,
        client_name: String,
        pairing_code: String,
    },
    ConnectionChanged {
        request_id: String,
        status: String,
    },
    ClientConnected {
        client_id: String,
        display_name: String,
    },
    ClientDisconnected {
        client_id: String,
        display_name: String,
        reason: String,
    },
    TaskChanged {
        task_id: String,
        status: String,
        client_id: String,
    },
    TaskFailed {
        task_id: String,
        client_id: String,
        command: String,
    },
    ProjectsChanged,
    SettingsChanged {
        revision: u64,
    },
    AuditFault {
        message: String,
    },
    EmergencyStop,
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<UiEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(512);
        Self { tx }
    }
}

impl EventBus {
    pub fn emit(&self, e: UiEvent) {
        let _ = self.tx.send(e);
    }
    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.tx.subscribe()
    }
}
