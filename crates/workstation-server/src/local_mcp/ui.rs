//! Desktop-only management surface. None of these operations are upstream tools.
use super::*;
use crate::{Core, state::ServerState};
use workstation_audit::AuditEvent;

impl Core {
    pub async fn ui_local_mcp(
        &self,
        action: &str,
        id: Option<String>,
        config: Option<ServerConfig>,
    ) -> LpResult<Value> {
        let id = id.unwrap_or_default();
        if matches!(action, "list" | "tools") {
            return if action == "list" {
                Ok(self.local_mcp.desktop_list())
            } else {
                self.local_mcp.tools(&id)
            };
        }
        if matches!(action, "start" | "restart" | "test")
            && matches!(
                self.state.get(),
                ServerState::EmergencyStopped | ServerState::Stopping | ServerState::Faulted
            )
        {
            return Err(LpError::new(
                ErrorCode::EmergencyStopActive,
                "Resume Local Pilot before starting MCP services",
            ));
        }
        self.audit.record_sync(AuditEvent {
            kind: "local_mcp_management".into(),
            command: Some(format!("{action} {id}")),
            result_status: "intent".into(),
            ..Default::default()
        })?;
        let result = match action {
            "add" | "save" => {
                let config = config.ok_or_else(|| LpError::invalid("Configuration required"))?;
                self.local_mcp
                    .save(config, action == "save")
                    .await
                    .map(|_| json!({"ok":true}))
            }
            "remove" => self.local_mcp.remove(&id).await.map(|_| json!({"ok":true})),
            "start" => self
                .local_mcp
                .start(&id)
                .await
                .and_then(|_| self.local_mcp.get(&id)),
            "stop" => self
                .local_mcp
                .stop(&id)
                .and_then(|_| self.local_mcp.get(&id)),
            "restart" => self
                .local_mcp
                .restart(&id)
                .await
                .and_then(|_| self.local_mcp.get(&id)),
            "refresh" => self.local_mcp.refresh(&id).await,
            "test" => {
                self.local_mcp
                    .test(config.ok_or_else(|| LpError::invalid("Configuration required"))?)
                    .await
            }
            _ => Err(LpError::invalid("Unknown MCP management action")),
        };
        self.audit
            .record(AuditEvent {
                kind: "local_mcp_management".into(),
                command: Some(format!("{action} {id}")),
                result_status: if result.is_ok() { "ok" } else { "error" }.into(),
                error: result.as_ref().err().map(|e| e.message.clone()),
                ..Default::default()
            })
            .await;
        result
    }
}
