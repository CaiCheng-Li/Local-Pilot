//! rmcp `ServerHandler`: tool listing and calls, delegated to the pipeline.

use std::sync::Arc;

use parking_lot::Mutex;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::Value;

use crate::Core;
use crate::auth::Principal;
use crate::tools::{self, CallInput};

/// Authentication result attached to each HTTP request by the auth layer.
#[derive(Clone)]
pub struct AuthContext {
    pub principal: Principal,
    pub remote_addr: Option<String>,
    pub request_id: String,
    pub share_ids: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone)]
pub struct McpHandler {
    pub core: Arc<Core>,
}

const INSTRUCTIONS: &str = "Local Pilot exposes a Windows development workstation. \
The trusted workspace is the user's Documents\\Projects folder: inside it you may create, edit, delete, build, test and run commands freely. \
Use projects_resolve to find a project by name and pass absolute paths (or paths relative to Documents\\Projects). \
Reads elsewhere are allowed except credential/secret locations, which are always denied; ask the user directly for any secret you need. \
Writes outside the workspace, system-wide installs, direct pushes to the default branch and destructive Git operations return status approval_required: \
tell the user, poll approval_status, and after approval call approval_resume (approval alone does not run anything). \
Long-running commands return a task_id; poll task_output and stop them with task_cancel/task_kill. \
Never add AI/agent/vendor attribution to commits, pull requests, issues or other GitHub content; such content is rejected.";

impl ServerHandler for McpHandler {
    fn get_info(&self) -> ServerConfig {
        let mut info = Implementation::new("local-pilot", workstation_core::VERSION);
        info.title = Some("Local Pilot".into());
        info.description =
            Some("Authorized MCP access to a Windows development workstation".into());
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(info)
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.core.tools.mcp_tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let auth = context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|p| p.extensions.get::<AuthContext>())
            .cloned()
            .ok_or_else(|| ErrorData::invalid_request("unauthenticated request", None))?;
        let input = CallInput {
            cancel: context.ct.clone(),
            name: request.name.to_string(),
            arguments: Value::Object(request.arguments.unwrap_or_default()),
            principal: auth.principal.clone(),
            protocol_version: context.protocol_version().map(|v| v.to_string()),
            client_info: context
                .client_info()
                .map(|i| format!("{} {}", i.name, i.version)),
            remote_addr: auth.remote_addr.clone(),
            request_id: auth.request_id.clone(),
            share_ids: Some(auth.share_ids.clone()),
        };
        Ok(tools::dispatch(self.core.clone(), input).await.into())
    }
}
