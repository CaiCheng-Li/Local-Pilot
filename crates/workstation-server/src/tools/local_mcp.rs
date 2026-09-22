use super::*;
use crate::local_mcp::policy;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Server {
    server: String,
    #[serde(default)]
    refresh: bool,
    #[serde(default)]
    idempotency_key: Option<String>,
}
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Call {
    server: String,
    tool: String,
    arguments: Value,
    #[serde(default)]
    idempotency_key: Option<String>,
}

pub fn register(r: &mut ToolRegistry) {
    let meta = |name, title, description, kind| ToolMeta {
        name,
        title,
        description,
        kind,
    };
    r.add(
        meta(
            "local_mcp_list_servers",
            "List local MCP services",
            "List configured downstream MCP services and connection status",
            Kind::Read,
        ),
        |ctx, _: Empty| async move { ok(ctx.core.local_mcp.list()) },
    );
    r.add(
        meta(
            "local_mcp_get_server",
            "Get local MCP service",
            "Get downstream connection metadata without credentials or launch arguments",
            Kind::Read,
        ),
        |ctx, a: Server| async move { ok(ctx.core.local_mcp.get(&a.server)?) },
    );
    r.add(
        meta(
            "local_mcp_list_tools",
            "List downstream tools",
            "List cached tool schemas; refresh=true refreshes a connected server",
            Kind::Read,
        ),
        |ctx, a: Server| async move {
            ok(if a.refresh {
                ctx.core.local_mcp.refresh(&a.server).await?
            } else {
                ctx.core.local_mcp.tools(&a.server)?
            })
        },
    );
    r.add(meta("local_mcp_call_tool","Call downstream MCP tool","Invoke one discovered downstream tool through Local Pilot permissions. Unknown and arbitrary-code tools require local approval. Timed-out calls are never automatically retried.",Kind::Execute),|ctx,a:Call|async move{
        let _=&a.idempotency_key;
        let config=ctx.core.local_mcp.config(&a.server)?;
        let descriptor=ctx.core.local_mcp.descriptor(&a.server,Some(&a.tool))?;
        policy::authorize(&ctx,&config,&a.tool,&a.arguments,descriptor.clone(),false)?;
        let result=ctx.core.local_mcp.call(&a.server,&a.tool,a.arguments,&descriptor,ctx.cancel.clone()).await?;
        ok(result)
    });
    for (name, title, op) in [
        ("local_mcp_start_server", "Start local MCP service", "start"),
        ("local_mcp_stop_server", "Stop local MCP service", "stop"),
        (
            "local_mcp_restart_server",
            "Restart local MCP service",
            "restart",
        ),
    ] {
        r.add(meta(name,title,"Manage a configured local MCP connection. Requires local approval because the service may be shared by agents.",Kind::Execute),move|ctx,a:Server|async move{
            let _=&a.idempotency_key;
            let config=ctx.core.local_mcp.config(&a.server)?;
            let descriptor=ctx.core.local_mcp.descriptor(&a.server,None)?;
            policy::authorize(&ctx,&config,op,&ctx.raw_args,descriptor,true)?;
            match op {"start"=>ctx.core.local_mcp.start(&a.server).await?,"restart"=>ctx.core.local_mcp.restart(&a.server).await?,_=>ctx.core.local_mcp.stop(&a.server)?}
            ok(ctx.core.local_mcp.get(&a.server)?)
        });
    }
}
