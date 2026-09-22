# Local MCP gateway architecture

Inspected before implementation: Local Pilot is a Rust workspace with a Tauri/React desktop. `workstation-server::Core` owns lifecycle, SQLite control storage, audit, sessions, approvals and the static tool registry. `tools::dispatch` enforces state, OAuth scopes, durable mutation intents, redaction and Data Shared recording; `ToolCtx::authorize` binds approval/resume to exact operation descriptors. The upstream server already uses rmcp 3.4.0. Desktop commands call Core directly through Tauri IPC. The executor launches standard-user processes suspended inside kill-on-close Windows Job Objects. Emergency Stop latches state and kills managed work.

Implementation adds downstream rmcp clients behind that pipeline, a separately migrated gateway database with DPAPI-encrypted configurations, per-server sessions/tool caches and local-only configuration commands. Interactive stdin is added to the existing secure process launcher; its job and restricted-token protections remain authoritative. HTTP uses loopback-only endpoints, disables proxies and redirects. No downstream tools are re-exported dynamically.

## Security Model

The downstream MCP gateway is **permission-mediated**, rather than fully OS-sandboxed.

- Local Pilot mediates upstream tool requests.
- Arbitrary-code and unknown tools require explicit user approval.
- Stdio MCPs run as a standard user.
- The Windows Job Object provides lifecycle containment (kill-on-close), but **Local Pilot does not yet provide filesystem or network OS sandboxing for the downstream MCP process itself**. Once running, a downstream MCP process operates with the standard privileges of the desktop user.
