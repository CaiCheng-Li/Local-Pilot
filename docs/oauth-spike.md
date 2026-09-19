# OAuth and MCP compatibility decision

The current service uses `rmcp` 3.4 for MCP Streamable HTTP and implements the authorization-server surface beside it with Axum. The protected resource is the configured public MCP URL. Discovery endpoints expose RFC 9728 protected-resource metadata and OAuth authorization-server metadata under the same configured path prefix.

Clients may use dynamic client registration when enabled. Registered confidential clients receive a generated client secret; public clients use PKCE. Authorization requests create a short-lived pending connection that must be approved in the local desktop control surface. The public authorization page shows a pairing code but cannot grant access itself.

Authorization codes are one-use and short-lived. Access and refresh tokens are random values; only keyed hashes are persisted. Refresh rotation revokes the previous refresh credential. Local client disablement, credential revocation, session expiry, MCP restart, and Emergency Stop invalidate access according to the settings and server state.

The endpoint layout is:

```text
<prefix>/mcp
<prefix>/authorize
<prefix>/token
<prefix>/register
<prefix>/.well-known/oauth-authorization-server
/.well-known/oauth-protected-resource<resource path>
```

Protocol and API-level interoperability are covered by `tests/protocol` and the OAuth integration scenario. A real ChatGPT developer-mode connection over the owner's public hostname is still required before claiming ChatGPT compatibility. That test must include discovery, local consent, token refresh, project resolution, a file read, an approved external write resume, and task start/poll/cancel.
