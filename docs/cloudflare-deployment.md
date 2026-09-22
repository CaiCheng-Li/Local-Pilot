# Cloudflare Tunnel deployment

How the owner's deployment is exposed through Cloudflare. Hostnames, account,
zone, tunnel and rule IDs are kept out of the repository; `mcp.example.com` and
`/<prefix>` below stand in for the real values.

## Topology

```text
MCP client --HTTPS--> Cloudflare --named tunnel--> cloudflared (Windows service)
                                                        |
                                                        v
                                            http://127.0.0.1:<port>
```

Local Pilot stays bound to loopback. The public MCP URL is
`https://mcp.example.com/<prefix>/mcp`, so several services can share one
hostname under different prefixes.

## Tunnel

A named, remotely managed tunnel (`config_src: cloudflare`) with one ingress
rule for the Local Pilot prefix and a 404 catch-all:

```yaml
ingress:
  - hostname: mcp.example.com
    path: ^/(\.well-known/oauth-(protected-resource|authorization-server)/)?<prefix>(/.*)?$
    service: http://127.0.0.1:<port>
  - service: http_status:404
```

The `.well-known` alternatives are required: RFC 9728 and RFC 8414 place the
discovery documents at the origin root with the resource path appended
(`/.well-known/oauth-protected-resource/<prefix>/mcp`,
`/.well-known/oauth-authorization-server/<prefix>`), outside the prefix.

Use `127.0.0.1` rather than `localhost` as the origin so cloudflared never tries
`::1`, which the listener does not bind.

DNS is a proxied CNAME from `mcp.example.com` to `<tunnel-id>.cfargotunnel.com`.

## Zone rules

All scoped to `http.host eq "mcp.example.com"`:

| Phase | Rule |
| --- | --- |
| `http_request_cache_settings` | Bypass cache |
| `http_config_settings` | Browser Integrity Check off (API clients send non-browser user agents) |
| `http_request_firewall_custom` | Block when `not ssl` |
| `http_ratelimit` | Block above 100 requests / 10 s per IP and colo for 10 s |

Bot Fight Mode must stay off for this zone: it cannot be skipped by WAF rules
and challenges non-browser clients. The legacy "Block AI bots" setting targets
training crawlers and does not affect MCP agent traffic.

Cloudflare Access is not enabled; Local Pilot's own OAuth and bearer tokens are
the authentication layer.

## Workstation

1. Install cloudflared machine-wide: `winget install --id Cloudflare.cloudflared --exact`.
   The service runs as LocalSystem, so its binary must not live in a
   user-writable directory.
2. From an elevated shell: `cloudflared service install <tunnel-token>`. The
   token is fetched from the Cloudflare API and never written to disk by hand
   or committed; the service keeps it in its own configuration.
3. In Local Pilot settings set `network.public_mcp_url` to the public MCP URL
   and `network.trusted_proxy` to `cloudflare_tunnel`. The port must match the
   tunnel's origin service.

## Verification

```powershell
Invoke-WebRequest https://mcp.example.com/<prefix>/health
Invoke-WebRequest https://mcp.example.com/.well-known/oauth-protected-resource/<prefix>/mcp
Invoke-WebRequest https://mcp.example.com/.well-known/oauth-authorization-server/<prefix>
```

`POST https://mcp.example.com/<prefix>/mcp` without a token must return 401 with
a `WWW-Authenticate: Bearer resource_metadata=...` challenge. Plain HTTP must
return 403, and paths outside the prefix 404. A 502 means the tunnel is up but
Local Pilot is not listening.
