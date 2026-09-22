import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Policy = { risk: string; permission: "ask" | "allow" | "deny" };
type Config = {
  id: string; name: string; transport: "stdio" | "streamable-http"; enabled: boolean;
  command: string; args: string[]; cwd: string; env: Record<string, string>; url: string;
  autoStart: boolean; autoConnect: boolean; trusted: boolean; connectionTimeoutSeconds: number;
  toolTimeoutSeconds: number; reconnectAttempts: number; toolPolicies: Record<string, Policy>; logging: boolean;
};
type Runtime = { status: string; pid?: number; toolCount: number; lastError?: string; logs: string[]; serverInfo?: unknown; restartCount: number; nextRetryAt?: number };
type Service = Config & { runtime: Runtime };
type Tool = { name: string; description?: string; inputSchema: unknown; policy: Policy };
const empty: Config = { id: "", name: "", transport: "stdio", enabled: true, command: "", args: [], cwd: "", env: {}, url: "", autoStart: false, autoConnect: false, trusted: false, connectionTimeoutSeconds: 10, toolTimeoutSeconds: 60, reconnectAttempts: 0, toolPolicies: {}, logging: true };
const risks = ["unknown", "read-only", "project-write", "filesystem-write", "process-execution", "network", "application-control", "arbitrary-code"];
const api = <T,>(action: string, id?: string, config?: Config) => invoke<T>("local_mcp_services", { action, id, config });
const configOnly = ({ runtime: _runtime, ...config }: Service): Config => config;

export default function LocalMcpServices() {
  const [services, setServices] = useState<Service[]>([]);
  const [edit, setEdit] = useState<Config>(); const [existing, setExisting] = useState(false);
  const [args, setArgs] = useState("[]"); const [env, setEnv] = useState("{}");
  const [tools, setTools] = useState<Tool[]>([]); const [selected, setSelected] = useState<string>();
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false); const [result, setResult] = useState("");
  const [logs, setLogs] = useState<string>();
  const load = useCallback(async () => { setServices(await api<Service[]>("list")); }, []);
  useEffect(() => { void load().catch(e => setError(String(e))); const timer = window.setInterval(() => void load().catch(e => setError(String(e))), 3000); return () => window.clearInterval(timer); }, [load]);
  const run = async (fn: () => Promise<void>) => { setBusy(true); setError(""); try { await fn(); await load(); } catch (e) { setError(String(e)); } finally { setBusy(false); } };
  const open = (service?: Service) => { const config = service ? configOnly(service) : structuredClone(empty); setEdit(config); setExisting(Boolean(service)); setArgs(JSON.stringify(config.args, null, 2)); setEnv(JSON.stringify(config.env, null, 2)); setResult(""); };
  const draft = (): Config => { if (!edit) throw new Error("No configuration"); return { ...edit, args: JSON.parse(args), env: JSON.parse(env) }; };
  const update = <K extends keyof Config>(key: K, value: Config[K]) => setEdit(previous => previous ? { ...previous, [key]: value } : previous);
  const inspect = async (id: string, refresh = false) => { setTools(await api<Tool[]>(refresh ? "refresh" : "tools", id)); setSelected(id); };
  const changePolicy = async (tool: string, policy: Policy) => {
    const service = services.find(s => s.id === selected); if (!service) return;
    const config = configOnly(service); config.toolPolicies = { ...config.toolPolicies, [tool]: policy };
    await api("save", config.id, config); setTools([]); setSelected(undefined);
  };
  return <>
    <section className="panel"><div className="section-heading"><div><h2>Local MCP Services</h2><p>Connect local tools through Local Pilot’s permissions and audit history.</p></div><button className="primary" disabled={busy} onClick={() => open()}>+ Add MCP Server</button></div>
      {error && <div className="error" role="alert"><span>{error}</span><button onClick={() => setError("")}>Dismiss</button></div>}
      {services.length === 0 && <div className="empty">Add a local stdio or Streamable HTTP MCP server to get started.</div>}
      {services.map(service => <article className="row-card" key={service.id}><div><strong>{service.name}</strong><span>{service.runtime.status} · {service.transport} · {service.runtime.toolCount} tools · {service.trusted ? "Trusted for classified low-risk tools" : "Restricted"}</span><small>{service.id}{service.runtime.pid ? ` · PID ${service.runtime.pid}` : ""} · {service.runtime.restartCount} reconnects</small>{service.runtime.lastError && <small className="error">{service.runtime.lastError}</small>}</div><div className="button-row">
        <button disabled={busy} onClick={() => void run(() => inspect(service.id))}>View Tools</button>
        <button disabled={busy || !service.enabled} onClick={() => void run(async () => { await api(service.runtime.status === "connected" ? "restart" : "start", service.id); })}>{service.runtime.status === "connected" ? "Restart" : "Start"}</button>
        <button disabled={busy} onClick={() => void run(async () => { await api("stop", service.id); })}>Stop</button>
        <button disabled={busy} onClick={() => open(service)}>Settings</button>
        <button onClick={() => setLogs(logs === service.id ? undefined : service.id)}>Logs</button>
        <button disabled={busy} onClick={() => void run(async () => { const config = configOnly(service); config.enabled = !config.enabled; await api("save", config.id, config); })}>{service.enabled ? "Disable" : "Enable"}</button>
        <button disabled={busy} onClick={() => void run(async () => { await api("remove", service.id); if (selected === service.id) { setSelected(undefined); setTools([]); } })}>Remove</button>
      </div></article>)}
    </section>
    {edit && <section className="panel form-grid"><h2>{existing ? "Server settings" : "Add MCP Server"}</h2>
      <label>ID<input value={edit.id} disabled={existing} placeholder="blender" onChange={e => update("id", e.target.value)} /></label>
      <label>Name<input value={edit.name} onChange={e => update("name", e.target.value)} /></label>
      <label>Transport<select value={edit.transport} onChange={e => update("transport", e.target.value as Config["transport"])}><option value="stdio">stdio — launch a local process</option><option value="streamable-http">Streamable HTTP — connect to loopback</option></select></label>
      {edit.transport === "stdio" ? <><label>Executable<input value={edit.command} placeholder="C:\path\python.exe" onChange={e => update("command", e.target.value)} /></label><label>Arguments (JSON array)<textarea rows={4} value={args} onChange={e => setArgs(e.target.value)} /></label><label>Working directory<input value={edit.cwd} onChange={e => update("cwd", e.target.value)} /></label><label className="toggle"><input type="checkbox" checked={edit.autoStart} onChange={e => update("autoStart", e.target.checked)} />Auto-start with Local Pilot</label></> : <><label>Local URL<input value={edit.url} placeholder="http://127.0.0.1:8123/mcp" onChange={e => update("url", e.target.value)} /></label><label className="toggle"><input type="checkbox" checked={edit.autoConnect} onChange={e => update("autoConnect", e.target.checked)} />Auto-connect with Local Pilot</label></>}
      <details className="mcp-advanced"><summary>Advanced settings and permissions</summary><div className="form-grid">
        <label>Environment (JSON object; encrypted at rest)<textarea rows={5} value={env} onChange={e => setEnv(e.target.value)} /><small>Values are write-only. Leave &lt;redacted&gt; unchanged to preserve a saved value.</small></label>
        <label>Connection timeout (seconds)<input type="number" min={1} max={120} value={edit.connectionTimeoutSeconds} onChange={e => update("connectionTimeoutSeconds", Number(e.target.value))} /></label>
        <label>Tool timeout (seconds)<input type="number" min={1} max={3600} value={edit.toolTimeoutSeconds} onChange={e => update("toolTimeoutSeconds", Number(e.target.value))} /></label>
        <label>Reconnect attempts (0 disables)<input type="number" min={0} max={5} value={edit.reconnectAttempts} onChange={e => update("reconnectAttempts", Number(e.target.value))} /></label>
        <label className="toggle"><input type="checkbox" checked={edit.trusted} onChange={e => update("trusted", e.target.checked)} />Always allow this server’s locally classified low-risk tools</label>
        <label className="toggle"><input type="checkbox" checked={edit.logging} onChange={e => update("logging", e.target.checked)} />Capture redacted process diagnostics</label>
        <p>Unknown, arbitrary-code, network, filesystem-write and process tools still require approval. Explicit denials always apply. Remote endpoints are unavailable. Saving settings stops the connection and invalidates pending operation descriptors.</p>
      </div></details>
      <div className="form-actions"><button disabled={busy} onClick={() => void run(async () => { const value = await api("test", edit.id, draft()); setResult(JSON.stringify(value, null, 2)); })}>Test Connection</button><button className="primary" disabled={busy} onClick={() => void run(async () => { await api(existing ? "save" : "add", edit.id, draft()); setEdit(undefined); })}>Save</button><button disabled={busy} onClick={() => setEdit(undefined)}>Cancel</button></div>
      {result && <pre className="mcp-output">{result}</pre>}
    </section>}
    {selected && <section className="panel"><div className="section-heading"><h2>{selected} / Tools</h2><button disabled={busy} onClick={() => void run(() => inspect(selected, true))}>Refresh tools</button></div><p>Classifications are set locally. Allowing a high-risk tool does not bypass approval. Policy changes stop this connection; start it again after editing.</p>{tools.length === 0 && <div className="empty">No cached tools. Start the service to discover its tools.</div>}{tools.map(tool => <details key={tool.name} className="mcp-tool"><summary>{tool.name} · {tool.policy.risk} · {tool.policy.permission}</summary><p>{tool.description}</p><pre className="mcp-output">{JSON.stringify(tool.inputSchema, null, 2)}</pre><div className="button-row"><label>Risk<select disabled={busy} value={tool.policy.risk} onChange={e => void run(() => changePolicy(tool.name, { ...tool.policy, risk: e.target.value }))}>{risks.map(risk => <option key={risk}>{risk}</option>)}</select></label><label>Permission<select disabled={busy} value={tool.policy.permission} onChange={e => void run(() => changePolicy(tool.name, { ...tool.policy, permission: e.target.value as Policy["permission"] }))}><option value="ask">Ask (allow once / session)</option><option value="allow">Always allow this tool when low risk</option><option value="deny">Deny</option></select></label></div></details>)}</section>}
    {logs && <section className="panel"><h2>{logs} / Process diagnostics</h2><pre className="mcp-output">{services.find(s => s.id === logs)?.runtime.logs.join("") || "No stderr output recorded."}</pre><h3>Initialization metadata</h3><pre className="mcp-output">{JSON.stringify(services.find(s => s.id === logs)?.runtime.serverInfo, null, 2)}</pre><p>Invocation history, agent identity, permission decisions and results appear in Audit and Data Shared.</p></section>}
  </>;
}
