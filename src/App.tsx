import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type Tab = "dashboard" | "approvals" | "clients" | "projects" | "tasks" | "audit" | "shared" | "settings";
type Row = Record<string, unknown>;

interface Status {
  version: string; state: string; remote_access: boolean; emergency_latched: boolean;
  fault?: string; config_fault?: string; audit_fault?: string; listener?: string;
  setup_completed: boolean; shell_checks_enabled: boolean; trusted_root: string;
  trusted_root_exists: boolean; running_tasks: number; pending_approvals: number;
  pending_connections: number; projects: number; helper_available: boolean;
  unknown_outcomes: number; public: { mcp_url: string; configured: boolean }; sessions: Row[];
}

interface Approval extends Row {
  approval_id: string; client_display_name?: string; tool_name: string; category: string;
  reason: string; risk: string; requires_admin: boolean; status: string; expires_at: number;
  summary: { paths: string[]; impact: string; command?: string };
}

interface Connection extends Row {
  request_id: string; client_name: string; pairing_code: string; scopes: string[]; expires_at: number;
}

interface SettingsDoc extends Row {
  network: { port: number; public_mcp_url?: string };
  shell_protection: { enabled: boolean };
  general: { autostart: boolean; close_to_tray: boolean };
  notifications: { enabled: boolean; approvals: boolean; connections: boolean; task_failures: boolean };
  sessions: { idle_timeout_minutes: number; absolute_lifetime_hours: number; pending_approval_minutes: number };
}

const tabs: Array<[Tab, string]> = [
  ["dashboard", "Dashboard"], ["approvals", "Approvals"], ["clients", "Clients"],
  ["projects", "Projects"], ["tasks", "Tasks"], ["audit", "Audit"],
  ["shared", "Data Shared"], ["settings", "Settings"]
];

function text(value: unknown): string {
  if (value === null || value === undefined) return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}
function date(value: unknown): string { return typeof value === "number" ? new Date(value).toLocaleString() : "—"; }
function short(value: unknown, max = 90): string { const rendered = text(value); return rendered.length > max ? `${rendered.slice(0, max)}…` : rendered; }
function Card({ label, value, tone }: { label: string; value: string | number; tone?: string }) { return <div className={`card ${tone ?? ""}`}><span>{label}</span><strong>{value}</strong></div>; }
function Empty({ children }: { children: string }) { return <div className="empty">{children}</div>; }
function ErrorBanner({ error, clear }: { error: string; clear: () => void }) { return <div className="error"><span>{error}</span><button onClick={clear}>Dismiss</button></div>; }

function Setup({ onDone }: { onDone: () => Promise<void> }) {
  const [port, setPort] = useState(7413); const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const submit = async () => {
    setBusy(true); setError("");
    try {
      await invoke("complete_setup", { request: { port, public_mcp_url: url.trim() || null, autostart: true, create_projects_folder: true, enable_remote_access: true } });
      await onDone();
    } catch (reason) { setError(String(reason)); } finally { setBusy(false); }
  };
  return <main className="setup"><div className="setup-panel">
    <div className="brand-mark">LP</div><p className="eyebrow">FIRST-RUN SETUP</p>
    <h1>Give agents a guarded place to work.</h1>
    <p>Local Pilot will create or use your Windows Documents\Projects folder, listen only on loopback, and keep remote access under this desktop control surface.</p>
    {error && <ErrorBanner error={error} clear={() => setError("")} />}
    <label>Local MCP port<input type="number" min="1024" max="65535" value={port} onChange={event => setPort(Number(event.target.value))} /></label>
    <label>Public MCP URL <small>Optional until your tunnel is ready</small><input placeholder="https://pilot.example.com/mcp" value={url} onChange={event => setUrl(event.target.value)} /></label>
    <button className="primary wide" disabled={busy} onClick={submit}>{busy ? "Starting…" : "Create workspace and start"}</button>
    <p className="fine">Shell checks start enabled. Structured-tool policy cannot be disabled.</p>
  </div></main>;
}

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard"); const [status, setStatus] = useState<Status>();
  const [approvals, setApprovals] = useState<Approval[]>([]); const [connections, setConnections] = useState<Connection[]>([]);
  const [clients, setClients] = useState<Row[]>([]); const [projects, setProjects] = useState<Row[]>([]);
  const [tasks, setTasks] = useState<Row[]>([]); const [audit, setAudit] = useState<Row[]>([]);
  const [shared, setShared] = useState<Row[]>([]); const [settings, setSettings] = useState<SettingsDoc>();
  const [error, setError] = useState(""); const [busy, setBusy] = useState("");
  const [token, setToken] = useState(""); const [taskOutput, setTaskOutput] = useState("");

  const load = useCallback(async () => {
    try {
      const current = await invoke<Status>("status"); setStatus(current);
      if (!current.setup_completed) return;
      const results = await Promise.all([
        invoke<Approval[]>("approvals"), invoke<Connection[]>("pending_connections"), invoke<Row[]>("clients"),
        invoke<Row[]>("projects"), invoke<Row[]>("tasks"), invoke<Row[]>("audit_events"),
        invoke<Row[]>("shared_data"), invoke<SettingsDoc>("settings")
      ]);
      setApprovals(results[0]); setConnections(results[1]); setClients(results[2]); setProjects(results[3]);
      setTasks(results[4]); setAudit(results[5]); setShared(results[6]); setSettings(results[7]);
    } catch (reason) { setError(String(reason)); }
  }, []);

  useEffect(() => {
    void load(); const timer = window.setInterval(() => void load(), 5000);
    const unlisten = listen("local-pilot", () => void load());
    return () => { window.clearInterval(timer); void unlisten.then(stop => stop()); };
  }, [load]);

  const act = async (name: string, command: string, args: Row = {}) => {
    setBusy(name); setError("");
    try { await invoke(command, args); await load(); } catch (reason) { setError(String(reason)); } finally { setBusy(""); }
  };
  const pending = useMemo(() => approvals.filter(item => item.status === "pending"), [approvals]);
  if (!status) return <main className="loading"><div className="brand-mark">LP</div><p>Starting Local Pilot…</p>{error && <ErrorBanner error={error} clear={() => setError("")} />}</main>;
  if (!status.setup_completed) return <Setup onDone={load} />;

  return <div className="shell"><aside>
    <div className="brand"><div className="brand-mark small">LP</div><div><strong>Local Pilot</strong><span>Workstation control</span></div></div>
    <nav>{tabs.map(([id, label]) => <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>{label}{id === "approvals" && pending.length > 0 && <b>{pending.length}</b>}</button>)}</nav>
    <div className="aside-state"><i className={status.remote_access ? "online" : "offline"} /><div><strong>{status.state.replaceAll("_", " ")}</strong><span>{status.listener ?? "Listener stopped"}</span></div></div>
    <button className="emergency" onClick={() => void act("emergency", "emergency_stop")}>Emergency Stop</button>
  </aside><main className="content">
    <header><div><p className="eyebrow">LOCAL WORKSTATION</p><h1>{tabs.find(([id]) => id === tab)?.[1]}</h1></div><button className="ghost" onClick={() => void load()}>Refresh</button></header>
    {error && <ErrorBanner error={error} clear={() => setError("")} />}
    {(status.fault || status.config_fault || status.audit_fault) && <div className="fault"><strong>Local attention required</strong><span>{status.fault || status.config_fault || status.audit_fault}</span></div>}

    {tab === "dashboard" && <><section className="cards">
      <Card label="Remote access" value={status.remote_access ? "Accepting" : "Paused"} tone={status.remote_access ? "good" : "warn"} />
      <Card label="Connected sessions" value={status.sessions.length} /><Card label="Running tasks" value={status.running_tasks} />
      <Card label="Pending approvals" value={status.pending_approvals} tone={status.pending_approvals ? "warn" : ""} />
    </section><section className="panel hero"><div><p className="eyebrow">TRUSTED WORKSPACE</p><h2>{status.trusted_root}</h2><p>{status.projects} indexed projects · shell checks {status.shell_checks_enabled ? "on" : "off"} · helper {status.helper_available ? "available" : "not installed"}</p></div><div className="button-row">
      {status.emergency_latched ? <button className="primary" onClick={() => void act("resume", "resume_after_emergency")}>Resume after Emergency Stop</button> : <button onClick={() => void act("access", "set_remote_access", { enabled: !status.remote_access })}>{status.remote_access ? "Pause access" : "Enable access"}</button>}
      <button onClick={() => void act("restart", "restart_mcp")}>Restart MCP</button>
    </div></section><section className="split"><div className="panel"><h2>Public connection</h2><code>{status.public.configured ? status.public.mcp_url : "No public URL configured"}</code><p>The local listener stays on loopback. Configure the tunnel separately.</p></div><div className="panel"><h2>Needs attention</h2><p>{connections.length} connection requests · {status.unknown_outcomes} unknown outcomes</p><p>{status.trusted_root_exists ? "Workspace is available." : "Trusted workspace is missing."}</p></div></section></>}

    {tab === "approvals" && <><section className="panel"><h2>Connection consent</h2>{connections.length === 0 ? <Empty>No OAuth connections are waiting.</Empty> : connections.map(item => <article className="request" key={item.request_id}><div><strong>{item.client_name}</strong><span>Pairing code {item.pairing_code}</span><small>{item.scopes.join(" · ")}</small></div><div className="button-row"><button className="primary" onClick={() => void act(item.request_id, "decide_connection", { requestId: item.request_id, approve: true })}>Approve</button><button onClick={() => void act(item.request_id, "decide_connection", { requestId: item.request_id, approve: false })}>Deny</button></div></article>)}</section>
      <section className="panel"><h2>Operation approvals</h2>{pending.length === 0 ? <Empty>No operations are waiting.</Empty> : pending.map(item => <article className="request" key={item.approval_id}><div><strong>{item.tool_name} · {item.category}</strong><span>{item.client_display_name ?? "Unknown client"} · {item.risk} risk{item.requires_admin ? " · administrator" : ""}</span><p>{item.reason}</p><small>{item.summary.impact} {item.summary.paths.join(", ")}</small></div><div className="button-row vertical"><button className="primary" onClick={() => void act(item.approval_id, "decide_approval", { approvalId: item.approval_id, decision: "allow_once" })}>Allow once</button><button onClick={() => void act(item.approval_id, "decide_approval", { approvalId: item.approval_id, decision: "allow_session" })}>Allow for session</button><button onClick={() => void act(item.approval_id, "decide_approval", { approvalId: item.approval_id, decision: "deny" })}>Deny</button></div></article>)}</section></>}

    {tab === "clients" && <section className="panel"><div className="section-head"><h2>Authorized clients</h2><button onClick={async () => { const name = window.prompt("Client display name"); if (name) await act("create", "create_client", { name }); }}>Add manual client</button></div>{token && <div className="token"><strong>Copy this token now. It will not be shown again.</strong><code>{token}</code><button onClick={() => setToken("")}>I saved it</button></div>}{clients.length === 0 ? <Empty>No clients yet.</Empty> : clients.map(client => <article className="row-card" key={text(client.client_id)}><div><strong>{text(client.display_name)}</strong><span>{text(client.vendor_label)} · last seen {date(client.last_seen_at)}</span><small>{text(client.client_id)}</small></div><div className="button-row"><button onClick={async () => { try { const result = await invoke<{ token: string }>("create_manual_token", { clientId: client.client_id }); setToken(result.token); await load(); } catch (reason) { setError(String(reason)); } }}>Create token</button><button onClick={() => void act(text(client.client_id), "set_client_enabled", { clientId: client.client_id, enabled: !client.enabled })}>{client.enabled ? "Disable" : "Enable"}</button><button onClick={() => void act(text(client.client_id), "disconnect_client", { clientId: client.client_id })}>Disconnect</button></div></article>)}</section>}

    {tab === "projects" && <section className="panel"><div className="section-head"><h2>Indexed projects</h2><button disabled={busy === "refresh-projects"} onClick={() => void act("refresh-projects", "refresh_projects")}>Refresh index</button></div>{projects.length === 0 ? <Empty>No projects found under the trusted root.</Empty> : projects.map(item => { const project = (item.project ?? {}) as Row; return <article className="row-card" key={text(project.project_id)}><div><strong>{text(project.display_name)}</strong><span>{text(project.canonical_path)}</span><small>{text(project.detected_project_types)} · {text(project.detected_languages)} · {project.git_repository ? "Git" : "No Git repository"}</small></div><span className="pill">{item.lease ? "write lease active" : "available"}</span></article>; })}</section>}

    {tab === "tasks" && <section className="panel"><h2>Managed tasks</h2>{taskOutput && <div className="output"><button onClick={() => setTaskOutput("")}>Close output</button><pre>{taskOutput}</pre></div>}{tasks.length === 0 ? <Empty>No managed tasks recorded.</Empty> : tasks.map(item => <article className="row-card" key={text(item.task_id)}><div><strong>{short(item.command)}</strong><span>{text(item.status)} · {text(item.tool_name)} · PID {text(item.pid)}</span><small>{text(item.cwd)}</small></div><div className="button-row"><button onClick={async () => { try { const value = await invoke<Row>("task_output", { taskId: item.task_id }); const chunks = Array.isArray(value.chunks) ? value.chunks as Row[] : []; setTaskOutput(chunks.map(chunk => `[${text(chunk.stream)}] ${text(chunk.text)}`).join("")); } catch (reason) { setError(String(reason)); } }}>Output</button>{item.status === "running" && <><button onClick={() => void act(text(item.task_id), "stop_task", { taskId: item.task_id, force: false })}>Cancel</button><button onClick={() => void act(text(item.task_id), "stop_task", { taskId: item.task_id, force: true })}>Kill</button></>}</div></article>)}</section>}

    {tab === "audit" && <LogTable title="Audit history" rows={audit} columns={["timestamp_start", "kind", "tool_name", "result_status"]} />}
    {tab === "shared" && <LogTable title="Data Shared" rows={shared} columns={["timestamp", "tool_name", "source_path", "byte_count"]} />}
    {tab === "settings" && settings && <Settings settings={settings} setSettings={setSettings} save={async () => { setBusy("save"); try { const next = await invoke<SettingsDoc>("save_settings", { settings }); setSettings(next); await load(); } catch (reason) { setError(String(reason)); } finally { setBusy(""); } }} stop={() => void invoke("stop_application")} busy={busy === "save"} />}
  </main></div>;
}

function LogTable({ title, rows, columns }: { title: string; rows: Row[]; columns: string[] }) {
  return <section className="panel"><h2>{title}</h2>{rows.length === 0 ? <Empty>No records yet.</Empty> : <div className="table"><div className="table-head">{columns.map(column => <span key={column}>{column.replaceAll("_", " ")}</span>)}</div>{rows.map((item, index) => <div className="table-row" key={`${text(item.event_id ?? item.share_event_id)}-${index}`}>{columns.map(column => <span title={text(item[column])} key={column}>{column.includes("time") || column.endsWith("_at") ? date(item[column]) : short(item[column])}</span>)}</div>)}</div>}</section>;
}

function Settings({ settings, setSettings, save, stop, busy }: { settings: SettingsDoc; setSettings: (value: SettingsDoc) => void; save: () => Promise<void>; stop: () => void; busy: boolean }) {
  const update = (section: "network" | "shell_protection" | "general" | "notifications" | "sessions", key: string, value: unknown) => { const next = structuredClone(settings); (next[section] as Row)[key] = value; setSettings(next); };
  return <><section className="panel form-grid"><h2>Security and connection</h2>
    <label>Local port<input type="number" value={settings.network.port} onChange={event => update("network", "port", Number(event.target.value))} /></label>
    <label>Public MCP URL<input value={settings.network.public_mcp_url ?? ""} onChange={event => update("network", "public_mcp_url", event.target.value || null)} /></label>
    <label className="toggle"><input type="checkbox" checked={settings.shell_protection.enabled} onChange={event => update("shell_protection", "enabled", event.target.checked)} /><span>Shell protection checks</span><small>Best-effort preflight for PowerShell, cmd, and raw processes.</small></label>
    <label className="toggle"><input type="checkbox" checked={settings.general.autostart} onChange={event => update("general", "autostart", event.target.checked)} /><span>Start with Windows</span></label>
    <label className="toggle"><input type="checkbox" checked={settings.general.close_to_tray} onChange={event => update("general", "close_to_tray", event.target.checked)} /><span>Keep running when the window closes</span></label>
    <label className="toggle"><input type="checkbox" checked={settings.notifications.enabled} onChange={event => update("notifications", "enabled", event.target.checked)} /><span>Windows notifications</span></label>
    <label className="toggle"><input type="checkbox" checked={settings.notifications.approvals} disabled={!settings.notifications.enabled} onChange={event => update("notifications", "approvals", event.target.checked)} /><span>Approval notifications</span></label>
    <label className="toggle"><input type="checkbox" checked={settings.notifications.connections} disabled={!settings.notifications.enabled} onChange={event => update("notifications", "connections", event.target.checked)} /><span>Connection notifications</span></label>
    <label className="toggle"><input type="checkbox" checked={settings.notifications.task_failures} disabled={!settings.notifications.enabled} onChange={event => update("notifications", "task_failures", event.target.checked)} /><span>Task failure notifications</span></label>
    <label>Session idle timeout (minutes)<input type="number" value={settings.sessions.idle_timeout_minutes} onChange={event => update("sessions", "idle_timeout_minutes", Number(event.target.value))} /></label>
    <label>Session maximum lifetime (hours)<input type="number" value={settings.sessions.absolute_lifetime_hours} onChange={event => update("sessions", "absolute_lifetime_hours", Number(event.target.value))} /></label>
    <label>Approval lifetime (minutes)<input type="number" value={settings.sessions.pending_approval_minutes} onChange={event => update("sessions", "pending_approval_minutes", Number(event.target.value))} /></label>
    <div className="form-actions"><button className="primary" disabled={busy} onClick={() => void save()}>{busy ? "Saving…" : "Save settings"}</button></div>
  </section><section className="panel danger-zone"><div><h2>Stop application</h2><p>Terminates managed task trees, stops MCP, flushes state, and exits Local Pilot.</p></div><button onClick={stop}>Stop Local Pilot</button></section></>;
}
