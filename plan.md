# Local Pilot — Implementation Plan

> **Purpose:** Build a public, installable Windows 11 desktop application that exposes a user's local development workstation to authorized MCP-compatible agents, with ChatGPT as the first supported client. The application must permit ordinary development inside the current user's `Documents\Projects` directory, enforce policy on structured tools, provide best-effort shell protections, support Git/GitHub workflows, maintain a redacted local audit trail within configured retention limits, and expose the MCP server remotely through a user-supplied public MCP URL.
>
> **Primary implementation target:** Windows 11 x64.
>
> **Recommended stack:** Rust + Tauri + React/TypeScript UI + SQLite.
>
> **MCP target:** Current stable MCP Streamable HTTP, using the official Rust MCP SDK (`rmcp`) where practical. Preserve compatibility with the prior stable protocol revision when the SDK provides it.
>
> **Important:** This document is an implementation specification for a coding agent. Follow it in phases. Do not silently weaken security requirements to make implementation easier.

---

## 1. Product Definition

Build a Windows application named **Local Pilot**. Use `LocalPilot` for its application-data directory and `local-pilot` for package identifiers where appropriate.

The application turns a Windows 11 desktop into a remotely accessible MCP workstation for AI agents. It is intended for software-development work, project inspection, shell commands, Git/GitHub operations, tests, builds, package installation, and related terminal-driven work.

The application is **not** a GUI remote-desktop system. Do not implement remote mouse control, remote keyboard control, screenshot streaming, or image passing.

The first supported integration is ChatGPT using an authenticated remote MCP connection in developer mode. Keep the core provider-neutral and add other clients through a tested compatibility matrix; do not promise compatibility with every MCP host before testing it. Public plugin-directory submission is not required for the initial working integration.

The default trusted workspace is:

```text
%USERPROFILE%\Documents\Projects
```

Do not hard-code a username or drive letter. Resolve the Windows Documents known folder dynamically using the appropriate Windows API. Do not assume it is always under `C:\Users\<name>\Documents`; it may be redirected to OneDrive or another location.

All project folders are children of the resolved `Projects` directory.

## 1.1 Implementation decisions

This revision incorporates the owner's decisions from September 19, 2026:

- Strict enforcement for application-mediated structured tools; best-effort protection for arbitrary shells and executables.
- A local Settings switch for shell checks, default ON. The implementation interpretation is that this switch affects shell checks only; structured-tool authorization remains enforced. See Section 4.
- ChatGPT first, including the OAuth flow needed for that integration; manual client tokens remain available for compatible clients and local testing.
- Approval grants permission but does not execute the pending action. The requesting client explicitly resumes the stored operation, with duplicate-execution protection.
- One narrow external-write exception rooted at `%LOCALAPPDATA%\LocalPilot\cache\temp`, with tool/task-specific children.
- Application-managed sessions with adjustable expiry and revocation behavior.

Bootstrap in the existing Git checkout, currently the nested `Local-Pilot` directory beside this plan. Do not initialize a second repository. During Phase 0, place the authoritative plan in that checkout and leave a pointer at the old location if needed; never maintain two independently edited specifications.

License selection is required before public release, but does not block local implementation. Public hostname, release/update hosting, signing-key custody, and Windows installer code-signing arrangements must be finalized before their deployment/release phases. Do not generate or commit private signing material as part of planning.

---

# 2. Core Permission Model

## 2.1 Trusted workspace

Anything whose **canonical filesystem path** resolves inside:

```text
<CurrentUserDocuments>\Projects
```

is the trusted workspace.

Inside this trusted workspace, an authorized agent may, by default:

- create files and directories;
- read files and directories;
- edit files;
- rename/move files;
- delete files and directories;
- create new projects;
- run executables and scripts;
- invoke PowerShell;
- invoke Command Prompt;
- run local package managers;
- install project-local dependencies;
- build software;
- run tests;
- run Playwright that is already installed/configured;
- invoke Git;
- invoke GitHub CLI (`gh`);
- start long-running development processes;
- terminate processes that the MCP workstation itself started;
- access the Internet from launched tools;
- clone repositories into the trusted workspace.

All subdirectories under the trusted workspace are trusted automatically, subject to protected-resource rules, application-control-data protection, and the explicit Git/admin exceptions below. These permissions are enforced by structured tools; arbitrary process behavior has the limitations in Section 4.

The trusted workspace rule must use canonicalized paths, not string-prefix matching.

Example:

```text
C:\Users\Alice\Documents\Projects\Clippy
```

is trusted.

This must **not** be considered trusted:

```text
C:\Users\Alice\Documents\Projects-Backup
```

Neither should path traversal or junction tricks be able to escape the trusted workspace.

---

## 2.2 Outside the trusted workspace

Outside `Documents\Projects`:

### Read operations

Read-only operations are generally allowed without asking the user, except for protected secret/credential locations.

Examples of automatically permitted reads:

- listing a normal directory;
- reading source files;
- reading configuration files that are not identified as credentials;
- reading installed program metadata;
- checking file existence;
- inspecting system information;
- querying environment/path information after secret filtering.

### Write/edit/delete operations

Application-mediated mutations outside the trusted workspace require explicit local user approval, except for the scoped cache/temp allowance in Section 14 and locally configured policy grants. Application maintenance of its own settings, logs, index, and updates is not an agent-granted filesystem exception.

This includes:

- creating files;
- modifying files;
- deleting files;
- moving/renaming files;
- changing ACLs;
- changing registry values;
- installing system-wide software;
- changing services;
- modifying startup configuration;
- changing firewall/network configuration;
- modifying application configuration outside the trusted project root;
- destructive Git actions affecting resources outside the trusted workspace;
- any administrative operation.

The approval should identify:

- requesting client/agent;
- requested operation;
- exact path(s);
- requested command if applicable;
- why the server classified it as requiring approval;
- potential impact;
- whether elevation is required.

The approval dialog must provide:

```text
Allow once
Allow for this session
Deny
```

Do not provide a permanent allow button inside the prompt itself. Persistent policy changes belong in Settings.

---

# 3. Protected Secrets and Credential Locations

Agents must not receive secrets from this MCP workstation simply because they can read the user's filesystem.

If an agent needs a secret, token, password, API key, private key, or similar information, it should request that information from the user directly through the agent's normal conversation interface.

The MCP server must **not** expose secret material from protected locations.

At minimum protect:

```text
%USERPROFILE%\.ssh
%USERPROFILE%\.aws
%USERPROFILE%\.azure
%USERPROFILE%\.gnupg
%USERPROFILE%\.kube
%APPDATA%\Microsoft\Credentials
%LOCALAPPDATA%\Microsoft\Credentials
Windows Credential Manager backing data
browser password stores / browser credential databases
password-manager storage
Git credential-store files
Cloudflare API/token credential stores
private-key files
known credential caches
```

Also protect by filename/pattern where reasonable:

```text
.env
.env.*
*.pem
*.pfx
*.p12
id_rsa
id_ed25519
credentials*
secrets*
*token*
```

Do not blindly block every file whose name contains a generic word such as `token` if that would make normal project development unusable. Protected-path rules should be deterministic and configurable.

Project `.env` behavior:

- By default, project `.env` files should be treated as sensitive.
- An agent may cause a local command to **use** environment configuration if the project already uses it, but direct file-content reads of secret-bearing `.env` files should be blocked unless the user explicitly changes policy.
- Do not return secret content in tool results, logs, or Data Shared records without explicit policy.
- If the application cannot confidently distinguish safe from sensitive `.env` content, classify it as sensitive.

### Credential use vs credential disclosure

Programs such as `git` and `gh` may use credentials already available to those programs through Windows/GitHub authentication.

That is allowed.

The MCP server may allow the local program to authenticate using an existing secure credential store, while still preventing the agent from reading/exporting the credential itself.

Examples:

```text
Allowed:
gh pr create
git push

Not allowed:
gh auth token
type %USERPROFILE%\.config\gh\hosts.yml
dump Git Credential Manager secrets
```

Create explicit policy rules for known credential-export commands.

### Policy precedence and protected operations

Protected-resource rules take precedence over trusted-workspace and cache/temp allowances. Apply them to direct reads, search snippets, indexing, binary/ranged reads, Git output, copy/move sources, and recursive directory operations. A copy into a trusted directory must not bypass source protection. Do not disclose protected content through error messages or previews.

By default, structured tools also deny modification, deletion, or relocation of protected secret files. Permit a narrowly scoped exception only through local Settings; an ordinary external-write approval is not a secret-disclosure grant. Support local exceptions for known non-secret templates such as `.env.example` rather than assuming every matching file is safe.

Treat Local Pilot's configuration, credentials, approval/session database, executable/helper files, audit storage, and update state as application control data. Agents cannot read or modify these through MCP tools; the cache/temp subtree is the separately classified exception. Local UI actions use authenticated backend APIs. These rules do not create OS isolation from same-user arbitrary processes; disclose that residual risk under Section 4.

---

# 4. Important Shell-Sandbox Limitation

The application must be honest about what it can and cannot enforce.

If arbitrary PowerShell/cmd/native programs execute as the same Windows user, that process may have the same filesystem rights as that Windows account. A userspace application cannot universally intercept every filesystem write performed by arbitrary native child processes without stronger OS-level isolation.

Therefore implement two layers:

## Layer A — Mandatory broker/policy enforcement

The MCP server must strictly enforce paths for every application-mediated filesystem tool.

Examples:

```text
read_file
write_file
patch_file
delete
move
copy
create_directory
list_directory
find
get_many
```

The server must also preflight shell commands, detect explicit paths/actions when possible, and prompt before clearly outside-workspace writes.

## Layer B — Shell guard / process monitoring

Implement reasonable shell protections:

- canonical working-directory checks;
- PowerShell AST inspection when launching PowerShell scripts/commands;
- command classification;
- known write-command detection;
- package-manager classification;
- Git/GitHub command classification;
- child-process tracking;
- post-operation filesystem monitoring/auditing where feasible;
- blocking known credential-dump/export commands;
- optional stronger containment architecture documented for future releases.

Do **not** claim that raw shell execution is a perfect filesystem sandbox unless an OS-level mechanism actually guarantees it.

Document this limitation in the application and project README.

The v1 security contract is strict enforcement at structured-tool boundaries and best-effort checks for raw commands. Same-user programs may read credentials, write outside approved paths, tamper with same-user app data, or send data directly over the network. Redaction and command inspection cannot guarantee prevention of these behaviors. Acceptance tests must distinguish broker enforcement from shell detection coverage; do not claim protection against every malicious program or complete observation of its side effects.

Provide a local-only **Shell protection checks** setting, default ON. Turning it OFF bypasses shell/process preflight blocks and approval prompts based on command/path classification, including detected credential-export and Git actions; show the exact scope and persistently display the disabled status. Continue authentication, structured-tool policy, standard-user execution, resource limits, task tracking, output redaction, auditing, and Emergency Stop. The switch never authorizes elevation or changes Windows permissions. Audit changes and revoke pending shell approvals when the mode changes. Remote tools cannot change this setting. This is the default interpretation of the owner's requested off switch, not a global authorization bypass.

Do not silently remove raw PowerShell/cmd support to avoid the problem; raw shells are a required feature.

---

# 5. Process Execution Model

Provide both structured process execution and raw shell execution.

Required MCP capabilities:

```text
process.run
shell.powershell
shell.cmd
task.get
task.list
task.output
task.cancel
task.kill
```

Conceptual signatures:

```text
process.run(
    executable,
    args[],
    cwd?,
    env_overrides?,
    timeout?,
    background?
)
```

```text
shell.powershell(
    script,
    cwd?,
    timeout?,
    background?
)
```

```text
shell.cmd(
    command,
    cwd?,
    timeout?,
    background?
)
```

Use Windows Job Objects so agent-launched child processes can be tracked as a tree.

Each running operation must receive a unique task ID.

Example:

```json
{
  "task_id": "task_01J...",
  "status": "running",
  "pid": 12345,
  "cwd": "C:\\Users\\Alice\\Documents\\Projects\\Clippy"
}
```

Long-running jobs must not require one HTTP request to remain open indefinitely.

Store stdout/stderr incrementally.

Provide bounded output retrieval:

```text
task.output(task_id, offset?, max_bytes?)
```

The application must prevent unbounded log memory usage.

Tasks, output, approvals, and session records belong to the authenticated Local Pilot principal that created them. A client can list, read, resume, cancel, or kill only its own records by default; the local UI can manage all clients. Credential rotation preserves ownership only for the same local principal. Opaque IDs are not authorization.

Run processes under a standard-user token even if the desktop app was launched elevated; fail closed if a standard-user launch cannot be established. Assign processes to their Job Object before allowing them to execute. A generic elevated launch is not part of `process.run` or the raw-shell tools.

---

# 6. Environment Handling

By default, agent-started commands should inherit the current user's normal Windows environment sufficiently to use installed developer tools.

Examples:

```text
PATH
HOME/USERPROFILE
TEMP/TMP
Git configuration
Node/Python/Cargo toolchains
Visual Studio tools where available
```

However, sensitive environment variables must be filtered before being exposed to the agent or stored in logs.

Examples to redact/block by default:

```text
*_TOKEN
*_SECRET
*_PASSWORD
*_KEY
OPENAI_API_KEY
ANTHROPIC_API_KEY
AWS_SECRET_ACCESS_KEY
GITHUB_TOKEN
GH_TOKEN
CLOUDFLARE_API_TOKEN
Authorization-style values
```

The desktop application must contain an **Environment** settings page where the user can:

- inspect which variable names are available to agent-launched processes;
- mark variables as allowed;
- mark variables as denied;
- control whether allowed values may be shown to agents or only inherited by child processes;
- reset to safe defaults.

Default behavior:

```text
process may inherit approved secret if needed by a configured tool
agent may not read/display secret value
logs must redact it
```

Secret variables are excluded from child environments by default. A configured-tool grant is a locally created mapping of variable names to an identified executable/tool profile and optional project scope. A process cannot grant itself inheritance using `env_overrides`, an executable alias, or an MCP argument. Revalidate the executable identity before launch and require review if it changes. Keep inherited secrets out of tool schemas/results, persisted arguments, and UI values unless separate disclosure policy permits them. Tool-profile grants reduce accidental exposure but cannot stop an authorized arbitrary program from exporting a secret it receives.

Set `TEMP` and `TMP` to the task's approved cache/temp directory and apply supported package-cache overrides there. Do not redirect the user's entire profile or credential configuration into that directory.

---

# 7. Project Discovery and Folder Map

Maintain an indexed folder map for all projects under the trusted Projects root.

The application should automatically detect projects by common markers such as:

```text
.git
package.json
Cargo.toml
pyproject.toml
requirements.txt
Pipfile
poetry.lock
go.mod
CMakeLists.txt
*.sln
*.csproj
*.vcxproj
pom.xml
build.gradle
gradlew
composer.json
Gemfile
```

Each indexed project should store at least:

```text
project_id
display_name
canonical_path
detected_project_types
detected_languages
git_repository_boolean
git_remote_urls (redacted if credentials embedded)
default_branch if known
last_scan_time
last_modified_time
search aliases
```

Use filesystem watching (`notify` or equivalent) so the map updates after the initial scan.

Do not continuously rescan the entire tree unnecessarily.

SQLite should persist the project index.

Use SQLite FTS5 where useful for project names/aliases and filename indexing.

Required MCP tools:

```text
projects.list
projects.resolve
projects.get
projects.refresh
files.find
files.search_names
files.search_text
```

Example:

```text
projects.resolve("Clippy")
```

returns:

```json
{
  "name": "Clippy",
  "path": "C:\\Users\\Alice\\Documents\\Projects\\Clippy",
  "confidence": 1.0
}
```

If direct project resolution fails, automatically fall back to filename/directory search.

For content search, prefer a fast local implementation such as ripgrep or a Rust-native equivalent.

Never send the entire project index to a remote agent when only a small subset is required.

---

# 8. Filesystem MCP Tool Surface

Implement a clear filesystem tool API.

Required minimum set:

```text
fs.stat
fs.exists
fs.list
fs.find
fs.get_many_metadata
fs.read_text
fs.read_bytes
fs.write_text
fs.write_bytes
fs.patch
fs.mkdir
fs.copy
fs.move
fs.delete
```

Every path must be:

1. expanded safely;
2. converted to an absolute path;
3. canonicalized as far as possible;
4. checked against junction/symlink/reparse-point behavior;
5. classified as trusted, normal external read, protected, or approval-required;
6. audited.

For a not-yet-existing write target, canonicalize the closest existing parent, then append the validated remaining path segments.

Prevent:

```text
..\..\escape
UNC path surprises
alternate data streams where inappropriate
device namespace paths
\\?\ path policy bypasses
junction/reparse-point escapes
case-insensitive comparison bugs
8.3 path aliases
```

Use Windows-native path semantics.

Include file identity and hard-link handling in the broker design. Canonical names alone do not prove that a file has no alias outside the trusted directory. Deny ambiguous multi-link mutations by default, and deny reads when a multi-link file cannot be shown to satisfy protected-resource policy. Use handle-based identity checks for reads/protected resources and race-safe operations. See Section 45.

Do not use simple string prefix checks.

---

# 9. Junctions, Symlinks, Reparse Points, and Escape Tests

This project must include explicit adversarial tests.

Test cases must include:

```text
Documents\Projects\project\..\..\secret.txt
```

```text
Documents\Projects\project\link -> C:\Users\Alice\.ssh
```

```text
Documents\Projects2
```

```text
\\localhost\C$\...
```

```text
\\server\share\...
```

```text
\\?\C:\...
```

and relevant Windows reparse-point variants.

If a path resolves outside the trusted workspace, treat it according to the resolved destination, not its apparent parent directory.

---

# 10. Git Integration

Git operations are allowed inside trusted projects.

The application should expose convenient structured tools in addition to raw shell support.

Required structured Git tools:

```text
git.status
git.diff
git.log
git.branch_list
git.branch_create
git.checkout
git.fetch
git.pull
git.add
git.commit
git.push
git.remote_list
git.stash
```

Do not override the user's existing Git identity.

Use the repository/current Git configuration:

```text
user.name
user.email
```

Do not automatically inject an AI/agent identity.

## Default push policy

The default workflow is branch-first.

Direct push to the repository default branch requires local user approval.

The application must have a Git setting:

```text
Allow automatic pushes to default branch
```

Default:

```text
OFF
```

When off, direct push to main/master/default branch triggers an approval.

Normal push to a non-default working branch may proceed without approval unless another dangerous condition applies.

---

# 11. Destructive Git Operations

The following must require approval by default even when the repository is inside `Documents\Projects`:

```text
git reset --hard
git clean -f / -fd / -fdx
force push
--force
--force-with-lease
delete remote branch
rewrite published history
delete tags on remote
history filtering
destructive rebase that affects remote-shared history
```

Provide a settings toggle:

```text
Automatically allow destructive Git operations
```

Default:

```text
OFF
```

This setting should include a warning.

Do not silently categorize ordinary `git checkout`, `git restore` or rebases as destructive without considering actual arguments.

---

# 12. GitHub and GitHub CLI

The agent may use the locally installed/authenticated GitHub CLI.

The workstation must preserve the existing user's `gh` authentication.

Do not expose GitHub auth tokens to the agent.

## Mandatory attribution rule

**Never mention the agent, the agent model, the agent vendor, or the agent's company in official GitHub actions.**

This includes, but is not limited to:

- commit messages;
- commit author;
- commit committer;
- `Co-authored-by` trailers;
- PR titles;
- PR bodies;
- issue titles;
- issue bodies;
- GitHub comments;
- review comments;
- branch names;
- tag names;
- release titles;
- release notes;
- generated repository files intended only to disclose AI authorship;
- GitHub Actions metadata added for attribution;
- automated "generated by AI" notes.

Do not change the existing configured Git identity.

The coding agent working on this project must obey this rule itself while creating the repository.

Implement application guardrails where practical:

- classify Git and `gh` commands;
- reject obvious prohibited attribution phrases in structured Git/GitHub operations;
- warn/block common AI-attribution trailers;
- preserve configured Git identity;
- avoid adding automatic AI attribution;
- audit relevant shell commands.

Do not attempt to rewrite legitimate project text merely because it contains a vendor/company name for unrelated reasons.

---

# 13. GitHub Structured Tools

Structured GitHub operations are useful but not required for every GitHub function because `gh` is available.

Recommended tools:

```text
github.repo_view
github.issue_list
github.issue_create
github.issue_comment
github.pr_list
github.pr_view
github.pr_create
github.pr_comment
github.pr_checks
github.release_list
```

All content-writing tools must pass through the GitHub attribution policy.

Raw `gh` remains available through shell.

---

# 14. Package Management Rules

Project-local dependency installs inside trusted projects are allowed automatically.

This allowance includes only declared tool cache/temp writes within the managed exception below. It does not automatically authorize global installation, credential changes, or arbitrary writes elsewhere by install scripts; detecting such script behavior is subject to Section 4.

Examples:

```text
npm install
pnpm install
yarn install
pip install -r requirements.txt inside a project venv
poetry install
cargo build
cargo fetch
dotnet restore
go mod download
```

System-wide or user-global installs outside the project root should trigger approval.

### Managed cache/temp exception

Resolve Local AppData with the Windows known-folder API and create:

```text
%LOCALAPPDATA%\LocalPilot\cache\temp\
    tools\<tool-profile>\<principal-or-project-scope>\
    tasks\<task-id>\
```

The UI may label this **Cache / Temp**; `/` is a directory separator, not part of a Windows folder name. Only assigned tool/task subdirectories are approved for temporary files and dependency caches without an external-write prompt. Requests must match the owning task/principal and tool profile. This does not make all of Local AppData or the entire Local Pilot directory trusted.

Redirect known cache settings and `TEMP`/`TMP` for agent-launched tools into these locations. Classify all source and destination paths normally, including reparse points, hard links, and protected files. Never use caches for authentication tokens, persistent application settings, helper binaries, audit records, or update packages. The app must not load privileged code or policy from agent-writable cache content.

When a tool cannot redirect an external write, request approval through the normal policy rather than broadening the exception. Add configurable disk quotas and cleanup, protect active task directories from cleanup, and stop further cache allocation with a clear error when the quota cannot be satisfied. Do not promise arbitrary package scripts are contained by these path settings.

Examples:

```text
winget install ...
choco install ...
npm install -g ...
pip install into global interpreter
cargo install ...
PowerShell module installs into user/system module paths
```

The settings UI must include a policy option controlling system-wide package installs.

Default:

```text
Require approval
```

---

# 15. Playwright

Do not build special browser-control infrastructure.

Playwright is already available/configured on the user's machine for project testing.

Agents may invoke project test commands or Playwright CLI/scripts through normal process/shell tools.

The agent's own host may separately provide web-search capabilities. Do not proxy general-purpose web search through this MCP server unless a later feature explicitly adds it.

---

# 16. Administrative Operations

The desktop application runs as the current Windows user.

No separate Windows account is created.

Normal agent tasks run with standard-user rights.

Administrative activity requires local user approval.

Do not automatically grant an agent unrestricted administrative power merely because the main application process happens to be elevated.

Preferred architecture:

```text
Tauri desktop app / MCP host
        |
        +--> standard child process (normal task)
        |
        +--> privileged request
                 |
                 +--> local approval
                 |
                 +--> short-lived elevated helper
                         |
                         +--> one authorized operation
```

Implement an elevated helper executable with a narrow IPC interface.

Requirements:

- helper accepts only signed/validated requests from the main application;
- request includes nonce/request ID;
- operation and arguments are explicit;
- helper does not expose a general unauthenticated local admin socket;
- helper logs the operation;
- helper exits after the operation or a short idle timeout;
- do not leave an always-on SYSTEM service unless a later design explicitly requires it.

If the user launches the application itself as Administrator:

- still classify privileged operations;
- still require user approval where policy says approval is required;
- do not interpret elevated launch as "agent has unlimited admin permission."

---

# 17. Approval System

Create an internal approval engine.

An approval request should include:

```text
approval_id
client_id
agent/client display name
operation category
tool name
exact path(s)
command/executable
arguments
working directory
reason
risk classification
requires_admin
created_at
expires_at
```

Statuses:

```text
pending
allowed_once
allowed_session
denied
expired
cancelled
consumed
invalidated
```

"Allow for this session" must be scoped.

Example scope:

```text
client X
operation fs.write
path C:\SomeFolder\*
until explicit application-session termination or configured expiry
```

Do not interpret "allow session" as blanket permission for every action.

Persist the decision in the audit log.

Pending approvals must appear in the UI and trigger a Windows notification.

Agent calls that need approval must receive a deterministic result such as:

```json
{
  "status": "approval_required",
  "approval_id": "...",
  "message": "Local user approval is required before this operation can run."
}
```

Provide an MCP read-only status tool:

```text
approval.status(approval_id)
```

Also provide:

```text
approval.resume(approval_id)
session.current
session.end
```

### Approval execution contract

Store an immutable operation snapshot when returning `approval_required`. Bind it to the principal, application session, tool, normalized arguments/payload digest, resolved paths and identities, working directory, executable/script identity, policy revision, and expiry. Sensitive execution data must not enter redacted audit fields; store pending payloads only in protected transient storage and cancel them on restart.

Local approval changes permission state only. The originating client calls `approval.resume` to execute the stored request; it cannot replace its arguments. Revalidate identity, current policy, paths, and session immediately before execution. A changed target or executable requires a new request. `approval.status` never executes work.

Atomically consume an allow-once grant and assign a stable execution/task ID before dispatch. Concurrent or repeated resume requests return the existing execution state/result instead of dispatching again. Use client-scoped idempotency keys for mutating calls; reject reuse with different arguments. Expired, denied, cancelled, or revoked approvals cannot execute. Resume requires the original operation's authorization scope as well as ownership of the approval. A crash after dispatch may leave an outcome unknown: record that uncertainty and require reconciliation, never automatically replay the side effect.

Suggested pending-approval lifetime is 10 minutes, adjustable locally. Session grants use the exact operation/path scope shown in the dialog and do not authorize arbitrary commands. Log execution separately from the permission decision.

### Application sessions

An application session is distinct from an HTTP connection, OAuth access token, or legacy MCP transport session. Default to one active authorization session per Local Pilot principal/credential grant; multiple chats using that grant share its scoped permissions. Separate grants are required for separate permission lifetimes. Expose this clearly in the UI.

Defaults: 30-minute idle expiry and 8-hour absolute lifetime. Adjust both in Settings. Authenticated work and heartbeats from owned active tasks update idle activity; status polling alone does not. Absolute expiry remains enforced. Token refresh preserves the same session only while it remains valid. HTTP reconnects do not reset expiry or recreate prior permissions.

Explicit `session.end`, local disconnect, credential revocation/disable, Emergency Stop, and app restart invalidate all relevant session grants and pending approvals. Expiry removes permission for new operations; already authorized ordinary tasks may finish unless the user enables termination on expiry. Default **Terminate this client's tasks on revoke/disable/disconnect** is ON and adjustable locally. Even when OFF, reject new calls immediately and leave remaining tasks controllable through the local UI. Emergency Stop always terminates managed agent tasks.

The remote agent must never be able to approve its own request.

When MCP client support is mature/compatible, optionally map this flow to MCP multi-round-trip input or Tasks, but preserve the local approval boundary regardless of protocol convenience.

---

# 18. Emergency Stop

The main UI must have a highly visible **Emergency Stop** button.

On activation:

1. immediately stop accepting new MCP tool calls;
2. reject queued tool calls;
3. revoke all session approvals;
4. mark pending approvals cancelled;
5. terminate all agent processes contained in managed Job Objects, including separately tracked approved elevated helpers;
6. cancel active tasks where possible;
7. close active MCP client connections;
8. suspend remote access;
9. preserve logs;
10. leave the local desktop UI open;
11. require an explicit local action to re-enable remote access.

Emergency Stop must not:

- shut down Windows;
- kill unrelated processes;
- delete projects;
- clear audit logs.

Use Windows Job Objects/process tracking so termination of contained process trees is reliable. Arbitrary programs may delegate work to pre-existing services or create processes outside the tracked tree; document and test these limits rather than claiming universal process containment. Do not kill unrelated service processes to compensate.

Stop accepting work and terminate managed tasks immediately; persist the EmergencyStopped latch before acknowledging durable completion. Persistence failure must not delay the immediate stop and must leave a visible fault. Use a crash-safe remote-access startup gate so an unclean shutdown or missing/unknown durable state cannot silently re-enable access. MCP restart, app relaunch, Windows reboot, token refresh, and autostart must not clear a stop latch. Only an explicit local Resume action re-enables access. Cancelling local work cannot undo an already completed filesystem or remote Git/GitHub side effect.

The UI must clearly display:

```text
REMOTE ACCESS DISABLED
```

after emergency stop.

---

# 19. Restart and Full Stop

## Restart

Restart should restart the MCP listener/control subsystem without restarting Windows.

Prompt or setting:

```text
Terminate active agent tasks before restart?
```

Default:

```text
Yes
```

The Tauri UI should remain open if possible.

MCP restart invalidates sessions and approvals regardless of whether active tasks are preserved. Preserved tasks retain their owner, Job Objects, and output capture; reconnecting does not restore their old session permissions. Restart never clears Emergency Stop.

## Full Stop

Provide a separate **Stop Application** action.

It should:

- stop MCP;
- terminate agent-launched tasks;
- disconnect clients;
- shut down background workers;
- flush SQLite/log writes;
- exit the tray process completely.

Closing the window should **not** full-stop the application.

Default close behavior:

```text
minimize to system tray
```

---

# 20. Concurrency and Multiple Agents

Default:

```text
Allow multiple agents: ON
Allow any authenticated vendor/client: ON
```

The application UI must allow the user to configure:

```text
Allow any authenticated agent
Allow only selected agents/clients
Maximum simultaneous clients
Maximum simultaneous tasks per client
Allow multiple agents to modify the same project
```

Maintain stable `client_id` identities associated with credentials.

Suggested concurrency safety:

- reads may be concurrent;
- unrelated projects may be edited concurrently;
- default to one active writer lease per project;
- allow user override for multiple writers;
- expose project lock status in UI;
- do not block unrelated shell tasks unnecessarily.

Project writer leases should have expiration/heartbeat logic so crashes do not permanently lock a project.

Treat unknown shell tasks as potential writers and hold their project lease until they stop unless an explicit read-only classification applies. Read-only status polling does not acquire a writer lease. Use canonical project identity for nested projects/worktrees and lock all known affected scopes for cross-project operations. Raw scripts with undiscoverable targets retain the Section 4 limitation; writer leases are not filesystem isolation. Implement the lease/ownership primitives before enabling concurrent mutations, even though the full concurrency UI comes later.

---

# 21. Authentication

Ship **OAuth for ChatGPT** in the initial integration, plus unique revocable manual client tokens for clients that support them. Do not use one shared global secret, anonymous workstation tools, or a secret embedded in a URL. Manual-token testing alone does not satisfy ChatGPT acceptance.

### ChatGPT compatibility

Implement authorization-code OAuth with PKCE S256, protected-resource and authorization-server discovery, resource/audience binding, and token expiry/scope validation. Support a documented client-registration method (CIMD, DCR, or a predefined client); never advertise unsupported methods. Use exact registered redirect URIs and appropriate authentication challenges. Declare tool security schemes and correct read-only/destructive annotations. Follow current issuer-identification and reauthorization requirements. These are integration requirements verified against [official authentication documentation](https://developers.openai.com/plugins/build/auth) on September 19, 2026; recheck during implementation.

### Local authorization architecture

Use a bundled authorization-server component exposed through the configured HTTPS origin, with local desktop consent as the workstation-owner authorization boundary. Prefer maintained server libraries/components and perform a Phase 0 compatibility spike before choosing them; an OAuth client library alone is not an authorization server. Do not require a paid identity-provider account or separate cloud VM for the default installation.

The public authorization page creates a short-lived pending connection request. It cannot approve itself or grant permissions. The Windows UI displays the requesting OAuth client, requested scopes, exact redirect destination, and a request-specific pairing code the owner can compare with the initiating browser. Only an authenticated local UI action may grant it. Bind consent to the full authorization request, and deliver a single-use authorization code only through the validated OAuth redirect. Protect the browser flow against CSRF, replay, arbitrary redirects, and request flooding. Use real owner presence/consent, not an unauthenticated web button.

Validate dynamic metadata safely if CIMD/DCR is enabled: constrain fetch destinations, redirects, size, timeouts, and client redirect registration; do not create an SSRF endpoint. Scope permission never overrides local protected-path, external-write, Git, or elevation rules. Advertise only working capabilities; document and test the complete flow rather than shipping a partial OAuth implementation.

Choose short-lived access tokens and revocable/rotating refresh grants. Every request checks current grant/principal revocation, including existing streams, cached results, and token refresh. Show authorization expiry and revocation in the UI. Protect authorization-server keys with Windows-protected storage and retain only hashes of opaque tokens and single-use codes where practical.

### Stable identities and manual credentials

Keep Local Pilot's `client_id` (principal identity) distinct from OAuth protocol `client_id`. Record the local principal, credential/grant ID, authentication method, display name, token hash where applicable, creation/last-use/expiry times, enabled state, granted scopes, and optional vendor label/profile. OAuth token refresh does not create a new local principal.

Manual tokens are generated locally, shown once, and stored only as secure hashes. Issued OAuth tokens are delivered through the token response and never persisted or logged in plaintext. Provide create/connect, revoke, rotate, disable, and rename controls. Revocation behavior for active tasks is defined in Section 17.

Both `OAuthAuthenticator` and `BearerTokenAuthenticator` implement `authenticate(request) -> Principal`, then use the same policy, session, rate-limit, and audit paths. Any compatible authenticated vendor client may connect under local policy; only tested integrations are advertised as supported.

---

# 22. MCP Protocol

Use the official Rust MCP SDK where practical:

```text
https://github.com/modelcontextprotocol/rust-sdk
```

As of this plan, the official Rust SDK (`rmcp`) supports the stable 2026-07-28 MCP specification and compatibility with 2025-11-25.

Use Streamable HTTP for remote access.

Default local bind:

```text
127.0.0.1:<configurable port>
```

Default path:

```text
/mcp
```

Do not listen on `0.0.0.0` by default.

The server should negotiate supported MCP versions using the SDK rather than hand-rolling version assumptions.

Support current MCP standard routing headers where the SDK supports them:

```text
MCP-Protocol-Version
Mcp-Method
Mcp-Name
Mcp-Param-*
```

Use these headers for auditing/routing/rate-limit policy where appropriate, but validate that they agree with the actual MCP request.

Do not trust headers without protocol/library validation.

Treat SDK transport compatibility separately from client-product compatibility. Add correct tool schemas, bounded results, security metadata, and capability negotiation for the actual ChatGPT connection. Test approval polling/resume and long tasks through ChatGPT, not just through an SDK harness. Never rely on model compliance or tool annotations as authorization enforcement.

---

# 23. MCP Tools vs Resources

Use tools for operations/actions.

Examples:

```text
fs.read_text
fs.write_text
process.run
git.status
projects.resolve
```

Optionally expose useful read-only project resources later.

Do not overcomplicate v1 with prompts or UI extensions unless they clearly improve functionality.

Core priority:

```text
tools
authentication
authorization
audit
task execution
```

---

# 24. Cloudflare / Public Connectivity

The coding agent implementing this project will be given access to a Cloudflare MCP for the domain used by the project owner.

The coding agent must use that Cloudflare MCP to inspect and modify the relevant Cloudflare configuration for the owner's deployment.

## Public software must remain provider-neutral

Do not hard-code:

```text
the owner's private deployment hostname
Cloudflare account IDs
zone IDs
tunnel IDs
tunnel tokens
API keys
```

into the application or public repository.

The setup wizard should ask the end user for their public MCP server URL, for example:

```text
https://mcp.example.com/mcp
```

or:

```text
https://example.com/workstation/mcp
```

Store it as configuration.

The application should be able to run behind Cloudflare Tunnel, another tunnel provider, a reverse proxy, or direct HTTPS.

---

# 25. Cloudflare Configuration for the Project Owner's Deployment

For the project owner's environment, the coding agent should use the provided Cloudflare MCP to configure a production-quality route.

Required design:

```text
Agent client
    |
    | HTTPS
    v
Cloudflare
    |
    | Cloudflare Tunnel
    v
cloudflared on Windows workstation
    |
    v
127.0.0.1:<MCP_PORT>/mcp
```

The local MCP server must remain bound to loopback.

Use a named Cloudflare Tunnel rather than a development Quick Tunnel.

The coding agent should:

1. inspect the existing Cloudflare zone;
2. inspect existing tunnels/routes/DNS;
3. avoid overwriting unrelated records;
4. create or reuse a dedicated tunnel for this workstation deployment;
5. configure the desired public hostname;
6. map it to the local loopback MCP service;
7. ensure TLS works externally;
8. disable caching for MCP traffic and authorization/token responses;
9. preserve MCP request/stream behavior;
10. add appropriate rate limiting/WAF rules without breaking valid MCP clients;
11. document all changes made;
12. never commit Cloudflare secrets.

Cloudflare currently supports mapping a public hostname to a local service behind `cloudflared`, e.g. a public HTTPS hostname to `http://localhost:<port>`.

Official references:

```text
https://developers.cloudflare.com/tunnel/get-started/
https://developers.cloudflare.com/tunnel/concepts/routing/
```

## Cloudflare Access

Do not require an interactive Cloudflare Access login page on the MCP endpoint by default because many MCP clients expect machine-to-machine HTTP authentication and may not support an interactive login flow.

The application's own authentication is mandatory: OAuth-issued bearer access tokens for ChatGPT, or manual bearer tokens for compatible clients. A tunnel or Cloudflare login does not replace application authorization.

Cloudflare Access/service-token protection may be offered as an advanced deployment option for clients that can supply the required Cloudflare headers.

If Access is enabled, validate the Access token at the origin or enable Cloudflare's origin-protection integration.

---

# 26. Cloudflare Security Rules

For the owner's deployment, configure conservatively.

Recommended:

```text
HTTPS only
no cache on /mcp
reasonable request size limit
reasonable rate limiting
Cloudflare DDoS/WAF protection
origin accessible only through tunnel
```

Do not block valid MCP Streamable HTTP/SSE behavior.

If using current MCP routing headers, Cloudflare rules may use:

```text
Mcp-Method
Mcp-Name
```

for rate limiting or observability, but application-level authorization remains authoritative.

Avoid brittle Cloudflare rules that make other compliant MCP clients fail.

---

# 27. Tunnel Lifecycle

The application should provide a **Connectivity** panel.

Display:

```text
Local MCP listener status
Configured public MCP URL
External reachability status
Last successful external health check
Tunnel process/service status when detectable
```

For a generic public release, do not require the application to own the tunnel lifecycle.

Support:

```text
External tunnel managed by user
Optional helper integration for cloudflared
```

For the project owner's deployment, the coding agent may install/configure `cloudflared` using the Cloudflare MCP and local setup.

A ChatGPT test endpoint is needed in Phase 2; the full production tunnel rollout remains Phase 9. Route the required OAuth discovery/authorization/token endpoints as well as `/mcp`, and support public URL path prefixes consistently. Keep the Windows listener on loopback. Bind the deployed tunnel to a stable configured port; do not silently choose a new port on every startup. If no Cloudflare management connector is available, complete local work and request the missing connection at deployment time; do not claim an unconfigured public URL is working.

Never expose the tunnel token in logs or Data Shared.

---

# 28. Health Endpoints

Keep MCP on:

```text
/mcp
```

Provide a minimal local/public health endpoint:

```text
/health
```

It should return no sensitive data.

Example:

```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

Do not disclose:

```text
username
filesystem paths
project names
client names
tokens
machine details
```

Provide a more detailed health view only inside the authenticated local UI.

---

# 29. Desktop Application Architecture

Recommended repository layout:

```text
local-pilot/
|
+-- src/                         # React/TypeScript Tauri UI
|   +-- pages/
|   +-- components/
|   +-- hooks/
|   +-- state/
|   +-- lib/
|
+-- src-tauri/
|   +-- src/
|   |   +-- main.rs
|   |   +-- app_state.rs
|   |   +-- mcp/
|   |   +-- auth/
|   |   +-- policy/
|   |   +-- approvals/
|   |   +-- filesystem/
|   |   +-- projects/
|   |   +-- process/
|   |   +-- git/
|   |   +-- github/
|   |   +-- audit/
|   |   +-- redaction/
|   |   +-- network/
|   |   +-- update/
|   |   +-- windows/
|   |
|   +-- capabilities/
|   +-- tauri.conf.json
|
+-- crates/
|   +-- workstation-core/
|   +-- workstation-policy/
|   +-- workstation-executor/
|   +-- workstation-index/
|   +-- workstation-audit/
|   +-- workstation-elevated-helper/
|
+-- tests/
|   +-- integration/
|   +-- security/
|   +-- protocol/
|   +-- fixtures/
|
+-- installer/
+-- scripts/
+-- docs/
+-- .github/
+-- README.md
+-- SECURITY.md
+-- CONTRIBUTING.md
+-- plan.md
```

Use a Cargo workspace.

Avoid putting all security logic directly into Tauri command handlers.

The UI should call a clean internal core API.

---

# 30. UI Technology

Recommended:

```text
Tauri v2
React
TypeScript
Vite
Tailwind CSS
shadcn/ui or similarly accessible component primitives
Lucide icons
```

Do not let UI framework decisions delay backend/security work.

The application should look like a real Windows utility, not a demo dashboard.

Support light/dark system theme if straightforward.

---

# 31. Main UI Pages

## Dashboard

Show:

```text
MCP status
Public URL
Remote access enabled/disabled
Connected agents
Running tasks
Pending approvals
Projects indexed
Recent actions
Emergency Stop
Restart MCP
```

## Connections

Show:

```text
connected clients
client ID
display name
reported MCP client info
remote IP/proxy information if trustworthy
connected/last seen
active tasks
credential status
```

Controls:

```text
disconnect
disable
revoke credential
allow only this client
```

## Projects

Show the folder map:

```text
project name
path
type
Git status summary
active agent(s)
writer lock
last modified
```

Actions:

```text
refresh
open in Explorer
copy path
rescan
lock/unlock project for agents
```

## Approvals

Show pending and historical approval requests.

## Tasks

Show:

```text
task ID
client
project
command
PID
runtime
status
stdout/stderr activity
```

Controls:

```text
cancel
terminate tree
view output
```

## Command History

Show retained audit history with filtering, retention boundaries, and any explicitly recorded gaps or interrupted outcomes.

## Data Shared

Separate page showing exactly what data was returned to remote agents.

## Security / Permissions

Show:

```text
trusted root
protected paths
external-write rules
Git rules
package install rules
admin rules
environment policy
allowed clients
concurrency policy
```

## Network

Show:

```text
local bind
port
public URL
health
tunnel status
```

## Settings

Show:

```text
startup
tray behavior
history retention
Data Shared size
notifications
updates
logs
advanced mode
```

---

# 32. Audit History

Record every application-mediated request, policy decision, approval, execution transition, and outbound tool result within the configured retention period. For arbitrary programs, record the command and observable activity; do not describe this as a complete audit of every filesystem or network side effect.

Audit event schema should include:

```text
event_id
timestamp_start
timestamp_end
client_id
client_display_name
mcp_protocol_version
tool_name
operation_category
project_id
cwd
command
arguments (redacted)
paths
policy_decision
approval_id
approval_result
task_id
pid
exit_code
stdout_bytes
stderr_bytes
result_status
duration_ms
error
```

Store in SQLite.

Default audit retention:

```text
30 days
```

Make configurable.

Also support a maximum database/log size.

Retention cleanup must not block the UI.

Audit logs should be user-readable and exportable.

Persist a minimal audit intent before dispatching mutations. Use bounded asynchronous queues for remaining records and apply backpressure when necessary. If durable audit storage cannot accept the intent, refuse new mutations/launches with `AUDIT_UNAVAILABLE`, surface the fault locally, and do not claim the action was logged. Recovery must mark uncertain outcomes rather than invent success or replay them.

---

# 33. Data Shared Log

Create a separate **Data Shared** subsystem.

Its purpose is to answer:

> "What exactly did this workstation send to that agent?"

Track application-level MCP results and file data emitted to clients. This covers data leaving through MCP, not arbitrary outbound traffic from launched programs. Record whether a payload was prepared, a transport send was attempted, and transmission failed/was interrupted; a successful write to a transport is not proof the remote model consumed it.

Store:

```text
share_event_id
timestamp
client_id
tool_name
request_id
source path if relevant
MIME/type
byte count
SHA-256
response payload
redaction metadata
```

Keep it separate from command history.

Default storage policy:

```text
250 MB rolling maximum
30-day maximum retention
```

Both must be adjustable independently.

When a size limit is reached, rotate the oldest records while recording the retention boundary. Active sessions do not make all their history permanently ineligible for rotation. Reserve space for bounded latest-event records per active session; validate that configured session/payload limits fit the budget. Make active-session truncation visible in the UI. Stop admitting sessions or emitting data when reserved evidence cannot fit, rather than silently exceeding the cap or losing new evidence.

Encrypting the local database at rest can be evaluated, but do not invent weak custom crypto.

Redact the outbound application payload once, before persistence and transmission. Record and hash exactly those post-redaction bytes, not a differently redacted copy of data already sent. Write the record durably before emitting tool payloads; on storage failure return a bounded `AUDIT_UNAVAILABLE` error without that data and fault remote data delivery until recovery. Error-path logging must not recurse indefinitely. OAuth code/token responses are authentication exchanges, not MCP tool payloads: record only redacted event metadata for them, never issued secrets.

Retention makes the history finite. Clearly display the retained time range and gaps. Neither Data Shared nor audit logs are tamper-proof against arbitrary same-user processes in v1.

---

# 34. Redaction Engine

Build one centralized redaction engine used by:

```text
stdout/stderr logging
audit arguments
Data Shared
environment inspection
error messages
Git remote URL logging
HTTP headers
```

Detect common secrets including:

```text
Bearer tokens
GitHub PAT prefixes
OAuth tokens
AWS keys
API-key-shaped values
private key blocks
Authorization headers
connection strings with passwords
Cloudflare tokens
```

Redaction example:

```text
ghp_********************************
Bearer <redacted>
```

Do not send unredacted secrets to the frontend simply so the UI can redact them later. Redact in backend before persistence/UI.

Apply redaction to every outbound data path, including search and Git results, binary/ranged reads, errors, and task output. Keep stream-boundary state so splitting a known secret across output chunks does not bypass filtering. Deny protected binary resources; do not corrupt arbitrary binary files with blind text replacements. Document that pattern/known-value detection cannot recognize every transformed or previously unknown secret.

---

# 35. Notifications

Use Windows notifications for:

```text
new approval required
agent connected
agent disconnected unexpectedly
emergency stop activated
important task failure
update available (optional)
```

Approval notifications should open/focus the relevant request when clicked.

Do not spam notifications for normal file reads.

---

# 36. Autostart and Tray

Default:

```text
Start with Windows: ON
```

User may turn it off.

Use a per-user startup mechanism appropriate for Tauri/Windows.

Do not require admin privileges for ordinary autostart.

On normal window close:

```text
minimize to tray
```

Tray menu:

```text
Open
Remote access: Enabled/Disabled
Emergency Stop
Restart MCP
Stop Application
```

---

# 37. Local Data Paths

Use Windows application-data locations rather than the project directory.

Required default application-data root:

```text
%LOCALAPPDATA%\LocalPilot\
```

Store:

```text
config
SQLite database
non-secret logs
cache
index
update state
```

Sensitive credentials should use Windows-protected storage where feasible rather than plaintext JSON.

Investigate DPAPI/Credential Manager for client-secret protection.

Do not store plaintext client tokens after generation.

The only agent-write allowance within application data is the assigned `cache\temp` subtree described in Section 14. Store configuration, databases, keys, logs, index, and updater state outside it. Keep sensitive control data out of support bundles and remote filesystem tools.

---

# 38. Settings Configuration

Use a versioned configuration schema.

Example categories:

```text
general
network
trusted_workspace
protected_paths
auth
sessions
concurrency
process
shell_protection
git
github
packages
cache_temp
environment
audit
data_shared
notifications
updates
advanced
```

Implement migration logic when schema changes.

Keep safe defaults.

A corrupted config must not result in "allow everything."

Fail closed for write/admin operations.

---

# 39. Network Authentication Flow

Expected request path:

```text
Remote MCP client
   |
   | Authorization: Bearer <OAuth access token or manual client token>
   v
Cloudflare / reverse proxy
   |
   v
127.0.0.1 MCP server
   |
   +--> validate token, resource binding, expiry, scopes and live revocation
   +--> resolve Principal/client_id
   +--> resolve current application session
   +--> apply connection policy
   +--> rate limit
   +--> dispatch MCP method
```

Never trust client-supplied identity fields over the credential-derived principal.

MCP `clientInfo` is useful display metadata, not proof of identity.

---

# 40. Rate Limits

Implement conservative server-side limits.

At minimum:

```text
per client requests/minute
concurrent tool calls per client
concurrent processes per client
maximum command output retained
maximum returned file size
maximum `get_many` item count
maximum search results
maximum request body
```

Make advanced limits configurable.

Do not make defaults so small that normal coding agents fail.

---

# 41. File Size Rules

Do not return arbitrarily large files by default.

For reads support:

```text
offset
length/max_bytes
```

For text:

```text
line ranges
byte ranges
```

If an agent asks for a huge file, return metadata and instruct it to request ranges.

Prevent one tool call from returning gigabytes.

---

# 42. Search Rules

`files.search_text` should support:

```text
project/path scope
query
literal vs regex
file glob
case sensitivity
max results
context lines
```

Use safe bounded defaults.

Avoid indexing dependency/build directories unless requested:

```text
node_modules
.git
target
dist
build
.venv
venv
bin
obj
```

Allow per-project ignore rules.

Respect `.gitignore` where sensible for search.

---

# 43. Admin Helper IPC

Design the elevated helper carefully.

Recommended communication:

```text
named pipe restricted to current user/session
```

Requirements:

- authenticated local peer;
- random per-request nonce;
- operation allowlist;
- signed request payload or equivalent trustworthy handshake;
- no arbitrary "execute this string as admin" endpoint for remote agents;
- exact operation approval;
- short lifetime.

Preferred privileged APIs should be structured.

A generic elevated shell, if ever added, must be explicitly approved and visually labeled high risk.

---

# 44. Security Boundaries

Threat model at minimum:

1. malicious/compromised remote agent;
2. stolen client token;
3. prompt injection inside a project;
4. malicious repository;
5. malicious package install/script;
6. path traversal;
7. symlink/junction escape;
8. command injection;
9. shell escaping policy checks;
10. credential exfiltration;
11. local unprivileged process attempting to impersonate the UI/backend;
12. reverse-proxy header spoofing;
13. replay of approvals;
14. race between approval and filesystem mutation;
15. confused-deputy behavior;
16. accidental destructive Git command;
17. runaway child process;
18. huge-output denial of service;
19. database/log growth denial of service;
20. updater compromise.

Create `SECURITY.md` documenting the threat model.

---

# 45. TOCTOU Safety

For every brokered filesystem operation, including trusted writes, protected reads, and cache/temp access, bind validation to the object actually accessed. For approval-bound operations additionally:

- approval must describe the resolved target;
- re-resolve/revalidate immediately before execution;
- detect if the target has changed into a junction/reparse point;
- expire approval after a short reasonable period;
- approval ID may not be reused for a different operation/path.

Do not approve one path and later perform on another because a symlink changed.

Path revalidation alone is insufficient. Use Windows handles and file identity to bind checks to the object actually read or changed; use parent-relative or equivalent race-safe operations for creation, rename, and deletion. Reparse-point changes, hard-link aliases, and recursive traversal require explicit handling. Approval-specific checks apply in addition to these rules. If the broker cannot establish the target safely, reject the operation rather than performing an unchecked path-based fallback. Add concurrent target-swap tests, not just static traversal tests.

---

# 46. Project-Local Free Access vs External Writes

Implement a central policy evaluator.

Conceptual function:

```rust
evaluate(OperationContext) -> PolicyDecision
```

Possible results:

```text
Allow
Deny
RequireApproval
```

Every filesystem mutation, process request, Git operation, package installation classification, and privileged request must route through this component.

Include the entry point (structured tool versus raw process/shell) and local shell-check mode in the operation context. Disabling shell checks does not bypass a structured Git/filesystem tool's authorization merely because its implementation launches a subprocess. Record the effective mode and decision in the audit event.

Do not duplicate authorization logic across tools.

---

# 47. Command Classification

Create a command classifier for shell/process calls.

The preflight enforcement below applies when Shell protection checks is ON. When OFF, apply the explicit bypass scope in Section 4 and continue recording the effective policy mode; structured tools remain subject to their own mandatory authorization.

Categories:

```text
read-only
trusted-project mutation
external mutation
package-local
package-global
git-safe
git-destructive
github-read
github-write
credential-access
system-change
admin
unknown
```

Unknown operations should not be treated as automatically safe merely because classification failed.

Inside trusted workspace, unknown standard-user commands may run according to the raw-shell policy, but log a policy warning.

Outside trusted workspace, uncertain mutation should request approval.

---

# 48. Process Working Directory

Default process working directory should be a resolved project path where applicable.

Do not infer safety solely from `cwd`.

A command started inside a project may reference:

```text
C:\Windows
%APPDATA%
..\..\...
```

Apply path/command policy independently.

---

# 49. Internet Access

Agent-launched programs have normal Internet access by default.

Do not build an outbound proxy/firewall in v1.

Record network-related commands where visible, but do not attempt full packet capture.

Future network sandboxing can be documented separately.

---

# 50. MCP Connection Metadata

Record:

```text
client credential identity
MCP clientInfo name/version
protocol version
connection time
last request time
proxy/remote addressing when available
```

If behind Cloudflare, only trust forwarded IP headers when requests are known to have come through the configured proxy/tunnel.

Do not use IP address as authentication.

Report application-session state and transport activity separately. A shared OAuth connection does not prove that each chat is a separate client, and a closed HTTP stream does not necessarily mean the application session ended.

---

# 51. Public URL Setup Wizard

First launch wizard should include:

## Step 1 — Welcome

Explain what remote workstation access means.

## Step 2 — Trusted workspace

Show resolved:

```text
<Documents>\Projects
```

Create it if missing after user confirmation/setup action.

## Step 3 — Local MCP listener

Choose a port or select a free port once and persist it. If the persisted port is unavailable later, show a configuration error rather than silently breaking the tunnel mapping.

## Step 4 — Public MCP URL

Ask user for:

```text
https://...
```

This is the external URL they configured through Cloudflare or another provider.

Validate format.

## Step 5 — Connect ChatGPT

Configure the public OAuth/resource URLs and guide the owner through adding the MCP connection in ChatGPT developer mode. Complete local connection consent and a read-only test. Account/workspace policy can affect developer-mode access; verify access during Phase 0 without making local setup depend on it. Follow the [current connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt), and treat actual ChatGPT tool calls as the compatibility test.

Offer manual client-token creation separately for compatible clients. Show manual tokens once with a copy action; do not present this as ChatGPT's default authentication path.

## Step 6 — Security defaults

Show:

```text
structured external writes require approval except assigned cache/temp paths
protected credentials blocked in structured tools
shell protection checks ON (best effort; locally adjustable)
direct main push requires approval
destructive Git requires approval
system installs require approval
session idle / absolute expiry: 30 minutes / 8 hours (adjustable)
terminate owned tasks on client revoke/disable/disconnect: ON (adjustable)
```

## Step 7 — Autostart

Default ON.

## Step 8 — Connectivity test

Test local health and, when possible, external health.

Do not make setup impossible if the user has not yet configured the external tunnel; allow completing setup and fixing connectivity later.

---

# 52. Cloudflare Setup During Development

Because the coding agent will have the project's Cloudflare MCP:

- discover the correct zone instead of asking the user for IDs already available through the tool;
- inspect existing DNS/tunnels before changes;
- create the required hostname/route;
- configure it to the chosen local listener;
- do not delete unrelated Cloudflare configuration;
- write a sanitized deployment note under `docs/cloudflare-deployment.md`, keeping private hostnames/IDs in local configuration;
- never write Cloudflare credentials/tokens into repository files;
- verify the public URL after setup.

If authentication/user interaction is needed for Cloudflare, request it at that point rather than attempting to bypass it.

---

# 53. Local Listener Security

Bind only:

```text
127.0.0.1
```

by default.

Implement Host/Origin validation appropriate to the MCP SDK and reverse-proxy deployment.

Protect against DNS rebinding.

Do not disable SDK security checks globally without an explicit reason and tests.

If reverse-proxy headers are trusted, make the trusted-proxy list explicit.

---

# 54. MCP Server Availability State

Internal state machine:

```text
Starting
Ready
Paused
EmergencyStopped
Restarting
Stopping
Faulted
```

Expose current state to UI.

MCP tool calls in disallowed states must fail cleanly.

---

# 55. Crash Recovery

On startup:

- detect tasks left "running" in the database;
- mark them interrupted unless process ownership can be safely reattached;
- release stale project locks;
- preserve logs;
- verify index database;
- validate config;
- preserve the EmergencyStopped latch and clear stale application sessions/approvals;
- resume filesystem watcher;
- never automatically repeat a previously dispatched mutation; mark ambiguous outcomes for reconciliation.

---

# 56. Update System

Use Tauri's updater.

Tauri update artifacts must be cryptographically signed.

Official reference:

```text
https://v2.tauri.app/plugin/updater/
```

Requirements:

- opt-in automatic updates;
- default setting may check automatically but ask before installation;
- signed artifacts;
- HTTPS update endpoint;
- never place signing private key in repository;
- store release signing credentials in secure CI secrets;
- support Windows NSIS/EXE and/or MSI output.

Do not implement an unsigned self-update mechanism.

Before Phase 10 release packaging, select the HTTPS update host and document signing-key ownership, backup, and recovery. Keep updater signatures and Windows installer publisher/code-signing decisions distinct; document the actual signing status of each distributed artifact.

---

# 57. Installer

Produce a user-friendly Windows installer.

Targets:

```text
.exe (NSIS)
.msi where practical
```

Installer should:

- install the Tauri application;
- install required bundled runtime components;
- register uninstall entry;
- optionally enable startup;
- preserve user configuration on upgrade;
- remove application binaries on uninstall;
- ask whether to keep or delete logs/config during uninstall.

Do not require admin installation unless a feature actually requires it.

The standard application should function as a per-user install where possible.

Cloudflare/tunnel setup remains environment-specific.

---

# 58. Public Repository Requirements

The project is intended to be publicly available.

Include:

```text
README.md
LICENSE
SECURITY.md
CONTRIBUTING.md
CHANGELOG.md
docs/
```

README should explain:

- what the tool does;
- the security model;
- trusted `Documents\Projects` root;
- remote-control implications;
- how approvals work;
- secret protections;
- shell sandbox limitation;
- supported MCP clients;
- generic reverse proxy/tunnel deployment;
- Cloudflare example;
- build instructions;
- release verification.

Do not include private infrastructure details.

---

# 59. GitHub Actions / CI

Create CI for:

```text
cargo fmt
cargo clippy
cargo test
frontend lint/typecheck/test
security tests
build
installer artifact build
```

Release workflow may build signed Tauri artifacts when signing secrets are configured.

Do not mention the coding agent, model, vendor, or agent company in:

```text
workflow names added for attribution
commit messages
release notes
PRs
issues
comments
generated docs
```

Use normal professional project language.

---

# 60. Testing Strategy

Implement tests in layers.

## Unit tests

Test:

```text
path classification
protected path matching
redaction
command classification
Git command classification
approval scope
token validation
session expiry and token-refresh continuity
cache/temp exception scope and quota
approval idempotency and policy revision binding
config migrations
project resolution
```

## Integration tests

Test:

```text
MCP connect/auth
ChatGPT OAuth consent, discovery, refresh, revocation and real tool calls
tool calls
filesystem operations
process execution
task lifecycle
Git operations
SQLite audit
Data Shared
approval flow
emergency stop
restart
```

## Security tests

Attempt:

```text
path traversal
junction escape
symlink escape
UNC path
device path
alternate data stream
hard-link alias and concurrent reparse-point swaps
credential reads
environment secret reads
direct token dump commands
approval replay
concurrent resume and crash after dispatch
approval target swap
cross-client task/output/approval access
OAuth code replay, bad redirects, wrong audience and metadata SSRF
unauthenticated MCP calls
revoked tokens
concurrent race conditions
oversized payloads
log flooding
disk-full audit and active-session Data Shared rotation
cache/temp traversal and access to sibling control data
process-tree escape
Emergency Stop surviving restart/reboot
shell protection OFF leaving structured checks enforced
```

## UI tests

Test:

```text
approval dialog
Emergency Stop
restart
tray behavior
settings
connection management
history filtering
Data Shared
startup setting
```

---

# 61. End-to-End Acceptance Tests

The release is not complete until these scenarios pass. Run the user-facing workflows through ChatGPT as tools become available, in addition to automated tests. Filesystem-policy cases use structured tools; raw-shell tests verify documented detection coverage with shell checks ON, not a claim of complete OS containment. Use synthetic secrets and isolated test projects.

### Test A — Resolve project

User asks remote agent:

```text
Where is my Clippy project?
```

Agent calls project resolver and receives a path under Documents\Projects.

### Test B — Create project

Agent creates:

```text
Documents\Projects\TestProject
```

without approval.

### Test C — Full trusted workspace edit

Agent creates, edits, runs, and deletes ordinary non-sensitive files inside TestProject without approval; protected-resource and Git/admin exceptions still apply.

### Test D — External read

Agent reads a normal non-sensitive text file outside Projects without approval.

### Test E — Protected read

Agent attempts to read SSH private key.

Result:

```text
Denied
```

No secret is returned.

### Test F — External write

Agent attempts to modify a normal file outside Projects.

Local approval appears.

Deny -> operation does not happen.

### Test G — Allow once

User chooses Allow once.

Approval alone does not execute anything. The originating client resumes the approval ID and exactly the stored operation is dispatched. Concurrent or repeated resume calls report the same execution without another side effect.

A second mutation asks again.

### Test H — Allow session

User grants scoped session permission.

Matching subsequent operations succeed until the client/session permission expires.

Reconnect and OAuth refresh retain only an unexpired application session. Validate adjustable idle/absolute expiry, explicit session end, and invalidation on restart. A different client cannot use the grant.

### Test I — System install

Agent runs a system-wide installer command.

Approval required.

### Test J — Local dependency

Agent runs `npm install` in an isolated project with a normal dependency fixture. It is allowed automatically with project files under the workspace and redirected cache/temp data under the assigned Local Pilot subtree. A requested unrelated external write still requires approval with shell checks ON; arbitrary lifecycle-script effects retain the documented limitation.

### Test K — Git branch push

Normal branch push succeeds.

### Test L — Default branch push

Direct default-branch push prompts by default.

### Test M — Destructive Git

Force push prompts by default.

### Test N — GitHub attribution

Attempt to add automatic agent/vendor attribution to a structured official GitHub action.

Operation is rejected.

### Test O — Long task

Start a long build.

Task ID returned.

Output available incrementally.

Task can be cancelled.

### Test P — Multiple clients

Two authenticated MCP clients connect.

UI shows both.

Policy/concurrency setting is respected.

### Test Q — Revoke client

Revoked client cannot make another authenticated request.

Its refresh grants and sessions are invalidated immediately. With the default setting, its managed processes are terminated; with termination disabled, existing tasks remain locally manageable without restoring remote access. Other clients' tasks are unaffected.

### Test R — Emergency Stop

With active commands running:

- press Emergency Stop;
- managed agent process trees and approved elevated helpers die;
- clients disconnect;
- new calls fail;
- UI remains open;
- manual local resume required, including after MCP/app restart and Windows reboot.

### Test S — Cloudflare

Remote MCP client accesses workstation through configured HTTPS URL while on a different network.

Local MCP port remains non-public.

### Test T — ChatGPT authentication and tools

Connect the owner's ChatGPT account through the documented OAuth flow. Discover tools and resolve a project, read a file, edit an ordinary project file, poll/resume a locally approved external write, and start/poll/cancel a task. Test token refresh, insufficient scopes, local consent denial, and revocation. Do not count an API-only test or successful `/health` response as ChatGPT compatibility.

### Test U — Cache/temp boundaries

Assigned cache/temp writes succeed without prompting. Access to another principal's task directory, a sibling settings/database path, a protected file, or an escaping reparse point is denied or requires the correct policy. Quota exhaustion reports a bounded error and does not delete active task data.

### Test V — Protection switch

Only the local UI changes shell-check mode. With checks OFF, a classified non-admin test command bypasses shell preflight, while equivalent structured operations retain their policy. Authentication, redaction, auditing, ownership, standard-user execution, and Emergency Stop remain active. Re-enabling checks restores preflight behavior.

### Test W — Audit and Data Shared failure behavior

Use synthetic sensitive values, output split across chunks, and capped responses. Verify recorded post-redaction payload hashes match emitted payloads. Under retention pressure show truncation explicitly; on storage failure refuse new mutations/data delivery as specified, keep the UI responsive, and retain a visible fault state. Test ambiguous execution recovery without replay.

---

# 62. Performance Targets

Reasonable desktop targets:

```text
idle CPU near zero
idle memory appropriate for Tauri app
project resolve usually <100 ms after indexing
filesystem stat/list low latency
search results begin quickly
UI remains responsive during builds
bounded audit overhead; no UI blocking; backpressure on saturation
```

Use async I/O appropriately.

Do not hold a global mutex around all MCP calls.

---

# 63. Database

Recommended SQLite tables:

```text
settings
clients
credentials
oauth_clients
oauth_grants
application_sessions
projects
project_aliases
project_locks
tasks
task_output_chunks
audit_events
approvals
operation_executions
idempotency_keys
session_permissions
data_shared
connection_events
schema_migrations
```

Use transactions.

Do not store plaintext authentication tokens.

Keep pending sensitive payloads and authorization codes out of general audit/result tables. Persist code/token hashes and operation metadata as appropriate; use protected transient storage for execution material and purge it on expiry/restart. Record unknown execution outcomes explicitly.

Use indexes for timestamp/client/project queries.

Use WAL mode if appropriate after testing Windows behavior.

---

# 64. Logging

Separate:

```text
application diagnostic log
security/audit history
agent command output
Data Shared
```

Diagnostic logs should use structured logging (`tracing` ecosystem).

No secret values.

Provide a "Create support bundle" action that removes sensitive information before packaging logs.

---

# 65. Error Model

MCP tool errors should be explicit and actionable.

Examples:

```text
AUTHENTICATION_FAILED
PERMISSION_DENIED
PROTECTED_RESOURCE
APPROVAL_REQUIRED
APPROVAL_DENIED
APPROVAL_EXPIRED
APPROVAL_INVALIDATED
SESSION_EXPIRED
IDEMPOTENCY_CONFLICT
OUTCOME_UNKNOWN
PATH_OUTSIDE_POLICY
PROJECT_NOT_FOUND
TASK_NOT_FOUND
COMMAND_FAILED
TIMEOUT
OUTPUT_LIMIT_REACHED
EMERGENCY_STOP_ACTIVE
CLIENT_DISABLED
PROJECT_LOCKED
AUDIT_UNAVAILABLE
CACHE_QUOTA_EXCEEDED
```

Do not return Rust panic/debug internals to remote clients.

Log internal error details locally.

---

# 66. Safe Defaults

On first install:

```text
Trusted root: Documents\Projects
First supported client: ChatGPT via OAuth
Read external normal files: allowed
Read credential/secret paths: denied
Structured external mutation: approval required except assigned cache/temp
Managed cache/temp root: %LOCALAPPDATA%\LocalPilot\cache\temp
Raw PowerShell/cmd: enabled
Shell protection checks: ON (best effort; locally switchable)
Structured-tool policy enforcement: always ON
Session idle timeout: 30 minutes
Session absolute lifetime: 8 hours
Pending approval lifetime: 10 minutes
Terminate tasks on client revoke/disable/disconnect: ON
Terminate ordinary tasks on session expiry: OFF
System-wide install: approval required
Destructive Git: approval required
Direct default-branch push: approval required
Multiple agents: enabled
Any authenticated vendor: enabled
Auto-start: enabled
Close-to-tray: enabled
Audit retention: 30 days
Data Shared retention: 30 days / 250 MB
Automatic update install: off
Update check: on
```

---

# 67. Settings That Must Be Adjustable

Expose controls for at least:

```text
autostart
public MCP URL
local port
allowed clients
multiple-agent mode
max concurrent clients
same-project concurrency
external write policy
system install policy
destructive Git policy
default-branch push policy
environment inheritance/filtering
configured-tool secret inheritance grants
protected paths
shell protection checks
session idle timeout
session absolute lifetime
pending approval lifetime
terminate tasks on client revoke/disable/disconnect
terminate tasks on session expiry
cache/temp quota and cleanup
audit retention
audit max size
Data Shared retention
Data Shared max size
notifications
update checks
auto updates
```

Changing critical security settings must be locally auditable.

Security settings are editable only from the local UI. Validate expiry/size limits and explain their scope. Tightening policy invalidates incompatible grants immediately; increasing expiry never revives an expired session or approval.

---

# 68. Development Phases

## Phase 0 — Repository/bootstrap

Create:

```text
Cargo workspace
Tauri app
React frontend
SQLite migrations
CI
format/lint/test setup
basic docs
```

Use the existing Git checkout and Local Pilot naming. Bring this plan into the repository as specified in Section 1.1. Verify the owner's ChatGPT developer-mode connection capability and the available Cloudflare connector; do not ask for account/zone IDs that the connector can discover.

Run a bounded OAuth/server-library compatibility spike and record the chosen implementation, client-registration method, endpoint layout, token lifecycle, and local-consent design. Add only the minimal local consent UI needed by Phase 2. No Cloudflare changes yet unless needed for the test endpoint; unresolved account access does not prevent local bootstrap.

## Phase 1 — Core path/policy engine

Implement:

```text
Documents known-folder resolution
trusted root creation
path canonicalization
handle-based target validation and hard-link rules
protected paths
application control-data protection and cache/temp classification
policy evaluator
redaction
security unit tests
```

Do not proceed to dangerous shell features until path tests pass.

## Phase 2 — MCP read-only server

Implement:

```text
Streamable HTTP
OAuth resource/authorization endpoints and local desktop consent
manual client tokens for compatible clients
application sessions and live revocation
rate limits and request/result bounds
project indexing
projects.resolve
fs.stat/list/find/read
audit
Data Shared
```

Test locally, then establish a narrowly scoped authenticated test endpoint and complete ChatGPT OAuth connection, tool discovery, project resolution, and a file read. Route required OAuth endpoints and keep mutations/shells unavailable at this milestone. A missing external account/connector can defer the live test, but document it as pending; do not claim ChatGPT support until it passes. Phase 9 completes production networking.

## Phase 3 — Filesystem mutations + approvals

Implement:

```text
write/edit/delete/move/copy
approval engine
Windows notifications
Approvals UI
session-scoped permissions
approval.resume and durable duplicate-dispatch prevention
task/approval ownership and project writer-lease primitives
```

## Phase 4 — Process execution

Implement:

```text
process.run
PowerShell
cmd
Job Objects
task IDs
output streaming/chunks
cancel/kill
command classification
redirected per-tool/task cache/temp and quotas
local shell-check switch
standard-user launches and client-specific termination
Emergency Stop latch and process-tree termination
```

## Phase 5 — Git/GitHub

Implement structured Git tools, Git rules, `gh`, attribution guardrails, default-branch policy, destructive action approval.

## Phase 6 — Main desktop UI

Complete dashboard, projects, clients, tasks, audit, Data Shared, settings, tray, restart, stop, Emergency Stop.

This completes presentation and management workflows; minimal local consent, approvals, Emergency Stop, and settings needed for earlier phases must already work before their associated features are exposed.

## Phase 7 — Multiple clients/concurrency

Complete multi-client UI/settings and stress-test client policies, locks, writer leases, session ownership, and rate limits introduced in earlier phases. Do not postpone basic isolation and limits until this phase.

## Phase 8 — Admin helper

Implement explicit privileged helper and approvals.

## Phase 9 — Public networking

Use owner's Cloudflare MCP.

Harden the test route into the dedicated production tunnel/public hostname, including OAuth routes, caching rules, stable port binding, and correct public URL metadata.

Verify remote MCP access.

Write generic connectivity documentation.

## Phase 10 — Installer/update

Build NSIS/MSI, signed updater, first-launch wizard, autostart.

Finalize the update host and signing custody; document installer publisher-signing status. Verify an upgrade preserves policy and Emergency Stop state.

## Phase 11 — Security hardening

Run full adversarial test suite.

Perform manual review of:

```text
path handling
auth
approvals
shell policy
secrets
admin helper
updater
Cloudflare configuration
```

## Phase 12 — Public release

Clean repository of secrets/private paths.

Resolve and add the owner-selected license before publishing. Confirm the compatibility matrix and retain actual ChatGPT end-to-end test evidence.

Create release artifacts and documentation.

---

# 69. Coding Agent Execution Rules

The coding agent implementing this plan must:

1. work through phases in order;
2. run tests after each phase;
3. fix failing tests before moving on;
4. use the provided Cloudflare MCP for Cloudflare work;
5. inspect existing Cloudflare state before making changes;
6. never commit secrets;
7. never expose secret values in chat/logs;
8. never add agent/vendor attribution to GitHub artifacts;
9. preserve existing Git identity;
10. prefer official/current APIs over deprecated tutorials;
11. verify package/API versions at implementation time;
12. document any intentional deviation from this plan;
13. do not weaken a security rule silently;
14. when a Windows limitation prevents perfect enforcement, clearly document the limitation and implement the strongest practical behavior;
15. leave the repository buildable and testable at each major milestone.

---

# 70. Reference Documentation

The coding agent should verify current documentation during implementation rather than assuming examples remain unchanged.

MCP:

```text
https://modelcontextprotocol.io/
https://github.com/modelcontextprotocol/rust-sdk
```

The stable 2026-07-28 MCP specification uses modern Streamable HTTP behavior and standardized request routing headers. Use the SDK's version negotiation/compatibility layer rather than copying a protocol implementation from old examples.

ChatGPT integration (checked September 19, 2026; recheck during implementation):

- [Authentication](https://developers.openai.com/plugins/build/auth)
- [Connect and test](https://developers.openai.com/plugins/deploy/connect-chatgpt)

These references concern product compatibility, not authorship attribution. Their inclusion is permitted under Section 12.

Cloudflare Tunnel:

```text
https://developers.cloudflare.com/tunnel/get-started/
https://developers.cloudflare.com/tunnel/concepts/routing/
https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/
```

Tauri:

```text
https://v2.tauri.app/
https://v2.tauri.app/plugin/updater/
```

Windows APIs to research/use:

```text
Known Folder APIs
Job Objects
Named Pipes
ShellExecuteEx / elevation
DPAPI / Windows Credential Manager
Reparse point APIs
CreateProcess
Windows notifications
```

---

# 71. Definition of Done

The project is done only when:

- the Windows installer works on a clean Windows 11 machine;
- the application starts normally without admin rights;
- the app resolves the current user's Documents folder dynamically;
- `Documents\Projects` is created/recognized;
- remote MCP clients can authenticate;
- ChatGPT can connect through OAuth and complete the required tool workflows;
- other clients are supported as recorded in the tested compatibility matrix;
- project discovery works;
- ordinary files inside Projects can be freely created/read/edited/deleted subject to the documented protected-resource and Git/admin exceptions;
- normal external reads work;
- protected credential reads and unauthorized secret mutations are blocked by structured tools;
- structured external writes require local approval except the scoped cache/temp allowance;
- cache/temp writes remain within the assigned application subtree and respect quotas;
- shell checks are ON by default, locally adjustable, and accurately described as best effort;
- PowerShell/cmd work;
- long-running tasks work;
- Git and GitHub CLI work;
- Git identity is preserved;
- official GitHub actions never automatically disclose agent/vendor attribution;
- direct push to default branch asks by default;
- destructive Git asks by default;
- system installs ask by default;
- multiple clients are manageable in UI;
- approval resume is bound to the original operation and retries do not dispatch it again;
- adjustable sessions expire/revoke correctly and clients cannot access each other's task/approval records;
- application-mediated actions are audited and redacted within retention limits, with storage failures and unknown outcomes visible;
- Data Shared accurately records outbound MCP data under its configured retention limit;
- Restart works;
- Emergency Stop terminates managed tasks and remains latched across restart/reboot until local resume;
- full Stop Application works;
- close-to-tray works;
- autostart is configurable;
- signed update artifacts can be produced and update hosting/signing custody are documented;
- a license is selected before public release;
- the owner's Cloudflare tunnel/public URL works from a separate network;
- no public repo file contains private Cloudflare credentials or other secrets;
- security/adversarial tests pass;
- README and SECURITY.md accurately describe remaining sandbox limitations.

---

# 72. Final Architectural Summary

Target architecture:

```text
                 MCP-capable agents
       ChatGPT first / other tested hosts
                         |
                         | HTTPS + MCP
                         v
              User's public MCP URL
                         |
                  Tunnel / proxy
             (Cloudflare for owner)
                         |
                         v
                127.0.0.1:<port>
                         |
       +-----------------------------------+
       | Local Pilot                       |
       |                                   |
       | OAuth / manual-token auth         |
       | Client management                 |
       | MCP Streamable HTTP               |
       | Policy engine                     |
       | Approval engine                   |
       | Project index                     |
       | Filesystem broker                 |
       | Process/task manager              |
       | PowerShell / cmd                  |
       | Git / GitHub CLI                  |
       | Audit + Data Shared               |
       | Secret redaction                  |
       | Update manager                    |
       |                                   |
       | Tauri Windows UI                  |
       +----------------+------------------+
                        |
          +-------------+--------------+
          |                            |
          v                            v
Documents\Projects               Windows OS/resources
ordinary project access          brokered reads per policy
                                 brokered writes: approval*
                                 protected broker reads denied
                                 admin requires approval
```

`*` Assigned `%LOCALAPPDATA%\LocalPilot\cache\temp` paths are the narrow external-write exception. Protected resources override workspace/cache allowances. Raw processes use best-effort shell checks and the current user's standard-user OS rights; the diagram is not an OS sandbox guarantee.

The application should feel like a local **agent workstation control center**, not merely an MCP endpoint.

The MCP protocol is the remote interface.

The Tauri application is the user's security/control surface.

`Documents\Projects` is the trusted work area.

Local user approval governs brokered external mutations and classified shell actions when shell checks are enabled. Arbitrary same-user programs remain subject to the limitations in Section 4.

Cloudflare or another user-chosen tunnel makes the loopback MCP endpoint reachable remotely without requiring the user to rent a cloud VM.
