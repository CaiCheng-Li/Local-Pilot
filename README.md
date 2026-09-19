# Local Pilot

Local Pilot is a Windows 11 workstation service for authenticated MCP clients. It brokers project discovery, file operations, processes, Git and GitHub workflows through a local policy engine, explicit approvals, owner-scoped sessions, redacted audit records, and a persistent Emergency Stop.

This checkout is under active development. The Rust service and policy layers are implemented and tested on Windows; the desktop packaging, public networking setup, signed updater, installer validation, and live ChatGPT compatibility test are not release-ready yet. Do not expose this build to the public Internet as a production service.

## Requirements

- Windows 11 x64
- Rust 1.88 or newer with the MSVC toolchain
- Node.js 22 and pnpm 12 for the desktop frontend
- Git and GitHub CLI for their corresponding tools

## Validate the service

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
pnpm install --frozen-lockfile
pnpm build
```

The integration suites cover MCP protocol behavior, OAuth authorization and refresh, project and file workflows, approvals, process jobs, Git policies, client isolation, Emergency Stop persistence, audit redaction, Windows path aliases, hard links, junctions, and concurrent reparse-point swaps. Build a local development installer with `.\scripts\build-installer.ps1 -Debug -Bundle nsis`.

## Repository layout

- `crates/workstation-core`: configuration, storage primitives, DPAPI, paths, and redaction
- `crates/workstation-policy`: Windows path validation and command/policy classification
- `crates/workstation-audit`: audit and Data Shared persistence and retention
- `crates/workstation-index`: project discovery and file/search index
- `crates/workstation-executor`: standard-user process execution and Job Objects
- `crates/workstation-server`: OAuth, sessions, approvals, MCP transport, tools, and local UI API
- `crates/workstation-elevated-helper`: one-shot structured UAC helper
- `tests`: integration, protocol, and adversarial Windows security suites
- `plan.md`: authoritative product and security specification

Local Pilot stores application control data under `%LOCALAPPDATA%\LocalPilot`. Its default trusted workspace is the current user's Windows Documents known folder plus `Projects`; the code resolves that known folder through Windows APIs.

## Security model

Structured tools enforce canonical destination checks and protected-resource rules. Arbitrary shell commands receive best-effort preflight checks and still run with the current user's Windows rights; they are not contained by an OS sandbox. Read [SECURITY.md](SECURITY.md) before testing with real data.

No license has been selected. The plan requires the owner to choose one before any public release.
