# Security

Local Pilot is pre-release software. Please report vulnerabilities privately to the repository owner rather than opening a public issue containing exploit details or secrets.

## Boundaries

Structured filesystem and Git tools apply Local Pilot's policy before acting. Paths are resolved with Windows-aware canonicalization and handle-relative operations where practical. Protected credentials remain denied even when a path appears under the trusted project root. External structured mutations require local approval unless they target the caller's assigned Local Pilot cache/temp subtree.

Shell inspection is a best-effort guard, not a Windows sandbox. A permitted executable runs with the current standard user's OS rights and may perform behavior that static command analysis cannot predict. Disabling shell checks affects shell preflight only; authentication, structured-tool policy, audit, redaction, ownership checks, Job Objects, and Emergency Stop remain active.

The elevated helper accepts one authenticated named-pipe request from the exact parent process and implements only a closed set of structured operations. It has no arbitrary elevated command endpoint. Windows still presents the UAC consent prompt.

## Sensitive data

Do not attach `%LOCALAPPDATA%\LocalPilot`, audit databases, support bundles, tokens, OAuth codes, `.env` files, credentials, private keys, command output, or Cloudflare configuration to a public report. Use synthetic values when reproducing redaction problems.

## Current release limitations

- No production installer or signed updater has been validated.
- No production Cloudflare route has been configured from this repository.
- Live ChatGPT OAuth/tool compatibility remains unverified.
- The desktop control surface compiles and packages but has not completed clean-machine usability testing.
- The application has not received an independent security review.

Passing automated tests does not remove these limitations.
