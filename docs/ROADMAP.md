# agentenv Roadmap

> Status: **alpha, scaffolding**. Tracking issues linked below. Umbrella: [#1](https://github.com/windoliver/agentenv/issues/1).

The work is organized into six milestones. Milestones are roughly sequential but internal issues within a milestone can be parallelized.

---

## M1 — Foundations

Core abstractions and supply-chain guarantees. No drivers yet.

- **M1-1** — Cargo workspace scaffold + CI + release pipeline
- **M1-2** — Driver protocol spec + capability handshake (`agentenv-proto`)
- **M1-3** — Blueprint format + lockfile + digest verification
- **M1-4** — Credential store (OS keyring + JSON fallback + injection contract)
- **M1-5** — Policy model + translator framework + tier/preset engine

Exit criterion: an empty workspace compiles, CI is green, and a mock driver can complete `initialize → preflight → create → destroy` against a test harness.

---

## M2 — Built-in drivers

First-class Rust drivers for the critical path.

- **M2-1** — `sandbox-openshell` (built-in)
- **H-2** — `sandbox-microvm` (built-in, Firecracker on Linux/KVM; Apple Container on macOS; Kata reserved)
- **M2-2** — Built-in agent drivers: Claude, Codex, OpenClaw
- **M2-3** — Built-in context drivers: filesystem, mcp-generic, none
- **M2-4** — Built-in inference drivers: openai, anthropic, ollama, passthrough

Exit criterion: `agentenv create` builds a working Claude-in-OpenShell env talking MCP to a filesystem context.

---

## M3 — Subprocess plugin host & polyglot drivers

- **M3-1** — Subprocess plugin host + JSON-RPC transport + driver discovery
- **M3-2** — External driver: `context-nexus-py` (Python, subprocess)
- **M3-3** — External driver: `agent-hermes-py` (Python, subprocess)

Exit criterion: a Python driver ships alongside the Rust binary and is discovered/used transparently.

---

## M4 — CLI and lifecycle

- **M4-1** — Core CLI: `create`, `enter`, `list`, `destroy`, `describe`
- **M4-2** — `freeze` / `reproduce` lockfile round-trip
- **M4-3** — Session model: attach / detach / resume

Exit criterion: an env created on machine A can be frozen, committed to git, and reproduced on machine B.

---

## M5 — Packaging, DX, and security

- **M5-1** — `curl | sh` installer + release artifacts
- **M5-2** — `uninstall.sh` + `agentenv uninstall`
- **M5-3** — BYO Dockerfile (`--from path/to/Dockerfile`)
- **M5-4** — Reference blueprints + sample projects
- **M5-5** — SSRF validation for outbound paths
- **M5-6** — Image hardening profiles

Exit criterion: zero-to-working-agent in one shell command on macOS / Linux.

---

## M6 — Day-2 operations

- **M6-1** — Activity event stream + audit log + `/metrics`
- **M6-2** — `agentenv term` operator TUI (ratatui)
- **M6-3** — Approvals queue + TUI + webhook/Slack
- **M6-4** — Env snapshot + safe migration with credential stripping

Exit criterion: an operator can observe live activity, approve unlisted egress requests in real time, and audit decisions after the fact.

---

## Post-MVP

- Docker sandbox driver
- E2B sandbox driver
- Community catalog (`agentenv-community` repo)
- Web dashboard for multi-env operators
- Hub-mode approvals with ReBAC
