# AGENTS.md — Guidance for AI Coding Agents

> `agentenv` is built agent-first. If you are an agent working on this repo, this file tells you how to be effective.

## Orient yourself fast

1. Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) end-to-end before touching code.
2. Read [`docs/DRIVER_PROTOCOL.md`](docs/DRIVER_PROTOCOL.md) if you'll touch anything in `crates/agentenv-proto/`, `crates/agentenv-plugin/`, or any driver.
3. Read [`docs/ROADMAP.md`](docs/ROADMAP.md) to understand which milestone a given issue belongs to.
4. Scan [`Cargo.toml`](Cargo.toml) for the crate graph.

## Project philosophy (respect these)

- **Env manager, not orchestrator.** When in doubt about CLI verbs, prefer `conda`/`pixi`/`devbox` vocabulary (`create`, `enter`, `freeze`, `reproduce`) over `kubectl` vocabulary (`apply`, `get`, `describe`).
- **Narrow waist.** MCP is the only agent↔context protocol. JSON-RPC is the only core↔driver protocol. Don't add shortcuts that bypass either.
- **Capability handshake.** Don't assume a driver can do X; check its capabilities and degrade gracefully.
- **Rust quality bar.** `cargo clippy -D warnings` must pass. No `.unwrap()` outside tests. `thiserror` in libs, `anyhow` in bins.
- **Security in depth.** Credentials never flow through drivers' generic RPC channel; they're env-injected at spawn. Outbound URLs validate through the SSRF module. Blueprints digest-verify before apply.

## What to do before proposing code

- Confirm the affected crates and list them in the PR description.
- Check the Driver Protocol doc for any method signatures you'll touch — changing a method is a schema-version bump.
- If a change adds a capability, update every driver that might need to declare support (or explicitly note which can degrade).

## What to NOT do

- Don't add a 5th pluggable axis without design discussion — the four-axis model is load-bearing.
- Don't introduce a second serialization format. `serde_json` over stdio + `serde_yaml` for blueprints, nothing else.
- Don't pull in `openssl`; use `rustls` via `reqwest`'s feature flags.
- Don't add Python, Node, or any other runtime as a build-time dependency of the core. External drivers may depend on any runtime they like at install time — the core doesn't.
- Don't use `println!` in library code. Use `tracing`.

## Workflow

For non-trivial changes:

1. Open or find an issue.
2. Propose an approach as a comment before writing code, especially if architectural surface is involved.
3. Implement on a feature branch.
4. Ensure `cargo fmt`, `cargo clippy -D warnings`, and `cargo test --workspace` all pass.
5. Open a PR referencing the issue, with a concise summary of the approach and the trade-offs.

## Skills (coming soon)

The `.agents/skills/` directory will host skill bundles for common workflows (triage-issue, generate-policy, author-driver, protocol-conformance). Until then, follow the conventions above and the existing code.
