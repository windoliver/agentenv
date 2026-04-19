# agent-codex

Built-in `agentenv` driver for running Codex as an agent inside a sandbox.

The driver installs Codex with `npm install -g @openai/codex`, renders the
Codex MCP configuration at `~/.codex/mcp_servers.json`, and supports both TUI
and headless entrypoints:

- TUI: `codex`
- Headless: `codex exec`

It declares `OPENAI_API_KEY` as a required API key credential.

OpenShell-backed install/probe tests live under `tests/openshell_install.rs` and stay ignored until `sandbox-openshell` supports `create + exec`.
