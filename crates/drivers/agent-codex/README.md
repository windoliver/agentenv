# agent-codex

Built-in `agentenv` driver for running Codex as an agent inside a sandbox.

The driver installs Codex with `npm install -g @openai/codex`, renders the
Codex MCP configuration at `~/.codex/mcp_servers.json`, and returns a
declarative `codex --version` health probe. It supports both TUI and headless
entrypoints:

- TUI: `codex`
- Headless: `codex exec`

For a given `AgentSpec`, it declares `OPENAI_API_KEY` as a required API key
credential.

OpenShell install/probe activation scaffolds live under `tests/openshell_install.rs` and stay ignored until `sandbox-openshell` supports `create + exec`.
They only run with `AGENTENV_RUN_OPEN_SHELL_TESTS` once sandbox execution exists.
