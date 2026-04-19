# agent-codex

Built-in `agentenv` driver for running Codex as an agent inside a sandbox.

The driver installs Codex with `npm install -g @openai/codex`, honoring
`AgentSpec.version` when present. It renders Codex MCP configuration into
`~/.codex/config.toml` using `[mcp_servers.*]` TOML tables and returns a
declarative `codex --version` health probe. It supports both TUI and headless
entrypoints:

- TUI: `codex`
- Headless: `codex exec`

For a given `AgentSpec`, it declares `OPENAI_API_KEY` as a required API key
credential.

OpenShell install/probe activation scaffolds live under `tests/openshell_install.rs` and stay ignored until `sandbox-openshell` supports `create + exec`.
They only run with `AGENTENV_RUN_OPEN_SHELL_TESTS` once sandbox execution exists.
