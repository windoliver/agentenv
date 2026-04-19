# agent-claude

Built-in agent driver for Claude Code.

The driver installs Claude Code with:

```dockerfile
RUN npm install -g @anthropic-ai/claude-code
```

For a given `AgentSpec`, it declares `ANTHROPIC_API_KEY` as a required API key
credential, writes MCP server configuration to `~/.claude/mcp_servers.json`,
and returns a declarative `claude --version` health probe.

Entrypoint rendering follows the shared agent config: TUI mode runs `claude`,
and headless mode runs `claude --headless`.

OpenShell install/probe activation scaffolds live under `tests/openshell_install.rs` and stay ignored until `sandbox-openshell` supports `create + exec`.
They only run with `AGENTENV_RUN_OPEN_SHELL_TESTS` once sandbox execution exists.
