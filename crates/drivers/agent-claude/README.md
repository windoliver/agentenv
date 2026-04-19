# agent-claude

Built-in agent driver for Claude Code.

The driver installs Claude Code with:

```dockerfile
RUN npm install -g @anthropic-ai/claude-code
```

It declares `ANTHROPIC_API_KEY` as a required API key credential, writes MCP
server configuration to `~/.claude/mcp_servers.json`, and uses
`claude --version` as its health probe.

Entrypoint rendering follows the shared agent config: TUI mode runs `claude`,
and headless mode runs `claude --headless`.
