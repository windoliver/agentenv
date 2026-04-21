# context-none

Built-in no-op context driver for agentenv.

This driver provisions no external context backend, returns no required network rules,
declares no credentials, and exposes an empty stdio MCP endpoint sentinel. Future
agent config assembly should skip empty endpoint URLs when rendering MCP config.
