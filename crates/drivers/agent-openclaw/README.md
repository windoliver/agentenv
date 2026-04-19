# agent-openclaw

Built-in OpenClaw agent driver for `agentenv`.

## Implemented behavior

- Installs OpenClaw with `RUN npm install -g openclaw`.
- Writes MCP configuration to `~/.openclaw/mcp_servers.json`.
- Renders deterministic MCP JSON using the same `mcpServers` shape as the other built-in agent drivers.
- Starts OpenClaw in TUI mode with `openclaw tui`.
- Starts OpenClaw in headless mode with `openclaw agent --headless`.
- Uses `openclaw --version` as the health-check probe.
- Reports MCP, slash-command, TUI, and headless capabilities.

## Configuration

Supported config keys:

- `mode`: `tui` (default) or `headless`.
- `provider`: `openai` or `anthropic`.
- `model`: optional model identifier used for provider inference.

Unknown keys and invalid values are rejected instead of silently falling back to defaults.

## Credential selection

OpenClaw defaults to OpenAI credentials:

```yaml
agent:
  name: openclaw
```

requires `OPENAI_API_KEY`.

Set `provider: anthropic` to require `ANTHROPIC_API_KEY`:

```yaml
agent:
  name: openclaw
  config:
    provider: anthropic
```

If `provider` is omitted, `model` prefixes are used when possible:

- `anthropic/...` requires `ANTHROPIC_API_KEY`.
- `openai/...` requires `OPENAI_API_KEY`.

An explicit provider that conflicts with an inferable model prefix is rejected.

OpenShell install/probe activation scaffolds live under `tests/openshell_install.rs` and stay ignored until `sandbox-openshell` supports `create + exec`.
They only run with `AGENTENV_RUN_OPEN_SHELL_TESTS` once sandbox execution exists.
