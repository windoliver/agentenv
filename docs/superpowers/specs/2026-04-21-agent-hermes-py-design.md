# Agent Hermes Python Driver Design

- Date: 2026-04-21
- Issue: https://github.com/windoliver/agentenv/issues/13
- Milestone: M3 Subprocess plugin host and polyglot drivers
- Affected paths: `external-drivers/agent-hermes-py`, `tests/driver-conformance`, `install.sh`, `tests/install/test_install.sh`, `docs/DRIVER_PROTOCOL.md`, `blueprints/hermes+nexus+openshell.yaml`

## 1. Context and Goals

Issue #13 adds the `agent-hermes-py` external agent driver. The driver adapts Nous Research Hermes Agent to the agentenv `AgentDriver` protocol as a Python subprocess driver.

The current repository already includes driver manifest discovery and `agentenv drivers list`. It does not yet include full subprocess lifecycle integration for `AgentDriver` execution during `agentenv create`. This design therefore implements the standalone Hermes driver package and its local conformance coverage, while documenting the remaining host integration as a follow-up instead of expanding this issue into the rest of M3-1.

Goals:

1. Ship a real external driver package in `external-drivers/agent-hermes-py/`.
2. Install into `~/.agentenv/drivers/agent-hermes/` with an isolated Python virtual environment.
3. Expose a valid `manifest.json` discovered as the `hermes` agent driver.
4. Implement the current `AgentDriver` JSON-RPC method surface.
5. Render Hermes MCP configuration in the format Hermes currently consumes.
6. Keep credentials out of JSON-RPC payloads and manifests.
7. Pass driver conformance and package-local tests without requiring live model credentials.

## 2. External Hermes Reference Points

Hermes Agent is installed from the official `NousResearch/hermes-agent` GitHub repository. Its `pyproject.toml` declares the `hermes-agent` Python package, the `hermes` console script, and optional extras including `mcp` and `acp`.

Relevant upstream behavior:

1. `hermes` defaults to interactive chat.
2. `hermes chat` starts an interactive chat session.
3. `hermes chat --query <text>` supports single-query non-interactive use.
4. `hermes --version` and `hermes version` print version information.
5. MCP server configuration is stored in `~/.hermes/config.yaml` under top-level `mcp_servers`.
6. `hermes mcp add` accepts HTTP/SSE URLs and stdio command entries.
7. Hermes ACP support exists as the `hermes-acp` console script, but issue #13 is about agentenv's driver protocol, not editor ACP integration.

## 3. Scope and Non-Goals

### In scope

1. Python package layout, tests, and launcher script.
2. JSON-RPC 2.0 over stdio with LSP-style framing.
3. `initialize`, `preflight`, `install_steps`, `mcp_config_path`, `render_mcp_config`, `render_entrypoint`, `credential_requirements`, `health_check_probe`, and `shutdown`.
4. Manifest and isolated-venv installation scripts.
5. Bundle script compatible with the existing top-level Python driver index installer.
6. Conformance coverage that invokes the driver binary directly.
7. Documentation of the M4/M3 host work still required before `agentenv create` can run Hermes end-to-end.

### Out of scope

1. Implementing the production subprocess `AgentDriver` adapter in Rust.
2. Implementing `agentenv create`, `enter`, or full lifecycle CLI commands.
3. Adding a second serialization format or changing `agentenv-proto`.
4. Passing credential values over RPC.
5. Vendoring Hermes source into this repository.
6. Proving real model calls in CI.
7. Changing Nexus or the context-driver path.

## 4. Package Layout

The driver lives at:

```text
external-drivers/agent-hermes-py/
|-- README.md
|-- pyproject.toml
|-- manifest.json.in
|-- scripts/
|   |-- build-bundle.sh
|   `-- install-driver.sh
|-- src/
|   `-- agentenv_agent_hermes/
|       |-- __init__.py
|       |-- __main__.py
|       |-- driver.py
|       |-- hermes.py
|       |-- jsonrpc.py
|       `-- protocol.py
`-- tests/
    |-- test_driver_methods.py
    |-- test_jsonrpc.py
    `-- test_protocol_shapes.py
```

Responsibilities:

1. `jsonrpc.py` reads and writes framed JSON-RPC messages and maps exceptions to protocol error responses.
2. `protocol.py` contains small Python representations and validation helpers for the subset of agentenv protocol messages the driver needs.
3. `hermes.py` owns Hermes-specific command, config, credential, and install-step rendering.
4. `driver.py` maps JSON-RPC methods to Hermes driver behavior.
5. `__main__.py` runs the stdio server.

The package should use the Python standard library for its own JSON-RPC server. It should declare `PyYAML` for Hermes config rendering and `pytest` for tests. The installed driver venv also includes Hermes Agent with the `mcp` extra from staged wheels.

## 5. Manifest

The installed manifest should be:

```json
{
  "schema_version": "1.0",
  "name": "hermes",
  "kind": "agent",
  "version": "0.1.0",
  "description": "Hermes Agent driver for agentenv",
  "binary": "./bin/agentenv-driver-hermes",
  "args": [],
  "env": {},
  "capabilities_preview": {
    "supports_mcp": true,
    "supports_slash_commands": true,
    "supports_tui": true,
    "supports_headless": true
  }
}
```

The installed directory is:

```text
~/.agentenv/drivers/agent-hermes/
|-- manifest.json
|-- bin/
|   `-- agentenv-driver-hermes
|-- venv/
`-- wheels/
```

The manifest name remains `hermes` because blueprints use `agent.driver: hermes`. The directory name can be `agent-hermes` to avoid ambiguity with future non-agent Hermes integrations.

## 6. Driver Protocol Behavior

### initialize

Accepts only compatible schema major versions. Returns:

```json
{
  "driver": {
    "name": "hermes",
    "kind": "agent",
    "version": "0.1.0",
    "protocol_version": "1.0"
  },
  "capabilities": {
    "supports_mcp": true,
    "supports_slash_commands": true,
    "supports_tui": true,
    "supports_headless": true
  }
}
```

Schema-version mismatch returns JSON-RPC error `-32002` with an actionable message.

### preflight

Preflight checks whether the installed venv can run `hermes --version`.

Results:

1. `ok: true` when `hermes --version` exits successfully.
2. `ok: false` with code `hermes_missing` when `hermes` is not available.
3. `ok: false` with code `hermes_version_failed` when the command exists but exits non-zero.

Preflight must not require `OPENAI_API_KEY` or any model provider key.

### install_steps

Returns Dockerfile fragments that install Hermes inside the sandbox:

```dockerfile
ARG HERMES_AGENT_PACKAGE="hermes-agent[mcp] @ git+https://github.com/NousResearch/hermes-agent.git"
RUN python3 -m pip install --no-cache-dir "$HERMES_AGENT_PACKAGE"
```

If `AgentSpec.version` is provided, treat it as a safe Git ref and render:

```dockerfile
RUN python3 -m pip install --no-cache-dir "hermes-agent[mcp] @ git+https://github.com/NousResearch/hermes-agent.git@<version>"
```

The default source can be overridden in sandbox builds with `--build-arg HERMES_AGENT_PACKAGE=...`.

### mcp_config_path

Returns:

```json
{"path": "~/.hermes/config.yaml"}
```

### render_mcp_config

Renders YAML with top-level `mcp_servers`. Endpoint names are deterministic: `endpoint_0`, `endpoint_1`, and so on.

HTTP and HTTP+SSE endpoints render as:

```yaml
mcp_servers:
  endpoint_0:
    url: "https://example.com/mcp"
```

Stdio endpoints render as:

```yaml
mcp_servers:
  endpoint_0:
    command: "npx"
    args: []
```

Because the current `McpEndpoint` type represents stdio as a single `url` string, the Hermes driver treats that string as the command and leaves `args` empty. If a context driver needs stdio arguments later, the protocol should add a structured stdio endpoint shape in a separate schema-versioned change.

Endpoint headers render as `headers` for HTTP entries when present:

```yaml
mcp_servers:
  endpoint_0:
    url: "https://example.com/mcp"
    headers:
      X-Example: "value"
```

`ssh+http` returns `-32000 CapabilityMissing` because Hermes MCP config does not document that transport.

The renderer should use a YAML serializer rather than ad hoc string concatenation.

### render_entrypoint

The driver accepts shared agent config:

```json
{
  "mode": "tui",
  "model": "openai/gpt-5.4",
  "provider": "openai"
}
```

Defaults:

1. `mode` defaults to `tui`.
2. `provider` defaults to `openai`.
3. `model` is optional.

TUI entrypoint:

```sh
#!/usr/bin/env sh
set -eu
exec hermes chat "$@"
```

Headless entrypoint:

```sh
#!/usr/bin/env sh
set -eu
exec hermes chat --quiet --query "$*"
```

If `model` is set, include `--model "<model>"`. If `provider` is set, include `--provider "<provider>"`. Shell arguments must be safely quoted.

### credential_requirements

The driver derives credential requirements from `AgentSpec.config.provider`.

Supported provider mapping:

| Provider | Credential |
| --- | --- |
| `openai`, `openai-codex` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openrouter` | `OPENROUTER_API_KEY` |
| `nous-api` | `NOUS_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |
| `zai` | `GLM_API_KEY` |
| `kimi-coding` | `KIMI_API_KEY` |
| `minimax` | `MINIMAX_API_KEY` |
| `minimax-cn` | `MINIMAX_CN_API_KEY` |
| `huggingface` | `HF_TOKEN` |
| `nvidia` | `NVIDIA_API_KEY` |
| `ollama-cloud` | `OLLAMA_API_KEY` |
| `kilocode` | `KILOCODE_API_KEY` |
| `ai-gateway` | `AI_GATEWAY_API_KEY` |
| `custom`, `lmstudio`, `ollama`, `vllm`, `llamacpp` | none |
| `auto` or omitted | `OPENAI_API_KEY` |

`OPENAI_API_KEY` remains the default to match the issue's blueprint. Unknown providers return a clear invalid-config error rather than silently declaring the wrong credential.

### health_check_probe

Returns:

```json
{
  "cmd": "hermes --version",
  "tty": false,
  "env": {},
  "success_exit_codes": [0]
}
```

### shutdown

Returns `{}` and exits after the response is flushed.

## 7. Packaging and Install

`scripts/install-driver.sh`:

1. resolves `AGENTENV_HOME` or defaults to `~/.agentenv`
2. creates a temporary staged directory
3. creates `venv` with `python3 -m venv`
4. builds wheels for the driver and `HERMES_AGENT_PACKAGE`
5. installs the driver and `hermes-agent[mcp]` from the staged wheel directory with `--no-index`
6. writes `bin/agentenv-driver-hermes`
7. writes `manifest.json`
8. atomically replaces `~/.agentenv/drivers/agent-hermes/`

`scripts/build-bundle.sh` creates a tarball whose root contains `manifest.json`, `bin/`, `wheels/`, and any install metadata needed by the existing top-level `install.sh` Python-driver bundle path.

The top-level installer should continue to install bundles from `AGENTENV_PYTHON_DRIVERS_INDEX_URL`. If changes are needed, keep them generic for Python driver bundles rather than special-casing Hermes.

## 8. Tests

### Python tests

Add package-local tests for:

1. JSON-RPC framing reads and writes valid LSP-style frames.
2. malformed JSON returns parse error.
3. unknown methods return `-32601`.
4. schema mismatch returns `-32002`.
5. initialize reports agent kind and agent capabilities.
6. install steps use the official Hermes GitHub source with `mcp` extras.
7. versioned install steps pin the Hermes Git source to a safe ref.
8. MCP config renders HTTP, HTTP+SSE, stdio, and headers.
9. `ssh+http` reports capability missing.
10. entrypoint renders TUI and headless modes.
11. credential requirements follow provider mapping.
12. health check probe uses `hermes --version`.

### Rust and conformance tests

Extend the direct subprocess conformance suite only where it can run the driver binary without needing core lifecycle support. The test should:

1. build or point to the Python driver launcher
2. run `initialize`
3. run `preflight` in a hermetic mode where Hermes is either installed in the test venv or expected to return a structured preflight issue
4. call the agent-specific JSON-RPC methods
5. call `shutdown`

If invoking Python packaging from Rust is too expensive for default workspace tests, keep it as a documented script under the driver package and include it in CI later.

### Installer tests

Add shell tests only if the generic bundle installer needs changes. Required coverage:

1. Hermes bundle installs under `drivers/agent-hermes`.
2. failed extraction preserves an existing driver directory.
3. installed manifest is discoverable by `agentenv drivers list`.

## 9. Error Handling

Python JSON-RPC errors use protocol codes from `agentenv-proto`:

| Code | Use |
| --- | --- |
| `-32700` | parse error |
| `-32600` | invalid request |
| `-32601` | method not found |
| `-32602` | invalid params |
| `-32603` | internal error |
| `-32000` | missing capability |
| `-32002` | incompatible schema version |

Every error message should include the method or config field that caused it.

## 10. Security

1. Credential values are never serialized in JSON-RPC params, manifests, generated MCP config, logs, or command argv.
2. The driver declares credential names only.
3. Manifest `env` remains empty by default.
4. Install scripts stage and atomically replace driver directories.
5. The package does not add Python as a build-time dependency of Rust core.
6. The default install builds from the official Hermes GitHub source and then installs from staged wheels with `--no-index`.

## 11. Acceptance and Follow-Ups

This implementation satisfies the standalone driver acceptance criteria:

1. driver installs into an isolated venv
2. `hermes --version` is represented as the health probe and checked by preflight
3. MCP config renders in Hermes' documented `mcp_servers` shape
4. missing Hermes installation is reported as an actionable preflight issue
5. direct protocol conformance passes for the driver's JSON-RPC surface

Remaining follow-ups:

1. Wire production subprocess `AgentDriver` adapters into `agentenv-core`.
2. Wire `agentenv create` lifecycle commands to instantiate external agent drivers.
3. Add an end-to-end Hermes + Nexus + OpenShell test once M4 lifecycle exists.
4. Revisit stdio MCP endpoint structure if context drivers need command arguments.
