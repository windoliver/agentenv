# Reference Blueprints

Reference blueprints are checked-in `agentenv.yaml` compositions that double as starter templates. Each file is runnable as-is after its listed credentials, URLs, and external drivers are available.

| Blueprint | Audience | Context | Policy | Pick it when |
|---|---|---|---|---|
| `claude+filesystem+openshell.yaml` | Getting started | Local filesystem | `balanced` | You want Claude Code over local projects. |
| `codex+filesystem+openshell.yaml` | Getting started | Local filesystem | `balanced` | You want Codex over local projects. |
| `openclaw+filesystem+openshell.yaml` | Getting started | Local filesystem | `balanced` | You want an OpenClaw assistant with persistent home state. |
| `claude+mcp-generic+openshell.yaml` | Integrators | Generic MCP endpoint | `restricted` | You have an MCP service and want Claude as the agent. |
| `hermes+filesystem+openshell.yaml` | Polyglot demos | Local filesystem | `balanced` | You want to exercise an external Hermes agent driver. |
| `claude+nexus+openshell.yaml` | Enterprise reference | Nexus hub | `balanced` | You use Claude with shared company context. |
| `codex+mcp-generic+openshell.yaml` | Integrators | Generic MCP endpoint | `restricted` | You have an MCP service and want Codex as the agent. |
| `hermes+nexus+openshell.yaml` | Polyglot enterprise demos | Nexus hub | `balanced` | You want Hermes through subprocess drivers with Nexus context. |
| `openclaw+nexus+openshell.yaml` | Enterprise reference | Nexus hub | `balanced` | You want OpenClaw with shared company context. |

## Getting-Started Filesystem Blueprints

`claude+filesystem+openshell.yaml`, `codex+filesystem+openshell.yaml`, and `openclaw+filesystem+openshell.yaml` mount `~/projects` through the filesystem context driver and expose it over MCP inside OpenShell. They are the lowest-friction templates because they do not require remote context infrastructure.

Required credentials:

- Claude: `ANTHROPIC_API_KEY`
- Codex and OpenClaw: `OPENAI_API_KEY`

Usage:

```sh
agentenv create myapp --blueprint blueprints/claude+filesystem+openshell.yaml
agentenv enter myapp
```

Trade-off: `balanced` policy includes common package and GitHub read presets, so these are better for local development than for tightly regulated data.

## Generic MCP Blueprints

`claude+mcp-generic+openshell.yaml` and `codex+mcp-generic+openshell.yaml` connect agents to any MCP-compatible HTTP+SSE endpoint.

Required environment:

- `MCP_URL`
- `MCP_TOKEN`
- agent API key for the selected agent

Usage:

```sh
export MCP_URL=https://mcp.internal.company.com
export MCP_TOKEN=mcp-token-example
agentenv create docs --blueprint blueprints/codex+mcp-generic+openshell.yaml
```

Trade-off: the `restricted` policy keeps egress narrow and allows only the configured MCP endpoint by default.

## Hermes Blueprints

`hermes+filesystem+openshell.yaml` and `hermes+nexus+openshell.yaml` use the external Hermes subprocess agent driver. Confirm it is installed before creating the env:

```sh
agentenv drivers list
```

Required environment:

- `OPENAI_API_KEY`
- `NEXUS_HUB_URL` and `NEXUS_TOKEN` for the Nexus variant

Trade-off: these blueprints demonstrate third-party driver composition, so they depend on driver installation in addition to normal credentials.

## Nexus Blueprints

`claude+nexus+openshell.yaml`, `hermes+nexus+openshell.yaml`, and `openclaw+nexus+openshell.yaml` connect to a shared Nexus hub.

Required environment:

- `NEXUS_HUB_URL`
- `NEXUS_TOKEN`
- agent API key for the selected agent

Usage:

```sh
export NEXUS_HUB_URL=https://nexus.company.com
export NEXUS_TOKEN=nexus-token-example
agentenv create enterprise --blueprint blueprints/claude+nexus+openshell.yaml
```

Trade-off: Nexus blueprints are the best fit for shared enterprise context, but they require a reachable hub and installed Nexus context driver.

## Sample Projects

- `examples/quickstart/` shows the smallest local project flow.
- `examples/enterprise-hub/` shows a Nexus hub template with company CA and internal base-image conventions.
- `examples/headless-ci/` shows a non-interactive CI template for automated code maintenance.
