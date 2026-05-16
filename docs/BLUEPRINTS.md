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

## Hardening Profiles

Blueprints may set `sandbox.hardening` to choose an image hardening profile.
When omitted, the core uses `baseline`.

- `baseline` is the default production posture. It removes common compilers and
  network/debug tools at the image layer, requests `NET_RAW` capability
  dropping, and keeps normal developer writable paths.
- `strict` is for sensitive work. It strips more tools, drops additional
  packages, and includes runtime recommendations for capability drops, `/tmp`
  tmpfs, core dumps, and user namespaces.
- `open` keeps only minimal image hardening for exploratory environments where
  tool availability matters more than locked-down images.

For BYO Dockerfiles, run:

```sh
agentenv blueprint lint <agentenv.yaml>
```

The linter resolves the selected profile and reports Dockerfile patterns that
conflict with hardening before creating the environment.

Current OpenShell BYO enforcement injects the selected Dockerfile fragment and
uses the supported filesystem policy merge. Runtime hardening metadata is parsed
and validated for future driver mappings; it is not currently translated into
extra OpenShell CLI arguments.

## DNS Egress Policy

Blueprints may configure DNS egress under `policy.dns`:

```yaml
policy:
  tier: restricted
  presets: []
  dns:
    resolvers_allowed:
      - 1.1.1.1
      - 8.8.8.8
    doh_upstreams_allowed:
      - https://cloudflare-dns.com/dns-query
      - https://dns.google/dns-query
    dot_upstreams_allowed:
      - 1.1.1.1:853
    log_all_queries: true
    pin_resolved_ips: true
```

`policy.dns` is enforced only by sandbox drivers that report
`supports_dns_egress_control`. Empty DNS policy preserves legacy behavior.
When DNS policy is active, the sandbox must use the driver-managed DNS guard,
and direct DNS, DoT, or DoH bypass traffic must be denied. Drivers that cannot
enforce those controls must report `supports_dns_egress_control = false`.

## MCP Tool-Call Guards

Blueprints may opt into core-mediated MCP tool-call guards under
`policy.mcp.confused_deputy_guards`. Reference blueprints keep this block
commented out by default so existing templates remain runnable without approval
prompts.

```yaml
policy:
  tier: restricted
  mcp:
    confused_deputy_guards:
      enabled: true
      default_approval: per-call
      tool_policies:
        "filesystem.read":
          approval: never
          rate_limit: 50/session
        "web.fetch":
          approval: per-call
          url_allowlist:
            - api.github.com
            - crates.io
          redact_args: true
        "*.write":
          approval: per-session
      cross_tool_flows:
        forbid_read_to_write_turns: 5
```

When enabled, HTTP and HTTP+SSE MCP endpoints are guarded in the host egress
proxy. Stdio MCP endpoints are wrapped with `agentenv mcp-guard run` before the
agent driver renders MCP config.

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
export MCP_URL=https://example.com/mcp
export MCP_TOKEN=mcp-token-example
agentenv create docs --blueprint blueprints/codex+mcp-generic+openshell.yaml
```

Note: the templates collect `MCP_TOKEN` as a credential reference, but the current generic MCP driver does not attach it to endpoint headers yet. Use endpoints that do not require header auth, or add driver support before relying on token auth.

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
export NEXUS_HUB_URL=https://example.com/nexus
export NEXUS_TOKEN=nexus-token-example
agentenv create enterprise --blueprint blueprints/claude+nexus+openshell.yaml
```

Trade-off: Nexus blueprints are the best fit for shared enterprise context, but they require a reachable hub and installed Nexus context driver.

## Sample Projects

- `examples/quickstart/` shows the smallest local project flow.
- `examples/enterprise-hub/` shows a Nexus hub template with company CA and internal base-image conventions.
- `examples/headless-ci/` shows a non-interactive CI template for automated code maintenance.
