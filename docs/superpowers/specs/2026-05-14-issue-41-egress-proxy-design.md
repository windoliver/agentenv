# H-5 Design: Brokered Egress Credential Injection

Date: 2026-05-14
Issue: [#41](https://github.com/windoliver/agentenv/issues/41)
Label: hardening

## Summary

Issue #41 replaces sandbox-visible API credentials with a host-owned egress broker.
The sandbox sees unauthenticated local proxy endpoints plus dummy values for SDKs that
require an API key environment variable. The broker resolves real credentials from the
host credstore at request time, injects upstream auth, enforces policy and rate limits,
emits audit events, and strips response headers that could leak upstream identity.

This is a full-scope one-PR design covering OpenAI, Anthropic, GitHub, generic MCP
bearer endpoints, and generic OCI registries.

The GitHub app available in this workspace could not post the required issue approach
comment because GitHub returned `403 Resource not accessible by integration`. Before
implementation starts, a maintainer must either post the approach from this spec on
issue #41 or explicitly accept this spec as the approach record.

## Affected Crates And Docs

- `crates/agentenv-core`
- `crates/agentenv`
- `crates/agentenv-proto`
- `crates/agentenv-events`
- `crates/agentenv-policy`
- `crates/agentenv-credstore`
- `crates/drivers/sandbox-openshell`
- `crates/drivers/sandbox-microvm`
- `crates/drivers/sandbox-remote-ssh`
- `crates/drivers/context-mcp-generic`
- `crates/drivers/inference-openai`
- `crates/drivers/inference-anthropic`
- `crates/drivers/inference-ollama`
- `docs/ARCHITECTURE.md`
- `docs/DRIVER_PROTOCOL.md`
- `docs/BLUEPRINTS.md`
- reference blueprints that declare provider or MCP credentials

## Goals

1. Prevent brokered credential values from entering sandbox process memory,
   filesystem state, driver RPC params, sandbox handles, policy YAML, logs, metrics,
   lockfiles, or snapshots.
2. Support the service patterns listed in issue #41: Anthropic, OpenAI, GitHub,
   generic OCI, and bearer-auth MCP endpoints.
3. Preserve the four-axis architecture. Do not add a fifth pluggable axis.
4. Keep MCP as the agent-context narrow waist and JSON-RPC as the core-driver narrow
   waist.
5. Reuse the existing SSRF and policy validation paths for allowed upstreams.
6. Emit structured `event/activity` records for every proxied request.
7. Degrade clearly when a sandbox driver cannot expose a host egress proxy.

## Non-Goals

- Building a fleet egress gateway or multi-tenant hub service.
- Adding a new driver kind.
- Supporting arbitrary transparent TCP proxying for all outbound traffic.
- Implementing Docker daemon credential storage on the host. The OCI slice is an HTTP
  registry proxy with sandbox-side dummy Docker auth config, not host daemon mutation.
- Supporting secret-bearing URLs. URLs with embedded credentials remain rejected.
- Changing the credential store backend model.

## Chosen Approach

Implement a core-owned host egress broker launched as a child process of `agentenv`
during `create`. The broker is part of the existing single binary through a hidden
subcommand such as:

```text
agentenv proxy run --env <name> --config <path> --events-db <path>
```

Runtime writes a private, host-only proxy config under the temporary env workspace,
starts the child process before sandbox creation, passes only non-secret proxy metadata
to the sandbox driver, and persists the broker handle in env state after successful
create. `destroy` stops the broker before or after sandbox teardown, depending on
which cleanup path is still available.

This keeps credential resolution in core/credstore and leaves sandbox drivers
responsible only for sandbox reachability.

## Architecture

### Core Broker Module

Add `agentenv-core::egress_proxy` with these responsibilities:

- Model broker routes and service kinds.
- Build proxy plans from resolved blueprint components, driver credential
  requirements, context endpoints, inference endpoints, and `NetworkPolicy`.
- Classify credentials as brokered or sandbox-injected.
- Render host-only broker config.
- Render sandbox environment variables and config snippets that contain no secret
  values.
- Provide pure request-auth helpers for tests.

The broker module depends on existing `RuntimeSecret`, `CredentialProvider`, SSRF
validation, and `agentenv-events` models. It must not depend on concrete driver crates.

### CLI Broker Runtime

Add a hidden `Proxy(ProxyArgs)` CLI path in `crates/agentenv` that exposes
`agentenv proxy run`, loads the host-only config, and runs an HTTP reverse proxy. It
uses the workspace's existing async stack:

- `tokio`
- `hyper`
- `http-body-util`
- `reqwest` for upstream client calls with `rustls`

The proxy process never prints credential values. Debug representations of route and
credential structs must redact values.

### Sandbox Driver Contract

Add an additive schema `1.3` sandbox capability:

```rust
pub struct SandboxCapabilities {
    // existing fields
    pub supports_host_egress_proxy: bool,
}
```

Sandbox drivers that advertise this capability accept these metadata keys in
`SandboxSpec.metadata`:

- `agentenv_egress_proxy_url`: sandbox-reachable HTTP base URL.
- `agentenv_egress_proxy_mode`: `loopback`, `host-gateway`, `uds`, or
  `unsupported`.

Bundled sandbox drivers report false until they can prove a sandbox-reachable host
or gateway-local endpoint. If a blueprint needs brokered credentials and the
selected sandbox reports false, runtime rejects `create` with `CapabilityMissing`.

The capability is additive, so older subprocess drivers deserialize missing fields as
false and fail closed.

## Service Routes

### OpenAI

Broker route:

```text
/v1/openai/* -> https://api.openai.com/v1/*
```

Sandbox environment:

```text
OPENAI_BASE_URL=<proxy-url>/v1/openai
OPENAI_API_KEY=agentenv-brokered
```

Injected upstream auth:

```text
Authorization: Bearer <openai.api_key>
```

Credential source compatibility:

- Existing driver requirement `OPENAI_API_KEY` maps to canonical broker credential
  name `openai.api_key`.
- Existing blueprints that declare `OPENAI_API_KEY` remain accepted.
- Lockfiles continue storing references only.

### Anthropic

Broker route:

```text
/v1/anthropic/* -> https://api.anthropic.com/*
```

Sandbox environment:

```text
ANTHROPIC_BASE_URL=<proxy-url>/v1/anthropic
ANTHROPIC_API_KEY=agentenv-brokered
```

Injected upstream auth:

```text
x-api-key: <anthropic.api_key>
```

The broker must strip any sandbox-supplied `x-api-key`, `anthropic-api-key`, or
`authorization` header before injecting host credentials.

### GitHub

Broker routes:

```text
/v1/github/api/* -> https://api.github.com/*
/v1/github/git/<owner>/<repo>.git/* -> https://github.com/<owner>/<repo>.git/*
```

Sandbox setup:

- Configure `GITHUB_API_URL=<proxy-url>/v1/github/api`.
- Add a git config rewrite:

```text
url."<proxy-url>/v1/github/git/".insteadOf=https://github.com/
```

Injected upstream auth:

```text
Authorization: Bearer <github.token>
```

The proxy must allow only HTTPS Git smart HTTP and GitHub API paths. It denies
path traversal, absolute upstream URLs in path segments, and non-GitHub hosts.

### Generic MCP Bearer

`context-mcp-generic` already declares optional `MCP_TOKEN` but does not attach it to
headers. The broker will make that usable without putting the token into agent config.

For an endpoint:

```yaml
context:
  driver: mcp-generic
  endpoint:
    transport: http
    url: https://mcp.example.test/mcp
  credentials:
    MCP_TOKEN:
      source: env
```

Runtime rewrites the agent-visible MCP endpoint to:

```text
<proxy-url>/v1/mcp/<route-id>
```

Injected upstream auth:

```text
Authorization: Bearer <mcp.<endpoint>.token>
```

Compatibility:

- Existing `MCP_TOKEN` maps to the route credential for the configured endpoint.
- If no MCP token resolves, the route can operate without auth only when the
  credential requirement is optional and the endpoint accepts unauthenticated probe
  behavior.
- Agent MCP config must not contain `Authorization` headers with real values.

### Generic OCI

Broker route:

```text
/v1/oci/<registry>/* -> https://<registry>/v2/*
```

Credential naming:

```text
oci.<registry>
```

Sandbox setup:

- For Docker-compatible clients, write a dummy auth entry pointing to the proxy
  registry host when a client insists on auth presence.
- Configure registry mirror or rewritten image reference only for explicit OCI
  registry routes declared by policy or blueprint config.

Injected upstream auth:

```text
Authorization: Bearer <oci.<registry>>
```

OCI is limited to distribution API paths under `/v2/`. The broker must not become a
generic package-manager proxy in this PR.

## Credential Classification

Runtime currently resolves all requirements and inserts resolved values into
`SandboxSpec.env`. Replace that with a classifier:

```text
CredentialRequirement -> CredentialDisposition
```

Dispositions:

- `Brokered { service, canonical_name, legacy_env_name }`
- `SandboxEnv { name }`
- `UnusedOptional { name }`

Rules:

- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `MCP_TOKEN`, `GITHUB_TOKEN`, and
  `GH_TOKEN` are brokered when their matching service route exists.
- `oci.<registry>` is brokered when an OCI route exists.
- Passthrough inference remains sandbox-injected because passthrough means the agent
  owns provider auth directly.
- Unknown credentials remain sandbox-injected for compatibility, unless a blueprint
  explicitly marks them as broker-only.

For brokered credentials, runtime resolves the value into the broker config or broker
credential resolver, emits a credential event with the name only, and omits the value
from `SandboxSpec.env`.

## Policy Integration

The broker receives a live allowlist derived from:

- `NetworkPolicy.network.allow`
- `NetworkPolicy.inference.routes`
- context driver `required_network_rules`
- explicit broker routes for GitHub and OCI

Every incoming request is validated in this order:

1. Match route by stable route id and service kind.
2. Validate method, path, and host rules for the service.
3. Validate upstream URL through existing SSRF options.
4. Enforce live policy allowlist.
5. Enforce rate limits.
6. Resolve credential.
7. Forward request with injected auth.

`apply_policy` remains the driver path for sandbox policy updates. Runtime also
updates the broker's live policy when policy changes by atomically replacing a
host-only JSON policy file watched by the broker.

## Rate Limits

Add route-level fixed-window limits in the broker config:

```yaml
rate_limits:
  openai:
    requests_per_minute: 60
  anthropic:
    requests_per_minute: 60
  github:
    requests_per_minute: 120
  mcp:
    requests_per_minute: 120
  oci:
    requests_per_minute: 240
```

Defaults are conservative and overridable through policy extra fields. A limit hit
returns HTTP `429` and emits an activity event with `reason_code=rate_limited`.

## Audit And Events

Every proxied request emits a redacted `ActivityEvent`:

- `kind=egress_allowed`, `result=ok` for successful forwarding.
- `kind=egress_denied`, `result=denied` for policy, SSRF, route, or method denial.
- `kind=egress_denied`, `result=denied`, `reason_code=rate_limited` for rate limit
  failures.

Subjects include:

- env name
- service kind
- route id
- method
- redacted upstream origin and path
- status code when available

Subjects and extras must never include:

- request headers
- response headers
- credential values
- query strings unless explicitly redacted by `agentenv-events`

The broker writes into the same env SQLite event store used by runtime and approvals.

## Response Sanitization

The proxy strips or rewrites response headers before returning to the sandbox:

- `www-authenticate`
- `server`
- `x-request-id`
- provider-specific organization, account, or trace headers
- `set-cookie`

The broker preserves protocol-critical headers such as content type, content length
when safe, transfer encoding behavior, and streaming response semantics.

## Lifecycle

Create flow:

1. Resolve blueprint and drivers.
2. Initialize drivers and capabilities.
3. Build context and inference handles.
4. Build broker plan from services, credentials, policy, and endpoints.
5. If the plan has brokered routes, require sandbox
   `supports_host_egress_proxy`.
6. Resolve brokered credentials on host.
7. Start the broker child process with a host-only config.
8. Render agent-visible MCP endpoint rewrites and sandbox env dummy values.
9. Create sandbox with no brokered credential values in `SandboxSpec.env`.
10. Install agent config and entrypoint.
11. Persist env state with proxy process metadata but no credential values.

Destroy flow:

1. Initialize persisted drivers.
2. Stop sandbox sessions.
3. Destroy sandbox.
4. Stop broker process.
5. Teardown inference and context handles.
6. Remove env registry state.

Rollback:

- If sandbox creation fails after broker start, stop the broker.
- If broker start fails, do not create the sandbox.
- If policy restore after install fails, stop the broker during normal rollback.

## State Model

Extend `EnvStateFile` with a non-secret proxy section:

```json
{
  "egress_proxy": {
    "pid": 12345,
    "listen_url": "http://127.0.0.1:17778",
    "config_path": ".../egress-proxy.json",
    "routes": ["openai", "anthropic", "github-api"]
  }
}
```

The config file lives under the env directory with `0600` permissions. It contains
credential names, credential source metadata, route metadata, and rate limits. It never
contains credential values. The broker resolves credentials at request time through a
broker-side `CredentialStore` instance pointed at the host root. Env-sourced
credentials are resolved from the broker process environment by name, not copied into
the config file.

## Blueprint Surface

Keep existing blueprint credential declarations working:

```yaml
inference:
  driver: openai
  credentials:
    OPENAI_API_KEY:
      source: env
```

Add optional broker policy configuration under existing `policy.extra` rather than a
new top-level section:

```yaml
policy:
  tier: restricted
  presets: []
  egress_proxy:
    github: true
    oci:
      registries:
        - ghcr.io
    rate_limits:
      openai:
        requests_per_minute: 60
```

Unknown `policy.egress_proxy` fields are rejected by runtime validation so typos do
not silently weaken policy.

## Error Handling

Use existing error types where possible:

- Missing sandbox support: `DriverError::CapabilityMissing`.
- Missing required credential: `RuntimeError::MissingCredential`.
- Invalid route config: `DriverError::InvalidInput`.
- SSRF or policy denial at request time: HTTP `403` plus `egress_denied` event.
- Missing optional credential: route forwards unauthenticated only when explicitly
  allowed for that service.
- Upstream failure: propagate status where safe, otherwise `502`, with redacted event
  context.

## Security Requirements

- No `.unwrap()` outside tests.
- No `println!` in library code.
- No OpenSSL dependency; continue using `reqwest` with `rustls`.
- Broker config and state files must be regular files under env-owned directories.
- The broker must use `no_proxy()` for upstream HTTP clients so host proxy env vars
  cannot redirect credentialed requests.
- Redirect following is disabled.
- Request bodies are streamed and are not logged.
- Response bodies are streamed and are not logged.
- All URL strings in events pass through existing redaction helpers.

## Testing Strategy

Use TDD for implementation. Key tests:

### Core Broker Planning

- Classifies OpenAI, Anthropic, GitHub, MCP, and OCI credentials as brokered when
  matching routes exist.
- Leaves passthrough inference credentials sandbox-visible.
- Builds sandbox env with dummy API keys and proxy base URLs only.
- Rewrites generic MCP endpoint URL without adding real auth headers.
- Rejects brokered plans when sandbox capability is missing.
- Persists env state without credential values.

### Proxy Runtime

- OpenAI requests inject `Authorization: Bearer <secret>` upstream and strip
  sandbox-supplied auth.
- Anthropic requests inject `x-api-key`.
- GitHub API and Git smart HTTP routes reject host/path escapes.
- MCP route injects bearer auth only for the matching configured endpoint.
- OCI route allows only `/v2/` distribution paths.
- Rate limit returns `429` and emits a redacted event.
- SSRF-blocked upstreams return `403` and emit `egress_denied`.
- Response header stripping removes provider identity headers.
- Streaming responses do not buffer entire bodies.

### Runtime Lifecycle

- `create_env` with brokered OpenAI does not place `OPENAI_API_KEY` value in
  `SandboxSpec.env`.
- `create_env` with brokered MCP does not write `Authorization` into agent MCP
  config.
- Broker start failure prevents sandbox creation.
- Sandbox creation failure stops the broker.
- Destroy stops broker and removes proxy state.
- Freeze and snapshot do not contain credential values or broker temp files.

### Driver And Protocol

- Sandbox capability defaults to false for older JSON.
- OpenShell, Remote SSH, and microVM report false until they implement a verified
  sandbox-reachable host proxy path.
- Driver protocol docs and exported schemas include the additive capability.

### Verification Commands

Before PR:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Rollout Notes

This PR changes the security posture for brokered service credentials but preserves
legacy behavior for unknown credentials and explicit passthrough inference. Reference
blueprints are updated so OpenAI, Anthropic, and MCP examples exercise brokered routes
by default.

The architecture document is updated to replace the old M1-4 statement that
credentials are injected as sandbox env vars with the new rule:

- Brokerable service credentials stay on the host and are injected at egress.
- Non-brokered credentials remain explicit sandbox env injections until each service
  gains a broker route.
