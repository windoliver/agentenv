# agentenv Driver Protocol (v1.3 draft)

> JSON-RPC 2.0 over stdio. LSP-style framing. One contract for built-in Rust drivers and subprocess drivers in any language.

## Status

**Draft.** This document is the north star; the actual schemas live in the `agentenv-proto` crate with `serde` types and auto-generated JSON Schema. When in doubt, the crate wins.

## Wire format

- JSON-RPC 2.0 over stdio
- Messages framed LSP-style:

  ```text
  Content-Length: <N>\r\n
  \r\n
  <JSON payload of length N>
  ```

- `stderr` is treated as driver-side logs and captured into the core event stream with driver provenance tags. Drivers should emit structured JSON lines on stderr when possible (the core tolerates plain text).

## Lifecycle

```text
spawn ──▶ initialize ──▶ <one or more method calls and notifications> ──▶ shutdown ──▶ exit
                                        │
                                        ▼
                              kind-specific methods
```

## Driver manifest

Every subprocess driver ships with a `manifest.json` at the root of its install directory:

```json
{
  "schema_version": "1.3",
  "name": "microvm",
  "kind": "sandbox",
  "version": "0.1.0",
  "description": "MicroVM sandbox backend driver",
  "binary": "./bin/agentenv-driver-microvm",
  "args": [],
  "env": {},
  "capabilities_preview": {
    "supports_hot_reload_policy": false,
    "supports_filesystem_lockdown": true,
    "supports_syscall_filter": true,
    "supports_native_inference_routing": false,
    "supports_remote_host": false,
    "supports_host_egress_proxy": false,
    "supports_persistent_sessions": false,
    "supports_dns_egress_control": false,
    "supports_snapshots": true,
    "supports_fork": true
  }
}
```

Installed to `~/.agentenv/drivers/<name>/manifest.json`. The core discovers it at startup and consults the manifest for the binary path and pre-declared capabilities (for fast listing without spawning every driver). The authoritative capability set is still what `initialize` returns.

## Core → Driver requests

### `initialize` (required, first)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "schema_version": "1.3",
    "core_version": "0.1.0",
    "workdir": "/home/alice/.agentenv/runs/myapp-01HXY",
    "log_level": "info"
  }
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "driver": {
      "name": "openshell",
      "kind": "sandbox",
      "version": "0.1.0",
      "protocol_version": "1.3"
    },
    "capabilities": {
      "supports_hot_reload_policy": true,
      "supports_filesystem_lockdown": true,
      "supports_syscall_filter": true,
      "supports_native_inference_routing": true,
      "supports_remote_host": true,
      "supports_host_egress_proxy": false,
      "supports_persistent_sessions": true,
      "supports_dns_egress_control": false,
      "supports_snapshots": false,
      "supports_fork": false
    }
  }
}
```

If `schema_version` incompatible, driver responds with a JSON-RPC error and exits. Core surfaces actionable guidance.

### `preflight`

Check host-side prerequisites for this driver (runtime installed, version matches, etc).

```json
{"method": "preflight", "params": {}}
→ {"result": {"ok": true, "issues": []}}
→ {"result": {"ok": false, "issues": [
    {"severity": "error", "code": "openshell_missing",
     "message": "OpenShell binary not found",
     "remediation": "curl ... | sh"}
  ]}}
```

### Kind-specific methods

Each driver kind (`sandbox` / `agent` / `context` / `inference`) has its own set. The shape is sketched below; the authoritative types live in `agentenv-proto`.

#### `SandboxDriver`

| Method | Params | Result |
|---|---|---|
| `create` | `SandboxSpec` | `SandboxHandle` |
| `connect` | `{handle}` | `ShellHandle` (session info) |
| `create_session` | `CreateSessionParams` | `SessionHandle` |
| `attach_session` | `AttachSessionParams` | `ExecResult` |
| `list_sessions` | `ListSessionsParams` | `ListSessionsResult` |
| `kill_session` | `KillSessionParams` | `{}` |
| `exec` | `{handle, cmd, tty, env}` | `ExecResult` |
| `copy_in` | `{handle, src_host_path, dst_sandbox_path}` | `{}` |
| `copy_out` | `{handle, src_sandbox_path, dst_host_path}` | `{}` |
| `apply_policy` | `{handle, policy: NetworkPolicy}` | `{hot_reloaded: bool}` |
| `status` | `{handle}` | `SandboxStatus` |
| `logs` | `{handle, since, follow: false}` | `[LogEntry]` |
| `logs_stream` | `{handle, since}` | streamed via notifications |
| `snapshot` | `SnapshotParams {handle, name?}` | `SnapshotId` |
| `fork_from_snapshot` | `ForkFromSnapshotParams {snapshot, spec}` | `SandboxHandle` |
| `stop` | `{handle}` | `{}` |
| `destroy` | `{handle}` | `{}` |

Sandbox capabilities:

| Capability | Type | Meaning |
|---|---|---|
| `supports_hot_reload_policy` | bool | Driver can apply supported policy changes without recreating the sandbox. |
| `supports_filesystem_lockdown` | bool | Driver can enforce filesystem read-only/read-write restrictions. |
| `supports_syscall_filter` | bool | Driver can enforce process syscall restrictions. |
| `supports_native_inference_routing` | bool | Driver has native support for routing inference calls without an in-sandbox proxy. |
| `supports_remote_host` | bool | Driver can connect to a sandbox hosted outside the local machine. |
| `supports_host_egress_proxy` | bool | Driver can reach a host-owned local proxy endpoint from the sandbox and accepts proxy endpoint metadata/env rewrites. |
| `supports_persistent_sessions` | bool | Driver can provide durable attach, detach, resume, and per-session kill semantics. |
| `supports_dns_egress_control` | bool | Driver can enforce DNS resolver allowlists, DNS bypass blocking, and DNS answer pinning. |
| `supports_snapshots` | bool | Driver can snapshot a sandbox into an opaque driver-owned snapshot id. |
| `supports_fork` | bool | Driver can create a sandbox from a previously produced snapshot. |

Schema `1.3` adds the `supports_host_egress_proxy` sandbox capability. If
`supports_host_egress_proxy` is false, core must not route credentials through
the host egress broker for that sandbox. Core either uses legacy env injection
for explicitly permitted credentials or fails closed when policy requires
brokered egress.

Schema `1.2` adds DNS egress control to `NetworkPolicy.network.dns`.
Sandbox drivers that advertise `supports_dns_egress_control = true` must
enforce resolver allowlists, block direct DNS/DoT/DoH bypass paths, and honor
DNS answer pinning when `pin_resolved_ips` is enabled. Drivers that cannot
enforce these controls must return `supports_dns_egress_control = false`; core
rejects active DNS policy before create/apply for those drivers.

Snapshot and fork are optional sandbox capabilities in schema 1.2. Core checks
`supports_snapshots` before `snapshot` and `supports_fork` before
`fork_from_snapshot`; drivers that cannot support them return
`CapabilityMissing`. `SnapshotId.id` is an opaque driver-owned string. `ForkSpec`
carries the target env name plus driver-specific metadata overrides such as a
Firecracker tap or SSH target; credentials still never flow over generic driver
RPC.

Image hardening profiles are create-time sandbox configuration in schema 1.1.
Core resolves `sandbox.hardening`, merges supported filesystem settings into
`SandboxSpec.policy`, and sends process, runtime, and image settings through
`SandboxSpec.metadata` keys prefixed with `hardening_`. Sandbox drivers may
consume that metadata during `create`; schema 1.1 does not define a separate
`apply_hardening` method.

Persistent sessions are optional. Core checks `supports_persistent_sessions`
before calling session methods. Drivers that cannot provide durable attach,
detach, resume, and single-session kill semantics return `CapabilityMissing`
for these methods.

#### `AgentDriver`

| Method | Params | Result |
|---|---|---|
| `install_steps` | `AgentSpec` | `[DockerfileFragment]` |
| `mcp_config_path` | `{}` | `{path: string}` |
| `render_mcp_config` | `{endpoints: [MCPEndpoint]}` | `{content: string}` |
| `render_entrypoint` | `AgentSpec` | `{content: string}` |
| `credential_requirements` | `AgentSpec` | `[CredentialRequirement]` |
| `health_check_probe` | `AgentSpec` | `AgentHealthCheckProbe` |

Agent-specific credential params are exported as `agent-credential-requirements-params.json`.
The shared `credential-requirements-params.json` schema remains the empty params object used by context and inference drivers.
Agent health checks are declarative probes exported as `agent-health-check-probe.json`; v0.2 does not expose a driver-owned `health_check({handle})` request/response schema.

#### `ContextDriver`

| Method | Params | Result |
|---|---|---|
| `provision` | `ContextSpec` | `ContextHandle` |
| `mcp_endpoint` | `{handle}` | `MCPEndpoint` |
| `required_network_rules` | `{handle}` | `[NetworkRule]` |
| `credential_requirements` | `{}` | `[CredentialRequirement]` |
| `status` | `{handle}` | `ContextStatus` |
| `teardown` | `{handle}` | `{}` |

For subprocess context drivers, the core sends the same method names over
JSON-RPC. Credentials are declared through `credential_requirements` and are not
included in generic method params. Driver-specific launchers receive credentials
only through their process environment when the lifecycle layer injects them.

For built-in context drivers, an empty `McpEndpoint.url` with `transport = stdio` is
the no-context sentinel and should be skipped when rendering agent MCP config.
Filesystem context endpoints encode the stdio command in `McpEndpoint.url` until a
future protocol version splits stdio command and arguments into separate fields.

Core may rewrite an `McpEndpoint` for guard mediation before passing it to an
agent driver. This is not a driver protocol change; context drivers continue to
report the unmediated endpoint they provision.

#### `InferenceDriver`

| Method | Params | Result |
|---|---|---|
| `provision` | `InferenceSpec` | `InferenceHandle` |
| `endpoint_in_sandbox` | `{handle}` | `{url: string}` |
| `credential_requirements` | `{}` | `[CredentialRequirement]` |
| `teardown` | `{handle}` | `{}` |

### `shutdown` (required, last)

Graceful shutdown. The driver should flush any buffered events, tear down in-flight resources it owns, and exit.

```json
{"method": "shutdown", "params": {}}
→ {"result": {}}
```

The core gives the driver a grace period (default 5s) then sends SIGTERM, then SIGKILL.

## Driver → Core notifications

Push-only messages (no `id`). Drivers use these for events, logs, and approval requests.

### `event/log`

```json
{
  "jsonrpc": "2.0",
  "method": "event/log",
  "params": {
    "level": "info",
    "ts": "2026-04-16T14:22:00Z",
    "msg": "policy applied (hot reload)",
    "kv": {"handle": "sb-01HXY", "rule_count": 42}
  }
}
```

### `event/activity`

Structured activity events for the activity log, audit log, metrics, and TUI.
Schema `1.1` accepts both the legacy flat params shape and the rich params
shape. The legacy `ActivityEventParams` shape remains valid for compatibility:

```json
{
  "jsonrpc": "2.0",
  "method": "event/activity",
  "params": {
    "kind": "egress_denied",
    "subject": "api.example.com:443",
    "reason": "not in policy",
    "ts": "2026-04-16T14:22:00Z",
    "handle": "sb-01HXY"
  }
}
```

Rich `DriverActivityEventParams` include typed kind/result fields plus structured
actor, subject, and extras maps:

```json
{
  "jsonrpc": "2.0",
  "method": "event/activity",
  "params": {
    "ts": "2026-04-16T14:22:00Z",
    "kind": "sandbox_create",
    "env": "myapp",
    "actor": {"driver": "openshell"},
    "subject": {"handle": "sb-01HXY"},
    "result": "ok",
    "latency_ms": 42,
    "trace_id": "trace-01HXY",
    "reason_code": "created",
    "extras": {"phase": "create"}
  }
}
```

### `event/approval_requested`

Approval `kind` values include `egress_host`, `mcp_tool`, `zone_access`, and
`package_install`.

```json
{
  "jsonrpc": "2.0",
  "method": "event/approval_requested",
  "params": {
    "request_id": "req_01HXYZ",
    "kind": "egress_host",
    "subject": "api.stripe.com:443",
    "reason": "agent fetch_url tool call",
    "context": {"url": "https://api.stripe.com/v1/charges"},
    "default_ttl": "session"
  }
}
```

Core resolves the request (via TUI, webhook, or CLI) and replies via:

### `approval/decision` (core → driver)

The core sends `approval/decision` as a JSON-RPC notification, not a request.
It has no `id`, and drivers must not send a JSON-RPC response for it. The
original driver request that caused the approval remains pending: the driver
emits `event/approval_requested`, waits for this decision notification, then
continues or fails the original request and sends that original response.

```json
{
  "jsonrpc": "2.0",
  "method": "approval/decision",
  "params": {
    "request_id": "req_01HXYZ",
    "decision": "allow",
    "scope": "session",
    "decided_by": "alice",
    "decided_at": "2026-04-16T14:22:08Z"
  }
}
```

## Errors

JSON-RPC error codes (reserved ranges follow JSON-RPC 2.0):

| Code | Meaning |
|---|---|
| `-32700` | Parse error |
| `-32600` | Invalid request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |
| `-32000` | `CapabilityMissing` — requested operation needs a capability the driver doesn't have |
| `-32001` | `PreflightFailed` |
| `-32002` | `SchemaVersionIncompatible` |
| `-32003` | `ResourceNotFound` (bad handle) |
| `-32004` | `CredentialMissing` |
| `-32005` | `PolicyTranslationFailed` |

Errors include `data` with machine-readable context when relevant (e.g., which capability was missing, which credential name).

## Versioning

- **Schema version** (`schema_version` in `initialize`) uses semver-ish `major.minor`. Breaking changes bump major; additive changes bump minor.
- **Driver version** is the driver's own versioning; independent of schema version.
- **Core version** is agentenv's version.
- Core refuses to run a driver whose `schema_version` major doesn't match its own.
- The `1.0` schema broke the old flat `NetworkPolicy` / `NetworkRule` wire shape. Drivers must speak the four-domain policy object with `network`, `filesystem`, `process`, and `inference`, and `approval_required` replaces the old `approval` field.
- The `1.1` schema adds rich driver activity notifications. Drivers may continue sending the legacy `event/activity` shape while adopting structured `actor`, `subject`, `result`, `trace_id`, and `extras` fields.
- The `1.2` schema adds DNS egress policy fields, the `supports_dns_egress_control` sandbox capability, and optional sandbox `snapshot` / `fork_from_snapshot` methods gated by `supports_snapshots` and `supports_fork`.
- The `1.3` schema adds the `supports_host_egress_proxy` sandbox capability for host-brokered egress.

## Built-in drivers

Built-in Rust drivers implement the `Driver` trait family directly — no subprocess, no JSON serialization. They are bound through the same `agentenv-proto` types (serde structs), so the trait method signature is identical to the RPC method signature.

```rust
#[async_trait]
pub trait SandboxDriver: Send + Sync {
    async fn initialize(&mut self, p: InitializeParams) -> Result<InitializeResult>;
    async fn preflight(&self) -> Result<PreflightResult>;
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxHandle>;
    async fn connect(&self, handle: &SandboxHandle) -> Result<ShellHandle>;
    // ...
}
```

The subprocess plugin host implements the same trait, marshalling calls to JSON-RPC and awaiting responses. This means **the rest of the core never knows whether a driver is built-in or subprocess.**

## Security

- Drivers run as the invoking user by default. No setuid behavior from the core.
- Stdin/stdout are the only trusted channels. Anything on stderr is logs (may be structured, may be noise).
- Credentials are injected into driver processes as environment variables at spawn time, never written to disk, never sent over the RPC channel after spawn.
- A driver that crashes does not take down the core; it's restarted once, then marked degraded.
