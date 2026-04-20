# M2-3 Built-In Context Drivers Design

Date: 2026-04-20
Issue: [#9](https://github.com/windoliver/agentenv/issues/9)
Milestone: M2 - Built-in drivers
Status: Draft for review

## Summary

Implement the full built-in context-driver issue scope in one pass: `context-none`,
`context-mcp-generic`, `context-filesystem`, and the embedded filesystem MCP server
binary. The implementation will make the three built-in `ContextDriver` crates real,
extend shared conformance coverage for context drivers, validate outbound MCP URLs
through the existing SSRF helpers, and ship a small `agentenv-fs-mcp` stdio server
that exposes `fs_read`, `fs_grep`, `fs_list`, and `fs_search` against a configured
mount.

The design keeps MCP as the only agent-to-context protocol and keeps JSON-RPC driver
traits as the core-to-driver contract. It does not add a new pluggable axis or a new
serialization format.

## Context And Constraints

- `docs/ARCHITECTURE.md` defines `ContextDriver` as the knowledge-backend axis. It
  provisions context, exposes an `MCPEndpoint`, declares network rules and credential
  requirements, and reports capabilities.
- `docs/DRIVER_PROTOCOL.md` already defines the `ContextDriver` method surface:
  `provision`, `mcp_endpoint`, `required_network_rules`, `credential_requirements`,
  `status`, and `teardown`.
- The current context crates are M1 scaffolds, while the registry and reference
  blueprints already recognize `filesystem`, `mcp-generic`, and `none`.
- `agentenv-mcp` already has SSRF-aware MCP endpoint validation for HTTP-like
  transports.
- There is no M4 create lifecycle yet that can install sidecars inside a sandbox. The
  filesystem MCP binary must therefore be directly testable as a crate binary and
  returned as an endpoint plan by the driver, while final sandbox materialization can
  use it later.
- Credentials must not flow through generic driver RPC. Drivers may declare credential
  names and header templates, but they must not store or expose credential values.

## Affected Crates And Docs

- `crates/agentenv-core`
- `crates/agentenv-mcp`
- `crates/drivers/context-none`
- `crates/drivers/context-mcp-generic`
- `crates/drivers/context-filesystem`
- `tests/driver-conformance`
- `docs/DRIVER_PROTOCOL.md`
- `blueprints/claude+filesystem+openshell.yaml`
- `blueprints/codex+mcp-generic+openshell.yaml`

`agentenv-proto` is not expected to need a schema-version bump because the existing
context-driver method signatures are sufficient. If implementation finds that MCP
stdio arguments cannot be represented safely in the current `McpEndpoint`, the
preferred fallback is to encode the command and arguments as a single stdio command
string for the current schema and document the limitation rather than changing the
protocol during this issue.

## Goals

- Implement honest context capabilities for all three built-in context drivers.
- Make `context-none` compose cleanly with no external MCP configuration.
- Make `context-mcp-generic` validate and expose external MCP HTTP/SSE endpoints.
- Make `context-filesystem` validate filesystem config and expose a local stdio MCP
  endpoint backed by a shipped Rust binary.
- Implement the filesystem MCP server tools required by issue #9.
- Add shared context-driver conformance checks and crate-level behavior tests.
- Preserve the security model: SSRF checks for outbound URLs, path containment for
  filesystem access, no credential values in handles or endpoints.

## Non-Goals

- Implementing the full M4 `agentenv create` orchestration pipeline.
- Adding a second context protocol besides MCP.
- Adding a second serialization format besides JSON-RPC/JSON for protocol and YAML
  for blueprints.
- Implementing remote filesystem sharing, context zones, or snapshots.
- Supporting writes through the filesystem MCP server. The issue only requires grep,
  read, list, and search tools; `readonly` is still parsed and preserved so future
  write tools can use it.

## Architecture

### 1. Shared Context Helpers

Add `agentenv-core::context_common` for small, deterministic helpers shared by the
three built-in context crates. It should own:

- context `InitializeResult` builders
- successful preflight and empty result helpers
- context capability constructors
- opaque handle construction and validation helpers backed by per-driver in-memory
  state maps
- small config parsing helpers for strings, booleans, string arrays, and nested maps
- filesystem mount normalization and path expansion for `~`
- endpoint host-to-network-rule conversion for `mcp-generic`

This mirrors the recent inference-driver shape and keeps per-driver crates thin.
Driver crates should still own behavior-specific structs, public driver types, and
tests.

### 2. `context-none`

`context-none` is a true no-op driver for agents that run without external context.

Behavior:

- Driver name: `none`.
- Capabilities: `is_remote = false`, `is_shared = false`, `supports_zones = false`,
  `supports_snapshots = false`.
- `preflight` succeeds without host checks.
- `provision` accepts an empty config and returns a stable `none|` handle.
- `mcp_endpoint` rejects invalid handles and otherwise returns an empty `stdio`
  endpoint as the protocol-compatible "no MCP config" sentinel.
- `required_network_rules` and `credential_requirements` return empty lists.
- `status` reports healthy with a short no-context detail.
- `teardown` and `shutdown` are no-ops.

The downstream lifecycle should treat an empty endpoint URL as "do not render an MCP
server entry." That filtering belongs in future orchestration or agent config assembly
instead of in this driver issue.

### 3. `context-mcp-generic`

`context-mcp-generic` points at an external MCP endpoint and does not own the
upstream service.

Supported blueprint shape:

```yaml
context:
  driver: mcp-generic
  endpoint:
    url: https://mcp.internal.company.com
    transport: http+sse
  credentials:
    MCP_TOKEN:
      source: env
```

Driver config comes through `ContextSpec.config` as:

- `endpoint.url`: required string
- `endpoint.transport`: required string, one of `http`, `http+sse`, or `ssh+http`

Credential declarations in the blueprint already live outside `ContextSpec.config`,
and the context credential method is intentionally config-independent in the current
driver protocol. The driver therefore declares a conventional optional `MCP_TOKEN`
credential requirement by name only. Blueprints remain the source of truth for whether
that token is required for a specific endpoint.

Security and behavior:

- `provision` parses the endpoint, validates it with `agentenv-mcp::validate_mcp_endpoint`,
  probes the endpoint with an MCP `initialize` request for `http` and `http+sse`
  transports, and returns an opaque handle.
- URL validation uses SSRF defaults with `allow_ssh_http = true` for MCP transports,
  matching blueprint verification.
- `mcp_endpoint` returns the stored endpoint for a valid handle.
- `required_network_rules` returns one `NetworkRule::Host` for the endpoint host,
  preserving scheme and port when present.
- Capabilities: `is_remote = true`, `is_shared = true`, `supports_zones = false`,
  `supports_snapshots = false`.
- `status` reports healthy after config validation succeeds.

The endpoint probe is implemented as a small crate-local helper using `reqwest` over
`rustls`. Unit tests should run it against a mock HTTP server built with `tokio` TCP
listeners so no external service is required. `ssh+http` is validated for URL safety
but not live-probed in this issue because it requires an SSH transport adapter that is
not part of M2-3.

### 4. `context-filesystem`

`context-filesystem` mounts a host directory and exposes it through a local stdio MCP
server.

Supported blueprint shape:

```yaml
context:
  driver: filesystem
  mount: ~/projects/myapp
  readonly: false
  exclude:
    - ".git/"
    - "node_modules/"
```

Driver config comes through `ContextSpec.config` as:

- `mount`: required string
- `readonly`: optional boolean, default `true`
- `exclude`: optional array of non-empty strings

Behavior:

- `provision` expands `~`, canonicalizes existing mounts when possible, rejects empty
  mounts, rejects non-directory mounts, stores the resolved config in the driver's
  in-memory state map, and returns an opaque filesystem handle.
- `mcp_endpoint` returns a `stdio` endpoint command invoking `agentenv-fs-mcp` with
  `--root`, `--readonly`, and repeated `--exclude` flags encoded in a single command
  string for the current `McpEndpoint` schema.
- `required_network_rules` returns no network rules.
- `credential_requirements` returns no credentials.
- Capabilities: `is_remote = false`, `is_shared = false`, `supports_zones = false`,
  `supports_snapshots = false`.
- `status` reports healthy when the mount still exists and is a directory.
- `teardown` and `shutdown` are no-ops because the stdio MCP process is owned by the
  agent runtime that launches it.

`readonly` is parsed, encoded in the endpoint command, and enforced by the server by
not exposing write tools. Because the initial tool set is read-only, `readonly: false`
does not create write access in this issue.

### 5. Filesystem MCP Server Binary

Add a binary target named `agentenv-fs-mcp` in the `context-filesystem` crate. It
speaks MCP over stdio using JSON-RPC framing compatible with MCP-style requests.

CLI flags:

```text
agentenv-fs-mcp --root <path> [--readonly] [--exclude <pattern>]...
```

Server methods:

- `initialize`
- `tools/list`
- `tools/call`

Tools:

- `fs_read`
  - input: `path`
  - output: UTF-8 file content
  - rejects directories, binary content, excluded paths, and paths outside root
- `fs_list`
  - input: optional `path`, optional `recursive`
  - output: sorted relative paths
  - skips excluded entries
- `fs_search`
  - input: `query`, optional `path`, optional `limit`
  - output: sorted relative paths whose filenames contain `query`
  - skips excluded entries
- `fs_grep`
  - input: `pattern`, optional `path`, optional `limit`
  - output: matches with relative path, 1-based line number, and line text
  - skips excluded entries and binary/unreadable files

Path rules:

- All tool paths are interpreted as relative to `--root`.
- Absolute paths are rejected.
- `.` is allowed and means the root.
- `..` traversal is rejected before any filesystem access.
- Symlinks are resolved; resolved paths must remain under the root.
- Exclude patterns are path-prefix style for entries ending in `/` and substring or
  exact segment style for other simple patterns. This is intentionally smaller than
  gitignore syntax and should be documented as such.

Limits:

- `fs_read` should cap returned content to a conservative size, for example 1 MiB.
- `fs_list`, `fs_search`, and `fs_grep` should honor `limit` with a default and a
  maximum to prevent unbounded output.
- The server should return structured JSON-RPC errors for invalid input and access
  denial, not panic.

This binary can live in `src/bin/agentenv-fs-mcp.rs` with reusable logic in
`context-filesystem/src/lib.rs` or sibling modules. The binary should use `tracing`
for diagnostics and avoid `println!` outside protocol stdout writes.

## Error Handling

Use `thiserror` in library code and map errors to `DriverError` at driver boundaries.

Driver errors should be specific for:

- missing required config keys
- config keys with the wrong type
- unsupported MCP transport strings
- blocked SSRF endpoint URLs
- invalid or stale handles
- mount paths that are empty, nonexistent, or not directories
- invalid excludes

Filesystem MCP server errors should distinguish:

- invalid params
- path outside root
- excluded path
- file too large
- unsupported binary content
- tool not found
- method not found

No `.unwrap()` should appear outside tests.

## Credential Handling

`context-none` and `context-filesystem` declare no credentials.

`context-mcp-generic` must not receive credential values through `ContextSpec`. The
normal blueprint credential references remain owned by core credential collection and
future sandbox injection. Endpoint headers are out of scope for this issue because the
current driver protocol has no safe path for credential values. Handles and status
strings must not include credential names, credential values, or endpoint query strings.

## Testing Strategy

Follow TDD for behavior changes.

### 1. Shared context conformance

Extend `tests/driver-conformance` with `assert_context_driver_contract`. It should
exercise:

- `initialize` reports `DriverKind::Context`
- capabilities use `Capabilities::Context`
- `preflight` succeeds
- `provision` returns a non-empty handle for valid specs
- `mcp_endpoint` accepts that handle
- `required_network_rules` and `credential_requirements` do not contain empty names or
  malformed host rules
- `status` reports healthy
- `teardown` succeeds

Each built-in context crate should have a test that passes this contract.

### 2. Driver unit tests

`context-none` tests:

- initializes with no-context capabilities
- provisions and returns the no-context sentinel endpoint
- rejects invalid handles
- returns no network rules and no credentials

`context-mcp-generic` tests:

- parses `http` and `http+sse` endpoint config
- rejects malformed, unsupported, and SSRF-blocked URLs
- connects to a mock MCP HTTP endpoint and accepts a valid initialize response
- reports a failed probe when the mock endpoint returns a non-MCP response
- returns remote/shared capabilities
- returns a network allow rule for the endpoint host
- declares optional `MCP_TOKEN` without storing a value
- never includes credential values or endpoint query strings in handles

`context-filesystem` tests:

- parses mount, readonly, and excludes
- rejects missing mount and non-directory mount
- returns local non-shared capabilities
- returns a stdio endpoint command for `agentenv-fs-mcp`
- returns no network rules and no credentials
- status detects when the mount disappears

### 3. Filesystem MCP server tests

Use temp directories and direct server handler functions rather than shelling out for
every case.

Tests should cover:

- `tools/list` advertises exactly `fs_read`, `fs_grep`, `fs_list`, and `fs_search`
- `fs_read` reads UTF-8 files under root
- `fs_read` rejects traversal, absolute paths, directories, binary files, excluded
  paths, and oversized files
- `fs_list` returns sorted relative paths and skips excluded directories
- `fs_search` finds filenames and respects limits
- `fs_grep` returns line-numbered matches and respects limits
- symlinks escaping the root are rejected
- JSON-RPC unknown methods and unknown tools return protocol errors

### 4. Integration smoke tests

Add a binary smoke test that starts `agentenv-fs-mcp` with a temp root, sends framed
JSON-RPC requests over stdio, and verifies `initialize`, `tools/list`, and one
`fs_read` call. This proves the stdio transport works without needing a full agent
or sandbox.

### 5. Verification commands

Run:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Acceptance Mapping

- All three drivers pass the protocol conformance suite: covered by shared context
  conformance and per-crate tests.
- `context-filesystem` serves grep/read/list tools against a host-mounted dir: covered
  by filesystem MCP server unit and stdio smoke tests.
- `context-mcp-generic` validates URL, passes SSRF check, and connects to a mock MCP
  server: covered by SSRF validation and MCP initialize probe tests.
- `context-none` composes cleanly and the agent starts without MCP config entries:
  covered by no-context sentinel endpoint and future lifecycle filtering contract.
- Honest capability reporting: covered by driver initialization tests and conformance.

## Trade-Offs

- Implementing the filesystem MCP binary now gives issue #9 real user-facing value,
  but it makes the change larger than the recent inference-driver MVP. The mitigation
  is to keep server logic local to `context-filesystem` and test it independently.
- Encoding stdio command arguments into `McpEndpoint.url` is not ideal, but it avoids a
  protocol change while the current schema only has `url`, `transport`, and `headers`.
  A future protocol revision can split stdio command and args.
- The exclude model is intentionally simpler than gitignore syntax. That keeps the
  server predictable and avoids adding a new pattern language dependency in this
  milestone.
- Live end-to-end testing with Claude in a sandbox depends on M4 lifecycle and agent
  orchestration. This issue will prove the binary and driver contracts locally, then
  leave full create/enter composition to the lifecycle milestone.

## Implementation Order

1. Add shared context-driver conformance tests.
2. Implement `context-none`.
3. Implement `context-mcp-generic` config parsing, SSRF validation, endpoint handling,
   and network rules.
4. Implement `context-filesystem` config parsing, mount validation, endpoint handling,
   and status checks.
5. Implement filesystem MCP server core path policy and tool handlers.
6. Add stdio JSON-RPC smoke coverage for `agentenv-fs-mcp`.
7. Update README/docs and any reference blueprint comments that need clarification.
8. Run formatting, clippy, and full workspace tests.
