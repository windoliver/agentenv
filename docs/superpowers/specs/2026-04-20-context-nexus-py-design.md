# M3-2 Context Nexus Python Driver Design

Date: 2026-04-20
Issue: [#12](https://github.com/windoliver/agentenv/issues/12)
Milestone: M3 - Subprocess plugin host and polyglot drivers

## Summary

Implement the first external context driver, `context-nexus-py`, as a Python
subprocess driver for the Nexus context backend. The driver ships in
`external-drivers/context-nexus-py/`, installs into
`~/.agentenv/drivers/context-nexus/` with an isolated virtual environment, and
is discoverable as the `nexus` context driver through the manifest discovery
foundation from M3-1.

The current `origin/main` includes manifest discovery and `agentenv drivers
list`, but it does not include the full subprocess JSON-RPC transport or trait
adapter. This design therefore includes the smallest core subprocess host slice
needed for issue #12: a manifest-backed JSON-RPC stdio client and a
`ContextDriver` adapter. It intentionally does not finish subprocess adapters
for sandbox, agent, or inference drivers.

## Affected Crates and Paths

- `crates/agentenv-plugin`
- `crates/agentenv-core`
- `crates/agentenv`
- `tests/driver-conformance`
- `external-drivers/context-nexus-py`
- `install.sh`
- `tests/install/test_install.sh`
- `docs/DRIVER_PROTOCOL.md`
- `blueprints/openclaw+nexus+openshell.yaml`
- `blueprints/hermes+nexus+openshell.yaml`

`crates/agentenv-proto` should not need a schema-version bump. The existing
`ContextDriver` method surface already contains the methods needed by the Nexus
driver.

## External Nexus Reference Points

Nexus exposes MCP through its CLI with commands shaped as:

```text
nexus mcp serve --transport stdio
nexus mcp serve --transport http --port 8081
NEXUS_URL=http://localhost:2026 NEXUS_API_KEY=... nexus mcp serve --transport stdio
```

The public Nexus docs also describe local mode through `NEXUS_DATA_DIR` and
remote mode through `NEXUS_URL` and `NEXUS_API_KEY`. The agentenv blueprint
uses `hub_url` and `NEXUS_TOKEN`; the Python driver maps these into Nexus'
environment names when starting local MCP HTTP processes or probing hub mode.

## Design Goals

1. Preserve the narrow waist: MCP remains the agent-to-context protocol and
   JSON-RPC remains the core-to-driver protocol.
2. Keep credentials out of generic RPC payloads. The driver declares
   `NEXUS_TOKEN`; runtime credential injection remains an environment concern.
3. Make `agentenv drivers list` show `nexus (context, subprocess)` through a
   real manifest.
4. Make the Python driver pass the existing subprocess conformance suite plus
   context-driver method checks.
5. Keep the core subprocess host slice reusable, but only implement the context
   adapter required by #12.
6. Degrade cleanly when Nexus itself is not installed: preflight reports a
   structured issue instead of failing driver discovery or binary installs.

## Blueprint Shape

The driver consumes the existing untyped `ContextSpec.config` map. The accepted
configuration is:

```yaml
context:
  driver: nexus
  mode: hub                   # hub | lite
  hub_url: ${NEXUS_HUB_URL}   # required in hub mode
  zones: [eng, ops]           # optional zone filter
  credentials:
    NEXUS_TOKEN:
      source: env
```

For direct RPC calls, the same fields appear under `ContextSpec.config`:

```json
{
  "mode": "hub",
  "hub_url": "https://nexus.company.com",
  "zones": ["eng", "ops"]
}
```

Defaults:

- `mode` defaults to `lite`.
- `zones` defaults to an empty list.
- lite mode uses a data directory under the driver work directory unless
  `data_dir` is supplied.
- lite mode binds the MCP HTTP server to `127.0.0.1` on an available port unless
  `mcp_port` is supplied.

## Core Subprocess Host Slice

### Manifest Usage

The discovery foundation already parses:

- `name`
- `kind`
- `version`
- `binary`
- `args`
- `env`
- `capabilities_preview`

The new host code will reuse `DiscoveredDriver` as its spawn source. It will
construct a subprocess command from `binary`, `args`, and the manifest `env`.
The spawned process receives a minimal base environment plus explicit manifest
env values. Credentials are not sourced from manifest env and are not passed as
JSON-RPC params.

### JSON-RPC Transport

Add a production transport implementation for JSON-RPC 2.0 over stdio with
LSP-style framing:

```text
Content-Length: <N>\r\n
\r\n
<JSON payload>
```

Responsibilities:

- spawn subprocesses with stdin/stdout piped
- write request frames
- read response and notification frames
- assign monotonically increasing request IDs
- enforce per-request timeout defaults
- surface JSON-RPC errors as `DriverError` values
- send `shutdown` and wait before killing the child on drop or explicit close

The first implementation can serialize calls through one async mutex. The issue
requires correctness before parallel request routing; full parallel routing can
remain an M3-1 follow-up if not needed by #12 tests.

### Context Adapter

Add `SubprocessContextDriver` implementing `agentenv_core::driver::ContextDriver`.
Each trait method maps one-to-one to the driver protocol:

| Trait method | JSON-RPC method |
| --- | --- |
| `initialize` | `initialize` |
| `preflight` | `preflight` |
| `provision` | `provision` |
| `mcp_endpoint` | `mcp_endpoint` |
| `required_network_rules` | `required_network_rules` |
| `credential_requirements` | `credential_requirements` |
| `status` | `status` |
| `teardown` | `teardown` |
| `shutdown` | `shutdown` |

The adapter validates that `initialize` reports `DriverKind::Context` and
`Capabilities::Context`. A kind mismatch is an invalid-driver error.

### CLI Wiring

The current CLI only lists drivers. This issue does not need full
`agentenv create`, but it should add enough plumbing for tests and operators to
exercise the external driver:

```text
agentenv drivers list
```

continues to show the installed manifest. If a small smoke command is needed,
prefer a hidden or test-only helper over committing a user-facing lifecycle verb
ahead of M4.

## Python Driver Package

### Layout

```text
external-drivers/context-nexus-py/
├── pyproject.toml
├── README.md
├── manifest.json.in
├── scripts/
│   ├── install-driver.sh
│   └── build-bundle.sh
├── src/
│   └── agentenv_context_nexus/
│       ├── __init__.py
│       ├── __main__.py
│       ├── driver.py
│       ├── jsonrpc.py
│       ├── nexus.py
│       └── protocol.py
└── tests/
    ├── test_driver_methods.py
    ├── test_jsonrpc.py
    └── fixtures/
        └── fake_nexus.py
```

### Dependencies

Use only standard-library modules for the JSON-RPC server and process
management. The package may declare an optional dependency on the Nexus CLI
package for installation, but default tests should not require a live Nexus
service or network access.

If packaging needs a project dependency, prefer the published Nexus Python
package that provides the `nexus` CLI. Do not add Python, Node, or any other
runtime as a build-time dependency of the Rust core.

### Driver Metadata

`initialize` returns:

```json
{
  "driver": {
    "name": "nexus",
    "kind": "context",
    "version": "0.1.0",
    "protocol_version": "1.0"
  },
  "capabilities": {
    "is_remote": true,
    "is_shared": true,
    "supports_zones": true,
    "supports_snapshots": true
  }
}
```

The capability values describe the driver's full capability set. Per-handle
status can still report whether a particular handle is hub or lite.

### Preflight

`preflight` checks:

1. the Python runtime is compatible with the package
2. the `nexus` CLI is available in the venv
3. `nexus --version` exits successfully when available

If Nexus is missing, preflight returns `ok: false` with a remediation that
points to installing the package into the driver venv. Discovery and
`agentenv drivers list` still work because they do not spawn or preflight the
driver.

### Provision

`provision` validates the `ContextSpec.config` map and returns a
`ContextHandle`.

Hub mode:

- requires `hub_url`
- validates that it is `http` or `https`
- stores handle state with `mode`, `hub_url`, and `zones`
- does not require the token value in the RPC payload
- returns a deterministic handle such as `nexus-hub-<hash>`

Lite mode:

- creates a per-handle data directory
- starts `nexus mcp serve --transport http --host 127.0.0.1 --port <port>`
- sets `NEXUS_DATA_DIR` for the child process
- stores the child PID, URL, data directory, and zones in handle state
- returns a handle such as `nexus-lite-<uuid>`

The driver owns lite-mode MCP server teardown. Hub mode owns no remote resource.

### MCP Endpoint

`mcp_endpoint` returns an `McpEndpoint`:

Hub mode:

- URL is derived from `hub_url`
- transport is `http`
- headers are empty because credentials are injected by the runtime layer, not
  serialized in endpoint metadata

Lite mode:

- URL is the local MCP HTTP URL started by `provision`
- transport is `http`
- headers are empty

If future Nexus hub deployments expose a distinct MCP path, the driver should
accept `mcp_url` as an explicit override without changing the protocol schema.

### Required Network Rules

`required_network_rules` returns:

- hub mode: one host rule for `hub_url`
- lite mode: no outbound network rules

The rule uses `NetworkTarget::Host` with parsed host, port, and scheme. Invalid
URLs are rejected during `provision` so this method is deterministic.

### Credential Requirements

`credential_requirements` returns one requirement:

```json
{
  "name": "NEXUS_TOKEN",
  "description": "Nexus hub API token",
  "kind": "token",
  "required": false
}
```

The requirement is optional at method level because lite mode does not need it.
Core blueprint credential validation can still require `NEXUS_TOKEN` when the
blueprint declares it.

### Status and Teardown

`status` returns:

- healthy hub handle if the handle exists and `hub_url` was valid
- healthy lite handle if the MCP process is still running
- unhealthy lite handle with detail if the process exited

`teardown`:

- terminates the lite-mode MCP process and waits for exit
- removes in-memory handle state
- no-ops for hub mode after removing handle state

`shutdown` tears down all lite handles before exiting.

## Packaging and Install

The Python driver install path is:

```text
~/.agentenv/drivers/context-nexus/
├── manifest.json
├── bin/
│   └── agentenv-driver-nexus
├── venv/
└── wheels/
```

`external-drivers/context-nexus-py/scripts/install-driver.sh`:

1. resolves the install root from `AGENTENV_HOME` or `~/.agentenv`
2. creates a staged driver directory
3. creates `venv` with `python3 -m venv`
4. installs the built wheel into the venv
5. writes a launcher script in `bin/agentenv-driver-nexus`
6. writes `manifest.json`
7. atomically replaces `~/.agentenv/drivers/context-nexus/`

The manifest installed to disk uses:

```json
{
  "schema_version": "1.0",
  "name": "nexus",
  "kind": "context",
  "version": "0.1.0",
  "description": "Nexus context backend driver",
  "binary": "./bin/agentenv-driver-nexus",
  "args": [],
  "env": {},
  "capabilities_preview": {
    "is_remote": true,
    "is_shared": true,
    "supports_zones": true,
    "supports_snapshots": true
  }
}
```

The repo-level `install.sh` currently installs Python driver bundles from a
published index. For this issue, keep that path working and add a local bundle
format produced by `build-bundle.sh`. The top-level installer should not require
Python unless Python drivers are explicitly requested or a bundle index is
available.

## Tests

### Rust Tests

Add tests for:

1. JSON-RPC framing read/write in production host code.
2. subprocess context adapter maps every `ContextDriver` method to the expected
   JSON-RPC method and params.
3. initialize rejects non-context drivers.
4. JSON-RPC errors become driver errors with method context.
5. shutdown is sent and the child exits.
6. discovered `nexus` manifest can instantiate a subprocess context driver.
7. `agentenv drivers list` shows the installed `nexus` manifest as context and
   installed/override source.

### Python Tests

Add tests for:

1. JSON-RPC server handles LSP frames and unknown methods.
2. initialize reports context capabilities.
3. schema mismatch returns the protocol error code.
4. credential requirements declares `NEXUS_TOKEN`.
5. hub provision validates missing and malformed `hub_url`.
6. hub required network rules parse host, scheme, and port.
7. lite provision starts a fake Nexus CLI fixture and returns an HTTP endpoint.
8. teardown terminates the fake process.

### Conformance

Extend `tests/driver-conformance` with context-driver subprocess checks:

1. run standard initialize/preflight/shutdown suite
2. call `credential_requirements`
3. provision a hub-mode config with a local fake URL
4. assert `mcp_endpoint`, `required_network_rules`, `status`, and `teardown`

### Gated E2E

The issue acceptance criterion mentions `agentenv create` and Claude calling
Nexus MCP tools. M4 lifecycle commands are not present in the current CLI, and
real Nexus hub availability cannot be assumed in CI. The implementation should
therefore include:

- a deterministic fake Nexus CLI fixture for default CI
- an ignored or environment-gated test for real Nexus lite mode
- documentation of the manual command needed to verify end-to-end once M4
  lifecycle exists

## Error Handling

Use `thiserror` in Rust libraries and `anyhow` in binaries. Python JSON-RPC
errors use protocol codes from `agentenv-proto`:

- `-32601` for unknown method
- `-32602` for invalid params
- `-32603` for internal errors
- `-32002` for incompatible schema version
- `-32003` for missing handles
- `-32004` for missing credentials when a future credential-injected path
  requires them

Every user-facing error should include the method or config field involved.

## Security

- Credentials are never included in JSON-RPC params, logs, manifests, command
  argv, or MCP endpoint headers.
- The manifest env is static driver configuration only.
- Hub URLs are parsed and validated before network rules are emitted.
- Lite-mode child processes inherit only the venv PATH and the Nexus-specific
  environment needed to run.
- Bundle installation uses a staged directory and atomic replacement to avoid
  partially installed drivers.

## Out of Scope

- Full subprocess adapters for sandbox, agent, and inference drivers.
- Restart-once degraded-state handling for long-lived driver crashes.
- `agentenv drivers install` and `agentenv drivers remove`.
- Full `agentenv create` lifecycle integration, because the current CLI does
  not expose create/enter/list/destroy yet.
- Nexus server-side ReBAC, hub hardening, or lightweight-profile changes.

## Open Follow-Ups

1. Finish the rest of M3-1 after #12 by generalizing the context subprocess
   adapter to all driver kinds.
2. Wire subprocess driver execution into `agentenv create` when M4 lifecycle
   commands land.
3. Add first-class `mcp_url` and `data_dir` blueprint schema fields if repeated
   Nexus deployments need them.
4. Replace fake Nexus e2e coverage with real fixture-data MCP search once the
   Nexus lightweight profile is stable in CI.
