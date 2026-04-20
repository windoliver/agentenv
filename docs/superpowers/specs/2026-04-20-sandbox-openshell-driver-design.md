# M2-1 Sandbox OpenShell Driver Design

Date: 2026-04-20
Issue: [#7](https://github.com/windoliver/agentenv/issues/7)
Milestone: M2 - Built-in Drivers

## Summary

Implement the first built-in `SandboxDriver` for OpenShell. The driver stays inside
the existing `crates/drivers/sandbox-openshell` crate, implements the current
`agentenv_core::driver::SandboxDriver` trait, shells out to the `openshell` CLI, and
uses the existing OpenShell policy translator for policy hot reloads.

The implementation covers the full issue scope: initialization, capability
declaration, preflight, create, connect, exec, copy in/out, apply policy, status,
logs, log streaming activation, stop, destroy, credential injection, and gated
end-to-end integration tests.

## Affected Crates

- `crates/drivers/sandbox-openshell`
- `crates/agentenv-core`
- `tests/driver-conformance`

`agentenv-proto` should not need a schema bump for this issue. The existing
`SandboxDriver` method surface already carries the required params and results.

## External CLI References

The OpenShell command mapping follows the current public OpenShell documentation:

- Manage sandboxes: `openshell sandbox create`, `connect`, `get`, `upload`,
  `download`, and `delete`
- Policy hot reload: `openshell policy set <sandbox> --policy <file> --wait`
- Logs: `openshell logs <sandbox>` with `--tail`, `--source`, `--level`, and
  `--since`
- Inference routing: `openshell inference set --provider <provider> --model <model>`
  with optional `--timeout`

Public docs document sandbox deletion but do not show a distinct `sandbox stop`
command. The driver will keep `stop` and `destroy` as separate trait methods:
`destroy` maps to documented deletion, while `stop` maps to `openshell sandbox stop`
and remains covered by gated integration. If the installed OpenShell CLI lacks that
verb, the driver returns an actionable command failure rather than silently deleting
the sandbox.

## Driver Architecture

### `OpenShellDriver`

`OpenShellDriver` is the public built-in driver type. It owns:

- the OpenShell binary path, defaulting to `openshell`
- a minimum supported CLI version, `0.0.30`
- a command runner abstraction for testability
- a temp directory root for policy files
- an in-memory map of handles to the last policy applied through this driver

The driver name reported by `initialize` is `openshell`, kind is `sandbox`, version
comes from `CARGO_PKG_VERSION`, and `protocol_version` is the current
`agentenv-proto` schema version.

Capabilities are declared exactly as issue #7 requires:

- `supports_hot_reload_policy: true`
- `supports_filesystem_lockdown: true`
- `supports_syscall_filter: true`
- `supports_native_inference_routing: true`
- `supports_remote_host: true`

### Command Runner

The crate will introduce a small internal `CommandRunner` trait. Production uses a
`ProcessCommandRunner` backed by `std::process::Command`. Unit tests use a recording
runner that returns scripted `stdout`, `stderr`, and exit statuses.

The runner receives command args and env vars separately. This is important for
credential safety: tests can assert credentials are injected into the process
environment and never serialized into argv, temp files, logs, policy files, or image
paths.

### Handles

OpenShell commands operate on sandbox names. `SandboxHandle.handle` will store the
OpenShell sandbox name.

Create name selection follows this precedence:

1. `spec.metadata["name"]` if it is a non-empty string
2. a generated `agentenv-<uuid>` name

`create` returns that name as the handle. This keeps the protocol stable and avoids
adding an OpenShell-specific handle schema.

## Method Design

### `initialize`

Validate `InitializeParams.schema_version` with
`assert_compatible_schema_version`. Return driver metadata and the required
capabilities.

### `preflight`

Run:

1. `openshell --version`
2. `openshell gateway status`

Preflight returns `ok: false` with structured issues for:

- missing CLI binary
- unparsable CLI version
- CLI version below `0.0.30`
- gateway status failure

The version parser accepts output that contains a semver token, such as
`openshell 0.0.30`.

### `create`

Build:

```text
openshell sandbox create --name <name> --keep --no-auto-providers --from <image>
```

If `SandboxSpec.image` is absent, use `openclaw` as the default community package for
the v0.1 path. This default gives the first driver a usable agent-oriented sandbox
without adding new blueprint schema.

Credential injection uses `SandboxSpec.env` as process environment only. Env keys and
values are not written to the generated policy file. The command runner API keeps env
separate from argv so tests can assert that no credential values enter command-line
arguments.

If `SandboxSpec.policy` is present, `create` applies it after sandbox creation through
the same internal policy path used by `apply_policy`, then stores it as the current
policy for the handle.

Remote host support is capability-only in this issue. If `spec.metadata["remote"]` is a
string, the driver appends `--remote <value>` to create commands. Other remote
configuration remains out of scope until the blueprint schema has first-class remote
host fields.

### `connect`

Return a `ShellHandle` after checking the sandbox is reachable with:

```text
openshell sandbox connect <handle> -- true
```

The shell handle contains:

- `session_id: <handle>`
- `tty: true`
- `working_dir: Some("/sandbox")`

Actual interactive attachment remains a later CLI concern. The built-in driver method
must prove that a connect target exists and return enough session information for core
lifecycle code.

### `exec`

Run non-interactive commands with:

```text
openshell sandbox connect <handle> -- <cmd>
```

`ExecParams.env` is injected into the process environment. `ExecResult.status` is the
child exit code or `1` when the process exits without an exit status. `stdout` and
`stderr` are passed through as UTF-8 lossily decoded strings.

The first implementation treats `ExecParams.cmd` as a shell command and passes it as
one post-`--` argument. That matches the current protocol, which exposes `cmd` as a
single string rather than an argv vector.

### `copy_in` and `copy_out`

Map to documented OpenShell transfer commands:

```text
openshell sandbox upload <handle> <src_host_path> <dst_sandbox_path>
openshell sandbox download <handle> <src_sandbox_path> <dst_host_path>
```

Both return `EmptyResult` on success and a driver error with stdout/stderr context on
failure.

### `apply_policy`

Policy application uses the existing `translate_for_openshell` path:

1. Compare the incoming policy with the stored current policy for the handle.
2. If filesystem or process domains changed, return the existing recreate-required
   policy error rather than invoking OpenShell.
3. Translate the full policy to OpenShell YAML.
4. Write the YAML to a host temp file with restrictive permissions.
5. Run:

   ```text
   openshell policy set <handle> --policy <temp-file> --wait
   ```

6. If translation includes an inference update, also run:

   ```text
   openshell inference set --provider <provider> --model <model> [--timeout <seconds>]
   ```

7. Store the policy as the current policy and return
   `ApplyPolicyResult { hot_reloaded: true }`.

The temp policy file is removed after the command returns. Policy files contain only
translated policy, never credentials.

### `status`

Run:

```text
openshell sandbox get <handle>
```

The initial parser maps a successful command to `SandboxPhase::Running` and
`healthy: true`. If output contains obvious stopped, deleted, or error markers, map to
`Stopped`, `Destroyed`, or `Error`. This keeps status useful without introducing a
second serialization format or depending on undocumented JSON flags.

### `logs`

Run:

```text
openshell logs <handle> [--since <since>] [--tail]
```

For non-following logs, parse each line into a `LogEntry` where possible and preserve
unparsed lines as `LogLevel::Info` messages. Denied egress log lines containing
`DENIED`, `BLOCKED`, or `action=deny` are tagged in `kv` so later event stream work can
promote them into `event/activity` notifications.

### `logs_stream`

Start `openshell logs <handle> --tail [--since <since>]` through the command runner and
return `EmptyResult` once spawning succeeds. Streaming notification fan-out is limited
by the current in-process trait, which has no callback sink. The implementation should
therefore establish the command path and keep the method non-panicking; richer event
delivery belongs with the events subsystem work.

### `stop`

Run:

```text
openshell sandbox stop <handle>
```

If the installed CLI reports that `stop` is unknown, return the command failure with a
message that the installed OpenShell version does not expose a non-destructive stop
verb.

### `destroy`

Run:

```text
openshell sandbox delete <handle>
```

On success, remove the handle from the in-memory current-policy map.

### `shutdown`

No persistent subprocess is owned by the driver, so shutdown returns `EmptyResult`.

## Error Handling

The existing `DriverError` is currently small. To avoid abusing
`CapabilityMissing`, add variants for:

- preflight failures
- command failures with command, status, stdout, and stderr
- policy translation failures
- invalid driver input

Library code uses `thiserror` and does not print. Command output included in errors is
trimmed to avoid noisy messages.

## Testing Strategy

### Unit Tests

Unit tests in `crates/drivers/sandbox-openshell/src/lib.rs` will cover:

- initialize returns the required capabilities
- preflight missing CLI, bad version, old version, and gateway-down cases
- version parsing from common `openshell --version` output
- create command construction, default image, explicit image, explicit name, generated
  name shape, and env-only credential injection
- create applies an initial policy when provided
- exec, copy, connect, status, logs, stop, and destroy command mapping
- apply policy writes translated YAML, uses `policy set --wait`, removes temp files, and
  applies inference updates
- locked filesystem/process policy changes fail before command execution
- credential values do not appear in argv, policy YAML, or logs produced by the driver

### Conformance

Add `driver_conformance::assert_sandbox_driver_contract` for in-process sandbox drivers.
The OpenShell driver will satisfy it using the recording runner so the conformance
suite does not require OpenShell in CI.

### Gated Integration

Add ignored tests behind the `integration` feature and an environment gate such as
`AGENTENV_RUN_OPENSHELL_INTEGRATION=1`.

The full integration test exercises:

1. `preflight`
2. `create`
3. `exec whoami`
4. `apply_policy` that blocks a `curl` request
5. logs contain a denial
6. `apply_policy` that allows the request
7. `exec curl -s https://api.github.com/zen`
8. `destroy`

Credential safety integration adds a one-shot env var with a unique secret marker,
creates a sandbox, greps expected filesystem/log locations, and asserts the marker is
absent.

The local workspace does not have `openshell` installed, so real integration will be
documented and skipped by default.

## Acceptance Mapping

- OpenShell driver passes protocol conformance: covered by the new sandbox conformance
  helper and unit tests.
- Capability flags are honest: covered by initialize tests and command behavior tests
  for each claimed capability.
- End-to-end against `openshell >= 0.0.30`: covered by gated integration.
- Policy hot reload without restart: covered by `policy set --wait` command mapping and
  gated create/exec/apply/exec integration.
- Credentials are never in image layers or sandbox filesystem: covered by env-only unit
  assertions and gated grep integration.
- Graceful errors for missing CLI, wrong version, and gateway down: covered by
  preflight unit tests.

## Risks and Trade-offs

- The current proto uses string commands rather than argv. The driver therefore sends
  `ExecParams.cmd` as one command string after `--`, which is faithful to the protocol
  but less precise than argv.
- OpenShell public docs do not show a separate non-destructive sandbox stop command.
  The implementation keeps the trait surface intact and lets integration validate the
  installed CLI behavior.
- `status` depends on documented `sandbox get` output rather than an official JSON
  output flag. The parser should be conservative and treat successful unknown output as
  running/healthy.
- Inference routing is gateway-scoped in OpenShell. Applying an inference update from a
  sandbox driver may affect every sandbox on the active gateway. That matches
  OpenShell's model and should be called out in driver docs.
