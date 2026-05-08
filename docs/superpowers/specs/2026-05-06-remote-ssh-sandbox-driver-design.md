# Remote SSH Sandbox Driver Design

## Summary

Issue: https://github.com/windoliver/agentenv/issues/37

Build a first-party `remote-ssh` sandbox driver that treats a pre-provisioned VM as the sandbox. The driver uses host `ssh` and `scp`, implements the existing `SandboxDriver` contract, and does not provision, stop, or power off remote machines.

The driver is a new built-in Rust crate, not an OpenShell extension and not a subprocess plugin. This keeps the implementation aligned with M2 built-in driver work while satisfying the issue's goal of generic SSH to any VM.

## Affected Crates And Files

- Create `crates/drivers/sandbox-remote-ssh`.
- Modify workspace membership in `Cargo.toml`.
- Modify `crates/agentenv/Cargo.toml` to depend on the new built-in driver.
- Modify `crates/agentenv/src/builtin_factory.rs` to resolve `remote-ssh` and `sandbox-remote-ssh`.
- Modify `crates/agentenv-core/src/runtime.rs` so sandbox blueprint extras are passed into `SandboxSpec.metadata` for generic sandbox drivers, while preserving existing OpenShell image metadata behavior.
- Add focused tests in the new crate, `crates/agentenv/src/builtin_factory.rs`, and `crates/agentenv-core/src/runtime.rs`.

## Architecture

`sandbox-remote-ssh` implements `agentenv_core::driver::SandboxDriver` directly. It uses the same testable command-runner shape as `sandbox-openshell`: production code delegates process execution to a small runner abstraction, and unit tests use scripted runners to assert exact argv and error mapping.

The implementation does not change `agentenv-proto` or `docs/DRIVER_PROTOCOL.md`. `SandboxSpec.metadata` is enough for `create`, and the persisted `SandboxHandle.handle` must carry enough non-secret SSH target data for later commands. Runtime operations such as `agentenv exec` and `agentenv enter` rebuild drivers in a fresh process and retain only the handle, so later driver methods must parse the handle rather than depend on in-memory create state.

The handle format is a URI-like string:

```text
remote-ssh://alice@dev-vm-alice.example.com:22?identity_file=/Users/alice/.ssh/id_ed25519&jump_host=bastion.example.com
```

Fields omitted in the blueprint are omitted from the query. `identity_file` paths are not credential values, but they are local host metadata and should not include private key contents. Query values are percent-encoded.

## Blueprint Shape

The supported user-facing config is:

```yaml
sandbox:
  driver: remote-ssh
  host: dev-vm-alice.example.com
  user: alice
  port: 22
  identity_file: ~/.ssh/id_ed25519
  jump_host: bastion.example.com
  enforce_remote_firewall: false
```

Required fields:

- `host`
- `user`

Optional fields:

- `port`, defaulting to `22`
- `identity_file`
- `jump_host`
- `enforce_remote_firewall`, defaulting to `false`

`identity_file` expands only a leading `~/`. Other shell forms are not expanded.

Remote VM prerequisites:

- Reachable through host `ssh`.
- POSIX `sh`, `mkdir`, and `chmod` available on the remote host.
- The remote user can create and write `/sandbox` and `/sandbox/.agentenv`.
- Agent-specific install commands may require additional remote tools, depending on the selected `AgentDriver`.

## Driver Behavior

### `initialize`

Return driver name `remote-ssh`, kind `sandbox`, workspace package version, and current protocol version.

Capabilities:

- `supports_hot_reload_policy: false`
- `supports_filesystem_lockdown: false`
- `supports_syscall_filter: false`
- `supports_native_inference_routing: false`
- `supports_remote_host: true`
- `supports_persistent_sessions: false`

The false capability values are intentional. A pre-provisioned VM can have these controls, but this first driver slice does not own or verify them.

### `preflight`

Check that host commands `ssh` and `scp` are available by running version/help probes that do not require a target VM. `preflight` does not test network connectivity because it does not receive the sandbox spec.

### `create`

Parse and validate metadata from `SandboxSpec.metadata`. Reject `enforce_remote_firewall: true` with `CapabilityMissing("supports_hot_reload_policy")`.

If `identity_file` is set, expand `~/`, verify the path exists and is a regular file, and fail before invoking `ssh` if it is missing or invalid.

Run a connectivity probe:

```text
ssh -o BatchMode=yes -p <port> [-i <identity_file>] [-J <jump_host>] <user>@<host> -- true
```

Then verify the remote workspace contract:

```text
ssh -o BatchMode=yes -p <port> [-i <identity_file>] [-J <jump_host>] <user>@<host> -- sh -lc "mkdir -p /sandbox/.agentenv/bin && test -w /sandbox"
```

Return a URI handle containing the validated target data.

### `connect`

Parse the handle and run the same `ssh ... -- true` probe. Return `ShellHandle` with:

- `session_id`: the handle
- `tty`: `true`
- `working_dir`: `Some("/sandbox")`

### `exec`

For `tty: false`, run:

```text
ssh -o BatchMode=yes -p <port> [-i <identity_file>] [-J <jump_host>] <user>@<host> -- sh -lc "cd /sandbox && <cmd>"
```

Return the remote command status, stdout, and stderr.

For `tty: true`, use the runner's interactive status path with the same argv. Return the exit status and empty stdout/stderr, matching the OpenShell driver's foreground TTY behavior.

### `copy_in`

Use `scp`:

```text
scp -P <port> [-i <identity_file>] [-J <jump_host>] <src_host_path> <user>@<host>:<dst_sandbox_path>
```

### `copy_out`

Use `scp`:

```text
scp -P <port> [-i <identity_file>] [-J <jump_host>] <user>@<host>:<src_sandbox_path> <dst_host_path>
```

### `apply_policy`

Return `CapabilityMissing("supports_hot_reload_policy")`. Remote nftables or ufw policy push is deferred because it needs a separate privilege, rollback, and safety design.

### `status`

Run `ssh ... -- true`. Report `Running` and healthy on exit code `0`; report `Error` and unhealthy on non-zero status. Command spawn failures still return driver errors.

### `logs` And `logs_stream`

Return `CapabilityMissing("remote_logs")`. The generic driver has no remote log source contract in this slice.

### `stop`

Return success without contacting the host. Agentenv does not own VM lifecycle for `remote-ssh`.

### `destroy`

Return success without powering off the host. No remote resource is destroyed.

### Session Methods

Use the default `supports_persistent_sessions` missing behavior from the trait. Persistent remote sessions through tmux or systemd-run are outside this issue slice.

## Validation And Errors

- Missing `metadata.host` or `metadata.user` returns `InvalidInput` naming the field.
- Non-string `host`, `user`, `identity_file`, or `jump_host` returns `InvalidInput`.
- `port` accepts a YAML integer or a numeric string in the TCP range `1..=65535`.
- Non-boolean `enforce_remote_firewall` returns `InvalidInput`.
- Command spawn failures map to `CommandSpawn`.
- Non-zero `ssh` or `scp` exits map to `CommandFailed` with stdout and stderr preserved.
- Invalid handles return `InvalidHandle` with the original handle and a short parse failure reason.
- SSH targets are always built as argv arrays. The driver must not shell-concatenate user, host, file paths, or jump host values.

## Security Notes

Credentials must not flow through generic RPC. The private key contents never enter driver metadata or command strings. The `identity_file` path can be stored in the handle and env state because it is not a credential value, but logs and errors should avoid inventing extra output that echoes it beyond the underlying `ssh`/`scp` command failure message already captured by the normal driver error path.

The driver does not claim filesystem, process, syscall, or network isolation. It composes above whatever isolation the remote VM already enforces. `enforce_remote_firewall` is parsed but rejected so users do not receive a false sense of policy enforcement.

## Testing Plan

Unit tests in `sandbox-remote-ssh`:

- Initialize reports the expected driver identity and conservative capabilities.
- Preflight checks `ssh` and `scp`.
- Config parsing accepts required fields and default port.
- Config parsing accepts integer and string ports.
- Config parsing rejects missing, wrong-typed, and out-of-range fields.
- `identity_file` expands a leading `~/` and rejects missing files before invoking `ssh`.
- `jump_host` emits `-J`.
- `create` runs the expected `ssh ... -- true` probe and returns a parseable URI handle.
- `exec` builds non-TTY and TTY argv correctly and preserves status/stdout/stderr.
- `copy_in` and `copy_out` build expected `scp` argv.
- `apply_policy` returns missing capability.
- `status`, `stop`, `destroy`, `logs`, and invalid handle paths behave as specified.
- Driver conformance passes with scripted preflight commands.

Runtime and factory tests:

- `remote-ssh` and `sandbox-remote-ssh` resolve as sandbox aliases.
- A blueprint with sandbox extras passes `host`, `user`, `port`, `identity_file`, `jump_host`, and `enforce_remote_firewall` into `SandboxSpec.metadata`.
- Existing OpenShell image metadata and BYO Dockerfile behavior remains unchanged.

Ignored integration test:

```text
AGENTENV_RUN_REMOTE_SSH_INTEGRATION=1 \
AGENTENV_REMOTE_SSH_HOST=dev-vm.example.com \
AGENTENV_REMOTE_SSH_USER=alice \
AGENTENV_REMOTE_SSH_IDENTITY_FILE=/Users/alice/.ssh/id_ed25519 \
cargo test -p sandbox-remote-ssh --features integration -- --ignored
```

The flow is:

```text
create -> exec "whoami" -> copy_in -> copy_out -> status -> destroy
```

The integration test must not require root on the remote host.

## Non-Goals

- Provisioning VMs.
- Powering off VMs.
- Driver-specific remote base image or tool provisioning.
- Remote firewall management.
- Persistent remote sessions.
- A new driver protocol method or schema-version bump.

## Acceptance Criteria

- `cargo fmt` passes.
- `cargo clippy -D warnings` passes.
- `cargo test --workspace` passes without requiring a live remote VM.
- `sandbox-remote-ssh` passes the in-process sandbox conformance suite.
- The new driver can be selected from blueprints using `driver: remote-ssh`.
- Policy enforcement is not implied when it is not active.
