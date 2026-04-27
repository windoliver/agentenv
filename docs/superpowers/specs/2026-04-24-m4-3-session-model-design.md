# M4-3 Session Model Design

## Context

Issue [#16](https://github.com/windoliver/agentenv/issues/16) separates long-lived sandboxes from attachable sessions. A sandbox is the durable resource created by `agentenv create` and destroyed by `agentenv destroy`. A session is a live shell or agent TUI attached to that sandbox, and it may detach, resume, or be killed without destroying the sandbox.

This belongs to M4 and builds on the M4-1 CLI lifecycle. The current runtime has a foreground `enter` path implemented as a sandbox `exec` of the agent entrypoint, and a detached `enter --detach` path implemented as a sandbox `connect` call. There is no persisted `sessions.json`, no `resume` command, no `sessions` command group, and sandbox capabilities do not declare persistent session support.

## Goals

- Add a first-class session protocol surface to `SandboxDriver`.
- Persist per-environment session metadata in `~/.agentenv/envs/<name>/sessions.json`.
- Support `enter`, `enter --detach`, `enter --new`, `resume`, `sessions list`, and `sessions kill`.
- Keep session mechanics driver-owned so core does not assume tmux, screen, dtach, or a platform-specific backend.
- Fail clearly when a sandbox driver does not support persistent sessions.
- Make sandbox destroy cleanly terminate known sessions.

## Non-Goals

- Do not introduce a second agent/context protocol.
- Do not make core own tmux or terminal multiplexer behavior.
- Do not implement a separate orchestrator-style controller.
- Do not add runtime dependencies to the core binary.

## Protocol

`agentenv-proto` will add `supports_persistent_sessions` to `SandboxCapabilities` and bump the protocol minor version from `1.0` to `1.1`. This is an additive change, so the major version remains `1`.

New sandbox RPC types:

- `CreateSessionParams { handle, name, command, detached, metadata }`
- `AttachSessionParams { handle, session_id }`
- `KillSessionParams { handle, session_id }`
- `ListSessionsParams { handle }`
- `SessionHandle { session_id, name, status, created_at, updated_at, command, working_dir }`
- `ListSessionsResult { sessions }`
- `SessionStatus { starting, attached, detached, exited, killed, unknown }`

New `SandboxDriver` methods:

- `create_session(CreateSessionParams) -> SessionHandle`
- `attach_session(AttachSessionParams) -> ExecResult`
- `list_sessions(ListSessionsParams) -> ListSessionsResult`
- `kill_session(KillSessionParams) -> EmptyResult`

Drivers that return `supports_persistent_sessions: false` must not be called for these operations by core. If a caller requests a session operation anyway, core returns `CapabilityMissing { capability: "supports_persistent_sessions" }` with CLI rendering that explains the driver only supports foreground `enter`.

## Core Metadata

Core owns env-local session metadata in `sessions.json`. This file is separate from `state.json` because sessions are volatile lifecycle records while `state.json` describes the env and driver handles.

Shape:

```json
{
  "version": "0.1.0",
  "env": "demo",
  "default_session_id": "01HXY...",
  "sessions": [
    {
      "id": "01HXY...",
      "driver_session_id": "01HXY...",
      "name": "demo",
      "status": "detached",
      "command": "/sandbox/.agentenv/bin/agentenv-agent",
      "created_at": "2026-04-24T17:00:00Z",
      "updated_at": "2026-04-24T17:05:00Z"
    }
  ]
}
```

Core reconciles persisted metadata with `SandboxDriver::list_sessions` when listing or resuming. Driver state wins for status, but core preserves user-visible names and default-session selection.

## CLI Behavior

`agentenv enter <env>`:

- If a live default session exists, attach it.
- If no live default exists, create a new attached default session running the agent entrypoint.
- For drivers without persistent sessions, preserve the existing foreground-only `exec` behavior.

`agentenv enter <env> --detach`:

- Requires `supports_persistent_sessions`.
- Creates the default session if none exists and leaves it detached.
- Prints the session ID.

`agentenv enter <env> --new`:

- Requires `supports_persistent_sessions`.
- Always creates a new session.
- If combined with `--detach`, starts it detached and prints the session ID.
- Without `--detach`, creates and attaches it.

`agentenv resume <env> [session-id]`:

- Requires `supports_persistent_sessions`.
- Uses `session-id` when provided.
- Without `session-id`, resumes the default detached session.
- Errors clearly if no resumable session exists.

`agentenv sessions list [<env>]`:

- Lists sessions for one env or all envs.
- Shows env, session ID, name, status, command, and updated time.
- Supports `--json`.

`agentenv sessions kill <session-id>`:

- Finds the owning env by scanning session metadata.
- Calls the sandbox driver's `kill_session`.
- Marks the session as `killed` in metadata.

`agentenv destroy <env>`:

- Lists known sessions for the env.
- Best-effort kills them before destroying the sandbox.
- Sandbox destroy remains the final cleanup authority.

## OpenShell Driver

OpenShell is the first built-in sandbox driver to declare `supports_persistent_sessions: true` when the driver can create durable sessions. The implementation uses host-side `tmux` to wrap `openshell sandbox exec --tty`, because the default OpenShell sandbox image does not ship an in-sandbox multiplexer. The core still does not know which backend is used.

The driver-level contract is:

- `create_session` starts the agent command in a durable backend and returns a stable session ID.
- `attach_session` attaches stdio to that existing backend.
- `list_sessions` reports backend-observed status.
- `kill_session` terminates only that session.

If OpenShell cannot find a usable host-side `tmux`, it returns `CapabilityMissing { capability: "supports_persistent_sessions" }`. Foreground `enter` remains available through `exec`.

## Error Handling

- Missing sandbox handle remains `MissingSandboxHandle`.
- Unsupported persistent sessions are capability errors, not generic command failures.
- Unknown session IDs return `InvalidHandle`.
- Stale metadata is reconciled into `exited` or `unknown` instead of crashing list operations.
- `SIGHUP` and detach-key handling are delegated to the driver backend. The CLI should not translate `SIGHUP` into a kill operation.

## Testing

Unit tests will cover:

- proto serialization and schema generation for session types.
- core `sessions.json` round-trip and metadata reconciliation.
- `enter --detach` creates and persists a session.
- `enter --new` creates multiple sessions.
- `resume` reattaches the default or requested session.
- unsupported drivers return `CapabilityMissing`.
- `destroy` attempts session cleanup before sandbox destroy.
- CLI command parsing and stable JSON/text output for session commands.

OpenShell driver tests will use the existing command-runner test harness to assert command construction and capability behavior without requiring a real OpenShell installation. Real OpenShell end-to-end coverage stays behind `AGENTENV_RUN_OPEN_SHELL_TESTS`.

## Affected Crates

- `crates/agentenv-proto`
- `crates/agentenv-core`
- `crates/agentenv`
- `crates/drivers/sandbox-openshell`
- `tests/driver-conformance`

## Trade-Offs

This design is larger than putting session state in the core, but it preserves the driver boundary while still working with OpenShell's default sandbox image. It also creates a protocol bump, but only an additive minor bump. The fallback path for unsupported drivers keeps current foreground `enter` behavior working while making detached and resumable behavior explicit.
