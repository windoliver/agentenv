# M4-1 Design: Core CLI And Lifecycle

- Date: 2026-04-21
- Issue: https://github.com/windoliver/agentenv/issues/14
- Milestone: M4 CLI and lifecycle
- Affected crates: `agentenv`, `agentenv-core`, `agentenv-events`, `agentenv-credstore`, `agentenv-policy`, built-in driver crates, `agentenv-proto` for reused types only

## 1. Context And Goals

Issue #14 adds the CLI surface that turns a resolved blueprint into a usable agent environment:
`create`, `enter`, `list`, `destroy`, `describe`, `status`, `logs`, and `exec`.

The repo already has the foundation this slice should build on:

1. `agentenv-core` can resolve, verify, freeze, and reproduce blueprints.
2. `agentenv-proto` defines the driver contract for preflight, create, connect, exec, status, logs, and teardown.
3. Built-in sandbox, agent, context, and inference drivers implement the relevant traits.
4. `agentenv-credstore` stores and resolves secrets without exposing values through display or debug output.
5. `agentenv-policy` composes tier and preset policy into the core `NetworkPolicy` wire type.

The goal is a full M4-1 implementation over the existing built-in driver path. The CLI should be useful end to end without introducing a second orchestration protocol or bypassing the driver traits.

## 2. Scope And Non-Goals

### In scope

1. Add top-level commands:
   - `agentenv create <name> [--blueprint <path>] [--reproduce <lockfile>] [--preflight-only] [--json] [--non-interactive]`
   - `agentenv enter <name> [--detach]`
   - `agentenv list [--json]`
   - `agentenv destroy <name> [--yes] [--purge-credentials]`
   - `agentenv describe <name> [--json]`
   - `agentenv status <name> [--json]`
   - `agentenv logs <name> [--follow] [--driver <kind>]`
   - `agentenv exec <name> -- <cmd> [<args>...]`
2. Persist env registry state under `~/.agentenv/envs/<name>/`.
3. Run selected driver preflights before create and expose machine-readable preflight results.
4. Resolve credential requirements and inject credential values only into sandbox creation environment.
5. Compose policy from blueprint tier, presets, overrides, and driver-required network rules.
6. Provision context and inference before sandbox creation when selected.
7. Expose `create --preflight-only --json` for coordinator admission checks without creating resources.
8. Render agent MCP config and entrypoint artifacts into sandbox metadata and copied files where driver support exists.
9. Persist non-secret driver handles and health state in `state.json`.
10. Append progress and lifecycle records to `events.jsonl`.
11. Support text output and stable `--json` output for machine consumers.
12. Provide stable reason codes and exit classes for terminal versus retryable failures.
13. Cover all four reference blueprints through unit or gated integration tests.

### Out of scope

1. Changing the driver protocol schema.
2. Adding a new serialization format.
3. Implementing a subprocess JSON-RPC transport beyond the existing discovery foundation.
4. Implementing M4-3 session resume as a full persistent session manager.
5. Implementing M6 audit UI, metrics, approval webhooks, or long-running operator TUI.
6. Adding post-MVP sandbox drivers such as Docker, E2B, or Firecracker.

`enter --detach` should create and persist a session handle when the selected sandbox driver can represent one. Full attach, detach, and resume semantics remain M4-3, but M4-1 must not fake success when a driver cannot support the requested behavior.

## 3. Architecture

Add a durable lifecycle layer to `agentenv-core`. The binary crate remains CLI glue.

`agentenv-core` owns:

1. env registry paths and state file schema.
2. env name validation and registry locking.
3. state transitions for create, destroy, status, logs, and exec.
4. driver selection and built-in driver instantiation.
5. preflight aggregation.
6. credential requirement aggregation without credential value rendering.
7. policy composition and driver-required network-rule merging.
8. stable data models for list, describe, status, preflight, and admission results.

`agentenv` owns:

1. clap command definitions and help text.
2. interactive prompts and `--yes` confirmation.
3. spinnered human progress for `create`.
4. `--json` rendering.
5. non-interactive behavior and progress events on stderr.
6. exit-code mapping.
7. terminal attachment for `enter` and `logs --follow`.

Driver protocol methods remain the narrow waist. The core should call built-in driver trait implementations directly in this slice. Future subprocess adapters can implement the same traits without changing CLI behavior.

## 4. Env Registry And State

The canonical state layout is:

```text
~/.agentenv/
  config.yaml
  envs/
    <name>/
      blueprint.yaml
      lock.yaml
      state.json
      events.jsonl
  drivers/
  credentials.json
```

`create` writes into a temporary sibling directory first, then atomically renames it to `envs/<name>` after the minimum viable state is present. If a driver operation fails after resources have been created, the temp directory is kept with enough state for cleanup and the error is marked retryable where appropriate.

`state.json` is versioned and contains no secrets:

```json
{
  "version": "0.1.0",
  "name": "myapp",
  "phase": "running",
  "created_at": "2026-04-21T12:34:56Z",
  "updated_at": "2026-04-21T12:35:10Z",
  "drivers": {
    "sandbox": {"name": "openshell", "version": "0.0.1-alpha0"},
    "agent": {"name": "codex", "version": "0.0.1-alpha0"},
    "context": {"name": "filesystem", "version": "0.0.1-alpha0"},
    "inference": {"name": "passthrough", "version": "0.0.1-alpha0"}
  },
  "handles": {
    "sandbox": "sb-01HXY",
    "context": "filesystem:/workspace",
    "inference": "passthrough"
  },
  "endpoints": {
    "context_mcp": {"transport": "stdio", "url": "..."},
    "inference": "http://inference.local"
  },
  "credential_names": ["OPENAI_API_KEY"],
  "health": {},
  "first_enter_hint_shown": false
}
```

Exact field names may be adjusted during implementation, but the invariant is strict: state may include names, backends, handles, endpoints, and health summaries, never credential values.

`events.jsonl` is append-only. Events should include lifecycle steps, progress, preflight results, admission decisions, command failures, and fallback log records. Driver logs remain the primary source for `agentenv logs`; `events.jsonl` is the fallback when driver logs are unavailable.

## 5. Create Flow

`agentenv create <name>` executes these steps:

1. Validate the env name and ensure `envs/<name>` does not already exist.
2. Resolve input:
   - `--blueprint <path>` reads that blueprint.
   - no explicit blueprint reads `agentenv.yaml` in the current directory.
   - `--reproduce <lockfile>` pins driver versions and blueprint hash from that lockfile.
3. Resolve and verify the blueprint through existing lifecycle code.
4. Discover drivers and instantiate the built-in driver implementations selected by the resolved blueprint.
5. Initialize each driver with current schema and core version.
6. Run every selected driver's `preflight`.
7. If any preflight has severity `error`, reject create before resources are created.
8. Collect credential requirements from agent, context, and inference drivers.
9. Resolve credentials from env vars or credstore:
   - interactive mode may prompt and store values through `agentenv-credstore`.
   - non-interactive mode requires existing credstore entries or environment variables.
10. Compose policy from blueprint tier, presets, overrides, and context-required network rules.
11. Provision context and inference drivers.
12. Render MCP config and entrypoint through the selected agent driver.
13. Create the sandbox with policy, metadata, and credential environment injection.
14. Persist `blueprint.yaml`, `lock.yaml`, `state.json`, and `events.jsonl`.
15. Print a ready summary with `enter`, `status`, and `logs` next steps.

The current M1-3 lockfile records driver pins, artifact digests, credential references, and the blueprint hash; it does not embed the full resolved blueprint. Therefore `create --reproduce <lockfile>` must also find the blueprint content before materializing resources. M4-1 should use this order:

1. explicit `--blueprint <path>` when provided.
2. a companion blueprint path next to the lockfile, using `<stem>.blueprint.yaml` or `<stem>.yaml` when the hash matches.
3. `agentenv.yaml` in the current directory when its hash matches the lockfile.

If none match, fail before driver initialization with reason code `reproduce_blueprint_missing`. M4-2 can later improve the freeze/reproduce artifact shape without changing the M4-1 command behavior.

The human output should use numbered, spinnered steps. Non-interactive progress should be stable JSON lines on stderr so shell and HTTP adapters do not parse prose.

`create --json` returns an admission-style object:

```json
{
  "status": "accepted",
  "reason_code": "created",
  "env": "myapp",
  "state_path": "/home/alice/.agentenv/envs/myapp/state.json",
  "next_steps": ["agentenv enter myapp", "agentenv status myapp"]
}
```

Rejections use `status: "rejected"` and a stable `reason_code`, such as `invalid_blueprint`, `preflight_failed`, `missing_credential`, `env_exists`, or `capability_missing`. `queued` is reserved for future remote or asynchronous create flows and should not be emitted by local built-in M4-1 unless there is an actual queued operation.

`create --preflight-only --json` stops after blueprint verification, driver initialization, preflight execution, and credential requirement discovery. It emits per-check results and an admission status without provisioning context, inference, or sandbox resources:

```json
{
  "status": "rejected",
  "reason_code": "preflight_failed",
  "env": "myapp",
  "checks": [
    {
      "driver": "openshell",
      "kind": "sandbox",
      "ok": false,
      "issues": [
        {
          "severity": "error",
          "code": "openshell_missing",
          "message": "OpenShell binary not found",
          "remediation": "Install OpenShell before creating an env."
        }
      ]
    }
  ]
}
```

## 6. Command Behavior

### `enter`

`agentenv enter <name>` loads state and calls the sandbox driver's `connect` with the persisted sandbox handle. It then attaches the user's terminal when the driver returns an attachable shell/session. The first successful enter prints a one-shot hint such as `run <agent> to start`, then sets `first_enter_hint_shown = true`. The hint is suppressed when `AGENTENV_NO_ENTER_HINT=1`.

`enter --detach` creates the session without attaching stdio when supported. If the driver cannot support detached sessions, the command fails with a capability reason code.

### `list`

`agentenv list` scans `~/.agentenv/envs/`, reads each valid `state.json`, and prints columns:

```text
NAME  AGENT  SANDBOX  CONTEXT  INFERENCE  STATUS  AGE
```

Invalid or partially written env directories are skipped in text mode with a warning on stderr. JSON mode includes a `warnings` array so automation can detect registry inconsistencies.

### `destroy`

`agentenv destroy <name>` prompts for confirmation unless `--yes` is passed. It tears down resources in reverse ownership order:

1. sandbox stop/destroy.
2. context teardown.
3. inference teardown.
4. registry directory removal.

Credentials are preserved by default. `--purge-credentials` removes credentials only if they are scoped to this env in state; shared global credentials are not deleted unless the state can prove ownership. If cleanup fails, state is preserved with phase `error` or `destroying` and a retryable reason code.

### `describe`

`agentenv describe <name>` prints stable sections:

1. env metadata.
2. blueprint and lockfile hashes.
3. drivers, versions, and capabilities when known.
4. handles.
5. policy summary.
6. credential names and backends only.
7. last known health.

`describe --json` serializes the same model and must remain parseable without scraping the text format.

### `status`

`agentenv status <name>` calls status methods for sandbox and context drivers when handles exist. Inference health is reported from provisioned endpoint state unless the selected inference driver exposes a stronger health surface later.

The command exits non-zero when any driver is unhealthy. Text mode prints a compact per-driver summary; JSON mode includes stable fields for `healthy`, `phase`, and `reason_code`.

### `logs`

`agentenv logs <name>` reads sandbox driver logs through `logs`. `--driver sandbox` filters to sandbox driver logs. Other driver filters may use `events.jsonl` until those drivers expose log streams.

`logs --follow` uses the streaming path and should not block non-following logs. The CLI remains attached until interrupted and should leave env state intact when interrupted.

### `exec`

`agentenv exec <name> -- <cmd> [<args>...]` reconstructs the command after `--`, calls sandbox `exec`, writes child stdout/stderr through to the local stdout/stderr, and exits with the command's exit status. CLI-level failures use agentenv exit codes instead of the child status.

## 7. Non-Interactive Mode

Non-interactive mode is enabled by `--non-interactive` or `AGENTENV_NON_INTERACTIVE=1`.

Rules:

1. No prompts.
2. Destructive operations require `--yes`.
3. Missing credentials fail with `missing_credential`.
4. Progress events are emitted as stable JSON lines on stderr.
5. Human spinners are disabled.
6. `create --json` emits only the final admission object on stdout.

This gives shell and HTTP adapters deterministic surfaces and avoids brittle parsing.

## 8. Exit Codes And Reason Codes

Add a small CLI exit classifier. Exact numeric values should be documented in CLI help or README once implemented.

Recommended classes:

1. `0`: success.
2. `1`: generic failure for unexpected internal errors.
3. `2`: usage or bad input.
4. `10`: terminal lifecycle failure, such as invalid blueprint or unsupported capability.
5. `11`: preflight failed.
6. `12`: missing credential.
7. `20`: retryable driver or cleanup failure.
8. `30`: unhealthy status.

Reason codes are stable snake_case strings. Initial codes:

1. `created`
2. `destroyed`
3. `invalid_blueprint`
4. `env_exists`
5. `env_not_found`
6. `preflight_failed`
7. `missing_credential`
8. `capability_missing`
9. `driver_unhealthy`
10. `driver_command_failed`
11. `cleanup_failed`
12. `non_interactive_prompt_required`
13. `reproduce_blueprint_missing`

## 9. Security And Privacy

The implementation must maintain the existing security boundaries:

1. Credential values never appear in `state.json`, `lock.yaml`, `events.jsonl`, stderr, stdout, command argv, or debug output.
2. Drivers receive credential values only through create-time environment injection.
3. Blueprint URL validation still flows through the SSRF module.
4. Blueprints and lockfiles remain digest-verified through existing lifecycle functions.
5. `describe` and `list` expose credential names and backends only.
6. Any path written under `~/.agentenv/envs/<name>/` must be derived from a validated env name.

## 10. Driver Support And Degradation

M4-1 should support the current built-in drivers first:

1. OpenShell sandbox for create, connect, exec, status, logs, stop, and destroy.
2. Agent drivers for install steps, MCP config, entrypoint, credential requirements, and health probes.
3. Context drivers for provision, MCP endpoint, network rules, credential requirements, status, and teardown.
4. Inference drivers for provision, endpoint, credential requirements, and teardown.

Capability checks must happen before dependent operations. Examples:

1. If an agent does not support MCP, create fails before sandbox creation when a context endpoint is selected.
2. If a sandbox cannot hot-reload policy, create can still apply locked create-time policy but runtime updates should report recreate-required later.
3. If detached enter is unsupported, `enter --detach` fails with `capability_missing`.

## 11. Testing Strategy

Use TDD for implementation.

### Core tests

1. env name validation rejects traversal and empty names.
2. registry paths resolve under a configurable root.
3. create writes `blueprint.yaml`, `lock.yaml`, `state.json`, and `events.jsonl`.
4. create rejects duplicate env names.
5. preflight errors reject before sandbox creation.
6. missing credentials fail in non-interactive mode.
7. state serialization excludes credential values.
8. describe model excludes secrets and includes driver versions.
9. list skips invalid env directories with warnings.
10. destroy preserves state on retryable cleanup failure.
11. status aggregates unhealthy driver results.
12. logs fallback reads `events.jsonl` when driver logs are unavailable.

### CLI tests

1. help includes all M4 verbs.
2. `create --json` returns parseable admission JSON.
3. `list --json` returns parseable env rows.
4. `describe --json` returns parseable detail without secrets.
5. `status` exits non-zero for unhealthy state.
6. `exec` forwards arguments after `--` and propagates child exit status.
7. `destroy --yes` removes the env directory after successful teardown.
8. destructive commands fail in non-interactive mode without `--yes`.
9. preflight JSON output is parseable with per-check results.
10. stable reason codes appear for common failures.

### Gated integration tests

Behind `AGENTENV_RUN_OPEN_SHELL_TESTS`, run create, status, exec, logs, enter where possible, and destroy for all four reference blueprints:

1. `blueprints/claude+filesystem+openshell.yaml`
2. `blueprints/codex+mcp-generic+openshell.yaml`
3. `blueprints/openclaw+nexus+openshell.yaml`
4. `blueprints/hermes+nexus+openshell.yaml`

The acceptance target is `create -> enter -> destroy` round-trip where the selected external dependencies are available, with deterministic skips when an external runtime or service is absent.

## 12. Implementation Notes

The implementation plan should split work into small checkpoints:

1. registry/state model and path safety.
2. CLI command definitions and help tests.
3. built-in driver factory.
4. preflight/admission models.
5. create orchestration without TTY attach.
6. list and describe.
7. status, logs, and exec.
8. destroy and cleanup retries.
9. interactive and non-interactive credential handling.
10. OpenShell-gated reference blueprint coverage.

The largest risk is blending CLI rendering with lifecycle logic. Keep orchestration in `agentenv-core` and pass typed result models to the binary crate for rendering. This preserves the future path for a TUI, HTTP adapter, or subprocess driver adapter without reimplementing lifecycle semantics.
