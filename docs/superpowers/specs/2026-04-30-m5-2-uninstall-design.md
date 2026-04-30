# M5-2 Design: Uninstall Story

- Date: 2026-04-30
- Issue: https://github.com/windoliver/agentenv/issues/18
- Milestone: M5 packaging, DX, and security
- Affected crates: `agentenv`
- Affected scripts and tests: `uninstall.sh`, `install.sh`, `tests/install/test_install.sh`, `crates/agentenv/tests/cli_behavior.rs`

## 1. Context And Goals

Issue #18 adds a clean, auditable removal path for agentenv:

1. a hosted `uninstall.sh` script that works as a one-line `curl | sh` flow.
2. an `agentenv uninstall` command with the same flags.
3. dry-run planning, confirmation, idempotence, and diagnostics for partial failure.

The installer already establishes the packaging conventions this work should follow:

1. shell scripts are POSIX `sh`.
2. downloads use SHA256 verification.
3. installation avoids `sudo`.
4. shell startup files are edited through a sentinel block and backed up before mutation.
5. `AGENTENV_INSTALLER_SOURCE_ONLY=1` lets installer tests source script functions directly.

The uninstall implementation should follow the same safety posture. It should remove only agentenv-owned artifacts, never delete user project directories, and continue best-effort cleanup when one resource fails.

## 2. Recommended Architecture

Use `uninstall.sh` as the single behavioral source of truth. The Rust CLI should be a delegating entry point, not a second implementation.

This keeps the hosted script and CLI behavior aligned:

1. `curl -LsSf .../uninstall.sh | sh` can remove agentenv without relying on a working installed binary.
2. `agentenv uninstall` can pass flags through to the same script.
3. tests can focus on one planning and removal engine.
4. future release packaging can host `install.sh`, `uninstall.sh`, and checksum files side by side.

The CLI still adds value by discovering the right script:

1. prefer `uninstall.sh` next to the running `agentenv` binary.
2. prefer a repository-local `uninstall.sh` in development builds.
3. fall back to downloading `uninstall.sh` and `uninstall.sh.sha256` from the configured release base URL.

The fallback download must verify SHA256 before execution.

## 3. Scope And Non-Goals

### In scope

1. Create a POSIX `uninstall.sh`.
2. Add `agentenv uninstall` with matching flags:
   - `--yes`, `-y`
   - `--keep-openshell`
   - `--keep-drivers`
   - `--keep-credentials`
   - `--keep-data`
   - `--delete-models`
   - `--dry-run`
3. Print a plan before deleting anything.
4. Confirm unless `--yes` or `--dry-run`.
5. Remove the agentenv binary.
6. Remove installer PATH blocks from `.bashrc`, `.zshrc`, and `.profile`, with backups.
7. Remove `~/.agentenv/` content while honoring keep flags.
8. Use `agentenv destroy --yes` to destroy registered envs through drivers when the binary is available.
9. Continue after individual destroy or delete failures.
10. Write a diagnostic bundle on partial failure.
11. Keep the script idempotent so a second run is a no-op.
12. Verify by tests that project directories outside `~/.agentenv` are never deleted.

### Out of scope

1. Changing the driver protocol.
2. Adding new credential store APIs.
3. Adding an explicit `--delete-openshell` flag in this issue.
4. Removing Docker itself.
5. Removing non-agentenv Docker resources.
6. Removing arbitrary user model directories by default.

Issue #18 lists `--keep-openshell`, but also says OpenShell is preserved by default unless an explicit delete flag is passed. Since the issue does not define a delete flag, this design preserves the OpenShell binary and OpenShell state by default. `--keep-openshell` is accepted and reflected in the plan as an explicit preservation choice.

## 4. Script Behavior

`uninstall.sh` should support two modes:

1. normal execution.
2. source-only mode for tests, using `AGENTENV_UNINSTALLER_SOURCE_ONLY=1`.

The script reads these defaults:

```sh
APP_NAME=agentenv
AGENTENV_HOME=${AGENTENV_HOME:-"$HOME/.agentenv"}
INSTALL_DIR=${AGENTENV_INSTALL_DIR:-"$HOME/.agentenv/bin"}
AGENTENV_BIN=${AGENTENV_BIN:-"$INSTALL_DIR/agentenv"}
INSTALLER_SENTINEL="# agentenv installer"
```

Argument parsing sets boolean flags:

```text
YES
DRY_RUN
KEEP_OPENSHELL
KEEP_DRIVERS
KEEP_CREDENTIALS
KEEP_DATA
DELETE_MODELS
```

The script then builds an uninstall plan before mutation. The plan includes:

1. envs to destroy through `agentenv destroy --yes`.
2. paths to remove.
3. shell startup files that contain the installer sentinel.
4. Docker images and volumes matching the `agentenv_` prefix when Docker is present.
5. optional model paths considered only when `--delete-models` is set.
6. paths and resources preserved by default or by keep flags.
7. estimated disk reclaimed for owned filesystem paths.

The script prints the plan in stable text. `--dry-run` exits after printing the plan with status 0.

Normal execution asks for confirmation unless `--yes` is set. The prompt should read from `/dev/tty` when available. If confirmation is required but no terminal is available, the script fails without deleting anything.

## 5. Removal Model

The script should delete only known owned paths:

```text
$INSTALL_DIR/agentenv
$AGENTENV_HOME/bin/agentenv
$AGENTENV_HOME/events.db
$AGENTENV_HOME/audit.key
$AGENTENV_HOME/audit-signing-key
$AGENTENV_HOME/envs/
$AGENTENV_HOME/drivers/
$AGENTENV_HOME/credentials.json
empty $AGENTENV_HOME directories after selected removals
```

`--keep-data` preserves `$AGENTENV_HOME/envs/`. When it is absent, the script first attempts driver-aware teardown:

```sh
agentenv list --json
agentenv destroy <name> --yes
```

If list or destroy fails, the script logs the failure, continues cleanup, and records the failure in the diagnostic bundle. It should not treat project paths referenced from blueprints or state as deletion targets.

`--keep-drivers` preserves `$AGENTENV_HOME/drivers/`.

`--keep-credentials` preserves `$AGENTENV_HOME/credentials.json`. Keyring credentials cannot be enumerated safely from shell today, so the script should not claim complete keyring cleanup. The plan and diagnostics should state that JSON fallback credentials are removable and OS keyring cleanup may require a future typed CLI path.

`--delete-models` enables removal of agentenv-owned local model cache paths. The initial implementation should be conservative:

```text
$AGENTENV_HOME/models/
```

It should not delete global Ollama model directories such as `~/.ollama/models` without a separate ownership marker.

OpenShell is preserved. The uninstaller should not delete `openshell` binaries or OpenShell global state in this issue.

Docker cleanup is best-effort:

```sh
docker volume ls --format '{{.Name}}' | grep '^agentenv_'
docker image ls --format '{{.Repository}}:{{.Tag}}' | grep '^agentenv_'
```

If Docker is missing or the commands fail, the script records a warning and continues.

## 6. Shell Startup Cleanup

The installer writes:

```text
# agentenv installer
export PATH=".../.agentenv/bin:$PATH"
```

The uninstaller should scan:

```text
$HOME/.bashrc
$HOME/.zshrc
$HOME/.profile
```

For each file containing the sentinel, it should:

1. create a timestamped backup next to the file.
2. remove the sentinel block and its immediate PATH export.
3. leave unrelated lines untouched.

If a file does not exist or lacks the sentinel, it is preserved and the plan says no PATH entry was found.

## 7. Diagnostics And Failure Handling

The script tracks failures in memory during execution. On any partial failure, it writes a diagnostic directory under:

```text
${TMPDIR:-/tmp}/agentenv-uninstall-diagnostics.<pid>/
```

The bundle should include:

```text
plan.txt
actions.log
errors.log
env-list.json when available
```

The final summary should print the diagnostic path. A partial failure exits non-zero after completing all remaining best-effort cleanup.

Idempotence rules:

1. missing files are reported as already absent, not errors.
2. missing Docker resources are ignored.
3. missing env registry entries are ignored.
4. no shell startup backup is created when no sentinel block is present.
5. running twice should produce an empty or already-absent plan on the second run.

## 8. CLI Delegation

Add a top-level `Uninstall(UninstallArgs)` variant to `crates/agentenv/src/main.rs`.

`UninstallArgs` mirrors script flags:

```rust
#[derive(Debug, Args)]
struct UninstallArgs {
    #[arg(short = 'y', long)]
    yes: bool,
    #[arg(long)]
    keep_openshell: bool,
    #[arg(long)]
    keep_drivers: bool,
    #[arg(long)]
    keep_credentials: bool,
    #[arg(long)]
    keep_data: bool,
    #[arg(long)]
    delete_models: bool,
    #[arg(long)]
    dry_run: bool,
}
```

`run_uninstall` locates a script and spawns `sh <script> <flags>`.

Script lookup order:

1. `AGENTENV_UNINSTALL_SCRIPT` when set, for tests and local overrides.
2. sibling `uninstall.sh` next to `std::env::current_exe()`.
3. repository-local `uninstall.sh` found from the current working directory or its ancestors.
4. hosted fallback.

Hosted fallback uses:

```text
AGENTENV_VERSION, defaulting to current package version with a `v` prefix
AGENTENV_RELEASE_BASE_URL, defaulting to GitHub release downloads
```

The CLI downloads:

```text
${AGENTENV_RELEASE_BASE_URL}/${version}/uninstall.sh
${AGENTENV_RELEASE_BASE_URL}/${version}/uninstall.sh.sha256
```

It verifies the script content with `sha2` and `hex`, writes the script into a temporary directory, and executes it with `sh`.

The CLI should propagate the script exit status. If the child exits due to signal or cannot be spawned, return an `anyhow` error and let existing CLI error rendering handle it.

## 9. Tests

Shell tests in `tests/install/test_install.sh` should source `uninstall.sh` and cover:

1. argument parsing accepts every flag.
2. dry-run prints a plan and does not delete files.
3. shell startup cleanup removes only the installer block and creates a backup.
4. keep flags preserve `drivers`, `credentials.json`, and `envs`.
5. default removal deletes owned agentenv files.
6. second run is a no-op.
7. project directories outside `$AGENTENV_HOME` are not deleted.
8. partial failures create a diagnostic bundle.

CLI tests in `crates/agentenv/tests/cli_behavior.rs` should cover:

1. `agentenv uninstall --dry-run` delegates to `AGENTENV_UNINSTALL_SCRIPT`.
2. every CLI flag is forwarded to the script.
3. non-zero script exit status is propagated.

Full workspace verification should run:

```sh
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
sh tests/install/test_install.sh
```

## 10. Security And Safety Notes

The uninstaller must never use `sudo`. It operates only on files the current user can access.

The uninstaller must not follow broad user-controlled paths from blueprint or state files. Env state can inform `agentenv destroy`, but filesystem deletion remains limited to known agentenv-owned roots.

Hosted script execution must be digest-verified by the CLI fallback. The raw `curl | sh` flow cannot verify itself after the shell has started executing bytes, so release documentation should prefer the checksum-aware download form where possible while still supporting the issue's one-line script acceptance criterion.

No credentials should be printed in plans, logs, or diagnostics. If `credentials.json` is included in a plan, it should appear only as a path and byte size.

## 11. Trade-Offs

Script-owned uninstall duplicates a small amount of process and filesystem work that Rust could express with stronger types. The benefit is a single hosted artifact that works even when the installed binary is broken or already removed.

Keyring cleanup remains intentionally limited in the first slice. Shell cannot enumerate agentenv keyring entries portably, and adding that support cleanly belongs in a typed credential-store API. This design preserves correctness by not claiming keyring deletion it cannot prove.

Docker and model cleanup are conservative. The uninstaller removes only `agentenv_` Docker resources and `$AGENTENV_HOME/models/`, avoiding accidental deletion of user-managed runtimes.
