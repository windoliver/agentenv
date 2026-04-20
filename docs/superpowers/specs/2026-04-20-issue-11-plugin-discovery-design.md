# Issue 11 Design: Subprocess Driver Discovery Foundation

- Date: 2026-04-20
- Issue: https://github.com/windoliver/agentenv/issues/11
- Milestone: M3 Subprocess plugin host
- Affected crates: `agentenv-core`, `agentenv`

## 1. Context and Goals

Issue #11 adds the subprocess plugin host for any-language drivers that speak JSON-RPC 2.0 over stdio. The full issue includes discovery, JSON-RPC transport, process lifecycle, trait adapters, install/remove tooling, crash handling, and credential isolation.

This design covers the first implementation slice only: driver manifest discovery, catalog metadata, registry integration for listing, and `agentenv drivers list`. It creates the foundation needed by the later transport and lifecycle slices without spawning subprocess drivers yet.

The design preserves the current architecture constraints:

1. MCP remains the only agent-to-context protocol.
2. JSON-RPC remains the only core-to-subprocess-driver protocol.
3. Built-in and subprocess drivers are listed uniformly.
4. Credentials are not passed through manifests or generic RPC.
5. The current blueprint resolver continues to pin driver versions through `DriverRegistry`.

## 2. Scope and Non-Goals

### In scope

1. Parse subprocess driver `manifest.json` files.
2. Discover manifests from installed and development override locations.
3. Model discovered drivers with source and provenance metadata.
4. Expose a catalog API that lists built-in and subprocess drivers uniformly.
5. Register discovered subprocess versions with `DriverRegistry` so future lifecycle code can resolve them.
6. Add `agentenv drivers list`.
7. Add unit and CLI tests for discovery behavior.

### Out of scope

1. JSON-RPC transport and LSP-style frame parsing in production code.
2. Spawning subprocess drivers with `tokio::process::Command`.
3. Initialize timeout, schema-version handshake, shutdown, SIGTERM, or SIGKILL behavior.
4. Restart-once and degraded runtime state.
5. `agentenv drivers install` and `agentenv drivers remove`.
6. Credential injection into driver subprocesses.
7. Any driver trait adapter such as `SubprocessDriver<K>`.

Those remain later slices of issue #11.

## 3. Manifest Format

Each subprocess driver root contains `manifest.json`:

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

The first implementation validates the fields needed for discovery and listing:

1. `schema_version` must be compatible with `agentenv-proto::SCHEMA_VERSION`.
2. `name` must be non-empty.
3. `kind` must be one of `sandbox`, `agent`, `context`, or `inference`.
4. `version` must parse as semver.
5. `binary` must resolve under the manifest root unless it is an absolute path.
6. the resolved binary must exist.
7. `args`, `env`, `description`, and `capabilities_preview` are retained as metadata for future host work.

`capabilities_preview` is intentionally not authoritative. Later transport work must still trust only the `initialize` result for real capabilities.

## 4. Architecture

### 4.1 Core-owned discovery

Add discovery to `agentenv-core` because blueprint resolution and `DriverRegistry` already live there. Keeping discovery beside registry code avoids a temporary split where the CLI knows about manifests but core cannot resolve them.

The primary public API should be shaped like this:

```rust
pub struct DriverCatalog {
    pub entries: Vec<DiscoveredDriver>,
}

pub struct DiscoveredDriver {
    pub kind: DriverKind,
    pub name: String,
    pub version: semver::Version,
    pub source: DriverSource,
    pub description: Option<String>,
    pub binary: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
}

pub enum DriverSource {
    BuiltIn,
    InstalledSubprocess,
    DevelopmentOverride,
}
```

Exact field visibility may be adjusted to match local style, but the data must support listing and future transport setup without reparsing manifests.

### 4.2 Built-in entries

The built-in driver list should be defined once and reused by:

1. `DriverRegistry::default()`
2. `DriverCatalog::discover(...)`
3. `agentenv drivers list`

This removes drift between version resolution and CLI listing. Existing aliases such as `openshell` and `sandbox-openshell` should remain registered. The list command may show each registered name as a row because aliases are currently valid driver identifiers.

### 4.3 Subprocess discovery roots

Discovery scans two sources:

1. Installed drivers: `~/.agentenv/drivers/*/manifest.json`.
2. Development overrides: each path in `AGENTENV_DRIVER_PATH`, split by `:` on Unix platforms.

An `AGENTENV_DRIVER_PATH` entry is interpreted flexibly:

1. If `<entry>/manifest.json` exists, the entry is one driver root.
2. Otherwise, if the entry is a directory, scan `<entry>/*/manifest.json`.
3. If the entry does not exist, discovery ignores it.

Missing `~/.agentenv/drivers` is also ignored.

### 4.4 Precedence and duplicates

Catalog entries are keyed by `(kind, name)`.

Precedence is:

1. Development override from `AGENTENV_DRIVER_PATH`.
2. Installed subprocess manifest.
3. Built-in driver.

If a higher-precedence source provides the same `(kind, name)`, the list view shows that source for the name. `DriverRegistry` still stores versions and pins the highest semver-compatible version for blueprint resolution. This means a development override can replace listing metadata while version resolution remains semver-driven.

Duplicate manifests with the same `(kind, name)` and same source class should fail with an error that includes both manifest paths. This avoids non-deterministic local behavior.

## 5. CLI Behavior

Add a top-level command:

```text
agentenv drivers list
```

The list command prints a stable table ordered by `kind`, then `name`, then `version`.

Required columns:

1. `KIND`
2. `NAME`
3. `VERSION`
4. `SOURCE`
5. `BINARY`

Built-in rows use `built-in` as source and `-` for binary. Subprocess rows use `installed` or `override` as source and show the resolved binary path.

No subprocess is spawned by this command. It is a metadata-only operation.

## 6. Error Model

Use `thiserror` in core and `anyhow` in the CLI.

Discovery ignores:

1. missing installed driver root
2. missing `AGENTENV_DRIVER_PATH` entries
3. directories that do not contain manifests

Discovery fails on:

1. unreadable manifest files
2. invalid JSON
3. incompatible manifest schema version
4. unknown driver kind
5. invalid semver version
6. empty names
7. missing binary path
8. binary paths that resolve outside the driver root when relative path traversal is used
9. duplicate drivers at the same precedence level

Every error must include the relevant manifest path or root path.

## 7. Testing Strategy

Follow TDD for each behavior.

### 7.1 Core tests

Add unit tests in `agentenv-core` for:

1. valid manifest parsing.
2. invalid kind rejection.
3. invalid semver rejection.
4. incompatible schema version rejection.
5. missing installed root is ignored.
6. direct override root discovery.
7. parent override root discovery.
8. override source wins over installed and built-in listing metadata.
9. duplicate manifests at the same precedence fail with both paths in the error.
10. relative binary paths are resolved against the manifest root.
11. relative binary paths cannot escape the manifest root.

### 7.2 CLI tests

Add integration tests in `crates/agentenv/tests/cli_behavior.rs` for:

1. `agentenv drivers list` includes built-in drivers.
2. `agentenv drivers list` includes a subprocess manifest discovered through `AGENTENV_DRIVER_PATH`.
3. malformed manifests fail with a path-rich error.

### 7.3 Verification commands

Run at minimum:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 8. Follow-Up Slices

After this foundation lands, issue #11 should continue in separate designs or implementation plans for:

1. JSON-RPC transport with LSP framing and parallel request routing.
2. Subprocess lifecycle with initialize timeout, shutdown, crash handling, and degraded state.
3. Trait adapters implementing `SandboxDriver`, `AgentDriver`, `ContextDriver`, and `InferenceDriver`.
4. `agentenv drivers install` and `agentenv drivers remove`.
5. credential injection and stdin/stdout capture tests proving credentials do not cross RPC.
