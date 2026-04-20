# Driver Discovery Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the issue #11 foundation slice: core-owned subprocess driver manifest discovery plus `agentenv drivers list`.

**Architecture:** Add a focused `agentenv-core::driver_catalog` module for built-in driver metadata, manifest parsing, source precedence, and catalog-to-registry registration. Keep `DriverRegistry` as the semver pinning mechanism, and add a thin CLI command that renders catalog metadata without spawning subprocesses.

**Tech Stack:** Rust 2021, `serde`, `serde_json`, `semver`, `thiserror`, `dirs`, `clap`, standard `std::fs` and `std::path` APIs.

---

## File Structure

- Create: `crates/agentenv-core/src/driver_catalog.rs`
  - Owns built-in driver specs, manifest parsing, discovery roots, source precedence, catalog entries, and discovery errors.
- Modify: `crates/agentenv-core/src/lib.rs`
  - Exports `driver_catalog`.
- Modify: `crates/agentenv-core/src/registry.rs`
  - Reuses built-in specs from `driver_catalog` and keeps `DriverRegistry` behavior unchanged.
- Modify: `crates/agentenv-core/Cargo.toml`
  - Adds `dirs.workspace = true`.
- Modify: `crates/agentenv/src/main.rs`
  - Adds `drivers list` CLI structs, dispatch, and table rendering.
- Modify: `crates/agentenv/tests/cli_behavior.rs`
  - Adds integration tests for built-ins, `AGENTENV_DRIVER_PATH`, and malformed manifests.

---

### Task 1: Shared Built-In Driver Metadata

**Files:**
- Create: `crates/agentenv-core/src/driver_catalog.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Modify: `crates/agentenv-core/src/registry.rs`

- [ ] **Step 1: Write failing tests for shared built-in metadata**

Create `crates/agentenv-core/src/driver_catalog.rs` with these tests and no implementation beyond the module imports needed by the test code:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::DriverKind;

    #[test]
    fn built_in_specs_include_current_aliases() {
        let specs = built_in_driver_specs();

        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Sandbox
                && spec.names == &["openshell", "sandbox-openshell"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Agent && spec.names == &["codex", "agent-codex"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Context && spec.names == &["filesystem", "context-filesystem"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Inference
                && spec.names == &["passthrough", "inference-passthrough"]
        }));
    }
}
```

Add the module export in `crates/agentenv-core/src/lib.rs`:

```rust
pub mod driver_catalog;
```

Add this test in `crates/agentenv-core/src/registry.rs` inside the existing `#[cfg(test)]` module:

```rust
#[test]
fn default_registry_uses_shared_builtin_aliases() {
    let registry = DriverRegistry::default();

    assert_eq!(
        registry
            .pin(DriverKind::Sandbox, "sandbox-openshell", None)
            .unwrap()
            .to_string(),
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        registry
            .pin(DriverKind::Agent, "agent-codex", None)
            .unwrap()
            .to_string(),
        env!("CARGO_PKG_VERSION")
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core built_in_specs_include_current_aliases
cargo test -p agentenv-core default_registry_uses_shared_builtin_aliases
```

Expected: FAIL because `BuiltInDriverSpec` and `built_in_driver_specs()` are not defined.

- [ ] **Step 3: Add built-in metadata and reuse it from the registry**

Add this implementation to `crates/agentenv-core/src/driver_catalog.rs` above the tests:

```rust
use crate::registry::DriverKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInDriverSpec {
    pub kind: DriverKind,
    pub names: &'static [&'static str],
}

const BUILT_IN_DRIVER_SPECS: &[BuiltInDriverSpec] = &[
    BuiltInDriverSpec {
        kind: DriverKind::Sandbox,
        names: &["openshell", "sandbox-openshell"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["claude", "agent-claude"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["codex", "agent-codex"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["hermes"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["openclaw", "agent-openclaw"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["filesystem", "context-filesystem"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["mcp-generic", "context-mcp-generic"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["nexus"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["none", "context-none"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["passthrough", "inference-passthrough"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["openai", "inference-openai"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["anthropic", "inference-anthropic"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["ollama", "inference-ollama"],
    },
];

pub fn built_in_driver_specs() -> &'static [BuiltInDriverSpec] {
    BUILT_IN_DRIVER_SPECS
}
```

Modify `crates/agentenv-core/src/registry.rs`:

```rust
use crate::driver_catalog::built_in_driver_specs;
```

Replace the hard-coded `register_current_version(...)` calls in `impl Default for DriverRegistry` with:

```rust
for spec in built_in_driver_specs() {
    register_current_version(&mut registry, spec.kind, spec.names, &current_version);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core built_in_specs_include_current_aliases
cargo test -p agentenv-core default_registry_uses_shared_builtin_aliases
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/driver_catalog.rs crates/agentenv-core/src/lib.rs crates/agentenv-core/src/registry.rs
git commit -m "feat: share built-in driver metadata"
```

---

### Task 2: Driver Manifest Parser

**Files:**
- Modify: `crates/agentenv-core/src/driver_catalog.rs`

- [ ] **Step 1: Write failing manifest parser tests**

Add these tests inside the `driver_catalog.rs` test module:

```rust
use std::{
    fs,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn parses_valid_manifest_and_resolves_relative_binary() {
    let root = make_temp_dir("manifest-valid");
    let binary = root.join("bin/context-nexus-py");
    touch_file(&binary);
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "description": "Nexus context backend",
          "binary": "./bin/context-nexus-py",
          "args": ["--stdio"],
          "env": {"RUST_LOG": "info"},
          "capabilities_preview": {"is_remote": true}
        }"#,
    );

    let manifest = DriverManifest::from_path(&root.join("manifest.json")).unwrap();

    assert_eq!(manifest.name, "nexus");
    assert_eq!(manifest.kind, DriverKind::Context);
    assert_eq!(manifest.version.to_string(), "0.2.0");
    assert_eq!(manifest.binary, binary);
    assert_eq!(manifest.args, vec!["--stdio"]);
    assert_eq!(manifest.env.get("RUST_LOG").unwrap(), "info");
    assert_eq!(manifest.description.as_deref(), Some("Nexus context backend"));
}

#[test]
fn rejects_invalid_manifest_kind() {
    let root = manifest_root_with_binary("manifest-bad-kind");
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "database",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
    );

    let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

    assert!(err.to_string().contains("unknown driver kind `database`"));
    assert!(err.to_string().contains("manifest.json"));
}

#[test]
fn rejects_invalid_manifest_version() {
    let root = manifest_root_with_binary("manifest-bad-version");
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "banana",
          "binary": "./bin/driver"
        }"#,
    );

    let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

    assert!(err.to_string().contains("invalid driver version `banana`"));
    assert!(err.to_string().contains("manifest.json"));
}

#[test]
fn rejects_incompatible_manifest_schema_version() {
    let root = manifest_root_with_binary("manifest-schema");
    write_manifest(
        &root,
        r#"{
          "schema_version": "2.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
    );

    let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

    assert!(err.to_string().contains("incompatible manifest schema version"));
    assert!(err.to_string().contains("manifest.json"));
}

#[test]
fn rejects_relative_binary_that_escapes_manifest_root() {
    let root = make_temp_dir("manifest-escape");
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "../outside-driver"
        }"#,
    );

    let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

    assert!(err.to_string().contains("escapes driver root"));
    assert!(err.to_string().contains("manifest.json"));
}

#[test]
fn rejects_manifest_with_missing_binary() {
    let root = make_temp_dir("manifest-missing-binary");
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/missing-driver"
        }"#,
    );

    let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

    assert!(err.to_string().contains("driver binary does not exist"));
    assert!(err.to_string().contains("manifest.json"));
}

fn manifest_root_with_binary(prefix: &str) -> PathBuf {
    let root = make_temp_dir(prefix);
    touch_file(&root.join("bin/driver"));
    root
}

fn write_manifest(root: &Path, contents: &str) {
    fs::write(root.join("manifest.json"), contents).unwrap();
}

fn touch_file(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, "").unwrap();
}

fn make_temp_dir(prefix: &str) -> PathBuf {
    let unique = format!(
        "{prefix}-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    fs::create_dir_all(&path).unwrap();
    path
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core manifest_
```

Expected: FAIL because `DriverManifest` and manifest error handling are not implemented.

- [ ] **Step 3: Add manifest parser implementation**

Add these imports and types to `crates/agentenv-core/src/driver_catalog.rs`:

```rust
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use agentenv_proto::assert_compatible_schema_version;
use semver::Version;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverManifest {
    pub schema_version: String,
    pub name: String,
    pub kind: DriverKind,
    pub version: Version,
    pub description: Option<String>,
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub capabilities_preview: Value,
    pub manifest_path: PathBuf,
    pub root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RawDriverManifest {
    schema_version: String,
    name: String,
    kind: String,
    version: String,
    #[serde(default)]
    description: Option<String>,
    binary: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    capabilities_preview: Value,
}

#[derive(Debug, Error)]
pub enum DriverDiscoveryError {
    #[error("failed to read driver manifest `{path}`: {source}")]
    ReadManifest {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON in driver manifest `{path}`: {source}")]
    InvalidManifestJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("incompatible manifest schema version in `{path}`: {source}")]
    IncompatibleSchemaVersion {
        path: PathBuf,
        #[source]
        source: agentenv_proto::SchemaVersionError,
    },
    #[error("driver manifest `{path}` has empty driver name")]
    EmptyName { path: PathBuf },
    #[error("unknown driver kind `{kind}` in manifest `{path}`")]
    UnknownKind { path: PathBuf, kind: String },
    #[error("invalid driver version `{version}` in manifest `{path}`: {source}")]
    InvalidVersion {
        path: PathBuf,
        version: String,
        #[source]
        source: semver::Error,
    },
    #[error("driver binary `{binary}` escapes driver root `{root}` in manifest `{path}`")]
    BinaryEscapesRoot {
        path: PathBuf,
        root: PathBuf,
        binary: PathBuf,
    },
    #[error("driver binary does not exist at `{binary}` from manifest `{path}`")]
    MissingBinary { path: PathBuf, binary: PathBuf },
}
```

Add this implementation:

```rust
impl DriverManifest {
    pub fn from_path(path: &Path) -> Result<Self, DriverDiscoveryError> {
        let raw_text = fs::read_to_string(path).map_err(|source| {
            DriverDiscoveryError::ReadManifest {
                path: path.to_path_buf(),
                source,
            }
        })?;
        let raw: RawDriverManifest =
            serde_json::from_str(&raw_text).map_err(|source| {
                DriverDiscoveryError::InvalidManifestJson {
                    path: path.to_path_buf(),
                    source,
                }
            })?;

        assert_compatible_schema_version(&raw.schema_version).map_err(|source| {
            DriverDiscoveryError::IncompatibleSchemaVersion {
                path: path.to_path_buf(),
                source,
            }
        })?;

        let name = raw.name.trim().to_owned();
        if name.is_empty() {
            return Err(DriverDiscoveryError::EmptyName {
                path: path.to_path_buf(),
            });
        }

        let kind = parse_driver_kind(&raw.kind).ok_or_else(|| {
            DriverDiscoveryError::UnknownKind {
                path: path.to_path_buf(),
                kind: raw.kind.clone(),
            }
        })?;

        let version =
            Version::parse(&raw.version).map_err(|source| DriverDiscoveryError::InvalidVersion {
                path: path.to_path_buf(),
                version: raw.version.clone(),
                source,
            })?;

        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let binary = resolve_manifest_binary(path, &root, &raw.binary)?;

        Ok(Self {
            schema_version: raw.schema_version,
            name,
            kind,
            version,
            description: raw.description,
            binary,
            args: raw.args,
            env: raw.env,
            capabilities_preview: raw.capabilities_preview,
            manifest_path: path.to_path_buf(),
            root,
        })
    }
}

fn parse_driver_kind(kind: &str) -> Option<DriverKind> {
    match kind {
        "sandbox" => Some(DriverKind::Sandbox),
        "agent" => Some(DriverKind::Agent),
        "context" => Some(DriverKind::Context),
        "inference" => Some(DriverKind::Inference),
        _ => None,
    }
}

fn resolve_manifest_binary(
    manifest_path: &Path,
    root: &Path,
    binary: &Path,
) -> Result<PathBuf, DriverDiscoveryError> {
    let resolved = if binary.is_absolute() {
        binary.to_path_buf()
    } else {
        let resolved = normalize_relative_path(root, binary);
        if !resolved.starts_with(root) {
            return Err(DriverDiscoveryError::BinaryEscapesRoot {
                path: manifest_path.to_path_buf(),
                root: root.to_path_buf(),
                binary: binary.to_path_buf(),
            });
        }
        resolved
    };

    if !resolved.is_file() {
        return Err(DriverDiscoveryError::MissingBinary {
            path: manifest_path.to_path_buf(),
            binary: resolved,
        });
    }

    Ok(resolved)
}

fn normalize_relative_path(root: &Path, relative: &Path) -> PathBuf {
    let mut normalized = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(segment) => normalized.push(segment),
            Component::Prefix(_) | Component::RootDir => normalized.push(component.as_os_str()),
        }
    }
    normalized
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core manifest_
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/driver_catalog.rs
git commit -m "feat: parse driver manifests"
```

---

### Task 3: Driver Catalog Discovery and Precedence

**Files:**
- Modify: `crates/agentenv-core/src/driver_catalog.rs`
- Modify: `crates/agentenv-core/Cargo.toml`

- [ ] **Step 1: Write failing discovery tests**

Add these tests inside the `driver_catalog.rs` test module:

```rust
#[test]
fn discovery_ignores_missing_roots() {
    let missing_root = make_temp_dir("discovery-missing").join("does-not-exist");
    let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
        missing_root,
        Vec::<PathBuf>::new(),
    ))
    .unwrap();

    assert!(catalog.entries.iter().any(|entry| {
        entry.source == DriverSource::BuiltIn
            && entry.kind == DriverKind::Agent
            && entry.name == "codex"
    }));
}

#[test]
fn discovery_reads_direct_override_root() {
    let root = manifest_root_with_binary("discovery-direct");
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
    );

    let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
        make_temp_dir("discovery-installed-empty"),
        vec![root.clone()],
    ))
    .unwrap();

    let entry = catalog
        .entries
        .iter()
        .find(|entry| entry.kind == DriverKind::Context && entry.name == "nexus")
        .unwrap();
    let expected_manifest = root.join("manifest.json");
    assert_eq!(entry.source, DriverSource::DevelopmentOverride);
    assert_eq!(entry.manifest_path.as_deref(), Some(expected_manifest.as_path()));
}

#[test]
fn discovery_reads_parent_override_root() {
    let parent = make_temp_dir("discovery-parent");
    let root = parent.join("context-nexus-py");
    fs::create_dir_all(&root).unwrap();
    touch_file(&root.join("bin/driver"));
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
    );

    let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
        make_temp_dir("discovery-installed-empty"),
        vec![parent],
    ))
    .unwrap();

    assert!(catalog.entries.iter().any(|entry| {
        entry.source == DriverSource::DevelopmentOverride
            && entry.kind == DriverKind::Context
            && entry.name == "nexus"
    }));
}

#[test]
fn development_override_wins_over_installed_and_builtin() {
    let installed_root = make_temp_dir("discovery-installed");
    let installed_driver = installed_root.join("codex-installed");
    fs::create_dir_all(&installed_driver).unwrap();
    touch_file(&installed_driver.join("bin/driver"));
    write_manifest(
        &installed_driver,
        r#"{
          "schema_version": "1.0",
          "name": "codex",
          "kind": "agent",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
    );

    let override_driver = manifest_root_with_binary("discovery-override");
    write_manifest(
        &override_driver,
        r#"{
          "schema_version": "1.0",
          "name": "codex",
          "kind": "agent",
          "version": "0.3.0",
          "binary": "./bin/driver"
        }"#,
    );

    let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
        installed_root,
        vec![override_driver],
    ))
    .unwrap();

    let entry = catalog
        .entries
        .iter()
        .find(|entry| entry.kind == DriverKind::Agent && entry.name == "codex")
        .unwrap();
    assert_eq!(entry.source, DriverSource::DevelopmentOverride);
    assert_eq!(entry.version.to_string(), "0.3.0");
}

#[test]
fn duplicate_manifests_at_same_precedence_fail_with_both_paths() {
    let parent = make_temp_dir("discovery-duplicates");
    for name in ["first", "second"] {
        let root = parent.join(name);
        fs::create_dir_all(&root).unwrap();
        touch_file(&root.join("bin/driver"));
        write_manifest(
            &root,
            r#"{
              "schema_version": "1.0",
              "name": "nexus",
              "kind": "context",
              "version": "0.2.0",
              "binary": "./bin/driver"
            }"#,
        );
    }

    let err = DriverCatalog::discover(DriverDiscoveryConfig::new(
        make_temp_dir("discovery-installed-empty"),
        vec![parent.clone()],
    ))
    .unwrap_err();

    assert!(err.to_string().contains("duplicate context driver `nexus`"));
    assert!(err.to_string().contains("first/manifest.json"));
    assert!(err.to_string().contains("second/manifest.json"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core discovery_
```

Expected: FAIL because `DriverCatalog`, `DriverDiscoveryConfig`, `DriverSource`, and duplicate handling are not implemented.

- [ ] **Step 3: Add discovery dependencies**

Modify `crates/agentenv-core/Cargo.toml`:

```toml
dirs.workspace = true
```

- [ ] **Step 4: Add catalog and discovery implementation**

Add these public types to `crates/agentenv-core/src/driver_catalog.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriverSource {
    BuiltIn,
    InstalledSubprocess,
    DevelopmentOverride,
}

impl DriverSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::InstalledSubprocess => "installed",
            Self::DevelopmentOverride => "override",
        }
    }

    fn precedence(self) -> u8 {
        match self {
            Self::BuiltIn => 0,
            Self::InstalledSubprocess => 1,
            Self::DevelopmentOverride => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDriver {
    pub kind: DriverKind,
    pub name: String,
    pub version: Version,
    pub source: DriverSource,
    pub description: Option<String>,
    pub binary: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub capabilities_preview: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverCatalog {
    pub entries: Vec<DiscoveredDriver>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverDiscoveryConfig {
    pub installed_root: PathBuf,
    pub driver_path_entries: Vec<PathBuf>,
}

impl DriverDiscoveryConfig {
    pub fn new(installed_root: PathBuf, driver_path_entries: Vec<PathBuf>) -> Self {
        Self {
            installed_root,
            driver_path_entries,
        }
    }

    pub fn from_env() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let installed_root = home.join(".agentenv/drivers");
        let driver_path_entries = std::env::var_os("AGENTENV_DRIVER_PATH")
            .map(|paths| std::env::split_paths(&paths).collect())
            .unwrap_or_default();

        Self::new(installed_root, driver_path_entries)
    }
}
```

Add the duplicate error variant:

```rust
#[error("duplicate {kind} driver `{name}` discovered at `{first}` and `{second}`")]
DuplicateDriver {
    kind: DriverKind,
    name: String,
    first: PathBuf,
    second: PathBuf,
},
```

Add catalog discovery implementation:

```rust
impl DriverCatalog {
    pub fn discover_from_environment() -> Result<Self, DriverDiscoveryError> {
        Self::discover(DriverDiscoveryConfig::from_env())
    }

    pub fn discover(config: DriverDiscoveryConfig) -> Result<Self, DriverDiscoveryError> {
        let mut builder = CatalogBuilder::default();
        builder.add_built_ins();
        discover_parent_root(
            &mut builder,
            &config.installed_root,
            DriverSource::InstalledSubprocess,
        )?;
        for entry in &config.driver_path_entries {
            discover_override_entry(&mut builder, entry)?;
        }

        Ok(Self {
            entries: builder.into_entries(),
        })
    }
}

#[derive(Default)]
struct CatalogBuilder {
    entries: BTreeMap<(DriverKind, String), DiscoveredDriver>,
}

impl CatalogBuilder {
    fn add_built_ins(&mut self) {
        let version = Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("crate version must be valid semver");
        for spec in built_in_driver_specs() {
            for name in spec.names {
                let entry = DiscoveredDriver {
                    kind: spec.kind,
                    name: (*name).to_owned(),
                    version: version.clone(),
                    source: DriverSource::BuiltIn,
                    description: None,
                    binary: None,
                    manifest_path: None,
                    args: Vec::new(),
                    env: BTreeMap::new(),
                    capabilities_preview: Value::Null,
                };
                self.entries.insert((spec.kind, (*name).to_owned()), entry);
            }
        }
    }

    fn add_manifest(
        &mut self,
        manifest: DriverManifest,
        source: DriverSource,
    ) -> Result<(), DriverDiscoveryError> {
        let key = (manifest.kind, manifest.name.clone());
        let incoming = DiscoveredDriver {
            kind: manifest.kind,
            name: manifest.name,
            version: manifest.version,
            source,
            description: manifest.description,
            binary: Some(manifest.binary),
            manifest_path: Some(manifest.manifest_path),
            args: manifest.args,
            env: manifest.env,
            capabilities_preview: manifest.capabilities_preview,
        };

        if let Some(existing) = self.entries.get(&key) {
            if existing.source == source {
                return Err(DriverDiscoveryError::DuplicateDriver {
                    kind: key.0,
                    name: key.1,
                    first: existing
                        .manifest_path
                        .clone()
                        .unwrap_or_else(|| PathBuf::from("<built-in>")),
                    second: incoming
                        .manifest_path
                        .clone()
                        .unwrap_or_else(|| PathBuf::from("<built-in>")),
                });
            }
            if existing.source.precedence() > source.precedence() {
                return Ok(());
            }
        }

        self.entries.insert(key, incoming);
        Ok(())
    }

    fn into_entries(self) -> Vec<DiscoveredDriver> {
        self.entries.into_values().collect()
    }
}

fn discover_override_entry(
    builder: &mut CatalogBuilder,
    entry: &Path,
) -> Result<(), DriverDiscoveryError> {
    if !entry.exists() {
        return Ok(());
    }
    let direct_manifest = entry.join("manifest.json");
    if direct_manifest.is_file() {
        let manifest = DriverManifest::from_path(&direct_manifest)?;
        builder.add_manifest(manifest, DriverSource::DevelopmentOverride)?;
        return Ok(());
    }

    discover_parent_root(builder, entry, DriverSource::DevelopmentOverride)
}

fn discover_parent_root(
    builder: &mut CatalogBuilder,
    root: &Path,
    source: DriverSource,
) -> Result<(), DriverDiscoveryError> {
    if !root.is_dir() {
        return Ok(());
    }

    let mut entries = fs::read_dir(root).map_err(|err| DriverDiscoveryError::ReadManifest {
        path: root.to_path_buf(),
        source: err,
    })?;
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|err| DriverDiscoveryError::ReadManifest {
            path: root.to_path_buf(),
            source: err,
        })?;
        let manifest_path = entry.path().join("manifest.json");
        if manifest_path.is_file() {
            let manifest = DriverManifest::from_path(&manifest_path)?;
            builder.add_manifest(manifest, source)?;
        }
    }

    Ok(())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core discovery_
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-core/Cargo.toml crates/agentenv-core/src/driver_catalog.rs Cargo.lock
git commit -m "feat: discover driver manifests"
```

---

### Task 4: Catalog Registration With DriverRegistry

**Files:**
- Modify: `crates/agentenv-core/src/driver_catalog.rs`

- [ ] **Step 1: Write failing registry integration test**

Add this test to the `driver_catalog.rs` test module:

```rust
#[test]
fn catalog_registers_subprocess_versions_for_pinning() {
    let root = manifest_root_with_binary("catalog-register");
    write_manifest(
        &root,
        r#"{
          "schema_version": "1.0",
          "name": "custom-context",
          "kind": "context",
          "version": "2.1.0",
          "binary": "./bin/driver"
        }"#,
    );
    let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
        make_temp_dir("catalog-empty-installed"),
        vec![root],
    ))
    .unwrap();

    let mut registry = crate::registry::DriverRegistry::default();
    catalog.register_with(&mut registry);

    let pinned = registry
        .pin(DriverKind::Context, "custom-context", Some(">=2.0.0,<3.0.0"))
        .unwrap();
    assert_eq!(pinned.to_string(), "2.1.0");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p agentenv-core catalog_registers_subprocess_versions_for_pinning
```

Expected: FAIL because `DriverCatalog::register_with` is not implemented.

- [ ] **Step 3: Implement catalog-to-registry registration**

Add this import to `driver_catalog.rs`:

```rust
use crate::registry::DriverRegistry;
```

Add this method to `impl DriverCatalog`:

```rust
pub fn register_with(&self, registry: &mut DriverRegistry) {
    for entry in &self.entries {
        if entry.source != DriverSource::BuiltIn {
            registry.register_version(entry.kind, entry.name.clone(), entry.version.clone());
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cargo test -p agentenv-core catalog_registers_subprocess_versions_for_pinning
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/driver_catalog.rs
git commit -m "feat: register discovered driver versions"
```

---

### Task 5: `agentenv drivers list`

**Files:**
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI integration tests**

Add these tests to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn drivers_list_includes_built_in_drivers() {
    let temp_dir = make_temp_dir("drivers-list-builtins");

    let output = Command::new(agentenv_bin())
        .arg("drivers")
        .arg("list")
        .env("HOME", &temp_dir)
        .env_remove("AGENTENV_DRIVER_PATH")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("KIND"));
    assert!(stdout.contains("agent"));
    assert!(stdout.contains("codex"));
    assert!(stdout.contains("built-in"));
}

#[test]
fn drivers_list_includes_override_manifest() {
    let temp_dir = make_temp_dir("drivers-list-override");
    let driver_root = temp_dir.join("context-nexus-py");
    fs::create_dir_all(driver_root.join("bin")).unwrap();
    fs::write(driver_root.join("bin/driver"), "").unwrap();
    fs::write(
        driver_root.join("manifest.json"),
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("drivers")
        .arg("list")
        .env("HOME", temp_dir.join("home"))
        .env("AGENTENV_DRIVER_PATH", &driver_root)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("context"));
    assert!(stdout.contains("nexus"));
    assert!(stdout.contains("0.2.0"));
    assert!(stdout.contains("override"));
    assert!(stdout.contains("bin/driver"));
}

#[test]
fn drivers_list_reports_malformed_manifest_path() {
    let temp_dir = make_temp_dir("drivers-list-bad-manifest");
    let driver_root = temp_dir.join("bad-driver");
    fs::create_dir_all(&driver_root).unwrap();
    fs::write(driver_root.join("manifest.json"), "{not-json").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("drivers")
        .arg("list")
        .env("HOME", temp_dir.join("home"))
        .env("AGENTENV_DRIVER_PATH", &driver_root)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("manifest.json"), "stderr was: {stderr}");
    assert!(stderr.contains("invalid JSON"), "stderr was: {stderr}");
}
```

Modify the existing unit test `cli_includes_commands` in `crates/agentenv/src/main.rs` so the expected command list includes `drivers`:

```rust
assert_eq!(
    subcommands,
    vec![
        "credentials".to_string(),
        "drivers".to_string(),
        "verify-blueprint".to_string(),
        "freeze".to_string(),
        "reproduce".to_string(),
    ]
);
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv drivers_list
cargo test -p agentenv cli_includes_commands
```

Expected: FAIL because the `drivers` command does not exist yet.

- [ ] **Step 3: Add CLI command types and dispatch**

Modify `crates/agentenv/src/main.rs` imports:

```rust
use agentenv_core::driver_catalog::{DiscoveredDriver, DriverCatalog};
```

Add the command variant:

```rust
Drivers(DriversArgs),
```

Place it after `Credentials(CredentialsArgs)` in the `Commands` enum.

Add these structs near `CredentialsArgs`:

```rust
#[derive(Debug, Args)]
struct DriversArgs {
    #[command(subcommand)]
    command: DriverCommand,
}

#[derive(Debug, Subcommand)]
enum DriverCommand {
    /// Lists built-in and discovered subprocess drivers.
    List,
}
```

Add dispatch in `run()`:

```rust
Some(Commands::Drivers(command)) => run_drivers(command),
```

Place it after the credentials dispatch arm.

- [ ] **Step 4: Add CLI rendering implementation**

Add this function to `crates/agentenv/src/main.rs` after `run_credentials`:

```rust
fn run_drivers(args: DriversArgs) -> Result<()> {
    match args.command {
        DriverCommand::List => {
            let catalog = DriverCatalog::discover_from_environment()
                .context("discover installed drivers")?;
            print_driver_table(&catalog.entries);
            Ok(())
        }
    }
}

fn print_driver_table(entries: &[DiscoveredDriver]) {
    println!(
        "{:<10} {:<24} {:<14} {:<10} BINARY",
        "KIND", "NAME", "VERSION", "SOURCE"
    );
    for entry in entries {
        let binary = entry
            .binary
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_owned());
        println!(
            "{:<10} {:<24} {:<14} {:<10} {}",
            entry.kind,
            entry.name,
            entry.version,
            entry.source.label(),
            binary
        );
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv drivers_list
cargo test -p agentenv cli_includes_commands
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv/src/main.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: list discovered drivers"
```

---

### Task 6: Final Verification

**Files:**
- All files touched by Tasks 1-5.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt
```

Expected: exit code 0.

- [ ] **Step 2: Run focused test suites**

Run:

```bash
cargo test -p agentenv-core driver_catalog
cargo test -p agentenv drivers_list
```

Expected: both commands exit code 0.

- [ ] **Step 3: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: exit code 0 with no warnings.

- [ ] **Step 4: Run full workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: exit code 0.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git diff --stat
```

Expected: only intended files are modified:

```text
crates/agentenv-core/Cargo.toml
crates/agentenv-core/src/driver_catalog.rs
crates/agentenv-core/src/lib.rs
crates/agentenv-core/src/registry.rs
crates/agentenv/src/main.rs
crates/agentenv/tests/cli_behavior.rs
Cargo.lock
```

- [ ] **Step 6: Commit verification fixes if formatting changed files**

If `cargo fmt` changed files after Task 5, commit those changes:

```bash
git add crates/agentenv-core/Cargo.toml crates/agentenv-core/src/driver_catalog.rs crates/agentenv-core/src/lib.rs crates/agentenv-core/src/registry.rs crates/agentenv/src/main.rs crates/agentenv/tests/cli_behavior.rs Cargo.lock
git commit -m "chore: format driver discovery changes"
```

If `cargo fmt` did not change files, do not create an empty commit.
