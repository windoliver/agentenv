# M4-2 Portable Lockfile Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `agentenv freeze`, `agentenv verify`, and `agentenv reproduce` as a portable, self-contained lockfile lifecycle for issue #15.

**Architecture:** Add a `0.2.0` portable lockfile model that preserves the current `0.1.0` parser for compatibility. Build local driver artifact verification on top of `DriverCatalog`, then route CLI freeze/verify/reproduce through new core APIs that reuse the M4-1 runtime create path after input resolution.

**Tech Stack:** Rust 1.95 workspace, `serde_yaml`, `serde_json`, `semver`, `sha2`, `agentenv-policy`, `agentenv-proto`, clap, Tokio tests where runtime calls are async.

---

## Scope Check

This plan implements one subsystem: portable lockfile lifecycle. The work crosses model, verification, runtime, and CLI layers, but each task produces testable behavior independently. Remote signed registry install remains outside this plan; missing external drivers produce actionable verification failures.

## File Structure

- Modify `crates/agentenv-core/src/lockfile.rs`: keep the existing `Lockfile` `0.1.0` model and add a versioned document parser plus `PortableLockfile` `0.2.0` structs.
- Create `crates/agentenv-core/src/driver_artifact.rs`: local driver artifact discovery and deterministic digesting for built-ins and subprocess driver roots.
- Modify `crates/agentenv-core/src/lifecycle.rs`: expose canonical resolved composition helpers used by portable lockfile building.
- Create `crates/agentenv-core/src/portable_lockfile.rs`: build, verify, serialize, and convert portable lockfiles.
- Modify `crates/agentenv-core/src/runtime.rs`: add freeze and reproduce entrypoints over persisted M4-1 env state; refactor create internals enough to share reproduction policy input.
- Modify `crates/agentenv-core/src/lib.rs`: export new modules.
- Modify `crates/agentenv/src/main.rs`: update clap shape and handlers for `freeze`, `verify`, and `reproduce`.
- Modify `crates/agentenv/src/render.rs`: add small text/JSON render helpers if the CLI handler needs structured verify output.
- Modify `crates/agentenv/tests/cli_behavior.rs`: replace old blueprint-freeze CLI tests and add verify/reproduce behavior.
- Add or modify tests in `crates/agentenv-core/tests/`: lockfile v2 model, artifact digest, portable verification, and runtime freeze/reproduce tests.

## Task 1: Add Versioned `0.2.0` Lockfile Model

**Files:**
- Modify: `crates/agentenv-core/src/lockfile.rs`
- Test: `crates/agentenv-core/tests/lockfile_security.rs`

- [ ] **Step 1: Write failing `0.2.0` lockfile parsing tests**

Add these tests to `crates/agentenv-core/tests/lockfile_security.rs`:

```rust
use agentenv_core::lockfile::{LockfileDocument, PortableLockfile};

#[test]
fn lockfile_security_parses_portable_v2_document() {
    let yaml = r#"
version: 0.2.0
driver_protocol_version: "1.0"
name: demo
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
composition:
  version: 0.1.0
  min_agentenv_version: 0.0.1-alpha0
  sandbox:
    driver: openshell
    version: 0.0.1-alpha0
  agent:
    driver: codex
    version: 0.0.1-alpha0
  context:
    driver: filesystem
    version: 0.0.1-alpha0
    mount: ~/projects
  inference:
    driver: passthrough
    version: 0.0.1-alpha0
  policy:
    tier: balanced
    presets:
      - github_read
  state:
    persist_home: true
policy:
  declared:
    tier: balanced
    presets:
      - github_read
    overrides: []
  resolved:
    network:
      reloadability: hot_reload
    filesystem:
      reloadability: locked_at_create
      read_only:
        - /usr
      read_write:
        - /sandbox
    process:
      reloadability: locked_at_create
      run_as_user: sandbox
      run_as_group: sandbox
      profile: balanced
    inference:
      reloadability: hot_reload
drivers:
  sandbox:
    kind: sandbox
    name: openshell
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  agent:
    kind: agent
    name: codex
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  context:
    kind: context
    name: filesystem
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  inference:
    kind: inference
    name: passthrough
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
credentials:
  OPENAI_API_KEY:
    source: env
    reference: OPENAI_API_KEY
    required: true
"#;

    let document = LockfileDocument::from_yaml(yaml).unwrap();
    let LockfileDocument::Portable(lockfile) = document else {
        panic!("expected portable lockfile");
    };

    assert_eq!(lockfile.version, "0.2.0");
    assert_eq!(lockfile.driver_protocol_version, "1.0");
    assert_eq!(lockfile.name, "demo");
    assert_eq!(lockfile.drivers["sandbox"].source.as_str(), "built-in");
}

#[test]
fn lockfile_security_portable_v2_rejects_credential_value_fields() {
    let yaml = r#"
version: 0.2.0
driver_protocol_version: "1.0"
name: demo
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
composition:
  version: 0.1.0
  min_agentenv_version: 0.0.1-alpha0
  sandbox:
    driver: openshell
    version: 0.0.1-alpha0
  agent:
    driver: codex
    version: 0.0.1-alpha0
  context:
    driver: filesystem
    version: 0.0.1-alpha0
  policy:
    tier: restricted
    presets: []
policy:
  declared:
    tier: restricted
    presets: []
    overrides: []
  resolved:
    network:
      reloadability: hot_reload
    filesystem:
      reloadability: locked_at_create
    process:
      reloadability: locked_at_create
      run_as_user: sandbox
      run_as_group: sandbox
      profile: restricted
    inference:
      reloadability: hot_reload
drivers:
  sandbox:
    kind: sandbox
    name: openshell
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  agent:
    kind: agent
    name: codex
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  context:
    kind: context
    name: filesystem
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
credentials:
  OPENAI_API_KEY:
    source: env
    reference: OPENAI_API_KEY
    value: sk-known-secret
"#;

    let error = LockfileDocument::from_yaml(yaml).unwrap_err();
    assert!(error.to_string().contains("value"), "error was {error}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test lockfile_security lockfile_security
```

Expected: FAIL with unresolved imports for `LockfileDocument` and `PortableLockfile`.

- [ ] **Step 3: Implement the minimal `0.2.0` data model**

Add these public types and parser helpers to `crates/agentenv-core/src/lockfile.rs`, preserving the existing `Lockfile` type:

```rust
use agentenv_proto::NetworkPolicy;
use serde_yaml::Value;

const PORTABLE_LOCKFILE_VERSION: &str = "0.2.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockfileDocument {
    Legacy(Lockfile),
    Portable(PortableLockfile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableLockfile {
    pub version: String,
    pub driver_protocol_version: String,
    pub name: String,
    pub blueprint_hash: String,
    pub composition: PortableComposition,
    pub policy: PortablePolicy,
    pub drivers: BTreeMap<String, PortableDriverPin>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifacts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableComposition {
    pub version: String,
    pub min_agentenv_version: String,
    pub sandbox: PortableComponent,
    pub agent: PortableComponent,
    pub context: PortableComponent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<PortableComponent>,
    pub policy: crate::blueprint::PolicySection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<crate::blueprint::StateSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableComponent {
    pub driver: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePolicy {
    pub declared: crate::blueprint::PolicySection,
    pub resolved: NetworkPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableDriverPin {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub source: DriverSourcePin,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverSourcePin {
    BuiltIn,
    Installed,
    Override,
}

impl DriverSourcePin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::Installed => "installed",
            Self::Override => "override",
        }
    }
}

impl LockfileDocument {
    pub fn from_yaml(yaml: &str) -> Result<Self, LockfileError> {
        let value: Value = serde_yaml::from_str(yaml).map_err(LockfileError::Deserialize)?;
        let version = value
            .as_mapping()
            .and_then(|map| map.get(Value::String("version".to_owned())))
            .and_then(Value::as_str)
            .ok_or_else(|| LockfileError::UnsupportedVersion {
                version: "<missing>".to_owned(),
            })?;

        match version {
            SUPPORTED_LOCKFILE_VERSION => Ok(Self::Legacy(Lockfile::from_yaml(yaml)?)),
            PORTABLE_LOCKFILE_VERSION => {
                let lockfile: PortableLockfile =
                    serde_yaml::from_value(value).map_err(LockfileError::Deserialize)?;
                lockfile.validate()?;
                Ok(Self::Portable(lockfile))
            }
            other => Err(LockfileError::UnsupportedVersion {
                version: other.to_owned(),
            }),
        }
    }
}

impl PortableLockfile {
    pub fn to_yaml_deterministic(&self) -> Result<String, LockfileError> {
        self.validate()?;
        serde_yaml::to_string(self).map_err(LockfileError::Serialize)
    }

    pub fn validate(&self) -> Result<(), LockfileError> {
        if self.version != PORTABLE_LOCKFILE_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                version: self.version.clone(),
            });
        }
        parse_sha256_hex(&self.blueprint_hash)
            .map_err(|source| LockfileError::InvalidBlueprintHash { source })?;
        for role in ["sandbox", "agent", "context"] {
            if !self.drivers.contains_key(role) {
                return Err(LockfileError::MissingRequiredDriverPin {
                    role: role.to_owned(),
                });
            }
        }
        for (name, artifact) in &self.artifacts {
            parse_sha256_digest(artifact).map_err(|source| {
                LockfileError::InvalidArtifactDigest {
                    name: name.clone(),
                    source,
                }
            })?;
        }
        for (role, driver) in &self.drivers {
            parse_sha256_digest(&driver.digest).map_err(|source| {
                LockfileError::InvalidArtifactDigest {
                    name: format!("{role}-driver"),
                    source,
                }
            })?;
        }
        validate_credentials(&self.credentials)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core --test lockfile_security lockfile_security
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/lockfile.rs crates/agentenv-core/tests/lockfile_security.rs
git commit -m "feat: add portable lockfile model"
```

## Task 2: Add Deterministic Driver Artifact Digests

**Files:**
- Create: `crates/agentenv-core/src/driver_artifact.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Test: `crates/agentenv-core/tests/driver_artifact.rs`

- [ ] **Step 1: Write failing artifact digest tests**

Create `crates/agentenv-core/tests/driver_artifact.rs`:

```rust
use std::fs;

use agentenv_core::driver_artifact::{
    digest_driver_root, discover_driver_artifacts, DriverArtifactError,
};
use agentenv_core::driver_catalog::{DriverDiscoveryConfig, DriverSource};
use agentenv_core::registry::DriverKind;

#[test]
fn driver_root_digest_is_stable_across_file_creation_order() {
    let left = tempfile_dir("driver-root-left");
    let right = tempfile_dir("driver-root-right");
    write_file(&left, "manifest.json", "{}\n");
    write_file(&left, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(&right, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(&right, "manifest.json", "{}\n");

    let left_digest = digest_driver_root(&left).unwrap();
    let right_digest = digest_driver_root(&right).unwrap();

    assert_eq!(left_digest, right_digest);
    assert!(left_digest.starts_with("sha256:"));
}

#[test]
fn driver_root_digest_hashes_symlink_metadata_without_following() {
    let root = tempfile_dir("driver-root-symlink");
    write_file(&root, "manifest.json", "{}\n");
    write_file(&root, "bin/driver", "#!/bin/sh\nexit 0\n");
    #[cfg(unix)]
    std::os::unix::fs::symlink("../outside", root.join("bin/link")).unwrap();

    let digest = digest_driver_root(&root).unwrap();

    assert!(digest.starts_with("sha256:"));
}

#[test]
fn discover_driver_artifacts_includes_installed_subprocess_digest() {
    let installed = tempfile_dir("installed-drivers");
    let root = installed.join("context-demo");
    write_file(&root, "bin/driver", "#!/bin/sh\nexit 0\n");
    write_file(
        &root,
        "manifest.json",
        r#"{
          "schema_version": "1.0",
          "name": "demo-context",
          "kind": "context",
          "version": "1.2.3",
          "binary": "./bin/driver"
        }"#,
    );

    let artifacts = discover_driver_artifacts(
        DriverDiscoveryConfig::new(installed, Vec::new()),
        Some(root.join("agentenv-test-binary")),
    )
    .unwrap();

    let artifact = artifacts
        .iter()
        .find(|item| item.kind == DriverKind::Context && item.name == "demo-context")
        .expect("missing demo-context artifact");
    assert_eq!(artifact.version.to_string(), "1.2.3");
    assert_eq!(artifact.source, DriverSource::InstalledSubprocess);
    assert!(artifact.digest.starts_with("sha256:"));
}

fn tempfile_dir(prefix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_file(root: &std::path::Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test driver_artifact
```

Expected: FAIL because `driver_artifact` module does not exist.

- [ ] **Step 3: Implement artifact resolver and root digest**

Create `crates/agentenv-core/src/driver_artifact.rs` with this public surface. Implement `digest_driver_root` by collecting every directory entry under `root`, sorting by normalized relative path, hashing an entry marker plus relative path for each entry, hashing regular-file bytes in fixed-size chunks, and hashing symlink targets from `read_link` without following them:

```rust
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use semver::Version;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    digest::sha256_hex,
    driver_catalog::{DriverCatalog, DriverDiscoveryConfig, DriverSource},
    registry::DriverKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverArtifact {
    pub kind: DriverKind,
    pub name: String,
    pub version: Version,
    pub source: DriverSource,
    pub digest: String,
    pub install_hint: Option<String>,
}

#[derive(Debug, Error)]
pub enum DriverArtifactError {
    #[error(transparent)]
    Discovery(#[from] crate::driver_catalog::DriverDiscoveryError),
    #[error("failed to read driver artifact `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to locate current agentenv executable: {source}")]
    CurrentExe {
        #[source]
        source: std::io::Error,
    },
    #[error("driver artifact path `{path}` is not under root `{root}`")]
    PathEscapesRoot { root: PathBuf, path: PathBuf },
}

pub fn discover_driver_artifacts(
    config: DriverDiscoveryConfig,
    built_in_binary: Option<PathBuf>,
) -> Result<Vec<DriverArtifact>, DriverArtifactError> {
    let catalog = DriverCatalog::discover(config)?;
    let built_in_path = match built_in_binary {
        Some(path) => path,
        None => std::env::current_exe()
            .map_err(|source| DriverArtifactError::CurrentExe { source })?,
    };
    let built_in_digest = digest_file(&built_in_path)?;

    let mut artifacts = Vec::new();
    for entry in catalog.entries {
        let digest = match entry.source {
            DriverSource::BuiltIn => built_in_digest.clone(),
            DriverSource::InstalledSubprocess | DriverSource::DevelopmentOverride => {
                let manifest = entry.manifest_path.as_ref().ok_or_else(|| {
                    DriverArtifactError::Io {
                        path: PathBuf::from("<missing manifest>"),
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "missing manifest path",
                        ),
                    }
                })?;
                let root = manifest.parent().unwrap_or_else(|| Path::new("."));
                digest_driver_root(root)?
            }
        };
        artifacts.push(DriverArtifact {
            kind: entry.kind,
            name: entry.name,
            version: entry.version,
            source: entry.source,
            digest,
            install_hint: None,
        });
    }
    artifacts.sort_by(|left, right| {
        (&left.kind, &left.name, &left.version, left.source)
            .cmp(&(&right.kind, &right.name, &right.version, right.source))
    });
    Ok(artifacts)
}

pub fn digest_driver_root(root: &Path) -> Result<String, DriverArtifactError> {
    let mut entries = Vec::new();
    collect_entries(root, root, &mut entries)?;
    entries.sort();

    let mut hasher = Sha256::new();
    for relative in entries {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).map_err(|source| DriverArtifactError::Io {
            path: path.clone(),
            source,
        })?;
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        if metadata.file_type().is_symlink() {
            hasher.update(b"symlink");
            hasher.update([0]);
            let target = fs::read_link(&path).map_err(|source| DriverArtifactError::Io {
                path: path.clone(),
                source,
            })?;
            hasher.update(target.to_string_lossy().as_bytes());
        } else if metadata.is_file() {
            hasher.update(b"file");
            hasher.update([0]);
            let mut file = fs::File::open(&path).map_err(|source| DriverArtifactError::Io {
                path: path.clone(),
                source,
            })?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|source| DriverArtifactError::Io {
                path: path.clone(),
                source,
            })?;
            hasher.update(bytes);
        }
        hasher.update([0]);
    }

    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn digest_file(path: &Path) -> Result<String, DriverArtifactError> {
    let bytes = fs::read(path).map_err(|source| DriverArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

fn collect_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<String>,
) -> Result<(), DriverArtifactError> {
    for entry in fs::read_dir(current).map_err(|source| DriverArtifactError::Io {
        path: current.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| DriverArtifactError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| DriverArtifactError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            collect_entries(root, &path, entries)?;
            continue;
        }
        if metadata.is_file() || metadata.file_type().is_symlink() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| DriverArtifactError::PathEscapesRoot {
                    root: root.to_path_buf(),
                    path: path.clone(),
                })?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push(relative);
        }
    }
    Ok(())
}
```

Add `pub mod driver_artifact;` to `crates/agentenv-core/src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core --test driver_artifact
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/driver_artifact.rs crates/agentenv-core/src/lib.rs crates/agentenv-core/tests/driver_artifact.rs
git commit -m "feat: verify local driver artifacts"
```

## Task 3: Build Portable Lockfiles From Blueprints And Env State

**Files:**
- Modify: `crates/agentenv-core/src/lifecycle.rs`
- Create: `crates/agentenv-core/src/portable_lockfile.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Test: `crates/agentenv-core/tests/portable_lockfile.rs`

- [ ] **Step 1: Write failing portable lockfile builder tests**

Create `crates/agentenv-core/tests/portable_lockfile.rs`:

```rust
use agentenv_core::{
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    lockfile::{DriverSourcePin, LockfileDocument},
    portable_lockfile::{build_portable_lockfile_from_blueprint, PortableLockfileInput},
    registry::DriverKind,
};
use semver::Version;

#[test]
fn portable_lockfile_builder_is_byte_identical_for_repeated_calls() {
    let yaml = reference_yaml();
    let artifacts = built_in_artifacts();
    let input = PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: yaml.clone(),
        driver_artifacts: artifacts.clone(),
    };

    let first = build_portable_lockfile_from_blueprint(input.clone())
        .unwrap()
        .to_yaml_deterministic()
        .unwrap();
    let second = build_portable_lockfile_from_blueprint(input)
        .unwrap()
        .to_yaml_deterministic()
        .unwrap();

    assert_eq!(first, second);
    assert!(first.contains("version: 0.2.0"));
    assert!(first.contains("driver_protocol_version: '1.0'") || first.contains("driver_protocol_version: \"1.0\""));
    assert!(!first.contains("sk-known-secret"));
}

#[test]
fn portable_lockfile_builder_records_resolved_policy_and_driver_sources() {
    let lockfile = build_portable_lockfile_from_blueprint(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .unwrap();

    assert_eq!(lockfile.policy.declared.tier, "balanced");
    assert!(!lockfile.policy.resolved.filesystem.read_write.is_empty());
    assert_eq!(lockfile.drivers["agent"].source, DriverSourcePin::BuiltIn);
    assert_eq!(lockfile.credentials["OPENAI_API_KEY"].reference.as_deref(), Some("OPENAI_API_KEY"));
}

#[test]
fn portable_lockfile_document_round_trips_builder_output() {
    let rendered = build_portable_lockfile_from_blueprint(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .unwrap()
    .to_yaml_deterministic()
    .unwrap();

    let parsed = LockfileDocument::from_yaml(&rendered).unwrap();
    assert!(matches!(parsed, LockfileDocument::Portable(_)));
}

fn reference_yaml() -> String {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
      note: sk-known-secret
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets:
    - github_read
state:
  persist_home: true
"#
    .to_owned()
}

fn built_in_artifacts() -> Vec<DriverArtifact> {
    let version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    [
        (DriverKind::Sandbox, "openshell"),
        (DriverKind::Agent, "codex"),
        (DriverKind::Context, "filesystem"),
        (DriverKind::Inference, "passthrough"),
    ]
    .into_iter()
    .map(|(kind, name)| DriverArtifact {
        kind,
        name: name.to_owned(),
        version: version.clone(),
        source: DriverSource::BuiltIn,
        digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        install_hint: None,
    })
    .collect()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile
```

Expected: FAIL because `portable_lockfile` module does not exist.

- [ ] **Step 3: Expose canonical composition helpers**

In `crates/agentenv-core/src/lifecycle.rs`, make these functions public within the crate:

```rust
pub(crate) fn portable_canonical_blueprint(
    resolved: &ResolvedBlueprint,
) -> Result<crate::lockfile::PortableComposition, LifecycleError> {
    let canonical = canonical_blueprint(resolved)?;
    Ok(crate::lockfile::PortableComposition {
        version: canonical.version,
        min_agentenv_version: canonical.min_agentenv_version,
        sandbox: portable_component(canonical.sandbox),
        agent: portable_component(canonical.agent),
        context: portable_component(canonical.context),
        inference: canonical.inference.map(portable_component),
        policy: canonical.policy,
        state: canonical.state,
    })
}

pub(crate) fn portable_blueprint_hash(
    composition: &crate::lockfile::PortableComposition,
) -> Result<String, LifecycleError> {
    let value = serde_yaml::to_value(composition)
        .map_err(LifecycleError::CanonicalBlueprintSerialize)?;
    let rendered = serde_yaml::to_string(&canonicalize_yaml_value(value))
        .map_err(LifecycleError::CanonicalBlueprintSerialize)?;
    Ok(crate::digest::sha256_hex(rendered.as_bytes()))
}

fn portable_component(
    component: CanonicalComponent,
) -> crate::lockfile::PortableComponent {
    crate::lockfile::PortableComponent {
        driver: component.driver,
        version: component.version,
        credentials: component.credentials,
        extra: component.extra,
    }
}
```

- [ ] **Step 4: Implement portable lockfile builder**

Create `crates/agentenv-core/src/portable_lockfile.rs`:

```rust
use std::collections::BTreeMap;

use agentenv_policy::{compose_policy, PresetRegistry, PresetSelection, Tier};
use agentenv_proto::SCHEMA_VERSION;
use thiserror::Error;

use crate::{
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    lifecycle::{portable_blueprint_hash, portable_canonical_blueprint, verify_blueprint_yaml},
    lockfile::{
        CredentialRef, DriverSourcePin, PortableDriverPin, PortableLockfile, PortablePolicy,
    },
    registry::DriverKind,
};

#[derive(Debug, Clone)]
pub struct PortableLockfileInput {
    pub name: String,
    pub blueprint_yaml: String,
    pub driver_artifacts: Vec<DriverArtifact>,
}

#[derive(Debug, Error)]
pub enum PortableLockfileError {
    #[error(transparent)]
    Lifecycle(#[from] crate::lifecycle::LifecycleError),
    #[error(transparent)]
    Policy(#[from] agentenv_policy::PolicyError),
    #[error("missing artifact for {kind} driver `{name}` version `{version}`")]
    MissingDriverArtifact {
        kind: DriverKind,
        name: String,
        version: String,
    },
}

pub fn build_portable_lockfile_from_blueprint(
    input: PortableLockfileInput,
) -> Result<PortableLockfile, PortableLockfileError> {
    let resolved = verify_blueprint_yaml(&input.blueprint_yaml)?;
    let composition = portable_canonical_blueprint(&resolved)?;
    let blueprint_hash = portable_blueprint_hash(&composition)?;
    let policy = PortablePolicy {
        declared: composition.policy.clone(),
        resolved: compose_policy(
            parse_tier(&composition.policy.tier)?,
            &parse_presets(&composition.policy.presets)?,
            None,
            &PresetRegistry::load_builtin()?,
        )?,
    };
    let credentials = collect_portable_credentials(&composition);
    let artifacts = crate::lifecycle::freeze_from_blueprint_yaml(&input.blueprint_yaml)
        .and_then(|yaml| crate::lockfile::Lockfile::from_yaml(&yaml).map_err(Into::into))?
        .artifacts;

    Ok(PortableLockfile {
        version: "0.2.0".to_owned(),
        driver_protocol_version: SCHEMA_VERSION.to_owned(),
        name: input.name,
        blueprint_hash,
        composition,
        policy,
        drivers: driver_pins(&resolved, &input.driver_artifacts)?,
        artifacts,
        credentials,
    })
}

fn driver_pins(
    resolved: &crate::lifecycle::ResolvedBlueprint,
    artifacts: &[DriverArtifact],
) -> Result<BTreeMap<String, PortableDriverPin>, PortableLockfileError> {
    let mut pins = BTreeMap::new();
    insert_driver_pin(&mut pins, "sandbox", &resolved.sandbox, artifacts)?;
    insert_driver_pin(&mut pins, "agent", &resolved.agent, artifacts)?;
    insert_driver_pin(&mut pins, "context", &resolved.context, artifacts)?;
    if let Some(inference) = &resolved.inference {
        insert_driver_pin(&mut pins, "inference", inference, artifacts)?;
    }
    Ok(pins)
}

fn insert_driver_pin(
    pins: &mut BTreeMap<String, PortableDriverPin>,
    role: &str,
    component: &crate::lifecycle::ResolvedComponent,
    artifacts: &[DriverArtifact],
) -> Result<(), PortableLockfileError> {
    let artifact = artifacts
        .iter()
        .find(|item| {
            item.kind == component.kind
                && item.name == component.driver
                && item.version == component.version
        })
        .ok_or_else(|| PortableLockfileError::MissingDriverArtifact {
            kind: component.kind,
            name: component.driver.clone(),
            version: component.version.to_string(),
        })?;
    pins.insert(
        role.to_owned(),
        PortableDriverPin {
            kind: component.kind.to_string(),
            name: component.driver.clone(),
            version: component.version.to_string(),
            source: source_pin(artifact.source),
            digest: artifact.digest.clone(),
        },
    );
    Ok(())
}

fn source_pin(source: DriverSource) -> DriverSourcePin {
    match source {
        DriverSource::BuiltIn => DriverSourcePin::BuiltIn,
        DriverSource::InstalledSubprocess => DriverSourcePin::Installed,
        DriverSource::DevelopmentOverride => DriverSourcePin::Override,
    }
}

fn collect_portable_credentials(
    composition: &crate::lockfile::PortableComposition,
) -> BTreeMap<String, CredentialRef> {
    let mut credentials = BTreeMap::new();
    credentials.extend(composition.sandbox.credentials.clone());
    credentials.extend(composition.agent.credentials.clone());
    credentials.extend(composition.context.credentials.clone());
    if let Some(inference) = &composition.inference {
        credentials.extend(inference.credentials.clone());
    }
    credentials
}

fn parse_tier(value: &str) -> Result<Tier, agentenv_policy::PolicyError> {
    match value {
        "restricted" => Ok(Tier::Restricted),
        "balanced" => Ok(Tier::Balanced),
        "open" => Ok(Tier::Open),
        other => Err(agentenv_policy::PolicyError::PresetRegistry {
            message: format!("unknown policy tier `{other}`"),
        }),
    }
}

fn parse_presets(values: &[String]) -> Result<Vec<PresetSelection>, agentenv_policy::PolicyError> {
    values
        .iter()
        .map(|value| PresetSelection::from_slug(value))
        .collect()
}
```

Add `pub mod portable_lockfile;` to `crates/agentenv-core/src/lib.rs`.

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-core/src/lifecycle.rs crates/agentenv-core/src/lib.rs crates/agentenv-core/src/portable_lockfile.rs crates/agentenv-core/tests/portable_lockfile.rs
git commit -m "feat: build portable lockfiles"
```

## Task 4: Add Portable Lockfile Verification

**Files:**
- Modify: `crates/agentenv-core/src/portable_lockfile.rs`
- Test: `crates/agentenv-core/tests/portable_lockfile.rs`

- [ ] **Step 1: Write failing verification tests**

Append these tests to `crates/agentenv-core/tests/portable_lockfile.rs`:

```rust
use agentenv_core::portable_lockfile::{
    verify_portable_lockfile_yaml, PortableVerifyIssueKind,
};

#[test]
fn verify_reports_missing_driver_artifact() {
    let rendered = build_portable_lockfile_from_blueprint(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: built_in_artifacts(),
    })
    .unwrap()
    .to_yaml_deterministic()
    .unwrap();

    let report = verify_portable_lockfile_yaml(&rendered, &[]).unwrap();

    assert!(report
        .errors
        .iter()
        .any(|issue| issue.kind == PortableVerifyIssueKind::MissingDriver));
}

#[test]
fn verify_reports_driver_digest_mismatch() {
    let mut artifacts = built_in_artifacts();
    let rendered = build_portable_lockfile_from_blueprint(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: artifacts.clone(),
    })
    .unwrap()
    .to_yaml_deterministic()
    .unwrap();
    artifacts[0].digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();

    let report = verify_portable_lockfile_yaml(&rendered, &artifacts).unwrap();

    assert!(report
        .errors
        .iter()
        .any(|issue| issue.kind == PortableVerifyIssueKind::DriverDigestMismatch));
}

#[test]
fn verify_accepts_matching_portable_lockfile() {
    let artifacts = built_in_artifacts();
    let rendered = build_portable_lockfile_from_blueprint(PortableLockfileInput {
        name: "demo".to_owned(),
        blueprint_yaml: reference_yaml(),
        driver_artifacts: artifacts.clone(),
    })
    .unwrap()
    .to_yaml_deterministic()
    .unwrap();

    let report = verify_portable_lockfile_yaml(&rendered, &artifacts).unwrap();

    assert!(report.errors.is_empty(), "report was {report:?}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile verify_
```

Expected: FAIL because verification types/functions do not exist.

- [ ] **Step 3: Implement structured verification**

Add to `crates/agentenv-core/src/portable_lockfile.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableVerifyReport {
    pub errors: Vec<PortableVerifyIssue>,
    pub warnings: Vec<PortableVerifyIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableVerifyIssue {
    pub kind: PortableVerifyIssueKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortableVerifyIssueKind {
    MissingDriver,
    DriverDigestMismatch,
    BlueprintHashMismatch,
    PolicyDrift,
}

pub fn verify_portable_lockfile_yaml(
    yaml: &str,
    artifacts: &[DriverArtifact],
) -> Result<PortableVerifyReport, crate::lockfile::LockfileError> {
    let document = crate::lockfile::LockfileDocument::from_yaml(yaml)?;
    let crate::lockfile::LockfileDocument::Portable(lockfile) = document else {
        return Ok(PortableVerifyReport {
            errors: Vec::new(),
            warnings: vec![PortableVerifyIssue {
                kind: PortableVerifyIssueKind::PolicyDrift,
                message: "legacy 0.1.0 lockfile is not self-contained for reproduction".to_owned(),
            }],
        });
    };

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    match portable_blueprint_hash(&lockfile.composition) {
        Ok(hash) if hash == lockfile.blueprint_hash => {}
        Ok(hash) => errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::BlueprintHashMismatch,
            message: format!(
                "blueprint hash mismatch: lockfile has `{}`, recomputed `{hash}`",
                lockfile.blueprint_hash
            ),
        }),
        Err(error) => errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::BlueprintHashMismatch,
            message: error.to_string(),
        }),
    }

    for (role, pin) in &lockfile.drivers {
        let matching = artifacts.iter().find(|artifact| {
            artifact.kind.to_string() == pin.kind
                && artifact.name == pin.name
                && artifact.version.to_string() == pin.version
        });
        let Some(artifact) = matching else {
            errors.push(PortableVerifyIssue {
                kind: PortableVerifyIssueKind::MissingDriver,
                message: format!(
                    "missing {} driver `{}` version `{}` for role `{role}`",
                    pin.kind, pin.name, pin.version
                ),
            });
            continue;
        };
        if artifact.digest != pin.digest {
            errors.push(PortableVerifyIssue {
                kind: PortableVerifyIssueKind::DriverDigestMismatch,
                message: format!(
                    "digest mismatch for {} driver `{}` version `{}`",
                    pin.kind, pin.name, pin.version
                ),
            });
        }
    }

    let current_policy = match (
        parse_tier(&lockfile.policy.declared.tier),
        parse_presets(&lockfile.policy.declared.presets),
        PresetRegistry::load_builtin(),
    ) {
        (Ok(tier), Ok(presets), Ok(registry)) => {
            compose_policy(tier, &presets, None, &registry).ok()
        }
        _ => None,
    };
    if let Some(current_policy) = current_policy {
        if current_policy != lockfile.policy.resolved {
            warnings.push(PortableVerifyIssue {
                kind: PortableVerifyIssueKind::PolicyDrift,
                message: "current policy presets differ from pinned resolved policy".to_owned(),
            });
        }
    }

    Ok(PortableVerifyReport { errors, warnings })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/portable_lockfile.rs crates/agentenv-core/tests/portable_lockfile.rs
git commit -m "feat: verify portable lockfiles"
```

## Task 5: Add Runtime Freeze Entry Point Over Persisted Env State

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`
- Test: `crates/agentenv-core/tests/runtime_freeze.rs`

- [ ] **Step 1: Write failing runtime freeze test**

Create `crates/agentenv-core/tests/runtime_freeze.rs`:

```rust
use std::fs;

use agentenv_core::{
    env::{DriverHandles, DriverRecord, EndpointState, EnvPaths, EnvPhase, EnvStateFile, StateDriverSet, STATE_VERSION},
    runtime::{freeze_env_lockfile, RuntimeOptions},
};
use agentenv_proto::LogLevel;

#[test]
fn runtime_freeze_reads_persisted_env_and_returns_portable_lockfile() {
    let root = tempfile_dir("runtime-freeze");
    let env_name = agentenv_core::env::validate_env_name("demo").unwrap();
    let paths = EnvPaths::new(root.join(".agentenv"), env_name);
    fs::create_dir_all(paths.env_dir()).unwrap();
    fs::write(paths.blueprint_path(), blueprint_yaml()).unwrap();
    fs::write(paths.lock_path(), "version: 0.1.0\nprotocol_version: '0.1'\nblueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736\ndrivers:\n  sandbox:\n    name: openshell\n    version: 0.0.1-alpha0\n  agent:\n    name: codex\n    version: 0.0.1-alpha0\n  context:\n    name: filesystem\n    version: 0.0.1-alpha0\n").unwrap();
    agentenv_core::env::write_state(&paths, &state_file("demo")).unwrap();

    let rendered = freeze_env_lockfile(
        &RuntimeOptions {
            root: root.join(".agentenv"),
            log_level: LogLevel::Info,
            non_interactive: true,
        },
        "demo",
    )
    .unwrap();

    assert!(rendered.contains("version: 0.2.0"));
    assert!(rendered.contains("name: demo"));
    assert!(!rendered.contains("sk-known-secret"));
}

fn blueprint_yaml() -> &'static str {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
      note: sk-known-secret
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#
}

fn state_file(name: &str) -> EnvStateFile {
    EnvStateFile {
        version: STATE_VERSION.to_owned(),
        name: name.to_owned(),
        phase: EnvPhase::Running,
        created_at: "2026-04-23T00:00:00Z".to_owned(),
        updated_at: "2026-04-23T00:00:00Z".to_owned(),
        drivers: StateDriverSet {
            sandbox: DriverRecord::new("openshell", env!("CARGO_PKG_VERSION")),
            agent: DriverRecord::new("codex", env!("CARGO_PKG_VERSION")),
            context: DriverRecord::new("filesystem", env!("CARGO_PKG_VERSION")),
            inference: Some(DriverRecord::new("passthrough", env!("CARGO_PKG_VERSION"))),
        },
        handles: DriverHandles::default(),
        endpoints: EndpointState::default(),
        credential_names: vec!["OPENAI_API_KEY".to_owned()],
        health: Default::default(),
        first_enter_hint_shown: false,
    }
}

fn tempfile_dir(prefix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p agentenv-core --test runtime_freeze
```

Expected: FAIL because `freeze_env_lockfile` does not exist.

- [ ] **Step 3: Implement runtime freeze**

Add to `crates/agentenv-core/src/runtime.rs`:

```rust
pub fn freeze_env_lockfile(options: &RuntimeOptions, name: &str) -> RuntimeResult<String> {
    let description = describe_env(options, name)?;
    let artifacts = crate::driver_artifact::discover_driver_artifacts(
        crate::driver_catalog::DriverDiscoveryConfig::from_env(),
        None,
    )
    .map_err(|error| {
        RuntimeError::Driver(crate::driver::DriverError::Subprocess {
            driver: "driver-artifacts".to_owned(),
            message: error.to_string(),
        })
    })?;
    let lockfile = crate::portable_lockfile::build_portable_lockfile_from_blueprint(
        crate::portable_lockfile::PortableLockfileInput {
            name: description.state.name,
            blueprint_yaml: description.blueprint_yaml,
            driver_artifacts: artifacts,
        },
    )
    .map_err(|error| {
        RuntimeError::Driver(crate::driver::DriverError::InvalidInput {
            message: error.to_string(),
        })
    })?;
    lockfile.to_yaml_deterministic().map_err(|error| {
        RuntimeError::Driver(crate::driver::DriverError::InvalidInput {
            message: error.to_string(),
        })
    })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cargo test -p agentenv-core --test runtime_freeze
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/runtime.rs crates/agentenv-core/tests/runtime_freeze.rs
git commit -m "feat: freeze persisted env lockfiles"
```

## Task 6: Update CLI Freeze And Add Verify Command

**Files:**
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI tests for new freeze and verify shape**

Modify `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn freeze_defaults_to_agentenv_lock_for_existing_env() {
    let temp_dir = make_temp_dir("freeze-default-agentenv-lock");
    write_minimal_env_state(&temp_dir, "demo");
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("blueprint.yaml"),
        minimal_blueprint(),
    )
    .unwrap();
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("lock.yaml"),
        minimal_legacy_lock(),
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr was: {}", String::from_utf8_lossy(&output.stderr));
    let lockfile = temp_dir.join("agentenv.lock");
    assert!(lockfile.is_file());
    assert!(fs::read_to_string(lockfile).unwrap().contains("version: 0.2.0"));
}

#[test]
fn freeze_output_dash_prints_lockfile_to_stdout() {
    let temp_dir = make_temp_dir("freeze-output-dash");
    write_minimal_env_state(&temp_dir, "demo");
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("blueprint.yaml"),
        minimal_blueprint(),
    )
    .unwrap();
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("lock.yaml"),
        minimal_legacy_lock(),
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--output")
        .arg("-")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr was: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("version: 0.2.0"));
    assert!(!temp_dir.join("-").exists());
}

#[test]
fn verify_command_accepts_generated_lockfile() {
    let temp_dir = make_temp_dir("verify-generated-lockfile");
    write_minimal_env_state(&temp_dir, "demo");
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("blueprint.yaml"),
        minimal_blueprint(),
    )
    .unwrap();
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("lock.yaml"),
        minimal_legacy_lock(),
    )
    .unwrap();
    let lockfile = temp_dir.join("agentenv.lock");
    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--output")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(freeze.status.success(), "stderr was: {}", String::from_utf8_lossy(&freeze.stderr));

    let verify = Command::new(agentenv_bin())
        .arg("verify")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(verify.status.success(), "stderr was: {}", String::from_utf8_lossy(&verify.stderr));
    assert!(String::from_utf8_lossy(&verify.stdout).contains("Lockfile verified"));
}

fn minimal_blueprint() -> &'static str {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#
}

fn minimal_legacy_lock() -> &'static str {
    r#"
version: 0.1.0
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  sandbox:
    name: openshell
    version: 0.0.1-alpha0
  agent:
    name: codex
    version: 0.0.1-alpha0
  context:
    name: filesystem
    version: 0.0.1-alpha0
"#
}
```

Remove or rewrite old tests that expect `freeze --blueprint --out`.

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv --test cli_behavior
```

Expected: FAIL because clap still expects old freeze args and has no `verify`.

- [ ] **Step 3: Update clap commands and handlers**

Modify `crates/agentenv/src/main.rs`:

```rust
#[derive(Debug, Subcommand)]
enum Commands {
    Create(CreateArgs),
    Enter(EnterArgs),
    List(ListArgs),
    Destroy(DestroyArgs),
    Describe(DescribeArgs),
    Status(StatusArgs),
    Logs(LogsArgs),
    Exec(ExecArgs),
    Credentials(CredentialsArgs),
    Drivers(DriversArgs),
    VerifyBlueprint {
        file: PathBuf,
    },
    Freeze(FreezeArgs),
    Verify {
        lockfile: PathBuf,
    },
    Reproduce(ReproduceArgs),
}

#[derive(Debug, Args)]
struct FreezeArgs {
    name: String,
    #[arg(long, value_name = "FILE", alias = "out")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ReproduceArgs {
    lockfile: PathBuf,
    #[arg(long)]
    name: Option<String>,
}
```

Update the `run` match:

```rust
Some(Commands::Freeze(args)) => freeze(args),
Some(Commands::Verify { lockfile }) => verify_lockfile(&lockfile),
Some(Commands::Reproduce(args)) => reproduce(args).await,
```

Replace the old `freeze` function:

```rust
fn freeze(args: FreezeArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let rendered = agentenv_core::runtime::freeze_env_lockfile(&options, &args.name)
        .with_context(|| format!("failed to freeze environment `{}`", args.name))?;
    match args.output.as_deref() {
        Some(path) if path == Path::new("-") => {
            print!("{rendered}");
        }
        Some(path) => {
            fs::write(path, rendered)
                .with_context(|| format!("failed to write lockfile `{}`", path.display()))?;
            println!("Lockfile written: {}", path.display());
        }
        None => {
            let path = Path::new("agentenv.lock");
            fs::write(path, rendered)
                .with_context(|| format!("failed to write lockfile `{}`", path.display()))?;
            println!("Lockfile written: {}", path.display());
        }
    }
    Ok(())
}

fn verify_lockfile(path: &Path) -> Result<()> {
    let yaml = read_text_file(path, "lockfile")?;
    let artifacts = agentenv_core::driver_artifact::discover_driver_artifacts(
        agentenv_core::driver_catalog::DriverDiscoveryConfig::from_env(),
        None,
    )
    .context("discover local driver artifacts")?;
    let report = agentenv_core::portable_lockfile::verify_portable_lockfile_yaml(&yaml, &artifacts)
        .with_context(|| format!("failed to verify lockfile `{}`", path.display()))?;
    if !report.errors.is_empty() {
        for issue in report.errors {
            eprintln!("error: {}", issue.message);
        }
        bail!("lockfile verification failed");
    }
    for issue in report.warnings {
        eprintln!("warning: {}", issue.message);
    }
    println!("Lockfile verified: {}", path.display());
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv --test cli_behavior
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/src/main.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: add lockfile freeze and verify CLI"
```

## Task 7: Add Reproduce Runtime And CLI Path

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing reproduce CLI test**

Add to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn reproduce_name_override_rejects_missing_required_env_credential_before_create() {
    let temp_dir = make_temp_dir("reproduce-missing-env-credential");
    write_minimal_env_state(&temp_dir, "source");
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("source").join("blueprint.yaml"),
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#,
    )
    .unwrap();
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("source").join("lock.yaml"),
        minimal_legacy_lock(),
    )
    .unwrap();
    let lockfile = temp_dir.join("agentenv.lock");
    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("source")
        .arg("--output")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(freeze.status.success(), "stderr was: {}", String::from_utf8_lossy(&freeze.stderr));

    let reproduce = Command::new(agentenv_bin())
        .arg("reproduce")
        .arg(&lockfile)
        .arg("--name")
        .arg("copy")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .env_remove("OPENAI_API_KEY")
        .output()
        .unwrap();

    assert!(!reproduce.status.success());
    assert!(String::from_utf8_lossy(&reproduce.stderr).contains("OPENAI_API_KEY"));
    assert!(!temp_dir.join(".agentenv").join("envs").join("copy").exists());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p agentenv --test cli_behavior reproduce_name_override_rejects_missing_required_env_credential_before_create
```

Expected: FAIL because `reproduce` has no `--name`/`--non-interactive` runtime path.

- [ ] **Step 3: Add core reproduce entrypoint**

In `crates/agentenv-core/src/runtime.rs`, add:

```rust
pub async fn reproduce_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    lockfile_yaml: &str,
) -> RuntimeResult<CreateResult> {
    let document = crate::lockfile::LockfileDocument::from_yaml(lockfile_yaml).map_err(|error| {
        RuntimeError::Driver(crate::driver::DriverError::InvalidInput {
            message: error.to_string(),
        })
    })?;
    let crate::lockfile::LockfileDocument::Portable(lockfile) = document else {
        return Err(RuntimeError::Driver(crate::driver::DriverError::InvalidInput {
            message: "legacy 0.1.0 lockfile requires companion blueprint; use create --reproduce with --blueprint".to_owned(),
        }));
    };
    let blueprint_yaml = serde_yaml::to_string(&lockfile.composition).map_err(|error| {
        RuntimeError::Driver(crate::driver::DriverError::InvalidInput {
            message: error.to_string(),
        })
    })?;
    create_env(options, factory, credentials, name, &blueprint_yaml).await
}
```

This first pass reuses `create_env`; Task 8 tightens it so `policy.resolved` is authoritative for reproduction.

- [ ] **Step 4: Add CLI reproduce args and handler**

In `crates/agentenv/src/main.rs`, update `ReproduceArgs` with non-interactive:

```rust
#[derive(Debug, Args)]
struct ReproduceArgs {
    lockfile: PathBuf,
    #[arg(long)]
    name: Option<String>,
    #[arg(
        long,
        env = "AGENTENV_NON_INTERACTIVE",
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    non_interactive: bool,
}
```

Replace old reproduce handler:

```rust
async fn reproduce(args: ReproduceArgs) -> Result<()> {
    let lockfile_yaml = read_text_file(&args.lockfile, "lockfile")?;
    let env_name = args
        .name
        .unwrap_or_else(|| derive_reproduced_env_name(&args.lockfile));
    let options = runtime_options(args.non_interactive)?;
    let store = CredentialStore::from_default_paths().context("initialize credential store")?;
    let mut provider = CliCredentialProvider {
        store,
        non_interactive: args.non_interactive,
        prompter: Box::new(TerminalCredentialPrompter),
    };
    let result = agentenv_core::runtime::reproduce_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &mut provider,
        &env_name,
        &lockfile_yaml,
    )
    .await
    .with_context(|| format!("failed to reproduce lockfile `{}`", args.lockfile.display()))?;
    render::print_admission_text(&result.admission);
    exit_if_rejected(&result.admission);
    println!("Next: agentenv enter {env_name}");
    Ok(())
}
```

- [ ] **Step 5: Run test to verify it passes**

Run:

```bash
cargo test -p agentenv --test cli_behavior reproduce_name_override_rejects_missing_required_env_credential_before_create
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-core/src/runtime.rs crates/agentenv/src/main.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: reproduce envs from portable lockfiles"
```

## Task 8: Make Reproduce Use Pinned Resolved Policy

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`
- Test: `crates/agentenv-core/tests/runtime_freeze.rs`

- [ ] **Step 1: Write failing pinned-policy unit test**

Add to `crates/agentenv-core/tests/runtime_freeze.rs`:

```rust
#[test]
fn runtime_reproduction_blueprint_yaml_preserves_lockfile_resolved_policy_marker() {
    let root = tempfile_dir("runtime-reproduce-policy");
    let env_name = agentenv_core::env::validate_env_name("demo").unwrap();
    let paths = EnvPaths::new(root.join(".agentenv"), env_name);
    fs::create_dir_all(paths.env_dir()).unwrap();
    fs::write(paths.blueprint_path(), blueprint_yaml()).unwrap();
    fs::write(paths.lock_path(), minimal_legacy_lock()).unwrap();
    agentenv_core::env::write_state(&paths, &state_file("demo")).unwrap();

    let rendered = freeze_env_lockfile(
        &RuntimeOptions {
            root: root.join(".agentenv"),
            log_level: LogLevel::Info,
            non_interactive: true,
        },
        "demo",
    )
    .unwrap();

    let document = agentenv_core::lockfile::LockfileDocument::from_yaml(&rendered).unwrap();
    let agentenv_core::lockfile::LockfileDocument::Portable(lockfile) = document else {
        panic!("expected portable lockfile");
    };

    assert_eq!(lockfile.policy.resolved.process.profile, "balanced");
}
```

- [ ] **Step 2: Run test to verify existing policy coverage**

Run:

```bash
cargo test -p agentenv-core --test runtime_freeze runtime_reproduction_blueprint_yaml_preserves_lockfile_resolved_policy_marker
```

Expected: PASS after Task 5; this locks the policy snapshot behavior before refactoring.

- [ ] **Step 3: Refactor runtime create into a shared input**

In `crates/agentenv-core/src/runtime.rs`, introduce:

```rust
struct MaterializeInput {
    blueprint_yaml: String,
    lock_yaml: String,
    resolved_policy: Option<agentenv_proto::NetworkPolicy>,
}
```

Refactor `create_env` so it calls:

```rust
async fn materialize_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    input: MaterializeInput,
) -> RuntimeResult<CreateResult>
```

Inside the policy block, replace direct policy composition with:

```rust
let mut policy = if let Some(policy) = input.resolved_policy.clone() {
    policy
} else {
    compose_policy(
        parse_tier(&resolved.blueprint.policy.tier)?,
        &parse_presets(&resolved.blueprint.policy.presets)?,
        policy_overrides(&resolved.blueprint.policy.overrides)?,
        &PresetRegistry::load_builtin().map_err(|err| {
            RuntimeError::Driver(crate::driver::DriverError::PolicyTranslation {
                message: err.to_string(),
            })
        })?,
    )
    .map_err(|err| {
        RuntimeError::Driver(crate::driver::DriverError::PolicyTranslation {
            message: err.to_string(),
        })
    })?
};
```

Update `reproduce_env` to pass:

```rust
MaterializeInput {
    blueprint_yaml,
    lock_yaml: lockfile_yaml.to_owned(),
    resolved_policy: Some(lockfile.policy.resolved.clone()),
}
```

Update `create_env` to pass:

```rust
MaterializeInput {
    blueprint_yaml: blueprint_yaml.to_owned(),
    lock_yaml: crate::lifecycle::freeze_from_blueprint_yaml(blueprint_yaml)?,
    resolved_policy: None,
}
```

- [ ] **Step 4: Run runtime and core tests**

Run:

```bash
cargo test -p agentenv-core --test runtime_freeze
cargo test -p agentenv-core --test portable_lockfile
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/runtime.rs crates/agentenv-core/tests/runtime_freeze.rs
git commit -m "fix: reproduce pinned resolved policy"
```

## Task 9: Add Compatibility And Security Coverage

**Files:**
- Modify: `crates/agentenv-core/tests/portable_lockfile.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write compatibility and known-secret tests**

Add to `crates/agentenv-core/tests/portable_lockfile.rs`:

```rust
#[test]
fn verify_warns_for_legacy_lockfile_without_errors() {
    let yaml = r#"
version: 0.1.0
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  sandbox:
    name: openshell
    version: 0.0.1-alpha0
  agent:
    name: codex
    version: 0.0.1-alpha0
  context:
    name: filesystem
    version: 0.0.1-alpha0
"#;

    let report = verify_portable_lockfile_yaml(yaml, &[]).unwrap();

    assert!(report.errors.is_empty());
    assert!(report
        .warnings
        .iter()
        .any(|issue| issue.message.contains("legacy 0.1.0")));
}
```

Add to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn freeze_and_verify_do_not_print_known_secret() {
    let temp_dir = make_temp_dir("freeze-verify-secret-output");
    write_minimal_env_state_with_credentials(&temp_dir, "demo", &["OPENAI_API_KEY"]);
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("blueprint.yaml"),
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
      note: sk-known-secret
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#,
    )
    .unwrap();
    fs::write(
        temp_dir.join(".agentenv").join("envs").join("demo").join("lock.yaml"),
        minimal_legacy_lock(),
    )
    .unwrap();
    let lockfile = temp_dir.join("agentenv.lock");

    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--output")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(freeze.status.success(), "stderr was: {}", String::from_utf8_lossy(&freeze.stderr));
    assert!(!String::from_utf8_lossy(&freeze.stdout).contains("sk-known-secret"));
    assert!(!String::from_utf8_lossy(&freeze.stderr).contains("sk-known-secret"));
    assert!(!fs::read_to_string(&lockfile).unwrap().contains("sk-known-secret"));

    let verify = Command::new(agentenv_bin())
        .arg("verify")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(verify.status.success(), "stderr was: {}", String::from_utf8_lossy(&verify.stderr));
    assert!(!String::from_utf8_lossy(&verify.stdout).contains("sk-known-secret"));
    assert!(!String::from_utf8_lossy(&verify.stderr).contains("sk-known-secret"));
}
```

- [ ] **Step 2: Run tests to verify they fail where coverage is incomplete**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile verify_warns_for_legacy_lockfile_without_errors
cargo test -p agentenv --test cli_behavior freeze_and_verify_do_not_print_known_secret
```

Expected: `verify_warns_for_legacy_lockfile_without_errors` FAILS if Task 4 did not already add the legacy warning path. `freeze_and_verify_do_not_print_known_secret` FAILS if freeze, verify, or lockfile serialization leaks credential note/value text.

- [ ] **Step 3: Fix compatibility or output leaks if needed**

If the tests fail, adjust only:

```text
crates/agentenv-core/src/portable_lockfile.rs
crates/agentenv/src/main.rs
```

Required behavior:

```rust
assert!(!rendered_lockfile.contains("sk-known-secret"));
assert!(!stdout.contains("sk-known-secret"));
assert!(!stderr.contains("sk-known-secret"));
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile
cargo test -p agentenv --test cli_behavior freeze_and_verify_do_not_print_known_secret
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/tests/portable_lockfile.rs crates/agentenv/tests/cli_behavior.rs crates/agentenv-core/src/portable_lockfile.rs crates/agentenv/src/main.rs
git commit -m "test: cover lockfile compatibility and secret stripping"
```

## Task 10: Final Verification And Documentation Touches

**Files:**
- Modify: `README.md` if command help or quickstart mentions old `freeze --blueprint --out`
- Modify: `docs/ARCHITECTURE.md` only if it needs the `verify` command or `0.2.0` lockfile detail

- [ ] **Step 1: Search for old CLI shape**

Run:

```bash
rg -n "freeze .*--blueprint|--out|verify <lockfile>|agentenv.lock|reproduce <lockfile>" README.md docs crates
```

Expected: command exits 0 and shows any docs/tests requiring updates.

- [ ] **Step 2: Patch docs that mention old freeze flags**

Replace old user-facing examples with:

```text
agentenv freeze myapp
agentenv freeze myapp --output agentenv.lock
agentenv verify agentenv.lock
agentenv reproduce agentenv.lock --name myapp-copy
```

- [ ] **Step 3: Run formatting and focused tests**

Run:

```bash
cargo fmt --check
cargo test -p agentenv-core --test lockfile_security
cargo test -p agentenv-core --test driver_artifact
cargo test -p agentenv-core --test portable_lockfile
cargo test -p agentenv-core --test runtime_freeze
cargo test -p agentenv --test cli_behavior
```

Expected: all commands PASS.

- [ ] **Step 4: Run full verification**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: both commands PASS. If gated OpenShell tests are ignored by default, that is acceptable.

- [ ] **Step 5: Inspect git state**

Run:

```bash
git status --short
git diff --check
```

Expected: `git diff --check` exits 0. `git status --short` shows only intentional source, test, and docs changes.

- [ ] **Step 6: Commit final docs or verification-only changes**

```bash
git add README.md docs/ARCHITECTURE.md
git commit -m "docs: document portable lockfile lifecycle"
```

Run this commit only if documentation files changed in Task 10.
