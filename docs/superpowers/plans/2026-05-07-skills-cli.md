# Skills Lifecycle CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the full `agentenv skills` lifecycle from issue #28 in one PR.

**Architecture:** Add an async `agentenv-core::skills` service that owns manifests, verification, local cache state, registry adapters, and config precedence. Add a thin `agentenv` CLI module that parses `skills` subcommands, calls the service, and renders text or JSON. Keep skills as core-managed resources; do not add a driver kind or driver protocol method.

**Tech Stack:** Rust 2021, `serde_yaml`, `serde_json`, `toml` for the issue-required user config file, `semver`, `sha2`, `ed25519-dalek`, `reqwest` with `rustls`, `tokio`, existing `agentenv-core::security::ssrf` validation, existing `agentenv-credstore` credential resolution.

---

## File Structure

- Modify `Cargo.toml`
  - Add workspace dependency `toml = "0.8"`.
- Modify `crates/agentenv-core/Cargo.toml`
  - Add `reqwest.workspace = true`.
  - Add `toml.workspace = true`.
- Modify `crates/agentenv/Cargo.toml`
  - Add `toml.workspace = true` only if CLI config loading stays in the binary crate.
- Modify `crates/agentenv-core/src/lib.rs`
  - Export `pub mod skills;`.
- Create `crates/agentenv-core/src/skills/mod.rs`
  - Re-export the service, config, registry, manifest, installed record, and error types.
- Create `crates/agentenv-core/src/skills/error.rs`
  - Own `SkillError` with `thiserror`.
- Create `crates/agentenv-core/src/skills/manifest.rs`
  - Parse and validate `skill.yaml`; expand exact files and trailing `/**` directory patterns deterministically.
- Create `crates/agentenv-core/src/skills/digest.rs`
  - Compute canonical `sha256:<hex>` bundle digests over declared files.
- Create `crates/agentenv-core/src/skills/signature.rs`
  - Verify Ed25519 signatures over normalized manifest JSON and content digest.
- Create `crates/agentenv-core/src/skills/index.rs`
  - Read and write `~/.agentenv/skills/index.yaml`.
- Create `crates/agentenv-core/src/skills/store.rs`
  - Own cache layout, staging directories, atomic installs, remove, info, and verify.
- Create `crates/agentenv-core/src/skills/config.rs`
  - Deserialize skills config from project YAML and user TOML, merge with CLI registry overrides.
- Create `crates/agentenv-core/src/skills/registry.rs`
  - Define `RegistryAdapter`, `RegistryConfig`, `SkillSearchHit`, and `FetchedSkill`.
- Create `crates/agentenv-core/src/skills/registry_filesystem.rs`
  - Implement filesystem registry search/add/publish.
- Create `crates/agentenv-core/src/skills/registry_http.rs`
  - Implement HTTP registry search/add/publish with SSRF validation.
- Create `crates/agentenv-core/src/skills/registry_oci.rs`
  - Implement OCI Distribution API search/add/publish using `reqwest`.
- Create `crates/agentenv-core/src/skills/service.rs`
  - Compose config, store, and adapters into async operations.
- Create `crates/agentenv-core/tests/skills.rs`
  - Cover core behavior and registry adapters.
- Modify `crates/agentenv/src/main.rs`
  - Add `Skills(skills_cli::SkillsArgs)` to `Commands`, route to `skills_cli::run_skills`.
- Create `crates/agentenv/src/skills_cli.rs`
  - Define clap args and render text/JSON output.
- Modify `crates/agentenv/src/render.rs`
  - Add JSON wrappers only if `skills_cli.rs` cannot serialize response structs directly with `render::print_json`.
- Modify `crates/agentenv/tests/cli_behavior.rs`
  - Add CLI integration tests for all `skills` subcommands and config precedence.

## Implementation Notes

- Service methods that touch registries are async. The design doc's API block is illustrative; implement the real API as `async fn` for `search`, `add`, and `publish`, and regular `fn` for local index reads where no network is involved.
- Do not use `.unwrap()` outside tests.
- Do not add a new driver kind or modify `agentenv-proto`.
- Use exact file patterns and trailing `/**` only. Do not add a glob dependency.
- Use atomic writes by writing a temporary file in the same directory and renaming it into place.
- Use temporary staging directories under `~/.agentenv/skills/.tmp/`.
- The issue explicitly requires `~/.config/agentenv/config.toml`; keep TOML support confined to skills config loading.

### Task 1: Core Skill Manifest and Digest

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agentenv-core/Cargo.toml`
- Modify: `crates/agentenv-core/src/lib.rs`
- Create: `crates/agentenv-core/src/skills/mod.rs`
- Create: `crates/agentenv-core/src/skills/error.rs`
- Create: `crates/agentenv-core/src/skills/manifest.rs`
- Create: `crates/agentenv-core/src/skills/digest.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing manifest and digest tests**

Add `crates/agentenv-core/tests/skills.rs` with these tests:

```rust
use std::{fs, path::{Path, PathBuf}};

use agentenv_core::skills::{
    compute_bundle_digest, load_skill_manifest, validate_skill_name, SkillError,
};

#[test]
fn skill_manifest_accepts_minimal_bundle() {
    let root = temp_dir("skill-manifest-minimal");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let manifest = load_skill_manifest(&root).expect("manifest should load");

    assert_eq!(manifest.name, "demo-skill");
    assert_eq!(manifest.version.to_string(), "0.1.0");
    assert_eq!(manifest.entry, PathBuf::from("SKILL.md"));
    assert_eq!(manifest.declared_files, vec![PathBuf::from("SKILL.md")]);
}

#[test]
fn skill_manifest_rejects_invalid_name() {
    let root = temp_dir("skill-manifest-invalid-name");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: ../demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("name must be rejected");

    assert!(matches!(error, SkillError::InvalidSkillName { .. }));
}

#[test]
fn skill_manifest_rejects_parent_traversal() {
    let root = temp_dir("skill-manifest-parent-traversal");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: ../SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("entry traversal must fail");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn skill_digest_is_stable_for_sorted_declared_files() {
    let root = temp_dir("skill-digest-stable");
    fs::create_dir_all(root.join("references")).unwrap();
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("references/a.md"), "A\n");
    write_file(&root.join("references/b.md"), "B\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - references/**\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();

    let first = compute_bundle_digest(&root, &manifest).unwrap();
    let second = compute_bundle_digest(&root, &manifest).unwrap();

    assert_eq!(first, second);
    assert!(first.starts_with("sha256:"));
    assert_eq!(first.len(), "sha256:".len() + 64);
}

#[test]
fn skill_digest_changes_when_content_changes() {
    let root = temp_dir("skill-digest-changes");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();
    let before = compute_bundle_digest(&root, &manifest).unwrap();

    write_file(&root.join("SKILL.md"), "# Changed\n");
    let after = compute_bundle_digest(&root, &manifest).unwrap();

    assert_ne!(before, after);
}

#[test]
fn validate_skill_name_accepts_conservative_identifiers() {
    for name in ["demo", "demo-skill", "demo_skill", "demo.skill", "a1"] {
        validate_skill_name(name).expect(name);
    }
}

fn temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("{prefix}-{}-{}", std::process::id(), unique_nanos()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills skill_manifest_accepts_minimal_bundle skill_digest_is_stable_for_sorted_declared_files
```

Expected: compile failure mentioning missing `agentenv_core::skills`.

- [ ] **Step 3: Add module exports and dependencies**

Edit root `Cargo.toml`:

```toml
toml = "0.8"
```

Edit `crates/agentenv-core/Cargo.toml`:

```toml
reqwest.workspace = true
toml.workspace = true
```

Edit `crates/agentenv-core/src/lib.rs`:

```rust
pub mod skills;
```

Create `crates/agentenv-core/src/skills/mod.rs`:

```rust
pub mod digest;
pub mod error;
pub mod manifest;

pub use digest::compute_bundle_digest;
pub use error::SkillError;
pub use manifest::{load_skill_manifest, validate_skill_name, SkillManifest};
```

- [ ] **Step 4: Implement `SkillError`**

Create `crates/agentenv-core/src/skills/error.rs`:

```rust
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SkillError {
    #[error("failed to read or write skill path `{path}`: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("failed to parse skill YAML at `{path}`: {source}")]
    Yaml { path: PathBuf, #[source] source: serde_yaml::Error },
    #[error("invalid skill name `{name}`")]
    InvalidSkillName { name: String },
    #[error("invalid skill version `{version}`: {source}")]
    InvalidVersion { version: String, #[source] source: semver::Error },
    #[error("unsafe skill bundle path `{path}`")]
    UnsafeBundlePath { path: PathBuf },
    #[error("declared skill file `{path}` is missing")]
    MissingDeclaredFile { path: PathBuf },
    #[error("declared skill pattern `{pattern}` matched no files")]
    EmptyFilePattern { pattern: String },
    #[error("skill manifest `{path}` is missing required field `{field}`")]
    MissingManifestField { path: PathBuf, field: &'static str },
    #[error("skill digest mismatch: expected `{expected}`, found `{actual}`")]
    DigestMismatch { expected: String, actual: String },
}
```

- [ ] **Step 5: Implement manifest parsing**

Create `crates/agentenv-core/src/skills/manifest.rs` with:

```rust
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use super::SkillError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillManifest {
    pub name: String,
    pub version: Version,
    pub description: Option<String>,
    pub entry: PathBuf,
    pub declared_files: Vec<PathBuf>,
    pub self_test_command: Option<String>,
    pub signature_ed25519: Option<String>,
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawManifest {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    entry: Option<PathBuf>,
    #[serde(default)]
    files: Vec<String>,
    self_test: Option<RawSelfTest>,
    signatures: Option<RawSignatures>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawSelfTest {
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSignatures {
    ed25519: Option<String>,
}

pub fn load_skill_manifest(root: &Path) -> Result<SkillManifest, SkillError> {
    let path = root.join("skill.yaml");
    let yaml = fs::read_to_string(&path).map_err(|source| SkillError::Io {
        path: path.clone(),
        source,
    })?;
    let raw: RawManifest = serde_yaml::from_str(&yaml).map_err(|source| SkillError::Yaml {
        path: path.clone(),
        source,
    })?;
    normalize_manifest(root, &path, raw)
}

pub fn validate_skill_name(name: &str) -> Result<(), SkillError> {
    let valid = !name.is_empty()
        && !name.starts_with('.')
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.')
        })
        && !name.contains('/')
        && !name.contains('\\');
    if valid {
        Ok(())
    } else {
        Err(SkillError::InvalidSkillName {
            name: name.to_owned(),
        })
    }
}

fn normalize_manifest(
    root: &Path,
    manifest_path: &Path,
    raw: RawManifest,
) -> Result<SkillManifest, SkillError> {
    let name = raw.name.ok_or_else(|| SkillError::MissingManifestField {
        path: manifest_path.to_path_buf(),
        field: "name",
    })?;
    validate_skill_name(&name)?;
    let version_text = raw.version.ok_or_else(|| SkillError::MissingManifestField {
        path: manifest_path.to_path_buf(),
        field: "version",
    })?;
    let version = Version::parse(&version_text).map_err(|source| SkillError::InvalidVersion {
        version: version_text,
        source,
    })?;
    let entry = normalize_relative_path(raw.entry.ok_or_else(|| SkillError::MissingManifestField {
        path: manifest_path.to_path_buf(),
        field: "entry",
    })?)?;
    let mut declared_files = expand_declared_files(root, &raw.files)?;
    declared_files.sort();
    declared_files.dedup();
    if !declared_files.contains(&entry) {
        return Err(SkillError::MissingDeclaredFile { path: entry });
    }
    Ok(SkillManifest {
        name,
        version,
        description: raw.description,
        entry,
        declared_files,
        self_test_command: raw.self_test.and_then(|value| value.command),
        signature_ed25519: raw.signatures.and_then(|value| value.ed25519),
        extra: raw.extra,
    })
}

fn expand_declared_files(root: &Path, patterns: &[String]) -> Result<Vec<PathBuf>, SkillError> {
    let mut files = Vec::new();
    for pattern in patterns {
        if let Some(prefix) = pattern.strip_suffix("/**") {
            let dir = normalize_relative_path(PathBuf::from(prefix))?;
            let before = files.len();
            collect_files(root, &dir, &mut files)?;
            if files.len() == before {
                return Err(SkillError::EmptyFilePattern {
                    pattern: pattern.clone(),
                });
            }
        } else {
            let path = normalize_relative_path(PathBuf::from(pattern))?;
            if !root.join(&path).is_file() {
                return Err(SkillError::MissingDeclaredFile { path });
            }
            files.push(path);
        }
    }
    Ok(files)
}

fn collect_files(root: &Path, relative_dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), SkillError> {
    let absolute = root.join(relative_dir);
    if !absolute.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&absolute).map_err(|source| SkillError::Io {
        path: absolute.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| SkillError::Io {
            path: absolute.clone(),
            source,
        })?;
        let child_relative = relative_dir.join(entry.file_name());
        let kind = entry.file_type().map_err(|source| SkillError::Io {
            path: entry.path(),
            source,
        })?;
        if kind.is_dir() {
            collect_files(root, &child_relative, files)?;
        } else if kind.is_file() {
            files.push(normalize_relative_path(child_relative)?);
        }
    }
    Ok(())
}

pub fn normalize_relative_path(path: PathBuf) -> Result<PathBuf, SkillError> {
    if path.is_absolute() {
        return Err(SkillError::UnsafeBundlePath { path });
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SkillError::UnsafeBundlePath { path });
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(SkillError::UnsafeBundlePath { path: normalized });
    }
    Ok(normalized)
}
```

- [ ] **Step 6: Implement digest computation**

Create `crates/agentenv-core/src/skills/digest.rs`:

```rust
use std::{fs, path::Path};

use sha2::{Digest, Sha256};

use super::{manifest::SkillManifest, SkillError};

pub fn compute_bundle_digest(root: &Path, manifest: &SkillManifest) -> Result<String, SkillError> {
    let mut hasher = Sha256::new();
    hasher.update(b"agentenv-skill-v1\n");
    for relative in &manifest.declared_files {
        let absolute = root.join(relative);
        let bytes = fs::read(&absolute).map_err(|source| SkillError::Io {
            path: absolute.clone(),
            source,
        })?;
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        hasher.update(relative_text.as_bytes());
        hasher.update(b"\0");
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(&bytes);
        hasher.update(b"\n");
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}
```

- [ ] **Step 7: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills skill_manifest skill_digest validate_skill_name
```

Expected: all tests in Task 1 pass.

- [ ] **Step 8: Commit Task 1**

Run:

```bash
git add Cargo.toml crates/agentenv-core/Cargo.toml crates/agentenv-core/src/lib.rs crates/agentenv-core/src/skills crates/agentenv-core/tests/skills.rs
git commit -m "feat: add skill manifest validation"
```

### Task 2: Signatures, Installed Store, and Verification

**Files:**
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Create: `crates/agentenv-core/src/skills/signature.rs`
- Create: `crates/agentenv-core/src/skills/index.rs`
- Create: `crates/agentenv-core/src/skills/store.rs`
- Modify: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing signature and store tests**

Append these tests to `crates/agentenv-core/tests/skills.rs`:

```rust
use agentenv_core::skills::{
    install_local_skill, verify_installed_skill, InstalledSkillSelector, SkillInstallOptions,
};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn signature_verification_accepts_signed_bundle() {
    let root = temp_dir("skill-signature-valid");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: signed-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();
    let digest = compute_bundle_digest(&root, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let payload = agentenv_core::skills::signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());

    agentenv_core::skills::verify_ed25519_signature(&manifest, &digest, &signature, &public_key)
        .expect("signature should verify");
}

#[test]
fn signature_verification_rejects_tampered_digest() {
    let root = temp_dir("skill-signature-tampered");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: signed-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();
    let digest = compute_bundle_digest(&root, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let payload = agentenv_core::skills::signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());

    let error = agentenv_core::skills::verify_ed25519_signature(
        &manifest,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &signature,
        &public_key,
    )
    .expect_err("tampered digest must fail");

    assert!(matches!(error, SkillError::InvalidSignature { .. }));
}

#[test]
fn local_install_writes_cache_and_index() {
    let home = temp_dir("skill-install-home");
    let bundle = temp_dir("skill-install-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: local-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let installed = install_local_skill(
        &home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_label: "local-dev".to_owned(),
        },
    )
    .expect("install should succeed");

    assert_eq!(installed.name, "local-demo");
    assert_eq!(installed.version, "0.1.0");
    assert!(installed.path.join("content/SKILL.md").is_file());
    assert!(home.join(".agentenv/skills/index.yaml").is_file());
}

#[test]
fn installed_verify_detects_content_tampering() {
    let home = temp_dir("skill-verify-home");
    let bundle = temp_dir("skill-verify-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: verify-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        &home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_label: "local-dev".to_owned(),
        },
    )
    .unwrap();
    write_file(&installed.path.join("content/SKILL.md"), "# Tampered\n");

    let error = verify_installed_skill(
        &home.join(".agentenv"),
        InstalledSkillSelector::Name("verify-demo".to_owned()),
    )
    .expect_err("tampering must fail");

    assert!(matches!(error, SkillError::DigestMismatch { .. }));
}

#[test]
fn installed_verify_runs_self_test_command() {
    let home = temp_dir("skill-self-test-home");
    let bundle = temp_dir("skill-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: self-test-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: \"test -f SKILL.md\"\n",
    );
    install_local_skill(
        &home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_label: "local-dev".to_owned(),
        },
    )
    .unwrap();

    let verified = verify_installed_skill(
        &home.join(".agentenv"),
        InstalledSkillSelector::Name("self-test-demo".to_owned()),
    )
    .expect("self-test command should pass");

    assert_eq!(verified.name, "self-test-demo");
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills signature_verification local_install installed_verify
```

Expected: compile failure for missing signature and store APIs.

- [ ] **Step 3: Extend `SkillError`**

Add these variants to `crates/agentenv-core/src/skills/error.rs`:

```rust
#[error("missing Ed25519 signature for skill `{name}` version `{version}`")]
MissingSignature { name: String, version: String },
#[error("invalid Ed25519 signature for skill `{name}` version `{version}`: {message}")]
InvalidSignature { name: String, version: String, message: String },
#[error("skill `{name}` is not installed")]
SkillNotInstalled { name: String },
#[error("skill `{name}` has multiple installed versions: {versions}")]
AmbiguousInstalledVersion { name: String, versions: String },
#[error("skill `{name}` version `{version}` is already installed with digest `{existing}`")]
AlreadyInstalledDifferentDigest { name: String, version: String, existing: String },
#[error("failed to parse or serialize installed skill JSON/YAML at `{path}`: {source}")]
Serde { path: PathBuf, #[source] source: serde_yaml::Error },
#[error("skill `{name}` version `{version}` self-test failed with status {status}")]
SelfTestFailed { name: String, version: String, status: i32 },
```

- [ ] **Step 4: Implement signature helpers**

Create `crates/agentenv-core/src/skills/signature.rs`:

```rust
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;

use super::{SkillError, SkillManifest};

#[derive(Serialize)]
struct SignedManifest<'a> {
    name: &'a str,
    version: String,
    description: &'a Option<String>,
    entry: String,
    files: Vec<String>,
    self_test_command: &'a Option<String>,
}

pub fn signature_payload(manifest: &SkillManifest, digest: &str) -> Result<Vec<u8>, SkillError> {
    let normalized = SignedManifest {
        name: &manifest.name,
        version: manifest.version.to_string(),
        description: &manifest.description,
        entry: manifest.entry.to_string_lossy().replace('\\', "/"),
        files: manifest
            .declared_files
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect(),
        self_test_command: &manifest.self_test_command,
    };
    let mut payload = b"agentenv-skill-signature-v1\n".to_vec();
    let json = serde_json::to_vec(&normalized).map_err(|source| SkillError::InvalidSignature {
        name: manifest.name.clone(),
        version: manifest.version.to_string(),
        message: source.to_string(),
    })?;
    payload.extend(json);
    payload.push(b'\n');
    payload.extend(digest.as_bytes());
    Ok(payload)
}

pub fn verify_ed25519_signature(
    manifest: &SkillManifest,
    digest: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), SkillError> {
    let public_key_bytes = hex::decode(public_key_hex).map_err(|source| SkillError::InvalidSignature {
        name: manifest.name.clone(),
        version: manifest.version.to_string(),
        message: source.to_string(),
    })?;
    let signature_bytes = hex::decode(signature_hex).map_err(|source| SkillError::InvalidSignature {
        name: manifest.name.clone(),
        version: manifest.version.to_string(),
        message: source.to_string(),
    })?;
    let public_key_array: [u8; 32] = public_key_bytes.as_slice().try_into().map_err(|_| {
        SkillError::InvalidSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            message: "public key must be 32 bytes".to_owned(),
        }
    })?;
    let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|source| {
        SkillError::InvalidSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            message: source.to_string(),
        }
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|source| {
        SkillError::InvalidSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            message: source.to_string(),
        }
    })?;
    let payload = signature_payload(manifest, digest)?;
    verifying_key.verify(&payload, &signature).map_err(|source| {
        SkillError::InvalidSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            message: source.to_string(),
        }
    })
}
```

- [ ] **Step 5: Implement installed record and store**

Create `index.rs` and `store.rs` with these public types:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InstalledSkill {
    pub name: String,
    pub version: String,
    pub source_type: String,
    pub source_label: String,
    pub digest: String,
    pub signature_status: String,
    pub entry: std::path::PathBuf,
    pub installed_at: String,
    pub path: std::path::PathBuf,
}

#[derive(Debug, Clone)]
pub struct SkillInstallOptions {
    pub allow_unsigned: bool,
    pub source_label: String,
}

#[derive(Debug, Clone)]
pub enum InstalledSkillSelector {
    Name(String),
    NameVersion { name: String, version: String },
}
```

Implement:

```rust
pub fn install_local_skill(
    root: &Path,
    bundle: &Path,
    options: SkillInstallOptions,
) -> Result<InstalledSkill, SkillError>

pub fn list_installed_skills(root: &Path) -> Result<Vec<InstalledSkill>, SkillError>

pub fn info_installed_skill(
    root: &Path,
    selector: InstalledSkillSelector,
) -> Result<InstalledSkill, SkillError>

pub fn remove_installed_skill(
    root: &Path,
    selector: InstalledSkillSelector,
) -> Result<InstalledSkill, SkillError>

pub fn verify_installed_skill(
    root: &Path,
    selector: InstalledSkillSelector,
) -> Result<InstalledSkill, SkillError>
```

Store layout:

```text
<root>/skills/index.yaml
<root>/skills/<name>/<version>/skill.yaml
<root>/skills/<name>/<version>/content/<declared files>
<root>/skills/<name>/<version>/installed.yaml
```

- [ ] **Step 6: Export new APIs**

Update `crates/agentenv-core/src/skills/mod.rs`:

```rust
pub mod index;
pub mod signature;
pub mod store;

pub use signature::{signature_payload, verify_ed25519_signature};
pub use store::{
    info_installed_skill, install_local_skill, list_installed_skills, remove_installed_skill,
    verify_installed_skill, InstalledSkill, InstalledSkillSelector, SkillInstallOptions,
};
```

- [ ] **Step 7: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills signature_verification local_install installed_verify
```

Expected: all Task 2 tests pass.

- [ ] **Step 8: Commit Task 2**

Run:

```bash
git add crates/agentenv-core/src/skills crates/agentenv-core/tests/skills.rs
git commit -m "feat: verify and store installed skills"
```

### Task 3: Skills Config and Registry Resolution

**Files:**
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Create: `crates/agentenv-core/src/skills/config.rs`
- Create: `crates/agentenv-core/src/skills/registry.rs`
- Modify: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing config tests**

Append tests:

```rust
use agentenv_core::skills::{
    load_project_skills_config, load_user_skills_config, merge_skills_config, RegistryKind,
    SkillsConfig, SkillsConfigOverride,
};

#[test]
fn skills_config_loads_project_yaml_section() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox: { driver: openshell }
agent: { driver: codex }
context: { driver: filesystem, mount: . }
policy: { tier: balanced, presets: [] }
skills:
  registries:
    - name: local-dev
      type: filesystem
      path: /tmp/skills
"#;

    let config = load_project_skills_config(yaml).unwrap();

    assert_eq!(config.registries.len(), 1);
    assert_eq!(config.registries[0].name, "local-dev");
    assert_eq!(config.registries[0].kind, RegistryKind::Filesystem);
}

#[test]
fn skills_config_loads_user_toml() {
    let toml = r#"
[skills]
registry_order = ["corp"]

[[skills.registries]]
name = "corp"
type = "http"
url = "https://skills.example.test"
auth = "bearer-from-credstore:CORP_SKILLS_TOKEN"
"#;

    let config = load_user_skills_config(toml).unwrap();

    assert_eq!(config.registry_order, vec!["corp"]);
    assert_eq!(config.registries[0].auth.as_deref(), Some("bearer-from-credstore:CORP_SKILLS_TOKEN"));
}

#[test]
fn cli_registry_override_wins_over_project_and_user_config() {
    let user = SkillsConfig {
        registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
            "user-local",
            PathBuf::from("/user"),
        )],
        registry_order: vec!["user-local".to_owned()],
    };
    let project = SkillsConfig {
        registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
            "project-local",
            PathBuf::from("/project"),
        )],
        registry_order: vec!["project-local".to_owned()],
    };

    let merged = merge_skills_config(
        user,
        Some(project),
        SkillsConfigOverride {
            registry: Some("file:///override".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries.len(), 1);
    assert_eq!(merged.registries[0].name, "cli");
    assert_eq!(merged.registry_order, vec!["cli"]);
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills skills_config
```

Expected: compile failure for missing config APIs.

- [ ] **Step 3: Implement config and registry types**

Create `config.rs` and `registry.rs` with:

```rust
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SkillsConfig {
    #[serde(default)]
    pub registries: Vec<RegistryConfig>,
    #[serde(default)]
    pub registry_order: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RegistryConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: RegistryKind,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub auth: Option<String>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryKind {
    Filesystem,
    Http,
    Oci,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillsConfigOverride {
    pub registry: Option<String>,
}
```

Implement:

```rust
pub fn load_project_skills_config(yaml: &str) -> Result<SkillsConfig, SkillError>
pub fn load_user_skills_config(toml_text: &str) -> Result<SkillsConfig, SkillError>
pub fn merge_skills_config(
    user: SkillsConfig,
    project: Option<SkillsConfig>,
    override_config: SkillsConfigOverride,
) -> Result<SkillsConfig, SkillError>
```

Resolution rules:

- user config is the base
- project config replaces base only when it has registries or order
- CLI `--registry` replaces the list with one `cli` registry
- `file://` and absolute paths become filesystem registries
- `http://` and `https://` become HTTP registries
- other strings without a URL scheme are treated as registry names to select from merged config

- [ ] **Step 4: Extend errors and exports**

Add errors:

```rust
#[error("registry `{name}` was not found")]
RegistryNotFound { name: String },
#[error("invalid skills config: {message}")]
InvalidConfig { message: String },
#[error("failed to parse skills config TOML: {source}")]
Toml { #[source] source: toml::de::Error },
```

Update `mod.rs` exports:

```rust
pub mod config;
pub mod registry;

pub use config::{
    load_project_skills_config, load_user_skills_config, merge_skills_config, RegistryConfig,
    RegistryKind, SkillsConfig, SkillsConfigOverride,
};
```

- [ ] **Step 5: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills skills_config
```

Expected: all Task 3 tests pass.

- [ ] **Step 6: Commit Task 3**

Run:

```bash
git add Cargo.toml crates/agentenv-core/Cargo.toml crates/agentenv-core/src/skills crates/agentenv-core/tests/skills.rs
git commit -m "feat: load skills registry config"
```

### Task 4: Filesystem Registry and Skill Service

**Files:**
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Create: `crates/agentenv-core/src/skills/registry_filesystem.rs`
- Create: `crates/agentenv-core/src/skills/service.rs`
- Modify: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing filesystem registry tests**

Append tests:

```rust
use agentenv_core::skills::{SkillAddRequest, SkillPublishRequest, SkillService};

#[tokio::test]
async fn filesystem_registry_search_add_and_publish_work() {
    let home = temp_dir("skill-fs-home");
    let registry = temp_dir("skill-fs-registry");
    let bundle = temp_dir("skill-fs-bundle");
    write_file(&bundle.join("SKILL.md"), "# Searchable Skill\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: searchable-skill\nversion: 0.1.0\ndescription: Searchable demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
                "local-dev",
                registry.clone(),
            )],
            registry_order: vec!["local-dev".to_owned()],
        },
    );

    service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: "local-dev".to_owned(),
            allow_unsigned: true,
        })
        .await
        .expect("publish should succeed");
    let hits = service.search("searchable").await.expect("search should work");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "searchable-skill");

    let installed = service
        .add(SkillAddRequest {
            handle: "searchable-skill@0.1.0".to_owned(),
            registry: None,
            allow_unsigned: true,
        })
        .await
        .expect("add should install");

    assert_eq!(installed.name, "searchable-skill");
}
```

- [ ] **Step 2: Run test and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills filesystem_registry_search_add_and_publish_work
```

Expected: compile failure for missing service and filesystem registry.

- [ ] **Step 3: Implement registry structs and trait**

In `registry.rs`, add:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SkillSearchHit {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub registry: String,
    pub digest: Option<String>,
    pub signature_ed25519: Option<String>,
    pub public_key_ed25519: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FetchedSkill {
    pub staging_path: PathBuf,
    pub registry: String,
    pub source_type: String,
}

#[async_trait::async_trait]
pub trait RegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError>;
    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError>;
    async fn publish(&self, bundle_path: &Path, allow_unsigned: bool) -> Result<SkillSearchHit, SkillError>;
}
```

- [ ] **Step 4: Implement filesystem registry**

Create `registry_filesystem.rs` with `FilesystemRegistryAdapter`. It should:

- read and write `<registry>/index.yaml`
- store bundles under `<registry>/bundles/<name>/<version>/`
- use `install_local_skill` validation before publishing
- refuse overwrite when same name/version has different digest
- update index entries sorted by name then version

- [ ] **Step 5: Implement `SkillService`**

Create `service.rs` with:

```rust
#[derive(Debug, Clone)]
pub struct SkillService {
    root: PathBuf,
    config: SkillsConfig,
}

#[derive(Debug, Clone)]
pub struct SkillAddRequest {
    pub handle: String,
    pub registry: Option<String>,
    pub allow_unsigned: bool,
}

#[derive(Debug, Clone)]
pub struct SkillPublishRequest {
    pub bundle_path: PathBuf,
    pub registry: String,
    pub allow_unsigned: bool,
}
```

Implement:

```rust
impl SkillService {
    pub fn new(root: PathBuf, config: SkillsConfig) -> Self
    pub async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError>
    pub async fn add(&self, request: SkillAddRequest) -> Result<InstalledSkill, SkillError>
    pub async fn publish(&self, request: SkillPublishRequest) -> Result<SkillSearchHit, SkillError>
    pub fn list(&self) -> Result<Vec<InstalledSkill>, SkillError>
    pub fn info(&self, selector: InstalledSkillSelector) -> Result<InstalledSkill, SkillError>
    pub fn remove(&self, selector: InstalledSkillSelector) -> Result<InstalledSkill, SkillError>
    pub fn verify(&self, selector: InstalledSkillSelector) -> Result<InstalledSkill, SkillError>
}
```

Handle parsing rules:

- `name@version` splits on the last `@`
- missing version selects highest semantic version from search results
- invalid name fails before registry access

- [ ] **Step 6: Export service and adapter**

Update `mod.rs`:

```rust
pub mod registry_filesystem;
pub mod service;

pub use registry::{FetchedSkill, RegistryAdapter, SkillSearchHit};
pub use service::{SkillAddRequest, SkillPublishRequest, SkillService};
```

- [ ] **Step 7: Run test and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills filesystem_registry_search_add_and_publish_work
```

Expected: test passes.

- [ ] **Step 8: Commit Task 4**

Run:

```bash
git add crates/agentenv-core/src/skills crates/agentenv-core/tests/skills.rs
git commit -m "feat: add filesystem skill registry"
```

### Task 5: HTTP Registry with SSRF and Credentials

**Files:**
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Create: `crates/agentenv-core/src/skills/registry_http.rs`
- Modify: `crates/agentenv-core/src/skills/service.rs`
- Modify: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing HTTP registry tests**

Append tests using a minimal Tokio TCP server:

```rust
#[tokio::test]
async fn http_registry_rejects_unsafe_url_before_request() {
    let home = temp_dir("skill-http-unsafe-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::http(
                "unsafe",
                "http://127.0.0.1:9",
                None,
            )],
            registry_order: vec!["unsafe".to_owned()],
        },
    );

    let error = service.search("demo").await.expect_err("loopback URL must be blocked");

    assert!(matches!(error, SkillError::RegistryUrlBlocked { .. }));
}
```

Add a second test after the local HTTP fixture helper is available:

```rust
#[tokio::test]
async fn http_registry_search_reads_static_index() {
    let server = TestHttpRegistry::start().await;
    server
        .add_response(
            "GET /index.yaml",
            "entries:\n  - name: http-demo\n    version: 0.1.0\n    description: HTTP demo\n",
        )
        .await;
    let home = temp_dir("skill-http-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::http(
                "http-dev",
                &server.public_base_url(),
                None,
            )],
            registry_order: vec!["http-dev".to_owned()],
        },
    );

    let hits = service.search("http").await.expect("search should succeed");

    assert_eq!(hits[0].name, "http-demo");
}

#[tokio::test]
async fn http_registry_publish_and_add_round_trip() {
    let server = TestHttpRegistry::start().await;
    let home = temp_dir("skill-http-round-trip-home");
    let bundle = temp_dir("skill-http-round-trip-bundle");
    write_file(&bundle.join("SKILL.md"), "# HTTP Skill\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: http-skill\nversion: 0.1.0\ndescription: HTTP skill\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::http(
                "http-dev",
                &server.public_base_url(),
                None,
            )],
            registry_order: vec!["http-dev".to_owned()],
        },
    );

    service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: "http-dev".to_owned(),
            allow_unsigned: true,
        })
        .await
        .expect("publish should upload files");

    let installed = service
        .add(SkillAddRequest {
            handle: "http-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
        })
        .await
        .expect("add should download uploaded files");

    assert_eq!(installed.name, "http-skill");
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills http_registry
```

Expected: compile failure for missing `registry_http` or failure because URL validation is not wired.

- [ ] **Step 3: Extend errors**

Add:

```rust
#[error("registry URL `{url}` was blocked by SSRF policy: {source}")]
RegistryUrlBlocked {
    url: String,
    #[source]
    source: crate::security::ssrf::SsrfBlocked,
},
#[error("HTTP registry request failed for `{url}`: {source}")]
HttpRegistry {
    url: String,
    #[source]
    source: reqwest::Error,
},
#[error("HTTP registry `{url}` returned status {status}")]
HttpStatus {
    url: String,
    status: reqwest::StatusCode,
},
#[error("credential reference `{name}` is not available")]
CredentialReferenceUnavailable { name: String },
```

- [ ] **Step 4: Implement HTTP adapter**

Create `registry_http.rs`. Required behavior:

- Validate base URL and each request URL with `validate_outbound(url, SsrfOptions::default())`.
- `GET /index.yaml` for search.
- `GET /bundles/<name>/<version>/skill.yaml` and content files for fetch.
- `PUT` canonical files for publish.
- Include `digest`, `signature_ed25519`, and `public_key_ed25519` in uploaded
  and downloaded index entries.
- Use bearer auth header when the service supplies a token.
- Do not log bearer tokens.

- [ ] **Step 5: Wire HTTP adapter into service**

In `service.rs`, instantiate `HttpRegistryAdapter` for `RegistryKind::Http`. Add a credential resolver callback to `SkillService`:

```rust
pub type SkillCredentialResolver =
    std::sync::Arc<dyn Fn(&str) -> Result<Option<String>, SkillError> + Send + Sync>;
```

Provide:

```rust
pub fn with_credential_resolver(self, resolver: SkillCredentialResolver) -> Self
```

Default resolver returns `Ok(None)`.

- [ ] **Step 6: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills http_registry
```

Expected: HTTP registry tests pass.

- [ ] **Step 7: Commit Task 5**

Run:

```bash
git add crates/agentenv-core/src/skills crates/agentenv-core/tests/skills.rs
git commit -m "feat: add http skill registry"
```

### Task 6: OCI Registry Adapter

**Files:**
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Create: `crates/agentenv-core/src/skills/registry_oci.rs`
- Modify: `crates/agentenv-core/src/skills/service.rs`
- Modify: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing OCI tests**

Append:

```rust
#[tokio::test]
async fn oci_registry_search_add_and_publish_use_distribution_api() {
    let registry = TestOciRegistry::start().await;
    let home = temp_dir("skill-oci-home");
    let bundle = temp_dir("skill-oci-bundle");
    write_file(&bundle.join("SKILL.md"), "# OCI Skill\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: oci-skill\nversion: 0.1.0\ndescription: OCI demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::oci(
                "oci-dev",
                &registry.base_reference("agentenv-test"),
                None,
            )],
            registry_order: vec!["oci-dev".to_owned()],
        },
    );

    service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: "oci-dev".to_owned(),
            allow_unsigned: true,
        })
        .await
        .expect("OCI publish should work against fixture");

    let hits = service.search("oci").await.expect("OCI search should work");
    assert_eq!(hits[0].name, "oci-skill");

    let installed = service
        .add(SkillAddRequest {
            handle: "oci-skill@0.1.0".to_owned(),
            registry: Some("oci-dev".to_owned()),
            allow_unsigned: true,
        })
        .await
        .expect("OCI add should install");
    assert_eq!(installed.name, "oci-skill");
}
```

- [ ] **Step 2: Run test and verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills oci_registry_search_add_and_publish_use_distribution_api
```

Expected: compile failure for missing OCI registry adapter.

- [ ] **Step 3: Implement minimal OCI client**

Create `registry_oci.rs` with:

```rust
const OCI_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const AGENTENV_SKILL_CONFIG: &str = "application/vnd.agentenv.skill.config.v1+json";
const AGENTENV_SKILL_MANIFEST: &str = "application/vnd.agentenv.skill.manifest.v1+yaml";
const AGENTENV_SKILL_FILE: &str = "application/vnd.agentenv.skill.file.v1";
const AGENTENV_SKILLS_INDEX: &str = "application/vnd.agentenv.skills.index.v1+yaml";
```

Implement the OCI Distribution API calls:

- `GET /v2/<repo>/manifests/skills-index`
- `GET /v2/<repo>/blobs/<digest>`
- `POST /v2/<repo>/blobs/uploads/`
- `PATCH <upload-location>`
- `PUT <upload-location>&digest=<sha256>`
- `PUT /v2/<repo>/manifests/<tag>`

Use one layer per declared bundle file. Store each original relative path in the descriptor annotation `io.agentenv.skill.path`.

- [ ] **Step 4: Add OCI auth errors**

Add:

```rust
#[error("unsupported OCI authentication scheme `{scheme}`")]
UnsupportedRegistryAuth { scheme: String },
#[error("invalid OCI registry reference `{reference}`")]
InvalidOciReference { reference: String },
```

- [ ] **Step 5: Wire OCI adapter into service**

Instantiate `OciRegistryAdapter` for `RegistryKind::Oci`. Resolve bearer credentials through the same resolver used by HTTP.

- [ ] **Step 6: Run test and verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills oci_registry_search_add_and_publish_use_distribution_api
```

Expected: test passes against fixture registry.

- [ ] **Step 7: Commit Task 6**

Run:

```bash
git add crates/agentenv-core/src/skills crates/agentenv-core/tests/skills.rs
git commit -m "feat: add oci skill registry"
```

### Task 7: CLI Command Group

**Files:**
- Modify: `crates/agentenv/src/main.rs`
- Create: `crates/agentenv/src/skills_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI help and local lifecycle tests**

Append tests to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn cli_help_includes_skills_command() {
    let output = Command::new(agentenv_bin()).arg("--help").output().unwrap();
    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("skills"), "stdout was: {stdout}");
}

#[test]
fn skills_help_lists_lifecycle_subcommands() {
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in ["search", "add", "install", "list", "info", "remove", "publish", "verify"] {
        assert!(stdout.contains(command), "missing {command}; stdout was: {stdout}");
    }
}

#[test]
fn skills_install_list_info_verify_and_remove_local_bundle() {
    let temp_dir = make_temp_dir("skills-cli-local");
    let bundle = temp_dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), "# CLI Skill\n").unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: cli-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    )
    .unwrap();

    let install = Command::new(agentenv_bin())
        .arg("skills")
        .arg("install")
        .arg("--from")
        .arg(&bundle)
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(install.status.success(), "{}", output_summary(&install));

    let list = Command::new(agentenv_bin())
        .arg("skills")
        .arg("list")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(list.status.success(), "{}", output_summary(&list));
    let json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(json["skills"][0]["name"], "cli-skill");

    let info = Command::new(agentenv_bin())
        .arg("skills")
        .arg("info")
        .arg("cli-skill")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(info.status.success(), "{}", output_summary(&info));
    let info_json: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info_json["name"], "cli-skill");

    let verify = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("cli-skill")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", output_summary(&verify));

    let remove = Command::new(agentenv_bin())
        .arg("skills")
        .arg("remove")
        .arg("cli-skill")
        .arg("--yes")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(remove.status.success(), "{}", output_summary(&remove));
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_help skills_install_list_info_verify_and_remove_local_bundle
```

Expected: failure because `skills` command does not exist.

- [ ] **Step 3: Create `skills_cli.rs`**

Implement clap structs:

```rust
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;

#[derive(Debug, Args)]
pub struct SkillsArgs {
    #[command(subcommand)]
    pub command: SkillsCommand,
}

#[derive(Debug, Subcommand)]
pub enum SkillsCommand {
    Search(SkillsSearchArgs),
    Add(SkillsAddArgs),
    Install(SkillsInstallArgs),
    List(SkillsListArgs),
    Info(SkillsInfoArgs),
    Remove(SkillsRemoveArgs),
    Publish(SkillsPublishArgs),
    Verify(SkillsVerifyArgs),
}
```

Define one args struct per command with the flags from the design.

- [ ] **Step 4: Add service construction and credential resolver**

In `skills_cli.rs`, implement:

```rust
pub async fn run_skills(args: SkillsArgs) -> Result<()> {
    let root = dirs::home_dir().context("home directory is unavailable")?.join(".agentenv");
    let config = load_effective_config(None)?;
    let service = agentenv_core::skills::SkillService::new(root, config)
        .with_credential_resolver(std::sync::Arc::new(resolve_skill_credential));
    dispatch(args, service).await
}
```

`resolve_skill_credential` should use `CredentialStore::from_default_paths()` and return `Ok(None)` for missing optional registry credentials.

- [ ] **Step 5: Route from main**

Modify `main.rs`:

```rust
mod skills_cli;
```

Add:

```rust
Skills(skills_cli::SkillsArgs),
```

Route:

```rust
Some(Commands::Skills(args)) => skills_cli::run_skills(args).await,
```

- [ ] **Step 6: Render JSON and text**

In `skills_cli.rs`, define:

```rust
#[derive(Debug, Serialize)]
struct SkillsListJson {
    skills: Vec<agentenv_core::skills::InstalledSkill>,
}
```

Text output:

- install/add/publish/verify: print `<name> <version> <digest>`
- list: table headers `NAME VERSION SOURCE DIGEST`
- info: one field per line
- remove: print removed name and version

- [ ] **Step 7: Run tests and verify GREEN**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_help skills_install_list_info_verify_and_remove_local_bundle
```

Expected: tests pass.

- [ ] **Step 8: Commit Task 7**

Run:

```bash
git add crates/agentenv/src/main.rs crates/agentenv/src/skills_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: add skills cli commands"
```

### Task 8: CLI Registry Workflows and Config Precedence

**Files:**
- Modify: `crates/agentenv/src/skills_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI registry tests**

Append:

```rust
#[test]
fn skills_search_add_and_publish_use_filesystem_registry_config() {
    let temp_dir = make_temp_dir("skills-cli-registry");
    let registry = temp_dir.join("registry");
    let bundle = temp_dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), "# Registry Skill\n").unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: registry-skill\nversion: 0.1.0\ndescription: Registry demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    )
    .unwrap();
    fs::write(
        temp_dir.join("agentenv.yaml"),
        format!(
            "version: 0.1.0\nmin_agentenv_version: 0.0.1-alpha0\nsandbox: {{ driver: openshell }}\nagent: {{ driver: codex }}\ncontext: {{ driver: filesystem, mount: . }}\npolicy: {{ tier: balanced, presets: [] }}\nskills:\n  registries:\n    - name: local-dev\n      type: filesystem\n      path: {}\n",
            registry.display()
        ),
    )
    .unwrap();

    let publish = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&bundle)
        .arg("--registry")
        .arg("local-dev")
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(publish.status.success(), "{}", output_summary(&publish));

    let search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("registry")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(search.status.success(), "{}", output_summary(&search));
    assert!(String::from_utf8_lossy(&search.stdout).contains("registry-skill"));

    let add = Command::new(agentenv_bin())
        .arg("skills")
        .arg("add")
        .arg("registry-skill@0.1.0")
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(add.status.success(), "{}", output_summary(&add));
}
```

- [ ] **Step 2: Run test and verify RED**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_search_add_and_publish_use_filesystem_registry_config
```

Expected: failure because CLI config loading or registry routing is incomplete.

- [ ] **Step 3: Implement effective config loading**

In `skills_cli.rs`:

- read `~/.config/agentenv/config.toml` if it exists
- read `agentenv.yaml` from current working directory if it exists
- call `merge_skills_config`
- pass command `--registry` as `SkillsConfigOverride`

Use `std::fs::read_to_string` and attach path context with `anyhow::Context`.

- [ ] **Step 4: Finish command dispatch**

Ensure every subcommand calls the matching service method:

- `search` -> `service.search`
- `add` -> `service.add`
- `install --from` -> `service.install_from_path`
- `list` -> `service.list`
- `info` -> `service.info`
- `remove` -> require `--yes` before deleting
- `publish` -> `service.publish`
- `verify` -> `service.verify`

- [ ] **Step 5: Run test and verify GREEN**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_search_add_and_publish_use_filesystem_registry_config
```

Expected: test passes.

- [ ] **Step 6: Commit Task 8**

Run:

```bash
git add crates/agentenv/src/skills_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: wire skills registry config in cli"
```

### Task 9: Final Verification and Issue Closure Prep

**Files:**
- Modify: `docs/superpowers/plans/2026-05-07-skills-cli.md` only if execution reveals a command correction.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt
```

Expected: exits 0.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: exits 0 with no warnings.

- [ ] **Step 3: Run full test suite**

Run:

```bash
cargo test --workspace
```

Expected: exits 0 with all tests passing.

- [ ] **Step 4: Inspect git status and summarize changed crates**

Run:

```bash
git status --short
git diff --stat HEAD
```

Expected: only intended files changed after the last task commit. PR summary should list `agentenv` and `agentenv-core` as affected crates.

- [ ] **Step 5: Prepare PR notes**

Include these points in the PR body:

```markdown
Closes #28.

Affected crates:
- `agentenv`
- `agentenv-core`

Summary:
- Added `agentenv skills` lifecycle commands.
- Added core-managed skill manifests, digest verification, Ed25519 signature checks, installed cache/index, and registry adapters.
- Added filesystem, HTTP, and OCI registry support without adding a driver axis or changing the driver protocol.
- Kept registry HTTP/OCI egress behind core SSRF URL validation.

Validation:
- `cargo fmt`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

Protocol notes:
- No `agentenv-proto` schema-version bump.
- No new driver kind.
```
