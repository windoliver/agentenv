# M7-5 Bundle As Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `agentenv bundle <source> --as-skill --out <dir>` so a frozen agentenv environment can be emitted as an installable skill bundle with both `skill.yaml` and `SKILL.md` metadata.

**Architecture:** Keep the CLI thin and put deterministic bundle rendering in `agentenv-core::bundle`. Runtime source material comes from the existing environment registry and `freeze_env_lockfile`, while the generated bundle remains compatible with the existing `agentenv skills install --from` path.

**Tech Stack:** Rust 2021, `clap`, `serde`, `serde_json`, `serde_yaml`, `sha2`, `semver`, `time`, existing `agentenv-core` runtime and skills APIs.

---

## File Structure

- Create: `crates/agentenv-core/src/bundle/mod.rs`
- Create: `crates/agentenv-core/src/bundle/model.rs`
- Create: `crates/agentenv-core/src/bundle/render.rs`
- Create: `crates/agentenv-core/src/bundle/writer.rs`
- Create: `crates/agentenv-core/tests/bundle.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Modify: `crates/agentenv-core/src/runtime.rs`
- Create: `crates/agentenv/src/bundle_cli.rs`
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`
- Reference: `docs/superpowers/specs/2026-05-09-m7-5-bundle-as-skill-design.md`

## Task 1: Core Bundle Writer

**Files:**
- Create: `crates/agentenv-core/tests/bundle.rs`
- Create: `crates/agentenv-core/src/bundle/mod.rs`
- Create: `crates/agentenv-core/src/bundle/model.rs`
- Create: `crates/agentenv-core/src/bundle/render.rs`
- Create: `crates/agentenv-core/src/bundle/writer.rs`
- Modify: `crates/agentenv-core/src/lib.rs`

- [ ] **Step 1: Write failing core layout tests**

Create `crates/agentenv-core/tests/bundle.rs` with tests that exercise the public API before it exists:

```rust
use std::{
    fs,
    path::{Path, PathBuf},
};

use agentenv_core::{
    bundle::{
        emit_skill_bundle, BundleSource, ReferenceDocument, SkillBundleInput,
        SkillBundleMetadata,
    },
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    portable_lockfile::{build_portable_lockfile, PortableLockfileInput},
    registry::DriverKind,
    skills::{compute_bundle_digest, load_skill_manifest},
};
use semver::Version;

#[test]
fn emit_skill_bundle_writes_expected_layout() {
    let root = temp_dir("bundle-layout");
    let out = root.join("demo-skill");
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    let output = emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: None,
            git_commit: None,
            git_dirty: None,
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec!["openshell".to_owned(), "codex".to_owned(), "filesystem".to_owned(), "dev-env".to_owned()],
        },
        blueprint_yaml: blueprint_yaml.clone(),
        lockfile_yaml: lockfile_yaml.clone(),
        reference_document: None,
        output_dir: out.clone(),
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap();

    assert_eq!(output.output_dir, out);
    assert_eq!(output.skill_name, "demo");
    assert_eq!(output.version, "1.0.0");
    assert!(out.join("SKILL.md").is_file());
    assert!(out.join("skill.yaml").is_file());
    assert!(out.join("blueprint.yaml").is_file());
    assert!(out.join("agentenv.lock").is_file());
    assert!(out.join("scripts/bootstrap.sh").is_file());
    assert!(out.join(".agentenv/manifest.json").is_file());
    assert!(out.join(".agentenv/provenance.json").is_file());
    assert!(!out.join("references").exists());

    let skill = fs::read_to_string(out.join("SKILL.md")).unwrap();
    assert!(skill.contains("agentenv-bundle: true"));
    assert!(skill.contains("agentenv-schema: \"0.1\""));
    assert!(skill.contains("agentenv reproduce agentenv.lock --name demo"));

    let bootstrap = fs::read_to_string(out.join("scripts/bootstrap.sh")).unwrap();
    assert!(bootstrap.contains("agentenv verify agentenv.lock"));
    assert!(bootstrap.contains("agentenv reproduce agentenv.lock --name \"${ENV_NAME}\""));

    let manifest = load_skill_manifest(&out).unwrap();
    assert_eq!(manifest.name, "demo");
    assert_eq!(manifest.version.to_string(), "1.0.0");
    assert_eq!(manifest.entry, PathBuf::from("SKILL.md"));
    assert!(manifest.declared_files.contains(&PathBuf::from("agentenv.lock")));
    assert!(!manifest.declared_files.iter().any(|path| path.starts_with("references")));

    let digest = compute_bundle_digest(&out, &manifest).unwrap();
    assert_eq!(output.bundle_digest, digest);
    assert_eq!(fs::read_to_string(out.join("blueprint.yaml")).unwrap(), ensure_trailing_newline(&blueprint_yaml));
    assert_eq!(fs::read_to_string(out.join("agentenv.lock")).unwrap(), ensure_trailing_newline(&lockfile_yaml));
}

#[test]
fn emit_skill_bundle_writes_reference_document_when_provided() {
    let root = temp_dir("bundle-reference");
    let out = root.join("demo-skill");
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: Some(root.join("project")),
            git_commit: Some("abc123".to_owned()),
            git_dirty: Some(false),
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: Some("Alice Example".to_owned()),
            license: Some("MIT".to_owned()),
            tags: vec!["openshell".to_owned(), "codex".to_owned(), "filesystem".to_owned(), "dev-env".to_owned()],
        },
        blueprint_yaml,
        lockfile_yaml,
        reference_document: Some(ReferenceDocument {
            source_relative_path: "docs/ARCHITECTURE.md".to_owned(),
            content: "# Architecture\n\nDetails\n".to_owned(),
        }),
        output_dir: out.clone(),
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap();

    let reference = fs::read_to_string(out.join("references/architecture.md")).unwrap();
    assert!(reference.starts_with("# Project Architecture\n\nSource: `docs/ARCHITECTURE.md`\n\n"));
    assert!(reference.contains("# Architecture"));

    let manifest = load_skill_manifest(&out).unwrap();
    assert!(manifest.declared_files.contains(&PathBuf::from("references/architecture.md")));

    let skill = fs::read_to_string(out.join("SKILL.md")).unwrap();
    assert!(skill.contains("author: Alice Example"));
    assert!(skill.contains("license: MIT"));
    assert!(skill.contains("tags: [openshell, codex, filesystem, dev-env]"));
}

#[test]
fn emit_skill_bundle_rejects_existing_output_path() {
    let root = temp_dir("bundle-existing");
    let out = root.join("demo-skill");
    fs::create_dir_all(&out).unwrap();
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    let error = emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: None,
            git_commit: None,
            git_dirty: None,
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec!["dev-env".to_owned()],
        },
        blueprint_yaml,
        lockfile_yaml,
        reference_document: None,
        output_dir: out,
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap_err();

    assert!(error.to_string().contains("output path already exists"));
}

fn minimal_blueprint() -> String {
    r#"version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#
    .to_owned()
}

fn portable_lock_yaml(name: &str, blueprint_yaml: &str, driver_artifacts: &[DriverArtifact]) -> String {
    build_portable_lockfile(PortableLockfileInput {
        name: name.to_owned(),
        blueprint_yaml: blueprint_yaml.to_owned(),
        driver_artifacts: driver_artifacts.to_vec(),
    })
    .unwrap()
    .to_yaml_deterministic()
    .unwrap()
}

fn test_driver_artifacts() -> Vec<DriverArtifact> {
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
        digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        install_hint: None,
        entry: None,
    })
    .collect()
}

fn ensure_trailing_newline(input: &str) -> String {
    if input.ends_with('\n') {
        input.to_owned()
    } else {
        format!("{input}\n")
    }
}

fn temp_dir(prefix: &str) -> PathBuf {
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

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test bundle
```

Expected: FAIL with unresolved import `agentenv_core::bundle`.

- [ ] **Step 3: Add core module exports and models**

Modify `crates/agentenv-core/src/lib.rs`:

```rust
pub mod bundle;
```

Create `crates/agentenv-core/src/bundle/mod.rs`:

```rust
mod model;
mod render;
mod writer;

pub use model::{
    BundleManifest, BundleManifestFile, BundleSource, BundleWarning, ReferenceDocument,
    SkillBundleInput, SkillBundleMetadata, SkillBundleOutput,
};
pub use writer::{emit_skill_bundle, BundleError};
```

Create `crates/agentenv-core/src/bundle/model.rs`:

```rust
use std::path::PathBuf;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::driver_artifact::DriverArtifact;

#[derive(Debug, Clone)]
pub struct SkillBundleInput {
    pub source: BundleSource,
    pub metadata: SkillBundleMetadata,
    pub blueprint_yaml: String,
    pub lockfile_yaml: String,
    pub reference_document: Option<ReferenceDocument>,
    pub output_dir: PathBuf,
    pub agentenv_version: String,
    pub created_at: String,
    pub driver_artifacts: Vec<DriverArtifact>,
}

#[derive(Debug, Clone)]
pub struct BundleSource {
    pub env_name: String,
    pub project_path: Option<PathBuf>,
    pub git_commit: Option<String>,
    pub git_dirty: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct SkillBundleMetadata {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub author: Option<String>,
    pub license: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReferenceDocument {
    pub source_relative_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillBundleOutput {
    pub output_dir: PathBuf,
    pub skill_name: String,
    pub version: String,
    pub bundle_digest: String,
    pub blueprint_digest: String,
    pub lockfile_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<BundleWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleWarning {
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifest {
    pub version: String,
    pub kind: String,
    pub skill: BundleManifestSkill,
    pub agentenv: BundleManifestAgentenv,
    pub files: Vec<BundleManifestFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifestSkill {
    pub name: String,
    pub version: String,
    pub entry: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifestAgentenv {
    pub schema: String,
    pub bundle: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifestFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleProvenance {
    pub version: String,
    pub created_at: String,
    pub agentenv_version: String,
    pub source: BundleProvenanceSource,
    pub digests: BundleProvenanceDigests,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleProvenanceSource {
    pub kind: String,
    pub env_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_git_dirty: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleProvenanceDigests {
    pub blueprint: String,
    pub lockfile: String,
    pub manifest: String,
}
```

- [ ] **Step 4: Add render helpers**

Create `crates/agentenv-core/src/bundle/render.rs`:

```rust
use super::model::{ReferenceDocument, SkillBundleMetadata};

pub(crate) const AGENTENV_BUNDLE_SCHEMA: &str = "0.1";

pub(crate) fn render_skill_md(metadata: &SkillBundleMetadata, env_name: &str, has_reference: bool) -> String {
    let mut frontmatter = Vec::new();
    frontmatter.push("---".to_owned());
    frontmatter.push(format!("name: {}", metadata.name));
    frontmatter.push(format!("description: {}", yaml_string(&metadata.description)));
    frontmatter.push(format!("version: {}", metadata.version));
    if let Some(author) = metadata.author.as_deref() {
        frontmatter.push(format!("author: {}", yaml_string(author)));
    }
    if let Some(license) = metadata.license.as_deref() {
        frontmatter.push(format!("license: {}", yaml_string(license)));
    }
    if !metadata.tags.is_empty() {
        frontmatter.push(format!("tags: [{}]", metadata.tags.join(", ")));
    }
    frontmatter.push("agentenv-bundle: true".to_owned());
    frontmatter.push(format!("agentenv-schema: \"{}\"", AGENTENV_BUNDLE_SCHEMA));
    frontmatter.push("---".to_owned());

    let mut body = vec![
        format!("# {}", metadata.name),
        String::new(),
        format!("This skill reconstructs the `{env_name}` development environment with `agentenv`."),
        String::new(),
        "## Bootstrap".to_owned(),
        String::new(),
        "Run this from the skill directory:".to_owned(),
        String::new(),
        "```bash".to_owned(),
        "scripts/bootstrap.sh".to_owned(),
        "```".to_owned(),
        String::new(),
        "The script verifies `agentenv.lock` and reproduces the environment with:".to_owned(),
        String::new(),
        "```bash".to_owned(),
        "agentenv verify agentenv.lock".to_owned(),
        format!("agentenv reproduce agentenv.lock --name {env_name}"),
        "```".to_owned(),
        String::new(),
        "## Included Files".to_owned(),
        String::new(),
        "- `blueprint.yaml` is the frozen blueprint used to create the environment.".to_owned(),
        "- `agentenv.lock` pins drivers, artifacts, policy, and credential references.".to_owned(),
    ];
    if has_reference {
        body.push("- `references/architecture.md` contains copied project architecture notes when available.".to_owned());
    }

    format!("{}\n\n{}\n", frontmatter.join("\n"), body.join("\n"))
}

pub(crate) fn render_skill_yaml(metadata: &SkillBundleMetadata, has_reference: bool) -> String {
    let mut files = vec![
        "  - SKILL.md".to_owned(),
        "  - blueprint.yaml".to_owned(),
        "  - agentenv.lock".to_owned(),
        "  - scripts/**".to_owned(),
        "  - .agentenv/**".to_owned(),
    ];
    if has_reference {
        files.push("  - references/**".to_owned());
    }

    let mut yaml = vec![
        format!("name: {}", metadata.name),
        format!("version: {}", metadata.version),
        format!("description: {}", yaml_string(&metadata.description)),
        "entry: SKILL.md".to_owned(),
        "files:".to_owned(),
    ];
    yaml.extend(files);
    if !metadata.tags.is_empty() {
        yaml.push("tags:".to_owned());
        yaml.extend(metadata.tags.iter().map(|tag| format!("  - {tag}")));
    }
    yaml.push("agentenv_bundle: true".to_owned());
    yaml.push(format!("agentenv_schema: \"{}\"", AGENTENV_BUNDLE_SCHEMA));
    format!("{}\n", yaml.join("\n"))
}

pub(crate) fn render_bootstrap(env_name: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n\nSCRIPT_DIR=\"$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\"\nBUNDLE_DIR=\"$(cd \"${{SCRIPT_DIR}}/..\" && pwd)\"\nENV_NAME=\"${{AGENTENV_ENV_NAME:-{env_name}}}\"\n\ncd \"${{BUNDLE_DIR}}\"\nagentenv verify agentenv.lock\nagentenv reproduce agentenv.lock --name \"${{ENV_NAME}}\"\n"
    )
}

pub(crate) fn render_reference(document: &ReferenceDocument) -> String {
    format!(
        "# Project Architecture\n\nSource: `{}`\n\n{}",
        document.source_relative_path,
        ensure_trailing_newline(&document.content)
    )
}

pub(crate) fn ensure_trailing_newline(input: &str) -> String {
    if input.ends_with('\n') {
        input.to_owned()
    } else {
        format!("{input}\n")
    }
}

fn yaml_string(input: &str) -> String {
    if input.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.' | b':' | b'/')) {
        input.to_owned()
    } else {
        serde_yaml::to_string(input)
            .expect("string serialization cannot fail")
            .trim()
            .to_owned()
    }
}
```

- [ ] **Step 5: Add writer implementation**

Create `crates/agentenv-core/src/bundle/writer.rs` with this structure:

```rust
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    model::{
        BundleManifest, BundleManifestAgentenv, BundleManifestFile, BundleManifestSkill,
        BundleProvenance, BundleProvenanceDigests, BundleProvenanceSource,
        SkillBundleInput, SkillBundleOutput,
    },
    render::{
        ensure_trailing_newline, render_bootstrap, render_reference, render_skill_md,
        render_skill_yaml, AGENTENV_BUNDLE_SCHEMA,
    },
};

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("output path already exists: `{path}`")]
    OutputExists { path: PathBuf },
    #[error("failed to read or write bundle path `{path}`: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("failed to serialize bundle data at `{path}`: {source}")]
    Serde { path: PathBuf, #[source] source: serde_json::Error },
    #[error(transparent)]
    Skill(#[from] crate::skills::SkillError),
    #[error(transparent)]
    Lockfile(#[from] crate::portable_lockfile::PortableLockfileError),
    #[error("generated lockfile did not verify: {details}")]
    LockfileVerification { details: String },
}

pub fn emit_skill_bundle(input: SkillBundleInput) -> Result<SkillBundleOutput, BundleError> {
    if input.output_dir.exists() {
        return Err(BundleError::OutputExists { path: input.output_dir });
    }

    let staging = staging_path(&input.output_dir)?;
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|source| BundleError::Io { path: staging.clone(), source })?;
    }
    fs::create_dir_all(&staging).map_err(|source| BundleError::Io { path: staging.clone(), source })?;

    let result = write_bundle(&input, &staging).and_then(|mut output| {
        validate_bundle(&input, &staging)?;
        fs::rename(&staging, &input.output_dir).map_err(|source| BundleError::Io {
            path: input.output_dir.clone(),
            source,
        })?;
        output.output_dir = input.output_dir.clone();
        Ok(output)
    });

    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }

    result
}

fn write_bundle(input: &SkillBundleInput, staging: &Path) -> Result<SkillBundleOutput, BundleError> {
    let has_reference = input.reference_document.is_some();
    write_file(&staging.join("SKILL.md"), &render_skill_md(&input.metadata, &input.source.env_name, has_reference))?;
    write_file(&staging.join("skill.yaml"), &render_skill_yaml(&input.metadata, has_reference))?;
    write_file(&staging.join("blueprint.yaml"), &ensure_trailing_newline(&input.blueprint_yaml))?;
    write_file(&staging.join("agentenv.lock"), &ensure_trailing_newline(&input.lockfile_yaml))?;
    write_file(&staging.join("scripts/bootstrap.sh"), &render_bootstrap(&input.source.env_name))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = staging.join("scripts/bootstrap.sh");
        let mut permissions = fs::metadata(&path).map_err(|source| BundleError::Io { path: path.clone(), source })?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).map_err(|source| BundleError::Io { path, source })?;
    }

    if let Some(reference) = input.reference_document.as_ref() {
        write_file(&staging.join("references/architecture.md"), &render_reference(reference))?;
    }

    let blueprint_digest = digest_file(&staging.join("blueprint.yaml"))?;
    let lockfile_digest = digest_file(&staging.join("agentenv.lock"))?;
    let mut manifest = manifest_for(input, staging)?;
    write_json(&staging.join(".agentenv/manifest.json"), &manifest)?;
    let manifest_digest = digest_file(&staging.join(".agentenv/manifest.json"))?;
    let provenance = BundleProvenance {
        version: AGENTENV_BUNDLE_SCHEMA.to_owned(),
        created_at: input.created_at.clone(),
        agentenv_version: input.agentenv_version.clone(),
        source: BundleProvenanceSource {
            kind: "environment".to_owned(),
            env_name: input.source.env_name.clone(),
            project_path: input.source.project_path.as_ref().map(|path| path.display().to_string()),
            project_git_commit: input.source.git_commit.clone(),
            project_git_dirty: input.source.git_dirty,
        },
        digests: BundleProvenanceDigests {
            blueprint: blueprint_digest.clone(),
            lockfile: lockfile_digest.clone(),
            manifest: manifest_digest,
        },
    };
    write_json(&staging.join(".agentenv/provenance.json"), &provenance)?;

    manifest.files = manifest_files(staging)?;
    write_json(&staging.join(".agentenv/manifest.json"), &manifest)?;

    let skill_manifest = crate::skills::load_skill_manifest(staging)?;
    let bundle_digest = crate::skills::compute_bundle_digest(staging, &skill_manifest)?;

    Ok(SkillBundleOutput {
        output_dir: staging.to_path_buf(),
        skill_name: input.metadata.name.clone(),
        version: input.metadata.version.to_string(),
        bundle_digest,
        blueprint_digest,
        lockfile_digest,
        warnings: Vec::new(),
    })
}
```

Continue the same file with these private helpers:

```rust
fn validate_bundle(input: &SkillBundleInput, staging: &Path) -> Result<(), BundleError> {
    let manifest = crate::skills::load_skill_manifest(staging)?;
    crate::skills::compute_bundle_digest(staging, &manifest)?;
    let report = crate::portable_lockfile::verify_portable_lockfile_yaml(
        &fs::read_to_string(staging.join("agentenv.lock")).map_err(|source| BundleError::Io {
            path: staging.join("agentenv.lock"),
            source,
        })?,
        &input.driver_artifacts,
    )?;
    if !report.errors.is_empty() {
        let details = report.errors.iter().map(|issue| issue.message.as_str()).collect::<Vec<_>>().join("; ");
        return Err(BundleError::LockfileVerification { details });
    }
    Ok(())
}

fn manifest_for(input: &SkillBundleInput, staging: &Path) -> Result<BundleManifest, BundleError> {
    Ok(BundleManifest {
        version: AGENTENV_BUNDLE_SCHEMA.to_owned(),
        kind: "agentenv.skill_bundle".to_owned(),
        skill: BundleManifestSkill {
            name: input.metadata.name.clone(),
            version: input.metadata.version.to_string(),
            entry: "SKILL.md".to_owned(),
        },
        agentenv: BundleManifestAgentenv {
            schema: AGENTENV_BUNDLE_SCHEMA.to_owned(),
            bundle: true,
        },
        files: manifest_files(staging)?,
    })
}

fn manifest_files(root: &Path) -> Result<Vec<BundleManifestFile>, BundleError> {
    let mut paths = Vec::new();
    collect_manifest_paths(root, root, &mut paths)?;
    paths.sort();
    paths.into_iter().map(|path| {
        let absolute = root.join(&path);
        Ok(BundleManifestFile {
            path: path.to_string_lossy().replace('\\', "/"),
            sha256: digest_file(&absolute)?,
        })
    }).collect()
}

fn collect_manifest_paths(root: &Path, dir: &Path, paths: &mut Vec<PathBuf>) -> Result<(), BundleError> {
    for entry in fs::read_dir(dir).map_err(|source| BundleError::Io { path: dir.to_path_buf(), source })? {
        let entry = entry.map_err(|source| BundleError::Io { path: dir.to_path_buf(), source })?;
        let path = entry.path();
        let relative = path.strip_prefix(root).expect("path collected from root").to_path_buf();
        if relative == Path::new(".agentenv/provenance.json") {
            continue;
        }
        let file_type = entry.file_type().map_err(|source| BundleError::Io { path: path.clone(), source })?;
        if file_type.is_dir() {
            collect_manifest_paths(root, &path, paths)?;
        } else if file_type.is_file() {
            paths.push(relative);
        }
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, BundleError> {
    let bytes = fs::read(path).map_err(|source| BundleError::Io { path: path.to_path_buf(), source })?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn write_file(path: &Path, content: &str) -> Result<(), BundleError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| BundleError::Io { path: parent.to_path_buf(), source })?;
    }
    fs::write(path, content).map_err(|source| BundleError::Io { path: path.to_path_buf(), source })
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), BundleError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| BundleError::Io { path: parent.to_path_buf(), source })?;
    }
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|source| BundleError::Serde { path: path.to_path_buf(), source })?;
    fs::write(path, format!("{rendered}\n")).map_err(|source| BundleError::Io { path: path.to_path_buf(), source })
}

fn staging_path(output: &Path) -> Result<PathBuf, BundleError> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let name = output.file_name().and_then(|name| name.to_str()).unwrap_or("bundle");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| BundleError::Io {
            path: parent.to_path_buf(),
            source: std::io::Error::other(source),
        })?
        .as_nanos();
    Ok(parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce)))
}
```

- [ ] **Step 6: Run core bundle tests**

Run:

```bash
cargo test -p agentenv-core --test bundle
```

Expected: PASS.

- [ ] **Step 7: Commit core writer**

```bash
git add crates/agentenv-core/src/lib.rs crates/agentenv-core/src/bundle crates/agentenv-core/tests/bundle.rs
git commit -m "feat: add skill bundle writer"
```

## Task 2: Runtime Freeze Source Helper

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`

- [ ] **Step 1: Add failing runtime unit test**

In the `#[cfg(test)]` module in `crates/agentenv-core/src/runtime.rs`, add:

```rust
#[test]
fn freeze_env_for_bundle_returns_persisted_blueprint_and_portable_lockfile() {
    let root = unique_root("agentenv-runtime-freeze-bundle-source");
    let options = RuntimeOptions {
        root: root.clone(),
        log_level: LogLevel::Info,
        non_interactive: true,
    };
    let env_dir = root.join("envs").join("demo");
    fs::create_dir_all(&env_dir).unwrap();
    let driver_version = env!("CARGO_PKG_VERSION");
    fs::write(
        env_dir.join("state.json"),
        serde_json::json!({
            "version": "0.1.0",
            "name": "demo",
            "phase": "running",
            "created_at": "2026-05-09T00:00:00Z",
            "updated_at": "2026-05-09T00:00:00Z",
            "drivers": {
                "sandbox": {"name": "openshell", "version": driver_version},
                "agent": {"name": "codex", "version": driver_version},
                "context": {"name": "filesystem", "version": driver_version},
                "inference": {"name": "passthrough", "version": driver_version}
            },
            "handles": {},
            "endpoints": {},
            "first_enter_hint_shown": false
        })
        .to_string(),
    )
    .unwrap();
    let blueprint_yaml = r#"version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;
    fs::write(env_dir.join("blueprint.yaml"), blueprint_yaml).unwrap();
    let lock_yaml = crate::lifecycle::freeze_from_blueprint_yaml(blueprint_yaml).unwrap();
    fs::write(env_dir.join("lock.yaml"), lock_yaml).unwrap();

    let frozen = freeze_env_for_bundle(&options, "demo").unwrap();

    assert_eq!(frozen.env_name, "demo");
    assert_eq!(frozen.blueprint_yaml, blueprint_yaml);
    assert!(frozen.lockfile_yaml.contains("version: 0.2.0"));
    assert!(frozen.lockfile_yaml.contains("name: demo"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p agentenv-core runtime::tests::freeze_env_for_bundle_returns_persisted_blueprint_and_portable_lockfile
```

Expected: FAIL with missing `freeze_env_for_bundle`.

- [ ] **Step 3: Add runtime helper**

Near `EnvDescription` in `crates/agentenv-core/src/runtime.rs`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenEnvBundleSource {
    pub env_name: String,
    pub blueprint_yaml: String,
    pub lockfile_yaml: String,
}
```

Near `freeze_env_lockfile`, add:

```rust
pub fn freeze_env_for_bundle(
    options: &RuntimeOptions,
    name: &str,
) -> RuntimeResult<FrozenEnvBundleSource> {
    let description = describe_env(options, name)?;
    let lockfile_yaml = freeze_env_lockfile(options, name)?;
    Ok(FrozenEnvBundleSource {
        env_name: description.state.name,
        blueprint_yaml: description.blueprint_yaml,
        lockfile_yaml,
    })
}
```

- [ ] **Step 4: Run runtime test**

Run:

```bash
cargo test -p agentenv-core runtime::tests::freeze_env_for_bundle_returns_persisted_blueprint_and_portable_lockfile
```

Expected: PASS.

- [ ] **Step 5: Commit runtime helper**

```bash
git add crates/agentenv-core/src/runtime.rs
git commit -m "feat: expose frozen env source for bundles"
```

## Task 3: CLI Command Skeleton

**Files:**
- Create: `crates/agentenv/src/bundle_cli.rs`
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Add failing CLI help and missing-env tests**

In `crates/agentenv/tests/cli_behavior.rs`, add near existing CLI command tests:

```rust
#[test]
fn bundle_help_lists_as_skill_and_out_flags() {
    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--as-skill"), "stdout was: {stdout}");
    assert!(stdout.contains("--out"), "stdout was: {stdout}");
    assert!(stdout.contains("--env"), "stdout was: {stdout}");
}

#[test]
fn bundle_as_skill_rejects_missing_env() {
    let temp_dir = make_temp_dir("bundle-missing-env");
    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("missing")
        .arg("--as-skill")
        .arg("--out")
        .arg(temp_dir.join("missing-skill"))
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("env `missing` not found") || stderr.contains("environment `missing` does not exist"), "stderr was: {stderr}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv --test cli_behavior bundle_help_lists_as_skill_and_out_flags bundle_as_skill_rejects_missing_env
```

Expected: FAIL because `bundle` is not a recognized command.

- [ ] **Step 3: Add CLI module and command enum entry**

Create `crates/agentenv/src/bundle_cli.rs`:

```rust
use std::path::PathBuf;

use agentenv_core::bundle::{
    emit_skill_bundle, BundleSource, ReferenceDocument, SkillBundleInput,
    SkillBundleMetadata, SkillBundleOutput,
};
use anyhow::{bail, Context, Result};
use clap::Args;
use semver::Version;
use serde::Serialize;

#[derive(Debug, Args)]
pub struct BundleArgs {
    pub source: String,
    #[arg(long)]
    pub as_skill: bool,
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub env: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub author: Option<String>,
    #[arg(long)]
    pub license: Option<String>,
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct BundleJson {
    output_dir: PathBuf,
    skill_name: String,
    version: String,
    bundle_digest: String,
    blueprint_digest: String,
    lockfile_digest: String,
}

pub fn run_bundle(args: BundleArgs) -> Result<()> {
    if !args.as_skill {
        bail!("bundle currently supports only --as-skill");
    }
    let out = args
        .out
        .clone()
        .context("bundle --as-skill requires --out <dir>")?;

    let source_path = PathBuf::from(&args.source);
    let project_path = source_path.is_dir().then_some(source_path.clone());
    let env_name = match args.env.as_deref() {
        Some(env) => env.to_owned(),
        None if project_path.is_some() => source_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("project directory must have a UTF-8 basename")?
            .to_owned(),
        None => args.source.clone(),
    };

    let options = crate::runtime_options(true)?;
    let frozen = agentenv_core::runtime::freeze_env_for_bundle(&options, &env_name)
        .with_context(|| format!("environment `{env_name}` does not exist or cannot be frozen"))?;
    let driver_artifacts = crate::discover_runtime_driver_artifacts(&options)?;
    let metadata = build_metadata(&args, &frozen, project_path.as_ref())?;
    let reference_document = load_reference_document(project_path.as_ref())?;

    let output = emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: frozen.env_name.clone(),
            project_path,
            git_commit: None,
            git_dirty: None,
        },
        metadata,
        blueprint_yaml: frozen.blueprint_yaml,
        lockfile_yaml: frozen.lockfile_yaml,
        reference_document,
        output_dir: out,
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        created_at: created_at_now(),
        driver_artifacts,
    })?;

    print_output(output, args.json)
}
```

Continue `bundle_cli.rs` with:

```rust
fn build_metadata(
    args: &BundleArgs,
    frozen: &agentenv_core::runtime::FrozenEnvBundleSource,
    _project_path: Option<&PathBuf>,
) -> Result<SkillBundleMetadata> {
    let name = args.name.clone().unwrap_or_else(|| frozen.env_name.clone());
    agentenv_core::skills::validate_skill_name(&name)
        .with_context(|| format!("derived skill name `{name}` is invalid; pass --name"))?;
    let version = args
        .version
        .as_deref()
        .unwrap_or("1.0.0")
        .parse::<Version>()
        .with_context(|| format!("invalid skill version `{}`", args.version.as_deref().unwrap_or("1.0.0")))?;
    let description = args
        .description
        .clone()
        .unwrap_or_else(|| format!("Reproducible dev env for {name}"));
    let mut tags = args.tags.clone();
    if tags.is_empty() {
        tags.push("dev-env".to_owned());
    }
    Ok(SkillBundleMetadata {
        name,
        version,
        description,
        author: args.author.clone(),
        license: args.license.clone(),
        tags,
    })
}

fn load_reference_document(project_path: Option<&PathBuf>) -> Result<Option<ReferenceDocument>> {
    let Some(project_path) = project_path else {
        return Ok(None);
    };
    for relative in ["docs/ARCHITECTURE.md", "ARCHITECTURE.md", "README.md"] {
        let path = project_path.join(relative);
        if path.is_file() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read reference document `{}`", path.display()))?;
            return Ok(Some(ReferenceDocument {
                source_relative_path: relative.to_owned(),
                content,
            }));
        }
    }
    Ok(None)
}

fn created_at_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting cannot fail")
}

fn print_output(output: SkillBundleOutput, json: bool) -> Result<()> {
    if json {
        let rendered = serde_json::to_string_pretty(&BundleJson {
            output_dir: output.output_dir,
            skill_name: output.skill_name,
            version: output.version,
            bundle_digest: output.bundle_digest,
            blueprint_digest: output.blueprint_digest,
            lockfile_digest: output.lockfile_digest,
        })?;
        println!("{rendered}");
    } else {
        println!(
            "Skill bundle written: {} ({})",
            output.output_dir.display(),
            output.bundle_digest
        );
    }
    Ok(())
}
```

Modify `crates/agentenv/src/main.rs`:

```rust
mod bundle_cli;
```

Add to `Commands`:

```rust
Bundle(bundle_cli::BundleArgs),
```

Add to `run()` match:

```rust
Some(Commands::Bundle(args)) => bundle_cli::run_bundle(args),
```

- [ ] **Step 4: Run CLI skeleton tests**

Run:

```bash
cargo test -p agentenv --test cli_behavior bundle_help_lists_as_skill_and_out_flags bundle_as_skill_rejects_missing_env
```

Expected: PASS.

- [ ] **Step 5: Commit CLI skeleton**

```bash
git add crates/agentenv/src/main.rs crates/agentenv/src/bundle_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: add bundle as skill cli skeleton"
```

## Task 4: Metadata And Reference Detection

**Files:**
- Modify: `crates/agentenv/src/bundle_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Add failing CLI export test with project metadata**

In `crates/agentenv/tests/cli_behavior.rs`, add:

```rust
#[test]
fn bundle_as_skill_exports_existing_env_with_project_reference() {
    let temp_dir = make_temp_dir("bundle-export-project");
    write_minimal_env_state(&temp_dir, "demo");
    let project = temp_dir.join("demo");
    fs::create_dir_all(project.join("docs")).unwrap();
    fs::write(project.join("docs/ARCHITECTURE.md"), "# Demo Architecture\n").unwrap();

    let output_dir = temp_dir.join("demo-skill");
    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg(&project)
        .arg("--as-skill")
        .arg("--out")
        .arg(&output_dir)
        .arg("--author")
        .arg("Alice Example")
        .arg("--license")
        .arg("MIT")
        .arg("--tag")
        .arg("rust")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_dir.join("SKILL.md").is_file());
    assert!(output_dir.join("skill.yaml").is_file());
    assert!(output_dir.join("references/architecture.md").is_file());

    let skill = fs::read_to_string(output_dir.join("SKILL.md")).unwrap();
    assert!(skill.contains("author: Alice Example"));
    assert!(skill.contains("license: MIT"));
    assert!(skill.contains("tags: [rust]"));

    let reference = fs::read_to_string(output_dir.join("references/architecture.md")).unwrap();
    assert!(reference.contains("Source: `docs/ARCHITECTURE.md`"));
    assert!(reference.contains("# Demo Architecture"));
}
```

- [ ] **Step 2: Run test to verify it fails on lockfile verification or metadata gaps**

Run:

```bash
cargo test -p agentenv --test cli_behavior bundle_as_skill_exports_existing_env_with_project_reference
```

Expected: FAIL if `write_minimal_env_state` writes a legacy lockfile that the bundle verifier rejects, or PASS if Task 3 already routes through `freeze_env_for_bundle` correctly. If it passes, continue to Step 4.

- [ ] **Step 3: Ensure CLI uses frozen portable lockfile and discovered driver artifacts**

If the test fails because the generated lockfile does not verify, keep the CLI call to `freeze_env_for_bundle` and verify `discover_runtime_driver_artifacts` is called after `runtime_options(true)`. Do not read `lock.yaml` directly in `bundle_cli.rs`.

Use this call shape in `run_bundle`:

```rust
let options = crate::runtime_options(true)?;
let frozen = agentenv_core::runtime::freeze_env_for_bundle(&options, &env_name)
    .with_context(|| format!("environment `{env_name}` does not exist or cannot be frozen"))?;
let driver_artifacts = crate::discover_runtime_driver_artifacts(&options)
    .context("failed to discover driver artifacts for bundle verification")?;
```

- [ ] **Step 4: Add git and license detection helpers**

Extend `build_metadata` in `crates/agentenv/src/bundle_cli.rs` so explicit CLI flags win and project detection fills absent optional fields:

```rust
let author = args
    .author
    .clone()
    .or_else(|| project_path.and_then(detect_git_author));
let license = args
    .license
    .clone()
    .or_else(|| project_path.and_then(detect_license));
```

Add helper functions:

```rust
fn detect_git_author(project_path: &PathBuf) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["config", "user.name"])
        .current_dir(project_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn detect_git_commit(project_path: &PathBuf) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(project_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn detect_git_dirty(project_path: &PathBuf) -> Option<bool> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(project_path)
        .output()
        .ok()?;
    output.status.success().then(|| !output.stdout.is_empty())
}

fn detect_license(project_path: &PathBuf) -> Option<String> {
    let cargo_toml = project_path.join("Cargo.toml");
    if cargo_toml.is_file() {
        let content = std::fs::read_to_string(cargo_toml).ok()?;
        let value: toml::Value = toml::from_str(&content).ok()?;
        if let Some(license) = value.get("package").and_then(|package| package.get("license")).and_then(|license| license.as_str()) {
            return Some(license.to_owned());
        }
        if let Some(license) = value.get("workspace").and_then(|workspace| workspace.get("package")).and_then(|package| package.get("license")).and_then(|license| license.as_str()) {
            return Some(license.to_owned());
        }
    }
    for name in ["LICENSE-MIT", "LICENSE_APACHE", "LICENSE-APACHE", "LICENSE"] {
        if project_path.join(name).is_file() {
            return Some(name.trim_start_matches("LICENSE-").trim_start_matches("LICENSE_").to_owned()).filter(|value| !value.is_empty());
        }
    }
    None
}
```

When building `BundleSource`, set git fields:

```rust
let git_commit = project_path.as_ref().and_then(detect_git_commit);
let git_dirty = project_path.as_ref().and_then(detect_git_dirty);
```

- [ ] **Step 5: Run metadata export test**

Run:

```bash
cargo test -p agentenv --test cli_behavior bundle_as_skill_exports_existing_env_with_project_reference
```

Expected: PASS.

- [ ] **Step 6: Commit metadata detection**

```bash
git add crates/agentenv/src/bundle_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: enrich skill bundle metadata"
```

## Task 5: JSON Output And Install Compatibility

**Files:**
- Modify: `crates/agentenv/tests/cli_behavior.rs`
- Modify: `crates/agentenv/src/bundle_cli.rs`

- [ ] **Step 1: Add failing JSON and install compatibility test**

In `crates/agentenv/tests/cli_behavior.rs`, add:

```rust
#[test]
fn bundle_as_skill_json_output_installs_as_local_skill() {
    let temp_dir = make_temp_dir("bundle-json-install");
    write_minimal_env_state(&temp_dir, "demo");
    let output_dir = temp_dir.join("demo-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("demo")
        .arg("--as-skill")
        .arg("--out")
        .arg(&output_dir)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["skill_name"], "demo");
    assert_eq!(json["version"], "1.0.0");
    assert!(json["bundle_digest"].as_str().unwrap().starts_with("sha256:"));
    assert!(json["blueprint_digest"].as_str().unwrap().starts_with("sha256:"));
    assert!(json["lockfile_digest"].as_str().unwrap().starts_with("sha256:"));

    let install = Command::new(agentenv_bin())
        .arg("skills")
        .arg("install")
        .arg("--from")
        .arg(&output_dir)
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );

    let verify = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("demo")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}
```

- [ ] **Step 2: Run test to verify it fails if JSON shape or install compatibility is incomplete**

Run:

```bash
cargo test -p agentenv --test cli_behavior bundle_as_skill_json_output_installs_as_local_skill
```

Expected: FAIL if JSON keys are absent or if `skill.yaml` does not declare all generated files.

- [ ] **Step 3: Fix JSON output shape**

Ensure `BundleJson` in `crates/agentenv/src/bundle_cli.rs` has exactly these fields:

```rust
#[derive(Debug, Serialize)]
struct BundleJson {
    output_dir: PathBuf,
    skill_name: String,
    version: String,
    bundle_digest: String,
    blueprint_digest: String,
    lockfile_digest: String,
}
```

Ensure `print_output` maps every field from `SkillBundleOutput` and prints pretty JSON with a trailing newline through `println!("{rendered}")`.

- [ ] **Step 4: Fix manifest compatibility if needed**

If install fails with an unsafe or missing bundle path, adjust `render_skill_yaml` in `crates/agentenv-core/src/bundle/render.rs` so `files` includes every generated regular file through accepted patterns:

```yaml
files:
  - SKILL.md
  - blueprint.yaml
  - agentenv.lock
  - scripts/**
  - .agentenv/**
```

When a reference document exists, also include:

```yaml
  - references/**
```

Do not include `references/**` when no reference document exists because `load_skill_manifest` rejects empty glob matches.

- [ ] **Step 5: Run compatibility test**

Run:

```bash
cargo test -p agentenv --test cli_behavior bundle_as_skill_json_output_installs_as_local_skill
```

Expected: PASS.

- [ ] **Step 6: Commit JSON and install compatibility**

```bash
git add crates/agentenv/src/bundle_cli.rs crates/agentenv-core/src/bundle/render.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "test: verify bundle installs as skill"
```

## Task 6: Final Verification And Documentation

**Files:**
- Modify: `docs/superpowers/specs/2026-05-09-m7-5-bundle-as-skill-design.md` if implementation names differ from the approved spec
- Modify: `docs/superpowers/plans/2026-05-09-m7-5-bundle-as-skill.md` only if the executed implementation intentionally changes task ordering

- [ ] **Step 1: Run focused tests**

Run:

```bash
cargo test -p agentenv-core --test bundle
cargo test -p agentenv-core runtime::tests::freeze_env_for_bundle_returns_persisted_blueprint_and_portable_lockfile
cargo test -p agentenv --test cli_behavior bundle
```

Expected: all PASS.

- [ ] **Step 2: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits 0 and formats touched Rust files.

- [ ] **Step 3: Run clippy**

Run:

```bash
cargo clippy --workspace -- -D warnings
```

Expected: PASS with no warnings.

- [ ] **Step 4: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git diff --stat
git diff -- docs/superpowers/specs/2026-05-09-m7-5-bundle-as-skill-design.md docs/superpowers/plans/2026-05-09-m7-5-bundle-as-skill.md
```

Expected: only intentional source, test, and documentation changes remain.

- [ ] **Step 6: Commit final verification fixes**

If verification required fixes, commit them:

```bash
git add crates/agentenv-core/src crates/agentenv-core/tests crates/agentenv/src crates/agentenv/tests docs/superpowers/specs/2026-05-09-m7-5-bundle-as-skill-design.md docs/superpowers/plans/2026-05-09-m7-5-bundle-as-skill.md
git commit -m "feat: emit agentenv bundles as skills"
```

If no fixes remain after prior task commits, do not create an empty commit.

## Self-Review Notes

- Spec coverage: the plan covers both metadata surfaces, strict frozen-env source material, output layout, bootstrap script, reference document selection, manifest/provenance generation, overwrite refusal, JSON output, and install compatibility.
- Scope: this is one coherent subsystem. It touches core rendering, runtime freeze material, CLI wiring, and tests, but does not add a driver axis or registry behavior.
- Type consistency: `SkillBundleInput`, `SkillBundleMetadata`, `BundleSource`, `ReferenceDocument`, and `SkillBundleOutput` use the same field names across core tests, core implementation, and CLI code.
- Verification: focused tests, formatting, clippy, and full workspace tests are listed as required final commands.
