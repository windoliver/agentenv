# M7-3 Local Skill Cache Lockfile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the local skill cache layout, portable lockfile skill pins, `agentenv skills verify --all`, and `agentenv skills prune`.

**Architecture:** Add a focused `agentenv_core::skills` module for cache paths, metadata, index rebuilding, verification, and prune planning. Extend the existing portable YAML lockfile with deterministic skill pins. Keep registry fetch/publish and sandboxed agent regression outside this issue.

**Tech Stack:** Rust 2021, `serde`, `serde_json`, `serde_yaml`, `sha2`, `hex`, `ed25519-dalek`, `thiserror`, existing `clap` CLI and integration test style.

---

## File Structure

- Create `crates/agentenv-core/src/skills.rs`
  - Owns `SkillCacheLayout`, metadata structs, index rebuilding, verification report types, trust keys, self-test execution, and prune planning.
- Modify `crates/agentenv-core/src/lib.rs`
  - Exposes `pub mod skills;`.
- Modify `crates/agentenv-core/src/lockfile.rs`
  - Adds `SkillPin`, `PortableLockfile.skills`, and duplicate/digest validation.
- Modify `crates/agentenv-core/src/portable_lockfile.rs`
  - Initializes `skills: Vec::new()` in generated portable lockfiles and includes skill pin verification helpers.
- Create `crates/agentenv-core/tests/skills_cache.rs`
  - Covers layout, metadata parsing, index ordering, verification, signatures, self-tests, and prune planning.
- Modify `crates/agentenv-core/tests/portable_lockfile.rs`
  - Covers skill pin serialization and duplicate validation.
- Modify `crates/agentenv/src/main.rs`
  - Adds `agentenv skills verify --all` and `agentenv skills prune [--dry-run]`.
- Modify `crates/agentenv/tests/cli_behavior.rs`
  - Covers CLI verify/prune success and failure behavior.

---

### Task 1: Skill Cache Layout, Metadata, And Index

**Files:**
- Create: `crates/agentenv-core/src/skills.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Test: `crates/agentenv-core/tests/skills_cache.rs`

- [ ] **Step 1: Write failing layout and metadata tests**

Create `crates/agentenv-core/tests/skills_cache.rs` with:

```rust
use std::{fs, path::PathBuf};

use agentenv_core::skills::{
    rebuild_skill_index, SkillArchive, SkillCacheLayout, SkillIndex, SkillManifest,
    SkillProvenance,
};

#[test]
fn skill_cache_layout_rejects_path_escape_segments() {
    let layout = SkillCacheLayout::new(PathBuf::from("/tmp/agentenv"));

    assert!(layout.installed_skill_dir("code-review", "1.2.0").is_ok());
    assert!(layout.installed_skill_dir("../escape", "1.2.0").is_err());
    assert!(layout.installed_skill_dir("code-review", "../escape").is_err());
    assert!(layout.installed_skill_dir("index.json", "1.2.0").is_err());
    assert!(layout.archive_path("not-a-sha").is_err());
}

#[test]
fn skill_manifest_and_provenance_reject_unknown_fields() {
    let manifest = r#"{
      "schema_version": "0.1",
      "name": "code-review",
      "version": "1.2.0",
      "source": "oci://ghcr.io/agentenv-community/code-review:1.2.0",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "signatures": [],
      "archive": {
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cache_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tar.zst"
      },
      "unexpected": true
    }"#;
    let err = SkillManifest::from_json_str(manifest).expect_err("unknown manifest field fails");
    assert!(err.to_string().contains("unknown field"));

    let provenance = r#"{
      "schema_version": "0.1",
      "subject": {
        "name": "code-review",
        "version": "1.2.0",
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      "attestations": [],
      "extra": "field"
    }"#;
    let err =
        SkillProvenance::from_json_str(provenance).expect_err("unknown provenance field fails");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn skill_index_rebuilds_in_deterministic_order() {
    let root = unique_root("skill-index-order");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "zeta",
        "2.0.0",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    write_installed_skill(
        &layout,
        "alpha",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    let index = rebuild_skill_index(&layout).expect("rebuild index");
    assert_eq!(
        index.skills.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>(),
        vec!["alpha", "zeta"]
    );

    let rendered = fs::read_to_string(layout.index_path()).expect("index written");
    let reparsed: SkillIndex = serde_json::from_str(&rendered).expect("index parses");
    assert_eq!(reparsed, index);
}

fn write_installed_skill(layout: &SkillCacheLayout, name: &str, version: &str, digest: &str) {
    let skill_dir = layout.installed_skill_dir(name, version).expect("skill dir");
    fs::create_dir_all(skill_dir.join(".agentenv")).expect("create skill metadata dir");
    fs::write(
        skill_dir.join("SKILL.md"),
        format!("---\nname: {name}\nversion: {version}\n---\n# {name}\n"),
    )
    .expect("write SKILL.md");
    let hex = digest.strip_prefix("sha256:").expect("digest prefix");
    let manifest = SkillManifest {
        schema_version: "0.1".to_owned(),
        name: name.to_owned(),
        version: version.to_owned(),
        source: format!("file:///skills/{name}/{version}"),
        digest: digest.to_owned(),
        signatures: Vec::new(),
        archive: Some(SkillArchive {
            digest: digest.to_owned(),
            cache_key: format!("{hex}.tar.zst"),
        }),
        self_test: None,
    };
    fs::write(
        skill_dir.join(".agentenv/manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("render manifest"),
    )
    .expect("write manifest");
}

fn unique_root(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills_cache
```

Expected: FAIL with unresolved import `agentenv_core::skills`.

- [ ] **Step 3: Implement layout, metadata, and index**

Add `pub mod skills;` to `crates/agentenv-core/src/lib.rs`.

Create `crates/agentenv-core/src/skills.rs` with these public types and functions:

```rust
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest::{parse_sha256_digest, parse_sha256_hex, DigestError};

pub const SKILL_METADATA_SCHEMA_VERSION: &str = "0.1";

#[derive(Debug, Error)]
pub enum SkillCacheError {
    #[error("invalid {kind} segment `{value}`")]
    InvalidPathSegment { kind: &'static str, value: String },
    #[error("invalid skill digest `{digest}`: {source}")]
    InvalidDigest {
        digest: String,
        #[source]
        source: DigestError,
    },
    #[error("failed to read or write `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse or serialize JSON at `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

pub type SkillCacheResult<T> = Result<T, SkillCacheError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillCacheLayout {
    root: PathBuf,
}

impl SkillCacheLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn skills_dir(&self) -> PathBuf {
        self.root.join("skills")
    }

    pub fn cache_skills_dir(&self) -> PathBuf {
        self.root.join("cache").join("skills")
    }

    pub fn index_path(&self) -> PathBuf {
        self.skills_dir().join("index.json")
    }

    pub fn installed_skill_dir(&self, name: &str, version: &str) -> SkillCacheResult<PathBuf> {
        validate_segment("skill name", name)?;
        validate_segment("skill version", version)?;
        Ok(self.skills_dir().join(name).join(version))
    }

    pub fn manifest_path(&self, name: &str, version: &str) -> SkillCacheResult<PathBuf> {
        Ok(self
            .installed_skill_dir(name, version)?
            .join(".agentenv")
            .join("manifest.json"))
    }

    pub fn provenance_path(&self, name: &str, version: &str) -> SkillCacheResult<PathBuf> {
        Ok(self
            .installed_skill_dir(name, version)?
            .join(".agentenv")
            .join("provenance.json"))
    }

    pub fn archive_path(&self, digest_hex: &str) -> SkillCacheResult<PathBuf> {
        parse_sha256_hex(digest_hex).map_err(|source| SkillCacheError::InvalidDigest {
            digest: digest_hex.to_owned(),
            source,
        })?;
        Ok(self.cache_skills_dir().join(format!("{digest_hex}.tar.zst")))
    }

    pub fn trust_keys_path(&self) -> PathBuf {
        self.skills_dir().join("trust_keys.json")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<SkillArchive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_test: Option<SkillSelfTest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillArchive {
    pub digest: String,
    pub cache_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSelfTest {
    #[serde(default = "default_self_test_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<SkillSelfTestAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SkillSelfTestAssertion {
    FileExists { path: String },
    CommandExitsZero { cmd: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillProvenance {
    pub schema_version: String,
    pub subject: SkillProvenanceSubject,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillProvenanceSubject {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillIndex {
    pub schema_version: String,
    pub skills: Vec<SkillIndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillIndexEntry {
    pub name: String,
    pub version: String,
    pub source: String,
    pub digest: String,
    pub current: bool,
    pub path: String,
}

impl SkillManifest {
    pub fn from_json_str(input: &str) -> SkillCacheResult<Self> {
        serde_json::from_str(input).map_err(|source| SkillCacheError::Json {
            path: PathBuf::from("<memory>"),
            source,
        })
    }
}

impl SkillProvenance {
    pub fn from_json_str(input: &str) -> SkillCacheResult<Self> {
        serde_json::from_str(input).map_err(|source| SkillCacheError::Json {
            path: PathBuf::from("<memory>"),
            source,
        })
    }
}

pub fn rebuild_skill_index(layout: &SkillCacheLayout) -> SkillCacheResult<SkillIndex> {
    let mut entries = Vec::new();
    let skills_dir = layout.skills_dir();
    if !skills_dir.exists() {
        return Ok(write_index(layout, entries)?);
    }

    for name_entry in read_dir_sorted(&skills_dir)? {
        if !name_entry.file_type().map_err(|source| SkillCacheError::Io {
            path: name_entry.path(),
            source,
        })?.is_dir()
        {
            continue;
        }
        let name = name_entry.file_name().to_string_lossy().to_string();
        if name == ".agentenv" {
            continue;
        }
        for version_entry in read_dir_sorted(&name_entry.path())? {
            if !version_entry.file_type().map_err(|source| SkillCacheError::Io {
                path: version_entry.path(),
                source,
            })?.is_dir()
            {
                continue;
            }
            let version = version_entry.file_name().to_string_lossy().to_string();
            let manifest_path = version_entry.path().join(".agentenv").join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }
            let manifest = read_manifest_file(&manifest_path)?;
            let relative_path = format!("skills/{name}/{version}");
            entries.push(SkillIndexEntry {
                name,
                version,
                source: manifest.source,
                digest: manifest.digest,
                current: false,
                path: relative_path,
            });
        }
    }

    entries.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    write_index(layout, entries)
}

fn read_manifest_file(path: &Path) -> SkillCacheResult<SkillManifest> {
    let content = fs::read_to_string(path).map_err(|source| SkillCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&content).map_err(|source| SkillCacheError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn write_index(
    layout: &SkillCacheLayout,
    skills: Vec<SkillIndexEntry>,
) -> SkillCacheResult<SkillIndex> {
    let index = SkillIndex {
        schema_version: SKILL_METADATA_SCHEMA_VERSION.to_owned(),
        skills,
    };
    let path = layout.index_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SkillCacheError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let rendered = serde_json::to_string_pretty(&index).map_err(|source| SkillCacheError::Json {
        path: path.clone(),
        source,
    })?;
    fs::write(&path, format!("{rendered}\n")).map_err(|source| SkillCacheError::Io {
        path,
        source,
    })?;
    Ok(index)
}

fn read_dir_sorted(path: &Path) -> SkillCacheResult<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| SkillCacheError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| SkillCacheError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn default_self_test_timeout_seconds() -> u64 {
    120
}

fn validate_segment(kind: &'static str, value: &str) -> SkillCacheResult<()> {
    let path = Path::new(value);
    let valid = !value.is_empty()
        && value != "index.json"
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(SkillCacheError::InvalidPathSegment {
            kind,
            value: value.to_owned(),
        })
    }
}
```

Remove the unused `BTreeMap` and `parse_sha256_digest` imports if the compiler reports them.

- [ ] **Step 4: Run tests to verify Task 1 passes**

Run:

```bash
cargo test -p agentenv-core --test skills_cache
```

Expected: PASS for the three new tests.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add crates/agentenv-core/src/lib.rs crates/agentenv-core/src/skills.rs crates/agentenv-core/tests/skills_cache.rs
git commit -m "feat: add local skill cache metadata"
```

---

### Task 2: Portable Lockfile Skill Pins

**Files:**
- Modify: `crates/agentenv-core/src/lockfile.rs`
- Modify: `crates/agentenv-core/src/portable_lockfile.rs`
- Test: `crates/agentenv-core/tests/portable_lockfile.rs`

- [ ] **Step 1: Write failing skill pin lockfile tests**

Add these imports and tests to `crates/agentenv-core/tests/portable_lockfile.rs`:

```rust
use agentenv_core::lockfile::SkillPin;

#[test]
fn portable_lockfile_serializes_skill_pins_deterministically() {
    let mut lockfile = reference_portable_lockfile();
    lockfile.skills = vec![
        SkillPin {
            name: "zeta".to_owned(),
            version: "2.0.0".to_owned(),
            source: "file:///skills/zeta".to_owned(),
            digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            signatures: Vec::new(),
        },
        SkillPin {
            name: "alpha".to_owned(),
            version: "1.0.0".to_owned(),
            source: "oci://ghcr.io/agentenv-community/alpha:1.0.0".to_owned(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            signatures: vec!["ed25519:test-key:cccc".to_owned()],
        },
    ];

    let rendered = lockfile.to_yaml_deterministic().expect("render lockfile");
    let alpha_index = rendered.find("name: alpha").expect("alpha skill rendered");
    let zeta_index = rendered.find("name: zeta").expect("zeta skill rendered");
    assert!(alpha_index < zeta_index, "skills should serialize sorted: {rendered}");
    assert!(rendered.contains("skills:"));
    assert!(rendered.contains("ed25519:test-key:cccc"));

    let reparsed = LockfileDocument::from_yaml(&rendered).expect("parse rendered lockfile");
    let LockfileDocument::Portable(reparsed) = reparsed else {
        panic!("expected portable lockfile");
    };
    assert_eq!(reparsed.skills[0].name, "alpha");
    assert_eq!(reparsed.skills[1].name, "zeta");
}

#[test]
fn portable_lockfile_rejects_duplicate_skill_pins() {
    let mut lockfile = reference_portable_lockfile();
    lockfile.skills = vec![
        SkillPin {
            name: "code-review".to_owned(),
            version: "1.2.0".to_owned(),
            source: "file:///skills/code-review".to_owned(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            signatures: Vec::new(),
        },
        SkillPin {
            name: "code-review".to_owned(),
            version: "1.2.0".to_owned(),
            source: "file:///skills/code-review".to_owned(),
            digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            signatures: Vec::new(),
        },
    ];

    let err = lockfile
        .to_yaml_deterministic()
        .expect_err("duplicate skill pin should fail validation");
    assert!(err.to_string().contains("duplicate skill pin"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile skill_pins
```

Expected: FAIL with unresolved import `agentenv_core::lockfile::SkillPin`.

- [ ] **Step 3: Implement skill pins in lockfiles**

In `crates/agentenv-core/src/lockfile.rs`, add `BTreeSet` to imports:

```rust
use std::collections::{BTreeMap, BTreeSet};
```

Add this field to `PortableLockfile` after `credentials`:

```rust
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<SkillPin>,
```

Add this type near `PortableDriverPin`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPin {
    pub name: String,
    pub version: String,
    pub source: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
}
```

Add this error variant:

```rust
    #[error("duplicate skill pin `{name}` version `{version}` from `{source}`")]
    DuplicateSkillPin {
        name: String,
        version: String,
        source: String,
    },
```

In `PortableLockfile::to_yaml_deterministic`, sort skill pins before serializing:

```rust
    pub fn to_yaml_deterministic(&self) -> Result<String, LockfileError> {
        let mut lockfile = self.clone();
        lockfile
            .skills
            .sort_by(|left, right| (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source)));
        lockfile.validate()?;
        serde_yaml::to_string(&lockfile).map_err(LockfileError::Serialize)
    }
```

In `PortableLockfile::validate`, call:

```rust
        validate_skill_pins(&self.skills)?;
```

Add this helper:

```rust
fn validate_skill_pins(skills: &[SkillPin]) -> Result<(), LockfileError> {
    let mut seen = BTreeSet::new();
    for skill in skills {
        parse_sha256_digest(&skill.digest).map_err(|source| LockfileError::InvalidArtifactDigest {
            name: format!("skill:{}:{}", skill.name, skill.version),
            source,
        })?;
        let key = (skill.name.clone(), skill.version.clone(), skill.source.clone());
        if !seen.insert(key) {
            return Err(LockfileError::DuplicateSkillPin {
                name: skill.name.clone(),
                version: skill.version.clone(),
                source: skill.source.clone(),
            });
        }
    }
    Ok(())
}
```

In `crates/agentenv-core/src/portable_lockfile.rs`, set the new field in `build_portable_lockfile`:

```rust
        skills: Vec::new(),
```

- [ ] **Step 4: Run tests to verify Task 2 passes**

Run:

```bash
cargo test -p agentenv-core --test portable_lockfile skill_pins
```

Expected: PASS for the two new tests.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add crates/agentenv-core/src/lockfile.rs crates/agentenv-core/src/portable_lockfile.rs crates/agentenv-core/tests/portable_lockfile.rs
git commit -m "feat: add skill pins to portable lockfiles"
```

---

### Task 3: Skill Verification, Signatures, And Self-Tests

**Files:**
- Modify: `crates/agentenv-core/src/skills.rs`
- Test: `crates/agentenv-core/tests/skills_cache.rs`

- [ ] **Step 1: Write failing verification tests**

Append these tests to `crates/agentenv-core/tests/skills_cache.rs`:

```rust
use agentenv_core::skills::{
    verify_all_installed_skills, SkillTrustKey, SkillVerifyOptions, SkillVerifyStatus,
};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn verify_all_accepts_valid_unsigned_skill_with_file_self_test() {
    let root = unique_root("skill-verify-valid");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "code-review", "1.2.0", digest);
    let skill_dir = layout
        .installed_skill_dir("code-review", "1.2.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.self_test = Some(agentenv_core::skills::SkillSelfTest {
        timeout_seconds: 5,
        assertions: vec![agentenv_core::skills::SkillSelfTestAssertion::FileExists {
            path: "SKILL.md".to_owned(),
        }],
    });
    write_manifest(&skill_dir, &manifest);
    write_archive(&layout, digest, b"archive bytes");
    rewrite_digest_to_actual_archive(&layout, &skill_dir);

    let report = verify_all_installed_skills(&layout, SkillVerifyOptions::default())
        .expect("verify all");
    assert!(report.is_ok(), "{report:?}");
    assert_eq!(report.skills[0].status, SkillVerifyStatus::Passed);
}

#[test]
fn verify_all_reports_archive_digest_mismatch() {
    let root = unique_root("skill-verify-digest-mismatch");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "code-review", "1.2.0", digest);
    write_archive(&layout, digest, b"different archive bytes");

    let report = verify_all_installed_skills(&layout, SkillVerifyOptions::default())
        .expect("verify all");
    assert!(!report.is_ok());
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("archive digest mismatch")));
}

#[test]
fn verify_all_reports_tree_digest_when_archive_is_missing() {
    let root = unique_root("skill-verify-tree-fallback");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "code-review", "1.2.0", digest);

    let report = verify_all_installed_skills(&layout, SkillVerifyOptions::default())
        .expect("verify all");
    assert!(report.is_ok(), "{report:?}");
    assert!(report.skills[0]
        .warnings
        .iter()
        .any(|warning| warning.contains("extracted tree digest")));
}

#[test]
fn verify_all_verifies_ed25519_signature_with_trust_key() {
    let root = unique_root("skill-verify-signature");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "signed", "1.0.0", digest);
    let skill_dir = layout.installed_skill_dir("signed", "1.0.0").expect("skill dir");
    write_archive(&layout, digest, b"signed archive bytes");
    rewrite_digest_to_actual_archive(&layout, &skill_dir);
    let mut manifest = read_manifest(&skill_dir);

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let message = manifest.digest.as_bytes();
    let signature = signing_key.sign(message);
    manifest.signatures = vec![format!("ed25519:test-key:{}", hex::encode(signature.to_bytes()))];
    write_manifest(&skill_dir, &manifest);

    let report = verify_all_installed_skills(
        &layout,
        SkillVerifyOptions {
            trust_keys: vec![SkillTrustKey {
                id: "test-key".to_owned(),
                public_key: verifying_key_hex,
            }],
        },
    )
    .expect("verify all");
    assert!(report.is_ok(), "{report:?}");
}

#[test]
fn verify_all_fails_invalid_ed25519_signature() {
    let root = unique_root("skill-verify-invalid-signature");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "signed", "1.0.0", digest);
    let skill_dir = layout.installed_skill_dir("signed", "1.0.0").expect("skill dir");
    write_archive(&layout, digest, b"signed archive bytes");
    rewrite_digest_to_actual_archive(&layout, &skill_dir);
    let mut manifest = read_manifest(&skill_dir);

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let wrong_key = SigningKey::from_bytes(&[8_u8; 32]);
    let wrong_key_hex = hex::encode(wrong_key.verifying_key().to_bytes());
    let signature = signing_key.sign(manifest.digest.as_bytes());
    manifest.signatures = vec![format!("ed25519:test-key:{}", hex::encode(signature.to_bytes()))];
    write_manifest(&skill_dir, &manifest);

    let report = verify_all_installed_skills(
        &layout,
        SkillVerifyOptions {
            trust_keys: vec![SkillTrustKey {
                id: "test-key".to_owned(),
                public_key: wrong_key_hex,
            }],
        },
    )
    .expect("verify all");
    assert!(!report.is_ok());
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("invalid signature")));
}

#[test]
fn verify_all_fails_when_signature_trust_key_is_missing() {
    let root = unique_root("skill-verify-missing-trust");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "signed", "1.0.0", digest);
    let skill_dir = layout.installed_skill_dir("signed", "1.0.0").expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.signatures = vec!["ed25519:test-key:abcd".to_owned()];
    write_manifest(&skill_dir, &manifest);

    let report = verify_all_installed_skills(&layout, SkillVerifyOptions::default())
        .expect("verify all");
    assert!(!report.is_ok());
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("missing trust key")));
}

#[test]
fn verify_all_reports_self_test_command_failure() {
    let root = unique_root("skill-verify-command-failure");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "command-skill", "1.0.0", digest);
    let skill_dir = layout
        .installed_skill_dir("command-skill", "1.0.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.self_test = Some(agentenv_core::skills::SkillSelfTest {
        timeout_seconds: 5,
        assertions: vec![agentenv_core::skills::SkillSelfTestAssertion::CommandExitsZero {
            cmd: "exit 3".to_owned(),
        }],
    });
    write_manifest(&skill_dir, &manifest);

    let report = verify_all_installed_skills(&layout, SkillVerifyOptions::default())
        .expect("verify all");
    assert!(!report.is_ok());
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("self-test command failed")));
}

#[cfg(unix)]
#[test]
fn verify_all_reports_self_test_timeout() {
    let root = unique_root("skill-verify-command-timeout");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_installed_skill(&layout, "slow-skill", "1.0.0", digest);
    let skill_dir = layout
        .installed_skill_dir("slow-skill", "1.0.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.self_test = Some(agentenv_core::skills::SkillSelfTest {
        timeout_seconds: 1,
        assertions: vec![agentenv_core::skills::SkillSelfTestAssertion::CommandExitsZero {
            cmd: "sleep 2".to_owned(),
        }],
    });
    write_manifest(&skill_dir, &manifest);

    let report = verify_all_installed_skills(&layout, SkillVerifyOptions::default())
        .expect("verify all");
    assert!(!report.is_ok());
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("timed out")));
}

fn read_manifest(skill_dir: &std::path::Path) -> SkillManifest {
    serde_json::from_str(&fs::read_to_string(skill_dir.join(".agentenv/manifest.json")).unwrap())
        .unwrap()
}

fn write_manifest(skill_dir: &std::path::Path, manifest: &SkillManifest) {
    fs::write(
        skill_dir.join(".agentenv/manifest.json"),
        serde_json::to_string_pretty(manifest).unwrap(),
    )
    .unwrap();
}

fn write_archive(layout: &SkillCacheLayout, digest: &str, bytes: &[u8]) {
    let hex = digest.strip_prefix("sha256:").unwrap();
    let path = layout.archive_path(hex).expect("archive path");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn rewrite_digest_to_actual_archive(layout: &SkillCacheLayout, skill_dir: &std::path::Path) {
    let mut manifest = read_manifest(skill_dir);
    let archive = manifest.archive.as_ref().unwrap();
    let archive_path = layout.cache_skills_dir().join(&archive.cache_key);
    let bytes = fs::read(&archive_path).unwrap();
    let actual = format!("sha256:{}", agentenv_core::digest::sha256_hex(&bytes));
    let actual_hex = actual.strip_prefix("sha256:").unwrap();
    let actual_path = layout.archive_path(actual_hex).unwrap();
    fs::rename(archive_path, actual_path).unwrap();
    manifest.digest = actual.clone();
    manifest.archive = Some(SkillArchive {
        digest: actual.clone(),
        cache_key: format!("{actual_hex}.tar.zst"),
    });
    write_manifest(skill_dir, &manifest);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills_cache verify_all_
```

Expected: FAIL with unresolved imports for `verify_all_installed_skills`, `SkillTrustKey`, `SkillVerifyOptions`, and `SkillVerifyStatus`.

- [ ] **Step 3: Implement verification reports and signature checks**

In `crates/agentenv-core/src/skills.rs`, add imports:

```rust
use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use sha2::{Digest, Sha256};
```

Add report and option types:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillVerifyOptions {
    pub trust_keys: Vec<SkillTrustKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTrustKey {
    pub id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTrustConfig {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<SkillTrustKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillVerifyReport {
    pub skills: Vec<SkillVerifyEntry>,
}

impl SkillVerifyReport {
    pub fn is_ok(&self) -> bool {
        self.skills.iter().all(|entry| entry.status == SkillVerifyStatus::Passed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillVerifyEntry {
    pub name: String,
    pub version: String,
    pub status: SkillVerifyStatus,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillVerifyStatus {
    Passed,
    Failed,
}
```

Add verification entry point:

```rust
pub fn verify_all_installed_skills(
    layout: &SkillCacheLayout,
    options: SkillVerifyOptions,
) -> SkillCacheResult<SkillVerifyReport> {
    let mut report = SkillVerifyReport::default();
    let skills_dir = layout.skills_dir();
    if !skills_dir.exists() {
        return Ok(report);
    }

    for name_entry in read_dir_sorted(&skills_dir)? {
        if !name_entry.file_type().map_err(|source| SkillCacheError::Io {
            path: name_entry.path(),
            source,
        })?.is_dir()
        {
            continue;
        }
        let name = name_entry.file_name().to_string_lossy().to_string();
        for version_entry in read_dir_sorted(&name_entry.path())? {
            if !version_entry.file_type().map_err(|source| SkillCacheError::Io {
                path: version_entry.path(),
                source,
            })?.is_dir()
            {
                continue;
            }
            let version = version_entry.file_name().to_string_lossy().to_string();
            report.skills.push(verify_installed_skill(
                layout,
                &name,
                &version,
                &version_entry.path(),
                &options,
            )?);
        }
    }

    report
        .skills
        .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    let _ = rebuild_skill_index(layout)?;
    Ok(report)
}
```

Add these helper functions:

```rust
fn verify_installed_skill(
    layout: &SkillCacheLayout,
    name: &str,
    version: &str,
    skill_dir: &Path,
    options: &SkillVerifyOptions,
) -> SkillCacheResult<SkillVerifyEntry> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let skill_md = skill_dir.join("SKILL.md");
    let frontmatter = fs::read_to_string(&skill_md)
        .map_err(|source| SkillCacheError::Io {
            path: skill_md.clone(),
            source,
        })
        .and_then(|content| parse_skill_frontmatter(&content).map_err(|message| SkillCacheError::Json {
            path: skill_md.clone(),
            source: serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, message)),
        }));

    match frontmatter {
        Ok(frontmatter) => {
            if frontmatter.name != name {
                errors.push(format!("SKILL.md name `{}` does not match path `{name}`", frontmatter.name));
            }
            if frontmatter.version != version {
                errors.push(format!("SKILL.md version `{}` does not match path `{version}`", frontmatter.version));
            }
        }
        Err(error) => errors.push(error.to_string()),
    }

    let manifest_path = skill_dir.join(".agentenv").join("manifest.json");
    let provenance_path = skill_dir.join(".agentenv").join("provenance.json");
    let manifest = read_manifest_file(&manifest_path);
    let provenance = read_provenance_file(&provenance_path);

    if let Ok(manifest) = &manifest {
        if manifest.name != name {
            errors.push(format!("manifest name `{}` does not match path `{name}`", manifest.name));
        }
        if manifest.version != version {
            errors.push(format!("manifest version `{}` does not match path `{version}`", manifest.version));
        }
        if let Err(source) = parse_sha256_digest(&manifest.digest) {
            errors.push(format!("invalid manifest digest `{}`: {source}", manifest.digest));
        }
        verify_archive_digest(layout, skill_dir, manifest, &mut warnings, &mut errors);
        verify_signatures(manifest, options, &mut errors);
        run_self_tests(skill_dir, manifest, &mut errors);
    } else if let Err(error) = manifest {
        errors.push(error.to_string());
    }

    if let (Ok(manifest), Ok(provenance)) = (&manifest, &provenance) {
        if provenance.subject.digest != manifest.digest {
            errors.push(format!(
                "provenance digest `{}` does not match manifest digest `{}`",
                provenance.subject.digest, manifest.digest
            ));
        }
    }

    match provenance {
        Ok(provenance) => {
            if provenance.subject.name != name {
                errors.push(format!("provenance name `{}` does not match path `{name}`", provenance.subject.name));
            }
            if provenance.subject.version != version {
                errors.push(format!("provenance version `{}` does not match path `{version}`", provenance.subject.version));
            }
        }
        Err(error) => errors.push(error.to_string()),
    }

    Ok(SkillVerifyEntry {
        name: name.to_owned(),
        version: version.to_owned(),
        status: if errors.is_empty() {
            SkillVerifyStatus::Passed
        } else {
            SkillVerifyStatus::Failed
        },
        warnings,
        errors,
    })
}
```

Add simple frontmatter parsing:

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillFrontmatter {
    name: String,
    version: String,
}

fn parse_skill_frontmatter(content: &str) -> Result<SkillFrontmatter, String> {
    let mut lines = content.lines();
    if lines.next() != Some("---") {
        return Err("SKILL.md must start with YAML frontmatter".to_owned());
    }
    let mut yaml = String::new();
    for line in lines {
        if line == "---" {
            return serde_yaml::from_str(&yaml).map_err(|error| error.to_string());
        }
        yaml.push_str(line);
        yaml.push('\n');
    }
    Err("SKILL.md frontmatter is missing closing delimiter".to_owned())
}
```

Add digest, signature, and self-test helpers:

```rust
fn verify_archive_digest(
    layout: &SkillCacheLayout,
    skill_dir: &Path,
    manifest: &SkillManifest,
    warnings: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(archive) = manifest.archive.as_ref() else {
        warnings.push("archive metadata unavailable".to_owned());
        return;
    };
    let Some(hex) = archive.digest.strip_prefix("sha256:") else {
        errors.push(format!("invalid archive digest `{}`", archive.digest));
        return;
    };
    let archive_path = layout.cache_skills_dir().join(&archive.cache_key);
    match fs::read(&archive_path) {
        Ok(bytes) => {
            let actual = format!("sha256:{}", crate::digest::sha256_hex(&bytes));
            if actual != archive.digest || actual != manifest.digest {
                errors.push(format!(
                    "archive digest mismatch for `{}`: expected `{}`, found `{actual}`",
                    archive_path.display(),
                    archive.digest
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match digest_installed_tree(skill_dir) {
                Ok(tree_digest) => warnings.push(format!(
                    "archive `{}` is unavailable; extracted tree digest is `{tree_digest}`",
                    archive_path.display()
                )),
                Err(message) => warnings.push(format!(
                    "archive `{}` is unavailable and extracted tree digest could not be computed: {message}",
                    archive_path.display()
                )),
            }
            let _ = hex;
        }
        Err(error) => errors.push(format!("failed to read archive `{}`: {error}", archive_path.display())),
    }
}

pub fn load_skill_trust_keys(layout: &SkillCacheLayout) -> SkillCacheResult<Vec<SkillTrustKey>> {
    let path = layout.trust_keys_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path).map_err(|source| SkillCacheError::Io {
        path: path.clone(),
        source,
    })?;
    let config: SkillTrustConfig =
        serde_json::from_str(&content).map_err(|source| SkillCacheError::Json {
            path,
            source,
        })?;
    Ok(config.keys)
}

fn digest_installed_tree(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for relative in files {
        let absolute = root.join(&relative);
        let content = fs::read(&absolute)
            .map_err(|error| format!("failed to read `{}`: {error}", absolute.display()))?;
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(crate::digest::sha256_hex(&content).as_bytes());
        hasher.update([0]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn collect_tree_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|error| format!("failed to read `{}`: {error}", current.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to read `{}`: {error}", current.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("failed to relativize `{}`: {error}", path.display()))?;
        if relative
            .components()
            .next()
            .is_some_and(|component| component == Component::Normal(std::ffi::OsStr::new(".agentenv")))
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect `{}`: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_tree_files(root, &path, files)?;
        } else if file_type.is_file() {
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn verify_signatures(
    manifest: &SkillManifest,
    options: &SkillVerifyOptions,
    errors: &mut Vec<String>,
) {
    for signature in &manifest.signatures {
        let parts = signature.split(':').collect::<Vec<_>>();
        if parts.len() != 3 || parts[0] != "ed25519" {
            errors.push(format!("invalid signature format `{signature}`"));
            continue;
        }
        let key_id = parts[1];
        let Some(trust_key) = options.trust_keys.iter().find(|key| key.id == key_id) else {
            errors.push(format!("missing trust key `{key_id}` for listed signature"));
            continue;
        };
        let Ok(public_key_bytes) = hex::decode(&trust_key.public_key) else {
            errors.push(format!("invalid public key hex for trust key `{key_id}`"));
            continue;
        };
        if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
            errors.push(format!("invalid public key length for trust key `{key_id}`"));
            continue;
        }
        let mut public_key = [0_u8; PUBLIC_KEY_LENGTH];
        public_key.copy_from_slice(&public_key_bytes);
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
            errors.push(format!("invalid Ed25519 public key for trust key `{key_id}`"));
            continue;
        };
        let Ok(signature_bytes) = hex::decode(parts[2]) else {
            errors.push(format!("invalid signature hex for trust key `{key_id}`"));
            continue;
        };
        let Ok(signature) = Signature::try_from(signature_bytes.as_slice()) else {
            errors.push(format!("invalid signature length for trust key `{key_id}`"));
            continue;
        };
        if verifying_key
            .verify(manifest.digest.as_bytes(), &signature)
            .is_err()
        {
            errors.push(format!("invalid signature for trust key `{key_id}`"));
        }
    }
}

fn run_self_tests(skill_dir: &Path, manifest: &SkillManifest, errors: &mut Vec<String>) {
    let Some(self_test) = manifest.self_test.as_ref() else {
        return;
    };
    let timeout = Duration::from_secs(self_test.timeout_seconds);
    for assertion in &self_test.assertions {
        match assertion {
            SkillSelfTestAssertion::FileExists { path } => {
                if !safe_child_path(skill_dir, path).is_some_and(|path| path.exists()) {
                    errors.push(format!("self-test file does not exist: {path}"));
                }
            }
            SkillSelfTestAssertion::CommandExitsZero { cmd } => {
                if let Err(message) = run_command_with_timeout(skill_dir, cmd, timeout) {
                    errors.push(message);
                }
            }
        }
    }
}

fn safe_child_path(root: &Path, child: &str) -> Option<PathBuf> {
    let child_path = Path::new(child);
    if child_path.is_absolute()
        || child_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(root.join(child_path))
}

fn run_command_with_timeout(
    skill_dir: &Path,
    cmd: &str,
    timeout: Duration,
) -> Result<(), String> {
    #[cfg(unix)]
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(skill_dir)
        .spawn()
        .map_err(|error| format!("failed to start self-test command `{cmd}`: {error}"))?;

    #[cfg(windows)]
    let mut child = Command::new("cmd")
        .arg("/C")
        .arg(cmd)
        .current_dir(skill_dir)
        .spawn()
        .map_err(|error| format!("failed to start self-test command `{cmd}`: {error}"))?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!("self-test command failed `{cmd}` with status {status}"));
            }
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("self-test command timed out `{cmd}`"));
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => return Err(format!("failed to wait for self-test command `{cmd}`: {error}")),
        }
    }
}

fn read_provenance_file(path: &Path) -> SkillCacheResult<SkillProvenance> {
    let content = fs::read_to_string(path).map_err(|source| SkillCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&content).map_err(|source| SkillCacheError::Json {
        path: path.to_path_buf(),
        source,
    })
}
```

If `serde_json::Error::io` is unavailable on the pinned serde_json version, add a new `SkillCacheError::InvalidSkillManifest { path: PathBuf, message: String }` variant and return that from frontmatter parsing instead.

- [ ] **Step 4: Run tests to verify Task 3 passes**

Run:

```bash
cargo test -p agentenv-core --test skills_cache verify_all_
```

Expected: PASS for all verification tests.

- [ ] **Step 5: Commit Task 3**

Run:

```bash
git add crates/agentenv-core/src/skills.rs crates/agentenv-core/tests/skills_cache.rs
git commit -m "feat: verify installed skills"
```

---

### Task 4: Skill Archive Prune Planner

**Files:**
- Modify: `crates/agentenv-core/src/skills.rs`
- Test: `crates/agentenv-core/tests/skills_cache.rs`

- [ ] **Step 1: Write failing prune tests**

Append this test to `crates/agentenv-core/tests/skills_cache.rs`:

```rust
use agentenv_core::skills::{execute_skill_prune, plan_skill_prune};

#[test]
fn prune_removes_only_unreferenced_archives() {
    let root = unique_root("skill-prune");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));
    let referenced = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let env_referenced = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let unreferenced = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    write_installed_skill(&layout, "code-review", "1.2.0", referenced);
    write_archive(&layout, referenced, b"referenced");
    write_archive(&layout, env_referenced, b"env referenced");
    write_archive(&layout, unreferenced, b"unreferenced");
    write_env_lockfile_with_skill(root.join(".agentenv/envs/demo/lock.yaml"), env_referenced);

    let plan = plan_skill_prune(&layout).expect("plan prune");
    assert_eq!(plan.removed_archives.len(), 1);
    assert!(plan.removed_archives[0].ends_with(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tar.zst"
    ));

    execute_skill_prune(&plan).expect("execute prune");
    assert!(layout
        .archive_path(referenced.strip_prefix("sha256:").unwrap())
        .unwrap()
        .exists());
    assert!(layout
        .archive_path(env_referenced.strip_prefix("sha256:").unwrap())
        .unwrap()
        .exists());
    assert!(!layout
        .archive_path(unreferenced.strip_prefix("sha256:").unwrap())
        .unwrap()
        .exists());
}

fn write_env_lockfile_with_skill(path: std::path::PathBuf, digest: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        format!(
            r#"version: 0.2.0
driver_protocol_version: '1.0'
name: demo
blueprint_hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
    tier: balanced
    presets: []
policy:
  declared:
    tier: balanced
    presets: []
  resolved:
    network:
      reloadability: hot
      allow: []
      deny: []
      approval_required: []
    filesystem:
      reloadability: locked_at_create
      read_only: []
      read_write: []
    process:
      reloadability: locked_at_create
      run_as_user: agent
      run_as_group: agent
      profile: default
      allow_syscalls: []
      deny_syscalls: []
    inference:
      reloadability: hot
      route: passthrough
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
skills:
  - name: env-skill
    version: 1.0.0
    source: file:///skills/env-skill
    digest: {digest}
"#
        ),
    )
    .unwrap();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills_cache prune_removes_only_unreferenced_archives
```

Expected: FAIL with unresolved imports `plan_skill_prune` and `execute_skill_prune`.

- [ ] **Step 3: Implement prune planning and execution**

In `crates/agentenv-core/src/skills.rs`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillPrunePlan {
    pub removed_archives: Vec<PathBuf>,
}

pub fn plan_skill_prune(layout: &SkillCacheLayout) -> SkillCacheResult<SkillPrunePlan> {
    let mut referenced = std::collections::BTreeSet::new();
    collect_installed_manifest_archive_refs(layout, &mut referenced)?;
    collect_env_lockfile_skill_refs(layout, &mut referenced)?;

    let mut removed_archives = Vec::new();
    let cache_dir = layout.cache_skills_dir();
    if cache_dir.exists() {
        for entry in read_dir_sorted(&cache_dir)? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("zst") {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Some(hex) = file_name.strip_suffix(".tar.zst") else {
                continue;
            };
            if parse_sha256_hex(hex).is_ok() && !referenced.contains(hex) {
                removed_archives.push(path);
            }
        }
    }
    removed_archives.sort();
    Ok(SkillPrunePlan { removed_archives })
}

pub fn execute_skill_prune(plan: &SkillPrunePlan) -> SkillCacheResult<()> {
    for path in &plan.removed_archives {
        fs::remove_file(path).map_err(|source| SkillCacheError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

fn collect_installed_manifest_archive_refs(
    layout: &SkillCacheLayout,
    referenced: &mut std::collections::BTreeSet<String>,
) -> SkillCacheResult<()> {
    let index = rebuild_skill_index(layout)?;
    for entry in index.skills {
        if let Some(hex) = entry.digest.strip_prefix("sha256:") {
            if parse_sha256_hex(hex).is_ok() {
                referenced.insert(hex.to_owned());
            }
        }
    }
    Ok(())
}

fn collect_env_lockfile_skill_refs(
    layout: &SkillCacheLayout,
    referenced: &mut std::collections::BTreeSet<String>,
) -> SkillCacheResult<()> {
    let envs_dir = layout.root().join("envs");
    if !envs_dir.exists() {
        return Ok(());
    }
    for entry in read_dir_sorted(&envs_dir)? {
        let lock_path = entry.path().join("lock.yaml");
        if !lock_path.is_file() {
            continue;
        }
        let lock_yaml = fs::read_to_string(&lock_path).map_err(|source| SkillCacheError::Io {
            path: lock_path.clone(),
            source,
        })?;
        if let Ok(crate::lockfile::LockfileDocument::Portable(lockfile)) =
            crate::lockfile::LockfileDocument::from_yaml(&lock_yaml)
        {
            for skill in lockfile.skills {
                if let Some(hex) = skill.digest.strip_prefix("sha256:") {
                    if parse_sha256_hex(hex).is_ok() {
                        referenced.insert(hex.to_owned());
                    }
                }
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify Task 4 passes**

Run:

```bash
cargo test -p agentenv-core --test skills_cache prune_removes_only_unreferenced_archives
```

Expected: PASS.

- [ ] **Step 5: Commit Task 4**

Run:

```bash
git add crates/agentenv-core/src/skills.rs crates/agentenv-core/tests/skills_cache.rs
git commit -m "feat: prune unreferenced skill archives"
```

---

### Task 5: CLI Commands For Skills Verify And Prune

**Files:**
- Modify: `crates/agentenv/src/main.rs`
- Test: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI tests**

Add tests to `crates/agentenv/tests/cli_behavior.rs` near other command behavior tests:

```rust
#[test]
fn skills_verify_all_succeeds_for_valid_local_cache() {
    let temp_dir = make_temp_dir("skills-verify-valid");
    write_cli_skill(
        &temp_dir,
        "code-review",
        "1.2.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        true,
    );

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("--all")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("verified"), "stdout was: {stdout}");
}

#[test]
fn skills_verify_all_fails_for_broken_local_cache() {
    let temp_dir = make_temp_dir("skills-verify-broken");
    write_cli_skill(
        &temp_dir,
        "code-review",
        "1.2.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        false,
    );

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("--all")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed"), "stderr was: {stderr}");
}

#[test]
fn skills_prune_dry_run_does_not_delete_archive() {
    let temp_dir = make_temp_dir("skills-prune-dry-run");
    let root = temp_dir.join(".agentenv");
    let cache_dir = root.join("cache/skills");
    fs::create_dir_all(&cache_dir).unwrap();
    let archive = cache_dir
        .join("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tar.zst");
    fs::write(&archive, b"unreferenced").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("prune")
        .arg("--dry-run")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    assert!(archive.exists(), "dry-run should not delete archive");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("would remove"), "stdout was: {stdout}");
}

#[test]
fn skills_prune_deletes_unreferenced_archive() {
    let temp_dir = make_temp_dir("skills-prune-delete");
    let root = temp_dir.join(".agentenv");
    let cache_dir = root.join("cache/skills");
    fs::create_dir_all(&cache_dir).unwrap();
    let archive = cache_dir
        .join("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tar.zst");
    fs::write(&archive, b"unreferenced").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("prune")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    assert!(!archive.exists(), "prune should delete unreferenced archive");
}

fn write_cli_skill(
    home: &Path,
    name: &str,
    version: &str,
    digest: &str,
    matching_skill_md: bool,
) {
    let skill_dir = home.join(".agentenv").join("skills").join(name).join(version);
    fs::create_dir_all(skill_dir.join(".agentenv")).unwrap();
    let skill_md_name = if matching_skill_md { name } else { "different-name" };
    fs::write(
        skill_dir.join("SKILL.md"),
        format!("---\nname: {skill_md_name}\nversion: {version}\n---\n# {name}\n"),
    )
    .unwrap();
    let hex = digest.strip_prefix("sha256:").unwrap();
    fs::write(
        skill_dir.join(".agentenv/manifest.json"),
        format!(
            r#"{{
  "schema_version": "0.1",
  "name": "{name}",
  "version": "{version}",
  "source": "file:///skills/{name}",
  "digest": "{digest}",
  "signatures": [],
  "archive": {{
    "digest": "{digest}",
    "cache_key": "{hex}.tar.zst"
  }}
}}"#
        ),
    )
    .unwrap();
    fs::write(
        skill_dir.join(".agentenv/provenance.json"),
        format!(
            r#"{{
  "schema_version": "0.1",
  "subject": {{
    "name": "{name}",
    "version": "{version}",
    "digest": "{digest}"
  }},
  "attestations": []
}}"#
        ),
    )
    .unwrap();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_
```

Expected: FAIL because `skills` is not a recognized subcommand.

- [ ] **Step 3: Implement CLI parsing and handlers**

In `crates/agentenv/src/main.rs`, add `Skills(SkillsArgs),` to `Commands`.

Add argument structs near `DriversArgs`:

```rust
#[derive(Debug, Args)]
struct SkillsArgs {
    #[command(subcommand)]
    command: SkillsCommand,
}

#[derive(Debug, Subcommand)]
enum SkillsCommand {
    Verify(SkillsVerifyArgs),
    Prune(SkillsPruneArgs),
}

#[derive(Debug, Args)]
struct SkillsVerifyArgs {
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct SkillsPruneArgs {
    #[arg(long)]
    dry_run: bool,
}
```

Add match arm:

```rust
        Some(Commands::Skills(args)) => run_skills(args),
```

Add handlers near `run_drivers`:

```rust
fn run_skills(args: SkillsArgs) -> Result<()> {
    match args.command {
        SkillsCommand::Verify(args) => run_skills_verify(args),
        SkillsCommand::Prune(args) => run_skills_prune(args),
    }
}

fn run_skills_verify(args: SkillsVerifyArgs) -> Result<()> {
    if !args.all {
        bail!("`agentenv skills verify` currently requires `--all`");
    }
    let options = runtime_options(true)?;
    let layout = agentenv_core::skills::SkillCacheLayout::new(options.root);
    let trust_keys =
        agentenv_core::skills::load_skill_trust_keys(&layout).context("failed to load skill trust keys")?;
    let report = agentenv_core::skills::verify_all_installed_skills(
        &layout,
        agentenv_core::skills::SkillVerifyOptions { trust_keys },
    )
    .context("failed to verify installed skills")?;

    for skill in &report.skills {
        match skill.status {
            agentenv_core::skills::SkillVerifyStatus::Passed => {
                println!("verified {} {}", skill.name, skill.version);
            }
            agentenv_core::skills::SkillVerifyStatus::Failed => {
                eprintln!("failed {} {}", skill.name, skill.version);
                for error in &skill.errors {
                    eprintln!("  error: {error}");
                }
                for warning in &skill.warnings {
                    eprintln!("  warning: {warning}");
                }
            }
        }
    }

    if !report.is_ok() {
        bail!("skill verification failed");
    }
    Ok(())
}

fn run_skills_prune(args: SkillsPruneArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let layout = agentenv_core::skills::SkillCacheLayout::new(options.root);
    let plan = agentenv_core::skills::plan_skill_prune(&layout).context("failed to plan skill prune")?;
    if args.dry_run {
        for path in &plan.removed_archives {
            println!("would remove {}", path.display());
        }
        println!("{} archive(s) would be removed", plan.removed_archives.len());
        return Ok(());
    }
    agentenv_core::skills::execute_skill_prune(&plan).context("failed to prune skill cache")?;
    let _ = agentenv_core::skills::rebuild_skill_index(&layout).context("failed to rebuild skill index")?;
    println!("removed {} archive(s)", plan.removed_archives.len());
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify Task 5 passes**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_
```

Expected: PASS for the four CLI skill tests.

- [ ] **Step 5: Commit Task 5**

Run:

```bash
git add crates/agentenv/src/main.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: add skill verify and prune cli"
```

---

### Task 6: Full Verification And Cleanup

**Files:**
- Review: all files changed in Tasks 1-5

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits successfully with no output or only rustfmt file updates.

- [ ] **Step 2: Run focused core tests**

Run:

```bash
cargo test -p agentenv-core --test skills_cache
cargo test -p agentenv-core --test portable_lockfile
```

Expected: both commands PASS.

- [ ] **Step 3: Run focused CLI tests**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_
```

Expected: command PASS.

- [ ] **Step 4: Run workspace clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: command PASS with no warnings.

- [ ] **Step 5: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: command PASS.

- [ ] **Step 6: Commit final cleanup if formatting or clippy changed files**

If `git status --short` shows changes after verification, run:

```bash
git add crates/agentenv-core/src/skills.rs crates/agentenv-core/src/lib.rs crates/agentenv-core/src/lockfile.rs crates/agentenv-core/src/portable_lockfile.rs crates/agentenv-core/tests/skills_cache.rs crates/agentenv-core/tests/portable_lockfile.rs crates/agentenv/src/main.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "chore: clean up skill cache implementation"
```

Expected: a cleanup commit is created only if there are remaining tracked changes.
