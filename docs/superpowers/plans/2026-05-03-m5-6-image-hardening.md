# M5-6 Image Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship baseline, strict, and open image-hardening profiles that default through create flows, propagate into sandbox policy/metadata, harden BYO Dockerfile builds, and provide `agentenv blueprint lint`.

**Architecture:** Keep the driver protocol stable. `agentenv-policy` owns profile parsing and profile-to-policy merge logic; `agentenv-core` resolves blueprint hardening and produces metadata/lint reports; `sandbox-openshell` consumes create-time metadata to inject image hardening and parse runtime requests.

**Tech Stack:** Rust 2021, `serde`, `serde_yaml`, `serde_json`, `clap`, existing `agentenv_proto::NetworkPolicy`, existing OpenShell command-runner test harness.

---

## File Structure

- Create `crates/agentenv-policy/hardening/baseline.yaml`: default profile data.
- Create `crates/agentenv-policy/hardening/strict.yaml`: strict profile data.
- Create `crates/agentenv-policy/hardening/open.yaml`: open profile data.
- Create `crates/agentenv-policy/src/hardening.rs`: typed profile structs, built-in/custom loading, validation, metadata serialization, and policy merge helpers.
- Modify `crates/agentenv-policy/src/error.rs`: add hardening-specific `PolicyError` variants.
- Modify `crates/agentenv-policy/src/lib.rs`: export hardening types and helpers.
- Create `crates/agentenv-policy/tests/hardening_profiles.rs`: profile parsing, validation, and merge coverage.
- Create `crates/agentenv-core/src/hardening.rs`: blueprint hardening resolution, Dockerfile linting, and lint report structs.
- Modify `crates/agentenv-core/src/lib.rs`: expose the new module.
- Modify `crates/agentenv-core/src/lifecycle.rs`: validate `sandbox.hardening` in blueprint verification.
- Modify `crates/agentenv-core/src/runtime.rs`: default/merge hardening during create, add hardening metadata to `SandboxSpec`, and replace BYO preflight warnings with hardening-aware lint diagnostics.
- Create `crates/agentenv-core/tests/hardening_lint.rs`: public lint and blueprint validation tests.
- Modify `crates/agentenv/src/main.rs`: add `agentenv blueprint lint <file> [--json]`.
- Modify `crates/agentenv/src/render.rs`: JSON/text rendering structs or helpers if keeping rendering out of `main.rs` is cleaner.
- Modify `crates/agentenv/tests/cli_behavior.rs`: integration tests for `blueprint lint`.
- Modify `crates/drivers/sandbox-openshell/src/lib.rs`: parse hardening metadata and inject generated hardening fragments into staged BYO Dockerfiles.
- Modify `crates/drivers/sandbox-openshell/README.md`: document hardening behavior for BYO builds.
- Modify `docs/DRIVER_PROTOCOL.md`: document create-time metadata approach and reserved future method.
- Modify `docs/BLUEPRINTS.md`: document `sandbox.hardening` defaults and profile choices.

## Task 0: Post The Issue Approach

**Files:**
- No repo file changes.

- [ ] **Step 1: Post the selected approach on issue #22**

Use the GitHub connector or this CLI command:

```bash
gh issue comment 22 --repo windoliver/agentenv --body 'Implementation approach:

- Keep the driver protocol stable for M5-6. Hardening is create-time sandbox configuration derived by core, not a new post-create driver RPC method.
- Add built-in hardening profile YAML and typed loaders in agentenv-policy for baseline, strict, and open.
- Resolve sandbox.hardening in core, default to baseline, merge supported filesystem/process posture into the existing policy, and pass image/runtime settings through SandboxSpec metadata.
- Extend OpenShell BYO Dockerfile staging to inject the selected hardening fragment before build while preserving digest verification and recording.
- Add agentenv blueprint lint to evaluate the selected hardening profile against the BYO Dockerfile with deterministic text and JSON diagnostics.
- Cover the change test-first across agentenv-policy, agentenv-core, sandbox-openshell, and agentenv CLI, then run cargo fmt, clippy -D warnings, and cargo test --workspace.'
```

Expected: the issue receives one top-level comment describing the protocol-stable approach.

## Task 1: Add Policy Hardening Profiles

**Files:**
- Create: `crates/agentenv-policy/hardening/baseline.yaml`
- Create: `crates/agentenv-policy/hardening/strict.yaml`
- Create: `crates/agentenv-policy/hardening/open.yaml`
- Create: `crates/agentenv-policy/src/hardening.rs`
- Modify: `crates/agentenv-policy/src/error.rs`
- Modify: `crates/agentenv-policy/src/lib.rs`
- Test: `crates/agentenv-policy/tests/hardening_profiles.rs`

- [ ] **Step 1: Write failing policy profile tests**

Create `crates/agentenv-policy/tests/hardening_profiles.rs`:

```rust
use agentenv_policy::{
    apply_hardening_to_policy, builtin_hardening_profile, hardening_metadata,
    resolve_hardening_profile, HardeningProfile, PresetRegistry, Tier,
};

#[test]
fn built_in_hardening_profiles_parse_and_differ() {
    let baseline = builtin_hardening_profile("baseline").expect("baseline profile");
    let strict = builtin_hardening_profile("strict").expect("strict profile");
    let open = builtin_hardening_profile("open").expect("open profile");

    assert_eq!(baseline.name, "baseline");
    assert_eq!(strict.name, "strict");
    assert_eq!(open.name, "open");
    assert!(baseline.packages.strip.iter().any(|pkg| pkg == "gcc"));
    assert!(strict.packages.strip.iter().any(|pkg| pkg == "curl"));
    assert!(!open.packages.strip.iter().any(|pkg| pkg == "gcc"));
    assert_eq!(baseline.ulimits.nproc, Some(512));
    assert_eq!(baseline.ulimits.nofile, Some(4096));
    assert!(strict.disable_core_dumps);
    assert!(strict.disable_user_namespaces);
    assert!(baseline.dockerfile.marker.contains("baseline"));
    assert!(strict.dockerfile.marker.contains("strict"));
}

#[test]
fn unknown_hardening_profile_reports_available_names() {
    let err = builtin_hardening_profile("sealed").expect_err("unknown profile");

    assert!(err.to_string().contains("sealed"));
    assert!(err.to_string().contains("baseline"));
    assert!(err.to_string().contains("strict"));
    assert!(err.to_string().contains("open"));
}

#[test]
fn resolve_hardening_profile_loads_custom_yaml_path() {
    let root = std::env::temp_dir().join(format!(
        "agentenv-hardening-profile-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp profile dir");
    let profile_path = root.join("custom.yaml");
    std::fs::write(
        &profile_path,
        r#"
name: custom
description: Custom test profile.
packages:
  strip: [gdb]
mounts:
  read_only: [/etc]
  read_write: [/sandbox]
  tmpfs:
    - path: /tmp
      size: 64m
ulimits:
  nproc: 128
  nofile: 1024
capabilities:
  drop: [NET_RAW]
disable_core_dumps: true
disable_user_namespaces: false
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=custom
  fragment: |
    RUN echo custom-hardening >/etc/agentenv-hardening
"#,
    )
    .expect("write custom profile");

    let profile = resolve_hardening_profile(profile_path.to_str().unwrap()).expect("load custom");

    assert_eq!(profile.name, "custom");
    assert_eq!(profile.mounts.tmpfs[0].path, "/tmp");
    assert_eq!(profile.mounts.tmpfs[0].size.as_deref(), Some("64m"));
    std::fs::remove_dir_all(root).expect("remove temp profile dir");
}

#[test]
fn hardening_merge_updates_filesystem_policy_and_persisted_home() {
    let registry = PresetRegistry::load_builtin().expect("registry");
    let mut policy =
        agentenv_policy::compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
    let profile = builtin_hardening_profile("baseline").expect("baseline");

    apply_hardening_to_policy(&mut policy, &profile, true).expect("merge hardening");

    assert!(policy.filesystem.read_only.contains(&"/etc".to_owned()));
    assert!(policy.filesystem.read_only.contains(&"/opt".to_owned()));
    assert!(policy.filesystem.read_write.contains(&"/workspace".to_owned()));
    assert!(policy.filesystem.read_write.contains(&"/tmp".to_owned()));
    assert!(policy.filesystem.read_write.contains(&"/var/tmp".to_owned()));
    assert!(policy.filesystem.read_write.contains(&"$HOME".to_owned()));
}

#[test]
fn hardening_metadata_is_stable_json() {
    let profile = builtin_hardening_profile("strict").expect("strict");
    let metadata = hardening_metadata(&profile).expect("metadata");

    assert_eq!(metadata["hardening_profile"], serde_json::json!("strict"));
    assert_eq!(metadata["hardening_ulimit_nproc"], serde_json::json!(512));
    assert_eq!(metadata["hardening_disable_core_dumps"], serde_json::json!(true));
    assert!(metadata["hardening_packages_strip"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "curl"));
}

#[test]
fn invalid_profile_rejects_non_positive_ulimits() {
    let yaml = r#"
name: broken
description: Broken profile.
packages:
  strip: []
mounts:
  read_only: []
  read_write: []
  tmpfs: []
ulimits:
  nproc: 0
  nofile: 4096
capabilities:
  drop: []
disable_core_dumps: false
disable_user_namespaces: false
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=broken
  fragment: |
    RUN true
"#;

    let err = HardeningProfile::from_yaml("broken.yaml", yaml).expect_err("invalid profile");

    assert!(err.to_string().contains("nproc"));
    assert!(err.to_string().contains("positive"));
}
```

- [ ] **Step 2: Run the failing policy test**

Run:

```bash
cargo test -p agentenv-policy --test hardening_profiles
```

Expected: FAIL because `hardening_profiles.rs` imports unresolved hardening APIs.

- [ ] **Step 3: Add built-in profile YAML files**

Create `crates/agentenv-policy/hardening/baseline.yaml`:

```yaml
name: baseline
description: Default production hardening for agentenv sandbox images.
packages:
  strip:
    - gcc
    - g++
    - make
    - nc
    - tcpdump
    - nmap
    - strace
    - gdb
mounts:
  read_only:
    - /etc
    - /usr
    - /opt
  read_write:
    - /workspace
    - /tmp
    - /var/tmp
  tmpfs: []
ulimits:
  nproc: 512
  nofile: 4096
capabilities:
  drop:
    - NET_RAW
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=baseline
  fragment: |
    RUN set -eu; \
        if command -v apt-get >/dev/null 2>&1; then \
          apt-get purge -y gcc g++ make netcat-openbsd netcat-traditional tcpdump nmap strace gdb || true; \
          apt-get autoremove -y || true; \
          rm -rf /var/lib/apt/lists/*; \
        elif command -v apk >/dev/null 2>&1; then \
          apk del gcc g++ make netcat-openbsd tcpdump nmap strace gdb || true; \
        else \
          echo "agentenv hardening: unsupported package manager" >&2; \
          exit 78; \
        fi; \
        find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
disable_core_dumps: false
disable_user_namespaces: false
```

Create `crates/agentenv-policy/hardening/strict.yaml`:

```yaml
name: strict
description: Sensitive-work hardening for legal, financial, PHI, and other high-risk sandboxes.
packages:
  strip:
    - gcc
    - g++
    - make
    - nc
    - tcpdump
    - nmap
    - strace
    - gdb
    - curl
    - wget
    - git
mounts:
  read_only:
    - /etc
    - /usr
    - /opt
  read_write:
    - /workspace
    - /var/tmp
  tmpfs:
    - path: /tmp
      size: 256m
ulimits:
  nproc: 512
  nofile: 4096
capabilities:
  drop:
    - NET_RAW
    - SYS_ADMIN
    - SYS_PTRACE
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=strict
  fragment: |
    RUN set -eu; \
        if command -v apt-get >/dev/null 2>&1; then \
          apt-get purge -y gcc g++ make netcat-openbsd netcat-traditional tcpdump nmap strace gdb curl wget git || true; \
          apt-get autoremove -y || true; \
          rm -rf /var/lib/apt/lists/*; \
        elif command -v apk >/dev/null 2>&1; then \
          apk del gcc g++ make netcat-openbsd tcpdump nmap strace gdb curl wget git || true; \
        else \
          echo "agentenv hardening: unsupported package manager" >&2; \
          exit 78; \
        fi; \
        find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true; \
        printf '* hard core 0\n* soft core 0\n' >/etc/security/limits.d/agentenv-core.conf
disable_core_dumps: true
disable_user_namespaces: true
```

Create `crates/agentenv-policy/hardening/open.yaml`:

```yaml
name: open
description: Minimal hardening for research and exploratory sandboxes.
packages:
  strip: []
mounts:
  read_only: []
  read_write:
    - /workspace
    - /tmp
    - /var/tmp
  tmpfs: []
ulimits: {}
capabilities:
  drop: []
dockerfile:
  marker: AGENTENV_HARDENING_PROFILE=open
  fragment: |
    RUN set -eu; \
        find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
disable_core_dumps: false
disable_user_namespaces: false
```

- [ ] **Step 4: Add hardening error variants**

Modify `crates/agentenv-policy/src/error.rs`:

```rust
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unknown preset `{name}`. available presets: {available}")]
    UnknownPreset { name: String, available: String },
    #[error("unsupported access mode `{access}` for preset `{name}`")]
    UnsupportedPresetAccess { name: String, access: String },
    #[error("policy update requires recreate for domains: {domains}")]
    RequiresRecreate { domains: String },
    #[error("failed to load preset registry: {message}")]
    PresetRegistry { message: String },
    #[error("unknown hardening profile `{name}`. available profiles: {available}")]
    UnknownHardeningProfile { name: String, available: String },
    #[error("invalid hardening profile `{name}`: {message}")]
    HardeningProfile { name: String, message: String },
    #[error("translator `{translator}` does not support this policy: {message}")]
    TranslationUnsupported {
        translator: &'static str,
        message: String,
    },
}
```

- [ ] **Step 5: Implement profile parsing and merge helpers**

Create `crates/agentenv-policy/src/hardening.rs`:

```rust
use std::{collections::BTreeMap, env, path::Path};

use agentenv_proto::NetworkPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{PolicyError, PolicyResult};

const BASELINE_PROFILE: &str = include_str!("../hardening/baseline.yaml");
const STRICT_PROFILE: &str = include_str!("../hardening/strict.yaml");
const OPEN_PROFILE: &str = include_str!("../hardening/open.yaml");
const BUILTIN_NAMES: [&str; 3] = ["baseline", "strict", "open"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningProfile {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub packages: HardeningPackages,
    #[serde(default)]
    pub mounts: HardeningMounts,
    #[serde(default)]
    pub ulimits: HardeningUlimits,
    #[serde(default)]
    pub capabilities: HardeningCapabilities,
    pub dockerfile: HardeningDockerfile,
    #[serde(default)]
    pub disable_core_dumps: bool,
    #[serde(default)]
    pub disable_user_namespaces: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningPackages {
    #[serde(default)]
    pub strip: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningMounts {
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
    #[serde(default)]
    pub tmpfs: Vec<HardeningTmpfsMount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningTmpfsMount {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningUlimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nproc: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nofile: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningCapabilities {
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningDockerfile {
    pub marker: String,
    pub fragment: String,
}

impl HardeningProfile {
    pub fn from_yaml(name: &str, yaml: &str) -> PolicyResult<Self> {
        let mut profile: HardeningProfile =
            serde_yaml::from_str(yaml).map_err(|err| PolicyError::HardeningProfile {
                name: name.to_owned(),
                message: err.to_string(),
            })?;
        profile.normalize();
        profile.validate()?;
        Ok(profile)
    }

    fn normalize(&mut self) {
        self.packages.strip.sort();
        self.packages.strip.dedup();
        self.mounts.read_only.sort();
        self.mounts.read_only.dedup();
        self.mounts.read_write.sort();
        self.mounts.read_write.dedup();
        self.capabilities.drop.sort();
        self.capabilities.drop.dedup();
    }

    fn validate(&self) -> PolicyResult<()> {
        if self.name.trim().is_empty() {
            return Err(invalid_profile(&self.name, "name must not be empty"));
        }
        if self.description.trim().is_empty() {
            return Err(invalid_profile(&self.name, "description must not be empty"));
        }
        if self.dockerfile.marker.trim().is_empty() {
            return Err(invalid_profile(&self.name, "dockerfile.marker must not be empty"));
        }
        if !self.dockerfile.fragment.contains("RUN ") {
            return Err(invalid_profile(
                &self.name,
                "dockerfile.fragment must contain a RUN instruction",
            ));
        }
        validate_positive(self.ulimits.nproc, &self.name, "ulimits.nproc")?;
        validate_positive(self.ulimits.nofile, &self.name, "ulimits.nofile")?;
        for mount in &self.mounts.tmpfs {
            if !mount.path.starts_with('/') {
                return Err(invalid_profile(
                    &self.name,
                    "mounts.tmpfs.path must be an absolute path",
                ));
            }
            if mount.size.as_deref().is_some_and(str::is_empty) {
                return Err(invalid_profile(
                    &self.name,
                    "mounts.tmpfs.size must not be empty when set",
                ));
            }
        }
        for package in &self.packages.strip {
            if package.trim().is_empty() || package.bytes().any(|byte| byte.is_ascii_whitespace()) {
                return Err(invalid_profile(
                    &self.name,
                    "packages.strip entries must be non-empty package names",
                ));
            }
        }
        Ok(())
    }
}

pub fn builtin_hardening_profile(name: &str) -> PolicyResult<HardeningProfile> {
    match name {
        "baseline" => HardeningProfile::from_yaml("baseline", BASELINE_PROFILE),
        "strict" => HardeningProfile::from_yaml("strict", STRICT_PROFILE),
        "open" => HardeningProfile::from_yaml("open", OPEN_PROFILE),
        other => Err(PolicyError::UnknownHardeningProfile {
            name: other.to_owned(),
            available: BUILTIN_NAMES.join(", "),
        }),
    }
}

pub fn resolve_hardening_profile(value: &str) -> PolicyResult<HardeningProfile> {
    if BUILTIN_NAMES.contains(&value) {
        return builtin_hardening_profile(value);
    }
    let direct = Path::new(value);
    if direct.is_file() {
        return load_profile_path(direct);
    }
    if let Ok(dir) = env::var("AGENTENV_HARDENING_PROFILE_DIR") {
        let candidate = Path::new(&dir).join(format!("{value}.yaml"));
        if candidate.is_file() {
            return load_profile_path(&candidate);
        }
    }
    if let Some(home) = dirs::home_dir() {
        let candidate = home.join(".agentenv").join("hardening").join(format!("{value}.yaml"));
        if candidate.is_file() {
            return load_profile_path(&candidate);
        }
    }
    Err(PolicyError::UnknownHardeningProfile {
        name: value.to_owned(),
        available: BUILTIN_NAMES.join(", "),
    })
}

fn load_profile_path(path: &Path) -> PolicyResult<HardeningProfile> {
    let yaml = std::fs::read_to_string(path).map_err(|err| PolicyError::HardeningProfile {
        name: path.display().to_string(),
        message: err.to_string(),
    })?;
    HardeningProfile::from_yaml(&path.display().to_string(), &yaml)
}

pub fn apply_hardening_to_policy(
    policy: &mut NetworkPolicy,
    profile: &HardeningProfile,
    persist_home: bool,
) -> PolicyResult<()> {
    merge_paths(&mut policy.filesystem.read_only, &mut policy.filesystem.read_write, &profile.mounts.read_only);
    merge_paths(&mut policy.filesystem.read_write, &mut policy.filesystem.read_only, &profile.mounts.read_write);
    if persist_home {
        merge_paths(
            &mut policy.filesystem.read_write,
            &mut policy.filesystem.read_only,
            &["$HOME".to_owned()],
        );
    }
    Ok(())
}

pub fn hardening_metadata(profile: &HardeningProfile) -> PolicyResult<BTreeMap<String, Value>> {
    let mut metadata = BTreeMap::new();
    metadata.insert("hardening_profile".to_owned(), Value::String(profile.name.clone()));
    metadata.insert(
        "hardening_packages_strip".to_owned(),
        serde_json::to_value(&profile.packages.strip).map_err(json_error(&profile.name))?,
    );
    metadata.insert(
        "hardening_tmpfs".to_owned(),
        serde_json::to_value(&profile.mounts.tmpfs).map_err(json_error(&profile.name))?,
    );
    metadata.insert(
        "hardening_capabilities_drop".to_owned(),
        serde_json::to_value(&profile.capabilities.drop).map_err(json_error(&profile.name))?,
    );
    metadata.insert(
        "hardening_dockerfile_marker".to_owned(),
        Value::String(profile.dockerfile.marker.clone()),
    );
    metadata.insert(
        "hardening_dockerfile_fragment".to_owned(),
        Value::String(profile.dockerfile.fragment.clone()),
    );
    if let Some(nproc) = profile.ulimits.nproc {
        metadata.insert("hardening_ulimit_nproc".to_owned(), Value::from(nproc));
    }
    if let Some(nofile) = profile.ulimits.nofile {
        metadata.insert("hardening_ulimit_nofile".to_owned(), Value::from(nofile));
    }
    metadata.insert(
        "hardening_disable_core_dumps".to_owned(),
        Value::Bool(profile.disable_core_dumps),
    );
    metadata.insert(
        "hardening_disable_user_namespaces".to_owned(),
        Value::Bool(profile.disable_user_namespaces),
    );
    Ok(metadata)
}

fn validate_positive(value: Option<u64>, profile: &str, field: &str) -> PolicyResult<()> {
    if value == Some(0) {
        return Err(invalid_profile(profile, &format!("{field} must be positive")));
    }
    Ok(())
}

fn invalid_profile(name: &str, message: &str) -> PolicyError {
    PolicyError::HardeningProfile {
        name: name.to_owned(),
        message: message.to_owned(),
    }
}

fn merge_paths(target: &mut Vec<String>, other: &mut Vec<String>, incoming: &[String]) {
    for path in incoming {
        target.retain(|existing| existing != path);
        other.retain(|existing| existing != path);
        target.push(path.clone());
    }
    target.sort();
    target.dedup();
}

fn json_error(profile: &str) -> impl FnOnce(serde_json::Error) -> PolicyError + '_ {
    move |err| PolicyError::HardeningProfile {
        name: profile.to_owned(),
        message: err.to_string(),
    }
}
```

Add `dirs.workspace = true` to `crates/agentenv-policy/Cargo.toml`.

- [ ] **Step 6: Export the new policy API**

Modify `crates/agentenv-policy/src/lib.rs`:

```rust
pub mod hardening;
```

Add these exports below the existing exports:

```rust
pub use crate::hardening::{
    apply_hardening_to_policy, builtin_hardening_profile, hardening_metadata,
    resolve_hardening_profile, HardeningCapabilities, HardeningDockerfile, HardeningMounts,
    HardeningPackages, HardeningProfile, HardeningTmpfsMount, HardeningUlimits,
};
```

- [ ] **Step 7: Run policy tests**

Run:

```bash
cargo test -p agentenv-policy --test hardening_profiles
cargo test -p agentenv-policy
```

Expected: PASS.

- [ ] **Step 8: Commit policy profiles**

```bash
git add Cargo.toml crates/agentenv-policy
git commit -m "feat: add hardening profile registry"
```

## Task 2: Resolve And Propagate Hardening In Core

**Files:**
- Create: `crates/agentenv-core/src/hardening.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Modify: `crates/agentenv-core/src/lifecycle.rs`
- Modify: `crates/agentenv-core/src/runtime.rs`
- Test: `crates/agentenv-core/src/runtime.rs`
- Test: `crates/agentenv-core/tests/roundtrip.rs`

- [ ] **Step 1: Write failing core tests**

Add this test to `crates/agentenv-core/tests/roundtrip.rs`:

```rust
#[test]
fn roundtrip_rejects_unknown_hardening_profile() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  hardening: sealed
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#;

    let err = agentenv_core::lifecycle::verify_blueprint_yaml(yaml)
        .expect_err("unknown profile should fail verification");

    assert!(err.to_string().contains("sealed"));
    assert!(err.to_string().contains("hardening"));
}
```

Add these tests inside the existing `#[cfg(test)] mod tests` in `crates/agentenv-core/src/runtime.rs`:

```rust
#[test]
fn sandbox_spec_defaults_to_baseline_hardening_metadata() {
    let selection = DriverSelection {
        sandbox: "openshell".to_owned(),
        agent: "codex".to_owned(),
        context: "filesystem".to_owned(),
        inference: None,
    };
    let endpoint = agentenv_proto::McpEndpoint {
        url: String::new(),
        transport: agentenv_proto::McpTransport::Stdio,
        headers: BTreeMap::new(),
    };
    let profile = crate::hardening::resolve_sandbox_hardening(&BTreeMap::new())
        .expect("baseline hardening");
    let spec = sandbox_spec_for_create(
        "demo",
        &selection,
        &BTreeMap::new(),
        &endpoint,
        BTreeMap::new(),
        None,
        &profile,
    )
    .expect("sandbox spec");

    assert_eq!(spec.metadata["hardening_profile"], serde_json::json!("baseline"));
    assert!(spec.metadata["hardening_packages_strip"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("gcc")));
}

#[test]
fn sandbox_spec_propagates_strict_hardening_metadata() {
    let selection = DriverSelection {
        sandbox: "openshell".to_owned(),
        agent: "codex".to_owned(),
        context: "filesystem".to_owned(),
        inference: None,
    };
    let endpoint = agentenv_proto::McpEndpoint {
        url: String::new(),
        transport: agentenv_proto::McpTransport::Stdio,
        headers: BTreeMap::new(),
    };
    let sandbox_extra = BTreeMap::from([(
        "hardening".to_owned(),
        serde_yaml::Value::String("strict".to_owned()),
    )]);
    let profile = crate::hardening::resolve_sandbox_hardening(&sandbox_extra)
        .expect("strict hardening");
    let spec = sandbox_spec_for_create(
        "demo",
        &selection,
        &sandbox_extra,
        &endpoint,
        BTreeMap::new(),
        None,
        &profile,
    )
    .expect("sandbox spec");

    assert_eq!(spec.metadata["hardening_profile"], serde_json::json!("strict"));
    assert_eq!(
        spec.metadata["hardening_disable_core_dumps"],
        serde_json::json!(true)
    );
    assert!(spec.metadata["hardening_packages_strip"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("curl")));
}
```

- [ ] **Step 2: Run failing core tests**

Run:

```bash
cargo test -p agentenv-core roundtrip_rejects_unknown_hardening_profile
cargo test -p agentenv-core sandbox_spec_defaults_to_baseline_hardening_metadata sandbox_spec_propagates_strict_hardening_metadata
```

Expected: FAIL because `crate::hardening` and the new `sandbox_spec_for_create` argument do not exist.

- [ ] **Step 3: Add core hardening resolution helpers**

Create `crates/agentenv-core/src/hardening.rs`:

```rust
use std::collections::BTreeMap;

use agentenv_policy::{hardening_metadata, resolve_hardening_profile, HardeningProfile};
use serde_yaml::Value;

use crate::{driver::DriverError, lifecycle::LifecycleError, runtime::RuntimeError};

#[derive(Debug, Clone)]
pub struct ResolvedHardening {
    pub profile: HardeningProfile,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

pub fn resolve_sandbox_hardening(
    sandbox_extra: &BTreeMap<String, Value>,
) -> Result<ResolvedHardening, RuntimeError> {
    let name = sandbox_hardening_value(sandbox_extra)
        .map_err(runtime_invalid_hardening)?
        .unwrap_or("baseline");
    let profile = resolve_hardening_profile(name).map_err(|err| {
        RuntimeError::Driver(DriverError::InvalidInput {
            message: err.to_string(),
        })
    })?;
    let metadata = hardening_metadata(&profile).map_err(|err| {
        RuntimeError::Driver(DriverError::InvalidInput {
            message: err.to_string(),
        })
    })?;
    Ok(ResolvedHardening { profile, metadata })
}

pub fn validate_sandbox_hardening(
    sandbox_extra: &BTreeMap<String, Value>,
) -> Result<(), LifecycleError> {
    let name = sandbox_hardening_value(sandbox_extra).map_err(|message| {
        LifecycleError::InvalidHardeningProfile {
            message,
        }
    })?;
    let Some(name) = name else {
        resolve_hardening_profile("baseline").map_err(|err| LifecycleError::InvalidHardeningProfile {
            message: err.to_string(),
        })?;
        return Ok(());
    };
    resolve_hardening_profile(name).map_err(|err| LifecycleError::InvalidHardeningProfile {
        message: err.to_string(),
    })?;
    Ok(())
}

fn sandbox_hardening_value(
    sandbox_extra: &BTreeMap<String, Value>,
) -> Result<Option<&str>, String> {
    match sandbox_extra.get("hardening") {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.as_str())),
        Some(Value::String(_)) => Err("sandbox.hardening must not be empty".to_owned()),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err("sandbox.hardening must be a string when set".to_owned()),
    }
}

fn runtime_invalid_hardening(message: String) -> RuntimeError {
    RuntimeError::Driver(DriverError::InvalidInput { message })
}
```

Modify `crates/agentenv-core/src/lib.rs`:

```rust
pub mod hardening;
```

Add a `LifecycleError` variant in `crates/agentenv-core/src/lifecycle.rs`:

```rust
#[error("invalid hardening profile: {message}")]
InvalidHardeningProfile { message: String },
```

Call validation in `verify_resolved_blueprint` after URL validation:

```rust
crate::hardening::validate_sandbox_hardening(&resolved.blueprint.sandbox.extra)?;
```

- [ ] **Step 4: Apply hardening during create and sandbox spec construction**

In `crates/agentenv-core/src/runtime.rs`, resolve hardening before composing policy in `create_env_inner`:

```rust
let hardening = crate::hardening::resolve_sandbox_hardening(&resolved.blueprint.sandbox.extra)?;
```

After composing policy and adding context network rules, merge hardening only when the policy came from the blueprint rather than a lockfile:

```rust
if input.resolved_policy.is_none() {
    let persist_home = resolved
        .blueprint
        .state
        .as_ref()
        .and_then(|state| state.persist_home)
        .unwrap_or(false);
    agentenv_policy::apply_hardening_to_policy(&mut policy, &hardening.profile, persist_home)
        .map_err(|err| RuntimeError::Driver(crate::driver::DriverError::InvalidInput {
            message: err.to_string(),
        }))?;
}
```

Change `sandbox_spec_for_create` signature:

```rust
fn sandbox_spec_for_create(
    name: &str,
    selection: &DriverSelection,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
    context_endpoint: &agentenv_proto::McpEndpoint,
    env: BTreeMap<String, String>,
    policy: Option<agentenv_proto::NetworkPolicy>,
    hardening: &crate::hardening::ResolvedHardening,
) -> RuntimeResult<agentenv_proto::SandboxSpec> {
```

Before returning `SandboxSpec`, merge metadata:

```rust
metadata.extend(hardening.metadata.clone());
```

Update the production call:

```rust
let sandbox_spec = sandbox_spec_for_create(
    name,
    &selection,
    &resolved.blueprint.sandbox.extra,
    &context_endpoint,
    env,
    Some(create_policy.clone()),
    &hardening,
)?;
```

Update every test call to pass `&profile` as shown in Step 1.

- [ ] **Step 5: Run core tests**

Run:

```bash
cargo test -p agentenv-core roundtrip_rejects_unknown_hardening_profile
cargo test -p agentenv-core sandbox_spec_defaults_to_baseline_hardening_metadata sandbox_spec_propagates_strict_hardening_metadata
cargo test -p agentenv-core
```

Expected: PASS.

- [ ] **Step 6: Commit core propagation**

```bash
git add crates/agentenv-core
git commit -m "feat: propagate sandbox hardening metadata"
```

## Task 3: Add Hardening-Aware Dockerfile Linting

**Files:**
- Modify: `crates/agentenv-core/src/hardening.rs`
- Modify: `crates/agentenv-core/src/runtime.rs`
- Test: `crates/agentenv-core/tests/hardening_lint.rs`

- [ ] **Step 1: Write failing public lint tests**

Create `crates/agentenv-core/tests/hardening_lint.rs`:

```rust
use agentenv_core::hardening::{lint_blueprint_hardening, HardeningLintSeverity};

fn temp_root(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "agentenv-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn lint_reports_strict_dockerfile_errors() {
    let root = temp_root("hardening-lint-strict");
    let dockerfile = root.join("Dockerfile");
    std::fs::write(
        &dockerfile,
        r#"
FROM alpine:3.20
RUN apk add --no-cache curl git
RUN docker run --privileged alpine true
RUN echo cap_add: NET_ADMIN
USER root
"#,
    )
    .unwrap();
    let yaml = format!(
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  hardening: strict
  image:
    source: byo
    dockerfile: {}
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#,
        dockerfile.display()
    );

    let report = lint_blueprint_hardening(&yaml, &root).expect("lint report");
    let codes = report
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();

    assert!(codes.contains(&"dockerfile_user_root"));
    assert!(codes.contains(&"dockerfile_privileged"));
    assert!(codes.contains(&"dockerfile_cap_add"));
    assert!(codes.contains(&"dockerfile_missing_hardening_marker"));
    assert!(codes.contains(&"dockerfile_reintroduces_stripped_package"));
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == HardeningLintSeverity::Error));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn lint_baseline_package_reintroduction_is_warning() {
    let root = temp_root("hardening-lint-baseline");
    let dockerfile = root.join("Dockerfile");
    std::fs::write(
        &dockerfile,
        r#"
FROM alpine:3.20
RUN apk add --no-cache gcc
USER sandbox
"#,
    )
    .unwrap();
    let yaml = format!(
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image:
    source: byo
    dockerfile: {}
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#,
        dockerfile.display()
    );

    let report = lint_blueprint_hardening(&yaml, &root).expect("lint report");
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "dockerfile_reintroduces_stripped_package")
        .expect("package diagnostic");

    assert_eq!(report.profile, "baseline");
    assert_eq!(diagnostic.severity, HardeningLintSeverity::Warning);
    std::fs::remove_dir_all(root).unwrap();
}
```

- [ ] **Step 2: Run failing lint tests**

Run:

```bash
cargo test -p agentenv-core --test hardening_lint
```

Expected: FAIL because `lint_blueprint_hardening` and lint types do not exist.

- [ ] **Step 3: Implement lint report types and Dockerfile analysis**

Append to `crates/agentenv-core/src/hardening.rs`:

```rust
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HardeningLintReport {
    pub profile: String,
    pub dockerfile: Option<PathBuf>,
    pub diagnostics: Vec<HardeningLintDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HardeningLintDiagnostic {
    pub severity: HardeningLintSeverity,
    pub code: String,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HardeningLintSeverity {
    Warning,
    Error,
}

pub fn lint_blueprint_hardening(
    blueprint_yaml: &str,
    cwd: &Path,
) -> Result<HardeningLintReport, RuntimeError> {
    let blueprint = crate::blueprint::Blueprint::from_yaml(blueprint_yaml)
        .map_err(crate::lifecycle::LifecycleError::from)?;
    let hardening = resolve_sandbox_hardening(&blueprint.sandbox.extra)?;
    let dockerfile = byo_dockerfile_path(&blueprint.sandbox.extra, cwd)?;
    let mut diagnostics = Vec::new();
    if let Some(path) = dockerfile.as_ref() {
        diagnostics.extend(lint_dockerfile(path, &hardening.profile));
    }
    diagnostics.extend(runtime_support_diagnostics(&hardening.profile, &blueprint.sandbox.driver));
    Ok(HardeningLintReport {
        profile: hardening.profile.name,
        dockerfile,
        diagnostics,
    })
}

pub fn dockerfile_preflight_issues(
    sandbox_extra: &BTreeMap<String, Value>,
) -> Vec<agentenv_proto::PreflightIssue> {
    let Ok(hardening) = resolve_sandbox_hardening(sandbox_extra) else {
        return Vec::new();
    };
    let Ok(Some(path)) = byo_dockerfile_path(sandbox_extra, Path::new(".")) else {
        return Vec::new();
    };
    lint_dockerfile(&path, &hardening.profile)
        .into_iter()
        .map(|diagnostic| agentenv_proto::PreflightIssue {
            severity: match diagnostic.severity {
                HardeningLintSeverity::Warning => agentenv_proto::IssueSeverity::Warning,
                HardeningLintSeverity::Error => agentenv_proto::IssueSeverity::Error,
            },
            code: diagnostic.code,
            message: diagnostic.message,
            remediation: diagnostic.remediation,
        })
        .collect()
}

fn byo_dockerfile_path(
    sandbox_extra: &BTreeMap<String, Value>,
    cwd: &Path,
) -> Result<Option<PathBuf>, RuntimeError> {
    let image = match sandbox_extra.get("image").and_then(Value::as_mapping) {
        Some(image) => image,
        None => return Ok(None),
    };
    if yaml_mapping_string(image, "source") != Some("byo") {
        return Ok(None);
    }
    let Some(raw) = yaml_mapping_string(image, "dockerfile") else {
        return Ok(None);
    };
    let path = Path::new(raw);
    Ok(Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }))
}

fn lint_dockerfile(
    path: &Path,
    profile: &agentenv_policy::HardeningProfile,
) -> Vec<HardeningLintDiagnostic> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) => {
            return vec![diagnostic(
                HardeningLintSeverity::Error,
                "dockerfile_unreadable",
                format!("could not read BYO Dockerfile `{}`: {err}", path.display()),
                "Check the Dockerfile path and permissions before creating the environment",
            )];
        }
    };
    let mut final_user = None::<String>;
    let mut saw_privileged = false;
    let mut saw_cap_add = false;
    let mut installed = Vec::<String>::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("--privileged") {
            saw_privileged = true;
        }
        if lower.contains("cap_add") || lower.contains("cap-add") {
            saw_cap_add = true;
        }
        if let Some(rest) = lower.strip_prefix("user ") {
            final_user = rest
                .split_whitespace()
                .next()
                .map(|user| user.split(':').next().unwrap_or(user).to_owned());
        }
        if lower.starts_with("run ") {
            installed.extend(installed_packages_from_run_line(&lower));
        }
    }

    let mut diagnostics = Vec::new();
    if matches!(final_user.as_deref(), Some("root" | "0")) {
        diagnostics.push(diagnostic(
            root_user_severity(profile),
            "dockerfile_user_root",
            format!("BYO Dockerfile `{}` leaves the final image user as root", path.display()),
            "Set a non-root final USER that matches the sandbox policy",
        ));
    }
    if saw_privileged {
        diagnostics.push(diagnostic(
            HardeningLintSeverity::Warning,
            "dockerfile_privileged",
            format!("BYO Dockerfile `{}` references `--privileged`", path.display()),
            "Remove privileged container nesting from the sandbox image build",
        ));
    }
    if saw_cap_add {
        diagnostics.push(diagnostic(
            HardeningLintSeverity::Warning,
            "dockerfile_cap_add",
            format!("BYO Dockerfile `{}` references cap_add or cap-add", path.display()),
            "Move Linux capability requirements into agentenv policy instead of the image",
        ));
    }
    if !contents.contains(&profile.dockerfile.marker) {
        diagnostics.push(diagnostic(
            HardeningLintSeverity::Warning,
            "dockerfile_missing_hardening_marker",
            format!("BYO Dockerfile `{}` does not contain `{}`", path.display(), profile.dockerfile.marker),
            "Run through agentenv create or include the selected hardening fragment in the image build",
        ));
    }
    for package in profile.packages.strip.iter().filter(|package| installed.contains(package)) {
        diagnostics.push(diagnostic(
            package_reintroduction_severity(profile),
            "dockerfile_reintroduces_stripped_package",
            format!("BYO Dockerfile `{}` installs `{package}`, which `{}` strips", path.display(), profile.name),
            "Remove the package install or choose a less restrictive hardening profile",
        ));
    }
    diagnostics
}

fn installed_packages_from_run_line(line: &str) -> Vec<String> {
    let mut packages = Vec::new();
    let tokens = line
        .split(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '\\' | ';' | '&'))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    for window in tokens.windows(2) {
        if matches!(window, ["add", pkg] | ["install", pkg]) && !pkg.starts_with('-') {
            packages.push((*pkg).to_owned());
        }
    }
    packages
}

fn runtime_support_diagnostics(
    profile: &agentenv_policy::HardeningProfile,
    driver: &str,
) -> Vec<HardeningLintDiagnostic> {
    if driver == "openshell" && (!profile.mounts.tmpfs.is_empty() || profile.disable_user_namespaces) {
        return vec![diagnostic(
            HardeningLintSeverity::Warning,
            "hardening_runtime_unsupported",
            format!("sandbox driver `{driver}` may not enforce every runtime setting in `{}`", profile.name),
            "Review driver preflight output and OpenShell support before relying on this setting",
        )];
    }
    Vec::new()
}

fn root_user_severity(profile: &agentenv_policy::HardeningProfile) -> HardeningLintSeverity {
    match profile.name.as_str() {
        "baseline" | "strict" => HardeningLintSeverity::Error,
        _ => HardeningLintSeverity::Warning,
    }
}

fn package_reintroduction_severity(profile: &agentenv_policy::HardeningProfile) -> HardeningLintSeverity {
    if profile.name == "strict" {
        HardeningLintSeverity::Error
    } else {
        HardeningLintSeverity::Warning
    }
}

fn diagnostic(
    severity: HardeningLintSeverity,
    code: &str,
    message: String,
    remediation: &str,
) -> HardeningLintDiagnostic {
    HardeningLintDiagnostic {
        severity,
        code: code.to_owned(),
        message,
        remediation: Some(remediation.to_owned()),
    }
}

fn yaml_mapping_string<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    mapping
        .get(serde_yaml::Value::String(key.to_owned()))
        .and_then(Value::as_str)
}
```

If duplicate `Path`, `Serialize`, or `Value` imports conflict with the top of the file, merge them into the existing `use` declarations.

- [ ] **Step 4: Replace old BYO preflight warnings with hardening-aware warnings**

Modify `add_byo_dockerfile_preflight_warnings` in `crates/agentenv-core/src/runtime.rs`:

```rust
pub fn add_byo_dockerfile_preflight_warnings(
    report: &mut crate::admission::AdmissionReport,
    sandbox_extra: &BTreeMap<String, serde_yaml::Value>,
) {
    let issues = crate::hardening::dockerfile_preflight_issues(sandbox_extra);
    if issues.is_empty() {
        return;
    }

    if let Some(check) = report
        .checks
        .iter_mut()
        .find(|check| check.kind == DriverKind::Sandbox)
    {
        check.issues.extend(issues);
        return;
    }

    report.checks.push(crate::admission::PreflightCheck {
        kind: DriverKind::Sandbox,
        driver: "openshell".to_owned(),
        ok: true,
        issues,
    });
}
```

Remove the old private `byo_dockerfile_path`, `dockerfile_preflight_warnings`, and `preflight_warning` helpers from `runtime.rs` after tests pass.

- [ ] **Step 5: Run lint and core tests**

Run:

```bash
cargo test -p agentenv-core --test hardening_lint
cargo test -p agentenv-core byo_dockerfile_preflight_warnings_detect_conflicting_patterns
cargo test -p agentenv-core
```

Expected: PASS. If `byo_dockerfile_preflight_warnings_detect_conflicting_patterns` now sees `dockerfile_*` codes instead of `byo_dockerfile_*`, update that test to assert the new codes.

- [ ] **Step 6: Commit core linting**

```bash
git add crates/agentenv-core
git commit -m "feat: lint hardening profiles against Dockerfiles"
```

## Task 4: Add `agentenv blueprint lint`

**Files:**
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/src/render.rs`
- Test: `crates/agentenv/src/main.rs`
- Test: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI tests**

In `crates/agentenv/src/main.rs`, update `cli_includes_commands` expected list by inserting `"blueprint".to_string()` before `"credentials".to_string()`.

Add this integration test to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn blueprint_lint_reports_json_diagnostics() {
    let temp_dir = make_temp_dir("blueprint-lint-json");
    let dockerfile = temp_dir.join("Dockerfile");
    fs::write(
        &dockerfile,
        r#"
FROM alpine:3.20
RUN apk add --no-cache curl git
USER root
"#,
    )
    .unwrap();
    let blueprint = temp_dir.join("agentenv.yaml");
    fs::write(
        &blueprint,
        format!(
            r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  hardening: strict
  image:
    source: byo
    dockerfile: {}
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#,
            dockerfile.display()
        ),
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("blueprint")
        .arg("lint")
        .arg(&blueprint)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "lint should fail on strict errors");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["profile"], "strict");
    let codes = json["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"dockerfile_user_root"));
    assert!(codes.contains(&"dockerfile_reintroduces_stripped_package"));
}
```

- [ ] **Step 2: Run failing CLI tests**

Run:

```bash
cargo test -p agentenv cli_includes_commands
cargo test -p agentenv --test cli_behavior blueprint_lint_reports_json_diagnostics
```

Expected: FAIL because the `blueprint` subcommand does not exist.

- [ ] **Step 3: Add the subcommand types and dispatcher**

In `crates/agentenv/src/main.rs`, add `Blueprint(BlueprintArgs)` to `Commands` before `Credentials`.

Add these arg structs near the other command args:

```rust
#[derive(Debug, Args)]
struct BlueprintArgs {
    #[command(subcommand)]
    command: BlueprintCommand,
}

#[derive(Debug, Subcommand)]
enum BlueprintCommand {
    Lint(BlueprintLintArgs),
}

#[derive(Debug, Args)]
struct BlueprintLintArgs {
    file: PathBuf,
    #[arg(long)]
    json: bool,
}
```

Add to the `match cli.command` dispatcher:

```rust
Some(Commands::Blueprint(args)) => run_blueprint(args),
```

Add the runner:

```rust
fn run_blueprint(args: BlueprintArgs) -> Result<()> {
    match args.command {
        BlueprintCommand::Lint(args) => run_blueprint_lint(args),
    }
}

fn run_blueprint_lint(args: BlueprintLintArgs) -> Result<()> {
    let yaml = read_text_file(&args.file, "blueprint")?;
    let cwd = args
        .file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let report = agentenv_core::hardening::lint_blueprint_hardening(&yaml, cwd)
        .with_context(|| format!("failed to lint blueprint `{}`", args.file.display()))?;
    let has_errors = report.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == agentenv_core::hardening::HardeningLintSeverity::Error
    });
    if args.json {
        render::print_json(&report)?;
    } else {
        print_hardening_lint_text(&report);
    }
    if has_errors {
        exit_process(1);
    }
    Ok(())
}

fn print_hardening_lint_text(report: &agentenv_core::hardening::HardeningLintReport) {
    println!("hardening profile: {}", report.profile);
    if let Some(path) = report.dockerfile.as_ref() {
        println!("dockerfile: {}", path.display());
    }
    if report.diagnostics.is_empty() {
        println!("ok: no hardening diagnostics");
        return;
    }
    for diagnostic in &report.diagnostics {
        println!(
            "{} {}: {}",
            match diagnostic.severity {
                agentenv_core::hardening::HardeningLintSeverity::Warning => "warning",
                agentenv_core::hardening::HardeningLintSeverity::Error => "error",
            },
            diagnostic.code,
            diagnostic.message
        );
        if let Some(remediation) = diagnostic.remediation.as_deref() {
            println!("  remediation: {remediation}");
        }
    }
}
```

- [ ] **Step 4: Run CLI tests**

Run:

```bash
cargo test -p agentenv cli_includes_commands
cargo test -p agentenv --test cli_behavior blueprint_lint_reports_json_diagnostics
```

Expected: PASS.

- [ ] **Step 5: Commit CLI lint command**

```bash
git add crates/agentenv/src/main.rs crates/agentenv/src/render.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: add blueprint hardening lint command"
```

## Task 5: Inject Hardening Into OpenShell BYO Builds

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`
- Test: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing OpenShell tests**

Modify `create_builds_byo_dockerfile_and_uses_staged_context` in `crates/drivers/sandbox-openshell/src/lib.rs`. Replace the staged Dockerfile equality assertion with:

```rust
let staged = std::fs::read_to_string(&stage_dockerfile).expect("staged Dockerfile");
assert!(staged.contains("FROM alpine:3.20"));
assert!(staged.contains("AGENTENV_HARDENING_PROFILE=strict"));
assert!(staged.contains("apk del"));
```

Add strict metadata to that test's `SandboxSpec.metadata`:

```rust
("hardening_profile".to_owned(), json!("strict")),
(
    "hardening_dockerfile_marker".to_owned(),
    json!("AGENTENV_HARDENING_PROFILE=strict"),
),
(
    "hardening_dockerfile_fragment".to_owned(),
    json!("RUN echo AGENTENV_HARDENING_PROFILE=strict && apk del curl git || true"),
),
("hardening_ulimit_nproc".to_owned(), json!(512)),
("hardening_ulimit_nofile".to_owned(), json!(4096)),
("hardening_disable_core_dumps".to_owned(), json!(true)),
("hardening_disable_user_namespaces".to_owned(), json!(true)),
```

Add this test near the BYO tests:

```rust
#[test]
fn create_rejects_invalid_hardening_metadata_before_build() {
    let tempdir = unique_tempdir("sandbox-openshell-invalid-hardening");
    let context_dir = tempdir.join("enterprise-sandbox");
    std::fs::create_dir_all(&context_dir).expect("create context");
    let dockerfile = context_dir.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write Dockerfile");
    let runner = Arc::new(FlexibleCommandRunner::new(Vec::new()));
    let driver = OpenShellDriver::with_command_runner_and_workdir(runner, tempdir.join(".agentenv"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let err = runtime
        .block_on(async {
            driver
                .create(SandboxSpec {
                    image: None,
                    env: BTreeMap::new(),
                    policy: None,
                    metadata: BTreeMap::from([
                        ("name".to_owned(), json!("devbox")),
                        ("byo_dockerfile".to_owned(), json!(dockerfile.display().to_string())),
                        ("hardening_profile".to_owned(), json!("strict")),
                        ("hardening_ulimit_nproc".to_owned(), json!(0)),
                    ]),
                })
                .await
        })
        .expect_err("invalid hardening should fail");

    assert!(err.to_string().contains("hardening_ulimit_nproc"));
    assert!(err.to_string().contains("positive"));
    std::fs::remove_dir_all(tempdir).expect("remove tempdir");
}
```

- [ ] **Step 2: Run failing OpenShell tests**

Run:

```bash
cargo test -p sandbox-openshell create_builds_byo_dockerfile_and_uses_staged_context create_rejects_invalid_hardening_metadata_before_build
```

Expected: FAIL because hardening fragment injection and metadata validation do not exist.

- [ ] **Step 3: Add OpenShell hardening config parsing**

In `crates/drivers/sandbox-openshell/src/lib.rs`, add structs near `ByoDockerfileConfig`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct OpenShellHardeningConfig {
    profile: Option<String>,
    dockerfile_marker: Option<String>,
    dockerfile_fragment: Option<String>,
    ulimit_nproc: Option<u64>,
    ulimit_nofile: Option<u64>,
    disable_core_dumps: bool,
    disable_user_namespaces: bool,
}
```

Add parsing helpers near `byo_dockerfile_config`:

```rust
fn hardening_config(metadata: &BTreeMap<String, Value>) -> DriverResult<OpenShellHardeningConfig> {
    let ulimit_nproc = optional_metadata_u64(metadata, "hardening_ulimit_nproc")?;
    let ulimit_nofile = optional_metadata_u64(metadata, "hardening_ulimit_nofile")?;
    validate_positive_metadata("hardening_ulimit_nproc", ulimit_nproc)?;
    validate_positive_metadata("hardening_ulimit_nofile", ulimit_nofile)?;
    Ok(OpenShellHardeningConfig {
        profile: optional_metadata_string(metadata, "hardening_profile")?,
        dockerfile_marker: optional_metadata_string(metadata, "hardening_dockerfile_marker")?,
        dockerfile_fragment: optional_metadata_string(metadata, "hardening_dockerfile_fragment")?,
        ulimit_nproc,
        ulimit_nofile,
        disable_core_dumps: optional_metadata_bool(metadata, "hardening_disable_core_dumps")?
            .unwrap_or(false),
        disable_user_namespaces: optional_metadata_bool(
            metadata,
            "hardening_disable_user_namespaces",
        )?
        .unwrap_or(false),
    })
}

fn optional_metadata_u64(
    metadata: &BTreeMap<String, Value>,
    key: &str,
) -> DriverResult<Option<u64>> {
    match metadata.get(key) {
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            DriverError::InvalidInput {
                message: format!("metadata.{key} must be an unsigned integer when set"),
            }
        }),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be an unsigned integer when set"),
        }),
    }
}

fn optional_metadata_bool(
    metadata: &BTreeMap<String, Value>,
    key: &str,
) -> DriverResult<Option<bool>> {
    match metadata.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be a boolean when set"),
        }),
    }
}

fn validate_positive_metadata(key: &str, value: Option<u64>) -> DriverResult<()> {
    if value == Some(0) {
        return Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be positive when set"),
        });
    }
    Ok(())
}
```

- [ ] **Step 4: Inject the fragment during staging**

Change `prepare_byo_dockerfile_context` signature:

```rust
fn prepare_byo_dockerfile_context(
    &self,
    name: &str,
    config: &ByoDockerfileConfig,
    hardening: &OpenShellHardeningConfig,
) -> DriverResult<String> {
```

After `stage_build_context(context_dir, &dockerfile, &stage_dir)?;`, add:

```rust
inject_hardening_fragment(&stage_dir.join("Dockerfile"), hardening)?;
```

Add helper:

```rust
fn inject_hardening_fragment(
    dockerfile: &Path,
    hardening: &OpenShellHardeningConfig,
) -> DriverResult<()> {
    let Some(fragment) = hardening.dockerfile_fragment.as_deref() else {
        return Ok(());
    };
    let marker = hardening
        .dockerfile_marker
        .as_deref()
        .unwrap_or("AGENTENV_HARDENING_PROFILE=custom");
    let mut contents = fs::read_to_string(dockerfile).map_err(|source| DriverError::InvalidInput {
        message: format!(
            "failed to read staged Dockerfile `{}` before hardening injection: {source}",
            dockerfile.display()
        ),
    })?;
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str("\n# agentenv hardening\n");
    contents.push_str("# ");
    contents.push_str(marker);
    contents.push('\n');
    contents.push_str(fragment.trim_end());
    contents.push('\n');
    fs::write(dockerfile, contents).map_err(|source| DriverError::InvalidInput {
        message: format!(
            "failed to write staged Dockerfile `{}` after hardening injection: {source}",
            dockerfile.display()
        ),
    })
}
```

In `create`, parse hardening before image preparation:

```rust
let hardening = hardening_config(&spec.metadata)?;
let image = match byo_dockerfile_config(&spec.metadata)? {
    Some(config) => self.prepare_byo_dockerfile_context(&name, &config, &hardening)?,
    None => spec.image.unwrap_or_else(|| "openclaw".to_owned()),
};
```

Keep `hardening` available for future OpenShell CLI mappings, but do not add CLI args that OpenShell does not support.

- [ ] **Step 5: Run OpenShell tests**

Run:

```bash
cargo test -p sandbox-openshell create_builds_byo_dockerfile_and_uses_staged_context create_rejects_invalid_hardening_metadata_before_build
cargo test -p sandbox-openshell
```

Expected: PASS.

- [ ] **Step 6: Commit OpenShell hardening build injection**

```bash
git add crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat: inject hardening into openshell BYO builds"
```

## Task 6: Update Documentation

**Files:**
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `docs/BLUEPRINTS.md`
- Modify: `crates/agentenv-policy/README.md`
- Modify: `crates/drivers/sandbox-openshell/README.md`

- [ ] **Step 1: Update driver protocol docs**

In `docs/DRIVER_PROTOCOL.md`, add this paragraph after the `SandboxDriver` method table:

```markdown
Image hardening profiles are create-time sandbox configuration in schema 1.1. Core resolves `sandbox.hardening`, merges supported filesystem/process settings into `SandboxSpec.policy`, and sends image/runtime settings through `SandboxSpec.metadata` keys prefixed with `hardening_`. Drivers that build or launch container images may consume those metadata keys during `create`. No separate `apply_hardening` method exists in schema 1.1; a future additive method is reserved for sandbox drivers that need post-create or independently reloadable hardening.
```

- [ ] **Step 2: Update blueprint docs**

In `docs/BLUEPRINTS.md`, add this section near the policy discussion:

````markdown
## Hardening Profiles

`sandbox.hardening` selects image and runtime hardening for container-image-backed sandboxes:

```yaml
sandbox:
  driver: openshell
  hardening: strict
```

When omitted, agentenv uses `baseline`. `baseline` removes build and network-debug tools, requests read-only system paths, tightens process limits, and strips SUID bits in the generated image fragment. `strict` also removes `curl`, `wget`, and `git`, requests tmpfs for `/tmp`, disables core dumps, and requests user namespaces disabled. `open` keeps minimal hardening for research environments where tooling availability matters more than production posture.

Use `agentenv blueprint lint <agentenv.yaml>` to check a BYO Dockerfile against the selected profile before create.
````

- [ ] **Step 3: Update policy crate README**

Append to `crates/agentenv-policy/README.md`:

```markdown
## Image Hardening Profiles

Built-in hardening profiles live under `hardening/` and are loaded through typed Rust structs:

- `baseline`: default production profile.
- `strict`: sensitive-work profile with stronger image stripping and runtime requests.
- `open`: minimal profile for exploratory environments.

The profile loader validates package names, tmpfs mounts, ulimit values, and generated Dockerfile fragments before core passes profile data to sandbox drivers.
```

- [ ] **Step 4: Update OpenShell README**

Append to `crates/drivers/sandbox-openshell/README.md`:

```markdown
## Hardening

OpenShell consumes hardening metadata from `SandboxSpec.metadata` during `create`. For BYO Dockerfile builds, the staged Dockerfile receives the selected agentenv hardening fragment before `docker build`, so digest verification reflects the hardened image. Runtime hardening fields that OpenShell cannot map directly are surfaced by blueprint lint/preflight diagnostics instead of being silently ignored.
```

- [ ] **Step 5: Commit docs**

```bash
git add docs/DRIVER_PROTOCOL.md docs/BLUEPRINTS.md crates/agentenv-policy/README.md crates/drivers/sandbox-openshell/README.md
git commit -m "docs: document image hardening profiles"
```

## Task 7: Full Verification And Fixups

**Files:**
- Modify only files needed to fix compiler, formatting, lint, or regression issues found by this task.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt
```

Expected: exits 0 with no required manual changes after formatting.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: PASS. Fix every warning in the smallest relevant file. Do not suppress warnings unless the lint is demonstrably wrong.

- [ ] **Step 3: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 4: Inspect final diff**

Run:

```bash
git status --short
git diff --stat origin/main..HEAD
```

Expected: only issue #22 hardening files and docs are changed.

- [ ] **Step 5: Commit verification fixes if needed**

If `cargo fmt`, clippy, or tests changed files after the last task commit:

```bash
git add -u
git commit -m "fix: stabilize hardening profile implementation"
```

Expected: branch contains focused commits and a clean worktree.

## Self-Review

Spec coverage:

- Three built-in profiles: Task 1.
- Baseline default and strict/open propagation: Tasks 1 and 2.
- BYO Dockerfile hardening fragment and digest preservation: Task 5.
- Runtime metadata and graceful unsupported diagnostics: Tasks 2, 3, and 5.
- `agentenv blueprint lint`: Tasks 3 and 4.
- Docs and protocol-stable explanation: Task 6.

Placeholder scan:

- The plan contains no placeholder markers, ellipsis implementation markers, or unnamed follow-up work.
- Code snippets use concrete file paths, function names, metadata keys, and command lines.

Type consistency:

- Policy APIs exported by Task 1 are the same APIs used by Tasks 2 and 3.
- `ResolvedHardening` is defined in Task 2 before runtime calls use it.
- Lint report structs are defined in Task 3 before CLI rendering uses them in Task 4.
- OpenShell metadata keys match `hardening_metadata` from Task 1.
