# M7-7 Skill Self-Test Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the full issue #33 self-test gate so skills cannot be installed locally or published unless a structured functional self-test reaches score `>= 0.8` and produces a signed attestation.

**Architecture:** Keep skills as core-managed resources. Add a reusable self-test engine and attestation verifier under `agentenv-core::skills`, inject the agent-producing runtime from the CLI, and keep registry adapters responsible only for storing already-gated artifacts plus attestations. Preserve existing `skill.yaml self_test.command` behavior by translating it into the structured assertion model.

**Tech Stack:** Rust 2021, `serde_yaml`, `serde_json`, `time`, `sha2`, `ed25519-dalek`, `rand_core`, existing `SkillService`, existing registry adapters, existing runtime `DriverFactory`.

---

## File Structure

- Create `crates/agentenv-core/src/skills/self_test.rs`: self-test spec parsing, normalization, assertion execution, score calculation, local command/file runners, and the `AgentProduceRunner` trait.
- Create `crates/agentenv-core/src/skills/attestation.rs`: signed self-test attestation model, local signing key load/create, canonical payload, validation, recency checks, and path layout.
- Modify `crates/agentenv-core/src/skills/mod.rs`: export self-test and attestation APIs.
- Modify `crates/agentenv-core/src/skills/error.rs`: add typed self-test and attestation errors.
- Modify `crates/agentenv-core/src/skills/manifest.rs`: preserve legacy `self_test.command`, expose helpers needed by structured self-test loading.
- Modify `crates/agentenv-core/src/skills/store.rs`: store self-test attestation summary on installed skills and run the install/verify gate.
- Modify `crates/agentenv-core/src/skills/service.rs`: add self-test runner injection and gate `add`, `install_from_path`, `verify`, and `publish`.
- Modify `crates/agentenv-core/src/skills/cache.rs`: map cache metadata self-tests into the shared self-test report and support JSON verify-all output.
- Modify `crates/agentenv-core/src/skills/registry.rs`: extend `RegistryAdapter::publish` to accept a verified attestation.
- Modify `crates/agentenv-core/src/skills/registry_filesystem.rs`: store attestation JSON next to published bundles and include summary fields in the index.
- Modify `crates/agentenv-core/src/skills/registry_http.rs`: upload attestation JSON with expanded bundle publish.
- Modify `crates/agentenv-core/src/skills/registry_oci.rs`: publish attestation as an OCI layer with annotations.
- Modify `crates/agentenv-core/src/skills/registry_git.rs`: update the trait signature and keep publish unsupported.
- Modify `crates/agentenv-core/Cargo.toml`: enable `rand_core` `getrandom` for key generation if needed.
- Modify `crates/agentenv/src/skills_cli.rs`: add CLI flags, JSON output, and runtime injection.
- Modify `crates/agentenv/src/main.rs`: expose or move credential-provider plumbing needed by the skills CLI `agent_produces` harness.
- Modify `crates/agentenv/tests/cli_behavior.rs`: add CLI gate coverage.
- Add `crates/agentenv-core/tests/skills_self_test.rs`: self-test parser, runner, scoring, attestation, and gate unit coverage.

## Task 1: Structured Self-Test Spec Parser

**Files:**
- Create: `crates/agentenv-core/src/skills/self_test.rs`
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Test: `crates/agentenv-core/tests/skills_self_test.rs`

- [ ] **Step 1: Write the failing parser tests**

Add `crates/agentenv-core/tests/skills_self_test.rs`:

```rust
use std::{fs, path::Path};

use agentenv_core::skills::{
    load_skill_self_test_spec, SkillError, SkillSelfTestAssertion, SkillSelfTestRunner,
};

#[test]
fn self_test_spec_loads_from_skill_test_yaml() {
    let root = temp_dir("self-test-yaml");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
  timeout_seconds: 120
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("self-test should load");

    assert_eq!(spec.runner, SkillSelfTestRunner::Agentenv);
    assert_eq!(spec.timeout_seconds, 120);
    assert_eq!(
        spec.assertions,
        vec![SkillSelfTestAssertion::FileExists {
            path: "SKILL.md".into()
        }]
    );
}

#[test]
fn self_test_spec_loads_from_skill_md_frontmatter() {
    let root = temp_dir("self-test-frontmatter");
    write_file(
        &root.join("SKILL.md"),
        r#"---
self_test:
  runner: agentenv
  assertions:
    - type: command_exits_zero
      cmd: "test -f SKILL.md"
---
# Demo
"#,
    );
    write_file(
        &root.join("skill.yaml"),
        "name: demo-frontmatter\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let spec = load_skill_self_test_spec(&root).expect("frontmatter self-test should load");

    assert_eq!(spec.assertions.len(), 1);
    assert!(matches!(
        &spec.assertions[0],
        SkillSelfTestAssertion::CommandExitsZero { cmd } if cmd == "test -f SKILL.md"
    ));
}

#[test]
fn self_test_spec_translates_legacy_skill_yaml_command() {
    let root = temp_dir("self-test-legacy-command");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        r#"name: legacy-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  command: "test -f SKILL.md"
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("legacy command should translate");

    assert_eq!(spec.timeout_seconds, 30);
    assert_eq!(
        spec.assertions,
        vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: "test -f SKILL.md".to_owned()
        }]
    );
}

#[test]
fn self_test_spec_rejects_conflicting_locations() {
    let root = temp_dir("self-test-conflict");
    write_file(
        &root.join("SKILL.md"),
        r#"---
self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
---
# Demo
"#,
    );
    write_file(
        &root.join("skill.yaml"),
        r#"name: conflict-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  runner: agentenv
  assertions:
    - type: command_exits_zero
      cmd: "test -f SKILL.md"
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("conflict must fail");

    assert!(matches!(error, SkillError::ConflictingSelfTestDeclarations { .. }));
}

#[test]
fn self_test_spec_rejects_invalid_agent_assertion_ratio() {
    let root = temp_dir("self-test-bad-ratio");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: bad-ratio\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  blueprint: test/minimal.yaml
  assertions:
    - type: agent_produces
      prompt: "summarize"
      expect_tokens_matching: ["Cargo.toml"]
      min_match_ratio: 1.2
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("ratio must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

fn temp_dir(prefix: &str) -> std::path::PathBuf {
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
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
```

- [ ] **Step 2: Run parser tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills_self_test self_test_spec -- --nocapture
```

Expected: FAIL with unresolved imports for `load_skill_self_test_spec`, `SkillSelfTestAssertion`, and `SkillSelfTestRunner`.

- [ ] **Step 3: Implement the parser model**

Create `crates/agentenv-core/src/skills/self_test.rs` with these public types and functions:

```rust
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use sha2::{Digest, Sha256};

use super::{manifest::normalize_bundle_path, SkillError};

const SKILL_TEST_FILE: &str = "skill-test.yaml";
const SKILL_MD_FILE: &str = "SKILL.md";
const SKILL_YAML_FILE: &str = "skill.yaml";
const DEFAULT_TIMEOUT_SECONDS: u64 = 120;
const LEGACY_TIMEOUT_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkillSelfTestRunner {
    Agentenv,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillSelfTestSpec {
    pub runner: SkillSelfTestRunner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blueprint: Option<PathBuf>,
    pub assertions: Vec<SkillSelfTestAssertion>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SkillSelfTestAssertion {
    CommandExitsZero { cmd: String },
    FileExists { path: PathBuf },
    AgentProduces {
        prompt: String,
        expect_tokens_matching: Vec<String>,
        min_match_ratio: f64,
    },
}

#[derive(Debug, Deserialize)]
struct SelfTestDocument {
    self_test: RawSelfTestSpec,
}

#[derive(Debug, Deserialize)]
struct RawSelfTestSpec {
    runner: Option<String>,
    blueprint: Option<String>,
    assertions: Option<Vec<SkillSelfTestAssertion>>,
    timeout_seconds: Option<u64>,
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSkillYaml {
    self_test: Option<RawSelfTestSpec>,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

pub fn load_skill_self_test_spec(root: impl AsRef<Path>) -> Result<SkillSelfTestSpec, SkillError> {
    let root = root.as_ref();
    let mut specs = Vec::new();

    if let Some(spec) = load_from_skill_test_yaml(root)? {
        specs.push(("skill-test.yaml", spec));
    }
    if let Some(spec) = load_from_skill_md_frontmatter(root)? {
        specs.push(("SKILL.md", spec));
    }
    if let Some(spec) = load_from_skill_yaml(root)? {
        specs.push(("skill.yaml", spec));
    }

    let Some((_, first)) = specs.first().cloned() else {
        return Err(SkillError::MissingSelfTest);
    };
    for (source, spec) in specs.iter().skip(1) {
        if normalized_self_test_digest(&first)? != normalized_self_test_digest(spec)? {
            return Err(SkillError::ConflictingSelfTestDeclarations {
                source: (*source).to_owned(),
            });
        }
    }
    Ok(first)
}

pub fn normalized_self_test_digest(spec: &SkillSelfTestSpec) -> Result<String, SkillError> {
    let bytes = serde_json::to_vec(spec).map_err(|source| SkillError::InvalidSelfTest {
        message: format!("failed to serialize normalized self-test: {source}"),
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}
```

Then implement the private helpers in the same file:

```rust
fn load_from_skill_test_yaml(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_TEST_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path).map_err(|source| SkillError::Io {
        path: path.clone(),
        source,
    })?;
    let document: SelfTestDocument =
        serde_yaml::from_str(&content).map_err(|source| SkillError::Yaml { path, source })?;
    normalize_raw_self_test(document.self_test, false).map(Some)
}

fn load_from_skill_yaml(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_YAML_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path).map_err(|source| SkillError::Io {
        path: path.clone(),
        source,
    })?;
    let document: RawSkillYaml =
        serde_yaml::from_str(&content).map_err(|source| SkillError::Yaml { path, source })?;
    document
        .self_test
        .map(|raw| normalize_raw_self_test(raw, true))
        .transpose()
}

fn load_from_skill_md_frontmatter(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_MD_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path).map_err(|source| SkillError::Io {
        path: path.clone(),
        source,
    })?;
    let Some(frontmatter) = yaml_frontmatter(&content) else {
        return Ok(None);
    };
    let document: SelfTestDocument =
        serde_yaml::from_str(frontmatter).map_err(|source| SkillError::Yaml { path, source })?;
    normalize_raw_self_test(document.self_test, false).map(Some)
}

fn yaml_frontmatter(content: &str) -> Option<&str> {
    let rest = content.strip_prefix("---\n")?;
    let end = rest.find("\n---")?;
    Some(&rest[..end])
}

fn normalize_raw_self_test(
    raw: RawSelfTestSpec,
    allow_legacy_command: bool,
) -> Result<SkillSelfTestSpec, SkillError> {
    if let Some(command) = raw.command {
        if !allow_legacy_command {
            return Err(SkillError::InvalidSelfTest {
                message: "self_test.command is only supported in skill.yaml".to_owned(),
            });
        }
        let command = command.trim();
        if command.is_empty() {
            return Err(SkillError::InvalidSelfTest {
                message: "self_test.command must not be empty".to_owned(),
            });
        }
        return Ok(SkillSelfTestSpec {
            runner: SkillSelfTestRunner::Agentenv,
            blueprint: None,
            assertions: vec![SkillSelfTestAssertion::CommandExitsZero {
                cmd: command.to_owned(),
            }],
            timeout_seconds: LEGACY_TIMEOUT_SECONDS,
        });
    }

    let runner = match raw.runner.as_deref() {
        Some("agentenv") => SkillSelfTestRunner::Agentenv,
        Some(other) => {
            return Err(SkillError::InvalidSelfTest {
                message: format!("unsupported self_test.runner `{other}`"),
            })
        }
        None => {
            return Err(SkillError::InvalidSelfTest {
                message: "self_test.runner is required".to_owned(),
            })
        }
    };
    let blueprint = raw
        .blueprint
        .map(|path| normalize_bundle_path(Path::new(&path)))
        .transpose()?;
    let assertions = raw.assertions.ok_or_else(|| SkillError::InvalidSelfTest {
        message: "self_test.assertions is required".to_owned(),
    })?;
    if assertions.is_empty() {
        return Err(SkillError::InvalidSelfTest {
            message: "self_test.assertions must not be empty".to_owned(),
        });
    }

    for assertion in &assertions {
        validate_assertion(assertion)?;
    }
    if assertions
        .iter()
        .any(|assertion| matches!(assertion, SkillSelfTestAssertion::AgentProduces { .. }))
        && blueprint.is_none()
    {
        return Err(SkillError::InvalidSelfTest {
            message: "self_test.blueprint is required for agent_produces".to_owned(),
        });
    }

    Ok(SkillSelfTestSpec {
        runner,
        blueprint,
        assertions,
        timeout_seconds: raw.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS),
    })
}

fn validate_assertion(assertion: &SkillSelfTestAssertion) -> Result<(), SkillError> {
    match assertion {
        SkillSelfTestAssertion::CommandExitsZero { cmd } if cmd.trim().is_empty() => {
            Err(SkillError::InvalidSelfTest {
                message: "command_exits_zero.cmd must not be empty".to_owned(),
            })
        }
        SkillSelfTestAssertion::CommandExitsZero { .. } => Ok(()),
        SkillSelfTestAssertion::FileExists { path } => {
            normalize_bundle_path(path).map(|_| ())
        }
        SkillSelfTestAssertion::AgentProduces {
            prompt,
            expect_tokens_matching,
            min_match_ratio,
        } => {
            if prompt.trim().is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces.prompt must not be empty".to_owned(),
                });
            }
            if expect_tokens_matching.is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces.expect_tokens_matching must not be empty".to_owned(),
                });
            }
            if !(0.0..=1.0).contains(min_match_ratio) {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces.min_match_ratio must be between 0.0 and 1.0"
                        .to_owned(),
                });
            }
            Ok(())
        }
    }
}
```

- [ ] **Step 4: Export the parser and add errors**

Modify `crates/agentenv-core/src/skills/mod.rs`:

```rust
pub mod self_test;

pub use self_test::{
    load_skill_self_test_spec, normalized_self_test_digest, SkillSelfTestAssertion,
    SkillSelfTestRunner, SkillSelfTestSpec,
};
```

Modify `crates/agentenv-core/src/skills/error.rs`:

```rust
#[error("skill self-test is missing")]
MissingSelfTest,
#[error("invalid skill self-test: {message}")]
InvalidSelfTest { message: String },
#[error("conflicting skill self-test declaration in `{source}`")]
ConflictingSelfTestDeclarations { source: String },
```

- [ ] **Step 5: Run parser tests and commit**

Run:

```bash
cargo test -p agentenv-core --test skills_self_test self_test_spec -- --nocapture
```

Expected: PASS for the five parser tests.

Commit:

```bash
git add crates/agentenv-core/src/skills/self_test.rs crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/tests/skills_self_test.rs
git commit -m "feat: parse structured skill self-tests"
```

## Task 2: Assertion Runner And Score Calculation

**Files:**
- Modify: `crates/agentenv-core/src/skills/self_test.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Test: `crates/agentenv-core/tests/skills_self_test.rs`

- [ ] **Step 1: Write failing runner tests**

Append to `crates/agentenv-core/tests/skills_self_test.rs`:

```rust
use agentenv_core::skills::{
    run_skill_self_test, AgentProduceRequest, AgentProduceRunner, SkillAssertionStatus,
    SkillSelfTestOptions,
};

#[derive(Default)]
struct FakeAgentRunner {
    output: String,
}

impl AgentProduceRunner for FakeAgentRunner {
    fn run_agent_prompt(
        &self,
        _request: AgentProduceRequest<'_>,
    ) -> Result<String, SkillError> {
        Ok(self.output.clone())
    }
}

#[test]
fn self_test_runner_scores_file_and_command_assertions() {
    let root = temp_dir("self-test-runner-score");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: score-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
    - type: command_exits_zero
      cmd: "test -f missing.txt"
"#,
    );
    let manifest = agentenv_core::skills::load_skill_manifest(&root).unwrap();
    let digest = agentenv_core::skills::compute_bundle_digest(&root, &manifest).unwrap();
    let spec = load_skill_self_test_spec(&root).unwrap();

    let report = run_skill_self_test(
        &root,
        &manifest.name,
        &manifest.version.to_string(),
        &digest,
        &spec,
        SkillSelfTestOptions::default(),
        &FakeAgentRunner::default(),
    )
    .expect("self-test should produce a report");

    assert_eq!(report.passed, 1);
    assert_eq!(report.total, 2);
    assert_eq!(report.score, 0.5);
    assert!(!report.publishable);
}

#[test]
fn self_test_runner_accepts_score_at_threshold() {
    let root = temp_dir("self-test-runner-threshold");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("present.txt"), "ok\n");
    write_file(
        &root.join("skill.yaml"),
        "name: threshold-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - present.txt\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
    - type: file_exists
      path: present.txt
    - type: command_exits_zero
      cmd: "test -f SKILL.md"
    - type: command_exits_zero
      cmd: "test -f present.txt"
    - type: command_exits_zero
      cmd: "test -f missing.txt"
"#,
    );
    let manifest = agentenv_core::skills::load_skill_manifest(&root).unwrap();
    let digest = agentenv_core::skills::compute_bundle_digest(&root, &manifest).unwrap();
    let spec = load_skill_self_test_spec(&root).unwrap();

    let report = run_skill_self_test(
        &root,
        &manifest.name,
        &manifest.version.to_string(),
        &digest,
        &spec,
        SkillSelfTestOptions::default(),
        &FakeAgentRunner::default(),
    )
    .unwrap();

    assert_eq!(report.score, 0.8);
    assert!(report.publishable);
}

#[test]
fn self_test_runner_scores_agent_produces_tokens() {
    let root = temp_dir("self-test-runner-agent");
    fs::create_dir_all(root.join("test")).unwrap();
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("test/minimal.yaml"), "version: 0.1.0\n");
    write_file(
        &root.join("skill.yaml"),
        "name: agent-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - test/minimal.yaml\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  blueprint: test/minimal.yaml
  assertions:
    - type: agent_produces
      prompt: "summarize"
      expect_tokens_matching: ["Cargo.toml", "src/"]
      min_match_ratio: 0.5
"#,
    );
    let manifest = agentenv_core::skills::load_skill_manifest(&root).unwrap();
    let digest = agentenv_core::skills::compute_bundle_digest(&root, &manifest).unwrap();
    let spec = load_skill_self_test_spec(&root).unwrap();

    let report = run_skill_self_test(
        &root,
        &manifest.name,
        &manifest.version.to_string(),
        &digest,
        &spec,
        SkillSelfTestOptions::default(),
        &FakeAgentRunner {
            output: "Cargo.toml is present".to_owned(),
        },
    )
    .unwrap();

    assert_eq!(report.assertions[0].status, SkillAssertionStatus::Passed);
    assert_eq!(report.score, 1.0);
}
```

- [ ] **Step 2: Run runner tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills_self_test self_test_runner -- --nocapture
```

Expected: FAIL with unresolved imports for runner/report types.

- [ ] **Step 3: Implement report types and runner API**

Add to `crates/agentenv-core/src/skills/self_test.rs`:

```rust
use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

use time::OffsetDateTime;

pub const SELF_TEST_PUBLISH_THRESHOLD: f64 = 0.8;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillSelfTestReport {
    pub name: String,
    pub version: String,
    pub digest: String,
    pub self_test_digest: String,
    pub score: f64,
    pub passed: usize,
    pub total: usize,
    pub publishable: bool,
    pub assertions: Vec<SkillAssertionResult>,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillAssertionResult {
    #[serde(rename = "type")]
    pub assertion_type: String,
    pub status: SkillAssertionStatus,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAssertionStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy)]
pub struct SkillSelfTestOptions {
    pub threshold: f64,
}

impl Default for SkillSelfTestOptions {
    fn default() -> Self {
        Self {
            threshold: SELF_TEST_PUBLISH_THRESHOLD,
        }
    }
}

pub struct AgentProduceRequest<'a> {
    pub skill_root: &'a Path,
    pub blueprint: &'a Path,
    pub prompt: &'a str,
    pub timeout: Duration,
}

pub trait AgentProduceRunner: Send + Sync {
    fn run_agent_prompt(&self, request: AgentProduceRequest<'_>) -> Result<String, SkillError>;
}

#[derive(Debug, Default)]
pub struct UnsupportedAgentProduceRunner;

impl AgentProduceRunner for UnsupportedAgentProduceRunner {
    fn run_agent_prompt(&self, _request: AgentProduceRequest<'_>) -> Result<String, SkillError> {
        Err(SkillError::UnsupportedAgentProduces)
    }
}
```

Add the runner function:

```rust
pub fn run_skill_self_test(
    skill_root: &Path,
    name: &str,
    version: &str,
    digest: &str,
    spec: &SkillSelfTestSpec,
    options: SkillSelfTestOptions,
    agent_runner: &dyn AgentProduceRunner,
) -> Result<SkillSelfTestReport, SkillError> {
    let started_at = OffsetDateTime::now_utc();
    let self_test_digest = normalized_self_test_digest(spec)?;
    let deadline = Instant::now() + Duration::from_secs(spec.timeout_seconds);
    let mut results = Vec::new();

    for assertion in &spec.assertions {
        if Instant::now() >= deadline {
            results.push(SkillAssertionResult {
                assertion_type: assertion.kind().to_owned(),
                status: SkillAssertionStatus::Skipped,
                message: "self-test deadline reached".to_owned(),
            });
            continue;
        }
        results.push(run_assertion(skill_root, spec, assertion, deadline, agent_runner));
    }

    let total = results.len();
    let passed = results
        .iter()
        .filter(|result| result.status == SkillAssertionStatus::Passed)
        .count();
    let score = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    Ok(SkillSelfTestReport {
        name: name.to_owned(),
        version: version.to_owned(),
        digest: digest.to_owned(),
        self_test_digest,
        score,
        passed,
        total,
        publishable: score >= options.threshold,
        assertions: results,
        started_at,
        completed_at: OffsetDateTime::now_utc(),
    })
}
```

Implement `run_assertion`, `run_command_assertion`, and `run_agent_produces_assertion` in the same module. Use `shell_command` from the existing `store.rs` pattern, `current_dir(skill_root)`, `stdout(Stdio::null())`, `stderr(Stdio::null())`, `try_wait`, and 25ms polling. `file_exists` must call `normalize_bundle_path(path)` and then check `skill_root.join(path).is_file()`. `agent_produces` must call `agent_runner.run_agent_prompt` with the normalized blueprint path, count expected token matches, and pass only when `matched / expected >= min_match_ratio`.

- [ ] **Step 4: Add remaining error variants and helper method**

Modify `crates/agentenv-core/src/skills/error.rs`:

```rust
#[error("skill self-test timed out after {timeout_seconds}s")]
SelfTestTimeout { timeout_seconds: u64 },
#[error("skill self-test score {score:.3} is below required threshold {threshold:.3}")]
SelfTestScoreBelowThreshold { score: f64, threshold: f64 },
#[error("agent_produces self-test assertions are unavailable in this execution context")]
UnsupportedAgentProduces,
```

Add to `SkillSelfTestAssertion`:

```rust
impl SkillSelfTestAssertion {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CommandExitsZero { .. } => "command_exits_zero",
            Self::FileExists { .. } => "file_exists",
            Self::AgentProduces { .. } => "agent_produces",
        }
    }
}
```

Modify `crates/agentenv-core/src/skills/mod.rs` to export the runner/report types introduced in this task:

```rust
pub use self_test::{
    AgentProduceRequest, AgentProduceRunner, SkillAssertionResult, SkillAssertionStatus,
    SkillSelfTestOptions, SkillSelfTestReport, UnsupportedAgentProduceRunner,
    SELF_TEST_PUBLISH_THRESHOLD,
};
```

- [ ] **Step 5: Run runner tests and commit**

Run:

```bash
cargo test -p agentenv-core --test skills_self_test self_test_runner -- --nocapture
```

Expected: PASS for parser and runner tests.

Commit:

```bash
git add crates/agentenv-core/src/skills/self_test.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/tests/skills_self_test.rs
git commit -m "feat: run skill self-test assertions"
```

## Task 3: Signed Self-Test Attestations

**Files:**
- Create: `crates/agentenv-core/src/skills/attestation.rs`
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Modify: `crates/agentenv-core/Cargo.toml`
- Test: `crates/agentenv-core/tests/skills_self_test.rs`

- [ ] **Step 1: Write failing attestation tests**

Append to `crates/agentenv-core/tests/skills_self_test.rs`:

```rust
use agentenv_core::skills::{
    sign_skill_self_test_attestation, validate_skill_publish_attestation,
    SkillAttestationValidationOptions, SkillSelfTestSigningKey,
};
use time::{Duration as TimeDuration, OffsetDateTime};

#[test]
fn self_test_attestation_signs_and_validates_report() {
    let key = SkillSelfTestSigningKey::from_secret_bytes([3_u8; 32]);
    let report = passing_report("attested-demo", "0.1.0");

    let attestation =
        sign_skill_self_test_attestation(&report, &key).expect("attestation should sign");

    validate_skill_publish_attestation(
        "attested-demo",
        "0.1.0",
        &report.digest,
        &report.self_test_digest,
        &attestation,
        SkillAttestationValidationOptions {
            trusted_public_keys: vec![key.public_key_hex()],
            now: report.completed_at + TimeDuration::minutes(5),
            max_age_seconds: 86_400,
            threshold: 0.8,
        },
    )
    .expect("matching attestation should validate");
}

#[test]
fn self_test_attestation_rejects_low_score() {
    let key = SkillSelfTestSigningKey::from_secret_bytes([4_u8; 32]);
    let mut report = passing_report("low-score-demo", "0.1.0");
    report.score = 0.799;
    report.publishable = false;
    let attestation = sign_skill_self_test_attestation(&report, &key).unwrap();

    let error = validate_skill_publish_attestation(
        "low-score-demo",
        "0.1.0",
        &report.digest,
        &report.self_test_digest,
        &attestation,
        SkillAttestationValidationOptions {
            trusted_public_keys: vec![key.public_key_hex()],
            now: report.completed_at,
            max_age_seconds: 86_400,
            threshold: 0.8,
        },
    )
    .expect_err("low score must fail");

    assert!(matches!(error, SkillError::SelfTestScoreBelowThreshold { .. }));
}

#[test]
fn self_test_attestation_rejects_stale_report() {
    let key = SkillSelfTestSigningKey::from_secret_bytes([5_u8; 32]);
    let report = passing_report("stale-demo", "0.1.0");
    let attestation = sign_skill_self_test_attestation(&report, &key).unwrap();

    let error = validate_skill_publish_attestation(
        "stale-demo",
        "0.1.0",
        &report.digest,
        &report.self_test_digest,
        &attestation,
        SkillAttestationValidationOptions {
            trusted_public_keys: vec![key.public_key_hex()],
            now: report.completed_at + TimeDuration::days(2),
            max_age_seconds: 86_400,
            threshold: 0.8,
        },
    )
    .expect_err("stale attestation must fail");

    assert!(matches!(error, SkillError::StaleSelfTestAttestation { .. }));
}

fn passing_report(name: &str, version: &str) -> agentenv_core::skills::SkillSelfTestReport {
    let now = OffsetDateTime::now_utc();
    agentenv_core::skills::SkillSelfTestReport {
        name: name.to_owned(),
        version: version.to_owned(),
        digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        self_test_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        score: 1.0,
        passed: 1,
        total: 1,
        publishable: true,
        assertions: vec![agentenv_core::skills::SkillAssertionResult {
            assertion_type: "file_exists".to_owned(),
            status: agentenv_core::skills::SkillAssertionStatus::Passed,
            message: "ok".to_owned(),
        }],
        started_at: now,
        completed_at: now,
    }
}
```

- [ ] **Step 2: Run attestation tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills_self_test self_test_attestation -- --nocapture
```

Expected: FAIL with unresolved attestation imports.

- [ ] **Step 3: Implement attestation model and signing**

Create `crates/agentenv-core/src/skills/attestation.rs`:

```rust
use std::{fs, io::Write, path::{Path, PathBuf}};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::{SkillAssertionResult, SkillError, SkillSelfTestReport};

const ATTESTATION_SCHEMA_VERSION: &str = "0.1";
const PREDICATE_TYPE: &str = "https://agentenv.dev/attestations/skill-self-test/v1";
const SIGNATURE_PAYLOAD_HEADER: &[u8] = b"agentenv-skill-self-test-attestation-v1\n";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillSelfTestAttestation {
    pub schema_version: String,
    pub predicate_type: String,
    pub subject: SkillSelfTestSubject,
    pub self_test_digest: String,
    pub runner: String,
    pub score: f64,
    pub publishable: bool,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
    pub assertions: Vec<SkillAssertionResult>,
    pub signature: SkillSelfTestAttestationSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillSelfTestSubject {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillSelfTestAttestationSignature {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_ed25519: String,
    pub value: String,
}

pub struct SkillSelfTestSigningKey {
    signing_key: SigningKey,
}
```

Implement:

```rust
impl SkillSelfTestSigningKey {
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn load_or_create(path: &Path) -> Result<Self, SkillError> {
        if path.exists() {
            #[cfg(unix)]
            ensure_unix_key_file_hygiene(path)?;
            let bytes = fs::read(path).map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                SkillError::InvalidSelfTestSigningKey {
                    path: path.to_path_buf(),
                }
            })?;
            return Ok(Self::from_secret_bytes(secret));
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| SkillError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let mut secret = [0_u8; 32];
        OsRng.fill_bytes(&mut secret);
        write_new_signing_key(path, &secret)?;
        Ok(Self::from_secret_bytes(secret))
    }
}

pub fn sign_skill_self_test_attestation(
    report: &SkillSelfTestReport,
    key: &SkillSelfTestSigningKey,
) -> Result<SkillSelfTestAttestation, SkillError> {
    let mut attestation = SkillSelfTestAttestation {
        schema_version: ATTESTATION_SCHEMA_VERSION.to_owned(),
        predicate_type: PREDICATE_TYPE.to_owned(),
        subject: SkillSelfTestSubject {
            name: report.name.clone(),
            version: report.version.clone(),
            digest: report.digest.clone(),
        },
        self_test_digest: report.self_test_digest.clone(),
        runner: "agentenv".to_owned(),
        score: report.score,
        publishable: report.publishable,
        started_at: report.started_at,
        completed_at: report.completed_at,
        assertions: report.assertions.clone(),
        signature: SkillSelfTestAttestationSignature {
            key_id: "local-agentenv".to_owned(),
            algorithm: "ed25519".to_owned(),
            public_key_ed25519: key.public_key_hex(),
            value: String::new(),
        },
    };
    let payload = attestation_payload(&attestation)?;
    attestation.signature.value = hex::encode(key.signing_key.sign(&payload).to_bytes());
    Ok(attestation)
}
```

- [ ] **Step 4: Implement validation and key file helpers**

Add `SkillAttestationValidationOptions` and validation:

```rust
pub struct SkillAttestationValidationOptions {
    pub trusted_public_keys: Vec<String>,
    pub now: OffsetDateTime,
    pub max_age_seconds: u64,
    pub threshold: f64,
}

pub fn validate_skill_publish_attestation(
    name: &str,
    version: &str,
    digest: &str,
    self_test_digest: &str,
    attestation: &SkillSelfTestAttestation,
    options: SkillAttestationValidationOptions,
) -> Result<(), SkillError> {
    if attestation.schema_version != ATTESTATION_SCHEMA_VERSION
        || attestation.predicate_type != PREDICATE_TYPE
    {
        return Err(SkillError::InvalidSelfTestAttestation {
            message: "unsupported self-test attestation schema".to_owned(),
        });
    }
    if attestation.subject.name != name
        || attestation.subject.version != version
        || attestation.subject.digest != digest
    {
        return Err(SkillError::SelfTestAttestationSubjectMismatch);
    }
    if attestation.self_test_digest != self_test_digest {
        return Err(SkillError::SelfTestAttestationDigestMismatch);
    }
    if attestation.score < options.threshold || !attestation.publishable {
        return Err(SkillError::SelfTestScoreBelowThreshold {
            score: attestation.score,
            threshold: options.threshold,
        });
    }
    let age = options.now - attestation.completed_at;
    if age.is_negative() || age.whole_seconds() as u64 > options.max_age_seconds {
        return Err(SkillError::StaleSelfTestAttestation {
            completed_at: attestation.completed_at.to_string(),
        });
    }
    verify_attestation_signature(attestation, &options.trusted_public_keys)
}
```

Add Unix key hygiene helpers by copying the focused shape from `crates/agentenv-core/src/snapshot.rs`: reject symlink/non-file keys, require no group/world permissions, create new key files with mode `0600`, and write 32 raw secret bytes.

Modify `crates/agentenv-core/Cargo.toml`:

```toml
rand_core = { workspace = true, features = ["getrandom"] }
```

Modify `crates/agentenv-core/src/skills/error.rs`:

```rust
#[error("invalid self-test signing key `{path}`")]
InvalidSelfTestSigningKey { path: PathBuf },
#[error("invalid self-test attestation: {message}")]
InvalidSelfTestAttestation { message: String },
#[error("self-test attestation subject does not match the skill artifact")]
SelfTestAttestationSubjectMismatch,
#[error("self-test attestation digest does not match the skill self-test")]
SelfTestAttestationDigestMismatch,
#[error("self-test attestation is stale; completed_at={completed_at}")]
StaleSelfTestAttestation { completed_at: String },
```

- [ ] **Step 5: Export, run tests, and commit**

Modify `crates/agentenv-core/src/skills/mod.rs`:

```rust
pub mod attestation;

pub use attestation::{
    sign_skill_self_test_attestation, validate_skill_publish_attestation,
    SkillAttestationValidationOptions, SkillSelfTestAttestation, SkillSelfTestSigningKey,
};
```

Run:

```bash
cargo test -p agentenv-core --test skills_self_test self_test_attestation -- --nocapture
```

Expected: PASS for attestation signing, low-score rejection, and stale rejection.

Commit:

```bash
git add crates/agentenv-core/Cargo.toml crates/agentenv-core/src/skills/attestation.rs crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/tests/skills_self_test.rs
git commit -m "feat: sign skill self-test attestations"
```

## Task 4: Gate Local Install And Verify

**Files:**
- Modify: `crates/agentenv-core/src/skills/store.rs`
- Modify: `crates/agentenv-core/src/skills/service.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing local gate tests**

Append to `crates/agentenv-core/tests/skills.rs`:

```rust
#[test]
fn local_install_rejects_missing_self_test() {
    let home = temp_dir("skill-install-missing-self-test-home");
    let bundle = skill_bundle("no-self-test", "0.1.0", "No self-test");

    let error = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
        },
    )
    .expect_err("install must reject missing self-test");

    assert!(matches!(error, SkillError::MissingSelfTest));
    assert!(!home.join(".agentenv/skills/no-self-test/0.1.0").exists());
}

#[test]
fn local_install_accepts_passing_self_test_and_records_score() {
    let home = temp_dir("skill-install-passing-self-test-home");
    let bundle = temp_dir("skill-install-passing-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: passing-self-test\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );

    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
        },
    )
    .expect("passing self-test should install");

    assert_eq!(installed.self_test_score, Some(1.0));
    assert!(installed.self_test_attestation.is_some());
}
```

- [ ] **Step 2: Run local gate tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills local_install_ -- --nocapture
```

Expected: FAIL because existing install accepts missing self-tests and `InstalledSkill` has no self-test fields.

- [ ] **Step 3: Extend installed record and install options**

Modify `crates/agentenv-core/src/skills/store.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct InstalledSkill {
    pub name: String,
    pub version: String,
    pub source_type: String,
    pub source_label: String,
    pub digest: String,
    pub signature_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_public_key_ed25519: Option<String>,
    pub entry: PathBuf,
    pub installed_at: String,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_test_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_test_attestation: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SkillInstallOptions {
    pub allow_unsigned: bool,
    pub source_type: String,
    pub source_label: String,
    pub unsafe_skip_self_test_gate: bool,
}
```

Update all existing `SkillInstallOptions` constructors in tests and service code with `unsafe_skip_self_test_gate: false`, except fixture helper paths that explicitly need to publish or install broken bundles.

- [ ] **Step 4: Run self-test before final install directory replace**

In `install_local_skill`, after computing `digest` and before creating `InstalledSkill`, load and run the self-test unless `unsafe_skip_self_test_gate` is true:

```rust
let self_test_result = if options.unsafe_skip_self_test_gate {
    None
} else {
    let spec = super::load_skill_self_test_spec(bundle)?;
    let report = super::run_skill_self_test(
        bundle,
        &manifest.name,
        &manifest.version.to_string(),
        &digest,
        &spec,
        super::SkillSelfTestOptions::default(),
        &super::UnsupportedAgentProduceRunner,
    )?;
    if !report.publishable {
        return Err(SkillError::SelfTestScoreBelowThreshold {
            score: report.score,
            threshold: super::SELF_TEST_PUBLISH_THRESHOLD,
        });
    }
    let key_path = super::self_test_signing_key_path(root);
    let key = super::SkillSelfTestSigningKey::load_or_create(&key_path)?;
    let attestation = super::sign_skill_self_test_attestation(&report, &key)?;
    let attestation_path = super::write_self_test_attestation(root, &attestation)?;
    Some((report.score, attestation_path))
};
```

When constructing `InstalledSkill`, set:

```rust
self_test_score: self_test_result.as_ref().map(|(score, _)| *score),
self_test_attestation: self_test_result.map(|(_, path)| path),
```

Remove the old `manifest.self_test_command` execution from `verify_installed_skill` and replace it with structured self-test execution only when a declaration exists. `verify_installed_skill` should update the installed record with the new score and attestation when a run succeeds.

- [ ] **Step 5: Run local gate tests and commit**

Run:

```bash
cargo test -p agentenv-core --test skills local_install_ -- --nocapture
```

Expected: PASS for missing-self-test rejection and passing-self-test install.

Commit:

```bash
git add crates/agentenv-core/src/skills/store.rs crates/agentenv-core/src/skills/service.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/tests/skills.rs
git commit -m "feat: gate local skill installs on self-tests"
```

## Task 5: CLI Runtime For `agent_produces`

**Files:**
- Modify: `crates/agentenv-core/src/skills/self_test.rs`
- Modify: `crates/agentenv-core/src/runtime.rs`
- Modify: `crates/agentenv/src/skills_cli.rs`
- Modify: `crates/agentenv/src/main.rs`
- Test: `crates/agentenv-core/tests/skills_self_test.rs`
- Test: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing runtime-injection tests**

Add a core test in `crates/agentenv-core/tests/skills_self_test.rs` proving `agent_produces` calls the injected runner:

```rust
#[test]
fn agent_produces_uses_injected_runner() {
    let root = temp_dir("agent-produces-injected-runner");
    fs::create_dir_all(root.join("test")).unwrap();
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("test/minimal.yaml"), "version: 0.1.0\n");
    write_file(
        &root.join("skill.yaml"),
        "name: injected-agent\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - test/minimal.yaml\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  blueprint: test/minimal.yaml
  assertions:
    - type: agent_produces
      prompt: "summarize"
      expect_tokens_matching: ["src/"]
      min_match_ratio: 1.0
"#,
    );
    let manifest = agentenv_core::skills::load_skill_manifest(&root).unwrap();
    let digest = agentenv_core::skills::compute_bundle_digest(&root, &manifest).unwrap();
    let spec = load_skill_self_test_spec(&root).unwrap();

    let report = run_skill_self_test(
        &root,
        "injected-agent",
        "0.1.0",
        &digest,
        &spec,
        SkillSelfTestOptions::default(),
        &FakeAgentRunner {
            output: "src/ exists".to_owned(),
        },
    )
    .unwrap();

    assert!(report.publishable);
}
```

- [ ] **Step 2: Run the runtime-injection test**

Run:

```bash
cargo test -p agentenv-core --test skills_self_test agent_produces_uses_injected_runner -- --nocapture
```

Expected: PASS if Task 2 already implemented runner injection. If it fails, fix `AgentProduceRequest` values before continuing.

- [ ] **Step 3: Add runtime helper for real headless prompts**

Add to `crates/agentenv-core/src/runtime.rs`:

```rust
pub async fn run_agent_prompt_once(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    prompt: &str,
) -> RuntimeResult<agentenv_proto::ExecResult> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
    initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
    let cmd = format!("{AGENT_ENTRYPOINT_PATH} {}", shell_quote(prompt));
    set.sandbox
        .exec(agentenv_proto::ExecParams {
            handle,
            cmd,
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .map_err(RuntimeError::Driver)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
```

Add a unit test near existing `enter_env` tests using the tiny sandbox driver to assert the command starts with `/sandbox/.agentenv/bin/agentenv-agent` and contains the quoted prompt.

- [ ] **Step 4: Move CLI credential provider into a reusable module**

Move `CliCredentialProvider`, `CredentialPrompter`, `TerminalCredentialPrompter`, and `credential_store_runtime_error` from `crates/agentenv/src/main.rs` into a new file `crates/agentenv/src/credentials_runtime.rs`. Export it from `main.rs` with:

```rust
mod credentials_runtime;
```

Use:

```rust
use credentials_runtime::{CliCredentialProvider, TerminalCredentialPrompter};
```

Keep the moved code byte-for-byte except for adding `pub(crate)` to the provider and prompter structs.

- [ ] **Step 5: Inject a CLI `AgentProduceRunner`**

In `crates/agentenv/src/skills_cli.rs`, define:

```rust
struct CliAgentProduceRunner {
    root: PathBuf,
    non_interactive: bool,
}

impl AgentProduceRunner for CliAgentProduceRunner {
    fn run_agent_prompt(
        &self,
        request: AgentProduceRequest<'_>,
    ) -> std::result::Result<String, SkillError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|source| {
            SkillError::InvalidSelfTest {
                message: format!("agent_produces requires a Tokio runtime: {source}"),
            }
        })?;
        runtime.block_on(self.run_agent_prompt_async(request))
    }
}
```

Add `run_agent_prompt_async` that:

1. Reads `request.skill_root.join(request.blueprint)`.
2. Uses env name `.skill-test-<pid>-<nanos>`.
3. Builds `RuntimeOptions { root: self.root.clone(), log_level: LogLevel::Info, non_interactive: self.non_interactive }`.
4. Creates the throwaway env through `runtime::create_env`.
5. Runs `runtime::run_agent_prompt_once`.
6. Destroys the env through `runtime::destroy_env` in both success and error paths.
7. Returns bounded `stdout + "\n" + stderr` on status zero; returns `SkillError::InvalidSelfTest` with status on nonzero.

Wire it into `run_skills`:

```rust
let service = SkillService::new(root.clone(), config)
    .with_credential_resolver(Arc::new(resolve_skill_credential))
    .with_agent_produce_runner(Arc::new(CliAgentProduceRunner {
        root: root.clone(),
        non_interactive: true,
    }));
```

- [ ] **Step 6: Run focused runtime tests and commit**

Run:

```bash
cargo test -p agentenv-core runtime::tests::run_agent_prompt_once
cargo test -p agentenv-core --test skills_self_test agent_produces -- --nocapture
```

Expected: PASS for runtime command construction and injected runner behavior.

Commit:

```bash
git add crates/agentenv-core/src/runtime.rs crates/agentenv-core/src/skills/self_test.rs crates/agentenv-core/tests/skills_self_test.rs crates/agentenv/src/main.rs crates/agentenv/src/skills_cli.rs crates/agentenv/src/credentials_runtime.rs
git commit -m "feat: support agent-producing skill self-tests"
```

## Task 6: Gate `SkillService` Add, Install, Verify, And Publish

**Files:**
- Modify: `crates/agentenv-core/src/skills/service.rs`
- Modify: `crates/agentenv-core/src/skills/store.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing service gate tests**

Append to `crates/agentenv-core/tests/skills.rs`:

```rust
#[tokio::test]
async fn service_publish_runs_self_test_and_rejects_low_score() {
    let home = temp_dir("skill-service-publish-low-score-home");
    let registry = temp_dir("skill-service-publish-low-score-registry");
    let service = filesystem_skill_service(&home, &registry);
    let bundle = temp_dir("skill-service-publish-low-score-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: low-score-publish\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: missing.md\n",
    );

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect_err("low-score publish should fail");

    assert!(matches!(error, SkillError::SelfTestScoreBelowThreshold { .. }));
}

#[tokio::test]
async fn service_publish_accepts_passing_self_test() {
    let home = temp_dir("skill-service-publish-passing-home");
    let registry = temp_dir("skill-service-publish-passing-registry");
    let service = filesystem_skill_service(&home, &registry);
    let bundle = temp_dir("skill-service-publish-passing-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: passing-publish\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );

    let hit = service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("passing self-test should publish");

    assert_eq!(hit.name, "passing-publish");
    assert_eq!(hit.self_test_score, Some(1.0));
}
```

- [ ] **Step 2: Run service gate tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test skills service_publish_ -- --nocapture
```

Expected: FAIL because `SkillPublishRequest` lacks self-test fields and publish does not gate.

- [ ] **Step 3: Extend service request and hit types**

Modify `crates/agentenv-core/src/skills/service.rs`:

```rust
pub struct SkillAddRequest {
    pub handle: String,
    pub registry: Option<String>,
    pub allow_unsigned: bool,
    pub self_test_attestation: Option<PathBuf>,
}

pub struct SkillPublishRequest {
    pub bundle_path: PathBuf,
    pub registry: Option<String>,
    pub allow_unsigned: bool,
    pub self_test_attestation: Option<PathBuf>,
    pub no_self_test_run: bool,
}
```

Modify `crates/agentenv-core/src/skills/registry.rs`:

```rust
pub struct SkillSearchHit {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub registry: String,
    pub digest: Option<String>,
    pub signature_ed25519: Option<String>,
    pub public_key_ed25519: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_test_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_test_attestation_digest: Option<String>,
}
```

Update every test construction of `SkillAddRequest`, `SkillPublishRequest`, and `SkillSearchHit` with the new fields.

- [ ] **Step 4: Add service gate helper**

Add to `SkillService`:

```rust
fn verify_or_run_self_test_for_bundle(
    &self,
    bundle_path: &Path,
    allow_supplied_attestation: Option<&Path>,
    no_self_test_run: bool,
) -> Result<SkillSelfTestAttestation, SkillError> {
    let manifest = super::load_skill_manifest(bundle_path)?;
    let digest = compute_bundle_digest(bundle_path, &manifest)?;
    let spec = super::load_skill_self_test_spec(bundle_path)?;
    let self_test_digest = super::normalized_self_test_digest(&spec)?;

    if let Some(path) = allow_supplied_attestation {
        let attestation = super::read_self_test_attestation(path)?;
        super::validate_skill_publish_attestation(
            &manifest.name,
            &manifest.version.to_string(),
            &digest,
            &self_test_digest,
            &attestation,
            self.attestation_validation_options(),
        )?;
        return Ok(attestation);
    }

    if no_self_test_run {
        return Err(SkillError::MissingSelfTestAttestation);
    }

    let report = super::run_skill_self_test(
        bundle_path,
        &manifest.name,
        &manifest.version.to_string(),
        &digest,
        &spec,
        super::SkillSelfTestOptions::default(),
        self.agent_produce_runner.as_ref(),
    )?;
    if !report.publishable {
        return Err(SkillError::SelfTestScoreBelowThreshold {
            score: report.score,
            threshold: super::SELF_TEST_PUBLISH_THRESHOLD,
        });
    }
    let key = super::SkillSelfTestSigningKey::load_or_create(
        &super::self_test_signing_key_path(&self.root),
    )?;
    super::sign_skill_self_test_attestation(&report, &key)
}
```

Add `agent_produce_runner: Arc<dyn AgentProduceRunner>` to `SkillService`, defaulting to `UnsupportedAgentProduceRunner`, and a builder method:

```rust
pub fn with_agent_produce_runner(mut self, runner: Arc<dyn AgentProduceRunner>) -> Self {
    self.agent_produce_runner = runner;
    self
}
```

- [ ] **Step 5: Gate service methods**

Update `add` so fetched skills call the same self-test gate before `install_fetched_skill`. Update `install_from_path` to accept an attestation path and pass the gate result into `install_local_skill`. Update `verify` to run the structured self-test and refresh attestation. Update `publish` to call `verify_or_run_self_test_for_bundle` before `adapter.publish`.

Add `MissingSelfTestAttestation` to `SkillError`:

```rust
#[error("missing signed self-test attestation for skill publish")]
MissingSelfTestAttestation,
```

- [ ] **Step 6: Run service gate tests and commit**

Run:

```bash
cargo test -p agentenv-core --test skills service_publish_ -- --nocapture
```

Expected: PASS for low-score rejection and passing publish.

Commit:

```bash
git add crates/agentenv-core/src/skills/service.rs crates/agentenv-core/src/skills/store.rs crates/agentenv-core/src/skills/registry.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/tests/skills.rs
git commit -m "feat: gate skill service operations on self-tests"
```

## Task 7: Publish Attestations Through Registry Adapters

**Files:**
- Modify: `crates/agentenv-core/src/skills/registry.rs`
- Modify: `crates/agentenv-core/src/skills/registry_filesystem.rs`
- Modify: `crates/agentenv-core/src/skills/registry_http.rs`
- Modify: `crates/agentenv-core/src/skills/registry_oci.rs`
- Modify: `crates/agentenv-core/src/skills/registry_git.rs`
- Test: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing registry persistence tests**

Append to `crates/agentenv-core/tests/skills.rs`:

```rust
#[tokio::test]
async fn filesystem_publish_stores_self_test_attestation() {
    let home = temp_dir("skill-fs-attestation-home");
    let registry = temp_dir("skill-fs-attestation-registry");
    let service = filesystem_skill_service(&home, &registry);
    let bundle = temp_dir("skill-fs-attestation-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: attested-fs\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );

    service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .unwrap();

    assert!(registry
        .join("bundles/attested-fs/0.1.0/self-test-attestation.json")
        .is_file());
}
```

- [ ] **Step 2: Run registry persistence test to verify it fails**

Run:

```bash
cargo test -p agentenv-core --test skills filesystem_publish_stores_self_test_attestation -- --nocapture
```

Expected: FAIL because adapters do not receive or store attestations.

- [ ] **Step 3: Change adapter trait signature**

Modify `crates/agentenv-core/src/skills/registry.rs`:

```rust
async fn publish(
    &self,
    bundle_path: &Path,
    allow_unsigned: bool,
    attestation: Option<&SkillSelfTestAttestation>,
) -> Result<SkillSearchHit, SkillError>;
```

Update all adapter implementations and call sites. Git keeps returning `UnsupportedRegistryPublish`.

- [ ] **Step 4: Store filesystem and HTTP attestations**

In `registry_filesystem.rs`, after copying bundle contents into the staging publish directory:

```rust
if let Some(attestation) = attestation {
    write_json_file(
        &staging.join("self-test-attestation.json"),
        attestation,
    )?;
}
```

Add `write_json_file` that serializes pretty JSON and uses the same atomic write pattern as index updates.

In `registry_http.rs`, after uploading declared files:

```rust
if let Some(attestation) = attestation {
    let bytes = serde_json::to_vec_pretty(attestation).map_err(|source| {
        SkillError::InvalidSelfTestAttestation {
            message: format!("failed to serialize attestation: {source}"),
        }
    })?;
    self.put_bytes(self.attestation_url(&manifest.name, &version)?, bytes).await?;
}
```

Add `attestation_url` next to `manifest_url` and `content_url`.

- [ ] **Step 5: Store OCI attestations**

In `registry_oci.rs`, add:

```rust
const AGENTENV_SKILL_SELF_TEST_ATTESTATION: &str =
    "application/vnd.agentenv.skill.self-test-attestation.v1+json";
const OCI_ANNOTATION_SELF_TEST_SCORE: &str = "dev.agentenv.skill.self-test.score";
const OCI_ANNOTATION_SELF_TEST_DIGEST: &str = "dev.agentenv.skill.self-test.digest";
const OCI_ANNOTATION_SELF_TEST_COMPLETED_AT: &str = "dev.agentenv.skill.self-test.completed-at";
```

When `attestation` is present, upload it as a layer and add annotations:

```rust
if let Some(attestation) = attestation {
    let mut descriptor = self
        .upload_blob(
            AGENTENV_SKILL_SELF_TEST_ATTESTATION,
            serde_json::to_vec_pretty(attestation).map_err(|source| {
                SkillError::InvalidSelfTestAttestation {
                    message: format!("failed to serialize attestation: {source}"),
                }
            })?,
        )
        .await?;
    descriptor.annotations.insert(
        OCI_ANNOTATION_SELF_TEST_SCORE.to_owned(),
        attestation.score.to_string(),
    );
    descriptor.annotations.insert(
        OCI_ANNOTATION_SELF_TEST_DIGEST.to_owned(),
        attestation.self_test_digest.clone(),
    );
    descriptor.annotations.insert(
        OCI_ANNOTATION_SELF_TEST_COMPLETED_AT.to_owned(),
        attestation.completed_at.to_string(),
    );
    layers.push(descriptor);
}
```

- [ ] **Step 6: Run registry tests and commit**

Run:

```bash
cargo test -p agentenv-core --test skills filesystem_publish_stores_self_test_attestation -- --nocapture
cargo test -p agentenv-core --test skills http_registry -- --nocapture
cargo test -p agentenv-core --test skills oci_registry -- --nocapture
```

Expected: PASS for filesystem attestation persistence and existing HTTP/OCI registry coverage after test updates.

Commit:

```bash
git add crates/agentenv-core/src/skills/registry.rs crates/agentenv-core/src/skills/registry_filesystem.rs crates/agentenv-core/src/skills/registry_http.rs crates/agentenv-core/src/skills/registry_oci.rs crates/agentenv-core/src/skills/registry_git.rs crates/agentenv-core/tests/skills.rs
git commit -m "feat: publish skill self-test attestations"
```

## Task 8: CLI Flags And JSON Verify-All

**Files:**
- Modify: `crates/agentenv/src/skills_cli.rs`
- Modify: `crates/agentenv-core/src/skills/cache.rs`
- Test: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI tests**

Append to `crates/agentenv/tests/cli_behavior.rs` near existing skills CLI tests:

```rust
#[test]
fn skills_cli_install_rejects_missing_self_test() {
    let temp_dir = make_temp_dir("skills-cli-install-missing-self-test");
    let bundle = temp_dir.join("missing-self-test");
    write_local_skill_bundle(&bundle, "missing-self-test", "0.1.0", "Missing", None);

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("install")
        .arg("--from")
        .arg(&bundle)
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("self-test is missing"),
        "{}",
        output_summary(&output)
    );
}

#[test]
fn skills_cli_publish_auto_runs_passing_self_test() {
    let temp_dir = make_temp_dir("skills-cli-publish-self-test");
    let registry = temp_dir.join("registry");
    fs::create_dir_all(&registry).unwrap();
    fs::write(
        temp_dir.join("agentenv.yaml"),
        format!(
            "version: 0.1.0\nmin_agentenv_version: 0.0.1-alpha0\nsandbox: {{ driver: openshell }}\nagent: {{ driver: codex }}\ncontext: {{ driver: filesystem, mount: . }}\npolicy: {{ tier: balanced, presets: [] }}\nskills:\n  registries:\n    - name: local-dev\n      type: filesystem\n      path: {}\n",
            registry.display()
        ),
    )
    .unwrap();
    let bundle = temp_dir.join("publish-self-test");
    write_local_skill_bundle(
        &bundle,
        "publish-self-test",
        "0.1.0",
        "Publish",
        Some("test -f SKILL.md"),
    );

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&bundle)
        .arg("--registry")
        .arg("local-dev")
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["name"], "publish-self-test");
    assert_eq!(json["self_test_score"], 1.0);
}
```

- [ ] **Step 2: Run CLI tests to verify they fail**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_cli_install_rejects_missing_self_test -- --nocapture
cargo test -p agentenv --test cli_behavior skills_cli_publish_auto_runs_passing_self_test -- --nocapture
```

Expected: FAIL because CLI arguments and service request fields are not wired.

- [ ] **Step 3: Add CLI args**

Modify `crates/agentenv/src/skills_cli.rs`:

```rust
pub struct SkillsAddArgs {
    pub handle: String,
    #[arg(long)]
    pub registry: Option<String>,
    #[arg(long)]
    pub allow_unsigned: bool,
    #[arg(long = "self-test-attestation")]
    pub self_test_attestation: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

pub struct SkillsInstallArgs {
    #[arg(long = "from", value_name = "PATH")]
    pub from: PathBuf,
    #[arg(long)]
    pub allow_unsigned: bool,
    #[arg(long = "self-test-attestation")]
    pub self_test_attestation: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

pub struct SkillsPublishArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub registry: Option<String>,
    #[arg(long)]
    pub allow_unsigned: bool,
    #[arg(long = "self-test-attestation")]
    pub self_test_attestation: Option<PathBuf>,
    #[arg(long = "no-self-test-run")]
    pub no_self_test_run: bool,
    #[arg(long)]
    pub json: bool,
}

pub struct SkillsVerifyArgs {
    pub name: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub all: bool,
    #[arg(long = "require-self-test")]
    pub require_self_test: bool,
    #[arg(long)]
    pub json: bool,
}
```

Pass the new fields into `SkillAddRequest`, `install_from_path`, and `SkillPublishRequest`.

- [ ] **Step 4: Support `verify --all --json`**

In `crates/agentenv-core/src/skills/cache.rs`, derive `Serialize` for `SkillVerifyReport`, `SkillVerifyEntry`, and `SkillVerifyStatus`. Add `require_self_test: bool` to `SkillVerifyOptions`.

When `require_self_test` is true and no self-test declaration exists, add an error:

```rust
errors.push("skill self-test is missing".to_owned());
```

In `crates/agentenv/src/skills_cli.rs`, update `run_verify_all`:

```rust
fn run_verify_all(root: &std::path::Path, json: bool, require_self_test: bool) -> Result<()> {
    let layout = SkillCacheLayout::new(root);
    let trust_keys = load_skill_trust_keys(&layout).context("failed to load skill trust keys")?;
    let report = verify_all_installed_skills(
        &layout,
        SkillVerifyOptions {
            trust_keys,
            require_self_test,
            ..Default::default()
        },
    )
    .context("failed to verify installed skills")?;

    if json {
        print_json(&report)?;
    } else {
        print_verify_all_text(&report);
    }
    if !report.is_ok() {
        bail!("skill verification failed");
    }
    Ok(())
}
```

- [ ] **Step 5: Run CLI tests and commit**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_cli_install_rejects_missing_self_test -- --nocapture
cargo test -p agentenv --test cli_behavior skills_cli_publish_auto_runs_passing_self_test -- --nocapture
```

Expected: PASS for both CLI tests.

Commit:

```bash
git add crates/agentenv/src/skills_cli.rs crates/agentenv-core/src/skills/cache.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: expose skill self-test gate in cli"
```

## Task 9: Full Regression And Documentation Updates

**Files:**
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/superpowers/specs/2026-05-12-m7-7-skill-self-test-gate-design.md`
- Test: workspace

- [ ] **Step 1: Update docs for the finalized behavior**

In `README.md`, add a short `agentenv skills verify` example near the skills CLI section:

```markdown
Skill publish is gated by functional self-tests. A skill can declare `self_test`
in `skill-test.yaml` or `SKILL.md` frontmatter. `agentenv skills verify <name>`
runs the test and writes a signed local attestation; `agentenv skills publish`
refuses artifacts without a recent attestation scoring at least `0.8`.
```

In `docs/ARCHITECTURE.md`, extend "Skills as a core-managed resource" with:

```markdown
Before a skill lands in the local installed set or a registry, core runs the
declared functional self-test and records a signed attestation for the exact
artifact digest. Registry adapters store that attestation with the artifact but
do not decide gate policy.
```

- [ ] **Step 2: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits zero and formats Rust files.

- [ ] **Step 3: Run focused test suites**

Run:

```bash
cargo test -p agentenv-core --test skills_self_test
cargo test -p agentenv-core --test skills
cargo test -p agentenv --test cli_behavior skills_cli
```

Expected: all focused self-test, skill registry, and skills CLI tests pass.

- [ ] **Step 4: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: clippy exits zero with no warnings.

- [ ] **Step 5: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: all workspace tests pass.

- [ ] **Step 6: Commit docs and final fixes**

Commit:

```bash
git add README.md docs/ARCHITECTURE.md docs/superpowers/specs/2026-05-12-m7-7-skill-self-test-gate-design.md Cargo.lock Cargo.toml crates/agentenv-core crates/agentenv
git commit -m "test: verify skill self-test gate"
```

## Self-Review Checklist

- Spec coverage: Tasks 1-2 cover declaration parsing, compatibility, local assertions, `agent_produces`, scoring, and thresholds. Task 3 covers signed attestations, recency, subject matching, and hub validation API. Tasks 4, 6, and 8 cover local install/add/verify/publish gates and CLI flags. Task 7 covers filesystem, HTTP, OCI, and git adapter behavior. Task 9 covers docs and final verification.
- Marker scan: This plan intentionally avoids unresolved markers and names exact files, tests, commands, and commits.
- Type consistency: The same names are used throughout: `SkillSelfTestSpec`, `SkillSelfTestAssertion`, `SkillSelfTestReport`, `SkillSelfTestAttestation`, `SkillSelfTestSigningKey`, `AgentProduceRunner`, `SkillSelfTestOptions`, and `SkillAttestationValidationOptions`.
