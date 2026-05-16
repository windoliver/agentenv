# M7-10 Skill CI Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `agentenv skills ci` and a reusable GitHub Actions workflow that validate skill publish candidates through static lint, deterministic review, semantic dedup, and functional self-test tiers.

**Architecture:** Add a focused `agentenv-core::skills::ci` module that owns report types, tier orchestration, SARIF serialization, static checks, review checks, dedup checks, and self-test tier integration. Keep registry storage and publish gates in the existing `SkillService`; the CLI and workflow call the new reusable validation engine without adding a driver protocol surface. The workflow remains a thin shell around `agentenv skills ci` so policy lives in Rust.

**Tech Stack:** Rust 2021, existing `agentenv-core::skills` APIs, `serde`, `serde_json`, `serde_yaml`, `sha2`, `ed25519-dalek`, `time`, `clap`, GitHub Actions YAML, optional external `gitleaks` process detected at runtime.

---

## File Structure

- Create `crates/agentenv-core/src/skills/ci.rs`: public CI request/report types, tier orchestration, candidate loading, static lint, review, dedup, self-test tier, and SARIF serialization.
- Modify `crates/agentenv-core/src/skills/mod.rs`: export the CI API.
- Modify `crates/agentenv-core/src/skills/error.rs`: add typed CI errors.
- Modify `crates/agentenv-core/src/skills/propose/score.rs`: expose a small reusable similarity helper or move equivalent token scoring into `ci.rs` without changing proposal behavior.
- Create `crates/agentenv-core/tests/skills_ci.rs`: core tier and SARIF tests.
- Modify `crates/agentenv/src/skills_cli.rs`: add the `skills ci` subcommand, JSON output, SARIF file output, registry snapshot loading, fail-fast flag handling, and process exit behavior.
- Modify `crates/agentenv/tests/cli_behavior.rs`: add CLI tests for pass, failure, SARIF, and dedup snapshot.
- Add `.github/workflows/skill-ci.yaml`: reusable skill validation workflow.
- Modify `README.md`: document `agentenv skills ci`.

## Task 1: Core CI Report Model and Fail-Fast Orchestrator

**Files:**
- Create: `crates/agentenv-core/src/skills/ci.rs`
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Test: `crates/agentenv-core/tests/skills_ci.rs`

- [ ] **Step 1: Write failing orchestration tests**

Create `crates/agentenv-core/tests/skills_ci.rs` with these first tests and helpers:

```rust
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use ed25519_dalek::{Signer, SigningKey};

use agentenv_core::skills::{
    compute_bundle_digest, load_skill_manifest, run_skill_ci, signature_payload,
    AgentProduceRequest, AgentProduceRunner, SkillCiRequest, SkillCiStatus, SkillCiTier,
    SkillCiTierStatus, SkillError,
};

#[test]
fn skill_ci_reports_candidate_and_runs_static_tier_first() {
    let bundle = skill_bundle("ci-valid", "0.1.0", "# CI valid\n\nUse this skill safely.\n");

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: true,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    assert_eq!(report.schema_version, "0.1");
    assert_eq!(report.candidate.name, "ci-valid");
    assert_eq!(report.candidate.version, "0.1.0");
    assert!(report.candidate.digest.starts_with("sha256:"));
    assert_eq!(report.tiers[0].tier, SkillCiTier::StaticLint);
    assert_eq!(report.tiers[0].status, SkillCiTierStatus::Passed);
}

#[test]
fn skill_ci_fail_fast_skips_later_tiers_after_static_failure() {
    let bundle = skill_bundle("ci-bad-md", "0.1.0", "# Bad\n\n```rust\nfn main() {}\n");

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: true,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should return report for validation failure");

    assert_eq!(report.status, SkillCiStatus::Failed);
    assert_eq!(report.tiers[0].tier, SkillCiTier::StaticLint);
    assert_eq!(report.tiers[0].status, SkillCiTierStatus::Failed);
    assert!(report.tiers.iter().any(|tier| tier.status == SkillCiTierStatus::Skipped));
}

#[derive(Debug)]
struct PanicAgentRunner;

impl AgentProduceRunner for PanicAgentRunner {
    fn run_agent_prompt(&self, _request: AgentProduceRequest<'_>) -> Result<String, SkillError> {
        panic!("agent runner should not be used by these tests");
    }
}

fn skill_bundle(name: &str, version: &str, skill_md: &str) -> PathBuf {
    let root = temp_dir(&format!("skill-ci-{name}-{version}"));
    write_file(&root.join("SKILL.md"), skill_md);
    write_file(
        &root.join("skill.yaml"),
        &format!(
            "name: {name}\nversion: {version}\ndescription: {name} skill\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n"
        ),
    );
    sign_skill_bundle(&root);
    root
}

fn sign_skill_bundle(root: &Path) {
    let manifest = load_skill_manifest(root).unwrap();
    let digest = compute_bundle_digest(root, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[36_u8; 32]);
    let payload = signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let mut manifest_text = fs::read_to_string(root.join("skill.yaml")).unwrap();
    manifest_text.push_str(&format!(
        "signatures:\n  ed25519: {signature}\n  public_key_ed25519: {public_key}\n"
    ));
    fs::write(root.join("skill.yaml"), manifest_text).unwrap();
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
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills_ci skill_ci_reports_candidate_and_runs_static_tier_first -- --nocapture
```

Expected: FAIL with unresolved imports for `run_skill_ci`, `SkillCiRequest`, `SkillCiStatus`, `SkillCiTier`, or `SkillCiTierStatus`.

- [ ] **Step 3: Add CI model and basic orchestration**

Create `crates/agentenv-core/src/skills/ci.rs` with the public surface below. The first implementation may make static lint check only candidate loading and Markdown fences; Task 2 expands static lint.

```rust
use std::{path::PathBuf, sync::Arc, time::Instant};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    compute_bundle_digest, load_skill_manifest, load_skill_self_test_spec, AgentProduceRunner,
    SkillError,
};

pub const SKILL_CI_SCHEMA_VERSION: &str = "0.1";

#[derive(Debug, Clone)]
pub struct SkillCiRequest {
    pub candidate_path: PathBuf,
    pub registry_snapshot: Option<SkillCiRegistrySnapshot>,
    pub fail_fast: bool,
    pub agent_runner: Arc<dyn AgentProduceRunner>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SkillCiRegistrySnapshot {
    #[serde(default)]
    pub skills: Vec<SkillCiRegistrySkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillCiRegistrySkill {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub procedure_text: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillCiReport {
    pub schema_version: &'static str,
    pub candidate: SkillCiCandidate,
    pub status: SkillCiStatus,
    pub tiers: Vec<SkillCiTierReport>,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillCiCandidate {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiTier {
    StaticLint,
    AgentReview,
    SemanticDedup,
    FunctionalRegression,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiTierStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillCiTierReport {
    pub tier: SkillCiTier,
    pub status: SkillCiTierStatus,
    pub duration_ms: u128,
    pub findings: Vec<SkillCiFinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillCiFinding {
    pub rule_id: String,
    pub severity: SkillCiSeverity,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiSeverity {
    Error,
    Warning,
    Note,
}

pub fn run_skill_ci(request: SkillCiRequest) -> Result<SkillCiReport, SkillError> {
    let started_at = OffsetDateTime::now_utc();
    let manifest = load_skill_manifest(&request.candidate_path)?;
    let digest = compute_bundle_digest(&request.candidate_path, &manifest)?;
    let candidate = SkillCiCandidate {
        name: manifest.name.clone(),
        version: manifest.version.to_string(),
        digest,
    };

    let mut tiers = Vec::new();
    let static_report = run_tier(SkillCiTier::StaticLint, || {
        run_static_lint(&request.candidate_path).map(|findings| tier_from_findings(SkillCiTier::StaticLint, findings))
    })?;
    let static_failed = static_report.status == SkillCiTierStatus::Failed;
    tiers.push(static_report);

    for tier in [
        SkillCiTier::AgentReview,
        SkillCiTier::SemanticDedup,
        SkillCiTier::FunctionalRegression,
    ] {
        if request.fail_fast && static_failed {
            tiers.push(skipped_tier(tier, "skipped because static_lint failed"));
        }
    }

    let status = if tiers.iter().any(|tier| tier.status == SkillCiTierStatus::Failed) {
        SkillCiStatus::Failed
    } else if tiers.iter().any(|tier| tier.status == SkillCiTierStatus::Skipped) {
        SkillCiStatus::Skipped
    } else {
        SkillCiStatus::Passed
    };

    let _ = load_skill_self_test_spec(&request.candidate_path);
    Ok(SkillCiReport {
        schema_version: SKILL_CI_SCHEMA_VERSION,
        candidate,
        status,
        tiers,
        started_at,
        completed_at: OffsetDateTime::now_utc(),
    })
}

fn run_tier<F>(tier: SkillCiTier, run: F) -> Result<SkillCiTierReport, SkillError>
where
    F: FnOnce() -> Result<SkillCiTierReport, SkillError>,
{
    let started = Instant::now();
    let mut report = run()?;
    report.tier = tier;
    report.duration_ms = started.elapsed().as_millis();
    Ok(report)
}

fn tier_from_findings(tier: SkillCiTier, findings: Vec<SkillCiFinding>) -> SkillCiTierReport {
    let status = if findings.iter().any(|finding| finding.severity == SkillCiSeverity::Error) {
        SkillCiTierStatus::Failed
    } else {
        SkillCiTierStatus::Passed
    };
    SkillCiTierReport {
        tier,
        status,
        duration_ms: 0,
        findings,
        details: None,
    }
}

fn skipped_tier(tier: SkillCiTier, message: &str) -> SkillCiTierReport {
    SkillCiTierReport {
        tier,
        status: SkillCiTierStatus::Skipped,
        duration_ms: 0,
        findings: vec![SkillCiFinding {
            rule_id: "agentenv.skill.ci.skipped".to_owned(),
            severity: SkillCiSeverity::Note,
            message: message.to_owned(),
            path: None,
            line: None,
        }],
        details: None,
    }
}
```

Add this temporary static-lint helper in the same file. Task 2 replaces it with full lint behavior while keeping the public report shape.

```rust
fn run_static_lint(candidate_path: &std::path::Path) -> Result<Vec<SkillCiFinding>, SkillError> {
    let mut findings = Vec::new();
    let skill_md = candidate_path.join("SKILL.md");
    let content = std::fs::read_to_string(&skill_md).map_err(|source| SkillError::Io {
        path: skill_md.clone(),
        source,
    })?;
    if has_unclosed_fence(&content) {
        findings.push(SkillCiFinding {
            rule_id: "agentenv.skill.markdown.unclosed-fence".to_owned(),
            severity: SkillCiSeverity::Error,
            message: "Markdown fenced code block is not closed".to_owned(),
            path: Some(skill_md),
            line: None,
        });
    }
    Ok(findings)
}

fn has_unclosed_fence(content: &str) -> bool {
    let mut open = false;
    for line in content.lines() {
        if line.trim_start().starts_with("```") {
            open = !open;
        }
    }
    open
}
```

Modify `crates/agentenv-core/src/skills/mod.rs`:

```rust
mod ci;

pub use ci::{
    run_skill_ci, SkillCiCandidate, SkillCiFinding, SkillCiRegistrySkill,
    SkillCiRegistrySnapshot, SkillCiRequest, SkillCiReport, SkillCiSeverity, SkillCiStatus,
    SkillCiTier, SkillCiTierReport, SkillCiTierStatus,
};
```

Modify `crates/agentenv-core/src/skills/error.rs`:

```rust
    #[error("invalid skill CI candidate `{path}`: {message}")]
    InvalidSkillCiCandidate { path: PathBuf, message: String },
    #[error("skill CI validation failed at tier `{tier}`")]
    SkillCiFailed { tier: String },
    #[error("failed to serialize skill CI SARIF: {message}")]
    SkillCiSarif { message: String },
```

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills_ci skill_ci_ -- --nocapture
```

Expected: PASS for the two `skill_ci_` tests in `skills_ci.rs`.

- [ ] **Step 5: Commit Task 1**

```bash
git add crates/agentenv-core/src/skills/ci.rs crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/tests/skills_ci.rs
git commit -m "feat(core): add skill ci report model"
```

## Task 2: Static Lint Tier and SARIF Serializer

**Files:**
- Modify: `crates/agentenv-core/src/skills/ci.rs`
- Test: `crates/agentenv-core/tests/skills_ci.rs`

- [ ] **Step 1: Add failing static lint and SARIF tests**

Append these tests to `crates/agentenv-core/tests/skills_ci.rs`:

```rust
#[test]
fn static_lint_rejects_secret_like_text_and_redacts_sarif() {
    let bundle = skill_bundle(
        "ci-secret",
        "0.1.0",
        "# Secret\n\nUse token sk-test-1234567890abcdefghijklmnop carefully.\n",
    );

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: true,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let static_tier = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::StaticLint)
        .unwrap();
    assert_eq!(static_tier.status, SkillCiTierStatus::Failed);
    assert!(static_tier
        .findings
        .iter()
        .any(|finding| finding.rule_id == "agentenv.skill.secret.detected"));

    let sarif = agentenv_core::skills::skill_ci_sarif(&report).unwrap();
    assert!(sarif.contains("agentenv.skill.secret.detected"));
    assert!(!sarif.contains("sk-test-1234567890abcdefghijklmnop"));
}

#[test]
fn static_lint_rejects_prerelease_versions() {
    let bundle = skill_bundle("ci-prerelease", "1.0.0-alpha.1", "# Prerelease\n");

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: true,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let static_tier = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::StaticLint)
        .unwrap();
    assert_eq!(static_tier.status, SkillCiTierStatus::Failed);
    assert!(static_tier
        .findings
        .iter()
        .any(|finding| finding.rule_id == "agentenv.skill.version.prerelease"));
}

#[test]
fn static_lint_rejects_unclosed_frontmatter() {
    let bundle = skill_bundle(
        "ci-frontmatter",
        "0.1.0",
        "---\nname: ci-frontmatter\n# Missing close marker\n",
    );

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: true,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let static_tier = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::StaticLint)
        .unwrap();
    assert_eq!(static_tier.status, SkillCiTierStatus::Failed);
    assert!(static_tier
        .findings
        .iter()
        .any(|finding| finding.rule_id == "agentenv.skill.frontmatter.unclosed"));
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills_ci static_lint_ -- --nocapture
```

Expected: FAIL because `skill_ci_sarif` is not exported and the static lint tier does not yet detect secret-like text, prerelease versions, or unclosed frontmatter.

- [ ] **Step 3: Implement static lint checks**

In `crates/agentenv-core/src/skills/ci.rs`, replace `run_static_lint` with a version that loads the manifest, digest, self-test spec, declared entry content, and bundled text files. Use this helper shape:

```rust
fn run_static_lint(candidate_path: &std::path::Path) -> Result<Vec<SkillCiFinding>, SkillError> {
    let mut findings = Vec::new();
    let manifest = match load_skill_manifest(candidate_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            findings.push(error_finding(
                "agentenv.skill.manifest.invalid",
                error.to_string(),
                Some(candidate_path.join("skill.yaml")),
                None,
            ));
            return Ok(findings);
        }
    };

    if !manifest.version.pre.is_empty() {
        findings.push(error_finding(
            "agentenv.skill.version.prerelease",
            format!("manifest version `{}` is a prerelease", manifest.version),
            Some(candidate_path.join("skill.yaml")),
            None,
        ));
    }

    let digest = compute_bundle_digest(candidate_path, &manifest)?;
    if let Err(error) = super::signature::verify_skill_package_signature(&manifest, &digest, false)
    {
        findings.push(error_finding(
            "agentenv.skill.signature.invalid",
            error.to_string(),
            Some(candidate_path.join("skill.yaml")),
            None,
        ));
    }

    if let Err(error) = load_skill_self_test_spec(candidate_path) {
        findings.push(error_finding(
            "agentenv.skill.self-test.invalid",
            error.to_string(),
            Some(candidate_path.join("skill.yaml")),
            None,
        ));
    }

    let entry_path = candidate_path.join(&manifest.entry);
    let entry_content = std::fs::read_to_string(&entry_path).map_err(|source| SkillError::Io {
        path: entry_path.clone(),
        source,
    })?;
    lint_markdown(&entry_content, &entry_path, &mut findings);

    for declared in &manifest.declared_files {
        let path = candidate_path.join(declared);
        if is_text_path(&path) {
            let content = std::fs::read_to_string(&path).map_err(|source| SkillError::Io {
                path: path.clone(),
                source,
            })?;
            lint_secrets(&content, &path, &mut findings);
        }
    }

    Ok(findings)
}
```

Add these helpers in the same module:

```rust
fn error_finding(
    rule_id: impl Into<String>,
    message: impl Into<String>,
    path: Option<PathBuf>,
    line: Option<usize>,
) -> SkillCiFinding {
    SkillCiFinding {
        rule_id: rule_id.into(),
        severity: SkillCiSeverity::Error,
        message: message.into(),
        path,
        line,
    }
}

fn lint_markdown(content: &str, path: &std::path::Path, findings: &mut Vec<SkillCiFinding>) {
    if content.starts_with("---\n") && !content[4..].contains("\n---") {
        findings.push(error_finding(
            "agentenv.skill.frontmatter.unclosed",
            "SKILL.md frontmatter is missing a closing delimiter",
            Some(path.to_path_buf()),
            Some(1),
        ));
    }

    let mut fence_line = None;
    let mut previous_heading = 0usize;
    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        if line.trim_start().starts_with("```") {
            fence_line = if fence_line.is_some() { None } else { Some(line_number) };
        }
        let heading_level = line.chars().take_while(|character| *character == '#').count();
        if heading_level > 0 && line.chars().nth(heading_level) == Some(' ') {
            if previous_heading > 0 && heading_level > previous_heading + 1 {
                findings.push(error_finding(
                    "agentenv.skill.markdown.heading-jump",
                    format!("heading jumps from level {previous_heading} to {heading_level}"),
                    Some(path.to_path_buf()),
                    Some(line_number),
                ));
            }
            previous_heading = heading_level;
        }
    }

    if let Some(line) = fence_line {
        findings.push(error_finding(
            "agentenv.skill.markdown.unclosed-fence",
            "Markdown fenced code block is not closed",
            Some(path.to_path_buf()),
            Some(line),
        ));
    }
}

fn lint_secrets(content: &str, path: &std::path::Path, findings: &mut Vec<SkillCiFinding>) {
    for (index, line) in content.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        let looks_like_secret = lower.contains("api_key")
            || lower.contains("api-key")
            || lower.contains("secret_key")
            || lower.contains("access_token")
            || lower.contains("private_key")
            || line.contains("sk-");
        if looks_like_secret {
            findings.push(error_finding(
                "agentenv.skill.secret.detected",
                "secret-like content detected in bundled text",
                Some(path.to_path_buf()),
                Some(index + 1),
            ));
        }
    }
}

fn is_text_path(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("md" | "yaml" | "yml" | "txt" | "json" | "toml" | "rs" | "sh")
    )
}
```

- [ ] **Step 4: Add SARIF serialization**

Add `skill_ci_sarif` to `ci.rs`:

```rust
pub fn skill_ci_sarif(report: &SkillCiReport) -> Result<String, SkillError> {
    let mut results = Vec::new();
    for tier in &report.tiers {
        if !matches!(tier.tier, SkillCiTier::StaticLint | SkillCiTier::AgentReview) {
            continue;
        }
        for finding in &tier.findings {
            if finding.severity == SkillCiSeverity::Note {
                continue;
            }
            results.push(sarif_result(finding));
        }
    }
    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agentenv skill ci",
                    "informationUri": "https://github.com/windoliver/agentenv",
                    "rules": sarif_rules(report)
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&sarif)
        .map_err(|source| SkillError::SkillCiSarif { message: source.to_string() })
}

fn sarif_result(finding: &SkillCiFinding) -> serde_json::Value {
    let mut region = serde_json::Map::new();
    if let Some(line) = finding.line {
        region.insert("startLine".to_owned(), serde_json::json!(line));
    }
    let location = match &finding.path {
        Some(path) => serde_json::json!({
            "physicalLocation": {
                "artifactLocation": { "uri": path.to_string_lossy() },
                "region": region
            }
        }),
        None => serde_json::json!({}),
    };
    serde_json::json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": { "text": finding.message },
        "locations": [location]
    })
}

fn sarif_level(severity: SkillCiSeverity) -> &'static str {
    match severity {
        SkillCiSeverity::Error => "error",
        SkillCiSeverity::Warning => "warning",
        SkillCiSeverity::Note => "note",
    }
}

fn sarif_rules(report: &SkillCiReport) -> Vec<serde_json::Value> {
    let mut rules = std::collections::BTreeSet::new();
    for tier in &report.tiers {
        for finding in &tier.findings {
            rules.insert(finding.rule_id.clone());
        }
    }
    rules
        .into_iter()
        .map(|id| serde_json::json!({ "id": id, "shortDescription": { "text": id } }))
        .collect()
}
```

Export `skill_ci_sarif` from `crates/agentenv-core/src/skills/mod.rs`:

```rust
pub use ci::{
    run_skill_ci, skill_ci_sarif, SkillCiCandidate, SkillCiFinding, SkillCiRegistrySkill,
    SkillCiRegistrySnapshot, SkillCiRequest, SkillCiReport, SkillCiSeverity, SkillCiStatus,
    SkillCiTier, SkillCiTierReport, SkillCiTierStatus,
};
```

- [ ] **Step 5: Run tests to verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills_ci static_lint_ -- --nocapture
```

Expected: PASS for all `static_lint_` tests.

- [ ] **Step 6: Commit Task 2**

```bash
git add crates/agentenv-core/src/skills/ci.rs crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/tests/skills_ci.rs
git commit -m "feat(core): add skill ci static lint"
```

## Task 3: Deterministic Agent Review Tier

**Files:**
- Modify: `crates/agentenv-core/src/skills/ci.rs`
- Test: `crates/agentenv-core/tests/skills_ci.rs`

- [ ] **Step 1: Add failing review-tier tests**

Append:

```rust
#[test]
fn agent_review_fails_destructive_instruction_without_consent() {
    let bundle = skill_bundle(
        "ci-destructive",
        "0.1.0",
        "# Destructive\n\nRun `rm -rf target` immediately before asking the user.\n",
    );

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: false,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let review = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::AgentReview)
        .unwrap();
    assert_eq!(review.status, SkillCiTierStatus::Failed);
    assert!(review
        .findings
        .iter()
        .any(|finding| finding.rule_id == "agentenv.skill.review.destructive-without-consent"));
}

#[test]
fn agent_review_passes_clear_bounded_non_destructive_skill() {
    let bundle = skill_bundle(
        "ci-clear",
        "0.1.0",
        "# Clear Skill\n\nUse this skill to inspect Rust files, summarize findings, and ask before changing files.\n",
    );

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: false,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let review = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::AgentReview)
        .unwrap();
    assert_eq!(review.status, SkillCiTierStatus::Passed);
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills_ci agent_review_ -- --nocapture
```

Expected: FAIL because `AgentReview` is still skipped or empty.

- [ ] **Step 3: Add review trait and default judge**

In `ci.rs`, add:

```rust
pub trait SkillReviewJudge: Send + Sync {
    fn review(&self, input: SkillReviewInput<'_>) -> Result<SkillReviewReport, SkillError>;
}

pub struct SkillReviewInput<'a> {
    pub manifest: &'a super::SkillManifest,
    pub skill_md: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillReviewReport {
    pub findings: Vec<SkillCiFinding>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RuleBasedSkillReviewJudge;

impl SkillReviewJudge for RuleBasedSkillReviewJudge {
    fn review(&self, input: SkillReviewInput<'_>) -> Result<SkillReviewReport, SkillError> {
        let mut findings = Vec::new();
        let text = input.skill_md.to_ascii_lowercase();

        if input.manifest.description.as_deref().unwrap_or("").trim().len() < 8 {
            findings.push(warning_finding(
                "agentenv.skill.review.description-vague",
                "description is too short to describe behavior",
                Some(PathBuf::from("skill.yaml")),
                None,
            ));
        }

        let destructive = ["rm -rf", "delete all", "drop database", "format disk"];
        let asks_consent = text.contains("ask before")
            || text.contains("with user consent")
            || text.contains("after confirmation")
            || text.contains("explicit consent");
        if destructive.iter().any(|needle| text.contains(needle)) && !asks_consent {
            findings.push(error_finding(
                "agentenv.skill.review.destructive-without-consent",
                "destructive operation is described without explicit user consent",
                Some(PathBuf::from("SKILL.md")),
                None,
            ));
        }

        if text.contains("api key") && !text.contains("credential") {
            findings.push(error_finding(
                "agentenv.skill.review.credential-handling",
                "credential handling must use agentenv credential language",
                Some(PathBuf::from("SKILL.md")),
                None,
            ));
        }

        Ok(SkillReviewReport { findings })
    }
}

fn warning_finding(
    rule_id: impl Into<String>,
    message: impl Into<String>,
    path: Option<PathBuf>,
    line: Option<usize>,
) -> SkillCiFinding {
    SkillCiFinding {
        rule_id: rule_id.into(),
        severity: SkillCiSeverity::Warning,
        message: message.into(),
        path,
        line,
    }
}
```

Wire the orchestrator after static lint. Load `SKILL.md` once and run `RuleBasedSkillReviewJudge.review(...)`. Convert findings with `tier_from_findings(SkillCiTier::AgentReview, findings)`.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills_ci agent_review_ -- --nocapture
```

Expected: PASS for both `agent_review_` tests.

- [ ] **Step 5: Commit Task 3**

```bash
git add crates/agentenv-core/src/skills/ci.rs crates/agentenv-core/tests/skills_ci.rs
git commit -m "feat(core): add skill ci review tier"
```

## Task 4: Semantic Dedup Tier with Registry Snapshot

**Files:**
- Modify: `crates/agentenv-core/src/skills/ci.rs`
- Test: `crates/agentenv-core/tests/skills_ci.rs`

- [ ] **Step 1: Add failing dedup tests**

Append:

```rust
#[test]
fn semantic_dedup_fails_exact_fingerprint_match() {
    let bundle = skill_bundle("ci-copy", "0.1.0", "# Copy\n\nSummarize Rust modules.\n");
    let digest = {
        let manifest = agentenv_core::skills::load_skill_manifest(&bundle).unwrap();
        agentenv_core::skills::compute_bundle_digest(&bundle, &manifest).unwrap()
    };

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: Some(agentenv_core::skills::SkillCiRegistrySnapshot {
            skills: vec![agentenv_core::skills::SkillCiRegistrySkill {
                name: "existing-copy".to_owned(),
                version: "0.1.0".to_owned(),
                description: "Existing copy".to_owned(),
                procedure_text: "Summarize Rust modules.".to_owned(),
                fingerprint: Some(digest),
            }],
        }),
        fail_fast: false,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let dedup = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::SemanticDedup)
        .unwrap();
    assert_eq!(dedup.status, SkillCiTierStatus::Failed);
    assert!(dedup
        .findings
        .iter()
        .any(|finding| finding.rule_id == "agentenv.skill.dedup.probable-duplicate"));
    assert_eq!(dedup.details.as_ref().unwrap()["novelty_score"], 0.0);
}

#[test]
fn semantic_dedup_reports_high_novelty_without_snapshot() {
    let bundle = skill_bundle("ci-new", "0.1.0", "# New\n\nInspect shell scripts for portability.\n");

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: false,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let dedup = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::SemanticDedup)
        .unwrap();
    assert_eq!(dedup.status, SkillCiTierStatus::Passed);
    assert_eq!(dedup.details.as_ref().unwrap()["novelty_score"], 0.9);
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills_ci semantic_dedup_ -- --nocapture
```

Expected: FAIL because semantic dedup details and duplicate findings are absent.

- [ ] **Step 3: Implement dedup scoring**

Add to `ci.rs`:

```rust
fn run_semantic_dedup(
    manifest: &super::SkillManifest,
    digest: &str,
    skill_md: &str,
    snapshot: Option<&SkillCiRegistrySnapshot>,
) -> SkillCiTierReport {
    let mut best: Option<(SkillCiRegistrySkill, f32, String)> = None;
    let mut novelty = 0.9_f32;

    if let Some(snapshot) = snapshot {
        for existing in &snapshot.skills {
            let similarity = if existing.fingerprint.as_deref() == Some(digest) {
                1.0
            } else {
                jaccard(skill_md, &existing.procedure_text)
                    .max(jaccard(manifest.description.as_deref().unwrap_or(""), &existing.description))
            };
            if best.as_ref().is_none_or(|(_, current, _)| similarity > *current) {
                let reason = if existing.fingerprint.as_deref() == Some(digest) {
                    "exact fingerprint match".to_owned()
                } else {
                    "local semantic similarity".to_owned()
                };
                best = Some((existing.clone(), similarity, reason));
            }
        }
    }

    let mut findings = Vec::new();
    let probable_duplicate = best
        .as_ref()
        .is_some_and(|(_, similarity, _)| *similarity > 0.92);
    if let Some((_, similarity, _)) = &best {
        novelty = if *similarity > 0.92 {
            0.0
        } else if *similarity >= 0.85 {
            0.3
        } else if *similarity >= 0.45 {
            0.6
        } else {
            0.9
        };
    }
    if probable_duplicate {
        findings.push(error_finding(
            "agentenv.skill.dedup.probable-duplicate",
            "candidate is probably a duplicate of an existing skill",
            Some(PathBuf::from("SKILL.md")),
            None,
        ));
    }

    let nearest_neighbors: Vec<serde_json::Value> = best
        .into_iter()
        .map(|(skill, similarity, reason)| {
            serde_json::json!({
                "name": skill.name,
                "version": skill.version,
                "similarity": similarity,
                "reason": reason
            })
        })
        .collect();
    let mut report = tier_from_findings(SkillCiTier::SemanticDedup, findings);
    report.details = Some(serde_json::json!({
        "nearest_neighbors": nearest_neighbors,
        "novelty_score": novelty,
        "probable_duplicate": probable_duplicate
    }));
    report
}

fn jaccard(left: &str, right: &str) -> f32 {
    let left = tokens(left);
    let right = tokens(right);
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let intersection = left.intersection(&right).count() as f32;
    let union = left.union(&right).count() as f32;
    if union == 0.0 { 0.0 } else { intersection / union }
}

fn tokens(value: &str) -> std::collections::BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}
```

Wire `run_semantic_dedup` after the review tier, passing `request.registry_snapshot.as_ref()`.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills_ci semantic_dedup_ -- --nocapture
```

Expected: PASS for both `semantic_dedup_` tests.

- [ ] **Step 5: Commit Task 4**

```bash
git add crates/agentenv-core/src/skills/ci.rs crates/agentenv-core/tests/skills_ci.rs
git commit -m "feat(core): add skill ci dedup tier"
```

## Task 5: Functional Regression Tier

**Files:**
- Modify: `crates/agentenv-core/src/skills/ci.rs`
- Test: `crates/agentenv-core/tests/skills_ci.rs`

- [ ] **Step 1: Add failing functional-regression tests**

Append:

```rust
#[test]
fn functional_regression_fails_below_threshold() {
    let bundle = skill_bundle("ci-low-score", "0.1.0", "# Low Score\n");
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n    - type: file_exists\n      path: missing-one\n    - type: file_exists\n      path: missing-two\n    - type: file_exists\n      path: missing-three\n    - type: file_exists\n      path: missing-four\n",
    );

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: false,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let regression = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::FunctionalRegression)
        .unwrap();
    assert_eq!(regression.status, SkillCiTierStatus::Failed);
    assert!(regression
        .findings
        .iter()
        .any(|finding| finding.rule_id == "agentenv.skill.self-test.score-below-threshold"));
    assert_eq!(regression.details.as_ref().unwrap()["score"], 0.2);
}

#[test]
fn functional_regression_passes_at_threshold() {
    let bundle = skill_bundle("ci-threshold", "0.1.0", "# Threshold\n");
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n    - type: file_exists\n      path: skill.yaml\n    - type: file_exists\n      path: SKILL.md\n    - type: file_exists\n      path: skill.yaml\n    - type: file_exists\n      path: missing-one\n",
    );

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: false,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    let regression = report
        .tiers
        .iter()
        .find(|tier| tier.tier == SkillCiTier::FunctionalRegression)
        .unwrap();
    assert_eq!(regression.status, SkillCiTierStatus::Passed);
    assert_eq!(regression.details.as_ref().unwrap()["score"], 0.8);
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
cargo test -p agentenv-core --test skills_ci functional_regression_ -- --nocapture
```

Expected: FAIL because the functional regression tier is not yet calling `run_skill_self_test`.

- [ ] **Step 3: Implement self-test tier**

In `ci.rs`, add:

```rust
fn run_functional_regression(
    candidate_path: &std::path::Path,
    manifest: &super::SkillManifest,
    digest: &str,
    agent_runner: Arc<dyn AgentProduceRunner>,
) -> Result<SkillCiTierReport, SkillError> {
    let spec = load_skill_self_test_spec(candidate_path)?;
    let report = super::run_skill_self_test(
        candidate_path,
        manifest.name.clone(),
        manifest.version.to_string(),
        digest.to_owned(),
        &spec,
        super::SkillSelfTestOptions::default(),
        agent_runner,
    )?;

    let mut findings = Vec::new();
    if !report.publishable {
        findings.push(error_finding(
            "agentenv.skill.self-test.score-below-threshold",
            format!(
                "self-test score {:.3} is below required threshold {:.3}",
                report.score,
                super::SELF_TEST_PUBLISH_THRESHOLD
            ),
            Some(PathBuf::from("skill-test.yaml")),
            None,
        ));
    }

    let mut tier = tier_from_findings(SkillCiTier::FunctionalRegression, findings);
    tier.details = Some(serde_json::json!({
        "score": report.score,
        "passed": report.passed,
        "total": report.total,
        "publishable": report.publishable,
        "self_test_digest": report.self_test_digest
    }));
    Ok(tier)
}
```

Wire this as the fourth tier. When fail-fast skips this tier after an earlier failure, keep the skipped report instead of running the self-test.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
cargo test -p agentenv-core --test skills_ci functional_regression_ -- --nocapture
```

Expected: PASS for both `functional_regression_` tests.

- [ ] **Step 5: Run all core CI tests**

Run:

```bash
cargo test -p agentenv-core --test skills_ci -- --nocapture
```

Expected: PASS for every test in `skills_ci.rs`.

- [ ] **Step 6: Commit Task 5**

```bash
git add crates/agentenv-core/src/skills/ci.rs crates/agentenv-core/tests/skills_ci.rs
git commit -m "feat(core): add skill ci self-test tier"
```

## Task 6: CLI Command

**Files:**
- Modify: `crates/agentenv/src/skills_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`
- Test: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Add failing CLI tests**

Append these tests near the other skills CLI tests in `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn skills_ci_json_passes_valid_bundle() {
    let temp_dir = make_temp_dir("skills-ci-json-pass");
    let bundle = temp_dir.join("bundle");
    write_local_skill_bundle_with_skill_test_file(&bundle, "ci-cli-pass", "0.1.0", "CI CLI pass");

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema_version"], "0.1");
    assert_eq!(json["candidate"]["name"], "ci-cli-pass");
    assert_eq!(json["status"], "passed");
}

#[test]
fn skills_ci_json_exits_one_for_invalid_bundle() {
    let temp_dir = make_temp_dir("skills-ci-json-fail");
    let bundle = temp_dir.join("bundle");
    write_local_skill_bundle_with_skill_test_file(&bundle, "ci-cli-fail", "0.1.0", "CI CLI fail");
    fs::write(bundle.join("SKILL.md"), "# Bad\n\n```rust\nfn main() {}\n").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "failed");
    assert_eq!(json["tiers"][0]["tier"], "static_lint");
}

#[test]
fn skills_ci_writes_sarif_file() {
    let temp_dir = make_temp_dir("skills-ci-sarif");
    let bundle = temp_dir.join("bundle");
    let sarif = temp_dir.join("skill-ci.sarif");
    write_local_skill_bundle_with_skill_test_file(&bundle, "ci-cli-sarif", "0.1.0", "CI CLI SARIF");
    fs::write(bundle.join("SKILL.md"), "# Bad\n\n```rust\nfn main() {}\n").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--json")
        .arg("--sarif")
        .arg(&sarif)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", output_summary(&output));
    let sarif_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&sarif).unwrap()).unwrap();
    assert_eq!(sarif_json["runs"][0]["tool"]["driver"]["name"], "agentenv skill ci");
}

#[test]
fn skills_ci_registry_snapshot_drives_dedup_failure() {
    let temp_dir = make_temp_dir("skills-ci-dedup");
    let bundle = temp_dir.join("bundle");
    let snapshot = temp_dir.join("snapshot.json");
    write_local_skill_bundle_with_skill_test_file(&bundle, "ci-cli-dedup", "0.1.0", "CI CLI dedup");
    fs::write(
        &snapshot,
        r#"{"skills":[{"name":"existing","version":"0.1.0","description":"CI CLI dedup","procedure_text":"CI CLI dedup","fingerprint":null}]}"#,
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--registry-snapshot")
        .arg(&snapshot)
        .arg("--no-fail-fast")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["tiers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tier| tier["tier"] == "semantic_dedup" && tier["status"] == "failed"));
}
```

- [ ] **Step 2: Run CLI tests to verify RED**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_ci_ -- --nocapture
```

Expected: FAIL because clap does not know the `skills ci` subcommand.

- [ ] **Step 3: Add CLI args and dispatch**

Modify imports in `crates/agentenv/src/skills_cli.rs`:

```rust
use agentenv_core::skills::{
    execute_skill_prune, load_project_skills_config, load_skill_trust_keys,
    load_user_skills_config, merge_skills_config, plan_skill_prune, rebuild_skill_index,
    run_skill_ci, skill_ci_sarif, verify_all_installed_skills, AgentProduceRequest,
    AgentProduceRunner, InstalledSkill, InstalledSkillSelector, SkillAddRequest, SkillCacheLayout,
    SkillCiRegistrySnapshot, SkillCiRequest, SkillCiStatus, SkillError, SkillPublishRequest,
    SkillSearchHit, SkillService, SkillVerifyOptions, SkillVerifyStatus, SkillsConfig,
    SkillsConfigOverride,
};
```

Add the subcommand:

```rust
#[derive(Debug, Subcommand)]
pub enum SkillsCommand {
    Propose(SkillsProposeArgs),
    Search(SkillsSearchArgs),
    Add(SkillsAddArgs),
    Install(SkillsInstallArgs),
    List(SkillsListArgs),
    Info(SkillsInfoArgs),
    Remove(SkillsRemoveArgs),
    Publish(SkillsPublishArgs),
    Verify(SkillsVerifyArgs),
    Ci(SkillsCiArgs),
    Prune(SkillsPruneArgs),
}

#[derive(Debug, Args)]
pub struct SkillsCiArgs {
    pub path: PathBuf,
    #[arg(long, value_name = "PATH")]
    pub registry_snapshot: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub sarif: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub no_fail_fast: bool,
}
```

Add dispatch arm:

```rust
        SkillsCommand::Ci(args) => run_ci(args, service).await,
```

Add `Ci(_)` to `registry_override_for_command` arm that returns `None`.

Add `run_ci`:

```rust
async fn run_ci(args: SkillsCiArgs, service: SkillService) -> Result<()> {
    let snapshot = match args.registry_snapshot.as_deref() {
        Some(path) => {
            let bytes = fs::read(path).with_context(|| format!("read `{}`", path.display()))?;
            Some(
                serde_json::from_slice::<SkillCiRegistrySnapshot>(&bytes)
                    .with_context(|| format!("parse registry snapshot `{}`", path.display()))?,
            )
        }
        None => None,
    };
    let report = run_skill_ci(SkillCiRequest {
        candidate_path: args.path,
        registry_snapshot: snapshot,
        fail_fast: !args.no_fail_fast,
        agent_runner: service.agent_produce_runner(),
    })?;

    if let Some(path) = args.sarif.as_deref() {
        let sarif = skill_ci_sarif(&report)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create SARIF directory `{}`", parent.display()))?;
        }
        fs::write(path, sarif).with_context(|| format!("write SARIF `{}`", path.display()))?;
    }

    if args.json {
        print_json(&report)?;
    } else {
        print_skill_ci_table(&report);
    }

    if report.status == SkillCiStatus::Passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
```

Because `SkillService` currently stores `agent_produce_runner` privately, add this method in `crates/agentenv-core/src/skills/service.rs`:

```rust
    pub fn agent_produce_runner(&self) -> Arc<dyn AgentProduceRunner> {
        Arc::clone(&self.agent_produce_runner)
    }
```

Add a human table helper in `skills_cli.rs`:

```rust
fn print_skill_ci_table(report: &agentenv_core::skills::SkillCiReport) {
    println!("skill: {} {}", report.candidate.name, report.candidate.version);
    println!("status: {:?}", report.status);
    for tier in &report.tiers {
        println!("{:?}: {:?}", tier.tier, tier.status);
        for finding in &tier.findings {
            eprintln!("  {:?}: {}", finding.severity, finding.message);
        }
    }
}
```

- [ ] **Step 4: Run CLI tests to verify GREEN**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_ci_ -- --nocapture
```

Expected: PASS for all `skills_ci_` tests.

- [ ] **Step 5: Commit Task 6**

```bash
git add crates/agentenv-core/src/skills/service.rs crates/agentenv/src/skills_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat(cli): add skills ci command"
```

## Task 7: GitHub Actions Workflow and README

**Files:**
- Add: `.github/workflows/skill-ci.yaml`
- Modify: `README.md`
- Test: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Add failing workflow smoke test**

Append to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn skill_ci_workflow_references_cli_command() {
    let workflow = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.github/workflows/skill-ci.yaml"),
    )
    .unwrap();
    assert!(workflow.contains("workflow_call"), "workflow was: {workflow}");
    assert!(workflow.contains("agentenv skills ci"), "workflow was: {workflow}");
    assert!(workflow.contains("upload-sarif"), "workflow was: {workflow}");
}
```

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
cargo test -p agentenv --test cli_behavior skill_ci_workflow_references_cli_command -- --nocapture
```

Expected: FAIL because `.github/workflows/skill-ci.yaml` does not exist.

- [ ] **Step 3: Add workflow**

Create `.github/workflows/skill-ci.yaml`:

```yaml
name: Skill CI

on:
  workflow_call:
    inputs:
      registry-snapshot:
        required: false
        type: string
  pull_request:
    paths:
      - ".agents/skills/**"
      - "skills/**"
      - "examples/**/skill.yaml"
      - ".github/workflows/skill-ci.yaml"

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  skill-ci:
    name: validate skills
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: stable
      - uses: Swatinem/rust-cache@v2
      - name: Build agentenv
        run: cargo build -p agentenv
      - name: Discover skill candidates
        id: discover
        shell: bash
        run: |
          set -euo pipefail
          mapfile -t skills < <(find . -name skill.yaml -not -path './target/*' -print | sed 's#/skill.yaml$##' | sort)
          printf 'count=%s\n' "${#skills[@]}" >> "$GITHUB_OUTPUT"
          printf '%s\n' "${skills[@]}" > skill-candidates.txt
      - name: Run skill CI
        if: steps.discover.outputs.count != '0'
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p skill-ci-reports
          status=0
          while IFS= read -r skill_dir; do
            safe_name="$(printf '%s' "$skill_dir" | tr -c 'A-Za-z0-9._-' '_')"
            args=(target/debug/agentenv skills ci "$skill_dir" --json --sarif "skill-ci-reports/${safe_name}.sarif")
            if [[ -n "${{ inputs.registry-snapshot || '' }}" ]]; then
              args+=(--registry-snapshot "${{ inputs.registry-snapshot }}")
            fi
            if ! "${args[@]}" > "skill-ci-reports/${safe_name}.json"; then
              status=1
            fi
          done < skill-candidates.txt
          exit "$status"
      - name: Upload SARIF
        if: always() && steps.discover.outputs.count != '0'
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: skill-ci-reports
      - name: Comment summary
        if: always() && github.event_name == 'pull_request' && steps.discover.outputs.count != '0'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const reports = fs.readdirSync('skill-ci-reports')
              .filter((name) => name.endsWith('.json'))
              .map((name) => JSON.parse(fs.readFileSync(`skill-ci-reports/${name}`, 'utf8')));
            const lines = ['## Skill CI', '', '| Skill | Status | Tiers |', '|---|---|---|'];
            for (const report of reports) {
              const tiers = report.tiers.map((tier) => `${tier.tier}: ${tier.status}`).join('<br>');
              lines.push(`| ${report.candidate.name}@${report.candidate.version} | ${report.status} | ${tiers} |`);
            }
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: lines.join('\n')
            });
```

- [ ] **Step 4: Update README**

Add this section near the existing skills CLI documentation in `README.md`:

```markdown
### Skill CI

`agentenv skills ci <path>` validates a skill publish candidate through four
sequential tiers: static lint, deterministic review, semantic dedup, and the
functional self-test gate. JSON output is intended for hubs and CI:

```bash
agentenv skills ci ./skills/my-skill --json --sarif skill-ci.sarif
```

`--registry-snapshot snapshot.json` supplies existing skill summaries for the
semantic dedup tier. `gitleaks` may be installed to enrich local secret scans,
but `agentenv` includes a portable built-in scanner and does not require
`gitleaks`.
```

- [ ] **Step 5: Run workflow smoke test to verify GREEN**

Run:

```bash
cargo test -p agentenv --test cli_behavior skill_ci_workflow_references_cli_command -- --nocapture
```

Expected: PASS for `skill_ci_workflow_references_cli_command`.

- [ ] **Step 6: Commit Task 7**

```bash
git add .github/workflows/skill-ci.yaml README.md crates/agentenv/tests/cli_behavior.rs
git commit -m "ci: add reusable skill validation workflow"
```

## Task 8: Full Verification and Cleanup

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run focused core tests**

Run:

```bash
cargo test -p agentenv-core --test skills_ci -- --nocapture
```

Expected: PASS for every test in `skills_ci.rs`.

- [ ] **Step 2: Run focused CLI tests**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_ci_ -- --nocapture
```

Expected: PASS for all `skills_ci_` tests.

- [ ] **Step 3: Run workflow smoke test**

Run:

```bash
cargo test -p agentenv --test cli_behavior skill_ci_workflow_references_cli_command -- --nocapture
```

Expected: PASS for `skill_ci_workflow_references_cli_command`.

- [ ] **Step 4: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits `0` and formats Rust files.

- [ ] **Step 5: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: command exits `0` with no warnings.

- [ ] **Step 6: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: command exits `0` with all workspace tests passing.

- [ ] **Step 7: Inspect final diff**

Run:

```bash
git diff --stat
git diff --check
```

Expected: `git diff --check` exits `0`; diff stat contains only the files named in this plan and commits from prior tasks.

- [ ] **Step 8: Commit final cleanup if needed**

If formatting or cleanup changed files after Task 7, commit them:

```bash
git add crates/agentenv-core/src/skills/ci.rs crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/src/skills/error.rs crates/agentenv-core/src/skills/service.rs crates/agentenv/src/skills_cli.rs crates/agentenv-core/tests/skills_ci.rs crates/agentenv/tests/cli_behavior.rs .github/workflows/skill-ci.yaml README.md
git commit -m "chore: polish skill ci validation"
```

If `git diff --stat` shows no remaining changes, do not create an empty cleanup commit.

## Self-Review

- Spec coverage: Tasks 1-5 cover the four core tiers, fail-fast behavior, JSON shape, and SARIF. Task 6 covers the CLI. Task 7 covers GitHub Actions and README documentation. Task 8 covers the required verification commands.
- Placeholder scan: This plan contains no deferred implementation markers and no unnamed files.
- Type consistency: Public names are consistent across tasks: `SkillCiRequest`, `SkillCiReport`, `SkillCiRegistrySnapshot`, `SkillCiTier`, `SkillCiTierStatus`, `SkillCiStatus`, `run_skill_ci`, and `skill_ci_sarif`.
