use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use ed25519_dalek::{Signer, SigningKey};

use agentenv_core::skills::{
    compute_bundle_digest, load_skill_manifest, run_skill_ci, signature_payload,
    AgentProduceRequest, AgentProduceRunner, SkillCiFinding, SkillCiRequest, SkillCiSeverity,
    SkillCiStatus, SkillCiTier, SkillCiTierStatus, SkillError,
};

#[test]
fn skill_ci_reports_candidate_and_runs_static_tier_first() {
    let bundle = skill_bundle(
        "ci-valid",
        "0.1.0",
        "# CI valid\n\nUse this skill safely.\n",
    );

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
    assert!(report.tiers[0].findings.iter().any(|finding| {
        finding.rule_id == "agentenv.skill.markdown.unclosed-fence"
            && finding.path.as_deref() == Some(Path::new("SKILL.md"))
    }));
    assert!(report
        .tiers
        .iter()
        .any(|tier| tier.status == SkillCiTierStatus::Skipped));
}

#[test]
fn skill_ci_static_tier_lints_nested_manifest_entry() {
    let bundle = skill_bundle_with_entry(
        "ci-nested-entry",
        "0.1.0",
        "docs/SKILL.md",
        "# Nested entry\n\nUse this nested skill safely.\n",
    );
    assert!(!bundle.join("SKILL.md").exists());

    let report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: true,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");

    assert_eq!(report.status, SkillCiStatus::Passed);
    assert_eq!(report.tiers[0].tier, SkillCiTier::StaticLint);
    assert_eq!(report.tiers[0].status, SkillCiTierStatus::Passed);
}

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

#[test]
fn static_lint_sarif_redacts_secret_values_in_finding_messages() {
    let bundle = skill_bundle("ci-sarif-redaction", "0.1.0", "# Redaction\n");

    let mut report = run_skill_ci(SkillCiRequest {
        candidate_path: bundle,
        registry_snapshot: None,
        fail_fast: true,
        agent_runner: Arc::new(PanicAgentRunner),
    })
    .expect("ci should run");
    report.tiers[0].findings.push(SkillCiFinding {
        rule_id: "agentenv.skill.synthetic".to_owned(),
        severity: SkillCiSeverity::Error,
        message:
            "review output included sk-test-1234567890abcdefghijklmnop and token=tok_1234567890abcdefghijklmnop"
                .to_owned(),
        path: Some(PathBuf::from("SKILL.md")),
        line: Some(1),
    });

    let sarif = agentenv_core::skills::skill_ci_sarif(&report).unwrap();

    assert!(!sarif.contains("sk-test-1234567890abcdefghijklmnop"));
    assert!(!sarif.contains("tok_1234567890abcdefghijklmnop"));
    assert!(sarif.contains("[REDACTED]"));
}

#[test]
fn static_lint_rejects_secret_like_text_in_skill_yaml() {
    let bundle = temp_dir("skill-ci-secret-skill-yaml");
    write_file(&bundle.join("SKILL.md"), "# Secret metadata\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: ci-secret-skill-yaml\nversion: 0.1.0\ndescription: token=tok_1234567890abcdefghijklmnop\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n",
    );
    sign_skill_bundle(&bundle);

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
    assert!(static_tier.findings.iter().any(|finding| {
        finding.rule_id == "agentenv.skill.secret.detected"
            && finding.path.as_deref() == Some(Path::new("skill.yaml"))
    }));
}

#[test]
fn static_lint_rejects_secret_like_text_in_skill_test_yaml() {
    let bundle = temp_dir("skill-ci-secret-skill-test-yaml");
    write_file(&bundle.join("SKILL.md"), "# Secret self-test\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: ci-secret-skill-test-yaml\nversion: 0.1.0\ndescription: self-test secret fixture\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: agent_produces\n      prompt: \"Use sk-test-1234567890abcdefghijklmnop\"\n      expect_tokens_matching:\n        - ok\n      min_match_ratio: 1.0\n",
    );
    sign_skill_bundle(&bundle);

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
    assert!(static_tier.findings.iter().any(|finding| {
        finding.rule_id == "agentenv.skill.secret.detected"
            && finding.path.as_deref() == Some(Path::new("skill-test.yaml"))
    }));
}

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
fn agent_review_fails_negated_consent_with_destructive_command() {
    let bundle = skill_bundle(
        "ci-negated-consent",
        "0.1.0",
        "# Negated Consent\n\nDo not ask before running `rm -rf target`.\n",
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
fn agent_review_fails_unrelated_consent_before_later_destructive_command() {
    let bundle = skill_bundle(
        "ci-unrelated-consent",
        "0.1.0",
        "# Unrelated Consent\n\nAsk before editing files. Run `rm -rf target` automatically.\n",
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
fn agent_review_fails_same_sentence_unrelated_consent_for_automatic_destructive_command() {
    let bundle = skill_bundle(
        "ci-same-sentence-unrelated-consent",
        "0.1.0",
        "# Same Sentence Consent\n\nAsk before editing files and run `rm -rf target` automatically.\n",
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
fn agent_review_fails_comma_then_unrelated_consent_for_destructive_command() {
    let bundle = skill_bundle(
        "ci-comma-then-unrelated-consent",
        "0.1.0",
        "# Comma Then Consent\n\nAsk before editing files, then run `rm -rf target`.\n",
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
fn agent_review_fails_then_unrelated_consent_for_destructive_command() {
    let bundle = skill_bundle(
        "ci-then-unrelated-consent",
        "0.1.0",
        "# Then Consent\n\nAsk before editing files then run `rm -rf target`.\n",
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
fn agent_review_passes_consent_directly_governing_destructive_command() {
    let bundle = skill_bundle(
        "ci-direct-destructive-consent",
        "0.1.0",
        "# Direct Consent\n\nAsk before running `rm -rf target`.\n",
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

#[test]
fn agent_review_fails_api_key_variants_without_credential_language() {
    for (name, skill_md) in [
        (
            "ci-api-key",
            "# API Key\n\nDocument how to request an api-key from the provider.\n",
        ),
        (
            "ci-apikey",
            "# APIKey\n\nDocument how to request an apikey from the provider.\n",
        ),
    ] {
        let bundle = skill_bundle(name, "0.1.0", skill_md);

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
            .any(|finding| finding.rule_id == "agentenv.skill.review.credential-handling"));
    }
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

#[derive(Debug)]
struct PanicAgentRunner;

impl AgentProduceRunner for PanicAgentRunner {
    fn run_agent_prompt(&self, _request: AgentProduceRequest<'_>) -> Result<String, SkillError> {
        panic!("agent runner should not be used by these tests");
    }
}

fn skill_bundle(name: &str, version: &str, skill_md: &str) -> PathBuf {
    skill_bundle_with_entry(name, version, "SKILL.md", skill_md)
}

fn skill_bundle_with_entry(name: &str, version: &str, entry: &str, skill_md: &str) -> PathBuf {
    let root = temp_dir(&format!("skill-ci-{name}-{version}"));
    write_file(&root.join(entry), skill_md);
    write_file(
        &root.join("skill.yaml"),
        &format!(
            "name: {name}\nversion: {version}\ndescription: {name} skill\nentry: {entry}\nfiles:\n  - {entry}\nself_test:\n  command: test -f {entry}\n"
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
    path.push(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
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
