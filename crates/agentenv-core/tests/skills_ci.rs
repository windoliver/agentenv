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
    assert!(report
        .tiers
        .iter()
        .any(|tier| tier.status == SkillCiTierStatus::Skipped));
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
