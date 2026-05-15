mod attestation;
pub mod cache;
mod ci;
mod config;
mod digest;
mod error;
mod index;
mod manifest;
pub mod propose;
mod registry;
mod registry_filesystem;
mod registry_git;
mod registry_http;
mod registry_oci;
pub mod self_test;
mod service;
mod signature;
mod store;

pub use attestation::{
    sign_skill_self_test_attestation, validate_skill_publish_attestation,
    SkillAttestationValidationOptions, SkillSelfTestAttestation, SkillSelfTestAttestationSignature,
    SkillSelfTestSigningKey, SkillSelfTestSubject,
};
pub use cache::{
    execute_skill_prune, load_skill_trust_keys, plan_skill_prune, rebuild_skill_index,
    verify_all_installed_skills, verify_skill_pins, SkillArchive, SkillCacheError,
    SkillCacheLayout, SkillIndex, SkillIndexEntry, SkillProvenance, SkillProvenanceSubject,
    SkillPrunePlan, SkillSelfTest, SkillTrustKey, SkillVerifyEntry, SkillVerifyOptions,
    SkillVerifyReport, SkillVerifyStatus, SKILL_METADATA_SCHEMA_VERSION,
};
pub use ci::{
    run_skill_ci, skill_ci_sarif, SkillCiCandidate, SkillCiFinding, SkillCiRegistrySkill,
    SkillCiRegistrySnapshot, SkillCiReport, SkillCiRequest, SkillCiSeverity, SkillCiStatus,
    SkillCiTier, SkillCiTierReport, SkillCiTierStatus, SKILL_CI_SCHEMA_VERSION,
};
pub use config::{
    load_project_skills_config, load_user_skills_config, merge_skills_config, ProposalConfig,
    ProposalLlmConfig, ProposalPrConfig, ProposalSemanticConfig, SkillsConfig,
    SkillsConfigOverride,
};
pub use digest::compute_bundle_digest;
pub use error::SkillError;
pub use manifest::{load_skill_manifest, validate_skill_name, SkillManifest};
pub use registry::{FetchedSkill, RegistryAdapter, RegistryConfig, RegistryKind, SkillSearchHit};
pub use self_test::{
    load_skill_self_test_spec, normalized_self_test_digest, run_skill_self_test,
    AgentProduceRequest, AgentProduceRunner, SkillAssertionResult, SkillAssertionStatus,
    SkillSelfTestAssertion, SkillSelfTestOptions, SkillSelfTestReport, SkillSelfTestRunner,
    SkillSelfTestSpec, UnsupportedAgentProduceRunner, SELF_TEST_PUBLISH_THRESHOLD,
};
pub use service::{SkillAddRequest, SkillCredentialResolver, SkillPublishRequest, SkillService};
pub use signature::{signature_payload, verify_ed25519_signature};
pub use store::{
    info_installed_skill, install_local_skill, list_installed_skills, read_self_test_attestation,
    remove_installed_skill, self_test_signing_key_path, verify_installed_skill,
    write_self_test_attestation, InstalledSkill, InstalledSkillSelector, SkillInstallOptions,
};
