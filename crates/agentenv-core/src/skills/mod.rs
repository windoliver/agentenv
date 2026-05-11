pub mod cache;
mod config;
mod digest;
mod error;
mod index;
mod manifest;
pub mod propose;
mod registry;
mod registry_filesystem;
mod registry_http;
mod registry_oci;
mod service;
mod signature;
mod store;

pub use cache::{
    execute_skill_prune, load_skill_trust_keys, plan_skill_prune, rebuild_skill_index,
    verify_all_installed_skills, verify_skill_pins, SkillArchive, SkillCacheError,
    SkillCacheLayout, SkillIndex, SkillIndexEntry, SkillProvenance, SkillProvenanceSubject,
    SkillPrunePlan, SkillSelfTest, SkillSelfTestAssertion, SkillTrustKey, SkillVerifyEntry,
    SkillVerifyOptions, SkillVerifyReport, SkillVerifyStatus, SKILL_METADATA_SCHEMA_VERSION,
};
pub use config::{
    load_project_skills_config, load_user_skills_config, merge_skills_config, SkillsConfig,
    SkillsConfigOverride,
};
pub use digest::compute_bundle_digest;
pub use error::SkillError;
pub use manifest::{load_skill_manifest, validate_skill_name, SkillManifest};
pub use registry::{FetchedSkill, RegistryAdapter, RegistryConfig, RegistryKind, SkillSearchHit};
pub use service::{SkillAddRequest, SkillCredentialResolver, SkillPublishRequest, SkillService};
pub use signature::{signature_payload, verify_ed25519_signature};
pub use store::{
    info_installed_skill, install_local_skill, list_installed_skills, remove_installed_skill,
    verify_installed_skill, InstalledSkill, InstalledSkillSelector, SkillInstallOptions,
};
