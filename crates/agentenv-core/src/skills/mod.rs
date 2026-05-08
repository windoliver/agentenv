mod config;
mod digest;
mod error;
mod index;
mod manifest;
mod registry;
mod registry_filesystem;
mod registry_http;
mod registry_oci;
mod service;
mod signature;
mod store;

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
