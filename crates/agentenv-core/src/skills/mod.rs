mod digest;
mod error;
mod index;
mod manifest;
mod signature;
mod store;

pub use digest::compute_bundle_digest;
pub use error::SkillError;
pub use manifest::{load_skill_manifest, validate_skill_name, SkillManifest};
pub use signature::{signature_payload, verify_ed25519_signature};
pub use store::{
    info_installed_skill, install_local_skill, list_installed_skills, remove_installed_skill,
    verify_installed_skill, InstalledSkill, InstalledSkillSelector, SkillInstallOptions,
};
