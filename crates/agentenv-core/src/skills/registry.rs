use std::path::{Path, PathBuf};

use super::{SkillError, SkillSelfTestAttestation};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RegistryConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: RegistryKind,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub auth: Option<String>,
}

impl RegistryConfig {
    pub fn filesystem(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Filesystem,
            url: None,
            path: Some(path.into()),
            auth: None,
        }
    }

    pub fn http(name: impl Into<String>, url: impl Into<String>, auth: Option<String>) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Http,
            url: Some(url.into()),
            path: None,
            auth,
        }
    }

    pub fn oci(
        name: impl Into<String>,
        reference: impl Into<String>,
        auth: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Oci,
            url: Some(reference.into()),
            path: None,
            auth,
        }
    }

    pub fn git(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Git,
            url: Some(url.into()),
            path: None,
            auth: None,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryKind {
    Filesystem,
    Http,
    Oci,
    Git,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
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

impl SkillSearchHit {
    pub(crate) fn apply_self_test_attestation(
        &mut self,
        attestation: Option<&SkillSelfTestAttestation>,
    ) {
        if let Some(attestation) = attestation {
            self.self_test_score = Some(attestation.score);
            self.self_test_attestation_digest = Some(attestation.self_test_digest.clone());
        }
    }
}

#[derive(Debug, Clone)]
pub struct FetchedSkill {
    pub staging_path: PathBuf,
    pub registry: String,
    pub source_type: String,
    pub name: String,
    pub version: String,
}

#[async_trait::async_trait]
pub trait RegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError>;
    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError>;
    async fn publish(
        &self,
        bundle_path: &Path,
        allow_unsigned: bool,
        attestation: Option<&SkillSelfTestAttestation>,
    ) -> Result<SkillSearchHit, SkillError>;
}
