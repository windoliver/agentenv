use std::path::PathBuf;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::driver_artifact::DriverArtifact;

#[derive(Debug, Clone)]
pub struct SkillBundleInput {
    pub source: BundleSource,
    pub metadata: SkillBundleMetadata,
    pub blueprint_yaml: String,
    pub lockfile_yaml: String,
    pub reference_document: Option<ReferenceDocument>,
    pub output_dir: PathBuf,
    pub agentenv_version: String,
    pub created_at: String,
    pub driver_artifacts: Vec<DriverArtifact>,
}

#[derive(Debug, Clone)]
pub struct BundleSource {
    pub env_name: String,
    pub project_path: Option<PathBuf>,
    pub git_commit: Option<String>,
    pub git_dirty: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct SkillBundleMetadata {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub author: Option<String>,
    pub license: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReferenceDocument {
    pub source_relative_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillBundleOutput {
    pub output_dir: PathBuf,
    pub skill_name: String,
    pub version: String,
    pub bundle_digest: String,
    pub blueprint_digest: String,
    pub lockfile_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<BundleWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleWarning {
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifest {
    pub version: String,
    pub kind: String,
    pub skill: BundleManifestSkill,
    pub agentenv: BundleManifestAgentenv,
    pub files: Vec<BundleManifestFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifestSkill {
    pub name: String,
    pub version: String,
    pub entry: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifestAgentenv {
    pub schema: String,
    pub bundle: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleManifestFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleProvenance {
    pub version: String,
    pub created_at: String,
    pub agentenv_version: String,
    pub source: BundleProvenanceSource,
    pub digests: BundleProvenanceDigests,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleProvenanceSource {
    pub kind: String,
    pub env_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_git_dirty: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleProvenanceDigests {
    pub blueprint: String,
    pub lockfile: String,
    pub manifest: String,
}
