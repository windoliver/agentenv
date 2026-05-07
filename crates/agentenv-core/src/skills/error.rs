use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SkillError {
    #[error("failed to read or write skill path `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse skill YAML at `{path}`: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid skill name `{name}`")]
    InvalidSkillName { name: String },
    #[error("invalid skill version `{version}`: {source}")]
    InvalidVersion {
        version: String,
        #[source]
        source: semver::Error,
    },
    #[error("unsafe skill bundle path `{path}`")]
    UnsafeBundlePath { path: PathBuf },
    #[error("declared skill file `{path}` is missing")]
    MissingDeclaredFile { path: PathBuf },
    #[error("declared skill pattern `{pattern}` matched no files")]
    EmptyFilePattern { pattern: String },
    #[error("skill manifest `{path}` is missing required field `{field}`")]
    MissingManifestField { path: PathBuf, field: &'static str },
    #[error("skill digest mismatch: expected `{expected}`, found `{actual}`")]
    DigestMismatch { expected: String, actual: String },
}
