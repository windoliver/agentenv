use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest::{parse_sha256_digest, parse_sha256_hex, DigestError};

const SUPPORTED_LOCKFILE_VERSION: &str = "0.1.0";
const SUPPORTED_PROTOCOL_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    pub version: String,
    pub protocol_version: String,
    pub blueprint_hash: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub drivers: BTreeMap<String, DriverPin>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifacts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverPin {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to parse lockfile YAML: {0}")]
    ParseYaml(serde_yaml::Error),
    #[error("failed to deserialize lockfile data: {0}")]
    Deserialize(serde_yaml::Error),
    #[error("failed to serialize lockfile data: {0}")]
    Serialize(serde_yaml::Error),
    #[error("invalid blueprint hash: {source}")]
    InvalidBlueprintHash {
        #[source]
        source: DigestError,
    },
    #[error("invalid artifact digest for `{name}`: {source}")]
    InvalidArtifactDigest {
        name: String,
        #[source]
        source: DigestError,
    },
    #[error("unsupported lockfile version `{version}`")]
    UnsupportedVersion { version: String },
    #[error("unsupported protocol version `{version}`")]
    UnsupportedProtocolVersion { version: String },
    #[error("missing required driver pin `{role}`")]
    MissingRequiredDriverPin { role: String },
    #[error("unsupported credential source `{credential_source}` for `{name}`")]
    UnsupportedCredentialSource {
        name: String,
        credential_source: String,
    },
    #[error("invalid credential reference for `{name}`: lockfiles only support reference-only credentials")]
    MissingCredentialReference { name: String },
}

impl Lockfile {
    pub fn from_yaml(yaml: &str) -> Result<Self, LockfileError> {
        let lockfile: Self = serde_yaml::from_str(yaml).map_err(LockfileError::Deserialize)?;
        lockfile.validate()?;
        Ok(lockfile)
    }

    pub fn to_yaml_deterministic(&self) -> Result<String, LockfileError> {
        self.validate()?;
        serde_yaml::to_string(self).map_err(LockfileError::Serialize)
    }

    pub fn validate_no_secret_values(&self) -> Result<(), LockfileError> {
        validate_credentials(&self.credentials)
    }

    fn validate(&self) -> Result<(), LockfileError> {
        if self.version != SUPPORTED_LOCKFILE_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                version: self.version.clone(),
            });
        }

        if self.protocol_version != SUPPORTED_PROTOCOL_VERSION {
            return Err(LockfileError::UnsupportedProtocolVersion {
                version: self.protocol_version.clone(),
            });
        }

        parse_sha256_hex(&self.blueprint_hash)
            .map_err(|source| LockfileError::InvalidBlueprintHash { source })?;

        for role in ["sandbox", "agent", "context"] {
            if !self.drivers.contains_key(role) {
                return Err(LockfileError::MissingRequiredDriverPin {
                    role: role.to_string(),
                });
            }
        }

        for (name, digest) in &self.artifacts {
            parse_sha256_digest(digest).map_err(|source| LockfileError::InvalidArtifactDigest {
                name: name.clone(),
                source,
            })?;
        }

        self.validate_no_secret_values()
    }
}

fn validate_credentials(
    credentials: &BTreeMap<String, CredentialRef>,
) -> Result<(), LockfileError> {
    for (name, credential) in credentials {
        match credential.source.as_str() {
            "env" | "credstore" => {}
            source => {
                return Err(LockfileError::UnsupportedCredentialSource {
                    name: name.clone(),
                    credential_source: source.to_string(),
                });
            }
        }

        if credential.reference.is_none() {
            return Err(LockfileError::MissingCredentialReference { name: name.clone() });
        }
    }

    Ok(())
}
