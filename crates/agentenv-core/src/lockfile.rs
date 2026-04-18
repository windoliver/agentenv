use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use thiserror::Error;

use crate::digest::{parse_sha256_digest, parse_sha256_hex, DigestError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct DriverPin {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRef {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
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
    #[error("lockfile credential values are not allowed for `{name}`")]
    CredentialValueNotAllowed { name: String },
    #[error("lockfile credential field `{field}` for `{name}` appears to contain an inline secret; credential values are not allowed")]
    CredentialFieldNotAllowed { name: String, field: String },
}

impl Lockfile {
    pub fn from_yaml(yaml: &str) -> Result<Self, LockfileError> {
        let value: Value = serde_yaml::from_str(yaml).map_err(LockfileError::ParseYaml)?;
        let lockfile: Self = serde_yaml::from_value(value).map_err(LockfileError::Deserialize)?;
        lockfile.validate()?;
        Ok(lockfile)
    }

    pub fn to_yaml_deterministic(&self) -> Result<String, LockfileError> {
        self.validate()?;
        serde_yaml::to_string(self).map_err(LockfileError::Serialize)
    }

    pub fn validate_no_secret_values(&self) -> Result<(), LockfileError> {
        for (name, credential) in &self.credentials {
            if credential.value.is_some() {
                return Err(LockfileError::CredentialValueNotAllowed { name: name.clone() });
            }

            for (field, value) in &credential.extra {
                if is_inline_secret_field(field)
                    && matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
                {
                    return Err(LockfileError::CredentialFieldNotAllowed {
                        name: name.clone(),
                        field: field.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), LockfileError> {
        parse_sha256_hex(&self.blueprint_hash)
            .map_err(|source| LockfileError::InvalidBlueprintHash { source })?;

        for (name, digest) in &self.artifacts {
            parse_sha256_digest(digest).map_err(|source| LockfileError::InvalidArtifactDigest {
                name: name.clone(),
                source,
            })?;
        }

        self.validate_no_secret_values()
    }
}

fn is_inline_secret_field(field: &str) -> bool {
    matches!(
        field.to_ascii_lowercase().as_str(),
        "value"
            | "secret"
            | "token"
            | "password"
            | "api_key"
            | "client_secret"
            | "access_token"
            | "refresh_token"
    )
}
