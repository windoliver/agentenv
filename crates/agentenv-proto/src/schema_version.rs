use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "1.3";

#[derive(Debug, Clone, Error, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchemaVersionError {
    #[error("schema version `{version}` is invalid; expected `major.minor`")]
    InvalidFormat { version: String },
    #[error(
        "schema version `{actual}` is incompatible with core schema version `{expected}`; {remediation}"
    )]
    IncompatibleMajor {
        expected: String,
        actual: String,
        remediation: String,
    },
}

pub fn schema_version_major(version: &str) -> Result<u64, SchemaVersionError> {
    let mut parts = version.split('.');
    let major = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| SchemaVersionError::InvalidFormat {
            version: version.to_owned(),
        })?;
    let minor = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| SchemaVersionError::InvalidFormat {
            version: version.to_owned(),
        })?;
    if parts.next().is_some() {
        return Err(SchemaVersionError::InvalidFormat {
            version: version.to_owned(),
        });
    }

    let major = major
        .parse::<u64>()
        .map_err(|_| SchemaVersionError::InvalidFormat {
            version: version.to_owned(),
        })?;
    minor
        .parse::<u64>()
        .map_err(|_| SchemaVersionError::InvalidFormat {
            version: version.to_owned(),
        })?;

    Ok(major)
}

pub fn is_compatible_schema_version(version: &str) -> bool {
    assert_compatible_schema_version(version).is_ok()
}

pub fn assert_compatible_schema_version(version: &str) -> Result<(), SchemaVersionError> {
    let expected_major = schema_version_major(SCHEMA_VERSION)?;
    let actual_major = schema_version_major(version)?;

    if expected_major == actual_major {
        Ok(())
    } else {
        Err(SchemaVersionError::IncompatibleMajor {
            expected: SCHEMA_VERSION.to_owned(),
            actual: version.to_owned(),
            remediation: format!(
                "upgrade the driver or the core so their major schema versions match (`{}`)",
                expected_major
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SCHEMA_VERSION;

    #[test]
    fn schema_version_is_1_3() {
        assert_eq!(SCHEMA_VERSION, "1.3");
    }
}
