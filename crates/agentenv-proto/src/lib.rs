#![forbid(unsafe_code)]

mod schema_version;
mod types;

pub use schema_version::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        assert_compatible_schema_version, is_compatible_schema_version, AgentHealthCheckProbe,
        SchemaVersionError, SCHEMA_VERSION,
    };

    #[test]
    fn accepts_matching_major_versions() {
        assert!(is_compatible_schema_version("0.9"));
        assert!(assert_compatible_schema_version("0.9").is_ok());
    }

    #[test]
    fn rejects_mismatched_major_versions() {
        let err = assert_compatible_schema_version("1.0").expect_err("major mismatch should fail");
        assert!(matches!(err, SchemaVersionError::IncompatibleMajor { .. }));
        assert!(err.to_string().contains("upgrade the driver or the core"));
    }

    #[test]
    fn rejects_malformed_schema_versions() {
        for version in ["0", "0.foo", "0.1.2", ".1", "0."] {
            let err = assert_compatible_schema_version(version)
                .expect_err("malformed schema versions should fail");
            assert!(matches!(err, SchemaVersionError::InvalidFormat { .. }));
            assert!(!is_compatible_schema_version(version));
        }
    }

    #[test]
    fn schema_version_is_0_2() {
        assert_eq!(SCHEMA_VERSION, "0.2");
    }

    #[test]
    fn agent_health_check_probe_defaults_to_zero_exit_code() {
        let probe = AgentHealthCheckProbe {
            cmd: "codex --version".to_owned(),
            tty: false,
            env: BTreeMap::new(),
            success_exit_codes: vec![0],
        };

        assert_eq!(probe.success_exit_codes, vec![0]);
    }
}
