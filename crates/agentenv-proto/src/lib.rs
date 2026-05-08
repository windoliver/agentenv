#![forbid(unsafe_code)]

mod schema_version;
mod types;

pub use schema_version::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::{
        assert_compatible_schema_version, is_compatible_schema_version, AgentHealthCheckProbe,
        DriverActivityEventParams, SandboxCapabilities, SchemaVersionError, SessionHandle,
        SessionStatus, SCHEMA_VERSION,
    };

    #[test]
    fn accepts_matching_major_versions() {
        assert!(is_compatible_schema_version(SCHEMA_VERSION));
        assert!(assert_compatible_schema_version(SCHEMA_VERSION).is_ok());
        assert!(is_compatible_schema_version("1.9"));
        assert!(assert_compatible_schema_version("1.9").is_ok());
    }

    #[test]
    fn rejects_mismatched_major_versions() {
        let err = assert_compatible_schema_version("0.2").expect_err("major mismatch should fail");
        assert!(matches!(err, SchemaVersionError::IncompatibleMajor { .. }));
        assert!(err.to_string().contains("upgrade the driver or the core"));

        let err = assert_compatible_schema_version("2.0").expect_err("major mismatch should fail");
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
    fn schema_version_is_1_2() {
        assert_eq!(SCHEMA_VERSION, "1.2");
    }

    #[test]
    fn driver_activity_event_accepts_legacy_shape() {
        let event: DriverActivityEventParams = serde_json::from_value(serde_json::json!({
            "kind": "egress_denied",
            "subject": "api.example.test:443",
            "reason": "not_in_policy",
            "ts": "2026-04-26T12:00:00Z",
            "handle": "sb-1"
        }))
        .expect("legacy driver activity event should deserialize");

        assert!(matches!(event, DriverActivityEventParams::Legacy(_)));
    }

    #[test]
    fn driver_activity_event_accepts_rich_shape() {
        let event: DriverActivityEventParams = serde_json::from_value(serde_json::json!({
            "ts": "2026-04-26T12:00:00Z",
            "kind": "sandbox_create",
            "env": "demo",
            "actor": {"driver": "openshell"},
            "subject": {"handle": "sb-1"},
            "result": "ok",
            "latency_ms": 42,
            "trace_id": "trace-1",
            "reason_code": "created",
            "extras": {"phase": "create"}
        }))
        .expect("rich driver activity event should deserialize");

        assert!(matches!(event, DriverActivityEventParams::Rich(_)));
    }

    #[test]
    fn driver_activity_schema_is_exported() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(manifest_dir
            .join("schema/driver-activity-event-params.json")
            .exists());
    }

    #[test]
    fn sandbox_capabilities_default_missing_optional_flags_to_false() {
        let capabilities: SandboxCapabilities = serde_json::from_value(serde_json::json!({
            "supports_hot_reload_policy": true,
            "supports_filesystem_lockdown": true,
            "supports_syscall_filter": true,
            "supports_native_inference_routing": true,
            "supports_remote_host": false
        }))
        .expect("legacy sandbox capabilities should deserialize");

        assert!(!capabilities.supports_persistent_sessions);
        assert!(!capabilities.supports_snapshots);
        assert!(!capabilities.supports_fork);
    }

    #[test]
    fn session_handle_round_trips() {
        let handle = SessionHandle {
            session_id: "01HSESSION".to_owned(),
            name: "demo".to_owned(),
            status: SessionStatus::Detached,
            created_at: "2026-04-24T17:00:00Z".to_owned(),
            updated_at: "2026-04-24T17:01:00Z".to_owned(),
            command: "/sandbox/.agentenv/bin/agentenv-agent".to_owned(),
            working_dir: Some("/sandbox".to_owned()),
        };

        let encoded = serde_json::to_value(&handle).expect("serialize session handle");
        assert_eq!(encoded["status"], "detached");
        let decoded: SessionHandle =
            serde_json::from_value(encoded).expect("deserialize session handle");
        assert_eq!(decoded, handle);
    }

    #[test]
    fn agent_health_check_probe_defaults_to_zero_exit_code() {
        let probe: AgentHealthCheckProbe = serde_json::from_value(serde_json::json!({
            "cmd": "codex --version",
            "tty": false
        }))
        .expect("probe without success_exit_codes should deserialize");

        assert_eq!(probe.success_exit_codes, vec![0]);
    }

    #[test]
    fn credential_requirement_schemas_are_kind_specific() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let empty_params_schema = std::fs::read_to_string(
            manifest_dir.join("schema/credential-requirements-params.json"),
        )
        .expect("read static credential requirements params schema");
        let agent_params_schema = std::fs::read_to_string(
            manifest_dir.join("schema/agent-credential-requirements-params.json"),
        )
        .expect("read agent credential requirements params schema");

        assert!(empty_params_schema.contains("\"title\": \"CredentialRequirementsParams\""));
        assert!(agent_params_schema.contains("\"title\": \"AgentSpec\""));
    }

    #[test]
    fn legacy_agent_health_check_schemas_are_not_exported() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

        assert!(!manifest_dir
            .join("schema/health-check-params.json")
            .exists());
        assert!(!manifest_dir
            .join("schema/health-check-result.json")
            .exists());
        assert!(manifest_dir
            .join("schema/agent-health-check-probe.json")
            .exists());
    }
}
