use std::sync::{Mutex, OnceLock};

use agentenv_core::{
    lifecycle::{resolve_blueprint, verify_blueprint_yaml, LifecycleError, ResolveError},
    registry::{DriverKind, RegistryError},
};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn fixture(path: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(path),
    )
    .unwrap()
}

#[test]
fn verify_failures_resolve_blueprint_pins_highest_satisfying_driver_versions() {
    let current_version = env!("CARGO_PKG_VERSION");
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  version: ">=0.0.1-alpha0,<0.1"
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;

    let resolved = resolve_blueprint(yaml).unwrap();

    assert_eq!(resolved.sandbox.version.to_string(), current_version);
    assert_eq!(resolved.agent.version.to_string(), current_version);
    assert_eq!(resolved.context.version.to_string(), current_version);
    assert_eq!(
        resolved.inference.unwrap().version.to_string(),
        current_version
    );
}

#[test]
fn verify_failures_resolve_blueprint_supports_shipped_driver_aliases() {
    for inference_driver in [
        "inference-openai",
        "inference-anthropic",
        "inference-ollama",
    ] {
        let yaml = format!(
            r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: context-none
inference:
  driver: {inference_driver}
policy:
  tier: balanced
  presets: []
"#
        );

        let resolved = resolve_blueprint(&yaml).unwrap();

        assert_eq!(resolved.context.driver, "context-none");
        assert_eq!(
            resolved.context.version.to_string(),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(resolved.inference.unwrap().driver, inference_driver);
    }
}

#[test]
fn verify_failures_invalid_blueprint_version_returns_typed_error() {
    let yaml = r#"
version: not-semver
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;

    let err = resolve_blueprint(yaml).unwrap_err();

    match err {
        ResolveError::InvalidBlueprintVersion { field, value, .. } => {
            assert_eq!(field, "version");
            assert_eq!(value, "not-semver");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_rejects_unsupported_blueprint_schema_version() {
    let yaml = r#"
version: 0.2.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;

    let err = resolve_blueprint(yaml).unwrap_err();

    match err {
        ResolveError::UnsupportedBlueprintVersion {
            version,
            supported_version,
        } => {
            assert_eq!(version, "0.2.0");
            assert_eq!(supported_version, "0.1.0");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_rejects_incompatible_min_agentenv_version() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 9.9.9
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;

    let err = resolve_blueprint(yaml).unwrap_err();

    match err {
        ResolveError::IncompatibleMinAgentenvVersion {
            min_version,
            current_version,
        } => {
            assert_eq!(min_version, "9.9.9");
            assert_eq!(current_version, env!("CARGO_PKG_VERSION"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_invalid_semver_range_returns_typed_error() {
    let yaml = fixture("invalid-semver.yaml");
    let err = resolve_blueprint(&yaml).unwrap_err();

    match err {
        ResolveError::Registry(RegistryError::InvalidSemverRequirement {
            kind,
            name,
            requirement,
            ..
        }) => {
            assert_eq!(kind, DriverKind::Sandbox);
            assert_eq!(name, "openshell");
            assert_eq!(requirement, "definitely-not-semver");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_unknown_driver_returns_typed_error() {
    let yaml = fixture("unknown-driver.yaml");
    let err = resolve_blueprint(&yaml).unwrap_err();

    match err {
        ResolveError::Registry(RegistryError::UnknownDriver { kind, name }) => {
            assert_eq!(kind, DriverKind::Sandbox);
            assert_eq!(name, "mysterybox");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_public_verify_api_reports_missing_digest_path() {
    let yaml = fixture("missing-digest.yaml");
    let err = verify_blueprint_yaml(&yaml).unwrap_err();

    match err {
        LifecycleError::MissingDigest { path } => {
            assert_eq!(path, "sandbox.digest");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_rejects_conflicting_duplicate_credentials() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    SHARED_TOKEN:
      source: env
      required: true
context:
  driver: mcp-generic
  credentials:
    SHARED_TOKEN:
      source: credstore
      required: true
  endpoint:
    url: https://mcp.internal.example.com
    transport: http+sse
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
"#;
    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::ConflictingCredential {
            name,
            first_path,
            second_path,
        } => {
            assert_eq!(name, "SHARED_TOKEN");
            assert_eq!(first_path, "agent.credentials.SHARED_TOKEN");
            assert_eq!(second_path, "context.credentials.SHARED_TOKEN");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_rejects_unsupported_literal_credential_sources() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: literal
      value: hard-coded-secret
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;
    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::UnsupportedCredentialSource {
            path,
            credential_source,
        } => {
            assert_eq!(path, "agent.credentials.OPENAI_API_KEY");
            assert_eq!(credential_source, "literal");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_failures_rejects_secret_like_interpolated_env_reference_values() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("OPENAI_API_KEY", "sk-secret-value");

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      value: ${OPENAI_API_KEY}
      required: true
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;
    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::InvalidCredentialReference {
            path,
            credential_source,
            reference,
        } => {
            assert_eq!(path, "agent.credentials.OPENAI_API_KEY");
            assert_eq!(credential_source, "env");
            assert_eq!(reference, "${OPENAI_API_KEY}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
