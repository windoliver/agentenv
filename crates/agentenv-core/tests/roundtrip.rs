use std::sync::{Mutex, OnceLock};

use agentenv_core::lockfile::Lockfile;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn workspace_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
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
fn roundtrip_reproduce_matches_describe() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("MCP_URL", "https://93.184.216.34");

    let yaml = std::fs::read_to_string(workspace_path(
        "blueprints/codex+mcp-generic+openshell.yaml",
    ))
    .unwrap();

    let created = agentenv_core::lifecycle::create_from_blueprint_yaml("env-a", &yaml).unwrap();
    let lockfile = agentenv_core::lifecycle::freeze_env(&created).unwrap();
    let reproduced = agentenv_core::lifecycle::reproduce_from_lockfile("env-a", &lockfile).unwrap();

    assert_eq!(created.describe(), reproduced.describe());
}

#[test]
fn roundtrip_public_verify_api_accepts_reference_blueprint() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("MCP_URL", "https://93.184.216.34");

    let yaml = std::fs::read_to_string(workspace_path(
        "blueprints/codex+mcp-generic+openshell.yaml",
    ))
    .unwrap();

    let verified = agentenv_core::lifecycle::verify_blueprint_yaml(&yaml).unwrap();

    assert_eq!(verified.sandbox.driver, "openshell");
    assert_eq!(verified.agent.driver, "codex");
    assert_eq!(verified.context.driver, "mcp-generic");
}

#[test]
fn roundtrip_same_lockfile_reproduces_equivalent_description() {
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
      required: true
context:
  driver: mcp-generic
  endpoint:
    url: https://93.184.216.36
    transport: http+sse
  mode: readonly
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
  overrides:
    - allow: https://93.184.216.36
"#;

    let frozen = agentenv_core::lifecycle::freeze_from_blueprint_yaml(yaml).unwrap();
    let lockfile = Lockfile::from_yaml(&frozen).unwrap();
    let created = agentenv_core::lifecycle::reproduce_from_lockfile("env-a", &frozen).unwrap();
    let reproduced = agentenv_core::lifecycle::reproduce_from_lockfile("env-a", &frozen).unwrap();

    assert_eq!(created.describe(), reproduced.describe());
    assert_eq!(created.describe().blueprint_hash, lockfile.blueprint_hash);
    assert!(created.describe().artifacts.is_empty());
}

#[test]
fn roundtrip_allows_byte_identical_duplicate_credentials() {
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
      source: env
      required: true
  endpoint:
    url: https://93.184.216.34
    transport: http+sse
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
"#;

    let frozen = agentenv_core::lifecycle::freeze_from_blueprint_yaml(yaml).unwrap();
    let lockfile = Lockfile::from_yaml(&frozen).unwrap();

    assert_eq!(lockfile.credentials.len(), 1);
    assert!(lockfile.credentials.contains_key("SHARED_TOKEN"));
}

#[test]
fn roundtrip_preserves_explicit_credential_reference_provenance() {
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
      value: ACTUAL_OPENAI_KEY
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

    let frozen = agentenv_core::lifecycle::freeze_from_blueprint_yaml(yaml).unwrap();
    let lockfile = Lockfile::from_yaml(&frozen).unwrap();
    let reproduced = agentenv_core::lifecycle::reproduce_from_lockfile("env-a", &frozen).unwrap();

    assert_eq!(
        lockfile.credentials["OPENAI_API_KEY"].reference.as_deref(),
        Some("ACTUAL_OPENAI_KEY")
    );
    assert_eq!(
        reproduced.describe().credentials["OPENAI_API_KEY"]
            .reference
            .as_deref(),
        Some("ACTUAL_OPENAI_KEY")
    );
}

#[test]
fn roundtrip_freeze_strips_credential_metadata_fields_from_lockfile() {
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
      required: true
      note: ${OPENAI_API_KEY}
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;

    let frozen = agentenv_core::lifecycle::freeze_from_blueprint_yaml(yaml).unwrap();
    let lockfile = Lockfile::from_yaml(&frozen).unwrap();

    assert_eq!(
        lockfile.credentials["OPENAI_API_KEY"].reference.as_deref(),
        Some("OPENAI_API_KEY")
    );
    assert!(!frozen.contains("note:"));
    assert!(!frozen.contains("sk-secret-value"));
}

#[test]
fn roundtrip_missing_digest_blueprint_is_rejected() {
    let yaml = fixture("missing-digest.yaml");
    let err = agentenv_core::lifecycle::verify_blueprint_yaml(&yaml).unwrap_err();

    assert!(err.to_string().contains("missing digest"));
}

#[test]
fn roundtrip_byo_sandbox_image_allows_omitted_expected_digest() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image:
    source: byo
    dockerfile: ./enterprise-sandbox/Containerfile
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#;

    let frozen = agentenv_core::lifecycle::freeze_from_blueprint_yaml(yaml).unwrap();
    let lockfile = Lockfile::from_yaml(&frozen).unwrap();

    assert!(!lockfile.artifacts.contains_key("sandbox-image"));
}

#[test]
fn roundtrip_byo_sandbox_image_rejects_non_string_expected_digest() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image:
    source: byo
    dockerfile: ./enterprise-sandbox/Containerfile
    expected_digest: 123
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: restricted
  presets: []
"#;

    let err = agentenv_core::lifecycle::verify_blueprint_yaml(yaml).unwrap_err();

    assert!(err.to_string().contains("sandbox.image.expected_digest"));
    assert!(err.to_string().contains("expected string"));
}

#[test]
fn roundtrip_byo_sandbox_image_records_expected_digest_artifact() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  image:
    source: byo
    dockerfile: ./enterprise-sandbox/Containerfile
    expected_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#;

    let frozen = agentenv_core::lifecycle::freeze_from_blueprint_yaml(yaml).unwrap();
    let lockfile = Lockfile::from_yaml(&frozen).unwrap();

    assert_eq!(
        lockfile.artifacts["sandbox-image"],
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
}

#[test]
fn roundtrip_rejects_unknown_hardening_profile() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  hardening: hardened-like-fort-knox
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#;

    let err = agentenv_core::lifecycle::verify_blueprint_yaml(yaml).unwrap_err();
    let message = err.to_string();

    assert!(
        message.contains("sandbox.hardening"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("hardened-like-fort-knox"),
        "unexpected error: {message}"
    );
    assert!(message.contains("hardening"), "unexpected error: {message}");
}
