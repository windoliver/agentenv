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
    std::env::set_var("MCP_URL", "https://mcp.internal.example.com");

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
    std::env::set_var("MCP_URL", "https://mcp.internal.example.com");

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
min_agentenv_version: 0.0.1
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
    url: https://mcp.alt.example.com
    transport: http+sse
  mode: readonly
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
  overrides:
    - allow: https://mcp.alt.example.com
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
min_agentenv_version: 0.0.1
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
    url: https://mcp.internal.example.com
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
fn roundtrip_missing_digest_blueprint_is_rejected() {
    let yaml = fixture("missing-digest.yaml");
    let err = agentenv_core::lifecycle::verify_blueprint_yaml(&yaml).unwrap_err();

    assert!(err.to_string().contains("missing digest"));
}
