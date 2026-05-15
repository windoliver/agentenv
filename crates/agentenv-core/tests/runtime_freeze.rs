use std::fs;

use agentenv_core::{
    env::{
        DriverHandles, DriverRecord, EndpointState, EnvPaths, EnvPhase, EnvStateFile,
        StateDriverSet, STATE_VERSION,
    },
    runtime::{freeze_env_lockfile, RuntimeError, RuntimeOptions},
};
use agentenv_proto::LogLevel;

#[test]
fn runtime_freeze_reads_persisted_env_and_returns_portable_lockfile() {
    let root = tempfile_dir("runtime-freeze");
    let env_name = agentenv_core::env::validate_env_name("demo").unwrap();
    let paths = EnvPaths::new(root.join(".agentenv"), env_name);
    fs::create_dir_all(paths.env_dir()).unwrap();
    fs::write(paths.blueprint_path(), blueprint_yaml()).unwrap();
    fs::write(paths.lock_path(), legacy_lock_yaml()).unwrap();
    agentenv_core::env::write_state(&paths, &state_file("demo")).unwrap();

    let rendered = freeze_env_lockfile(
        &RuntimeOptions {
            root: root.join(".agentenv"),
            log_level: LogLevel::Info,
            non_interactive: true,
        },
        "demo",
    )
    .unwrap();

    assert!(rendered.contains("version: 0.2.0"));
    assert!(rendered.contains("name: demo"));
    assert!(rendered.contains("sandbox:"));
    assert!(rendered.contains("name: openshell"));
    assert!(rendered.contains("agent:"));
    assert!(rendered.contains("name: codex"));
    assert!(rendered.contains("context:"));
    assert!(rendered.contains("name: filesystem"));
    assert!(rendered.contains("inference:"));
    assert!(rendered.contains("name: passthrough"));
    assert!(rendered.contains("digest: sha256:"));
    assert!(!rendered.contains("sk-known-secret"));
}

#[test]
fn runtime_freeze_rejects_lockfile_pin_that_differs_from_persisted_state() {
    let root = tempfile_dir("runtime-freeze-mismatch");
    let env_name = agentenv_core::env::validate_env_name("demo").unwrap();
    let paths = EnvPaths::new(root.join(".agentenv"), env_name);
    fs::create_dir_all(paths.env_dir()).unwrap();
    fs::write(paths.blueprint_path(), blueprint_yaml()).unwrap();
    fs::write(paths.lock_path(), legacy_lock_yaml()).unwrap();
    let mut state = state_file("demo");
    state.drivers.agent.version = "9.9.9".to_owned();
    agentenv_core::env::write_state(&paths, &state).unwrap();

    let error = freeze_env_lockfile(
        &RuntimeOptions {
            root: root.join(".agentenv"),
            log_level: LogLevel::Info,
            non_interactive: true,
        },
        "demo",
    )
    .unwrap_err();

    assert!(matches!(
        error,
        RuntimeError::FrozenLockfileDriverMismatch {
            role,
            expected_name,
            expected_version,
            actual_name,
            ..
        } if role == "agent"
            && expected_name == "codex"
            && expected_version == "9.9.9"
            && actual_name == "codex"
    ));
}

fn blueprint_yaml() -> &'static str {
    r#"
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
      note: sk-known-secret
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#
}

fn legacy_lock_yaml() -> &'static str {
    r#"
version: 0.1.0
protocol_version: '0.1'
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  sandbox:
    name: openshell
    version: 0.0.1-alpha0
  agent:
    name: codex
    version: 0.0.1-alpha0
  context:
    name: filesystem
    version: 0.0.1-alpha0
"#
}

fn state_file(name: &str) -> EnvStateFile {
    EnvStateFile {
        version: STATE_VERSION.to_owned(),
        name: name.to_owned(),
        phase: EnvPhase::Running,
        created_at: "2026-04-23T00:00:00Z".to_owned(),
        updated_at: "2026-04-23T00:00:00Z".to_owned(),
        drivers: StateDriverSet {
            sandbox: DriverRecord::new("openshell", env!("CARGO_PKG_VERSION")),
            agent: DriverRecord::new("codex", env!("CARGO_PKG_VERSION")),
            context: DriverRecord::new("filesystem", env!("CARGO_PKG_VERSION")),
            inference: Some(DriverRecord::new("passthrough", env!("CARGO_PKG_VERSION"))),
        },
        handles: DriverHandles::default(),
        endpoints: EndpointState::default(),
        egress_proxy: None,
        resolved_policy: None,
        credential_names: vec!["OPENAI_API_KEY".to_owned()],
        health: Default::default(),
        first_enter_hint_shown: false,
    }
}

fn tempfile_dir(prefix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}
