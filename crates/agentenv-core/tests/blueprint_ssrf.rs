use std::sync::{Mutex, OnceLock};

use agentenv_core::lifecycle::{verify_blueprint_yaml, LifecycleError};
use agentenv_core::security::ssrf::SsrfBlockReason;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn with_env_lock() -> std::sync::MutexGuard<'static, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn workspace_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(path)
}

fn read_blueprint(path: &str) -> String {
    std::fs::read_to_string(workspace_path(path)).unwrap()
}

#[test]
fn blueprint_verification_rejects_metadata_mcp_endpoint_url() {
    let _guard = with_env_lock();

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
  endpoint:
    url: http://169.254.169.254/latest/meta-data/
    transport: http+sse
policy:
  tier: restricted
  presets: []
"#;

    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::SsrfBlocked { path, .. } => {
            assert_eq!(path, "context.endpoint.url");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn blueprint_verification_rejects_metadata_hub_url() {
    let _guard = with_env_lock();

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: nexus
  mode: hub
  hub_url: http://169.254.169.254/latest/meta-data/
policy:
  tier: balanced
  presets: []
"#;

    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::SsrfBlocked { path, .. } => {
            assert_eq!(path, "context.hub_url");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn blueprint_verification_accepts_reference_blueprint_urls() {
    let _guard = with_env_lock();
    let original = std::env::var("MCP_URL").ok();
    std::env::set_var("MCP_URL", "https://mcp.internal.example.com");

    let yaml = read_blueprint("blueprints/codex+mcp-generic+openshell.yaml");
    let verified = verify_blueprint_yaml(&yaml).unwrap();
    assert_eq!(verified.context.driver, "mcp-generic");

    match original {
        Some(original) => std::env::set_var("MCP_URL", original),
        None => std::env::remove_var("MCP_URL"),
    }
}

#[test]
fn blueprint_verification_rejects_unsupported_scheme_in_context_endpoint_url() {
    let _guard = with_env_lock();

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
  endpoint:
    url: ftp://169.254.169.254/latest/meta-data/
    transport: http+sse
policy:
  tier: restricted
  presets: []
"#;

    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::SsrfBlocked { path, source, .. } => {
            assert_eq!(path, "context.endpoint.url");
            assert!(matches!(
                source.reason,
                SsrfBlockReason::UnsupportedScheme { scheme } if scheme == "ftp"
            ));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn blueprint_verification_rejects_unsupported_scheme_in_inference_blueprint_url() {
    let _guard = with_env_lock();

    let yaml = r#"
version: 0.1.0
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
  upstream_url: ftp://169.254.169.254/latest/meta-data/
policy:
  tier: balanced
  presets: []
"#;

    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::SsrfBlocked { path, .. } => {
            assert_eq!(path, "inference.upstream_url");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn blueprint_verification_rejects_unsupported_scheme_in_policy_override_allow_url() {
    let _guard = with_env_lock();

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
  endpoint:
    url: https://mcp.internal.example.com
    transport: http+sse
policy:
  tier: restricted
  presets: []
  overrides:
    - allow: ftp://169.254.169.254/
      deny: not-a-url
"#;

    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::SsrfBlocked { path, source, .. } => {
            assert_eq!(path, "policy.overrides[0].allow");
            assert!(matches!(
                source.reason,
                SsrfBlockReason::UnsupportedScheme { scheme } if scheme == "ftp"
            ));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn blueprint_verification_rejects_malformed_url_like_policy_override_allow() {
    let _guard = with_env_lock();

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
  endpoint:
    url: https://mcp.internal.example.com
    transport: http+sse
policy:
  tier: restricted
  presets: []
  overrides:
    - allow: https://
      deny: not-a-url
"#;

    let err = verify_blueprint_yaml(yaml).unwrap_err();

    match err {
        LifecycleError::SsrfBlocked { path, source, .. } => {
            assert_eq!(path, "policy.overrides[0].allow");
            assert!(matches!(source.reason, SsrfBlockReason::MalformedRedirect { .. }));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn blueprint_verification_allows_non_url_policy_override_string() {
    let _guard = with_env_lock();

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
  endpoint:
    url: https://mcp.internal.example.com
    transport: http+sse
policy:
  tier: restricted
  presets: []
  overrides:
    - allow: not-a-url
      deny: not-a-url-either
"#;

    let verified = verify_blueprint_yaml(yaml).unwrap();
    assert_eq!(verified.context.driver, "mcp-generic");
}
