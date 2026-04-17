use std::sync::{Mutex, OnceLock};

use agentenv_core::blueprint::Blueprint;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn workspace_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn all_reference_blueprints_parse() {
    let _guard = env_lock().lock().unwrap();

    std::env::set_var("MCP_URL", "https://mcp.internal.example.com");
    std::env::set_var("NEXUS_HUB_URL", "https://nexus.internal.example.com");

    for path in [
        "blueprints/claude+filesystem+openshell.yaml",
        "blueprints/codex+mcp-generic+openshell.yaml",
        "blueprints/hermes+nexus+openshell.yaml",
        "blueprints/openclaw+nexus+openshell.yaml",
    ] {
        let doc = std::fs::read_to_string(workspace_path(path)).unwrap();
        let blueprint = Blueprint::from_yaml(&doc);
        assert!(blueprint.is_ok(), "failed to parse {path}: {blueprint:?}");
    }
}

#[test]
fn interpolation_resolves_env_variable() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("MCP_URL", "https://mcp.internal.example.com");

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
  endpoint:
    url: ${MCP_URL}
    transport: http+sse
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
"#;

    let blueprint = Blueprint::from_yaml(yaml).unwrap();
    let endpoint = blueprint.context.extra.get("endpoint").unwrap();
    let url = endpoint
        .get("url")
        .and_then(|value| value.as_str())
        .unwrap();

    assert_eq!(url, "https://mcp.internal.example.com");
}

#[test]
fn interpolation_resolves_credstore_reference() {
    struct StaticResolver;

    impl agentenv_core::blueprint::InterpolationResolver for StaticResolver {
        fn resolve_env(&self, name: &str) -> Result<String, agentenv_core::error::BlueprintError> {
            Err(agentenv_core::error::BlueprintError::UnresolvedEnvVar {
                name: name.to_string(),
            })
        }

        fn resolve_credstore(
            &self,
            name: &str,
        ) -> Result<String, agentenv_core::error::BlueprintError> {
            match name {
                "NEXUS_TOKEN" => Ok("resolved-token".to_string()),
                _ => Err(agentenv_core::error::BlueprintError::UnresolvedCredential {
                    name: name.to_string(),
                }),
            }
        }
    }

    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1
sandbox:
  driver: openshell
agent:
  driver: hermes
context:
  driver: nexus
  credentials:
    NEXUS_TOKEN:
      source: literal
      value: ${credstore:NEXUS_TOKEN}
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#;

    let blueprint = Blueprint::from_yaml_with_resolver(yaml, &StaticResolver).unwrap();
    let token = blueprint
        .context
        .credentials
        .as_ref()
        .unwrap()
        .get("NEXUS_TOKEN")
        .unwrap()
        .value
        .as_deref()
        .unwrap();

    assert_eq!(token, "resolved-token");
}
