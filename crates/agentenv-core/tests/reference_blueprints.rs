use std::sync::{Mutex, OnceLock};

use agentenv_core::{
    blueprint::Blueprint, error::BlueprintError, lifecycle::verify_blueprint_yaml,
};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn workspace_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

struct ReferenceBlueprint {
    path: &'static str,
    agent_driver: &'static str,
    context_driver: &'static str,
    tier: &'static str,
    persists_home: Option<bool>,
    context: ContextExpectation,
}

enum ContextExpectation {
    Filesystem {
        mount: &'static str,
    },
    GenericMcp {
        url: &'static str,
        transport: &'static str,
    },
    Nexus {
        hub_url: &'static str,
    },
}

fn reference_blueprints() -> Vec<ReferenceBlueprint> {
    vec![
        ReferenceBlueprint {
            path: "blueprints/claude+filesystem+openshell.yaml",
            agent_driver: "claude",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/codex+filesystem+openshell.yaml",
            agent_driver: "codex",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/openclaw+filesystem+openshell.yaml",
            agent_driver: "openclaw",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/claude+mcp-generic+openshell.yaml",
            agent_driver: "claude",
            context_driver: "mcp-generic",
            tier: "restricted",
            persists_home: Some(true),
            context: ContextExpectation::GenericMcp {
                url: "https://93.184.216.34",
                transport: "http+sse",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/hermes+filesystem+openshell.yaml",
            agent_driver: "hermes",
            context_driver: "filesystem",
            tier: "balanced",
            persists_home: None,
            context: ContextExpectation::Filesystem {
                mount: "~/projects",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/claude+nexus+openshell.yaml",
            agent_driver: "claude",
            context_driver: "nexus",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Nexus {
                hub_url: "https://93.184.216.35",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/codex+mcp-generic+openshell.yaml",
            agent_driver: "codex",
            context_driver: "mcp-generic",
            tier: "restricted",
            persists_home: None,
            context: ContextExpectation::GenericMcp {
                url: "https://93.184.216.34",
                transport: "http+sse",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/hermes+nexus+openshell.yaml",
            agent_driver: "hermes",
            context_driver: "nexus",
            tier: "balanced",
            persists_home: None,
            context: ContextExpectation::Nexus {
                hub_url: "https://93.184.216.35",
            },
        },
        ReferenceBlueprint {
            path: "blueprints/openclaw+nexus+openshell.yaml",
            agent_driver: "openclaw",
            context_driver: "nexus",
            tier: "balanced",
            persists_home: Some(true),
            context: ContextExpectation::Nexus {
                hub_url: "https://93.184.216.35",
            },
        },
    ]
}

#[test]
fn all_reference_blueprints_parse() {
    let _guard = env_lock().lock().unwrap();

    std::env::set_var("MCP_URL", "https://93.184.216.34");
    std::env::set_var("NEXUS_HUB_URL", "https://93.184.216.35");

    for expected in reference_blueprints() {
        let path = expected.path;
        let doc = std::fs::read_to_string(workspace_path(path))
            .unwrap_or_else(|err| panic!("{path}: {err}"));
        let blueprint = Blueprint::from_yaml(&doc).unwrap();

        assert_eq!(blueprint.version, "0.1.0", "{path}");
        assert_eq!(
            blueprint.min_agentenv_version,
            env!("CARGO_PKG_VERSION"),
            "{path}"
        );
        assert_eq!(blueprint.sandbox.driver, "openshell", "{path}");
        assert_eq!(blueprint.agent.driver, expected.agent_driver, "{path}");
        assert_eq!(blueprint.context.driver, expected.context_driver, "{path}");
        assert_eq!(blueprint.policy.tier, expected.tier, "{path}");
        assert_eq!(
            blueprint
                .inference
                .as_ref()
                .map(|section| section.driver.as_str()),
            Some("passthrough"),
            "{path}"
        );
        assert_eq!(
            blueprint
                .state
                .as_ref()
                .and_then(|state| state.persist_home),
            expected.persists_home,
            "{path}"
        );

        match expected.context {
            ContextExpectation::Filesystem {
                mount: expected_mount,
            } => {
                let mount = blueprint
                    .context
                    .extra
                    .get("mount")
                    .unwrap()
                    .as_str()
                    .unwrap();
                assert_eq!(mount, expected_mount, "{path}");
            }
            ContextExpectation::GenericMcp {
                url: expected_url,
                transport: expected_transport,
            } => {
                let endpoint = blueprint.context.extra.get("endpoint").unwrap();
                let url = yaml_string_field(endpoint, "url");
                let transport = yaml_string_field(endpoint, "transport");
                assert_eq!(url, expected_url, "{path}");
                assert_eq!(transport, expected_transport, "{path}");
            }
            ContextExpectation::Nexus {
                hub_url: expected_hub_url,
            } => {
                assert_eq!(
                    blueprint
                        .context
                        .extra
                        .get("mode")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "hub",
                    "{path}"
                );
                assert_eq!(
                    blueprint
                        .context
                        .extra
                        .get("hub_url")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    expected_hub_url,
                    "{path}"
                );
            }
        }
    }
}

#[test]
fn docs_catalog_mentions_every_reference_blueprint() {
    let docs = std::fs::read_to_string(workspace_path("docs/BLUEPRINTS.md")).unwrap();

    for case in reference_blueprints() {
        let file_name = case.path.strip_prefix("blueprints/").unwrap();
        assert!(
            docs.contains(file_name),
            "docs/BLUEPRINTS.md must mention {file_name}"
        );
    }
}

#[test]
fn sample_project_blueprints_parse() {
    let _guard = env_lock().lock().unwrap();

    std::env::set_var("NEXUS_HUB_URL", "https://93.184.216.35");

    for path in [
        "examples/quickstart/agentenv.yaml",
        "examples/enterprise-hub/agentenv.yaml",
        "examples/headless-ci/agentenv.yaml",
    ] {
        let doc = std::fs::read_to_string(workspace_path(path))
            .unwrap_or_else(|err| panic!("{path}: {err}"));
        let blueprint = Blueprint::from_yaml(&doc).unwrap_or_else(|err| panic!("{path}: {err}"));
        verify_blueprint_yaml(&doc).unwrap_or_else(|err| panic!("{path}: {err}"));

        assert_eq!(blueprint.version, "0.1.0", "{path}");
        assert_eq!(blueprint.sandbox.driver, "openshell", "{path}");
        assert_eq!(
            blueprint
                .inference
                .as_ref()
                .map(|section| section.driver.as_str()),
            Some("passthrough"),
            "{path}"
        );
    }
}

#[test]
fn interpolation_resolves_env_variable() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("MCP_URL", "https://93.184.216.34");

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
    let url = yaml_string_field(endpoint, "url");

    assert_eq!(url, "https://93.184.216.34");
}

#[test]
fn interpolation_does_not_resolve_credential_reference_values() {
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
min_agentenv_version: 0.0.1-alpha0
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

    assert_eq!(token, "${credstore:NEXUS_TOKEN}");
}

#[test]
fn interpolation_skips_credential_objects_but_still_resolves_other_fields() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("OPENAI_API_KEY", "sk-secret-value");
    std::env::set_var("MCP_URL", "https://93.184.216.34");

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
    let credential = blueprint
        .agent
        .credentials
        .as_ref()
        .unwrap()
        .get("OPENAI_API_KEY")
        .unwrap();
    let note = credential.extra.get("note").unwrap().as_str().unwrap();
    let endpoint = blueprint.context.extra.get("endpoint").unwrap();
    let url = yaml_string_field(endpoint, "url");

    assert_eq!(note, "${OPENAI_API_KEY}");
    assert_eq!(url, "https://93.184.216.34");
}

#[test]
fn blueprint_allows_missing_inference_section() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: claude
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: balanced
  presets: []
"#;

    let blueprint = Blueprint::from_yaml(yaml).unwrap();

    assert!(blueprint.inference.is_none());
}

#[test]
fn interpolation_reports_path_for_unresolved_placeholder() {
    let _guard = env_lock().lock().unwrap();
    std::env::remove_var("MISSING_URL");

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
    url: ${MISSING_URL}
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
"#;

    let err = Blueprint::from_yaml(yaml).unwrap_err();

    match err {
        BlueprintError::Interpolation { path, source } => {
            assert_eq!(path, "context.endpoint.url");
            match *source {
                BlueprintError::UnresolvedEnvVar { name } => assert_eq!(name, "MISSING_URL"),
                other => panic!("expected unresolved env var, got {other:?}"),
            }
        }
        other => panic!("expected interpolation error, got {other:?}"),
    }
}

fn yaml_string_field<'a>(value: &'a serde_yaml::Value, key: &str) -> &'a str {
    value
        .get(serde_yaml::Value::String(key.to_string()))
        .and_then(|item| item.as_str())
        .unwrap()
}
