use agentenv_core::{
    digest::{parse_sha256_digest, sha256_hex},
    lockfile::Lockfile,
};

fn fixture(path: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(path),
    )
    .unwrap()
}

#[test]
fn lockfile_security_digest_must_be_sha256_lower_hex() {
    let valid = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(parse_sha256_digest(valid).is_ok());

    let uppercase = "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(parse_sha256_digest(uppercase).is_err());
    assert!(parse_sha256_digest("sha512:0123").is_err());
}

#[test]
fn lockfile_security_sha256_hex_hashes_bytes_deterministically() {
    assert_eq!(
        sha256_hex(b"agentenv"),
        "e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736"
    );
}

#[test]
fn lockfile_security_round_trips_and_serializes_deterministically() {
    let yaml = r#"
version: "0.1.0"
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  agent:
    name: codex
    version: 0.0.2
  context:
    name: filesystem
    version: 0.0.2
  sandbox:
    name: openshell
    version: 0.0.31
artifacts:
  sandbox-image: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
credentials:
  OPENAI_API_KEY:
    source: credstore
    reference: OPENAI_API_KEY
"#;

    let lockfile = Lockfile::from_yaml(yaml).unwrap();
    let rendered = lockfile.to_yaml_deterministic().unwrap();
    let reparsed = Lockfile::from_yaml(&rendered).unwrap();

    assert_eq!(reparsed, lockfile);
    assert_eq!(rendered, reparsed.to_yaml_deterministic().unwrap());
    assert!(!rendered.contains("\n    value:"));
}

#[test]
fn lockfile_security_rejects_unknown_top_level_fields() {
    let yaml = r#"
version: "0.1.0"
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  agent:
    name: codex
    version: 0.0.2
  context:
    name: filesystem
    version: 0.0.2
  sandbox:
    name: openshell
    version: 0.0.31
unexpected: true
"#;

    let err = Lockfile::from_yaml(yaml).unwrap_err();

    assert!(err.to_string().contains("unknown field `unexpected`"));
}

#[test]
fn lockfile_security_rejects_unsupported_lockfile_version() {
    let yaml = r#"
version: "9.9.9"
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  agent:
    name: codex
    version: 0.0.2
  context:
    name: filesystem
    version: 0.0.2
  sandbox:
    name: openshell
    version: 0.0.31
"#;

    let err = Lockfile::from_yaml(yaml).unwrap_err();

    assert!(err.to_string().contains("unsupported lockfile version"));
}

#[test]
fn lockfile_security_rejects_unsupported_protocol_version() {
    let yaml = r#"
version: "0.1.0"
protocol_version: "9.9"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  agent:
    name: codex
    version: 0.0.2
  context:
    name: filesystem
    version: 0.0.2
  sandbox:
    name: openshell
    version: 0.0.31
"#;

    let err = Lockfile::from_yaml(yaml).unwrap_err();

    assert!(err.to_string().contains("unsupported protocol version"));
}

#[test]
fn lockfile_security_requires_sandbox_agent_and_context_driver_pins() {
    let yaml = r#"
version: "0.1.0"
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  agent:
    name: codex
    version: 0.0.2
  sandbox:
    name: openshell
    version: 0.0.31
"#;

    let err = Lockfile::from_yaml(yaml).unwrap_err();

    assert!(err.to_string().contains("missing required driver pin"));
    assert!(err.to_string().contains("context"));
}

#[test]
fn lockfile_security_lockfile_with_inline_credential_value_is_rejected() {
    let text = fixture("lockfile-with-secret.yaml");
    let err = Lockfile::from_yaml(&text).unwrap_err();

    assert!(err.to_string().contains("unknown field `value`"));
}

#[test]
fn lockfile_security_rejects_unknown_credential_metadata_fields() {
    let yaml = r#"
version: "0.1.0"
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  agent:
    name: codex
    version: 0.0.2
  context:
    name: filesystem
    version: 0.0.2
  sandbox:
    name: openshell
    version: 0.0.31
credentials:
  OPENAI_API_KEY:
    source: credstore
    reference: OPENAI_API_KEY
    metadata:
      owner: platform
"#;

    let err = Lockfile::from_yaml(yaml).unwrap_err();

    assert!(err.to_string().contains("unknown field `metadata`"));
}

#[test]
fn lockfile_security_map_order_serializes_identically() {
    let yaml_a = r#"
version: "0.1.0"
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  sandbox:
    name: openshell
    version: 0.0.31
  context:
    name: filesystem
    version: 0.0.2
  agent:
    name: codex
    version: 0.0.2
artifacts:
  sandbox-image: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  agent-image: sha256:1111111111111111111111111111111111111111111111111111111111111111
credentials:
  OPENAI_API_KEY:
    source: credstore
    reference: OPENAI_API_KEY
  MCP_TOKEN:
    source: env
    reference: MCP_TOKEN
"#;

    let yaml_b = r#"
version: "0.1.0"
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
drivers:
  agent:
    name: codex
    version: 0.0.2
  sandbox:
    name: openshell
    version: 0.0.31
  context:
    name: filesystem
    version: 0.0.2
artifacts:
  agent-image: sha256:1111111111111111111111111111111111111111111111111111111111111111
  sandbox-image: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
credentials:
  MCP_TOKEN:
    source: env
    reference: MCP_TOKEN
  OPENAI_API_KEY:
    source: credstore
    reference: OPENAI_API_KEY
"#;

    let rendered_a = Lockfile::from_yaml(yaml_a)
        .unwrap()
        .to_yaml_deterministic()
        .unwrap();
    let rendered_b = Lockfile::from_yaml(yaml_b)
        .unwrap()
        .to_yaml_deterministic()
        .unwrap();

    assert_eq!(rendered_a, rendered_b);
}
