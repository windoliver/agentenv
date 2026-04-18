use agentenv_core::lifecycle::resolve_blueprint;

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
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1
sandbox:
  driver: openshell
  version: ">=0.0.30,<0.1"
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

    assert_eq!(resolved.sandbox.version.to_string(), "0.0.31");
    assert_eq!(resolved.agent.version.to_string(), "0.0.2");
    assert_eq!(resolved.context.version.to_string(), "0.0.2");
    assert_eq!(resolved.inference.unwrap().version.to_string(), "0.0.2");
}

#[test]
fn verify_failures_invalid_semver_range_is_rejected() {
    let yaml = fixture("invalid-semver.yaml");
    let err = resolve_blueprint(&yaml).unwrap_err();

    assert!(
        err.to_string().contains("invalid semver"),
        "unexpected error: {err}"
    );
}

#[test]
fn verify_failures_unknown_driver_is_rejected() {
    let yaml = fixture("unknown-driver.yaml");
    let err = resolve_blueprint(&yaml).unwrap_err();

    assert!(
        err.to_string().contains("unknown driver"),
        "unexpected error: {err}"
    );
}
