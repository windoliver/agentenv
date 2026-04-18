use agentenv_core::lockfile::Lockfile;

fn workspace_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn freeze_determinism_is_byte_for_byte_deterministic() {
    let yaml = std::fs::read_to_string(workspace_path(
        "blueprints/claude+filesystem+openshell.yaml",
    ))
    .unwrap();

    let one = agentenv_core::lifecycle::freeze_from_blueprint_yaml(&yaml).unwrap();
    let two = agentenv_core::lifecycle::freeze_from_blueprint_yaml(&yaml).unwrap();

    assert_eq!(one, two);
}

#[test]
fn freeze_determinism_omits_synthetic_driver_artifacts() {
    let yaml = std::fs::read_to_string(workspace_path(
        "blueprints/claude+filesystem+openshell.yaml",
    ))
    .unwrap();

    let rendered = agentenv_core::lifecycle::freeze_from_blueprint_yaml(&yaml).unwrap();
    let lockfile = Lockfile::from_yaml(&rendered).unwrap();

    assert!(!rendered.contains("resolved_blueprint:"));
    assert!(lockfile.artifacts.is_empty());
}

#[test]
fn freeze_determinism_semantic_interpolation_changes_hash_and_output() {
    let yaml = std::fs::read_to_string(workspace_path(
        "blueprints/codex+mcp-generic+openshell.yaml",
    ))
    .unwrap();

    std::env::set_var("MCP_URL", "https://mcp.one.example.com");
    let one = agentenv_core::lifecycle::freeze_from_blueprint_yaml(&yaml).unwrap();
    let one_lockfile = Lockfile::from_yaml(&one).unwrap();

    std::env::set_var("MCP_URL", "https://mcp.two.example.com");
    let two = agentenv_core::lifecycle::freeze_from_blueprint_yaml(&yaml).unwrap();
    let two_lockfile = Lockfile::from_yaml(&two).unwrap();

    assert_ne!(one, two);
    assert_ne!(one_lockfile.blueprint_hash, two_lockfile.blueprint_hash);
}
