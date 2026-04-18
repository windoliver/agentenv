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

    assert!(lockfile.artifacts.is_empty());
}
