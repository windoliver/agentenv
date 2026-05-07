use std::{
    fs,
    path::{Path, PathBuf},
};

use agentenv_core::skills::{
    compute_bundle_digest, load_skill_manifest, validate_skill_name, SkillError,
};

#[test]
fn skill_manifest_accepts_minimal_bundle() {
    let root = temp_dir("skill-manifest-minimal");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let manifest = load_skill_manifest(&root).expect("manifest should load");

    assert_eq!(manifest.name, "demo-skill");
    assert_eq!(manifest.version.to_string(), "0.1.0");
    assert_eq!(manifest.entry, PathBuf::from("SKILL.md"));
    assert_eq!(manifest.declared_files, vec![PathBuf::from("SKILL.md")]);
}

#[test]
fn skill_manifest_reads_nested_self_test_and_signature() {
    let root = temp_dir("skill-manifest-nested-metadata");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\nsignatures:\n  ed25519: abc123\n",
    );

    let manifest = load_skill_manifest(&root).expect("manifest should load");

    assert_eq!(
        manifest.self_test_command.as_deref(),
        Some("test -f SKILL.md")
    );
    assert_eq!(manifest.signature_ed25519.as_deref(), Some("abc123"));
}

#[test]
fn skill_manifest_rejects_invalid_name() {
    let root = temp_dir("skill-manifest-invalid-name");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: ../demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("name must be rejected");

    assert!(matches!(error, SkillError::InvalidSkillName { .. }));
}

#[test]
fn skill_manifest_rejects_parent_traversal() {
    let root = temp_dir("skill-manifest-parent-traversal");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: ../SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("entry traversal must fail");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn skill_manifest_rejects_missing_files_field() {
    let root = temp_dir("skill-manifest-missing-files");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("files must be required");

    assert!(matches!(
        error,
        SkillError::MissingManifestField { field: "files", .. }
    ));
}

#[test]
fn skill_manifest_rejects_entry_not_declared_in_files() {
    let root = temp_dir("skill-manifest-entry-not-declared");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("README.md"), "# Readme\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - README.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("entry must be declared");

    assert!(matches!(error, SkillError::MissingDeclaredFile { .. }));
}

#[test]
fn skill_manifest_rejects_missing_declared_file() {
    let root = temp_dir("skill-manifest-missing-declared-file");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - missing.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("declared files must exist");

    assert!(matches!(error, SkillError::MissingDeclaredFile { .. }));
}

#[cfg(unix)]
#[test]
fn skill_manifest_rejects_entry_inside_symlinked_directory() {
    let root = temp_dir("skill-manifest-symlinked-entry-parent");
    let outside = temp_dir("skill-manifest-symlinked-entry-outside");
    write_file(&outside.join("SKILL.md"), "# Outside\n");
    std::os::unix::fs::symlink(&outside, root.join("linked")).unwrap();
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: linked/SKILL.md\nfiles:\n  - linked/SKILL.md\n",
    );

    let error = load_skill_manifest(&root).expect_err("symlinked parents must be rejected");

    assert!(matches!(error, SkillError::MissingDeclaredFile { .. }));
}

#[cfg(unix)]
#[test]
fn skill_manifest_rejects_symlinked_file_in_recursive_declaration() {
    let root = temp_dir("skill-manifest-recursive-symlinked-file");
    fs::create_dir_all(root.join("references")).unwrap();
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("references/real.md"), "# Real\n");
    let outside = temp_dir("skill-manifest-recursive-symlinked-file-outside");
    write_file(&outside.join("linked.md"), "# Outside\n");
    std::os::unix::fs::symlink(outside.join("linked.md"), root.join("references/linked.md"))
        .unwrap();
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - references/**\n",
    );

    let error = load_skill_manifest(&root).expect_err("recursive symlinked files must fail");

    assert!(matches!(error, SkillError::MissingDeclaredFile { .. }));
}

#[cfg(unix)]
#[test]
fn skill_manifest_rejects_symlinked_directory_in_recursive_declaration() {
    let root = temp_dir("skill-manifest-recursive-symlinked-dir");
    fs::create_dir_all(root.join("references")).unwrap();
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("references/real.md"), "# Real\n");
    let outside = temp_dir("skill-manifest-recursive-symlinked-dir-outside");
    write_file(&outside.join("linked.md"), "# Outside\n");
    std::os::unix::fs::symlink(&outside, root.join("references/linked")).unwrap();
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - references/**\n",
    );

    let error = load_skill_manifest(&root).expect_err("recursive symlinked dirs must fail");

    assert!(matches!(error, SkillError::MissingDeclaredFile { .. }));
}

#[cfg(unix)]
#[test]
fn skill_manifest_rejects_symlinked_manifest_file() {
    let root = temp_dir("skill-manifest-symlinked-manifest");
    let outside = temp_dir("skill-manifest-symlinked-manifest-outside");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &outside.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    std::os::unix::fs::symlink(outside.join("skill.yaml"), root.join("skill.yaml")).unwrap();

    let error = load_skill_manifest(&root).expect_err("manifest symlinks must be rejected");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn skill_digest_is_stable_for_sorted_declared_files() {
    let root = temp_dir("skill-digest-stable");
    fs::create_dir_all(root.join("references")).unwrap();
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("references/a.md"), "A\n");
    write_file(&root.join("references/b.md"), "B\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - references/**\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();

    let first = compute_bundle_digest(&root, &manifest).unwrap();
    let second = compute_bundle_digest(&root, &manifest).unwrap();

    assert_eq!(first, second);
    assert!(first.starts_with("sha256:"));
    assert_eq!(first.len(), "sha256:".len() + 64);
}

#[test]
fn skill_digest_changes_when_content_changes() {
    let root = temp_dir("skill-digest-changes");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();
    let before = compute_bundle_digest(&root, &manifest).unwrap();

    write_file(&root.join("SKILL.md"), "# Changed\n");
    let after = compute_bundle_digest(&root, &manifest).unwrap();

    assert_ne!(before, after);
}

#[cfg(unix)]
#[test]
fn skill_digest_rejects_declared_symlink() {
    let root = temp_dir("skill-digest-symlink");
    write_file(&root.join("target.md"), "# Target\n");
    std::os::unix::fs::symlink(root.join("target.md"), root.join("SKILL.md")).unwrap();
    let manifest = agentenv_core::skills::SkillManifest {
        name: "demo".to_owned(),
        version: semver::Version::parse("0.1.0").unwrap(),
        description: None,
        entry: PathBuf::from("SKILL.md"),
        declared_files: vec![PathBuf::from("SKILL.md")],
        self_test_command: None,
        signature_ed25519: None,
        extra: Default::default(),
    };

    let error = compute_bundle_digest(&root, &manifest).expect_err("symlink must be rejected");

    assert!(matches!(error, SkillError::MissingDeclaredFile { .. }));
}

#[cfg(unix)]
#[test]
fn skill_digest_rejects_symlinked_parent_directory() {
    let root = temp_dir("skill-digest-symlinked-parent");
    let outside = temp_dir("skill-digest-symlinked-parent-outside");
    write_file(&outside.join("SKILL.md"), "# Outside\n");
    std::os::unix::fs::symlink(&outside, root.join("linked")).unwrap();
    let manifest = agentenv_core::skills::SkillManifest {
        name: "demo".to_owned(),
        version: semver::Version::parse("0.1.0").unwrap(),
        description: None,
        entry: PathBuf::from("linked/SKILL.md"),
        declared_files: vec![PathBuf::from("linked/SKILL.md")],
        self_test_command: None,
        signature_ed25519: None,
        extra: Default::default(),
    };

    let error =
        compute_bundle_digest(&root, &manifest).expect_err("symlinked parent must be rejected");

    assert!(matches!(error, SkillError::MissingDeclaredFile { .. }));
}

#[test]
fn validate_skill_name_accepts_conservative_identifiers() {
    for name in ["demo", "demo-skill", "demo_skill", "demo.skill", "a1"] {
        validate_skill_name(name).expect(name);
    }
}

fn temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
