use std::{
    collections::BTreeMap,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use agentenv_core::security::ssrf::SsrfOptions;
use agentenv_core::skills::{
    compute_bundle_digest, install_local_skill, list_installed_skills, load_project_skills_config,
    load_skill_manifest, load_user_skills_config, merge_skills_config, read_self_test_attestation,
    validate_skill_name, verify_installed_skill, InstalledSkillSelector, RegistryKind,
    SkillAddRequest, SkillError, SkillInstallOptions, SkillPublishRequest, SkillService,
    SkillsConfig, SkillsConfigOverride,
};
use ed25519_dalek::{Signer, SigningKey};

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
        signature_public_key_ed25519: None,
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
        signature_public_key_ed25519: None,
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

#[test]
fn signature_verification_accepts_signed_bundle() {
    let root = temp_dir("skill-signature-valid");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: signed-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();
    let digest = compute_bundle_digest(&root, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let payload = agentenv_core::skills::signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());

    agentenv_core::skills::verify_ed25519_signature(&manifest, &digest, &signature, &public_key)
        .expect("signature should verify");
}

#[test]
fn signature_verification_rejects_tampered_digest() {
    let root = temp_dir("skill-signature-tampered");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: signed-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();
    let digest = compute_bundle_digest(&root, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let payload = agentenv_core::skills::signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());

    let error = agentenv_core::skills::verify_ed25519_signature(
        &manifest,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &signature,
        &public_key,
    )
    .expect_err("tampered digest must fail");

    assert!(matches!(error, SkillError::InvalidSignature { .. }));
}

#[test]
fn signature_verification_rejects_extra_metadata_tamper() {
    let root = temp_dir("skill-signature-extra-tamper");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: signed-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\ncapability: safe\n",
    );
    let manifest = load_skill_manifest(&root).unwrap();
    let digest = compute_bundle_digest(&root, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
    let payload = agentenv_core::skills::signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let mut tampered = manifest.clone();
    tampered.extra.insert(
        "capability".to_owned(),
        serde_yaml::Value::String("unsafe".to_owned()),
    );

    let error = agentenv_core::skills::verify_ed25519_signature(
        &tampered,
        &digest,
        &signature,
        &public_key,
    )
    .expect_err("extra metadata tampering must fail signature verification");

    assert!(matches!(error, SkillError::InvalidSignature { .. }));
}

#[test]
fn local_install_writes_cache_and_index() {
    let home = temp_dir("skill-install-home");
    let bundle = temp_dir("skill-install-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: local-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .expect("install should succeed");

    assert_eq!(installed.name, "local-demo");
    assert_eq!(installed.version, "0.1.0");
    assert!(installed.path.join("content/SKILL.md").is_file());
    assert!(home.join(".agentenv/skills/index.yaml").is_file());
}

#[test]
fn local_install_rejects_missing_self_test() {
    let home = temp_dir("skill-install-missing-self-test-home");
    let bundle = temp_dir("skill-install-missing-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: missing-self-test-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: false,
        },
    )
    .expect_err("install without a self-test must fail");

    assert!(matches!(error, SkillError::MissingSelfTest));
    assert!(!home
        .join(".agentenv/skills/missing-self-test-demo/0.1.0")
        .exists());
}

#[test]
fn local_install_accepts_passing_self_test_and_records_score() {
    let home = temp_dir("skill-install-passing-self-test-home");
    let bundle = temp_dir("skill-install-passing-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: passing-self-test-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );

    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: false,
        },
    )
    .expect("passing self-test should install");

    assert_eq!(installed.self_test_score, Some(1.0));
    assert!(installed.self_test_attestation.is_some());
    assert!(installed.self_test_attestation.as_ref().unwrap().is_file());
}

#[test]
fn local_reinstall_same_digest_keeps_existing_record() {
    let home = temp_dir("skill-install-idempotent-home");
    let bundle = temp_dir("skill-install-idempotent-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: idempotent-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let first = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "first-source".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();

    let second = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "second-source".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();

    assert_eq!(second.source_label, "first-source");
    assert_eq!(second.installed_at, first.installed_at);
}

#[test]
fn local_reinstall_reruns_self_test_when_digest_matches() {
    let home = temp_dir("skill-install-rerun-self-test-home");
    let bundle = temp_dir("skill-install-rerun-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );
    write_file(
        &bundle.join("skill.yaml"),
        "name: rerun-self-test-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: false,
        },
    )
    .expect("initial passing self-test should install");
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: missing.md\n",
    );

    let error = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: false,
        },
    )
    .expect_err("same-digest reinstall must rerun the current self-test");

    assert!(matches!(
        error,
        SkillError::SelfTestScoreBelowThreshold { .. }
    ));
}

#[test]
fn local_reinstall_repairs_tampered_cached_content() {
    let home = temp_dir("skill-install-repair-home");
    let bundle = temp_dir("skill-install-repair-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );
    write_file(
        &bundle.join("skill.yaml"),
        "name: repair-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    write_file(&installed.path.join("content/SKILL.md"), "# Tampered\n");

    install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .expect("reinstall should repair tampered same-digest cache");

    let verified = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("repair-demo".to_owned()),
    )
    .expect("repaired cache should verify");
    assert_eq!(verified.name, "repair-demo");
}

#[cfg(unix)]
#[test]
fn local_reinstall_rejects_symlinked_existing_version_directory() {
    let home = temp_dir("skill-install-existing-symlink-home");
    let bundle = temp_dir("skill-install-existing-symlink-bundle");
    let outside = temp_dir("skill-install-existing-symlink-outside");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: existing-symlink-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    write_file(
        &outside.join("installed.yaml"),
        &format!(
            "name: existing-symlink-demo\nversion: 0.1.0\nsource_type: local\nsource_label: outside\ndigest: {digest}\nsignature_status: unsigned\nentry: content/SKILL.md\ninstalled_at: \"2026-05-08T00:00:00Z\"\npath: ignored\n"
        ),
    );
    let version_parent = home.join(".agentenv/skills/existing-symlink-demo");
    fs::create_dir_all(&version_parent).unwrap();
    std::os::unix::fs::symlink(&outside, version_parent.join("0.1.0")).unwrap();

    let error = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .expect_err("reinstall must reject symlinked existing install dirs");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[cfg(unix)]
#[test]
fn local_reinstall_rejects_symlinked_cached_content_directory() {
    let home = temp_dir("skill-install-content-symlink-home");
    let bundle = temp_dir("skill-install-content-symlink-bundle");
    let outside = temp_dir("skill-install-content-symlink-outside");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: content-symlink-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    write_file(&outside.join("SKILL.md"), "# Demo\n");
    fs::remove_dir_all(installed.path.join("content")).unwrap();
    std::os::unix::fs::symlink(&outside, installed.path.join("content")).unwrap();

    let error = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .expect_err("reinstall must reject symlinked cached content dirs");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[cfg(unix)]
#[test]
fn local_reinstall_rejects_symlinked_cached_content_with_missing_files() {
    let home = temp_dir("skill-install-content-symlink-missing-home");
    let bundle = temp_dir("skill-install-content-symlink-missing-bundle");
    let outside = temp_dir("skill-install-content-symlink-missing-outside");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: content-symlink-missing-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    fs::remove_dir_all(installed.path.join("content")).unwrap();
    std::os::unix::fs::symlink(&outside, installed.path.join("content")).unwrap();

    let error = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .expect_err("broken symlinked content dirs must be rejected before repair");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn local_install_treats_manifest_public_key_as_untrusted() {
    let home = temp_dir("skill-install-untrusted-manifest-key-home");
    let bundle = temp_dir("skill-install-untrusted-manifest-key-bundle");
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        &format!(
            "name: untrusted-key-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nsignatures:\n  ed25519: {}\n  public_key_ed25519: {}\n",
            "00".repeat(64),
            public_key
        ),
    );

    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .expect("self-supplied keys should not be treated as trusted signatures");

    assert_eq!(installed.signature_status, "unsigned");
}

#[test]
fn installed_verify_detects_content_tampering() {
    let home = temp_dir("skill-verify-home");
    let bundle = temp_dir("skill-verify-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: verify-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    write_file(&installed.path.join("content/SKILL.md"), "# Tampered\n");

    let error = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("verify-demo".to_owned()),
    )
    .expect_err("tampering must fail");

    assert!(matches!(error, SkillError::DigestMismatch { .. }));
}

#[test]
fn installed_verify_rejects_signed_record_without_public_key() {
    let home = temp_dir("skill-verify-missing-public-key-home");
    let bundle = temp_dir("skill-verify-missing-public-key-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: missing-public-key-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nsignatures:\n  ed25519: abcd\n",
    );
    let mut installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    installed.signature_status = "signed".to_owned();
    write_file(
        &installed.path.join("installed.yaml"),
        &serde_yaml::to_string(&installed).unwrap(),
    );

    let error = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("missing-public-key-demo".to_owned()),
    )
    .expect_err("signed records without public keys must fail verification");

    assert!(matches!(error, SkillError::MissingSignature { .. }));
}

#[cfg(unix)]
#[test]
fn installed_verify_rejects_symlinked_cached_content_directory() {
    let home = temp_dir("skill-verify-content-symlink-home");
    let bundle = temp_dir("skill-verify-content-symlink-bundle");
    let outside = temp_dir("skill-verify-content-symlink-outside");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: verify-content-symlink-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    write_file(&outside.join("SKILL.md"), "# Demo\n");
    fs::remove_dir_all(installed.path.join("content")).unwrap();
    std::os::unix::fs::symlink(&outside, installed.path.join("content")).unwrap();

    let error = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("verify-content-symlink-demo".to_owned()),
    )
    .expect_err("verify must reject symlinked cached content dirs");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn installed_verify_rejects_record_entry_tamper() {
    let home = temp_dir("skill-verify-entry-tamper-home");
    let bundle = temp_dir("skill-verify-entry-tamper-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: entry-tamper-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let mut installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    installed.entry = PathBuf::from("content/OTHER.md");
    write_file(
        &installed.path.join("installed.yaml"),
        &serde_yaml::to_string(&installed).unwrap(),
    );

    let error = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("entry-tamper-demo".to_owned()),
    )
    .expect_err("verify must reject installed record entry tampering");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn installed_verify_rejects_signature_status_downgrade() {
    let home = temp_dir("skill-verify-signature-downgrade-home");
    let bundle = temp_dir("skill-verify-signature-downgrade-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );
    write_file(
        &bundle.join("skill.yaml"),
        "name: signature-downgrade-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
    let payload = agentenv_core::skills::signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    write_file(
        &bundle.join("skill.yaml"),
        &format!(
            "name: signature-downgrade-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nsignatures:\n  ed25519: {signature}\n  public_key_ed25519: {public_key}\n"
        ),
    );
    let mut installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    installed.signature_status = "signed".to_owned();
    installed.signature_public_key_ed25519 = Some(public_key);
    write_file(
        &installed.path.join("installed.yaml"),
        &serde_yaml::to_string(&installed).unwrap(),
    );
    verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("signature-downgrade-demo".to_owned()),
    )
    .expect("trusted signed record should verify");

    installed.signature_status = "unsigned".to_owned();
    installed.signature_public_key_ed25519 = None;
    write_file(
        &installed.path.join("installed.yaml"),
        &serde_yaml::to_string(&installed).unwrap(),
    );

    let error = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("signature-downgrade-demo".to_owned()),
    )
    .expect_err("record edits must not downgrade signed manifests to unsigned");

    assert!(matches!(error, SkillError::MissingSignature { .. }));
}

#[cfg(unix)]
#[test]
fn installed_index_rejects_symlinked_version_directory() {
    let home = temp_dir("skill-index-symlink-home");
    let outside = temp_dir("skill-index-symlink-outside");
    let installed_yaml = r#"name: linked-demo
version: 0.1.0
source_type: local
source_label: outside
digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
signature_status: unsigned
entry: content/SKILL.md
installed_at: "2026-05-08T00:00:00Z"
path: ignored
"#;
    write_file(&outside.join("installed.yaml"), installed_yaml);
    let version_parent = home.join(".agentenv/skills/linked-demo");
    fs::create_dir_all(&version_parent).unwrap();
    std::os::unix::fs::symlink(&outside, version_parent.join("0.1.0")).unwrap();

    let error = list_installed_skills(home.join(".agentenv"))
        .expect_err("store symlinked version directories must be rejected");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn installed_index_ignores_stale_staging_directories() {
    let home = temp_dir("skill-index-stale-staging-home");
    let bundle = temp_dir("skill-index-stale-staging-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: stale-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();
    let stale_dir = installed.path.parent().unwrap().join(".0.1.0.backup-test");
    fs::create_dir_all(&stale_dir).unwrap();
    write_file(
        &stale_dir.join("installed.yaml"),
        &serde_yaml::to_string(&installed).unwrap(),
    );

    let installed = list_installed_skills(home.join(".agentenv")).unwrap();

    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].name, "stale-demo");
}

#[test]
fn installed_verify_runs_self_test_command() {
    let home = temp_dir("skill-self-test-home");
    let bundle = temp_dir("skill-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        &format!(
            "name: self-test-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: {:?}\n",
            self_test_file_exists_command()
        ),
    );
    install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: true,
        },
    )
    .unwrap();

    let verified = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("self-test-demo".to_owned()),
    )
    .expect("self-test command should pass");

    assert_eq!(verified.name, "self-test-demo");
}

#[test]
fn installed_verify_runs_structured_skill_yaml_self_test() {
    let home = temp_dir("skill-verify-structured-skill-yaml-home");
    let bundle = temp_dir("skill-verify-structured-skill-yaml-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        r#"name: structured-skill-yaml-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
"#,
    );
    install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_type: "local".to_owned(),
            source_label: "local-dev".to_owned(),
            unsafe_skip_self_test_gate: false,
        },
    )
    .expect("structured skill.yaml self-test should install");

    let verified = verify_installed_skill(
        home.join(".agentenv"),
        InstalledSkillSelector::Name("structured-skill-yaml-demo".to_owned()),
    )
    .expect("structured skill.yaml self-test should verify");

    assert_eq!(verified.self_test_score, Some(1.0));
    assert!(verified.self_test_attestation.is_some());
}

#[test]
fn skills_config_loads_project_yaml_section() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox: { driver: openshell }
agent: { driver: codex }
context: { driver: filesystem, mount: . }
policy: { tier: balanced, presets: [] }
skills:
  registries:
    - name: local-dev
      type: filesystem
      path: /tmp/skills
"#;

    let config = load_project_skills_config(yaml).unwrap();

    assert_eq!(config.registries.len(), 1);
    assert_eq!(config.registries[0].name, "local-dev");
    assert_eq!(config.registries[0].kind, RegistryKind::Filesystem);
}

#[test]
fn skills_config_loads_user_toml() {
    let toml = r#"
[skills]
registry_order = ["corp"]

[[skills.registries]]
name = "corp"
type = "http"
url = "https://skills.example.test"
auth = "bearer-from-credstore:CORP_SKILLS_TOKEN"
"#;

    let config = load_user_skills_config(toml).unwrap();

    assert_eq!(config.registry_order, vec!["corp"]);
    assert_eq!(
        config.registries[0].auth.as_deref(),
        Some("bearer-from-credstore:CORP_SKILLS_TOKEN")
    );
}

#[test]
fn skills_config_loads_git_registry_from_project_yaml() {
    let yaml = r#"
skills:
  registries:
    - name: git-dev
      type: git
      url: git+https://github.com/acme/skills
"#;

    let config = load_project_skills_config(yaml).unwrap();

    assert_eq!(config.registries[0].name, "git-dev");
    assert_eq!(config.registries[0].kind, RegistryKind::Git);
    assert_eq!(
        config.registries[0].url.as_deref(),
        Some("git+https://github.com/acme/skills")
    );
}

#[test]
fn skills_config_loads_git_registry_from_user_toml() {
    let toml = r#"
[[skills.registries]]
name = "git-dev"
type = "git"
url = "git+https://github.com/acme/skills"
"#;

    let config = load_user_skills_config(toml).unwrap();

    assert_eq!(config.registries[0].kind, RegistryKind::Git);
}

#[test]
fn cli_registry_override_parses_git_source() {
    let merged = merge_skills_config(
        SkillsConfig::default(),
        None,
        SkillsConfigOverride {
            registry: Some("git+https://github.com/acme/skills".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries[0].name, "cli");
    assert_eq!(merged.registries[0].kind, RegistryKind::Git);
    assert_eq!(merged.registry_order, vec!["cli"]);
}

#[test]
fn skills_config_rejects_unsafe_git_registry_urls() {
    for url in [
        "https://github.com/acme/skills",
        "git+ssh://github.com/acme/skills",
        "git+https://user:pass@github.com/acme/skills",
        "git+https://github.com/acme/skills?branch=main",
        "git+https://github.com/acme/skills#main",
    ] {
        let yaml = format!(
            "skills:\n  registries:\n    - name: git-dev\n      type: git\n      url: {url}\n"
        );

        let error = load_project_skills_config(&yaml)
            .expect_err("unsafe git registry URL must be rejected");

        assert!(matches!(error, SkillError::InvalidConfig { .. }));
    }
}

#[test]
fn cli_registry_override_wins_over_project_and_user_config() {
    let user = SkillsConfig {
        registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
            "user-local",
            PathBuf::from("/user"),
        )],
        registry_order: vec!["user-local".to_owned()],
    };
    let project = SkillsConfig {
        registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
            "project-local",
            PathBuf::from("/project"),
        )],
        registry_order: vec!["project-local".to_owned()],
    };

    let merged = merge_skills_config(
        user,
        Some(project),
        SkillsConfigOverride {
            registry: Some("file:///override".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries.len(), 1);
    assert_eq!(merged.registries[0].name, "cli");
    assert_eq!(merged.registry_order, vec!["cli"]);
}

#[test]
fn cli_registry_override_selects_named_registry() {
    let user = SkillsConfig {
        registries: vec![
            agentenv_core::skills::RegistryConfig::filesystem("local", PathBuf::from("/local")),
            agentenv_core::skills::RegistryConfig::http(
                "corp",
                "https://skills.example.test",
                None,
            ),
        ],
        registry_order: vec!["local".to_owned(), "corp".to_owned()],
    };

    let merged = merge_skills_config(
        user,
        None,
        SkillsConfigOverride {
            registry: Some("corp".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries.len(), 1);
    assert_eq!(merged.registries[0].name, "corp");
    assert_eq!(merged.registry_order, vec!["corp"]);
}

#[test]
fn project_config_overrides_user_registries_by_name_without_erasing_others() {
    let user = SkillsConfig {
        registries: vec![
            agentenv_core::skills::RegistryConfig::filesystem("local", PathBuf::from("/user")),
            agentenv_core::skills::RegistryConfig::http(
                "corp",
                "https://skills.example.test",
                None,
            ),
        ],
        registry_order: vec!["local".to_owned(), "corp".to_owned()],
    };
    let project = SkillsConfig {
        registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
            "local",
            PathBuf::from("/project"),
        )],
        registry_order: vec!["local".to_owned()],
    };

    let merged = merge_skills_config(
        user,
        Some(project),
        SkillsConfigOverride {
            registry: Some("corp".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries.len(), 1);
    assert_eq!(merged.registries[0].name, "corp");
}

#[test]
fn cli_registry_override_reports_missing_named_registry() {
    let user = SkillsConfig {
        registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
            "local",
            PathBuf::from("/local"),
        )],
        registry_order: vec!["local".to_owned()],
    };

    let error = merge_skills_config(
        user,
        None,
        SkillsConfigOverride {
            registry: Some("corp".to_owned()),
        },
    )
    .expect_err("missing named registry must be reported");

    assert!(matches!(error, SkillError::RegistryNotFound { name } if name == "corp"));
}

#[test]
fn cli_registry_override_parses_http_and_oci_sources() {
    let http = merge_skills_config(
        SkillsConfig::default(),
        None,
        SkillsConfigOverride {
            registry: Some("https://skills.example.test".to_owned()),
        },
    )
    .unwrap();
    let oci = merge_skills_config(
        SkillsConfig::default(),
        None,
        SkillsConfigOverride {
            registry: Some("oci://ghcr.io/agentenv-community".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(http.registries[0].kind, RegistryKind::Http);
    assert_eq!(oci.registries[0].kind, RegistryKind::Oci);
}

#[test]
fn cli_registry_override_parses_bare_oci_reference() {
    let merged = merge_skills_config(
        SkillsConfig::default(),
        None,
        SkillsConfigOverride {
            registry: Some("ghcr.io/agentenv-community".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries[0].kind, RegistryKind::Oci);
    assert_eq!(
        merged.registries[0].url.as_deref(),
        Some("ghcr.io/agentenv-community")
    );
}

#[test]
fn cli_registry_override_parses_bare_oci_reference_with_port() {
    let merged = merge_skills_config(
        SkillsConfig::default(),
        None,
        SkillsConfigOverride {
            registry: Some("ghcr.io:5000/agentenv-community".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(merged.registries[0].kind, RegistryKind::Oci);
    assert_eq!(
        merged.registries[0].url.as_deref(),
        Some("ghcr.io:5000/agentenv-community")
    );
}

#[test]
fn skills_config_rejects_missing_required_registry_fields() {
    let yaml = r#"
skills:
  registries:
    - name: missing-url
      type: http
"#;

    let error = load_project_skills_config(yaml).expect_err("http registry requires url");

    assert!(matches!(error, SkillError::InvalidConfig { .. }));
}

#[test]
fn skills_config_rejects_invalid_http_registry_url() {
    let yaml = r#"
skills:
  registries:
    - name: bad-http
      type: http
      url: ftp://skills.example.test
"#;

    let error = load_project_skills_config(yaml).expect_err("http URL scheme must be validated");

    assert!(matches!(error, SkillError::InvalidConfig { .. }));
}

#[test]
fn skills_config_rejects_invalid_oci_registry_reference() {
    let yaml = r#"
skills:
  registries:
    - name: bad-oci
      type: oci
      url: not-a-reference
"#;

    let error = load_project_skills_config(yaml).expect_err("OCI reference must be validated");

    assert!(matches!(error, SkillError::InvalidConfig { .. }));
}

#[test]
fn skills_config_rejects_oci_reference_with_invalid_parts() {
    for reference in [
        "ghcr.io/bad$path",
        "oci://user:pass@ghcr.io/agentenv-community",
        "oci://ghcr.io/agentenv-community?tag=latest",
        "oci://ghcr.io/agentenv-community#frag",
        "ghcr.io:abc/agentenv-community",
        "ghcr.io:5000:extra/agentenv-community",
    ] {
        let error = merge_skills_config(
            SkillsConfig::default(),
            None,
            SkillsConfigOverride {
                registry: Some(reference.to_owned()),
            },
        )
        .expect_err(reference);

        assert!(matches!(error, SkillError::InvalidConfig { .. }));
    }
}

#[tokio::test]
async fn filesystem_registry_search_add_and_publish_work() {
    let home = temp_dir("skill-fs-home");
    let registry = temp_dir("skill-fs-registry");
    let bundle = skill_bundle("searchable-skill", "0.1.0", "Searchable demo");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
                "local-dev",
                registry.clone(),
            )],
            registry_order: vec!["local-dev".to_owned()],
        },
    );

    service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should succeed");
    let hits = service
        .search("searchable")
        .await
        .expect("search should work");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "searchable-skill");

    let installed = service
        .add(SkillAddRequest {
            handle: "searchable-skill@0.1.0".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should install");

    assert_eq!(installed.name, "searchable-skill");
}

#[tokio::test]
async fn skill_service_publish_rejects_missing_self_test() {
    let home = temp_dir("skill-fs-publish-missing-self-test-home");
    let registry = temp_dir("skill-fs-publish-missing-self-test-registry");
    let bundle = temp_dir("skill-fs-publish-missing-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Missing self-test\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: missing-self-test\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let service = filesystem_skill_service(&home, &registry);

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect_err("publish must reject bundles without a self-test");

    assert!(matches!(error, SkillError::MissingSelfTest));
    assert!(service
        .search("missing-self-test")
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn skill_service_publish_checks_signature_before_self_test() {
    let home = temp_dir("skill-fs-publish-signature-before-self-test-home");
    let registry = temp_dir("skill-fs-publish-signature-before-self-test-registry");
    let bundle = temp_dir("skill-fs-publish-signature-before-self-test-bundle");
    write_file(&bundle.join("SKILL.md"), "# Unsigned publish\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: unsigned-publish-order\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: touch self-test-ran\n",
    );
    let service = filesystem_skill_service(&home, &registry);

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: bundle.clone(),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: false,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect_err("publish must reject unsigned bundles before running self-tests");

    assert!(matches!(error, SkillError::MissingSignature { .. }));
    assert!(!bundle.join("self-test-ran").exists());
}

#[tokio::test]
async fn skill_service_add_checks_signature_before_self_test() {
    let home = temp_dir("skill-fs-add-signature-before-self-test-home");
    let registry = temp_dir("skill-fs-add-signature-before-self-test-registry");
    write_file(
        &registry.join("unsigned-add-order/skill.yaml"),
        "name: unsigned-add-order\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: false\n",
    );
    write_file(
        &registry.join("unsigned-add-order/SKILL.md"),
        "# Unsigned add\n",
    );
    let service = filesystem_skill_service(&home, &registry);

    let error = service
        .add(SkillAddRequest {
            handle: "unsigned-add-order@0.1.0".to_owned(),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: false,
            self_test_attestation: None,
        })
        .await
        .expect_err("add must reject unsigned bundles before running self-tests");

    assert!(matches!(error, SkillError::MissingSignature { .. }));
    assert!(service.list().unwrap().is_empty());
}

#[tokio::test]
async fn skill_service_publish_rejects_low_self_test_score() {
    let home = temp_dir("skill-fs-publish-low-score-home");
    let registry = temp_dir("skill-fs-publish-low-score-registry");
    let bundle = temp_dir("skill-fs-publish-low-score-bundle");
    write_file(&bundle.join("SKILL.md"), "# Low score\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: low-score-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n    - type: file_exists\n      path: missing.txt\n  timeout_seconds: 5\n",
    );
    let service = filesystem_skill_service(&home, &registry);

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect_err("publish must reject scores below the threshold");

    assert!(matches!(
        error,
        SkillError::SelfTestScoreBelowThreshold {
            score,
            threshold
        } if (score - 0.5).abs() < f64::EPSILON && (threshold - 0.8).abs() < f64::EPSILON
    ));
    assert!(service.search("low-score-skill").await.unwrap().is_empty());
}

#[tokio::test]
async fn skill_service_publish_no_self_test_run_requires_attestation() {
    let home = temp_dir("skill-fs-publish-attestation-required-home");
    let registry = temp_dir("skill-fs-publish-attestation-required-registry");
    let service = filesystem_skill_service(&home, &registry);

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("attestation-required", "0.1.0", "Attestation required"),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: true,
        })
        .await
        .expect_err("publish without running a self-test must require an attestation");

    assert!(matches!(error, SkillError::MissingSelfTestAttestation));
}

#[tokio::test]
async fn filesystem_registry_publish_stores_self_test_attestation() {
    let home = temp_dir("skill-fs-publish-attestation-home");
    let registry = temp_dir("skill-fs-publish-attestation-registry");
    let service = filesystem_skill_service(&home, &registry);

    let hit = service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("attested-skill", "0.1.0", "Attested"),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should store the generated self-test attestation");

    assert_eq!(hit.self_test_score, Some(1.0));
    assert!(hit.self_test_attestation_digest.is_some());
    let attestation_path = registry.join("bundles/attested-skill/0.1.0/self-test-attestation.json");
    let attestation = read_self_test_attestation(&attestation_path).unwrap();
    assert_eq!(attestation.subject.name, "attested-skill");
    assert_eq!(attestation.subject.version, "0.1.0");
    assert_eq!(
        hit.self_test_attestation_digest.as_deref(),
        Some(attestation.self_test_digest.as_str())
    );
}

#[tokio::test]
async fn filesystem_registry_publish_and_add_preserves_skill_test_yaml() {
    let home = temp_dir("skill-fs-publish-skill-test-file-home");
    let registry = temp_dir("skill-fs-publish-skill-test-file-registry");
    let service = filesystem_skill_service(&home, &registry);
    let bundle = skill_test_file_bundle("file-backed-self-test", "0.1.0", "File-backed self-test");

    service
        .publish(SkillPublishRequest {
            bundle_path: bundle.clone(),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should accept skill-test.yaml backed self-tests");

    assert!(registry
        .join("bundles/file-backed-self-test/0.1.0/skill-test.yaml")
        .is_file());

    let updated_skill_test = "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n  timeout_seconds: 5\n";
    write_file(&bundle.join("skill-test.yaml"), updated_skill_test);
    service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("republishing the same digest should refresh undeclared self-test files");
    let stored_skill_test =
        fs::read_to_string(registry.join("bundles/file-backed-self-test/0.1.0/skill-test.yaml"))
            .unwrap();
    assert_eq!(stored_skill_test, updated_skill_test);

    let installed = service
        .add(SkillAddRequest {
            handle: "file-backed-self-test@0.1.0".to_owned(),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should rerun the preserved skill-test.yaml");

    assert_eq!(installed.self_test_score, Some(1.0));
    assert!(installed.path.join("content/skill-test.yaml").is_file());
}

#[tokio::test]
async fn filesystem_registry_search_scans_skill_subdirectories_without_index() {
    let home = temp_dir("skill-fs-scan-home");
    let registry = temp_dir("skill-fs-scan-registry");
    write_file(
        &registry.join("scan-skill/skill.yaml"),
        "name: scan-skill\nversion: 0.2.0\ndescription: Scan demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(&registry.join("scan-skill/SKILL.md"), "# Scan demo\n");
    let service = filesystem_skill_service(&home, &registry);

    let hits = service.search("scan").await.expect("search should scan");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "scan-skill");
    assert_eq!(hits[0].version, "0.2.0");
    assert_eq!(hits[0].registry, "local-dev");
}

#[cfg(unix)]
#[tokio::test]
async fn filesystem_registry_scan_ignores_symlinked_manifest_files() {
    let home = temp_dir("skill-fs-scan-symlink-manifest-home");
    let registry = temp_dir("skill-fs-scan-symlink-manifest-registry");
    let outside = temp_dir("skill-fs-scan-symlink-manifest-outside");
    fs::create_dir_all(registry.join("linked-manifest")).unwrap();
    write_file(
        &outside.join("skill.yaml"),
        "name: linked-manifest\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    std::os::unix::fs::symlink(
        outside.join("skill.yaml"),
        registry.join("linked-manifest/skill.yaml"),
    )
    .unwrap();
    write_file(&registry.join("linked-manifest/SKILL.md"), "# Linked\n");
    let service = filesystem_skill_service(&home, &registry);

    let hits = service
        .search("linked")
        .await
        .expect("symlinked manifests should be skipped during scan");

    assert!(hits.is_empty());
}

#[tokio::test]
async fn filesystem_registry_add_uses_scanned_subdirectory_without_index() {
    let home = temp_dir("skill-fs-scan-add-home");
    let registry = temp_dir("skill-fs-scan-add-registry");
    write_file(
        &registry.join("scan-add/skill.yaml"),
        "name: scan-add\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n",
    );
    write_file(&registry.join("scan-add/SKILL.md"), "# Scan add\n");
    let service = filesystem_skill_service(&home, &registry);

    let installed = service
        .add(SkillAddRequest {
            handle: "scan-add".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should use scanned directory");

    assert_eq!(installed.name, "scan-add");
    assert_eq!(
        installed.source_label,
        "filesystem:local-dev:scan-add@0.1.0"
    );
}

#[tokio::test]
async fn filesystem_registry_publish_keeps_scanned_subdirectories_ephemeral() {
    let home = temp_dir("skill-fs-scan-ephemeral-home");
    let registry = temp_dir("skill-fs-scan-ephemeral-registry");
    write_file(
        &registry.join("scan-live/skill.yaml"),
        "name: scan-live\nversion: 0.1.0\ndescription: Before publish\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(&registry.join("scan-live/SKILL.md"), "# Scan live\n");
    let service = filesystem_skill_service(&home, &registry);

    service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("published-skill", "0.1.0", "Published"),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should succeed");

    write_file(
        &registry.join("scan-live/skill.yaml"),
        "name: scan-live\nversion: 0.1.0\ndescription: After publish\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let hits = service
        .search("After publish")
        .await
        .expect("search should use live scanned metadata");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "scan-live");
    let index = fs::read_to_string(registry.join("index.yaml")).unwrap();
    assert!(!index.contains("scan-live"));
}

#[tokio::test]
async fn filesystem_registry_rejects_duplicate_scanned_skill_versions() {
    let home = temp_dir("skill-fs-scan-duplicate-home");
    let registry = temp_dir("skill-fs-scan-duplicate-registry");
    write_file(
        &registry.join("first/skill.yaml"),
        "name: duplicate-scan\nversion: 0.1.0\ndescription: First duplicate\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(&registry.join("first/SKILL.md"), "# First duplicate\n");
    write_file(
        &registry.join("second/skill.yaml"),
        "name: duplicate-scan\nversion: 0.1.0\ndescription: Second duplicate\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(&registry.join("second/SKILL.md"), "# Second duplicate\n");
    let service = filesystem_skill_service(&home, &registry);

    let error = service
        .search("duplicate")
        .await
        .expect_err("duplicate scanned skill versions must be rejected");

    assert!(matches!(&error, SkillError::InvalidConfig { message }
            if message.contains("duplicate-scan") && message.contains("0.1.0")));
}

#[tokio::test]
async fn filesystem_registry_fetch_does_not_fallback_to_shadowed_scanned_directory() {
    let home = temp_dir("skill-fs-shadow-home");
    let registry = temp_dir("skill-fs-shadow-registry");
    write_file(
        &registry.join("index.yaml"),
        "skills:\n  - name: shadowed-skill\n    version: 0.1.0\n    registry: local-dev\n",
    );
    write_file(
        &registry.join("dev-copy/skill.yaml"),
        "name: shadowed-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &registry.join("dev-copy/SKILL.md"),
        "# Should not install\n",
    );
    let service = filesystem_skill_service(&home, &registry);

    let error = service
        .add(SkillAddRequest {
            handle: "shadowed-skill@0.1.0".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("indexed hit with missing bundle must not fall back to scanned directory");

    assert!(matches!(error, SkillError::SkillNotInstalled { name } if name == "shadowed-skill"));
    assert!(service.list().unwrap().is_empty());
}

#[tokio::test]
async fn skill_service_add_without_version_installs_highest_semver() {
    let home = temp_dir("skill-fs-highest-home");
    let registry = temp_dir("skill-fs-highest-registry");
    let service = filesystem_skill_service(&home, &registry);

    publish_test_skill(&service, "versioned-skill", "0.1.0", "Old release").await;
    publish_test_skill(&service, "versioned-skill", "0.3.0", "New release").await;
    publish_test_skill(&service, "versioned-skill", "0.2.0", "Middle release").await;

    let installed = service
        .add(SkillAddRequest {
            handle: "versioned-skill".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add without version should install highest semver");

    assert_eq!(installed.version, "0.3.0");
}

#[tokio::test]
async fn skill_service_rejects_invalid_handle_before_registry_access() {
    let home = temp_dir("skill-fs-invalid-handle-home");
    let missing_registry = temp_dir("skill-fs-invalid-handle-missing-registry").join("missing");
    let service = filesystem_skill_service(&home, &missing_registry);

    let error = service
        .add(SkillAddRequest {
            handle: "../bad@0.1.0".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("invalid handles must fail before registry access");

    assert!(matches!(error, SkillError::InvalidSkillName { .. }));
}

#[tokio::test]
async fn filesystem_registry_refuses_same_version_with_different_digest() {
    let home = temp_dir("skill-fs-overwrite-home");
    let registry = temp_dir("skill-fs-overwrite-registry");
    let service = filesystem_skill_service(&home, &registry);
    publish_test_skill(&service, "overwrite-skill", "0.1.0", "First content").await;

    let changed = skill_bundle("overwrite-skill", "0.1.0", "Changed content");
    let error = service
        .publish(SkillPublishRequest {
            bundle_path: changed,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect_err("publishing a different digest over the same version must fail");

    assert!(matches!(
        error,
        SkillError::AlreadyInstalledDifferentDigest {
            name,
            version,
            ..
        } if name == "overwrite-skill" && version == "0.1.0"
    ));
}

#[tokio::test]
async fn skill_service_publish_uses_first_ordered_registry_when_unspecified() {
    let home = temp_dir("skill-fs-publish-default-home");
    let registry = temp_dir("skill-fs-publish-default-registry");
    let service = filesystem_skill_service(&home, &registry);

    let published = service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("default-registry-skill", "0.1.0", "Default registry"),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish without registry should use configured registry order");

    assert_eq!(published.registry, "local-dev");
    assert!(registry
        .join("bundles/default-registry-skill/0.1.0/SKILL.md")
        .is_file());
}

#[tokio::test]
async fn filesystem_registry_rejects_index_hit_with_mismatched_manifest_identity() {
    let home = temp_dir("skill-fs-mismatched-manifest-home");
    let registry = temp_dir("skill-fs-mismatched-manifest-registry");
    let service = filesystem_skill_service(&home, &registry);
    write_file(
        &registry.join("index.yaml"),
        "skills:\n  - name: requested-skill\n    version: 0.1.0\n    registry: local-dev\n",
    );
    write_file(
        &registry.join("bundles/requested-skill/0.1.0/SKILL.md"),
        "# Other skill\n",
    );
    write_file(
        &registry.join("bundles/requested-skill/0.1.0/skill.yaml"),
        "name: other-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = service
        .add(SkillAddRequest {
            handle: "requested-skill@0.1.0".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("index identity must match fetched manifest identity");

    assert!(matches!(
        error,
        SkillError::UnsafeBundlePath { .. } | SkillError::InvalidConfig { .. }
    ));
    assert!(service.list().unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn filesystem_registry_rejects_symlinked_bundles_directory() {
    let home = temp_dir("skill-fs-symlink-bundles-home");
    let registry = temp_dir("skill-fs-symlink-bundles-registry");
    let outside = temp_dir("skill-fs-symlink-bundles-outside");
    let service = filesystem_skill_service(&home, &registry);
    write_file(
        &registry.join("index.yaml"),
        "skills:\n  - name: symlinked-skill\n    version: 0.1.0\n    registry: local-dev\n",
    );
    std::os::unix::fs::symlink(&outside, registry.join("bundles")).unwrap();
    write_file(
        &outside.join("symlinked-skill/0.1.0/SKILL.md"),
        "# Symlinked skill\n",
    );
    write_file(
        &outside.join("symlinked-skill/0.1.0/skill.yaml"),
        "name: symlinked-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = service
        .add(SkillAddRequest {
            handle: "symlinked-skill@0.1.0".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("symlinked registry bundle parents must be rejected");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[tokio::test]
async fn filesystem_registry_publish_repairs_stale_index_without_bundle() {
    let home = temp_dir("skill-fs-stale-index-home");
    let registry = temp_dir("skill-fs-stale-index-registry");
    let service = filesystem_skill_service(&home, &registry);
    let bundle = skill_bundle("stale-index-skill", "0.1.0", "Stale index");
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    write_file(
        &registry.join("index.yaml"),
        &format!(
            "skills:\n  - name: stale-index-skill\n    version: 0.1.0\n    registry: local-dev\n    digest: {digest}\n"
        ),
    );

    service
        .publish(SkillPublishRequest {
            bundle_path: bundle,
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should repair stale index entries whose bundle is missing");

    assert!(registry
        .join("bundles/stale-index-skill/0.1.0/SKILL.md")
        .is_file());
}

#[tokio::test]
async fn skill_service_add_records_registry_source_with_resolved_version() {
    let home = temp_dir("skill-fs-provenance-home");
    let registry = temp_dir("skill-fs-provenance-registry");
    let service = filesystem_skill_service(&home, &registry);
    publish_test_skill(&service, "provenance-skill", "0.1.0", "Old release").await;
    publish_test_skill(&service, "provenance-skill", "0.4.0", "New release").await;

    let installed = service
        .add(SkillAddRequest {
            handle: "provenance-skill".to_owned(),
            registry: None,
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should install from registry");

    assert_eq!(installed.version, "0.4.0");
    assert_eq!(installed.source_type, "filesystem");
    assert_eq!(
        installed.source_label,
        "filesystem:local-dev:provenance-skill@0.4.0"
    );
}

#[tokio::test]
async fn http_registry_rejects_unsafe_url_before_request() {
    let home = temp_dir("skill-http-unsafe-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::http(
                "unsafe",
                "http://127.0.0.1:9",
                None,
            )],
            registry_order: vec!["unsafe".to_owned()],
        },
    );

    let error = service
        .search("demo")
        .await
        .expect_err("loopback URL must be blocked");

    assert!(matches!(error, SkillError::RegistryUrlBlocked { .. }));
}

#[tokio::test]
async fn http_registry_search_reads_static_index() {
    let server = TestHttpRegistry::start().await;
    server
        .add_response(
            "GET",
            "/index.yaml",
            "skills:\n  - name: http-demo\n    version: 0.1.0\n    description: HTTP demo\n    registry: ignored\n",
        )
        .await;
    let home = temp_dir("skill-http-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let hits = service.search("http").await.expect("search should succeed");

    assert_eq!(hits[0].name, "http-demo");
    assert_eq!(hits[0].registry, "http-dev");
}

#[tokio::test]
async fn http_registry_search_prefers_index_json() {
    let server = TestHttpRegistry::start().await;
    server
        .add_response(
            "GET",
            "/index.json",
            r#"{"skills":[{"name":"json-demo","version":"0.1.0","description":"JSON demo","registry":"ignored","digest":null,"signature_ed25519":null,"public_key_ed25519":null}]}"#,
        )
        .await;
    server
        .add_response(
            "GET",
            "/index.yaml",
            "skills:\n  - name: yaml-demo\n    version: 0.1.0\n    registry: ignored\n",
        )
        .await;
    let home = temp_dir("skill-http-json-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let hits = service
        .search("demo")
        .await
        .expect("search should use JSON");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "json-demo");
    assert_eq!(hits[0].registry, "http-dev");
}

#[tokio::test]
async fn http_registry_publish_and_add_round_trip() {
    let server = TestHttpRegistry::start().await;
    server
        .add_response("GET", "/index.yaml", "skills: []\n")
        .await;
    let home = temp_dir("skill-http-round-trip-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    service
        .publish(SkillPublishRequest {
            bundle_path: skill_test_file_bundle("http-skill", "0.1.0", "HTTP skill"),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should upload files");

    let installed = service
        .add(SkillAddRequest {
            handle: "http-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should download uploaded files");

    assert_eq!(installed.name, "http-skill");
    assert_eq!(installed.source_type, "http");
    assert_eq!(installed.source_label, "http:http-dev:http-skill@0.1.0");
    assert_eq!(installed.self_test_score, Some(1.0));
    assert!(installed.path.join("content/skill-test.yaml").is_file());
}

#[tokio::test]
async fn http_registry_publish_updates_existing_index_json() {
    let server = TestHttpRegistry::start().await;
    server
        .add_response("GET", "/index.json", r#"{"skills":[]}"#)
        .await;
    let home = temp_dir("skill-http-json-publish-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("json-published", "0.1.0", "JSON publish"),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should update existing JSON index");

    let installed = service
        .add(SkillAddRequest {
            handle: "json-published@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should read updated JSON index");

    assert_eq!(installed.name, "json-published");
}

#[tokio::test]
async fn http_registry_publish_defaults_missing_index_to_json() {
    let server = TestHttpRegistry::start().await;
    let home = temp_dir("skill-http-missing-index-json-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("json-default", "0.1.0", "JSON default"),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should create a new JSON index");

    let index_json = server
        .response_body("GET", "/index.json")
        .await
        .expect("new HTTP registries should use index.json");
    let index: serde_json::Value = serde_json::from_slice(&index_json).unwrap();
    assert_eq!(index["skills"][0]["name"], "json-default");
    assert!(server.response_body("GET", "/index.yaml").await.is_none());
}

#[tokio::test]
async fn http_registry_add_downloads_tar_zst_skill_artifact() {
    let server = TestHttpRegistry::start().await;
    let bundle = skill_bundle("tarball-skill", "0.1.0", "Tarball skill");
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    let index = format!(
        r#"{{"skills":[{{"name":"tarball-skill","version":"0.1.0","description":null,"registry":"ignored","digest":"{digest}","signature_ed25519":null,"public_key_ed25519":null}}]}}"#
    );
    server.add_response("GET", "/index.json", &index).await;
    add_binary_response(
        &server,
        "GET",
        "/skills/tarball-skill/0.1.0.tar.zst",
        tar_zst_bundle_bytes(&bundle),
    )
    .await;
    let home = temp_dir("skill-http-tarball-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let installed = service
        .add(SkillAddRequest {
            handle: "tarball-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should unpack tar.zst artifact");

    assert_eq!(installed.name, "tarball-skill");
    assert_eq!(installed.source_label, "http:http-dev:tarball-skill@0.1.0");
}

#[tokio::test]
async fn http_registry_add_verifies_tar_zst_signature_sidecar() {
    let server = TestHttpRegistry::start().await;
    let bundle = skill_bundle("signed-tarball-skill", "0.1.0", "Signed tarball skill");
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let payload = agentenv_core::skills::signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let index = format!(
        r#"{{"skills":[{{"name":"signed-tarball-skill","version":"0.1.0","description":null,"registry":"ignored","digest":"{digest}","signature_ed25519":"{signature}","public_key_ed25519":"{public_key}"}}]}}"#
    );
    server.add_response("GET", "/index.json", &index).await;
    add_binary_response(
        &server,
        "GET",
        "/skills/signed-tarball-skill/0.1.0.tar.zst",
        tar_zst_bundle_bytes(&bundle),
    )
    .await;
    server
        .add_response(
            "GET",
            "/skills/signed-tarball-skill/0.1.0.tar.zst.sig",
            &signature,
        )
        .await;
    let home = temp_dir("skill-http-signed-tarball-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let installed = service
        .add(SkillAddRequest {
            handle: "signed-tarball-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("add should verify the tar.zst signature sidecar");

    assert_eq!(installed.name, "signed-tarball-skill");
}

#[tokio::test]
async fn http_registry_add_rejects_invalid_tar_zst_signature_sidecar() {
    let server = TestHttpRegistry::start().await;
    let bundle = skill_bundle("bad-signature-tarball", "0.1.0", "Bad signature tarball");
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let index = format!(
        r#"{{"skills":[{{"name":"bad-signature-tarball","version":"0.1.0","description":null,"registry":"ignored","digest":"{digest}","signature_ed25519":null,"public_key_ed25519":"{public_key}"}}]}}"#
    );
    server.add_response("GET", "/index.json", &index).await;
    add_binary_response(
        &server,
        "GET",
        "/skills/bad-signature-tarball/0.1.0.tar.zst",
        tar_zst_bundle_bytes(&bundle),
    )
    .await;
    server
        .add_response(
            "GET",
            "/skills/bad-signature-tarball/0.1.0.tar.zst.sig",
            "00",
        )
        .await;
    let home = temp_dir("skill-http-bad-signature-tarball-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let error = service
        .add(SkillAddRequest {
            handle: "bad-signature-tarball@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("add should reject an invalid tar.zst signature sidecar");

    assert!(matches!(error, SkillError::InvalidSignature { .. }));
    assert!(service.list().unwrap().is_empty());
}

#[tokio::test]
async fn http_registry_add_rejects_tar_zst_parent_traversal_entry() {
    let server = TestHttpRegistry::start().await;
    let bundle = skill_bundle("unsafe-tarball-skill", "0.1.0", "Unsafe tarball skill");
    server
        .add_response(
            "GET",
            "/index.json",
            r#"{"skills":[{"name":"unsafe-tarball-skill","version":"0.1.0","description":null,"registry":"ignored","digest":null,"signature_ed25519":null,"public_key_ed25519":null}]}"#,
        )
        .await;
    add_binary_response(
        &server,
        "GET",
        "/skills/unsafe-tarball-skill/0.1.0.tar.zst",
        tar_zst_bundle_bytes_with_extra_file(&bundle, "../evil", b"evil"),
    )
    .await;
    let home = temp_dir("skill-http-tarball-traversal-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let error = service
        .add(SkillAddRequest {
            handle: "unsafe-tarball-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("add should reject unsafe tar path");

    assert!(matches!(
        error,
        SkillError::UnsafeBundlePath { .. } | SkillError::InvalidConfig { .. }
    ));
    assert!(service.list().unwrap().is_empty());
}

#[tokio::test]
async fn http_registry_add_rejects_tar_zst_symlink_entry() {
    let server = TestHttpRegistry::start().await;
    let bundle = skill_bundle("symlink-tarball-skill", "0.1.0", "Symlink tarball skill");
    server
        .add_response(
            "GET",
            "/index.json",
            r#"{"skills":[{"name":"symlink-tarball-skill","version":"0.1.0","description":null,"registry":"ignored","digest":null,"signature_ed25519":null,"public_key_ed25519":null}]}"#,
        )
        .await;
    add_binary_response(
        &server,
        "GET",
        "/skills/symlink-tarball-skill/0.1.0.tar.zst",
        tar_zst_bundle_bytes_with_symlink(&bundle, "linked-skill.md", "SKILL.md"),
    )
    .await;
    let home = temp_dir("skill-http-tarball-symlink-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let error = service
        .add(SkillAddRequest {
            handle: "symlink-tarball-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("add should reject tar symlink");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
    assert!(service.list().unwrap().is_empty());
}

#[tokio::test]
async fn http_registry_rejects_tarball_hardlink_entries() {
    let server = TestHttpRegistry::start().await;
    server
        .add_response(
            "GET",
            "/index.json",
            r#"{"skills":[{"name":"hardlink-skill","version":"0.1.0","description":null,"registry":"ignored","digest":null,"signature_ed25519":null,"public_key_ed25519":null}]}"#,
        )
        .await;
    add_binary_response(
        &server,
        "GET",
        "/skills/hardlink-skill/0.1.0.tar.zst",
        tar_zst_bundle_with_hardlink("hardlink-skill", "0.1.0"),
    )
    .await;
    let home = temp_dir("skill-http-tar-hardlink-home");
    let service =
        http_skill_service(&home, &server).with_ssrf_options(test_http_registry_ssrf_options());

    let error = service
        .add(SkillAddRequest {
            handle: "hardlink-skill@0.1.0".to_owned(),
            registry: Some("http-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect_err("hardlink tar entries must be rejected");

    assert!(matches!(
        error,
        SkillError::UnsafeBundlePath { .. } | SkillError::InvalidConfig { .. }
    ));
    assert!(service.list().unwrap().is_empty());
}

#[tokio::test]
async fn http_registry_uses_bearer_token_from_credential_resolver() {
    let server = TestHttpRegistry::start().await;
    server.require_authorization("secret-token").await;
    server
        .add_response(
            "GET",
            "/index.yaml",
            "skills:\n  - name: auth-demo\n    version: 0.1.0\n    registry: ignored\n",
        )
        .await;
    let home = temp_dir("skill-http-auth-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::http(
                "http-dev",
                server.base_url(),
                Some("bearer-from-credstore:CUSTOM_SKILLS_TOKEN".to_owned()),
            )],
            registry_order: vec!["http-dev".to_owned()],
        },
    )
    .with_ssrf_options(test_http_registry_ssrf_options())
    .with_credential_resolver(Arc::new(|name| {
        assert_eq!(name, "CUSTOM_SKILLS_TOKEN");
        Ok(Some("secret-token".to_owned()))
    }));

    let hits = service
        .search("auth")
        .await
        .expect("authenticated search should succeed");

    assert_eq!(hits[0].name, "auth-demo");
    assert!(server
        .authorization_headers()
        .await
        .iter()
        .any(|header| header.as_deref() == Some("Bearer secret-token")));
}

#[tokio::test]
async fn oci_registry_search_add_and_publish_use_distribution_api() {
    let registry = TestOciRegistry::start().await;
    let home = temp_dir("skill-oci-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::oci(
                "oci-dev",
                registry.base_reference("agentenv-test"),
                None,
            )],
            registry_order: vec!["oci-dev".to_owned()],
        },
    )
    .with_ssrf_options(test_http_registry_ssrf_options());

    service
        .publish(SkillPublishRequest {
            bundle_path: skill_test_file_bundle("oci-skill", "0.1.0", "OCI skill"),
            registry: Some("oci-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("OCI publish should work against fixture");

    let hits = service.search("oci").await.expect("OCI search should work");
    assert_eq!(hits[0].name, "oci-skill");

    let installed = service
        .add(SkillAddRequest {
            handle: "oci-skill@0.1.0".to_owned(),
            registry: Some("oci-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
        })
        .await
        .expect("OCI add should install");

    assert_eq!(installed.name, "oci-skill");
    assert_eq!(installed.source_type, "oci");
    assert_eq!(installed.source_label, "oci:oci-dev:oci-skill@0.1.0");
    assert_eq!(installed.self_test_score, Some(1.0));
    assert!(installed.path.join("content/skill-test.yaml").is_file());
}

#[tokio::test]
async fn git_registry_publish_is_reported_as_unsupported() {
    let home = temp_dir("skill-git-publish-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::git(
                "git-dev",
                "git+https://github.com/acme/skills",
            )],
            registry_order: vec!["git-dev".to_owned()],
        },
    );

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("git-publish", "0.1.0", "Git publish"),
            registry: Some("git-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect_err("git publish should be read-only");

    assert!(matches!(
        error,
        SkillError::UnsupportedRegistryPublish { registry, kind }
            if registry == "git-dev" && kind == "git"
    ));
}

#[tokio::test]
async fn git_registry_rejects_invalid_registry_name_before_cache_path_use() {
    let home = temp_dir("skill-git-invalid-registry-home");
    let service = SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::git(
                "../../outside",
                "git+https://github.com/acme/skills",
            )],
            registry_order: vec!["../../outside".to_owned()],
        },
    );

    let error = service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle("git-name-reject", "0.1.0", "Git name reject"),
            registry: Some("../../outside".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect_err("invalid registry names must be rejected before adapter construction");

    assert!(matches!(
        error,
        SkillError::InvalidSkillName { name } if name == "../../outside"
    ));
}

#[cfg(windows)]
fn self_test_file_exists_command() -> &'static str {
    "if exist SKILL.md (exit /B 0) else (exit /B 1)"
}

#[cfg(not(windows))]
fn self_test_file_exists_command() -> &'static str {
    "test -f SKILL.md"
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

fn filesystem_skill_service(home: &Path, registry: &Path) -> SkillService {
    SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::filesystem(
                "local-dev",
                registry.to_path_buf(),
            )],
            registry_order: vec!["local-dev".to_owned()],
        },
    )
}

async fn publish_test_skill(service: &SkillService, name: &str, version: &str, content: &str) {
    service
        .publish(SkillPublishRequest {
            bundle_path: skill_bundle(name, version, content),
            registry: Some("local-dev".to_owned()),
            allow_unsigned: true,
            self_test_attestation: None,
            no_self_test_run: false,
        })
        .await
        .expect("publish should succeed");
}

fn http_skill_service(home: &Path, server: &TestHttpRegistry) -> SkillService {
    SkillService::new(
        home.join(".agentenv"),
        SkillsConfig {
            registries: vec![agentenv_core::skills::RegistryConfig::http(
                "http-dev",
                server.base_url(),
                None,
            )],
            registry_order: vec!["http-dev".to_owned()],
        },
    )
}

fn test_http_registry_ssrf_options() -> SsrfOptions {
    SsrfOptions {
        allow_private: true,
        allow_loopback: true,
        ..SsrfOptions::default()
    }
}

fn skill_bundle(name: &str, version: &str, content: &str) -> PathBuf {
    let bundle = temp_dir(&format!("skill-fs-bundle-{name}-{version}"));
    write_file(&bundle.join("SKILL.md"), &format!("# {content}\n"));
    write_file(
        &bundle.join("skill.yaml"),
        &format!(
            "name: {name}\nversion: {version}\ndescription: {content}\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n"
        ),
    );
    bundle
}

fn skill_test_file_bundle(name: &str, version: &str, content: &str) -> PathBuf {
    let bundle = temp_dir(&format!("skill-test-file-bundle-{name}-{version}"));
    write_file(&bundle.join("SKILL.md"), &format!("# {content}\n"));
    write_file(
        &bundle.join("skill.yaml"),
        &format!(
            "name: {name}\nversion: {version}\ndescription: {content}\nentry: SKILL.md\nfiles:\n  - SKILL.md\n"
        ),
    );
    write_file(
        &bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n",
    );
    bundle
}

fn tar_zst_bundle_bytes(bundle_path: &Path) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_bundle_minimal_files(&mut builder, bundle_path);
        builder.finish().unwrap();
    }
    zstd::stream::encode_all(tar_bytes.as_slice(), 0).unwrap()
}

fn tar_zst_bundle_bytes_with_extra_file(
    bundle_path: &Path,
    entry_path: &str,
    content: &[u8],
) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_bundle_minimal_files(&mut builder, bundle_path);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.as_mut_bytes()[0..entry_path.len()].copy_from_slice(entry_path.as_bytes());
        header.set_cksum();
        builder.append(&header, io::Cursor::new(content)).unwrap();
        builder.finish().unwrap();
    }
    zstd::stream::encode_all(tar_bytes.as_slice(), 0).unwrap()
}

fn tar_zst_bundle_bytes_with_symlink(
    bundle_path: &Path,
    entry_path: &str,
    target_path: &str,
) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_bundle_minimal_files(&mut builder, bundle_path);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_link_name(target_path).unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, entry_path, io::empty())
            .unwrap();
        builder.finish().unwrap();
    }
    zstd::stream::encode_all(tar_bytes.as_slice(), 0).unwrap()
}

fn tar_zst_bundle_with_hardlink(name: &str, version: &str) -> Vec<u8> {
    let bundle = skill_bundle(name, version, "Hardlink tarball skill");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_bundle_minimal_files(&mut builder, &bundle);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_link_name("SKILL.md").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink-skill.md", io::empty())
            .unwrap();
        builder.finish().unwrap();
    }
    zstd::stream::encode_all(tar_bytes.as_slice(), 0).unwrap()
}

fn append_bundle_minimal_files<W: io::Write>(builder: &mut tar::Builder<W>, bundle_path: &Path) {
    builder
        .append_path_with_name(bundle_path.join("skill.yaml"), "skill.yaml")
        .unwrap();
    builder
        .append_path_with_name(bundle_path.join("SKILL.md"), "SKILL.md")
        .unwrap();
    let skill_test_path = bundle_path.join("skill-test.yaml");
    if skill_test_path.is_file() {
        builder
            .append_path_with_name(skill_test_path, "skill-test.yaml")
            .unwrap();
    }
}

async fn add_binary_response(server: &TestHttpRegistry, method: &str, path: &str, body: Vec<u8>) {
    server.add_binary_response(method, path, body).await;
}

#[derive(Clone)]
struct TestHttpRegistry {
    addr: SocketAddr,
    state: Arc<Mutex<TestHttpRegistryState>>,
}

#[derive(Default)]
struct TestHttpRegistryState {
    responses: BTreeMap<(String, String), Vec<u8>>,
    requests: Vec<TestHttpRegistryRequest>,
    required_authorization: Option<String>,
}

struct TestHttpRegistryRequest {
    authorization: Option<String>,
}

#[derive(Clone)]
struct TestOciRegistry {
    addr: SocketAddr,
}

#[derive(Default)]
struct TestOciRegistryState {
    blobs: BTreeMap<String, Vec<u8>>,
    manifests: BTreeMap<String, Vec<u8>>,
    uploads: BTreeMap<String, Vec<u8>>,
    next_upload: u64,
}

impl TestHttpRegistry {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(TestHttpRegistryState::default()));
        let server = Self {
            addr,
            state: state.clone(),
        };

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    handle_test_http_registry_connection(stream, state).await;
                });
            }
        });

        server
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn add_response(&self, method: &str, path: &str, body: &str) {
        self.state.lock().unwrap().responses.insert(
            (method.to_owned(), path.to_owned()),
            body.as_bytes().to_vec(),
        );
    }

    async fn add_binary_response(&self, method: &str, path: &str, body: Vec<u8>) {
        self.state
            .lock()
            .unwrap()
            .responses
            .insert((method.to_owned(), path.to_owned()), body);
    }

    async fn require_authorization(&self, token: &str) {
        self.state.lock().unwrap().required_authorization = Some(format!("Bearer {token}"));
    }

    async fn authorization_headers(&self) -> Vec<Option<String>> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|request| request.authorization.clone())
            .collect()
    }

    async fn response_body(&self, method: &str, path: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .unwrap()
            .responses
            .get(&(method.to_owned(), path.to_owned()))
            .cloned()
    }
}

impl TestOciRegistry {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(TestOciRegistryState::default()));
        let registry = Self { addr };
        let base_url = format!("http://{addr}");

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = state.clone();
                let base_url = base_url.clone();
                tokio::spawn(async move {
                    handle_test_oci_registry_connection(stream, state, base_url).await;
                });
            }
        });

        registry
    }

    fn base_reference(&self, repository: &str) -> String {
        format!("{}/{}", self.addr, repository)
    }
}

async fn handle_test_http_registry_connection(
    mut stream: tokio::net::TcpStream,
    state: Arc<Mutex<TestHttpRegistryState>>,
) {
    use tokio::io::AsyncWriteExt;

    let Some((method, path, headers, body)) = read_test_http_request(&mut stream).await else {
        return;
    };
    let authorization = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.clone());

    let (status, response_body) = {
        let mut state = state.lock().unwrap();
        state.requests.push(TestHttpRegistryRequest {
            authorization: authorization.clone(),
        });

        if let Some(required) = state.required_authorization.as_deref() {
            if authorization.as_deref() != Some(required) {
                (401, Vec::new())
            } else {
                test_http_registry_response(&mut state, &method, &path, body)
            }
        } else {
            test_http_registry_response(&mut state, &method, &path, body)
        }
    };

    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(&response_body).await;
}

fn test_http_registry_response(
    state: &mut TestHttpRegistryState,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> (u16, Vec<u8>) {
    match method {
        "GET" => state
            .responses
            .get(&(method.to_owned(), path.to_owned()))
            .cloned()
            .map(|body| (200, body))
            .unwrap_or_else(|| (404, Vec::new())),
        "PUT" => {
            state
                .responses
                .insert(("GET".to_owned(), path.to_owned()), body);
            (204, Vec::new())
        }
        _ => (404, Vec::new()),
    }
}

async fn read_test_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };

    let header = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = header.split("\r\n");
    let request_line = lines.next()?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next()?.to_owned();
    let path = request_parts.next()?.to_owned();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Some((method, path, headers, body))
}

async fn handle_test_oci_registry_connection(
    mut stream: tokio::net::TcpStream,
    state: Arc<Mutex<TestOciRegistryState>>,
    base_url: String,
) {
    use tokio::io::AsyncWriteExt;

    let Some((method, target, _headers, body)) = read_test_http_request(&mut stream).await else {
        return;
    };
    let (status, headers, response_body) =
        test_oci_registry_response(&state, &base_url, &method, &target, body);
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        404 => "Not Found",
        _ => "Error",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response_body.len()
    );
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(&response_body).await;
}

fn test_oci_registry_response(
    state: &Arc<Mutex<TestOciRegistryState>>,
    base_url: &str,
    method: &str,
    target: &str,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut state = state.lock().unwrap();
    match method {
        "POST" if path.ends_with("/blobs/uploads/") => {
            state.next_upload += 1;
            let upload_path = format!("{path}{}", state.next_upload);
            state.uploads.insert(upload_path.clone(), Vec::new());
            (
                202,
                vec![("Location".to_owned(), format!("{base_url}{upload_path}"))],
                Vec::new(),
            )
        }
        "PATCH" if path.contains("/blobs/uploads/") => {
            state.uploads.insert(path.to_owned(), body);
            (
                202,
                vec![("Location".to_owned(), format!("{base_url}{path}"))],
                Vec::new(),
            )
        }
        "PUT" if path.contains("/blobs/uploads/") => {
            let Some(digest) = query.strip_prefix("digest=") else {
                return (404, Vec::new(), Vec::new());
            };
            let digest = digest.replace("%3A", ":");
            let Some(upload) = state.uploads.remove(path) else {
                return (404, Vec::new(), Vec::new());
            };
            state.blobs.insert(digest, upload);
            (201, Vec::new(), Vec::new())
        }
        "PUT" if path.contains("/manifests/") => {
            state.manifests.insert(path.to_owned(), body);
            (201, Vec::new(), Vec::new())
        }
        "GET" if path.contains("/manifests/") => state
            .manifests
            .get(path)
            .cloned()
            .map(|body| (200, Vec::new(), body))
            .unwrap_or_else(|| (404, Vec::new(), Vec::new())),
        "GET" if path.contains("/blobs/") => {
            let Some((_, digest)) = path.rsplit_once("/blobs/") else {
                return (404, Vec::new(), Vec::new());
            };
            state
                .blobs
                .get(digest)
                .cloned()
                .map(|body| (200, Vec::new(), body))
                .unwrap_or_else(|| (404, Vec::new(), Vec::new()))
        }
        _ => (404, Vec::new(), Vec::new()),
    }
}

fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
