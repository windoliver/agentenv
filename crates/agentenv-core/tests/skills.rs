use std::{
    fs,
    path::{Path, PathBuf},
};

use agentenv_core::skills::{
    compute_bundle_digest, install_local_skill, list_installed_skills, load_project_skills_config,
    load_skill_manifest, load_user_skills_config, merge_skills_config, validate_skill_name,
    verify_installed_skill, InstalledSkillSelector, RegistryKind, SkillError, SkillInstallOptions,
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
            source_label: "local-dev".to_owned(),
        },
    )
    .expect("install should succeed");

    assert_eq!(installed.name, "local-demo");
    assert_eq!(installed.version, "0.1.0");
    assert!(installed.path.join("content/SKILL.md").is_file());
    assert!(home.join(".agentenv/skills/index.yaml").is_file());
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
            source_label: "first-source".to_owned(),
        },
    )
    .unwrap();

    let second = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_label: "second-source".to_owned(),
        },
    )
    .unwrap();

    assert_eq!(second.source_label, "first-source");
    assert_eq!(second.installed_at, first.installed_at);
}

#[test]
fn local_reinstall_repairs_tampered_cached_content() {
    let home = temp_dir("skill-install-repair-home");
    let bundle = temp_dir("skill-install-repair-bundle");
    write_file(&bundle.join("SKILL.md"), "# Demo\n");
    write_file(
        &bundle.join("skill.yaml"),
        "name: repair-demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    let installed = install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_label: "local-dev".to_owned(),
        },
    )
    .unwrap();
    write_file(&installed.path.join("content/SKILL.md"), "# Tampered\n");

    install_local_skill(
        home.join(".agentenv"),
        &bundle,
        SkillInstallOptions {
            allow_unsigned: true,
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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
            source_label: "local-dev".to_owned(),
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

fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
