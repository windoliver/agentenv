use std::{fs, path::PathBuf};

use agentenv_core::skills::{
    rebuild_skill_index, verify_all_installed_skills, SkillArchive, SkillCacheLayout, SkillIndex,
    SkillManifest, SkillProvenance, SkillSelfTest, SkillSelfTestAssertion, SkillTrustKey,
    SkillVerifyOptions, SkillVerifyStatus,
};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn skill_cache_layout_rejects_path_escape_segments() {
    let layout = SkillCacheLayout::new(PathBuf::from("/tmp/agentenv"));

    assert!(layout.installed_skill_dir("code-review", "1.2.0").is_ok());
    assert!(layout.installed_skill_dir("../escape", "1.2.0").is_err());
    assert!(layout
        .installed_skill_dir("code-review", "../escape")
        .is_err());
    assert!(layout.installed_skill_dir("index.json", "1.2.0").is_err());
    assert!(layout.archive_path("not-a-sha").is_err());
}

#[test]
fn skill_manifest_and_provenance_reject_unknown_fields() {
    let manifest = r#"{
      "schema_version": "0.1",
      "name": "code-review",
      "version": "1.2.0",
      "source": "oci://ghcr.io/agentenv-community/code-review:1.2.0",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "signatures": [],
      "archive": {
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cache_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tar.zst"
      },
      "unexpected": true
    }"#;
    let err = SkillManifest::from_json_str(manifest).expect_err("unknown manifest field fails");
    assert!(err.to_string().contains("unknown field"));

    let provenance = r#"{
      "schema_version": "0.1",
      "subject": {
        "name": "code-review",
        "version": "1.2.0",
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      "attestations": [],
      "extra": "field"
    }"#;
    let err =
        SkillProvenance::from_json_str(provenance).expect_err("unknown provenance field fails");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn skill_index_rebuilds_in_deterministic_order() {
    let root = unique_root("skill-index-order");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "zeta",
        "2.0.0",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    write_installed_skill(
        &layout,
        "alpha",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    let index = rebuild_skill_index(&layout).expect("rebuild index");
    assert_eq!(
        index
            .skills
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "zeta"]
    );

    let rendered = fs::read_to_string(layout.index_path()).expect("index written");
    let reparsed: SkillIndex = serde_json::from_str(&rendered).expect("index parses");
    assert_eq!(reparsed, index);
}

#[test]
fn verify_all_accepts_valid_unsigned_skill_with_file_self_test() {
    let root = unique_root("verify-valid-unsigned");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "file-check",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("file-check", "1.0.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.self_test = Some(SkillSelfTest {
        timeout_seconds: 5,
        assertions: vec![SkillSelfTestAssertion::FileExists {
            path: "SKILL.md".to_owned(),
        }],
    });
    write_manifest(&skill_dir, &manifest);
    write_archive(&layout, &manifest.digest, b"valid archive bytes");
    rewrite_digest_to_actual_archive(&layout, &skill_dir);

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(report.skills[0].status, SkillVerifyStatus::Passed);
}

#[test]
fn verify_all_reports_archive_digest_mismatch() {
    let root = unique_root("verify-archive-mismatch");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "bad-archive",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    write_archive(
        &layout,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"different archive bytes",
    );

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("archive digest mismatch")));
}

#[test]
fn verify_all_reports_tree_digest_when_archive_is_missing() {
    let root = unique_root("verify-tree-digest");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "missing-archive",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .warnings
        .iter()
        .any(|warning| warning.contains("extracted tree digest")));
}

#[test]
fn verify_all_rejects_unknown_skill_frontmatter_fields() {
    let root = unique_root("verify-frontmatter-unknown");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "frontmatter-extra",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("frontmatter-extra", "1.0.0")
        .expect("skill dir");
    fs::write(
        skill_dir.join("SKILL.md"),
        "---\nname: frontmatter-extra\nversion: 1.0.0\nextra: no\n---\n# frontmatter-extra\n",
    )
    .expect("write SKILL.md");

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("unknown field")));
}

#[test]
fn verify_all_fails_when_provenance_is_missing() {
    let root = unique_root("verify-missing-provenance");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "missing-provenance",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("missing-provenance", "1.0.0")
        .expect("skill dir");
    fs::remove_file(skill_dir.join(".agentenv/provenance.json")).expect("remove provenance");

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("provenance")));
}

#[test]
fn verify_all_reports_manifest_identity_mismatch_under_installed_path() {
    let root = unique_root("verify-manifest-identity");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "path-name",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("path-name", "1.0.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.name = "manifest-name".to_owned();
    write_manifest(&skill_dir, &manifest);

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert_eq!(report.skills[0].name, "path-name");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("manifest name mismatch")));
}

#[test]
fn verify_all_verifies_ed25519_signature_with_trust_key() {
    let root = unique_root("verify-signature-valid");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "signed-skill",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("signed-skill", "1.0.0")
        .expect("skill dir");
    write_archive(
        &layout,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"signed archive bytes",
    );
    rewrite_digest_to_actual_archive(&layout, &skill_dir);

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let mut manifest = read_manifest(&skill_dir);
    let signature = signing_key.sign(manifest.digest.as_bytes());
    manifest.signatures = vec![format!(
        "ed25519:test-key:{}",
        hex::encode(signature.to_bytes())
    )];
    write_manifest(&skill_dir, &manifest);

    let report = verify_all_installed_skills(
        &layout,
        SkillVerifyOptions {
            trust_keys: vec![SkillTrustKey {
                id: "test-key".to_owned(),
                public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            }],
        },
    )
    .expect("verify skills");

    assert!(report.is_ok(), "{report:#?}");
}

#[test]
fn verify_all_fails_invalid_ed25519_signature() {
    let root = unique_root("verify-signature-invalid");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "signed-skill",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("signed-skill", "1.0.0")
        .expect("skill dir");
    write_archive(
        &layout,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"signed archive bytes",
    );
    rewrite_digest_to_actual_archive(&layout, &skill_dir);

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let wrong_key = SigningKey::from_bytes(&[8_u8; 32]);
    let mut manifest = read_manifest(&skill_dir);
    let signature = signing_key.sign(manifest.digest.as_bytes());
    manifest.signatures = vec![format!(
        "ed25519:test-key:{}",
        hex::encode(signature.to_bytes())
    )];
    write_manifest(&skill_dir, &manifest);

    let report = verify_all_installed_skills(
        &layout,
        SkillVerifyOptions {
            trust_keys: vec![SkillTrustKey {
                id: "test-key".to_owned(),
                public_key: hex::encode(wrong_key.verifying_key().to_bytes()),
            }],
        },
    )
    .expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("invalid signature")));
}

#[test]
fn verify_all_fails_when_signature_trust_key_is_missing() {
    let root = unique_root("verify-signature-missing-key");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "signed-skill",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("signed-skill", "1.0.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.signatures = vec!["ed25519:test-key:abcd".to_owned()];
    write_manifest(&skill_dir, &manifest);

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("missing trust key")));
}

#[test]
fn verify_all_reports_self_test_command_failure() {
    let root = unique_root("verify-self-test-command-failure");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "command-failure",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("command-failure", "1.0.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.self_test = Some(SkillSelfTest {
        timeout_seconds: 5,
        assertions: vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: "exit 3".to_owned(),
        }],
    });
    write_manifest(&skill_dir, &manifest);

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("self-test command failed")));
}

#[cfg(unix)]
#[test]
fn verify_all_reports_self_test_timeout() {
    let root = unique_root("verify-self-test-timeout");
    let layout = SkillCacheLayout::new(root.join(".agentenv"));

    write_installed_skill(
        &layout,
        "command-timeout",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let skill_dir = layout
        .installed_skill_dir("command-timeout", "1.0.0")
        .expect("skill dir");
    let mut manifest = read_manifest(&skill_dir);
    manifest.self_test = Some(SkillSelfTest {
        timeout_seconds: 1,
        assertions: vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: "sleep 2".to_owned(),
        }],
    });
    write_manifest(&skill_dir, &manifest);

    let report =
        verify_all_installed_skills(&layout, SkillVerifyOptions::default()).expect("verify skills");

    assert!(!report.is_ok(), "{report:#?}");
    assert!(report.skills[0]
        .errors
        .iter()
        .any(|error| error.contains("timed out")));
}

fn write_installed_skill(layout: &SkillCacheLayout, name: &str, version: &str, digest: &str) {
    let skill_dir = layout
        .installed_skill_dir(name, version)
        .expect("skill dir");
    fs::create_dir_all(skill_dir.join(".agentenv")).expect("create skill metadata dir");
    fs::write(
        skill_dir.join("SKILL.md"),
        format!("---\nname: {name}\nversion: {version}\n---\n# {name}\n"),
    )
    .expect("write SKILL.md");
    let hex = digest.strip_prefix("sha256:").expect("digest prefix");
    let manifest = SkillManifest {
        schema_version: "0.1".to_owned(),
        name: name.to_owned(),
        version: version.to_owned(),
        source: format!("file:///skills/{name}/{version}"),
        digest: digest.to_owned(),
        signatures: Vec::new(),
        archive: Some(SkillArchive {
            digest: digest.to_owned(),
            cache_key: format!("{hex}.tar.zst"),
        }),
        self_test: None,
    };
    fs::write(
        skill_dir.join(".agentenv/manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("render manifest"),
    )
    .expect("write manifest");
    write_provenance(&skill_dir, name, version, digest);
}

fn read_manifest(skill_dir: &std::path::Path) -> SkillManifest {
    let content =
        fs::read_to_string(skill_dir.join(".agentenv/manifest.json")).expect("read manifest");
    serde_json::from_str(&content).expect("parse manifest")
}

fn write_manifest(skill_dir: &std::path::Path, manifest: &SkillManifest) {
    fs::write(
        skill_dir.join(".agentenv/manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(manifest).expect("render manifest")
        ),
    )
    .expect("write manifest");
}

fn write_archive(layout: &SkillCacheLayout, digest: &str, bytes: &[u8]) {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let path = layout.archive_path(hex).expect("archive path");
    fs::create_dir_all(path.parent().expect("archive parent")).expect("create archive parent");
    fs::write(path, bytes).expect("write archive");
}

fn rewrite_digest_to_actual_archive(layout: &SkillCacheLayout, skill_dir: &std::path::Path) {
    let mut manifest = read_manifest(skill_dir);
    let archive = manifest.archive.as_ref().expect("manifest archive");
    let expected_hex = archive
        .digest
        .strip_prefix("sha256:")
        .expect("archive digest prefix");
    let expected_path = layout
        .archive_path(expected_hex)
        .expect("expected archive path");
    let bytes = fs::read(&expected_path).expect("read expected archive");
    let actual_hex = agentenv_core::digest::sha256_hex(&bytes);
    let actual_path = layout
        .archive_path(&actual_hex)
        .expect("actual archive path");
    if expected_path != actual_path {
        fs::rename(&expected_path, &actual_path).expect("rename archive to actual digest");
    }
    let actual_digest = format!("sha256:{actual_hex}");
    manifest.digest = actual_digest.clone();
    manifest.archive = Some(SkillArchive {
        digest: actual_digest.clone(),
        cache_key: format!("{actual_hex}.tar.zst"),
    });
    write_manifest(skill_dir, &manifest);
    write_provenance(skill_dir, &manifest.name, &manifest.version, &actual_digest);
}

fn write_provenance(skill_dir: &std::path::Path, name: &str, version: &str, digest: &str) {
    let provenance = SkillProvenance {
        schema_version: "0.1".to_owned(),
        subject: agentenv_core::skills::SkillProvenanceSubject {
            name: name.to_owned(),
            version: version.to_owned(),
            digest: digest.to_owned(),
        },
        attestations: Vec::new(),
    };
    fs::write(
        skill_dir.join(".agentenv/provenance.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&provenance).expect("render provenance")
        ),
    )
    .expect("write provenance");
}

fn unique_root(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
