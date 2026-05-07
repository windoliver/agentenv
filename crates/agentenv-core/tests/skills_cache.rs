use std::{fs, path::PathBuf};

use agentenv_core::skills::{
    rebuild_skill_index, SkillArchive, SkillCacheLayout, SkillIndex, SkillManifest, SkillProvenance,
};

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
}

fn unique_root(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
