use std::{fs, path::PathBuf};

use agentenv_core::{
    bundle::{
        emit_skill_bundle, BundleSource, ReferenceDocument, SkillBundleInput, SkillBundleMetadata,
        SkillBundleOutput,
    },
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    portable_lockfile::{build_portable_lockfile, PortableLockfileInput},
    registry::DriverKind,
    skills::{compute_bundle_digest, load_skill_manifest},
};
use semver::Version;

#[test]
fn emit_skill_bundle_writes_expected_layout() {
    let root = temp_dir("bundle-layout");
    let out = root.join("demo-skill");
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    let output: SkillBundleOutput = emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: None,
            git_commit: None,
            git_dirty: None,
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec![
                "openshell".to_owned(),
                "codex".to_owned(),
                "filesystem".to_owned(),
                "dev-env".to_owned(),
            ],
        },
        blueprint_yaml: blueprint_yaml.clone(),
        lockfile_yaml: lockfile_yaml.clone(),
        reference_document: None,
        output_dir: out.clone(),
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap();

    assert_eq!(output.output_dir, out);
    assert_eq!(output.skill_name, "demo");
    assert_eq!(output.version, "1.0.0");
    assert!(output.warnings.is_empty());
    assert!(out.join("SKILL.md").is_file());
    assert!(out.join("skill.yaml").is_file());
    assert!(out.join("blueprint.yaml").is_file());
    assert!(out.join("agentenv.lock").is_file());
    assert!(out.join("scripts/bootstrap.sh").is_file());
    assert!(out.join(".agentenv/manifest.json").is_file());
    assert!(out.join(".agentenv/provenance.json").is_file());
    assert!(!out.join("references").exists());

    let skill = fs::read_to_string(out.join("SKILL.md")).unwrap();
    assert!(skill.contains("agentenv-bundle: true"));
    assert!(skill.contains("agentenv-schema: \"0.1\""));
    assert!(skill.contains("agentenv reproduce agentenv.lock --name demo"));

    let bootstrap = fs::read_to_string(out.join("scripts/bootstrap.sh")).unwrap();
    assert!(bootstrap.contains("agentenv verify agentenv.lock"));
    assert!(bootstrap.contains("agentenv reproduce agentenv.lock --name \"${ENV_NAME}\""));

    let manifest = load_skill_manifest(&out).unwrap();
    assert_eq!(manifest.name, "demo");
    assert_eq!(manifest.version.to_string(), "1.0.0");
    assert_eq!(manifest.entry, PathBuf::from("SKILL.md"));
    assert!(manifest
        .declared_files
        .contains(&PathBuf::from("agentenv.lock")));
    assert!(!manifest
        .declared_files
        .iter()
        .any(|path| path.starts_with("references")));

    let digest = compute_bundle_digest(&out, &manifest).unwrap();
    assert_eq!(output.bundle_digest, digest);
    assert_eq!(output.blueprint_digest, sha256_digest(&blueprint_yaml));
    assert_eq!(output.lockfile_digest, sha256_digest(&lockfile_yaml));
    assert_eq!(
        fs::read_to_string(out.join("blueprint.yaml")).unwrap(),
        ensure_trailing_newline(&blueprint_yaml)
    );
    assert_eq!(
        fs::read_to_string(out.join("agentenv.lock")).unwrap(),
        ensure_trailing_newline(&lockfile_yaml)
    );
}

#[test]
fn emit_skill_bundle_writes_reference_document_when_provided() {
    let root = temp_dir("bundle-reference");
    let out = root.join("demo-skill");
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: Some(root.join("project")),
            git_commit: Some("abc123".to_owned()),
            git_dirty: Some(false),
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: Some("Alice Example".to_owned()),
            license: Some("MIT".to_owned()),
            tags: vec![
                "openshell".to_owned(),
                "codex".to_owned(),
                "filesystem".to_owned(),
                "dev-env".to_owned(),
            ],
        },
        blueprint_yaml,
        lockfile_yaml,
        reference_document: Some(ReferenceDocument {
            source_relative_path: "docs/ARCHITECTURE.md".to_owned(),
            content: "# Architecture\n\nDetails\n".to_owned(),
        }),
        output_dir: out.clone(),
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap();

    let reference = fs::read_to_string(out.join("references/architecture.md")).unwrap();
    assert!(reference.starts_with("# Project Architecture\n\nSource: `docs/ARCHITECTURE.md`\n\n"));
    assert!(reference.contains("# Architecture"));

    let manifest = load_skill_manifest(&out).unwrap();
    assert!(manifest
        .declared_files
        .contains(&PathBuf::from("references/architecture.md")));

    let skill = fs::read_to_string(out.join("SKILL.md")).unwrap();
    assert!(skill.contains("author: Alice Example"));
    assert!(skill.contains("license: MIT"));
    assert!(skill.contains("tags: [openshell, codex, filesystem, dev-env]"));
}

#[test]
fn emit_skill_bundle_keeps_skill_yaml_and_frontmatter_in_sync() {
    let root = temp_dir("bundle-parity");
    let out = root.join("demo-skill");
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: None,
            git_commit: None,
            git_dirty: None,
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec![
                "openshell".to_owned(),
                "codex".to_owned(),
                "dev-env".to_owned(),
            ],
        },
        blueprint_yaml,
        lockfile_yaml,
        reference_document: None,
        output_dir: out.clone(),
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap();

    let skill_yaml: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(out.join("skill.yaml")).unwrap()).unwrap();
    let skill_md = fs::read_to_string(out.join("SKILL.md")).unwrap();
    let frontmatter = parse_skill_frontmatter(&skill_md);

    assert_eq!(
        yaml_string_field(&frontmatter, "name"),
        yaml_string_field(&skill_yaml, "name")
    );
    assert_eq!(
        yaml_string_field(&frontmatter, "version"),
        yaml_string_field(&skill_yaml, "version")
    );
    assert_eq!(
        yaml_string_field(&frontmatter, "description"),
        yaml_string_field(&skill_yaml, "description")
    );
    assert_eq!(
        yaml_string_sequence(&frontmatter, "tags"),
        yaml_string_sequence(&skill_yaml, "tags")
    );
    assert_eq!(
        yaml_string_field(&frontmatter, "agentenv-schema"),
        yaml_string_field(&skill_yaml, "agentenv_schema")
    );
    assert_eq!(
        frontmatter["agentenv-bundle"].as_bool(),
        skill_yaml["agentenv_bundle"].as_bool()
    );
}

#[test]
fn emit_skill_bundle_records_blueprint_lockfile_and_manifest_digests() {
    let root = temp_dir("bundle-digests");
    let out = root.join("demo-skill");
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    let output = emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: None,
            git_commit: None,
            git_dirty: None,
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec!["dev-env".to_owned()],
        },
        blueprint_yaml: blueprint_yaml.clone(),
        lockfile_yaml: lockfile_yaml.clone(),
        reference_document: None,
        output_dir: out.clone(),
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap();

    let manifest_json = fs::read_to_string(out.join(".agentenv/manifest.json")).unwrap();
    assert!(manifest_json.contains("\"path\": \"SKILL.md\""));
    assert!(manifest_json.contains("\"path\": \"skill.yaml\""));
    assert!(manifest_json.contains("\"path\": \"blueprint.yaml\""));
    assert!(manifest_json.contains("\"path\": \"agentenv.lock\""));
    assert!(manifest_json.contains("\"path\": \"scripts/bootstrap.sh\""));
    assert!(!manifest_json.contains("provenance.json"));

    let provenance_json = fs::read_to_string(out.join(".agentenv/provenance.json")).unwrap();
    assert!(provenance_json.contains("\"created_at\": \"2026-05-09T00:00:00Z\""));
    assert!(provenance_json.contains(&format!("\"blueprint\": \"{}\"", output.blueprint_digest)));
    assert!(provenance_json.contains(&format!("\"lockfile\": \"{}\"", output.lockfile_digest)));
    assert!(provenance_json.contains("\"manifest\": \"sha256:"));
}

#[test]
fn emit_skill_bundle_rejects_existing_output_path() {
    let root = temp_dir("bundle-existing");
    let out = root.join("demo-skill");
    fs::create_dir_all(&out).unwrap();
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    let error = emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: None,
            git_commit: None,
            git_dirty: None,
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec!["dev-env".to_owned()],
        },
        blueprint_yaml,
        lockfile_yaml,
        reference_document: None,
        output_dir: out,
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap_err();

    assert!(error.to_string().contains("output path already exists"));
}

#[cfg(unix)]
#[test]
fn emit_skill_bundle_rejects_dangling_symlink_output_path() {
    let root = temp_dir("bundle-existing-symlink");
    let out = root.join("demo-skill");
    std::os::unix::fs::symlink(root.join("missing-target"), &out).unwrap();
    let blueprint_yaml = minimal_blueprint();
    let driver_artifacts = test_driver_artifacts();
    let lockfile_yaml = portable_lock_yaml("demo", &blueprint_yaml, &driver_artifacts);

    let error = emit_skill_bundle(SkillBundleInput {
        source: BundleSource {
            env_name: "demo".to_owned(),
            project_path: None,
            git_commit: None,
            git_dirty: None,
        },
        metadata: SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec!["dev-env".to_owned()],
        },
        blueprint_yaml,
        lockfile_yaml,
        reference_document: None,
        output_dir: out,
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-09T00:00:00Z".to_owned(),
        driver_artifacts,
    })
    .unwrap_err();

    assert!(error.to_string().contains("output path already exists"));
}

fn minimal_blueprint() -> String {
    r#"version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#
    .to_owned()
}

fn portable_lock_yaml(
    name: &str,
    blueprint_yaml: &str,
    driver_artifacts: &[DriverArtifact],
) -> String {
    build_portable_lockfile(PortableLockfileInput {
        name: name.to_owned(),
        blueprint_yaml: blueprint_yaml.to_owned(),
        driver_artifacts: driver_artifacts.to_vec(),
    })
    .unwrap()
    .to_yaml_deterministic()
    .unwrap()
}

fn test_driver_artifacts() -> Vec<DriverArtifact> {
    let version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    [
        (DriverKind::Sandbox, "openshell"),
        (DriverKind::Agent, "codex"),
        (DriverKind::Context, "filesystem"),
        (DriverKind::Inference, "passthrough"),
    ]
    .into_iter()
    .map(|(kind, name)| DriverArtifact {
        kind,
        name: name.to_owned(),
        version: version.clone(),
        source: DriverSource::BuiltIn,
        digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_owned(),
        install_hint: None,
        entry: None,
    })
    .collect()
}

fn ensure_trailing_newline(input: &str) -> String {
    if input.ends_with('\n') {
        input.to_owned()
    } else {
        format!("{input}\n")
    }
}

fn sha256_digest(input: &str) -> String {
    format!(
        "sha256:{}",
        agentenv_core::digest::sha256_hex(ensure_trailing_newline(input).as_bytes())
    )
}

fn parse_skill_frontmatter(skill_md: &str) -> serde_yaml::Value {
    let mut lines = skill_md.lines();
    assert_eq!(lines.next(), Some("---"));
    let mut frontmatter = Vec::new();
    for line in lines {
        if line == "---" {
            return serde_yaml::from_str(&frontmatter.join("\n")).unwrap();
        }
        frontmatter.push(line);
    }
    panic!("SKILL.md frontmatter was not closed");
}

fn yaml_string_field(value: &serde_yaml::Value, key: &str) -> String {
    value[key].as_str().unwrap().to_owned()
}

fn yaml_string_sequence(value: &serde_yaml::Value, key: &str) -> Vec<String> {
    value[key]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn temp_dir(prefix: &str) -> PathBuf {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf();
    let path = workspace_root.join("target").join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}
