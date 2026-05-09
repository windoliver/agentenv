use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use thiserror::Error;
use uuid::Uuid;

use super::{
    model::{
        BundleManifest, BundleManifestAgentenv, BundleManifestFile, BundleManifestSkill,
        BundleProvenance, BundleProvenanceDigests, BundleProvenanceSource, BundleWarning,
        SkillBundleInput, SkillBundleMetadata, SkillBundleOutput,
    },
    render::{
        ensure_trailing_newline, render_bootstrap, render_reference, render_skill_md,
        render_skill_yaml, AGENTENV_BUNDLE_SCHEMA,
    },
};
use crate::{
    digest::sha256_hex,
    env::{validate_env_name, EnvError},
    portable_lockfile::{verify_portable_lockfile_yaml, PortableLockfileError},
    skills::{
        compute_bundle_digest, load_skill_manifest, validate_skill_name, SkillError, SkillManifest,
    },
};

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("output path already exists: `{path}`")]
    OutputExists { path: PathBuf },
    #[error("output path ancestry contains symlink `{path}`")]
    SymlinkAncestor { path: PathBuf },
    #[error("failed to read or write bundle path `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize bundle JSON at `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize bundle YAML at `{path}`: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error(transparent)]
    Env(#[from] EnvError),
    #[error(transparent)]
    Skill(#[from] SkillError),
    #[error(transparent)]
    Lockfile(#[from] PortableLockfileError),
    #[error("portable lockfile verification failed: {messages}")]
    LockfileVerification { messages: String },
    #[error("bundle manifest inventory mismatch for `{path}`")]
    ManifestDigestMismatch { path: String },
    #[error("bundle validation failed: {message}")]
    Validation { message: String },
}

struct WrittenBundle {
    blueprint_digest: String,
    lockfile_digest: String,
    warnings: Vec<BundleWarning>,
}

pub fn emit_skill_bundle(input: SkillBundleInput) -> Result<SkillBundleOutput, BundleError> {
    match fs::symlink_metadata(&input.output_dir) {
        Ok(_) => {
            return Err(BundleError::OutputExists {
                path: input.output_dir,
            });
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(BundleError::Io {
                path: input.output_dir,
                source,
            });
        }
    }
    validate_output_ancestry(&input.output_dir)?;
    validate_skill_name(&input.metadata.name)?;
    validate_env_name(&input.source.env_name)?;

    let staging_dir = create_unique_staging_dir(&input.output_dir)?;

    let result = publish_validated_bundle(&input, &staging_dir);
    match result {
        Ok(output) => Ok(output),
        Err(error) => {
            let cleanup = remove_dir_all(&staging_dir);
            if cleanup.is_err() {
                return Err(error);
            }
            Err(error)
        }
    }
}

fn publish_validated_bundle(
    input: &SkillBundleInput,
    staging_dir: &Path,
) -> Result<SkillBundleOutput, BundleError> {
    let written = write_and_validate_staging(input, staging_dir)?;
    publish_staging(staging_dir, &input.output_dir)?;
    let manifest = load_skill_manifest(&input.output_dir)?;
    let bundle_digest = compute_bundle_digest(&input.output_dir, &manifest)?;
    Ok(SkillBundleOutput {
        output_dir: input.output_dir.clone(),
        skill_name: input.metadata.name.clone(),
        version: input.metadata.version.to_string(),
        bundle_digest,
        blueprint_digest: written.blueprint_digest,
        lockfile_digest: written.lockfile_digest,
        warnings: written.warnings,
    })
}

fn write_and_validate_staging(
    input: &SkillBundleInput,
    staging_dir: &Path,
) -> Result<WrittenBundle, BundleError> {
    let has_reference = input.reference_document.is_some();
    let blueprint_yaml = ensure_trailing_newline(&input.blueprint_yaml);
    let lockfile_yaml = ensure_trailing_newline(&input.lockfile_yaml);
    let blueprint_digest = sha256_digest(blueprint_yaml.as_bytes());
    let lockfile_digest = sha256_digest(lockfile_yaml.as_bytes());

    let verify_report = verify_portable_lockfile_yaml(&lockfile_yaml, &input.driver_artifacts)?;
    if !verify_report.errors.is_empty() {
        return Err(BundleError::LockfileVerification {
            messages: verify_report
                .errors
                .iter()
                .map(|issue| issue.message.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        });
    }
    let warnings = verify_report
        .warnings
        .iter()
        .map(|issue| BundleWarning {
            message: issue.message.clone(),
        })
        .collect::<Vec<_>>();

    write_file(
        staging_dir,
        "SKILL.md",
        render_skill_md(&input.metadata, &input.source.env_name, has_reference)
            .map_err(|source| BundleError::Yaml {
                path: staging_dir.join("SKILL.md"),
                source,
            })?
            .as_bytes(),
    )?;
    write_file(
        staging_dir,
        "skill.yaml",
        render_skill_yaml(&input.metadata, has_reference)
            .map_err(|source| BundleError::Yaml {
                path: staging_dir.join("skill.yaml"),
                source,
            })?
            .as_bytes(),
    )?;
    write_file(staging_dir, "blueprint.yaml", blueprint_yaml.as_bytes())?;
    write_file(staging_dir, "agentenv.lock", lockfile_yaml.as_bytes())?;
    write_file(
        staging_dir,
        "scripts/bootstrap.sh",
        render_bootstrap(&input.source.env_name).as_bytes(),
    )?;
    set_executable(staging_dir.join("scripts/bootstrap.sh"))?;

    if let Some(document) = input.reference_document.as_ref() {
        write_file(
            staging_dir,
            "references/architecture.md",
            render_reference(document).as_bytes(),
        )?;
    }

    let manifest = bundle_manifest(staging_dir, &input.metadata)?;
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|source| BundleError::Json {
            path: staging_dir.join(".agentenv/manifest.json"),
            source,
        })?;
    write_file(
        staging_dir,
        ".agentenv/manifest.json",
        ensure_trailing_newline(&manifest_json).as_bytes(),
    )?;
    let manifest_digest = sha256_file(staging_dir.join(".agentenv/manifest.json"))?;

    let provenance = BundleProvenance {
        version: AGENTENV_BUNDLE_SCHEMA.to_owned(),
        created_at: input.created_at.clone(),
        agentenv_version: input.agentenv_version.clone(),
        source: BundleProvenanceSource {
            kind: "environment".to_owned(),
            env_name: input.source.env_name.clone(),
            project_path: input
                .source
                .project_path
                .as_ref()
                .map(|path| path.display().to_string()),
            project_git_commit: input.source.git_commit.clone(),
            project_git_dirty: input.source.git_dirty,
        },
        digests: BundleProvenanceDigests {
            blueprint: blueprint_digest.clone(),
            lockfile: lockfile_digest.clone(),
            manifest: manifest_digest,
        },
    };
    let provenance_json =
        serde_json::to_string_pretty(&provenance).map_err(|source| BundleError::Json {
            path: staging_dir.join(".agentenv/provenance.json"),
            source,
        })?;
    write_file(
        staging_dir,
        ".agentenv/provenance.json",
        ensure_trailing_newline(&provenance_json).as_bytes(),
    )?;

    validate_staging(staging_dir, &manifest, &input.metadata, has_reference)?;

    Ok(WrittenBundle {
        blueprint_digest,
        lockfile_digest,
        warnings,
    })
}

fn bundle_manifest(
    staging_dir: &Path,
    metadata: &super::model::SkillBundleMetadata,
) -> Result<BundleManifest, BundleError> {
    let mut files = generated_inventory_paths(staging_dir)?;
    files.retain(|path| path != ".agentenv/manifest.json" && path != ".agentenv/provenance.json");
    let mut manifest_files = Vec::with_capacity(files.len());
    for path in files {
        let digest = sha256_file(staging_dir.join(&path))?;
        manifest_files.push(BundleManifestFile {
            path,
            sha256: digest,
        });
    }

    Ok(BundleManifest {
        version: AGENTENV_BUNDLE_SCHEMA.to_owned(),
        kind: "agentenv.skill_bundle".to_owned(),
        skill: BundleManifestSkill {
            name: metadata.name.clone(),
            version: metadata.version.to_string(),
            entry: "SKILL.md".to_owned(),
        },
        agentenv: BundleManifestAgentenv {
            schema: AGENTENV_BUNDLE_SCHEMA.to_owned(),
            bundle: true,
        },
        files: manifest_files,
    })
}

fn validate_staging(
    staging_dir: &Path,
    manifest: &BundleManifest,
    metadata: &super::model::SkillBundleMetadata,
    has_reference: bool,
) -> Result<(), BundleError> {
    let skill_manifest = load_skill_manifest(staging_dir)?;
    if skill_manifest.name != metadata.name || skill_manifest.version != metadata.version {
        return Err(BundleError::Validation {
            message: "skill.yaml metadata does not match bundle metadata".to_owned(),
        });
    }
    if !has_reference
        && skill_manifest
            .declared_files
            .iter()
            .any(|path| path.starts_with("references"))
    {
        return Err(BundleError::Validation {
            message: "skill.yaml declares references without a reference document".to_owned(),
        });
    }

    let skill_md = read_to_string(staging_dir.join("SKILL.md"))?;
    validate_metadata_parity(&skill_manifest, &skill_md, metadata)?;
    if !skill_md.contains("agentenv-bundle: true")
        || !skill_md.contains("agentenv verify agentenv.lock")
        || !skill_md.contains("agentenv reproduce agentenv.lock")
    {
        return Err(BundleError::Validation {
            message: "SKILL.md is missing required agentenv bundle instructions".to_owned(),
        });
    }

    let bootstrap = read_to_string(staging_dir.join("scripts/bootstrap.sh"))?;
    if !bootstrap.contains("agentenv verify agentenv.lock")
        || !bootstrap.contains("agentenv reproduce agentenv.lock --name \"${ENV_NAME}\"")
    {
        return Err(BundleError::Validation {
            message: "bootstrap script is missing required agentenv commands".to_owned(),
        });
    }

    for file in &manifest.files {
        let actual = sha256_file(staging_dir.join(&file.path))?;
        if actual != file.sha256 {
            return Err(BundleError::ManifestDigestMismatch {
                path: file.path.clone(),
            });
        }
    }

    compute_bundle_digest(staging_dir, &skill_manifest)?;
    Ok(())
}

fn validate_metadata_parity(
    skill_manifest: &SkillManifest,
    skill_md: &str,
    metadata: &SkillBundleMetadata,
) -> Result<(), BundleError> {
    let frontmatter = parse_skill_md_frontmatter(skill_md)?;

    let frontmatter_name = required_string(&frontmatter, "name", "SKILL.md frontmatter")?;
    validate_equal("name", &frontmatter_name, &metadata.name)?;
    validate_equal("name", &skill_manifest.name, &metadata.name)?;

    let expected_version = metadata.version.to_string();
    let frontmatter_version = required_string(&frontmatter, "version", "SKILL.md frontmatter")?;
    validate_equal("version", &frontmatter_version, &expected_version)?;
    validate_equal(
        "version",
        &skill_manifest.version.to_string(),
        &expected_version,
    )?;

    let frontmatter_description =
        required_string(&frontmatter, "description", "SKILL.md frontmatter")?;
    validate_equal(
        "description",
        &frontmatter_description,
        &metadata.description,
    )?;
    let manifest_description =
        skill_manifest
            .description
            .as_deref()
            .ok_or_else(|| BundleError::Validation {
                message: "skill.yaml is missing description".to_owned(),
            })?;
    validate_equal(
        "description",
        manifest_description,
        metadata.description.as_str(),
    )?;

    let frontmatter_tags = optional_string_sequence(&frontmatter, "tags", "SKILL.md frontmatter")?;
    let manifest_tags =
        optional_string_sequence(&skill_manifest.extra, "tags", "skill.yaml extra metadata")?;
    validate_equal("tags", &frontmatter_tags, &metadata.tags)?;
    validate_equal("tags", &manifest_tags, &metadata.tags)?;

    let frontmatter_schema =
        required_string(&frontmatter, "agentenv-schema", "SKILL.md frontmatter")?;
    let manifest_schema = required_string(
        &skill_manifest.extra,
        "agentenv_schema",
        "skill.yaml extra metadata",
    )?;
    validate_equal(
        "agentenv schema",
        frontmatter_schema.as_str(),
        AGENTENV_BUNDLE_SCHEMA,
    )?;
    validate_equal(
        "agentenv schema",
        manifest_schema.as_str(),
        AGENTENV_BUNDLE_SCHEMA,
    )?;

    let frontmatter_bundle =
        required_bool(&frontmatter, "agentenv-bundle", "SKILL.md frontmatter")?;
    let manifest_bundle = required_bool(
        &skill_manifest.extra,
        "agentenv_bundle",
        "skill.yaml extra metadata",
    )?;
    if !frontmatter_bundle || !manifest_bundle {
        return Err(BundleError::Validation {
            message: "agentenv bundle marker must be true in SKILL.md and skill.yaml".to_owned(),
        });
    }

    Ok(())
}

fn parse_skill_md_frontmatter(
    skill_md: &str,
) -> Result<BTreeMap<String, serde_yaml::Value>, BundleError> {
    let mut lines = skill_md.lines();
    if lines.next() != Some("---") {
        return Err(BundleError::Validation {
            message: "SKILL.md is missing frontmatter".to_owned(),
        });
    }

    let mut frontmatter = Vec::new();
    for line in lines {
        if line == "---" {
            return serde_yaml::from_str(&frontmatter.join("\n")).map_err(|source| {
                BundleError::Validation {
                    message: format!("failed to parse SKILL.md frontmatter: {source}"),
                }
            });
        }
        frontmatter.push(line);
    }

    Err(BundleError::Validation {
        message: "SKILL.md frontmatter is not closed".to_owned(),
    })
}

fn required_string(
    map: &BTreeMap<String, serde_yaml::Value>,
    key: &str,
    source: &str,
) -> Result<String, BundleError> {
    match map.get(key) {
        Some(serde_yaml::Value::String(value)) => Ok(value.clone()),
        Some(value) => Err(BundleError::Validation {
            message: format!("{source} field `{key}` must be a string, found `{value:?}`"),
        }),
        None => Err(BundleError::Validation {
            message: format!("{source} is missing `{key}`"),
        }),
    }
}

fn required_bool(
    map: &BTreeMap<String, serde_yaml::Value>,
    key: &str,
    source: &str,
) -> Result<bool, BundleError> {
    match map.get(key) {
        Some(serde_yaml::Value::Bool(value)) => Ok(*value),
        Some(value) => Err(BundleError::Validation {
            message: format!("{source} field `{key}` must be a boolean, found `{value:?}`"),
        }),
        None => Err(BundleError::Validation {
            message: format!("{source} is missing `{key}`"),
        }),
    }
}

fn optional_string_sequence(
    map: &BTreeMap<String, serde_yaml::Value>,
    key: &str,
    source: &str,
) -> Result<Vec<String>, BundleError> {
    let Some(value) = map.get(key) else {
        return Ok(Vec::new());
    };
    let serde_yaml::Value::Sequence(items) = value else {
        return Err(BundleError::Validation {
            message: format!("{source} field `{key}` must be a string sequence"),
        });
    };

    items
        .iter()
        .map(|item| match item {
            serde_yaml::Value::String(value) => Ok(value.clone()),
            other => Err(BundleError::Validation {
                message: format!("{source} field `{key}` contains non-string item `{other:?}`"),
            }),
        })
        .collect()
}

fn validate_equal<T>(field: &str, actual: &T, expected: &T) -> Result<(), BundleError>
where
    T: std::fmt::Debug + PartialEq + ?Sized,
{
    if actual == expected {
        return Ok(());
    }

    Err(BundleError::Validation {
        message: format!(
            "skill metadata `{field}` mismatch: expected `{expected:?}`, found `{actual:?}`"
        ),
    })
}

fn generated_inventory_paths(root: &Path) -> Result<Vec<String>, BundleError> {
    let mut paths = Vec::new();
    collect_file_paths(root, root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_file_paths(
    root: &Path,
    current: &Path,
    paths: &mut Vec<String>,
) -> Result<(), BundleError> {
    let entries = fs::read_dir(current).map_err(|source| BundleError::Io {
        path: current.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| BundleError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| BundleError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(BundleError::Validation {
                message: format!("generated bundle path `{}` is a symlink", path.display()),
            });
        }
        if metadata.is_dir() {
            collect_file_paths(root, &path, paths)?;
        } else if metadata.is_file() {
            paths.push(relative_slash_path(root, &path)?);
        }
    }
    Ok(())
}

fn relative_slash_path(root: &Path, path: &Path) -> Result<String, BundleError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| BundleError::Validation {
            message: format!(
                "generated path `{}` escaped bundle root `{}`",
                path.display(),
                root.display()
            ),
        })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(BundleError::Validation {
                message: format!("generated path `{}` is not relative", path.display()),
            });
        };
        let Some(part) = part.to_str() else {
            return Err(BundleError::Validation {
                message: format!("generated path `{}` is not UTF-8", path.display()),
            });
        };
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn validate_output_ancestry(output_dir: &Path) -> Result<(), BundleError> {
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BundleError::SymlinkAncestor { path: current });
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                create_dir_all(&current)?;
            }
            Err(source) => {
                return Err(BundleError::Io {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn create_unique_staging_dir(output_dir: &Path) -> Result<PathBuf, BundleError> {
    create_unique_staging_dir_with_candidates(
        output_dir,
        std::iter::repeat_with(|| staging_dir_name(output_dir)),
    )
}

fn create_unique_staging_dir_with_candidates(
    output_dir: &Path,
    candidates: impl IntoIterator<Item = String>,
) -> Result<PathBuf, BundleError> {
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    for candidate in candidates.into_iter().take(16) {
        let path = parent.join(candidate);
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(BundleError::Io { path, source }),
        }
    }

    Err(BundleError::Validation {
        message: "failed to allocate unique staging directory".to_owned(),
    })
}

fn staging_dir_name(output_dir: &Path) -> String {
    let name = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bundle");
    format!(".{name}.agentenv-staging-{}", Uuid::new_v4())
}

fn write_file(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), BundleError> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    fs::write(&path, bytes).map_err(|source| BundleError::Io { path, source })
}

fn read_to_string(path: PathBuf) -> Result<String, BundleError> {
    fs::read_to_string(&path).map_err(|source| BundleError::Io { path, source })
}

fn create_dir_all(path: &Path) -> Result<(), BundleError> {
    fs::create_dir_all(path).map_err(|source| BundleError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_dir_all(path: &Path) -> Result<(), BundleError> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_dir_all(path).map_err(|source| BundleError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn publish_staging(from: &Path, to: &Path) -> Result<(), BundleError> {
    publish_staging_no_replace(from, to)
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn publish_staging_no_replace(from: &Path, to: &Path) -> Result<(), BundleError> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};

    match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::EXIST) => Err(BundleError::OutputExists {
            path: to.to_path_buf(),
        }),
        Err(source) => Err(BundleError::Io {
            path: to.to_path_buf(),
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        }),
    }
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
fn publish_staging_no_replace(from: &Path, to: &Path) -> Result<(), BundleError> {
    fs::rename(from, to).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            BundleError::OutputExists {
                path: to.to_path_buf(),
            }
        } else {
            BundleError::Io {
                path: to.to_path_buf(),
                source,
            }
        }
    })
}

fn sha256_file(path: PathBuf) -> Result<String, BundleError> {
    let bytes = fs::read(&path).map_err(|source| BundleError::Io { path, source })?;
    Ok(sha256_digest(&bytes))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

#[cfg(unix)]
fn set_executable(path: PathBuf) -> Result<(), BundleError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(&path)
        .map_err(|source| BundleError::Io {
            path: path.clone(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).map_err(|source| BundleError::Io { path, source })
}

#[cfg(not(unix))]
fn set_executable(_path: PathBuf) -> Result<(), BundleError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use semver::Version;
    use serde_yaml::Value;

    use super::*;
    use crate::skills::SkillManifest;

    #[test]
    fn publish_staging_rejects_existing_output_path() {
        let root = temp_test_dir("publish-existing");
        let staging = root.join("staging");
        let output = root.join("output");
        fs::create_dir(&staging).unwrap();
        fs::create_dir(&output).unwrap();

        let error = publish_staging(&staging, &output).unwrap_err();

        assert!(matches!(error, BundleError::OutputExists { .. }));
        assert!(staging.is_dir());
        assert!(output.is_dir());
    }

    #[test]
    fn unique_staging_dir_does_not_remove_existing_collision() {
        let root = temp_test_dir("staging-collision");
        let output = root.join("bundle");
        let collision = root.join(".bundle.agentenv-staging-test-collision");
        fs::create_dir(&collision).unwrap();
        fs::write(collision.join("sentinel"), b"keep").unwrap();

        let created = create_unique_staging_dir_with_candidates(
            &output,
            [
                ".bundle.agentenv-staging-test-collision".to_owned(),
                ".bundle.agentenv-staging-test-created".to_owned(),
            ],
        )
        .unwrap();

        assert_eq!(created, root.join(".bundle.agentenv-staging-test-created"));
        assert!(collision.join("sentinel").is_file());
        assert!(created.is_dir());
    }

    #[test]
    fn metadata_parity_rejects_frontmatter_description_tags_and_schema_drift() {
        let metadata = SkillBundleMetadata {
            name: "demo".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            description: "Reproducible dev env for demo".to_owned(),
            author: None,
            license: None,
            tags: vec!["openshell".to_owned(), "dev-env".to_owned()],
        };
        let manifest = skill_manifest_for(&metadata);
        let skill_md = r#"---
name: demo
description: Reproducible dev env for demo
version: 1.0.0
tags: [openshell, dev-env]
agentenv-bundle: true
agentenv-schema: "0.1"
---

# demo
"#;

        validate_metadata_parity(&manifest, skill_md, &metadata).unwrap();

        let description_drift = skill_md.replace(
            "description: Reproducible dev env for demo",
            "description: drift",
        );
        assert!(validate_metadata_parity(&manifest, &description_drift, &metadata).is_err());

        let tag_drift = skill_md.replace("tags: [openshell, dev-env]", "tags: [other]");
        assert!(validate_metadata_parity(&manifest, &tag_drift, &metadata).is_err());

        let schema_drift = skill_md.replace("agentenv-schema: \"0.1\"", "agentenv-schema: \"9.9\"");
        assert!(validate_metadata_parity(&manifest, &schema_drift, &metadata).is_err());
    }

    fn skill_manifest_for(metadata: &SkillBundleMetadata) -> SkillManifest {
        let mut extra = BTreeMap::new();
        extra.insert(
            "tags".to_owned(),
            Value::Sequence(
                metadata
                    .tags
                    .iter()
                    .map(|tag| Value::String(tag.clone()))
                    .collect(),
            ),
        );
        extra.insert("agentenv_bundle".to_owned(), Value::Bool(true));
        extra.insert(
            "agentenv_schema".to_owned(),
            Value::String(AGENTENV_BUNDLE_SCHEMA.to_owned()),
        );

        SkillManifest {
            name: metadata.name.clone(),
            version: metadata.version.clone(),
            description: Some(metadata.description.clone()),
            entry: PathBuf::from("SKILL.md"),
            declared_files: vec![PathBuf::from("SKILL.md")],
            self_test_command: None,
            signature_ed25519: None,
            signature_public_key_ed25519: None,
            extra,
        }
    }

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .unwrap()
            .to_path_buf();
        let root = workspace_root.join("target").join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }
}
