use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

use super::{
    model::{
        BundleManifest, BundleManifestAgentenv, BundleManifestFile, BundleManifestSkill,
        BundleProvenance, BundleProvenanceDigests, BundleProvenanceSource, BundleWarning,
        SkillBundleInput, SkillBundleOutput,
    },
    render::{
        ensure_trailing_newline, render_bootstrap, render_reference, render_skill_md,
        render_skill_yaml, AGENTENV_BUNDLE_SCHEMA,
    },
};
use crate::{
    digest::sha256_hex,
    portable_lockfile::{verify_portable_lockfile_yaml, PortableLockfileError},
    skills::{compute_bundle_digest, load_skill_manifest, validate_skill_name, SkillError},
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
    if input.output_dir.exists() {
        return Err(BundleError::OutputExists {
            path: input.output_dir,
        });
    }
    validate_output_ancestry(&input.output_dir)?;
    validate_skill_name(&input.metadata.name)?;

    let staging_dir = staging_dir_for(&input.output_dir)?;
    if staging_dir.exists() {
        remove_dir_all(&staging_dir)?;
    }
    create_dir_all(&staging_dir)?;

    let result = write_and_validate_staging(&input, &staging_dir);
    match result {
        Ok(written) => {
            rename(&staging_dir, &input.output_dir)?;
            let manifest = load_skill_manifest(&input.output_dir)?;
            let bundle_digest = compute_bundle_digest(&input.output_dir, &manifest)?;
            Ok(SkillBundleOutput {
                output_dir: input.output_dir,
                skill_name: input.metadata.name,
                version: input.metadata.version.to_string(),
                bundle_digest,
                blueprint_digest: written.blueprint_digest,
                lockfile_digest: written.lockfile_digest,
                warnings: written.warnings,
            })
        }
        Err(error) => {
            let cleanup = remove_dir_all(&staging_dir);
            if cleanup.is_err() {
                return Err(error);
            }
            Err(error)
        }
    }
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
        render_skill_md(&input.metadata, &input.source.env_name, has_reference).as_bytes(),
    )?;
    write_file(
        staging_dir,
        "skill.yaml",
        render_skill_yaml(&input.metadata, has_reference).as_bytes(),
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
    if !skill_md.contains("agentenv-bundle: true")
        || !skill_md.contains("agentenv-schema: \"0.1\"")
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

fn staging_dir_for(output_dir: &Path) -> Result<PathBuf, BundleError> {
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    let name = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bundle");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| BundleError::Validation {
            message: format!("system clock is before UNIX epoch: {source}"),
        })?
        .as_nanos();
    Ok(parent.join(format!(
        ".{name}.agentenv-staging-{}-{nanos}",
        std::process::id()
    )))
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

fn rename(from: &Path, to: &Path) -> Result<(), BundleError> {
    fs::rename(from, to).map_err(|source| BundleError::Io {
        path: to.to_path_buf(),
        source,
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
