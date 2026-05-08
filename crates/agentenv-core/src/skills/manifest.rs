use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use semver::Version;
use serde::Deserialize;
use serde_yaml::Value;

use super::SkillError;

const MANIFEST_FILE: &str = "skill.yaml";

#[derive(Debug, Clone, PartialEq)]
pub struct SkillManifest {
    pub name: String,
    pub version: Version,
    pub description: Option<String>,
    pub entry: PathBuf,
    pub declared_files: Vec<PathBuf>,
    pub self_test_command: Option<String>,
    pub signature_ed25519: Option<String>,
    pub signature_public_key_ed25519: Option<String>,
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawSkillManifest {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    entry: Option<String>,
    files: Option<Vec<String>>,
    self_test: Option<RawSelfTest>,
    signatures: Option<RawSignatures>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawSelfTest {
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSignatures {
    ed25519: Option<String>,
    public_key: Option<String>,
    public_key_ed25519: Option<String>,
}

pub fn load_skill_manifest(root: impl AsRef<Path>) -> Result<SkillManifest, SkillError> {
    let root = root.as_ref();
    let manifest_path = root.join(MANIFEST_FILE);
    let content = read_manifest_file(&manifest_path)?;
    let raw = parse_raw_manifest(&content, &manifest_path)?;
    manifest_from_raw(raw, &manifest_path, Some(root))
}

pub(crate) fn load_remote_skill_manifest(
    content: &str,
    manifest_path: &Path,
) -> Result<SkillManifest, SkillError> {
    let raw = parse_raw_manifest(content, manifest_path)?;
    manifest_from_raw(raw, manifest_path, None)
}

fn parse_raw_manifest(content: &str, manifest_path: &Path) -> Result<RawSkillManifest, SkillError> {
    serde_yaml::from_str(content).map_err(|source| SkillError::Yaml {
        path: manifest_path.to_path_buf(),
        source,
    })
}

fn manifest_from_raw(
    raw: RawSkillManifest,
    manifest_path: &Path,
    root: Option<&Path>,
) -> Result<SkillManifest, SkillError> {
    let name = required(raw.name, manifest_path, "name")?;
    validate_skill_name(&name)?;

    let version = required(raw.version, manifest_path, "version")?;
    let version = version
        .parse::<Version>()
        .map_err(|source| SkillError::InvalidVersion {
            version: version.clone(),
            source,
        })?;

    let entry = required(raw.entry, manifest_path, "entry")?;
    let entry = normalize_bundle_path(Path::new(&entry))?;
    if let Some(root) = root {
        ensure_declared_file(root, &entry)?;
    }

    let files = raw.files.ok_or_else(|| SkillError::MissingManifestField {
        path: manifest_path.to_path_buf(),
        field: "files",
    })?;
    let declared_files = match root {
        Some(root) => expand_declared_files(root, files)?,
        None => normalize_explicit_declared_files(files)?,
    };
    if !declared_files.contains(&entry) {
        return Err(SkillError::MissingDeclaredFile { path: entry });
    }

    Ok(SkillManifest {
        name,
        version,
        description: raw.description,
        entry,
        declared_files,
        self_test_command: raw.self_test.and_then(|self_test| self_test.command),
        signature_ed25519: raw
            .signatures
            .as_ref()
            .and_then(|signatures| signatures.ed25519.clone()),
        signature_public_key_ed25519: raw
            .signatures
            .and_then(|signatures| signatures.public_key_ed25519.or(signatures.public_key)),
        extra: raw.extra,
    })
}

pub fn validate_skill_name(name: &str) -> Result<(), SkillError> {
    if name.is_empty()
        || name.starts_with('.')
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(SkillError::InvalidSkillName {
            name: name.to_owned(),
        });
    }

    Ok(())
}

pub(crate) fn normalize_bundle_path(path: &Path) -> Result<PathBuf, SkillError> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\\') {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SkillError::UnsafeBundlePath {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }

    Ok(normalized)
}

fn required(
    value: Option<String>,
    manifest_path: &Path,
    field: &'static str,
) -> Result<String, SkillError> {
    value.ok_or_else(|| SkillError::MissingManifestField {
        path: manifest_path.to_path_buf(),
        field,
    })
}

fn read_manifest_file(path: &Path) -> Result<String, SkillError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }

    read_manifest_file_no_follow(path)
}

#[cfg(unix)]
fn read_manifest_file_no_follow(path: &Path) -> Result<String, SkillError> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(content)
}

#[cfg(not(unix))]
fn read_manifest_file_no_follow(path: &Path) -> Result<String, SkillError> {
    fs::read_to_string(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn expand_declared_files(root: &Path, patterns: Vec<String>) -> Result<Vec<PathBuf>, SkillError> {
    let mut files = BTreeSet::new();

    for pattern in patterns {
        if let Some(directory) = pattern.strip_suffix("/**") {
            let directory = normalize_bundle_path(Path::new(directory))?;
            let matched = collect_declared_files(root, &directory, &mut files)?;
            if matched == 0 {
                return Err(SkillError::EmptyFilePattern { pattern });
            }
        } else {
            let file = normalize_bundle_path(Path::new(&pattern))?;
            ensure_declared_file(root, &file)?;
            files.insert(file);
        }
    }

    Ok(files.into_iter().collect())
}

fn normalize_explicit_declared_files(patterns: Vec<String>) -> Result<Vec<PathBuf>, SkillError> {
    let mut files = BTreeSet::new();
    for pattern in patterns {
        if pattern.ends_with("/**") {
            return Err(SkillError::InvalidConfig {
                message: format!(
                    "HTTP registry fetch requires explicit file entries; recursive pattern `{pattern}` is not fetchable"
                ),
            });
        }
        files.insert(normalize_bundle_path(Path::new(&pattern))?);
    }
    Ok(files.into_iter().collect())
}

fn collect_declared_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<usize, SkillError> {
    validated_bundle_directory(root, directory)?;
    collect_declared_files_inner(root, directory, files)
}

fn collect_declared_files_inner(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<usize, SkillError> {
    let absolute_directory = root.join(directory);
    let entries = fs::read_dir(&absolute_directory).map_err(|source| SkillError::Io {
        path: absolute_directory.clone(),
        source,
    })?;
    let mut matched = 0;

    for entry in entries {
        let entry = entry.map_err(|source| SkillError::Io {
            path: absolute_directory.clone(),
            source,
        })?;
        let file_name = entry.file_name();
        let relative_path = normalize_bundle_path(&directory.join(file_name))?;
        let absolute_path = root.join(&relative_path);
        let metadata = fs::symlink_metadata(&absolute_path)
            .map_err(|source| missing_or_io_error(source, &absolute_path, &relative_path))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            matched += collect_declared_files_inner(root, &relative_path, files)?;
        } else if file_type.is_file() {
            files.insert(relative_path);
            matched += 1;
        } else {
            return Err(SkillError::MissingDeclaredFile {
                path: relative_path,
            });
        }
    }

    Ok(matched)
}

fn ensure_declared_file(root: &Path, relative_path: &Path) -> Result<(), SkillError> {
    validated_bundle_file(root, relative_path).map(|_| ())
}

pub(crate) fn validated_bundle_file(
    root: &Path,
    relative_path: &Path,
) -> Result<PathBuf, SkillError> {
    validate_bundle_path_kind(root, relative_path, BundlePathKind::File)
}

fn validated_bundle_directory(root: &Path, relative_path: &Path) -> Result<PathBuf, SkillError> {
    validate_bundle_path_kind(root, relative_path, BundlePathKind::Directory)
}

#[derive(Debug, Clone, Copy)]
enum BundlePathKind {
    File,
    Directory,
}

fn validate_bundle_path_kind(
    root: &Path,
    relative_path: &Path,
    expected: BundlePathKind,
) -> Result<PathBuf, SkillError> {
    let relative_path = normalize_bundle_path(relative_path)?;
    let mut absolute_path = root.to_path_buf();
    let mut components = relative_path.components().peekable();

    while let Some(component) = components.next() {
        let Component::Normal(part) = component else {
            return Err(SkillError::UnsafeBundlePath {
                path: relative_path.clone(),
            });
        };
        absolute_path.push(part);
        let metadata = fs::symlink_metadata(&absolute_path)
            .map_err(|source| missing_or_io_error(source, &absolute_path, &relative_path))?;
        let file_type = metadata.file_type();

        if components.peek().is_some() {
            if !file_type.is_dir() {
                return Err(SkillError::MissingDeclaredFile {
                    path: relative_path.clone(),
                });
            }
            continue;
        }

        let matches_expected = match expected {
            BundlePathKind::File => file_type.is_file(),
            BundlePathKind::Directory => file_type.is_dir(),
        };
        if matches_expected {
            return Ok(absolute_path);
        }

        return Err(SkillError::MissingDeclaredFile {
            path: relative_path.clone(),
        });
    }

    Err(SkillError::UnsafeBundlePath {
        path: relative_path,
    })
}

fn missing_or_io_error(
    source: std::io::Error,
    absolute_path: &Path,
    relative_path: &Path,
) -> SkillError {
    if source.kind() == std::io::ErrorKind::NotFound {
        SkillError::MissingDeclaredFile {
            path: relative_path.to_path_buf(),
        }
    } else {
        SkillError::Io {
            path: absolute_path.to_path_buf(),
            source,
        }
    }
}
