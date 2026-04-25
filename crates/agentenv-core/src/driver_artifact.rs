use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use semver::Version;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    driver_catalog::{
        built_in_driver_entries, DiscoveredDriver, DriverCatalog, DriverDiscoveryConfig,
        DriverSource,
    },
    registry::DriverKind,
};

const DIGEST_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverArtifact {
    pub kind: DriverKind,
    pub name: String,
    pub version: Version,
    pub source: DriverSource,
    pub digest: String,
    pub install_hint: Option<String>,
    pub entry: Option<DiscoveredDriver>,
}

#[derive(Debug, Error)]
pub enum DriverArtifactError {
    #[error(transparent)]
    Discovery(#[from] crate::driver_catalog::DriverDiscoveryError),
    #[error("failed to read driver artifact `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to locate current agentenv executable: {source}")]
    CurrentExe {
        #[source]
        source: std::io::Error,
    },
    #[error("missing manifest path for {kind} driver `{name}`")]
    MissingManifest { kind: DriverKind, name: String },
    #[error("driver artifact path `{path}` is not under root `{root}`")]
    PathEscapesRoot { root: PathBuf, path: PathBuf },
}

pub fn discover_driver_artifacts(
    config: DriverDiscoveryConfig,
    built_in_binary: Option<PathBuf>,
) -> Result<Vec<DriverArtifact>, DriverArtifactError> {
    let catalog = DriverCatalog::discover(config)?;
    let built_in_path = match built_in_binary {
        Some(path) => path,
        None => {
            std::env::current_exe().map_err(|source| DriverArtifactError::CurrentExe { source })?
        }
    };
    let built_in_digest = digest_file(&built_in_path)?;

    let mut artifacts = Vec::new();
    let mut seen = BTreeSet::new();
    let built_in_entries = built_in_driver_entries();
    for entry in built_in_entries.iter().chain(catalog.registry_entries()) {
        let key = artifact_key(entry);
        if !seen.insert(key) {
            continue;
        }

        let (digest, install_hint) = match entry.source {
            DriverSource::BuiltIn => (built_in_digest.clone(), None),
            DriverSource::InstalledSubprocess | DriverSource::DevelopmentOverride => {
                let manifest = entry.manifest_path.as_ref().ok_or_else(|| {
                    DriverArtifactError::MissingManifest {
                        kind: entry.kind,
                        name: entry.name.clone(),
                    }
                })?;
                let root = manifest.parent().unwrap_or_else(|| Path::new("."));
                (digest_driver_root(root)?, Some(root.display().to_string()))
            }
        };

        artifacts.push(DriverArtifact {
            kind: entry.kind,
            name: entry.name.clone(),
            version: entry.version.clone(),
            source: entry.source,
            digest,
            install_hint,
            entry: Some(entry.clone()),
        });
    }

    artifacts.sort_by(|left, right| {
        (&left.kind, &left.name, &left.version, left.source).cmp(&(
            &right.kind,
            &right.name,
            &right.version,
            right.source,
        ))
    });
    Ok(artifacts)
}

pub fn digest_driver_root(root: &Path) -> Result<String, DriverArtifactError> {
    let canonical_root = fs::canonicalize(root).map_err(|source| DriverArtifactError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let mut entries = Vec::new();
    collect_entries(root, &canonical_root, root, &mut entries)?;
    entries.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));

    let mut hasher = Sha256::new();
    for entry in entries {
        update_field(&mut hasher, b"entry");
        update_field(&mut hasher, entry.kind.marker());
        update_field(&mut hasher, &entry.sort_key);

        match entry.kind {
            ArtifactEntryKind::Directory => {}
            ArtifactEntryKind::File => {
                let metadata =
                    fs::metadata(&entry.path).map_err(|source| DriverArtifactError::Io {
                        path: entry.path.clone(),
                        source,
                    })?;
                update_field(&mut hasher, file_mode_class(&metadata));
                update_payload_len(&mut hasher, metadata.len());
                hash_file_bytes(&entry.path, &mut hasher)?;
            }
            ArtifactEntryKind::Symlink => {
                let target =
                    fs::read_link(&entry.path).map_err(|source| DriverArtifactError::Io {
                        path: entry.path.clone(),
                        source,
                    })?;
                let target_bytes = path_bytes(&target);
                update_field(&mut hasher, &target_bytes);
            }
        }
    }

    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn digest_file(path: &Path) -> Result<String, DriverArtifactError> {
    let mut hasher = Sha256::new();
    hash_file_bytes(path, &mut hasher)?;
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn artifact_key(entry: &DiscoveredDriver) -> (DriverKind, String, Version, DriverSource, PathBuf) {
    (
        entry.kind,
        entry.name.clone(),
        entry.version.clone(),
        entry.source,
        entry.manifest_path.clone().unwrap_or_default(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactEntry {
    path: PathBuf,
    sort_key: Vec<u8>,
    kind: ArtifactEntryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactEntryKind {
    Directory,
    File,
    Symlink,
}

impl ArtifactEntryKind {
    fn marker(self) -> &'static [u8] {
        match self {
            Self::Directory => b"dir",
            Self::File => b"file",
            Self::Symlink => b"symlink",
        }
    }
}

fn collect_entries(
    root: &Path,
    canonical_root: &Path,
    current: &Path,
    entries: &mut Vec<ArtifactEntry>,
) -> Result<(), DriverArtifactError> {
    for entry in fs::read_dir(current).map_err(|source| DriverArtifactError::Io {
        path: current.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| DriverArtifactError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| DriverArtifactError::Io {
            path: path.clone(),
            source,
        })?;
        let file_type = metadata.file_type();

        let kind = if file_type.is_symlink() {
            validate_symlink_target(root, canonical_root, &path)?;
            ArtifactEntryKind::Symlink
        } else if metadata.is_dir() {
            ArtifactEntryKind::Directory
        } else if metadata.is_file() {
            ArtifactEntryKind::File
        } else {
            continue;
        };

        let relative = normalized_relative_path(root, &path)?;
        entries.push(ArtifactEntry {
            path: path.clone(),
            sort_key: path_bytes(&relative),
            kind,
        });

        if kind == ArtifactEntryKind::Directory {
            collect_entries(root, canonical_root, &path, entries)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn file_mode_class(metadata: &fs::Metadata) -> &'static [u8] {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o111 == 0 {
        b"file"
    } else {
        b"executable-file"
    }
}

#[cfg(not(unix))]
fn file_mode_class(_metadata: &fs::Metadata) -> &'static [u8] {
    b"file"
}

fn validate_symlink_target(
    root: &Path,
    canonical_root: &Path,
    path: &Path,
) -> Result<(), DriverArtifactError> {
    let canonical_target = fs::canonicalize(path).map_err(|source| DriverArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !canonical_target.starts_with(canonical_root) {
        return Err(DriverArtifactError::PathEscapesRoot {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn normalized_relative_path(root: &Path, path: &Path) -> Result<PathBuf, DriverArtifactError> {
    path.strip_prefix(root).map(Path::to_path_buf).map_err(|_| {
        DriverArtifactError::PathEscapesRoot {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
        }
    })
}

fn hash_file_bytes(path: &Path, hasher: &mut Sha256) -> Result<(), DriverArtifactError> {
    let mut file = fs::File::open(path).map_err(|source| DriverArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buffer = [0; DIGEST_CHUNK_SIZE];

    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| DriverArtifactError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(())
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    update_payload_len(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn update_payload_len(hasher: &mut Sha256, len: u64) {
    hasher.update(len.to_be_bytes());
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for component in path.components() {
        let (tag, value) = component_parts(component);
        bytes.push(tag);
        update_component_bytes(&mut bytes, value);
    }
    bytes
}

#[cfg(not(unix))]
fn component_parts(component: std::path::Component<'_>) -> (u8, &std::ffi::OsStr) {
    match component {
        std::path::Component::Prefix(prefix) => (b'p', prefix.as_os_str()),
        std::path::Component::RootDir => (b'r', std::ffi::OsStr::new("")),
        std::path::Component::CurDir => (b'c', std::ffi::OsStr::new("")),
        std::path::Component::ParentDir => (b'u', std::ffi::OsStr::new("")),
        std::path::Component::Normal(value) => (b'n', value),
    }
}

#[cfg(not(unix))]
fn update_component_bytes(bytes: &mut Vec<u8>, value: &std::ffi::OsStr) {
    let encoded = value.as_encoded_bytes();
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(encoded);
}
