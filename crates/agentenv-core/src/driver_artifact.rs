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
    driver_catalog::{DiscoveredDriver, DriverCatalog, DriverDiscoveryConfig, DriverSource},
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
    for entry in catalog
        .entries
        .iter()
        .filter(|entry| entry.source == DriverSource::BuiltIn)
        .chain(catalog.registry_entries())
    {
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
    let mut entries = Vec::new();
    collect_entries(root, root, &mut entries)?;
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
            collect_entries(root, &path, entries)?;
        }
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
