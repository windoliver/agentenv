use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use semver::Version;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    driver_catalog::{DriverCatalog, DriverDiscoveryConfig, DriverSource},
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
    for entry in catalog.entries {
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
            name: entry.name,
            version: entry.version,
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
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));

    let mut hasher = Sha256::new();
    for entry in entries {
        let path = root.join(&entry.relative);
        hasher.update(entry.kind.marker());
        hasher.update([0]);
        hasher.update(entry.relative.as_bytes());
        hasher.update([0]);

        match entry.kind {
            ArtifactEntryKind::Directory => {}
            ArtifactEntryKind::File => hash_file_bytes(&path, &mut hasher)?,
            ArtifactEntryKind::Symlink => {
                let target = fs::read_link(&path).map_err(|source| DriverArtifactError::Io {
                    path: path.clone(),
                    source,
                })?;
                hasher.update(target.to_string_lossy().as_bytes());
                hasher.update([0]);
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactEntry {
    relative: String,
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

        entries.push(ArtifactEntry {
            relative: normalized_relative_path(root, &path)?,
            kind,
        });

        if kind == ArtifactEntryKind::Directory {
            collect_entries(root, &path, entries)?;
        }
    }

    Ok(())
}

fn normalized_relative_path(root: &Path, path: &Path) -> Result<String, DriverArtifactError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| DriverArtifactError::PathEscapesRoot {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
        })?;

    Ok(relative.to_string_lossy().replace('\\', "/"))
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
