use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    manifest::{normalize_bundle_path, validated_bundle_file},
    SkillError, SkillManifest,
};

const DIGEST_HEADER: &[u8] = b"agentenv-skill-v1\n";

pub fn compute_bundle_digest(
    root: impl AsRef<Path>,
    manifest: &SkillManifest,
) -> Result<String, SkillError> {
    let root = root.as_ref();
    let mut files = BTreeMap::new();
    for file in &manifest.declared_files {
        let normalized = normalize_bundle_path(file)?;
        files.insert(canonical_relative_path(&normalized)?, normalized);
    }

    let mut hasher = Sha256::new();
    hasher.update(DIGEST_HEADER);

    for (relative_path, file) in files {
        let absolute_path = validated_bundle_file(root, &file)?;
        let bytes = fs::read(&absolute_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                SkillError::MissingDeclaredFile { path: file.clone() }
            } else {
                SkillError::Io {
                    path: absolute_path,
                    source,
                }
            }
        })?;

        hasher.update(relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        hasher.update(b"\n");
    }

    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn canonical_relative_path(path: &Path) -> Result<String, SkillError> {
    let normalized = normalize_bundle_path(path)?;
    let mut parts = Vec::new();
    for component in normalized.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(SkillError::UnsafeBundlePath {
                path: path.to_path_buf(),
            });
        };
        let part = part.to_str().ok_or_else(|| SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        })?;
        parts.push(part);
    }

    if parts.is_empty() {
        return Err(SkillError::UnsafeBundlePath {
            path: PathBuf::from(path),
        });
    }

    Ok(parts.join("/"))
}
