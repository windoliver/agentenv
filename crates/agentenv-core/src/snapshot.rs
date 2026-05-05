use std::{collections::BTreeMap, fs, io, path::Path};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

pub const SNAPSHOT_VERSION: &str = "0.1.0";

pub type SnapshotResult<T> = Result<T, SnapshotError>;

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("snapshot IO error: {0}")]
    Io(#[from] io::Error),
    #[error("snapshot JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("snapshot YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("snapshot hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("snapshot signature error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("invalid snapshot path `{path}`")]
    InvalidPath { path: String },
    #[error("digest mismatch for `{path}`: expected `{expected}`, got `{actual}`")]
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("merkle root mismatch: expected `{expected}`, got `{actual}`")]
    MerkleRootMismatch { expected: String, actual: String },
    #[error("manifest hash mismatch: expected `{expected}`, got `{actual}`")]
    ManifestHashMismatch { expected: String, actual: String },
    #[error("signature verification failed")]
    SignatureVerification,
    #[error("payload path `{path}` is not listed in manifest")]
    ExtraPayload { path: String },
    #[error("snapshot is missing required workspace payload at `{path}`")]
    MissingWorkspace { path: String },
    #[error("unsupported snapshot version `{version}`")]
    UnsupportedVersion { version: String },
    #[error("invalid signing key length: expected 32 bytes, got {actual}")]
    InvalidSigningKeyLength { actual: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotEntryKind {
    File,
    Directory,
    Symlink,
}

impl SnapshotEntryKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFileEntry {
    pub path: String,
    pub kind: SnapshotEntryKind,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSection {
    pub path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SnapshotEntryKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCredentialRequirement {
    pub name: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStrippedEntry {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub version: String,
    pub agentenv_version: String,
    pub source_env: String,
    pub created_at: String,
    pub min_agentenv_version: String,
    pub driver_protocol_version: String,
    pub sections: BTreeMap<String, SnapshotSection>,
    pub files: Vec<SnapshotFileEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_requirements: Vec<SnapshotCredentialRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stripped: Vec<SnapshotStrippedEntry>,
    pub merkle_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSignatures {
    pub version: String,
    pub signature_algorithm: String,
    pub hash_algorithm: String,
    pub public_key: String,
    pub manifest_sha256: String,
    pub merkle_root: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
struct Inventory {
    files: Vec<SnapshotFileEntry>,
    merkle_root: String,
    sections: BTreeMap<String, SnapshotSection>,
}

pub fn write_manifest_and_signature(snapshot_dir: &Path, key_path: &Path) -> SnapshotResult<()> {
    let workspace = snapshot_dir.join("workspace");
    if !workspace.is_dir() {
        return Err(SnapshotError::MissingWorkspace {
            path: "workspace".to_owned(),
        });
    }

    let inventory = build_inventory(snapshot_dir)?;
    let manifest = SnapshotManifest {
        version: SNAPSHOT_VERSION.to_owned(),
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_env: "test-env".to_owned(),
        created_at: OffsetDateTime::now_utc().unix_timestamp().to_string(),
        min_agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        driver_protocol_version: agentenv_proto::SCHEMA_VERSION.to_owned(),
        sections: inventory.sections,
        files: inventory.files,
        credential_requirements: Vec::new(),
        stripped: Vec::new(),
        merkle_root: inventory.merkle_root,
    };

    write_signed_manifest(snapshot_dir, key_path, &manifest)
}

pub fn write_signed_manifest(
    snapshot_dir: &Path,
    key_path: &Path,
    manifest: &SnapshotManifest,
) -> SnapshotResult<()> {
    let manifest_path = snapshot_dir.join("manifest.json");
    let signatures_path = snapshot_dir.join("signatures.json");

    let manifest_bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    let manifest_sha256 = sha256_prefixed(&manifest_bytes);

    let signing_key = load_or_create_signing_key(key_path)?;
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let signed_bytes = canonical_signed_message(&manifest_sha256, &manifest.merkle_root)?;
    let signature = signing_key.sign(&signed_bytes);

    let signatures = SnapshotSignatures {
        version: SNAPSHOT_VERSION.to_owned(),
        signature_algorithm: "ed25519".to_owned(),
        hash_algorithm: "sha256".to_owned(),
        public_key,
        manifest_sha256,
        merkle_root: manifest.merkle_root.clone(),
        signature: hex::encode(signature.to_bytes()),
    };

    fs::write(signatures_path, serde_json::to_vec_pretty(&signatures)?)?;
    Ok(())
}

pub fn verify_snapshot_dir(snapshot_dir: &Path) -> SnapshotResult<SnapshotManifest> {
    let manifest_path = snapshot_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.version != SNAPSHOT_VERSION {
        return Err(SnapshotError::UnsupportedVersion {
            version: manifest.version.clone(),
        });
    }

    for entry in &manifest.files {
        validate_relative_display_path(Path::new(&entry.path))?;
    }
    for section in manifest.sections.values() {
        validate_relative_display_path(Path::new(&section.path))?;
    }

    let signatures = read_signatures(&snapshot_dir.join("signatures.json"))?;
    if signatures.version != SNAPSHOT_VERSION {
        return Err(SnapshotError::UnsupportedVersion {
            version: signatures.version.clone(),
        });
    }

    let inventory = build_inventory(snapshot_dir)?;
    let mut actual_by_path = BTreeMap::new();
    for entry in inventory.files {
        actual_by_path.insert(entry.path.clone(), entry);
    }

    let mut listed_by_path = BTreeMap::new();
    for entry in &manifest.files {
        listed_by_path.insert(entry.path.clone(), entry);
    }

    for path in actual_by_path.keys() {
        if !listed_by_path.contains_key(path) {
            return Err(SnapshotError::ExtraPayload { path: path.clone() });
        }
    }

    for (path, expected) in listed_by_path {
        let actual = actual_by_path
            .get(&path)
            .ok_or_else(|| SnapshotError::DigestMismatch {
                path: path.clone(),
                expected: expected.sha256.clone(),
                actual: "<missing>".to_owned(),
            })?;

        if expected.kind != actual.kind {
            return Err(SnapshotError::DigestMismatch {
                path,
                expected: expected.kind.as_str().to_owned(),
                actual: actual.kind.as_str().to_owned(),
            });
        }

        if expected.sha256 != actual.sha256 {
            return Err(SnapshotError::DigestMismatch {
                path,
                expected: expected.sha256.clone(),
                actual: actual.sha256.clone(),
            });
        }
    }

    if manifest.merkle_root != compute_merkle_root(&manifest.files) {
        return Err(SnapshotError::MerkleRootMismatch {
            expected: manifest.merkle_root.clone(),
            actual: compute_merkle_root(&manifest.files),
        });
    }

    if manifest.merkle_root != signatures.merkle_root {
        return Err(SnapshotError::MerkleRootMismatch {
            expected: signatures.merkle_root,
            actual: manifest.merkle_root.clone(),
        });
    }

    let actual_manifest_hash = sha256_prefixed(&manifest_bytes);
    if actual_manifest_hash != signatures.manifest_sha256 {
        return Err(SnapshotError::ManifestHashMismatch {
            expected: signatures.manifest_sha256.clone(),
            actual: actual_manifest_hash,
        });
    }

    let message = canonical_signed_message(&signatures.manifest_sha256, &signatures.merkle_root)?;
    verify_signature(&signatures, &message)?;

    Ok(manifest)
}

pub fn read_signatures(path: &Path) -> SnapshotResult<SnapshotSignatures> {
    let content = fs::read(path)?;
    let signatures: SnapshotSignatures = serde_json::from_slice(&content)?;
    Ok(signatures)
}

fn build_inventory(root: &Path) -> SnapshotResult<Inventory> {
    let mut files = Vec::new();
    walk_payload(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let merkle_root = compute_merkle_root(&files);
    let sections = build_sections(&files)?;

    Ok(Inventory {
        files,
        merkle_root,
        sections,
    })
}

fn walk_payload(
    root: &Path,
    current: &Path,
    files: &mut Vec<SnapshotFileEntry>,
) -> SnapshotResult<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(current)? {
        entries.push(entry?);
    }

    entries.sort_by_key(|left| left.file_name());

    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| SnapshotError::InvalidPath {
                path: path.display().to_string(),
            })?;
        let relative_display = validate_relative_display_path(relative)?;

        if relative_display == "manifest.json" || relative_display == "signatures.json" {
            continue;
        }

        let file_type = metadata.file_type();
        if file_type.is_dir() {
            walk_payload(root, &path, files)?;
            continue;
        }

        if file_type.is_file() {
            let bytes = fs::read(&path)?;
            files.push(SnapshotFileEntry {
                path: relative_display,
                kind: SnapshotEntryKind::File,
                sha256: sha256_prefixed(&bytes),
                size: Some(bytes.len() as u64),
            });
            continue;
        }

        if file_type.is_symlink() {
            let target = fs::read_link(&path)?;
            let target_bytes = symlink_target_bytes(&target);
            files.push(SnapshotFileEntry {
                path: relative_display,
                kind: SnapshotEntryKind::Symlink,
                sha256: sha256_prefixed(&target_bytes),
                size: None,
            });
            continue;
        }

        return Err(SnapshotError::InvalidPath {
            path: path.display().to_string(),
        });
    }

    Ok(())
}

fn build_sections(
    files: &[SnapshotFileEntry],
) -> SnapshotResult<BTreeMap<String, SnapshotSection>> {
    let mut sections = BTreeMap::new();

    for (name, path) in [
        ("blueprint", "blueprint.yaml"),
        ("lock", "lock.yaml"),
        ("policy", "policy.yaml"),
    ] {
        let entry = files
            .iter()
            .find(|entry| entry.path == path)
            .ok_or_else(|| SnapshotError::InvalidPath {
                path: path.to_owned(),
            })?;
        sections.insert(
            name.to_owned(),
            SnapshotSection {
                path: path.to_owned(),
                sha256: entry.sha256.clone(),
                kind: Some(SnapshotEntryKind::File),
            },
        );
    }

    if let Some(entry) = files.iter().find(|entry| entry.path == "events.db") {
        sections.insert(
            "events".to_owned(),
            SnapshotSection {
                path: "events.db".to_owned(),
                sha256: entry.sha256.clone(),
                kind: Some(SnapshotEntryKind::File),
            },
        );
    }

    if has_prefix(files, "workspace/") {
        sections.insert(
            "workspace".to_owned(),
            SnapshotSection {
                path: "workspace".to_owned(),
                sha256: subtree_digest(files, "workspace/"),
                kind: Some(SnapshotEntryKind::Directory),
            },
        );
    }

    if has_prefix(files, "home/") {
        sections.insert(
            "home".to_owned(),
            SnapshotSection {
                path: "home".to_owned(),
                sha256: subtree_digest(files, "home/"),
                kind: Some(SnapshotEntryKind::Directory),
            },
        );
    }

    Ok(sections)
}

fn has_prefix(files: &[SnapshotFileEntry], prefix: &str) -> bool {
    files.iter().any(|entry| entry.path.starts_with(prefix))
}

fn subtree_digest(files: &[SnapshotFileEntry], prefix: &str) -> String {
    let subset: Vec<SnapshotFileEntry> = files
        .iter()
        .filter(|entry| entry.path.starts_with(prefix))
        .cloned()
        .collect();
    compute_merkle_root(&subset)
}

fn compute_merkle_root(files: &[SnapshotFileEntry]) -> String {
    let mut hasher = Sha256::new();
    for entry in files {
        hasher.update(entry.path.as_bytes());
        hasher.update([0_u8]);
        hasher.update(entry.kind.as_str().as_bytes());
        hasher.update([0_u8]);
        hasher.update(entry.sha256.as_bytes());
        hasher.update([0_u8]);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn validate_relative_display_path(path: &Path) -> SnapshotResult<String> {
    use std::path::Component;

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SnapshotError::InvalidPath {
                    path: path.display().to_string(),
                })
            }
        }
    }

    if parts.is_empty() {
        return Err(SnapshotError::InvalidPath {
            path: path.display().to_string(),
        });
    }

    Ok(parts.join("/"))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn canonical_signed_message(manifest_sha256: &str, merkle_root: &str) -> SnapshotResult<Vec<u8>> {
    #[derive(Serialize)]
    struct SignedMessage<'a> {
        manifest_sha256: &'a str,
        merkle_root: &'a str,
    }

    Ok(serde_json::to_vec(&SignedMessage {
        manifest_sha256,
        merkle_root,
    })?)
}

fn load_or_create_signing_key(key_path: &Path) -> SnapshotResult<SigningKey> {
    if key_path.exists() {
        let bytes = fs::read(key_path)?;
        if bytes.len() != 32 {
            return Err(SnapshotError::InvalidSigningKeyLength {
                actual: bytes.len(),
            });
        }
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(&bytes);
        return Ok(SigningKey::from_bytes(&secret));
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    fs::write(key_path, secret)?;
    Ok(SigningKey::from_bytes(&secret))
}

fn verify_signature(signatures: &SnapshotSignatures, message: &[u8]) -> SnapshotResult<()> {
    let public_key_bytes = hex::decode(&signatures.public_key)?;
    if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(SnapshotError::InvalidSigningKeyLength {
            actual: public_key_bytes.len(),
        });
    }
    let mut public_key = [0_u8; PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&public_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&public_key)?;

    let signature_bytes = hex::decode(&signatures.signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| SnapshotError::SignatureVerification)
}

#[cfg(unix)]
fn symlink_target_bytes(target: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    target.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn symlink_target_bytes(target: &Path) -> Vec<u8> {
    target.to_string_lossy().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn inventory_is_deterministic_for_identical_trees() {
        let root = temp_dir("snapshot-inventory-deterministic");
        fs::create_dir_all(root.join("workspace/src")).unwrap();
        fs::write(root.join("blueprint.yaml"), "version: 0.1.0\n").unwrap();
        fs::write(root.join("lock.yaml"), "version: 0.2.0\n").unwrap();
        fs::write(root.join("policy.yaml"), "network: {}\n").unwrap();
        fs::write(root.join("workspace/src/main.rs"), "fn main() {}\n").unwrap();

        let first = build_inventory(&root).expect("first inventory");
        let second = build_inventory(&root).expect("second inventory");

        assert_eq!(first.files, second.files);
        assert_eq!(first.merkle_root, second.merkle_root);
        assert!(first
            .files
            .iter()
            .any(|entry| entry.path == "workspace/src/main.rs"));
    }

    #[test]
    fn verify_detects_payload_tampering() {
        let root = temp_dir("snapshot-verify-tamper");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        fs::write(root.join("workspace/README.md"), "changed\n").unwrap();

        let error = verify_snapshot_dir(&root).expect_err("tampering must fail");
        let rendered = error.to_string();
        assert!(
            rendered.contains("digest mismatch") || rendered.contains("merkle root mismatch"),
            "unexpected error: {rendered}"
        );
    }

    #[test]
    fn verify_detects_signature_mismatch() {
        let root = temp_dir("snapshot-verify-signature");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mut signatures = read_signatures(&root.join("signatures.json")).unwrap();
        signatures.signature = "00".repeat(64);
        fs::write(
            root.join("signatures.json"),
            serde_json::to_string_pretty(&signatures).unwrap(),
        )
        .unwrap();

        let error = verify_snapshot_dir(&root).expect_err("signature mismatch must fail");
        assert!(
            error.to_string().contains("signature"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn verify_rejects_extra_payload_files() {
        let root = temp_dir("snapshot-verify-extra-file");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");
        fs::write(root.join("workspace/extra.txt"), "not inventoried\n").unwrap();

        let error = verify_snapshot_dir(&root).expect_err("extra file must fail");
        assert!(
            error.to_string().contains("not listed in manifest"),
            "unexpected error: {error}"
        );
    }

    fn write_minimal_payload(root: &Path) {
        fs::create_dir_all(root.join("workspace")).unwrap();
        fs::write(root.join("blueprint.yaml"), "version: 0.1.0\n").unwrap();
        fs::write(root.join("lock.yaml"), "version: 0.2.0\n").unwrap();
        fs::write(root.join("policy.yaml"), "network: {}\n").unwrap();
        fs::write(root.join("workspace/README.md"), "hello\n").unwrap();
    }

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
