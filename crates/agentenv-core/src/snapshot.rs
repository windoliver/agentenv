use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    path::Path,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const SNAPSHOT_VERSION: &str = "0.1.0";
const SECRET_SCAN_CHUNK_BYTES: usize = 8 * 1024;
const SECRET_SCAN_TAIL_BYTES: usize = 4 * 1024;

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
    #[error("section mismatch for `{section}`")]
    SectionMismatch { section: String },
    #[error("duplicate manifest file entry for path `{path}`")]
    DuplicateManifestPath { path: String },
    #[error("manifest file entry mismatch for `{path}`")]
    ManifestFileEntryMismatch { path: String },
    #[error("manifest files are not in canonical deterministic order")]
    NonCanonicalManifestFileOrder,
    #[error("unsupported signature algorithm `{algorithm}`")]
    UnsupportedSignatureAlgorithm { algorithm: String },
    #[error("unsupported hash algorithm `{algorithm}`")]
    UnsupportedHashAlgorithm { algorithm: String },
    #[error("insecure signing key permissions at `{path}`")]
    InsecureSigningKeyPermissions { path: String },
    #[error("snapshot time formatting error: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("secret patterns detected after snapshot sanitization: {findings}")]
    SecretPatternDetected { findings: String },
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
    pub mode: SnapshotEntryKind,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizerReport {
    pub stripped: Vec<SnapshotStrippedEntry>,
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

/// Writes and signs a minimal snapshot manifest for tests and simple callers.
///
/// This helper always uses `source_env = "test-env"`. Production flows should
/// construct a complete [`SnapshotManifest`] and call [`write_signed_manifest`].
pub fn write_manifest_and_signature(snapshot_dir: &Path, key_path: &Path) -> SnapshotResult<()> {
    let manifest = manifest_for_snapshot_dir(snapshot_dir, "test-env", Vec::new(), Vec::new())?;

    write_signed_manifest(snapshot_dir, key_path, &manifest)
}

pub fn manifest_for_snapshot_dir(
    snapshot_dir: &Path,
    source_env: &str,
    credential_requirements: Vec<SnapshotCredentialRequirement>,
    stripped: Vec<SnapshotStrippedEntry>,
) -> SnapshotResult<SnapshotManifest> {
    let workspace = snapshot_dir.join("workspace");
    if !workspace.is_dir() {
        return Err(SnapshotError::MissingWorkspace {
            path: "workspace".to_owned(),
        });
    }

    let inventory = build_inventory(snapshot_dir)?;
    Ok(SnapshotManifest {
        version: SNAPSHOT_VERSION.to_owned(),
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_env: source_env.to_owned(),
        created_at: snapshot_timestamp()?,
        min_agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        driver_protocol_version: agentenv_proto::SCHEMA_VERSION.to_owned(),
        sections: inventory.sections,
        files: inventory.files,
        credential_requirements,
        stripped,
        merkle_root: inventory.merkle_root,
    })
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

/// Verifies snapshot integrity against the embedded public key material.
///
/// This validates payload digests, canonical inventory, manifest/signature
/// linkage, and Ed25519 signature correctness, but it does not establish
/// external signer trust.
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
    if signatures.signature_algorithm != "ed25519" {
        return Err(SnapshotError::UnsupportedSignatureAlgorithm {
            algorithm: signatures.signature_algorithm.clone(),
        });
    }
    if signatures.hash_algorithm != "sha256" {
        return Err(SnapshotError::UnsupportedHashAlgorithm {
            algorithm: signatures.hash_algorithm.clone(),
        });
    }

    let inventory = build_inventory(snapshot_dir)?;
    let inventory_merkle_root = inventory.merkle_root.clone();
    if !inventory
        .files
        .iter()
        .any(|entry| entry.path == "workspace" && entry.kind == SnapshotEntryKind::Directory)
    {
        return Err(SnapshotError::MissingWorkspace {
            path: "workspace".to_owned(),
        });
    }
    ensure_manifest_files_match(&manifest.files, &inventory.files)?;

    if manifest.merkle_root != inventory_merkle_root {
        return Err(SnapshotError::MerkleRootMismatch {
            expected: manifest.merkle_root.clone(),
            actual: inventory_merkle_root,
        });
    }

    if manifest.merkle_root != signatures.merkle_root {
        return Err(SnapshotError::MerkleRootMismatch {
            expected: signatures.merkle_root,
            actual: manifest.merkle_root.clone(),
        });
    }

    ensure_sections_match(&manifest.sections, &inventory.sections)?;

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

pub fn sanitize_snapshot_tree(root: &Path) -> SnapshotResult<SanitizerReport> {
    let mut report = SanitizerReport {
        stripped: Vec::new(),
    };

    strip_credential_paths(root, root, &mut report)?;
    redact_structured_files(root)?;
    scan_for_remaining_secrets(root)?;

    report.stripped.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.reason.cmp(&right.reason))
    });
    Ok(report)
}

pub fn read_signatures(path: &Path) -> SnapshotResult<SnapshotSignatures> {
    let content = fs::read(path)?;
    let signatures: SnapshotSignatures = serde_json::from_slice(&content)?;
    Ok(signatures)
}

fn build_inventory(root: &Path) -> SnapshotResult<Inventory> {
    let mut files = Vec::new();
    let _ = walk_payload(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let merkle_root = compute_merkle_root(&files);
    let sections = build_sections(&files)?;

    Ok(Inventory {
        files,
        merkle_root,
        sections,
    })
}

fn strip_credential_paths(
    root: &Path,
    current: &Path,
    report: &mut SanitizerReport,
) -> SnapshotResult<()> {
    for entry in read_dir_sorted(current)? {
        let path = entry.path();
        let relative = relative_path(root, &path)?;
        if is_credential_path(Path::new(&relative)) {
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
            report.stripped.push(SnapshotStrippedEntry {
                path: relative,
                reason: "credential_path".to_owned(),
            });
            continue;
        }

        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            strip_credential_paths(root, &path, report)?;
        }
    }

    Ok(())
}

fn redact_structured_files(root: &Path) -> SnapshotResult<()> {
    for path in payload_files(root, root)? {
        match structured_file_format(&path) {
            Some(StructuredFileFormat::Json) => redact_json_file(&path)?,
            Some(StructuredFileFormat::Yaml) => redact_yaml_file(&path)?,
            None => {}
        }
    }

    Ok(())
}

fn scan_for_remaining_secrets(root: &Path) -> SnapshotResult<()> {
    let mut findings = Vec::new();
    for path in payload_files(root, root)? {
        let relative = relative_path(root, &path)?;
        for pattern_class in scan_file_for_secret_pattern_classes(&path)? {
            findings.push(format!("{relative}:{pattern_class}"));
        }
    }

    findings.sort();
    findings.dedup();
    if findings.is_empty() {
        return Ok(());
    }

    Err(SnapshotError::SecretPatternDetected {
        findings: findings.join(", "),
    })
}

fn payload_files(root: &Path, current: &Path) -> SnapshotResult<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in read_dir_sorted(current)? {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            files.extend(payload_files(root, &path)?);
            continue;
        }

        if metadata.file_type().is_file() {
            let relative = relative_path(root, &path)?;
            if relative != "manifest.json" && relative != "signatures.json" {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn walk_payload(
    root: &Path,
    current: &Path,
    files: &mut Vec<SnapshotFileEntry>,
) -> SnapshotResult<String> {
    let mut digest_parts = Vec::new();

    for entry in read_dir_sorted(current)? {
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
            let digest = walk_payload(root, &path, files)?;
            files.push(SnapshotFileEntry {
                path: relative_display.clone(),
                kind: SnapshotEntryKind::Directory,
                mode: SnapshotEntryKind::Directory,
                sha256: digest.clone(),
                size: None,
            });
            digest_parts.push((relative_display, SnapshotEntryKind::Directory, digest));
            continue;
        }

        if file_type.is_file() {
            let bytes = fs::read(&path)?;
            let digest = sha256_prefixed(&bytes);
            files.push(SnapshotFileEntry {
                path: relative_display.clone(),
                kind: SnapshotEntryKind::File,
                mode: SnapshotEntryKind::File,
                sha256: digest.clone(),
                size: Some(bytes.len() as u64),
            });
            digest_parts.push((relative_display, SnapshotEntryKind::File, digest));
            continue;
        }

        if file_type.is_symlink() {
            let target = fs::read_link(&path)?;
            let target_bytes = symlink_target_bytes(&target);
            let digest = sha256_prefixed(&target_bytes);
            files.push(SnapshotFileEntry {
                path: relative_display.clone(),
                kind: SnapshotEntryKind::Symlink,
                mode: SnapshotEntryKind::Symlink,
                sha256: digest.clone(),
                size: None,
            });
            digest_parts.push((relative_display, SnapshotEntryKind::Symlink, digest));
            continue;
        }

        return Err(SnapshotError::InvalidPath {
            path: path.display().to_string(),
        });
    }

    Ok(compute_directory_digest(&digest_parts))
}

fn build_sections(
    files: &[SnapshotFileEntry],
) -> SnapshotResult<BTreeMap<String, SnapshotSection>> {
    let mut sections = BTreeMap::new();

    for (name, path) in [
        ("blueprint", "blueprint.yaml"),
        ("lockfile", "lock.yaml"),
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

    if let Some(entry) = files
        .iter()
        .find(|entry| entry.path == "workspace" && entry.kind == SnapshotEntryKind::Directory)
    {
        sections.insert(
            "workspace".to_owned(),
            SnapshotSection {
                path: "workspace".to_owned(),
                sha256: entry.sha256.clone(),
                kind: Some(SnapshotEntryKind::Directory),
            },
        );
    }

    if let Some(entry) = files
        .iter()
        .find(|entry| entry.path == "home" && entry.kind == SnapshotEntryKind::Directory)
    {
        sections.insert(
            "home".to_owned(),
            SnapshotSection {
                path: "home".to_owned(),
                sha256: entry.sha256.clone(),
                kind: Some(SnapshotEntryKind::Directory),
            },
        );
    }

    Ok(sections)
}

fn ensure_sections_match(
    manifest_sections: &BTreeMap<String, SnapshotSection>,
    inventory_sections: &BTreeMap<String, SnapshotSection>,
) -> SnapshotResult<()> {
    for (name, inventory_section) in inventory_sections {
        match manifest_sections.get(name) {
            Some(manifest_section) if manifest_section == inventory_section => {}
            _ => {
                return Err(SnapshotError::SectionMismatch {
                    section: name.clone(),
                });
            }
        }
    }

    for name in manifest_sections.keys() {
        if !inventory_sections.contains_key(name) {
            return Err(SnapshotError::SectionMismatch {
                section: name.clone(),
            });
        }
    }

    Ok(())
}

fn ensure_manifest_files_match(
    manifest_files: &[SnapshotFileEntry],
    inventory_files: &[SnapshotFileEntry],
) -> SnapshotResult<()> {
    let mut seen_manifest_paths = BTreeSet::new();
    for entry in manifest_files {
        if !seen_manifest_paths.insert(entry.path.clone()) {
            return Err(SnapshotError::DuplicateManifestPath {
                path: entry.path.clone(),
            });
        }
    }

    let mut inventory_by_path = BTreeMap::new();
    for entry in inventory_files {
        inventory_by_path.insert(entry.path.clone(), entry);
    }

    for entry in inventory_files {
        if !seen_manifest_paths.contains(&entry.path) {
            return Err(SnapshotError::ExtraPayload {
                path: entry.path.clone(),
            });
        }
    }

    if manifest_files == inventory_files {
        return Ok(());
    }

    for entry in manifest_files {
        let actual =
            inventory_by_path
                .get(&entry.path)
                .ok_or_else(|| SnapshotError::DigestMismatch {
                    path: entry.path.clone(),
                    expected: entry.sha256.clone(),
                    actual: "<missing>".to_owned(),
                })?;

        if entry.kind != actual.kind {
            return Err(SnapshotError::DigestMismatch {
                path: entry.path.clone(),
                expected: entry.kind.as_str().to_owned(),
                actual: actual.kind.as_str().to_owned(),
            });
        }
        if entry.mode != actual.mode {
            return Err(SnapshotError::ManifestFileEntryMismatch {
                path: entry.path.clone(),
            });
        }
        if entry.sha256 != actual.sha256 {
            return Err(SnapshotError::DigestMismatch {
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: actual.sha256.clone(),
            });
        }
        if entry.size != actual.size {
            return Err(SnapshotError::ManifestFileEntryMismatch {
                path: entry.path.clone(),
            });
        }
    }

    Err(SnapshotError::NonCanonicalManifestFileOrder)
}

fn compute_directory_digest(parts: &[(String, SnapshotEntryKind, String)]) -> String {
    let mut hasher = Sha256::new();
    for (path, kind, digest) in parts {
        hasher.update(path.as_bytes());
        hasher.update([0_u8]);
        hasher.update(kind.as_str().as_bytes());
        hasher.update([0_u8]);
        hasher.update(digest.as_bytes());
        hasher.update([0_u8]);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
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

fn snapshot_timestamp() -> SnapshotResult<String> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

fn read_dir_sorted(path: &Path) -> SnapshotResult<Vec<fs::DirEntry>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn relative_path(root: &Path, path: &Path) -> SnapshotResult<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| SnapshotError::InvalidPath {
            path: path.display().to_string(),
        })?;
    validate_relative_display_path(relative)
}

fn validate_relative_display_path(path: &Path) -> SnapshotResult<String> {
    use std::path::Component;

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let component = part.to_str().ok_or_else(|| SnapshotError::InvalidPath {
                    path: path.display().to_string(),
                })?;
                parts.push(component.to_owned());
            }
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

fn is_credential_path(path: &Path) -> bool {
    let components: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();

    let Some(basename) = components.last() else {
        return false;
    };

    if basename.starts_with("credentials") {
        return true;
    }

    if components
        .windows(3)
        .any(|window| window[0] == ".config" && window[1] == "gh" && window[2] == "hosts.yml")
    {
        return true;
    }

    let credential_dirs = [".agentenv", ".codex", ".claude", ".openclaw"];
    for (index, component) in components.iter().enumerate() {
        if credential_dirs.contains(&component.as_str())
            && components
                .get(index + 1)
                .is_some_and(|next| next.starts_with("credentials"))
        {
            return true;
        }

        if component == ".aws"
            && components
                .iter()
                .skip(index + 1)
                .any(|part| part.contains("credentials"))
        {
            return true;
        }
    }

    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StructuredFileFormat {
    Json,
    Yaml,
}

fn structured_file_format(path: &Path) -> Option<StructuredFileFormat> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => Some(StructuredFileFormat::Json),
        Some("yaml" | "yml") => Some(StructuredFileFormat::Yaml),
        _ => None,
    }
}

fn redact_json_file(path: &Path) -> SnapshotResult<()> {
    let content = fs::read(path)?;
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&content) else {
        return Ok(());
    };

    if redact_json_value(&mut value) {
        fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    }
    Ok(())
}

fn redact_json_value(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            let mut changed = false;
            for (key, child) in map {
                if is_secret_like_key(key) {
                    if *child != serde_json::Value::String("[redacted]".to_owned()) {
                        *child = serde_json::Value::String("[redacted]".to_owned());
                        changed = true;
                    }
                } else if redact_json_value(child) {
                    changed = true;
                }
            }
            changed
        }
        serde_json::Value::Array(items) => {
            let mut changed = false;
            for item in items {
                if redact_json_value(item) {
                    changed = true;
                }
            }
            changed
        }
        _ => false,
    }
}

fn redact_yaml_file(path: &Path) -> SnapshotResult<()> {
    let content = fs::read(path)?;
    let Ok(mut value) = serde_yaml::from_slice::<serde_yaml::Value>(&content) else {
        return Ok(());
    };

    if redact_yaml_value(&mut value) {
        fs::write(path, serde_yaml::to_string(&value)?)?;
    }
    Ok(())
}

fn redact_yaml_value(value: &mut serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Mapping(map) => {
            let mut changed = false;
            for (key, child) in map {
                if yaml_key_is_secret_like(key) {
                    if *child != serde_yaml::Value::String("[redacted]".to_owned()) {
                        *child = serde_yaml::Value::String("[redacted]".to_owned());
                        changed = true;
                    }
                } else if redact_yaml_value(child) {
                    changed = true;
                }
            }
            changed
        }
        serde_yaml::Value::Sequence(items) => {
            let mut changed = false;
            for item in items {
                if redact_yaml_value(item) {
                    changed = true;
                }
            }
            changed
        }
        _ => false,
    }
}

fn yaml_key_is_secret_like(key: &serde_yaml::Value) -> bool {
    match key {
        serde_yaml::Value::String(key) => is_secret_like_key(key),
        _ => false,
    }
}

fn is_secret_like_key(key: &str) -> bool {
    let normalized = normalize_secret_key(key);
    let secret_markers = [
        "token",
        "secret",
        "password",
        "apikey",
        "authorization",
        "credential",
    ];
    let secret_like = secret_markers
        .iter()
        .any(|marker| normalized.contains(marker));
    let provider_secret_like = (normalized.contains("mcp") || normalized.contains("nexus"))
        && (secret_like || normalized.contains("key"));

    secret_like || provider_secret_like
}

fn normalize_secret_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn detect_secret_pattern_classes(content: &str) -> Vec<&'static str> {
    let mut classes = BTreeSet::new();
    for token in content.split(|character: char| !is_secret_token_character(character)) {
        if token.starts_with("sk-ant-") {
            classes.insert("anthropic_token");
        } else if token.starts_with("sk-") {
            classes.insert("openai_token");
        }

        if token.starts_with("ghp_")
            || token.starts_with("gho_")
            || token.starts_with("ghu_")
            || token.starts_with("ghs_")
            || token.starts_with("ghr_")
            || token.starts_with("github_pat_")
        {
            classes.insert("github_token");
        }

        if token.starts_with("AKIA") || token.starts_with("ASIA") {
            classes.insert("aws_access_key_id");
        }

        if token.starts_with("xoxb-") || token.starts_with("xoxp-") || token.starts_with("xapp-") {
            classes.insert("slack_token");
        }
    }

    for line in content.lines() {
        if key_value_line_has_non_empty_secret(line, &["webhook"]) {
            classes.insert("webhook_secret");
        }
        if key_value_line_has_non_empty_secret(line, &["mcp"]) {
            classes.insert("mcp_token");
        }
        if key_value_line_has_non_empty_secret(line, &["nexus"]) {
            classes.insert("nexus_token");
        }
    }

    classes.into_iter().collect()
}

fn scan_file_for_secret_pattern_classes(path: &Path) -> SnapshotResult<Vec<&'static str>> {
    let mut file = fs::File::open(path)?;
    let mut buffer = [0_u8; SECRET_SCAN_CHUNK_BYTES];
    let mut tail = Vec::new();
    let mut classes = BTreeSet::new();

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        let mut window = Vec::with_capacity(tail.len() + read);
        window.extend_from_slice(&tail);
        window.extend_from_slice(&buffer[..read]);

        let text = String::from_utf8_lossy(&window);
        classes.extend(detect_secret_pattern_classes(&text));

        let tail_start = window.len().saturating_sub(SECRET_SCAN_TAIL_BYTES);
        tail.clear();
        tail.extend_from_slice(&window[tail_start..]);
    }

    Ok(classes.into_iter().collect())
}

fn is_secret_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
}

fn key_value_line_has_non_empty_secret(line: &str, required_key_markers: &[&str]) -> bool {
    let Some((raw_key, raw_value)) = split_key_value(line) else {
        return false;
    };

    let key = normalize_secret_key(raw_key);
    let value = raw_value
        .trim()
        .trim_end_matches(',')
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    if value.is_empty() || value == "[redacted]" {
        return false;
    }

    required_key_markers
        .iter()
        .all(|marker| key.contains(marker))
        && (key.contains("token")
            || key.contains("secret")
            || key.contains("password")
            || key.contains("apikey")
            || key.contains("authorization")
            || key.contains("credential")
            || key.contains("key"))
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    for delimiter in ['=', ':'] {
        if let Some((key, value)) = line.split_once(delimiter) {
            return Some((key, value));
        }
    }

    None
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
        #[cfg(unix)]
        ensure_unix_key_file_hygiene(key_path)?;
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
    write_new_signing_key(key_path, &secret)?;
    Ok(SigningKey::from_bytes(&secret))
}

#[cfg(unix)]
fn ensure_unix_key_file_hygiene(key_path: &Path) -> SnapshotResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(key_path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(SnapshotError::InsecureSigningKeyPermissions {
            path: key_path.display().to_string(),
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SnapshotError::InsecureSigningKeyPermissions {
            path: key_path.display().to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn write_new_signing_key(key_path: &Path, secret: &[u8; 32]) -> SnapshotResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(key_path)?;
    file.write_all(secret)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_new_signing_key(key_path: &Path, secret: &[u8; 32]) -> SnapshotResult<()> {
    fs::write(key_path, secret)?;
    Ok(())
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

    #[test]
    fn verify_rejects_non_lexicographic_manifest_order() {
        let root = temp_dir("snapshot-verify-order");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mut manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        manifest.files.reverse();
        manifest.merkle_root = compute_merkle_root(&manifest.files);
        write_signed_manifest(&root, &key_path, &manifest).expect("rewrite signed snapshot");

        let error = verify_snapshot_dir(&root).expect_err("manifest order mismatch must fail");
        assert!(
            error.to_string().contains("merkle root mismatch")
                || error.to_string().contains("canonical"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn verify_rejects_manifest_section_mismatch() {
        let root = temp_dir("snapshot-verify-sections");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mut manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        manifest.sections.remove("blueprint");
        write_signed_manifest(&root, &key_path, &manifest).expect("rewrite signed snapshot");

        let error = verify_snapshot_dir(&root).expect_err("section mismatch must fail");
        let rendered = error.to_string();
        assert!(
            rendered.contains("section")
                || rendered.contains("blueprint")
                || rendered.contains("digest mismatch"),
            "unexpected error: {rendered}"
        );
    }

    #[test]
    fn verify_rejects_duplicate_manifest_paths() {
        let root = temp_dir("snapshot-verify-duplicate-path");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mut manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        let duplicate = manifest
            .files
            .iter()
            .find(|entry| entry.path == "workspace/README.md")
            .expect("workspace file")
            .clone();
        manifest.files.push(duplicate);
        write_signed_manifest(&root, &key_path, &manifest).expect("rewrite signed snapshot");

        let error = verify_snapshot_dir(&root).expect_err("duplicate paths must fail");
        let rendered = error.to_string();
        assert!(
            rendered.contains("duplicate") || rendered.contains("manifest"),
            "unexpected error: {rendered}"
        );
    }

    #[test]
    fn verify_rejects_manifest_size_mismatch() {
        let root = temp_dir("snapshot-verify-size-mismatch");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mut manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        let workspace_entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "workspace/README.md")
            .expect("workspace file");
        workspace_entry.size = Some(workspace_entry.size.unwrap_or(0) + 1);
        write_signed_manifest(&root, &key_path, &manifest).expect("rewrite signed snapshot");

        let error = verify_snapshot_dir(&root).expect_err("size mismatch must fail");
        let rendered = error.to_string();
        assert!(
            rendered.contains("size") || rendered.contains("manifest"),
            "unexpected error: {rendered}"
        );
    }

    #[test]
    fn verify_rejects_unsupported_signature_algorithms() {
        let root = temp_dir("snapshot-verify-algorithms");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mut signatures =
            read_signatures(&root.join("signatures.json")).expect("read signatures");
        signatures.signature_algorithm = "rsa".to_owned();
        signatures.hash_algorithm = "sha1".to_owned();
        fs::write(
            root.join("signatures.json"),
            serde_json::to_string_pretty(&signatures).expect("serialize signatures"),
        )
        .expect("write signatures");

        let error = verify_snapshot_dir(&root).expect_err("unsupported algorithms must fail");
        let rendered = error.to_string();
        assert!(
            rendered.contains("algorithm") || rendered.contains("signature"),
            "unexpected error: {rendered}"
        );
    }

    #[test]
    fn manifest_sections_use_lockfile_key() {
        let root = temp_dir("snapshot-sections-lockfile");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        assert!(manifest.sections.contains_key("lockfile"));
        assert!(!manifest.sections.contains_key("lock"));
    }

    #[test]
    fn written_manifest_entries_include_mode_field() {
        let root = temp_dir("snapshot-mode-field");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let raw = fs::read_to_string(root.join("manifest.json")).expect("read manifest json");
        let json: serde_json::Value = serde_json::from_str(&raw).expect("parse json");
        let files = json
            .get("files")
            .and_then(serde_json::Value::as_array)
            .expect("files array");
        assert!(!files.is_empty());
        assert!(files.iter().all(|entry| entry.get("mode").is_some()));

        let manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        assert!(manifest.files.iter().all(|entry| entry.kind == entry.mode));
    }

    #[test]
    fn inventory_includes_empty_directories_and_verify_rejects_new_empty_directory() {
        let root = temp_dir("snapshot-empty-dirs");
        write_minimal_payload(&root);
        fs::create_dir_all(root.join("workspace/empty")).unwrap();
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        assert!(manifest
            .files
            .iter()
            .any(|entry| entry.path == "workspace/empty"
                && entry.kind == SnapshotEntryKind::Directory));

        fs::create_dir_all(root.join("workspace/new-empty")).unwrap();
        let error = verify_snapshot_dir(&root).expect_err("extra empty directory must fail");
        assert!(
            error.to_string().contains("not listed in manifest"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn verify_rejects_manifest_mode_mismatch() {
        let root = temp_dir("snapshot-mode-mismatch");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mut manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "workspace/README.md")
            .expect("workspace file");
        entry.mode = SnapshotEntryKind::Directory;
        write_signed_manifest(&root, &key_path, &manifest).expect("rewrite signed snapshot");

        let error = verify_snapshot_dir(&root).expect_err("mode mismatch must fail");
        assert!(
            error.to_string().contains("manifest file entry mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn verify_rejects_missing_workspace_payload() {
        let root = temp_dir("snapshot-missing-workspace");
        fs::write(root.join("blueprint.yaml"), "version: 0.1.0\n").unwrap();
        fs::write(root.join("lock.yaml"), "version: 0.2.0\n").unwrap();
        fs::write(root.join("policy.yaml"), "network: {}\n").unwrap();
        let key_path = root.with_extension("key");

        let inventory = build_inventory(&root).expect("inventory");
        let manifest = SnapshotManifest {
            version: SNAPSHOT_VERSION.to_owned(),
            agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_env: "test-env".to_owned(),
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .expect("format timestamp"),
            min_agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            driver_protocol_version: agentenv_proto::SCHEMA_VERSION.to_owned(),
            sections: inventory.sections,
            files: inventory.files,
            credential_requirements: Vec::new(),
            stripped: Vec::new(),
            merkle_root: inventory.merkle_root,
        };
        write_signed_manifest(&root, &key_path, &manifest).expect("write signed snapshot");

        let error = verify_snapshot_dir(&root).expect_err("missing workspace must fail");
        assert!(
            error.to_string().contains("missing required workspace"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn sanitizer_removes_known_credential_paths() {
        let root = temp_dir("snapshot-sanitize-paths");
        fs::create_dir_all(root.join("home/.agentenv/credentials.d")).unwrap();
        fs::create_dir_all(root.join("home/.codex")).unwrap();
        fs::create_dir_all(root.join("home/.claude")).unwrap();
        fs::create_dir_all(root.join("home/.openclaw")).unwrap();
        fs::create_dir_all(root.join("home/.config/gh")).unwrap();
        fs::create_dir_all(root.join("home/.aws/profile")).unwrap();
        fs::create_dir_all(root.join("workspace")).unwrap();
        fs::write(root.join("home/.agentenv/credentials.d/token"), "secret").unwrap();
        fs::write(root.join("home/.codex/credentials.json"), "secret").unwrap();
        fs::write(root.join("home/.claude/credentials.yml"), "secret").unwrap();
        fs::write(root.join("home/.openclaw/credentials"), "secret").unwrap();
        fs::write(root.join("home/.config/gh/hosts.yml"), "secret").unwrap();
        fs::write(root.join("home/.aws/profile/credentials.backup"), "secret").unwrap();
        fs::write(root.join("workspace/credentials.local"), "secret").unwrap();
        fs::write(root.join("workspace/keep.txt"), "safe").unwrap();

        let report = sanitize_snapshot_tree(&root).expect("sanitize tree");
        let mut stripped_paths: Vec<_> = report
            .stripped
            .iter()
            .map(|entry| (entry.path.as_str(), entry.reason.as_str()))
            .collect();
        stripped_paths.sort_unstable();

        assert_eq!(
            stripped_paths,
            vec![
                ("home/.agentenv/credentials.d", "credential_path"),
                ("home/.aws/profile/credentials.backup", "credential_path"),
                ("home/.claude/credentials.yml", "credential_path"),
                ("home/.codex/credentials.json", "credential_path"),
                ("home/.config/gh/hosts.yml", "credential_path"),
                ("home/.openclaw/credentials", "credential_path"),
                ("workspace/credentials.local", "credential_path"),
            ]
        );
        assert!(!root.join("home/.agentenv/credentials.d").exists());
        assert!(!root.join("home/.codex/credentials.json").exists());
        assert!(!root.join("home/.config/gh/hosts.yml").exists());
        assert!(!root.join("home/.aws/profile/credentials.backup").exists());
        assert!(!root.join("workspace/credentials.local").exists());
        assert_eq!(
            fs::read_to_string(root.join("workspace/keep.txt")).unwrap(),
            "safe"
        );
    }

    #[test]
    fn sanitizer_redacts_structured_json_and_yaml_secrets() {
        let root = temp_dir("snapshot-sanitize-redact");
        fs::create_dir_all(root.join("workspace/config")).unwrap();
        fs::write(
            root.join("workspace/config/settings.json"),
            r#"{
  "token": "sk-test-redact-json",
  "nested": {
    "mcp_token": "mcp-secret",
    "safe": "keep"
  },
  "items": [
    {"nexus_api_key": "nexus-secret"}
  ]
}
"#,
        )
        .unwrap();
        fs::write(
            root.join("workspace/config/settings.yaml"),
            "service:\n  password: yaml-secret\n  authorization: bearer-secret\n  nested:\n    - credential: nested-secret\n    - name: safe\n",
        )
        .unwrap();

        let report = sanitize_snapshot_tree(&root).expect("sanitize tree");
        assert!(report.stripped.is_empty());

        let json: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("workspace/config/settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(json["token"], "[redacted]");
        assert_eq!(json["nested"]["mcp_token"], "[redacted]");
        assert_eq!(json["nested"]["safe"], "keep");
        assert_eq!(json["items"][0]["nexus_api_key"], "[redacted]");

        let yaml: serde_yaml::Value = serde_yaml::from_str(
            &fs::read_to_string(root.join("workspace/config/settings.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(yaml["service"]["password"], "[redacted]");
        assert_eq!(yaml["service"]["authorization"], "[redacted]");
        assert_eq!(yaml["service"]["nested"][0]["credential"], "[redacted]");
        assert_eq!(yaml["service"]["nested"][1]["name"], "safe");
    }

    #[test]
    fn sanitizer_fails_closed_when_secret_pattern_remains() {
        let root = temp_dir("snapshot-sanitize-fails-closed");
        fs::create_dir_all(root.join("workspace")).unwrap();
        let openai_secret = "sk-testABCDEFGHIJKLMNOP";
        let ghp_secret = "ghp_ABCDEFGHIJKLMNOP";
        let github_pat_secret = "github_pat_11ABCDEFGSECRETSECRETSECRETSECRETSECRET";
        fs::write(
            root.join("workspace/openai.txt"),
            format!("token={openai_secret}\n"),
        )
        .unwrap();
        fs::write(
            root.join("workspace/ghp.txt"),
            format!("token={ghp_secret}\n"),
        )
        .unwrap();
        fs::write(
            root.join("workspace/github-pat.txt"),
            format!("token={github_pat_secret}\n"),
        )
        .unwrap();
        fs::write(
            root.join("workspace/aws.txt"),
            "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n",
        )
        .unwrap();

        let error = sanitize_snapshot_tree(&root).expect_err("leaks must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("workspace/openai.txt"));
        assert!(rendered.contains("openai_token"));
        assert!(rendered.contains("workspace/ghp.txt"));
        assert!(rendered.contains("github_token"));
        assert!(rendered.contains("workspace/github-pat.txt"));
        assert!(rendered.contains("workspace/aws.txt"));
        assert!(rendered.contains("aws_access_key_id"));
        assert!(
            !rendered.contains(openai_secret),
            "error leaked injected secret: {rendered}"
        );
        assert!(
            !rendered.contains(ghp_secret),
            "error leaked injected secret: {rendered}"
        );
        assert!(
            !rendered.contains(github_pat_secret),
            "error leaked injected secret: {rendered}"
        );
        assert!(
            !rendered.contains("AKIAABCDEFGHIJKLMNOP"),
            "error leaked AWS fixture: {rendered}"
        );
    }

    #[test]
    fn sanitizer_ignores_malformed_structured_files_with_safe_text() {
        let root = temp_dir("snapshot-sanitize-malformed-safe");
        fs::create_dir_all(root.join("workspace")).unwrap();
        fs::write(root.join("workspace/bad.json"), "{ not valid json: safe\n").unwrap();
        fs::write(root.join("workspace/bad.yaml"), "safe: [not valid yaml\n").unwrap();

        let report = sanitize_snapshot_tree(&root).expect("safe malformed files should sanitize");
        assert!(report.stripped.is_empty());
        assert_eq!(
            fs::read_to_string(root.join("workspace/bad.json")).unwrap(),
            "{ not valid json: safe\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("workspace/bad.yaml")).unwrap(),
            "safe: [not valid yaml\n"
        );
    }

    #[test]
    fn sanitizer_scans_malformed_structured_files_for_deny_patterns() {
        let root = temp_dir("snapshot-sanitize-malformed-leak");
        fs::create_dir_all(root.join("workspace")).unwrap();
        let secret = "sk-testMALFORMEDSECRET";
        fs::write(
            root.join("workspace/bad.json"),
            format!("{{ token: {secret}\n"),
        )
        .unwrap();
        fs::write(root.join("workspace/bad.yaml"), "safe: [not valid yaml\n").unwrap();

        let error = sanitize_snapshot_tree(&root).expect_err("malformed leaked secret must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("workspace/bad.json"));
        assert!(rendered.contains("openai_token"));
        assert!(
            !rendered.contains(secret),
            "error leaked secret: {rendered}"
        );
    }

    #[test]
    fn helper_created_at_is_rfc3339_utc_shape() {
        let root = temp_dir("snapshot-created-at");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let manifest = read_manifest(&root.join("manifest.json")).expect("read manifest");
        assert!(manifest.created_at.contains('T'));
        assert!(manifest.created_at.ends_with('Z'));
    }

    #[cfg(unix)]
    #[test]
    fn generated_signing_key_is_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("snapshot-key-mode");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        write_manifest_and_signature(&root, &key_path).expect("write signed snapshot");

        let mode = fs::metadata(&key_path)
            .expect("key metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "key mode must not expose group/world bits");
    }

    #[cfg(unix)]
    #[test]
    fn inventory_rejects_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = temp_dir("snapshot-non-utf8");
        write_minimal_payload(&root);
        let bad = OsString::from_vec(vec![b'b', b'a', b'd', 0x80]);
        if fs::write(root.join(bad), "oops\n").is_err() {
            return;
        }

        let error = build_inventory(&root).expect_err("non-utf8 path must fail");
        assert!(
            error.to_string().contains("invalid snapshot path"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_insecure_signing_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("snapshot-key-insecure-existing");
        write_minimal_payload(&root);
        let key_path = root.with_extension("key");
        fs::write(&key_path, [0x11_u8; 32]).unwrap();

        let mut permissions = fs::metadata(&key_path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&key_path, permissions).unwrap();

        let error = write_manifest_and_signature(&root, &key_path)
            .expect_err("insecure existing key must fail");
        assert!(
            error
                .to_string()
                .contains("insecure signing key permissions"),
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

    fn read_manifest(path: &Path) -> SnapshotResult<SnapshotManifest> {
        let bytes = fs::read(path)?;
        let manifest = serde_json::from_slice(&bytes)?;
        Ok(manifest)
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
