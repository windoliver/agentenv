use std::{
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::digest::{parse_sha256_digest, parse_sha256_hex, DigestError};

pub const SKILL_METADATA_SCHEMA_VERSION: &str = "0.1";

#[derive(Debug, Error)]
pub enum SkillCacheError {
    #[error("invalid {kind} segment `{value}`")]
    InvalidPathSegment { kind: &'static str, value: String },
    #[error("invalid skill digest `{digest}`: {source}")]
    InvalidDigest {
        digest: String,
        #[source]
        source: DigestError,
    },
    #[error("failed to read or write `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse or serialize JSON at `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid skill manifest `{path}`: {message}")]
    InvalidSkillManifest { path: PathBuf, message: String },
}

pub type SkillCacheResult<T> = Result<T, SkillCacheError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillCacheLayout {
    root: PathBuf,
}

impl SkillCacheLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn skills_dir(&self) -> PathBuf {
        self.root.join("skills")
    }

    pub fn cache_skills_dir(&self) -> PathBuf {
        self.root.join("cache").join("skills")
    }

    pub fn index_path(&self) -> PathBuf {
        self.skills_dir().join("index.json")
    }

    pub fn installed_skill_dir(&self, name: &str, version: &str) -> SkillCacheResult<PathBuf> {
        validate_segment("skill name", name)?;
        validate_segment("skill version", version)?;
        Ok(self.skills_dir().join(name).join(version))
    }

    pub fn manifest_path(&self, name: &str, version: &str) -> SkillCacheResult<PathBuf> {
        Ok(self
            .installed_skill_dir(name, version)?
            .join(".agentenv")
            .join("manifest.json"))
    }

    pub fn provenance_path(&self, name: &str, version: &str) -> SkillCacheResult<PathBuf> {
        Ok(self
            .installed_skill_dir(name, version)?
            .join(".agentenv")
            .join("provenance.json"))
    }

    pub fn archive_path(&self, digest_hex: &str) -> SkillCacheResult<PathBuf> {
        parse_sha256_hex(digest_hex).map_err(|source| SkillCacheError::InvalidDigest {
            digest: digest_hex.to_owned(),
            source,
        })?;
        Ok(self
            .cache_skills_dir()
            .join(format!("{digest_hex}.tar.zst")))
    }

    pub fn trust_keys_path(&self) -> PathBuf {
        self.skills_dir().join("trust_keys.json")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<SkillArchive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_test: Option<SkillSelfTest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillArchive {
    pub digest: String,
    pub cache_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSelfTest {
    #[serde(default = "default_self_test_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<SkillSelfTestAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SkillSelfTestAssertion {
    FileExists { path: String },
    CommandExitsZero { cmd: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillProvenance {
    pub schema_version: String,
    pub subject: SkillProvenanceSubject,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillProvenanceSubject {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillIndex {
    pub schema_version: String,
    pub skills: Vec<SkillIndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillIndexEntry {
    pub name: String,
    pub version: String,
    pub source: String,
    pub digest: String,
    pub current: bool,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillVerifyOptions {
    pub trust_keys: Vec<SkillTrustKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTrustKey {
    pub id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTrustConfig {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<SkillTrustKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillVerifyReport {
    pub skills: Vec<SkillVerifyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillVerifyEntry {
    pub name: String,
    pub version: String,
    pub status: SkillVerifyStatus,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillVerifyStatus {
    Passed,
    Failed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillFrontmatter {
    name: String,
    version: String,
}

impl SkillVerifyReport {
    pub fn is_ok(&self) -> bool {
        self.skills
            .iter()
            .all(|entry| entry.status == SkillVerifyStatus::Passed)
    }
}

impl SkillManifest {
    pub fn from_json_str(input: &str) -> SkillCacheResult<Self> {
        serde_json::from_str(input).map_err(|source| SkillCacheError::Json {
            path: PathBuf::from("<memory>"),
            source,
        })
    }
}

impl SkillProvenance {
    pub fn from_json_str(input: &str) -> SkillCacheResult<Self> {
        serde_json::from_str(input).map_err(|source| SkillCacheError::Json {
            path: PathBuf::from("<memory>"),
            source,
        })
    }
}

pub fn verify_all_installed_skills(
    layout: &SkillCacheLayout,
    options: SkillVerifyOptions,
) -> SkillCacheResult<SkillVerifyReport> {
    let mut report = SkillVerifyReport::default();
    let skills_dir = layout.skills_dir();

    if skills_dir.is_dir() {
        for name_entry in read_dir_sorted(&skills_dir)? {
            if !name_entry
                .file_type()
                .map_err(|source| SkillCacheError::Io {
                    path: name_entry.path(),
                    source,
                })?
                .is_dir()
            {
                continue;
            }

            let name = name_entry.file_name().to_string_lossy().to_string();
            for version_entry in read_dir_sorted(&name_entry.path())? {
                if !version_entry
                    .file_type()
                    .map_err(|source| SkillCacheError::Io {
                        path: version_entry.path(),
                        source,
                    })?
                    .is_dir()
                {
                    continue;
                }

                let version = version_entry.file_name().to_string_lossy().to_string();
                report.skills.push(verify_installed_skill(
                    layout,
                    &version_entry.path(),
                    &name,
                    &version,
                    &options,
                ));
            }
        }
    }

    report
        .skills
        .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    rebuild_skill_index(layout)?;
    Ok(report)
}

pub fn load_skill_trust_keys(layout: &SkillCacheLayout) -> SkillCacheResult<Vec<SkillTrustKey>> {
    let path = layout.trust_keys_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&path).map_err(|source| SkillCacheError::Io {
        path: path.clone(),
        source,
    })?;
    let config: SkillTrustConfig =
        serde_json::from_str(&content).map_err(|source| SkillCacheError::Json { path, source })?;
    Ok(config.keys)
}

pub fn rebuild_skill_index(layout: &SkillCacheLayout) -> SkillCacheResult<SkillIndex> {
    let mut entries = Vec::new();
    let skills_dir = layout.skills_dir();
    if !skills_dir.exists() {
        return write_index(layout, entries);
    }

    for name_entry in read_dir_sorted(&skills_dir)? {
        if !name_entry
            .file_type()
            .map_err(|source| SkillCacheError::Io {
                path: name_entry.path(),
                source,
            })?
            .is_dir()
        {
            continue;
        }

        let name = name_entry.file_name().to_string_lossy().to_string();
        if name == ".agentenv" {
            continue;
        }

        for version_entry in read_dir_sorted(&name_entry.path())? {
            if !version_entry
                .file_type()
                .map_err(|source| SkillCacheError::Io {
                    path: version_entry.path(),
                    source,
                })?
                .is_dir()
            {
                continue;
            }

            let version = version_entry.file_name().to_string_lossy().to_string();
            let manifest_path = version_entry.path().join(".agentenv").join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }

            let manifest = read_manifest_file(&manifest_path)?;
            entries.push(SkillIndexEntry {
                path: format!("skills/{name}/{version}"),
                name: name.clone(),
                version,
                source: manifest.source,
                digest: manifest.digest,
                current: false,
            });
        }
    }

    entries.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    write_index(layout, entries)
}

fn verify_installed_skill(
    layout: &SkillCacheLayout,
    skill_dir: &Path,
    dir_name: &str,
    dir_version: &str,
    options: &SkillVerifyOptions,
) -> SkillVerifyEntry {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    let manifest_path = skill_dir.join(".agentenv").join("manifest.json");
    let manifest = match read_manifest_file(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            return SkillVerifyEntry {
                name: dir_name.to_owned(),
                version: dir_version.to_owned(),
                status: SkillVerifyStatus::Failed,
                warnings,
                errors: vec![error.to_string()],
            };
        }
    };

    verify_manifest_identity(&manifest, dir_name, dir_version, &mut errors);
    verify_skill_frontmatter(skill_dir, &manifest, &mut errors);
    verify_skill_provenance(skill_dir, &manifest, &mut errors);
    verify_archive(layout, skill_dir, &manifest, &mut warnings, &mut errors);
    verify_signatures(&manifest, options, &mut errors);
    verify_self_tests(skill_dir, &manifest, &mut errors);

    let status = if errors.is_empty() {
        SkillVerifyStatus::Passed
    } else {
        SkillVerifyStatus::Failed
    };
    SkillVerifyEntry {
        name: dir_name.to_owned(),
        version: dir_version.to_owned(),
        status,
        warnings,
        errors,
    }
}

fn verify_manifest_identity(
    manifest: &SkillManifest,
    dir_name: &str,
    dir_version: &str,
    errors: &mut Vec<String>,
) {
    if manifest.name != dir_name {
        errors.push(format!(
            "manifest name mismatch: directory `{dir_name}`, manifest `{}`",
            manifest.name
        ));
    }
    if manifest.version != dir_version {
        errors.push(format!(
            "manifest version mismatch: directory `{dir_version}`, manifest `{}`",
            manifest.version
        ));
    }
    if let Err(source) = parse_sha256_digest(&manifest.digest) {
        errors.push(format!(
            "invalid manifest digest `{}`: {source}",
            manifest.digest
        ));
    }
}

fn verify_skill_frontmatter(skill_dir: &Path, manifest: &SkillManifest, errors: &mut Vec<String>) {
    match read_skill_frontmatter(skill_dir) {
        Ok(frontmatter) => {
            if frontmatter.name != manifest.name {
                errors.push(format!(
                    "SKILL.md frontmatter name mismatch: manifest `{}`, frontmatter `{}`",
                    manifest.name, frontmatter.name
                ));
            }
            if frontmatter.version != manifest.version {
                errors.push(format!(
                    "SKILL.md frontmatter version mismatch: manifest `{}`, frontmatter `{}`",
                    manifest.version, frontmatter.version
                ));
            }
        }
        Err(error) => errors.push(error.to_string()),
    }
}

fn read_skill_frontmatter(skill_dir: &Path) -> SkillCacheResult<SkillFrontmatter> {
    let path = skill_dir.join("SKILL.md");
    let content = fs::read_to_string(&path).map_err(|source| SkillCacheError::Io {
        path: path.clone(),
        source,
    })?;
    parse_skill_frontmatter(&path, &content)
}

fn parse_skill_frontmatter(path: &Path, content: &str) -> SkillCacheResult<SkillFrontmatter> {
    let mut lines = content.lines();
    if !matches!(lines.next(), Some(line) if line.trim_end() == "---") {
        return Err(SkillCacheError::InvalidSkillManifest {
            path: path.to_path_buf(),
            message: "SKILL.md must start with YAML frontmatter delimiter `---`".to_owned(),
        });
    }

    let mut yaml = String::new();
    let mut closed = false;
    for line in lines {
        if line.trim_end() == "---" {
            closed = true;
            break;
        }
        yaml.push_str(line);
        yaml.push('\n');
    }

    if !closed {
        return Err(SkillCacheError::InvalidSkillManifest {
            path: path.to_path_buf(),
            message: "SKILL.md frontmatter is missing closing delimiter `---`".to_owned(),
        });
    }

    serde_yaml::from_str(&yaml).map_err(|source| SkillCacheError::InvalidSkillManifest {
        path: path.to_path_buf(),
        message: format!("invalid SKILL.md frontmatter: {source}"),
    })
}

fn verify_skill_provenance(skill_dir: &Path, manifest: &SkillManifest, errors: &mut Vec<String>) {
    let path = skill_dir.join(".agentenv").join("provenance.json");
    if !path.is_file() {
        errors.push(format!("missing skill provenance `{}`", path.display()));
        return;
    }

    let provenance = match read_provenance_file(&path) {
        Ok(provenance) => provenance,
        Err(error) => {
            errors.push(error.to_string());
            return;
        }
    };

    if provenance.subject.name != manifest.name {
        errors.push(format!(
            "provenance name mismatch: manifest `{}`, provenance `{}`",
            manifest.name, provenance.subject.name
        ));
    }
    if provenance.subject.version != manifest.version {
        errors.push(format!(
            "provenance version mismatch: manifest `{}`, provenance `{}`",
            manifest.version, provenance.subject.version
        ));
    }
    if provenance.subject.digest != manifest.digest {
        errors.push(format!(
            "provenance digest mismatch: manifest `{}`, provenance `{}`",
            manifest.digest, provenance.subject.digest
        ));
    }
}

fn read_provenance_file(path: &Path) -> SkillCacheResult<SkillProvenance> {
    let content = fs::read_to_string(path).map_err(|source| SkillCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&content).map_err(|source| SkillCacheError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn verify_archive(
    layout: &SkillCacheLayout,
    skill_dir: &Path,
    manifest: &SkillManifest,
    warnings: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(archive) = &manifest.archive else {
        warn_with_extracted_tree_digest(skill_dir, warnings, errors);
        return;
    };

    let Some(archive_hex) = verified_digest_hex("archive digest", &archive.digest, errors) else {
        warn_with_extracted_tree_digest(skill_dir, warnings, errors);
        return;
    };

    if manifest.digest != archive.digest {
        errors.push(format!(
            "manifest/archive digest mismatch: manifest `{}`, archive `{}`",
            manifest.digest, archive.digest
        ));
    }

    let expected_cache_key = format!("{archive_hex}.tar.zst");
    if archive.cache_key != expected_cache_key {
        errors.push(format!(
            "archive cache key mismatch: expected `{expected_cache_key}`, found `{}`",
            archive.cache_key
        ));
    }

    let archive_path = match layout.archive_path(&archive_hex) {
        Ok(path) => path,
        Err(error) => {
            errors.push(error.to_string());
            return;
        }
    };
    if !archive_path.is_file() {
        warn_with_extracted_tree_digest(skill_dir, warnings, errors);
        return;
    }

    let bytes = match fs::read(&archive_path) {
        Ok(bytes) => bytes,
        Err(source) => {
            errors.push(
                SkillCacheError::Io {
                    path: archive_path,
                    source,
                }
                .to_string(),
            );
            return;
        }
    };
    let actual_digest = prefixed_sha256(&bytes);
    if actual_digest != manifest.digest || actual_digest != archive.digest {
        errors.push(format!(
            "archive digest mismatch: manifest `{}`, archive `{}`, actual `{actual_digest}`",
            manifest.digest, archive.digest
        ));
    }
}

fn verified_digest_hex(label: &str, digest: &str, errors: &mut Vec<String>) -> Option<String> {
    match parse_sha256_digest(digest) {
        Ok(_) => digest.strip_prefix("sha256:").map(str::to_owned),
        Err(source) => {
            errors.push(format!("invalid {label} `{digest}`: {source}"));
            None
        }
    }
}

fn warn_with_extracted_tree_digest(
    skill_dir: &Path,
    warnings: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match compute_extracted_tree_digest(skill_dir) {
        Ok(digest) => warnings.push(format!(
            "archive missing; extracted tree digest is `{digest}`"
        )),
        Err(error) => errors.push(error.to_string()),
    }
}

fn compute_extracted_tree_digest(skill_dir: &Path) -> SkillCacheResult<String> {
    let mut hasher = Sha256::new();
    update_tree_digest(skill_dir, skill_dir, &mut hasher)?;
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn update_tree_digest(root: &Path, path: &Path, hasher: &mut Sha256) -> SkillCacheResult<()> {
    for entry in read_dir_sorted(path)? {
        let file_name = entry.file_name();
        if file_name == ".agentenv" {
            continue;
        }

        let entry_path = entry.path();
        let relative_path = relative_digest_path(root, &entry_path)?;
        let metadata = fs::symlink_metadata(&entry_path).map_err(|source| SkillCacheError::Io {
            path: entry_path.clone(),
            source,
        })?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            update_digest_record(hasher, "dir", &relative_path, &[]);
            update_tree_digest(root, &entry_path, hasher)?;
        } else if file_type.is_file() {
            let bytes = fs::read(&entry_path).map_err(|source| SkillCacheError::Io {
                path: entry_path.clone(),
                source,
            })?;
            update_digest_record(hasher, "file", &relative_path, &bytes);
        } else if file_type.is_symlink() {
            let target = fs::read_link(&entry_path).map_err(|source| SkillCacheError::Io {
                path: entry_path.clone(),
                source,
            })?;
            update_digest_record(
                hasher,
                "symlink",
                &relative_path,
                target.to_string_lossy().as_bytes(),
            );
        }
    }
    Ok(())
}

fn relative_digest_path(root: &Path, path: &Path) -> SkillCacheResult<String> {
    let relative =
        path.strip_prefix(root)
            .map_err(|source| SkillCacheError::InvalidSkillManifest {
                path: path.to_path_buf(),
                message: format!("failed to compute relative path: {source}"),
            })?;
    let parts = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    Ok(parts.join("/"))
}

fn update_digest_record(hasher: &mut Sha256, kind: &str, path: &str, bytes: &[u8]) {
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(path.as_bytes());
    hasher.update([0]);
    hasher.update(prefixed_sha256(bytes).as_bytes());
    hasher.update([0]);
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn verify_signatures(
    manifest: &SkillManifest,
    options: &SkillVerifyOptions,
    errors: &mut Vec<String>,
) {
    for signature in &manifest.signatures {
        let mut parts = signature.splitn(3, ':');
        let scheme = parts.next();
        let key_id = parts.next();
        let signature_hex = parts.next();
        let (Some("ed25519"), Some(key_id), Some(signature_hex)) = (scheme, key_id, signature_hex)
        else {
            errors.push(format!("invalid signature format `{signature}`"));
            continue;
        };

        let Some(trust_key) = options.trust_keys.iter().find(|key| key.id == key_id) else {
            errors.push(format!("missing trust key `{key_id}`"));
            continue;
        };

        let verifying_key = match parse_verifying_key(trust_key) {
            Ok(verifying_key) => verifying_key,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        let signature = match parse_ed25519_signature(signature_hex) {
            Ok(signature) => signature,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        if verifying_key
            .verify(manifest.digest.as_bytes(), &signature)
            .is_err()
        {
            errors.push(format!("invalid signature for trust key `{key_id}`"));
        }
    }
}

fn parse_verifying_key(trust_key: &SkillTrustKey) -> Result<VerifyingKey, String> {
    let mut bytes = [0_u8; PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(&trust_key.public_key, &mut bytes).map_err(|source| {
        format!(
            "invalid trust key `{}` public key encoding: {source}",
            trust_key.id
        )
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|source| format!("invalid trust key `{}` public key: {source}", trust_key.id))
}

fn parse_ed25519_signature(signature_hex: &str) -> Result<Signature, String> {
    let bytes = hex::decode(signature_hex)
        .map_err(|source| format!("invalid signature encoding: {source}"))?;
    Signature::from_slice(&bytes).map_err(|source| format!("invalid signature encoding: {source}"))
}

fn verify_self_tests(skill_dir: &Path, manifest: &SkillManifest, errors: &mut Vec<String>) {
    let Some(self_test) = &manifest.self_test else {
        return;
    };

    let timeout = Duration::from_secs(self_test.timeout_seconds);
    for assertion in &self_test.assertions {
        match assertion {
            SkillSelfTestAssertion::FileExists { path } => {
                verify_self_test_file_exists(skill_dir, path, errors);
            }
            SkillSelfTestAssertion::CommandExitsZero { cmd } => {
                if let Err(error) = run_self_test_command(skill_dir, cmd, timeout) {
                    errors.push(error);
                }
            }
        }
    }
}

fn verify_self_test_file_exists(skill_dir: &Path, path: &str, errors: &mut Vec<String>) {
    let relative_path = match safe_relative_path(path) {
        Ok(path) => path,
        Err(error) => {
            errors.push(error);
            return;
        }
    };
    if !skill_dir.join(&relative_path).is_file() {
        errors.push(format!("self-test file does not exist `{path}`"));
    }
}

fn safe_relative_path(path: &str) -> Result<PathBuf, String> {
    let source = Path::new(path);
    if source.as_os_str().is_empty() {
        return Err("self-test path must not be empty".to_owned());
    }

    let mut relative = PathBuf::new();
    for component in source.components() {
        match component {
            Component::Normal(segment) => relative.push(segment),
            _ => {
                return Err(format!(
                    "self-test path must be a safe relative path `{path}`"
                ))
            }
        }
    }

    if relative.as_os_str().is_empty() {
        Err("self-test path must not be empty".to_owned())
    } else {
        Ok(relative)
    }
}

fn run_self_test_command(skill_dir: &Path, cmd: &str, timeout: Duration) -> Result<(), String> {
    let mut command = shell_command(cmd);
    let mut child = command
        .current_dir(skill_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|source| format!("self-test command failed to start `{cmd}`: {source}"))?;
    let started_at = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "self-test command failed `{cmd}` with status {status}"
                ));
            }
            Ok(None) => {
                if started_at.elapsed() >= timeout {
                    if let Err(source) = child.kill() {
                        return Err(format!(
                            "self-test command timed out after {}s and could not be killed: {source}",
                            timeout.as_secs()
                        ));
                    }
                    if let Err(source) = child.wait() {
                        return Err(format!(
                            "self-test command timed out after {}s and wait failed: {source}",
                            timeout.as_secs()
                        ));
                    }
                    return Err(format!(
                        "self-test command timed out after {}s `{cmd}`",
                        timeout.as_secs()
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(source) => {
                return Err(format!(
                    "self-test command failed to poll `{cmd}`: {source}"
                ));
            }
        }
    }
}

#[cfg(unix)]
fn shell_command(cmd: &str) -> Command {
    let mut command = Command::new("sh");
    command.arg("-c").arg(cmd);
    command
}

#[cfg(windows)]
fn shell_command(cmd: &str) -> Command {
    let mut command = Command::new("cmd");
    command.arg("/C").arg(cmd);
    command
}

fn read_manifest_file(path: &Path) -> SkillCacheResult<SkillManifest> {
    let content = fs::read_to_string(path).map_err(|source| SkillCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&content).map_err(|source| SkillCacheError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn write_index(
    layout: &SkillCacheLayout,
    skills: Vec<SkillIndexEntry>,
) -> SkillCacheResult<SkillIndex> {
    let index = SkillIndex {
        schema_version: SKILL_METADATA_SCHEMA_VERSION.to_owned(),
        skills,
    };
    let path = layout.index_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SkillCacheError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let rendered =
        serde_json::to_string_pretty(&index).map_err(|source| SkillCacheError::Json {
            path: path.clone(),
            source,
        })?;
    fs::write(&path, format!("{rendered}\n"))
        .map_err(|source| SkillCacheError::Io { path, source })?;
    Ok(index)
}

fn read_dir_sorted(path: &Path) -> SkillCacheResult<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| SkillCacheError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| SkillCacheError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn default_self_test_timeout_seconds() -> u64 {
    120
}

fn validate_segment(kind: &'static str, value: &str) -> SkillCacheResult<()> {
    let path = Path::new(value);
    let valid = !value.is_empty()
        && value != "index.json"
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)));

    if valid {
        Ok(())
    } else {
        Err(SkillCacheError::InvalidPathSegment {
            kind,
            value: value.to_owned(),
        })
    }
}
