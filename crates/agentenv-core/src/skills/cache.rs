#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    collections::BTreeSet,
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::digest::{parse_sha256_digest, parse_sha256_hex, DigestError};

pub use super::self_test::SkillSelfTestAssertion;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSelfTest {
    #[serde(default = "default_self_test_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<SkillSelfTestAssertion>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillVerifyOptions {
    pub trust_keys: Vec<SkillTrustKey>,
    pub run_self_tests: bool,
}

impl Default for SkillVerifyOptions {
    fn default() -> Self {
        Self {
            trust_keys: Vec::new(),
            run_self_tests: true,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillPrunePlan {
    pub removed_archives: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillFrontmatter {
    name: String,
    version: String,
}

struct VerifiedSkill {
    entry: SkillVerifyEntry,
    index_entry: Option<SkillIndexEntry>,
    manifest: Option<SkillManifest>,
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
    let mut index_entries = Vec::new();
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
            let name_path = name_entry.path();
            let current_version = current_version_for_skill_dir(&name_path)?;
            for version_entry in read_dir_sorted(&name_path)? {
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
                let verified = verify_installed_skill(
                    layout,
                    &version_entry.path(),
                    &name,
                    &version,
                    &options,
                );
                if let Some(mut index_entry) = verified.index_entry {
                    index_entry.current =
                        current_version.as_deref() == Some(index_entry.version.as_str());
                    index_entries.push(index_entry);
                }
                report.skills.push(verified.entry);
            }
        }
    }

    report
        .skills
        .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    index_entries.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    write_index(layout, index_entries)?;
    Ok(report)
}

pub fn verify_skill_pins(
    layout: &SkillCacheLayout,
    pins: &[crate::lockfile::SkillPin],
    options: SkillVerifyOptions,
) -> SkillCacheResult<SkillVerifyReport> {
    let mut report = SkillVerifyReport::default();

    for pin in pins {
        report.skills.push(verify_skill_pin(layout, pin, &options)?);
    }

    report
        .skills
        .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
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

pub fn plan_skill_prune(layout: &SkillCacheLayout) -> SkillCacheResult<SkillPrunePlan> {
    let mut referenced = BTreeSet::new();
    collect_installed_manifest_archive_refs(layout, &mut referenced)?;
    collect_env_lockfile_skill_refs(layout, &mut referenced)?;

    let mut removed_archives = Vec::new();
    let cache_dir = layout.cache_skills_dir();
    if cache_dir.is_dir() {
        for entry in read_dir_sorted(&cache_dir)? {
            let path = entry.path();
            if !entry
                .file_type()
                .map_err(|source| SkillCacheError::Io {
                    path: path.clone(),
                    source,
                })?
                .is_file()
            {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Some(hex) = file_name.strip_suffix(".tar.zst") else {
                continue;
            };
            if parse_sha256_hex(hex).is_ok() && !referenced.contains(hex) {
                removed_archives.push(path);
            }
        }
    }

    removed_archives.sort();
    Ok(SkillPrunePlan { removed_archives })
}

pub fn execute_skill_prune(plan: &SkillPrunePlan) -> SkillCacheResult<()> {
    for path in &plan.removed_archives {
        fs::remove_file(path).map_err(|source| SkillCacheError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
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

        let name_path = name_entry.path();
        let current_version = current_version_for_skill_dir(&name_path)?;
        for version_entry in read_dir_sorted(&name_path)? {
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
            let current = current_version.as_deref() == Some(version.as_str());
            entries.push(SkillIndexEntry {
                path: format!("skills/{name}/{version}"),
                name: name.clone(),
                version,
                source: manifest.source,
                digest: manifest.digest,
                current,
            });
        }
    }

    entries.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    write_index(layout, entries)
}

fn collect_installed_manifest_archive_refs(
    layout: &SkillCacheLayout,
    referenced: &mut BTreeSet<String>,
) -> SkillCacheResult<()> {
    let index = rebuild_skill_index(layout)?;
    for entry in index.skills {
        if let Some(hex) = valid_digest_hex(&entry.digest) {
            referenced.insert(hex);
        }
    }
    Ok(())
}

fn collect_env_lockfile_skill_refs(
    layout: &SkillCacheLayout,
    referenced: &mut BTreeSet<String>,
) -> SkillCacheResult<()> {
    let envs_dir = layout.root().join("envs");
    if !envs_dir.is_dir() {
        return Ok(());
    }

    for entry in read_dir_sorted(&envs_dir)? {
        let lock_path = entry.path().join("lock.yaml");
        if !lock_path.is_file() {
            continue;
        }
        let lock_yaml = fs::read_to_string(&lock_path).map_err(|source| SkillCacheError::Io {
            path: lock_path.clone(),
            source,
        })?;
        if let Ok(crate::lockfile::LockfileDocument::Portable(lockfile)) =
            crate::lockfile::LockfileDocument::from_yaml(&lock_yaml)
        {
            for skill in lockfile.skills {
                if let Some(hex) = valid_digest_hex(&skill.digest) {
                    referenced.insert(hex);
                }
            }
        }
    }

    Ok(())
}

fn valid_digest_hex(digest: &str) -> Option<String> {
    let hex = digest.strip_prefix("sha256:")?;
    parse_sha256_hex(hex).ok()?;
    Some(hex.to_owned())
}

fn verify_installed_skill(
    layout: &SkillCacheLayout,
    skill_dir: &Path,
    dir_name: &str,
    dir_version: &str,
    options: &SkillVerifyOptions,
) -> VerifiedSkill {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    let manifest_path = skill_dir.join(".agentenv").join("manifest.json");
    let manifest = match read_manifest_file(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            return VerifiedSkill {
                entry: SkillVerifyEntry {
                    name: dir_name.to_owned(),
                    version: dir_version.to_owned(),
                    status: SkillVerifyStatus::Failed,
                    warnings,
                    errors: vec![error.to_string()],
                },
                index_entry: None,
                manifest: None,
            };
        }
    };

    verify_manifest_schema(&manifest, &mut errors);
    verify_manifest_identity(&manifest, dir_name, dir_version, &mut errors);
    verify_skill_frontmatter(skill_dir, &manifest, &mut errors);
    verify_skill_provenance(skill_dir, &manifest, &mut errors);
    verify_archive(layout, skill_dir, &manifest, &mut warnings, &mut errors);
    verify_signatures(&manifest, options, &mut errors);
    if options.run_self_tests {
        verify_self_tests(skill_dir, &manifest, &mut errors);
    }

    let status = if errors.is_empty() {
        SkillVerifyStatus::Passed
    } else {
        SkillVerifyStatus::Failed
    };

    let index_entry = (status == SkillVerifyStatus::Passed).then(|| SkillIndexEntry {
        path: format!("skills/{dir_name}/{dir_version}"),
        name: dir_name.to_owned(),
        version: dir_version.to_owned(),
        source: manifest.source.clone(),
        digest: manifest.digest.clone(),
        current: false,
    });

    VerifiedSkill {
        entry: SkillVerifyEntry {
            name: dir_name.to_owned(),
            version: dir_version.to_owned(),
            status,
            warnings,
            errors,
        },
        index_entry,
        manifest: Some(manifest),
    }
}

fn verify_skill_pin(
    layout: &SkillCacheLayout,
    pin: &crate::lockfile::SkillPin,
    options: &SkillVerifyOptions,
) -> SkillCacheResult<SkillVerifyEntry> {
    let skill_dir = match layout.installed_skill_dir(&pin.name, &pin.version) {
        Ok(path) => path,
        Err(error) => {
            return Ok(failed_skill_pin_entry(pin, vec![error.to_string()]));
        }
    };

    if !skill_dir.is_dir() {
        return Ok(failed_skill_pin_entry(
            pin,
            vec![format!(
                "missing skill pin `{}` version `{}` from `{}`",
                pin.name, pin.version, pin.source
            )],
        ));
    }

    let verified = verify_installed_skill(layout, &skill_dir, &pin.name, &pin.version, options);
    let mut entry = verified.entry;

    if let Some(manifest) = verified.manifest {
        verify_skill_pin_manifest(pin, &manifest, &mut entry.errors);
    }
    for warning in &entry.warnings {
        entry.errors.push(format!(
            "skill pin `{}` version `{}` has verification warning: {warning}",
            pin.name, pin.version
        ));
    }
    if !entry.errors.is_empty() {
        entry.status = SkillVerifyStatus::Failed;
    }

    Ok(entry)
}

fn failed_skill_pin_entry(
    pin: &crate::lockfile::SkillPin,
    errors: Vec<String>,
) -> SkillVerifyEntry {
    SkillVerifyEntry {
        name: pin.name.clone(),
        version: pin.version.clone(),
        status: SkillVerifyStatus::Failed,
        warnings: Vec::new(),
        errors,
    }
}

fn verify_skill_pin_manifest(
    pin: &crate::lockfile::SkillPin,
    manifest: &SkillManifest,
    errors: &mut Vec<String>,
) {
    if manifest.source != pin.source {
        errors.push(format!(
            "skill pin source mismatch for `{}` version `{}`: lockfile `{}`, manifest `{}`",
            pin.name, pin.version, pin.source, manifest.source
        ));
    }
    if manifest.digest != pin.digest {
        errors.push(format!(
            "skill pin digest mismatch for `{}` version `{}`: lockfile `{}`, manifest `{}`",
            pin.name, pin.version, pin.digest, manifest.digest
        ));
    }
    if !pin.signatures.is_empty() {
        let pinned = pin.signatures.iter().collect::<BTreeSet<_>>();
        let installed = manifest.signatures.iter().collect::<BTreeSet<_>>();
        if pinned != installed {
            errors.push(format!(
                "skill pin signatures mismatch for `{}` version `{}`",
                pin.name, pin.version
            ));
        }
    }
}

fn verify_manifest_schema(manifest: &SkillManifest, errors: &mut Vec<String>) {
    if manifest.schema_version != SKILL_METADATA_SCHEMA_VERSION {
        errors.push(format!(
            "unsupported skill manifest schema version `{}`; expected `{SKILL_METADATA_SCHEMA_VERSION}`",
            manifest.schema_version
        ));
    }
}

fn current_version_for_skill_dir(skill_name_dir: &Path) -> SkillCacheResult<Option<String>> {
    let current_path = skill_name_dir.join("current");
    let metadata = match fs::symlink_metadata(&current_path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(SkillCacheError::Io {
                path: current_path,
                source,
            });
        }
    };

    if !metadata.file_type().is_symlink() {
        return Ok(None);
    }

    let target = fs::read_link(&current_path).map_err(|source| SkillCacheError::Io {
        path: current_path.clone(),
        source,
    })?;
    let mut components = target.components();
    let Some(Component::Normal(version)) = components.next() else {
        return Err(invalid_current_target(&target));
    };
    if components.next().is_some() {
        return Err(invalid_current_target(&target));
    }
    let Some(version) = version.to_str() else {
        return Err(invalid_current_target(&target));
    };
    validate_segment("skill current target", version)?;
    Ok(Some(version.to_owned()))
}

fn invalid_current_target(target: &Path) -> SkillCacheError {
    SkillCacheError::InvalidPathSegment {
        kind: "skill current target",
        value: target.display().to_string(),
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

    if provenance.schema_version != SKILL_METADATA_SCHEMA_VERSION {
        errors.push(format!(
            "unsupported skill provenance schema version `{}`; expected `{SKILL_METADATA_SCHEMA_VERSION}`",
            provenance.schema_version
        ));
    }
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
            SkillSelfTestAssertion::AgentProduces { .. } => {
                errors.push(
                    "agent_produces self-test assertions require the self-test runner".to_owned(),
                );
            }
        }
    }
}

fn verify_self_test_file_exists(skill_dir: &Path, path: &Path, errors: &mut Vec<String>) {
    let relative_path = match safe_relative_path(path) {
        Ok(path) => path,
        Err(error) => {
            errors.push(error);
            return;
        }
    };
    if !skill_dir.join(&relative_path).is_file() {
        errors.push(format!(
            "self-test file does not exist `{}`",
            path.display()
        ));
    }
}

fn safe_relative_path(source: &Path) -> Result<PathBuf, String> {
    if source.as_os_str().is_empty() {
        return Err("self-test path must not be empty".to_owned());
    }

    let mut relative = PathBuf::new();
    for component in source.components() {
        match component {
            Component::Normal(segment) => relative.push(segment),
            _ => {
                return Err(format!(
                    "self-test path must be a safe relative path `{}`",
                    source.display()
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
                    if let Err(error) = terminate_timed_out_self_test(&mut child) {
                        return Err(format!(
                            "self-test command timed out after {}s and {error}",
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
    command.arg("-c").arg(format!(
        "trap 'jobs -p | xargs kill -KILL 2>/dev/null || true' EXIT\n{cmd}"
    ));
    command.process_group(0);
    command
}

#[cfg(windows)]
fn shell_command(cmd: &str) -> Command {
    let mut command = Command::new("cmd");
    command.arg("/C").arg(cmd);
    command
}

#[cfg(unix)]
fn terminate_timed_out_self_test(child: &mut Child) -> Result<(), String> {
    let process_group_id = child.id() as i32;
    let mut descendant_pids = unix_descendant_pids(process_group_id).unwrap_or_default();
    let _ = unix_signal_process_group(process_group_id, "STOP");
    unix_signal_pids(&descendant_pids, "STOP");
    thread::sleep(Duration::from_millis(25));

    if let Ok(mut discovered_pids) = unix_descendant_pids(process_group_id) {
        descendant_pids.append(&mut discovered_pids);
        descendant_pids.sort_unstable();
        descendant_pids.dedup();
    }

    let group_signal_error = unix_kill_process_group(process_group_id).err();
    unix_kill_pids(&descendant_pids);

    let _ = Command::new("pkill")
        .arg("-KILL")
        .arg("-g")
        .arg(process_group_id.to_string())
        .status();

    child
        .wait()
        .map_err(|source| format!("wait failed: {source}"))?;

    let started_at = Instant::now();
    loop {
        let survivor_pids = unix_process_group_pids(process_group_id)?;
        if survivor_pids.is_empty() {
            return Ok(());
        }

        unix_kill_pids(&survivor_pids);
        if started_at.elapsed() >= Duration::from_secs(2) {
            let group_signal_error = group_signal_error
                .as_deref()
                .unwrap_or("process-group signal started successfully");
            return Err(format!(
                "process group {process_group_id} still has survivor pids {survivor_pids:?}; {group_signal_error}"
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn unix_kill_process_group(process_group_id: i32) -> Result<(), String> {
    unix_signal_process_group(process_group_id, "KILL")
}

#[cfg(unix)]
fn unix_signal_process_group(process_group_id: i32, signal: &str) -> Result<(), String> {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{process_group_id}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| format!("could not start process-group signal: {source}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "process-group signal {signal} exited with {status}"
        ))
    }
}

#[cfg(unix)]
fn unix_kill_pids(pids: &[i32]) {
    unix_signal_pids(pids, "KILL");
}

#[cfg(unix)]
fn unix_signal_pids(pids: &[i32], signal: &str) {
    for pid in pids {
        let _ = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg("--")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(unix)]
fn unix_process_group_pids(process_group_id: i32) -> Result<Vec<i32>, String> {
    let output = Command::new("pgrep")
        .arg("-g")
        .arg(process_group_id.to_string())
        .output()
        .map_err(|source| format!("could not list process group {process_group_id}: {source}"))?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    parse_pid_lines(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(unix)]
fn unix_descendant_pids(root_pid: i32) -> Result<Vec<i32>, String> {
    let output = Command::new("ps")
        .arg("-axo")
        .arg("pid=,ppid=")
        .output()
        .map_err(|source| format!("could not list processes: {source}"))?;
    if !output.status.success() {
        return Err(format!("process listing exited with {}", output.status));
    }

    let mut processes = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(parent_pid)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(pid), Ok(parent_pid)) = (pid.parse::<i32>(), parent_pid.parse::<i32>()) else {
            continue;
        };
        processes.push((pid, parent_pid));
    }

    let mut descendants = Vec::new();
    let mut stack = vec![root_pid];
    while let Some(parent_pid) = stack.pop() {
        for (pid, candidate_parent_pid) in &processes {
            if *candidate_parent_pid == parent_pid {
                descendants.push(*pid);
                stack.push(*pid);
            }
        }
    }

    descendants.sort_unstable();
    descendants.dedup();
    Ok(descendants)
}

#[cfg(unix)]
fn parse_pid_lines(stdout: &str) -> Result<Vec<i32>, String> {
    let mut pids = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let pid = trimmed
            .parse::<i32>()
            .map_err(|source| format!("failed to parse pid `{trimmed}`: {source}"))?;
        pids.push(pid);
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

#[cfg(windows)]
fn terminate_timed_out_self_test(child: &mut Child) -> Result<(), String> {
    let status = Command::new("taskkill")
        .arg("/PID")
        .arg(child.id().to_string())
        .arg("/T")
        .arg("/F")
        .status()
        .map_err(|source| format!("could not start taskkill: {source}"))?;
    if !status.success() {
        child.kill().map_err(|source| {
            format!("taskkill failed with {status}; direct kill failed: {source}")
        })?;
    }
    child
        .wait()
        .map_err(|source| format!("wait failed: {source}"))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn terminate_timed_out_self_test(child: &mut Child) -> Result<(), String> {
    child
        .kill()
        .map_err(|source| format!("could not kill child: {source}"))?;
    child
        .wait()
        .map_err(|source| format!("wait failed: {source}"))?;
    Ok(())
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
