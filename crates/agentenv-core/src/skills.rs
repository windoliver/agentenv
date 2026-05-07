use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest::{parse_sha256_hex, DigestError};

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
