use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use crate::registry::DriverKind;
use agentenv_proto::assert_compatible_schema_version;
use semver::Version;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInDriverSpec {
    pub kind: DriverKind,
    pub names: &'static [&'static str],
}

const BUILT_IN_DRIVER_SPECS: &[BuiltInDriverSpec] = &[
    BuiltInDriverSpec {
        kind: DriverKind::Sandbox,
        names: &["openshell", "sandbox-openshell"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["claude", "agent-claude"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["codex", "agent-codex"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["hermes"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["openclaw", "agent-openclaw"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["filesystem", "context-filesystem"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["mcp-generic", "context-mcp-generic"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["nexus"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["none", "context-none"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["passthrough", "inference-passthrough"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["openai", "inference-openai"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["anthropic", "inference-anthropic"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["ollama", "inference-ollama"],
    },
];

pub fn built_in_driver_specs() -> &'static [BuiltInDriverSpec] {
    BUILT_IN_DRIVER_SPECS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverManifest {
    pub schema_version: String,
    pub name: String,
    pub kind: DriverKind,
    pub version: Version,
    pub description: Option<String>,
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub capabilities_preview: Value,
    pub manifest_path: PathBuf,
    pub root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RawDriverManifest {
    schema_version: String,
    name: String,
    kind: String,
    version: String,
    #[serde(default)]
    description: Option<String>,
    binary: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    capabilities_preview: Value,
}

#[derive(Debug, Error)]
pub enum DriverDiscoveryError {
    #[error("failed to read driver manifest `{path}`: {source}")]
    ReadManifest {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON in driver manifest `{path}`: {source}")]
    InvalidManifestJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("incompatible manifest schema version in `{path}`: {source}")]
    IncompatibleSchemaVersion {
        path: PathBuf,
        #[source]
        source: agentenv_proto::SchemaVersionError,
    },
    #[error("driver manifest `{path}` has empty driver name")]
    EmptyName { path: PathBuf },
    #[error("unknown driver kind `{kind}` in manifest `{path}`")]
    UnknownKind { path: PathBuf, kind: String },
    #[error("invalid driver version `{version}` in manifest `{path}`: {source}")]
    InvalidVersion {
        path: PathBuf,
        version: String,
        #[source]
        source: semver::Error,
    },
    #[error("driver binary `{binary}` escapes driver root `{root}` in manifest `{path}`")]
    BinaryEscapesRoot {
        path: PathBuf,
        root: PathBuf,
        binary: PathBuf,
    },
    #[error("driver binary does not exist at `{binary}` from manifest `{path}`")]
    MissingBinary { path: PathBuf, binary: PathBuf },
}

impl DriverManifest {
    pub fn from_path(path: &Path) -> Result<Self, DriverDiscoveryError> {
        let raw_text =
            fs::read_to_string(path).map_err(|source| DriverDiscoveryError::ReadManifest {
                path: path.to_path_buf(),
                source,
            })?;
        let raw: RawDriverManifest = serde_json::from_str(&raw_text).map_err(|source| {
            DriverDiscoveryError::InvalidManifestJson {
                path: path.to_path_buf(),
                source,
            }
        })?;

        assert_compatible_schema_version(&raw.schema_version).map_err(|source| {
            DriverDiscoveryError::IncompatibleSchemaVersion {
                path: path.to_path_buf(),
                source,
            }
        })?;

        let name = raw.name.trim().to_owned();
        if name.is_empty() {
            return Err(DriverDiscoveryError::EmptyName {
                path: path.to_path_buf(),
            });
        }

        let kind =
            parse_driver_kind(&raw.kind).ok_or_else(|| DriverDiscoveryError::UnknownKind {
                path: path.to_path_buf(),
                kind: raw.kind.clone(),
            })?;

        let version = Version::parse(&raw.version).map_err(|source| {
            DriverDiscoveryError::InvalidVersion {
                path: path.to_path_buf(),
                version: raw.version.clone(),
                source,
            }
        })?;

        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let binary = resolve_manifest_binary(path, &root, &raw.binary)?;

        Ok(Self {
            schema_version: raw.schema_version,
            name,
            kind,
            version,
            description: raw.description,
            binary,
            args: raw.args,
            env: raw.env,
            capabilities_preview: raw.capabilities_preview,
            manifest_path: path.to_path_buf(),
            root,
        })
    }
}

fn parse_driver_kind(kind: &str) -> Option<DriverKind> {
    match kind {
        "sandbox" => Some(DriverKind::Sandbox),
        "agent" => Some(DriverKind::Agent),
        "context" => Some(DriverKind::Context),
        "inference" => Some(DriverKind::Inference),
        _ => None,
    }
}

fn resolve_manifest_binary(
    manifest_path: &Path,
    root: &Path,
    binary: &Path,
) -> Result<PathBuf, DriverDiscoveryError> {
    let resolved = if binary.is_absolute() {
        binary.to_path_buf()
    } else {
        let resolved = normalize_relative_path(root, binary);
        if !resolved.starts_with(root) {
            return Err(DriverDiscoveryError::BinaryEscapesRoot {
                path: manifest_path.to_path_buf(),
                root: root.to_path_buf(),
                binary: binary.to_path_buf(),
            });
        }
        resolved
    };

    if !resolved.is_file() {
        return Err(DriverDiscoveryError::MissingBinary {
            path: manifest_path.to_path_buf(),
            binary: resolved,
        });
    }

    Ok(resolved)
}

fn normalize_relative_path(root: &Path, relative: &Path) -> PathBuf {
    let mut normalized = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(segment) => normalized.push(segment),
            Component::Prefix(_) | Component::RootDir => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::DriverKind;
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn built_in_specs_include_current_aliases() {
        let specs = built_in_driver_specs();

        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Sandbox && spec.names == &["openshell", "sandbox-openshell"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Agent && spec.names == &["codex", "agent-codex"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Context && spec.names == &["filesystem", "context-filesystem"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Inference
                && spec.names == &["passthrough", "inference-passthrough"]
        }));
    }

    #[test]
    fn parses_valid_manifest_and_resolves_relative_binary() {
        let root = make_temp_dir("manifest-valid");
        let binary = root.join("bin/context-nexus-py");
        touch_file(&binary);
        write_manifest(
            &root,
            r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "description": "Nexus context backend",
          "binary": "./bin/context-nexus-py",
          "args": ["--stdio"],
          "env": {"RUST_LOG": "info"},
          "capabilities_preview": {"is_remote": true}
        }"#,
        );

        let manifest = DriverManifest::from_path(&root.join("manifest.json")).unwrap();

        assert_eq!(manifest.name, "nexus");
        assert_eq!(manifest.kind, DriverKind::Context);
        assert_eq!(manifest.version.to_string(), "0.2.0");
        assert_eq!(manifest.binary, binary);
        assert_eq!(manifest.args, vec!["--stdio"]);
        assert_eq!(manifest.env.get("RUST_LOG").unwrap(), "info");
        assert_eq!(
            manifest.description.as_deref(),
            Some("Nexus context backend")
        );
    }

    #[test]
    fn rejects_invalid_manifest_kind() {
        let root = manifest_root_with_binary("manifest-bad-kind");
        write_manifest(
            &root,
            r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "database",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
        );

        let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

        assert!(err.to_string().contains("unknown driver kind `database`"));
        assert!(err.to_string().contains("manifest.json"));
    }

    #[test]
    fn rejects_invalid_manifest_version() {
        let root = manifest_root_with_binary("manifest-bad-version");
        write_manifest(
            &root,
            r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "banana",
          "binary": "./bin/driver"
        }"#,
        );

        let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

        assert!(err.to_string().contains("invalid driver version `banana`"));
        assert!(err.to_string().contains("manifest.json"));
    }

    #[test]
    fn rejects_incompatible_manifest_schema_version() {
        let root = manifest_root_with_binary("manifest-schema");
        write_manifest(
            &root,
            r#"{
          "schema_version": "2.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
        );

        let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

        assert!(err
            .to_string()
            .contains("incompatible manifest schema version"));
        assert!(err.to_string().contains("manifest.json"));
    }

    #[test]
    fn rejects_relative_binary_that_escapes_manifest_root() {
        let root = make_temp_dir("manifest-escape");
        write_manifest(
            &root,
            r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "../outside-driver"
        }"#,
        );

        let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

        assert!(err.to_string().contains("escapes driver root"));
        assert!(err.to_string().contains("manifest.json"));
    }

    #[test]
    fn rejects_manifest_with_missing_binary() {
        let root = make_temp_dir("manifest-missing-binary");
        write_manifest(
            &root,
            r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/missing-driver"
        }"#,
        );

        let err = DriverManifest::from_path(&root.join("manifest.json")).unwrap_err();

        assert!(err.to_string().contains("driver binary does not exist"));
        assert!(err.to_string().contains("manifest.json"));
    }

    fn manifest_root_with_binary(prefix: &str) -> PathBuf {
        let root = make_temp_dir(prefix);
        touch_file(&root.join("bin/driver"));
        root
    }

    fn write_manifest(root: &Path, contents: &str) {
        fs::write(root.join("manifest.json"), contents).unwrap();
    }

    fn touch_file(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, "").unwrap();
    }

    fn make_temp_dir(prefix: &str) -> PathBuf {
        let unique = format!(
            "{prefix}-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }
}
