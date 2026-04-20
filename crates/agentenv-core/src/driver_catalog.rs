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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriverSource {
    BuiltIn,
    InstalledSubprocess,
    DevelopmentOverride,
}

impl DriverSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::InstalledSubprocess => "installed",
            Self::DevelopmentOverride => "override",
        }
    }

    fn precedence(self) -> u8 {
        match self {
            Self::BuiltIn => 0,
            Self::InstalledSubprocess => 1,
            Self::DevelopmentOverride => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDriver {
    pub kind: DriverKind,
    pub name: String,
    pub version: Version,
    pub source: DriverSource,
    pub description: Option<String>,
    pub binary: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub capabilities_preview: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverCatalog {
    pub entries: Vec<DiscoveredDriver>,
}

impl DriverCatalog {
    pub fn discover_from_environment() -> Result<Self, DriverDiscoveryError> {
        Self::discover(DriverDiscoveryConfig::from_env())
    }

    pub fn discover(config: DriverDiscoveryConfig) -> Result<Self, DriverDiscoveryError> {
        let mut catalog = CatalogBuilder::default();
        catalog.add_built_ins();

        if config.installed_root.is_dir() {
            discover_parent_root(
                &mut catalog,
                &config.installed_root,
                DriverSource::InstalledSubprocess,
            )?;
        }

        for entry in config.driver_path_entries {
            discover_override_entry(&mut catalog, &entry)?;
        }

        Ok(catalog.into_entries())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverDiscoveryConfig {
    pub installed_root: PathBuf,
    pub driver_path_entries: Vec<PathBuf>,
}

impl DriverDiscoveryConfig {
    pub fn new(installed_root: PathBuf, driver_path_entries: Vec<PathBuf>) -> Self {
        Self {
            installed_root,
            driver_path_entries,
        }
    }

    pub fn from_env() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let installed_root = home.join(".agentenv/drivers");
        let driver_path_entries = std::env::var_os("AGENTENV_DRIVER_PATH")
            .map(|paths| std::env::split_paths(&paths).collect())
            .unwrap_or_default();

        Self::new(installed_root, driver_path_entries)
    }
}

#[derive(Debug, Default)]
struct CatalogBuilder {
    entries: BTreeMap<(DriverKind, String), DiscoveredDriver>,
}

impl CatalogBuilder {
    fn add_built_ins(&mut self) {
        let version =
            Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version must be valid semver");

        for spec in built_in_driver_specs() {
            for name in spec.names {
                self.entries.insert(
                    (spec.kind, (*name).to_string()),
                    DiscoveredDriver {
                        kind: spec.kind,
                        name: (*name).to_string(),
                        version: version.clone(),
                        source: DriverSource::BuiltIn,
                        description: None,
                        binary: None,
                        manifest_path: None,
                        args: Vec::new(),
                        env: BTreeMap::new(),
                        capabilities_preview: Value::Null,
                    },
                );
            }
        }
    }

    fn add_manifest(
        &mut self,
        manifest: DriverManifest,
        source: DriverSource,
    ) -> Result<(), DriverDiscoveryError> {
        let key = (manifest.kind, manifest.name.clone());

        if let Some(existing) = self.entries.get(&key) {
            if existing.source == source && source != DriverSource::BuiltIn {
                return Err(DriverDiscoveryError::DuplicateDriver {
                    kind: manifest.kind,
                    name: manifest.name,
                    first: existing
                        .manifest_path
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| PathBuf::from("<unknown>")),
                    second: manifest.manifest_path,
                });
            }

            if source.precedence() <= existing.source.precedence() {
                return Ok(());
            }
        }

        self.entries.insert(
            key,
            DiscoveredDriver {
                kind: manifest.kind,
                name: manifest.name,
                version: manifest.version,
                source,
                description: manifest.description,
                binary: Some(manifest.binary),
                manifest_path: Some(manifest.manifest_path),
                args: manifest.args,
                env: manifest.env,
                capabilities_preview: manifest.capabilities_preview,
            },
        );

        Ok(())
    }

    fn into_entries(self) -> DriverCatalog {
        let mut entries: Vec<_> = self.entries.into_values().collect();
        entries.sort_by(|left, right| {
            (&left.kind, &left.name, left.source.precedence()).cmp(&(
                &right.kind,
                &right.name,
                right.source.precedence(),
            ))
        });

        DriverCatalog { entries }
    }
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
    #[error("duplicate {kind} driver `{name}` discovered at `{first}` and `{second}`")]
    DuplicateDriver {
        kind: DriverKind,
        name: String,
        first: PathBuf,
        second: PathBuf,
    },
}

fn discover_override_entry(
    catalog: &mut CatalogBuilder,
    path: &Path,
) -> Result<(), DriverDiscoveryError> {
    if !path.exists() {
        return Ok(());
    }

    let manifest_path = path.join("manifest.json");
    if manifest_path.is_file() {
        let manifest = DriverManifest::from_path(&manifest_path)?;
        return catalog.add_manifest(manifest, DriverSource::DevelopmentOverride);
    }

    if path.is_dir() {
        discover_parent_root(catalog, path, DriverSource::DevelopmentOverride)?;
    }

    Ok(())
}

fn discover_parent_root(
    catalog: &mut CatalogBuilder,
    root: &Path,
    source: DriverSource,
) -> Result<(), DriverDiscoveryError> {
    for entry in fs::read_dir(root).map_err(|source| DriverDiscoveryError::ReadManifest {
        path: root.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| DriverDiscoveryError::ReadManifest {
            path: root.to_path_buf(),
            source,
        })?;

        let manifest_path = entry.path().join("manifest.json");
        if !manifest_path.is_file() {
            continue;
        }

        let manifest = DriverManifest::from_path(&manifest_path)?;
        catalog.add_manifest(manifest, source)?;
    }

    Ok(())
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

    #[test]
    fn discovery_ignores_missing_roots() {
        let missing_root = make_temp_dir("discovery-missing").join("does-not-exist");
        let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
            missing_root,
            Vec::<PathBuf>::new(),
        ))
        .unwrap();

        assert!(catalog.entries.iter().any(|entry| {
            entry.source == DriverSource::BuiltIn
                && entry.kind == DriverKind::Agent
                && entry.name == "codex"
        }));
    }

    #[test]
    fn discovery_reads_direct_override_root() {
        let root = manifest_root_with_binary("discovery-direct");
        write_manifest(
            &root,
            r#"{
              "schema_version": "1.0",
              "name": "nexus",
              "kind": "context",
              "version": "0.2.0",
              "binary": "./bin/driver"
            }"#,
        );

        let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
            make_temp_dir("discovery-installed-empty"),
            vec![root.clone()],
        ))
        .unwrap();

        let entry = catalog
            .entries
            .iter()
            .find(|entry| entry.kind == DriverKind::Context && entry.name == "nexus")
            .unwrap();
        let expected_manifest = root.join("manifest.json");
        assert_eq!(entry.source, DriverSource::DevelopmentOverride);
        assert_eq!(
            entry.manifest_path.as_deref(),
            Some(expected_manifest.as_path())
        );
    }

    #[test]
    fn discovery_reads_parent_override_root() {
        let parent = make_temp_dir("discovery-parent");
        let root = parent.join("context-nexus-py");
        fs::create_dir_all(&root).unwrap();
        touch_file(&root.join("bin/driver"));
        write_manifest(
            &root,
            r#"{
              "schema_version": "1.0",
              "name": "nexus",
              "kind": "context",
              "version": "0.2.0",
              "binary": "./bin/driver"
            }"#,
        );

        let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
            make_temp_dir("discovery-installed-empty"),
            vec![parent],
        ))
        .unwrap();

        assert!(catalog.entries.iter().any(|entry| {
            entry.source == DriverSource::DevelopmentOverride
                && entry.kind == DriverKind::Context
                && entry.name == "nexus"
        }));
    }

    #[test]
    fn development_override_wins_over_installed_and_builtin() {
        let installed_root = make_temp_dir("discovery-installed");
        let installed_driver = installed_root.join("codex-installed");
        fs::create_dir_all(&installed_driver).unwrap();
        touch_file(&installed_driver.join("bin/driver"));
        write_manifest(
            &installed_driver,
            r#"{
              "schema_version": "1.0",
              "name": "codex",
              "kind": "agent",
              "version": "0.2.0",
              "binary": "./bin/driver"
            }"#,
        );

        let override_driver = manifest_root_with_binary("discovery-override");
        write_manifest(
            &override_driver,
            r#"{
              "schema_version": "1.0",
              "name": "codex",
              "kind": "agent",
              "version": "0.3.0",
              "binary": "./bin/driver"
            }"#,
        );

        let catalog = DriverCatalog::discover(DriverDiscoveryConfig::new(
            installed_root,
            vec![override_driver],
        ))
        .unwrap();

        let entry = catalog
            .entries
            .iter()
            .find(|entry| entry.kind == DriverKind::Agent && entry.name == "codex")
            .unwrap();
        assert_eq!(entry.source, DriverSource::DevelopmentOverride);
        assert_eq!(entry.version.to_string(), "0.3.0");
    }

    #[test]
    fn duplicate_manifests_at_same_precedence_fail_with_both_paths() {
        let parent = make_temp_dir("discovery-duplicates");
        for name in ["first", "second"] {
            let root = parent.join(name);
            fs::create_dir_all(&root).unwrap();
            touch_file(&root.join("bin/driver"));
            write_manifest(
                &root,
                r#"{
                  "schema_version": "1.0",
                  "name": "nexus",
                  "kind": "context",
                  "version": "0.2.0",
                  "binary": "./bin/driver"
                }"#,
            );
        }

        let err = DriverCatalog::discover(DriverDiscoveryConfig::new(
            make_temp_dir("discovery-installed-empty"),
            vec![parent.clone()],
        ))
        .unwrap_err();

        assert!(err.to_string().contains("duplicate context driver `nexus`"));
        assert!(err.to_string().contains("first/manifest.json"));
        assert!(err.to_string().contains("second/manifest.json"));
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
