use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use agentenv_proto::{McpEndpoint, McpTransport, NetworkPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const STATE_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum EnvError {
    #[error(
        "invalid env name `{name}`: use ASCII letters, numbers, dot, dash, or underscore, and do not start with dot"
    )]
    InvalidName { name: String },
    #[error("env `{name}` already exists")]
    AlreadyExists { name: String },
    #[error("env `{name}` not found")]
    NotFound { name: String },
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

pub type EnvResult<T> = Result<T, EnvError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvName(String);

impl EnvName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn validate_env_name(name: &str) -> EnvResult<EnvName> {
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));

    if valid {
        Ok(EnvName(name.to_owned()))
    } else {
        Err(EnvError::InvalidName {
            name: name.to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPaths {
    root: PathBuf,
    name: EnvName,
}

impl EnvPaths {
    pub fn new(root: PathBuf, name: EnvName) -> Self {
        Self { root, name }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn name(&self) -> &EnvName {
        &self.name
    }

    pub fn envs_dir(&self) -> PathBuf {
        self.root.join("envs")
    }

    pub fn env_dir(&self) -> PathBuf {
        self.envs_dir().join(self.name.as_str())
    }

    pub fn temp_env_dir(&self) -> PathBuf {
        self.envs_dir()
            .join(format!(".{}.creating", self.name.as_str()))
    }

    pub fn blueprint_path(&self) -> PathBuf {
        self.env_dir().join("blueprint.yaml")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.env_dir().join("lock.yaml")
    }

    pub fn state_path(&self) -> PathBuf {
        self.env_dir().join("state.json")
    }

    pub fn events_path(&self) -> PathBuf {
        self.env_dir().join("events.jsonl")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvPhase {
    Creating,
    Running,
    Destroying,
    Destroyed,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverRecord {
    pub name: String,
    pub version: String,
}

impl DriverRecord {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

impl Default for DriverRecord {
    fn default() -> Self {
        Self::new("", "")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDriverSet {
    pub sandbox: DriverRecord,
    pub agent: DriverRecord,
    pub context: DriverRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<DriverRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverHandles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedMcpEndpoint {
    pub url: String,
    pub transport: McpTransport,
}

impl PersistedMcpEndpoint {
    pub fn from_mcp(endpoint: McpEndpoint) -> Self {
        Self {
            url: endpoint.url,
            transport: endpoint.transport,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_mcp: Option<PersistedMcpEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthRecord {
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvStateFile {
    pub version: String,
    pub name: String,
    pub phase: EnvPhase,
    pub created_at: String,
    pub updated_at: String,
    pub drivers: StateDriverSet,
    pub handles: DriverHandles,
    pub endpoints: EndpointState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_policy: Option<NetworkPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_names: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub health: BTreeMap<String, HealthRecord>,
    pub first_enter_hint_shown: bool,
}

pub fn write_state(paths: &EnvPaths, state: &EnvStateFile) -> EnvResult<()> {
    let path = paths.state_path();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| EnvError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let rendered = serde_json::to_string_pretty(state).map_err(|source| EnvError::Json {
        path: path.clone(),
        source,
    })?;
    let rendered = rendered.as_bytes();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| EnvError::Io {
            path: path.clone(),
            source: std::io::Error::other(source),
        })?;
    let temp_path = path.with_file_name(format!(
        ".state.json.{}.{}.tmp",
        std::process::id(),
        timestamp.as_nanos()
    ));

    let mut options = OpenOptions::new();
    restrict_file_permissions(&mut options);
    let mut tmp_file = options
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|source| EnvError::Io {
            path: temp_path.clone(),
            source,
        })?;
    tmp_file
        .write_all(rendered)
        .map_err(|source| EnvError::Io {
            path: temp_path.clone(),
            source,
        })?;
    tmp_file.sync_all().map_err(|source| EnvError::Io {
        path: temp_path.clone(),
        source,
    })?;
    drop(tmp_file);

    fs::rename(&temp_path, &path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        EnvError::Io { path, source }
    })
}

pub fn read_state(paths: &EnvPaths) -> EnvResult<EnvStateFile> {
    let path = paths.state_path();
    let bytes = read_regular_file(&path)?;
    serde_json::from_slice(&bytes).map_err(|source| EnvError::Json { path, source })
}

pub fn read_regular_file(path: &Path) -> EnvResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|source| EnvError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(EnvError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry file is not a regular file",
            ),
        });
    }

    fs::read(path).map_err(|source| EnvError::Io {
        path: path.to_path_buf(),
        source,
    })
}

pub fn append_event(paths: &EnvPaths, event: serde_json::Value) -> EnvResult<()> {
    let path = paths.events_path();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| EnvError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let mut encoded = serde_json::to_vec(&event).map_err(|source| EnvError::Json {
        path: path.clone(),
        source,
    })?;
    encoded.push(b'\n');
    let mut options = OpenOptions::new();
    restrict_file_permissions(&mut options);
    let mut file = options
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| EnvError::Io {
            path: path.clone(),
            source,
        })?;
    file.write_all(&encoded)
        .map_err(|source| EnvError::Io { path, source })
}

#[cfg(unix)]
fn restrict_file_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn restrict_file_permissions(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use serde_json::Value;

    use super::{
        append_event, read_state, validate_env_name, write_state, DriverHandles, DriverRecord,
        EndpointState, EnvPaths, EnvPhase, EnvStateFile, HealthRecord, PersistedMcpEndpoint,
        StateDriverSet, STATE_VERSION,
    };
    use agentenv_proto::{McpEndpoint, McpTransport};

    #[test]
    fn env_name_validation_rejects_traversal_and_empty_names() {
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "../demo",
            "demo/name",
            "demo:name",
            "demo name",
        ] {
            let err = validate_env_name(bad).expect_err("bad env name must fail");
            assert!(
                err.to_string().contains("invalid env name"),
                "err was {err}"
            );
        }

        assert_eq!(validate_env_name("demo-01").unwrap().as_str(), "demo-01");
        assert_eq!(
            validate_env_name("team_demo.01").unwrap().as_str(),
            "team_demo.01"
        );
    }

    #[test]
    fn env_paths_stay_under_root() {
        let root = std::env::temp_dir().join(format!("agentenv-env-paths-{}", std::process::id()));
        let paths = EnvPaths::new(root.clone(), validate_env_name("demo").unwrap());

        assert_eq!(paths.env_dir(), root.join("envs").join("demo"));
        assert_eq!(
            paths.state_path(),
            root.join("envs").join("demo").join("state.json")
        );
        assert_eq!(
            paths.events_path(),
            root.join("envs").join("demo").join("events.jsonl")
        );
    }

    #[test]
    fn state_roundtrip_excludes_secret_values() {
        let root =
            std::env::temp_dir().join(format!("agentenv-state-roundtrip-{}", std::process::id()));
        let paths = EnvPaths::new(root, validate_env_name("demo").unwrap());
        fs::create_dir_all(paths.env_dir()).unwrap();

        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_owned(), "sk-secret-value".to_owned());
        headers.insert("x-api-key".to_owned(), "very-secret-key".to_owned());

        let context_mcp = PersistedMcpEndpoint::from_mcp(McpEndpoint {
            url: "stdio://agentenv-fs-mcp".to_owned(),
            transport: McpTransport::Stdio,
            headers,
        });

        let drivers = StateDriverSet {
            sandbox: DriverRecord::new("openshell", "0.0.1-alpha0"),
            agent: DriverRecord::new("codex", "0.0.1-alpha0"),
            context: DriverRecord::new("filesystem", "0.0.1-alpha0"),
            inference: Some(DriverRecord::new("passthrough", "0.0.1-alpha0")),
        };

        let state = EnvStateFile {
            version: STATE_VERSION.to_owned(),
            name: "demo".to_owned(),
            phase: EnvPhase::Running,
            created_at: "2026-04-21T00:00:00Z".to_owned(),
            updated_at: "2026-04-21T00:01:00Z".to_owned(),
            drivers,
            handles: DriverHandles {
                sandbox: Some("sb-1".to_owned()),
                context: Some("ctx-1".to_owned()),
                inference: Some("inf-1".to_owned()),
            },
            endpoints: EndpointState {
                context_mcp: Some(context_mcp),
                inference: Some("http://inference.local".to_owned()),
            },
            resolved_policy: None,
            credential_names: vec!["OPENAI_API_KEY".to_owned()],
            health: BTreeMap::from([(
                "sandbox".to_owned(),
                HealthRecord {
                    healthy: true,
                    phase: Some("running".to_owned()),
                    detail: None,
                    checked_at: "2026-04-21T00:01:00Z".to_owned(),
                },
            )]),
            first_enter_hint_shown: false,
        };

        write_state(&paths, &state).unwrap();
        let rendered = fs::read_to_string(paths.state_path()).unwrap();
        assert!(!rendered.contains("sk-secret-value"));
        assert!(!rendered.contains("very-secret-key"));
        let rendered_json: Value = serde_json::from_str(&rendered).unwrap();
        assert!(rendered_json["endpoints"]["context_mcp"]
            .get("headers")
            .is_none());
        assert!(rendered.contains("OPENAI_API_KEY"));

        let loaded = read_state(&paths).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn append_event_writes_json_lines() {
        let root = std::env::temp_dir().join(format!("agentenv-events-{}", std::process::id()));
        let paths = EnvPaths::new(root, validate_env_name("demo").unwrap());
        fs::create_dir_all(paths.env_dir()).unwrap();

        append_event(
            &paths,
            serde_json::json!({
                "kind": "progress",
                "step": "preflight",
                "ok": true
            }),
        )
        .unwrap();
        append_event(
            &paths,
            serde_json::json!({
                "kind": "admission",
                "status": "accepted",
                "reason_code": "created"
            }),
        )
        .unwrap();

        let lines = fs::read_to_string(paths.events_path()).unwrap();
        let parsed = lines
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["step"], "preflight");
        assert_eq!(parsed[1]["reason_code"], "created");
    }
}
