#![forbid(unsafe_code)]

use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs,
    path::{Component, Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use agentenv_core::{
    context_common::{
        context_initialize, empty_credential_requirements, empty_network_rules, empty_result,
        expand_tilde, local_context_capabilities, optional_bool, optional_string_list,
        required_string, successful_preflight,
    },
    driver::{ContextDriver, DriverError, DriverResult},
};
use agentenv_proto::{
    ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus, CredentialRequirementsParams,
    CredentialRequirementsResult, EmptyResult, InitializeParams, InitializeResult, McpEndpoint,
    McpTransport, PreflightParams, PreflightResult, RequiredNetworkRulesResult, ShutdownParams,
};
use async_trait::async_trait;
use serde_json::{json, Value};
use thiserror::Error;

pub const CRATE_NAME: &str = "context-filesystem";
const DRIVER_NAME: &str = "filesystem";
const MAX_READ_BYTES: u64 = 1024 * 1024;
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Error)]
pub enum FsMcpError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("path `{0}` is outside root")]
    OutsideRoot(String),
    #[error("path `{0}` is excluded")]
    Excluded(String),
    #[error("path `{0}` is a directory")]
    Directory(String),
    #[error("file `{0}` is too large")]
    FileTooLarge(String),
    #[error("file `{0}` is not UTF-8 text")]
    Binary(String),
    #[error("unknown tool `{0}`")]
    UnknownTool(String),
    #[error("filesystem error for `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct FilesystemMcpServer {
    root: PathBuf,
    readonly: bool,
    exclude: Vec<String>,
}

impl FilesystemMcpServer {
    pub fn new(root: PathBuf, readonly: bool, exclude: Vec<String>) -> Result<Self, FsMcpError> {
        let root = fs::canonicalize(&root).map_err(|source| FsMcpError::Io {
            path: root.display().to_string(),
            source,
        })?;
        if !root.is_dir() {
            return Err(FsMcpError::InvalidParams(format!(
                "{} is not a directory",
                root.display()
            )));
        }

        Ok(Self {
            root,
            readonly,
            exclude,
        })
    }

    pub fn tools_list(&self) -> Value {
        json!([
            {
                "name": "fs_grep",
                "description": "Search file contents under the mounted root",
                "readOnly": self.readonly
            },
            {
                "name": "fs_list",
                "description": "List files under the mounted root",
                "readOnly": self.readonly
            },
            {
                "name": "fs_read",
                "description": "Read a UTF-8 text file under the mounted root",
                "readOnly": self.readonly
            },
            {
                "name": "fs_search",
                "description": "Search filenames under the mounted root",
                "readOnly": self.readonly
            }
        ])
    }

    pub fn call_tool(&self, call: ToolCall) -> Result<Value, FsMcpError> {
        match call.name.as_str() {
            "fs_read" => self.fs_read(&call.arguments),
            "fs_list" => self.fs_list(&call.arguments),
            "fs_search" => self.fs_search(&call.arguments),
            "fs_grep" => self.fs_grep(&call.arguments),
            other => Err(FsMcpError::UnknownTool(other.to_owned())),
        }
    }

    fn fs_read(&self, args: &Value) -> Result<Value, FsMcpError> {
        let path = self.required_arg(args, "path")?;
        let resolved = self.resolve_path(path)?;
        let metadata = fs::metadata(&resolved).map_err(|source| FsMcpError::Io {
            path: path.to_owned(),
            source,
        })?;
        if metadata.is_dir() {
            return Err(FsMcpError::Directory(path.to_owned()));
        }
        if metadata.len() > MAX_READ_BYTES {
            return Err(FsMcpError::FileTooLarge(path.to_owned()));
        }

        let bytes = fs::read(&resolved).map_err(|source| FsMcpError::Io {
            path: path.to_owned(),
            source,
        })?;
        let content = String::from_utf8(bytes).map_err(|_| FsMcpError::Binary(path.to_owned()))?;

        Ok(json!({ "content": content }))
    }

    fn fs_list(&self, args: &Value) -> Result<Value, FsMcpError> {
        let path = self.optional_arg(args, "path").unwrap_or(".");
        let recursive = args
            .get("recursive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let root = self.resolve_path(path)?;
        let mut paths = Vec::new();

        self.collect_paths(&root, recursive, &mut paths)?;
        paths.sort();

        Ok(json!({ "paths": paths }))
    }

    fn fs_search(&self, args: &Value) -> Result<Value, FsMcpError> {
        let query = self.required_arg(args, "query")?;
        let path = self.optional_arg(args, "path").unwrap_or(".");
        let limit = self.limit(args);
        let root = self.resolve_path(path)?;
        let mut paths = Vec::new();

        self.collect_paths(&root, true, &mut paths)?;
        paths.retain(|path| path.rsplit('/').next().unwrap_or(path).contains(query));
        paths.sort();
        paths.truncate(limit);

        Ok(json!({ "paths": paths }))
    }

    fn fs_grep(&self, args: &Value) -> Result<Value, FsMcpError> {
        let pattern = self.required_arg(args, "pattern")?;
        let path = self.optional_arg(args, "path").unwrap_or(".");
        let limit = self.limit(args);
        let root = self.resolve_path(path)?;
        let mut paths = Vec::new();

        self.collect_paths(&root, true, &mut paths)?;
        paths.sort();

        let mut matches = Vec::new();
        for relative in paths {
            let full = self.root.join(&relative);
            if fs::metadata(&full)
                .map(|metadata| metadata.is_dir())
                .unwrap_or(true)
            {
                continue;
            }

            let Ok(content) = fs::read_to_string(&full) else {
                continue;
            };
            for (index, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    matches.push(json!({
                        "path": relative,
                        "line": index + 1,
                        "text": line,
                    }));
                    if matches.len() == limit {
                        return Ok(json!({ "matches": matches }));
                    }
                }
            }
        }

        Ok(json!({ "matches": matches }))
    }

    fn required_arg<'a>(&self, args: &'a Value, field: &str) -> Result<&'a str, FsMcpError> {
        self.optional_arg(args, field)
            .ok_or_else(|| FsMcpError::InvalidParams(format!("missing `{field}`")))
    }

    fn optional_arg<'a>(&self, args: &'a Value, field: &str) -> Option<&'a str> {
        args.get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
    }

    fn limit(&self, args: &Value) -> usize {
        args.get("limit")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_LIMIT)
            .clamp(1, MAX_LIMIT)
    }

    fn resolve_path(&self, path: &str) -> Result<PathBuf, FsMcpError> {
        let relative = Path::new(path);
        if relative.is_absolute() {
            return Err(FsMcpError::OutsideRoot(path.to_owned()));
        }
        if relative
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(FsMcpError::OutsideRoot(path.to_owned()));
        }
        if self.is_excluded(path) {
            return Err(FsMcpError::Excluded(path.to_owned()));
        }

        let joined = self.root.join(relative);
        let canonical = fs::canonicalize(&joined).map_err(|source| FsMcpError::Io {
            path: path.to_owned(),
            source,
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(FsMcpError::OutsideRoot(path.to_owned()));
        }

        Ok(canonical)
    }

    fn collect_paths(
        &self,
        root: &Path,
        recursive: bool,
        paths: &mut Vec<String>,
    ) -> Result<(), FsMcpError> {
        let metadata = fs::metadata(root).map_err(|source| FsMcpError::Io {
            path: root.display().to_string(),
            source,
        })?;
        if metadata.is_file() {
            self.push_file_path(root, paths)?;
            return Ok(());
        }

        for entry in fs::read_dir(root).map_err(|source| FsMcpError::Io {
            path: root.display().to_string(),
            source,
        })? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let relative = self.relative_string(&path)?;
            if self.is_excluded(&relative) {
                continue;
            }

            let Ok(canonical) = fs::canonicalize(&path) else {
                continue;
            };
            if !canonical.starts_with(&self.root) {
                continue;
            }

            let Ok(metadata) = fs::metadata(&canonical) else {
                continue;
            };
            if metadata.is_dir() {
                if recursive {
                    self.collect_paths(&path, recursive, paths)?;
                }
            } else if metadata.is_file() {
                paths.push(relative);
            }
        }

        Ok(())
    }

    fn push_file_path(&self, path: &Path, paths: &mut Vec<String>) -> Result<(), FsMcpError> {
        let relative = self.relative_string(path)?;
        if !self.is_excluded(&relative) {
            paths.push(relative);
        }
        Ok(())
    }

    fn relative_string(&self, path: &Path) -> Result<String, FsMcpError> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| FsMcpError::OutsideRoot(path.display().to_string()))?;

        Ok(relative.to_string_lossy().replace('\\', "/"))
    }

    fn is_excluded(&self, relative: &str) -> bool {
        let normalized = relative.trim_start_matches("./");
        self.exclude.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix('/') {
                normalized == prefix || normalized.starts_with(&format!("{prefix}/"))
            } else {
                normalized == pattern
                    || normalized
                        .split('/')
                        .any(|segment| segment == pattern || segment.contains(pattern))
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemConfig {
    pub root: PathBuf,
    pub readonly: bool,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone)]
struct FilesystemState {
    config: FilesystemConfig,
}

#[derive(Debug)]
struct FilesystemStore {
    next_id: u64,
    states: BTreeMap<String, FilesystemState>,
}

#[derive(Debug)]
pub struct FilesystemContextDriver {
    store: Mutex<FilesystemStore>,
}

impl Default for FilesystemContextDriver {
    fn default() -> Self {
        Self {
            store: Mutex::new(FilesystemStore {
                next_id: 1,
                states: BTreeMap::new(),
            }),
        }
    }
}

#[async_trait]
impl ContextDriver for FilesystemContextDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(context_initialize(
            DRIVER_NAME,
            local_context_capabilities(),
        ))
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(successful_preflight())
    }

    async fn provision(&self, spec: ContextSpec) -> DriverResult<ContextHandle> {
        let config = filesystem_config_from_spec(&spec)?;
        let mut store = self.store()?;
        let handle = loop {
            let handle = format!("{DRIVER_NAME}|{}", store.next_id);
            store.next_id += 1;
            if let Entry::Vacant(entry) = store.states.entry(handle.clone()) {
                entry.insert(FilesystemState {
                    config: config.clone(),
                });
                break handle;
            }
        };

        Ok(ContextHandle { handle })
    }

    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        let state = self.state(&params.handle)?;

        Ok(McpEndpoint {
            url: filesystem_endpoint_command(&state.config),
            transport: McpTransport::Stdio,
            headers: BTreeMap::new(),
        })
    }

    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        self.state(&params.handle)?;

        Ok(empty_network_rules())
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(empty_credential_requirements())
    }

    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        let state = self.state(&params.handle)?;
        let healthy = state.config.root.is_dir();
        let detail = if healthy {
            Some(format!("mounted {}", state.config.root.display()))
        } else {
            Some(format!(
                "{} is not a directory",
                state.config.root.display()
            ))
        };

        Ok(ContextStatus { healthy, detail })
    }

    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        let mut store = self.store()?;
        store
            .states
            .remove(&params.handle)
            .ok_or_else(|| invalid_handle(&params.handle))?;

        Ok(empty_result())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(empty_result())
    }
}

impl FilesystemContextDriver {
    fn state(&self, handle: &str) -> DriverResult<FilesystemState> {
        let store = self.store()?;
        store
            .states
            .get(handle)
            .cloned()
            .ok_or_else(|| invalid_handle(handle))
    }

    fn store(&self) -> DriverResult<MutexGuard<'_, FilesystemStore>> {
        self.store.lock().map_err(|_| DriverError::CleanupFailed {
            message: "filesystem context store mutex poisoned".to_owned(),
        })
    }
}

pub fn filesystem_config_from_spec(spec: &ContextSpec) -> DriverResult<FilesystemConfig> {
    let mount = required_string(&spec.config, "mount")?;
    let home = std::env::var("HOME").ok();
    let expanded = expand_tilde(&mount, home.as_deref());
    let root = fs::canonicalize(&expanded).map_err(|err| DriverError::InvalidConfig {
        field: "mount".to_owned(),
        message: format!("failed to canonicalize `{}`: {err}", expanded.display()),
    })?;
    if !root.is_dir() {
        return Err(DriverError::InvalidConfig {
            field: "mount".to_owned(),
            message: format!("{} is not a directory", root.display()),
        });
    }

    Ok(FilesystemConfig {
        root,
        readonly: optional_bool(&spec.config, "readonly")?.unwrap_or(true),
        exclude: optional_string_list(&spec.config, "exclude")?,
    })
}

pub fn filesystem_endpoint_command(config: &FilesystemConfig) -> String {
    let mut parts = vec![
        "agentenv-fs-mcp".to_owned(),
        "--root".to_owned(),
        shell_quote(&config.root.to_string_lossy()),
    ];

    if config.readonly {
        parts.push("--readonly".to_owned());
    }

    for pattern in &config.exclude {
        parts.push("--exclude".to_owned());
        parts.push(shell_quote(pattern));
    }

    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':'))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn invalid_handle(handle: &str) -> DriverError {
    DriverError::InvalidHandle {
        handle: handle.to_owned(),
        message: "unknown filesystem context handle".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use agentenv_core::driver::ContextDriver;
    use agentenv_proto::{
        Capabilities, ContextHandleRequest, ContextSpec, CredentialRequirementsParams,
        InitializeParams, LogLevel, McpTransport, SCHEMA_VERSION,
    };
    use serde_json::json;

    use super::{filesystem_config_from_spec, FilesystemContextDriver};

    fn init_params() -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-alpha0".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        }
    }

    fn spec(root: &std::path::Path) -> ContextSpec {
        ContextSpec {
            config: BTreeMap::from([
                ("mount".to_owned(), json!(root.to_string_lossy())),
                ("readonly".to_owned(), json!(false)),
                ("exclude".to_owned(), json!([".git/", "target/"])),
            ]),
        }
    }

    #[test]
    fn filesystem_config_parses_mount_readonly_and_excludes() {
        let tmp = tempfile::tempdir().unwrap();
        let config = filesystem_config_from_spec(&spec(tmp.path())).unwrap();

        assert_eq!(config.root, tmp.path().canonicalize().unwrap());
        assert!(!config.readonly);
        assert_eq!(
            config.exclude,
            vec![".git/".to_owned(), "target/".to_owned()]
        );
    }

    #[test]
    fn filesystem_config_rejects_missing_mount() {
        let err = filesystem_config_from_spec(&ContextSpec {
            config: BTreeMap::new(),
        })
        .unwrap_err();

        assert!(err.to_string().contains("mount"));
    }

    #[test]
    fn filesystem_config_rejects_file_mount() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        fs::write(&file, "not a directory").unwrap();

        let err = filesystem_config_from_spec(&spec(&file)).unwrap_err();

        assert!(err.to_string().contains("directory"));
    }

    #[tokio::test]
    async fn initialize_returns_local_capabilities() {
        let mut driver = FilesystemContextDriver::default();
        let result = driver.initialize(init_params()).await.unwrap();

        assert_eq!(result.driver.name, "filesystem");
        let Capabilities::Context(capabilities) = result.capabilities else {
            panic!("expected context capabilities");
        };
        assert!(!capabilities.is_remote);
        assert!(!capabilities.is_shared);
        assert!(!capabilities.supports_zones);
        assert!(!capabilities.supports_snapshots);
    }

    #[tokio::test]
    async fn provision_returns_stdio_endpoint_and_empty_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let driver = FilesystemContextDriver::default();
        let handle = driver.provision(spec(tmp.path())).await.unwrap();
        let request = ContextHandleRequest {
            handle: handle.handle.clone(),
        };

        let endpoint = driver.mcp_endpoint(request.clone()).await.unwrap();
        let rules = driver
            .required_network_rules(request.clone())
            .await
            .unwrap();
        let credentials = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert_eq!(endpoint.transport, McpTransport::Stdio);
        assert!(endpoint.url.contains("agentenv-fs-mcp"));
        assert!(endpoint.url.contains("--root"));
        assert!(endpoint.url.contains("--exclude"));
        assert!(rules.rules.is_empty());
        assert!(credentials.requirements.is_empty());
    }

    #[tokio::test]
    async fn status_reports_unhealthy_when_mount_disappears() {
        let tmp = tempfile::tempdir().unwrap();
        let driver = FilesystemContextDriver::default();
        let handle = driver.provision(spec(tmp.path())).await.unwrap();
        let mount = tmp.into_path();
        fs::remove_dir_all(&mount).unwrap();

        let status = driver
            .status(ContextHandleRequest {
                handle: handle.handle,
            })
            .await
            .unwrap();

        assert!(!status.healthy);
        assert!(status.detail.unwrap().contains("not a directory"));
    }

    #[tokio::test]
    async fn filesystem_driver_satisfies_context_conformance_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = FilesystemContextDriver::default();

        driver_conformance::assert_context_driver_contract(&mut driver, spec(tmp.path()))
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod mcp_tool_tests {
    use std::fs;

    use serde_json::json;

    use super::{FilesystemMcpServer, ToolCall};

    #[test]
    fn tools_list_advertises_expected_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();
        let tools = server.tools_list();

        let names: Vec<_> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool.get("name").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["fs_grep", "fs_list", "fs_read", "fs_search"]);
    }

    #[test]
    fn fs_read_reads_utf8_file_under_root() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("README.md"), "hello\n").unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();

        let result = server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "README.md"}),
            })
            .unwrap();

        assert_eq!(result, json!({"content": "hello\n"}));
    }

    #[test]
    fn fs_read_rejects_traversal_and_excluded_paths() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(tmp.path().join(".git/config"), "secret").unwrap();
        let server =
            FilesystemMcpServer::new(tmp.path().to_path_buf(), true, vec![".git/".to_owned()])
                .unwrap();

        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "../outside"}),
            })
            .unwrap_err()
            .to_string()
            .contains("outside root"));
        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": ".git/config"}),
            })
            .unwrap_err()
            .to_string()
            .contains("excluded"));
    }

    #[test]
    fn fs_list_search_and_grep_skip_excluded_paths_and_sort_results() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::create_dir_all(tmp.path().join("target")).unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "pub fn alpha() {}\n").unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\nalpha();\n").unwrap();
        fs::write(tmp.path().join("target/cache.txt"), "alpha\n").unwrap();
        let server =
            FilesystemMcpServer::new(tmp.path().to_path_buf(), true, vec!["target/".to_owned()])
                .unwrap();

        let listed = server
            .call_tool(ToolCall {
                name: "fs_list".to_owned(),
                arguments: json!({"path": ".", "recursive": true}),
            })
            .unwrap();
        assert_eq!(listed, json!({"paths": ["src/lib.rs", "src/main.rs"]}));

        let searched = server
            .call_tool(ToolCall {
                name: "fs_search".to_owned(),
                arguments: json!({"query": "main"}),
            })
            .unwrap();
        assert_eq!(searched, json!({"paths": ["src/main.rs"]}));

        let grep = server
            .call_tool(ToolCall {
                name: "fs_grep".to_owned(),
                arguments: json!({"pattern": "alpha"}),
            })
            .unwrap();
        assert_eq!(
            grep,
            json!({
                "matches": [
                    {"path": "src/lib.rs", "line": 1, "text": "pub fn alpha() {}"},
                    {"path": "src/main.rs", "line": 2, "text": "alpha();"}
                ]
            })
        );
    }

    #[test]
    fn fs_read_rejects_absolute_paths_directories_binary_and_oversized_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("dir")).unwrap();
        fs::write(tmp.path().join("binary.bin"), b"\xff\xfe\xfd").unwrap();
        fs::write(tmp.path().join("large.txt"), vec![b'a'; 1024 * 1024 + 1]).unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();

        let absolute = tmp.path().join("large.txt");
        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": absolute}),
            })
            .unwrap_err()
            .to_string()
            .contains("outside root"));
        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "dir"}),
            })
            .unwrap_err()
            .to_string()
            .contains("directory"));
        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "binary.bin"}),
            })
            .unwrap_err()
            .to_string()
            .contains("UTF-8"));
        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "large.txt"}),
            })
            .unwrap_err()
            .to_string()
            .contains("too large"));
    }

    #[test]
    fn fs_search_and_grep_limits_are_respected() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("alpha_one.txt"), "needle\nneedle again\n").unwrap();
        fs::write(tmp.path().join("alpha_two.txt"), "needle\n").unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();

        let searched = server
            .call_tool(ToolCall {
                name: "fs_search".to_owned(),
                arguments: json!({"query": "alpha", "limit": 1}),
            })
            .unwrap();
        assert_eq!(searched, json!({"paths": ["alpha_one.txt"]}));

        let grep = server
            .call_tool(ToolCall {
                name: "fs_grep".to_owned(),
                arguments: json!({"pattern": "needle", "limit": 2}),
            })
            .unwrap();
        assert_eq!(
            grep,
            json!({
                "matches": [
                    {"path": "alpha_one.txt", "line": 1, "text": "needle"},
                    {"path": "alpha_one.txt", "line": 2, "text": "needle again"}
                ]
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escaping_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        symlink(
            outside.path().join("secret.txt"),
            tmp.path().join("link.txt"),
        )
        .unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();

        let err = server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "link.txt"}),
            })
            .unwrap_err();

        assert!(err.to_string().contains("outside root"));
    }
}
