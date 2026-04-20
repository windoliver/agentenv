#![forbid(unsafe_code)]

use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs,
    path::PathBuf,
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

pub const CRATE_NAME: &str = "context-filesystem";
const DRIVER_NAME: &str = "filesystem";

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
