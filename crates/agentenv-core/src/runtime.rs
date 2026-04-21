use std::{fmt, path::PathBuf};

use agentenv_proto::{
    AgentSpec, ContextSpec, InferenceSpec, InitializeParams, InitializeResult, LogLevel,
    PreflightParams, SCHEMA_VERSION,
};
use thiserror::Error;

use crate::{
    driver::{AgentDriver, ContextDriver, DriverError, InferenceDriver, SandboxDriver},
    env::EnvError,
};

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub root: PathBuf,
    pub log_level: LogLevel,
    pub non_interactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverSelection {
    pub sandbox: String,
    pub agent: String,
    pub context: String,
    pub inference: Option<String>,
}

pub struct DriverSet {
    pub sandbox: Box<dyn SandboxDriver>,
    pub agent: Box<dyn AgentDriver>,
    pub context: Box<dyn ContextDriver>,
    pub inference: Option<Box<dyn InferenceDriver>>,
}

pub trait DriverFactory {
    fn build(&self, selection: &DriverSelection) -> RuntimeResult<DriverSet>;
}

pub trait CredentialProvider {
    fn resolve(
        &mut self,
        requirement: &agentenv_proto::CredentialRequirement,
    ) -> RuntimeResult<Option<String>>;
    fn backend_name(&self, name: &str) -> RuntimeResult<Option<String>>;
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Env(#[from] EnvError),
    #[error(transparent)]
    Driver(#[from] DriverError),
    #[error(transparent)]
    Lifecycle(#[from] crate::lifecycle::LifecycleError),
    #[error("unsupported driver `{name}` for {kind}")]
    UnsupportedDriver { kind: &'static str, name: String },
    #[error("missing credential `{name}`")]
    MissingCredential { name: String },
    #[error("command exited with status {status}")]
    CommandStatus { status: i32 },
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;

pub async fn initialize_sandbox_driver(
    options: &RuntimeOptions,
    driver: &mut dyn SandboxDriver,
) -> RuntimeResult<InitializeResult> {
    driver
        .initialize(initialize_params(options))
        .await
        .map_err(Into::into)
}

pub async fn initialize_agent_driver(
    options: &RuntimeOptions,
    driver: &mut dyn AgentDriver,
) -> RuntimeResult<InitializeResult> {
    driver
        .initialize(initialize_params(options))
        .await
        .map_err(Into::into)
}

pub async fn initialize_context_driver(
    options: &RuntimeOptions,
    driver: &mut dyn ContextDriver,
) -> RuntimeResult<InitializeResult> {
    driver
        .initialize(initialize_params(options))
        .await
        .map_err(Into::into)
}

pub async fn initialize_inference_driver(
    options: &RuntimeOptions,
    driver: &mut dyn InferenceDriver,
) -> RuntimeResult<InitializeResult> {
    driver
        .initialize(initialize_params(options))
        .await
        .map_err(Into::into)
}

fn initialize_params(options: &RuntimeOptions) -> InitializeParams {
    InitializeParams {
        schema_version: SCHEMA_VERSION.to_owned(),
        core_version: env!("CARGO_PKG_VERSION").to_owned(),
        workdir: options.root.display().to_string(),
        log_level: options.log_level.clone(),
    }
}

pub fn empty_preflight_params() -> PreflightParams {
    PreflightParams {}
}

pub fn component_spec(
    extra: std::collections::BTreeMap<String, serde_yaml::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    extra
        .into_iter()
        .filter_map(|(key, value)| serde_json::to_value(value).ok().map(|value| (key, value)))
        .collect()
}

pub fn agent_spec(
    extra: std::collections::BTreeMap<String, serde_yaml::Value>,
    version: Option<String>,
) -> AgentSpec {
    AgentSpec {
        version,
        config: component_spec(extra).into_iter().collect(),
    }
}

pub fn context_spec(extra: std::collections::BTreeMap<String, serde_yaml::Value>) -> ContextSpec {
    ContextSpec {
        config: component_spec(extra).into_iter().collect(),
    }
}

pub fn inference_spec(
    extra: std::collections::BTreeMap<String, serde_yaml::Value>,
) -> InferenceSpec {
    InferenceSpec {
        config: component_spec(extra).into_iter().collect(),
    }
}

impl fmt::Debug for DriverSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverSet").finish_non_exhaustive()
    }
}

#[cfg(test)]
pub mod tests_support {
    use agentenv_proto::{
        AgentCapabilities, AgentHealthCheckProbe, AgentSpec, Capabilities,
        CredentialRequirementsResult, DriverInfo, DriverKind, EmptyResult, InitializeParams,
        InitializeResult, InstallStepsResult, McpConfigPathParams, McpConfigPathResult,
        PreflightParams, PreflightResult, RenderEntrypointResult, RenderMcpConfigParams,
        RenderMcpConfigResult, SCHEMA_VERSION,
    };
    use async_trait::async_trait;

    use crate::driver::{AgentDriver, DriverResult};

    pub struct TinyAgentDriver;

    #[async_trait]
    impl AgentDriver for TinyAgentDriver {
        async fn initialize(
            &mut self,
            _params: InitializeParams,
        ) -> DriverResult<InitializeResult> {
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "codex".to_owned(),
                    kind: DriverKind::Agent,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Agent(AgentCapabilities {
                    supports_mcp: true,
                    supports_slash_commands: true,
                    supports_tui: true,
                    supports_headless: true,
                }),
            })
        }
        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }
        async fn install_steps(&self, _spec: AgentSpec) -> DriverResult<InstallStepsResult> {
            Ok(InstallStepsResult { steps: Vec::new() })
        }
        async fn mcp_config_path(
            &self,
            _params: McpConfigPathParams,
        ) -> DriverResult<McpConfigPathResult> {
            Ok(McpConfigPathResult {
                path: "~/.codex/config.toml".to_owned(),
            })
        }
        async fn render_mcp_config(
            &self,
            _params: RenderMcpConfigParams,
        ) -> DriverResult<RenderMcpConfigResult> {
            Ok(RenderMcpConfigResult {
                content: String::new(),
            })
        }
        async fn render_entrypoint(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<RenderEntrypointResult> {
            Ok(RenderEntrypointResult {
                content: "#!/usr/bin/env sh\nexec codex \"$@\"\n".to_owned(),
            })
        }
        async fn credential_requirements(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<CredentialRequirementsResult> {
            Ok(CredentialRequirementsResult {
                requirements: Vec::new(),
            })
        }
        async fn health_check_probe(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<AgentHealthCheckProbe> {
            Ok(AgentHealthCheckProbe {
                cmd: "codex --version".to_owned(),
                tty: false,
                env: Default::default(),
                success_exit_codes: vec![0],
            })
        }
        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use agentenv_proto::{
        Capabilities, ContextCapabilities, DriverInfo, DriverKind, EmptyResult, InitializeParams,
        InitializeResult, LogLevel, PreflightParams, PreflightResult, SandboxCapabilities,
        SCHEMA_VERSION,
    };
    use async_trait::async_trait;

    use crate::driver::{ContextDriver, DriverResult, SandboxDriver};

    use super::{
        initialize_context_driver, initialize_sandbox_driver, DriverFactory, DriverSet,
        RuntimeOptions,
    };

    #[derive(Default)]
    struct TinyFactory;

    impl DriverFactory for TinyFactory {
        fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
            Ok(DriverSet {
                sandbox: Box::new(TinySandboxDriver),
                agent: Box::new(super::tests_support::TinyAgentDriver),
                context: Box::new(TinyContextDriver),
                inference: None,
            })
        }
    }

    struct TinySandboxDriver;

    #[async_trait]
    impl SandboxDriver for TinySandboxDriver {
        async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
            assert_eq!(params.schema_version, SCHEMA_VERSION);
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "openshell".to_owned(),
                    kind: DriverKind::Sandbox,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn create(
            &self,
            _spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            Ok(agentenv_proto::SandboxHandle {
                handle: "sb-1".to_owned(),
            })
        }

        async fn connect(
            &self,
            _params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            Ok(agentenv_proto::ShellHandle {
                session_id: "sh-1".to_owned(),
                tty: true,
                working_dir: None,
            })
        }

        async fn exec(
            &self,
            _params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: "ok\n".to_owned(),
                stderr: String::new(),
            })
        }

        async fn copy_in(
            &self,
            _params: agentenv_proto::CopyInParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn copy_out(
            &self,
            _params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn apply_policy(
            &self,
            _params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            Ok(agentenv_proto::ApplyPolicyResult { hot_reloaded: true })
        }
        async fn status(
            &self,
            _params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            Ok(agentenv_proto::SandboxStatus {
                phase: agentenv_proto::SandboxPhase::Running,
                healthy: true,
                last_ping: Some("2026-04-21T00:00:00Z".to_owned()),
            })
        }
        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }
        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn destroy(
            &self,
            _params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    struct TinyContextDriver;

    #[async_trait]
    impl ContextDriver for TinyContextDriver {
        async fn initialize(
            &mut self,
            _params: InitializeParams,
        ) -> DriverResult<InitializeResult> {
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "filesystem".to_owned(),
                    kind: DriverKind::Context,
                    version: "0.0.1-alpha0".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Context(ContextCapabilities {
                    is_remote: false,
                    is_shared: false,
                    supports_zones: false,
                    supports_snapshots: false,
                }),
            })
        }
        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }
        async fn provision(
            &self,
            _spec: agentenv_proto::ContextSpec,
        ) -> DriverResult<agentenv_proto::ContextHandle> {
            Ok(agentenv_proto::ContextHandle {
                handle: "ctx-1".to_owned(),
            })
        }
        async fn mcp_endpoint(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::McpEndpoint> {
            Ok(agentenv_proto::McpEndpoint {
                url: "agentenv-fs-mcp".to_owned(),
                transport: agentenv_proto::McpTransport::Stdio,
                headers: BTreeMap::new(),
            })
        }
        async fn required_network_rules(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::RequiredNetworkRulesResult> {
            Ok(agentenv_proto::RequiredNetworkRulesResult { rules: Vec::new() })
        }
        async fn credential_requirements(
            &self,
            _params: agentenv_proto::CredentialRequirementsParams,
        ) -> DriverResult<agentenv_proto::CredentialRequirementsResult> {
            Ok(agentenv_proto::CredentialRequirementsResult {
                requirements: Vec::new(),
            })
        }
        async fn status(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<agentenv_proto::ContextStatus> {
            Ok(agentenv_proto::ContextStatus {
                healthy: true,
                detail: None,
            })
        }
        async fn teardown(
            &self,
            _params: agentenv_proto::ContextHandleRequest,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
        async fn shutdown(
            &mut self,
            _params: agentenv_proto::ShutdownParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult {})
        }
    }

    #[tokio::test]
    async fn initialize_helpers_use_current_protocol() {
        let mut sandbox = TinySandboxDriver;
        let mut context = TinyContextDriver;
        let options = RuntimeOptions {
            root: std::env::temp_dir(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };

        let sandbox_info = initialize_sandbox_driver(&options, &mut sandbox)
            .await
            .unwrap();
        let context_info = initialize_context_driver(&options, &mut context)
            .await
            .unwrap();

        assert_eq!(sandbox_info.driver.name, "openshell");
        assert_eq!(context_info.driver.name, "filesystem");
    }

    #[test]
    fn factory_trait_builds_driver_set() {
        let selection = super::DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: None,
        };
        let set = TinyFactory.build(&selection).unwrap();
        let _set: Arc<str> = Arc::from(selection.agent.as_str());
        drop(set);
    }
}
