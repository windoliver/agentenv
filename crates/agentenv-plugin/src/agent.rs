use std::sync::Arc;
use std::time::Duration;
use std::{fmt, fmt::Formatter};

use agentenv_core::driver::{ensure_protocol_compatible, AgentDriver, DriverError, DriverResult};
use agentenv_core::driver_catalog::DiscoveredDriver;
use agentenv_core::registry::DriverKind as CatalogKind;
use agentenv_events::{EventEmitter, NoopEventEmitter};
use agentenv_proto::{
    AgentHealthCheckProbe, AgentSpec, Capabilities, CredentialRequirementsResult, EmptyResult,
    InitializeParams, InitializeResult, InstallStepsResult, McpConfigPathParams,
    McpConfigPathResult, PreflightParams, PreflightResult, RenderEntrypointResult,
    RenderMcpConfigParams, RenderMcpConfigResult, ShutdownParams,
};
use async_trait::async_trait;

use crate::jsonrpc::{JsonRpcClient, JsonRpcClientConfig, JsonRpcError};

pub struct SubprocessAgentDriver {
    name: String,
    entry: DiscoveredDriver,
    timeout: Duration,
    event_emitter: Arc<dyn EventEmitter>,
    approval_context: Option<ApprovalDriverContext>,
    client: Option<JsonRpcClient>,
}

#[derive(Clone)]
struct ApprovalDriverContext {
    env_name: String,
    coordinator: agentenv_approvals::ApprovalCoordinator,
}

impl fmt::Debug for SubprocessAgentDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubprocessAgentDriver")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl SubprocessAgentDriver {
    pub fn from_discovered_unstarted(
        entry: DiscoveredDriver,
        timeout: Duration,
    ) -> DriverResult<Self> {
        if entry.kind != CatalogKind::Agent {
            return Err(DriverError::Subprocess {
                driver: entry.name,
                message: format!("expected agent driver entry, got {}", entry.kind),
            });
        }

        if entry.binary.is_none() {
            return Err(DriverError::Subprocess {
                driver: entry.name.clone(),
                message: "discovered subprocess agent driver is missing binary".to_owned(),
            });
        }

        Ok(Self {
            name: entry.name.clone(),
            entry,
            timeout,
            event_emitter: Arc::new(NoopEventEmitter),
            approval_context: None,
            client: None,
        })
    }

    pub fn with_event_emitter(mut self, event_emitter: Arc<dyn EventEmitter>) -> Self {
        self.event_emitter = event_emitter;
        self
    }

    pub fn with_approval_coordinator(
        mut self,
        env_name: impl Into<String>,
        coordinator: agentenv_approvals::ApprovalCoordinator,
    ) -> Self {
        self.approval_context = Some(ApprovalDriverContext {
            env_name: env_name.into(),
            coordinator,
        });
        self
    }

    async fn spawn_client(&self) -> DriverResult<JsonRpcClient> {
        let binary = self
            .entry
            .binary
            .clone()
            .ok_or_else(|| DriverError::Subprocess {
                driver: self.name.clone(),
                message: "discovered subprocess agent driver is missing binary".to_owned(),
            })?;
        let mut client = JsonRpcClient::spawn(JsonRpcClientConfig {
            binary,
            args: self.entry.args.clone(),
            env: self.entry.env.clone(),
            timeout: self.timeout,
        })
        .await
        .map_err(|err| map_jsonrpc_error(&self.name, err))?;
        client.set_event_emitter_arc(Arc::clone(&self.event_emitter));
        if let Some(approval_context) = &self.approval_context {
            client.set_approval_coordinator(
                approval_context.env_name.clone(),
                approval_context.coordinator.clone(),
            );
        }
        Ok(client)
    }

    fn client(&self) -> DriverResult<&JsonRpcClient> {
        self.client.as_ref().ok_or_else(|| DriverError::Subprocess {
            driver: self.name.clone(),
            message: "subprocess agent driver used before initialize".to_owned(),
        })
    }
}

pub fn validate_agent_initialize(result: &InitializeResult) -> DriverResult<()> {
    ensure_protocol_compatible(result)?;

    if result.driver.kind != agentenv_proto::DriverKind::Agent {
        return Err(DriverError::Subprocess {
            driver: result.driver.name.clone(),
            message: format!("expected agent driver kind, got {:?}", result.driver.kind),
        });
    }

    if !matches!(result.capabilities, Capabilities::Agent(_)) {
        return Err(DriverError::Subprocess {
            driver: result.driver.name.clone(),
            message: "expected agent driver capabilities".to_owned(),
        });
    }

    Ok(())
}

fn map_jsonrpc_error(driver: &str, err: JsonRpcError) -> DriverError {
    DriverError::Subprocess {
        driver: driver.to_owned(),
        message: err.to_string(),
    }
}

#[async_trait]
impl AgentDriver for SubprocessAgentDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        if self.client.is_none() {
            self.client = Some(self.spawn_client().await?);
        }
        let result = self
            .client()?
            .call("initialize", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))?;
        validate_agent_initialize(&result)?;
        Ok(result)
    }

    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
        self.client()?
            .call("preflight", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn install_steps(&self, spec: AgentSpec) -> DriverResult<InstallStepsResult> {
        self.client()?
            .call("install_steps", &spec)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn mcp_config_path(
        &self,
        params: McpConfigPathParams,
    ) -> DriverResult<McpConfigPathResult> {
        self.client()?
            .call("mcp_config_path", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn render_mcp_config(
        &self,
        params: RenderMcpConfigParams,
    ) -> DriverResult<RenderMcpConfigResult> {
        self.client()?
            .call("render_mcp_config", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn render_entrypoint(&self, spec: AgentSpec) -> DriverResult<RenderEntrypointResult> {
        self.client()?
            .call("render_entrypoint", &spec)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn credential_requirements(
        &self,
        spec: AgentSpec,
    ) -> DriverResult<CredentialRequirementsResult> {
        self.client()?
            .call("credential_requirements", &spec)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn health_check_probe(&self, spec: AgentSpec) -> DriverResult<AgentHealthCheckProbe> {
        self.client()?
            .call("health_check_probe", &spec)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        if let Some(client) = self.client.as_mut() {
            client
                .shutdown()
                .await
                .map_err(|err| map_jsonrpc_error(&self.name, err))?;
        }
        Ok(EmptyResult::default())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use agentenv_core::driver_catalog::{DiscoveredDriver, DriverSource};
    use agentenv_core::registry::DriverKind as CatalogKind;
    use agentenv_proto::{
        AgentCapabilities, Capabilities, DriverInfo, DriverKind, InitializeResult, SCHEMA_VERSION,
    };
    use semver::Version;
    use serde_json::Value;

    fn mock_entry() -> DiscoveredDriver {
        DiscoveredDriver {
            kind: CatalogKind::Agent,
            name: "hermes".to_owned(),
            version: Version::parse("0.1.0").unwrap(),
            source: DriverSource::DevelopmentOverride,
            description: None,
            binary: Some(PathBuf::from("driver")),
            manifest_path: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            capabilities_preview: Value::Null,
        }
    }

    #[test]
    fn constructor_rejects_built_in_entries_without_binary() {
        let mut entry = mock_entry();
        entry.binary = None;

        let err =
            super::SubprocessAgentDriver::from_discovered_unstarted(entry, Duration::from_secs(1))
                .unwrap_err();

        assert!(err.to_string().contains("binary"));
    }

    #[test]
    fn initialize_result_validator_accepts_agent_driver() {
        let init = InitializeResult {
            driver: DriverInfo {
                name: "hermes".to_owned(),
                kind: DriverKind::Agent,
                version: "0.1.0".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Agent(AgentCapabilities {
                supports_mcp: true,
                supports_slash_commands: true,
                supports_tui: true,
                supports_headless: true,
            }),
        };

        super::validate_agent_initialize(&init).unwrap();
    }

    #[test]
    fn initialize_result_validator_rejects_context_driver() {
        let init = InitializeResult {
            driver: DriverInfo {
                name: "bad".to_owned(),
                kind: DriverKind::Context,
                version: "0.1.0".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Agent(AgentCapabilities {
                supports_mcp: true,
                supports_slash_commands: true,
                supports_tui: true,
                supports_headless: true,
            }),
        };

        let err = super::validate_agent_initialize(&init).unwrap_err();
        assert!(err.to_string().contains("expected agent driver kind"));
    }
}
