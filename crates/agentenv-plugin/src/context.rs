use std::sync::Arc;
use std::time::Duration;
use std::{fmt, fmt::Formatter};

use agentenv_core::driver::{ensure_protocol_compatible, ContextDriver, DriverError, DriverResult};
use agentenv_core::driver_catalog::DiscoveredDriver;
use agentenv_core::registry::DriverKind as CatalogKind;
use agentenv_events::{EventEmitter, NoopEventEmitter};
use agentenv_proto::{
    Capabilities, ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus,
    CredentialRequirementsParams, CredentialRequirementsResult, EmptyResult, InitializeParams,
    InitializeResult, McpEndpoint, PreflightParams, PreflightResult, RequiredNetworkRulesResult,
    ShutdownParams,
};
use async_trait::async_trait;

use crate::jsonrpc::{JsonRpcClient, JsonRpcClientConfig, JsonRpcError};

pub struct SubprocessContextDriver {
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

impl fmt::Debug for SubprocessContextDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubprocessContextDriver")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl SubprocessContextDriver {
    pub async fn from_discovered(entry: DiscoveredDriver, timeout: Duration) -> DriverResult<Self> {
        Self::from_discovered_unstarted(entry, timeout)
    }

    pub fn from_discovered_unstarted(
        entry: DiscoveredDriver,
        timeout: Duration,
    ) -> DriverResult<Self> {
        if entry.kind != CatalogKind::Context {
            return Err(DriverError::Subprocess {
                driver: entry.name,
                message: format!("expected context driver entry, got {}", entry.kind),
            });
        }

        if entry.binary.is_none() {
            return Err(DriverError::Subprocess {
                driver: entry.name.clone(),
                message: "discovered subprocess context driver is missing binary".to_owned(),
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
                message: "discovered subprocess context driver is missing binary".to_owned(),
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
            message: "subprocess context driver used before initialize".to_owned(),
        })
    }
}

pub fn validate_context_initialize(result: &InitializeResult) -> DriverResult<()> {
    ensure_protocol_compatible(result)?;

    if result.driver.kind != agentenv_proto::DriverKind::Context {
        return Err(DriverError::Subprocess {
            driver: result.driver.name.clone(),
            message: format!("expected context driver kind, got {:?}", result.driver.kind),
        });
    }

    if !matches!(result.capabilities, Capabilities::Context(_)) {
        return Err(DriverError::Subprocess {
            driver: result.driver.name.clone(),
            message: "expected context driver capabilities".to_owned(),
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
impl ContextDriver for SubprocessContextDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        if self.client.is_none() {
            self.client = Some(self.spawn_client().await?);
        }
        let result = self
            .client()?
            .call("initialize", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))?;
        validate_context_initialize(&result)?;
        Ok(result)
    }

    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
        self.client()?
            .call("preflight", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn provision(&self, spec: ContextSpec) -> DriverResult<ContextHandle> {
        self.client()?
            .call("provision", &spec)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        self.client()?
            .call("mcp_endpoint", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        self.client()?
            .call("required_network_rules", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn credential_requirements(
        &self,
        params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        self.client()?
            .call("credential_requirements", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        self.client()?
            .call("status", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        self.client()?
            .call("teardown", &params)
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
        Capabilities, ContextCapabilities, DriverInfo, DriverKind, InitializeResult, SCHEMA_VERSION,
    };
    use semver::Version;
    use serde_json::Value;

    use super::SubprocessContextDriver;

    fn mock_entry() -> DiscoveredDriver {
        DiscoveredDriver {
            kind: CatalogKind::Context,
            name: "nexus".to_owned(),
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

    #[tokio::test]
    async fn constructor_rejects_built_in_entries_without_binary() {
        let mut entry = mock_entry();
        entry.binary = None;

        let err = SubprocessContextDriver::from_discovered(entry, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("binary"));
    }

    #[test]
    fn initialize_result_validator_accepts_context_driver() {
        let init = InitializeResult {
            driver: DriverInfo {
                name: "nexus".to_owned(),
                kind: DriverKind::Context,
                version: "0.1.0".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Context(ContextCapabilities {
                is_remote: true,
                is_shared: true,
                supports_zones: true,
                supports_snapshots: true,
            }),
        };

        super::validate_context_initialize(&init).unwrap();
    }

    #[test]
    fn initialize_result_validator_rejects_agent_driver() {
        let init = InitializeResult {
            driver: DriverInfo {
                name: "bad".to_owned(),
                kind: DriverKind::Agent,
                version: "0.1.0".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Context(ContextCapabilities {
                is_remote: true,
                is_shared: true,
                supports_zones: true,
                supports_snapshots: true,
            }),
        };

        let err = super::validate_context_initialize(&init).unwrap_err();
        assert!(err.to_string().contains("context"));
    }
}
