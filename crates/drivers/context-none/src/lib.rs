#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use agentenv_core::{
    context_common::{
        context_initialize, empty_credential_requirements, empty_network_rules, empty_result,
        local_context_capabilities, successful_preflight,
    },
    driver::{ContextDriver, DriverError, DriverResult},
};
use agentenv_proto::{
    ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus, CredentialRequirementsParams,
    CredentialRequirementsResult, EmptyResult, InitializeParams, InitializeResult, McpEndpoint,
    McpTransport, PreflightParams, PreflightResult, RequiredNetworkRulesResult, ShutdownParams,
};
use async_trait::async_trait;

pub const CRATE_NAME: &str = "context-none";
const DRIVER_NAME: &str = "none";
const HANDLE: &str = "none|";

#[derive(Debug, Default)]
pub struct NoneContextDriver;

#[async_trait]
impl ContextDriver for NoneContextDriver {
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
        if !spec.config.is_empty() {
            return Err(DriverError::InvalidConfig {
                field: "context".to_owned(),
                message: "context-none does not accept configuration".to_owned(),
            });
        }

        Ok(ContextHandle {
            handle: HANDLE.to_owned(),
        })
    }

    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        validate_handle(&params.handle)?;

        Ok(McpEndpoint {
            url: String::new(),
            transport: McpTransport::Stdio,
            headers: BTreeMap::new(),
        })
    }

    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        validate_handle(&params.handle)?;

        Ok(empty_network_rules())
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(empty_credential_requirements())
    }

    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        validate_handle(&params.handle)?;

        Ok(ContextStatus {
            healthy: true,
            detail: Some("no context configured".to_owned()),
        })
    }

    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        validate_handle(&params.handle)?;

        Ok(empty_result())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(empty_result())
    }
}

fn validate_handle(handle: &str) -> DriverResult<()> {
    if handle == HANDLE {
        Ok(())
    } else {
        Err(DriverError::InvalidHandle {
            handle: handle.to_owned(),
            message: "expected context-none handle `none|`".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_core::driver::ContextDriver;
    use agentenv_proto::{
        Capabilities, ContextHandleRequest, ContextSpec, CredentialRequirementsParams,
        InitializeParams, LogLevel, McpTransport, PreflightParams, SCHEMA_VERSION,
    };

    use super::NoneContextDriver;

    fn empty_context_spec() -> ContextSpec {
        ContextSpec {
            config: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn none_driver_satisfies_context_conformance_contract() {
        let mut driver = NoneContextDriver;

        driver_conformance::assert_context_driver_contract(&mut driver, empty_context_spec())
            .await
            .expect("context-none should satisfy context driver conformance");
    }

    #[tokio::test]
    async fn initialize_returns_no_context_capabilities() {
        let mut driver = NoneContextDriver;

        let result = driver
            .initialize(InitializeParams {
                schema_version: SCHEMA_VERSION.to_owned(),
                core_version: "0.0.1".to_owned(),
                workdir: "/tmp/agentenv".to_owned(),
                log_level: LogLevel::Info,
            })
            .await
            .expect("initialize should succeed");

        assert_eq!(result.driver.name, "none");
        let Capabilities::Context(capabilities) = result.capabilities else {
            panic!("expected context capabilities");
        };
        assert!(!capabilities.is_remote);
        assert!(!capabilities.is_shared);
        assert!(!capabilities.supports_zones);
        assert!(!capabilities.supports_snapshots);
    }

    #[tokio::test]
    async fn provision_returns_empty_stdio_endpoint_and_no_requirements() {
        let driver = NoneContextDriver;

        let handle = driver
            .provision(empty_context_spec())
            .await
            .expect("provision should succeed");
        let endpoint = driver
            .mcp_endpoint(ContextHandleRequest {
                handle: handle.handle.clone(),
            })
            .await
            .expect("mcp endpoint should succeed");
        let network_rules = driver
            .required_network_rules(ContextHandleRequest {
                handle: handle.handle.clone(),
            })
            .await
            .expect("network rules should succeed");
        let credentials = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .expect("credential requirements should succeed");

        assert_eq!(handle.handle, "none|");
        assert_eq!(endpoint.url, "");
        assert_eq!(endpoint.transport, McpTransport::Stdio);
        assert!(endpoint.headers.is_empty());
        assert!(network_rules.rules.is_empty());
        assert!(credentials.requirements.is_empty());
    }

    #[tokio::test]
    async fn invalid_handle_is_rejected() {
        let driver = NoneContextDriver;

        let err = driver
            .mcp_endpoint(ContextHandleRequest {
                handle: "filesystem|1".to_owned(),
            })
            .await
            .expect_err("invalid handle should fail");

        assert!(err.to_string().contains("invalid"));
    }

    #[tokio::test]
    async fn preflight_succeeds() {
        let driver = NoneContextDriver;

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight should succeed");

        assert!(result.ok);
        assert!(result.issues.is_empty());
    }
}
