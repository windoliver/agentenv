use agentenv_proto::{
    assert_compatible_schema_version, AgentSpec, ApplyPolicyParams, ApplyPolicyResult,
    ConnectParams, ContextHandleRequest, ContextSpec, ContextStatus, CredentialRequirementsParams,
    CredentialRequirementsResult, DestroyParams, EmptyResult, EndpointInSandboxResult, ExecParams,
    ExecResult, InferenceHandleRequest, InferenceSpec, InitializeParams, InitializeResult,
    InstallStepsResult, LogsParams, LogsResult, LogsStreamParams, McpConfigPathParams,
    McpConfigPathResult, McpEndpoint, PreflightParams, PreflightResult, RenderEntrypointResult,
    RenderMcpConfigParams, RenderMcpConfigResult, RequiredNetworkRulesResult, SandboxHandle,
    SandboxSpec, SandboxStatus, SandboxStatusParams, SchemaVersionError, ShellHandle,
    ShutdownParams, StopParams,
};
use async_trait::async_trait;
use thiserror::Error;

pub type DriverResult<T> = Result<T, DriverError>;

#[derive(Debug, Error)]
pub enum DriverError {
    #[error(transparent)]
    SchemaVersion(#[from] SchemaVersionError),
    #[error("driver is missing capability `{capability}`")]
    CapabilityMissing { capability: String },
}

pub fn ensure_protocol_compatible(result: &InitializeResult) -> DriverResult<()> {
    assert_compatible_schema_version(&result.driver.protocol_version)?;
    Ok(())
}

pub fn require_capability(capability: &str, supported: bool) -> DriverResult<()> {
    if supported {
        Ok(())
    } else {
        Err(DriverError::CapabilityMissing {
            capability: capability.to_owned(),
        })
    }
}

#[async_trait]
pub trait SandboxDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn create(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle>;
    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle>;
    async fn exec(&self, params: ExecParams) -> DriverResult<ExecResult>;
    async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult>;
    async fn copy_out(&self, params: agentenv_proto::CopyOutParams) -> DriverResult<EmptyResult>;
    async fn apply_policy(&self, params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult>;
    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus>;
    async fn logs(&self, params: LogsParams) -> DriverResult<LogsResult>;
    async fn logs_stream(&self, params: LogsStreamParams) -> DriverResult<EmptyResult>;
    async fn stop(&self, params: StopParams) -> DriverResult<EmptyResult>;
    async fn destroy(&self, params: DestroyParams) -> DriverResult<EmptyResult>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[async_trait]
pub trait AgentDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn install_steps(&self, spec: AgentSpec) -> DriverResult<InstallStepsResult>;
    async fn mcp_config_path(
        &self,
        params: McpConfigPathParams,
    ) -> DriverResult<McpConfigPathResult>;
    async fn render_mcp_config(
        &self,
        params: RenderMcpConfigParams,
    ) -> DriverResult<RenderMcpConfigResult>;
    async fn render_entrypoint(&self, spec: AgentSpec) -> DriverResult<RenderEntrypointResult>;
    async fn credential_requirements(
        &self,
        spec: AgentSpec,
    ) -> DriverResult<CredentialRequirementsResult>;
    async fn health_check_probe(
        &self,
        spec: AgentSpec,
    ) -> DriverResult<agentenv_proto::AgentHealthCheckProbe>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[async_trait]
pub trait ContextDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn provision(&self, spec: ContextSpec) -> DriverResult<agentenv_proto::ContextHandle>;
    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint>;
    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult>;
    async fn credential_requirements(
        &self,
        params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult>;
    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus>;
    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[async_trait]
pub trait InferenceDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn provision(&self, spec: InferenceSpec)
        -> DriverResult<agentenv_proto::InferenceHandle>;
    async fn endpoint_in_sandbox(
        &self,
        params: InferenceHandleRequest,
    ) -> DriverResult<EndpointInSandboxResult>;
    async fn credential_requirements(
        &self,
        params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult>;
    async fn teardown(&self, params: InferenceHandleRequest) -> DriverResult<EmptyResult>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[cfg(test)]
mod tests {
    use agentenv_proto::{
        schema_version_major, Capabilities, DriverInfo, DriverKind, InitializeResult,
        SandboxCapabilities, SCHEMA_VERSION,
    };

    use super::{ensure_protocol_compatible, require_capability, DriverError};

    #[test]
    fn compatibility_guard_rejects_mismatched_protocol_major() {
        let mismatched_protocol_version = format!(
            "{}.0",
            schema_version_major(SCHEMA_VERSION).expect("schema version should parse") + 1
        );
        let result = InitializeResult {
            driver: DriverInfo {
                name: "mock".to_owned(),
                kind: DriverKind::Sandbox,
                version: "0.0.1".to_owned(),
                protocol_version: mismatched_protocol_version,
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: true,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: true,
                supports_remote_host: false,
            }),
        };

        let err = ensure_protocol_compatible(&result).expect_err("major mismatch should fail");
        assert!(err.to_string().contains("upgrade the driver or the core"));
    }

    #[test]
    fn compatibility_guard_accepts_matching_protocol_version() {
        let result = InitializeResult {
            driver: DriverInfo {
                name: "mock".to_owned(),
                kind: DriverKind::Sandbox,
                version: "0.0.1".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: true,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: true,
                supports_remote_host: false,
            }),
        };

        ensure_protocol_compatible(&result).expect("matching schema version should pass");
    }

    #[test]
    fn capability_guard_returns_expected_error() {
        let err = require_capability("supports_hot_reload_policy", false)
            .expect_err("unsupported capability should fail");

        assert!(matches!(err, DriverError::CapabilityMissing { .. }));
    }
}
