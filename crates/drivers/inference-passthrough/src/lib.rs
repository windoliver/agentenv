#![forbid(unsafe_code)]

use agentenv_core::{
    driver::{DriverResult, InferenceDriver},
    inference::{
        empty_credential_requirements, empty_result, passthrough_endpoint, passthrough_handle,
        passthrough_initialize, successful_preflight,
    },
};
use agentenv_proto::{
    CredentialRequirementsParams, CredentialRequirementsResult, EmptyResult,
    EndpointInSandboxResult, InferenceHandle, InferenceHandleRequest, InferenceSpec,
    InitializeParams, InitializeResult, PreflightParams, PreflightResult, ShutdownParams,
};
use async_trait::async_trait;

pub const CRATE_NAME: &str = "inference-passthrough";

#[derive(Debug, Default)]
pub struct PassthroughInferenceDriver;

#[async_trait]
impl InferenceDriver for PassthroughInferenceDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(passthrough_initialize("passthrough"))
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(successful_preflight())
    }

    async fn provision(&self, _spec: InferenceSpec) -> DriverResult<InferenceHandle> {
        Ok(passthrough_handle())
    }

    async fn endpoint_in_sandbox(
        &self,
        params: InferenceHandleRequest,
    ) -> DriverResult<EndpointInSandboxResult> {
        passthrough_endpoint(&params.handle)
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(empty_credential_requirements())
    }

    async fn teardown(&self, _params: InferenceHandleRequest) -> DriverResult<EmptyResult> {
        Ok(empty_result())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(empty_result())
    }
}

#[cfg(test)]
mod tests {
    use agentenv_core::driver::InferenceDriver;
    use agentenv_proto::{
        Capabilities, CredentialRequirementsParams, InferenceSpec, InitializeParams, LogLevel,
        PreflightParams, SCHEMA_VERSION,
    };

    use super::PassthroughInferenceDriver;

    fn init_params() -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-alpha0".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        }
    }

    #[tokio::test]
    async fn initialize_returns_passthrough_capabilities() {
        let mut driver = PassthroughInferenceDriver;
        let result = driver.initialize(init_params()).await.unwrap();

        assert_eq!(result.driver.name, "passthrough");
        let Capabilities::Inference(capabilities) = result.capabilities else {
            panic!("expected inference capabilities");
        };
        assert!(!capabilities.strips_caller_credentials);
        assert!(!capabilities.supports_model_switching);
    }

    #[tokio::test]
    async fn preflight_succeeds_without_host_checks() {
        let driver = PassthroughInferenceDriver;
        let result = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(result.ok);
        assert!(result.issues.is_empty());
    }

    #[tokio::test]
    async fn provision_is_noop_and_endpoint_is_empty() {
        let driver = PassthroughInferenceDriver;
        let handle = driver
            .provision(InferenceSpec {
                config: Default::default(),
            })
            .await
            .unwrap();
        let endpoint = driver
            .endpoint_in_sandbox(agentenv_proto::InferenceHandleRequest {
                handle: handle.handle,
            })
            .await
            .unwrap();

        assert_eq!(endpoint.url, "");
    }

    #[tokio::test]
    async fn credential_requirements_are_empty() {
        let driver = PassthroughInferenceDriver;
        let requirements = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert!(requirements.requirements.is_empty());
    }
}
