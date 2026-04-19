#![forbid(unsafe_code)]

use agentenv_core::driver::{DriverResult, InferenceDriver};
use agentenv_core::inference::{
    empty_result, routed_credential_requirements, routed_endpoint, routed_handle,
    routed_initialize, successful_preflight, NativeRoutingPlan, ProviderConfig, ProviderDefaults,
    ProxySidecarPlan,
};
use agentenv_proto::{
    CredentialRequirementsParams, CredentialRequirementsResult, EmptyResult,
    EndpointInSandboxResult, InferenceHandle, InferenceHandleRequest, InferenceSpec,
    InitializeParams, InitializeResult, PreflightParams, PreflightResult, ShutdownParams,
};
use async_trait::async_trait;

pub const CRATE_NAME: &str = "inference-anthropic";

const DEFAULTS: ProviderDefaults = ProviderDefaults {
    driver_name: "anthropic",
    provider: "anthropic",
    default_model: "claude-3-5-sonnet-latest",
    default_base_url: "https://api.anthropic.com",
    credential_env: Some("ANTHROPIC_API_KEY"),
};

#[derive(Debug, Default)]
pub struct AnthropicInferenceDriver;

#[async_trait]
impl InferenceDriver for AnthropicInferenceDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(routed_initialize(DEFAULTS))
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(successful_preflight())
    }

    async fn provision(&self, spec: InferenceSpec) -> DriverResult<InferenceHandle> {
        let _ = ProviderConfig::from_spec(DEFAULTS, &spec)?;
        Ok(routed_handle(DEFAULTS))
    }

    async fn endpoint_in_sandbox(
        &self,
        params: InferenceHandleRequest,
    ) -> DriverResult<EndpointInSandboxResult> {
        routed_endpoint(DEFAULTS, &params.handle)
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(routed_credential_requirements(DEFAULTS))
    }

    async fn teardown(&self, _params: InferenceHandleRequest) -> DriverResult<EmptyResult> {
        Ok(empty_result())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(empty_result())
    }
}

pub fn provider_config(spec: &InferenceSpec) -> DriverResult<ProviderConfig> {
    ProviderConfig::from_spec(DEFAULTS, spec)
}

pub fn native_routing_plan(spec: &InferenceSpec) -> DriverResult<NativeRoutingPlan> {
    Ok(provider_config(spec)?.native_routing_plan())
}

pub fn proxy_sidecar_plan(spec: &InferenceSpec) -> DriverResult<ProxySidecarPlan> {
    Ok(provider_config(spec)?.proxy_sidecar_plan())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_core::driver::InferenceDriver;
    use agentenv_proto::{
        Capabilities, CredentialRequirementsParams, InferenceSpec, InitializeParams, LogLevel,
        SCHEMA_VERSION,
    };
    use serde_json::{json, Value};

    use super::{
        native_routing_plan, provider_config, proxy_sidecar_plan, AnthropicInferenceDriver,
    };

    fn init_params() -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-alpha0".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        }
    }

    fn spec(entries: Vec<(&str, Value)>) -> InferenceSpec {
        InferenceSpec {
            config: entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[tokio::test]
    async fn initialize_returns_anthropic_capabilities() {
        let mut driver = AnthropicInferenceDriver::default();
        let result = driver.initialize(init_params()).await.unwrap();

        assert_eq!(result.driver.name, "anthropic");
        let Capabilities::Inference(capabilities) = result.capabilities else {
            panic!("expected inference capabilities");
        };
        assert!(capabilities.strips_caller_credentials);
        assert!(capabilities.supports_model_switching);
    }

    #[test]
    fn provider_config_defaults_to_anthropic_model_and_url() {
        let config = provider_config(&spec(Vec::new())).unwrap();

        assert_eq!(config.model, "claude-3-5-sonnet-latest");
        assert_eq!(config.base_url, "https://api.anthropic.com");
        assert_eq!(config.credential_env.as_deref(), Some("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn provider_config_accepts_custom_model_and_base_url() {
        let config = provider_config(&spec(vec![
            ("model", json!("claude-3-7-sonnet-latest")),
            ("base_url", json!("https://api.anthropic.example.com")),
        ]))
        .unwrap();

        assert_eq!(config.model, "claude-3-7-sonnet-latest");
        assert_eq!(config.base_url, "https://api.anthropic.example.com");
    }

    #[test]
    fn empty_model_is_rejected() {
        let bad_config = spec(vec![("model", json!(""))]);
        let err = provider_config(&bad_config).expect_err("empty model must fail");

        assert_eq!(
            err.to_string(),
            "invalid driver config field `model`: must not be empty"
        );
    }

    #[tokio::test]
    async fn credential_requirements_include_anthropic_key_once() {
        let driver = AnthropicInferenceDriver::default();
        let requirements = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert_eq!(requirements.requirements.len(), 1);
        assert_eq!(requirements.requirements[0].name, "ANTHROPIC_API_KEY");
        assert!(requirements.requirements[0].required);
    }

    #[test]
    fn native_routing_plan_uses_inference_local_endpoint() {
        let plan = native_routing_plan(&spec(Vec::new())).unwrap();

        assert_eq!(plan.endpoint, "http://inference.local");
        assert_eq!(plan.provider, "anthropic");
        assert_eq!(plan.model, "claude-3-5-sonnet-latest");
        assert_eq!(plan.base_url, "https://api.anthropic.com");
    }

    #[test]
    fn proxy_sidecar_plan_uses_loopback_and_anthropic_credentials() {
        let plan = proxy_sidecar_plan(&spec(Vec::new())).unwrap();

        assert_eq!(plan.listen_url, "http://127.0.0.1:18080");
        assert_eq!(plan.upstream_base_url, "https://api.anthropic.com");
        assert_eq!(plan.provider, "anthropic");
        assert_eq!(plan.model, "claude-3-5-sonnet-latest");
        assert_eq!(plan.credential_env.as_deref(), Some("ANTHROPIC_API_KEY"));
    }

    #[tokio::test]
    async fn provision_then_endpoint_in_sandbox_returns_inference_local() {
        let driver = AnthropicInferenceDriver::default();
        let handle = driver.provision(spec(Vec::new())).await.unwrap();
        let endpoint = driver
            .endpoint_in_sandbox(agentenv_proto::InferenceHandleRequest {
                handle: handle.handle,
            })
            .await
            .unwrap();

        assert_eq!(endpoint.url, "http://inference.local");
    }
}
