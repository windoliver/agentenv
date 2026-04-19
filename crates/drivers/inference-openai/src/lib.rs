#![forbid(unsafe_code)]

use agentenv_core::driver::{DriverResult, InferenceDriver};
use agentenv_core::inference::{
    empty_result, ProviderConfig, ProviderDefaults, NativeRoutingPlan, ProxySidecarPlan,
    routed_credential_requirements, routed_endpoint, routed_handle, routed_initialize,
    successful_preflight,
};
use agentenv_proto::{
    CredentialRequirementsParams, CredentialRequirementsResult, EmptyResult, EndpointInSandboxResult,
    InferenceHandle, InferenceHandleRequest, InferenceSpec, InitializeParams, InitializeResult,
    PreflightParams, PreflightResult, ShutdownParams,
};
use async_trait::async_trait;

pub const CRATE_NAME: &str = "inference-openai";

const DEFAULTS: ProviderDefaults = ProviderDefaults {
    driver_name: "openai",
    provider: "openai",
    default_model: "gpt-4o",
    default_base_url: "https://api.openai.com/v1",
    credential_env: Some("OPENAI_API_KEY"),
};

#[derive(Debug, Default)]
pub struct OpenAiInferenceDriver;

#[async_trait]
impl InferenceDriver for OpenAiInferenceDriver {
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

    use super::{native_routing_plan, provider_config, proxy_sidecar_plan, OpenAiInferenceDriver};

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
    async fn initialize_returns_openai_capabilities() {
        let mut driver = OpenAiInferenceDriver::default();
        let result = driver.initialize(init_params()).await.unwrap();

        assert_eq!(result.driver.name, "openai");
        let Capabilities::Inference(capabilities) = result.capabilities else {
            panic!("expected inference capabilities");
        };
        assert!(capabilities.strips_caller_credentials);
        assert!(capabilities.supports_model_switching);
    }

    #[test]
    fn provider_config_defaults_to_openai_model_and_url() {
        let config = provider_config(&spec(Vec::new())).unwrap();

        assert_eq!(config.model, "gpt-4o");
        assert_eq!(config.base_url, "https://api.openai.com/v1");
        assert_eq!(config.credential_env.as_deref(), Some("OPENAI_API_KEY"));
    }

    #[test]
    fn provider_config_accepts_custom_model_and_base_url() {
        let config = provider_config(&spec(vec![
            ("model", json!("gpt-4.1")),
            ("base_url", json!("https://azure.example.com/openai")),
        ]))
        .unwrap();

        assert_eq!(config.model, "gpt-4.1");
        assert_eq!(config.base_url, "https://azure.example.com/openai");
    }

    #[test]
    fn malformed_base_url_is_rejected() {
        let bad_config = spec(vec![("base_url", json!("not-a-url"))]);
        let err = provider_config(&bad_config).expect_err(
            "malformed base_url must fail",
        );

        assert_eq!(
            err.to_string(),
            "invalid driver config field `base_url`: must be a valid http or https URL"
        );
    }

    #[tokio::test]
    async fn credential_requirements_include_openai_key_once() {
        let driver = OpenAiInferenceDriver::default();
        let requirements = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert_eq!(requirements.requirements.len(), 1);
        assert_eq!(requirements.requirements[0].name, "OPENAI_API_KEY");
        assert!(requirements.requirements[0].required);
    }

    #[test]
    fn native_routing_plan_uses_inference_local_endpoint() {
        let plan = native_routing_plan(&spec(Vec::new())).unwrap();

        assert_eq!(plan.endpoint, "http://inference.local");
        assert_eq!(plan.provider, "openai");
        assert_eq!(plan.model, "gpt-4o");
        assert_eq!(plan.base_url, "https://api.openai.com/v1");
    }

    #[test]
    fn proxy_sidecar_plan_uses_loopback_and_openai_credentials() {
        let plan = proxy_sidecar_plan(&spec(Vec::new())).unwrap();

        assert_eq!(plan.listen_url, "http://127.0.0.1:18080");
        assert_eq!(plan.upstream_base_url, "https://api.openai.com/v1");
        assert_eq!(plan.provider, "openai");
        assert_eq!(plan.model, "gpt-4o");
        assert_eq!(plan.credential_env.as_deref(), Some("OPENAI_API_KEY"));
    }

    #[tokio::test]
    async fn provision_then_endpoint_in_sandbox_returns_inference_local() {
        let driver = OpenAiInferenceDriver::default();
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
