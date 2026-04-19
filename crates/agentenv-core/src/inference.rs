use agentenv_proto::{
    Capabilities, CredentialKind, CredentialRequirement, CredentialRequirementsResult, DriverInfo,
    DriverKind, EmptyResult, EndpointInSandboxResult, InferenceCapabilities, InferenceHandle,
    InitializeResult, PreflightResult, SCHEMA_VERSION,
};
use serde_json::Value;

use crate::driver::{DriverError, DriverResult};

pub const DEFAULT_NATIVE_ENDPOINT: &str = "http://inference.local";
pub const DEFAULT_PROXY_LISTEN_URL: &str = "http://127.0.0.1:18080";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderDefaults {
    pub driver_name: &'static str,
    pub provider: &'static str,
    pub default_model: &'static str,
    pub default_base_url: &'static str,
    pub credential_env: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub credential_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRoutingPlan {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySidecarPlan {
    pub listen_url: String,
    pub upstream_base_url: String,
    pub provider: String,
    pub model: String,
    pub credential_env: Option<String>,
}

impl ProviderConfig {
    pub fn from_spec(
        defaults: ProviderDefaults,
        spec: &agentenv_proto::InferenceSpec,
    ) -> DriverResult<Self> {
        let model = optional_string(&spec.config, "model")?
            .unwrap_or_else(|| defaults.default_model.to_owned());
        let base_url = optional_string(&spec.config, "base_url")?
            .unwrap_or_else(|| defaults.default_base_url.to_owned());
        validate_http_url("base_url", &base_url)?;

        Ok(Self {
            provider: defaults.provider.to_owned(),
            model,
            base_url,
            credential_env: defaults.credential_env.map(str::to_owned),
        })
    }

    pub fn native_routing_plan(&self) -> NativeRoutingPlan {
        NativeRoutingPlan {
            provider: self.provider.clone(),
            model: self.model.clone(),
            base_url: self.base_url.clone(),
            endpoint: DEFAULT_NATIVE_ENDPOINT.to_owned(),
        }
    }

    pub fn proxy_sidecar_plan(&self) -> ProxySidecarPlan {
        ProxySidecarPlan {
            listen_url: DEFAULT_PROXY_LISTEN_URL.to_owned(),
            upstream_base_url: self.base_url.clone(),
            provider: self.provider.clone(),
            model: self.model.clone(),
            credential_env: self.credential_env.clone(),
        }
    }
}

pub fn passthrough_initialize(driver_name: &str) -> InitializeResult {
    InitializeResult {
        driver: DriverInfo {
            name: driver_name.to_owned(),
            kind: DriverKind::Inference,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: SCHEMA_VERSION.to_owned(),
        },
        capabilities: Capabilities::Inference(InferenceCapabilities {
            strips_caller_credentials: false,
            supports_model_switching: false,
        }),
    }
}

pub fn routed_initialize(defaults: ProviderDefaults) -> InitializeResult {
    InitializeResult {
        driver: DriverInfo {
            name: defaults.driver_name.to_owned(),
            kind: DriverKind::Inference,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: SCHEMA_VERSION.to_owned(),
        },
        capabilities: Capabilities::Inference(InferenceCapabilities {
            strips_caller_credentials: true,
            supports_model_switching: true,
        }),
    }
}

pub fn successful_preflight() -> PreflightResult {
    PreflightResult {
        ok: true,
        issues: Vec::new(),
    }
}

pub fn empty_result() -> EmptyResult {
    EmptyResult {}
}

pub fn passthrough_handle() -> InferenceHandle {
    InferenceHandle {
        handle: "passthrough|".to_owned(),
    }
}

pub fn passthrough_endpoint(handle: &str) -> DriverResult<EndpointInSandboxResult> {
    if handle == "passthrough|" {
        Ok(EndpointInSandboxResult { url: String::new() })
    } else {
        Err(DriverError::InvalidHandle {
            handle: handle.to_owned(),
            message: "expected passthrough handle `passthrough|`".to_owned(),
        })
    }
}

pub fn routed_handle(defaults: ProviderDefaults) -> InferenceHandle {
    InferenceHandle {
        handle: format!("{}|{}", defaults.driver_name, DEFAULT_NATIVE_ENDPOINT),
    }
}

pub fn routed_endpoint(
    defaults: ProviderDefaults,
    handle: &str,
) -> DriverResult<EndpointInSandboxResult> {
    let prefix = format!("{}|", defaults.driver_name);
    let endpoint = handle
        .strip_prefix(&prefix)
        .ok_or_else(|| DriverError::InvalidHandle {
            handle: handle.to_owned(),
            message: format!("expected prefix `{prefix}`"),
        })?;

    validate_http_url("handle.endpoint", endpoint)?;

    Ok(EndpointInSandboxResult {
        url: endpoint.to_owned(),
    })
}

pub fn routed_credential_requirements(
    defaults: ProviderDefaults,
) -> CredentialRequirementsResult {
    let requirements = defaults
        .credential_env
        .map(|name| CredentialRequirement {
            name: name.to_owned(),
            description: format!("API key used by the {} inference driver", defaults.provider),
            kind: CredentialKind::ApiKey,
            required: true,
            validator: None,
        })
        .into_iter()
        .collect();

    CredentialRequirementsResult { requirements }
}

pub fn empty_credential_requirements() -> CredentialRequirementsResult {
    CredentialRequirementsResult {
        requirements: Vec::new(),
    }
}

fn optional_string(
    config: &std::collections::BTreeMap<String, Value>,
    field: &str,
) -> DriverResult<Option<String>> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(DriverError::InvalidConfig {
            field: field.to_owned(),
            message: "must not be empty".to_owned(),
        }),
        Some(_) => Err(DriverError::InvalidConfig {
            field: field.to_owned(),
            message: "must be a string".to_owned(),
        }),
    }
}

fn validate_http_url(field: &str, value: &str) -> DriverResult<()> {
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(invalid_url(field));
    };

    if !matches!(scheme, "http" | "https")
        || rest.is_empty()
        || rest.starts_with('/')
        || rest.starts_with('?')
        || rest.starts_with('#')
        || rest.contains(char::is_whitespace)
    {
        return Err(invalid_url(field));
    }

    Ok(())
}

fn invalid_url(field: &str) -> DriverError {
    DriverError::InvalidConfig {
        field: field.to_owned(),
        message: "must be a valid http or https URL".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_proto::InferenceSpec;
    use serde_json::json;

    use super::{ProviderConfig, ProviderDefaults, DEFAULT_NATIVE_ENDPOINT};

    const DEFAULTS: ProviderDefaults = ProviderDefaults {
        driver_name: "openai",
        provider: "openai",
        default_model: "gpt-4o",
        default_base_url: "https://api.openai.com/v1",
        credential_env: Some("OPENAI_API_KEY"),
    };

    fn spec(entries: Vec<(&str, serde_json::Value)>) -> InferenceSpec {
        InferenceSpec {
            config: entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn provider_config_uses_defaults_when_config_is_empty() {
        let config = ProviderConfig::from_spec(DEFAULTS, &spec(Vec::new())).unwrap();

        assert_eq!(config.provider, "openai");
        assert_eq!(config.model, "gpt-4o");
        assert_eq!(config.base_url, "https://api.openai.com/v1");
        assert_eq!(config.credential_env.as_deref(), Some("OPENAI_API_KEY"));
    }

    #[test]
    fn provider_config_accepts_custom_model_and_base_url() {
        let config = ProviderConfig::from_spec(
            DEFAULTS,
            &spec(vec![
                ("model", json!("gpt-4.1")),
                ("base_url", json!("https://azure.example.com/openai")),
            ]),
        )
        .unwrap();

        assert_eq!(config.model, "gpt-4.1");
        assert_eq!(config.base_url, "https://azure.example.com/openai");
    }

    #[test]
    fn provider_config_rejects_non_string_model() {
        let err = ProviderConfig::from_spec(DEFAULTS, &spec(vec![("model", json!(42))]))
            .expect_err("non-string model must be rejected");

        assert_eq!(
            err.to_string(),
            "invalid driver config field `model`: must be a string"
        );
    }

    #[test]
    fn provider_config_rejects_malformed_base_url() {
        let err = ProviderConfig::from_spec(
            DEFAULTS,
            &spec(vec![("base_url", json!("not-a-url"))]),
        )
        .expect_err("malformed URL must be rejected");

        assert_eq!(
            err.to_string(),
            "invalid driver config field `base_url`: must be a valid http or https URL"
        );
    }

    #[test]
    fn native_plan_uses_inference_local_endpoint() {
        let config = ProviderConfig::from_spec(DEFAULTS, &spec(Vec::new())).unwrap();
        let plan = config.native_routing_plan();

        assert_eq!(plan.provider, "openai");
        assert_eq!(plan.model, "gpt-4o");
        assert_eq!(plan.base_url, "https://api.openai.com/v1");
        assert_eq!(plan.endpoint, DEFAULT_NATIVE_ENDPOINT);
    }

    #[test]
    fn proxy_plan_uses_loopback_and_credential_name_only() {
        let config = ProviderConfig::from_spec(DEFAULTS, &spec(Vec::new())).unwrap();
        let plan = config.proxy_sidecar_plan();

        assert_eq!(plan.listen_url, "http://127.0.0.1:18080");
        assert_eq!(plan.upstream_base_url, "https://api.openai.com/v1");
        assert_eq!(plan.credential_env.as_deref(), Some("OPENAI_API_KEY"));
    }
}
