# M2-4 Built-In Inference Drivers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the scaffold-compatible MVP for built-in inference drivers: passthrough, OpenAI, Anthropic, and Ollama.

**Architecture:** Keep the public protocol unchanged and implement the existing `InferenceDriver` trait. Add generic inference support helpers in `agentenv-core`, then keep each provider crate thin and provider-specific.

**Tech Stack:** Rust 1.95, `agentenv-core`, `agentenv-proto`, `async-trait`, `tokio` test runtime, `serde_json` config values.

---

## File Structure

- Modify `crates/agentenv-core/src/driver.rs`: add structured driver errors for invalid inference config and invalid handles.
- Create `crates/agentenv-core/src/inference.rs`: shared helper types and functions for routed inference providers.
- Modify `crates/agentenv-core/src/lib.rs`: export the new `inference` module.
- Modify `crates/drivers/inference-passthrough/Cargo.toml`: add dependencies needed for the driver implementation and tests.
- Replace `crates/drivers/inference-passthrough/src/lib.rs`: implement `PassthroughInferenceDriver`.
- Modify `crates/drivers/inference-openai/Cargo.toml`: add dependencies needed for the driver implementation and tests.
- Replace `crates/drivers/inference-openai/src/lib.rs`: implement `OpenAiInferenceDriver`.
- Modify `crates/drivers/inference-anthropic/Cargo.toml`: add dependencies needed for the driver implementation and tests.
- Replace `crates/drivers/inference-anthropic/src/lib.rs`: implement `AnthropicInferenceDriver`.
- Modify `crates/drivers/inference-ollama/Cargo.toml`: add dependencies needed for the driver implementation and tests.
- Replace `crates/drivers/inference-ollama/src/lib.rs`: implement `OllamaInferenceDriver`.

## Task 1: Add Structured Driver Errors

**Files:**
- Modify: `crates/agentenv-core/src/driver.rs`

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `#[cfg(test)] mod tests` in `crates/agentenv-core/src/driver.rs`:

```rust
#[test]
fn invalid_config_error_includes_field_and_message() {
    let err = DriverError::InvalidConfig {
        field: "base_url".to_owned(),
        message: "must be a valid http or https URL".to_owned(),
    };

    assert_eq!(
        err.to_string(),
        "invalid driver config field `base_url`: must be a valid http or https URL"
    );
}

#[test]
fn invalid_handle_error_includes_handle_and_message() {
    let err = DriverError::InvalidHandle {
        handle: "openai|not-a-url".to_owned(),
        message: "expected prefix `openai|`".to_owned(),
    };

    assert_eq!(
        err.to_string(),
        "invalid inference handle `openai|not-a-url`: expected prefix `openai|`"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core invalid_config_error_includes_field_and_message
cargo test -p agentenv-core invalid_handle_error_includes_handle_and_message
```

Expected: FAIL because `DriverError::InvalidConfig` and `DriverError::InvalidHandle` do not exist.

- [ ] **Step 3: Add the minimal error variants**

Update `DriverError` in `crates/agentenv-core/src/driver.rs`:

```rust
#[derive(Debug, Error)]
pub enum DriverError {
    #[error(transparent)]
    SchemaVersion(#[from] SchemaVersionError),
    #[error("driver is missing capability `{capability}`")]
    CapabilityMissing { capability: String },
    #[error("invalid driver config field `{field}`: {message}")]
    InvalidConfig { field: String, message: String },
    #[error("invalid inference handle `{handle}`: {message}")]
    InvalidHandle { handle: String, message: String },
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core invalid_config_error_includes_field_and_message
cargo test -p agentenv-core invalid_handle_error_includes_handle_and_message
```

Expected: PASS for both tests.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/agentenv-core/src/driver.rs
git commit -m "feat: add inference driver config errors"
```

## Task 2: Add Shared Inference Support Helpers

**Files:**
- Create: `crates/agentenv-core/src/inference.rs`
- Modify: `crates/agentenv-core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/agentenv-core/src/inference.rs` with only these tests first:

```rust
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
```

Add this module export to `crates/agentenv-core/src/lib.rs`:

```rust
pub mod inference;
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core inference::
```

Expected: FAIL because `ProviderDefaults`, `ProviderConfig`, and the plan helpers do not exist.

- [ ] **Step 3: Implement the helper module**

Replace `crates/agentenv-core/src/inference.rs` with this module, keeping the tests from Step 1 at the bottom:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core inference::
```

Expected: PASS for the `agentenv-core::inference` tests.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/agentenv-core/src/lib.rs crates/agentenv-core/src/inference.rs
git commit -m "feat: add inference driver support helpers"
```

## Task 3: Implement Passthrough Inference Driver

**Files:**
- Modify: `crates/drivers/inference-passthrough/Cargo.toml`
- Replace: `crates/drivers/inference-passthrough/src/lib.rs`

- [ ] **Step 1: Write the failing tests and dependencies**

Update `crates/drivers/inference-passthrough/Cargo.toml`:

```toml
[package]
name = "inference-passthrough"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
homepage.workspace = true
authors.workspace = true
readme = "README.md"
description = "Passthrough inference driver scaffold for agentenv"

[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true

[dev-dependencies]
tokio.workspace = true
```

Replace `crates/drivers/inference-passthrough/src/lib.rs` with tests first:

```rust
#![forbid(unsafe_code)]

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
        let mut driver = PassthroughInferenceDriver::default();
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
        let driver = PassthroughInferenceDriver::default();
        let result = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(result.ok);
        assert!(result.issues.is_empty());
    }

    #[tokio::test]
    async fn provision_is_noop_and_endpoint_is_empty() {
        let driver = PassthroughInferenceDriver::default();
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
        let driver = PassthroughInferenceDriver::default();
        let requirements = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert!(requirements.requirements.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p inference-passthrough
```

Expected: FAIL because `PassthroughInferenceDriver` does not exist.

- [ ] **Step 3: Implement the passthrough driver**

Replace `crates/drivers/inference-passthrough/src/lib.rs` with:

```rust
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
        let mut driver = PassthroughInferenceDriver::default();
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
        let driver = PassthroughInferenceDriver::default();
        let result = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(result.ok);
        assert!(result.issues.is_empty());
    }

    #[tokio::test]
    async fn provision_is_noop_and_endpoint_is_empty() {
        let driver = PassthroughInferenceDriver::default();
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
        let driver = PassthroughInferenceDriver::default();
        let requirements = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert!(requirements.requirements.is_empty());
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p inference-passthrough
```

Expected: PASS for all passthrough tests.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/drivers/inference-passthrough/Cargo.toml crates/drivers/inference-passthrough/src/lib.rs
git commit -m "feat: implement passthrough inference driver"
```

## Task 4: Implement OpenAI Routed Inference Driver

**Files:**
- Modify: `crates/drivers/inference-openai/Cargo.toml`
- Replace: `crates/drivers/inference-openai/src/lib.rs`

- [ ] **Step 1: Write the failing tests and dependencies**

Update `crates/drivers/inference-openai/Cargo.toml`:

```toml
[package]
name = "inference-openai"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
homepage.workspace = true
authors.workspace = true
readme = "README.md"
description = "OpenAI inference driver scaffold for agentenv"

[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true

[dev-dependencies]
serde_json.workspace = true
tokio.workspace = true
```

Write tests in `crates/drivers/inference-openai/src/lib.rs` that assert:

```rust
assert_eq!(result.driver.name, "openai");
assert!(capabilities.strips_caller_credentials);
assert!(capabilities.supports_model_switching);
assert_eq!(config.model, "gpt-4o");
assert_eq!(config.base_url, "https://api.openai.com/v1");
assert_eq!(requirements.requirements[0].name, "OPENAI_API_KEY");
assert_eq!(config.native_routing_plan().endpoint, "http://inference.local");
assert_eq!(config.proxy_sidecar_plan().listen_url, "http://127.0.0.1:18080");
assert_eq!(endpoint.url, "http://inference.local");
```

Also include a failing assertion for invalid config:

```rust
assert_eq!(
    provider_config(&InferenceSpec {
        config: [("base_url".to_owned(), serde_json::json!("not-a-url"))].into(),
    })
    .expect_err("malformed URL must fail")
    .to_string(),
    "invalid driver config field `base_url`: must be a valid http or https URL"
);
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p inference-openai
```

Expected: FAIL because `OpenAiInferenceDriver` and `provider_config` do not exist.

- [ ] **Step 3: Implement the OpenAI driver**

Replace `crates/drivers/inference-openai/src/lib.rs` with a thin wrapper around `agentenv_core::inference` using these exact provider defaults:

```rust
const DEFAULTS: ProviderDefaults = ProviderDefaults {
    driver_name: "openai",
    provider: "openai",
    default_model: "gpt-4o",
    default_base_url: "https://api.openai.com/v1",
    credential_env: Some("OPENAI_API_KEY"),
};
```

The crate must export:

```rust
pub struct OpenAiInferenceDriver;

pub fn provider_config(spec: &InferenceSpec) -> DriverResult<ProviderConfig> {
    ProviderConfig::from_spec(DEFAULTS, spec)
}

pub fn native_routing_plan(spec: &InferenceSpec) -> DriverResult<NativeRoutingPlan> {
    Ok(provider_config(spec)?.native_routing_plan())
}

pub fn proxy_sidecar_plan(spec: &InferenceSpec) -> DriverResult<ProxySidecarPlan> {
    Ok(provider_config(spec)?.proxy_sidecar_plan())
}
```

The `InferenceDriver` implementation must call:

```rust
routed_initialize(DEFAULTS)
successful_preflight()
ProviderConfig::from_spec(DEFAULTS, &spec)?
routed_handle(DEFAULTS)
routed_endpoint(DEFAULTS, &params.handle)
routed_credential_requirements(DEFAULTS)
empty_result()
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p inference-openai
```

Expected: PASS for all OpenAI tests.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/drivers/inference-openai/Cargo.toml crates/drivers/inference-openai/src/lib.rs
git commit -m "feat: implement openai inference driver"
```

## Task 5: Implement Anthropic Routed Inference Driver

**Files:**
- Modify: `crates/drivers/inference-anthropic/Cargo.toml`
- Replace: `crates/drivers/inference-anthropic/src/lib.rs`

- [ ] **Step 1: Write the failing tests and dependencies**

Update `crates/drivers/inference-anthropic/Cargo.toml`:

```toml
[package]
name = "inference-anthropic"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
homepage.workspace = true
authors.workspace = true
readme = "README.md"
description = "Anthropic inference driver scaffold for agentenv"

[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true

[dev-dependencies]
serde_json.workspace = true
tokio.workspace = true
```

Write tests in `crates/drivers/inference-anthropic/src/lib.rs` that assert:

```rust
assert_eq!(result.driver.name, "anthropic");
assert!(capabilities.strips_caller_credentials);
assert!(capabilities.supports_model_switching);
assert_eq!(config.model, "claude-3-5-sonnet-latest");
assert_eq!(config.base_url, "https://api.anthropic.com");
assert_eq!(requirements.requirements[0].name, "ANTHROPIC_API_KEY");
assert_eq!(config.native_routing_plan().endpoint, "http://inference.local");
assert_eq!(config.proxy_sidecar_plan().upstream_base_url, "https://api.anthropic.com");
assert_eq!(endpoint.url, "http://inference.local");
```

Also include a failing assertion for an empty model:

```rust
assert_eq!(
    provider_config(&InferenceSpec {
        config: [("model".to_owned(), serde_json::json!(""))].into(),
    })
    .expect_err("empty model must fail")
    .to_string(),
    "invalid driver config field `model`: must not be empty"
);
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p inference-anthropic
```

Expected: FAIL because `AnthropicInferenceDriver` and `provider_config` do not exist.

- [ ] **Step 3: Implement the Anthropic driver**

Replace `crates/drivers/inference-anthropic/src/lib.rs` with a thin wrapper around `agentenv_core::inference` using these exact provider defaults:

```rust
const DEFAULTS: ProviderDefaults = ProviderDefaults {
    driver_name: "anthropic",
    provider: "anthropic",
    default_model: "claude-3-5-sonnet-latest",
    default_base_url: "https://api.anthropic.com",
    credential_env: Some("ANTHROPIC_API_KEY"),
};
```

The crate must export:

```rust
pub struct AnthropicInferenceDriver;

pub fn provider_config(spec: &InferenceSpec) -> DriverResult<ProviderConfig> {
    ProviderConfig::from_spec(DEFAULTS, spec)
}

pub fn native_routing_plan(spec: &InferenceSpec) -> DriverResult<NativeRoutingPlan> {
    Ok(provider_config(spec)?.native_routing_plan())
}

pub fn proxy_sidecar_plan(spec: &InferenceSpec) -> DriverResult<ProxySidecarPlan> {
    Ok(provider_config(spec)?.proxy_sidecar_plan())
}
```

The `InferenceDriver` implementation must call:

```rust
routed_initialize(DEFAULTS)
successful_preflight()
ProviderConfig::from_spec(DEFAULTS, &spec)?
routed_handle(DEFAULTS)
routed_endpoint(DEFAULTS, &params.handle)
routed_credential_requirements(DEFAULTS)
empty_result()
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p inference-anthropic
```

Expected: PASS for all Anthropic tests.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/drivers/inference-anthropic/Cargo.toml crates/drivers/inference-anthropic/src/lib.rs
git commit -m "feat: implement anthropic inference driver"
```

## Task 6: Implement Ollama Routed Inference Driver

**Files:**
- Modify: `crates/drivers/inference-ollama/Cargo.toml`
- Replace: `crates/drivers/inference-ollama/src/lib.rs`

- [ ] **Step 1: Write the failing tests and dependencies**

Update `crates/drivers/inference-ollama/Cargo.toml`:

```toml
[package]
name = "inference-ollama"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
homepage.workspace = true
authors.workspace = true
readme = "README.md"
description = "Ollama inference driver scaffold for agentenv"

[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true

[dev-dependencies]
serde_json.workspace = true
tokio.workspace = true
```

Write tests in `crates/drivers/inference-ollama/src/lib.rs` that assert:

```rust
assert_eq!(result.driver.name, "ollama");
assert!(capabilities.strips_caller_credentials);
assert!(capabilities.supports_model_switching);
assert_eq!(config.model, "llama3.1");
assert_eq!(config.base_url, "http://127.0.0.1:11434");
assert!(config.credential_env.is_none());
assert!(requirements.requirements.is_empty());
assert_eq!(config.native_routing_plan().endpoint, "http://inference.local");
assert_eq!(config.proxy_sidecar_plan().upstream_base_url, "http://127.0.0.1:11434");
assert_eq!(endpoint.url, "http://inference.local");
```

Also include a failing assertion for a malformed handle:

```rust
assert_eq!(
    driver
        .endpoint_in_sandbox(agentenv_proto::InferenceHandleRequest {
            handle: "openai|http://inference.local".to_owned(),
        })
        .await
        .expect_err("wrong provider handle must fail")
        .to_string(),
    "invalid inference handle `openai|http://inference.local`: expected prefix `ollama|`"
);
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p inference-ollama
```

Expected: FAIL because `OllamaInferenceDriver` and `provider_config` do not exist.

- [ ] **Step 3: Implement the Ollama driver**

Replace `crates/drivers/inference-ollama/src/lib.rs` with a thin wrapper around `agentenv_core::inference` using these exact provider defaults:

```rust
const DEFAULTS: ProviderDefaults = ProviderDefaults {
    driver_name: "ollama",
    provider: "ollama",
    default_model: "llama3.1",
    default_base_url: "http://127.0.0.1:11434",
    credential_env: None,
};
```

The crate must export:

```rust
pub struct OllamaInferenceDriver;

pub fn provider_config(spec: &InferenceSpec) -> DriverResult<ProviderConfig> {
    ProviderConfig::from_spec(DEFAULTS, spec)
}

pub fn native_routing_plan(spec: &InferenceSpec) -> DriverResult<NativeRoutingPlan> {
    Ok(provider_config(spec)?.native_routing_plan())
}

pub fn proxy_sidecar_plan(spec: &InferenceSpec) -> DriverResult<ProxySidecarPlan> {
    Ok(provider_config(spec)?.proxy_sidecar_plan())
}
```

The `InferenceDriver` implementation must call:

```rust
routed_initialize(DEFAULTS)
successful_preflight()
ProviderConfig::from_spec(DEFAULTS, &spec)?
routed_handle(DEFAULTS)
routed_endpoint(DEFAULTS, &params.handle)
routed_credential_requirements(DEFAULTS)
empty_result()
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p inference-ollama
```

Expected: PASS for all Ollama tests.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/drivers/inference-ollama/Cargo.toml crates/drivers/inference-ollama/src/lib.rs
git commit -m "feat: implement ollama inference driver"
```

## Task 7: Final Workspace Verification

**Files:**
- Verify: entire workspace

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt
```

Expected: command exits 0.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace -- -D warnings
```

Expected: command exits 0 with no warnings.

- [ ] **Step 3: Run tests**

Run:

```bash
cargo test --workspace
```

Expected: command exits 0 with all workspace tests passing.

- [ ] **Step 4: Inspect changed files**

Run:

```bash
git status --short
git diff --stat
```

Expected: only the files listed in this plan are modified after the implementation tasks.

- [ ] **Step 5: Commit verification cleanup if formatting changed files**

If `cargo fmt` changed files after the task commits, run:

```bash
git add crates/agentenv-core/src/driver.rs crates/agentenv-core/src/inference.rs crates/agentenv-core/src/lib.rs crates/drivers/inference-passthrough crates/drivers/inference-openai crates/drivers/inference-anthropic crates/drivers/inference-ollama
git commit -m "style: format inference driver implementation"
```

Expected: either no formatting commit is needed, or the formatting commit contains only rustfmt changes.

## Spec Coverage Self-Review

- Passthrough no-op behavior is covered by Task 3.
- Routed provider metadata, defaults, credential requirements, and endpoint behavior are covered by Tasks 4, 5, and 6.
- Native routing and proxy sidecar planning helpers are covered by Task 2 plus provider crate tests in Tasks 4, 5, and 6.
- Structured config and handle errors are covered by Task 1 and exercised by Tasks 2, 4, 5, and 6.
- No live proxy, OpenShell command execution, or network call is included, matching the approved MVP scope.
