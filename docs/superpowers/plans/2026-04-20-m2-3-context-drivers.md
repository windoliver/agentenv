# M2-3 Built-In Context Drivers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement built-in `ContextDriver` crates for `none`, `mcp-generic`, and `filesystem`, plus the `agentenv-fs-mcp` stdio filesystem MCP server required by issue #9.

**Architecture:** Add small shared context helpers in `agentenv-core`, extend `driver-conformance` with in-process context-driver checks, and keep each driver crate thin around its protocol behavior. `context-mcp-generic` validates HTTP-like MCP endpoints with the existing SSRF helper and probes HTTP endpoints with a mockable MCP initialize client; `context-filesystem` returns a stdio endpoint for a shipped `agentenv-fs-mcp` binary whose tool engine enforces root containment and excludes.

**Tech Stack:** Rust 2021, `async-trait`, `serde_json`, `thiserror`, `reqwest` with `rustls`, `tokio` tests, Cargo workspace tests, JSON-RPC framing over stdio

---

## File Structure

### Shared Core And Conformance

- Modify: `crates/agentenv-core/src/lib.rs`
- Create: `crates/agentenv-core/src/context_common.rs`
- Modify: `tests/driver-conformance/src/lib.rs`

### Context Drivers

- Modify: `crates/drivers/context-none/Cargo.toml`
- Modify: `crates/drivers/context-none/src/lib.rs`
- Modify: `crates/drivers/context-none/README.md`
- Modify: `crates/drivers/context-mcp-generic/Cargo.toml`
- Modify: `crates/drivers/context-mcp-generic/src/lib.rs`
- Modify: `crates/drivers/context-mcp-generic/README.md`
- Modify: `crates/drivers/context-filesystem/Cargo.toml`
- Modify: `crates/drivers/context-filesystem/src/lib.rs`
- Create: `crates/drivers/context-filesystem/src/bin/agentenv-fs-mcp.rs`
- Create: `crates/drivers/context-filesystem/tests/fs_mcp_stdio.rs`
- Modify: `crates/drivers/context-filesystem/README.md`

### Docs And Verification

- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `blueprints/claude+filesystem+openshell.yaml`
- Modify: `blueprints/codex+mcp-generic+openshell.yaml`

### Verification Commands

- `cargo fmt`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Task 1: Add Shared Context Helpers

**Files:**
- Create: `crates/agentenv-core/src/context_common.rs`
- Modify: `crates/agentenv-core/src/lib.rs`
- Test: `crates/agentenv-core/src/context_common.rs`

- [ ] **Step 1: Write the failing context helper tests**

Create `crates/agentenv-core/src/context_common.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_proto::{
        Capabilities, ContextCapabilities, ContextSpec, HttpAccessLevel, McpEndpoint,
        McpTransport, NetworkTarget,
    };
    use serde_json::json;

    use super::{
        context_initialize, empty_credential_requirements, empty_network_rules, endpoint_host_rule,
        expand_tilde, local_context_capabilities, optional_bool, optional_string_list,
        remote_context_capabilities, required_object, required_string,
    };

    #[test]
    fn context_initialize_reports_context_driver_metadata() {
        let result = context_initialize("filesystem", local_context_capabilities());

        assert_eq!(result.driver.name, "filesystem");
        let Capabilities::Context(capabilities) = result.capabilities else {
            panic!("expected context capabilities");
        };
        assert_eq!(
            capabilities,
            ContextCapabilities {
                is_remote: false,
                is_shared: false,
                supports_zones: false,
                supports_snapshots: false,
            }
        );
    }

    #[test]
    fn remote_context_capabilities_are_remote_and_shared() {
        assert_eq!(
            remote_context_capabilities(),
            ContextCapabilities {
                is_remote: true,
                is_shared: true,
                supports_zones: false,
                supports_snapshots: false,
            }
        );
    }

    #[test]
    fn config_helpers_parse_expected_types() {
        let spec = ContextSpec {
            config: BTreeMap::from([
                ("mount".to_owned(), json!("/tmp/project")),
                ("readonly".to_owned(), json!(false)),
                ("exclude".to_owned(), json!([".git/", "target/"])),
                ("endpoint".to_owned(), json!({"url": "https://example.com/mcp"})),
            ]),
        };

        assert_eq!(required_string(&spec.config, "mount").unwrap(), "/tmp/project");
        assert_eq!(optional_bool(&spec.config, "readonly").unwrap(), Some(false));
        assert_eq!(
            optional_string_list(&spec.config, "exclude").unwrap(),
            vec![".git/".to_owned(), "target/".to_owned()]
        );
        assert_eq!(
            required_object(&spec.config, "endpoint")
                .unwrap()
                .get("url")
                .unwrap(),
            &json!("https://example.com/mcp")
        );
    }

    #[test]
    fn endpoint_host_rule_preserves_host_port_scheme_and_full_access() {
        let rule = endpoint_host_rule(&McpEndpoint {
            url: "https://mcp.example.com:8443/sse".to_owned(),
            transport: McpTransport::HttpSse,
            headers: BTreeMap::new(),
        })
        .unwrap();

        let NetworkTarget::Host {
            host,
            port,
            scheme,
            http_access,
        } = rule.target
        else {
            panic!("expected host rule");
        };

        assert_eq!(host, "mcp.example.com");
        assert_eq!(port, Some(8443));
        assert_eq!(scheme.as_deref(), Some("https"));
        assert_eq!(http_access, Some(HttpAccessLevel::Full));
    }

    #[test]
    fn empty_results_are_empty() {
        assert!(empty_network_rules().rules.is_empty());
        assert!(empty_credential_requirements().requirements.is_empty());
    }

    #[test]
    fn tilde_expansion_uses_home_when_available() {
        let expanded = expand_tilde("~/project", Some("/home/alice"));

        assert_eq!(expanded.to_string_lossy(), "/home/alice/project");
    }
}
```

- [ ] **Step 2: Run the core test and verify the expected failure**

Run: `cargo test -p agentenv-core context_common`

Expected: FAIL with unresolved imports for the helper functions and because `context_common` is not exported yet.

- [ ] **Step 3: Implement `context_common`**

Replace `crates/agentenv-core/src/context_common.rs` with:

```rust
use std::{collections::BTreeMap, path::PathBuf};

use agentenv_proto::{
    Capabilities, ContextCapabilities, CredentialRequirementsResult, DriverInfo, DriverKind,
    EmptyResult, HttpAccessLevel, InitializeResult, McpEndpoint, NetworkRule, NetworkTarget,
    PreflightResult, RequiredNetworkRulesResult, SCHEMA_VERSION,
};
use serde_json::{Map, Value};
use url::Url;

use crate::driver::{DriverError, DriverResult};

pub fn context_initialize(driver_name: &str, capabilities: ContextCapabilities) -> InitializeResult {
    InitializeResult {
        driver: DriverInfo {
            name: driver_name.to_owned(),
            kind: DriverKind::Context,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: SCHEMA_VERSION.to_owned(),
        },
        capabilities: Capabilities::Context(capabilities),
    }
}

pub fn local_context_capabilities() -> ContextCapabilities {
    ContextCapabilities {
        is_remote: false,
        is_shared: false,
        supports_zones: false,
        supports_snapshots: false,
    }
}

pub fn remote_context_capabilities() -> ContextCapabilities {
    ContextCapabilities {
        is_remote: true,
        is_shared: true,
        supports_zones: false,
        supports_snapshots: false,
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

pub fn empty_network_rules() -> RequiredNetworkRulesResult {
    RequiredNetworkRulesResult { rules: Vec::new() }
}

pub fn empty_credential_requirements() -> CredentialRequirementsResult {
    CredentialRequirementsResult {
        requirements: Vec::new(),
    }
}

pub fn required_string(config: &BTreeMap<String, Value>, field: &str) -> DriverResult<String> {
    match config.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(invalid_config(field, "must not be empty")),
        Some(_) => Err(invalid_config(field, "must be a string")),
        None => Err(invalid_config(field, "is required")),
    }
}

pub fn optional_string(config: &BTreeMap<String, Value>, field: &str) -> DriverResult<Option<String>> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(invalid_config(field, "must not be empty")),
        Some(_) => Err(invalid_config(field, "must be a string")),
    }
}

pub fn optional_bool(config: &BTreeMap<String, Value>, field: &str) -> DriverResult<Option<bool>> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_config(field, "must be a boolean")),
    }
}

pub fn optional_string_list(
    config: &BTreeMap<String, Value>,
    field: &str,
) -> DriverResult<Vec<String>> {
    match config.get(field) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                Value::String(item) if !item.trim().is_empty() => Ok(item.clone()),
                Value::String(_) => Err(invalid_config(
                    &format!("{field}[{index}]"),
                    "must not be empty",
                )),
                _ => Err(invalid_config(
                    &format!("{field}[{index}]"),
                    "must be a string",
                )),
            })
            .collect(),
        Some(_) => Err(invalid_config(field, "must be an array of strings")),
    }
}

pub fn required_object<'a>(
    config: &'a BTreeMap<String, Value>,
    field: &str,
) -> DriverResult<&'a Map<String, Value>> {
    match config.get(field) {
        Some(Value::Object(value)) => Ok(value),
        Some(_) => Err(invalid_config(field, "must be an object")),
        None => Err(invalid_config(field, "is required")),
    }
}

pub fn object_required_string(object: &Map<String, Value>, field: &str) -> DriverResult<String> {
    match object.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(invalid_config(field, "must not be empty")),
        Some(_) => Err(invalid_config(field, "must be a string")),
        None => Err(invalid_config(field, "is required")),
    }
}

pub fn endpoint_host_rule(endpoint: &McpEndpoint) -> DriverResult<NetworkRule> {
    let parsed = Url::parse(&endpoint.url).map_err(|_| invalid_config("endpoint.url", "must be a valid URL"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_config("endpoint.url", "must include a host"))?;

    Ok(NetworkRule {
        target: NetworkTarget::Host {
            host: host.to_owned(),
            port: parsed.port_or_known_default(),
            scheme: Some(parsed.scheme().to_owned()),
            http_access: Some(HttpAccessLevel::Full),
        },
    })
}

pub fn expand_tilde(path: &str, home: Option<&str>) -> PathBuf {
    if path == "~" {
        return home.map(PathBuf::from).unwrap_or_else(|| PathBuf::from(path));
    }

    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home {
            return PathBuf::from(home).join(rest);
        }
    }

    PathBuf::from(path)
}

pub fn invalid_config(field: &str, message: &str) -> DriverError {
    DriverError::InvalidConfig {
        field: field.to_owned(),
        message: message.to_owned(),
    }
}
```

Add the module export to `crates/agentenv-core/src/lib.rs`:

```rust
pub mod context_common;
```

- [ ] **Step 4: Rerun the core tests**

Run: `cargo test -p agentenv-core context_common`

Expected: PASS.

- [ ] **Step 5: Commit the shared helpers**

```bash
git add crates/agentenv-core/src/lib.rs crates/agentenv-core/src/context_common.rs
git commit -m "feat: add shared context driver helpers"
```

## Task 2: Add Context Driver Conformance Coverage

**Files:**
- Modify: `tests/driver-conformance/src/lib.rs`
- Test: `tests/driver-conformance/src/lib.rs`

- [ ] **Step 1: Write the failing context conformance test**

In `tests/driver-conformance/src/lib.rs`, update the test module imports to include `ContextDriver` and context protocol types, then add:

```rust
use agentenv_core::driver::ContextDriver;
use agentenv_proto::{
    ContextCapabilities, ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus,
    CredentialRequirementsParams, DriverKind, McpEndpoint, McpTransport,
    RequiredNetworkRulesResult,
};

#[derive(Default)]
struct FakeContextDriver {
    init_kind: Option<DriverKind>,
    init_capabilities: Option<Capabilities>,
    credential_name: Option<String>,
    preflight_ok: bool,
}

#[async_trait]
impl ContextDriver for FakeContextDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(InitializeResult {
            driver: DriverInfo {
                name: "fake-context".to_owned(),
                kind: self.init_kind.clone().unwrap_or(DriverKind::Context),
                version: "0.0.1".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: self.init_capabilities.clone().unwrap_or_else(|| {
                Capabilities::Context(ContextCapabilities {
                    is_remote: false,
                    is_shared: false,
                    supports_zones: false,
                    supports_snapshots: false,
                })
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(PreflightResult {
            ok: self.preflight_ok,
            issues: Vec::new(),
        })
    }

    async fn provision(&self, _spec: ContextSpec) -> DriverResult<ContextHandle> {
        Ok(ContextHandle {
            handle: "fake-context|1".to_owned(),
        })
    }

    async fn mcp_endpoint(&self, _params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        Ok(McpEndpoint {
            url: "agentenv-fake-context".to_owned(),
            transport: McpTransport::Stdio,
            headers: BTreeMap::new(),
        })
    }

    async fn required_network_rules(
        &self,
        _params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        Ok(RequiredNetworkRulesResult { rules: Vec::new() })
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(CredentialRequirementsResult {
            requirements: self
                .credential_name
                .clone()
                .map(|name| {
                    vec![CredentialRequirement {
                        name,
                        kind: CredentialKind::Token,
                        required: false,
                        description: "Fake context token.".to_owned(),
                        validator: None,
                    }]
                })
                .unwrap_or_default(),
        })
    }

    async fn status(&self, _params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        Ok(ContextStatus {
            healthy: true,
            detail: Some("ready".to_owned()),
        })
    }

    async fn teardown(&self, _params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        Ok(EmptyResult::default())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult::default())
    }
}

#[tokio::test]
async fn context_driver_contract_accepts_context_capabilities() {
    let mut driver = FakeContextDriver::default();

    assert_context_driver_contract(
        &mut driver,
        ContextSpec {
            config: BTreeMap::new(),
        },
    )
    .await
    .expect("fake context should satisfy the in-process conformance contract");
}

#[tokio::test]
async fn context_driver_contract_rejects_empty_credential_names() {
    let mut driver = FakeContextDriver {
        credential_name: Some(String::new()),
        ..FakeContextDriver::default()
    };

    let err = assert_context_driver_contract(
        &mut driver,
        ContextSpec {
            config: BTreeMap::new(),
        },
    )
    .await
    .expect_err("context conformance should reject empty credential names");

    assert!(err.to_string().contains("credential name"));
}
```

- [ ] **Step 2: Run the conformance tests and verify the expected failure**

Run: `cargo test -p driver-conformance context_driver_contract`

Expected: FAIL with `cannot find function assert_context_driver_contract`.

- [ ] **Step 3: Implement `assert_context_driver_contract`**

Add this public helper near the existing agent and sandbox helpers in `tests/driver-conformance/src/lib.rs`:

```rust
pub async fn assert_context_driver_contract<D: agentenv_core::driver::ContextDriver>(
    driver: &mut D,
    spec: agentenv_proto::ContextSpec,
) -> anyhow::Result<()> {
    let init = driver
        .initialize(agentenv_proto::InitializeParams {
            schema_version: agentenv_proto::SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1".to_owned(),
            workdir: "/tmp/agentenv".to_owned(),
            log_level: agentenv_proto::LogLevel::Info,
        })
        .await?;

    agentenv_core::driver::ensure_protocol_compatible(&init)?;
    anyhow::ensure!(
        init.driver.kind == DriverKind::Context,
        "initialize must report DriverKind::Context"
    );
    anyhow::ensure!(
        matches!(init.capabilities, Capabilities::Context(_)),
        "initialize must report Capabilities::Context"
    );

    let preflight = driver
        .preflight(agentenv_proto::PreflightParams::default())
        .await?;
    anyhow::ensure!(preflight.ok, "preflight must pass");

    let handle = driver.provision(spec).await?;
    anyhow::ensure!(
        !handle.handle.trim().is_empty(),
        "context handle must not be empty"
    );

    let request = agentenv_proto::ContextHandleRequest {
        handle: handle.handle,
    };
    let _endpoint = driver.mcp_endpoint(request.clone()).await?;
    let network_rules = driver.required_network_rules(request.clone()).await?;
    for rule in network_rules.rules {
        if let agentenv_proto::NetworkTarget::Host { host, .. } = rule.target {
            anyhow::ensure!(!host.trim().is_empty(), "network host must not be empty");
        }
    }

    let credentials = driver
        .credential_requirements(agentenv_proto::CredentialRequirementsParams::default())
        .await?;
    anyhow::ensure!(
        credentials
            .requirements
            .iter()
            .all(|requirement| !requirement.name.trim().is_empty()),
        "credential name must not be empty"
    );

    let status = driver.status(request.clone()).await?;
    anyhow::ensure!(status.healthy, "context status must be healthy");
    driver.teardown(request).await?;

    Ok(())
}
```

- [ ] **Step 4: Rerun the conformance tests**

Run: `cargo test -p driver-conformance context_driver_contract`

Expected: PASS.

- [ ] **Step 5: Commit context conformance coverage**

```bash
git add tests/driver-conformance/src/lib.rs
git commit -m "test: add context driver conformance checks"
```

## Task 3: Implement `context-none`

**Files:**
- Modify: `crates/drivers/context-none/Cargo.toml`
- Modify: `crates/drivers/context-none/src/lib.rs`
- Modify: `crates/drivers/context-none/README.md`
- Test: `crates/drivers/context-none/src/lib.rs`

- [ ] **Step 1: Add dependencies**

Update `crates/drivers/context-none/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true

[dev-dependencies]
tokio.workspace = true
driver-conformance = { path = "../../../tests/driver-conformance" }
```

- [ ] **Step 2: Write the failing `context-none` tests**

Replace the placeholder tests in `crates/drivers/context-none/src/lib.rs` with:

```rust
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_core::driver::ContextDriver;
    use agentenv_proto::{
        Capabilities, ContextHandleRequest, ContextSpec, CredentialRequirementsParams,
        InitializeParams, LogLevel, McpTransport, PreflightParams, SCHEMA_VERSION,
    };

    use super::NoneContextDriver;

    fn init_params() -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-alpha0".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        }
    }

    #[tokio::test]
    async fn none_driver_satisfies_context_conformance_contract() {
        let mut driver = NoneContextDriver;

        driver_conformance::assert_context_driver_contract(
            &mut driver,
            ContextSpec {
                config: BTreeMap::new(),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn initialize_returns_no_context_capabilities() {
        let mut driver = NoneContextDriver;
        let result = driver.initialize(init_params()).await.unwrap();

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
            .provision(ContextSpec {
                config: BTreeMap::new(),
            })
            .await
            .unwrap();

        let endpoint = driver
            .mcp_endpoint(ContextHandleRequest {
                handle: handle.handle.clone(),
            })
            .await
            .unwrap();
        let rules = driver
            .required_network_rules(ContextHandleRequest {
                handle: handle.handle.clone(),
            })
            .await
            .unwrap();
        let credentials = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert_eq!(endpoint.url, "");
        assert_eq!(endpoint.transport, McpTransport::Stdio);
        assert!(endpoint.headers.is_empty());
        assert!(rules.rules.is_empty());
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
            .unwrap_err();

        assert!(err.to_string().contains("invalid"));
    }

    #[tokio::test]
    async fn preflight_succeeds() {
        let driver = NoneContextDriver;
        let result = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(result.ok);
        assert!(result.issues.is_empty());
    }
}
```

- [ ] **Step 3: Run the `context-none` tests and verify the expected failure**

Run: `cargo test -p context-none`

Expected: FAIL with missing `NoneContextDriver`.

- [ ] **Step 4: Implement `NoneContextDriver`**

Replace `crates/drivers/context-none/src/lib.rs` with:

```rust
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
        Ok(context_initialize(DRIVER_NAME, local_context_capabilities()))
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
```

- [ ] **Step 5: Restore the tests and rerun**

Keep the test module from Step 2 at the bottom of `crates/drivers/context-none/src/lib.rs`.

Run: `cargo test -p context-none`

Expected: PASS.

- [ ] **Step 6: Update the README**

Replace `crates/drivers/context-none/README.md` with:

```markdown
# context-none

Built-in no-op context driver for agentenv.

This driver provisions no external context backend, returns no required network rules,
declares no credentials, and exposes an empty stdio MCP endpoint sentinel. Future
agent config assembly should skip empty endpoint URLs when rendering MCP config.
```

- [ ] **Step 7: Commit `context-none`**

```bash
git add crates/drivers/context-none/Cargo.toml \
        crates/drivers/context-none/src/lib.rs \
        crates/drivers/context-none/README.md
git commit -m "feat: implement context-none driver"
```

## Task 4: Implement `context-mcp-generic`

**Files:**
- Modify: `crates/drivers/context-mcp-generic/Cargo.toml`
- Modify: `crates/drivers/context-mcp-generic/src/lib.rs`
- Modify: `crates/drivers/context-mcp-generic/README.md`
- Test: `crates/drivers/context-mcp-generic/src/lib.rs`

- [ ] **Step 1: Add dependencies**

Update `crates/drivers/context-mcp-generic/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-mcp = { path = "../../agentenv-mcp" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true
reqwest.workspace = true
serde_json.workspace = true
url.workspace = true

[dev-dependencies]
driver-conformance = { path = "../../../tests/driver-conformance" }
tokio.workspace = true
```

- [ ] **Step 2: Write failing endpoint parsing and probe tests**

Replace `crates/drivers/context-mcp-generic/src/lib.rs` with the test module scaffold below. It intentionally references missing public items.

```rust
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use agentenv_core::{
        driver::ContextDriver,
        security::ssrf::StaticDnsResolver,
    };
    use agentenv_proto::{
        Capabilities, ContextHandleRequest, ContextSpec, CredentialRequirementsParams,
        InitializeParams, LogLevel, McpTransport, NetworkTarget, SCHEMA_VERSION,
    };
    use serde_json::{json, Value};

    use super::{
        endpoint_from_spec, probe_mcp_initialize, validate_endpoint_for_driver,
        GenericMcpContextDriver,
        ProbeExpectation,
    };

    fn init_params() -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-alpha0".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        }
    }

    fn spec(url: &str, transport: &str) -> ContextSpec {
        ContextSpec {
            config: BTreeMap::from([(
                "endpoint".to_owned(),
                json!({
                    "url": url,
                    "transport": transport,
                }),
            )]),
        }
    }

    #[test]
    fn endpoint_from_spec_accepts_http_sse() {
        let endpoint = endpoint_from_spec(&spec("https://mcp.example.com/sse", "http+sse"))
            .unwrap();

        assert_eq!(endpoint.url, "https://mcp.example.com/sse");
        assert_eq!(endpoint.transport, McpTransport::HttpSse);
        assert!(endpoint.headers.is_empty());
    }

    #[test]
    fn endpoint_from_spec_rejects_unsupported_transport() {
        let err = endpoint_from_spec(&spec("https://mcp.example.com/sse", "websocket"))
            .unwrap_err();

        assert!(err.to_string().contains("unsupported MCP transport"));
    }

    #[test]
    fn endpoint_validation_rejects_ssrf_blocked_targets() {
        let endpoint = endpoint_from_spec(&spec("https://metadata.example.test/sse", "http+sse"))
            .unwrap();
        let resolver =
            StaticDnsResolver::try_from_pairs([("metadata.example.test", ["169.254.169.254"])])
                .unwrap();

        let err = validate_endpoint_for_driver(&endpoint, &resolver).unwrap_err();

        assert!(err.to_string().contains("blocked"));
    }

    #[tokio::test]
    async fn initialize_probe_accepts_mock_mcp_response() {
        let server = spawn_probe_server(ProbeExpectation::ValidInitialize);

        probe_mcp_initialize(&server.url()).await.unwrap();
    }

    #[tokio::test]
    async fn initialize_probe_rejects_non_mcp_response() {
        let server = spawn_probe_server(ProbeExpectation::InvalidInitialize);

        let err = probe_mcp_initialize(&server.url()).await.unwrap_err();

        assert!(err.to_string().contains("MCP initialize"));
    }

    #[tokio::test]
    async fn driver_reports_remote_shared_capabilities() {
        let mut driver = GenericMcpContextDriver::new_for_tests_without_probe();
        let result = driver.initialize(init_params()).await.unwrap();

        assert_eq!(result.driver.name, "mcp-generic");
        let Capabilities::Context(capabilities) = result.capabilities else {
            panic!("expected context capabilities");
        };
        assert!(capabilities.is_remote);
        assert!(capabilities.is_shared);
        assert!(!capabilities.supports_zones);
        assert!(!capabilities.supports_snapshots);
    }

    #[tokio::test]
    async fn provision_stores_endpoint_and_network_rule_without_query_in_handle() {
        let driver = GenericMcpContextDriver::new_for_tests_without_probe();
        let handle = driver
            .provision(spec("https://mcp.example.com:8443/sse?state=abc", "http+sse"))
            .await
            .unwrap();

        assert!(!handle.handle.contains("state=abc"));

        let request = ContextHandleRequest {
            handle: handle.handle,
        };
        let endpoint = driver.mcp_endpoint(request.clone()).await.unwrap();
        let rules = driver.required_network_rules(request).await.unwrap();

        assert_eq!(endpoint.url, "https://mcp.example.com:8443/sse?state=abc");
        assert_eq!(rules.rules.len(), 1);
        let NetworkTarget::Host {
            host,
            port,
            scheme,
            ..
        } = &rules.rules[0].target
        else {
            panic!("expected host network rule");
        };
        assert_eq!(host, "mcp.example.com");
        assert_eq!(*port, Some(8443));
        assert_eq!(scheme.as_deref(), Some("https"));
    }

    #[tokio::test]
    async fn credential_requirements_declare_optional_mcp_token() {
        let driver = GenericMcpContextDriver::new_for_tests_without_probe();
        let requirements = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert_eq!(requirements.requirements.len(), 1);
        assert_eq!(requirements.requirements[0].name, "MCP_TOKEN");
        assert!(!requirements.requirements[0].required);
    }

    #[tokio::test]
    async fn generic_driver_satisfies_context_conformance_contract() {
        let mut driver = GenericMcpContextDriver::new_for_tests_without_probe();

        driver_conformance::assert_context_driver_contract(
            &mut driver,
            spec("https://mcp.example.com/sse", "http+sse"),
        )
        .await
        .unwrap();
    }

    struct ProbeServer {
        url: String,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl ProbeServer {
        fn url(&self) -> String {
            self.url.clone()
        }
    }

    impl Drop for ProbeServer {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                thread.join().expect("probe server thread should finish");
            }
        }
    }

    fn spawn_probe_server(expectation: ProbeExpectation) -> ProbeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let read = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..read]);
            assert!(request.contains("initialize"));

            let body: Value = match expectation {
                ProbeExpectation::ValidInitialize => json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "serverInfo": {"name": "mock", "version": "0.0.1"}
                    }
                }),
                ProbeExpectation::InvalidInitialize => json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": null
                }),
            };
            let body = serde_json::to_string(&body).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        ProbeServer {
            url,
            thread: Some(thread),
        }
    }
}
```

- [ ] **Step 3: Run the `context-mcp-generic` tests and verify the expected failure**

Run: `cargo test -p context-mcp-generic`

Expected: FAIL with missing `GenericMcpContextDriver`, `endpoint_from_spec`, and `probe_mcp_initialize`.

- [ ] **Step 4: Implement endpoint parsing, probing, and the driver**

Replace `crates/drivers/context-mcp-generic/src/lib.rs` with an implementation containing these items:

```rust
#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    sync::Mutex,
};

use agentenv_core::{
    context_common::{
        context_initialize, endpoint_host_rule, object_required_string, remote_context_capabilities,
        required_object, successful_preflight,
    },
    driver::{ContextDriver, DriverError, DriverResult},
    security::ssrf::{DnsResolver, SsrfOptions, SystemDnsResolver},
};
use agentenv_mcp::validate_mcp_endpoint;
use agentenv_proto::{
    ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus, CredentialKind,
    CredentialRequirement, CredentialRequirementsParams, CredentialRequirementsResult,
    EmptyResult, InitializeParams, InitializeResult, McpEndpoint, McpTransport, PreflightParams,
    PreflightResult, RequiredNetworkRulesResult, ShutdownParams,
};
use async_trait::async_trait;
use serde_json::json;

pub const CRATE_NAME: &str = "context-mcp-generic";
const DRIVER_NAME: &str = "mcp-generic";

#[derive(Debug, Clone, Copy)]
pub enum ProbeExpectation {
    ValidInitialize,
    InvalidInitialize,
}

#[derive(Debug, Clone)]
struct GenericMcpState {
    endpoint: McpEndpoint,
}

#[derive(Debug)]
struct GenericMcpStore {
    next_id: u64,
    states: BTreeMap<String, GenericMcpState>,
}

#[derive(Clone)]
struct ProbeSettings {
    enabled: bool,
    validate_ssrf: bool,
}

pub struct GenericMcpContextDriver {
    store: Mutex<GenericMcpStore>,
    probe: ProbeSettings,
}

impl Default for GenericMcpContextDriver {
    fn default() -> Self {
        Self {
            store: Mutex::new(GenericMcpStore {
                next_id: 1,
                states: BTreeMap::new(),
            }),
            probe: ProbeSettings {
                enabled: true,
                validate_ssrf: true,
            },
        }
    }
}

impl GenericMcpContextDriver {
    pub fn new_for_tests_without_probe() -> Self {
        Self {
            probe: ProbeSettings {
                enabled: false,
                validate_ssrf: false,
            },
            ..Self::default()
        }
    }
}

#[async_trait]
impl ContextDriver for GenericMcpContextDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(context_initialize(DRIVER_NAME, remote_context_capabilities()))
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(successful_preflight())
    }

    async fn provision(&self, spec: ContextSpec) -> DriverResult<ContextHandle> {
        let endpoint = endpoint_from_spec(&spec)?;
        if self.probe.validate_ssrf {
            validate_endpoint_for_driver(&endpoint, &SystemDnsResolver)?;
        }

        if self.probe.enabled && matches!(endpoint.transport, McpTransport::Http | McpTransport::HttpSse) {
            probe_mcp_initialize(&endpoint.url).await?;
        }

        let mut store = self.store.lock().expect("generic MCP store mutex");
        let handle = format!("{DRIVER_NAME}|{}", store.next_id);
        store.next_id += 1;
        store.states.insert(
            handle.clone(),
            GenericMcpState {
                endpoint: endpoint.clone(),
            },
        );

        Ok(ContextHandle { handle })
    }

    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        Ok(self.state(&params.handle)?.endpoint)
    }

    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        let endpoint = self.state(&params.handle)?.endpoint;
        Ok(RequiredNetworkRulesResult {
            rules: vec![endpoint_host_rule(&endpoint)?],
        })
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(CredentialRequirementsResult {
            requirements: vec![CredentialRequirement {
                name: "MCP_TOKEN".to_owned(),
                description: "Optional bearer token for generic MCP endpoints.".to_owned(),
                kind: CredentialKind::Token,
                required: false,
                validator: None,
            }],
        })
    }

    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        self.state(&params.handle)?;
        Ok(ContextStatus {
            healthy: true,
            detail: Some("generic MCP endpoint configured".to_owned()),
        })
    }

    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        let mut store = self.store.lock().expect("generic MCP store mutex");
        store.states.remove(&params.handle).ok_or_else(|| invalid_handle(&params.handle))?;
        Ok(EmptyResult::default())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult::default())
    }
}

impl GenericMcpContextDriver {
    fn state(&self, handle: &str) -> DriverResult<GenericMcpState> {
        let store = self.store.lock().expect("generic MCP store mutex");
        store
            .states
            .get(handle)
            .cloned()
            .ok_or_else(|| invalid_handle(handle))
    }
}

pub fn endpoint_from_spec(spec: &ContextSpec) -> DriverResult<McpEndpoint> {
    let endpoint = required_object(&spec.config, "endpoint")?;
    let url = object_required_string(endpoint, "url")?;
    let transport = match object_required_string(endpoint, "transport")?.as_str() {
        "http" => McpTransport::Http,
        "http+sse" => McpTransport::HttpSse,
        "ssh+http" => McpTransport::SshHttp,
        other => {
            return Err(DriverError::InvalidConfig {
                field: "endpoint.transport".to_owned(),
                message: format!("unsupported MCP transport `{other}`"),
            })
        }
    };

    Ok(McpEndpoint {
        url,
        transport,
        headers: BTreeMap::new(),
    })
}

pub fn validate_endpoint_for_driver(
    endpoint: &McpEndpoint,
    resolver: &dyn DnsResolver,
) -> DriverResult<()> {
    let options = SsrfOptions {
        allow_ssh_http: true,
        ..SsrfOptions::default()
    };
    validate_mcp_endpoint(endpoint, options, resolver)
        .map(|_| ())
        .map_err(|err| DriverError::InvalidConfig {
            field: "endpoint.url".to_owned(),
            message: err.to_string(),
        })
}

pub async fn probe_mcp_initialize(url: &str) -> DriverResult<()> {
    let response = reqwest::Client::new()
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "agentenv", "version": env!("CARGO_PKG_VERSION")}
            }
        }))
        .send()
        .await
        .map_err(|err| DriverError::PreflightFailed {
            message: format!("MCP initialize request failed: {err}"),
        })?;

    if !response.status().is_success() {
        return Err(DriverError::PreflightFailed {
            message: format!("MCP initialize returned HTTP {}", response.status()),
        });
    }

    let body: serde_json::Value = response.json().await.map_err(|err| DriverError::PreflightFailed {
        message: format!("MCP initialize response was not JSON: {err}"),
    })?;
    if body.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0")
        || body.get("id") != Some(&json!(1))
        || body.get("result").is_none()
        || body.get("result") == Some(&serde_json::Value::Null)
    {
        return Err(DriverError::PreflightFailed {
            message: "MCP initialize response did not contain a JSON-RPC result".to_owned(),
        });
    }

    Ok(())
}

fn invalid_handle(handle: &str) -> DriverError {
    DriverError::InvalidHandle {
        handle: handle.to_owned(),
        message: "unknown generic MCP context handle".to_owned(),
    }
}
```

- [ ] **Step 5: Restore the tests and rerun**

Keep the test module from Step 2 at the bottom of `crates/drivers/context-mcp-generic/src/lib.rs`.

Run: `cargo test -p context-mcp-generic`

Expected: PASS.

- [ ] **Step 6: Update the README**

Replace `crates/drivers/context-mcp-generic/README.md` with:

````markdown
# context-mcp-generic

Built-in context driver for existing MCP HTTP endpoints.

Supported config:

```yaml
context:
  driver: mcp-generic
  endpoint:
    url: https://mcp.example.com/sse
    transport: http+sse
  credentials:
    MCP_TOKEN:
      source: env
```

The driver validates outbound endpoint URLs through the shared SSRF validator,
declares an optional `MCP_TOKEN` credential name, returns one network allow rule for
the endpoint host, and never stores credential values.
````

- [ ] **Step 7: Commit `context-mcp-generic`**

```bash
git add crates/drivers/context-mcp-generic/Cargo.toml \
        crates/drivers/context-mcp-generic/src/lib.rs \
        crates/drivers/context-mcp-generic/README.md
git commit -m "feat: implement generic MCP context driver"
```

## Task 5: Implement `context-filesystem` Driver Surface

**Files:**
- Modify: `crates/drivers/context-filesystem/Cargo.toml`
- Modify: `crates/drivers/context-filesystem/src/lib.rs`
- Test: `crates/drivers/context-filesystem/src/lib.rs`

- [ ] **Step 1: Add dependencies**

Update `crates/drivers/context-filesystem/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tracing.workspace = true

[dev-dependencies]
driver-conformance = { path = "../../../tests/driver-conformance" }
tempfile = "=3.16.0"
tokio.workspace = true
```

- [ ] **Step 2: Write the failing filesystem driver tests**

Replace `crates/drivers/context-filesystem/src/lib.rs` with a test module scaffold that references missing driver items:

```rust
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use agentenv_core::driver::ContextDriver;
    use agentenv_proto::{
        Capabilities, ContextHandleRequest, ContextSpec, CredentialRequirementsParams,
        InitializeParams, LogLevel, McpTransport, SCHEMA_VERSION,
    };
    use serde_json::json;

    use super::{filesystem_config_from_spec, FilesystemContextDriver};

    fn init_params() -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-alpha0".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        }
    }

    fn spec(root: &std::path::Path) -> ContextSpec {
        ContextSpec {
            config: BTreeMap::from([
                ("mount".to_owned(), json!(root.to_string_lossy())),
                ("readonly".to_owned(), json!(false)),
                ("exclude".to_owned(), json!([".git/", "target/"])),
            ]),
        }
    }

    #[test]
    fn filesystem_config_parses_mount_readonly_and_excludes() {
        let tmp = tempfile::tempdir().unwrap();
        let config = filesystem_config_from_spec(&spec(tmp.path())).unwrap();

        assert_eq!(config.root, tmp.path().canonicalize().unwrap());
        assert!(!config.readonly);
        assert_eq!(config.exclude, vec![".git/".to_owned(), "target/".to_owned()]);
    }

    #[test]
    fn filesystem_config_rejects_missing_mount() {
        let err = filesystem_config_from_spec(&ContextSpec {
            config: BTreeMap::new(),
        })
        .unwrap_err();

        assert!(err.to_string().contains("mount"));
    }

    #[test]
    fn filesystem_config_rejects_file_mount() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        fs::write(&file, "not a directory").unwrap();

        let err = filesystem_config_from_spec(&spec(&file)).unwrap_err();

        assert!(err.to_string().contains("directory"));
    }

    #[tokio::test]
    async fn initialize_returns_local_capabilities() {
        let mut driver = FilesystemContextDriver::default();
        let result = driver.initialize(init_params()).await.unwrap();

        assert_eq!(result.driver.name, "filesystem");
        let Capabilities::Context(capabilities) = result.capabilities else {
            panic!("expected context capabilities");
        };
        assert!(!capabilities.is_remote);
        assert!(!capabilities.is_shared);
        assert!(!capabilities.supports_zones);
        assert!(!capabilities.supports_snapshots);
    }

    #[tokio::test]
    async fn provision_returns_stdio_endpoint_and_empty_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let driver = FilesystemContextDriver::default();
        let handle = driver.provision(spec(tmp.path())).await.unwrap();
        let request = ContextHandleRequest {
            handle: handle.handle.clone(),
        };

        let endpoint = driver.mcp_endpoint(request.clone()).await.unwrap();
        let rules = driver.required_network_rules(request.clone()).await.unwrap();
        let credentials = driver
            .credential_requirements(CredentialRequirementsParams::default())
            .await
            .unwrap();

        assert_eq!(endpoint.transport, McpTransport::Stdio);
        assert!(endpoint.url.contains("agentenv-fs-mcp"));
        assert!(endpoint.url.contains("--root"));
        assert!(endpoint.url.contains("--exclude"));
        assert!(rules.rules.is_empty());
        assert!(credentials.requirements.is_empty());
    }

    #[tokio::test]
    async fn status_reports_unhealthy_when_mount_disappears() {
        let tmp = tempfile::tempdir().unwrap();
        let driver = FilesystemContextDriver::default();
        let handle = driver.provision(spec(tmp.path())).await.unwrap();
        let mount = tmp.into_path();
        fs::remove_dir_all(&mount).unwrap();

        let status = driver
            .status(ContextHandleRequest {
                handle: handle.handle,
            })
            .await
            .unwrap();

        assert!(!status.healthy);
        assert!(status.detail.unwrap().contains("not a directory"));
    }

    #[tokio::test]
    async fn filesystem_driver_satisfies_context_conformance_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = FilesystemContextDriver::default();

        driver_conformance::assert_context_driver_contract(&mut driver, spec(tmp.path()))
            .await
            .unwrap();
    }
}
```

- [ ] **Step 3: Run the filesystem driver tests and verify the expected failure**

Run: `cargo test -p context-filesystem filesystem_config`

Expected: FAIL with missing `FilesystemContextDriver` and `filesystem_config_from_spec`.

- [ ] **Step 4: Implement filesystem config parsing and driver methods**

Add this driver surface to `crates/drivers/context-filesystem/src/lib.rs` above the test module:

```rust
#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::Mutex,
};

use agentenv_core::{
    context_common::{
        context_initialize, empty_credential_requirements, empty_network_rules, empty_result,
        expand_tilde, local_context_capabilities, optional_bool, optional_string_list,
        required_string, successful_preflight,
    },
    driver::{ContextDriver, DriverError, DriverResult},
};
use agentenv_proto::{
    ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus, CredentialRequirementsParams,
    CredentialRequirementsResult, EmptyResult, InitializeParams, InitializeResult, McpEndpoint,
    McpTransport, PreflightParams, PreflightResult, RequiredNetworkRulesResult, ShutdownParams,
};
use async_trait::async_trait;

pub const CRATE_NAME: &str = "context-filesystem";
const DRIVER_NAME: &str = "filesystem";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemConfig {
    pub root: PathBuf,
    pub readonly: bool,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone)]
struct FilesystemState {
    config: FilesystemConfig,
}

#[derive(Debug, Default)]
struct FilesystemStore {
    next_id: u64,
    states: BTreeMap<String, FilesystemState>,
}

#[derive(Debug, Default)]
pub struct FilesystemContextDriver {
    store: Mutex<FilesystemStore>,
}

#[async_trait]
impl ContextDriver for FilesystemContextDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(context_initialize(DRIVER_NAME, local_context_capabilities()))
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(successful_preflight())
    }

    async fn provision(&self, spec: ContextSpec) -> DriverResult<ContextHandle> {
        let config = filesystem_config_from_spec(&spec)?;
        let mut store = self.store.lock().expect("filesystem context store mutex");
        store.next_id += 1;
        let handle = format!("{DRIVER_NAME}|{}", store.next_id);
        store.states.insert(handle.clone(), FilesystemState { config });

        Ok(ContextHandle { handle })
    }

    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        let state = self.state(&params.handle)?;
        Ok(McpEndpoint {
            url: filesystem_endpoint_command(&state.config),
            transport: McpTransport::Stdio,
            headers: BTreeMap::new(),
        })
    }

    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        self.state(&params.handle)?;
        Ok(empty_network_rules())
    }

    async fn credential_requirements(
        &self,
        _params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(empty_credential_requirements())
    }

    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        let state = self.state(&params.handle)?;
        let healthy = state.config.root.is_dir();
        let detail = if healthy {
            Some(format!("mounted {}", state.config.root.display()))
        } else {
            Some(format!("{} is not a directory", state.config.root.display()))
        };

        Ok(ContextStatus { healthy, detail })
    }

    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        let mut store = self.store.lock().expect("filesystem context store mutex");
        store.states.remove(&params.handle).ok_or_else(|| invalid_handle(&params.handle))?;
        Ok(empty_result())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(empty_result())
    }
}

impl FilesystemContextDriver {
    fn state(&self, handle: &str) -> DriverResult<FilesystemState> {
        let store = self.store.lock().expect("filesystem context store mutex");
        store
            .states
            .get(handle)
            .cloned()
            .ok_or_else(|| invalid_handle(handle))
    }
}

pub fn filesystem_config_from_spec(spec: &ContextSpec) -> DriverResult<FilesystemConfig> {
    let mount = required_string(&spec.config, "mount")?;
    let home = std::env::var("HOME").ok();
    let expanded = expand_tilde(&mount, home.as_deref());
    let root = fs::canonicalize(&expanded).map_err(|err| DriverError::InvalidConfig {
        field: "mount".to_owned(),
        message: format!("failed to canonicalize `{}`: {err}", expanded.display()),
    })?;
    if !root.is_dir() {
        return Err(DriverError::InvalidConfig {
            field: "mount".to_owned(),
            message: format!("{} is not a directory", root.display()),
        });
    }

    Ok(FilesystemConfig {
        root,
        readonly: optional_bool(&spec.config, "readonly")?.unwrap_or(true),
        exclude: optional_string_list(&spec.config, "exclude")?,
    })
}

pub fn filesystem_endpoint_command(config: &FilesystemConfig) -> String {
    let mut parts = vec![
        "agentenv-fs-mcp".to_owned(),
        "--root".to_owned(),
        shell_quote(&config.root.to_string_lossy()),
    ];
    if config.readonly {
        parts.push("--readonly".to_owned());
    }
    for pattern in &config.exclude {
        parts.push("--exclude".to_owned());
        parts.push(shell_quote(pattern));
    }

    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':')) {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn invalid_handle(handle: &str) -> DriverError {
    DriverError::InvalidHandle {
        handle: handle.to_owned(),
        message: "unknown filesystem context handle".to_owned(),
    }
}
```

- [ ] **Step 5: Restore the tests and rerun**

Keep the test module from Step 2 at the bottom of `crates/drivers/context-filesystem/src/lib.rs`.

Run: `cargo test -p context-filesystem filesystem`

Expected: PASS.

- [ ] **Step 6: Commit the filesystem driver surface**

```bash
git add crates/drivers/context-filesystem/Cargo.toml \
        crates/drivers/context-filesystem/src/lib.rs
git commit -m "feat: implement filesystem context driver"
```

## Task 6: Implement Filesystem MCP Tool Engine

**Files:**
- Modify: `crates/drivers/context-filesystem/src/lib.rs`
- Test: `crates/drivers/context-filesystem/src/lib.rs`

- [ ] **Step 1: Write failing tool-engine tests**

Append this test module inside `crates/drivers/context-filesystem/src/lib.rs`:

```rust
#[cfg(test)]
mod mcp_tool_tests {
    use std::fs;

    use serde_json::json;

    use super::{FilesystemMcpServer, ToolCall};

    #[test]
    fn tools_list_advertises_expected_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();
        let tools = server.tools_list();

        let names: Vec<_> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool.get("name").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["fs_grep", "fs_list", "fs_read", "fs_search"]);
    }

    #[test]
    fn fs_read_reads_utf8_file_under_root() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("README.md"), "hello\n").unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();

        let result = server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "README.md"}),
            })
            .unwrap();

        assert_eq!(result, json!({"content": "hello\n"}));
    }

    #[test]
    fn fs_read_rejects_traversal_and_excluded_paths() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(tmp.path().join(".git/config"), "secret").unwrap();
        let server =
            FilesystemMcpServer::new(tmp.path().to_path_buf(), true, vec![".git/".to_owned()])
                .unwrap();

        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "../outside"}),
            })
            .unwrap_err()
            .to_string()
            .contains("outside root"));
        assert!(server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": ".git/config"}),
            })
            .unwrap_err()
            .to_string()
            .contains("excluded"));
    }

    #[test]
    fn fs_list_search_and_grep_skip_excluded_paths_and_sort_results() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::create_dir_all(tmp.path().join("target")).unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "pub fn alpha() {}\n").unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\nalpha();\n").unwrap();
        fs::write(tmp.path().join("target/cache.txt"), "alpha\n").unwrap();
        let server =
            FilesystemMcpServer::new(tmp.path().to_path_buf(), true, vec!["target/".to_owned()])
                .unwrap();

        let listed = server
            .call_tool(ToolCall {
                name: "fs_list".to_owned(),
                arguments: json!({"path": ".", "recursive": true}),
            })
            .unwrap();
        assert_eq!(listed, json!({"paths": ["src/lib.rs", "src/main.rs"]}));

        let searched = server
            .call_tool(ToolCall {
                name: "fs_search".to_owned(),
                arguments: json!({"query": "main"}),
            })
            .unwrap();
        assert_eq!(searched, json!({"paths": ["src/main.rs"]}));

        let grep = server
            .call_tool(ToolCall {
                name: "fs_grep".to_owned(),
                arguments: json!({"pattern": "alpha"}),
            })
            .unwrap();
        assert_eq!(
            grep,
            json!({
                "matches": [
                    {"path": "src/lib.rs", "line": 1, "text": "pub fn alpha() {}"},
                    {"path": "src/main.rs", "line": 2, "text": "alpha();"}
                ]
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escaping_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        symlink(outside.path().join("secret.txt"), tmp.path().join("link.txt")).unwrap();
        let server = FilesystemMcpServer::new(tmp.path().to_path_buf(), true, Vec::new()).unwrap();

        let err = server
            .call_tool(ToolCall {
                name: "fs_read".to_owned(),
                arguments: json!({"path": "link.txt"}),
            })
            .unwrap_err();

        assert!(err.to_string().contains("outside root"));
    }
}
```

- [ ] **Step 2: Run the tool tests and verify the expected failure**

Run: `cargo test -p context-filesystem mcp_tool_tests`

Expected: FAIL with missing `FilesystemMcpServer` and `ToolCall`.

- [ ] **Step 3: Implement tool engine types and handlers**

Add these public types and constants to `crates/drivers/context-filesystem/src/lib.rs`:

```rust
use serde_json::{json, Value};
use thiserror::Error;

const MAX_READ_BYTES: u64 = 1024 * 1024;
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Error)]
pub enum FsMcpError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("path `{0}` is outside root")]
    OutsideRoot(String),
    #[error("path `{0}` is excluded")]
    Excluded(String),
    #[error("path `{0}` is a directory")]
    Directory(String),
    #[error("file `{0}` is too large")]
    FileTooLarge(String),
    #[error("file `{0}` is not UTF-8 text")]
    Binary(String),
    #[error("unknown tool `{0}`")]
    UnknownTool(String),
    #[error("filesystem error for `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct FilesystemMcpServer {
    root: PathBuf,
    readonly: bool,
    exclude: Vec<String>,
}
```

Implement these methods in the same file:

```rust
impl FilesystemMcpServer {
    pub fn new(root: PathBuf, readonly: bool, exclude: Vec<String>) -> Result<Self, FsMcpError> {
        let root = fs::canonicalize(&root).map_err(|source| FsMcpError::Io {
            path: root.display().to_string(),
            source,
        })?;
        if !root.is_dir() {
            return Err(FsMcpError::InvalidParams(format!(
                "{} is not a directory",
                root.display()
            )));
        }

        Ok(Self {
            root,
            readonly,
            exclude,
        })
    }

    pub fn tools_list(&self) -> Value {
        let readonly = self.readonly;
        json!([
            {"name": "fs_grep", "description": "Search file contents under the mounted root", "readOnly": readonly},
            {"name": "fs_list", "description": "List files under the mounted root", "readOnly": readonly},
            {"name": "fs_read", "description": "Read a UTF-8 text file under the mounted root", "readOnly": readonly},
            {"name": "fs_search", "description": "Search filenames under the mounted root", "readOnly": readonly}
        ])
    }

    pub fn call_tool(&self, call: ToolCall) -> Result<Value, FsMcpError> {
        match call.name.as_str() {
            "fs_read" => self.fs_read(&call.arguments),
            "fs_list" => self.fs_list(&call.arguments),
            "fs_search" => self.fs_search(&call.arguments),
            "fs_grep" => self.fs_grep(&call.arguments),
            other => Err(FsMcpError::UnknownTool(other.to_owned())),
        }
    }

    fn fs_read(&self, args: &Value) -> Result<Value, FsMcpError> {
        let path = self.required_arg(args, "path")?;
        let resolved = self.resolve_path(path)?;
        let metadata = fs::metadata(&resolved).map_err(|source| FsMcpError::Io {
            path: path.to_owned(),
            source,
        })?;
        if metadata.is_dir() {
            return Err(FsMcpError::Directory(path.to_owned()));
        }
        if metadata.len() > MAX_READ_BYTES {
            return Err(FsMcpError::FileTooLarge(path.to_owned()));
        }
        let bytes = fs::read(&resolved).map_err(|source| FsMcpError::Io {
            path: path.to_owned(),
            source,
        })?;
        let content = String::from_utf8(bytes).map_err(|_| FsMcpError::Binary(path.to_owned()))?;
        Ok(json!({ "content": content }))
    }

    fn fs_list(&self, args: &Value) -> Result<Value, FsMcpError> {
        let path = self.optional_arg(args, "path").unwrap_or(".");
        let recursive = args.get("recursive").and_then(Value::as_bool).unwrap_or(false);
        let root = self.resolve_path(path)?;
        let mut paths = Vec::new();
        self.collect_paths(&root, recursive, &mut paths)?;
        paths.sort();
        Ok(json!({ "paths": paths }))
    }

    fn fs_search(&self, args: &Value) -> Result<Value, FsMcpError> {
        let query = self.required_arg(args, "query")?;
        let path = self.optional_arg(args, "path").unwrap_or(".");
        let limit = self.limit(args);
        let root = self.resolve_path(path)?;
        let mut paths = Vec::new();
        self.collect_paths(&root, true, &mut paths)?;
        paths.retain(|path| path.rsplit('/').next().unwrap_or(path).contains(query));
        paths.sort();
        paths.truncate(limit);
        Ok(json!({ "paths": paths }))
    }

    fn fs_grep(&self, args: &Value) -> Result<Value, FsMcpError> {
        let pattern = self.required_arg(args, "pattern")?;
        let path = self.optional_arg(args, "path").unwrap_or(".");
        let limit = self.limit(args);
        let root = self.resolve_path(path)?;
        let mut paths = Vec::new();
        self.collect_paths(&root, true, &mut paths)?;
        paths.sort();

        let mut matches = Vec::new();
        for relative in paths {
            let full = self.root.join(&relative);
            if fs::metadata(&full).map(|metadata| metadata.is_dir()).unwrap_or(true) {
                continue;
            }
            let Ok(content) = fs::read_to_string(&full) else {
                continue;
            };
            for (index, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    matches.push(json!({
                        "path": relative,
                        "line": index + 1,
                        "text": line,
                    }));
                    if matches.len() == limit {
                        return Ok(json!({ "matches": matches }));
                    }
                }
            }
        }

        Ok(json!({ "matches": matches }))
    }
}
```

Add the path helper methods:

```rust
impl FilesystemMcpServer {
    fn required_arg<'a>(&self, args: &'a Value, field: &str) -> Result<&'a str, FsMcpError> {
        self.optional_arg(args, field)
            .ok_or_else(|| FsMcpError::InvalidParams(format!("missing `{field}`")))
    }

    fn optional_arg<'a>(&self, args: &'a Value, field: &str) -> Option<&'a str> {
        args.get(field).and_then(Value::as_str).filter(|value| !value.trim().is_empty())
    }

    fn limit(&self, args: &Value) -> usize {
        args.get("limit")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_LIMIT)
            .clamp(1, MAX_LIMIT)
    }

    fn resolve_path(&self, path: &str) -> Result<PathBuf, FsMcpError> {
        let relative = std::path::Path::new(path);
        if relative.is_absolute() {
            return Err(FsMcpError::OutsideRoot(path.to_owned()));
        }
        if relative.components().any(|component| matches!(component, std::path::Component::ParentDir)) {
            return Err(FsMcpError::OutsideRoot(path.to_owned()));
        }
        if self.is_excluded(path) {
            return Err(FsMcpError::Excluded(path.to_owned()));
        }

        let joined = self.root.join(relative);
        let canonical = fs::canonicalize(&joined).map_err(|source| FsMcpError::Io {
            path: path.to_owned(),
            source,
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(FsMcpError::OutsideRoot(path.to_owned()));
        }
        Ok(canonical)
    }

    fn collect_paths(
        &self,
        root: &std::path::Path,
        recursive: bool,
        paths: &mut Vec<String>,
    ) -> Result<(), FsMcpError> {
        for entry in fs::read_dir(root).map_err(|source| FsMcpError::Io {
            path: root.display().to_string(),
            source,
        })? {
            let entry = entry.map_err(|source| FsMcpError::Io {
                path: root.display().to_string(),
                source,
            })?;
            let path = entry.path();
            let relative = path
                .strip_prefix(&self.root)
                .map_err(|_| FsMcpError::OutsideRoot(path.display().to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            if self.is_excluded(&relative) {
                continue;
            }
            let Ok(canonical) = fs::canonicalize(&path) else {
                continue;
            };
            if !canonical.starts_with(&self.root) {
                continue;
            }
            if fs::metadata(&canonical).map(|metadata| metadata.is_dir()).unwrap_or(false) {
                if recursive {
                    self.collect_paths(&canonical, recursive, paths)?;
                }
            } else {
                paths.push(relative);
            }
        }
        Ok(())
    }

    fn is_excluded(&self, relative: &str) -> bool {
        let normalized = relative.trim_start_matches("./");
        self.exclude.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix('/') {
                normalized == prefix || normalized.starts_with(&format!("{prefix}/"))
            } else {
                normalized == pattern
                    || normalized
                        .split('/')
                        .any(|segment| segment == pattern || segment.contains(pattern))
            }
        })
    }
}
```

- [ ] **Step 4: Rerun the tool tests**

Run: `cargo test -p context-filesystem mcp_tool_tests`

Expected: PASS.

- [ ] **Step 5: Commit the tool engine**

```bash
git add crates/drivers/context-filesystem/src/lib.rs
git commit -m "feat: add filesystem MCP tool engine"
```

## Task 7: Add `agentenv-fs-mcp` Stdio Binary

**Files:**
- Create: `crates/drivers/context-filesystem/src/bin/agentenv-fs-mcp.rs`
- Modify: `crates/drivers/context-filesystem/src/lib.rs`
- Test: `crates/drivers/context-filesystem/src/bin/agentenv-fs-mcp.rs`

- [ ] **Step 1: Write failing JSON-RPC smoke tests**

Create `crates/drivers/context-filesystem/src/bin/agentenv-fs-mcp.rs` with this test module first:

```rust
#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use serde_json::json;

    use super::{handle_request, read_framed_json, write_framed_json};

    #[test]
    fn framed_json_round_trips() {
        let mut bytes = Vec::new();
        write_framed_json(&mut bytes, &json!({"jsonrpc": "2.0", "id": 1})).unwrap();
        let mut reader = BufReader::new(Cursor::new(bytes));

        let value = read_framed_json(&mut reader).unwrap();

        assert_eq!(value, json!({"jsonrpc": "2.0", "id": 1}));
    }

    #[test]
    fn initialize_request_returns_server_info() {
        let tmp = tempfile::tempdir().unwrap();
        let response = handle_request(
            tmp.path().to_path_buf(),
            true,
            Vec::new(),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }),
        );

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["serverInfo"]["name"], "agentenv-fs-mcp");
    }

    #[test]
    fn tools_call_fs_read_returns_json_rpc_result() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("note.txt"), "hello").unwrap();
        let response = handle_request(
            tmp.path().to_path_buf(),
            true,
            Vec::new(),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "fs_read",
                    "arguments": {"path": "note.txt"}
                }
            }),
        );

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 2);
        assert_eq!(response["result"], json!({"content": "hello"}));
    }
}
```

- [ ] **Step 2: Run the binary tests and verify the expected failure**

Run: `cargo test -p context-filesystem --bin agentenv-fs-mcp`

Expected: FAIL with missing `main`, `handle_request`, and framing functions.

- [ ] **Step 3: Implement the stdio binary**

Replace `crates/drivers/context-filesystem/src/bin/agentenv-fs-mcp.rs` with:

```rust
use std::{
    env,
    io::{self, BufRead, BufReader, Read, Write},
    path::PathBuf,
};

use context_filesystem::{FilesystemMcpServer, ToolCall};
use serde_json::{json, Value};

fn main() {
    let args: Vec<String> = env::args().collect();
    let Ok(config) = parse_args(&args) else {
        eprintln!("usage: agentenv-fs-mcp --root <path> [--readonly] [--exclude <pattern>]...");
        std::process::exit(2);
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    loop {
        match read_framed_json(&mut reader) {
            Ok(request) => {
                let response = handle_request(
                    config.root.clone(),
                    config.readonly,
                    config.exclude.clone(),
                    request,
                );
                if write_framed_json(&mut writer, &response).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[derive(Debug, Clone)]
struct CliConfig {
    root: PathBuf,
    readonly: bool,
    exclude: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<CliConfig, String> {
    let mut root = None;
    let mut readonly = false;
    let mut exclude = Vec::new();
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--root" => {
                index += 1;
                root = args.get(index).map(PathBuf::from);
            }
            "--readonly" => readonly = true,
            "--exclude" => {
                index += 1;
                let value = args
                    .get(index)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| "--exclude requires a value".to_owned())?;
                exclude.push(value.clone());
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
        index += 1;
    }

    Ok(CliConfig {
        root: root.ok_or_else(|| "--root is required".to_owned())?,
        readonly,
        exclude,
    })
}

pub fn handle_request(root: PathBuf, readonly: bool, exclude: Vec<String>, request: Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");

    match method {
        "initialize" => success(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentenv-fs-mcp", "version": env!("CARGO_PKG_VERSION")}
            }),
        ),
        "tools/list" => match FilesystemMcpServer::new(root, readonly, exclude) {
            Ok(server) => success(id, json!({"tools": server.tools_list()})),
            Err(err) => error(id, -32603, err.to_string()),
        },
        "tools/call" => {
            let Some(params) = request.get("params") else {
                return error(id, -32602, "missing params".to_owned());
            };
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return error(id, -32602, "missing tool name".to_owned());
            };
            let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match FilesystemMcpServer::new(root, readonly, exclude)
                .and_then(|server| server.call_tool(ToolCall {
                    name: name.to_owned(),
                    arguments,
                }))
            {
                Ok(result) => success(id, result),
                Err(err) => error(id, -32602, err.to_string()),
            }
        }
        _ => error(id, -32601, format!("unknown method `{method}`")),
    }
}

fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

pub fn write_framed_json<W: Write>(writer: &mut W, message: &Value) -> io::Result<()> {
    let payload = serde_json::to_vec(message).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("serialize JSON: {err}"))
    })?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()
}

pub fn read_framed_json<R: BufRead>(reader: &mut R) -> io::Result<Value> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing JSON-RPC header"));
        }
        if line == "\r\n" {
            break;
        }
        if let Some(raw) = line.strip_prefix("Content-Length: ") {
            content_length = Some(raw.trim().parse::<usize>().map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid Content-Length: {err}"))
            })?);
        }
    }

    let length = content_length.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length header")
    })?;
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid JSON payload: {err}"))
    })
}
```

Keep the tests from Step 1 at the bottom of the file.

- [ ] **Step 4: Run the binary tests**

Run: `cargo test -p context-filesystem --bin agentenv-fs-mcp`

Expected: PASS.

- [ ] **Step 5: Add a process-level smoke test**

Create `crates/drivers/context-filesystem/tests/fs_mcp_stdio.rs`:

```rust
use std::io::{self, BufRead, BufReader, Read, Write};

use serde_json::{json, Value};

#[test]
fn process_smoke_reads_file_over_stdio() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("note.txt"), "hello").unwrap();
    let binary = env!("CARGO_BIN_EXE_agentenv-fs-mcp");
    let mut child = std::process::Command::new(binary)
        .arg("--root")
        .arg(tmp.path())
        .arg("--readonly")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "fs_read", "arguments": {"path": "note.txt"}}
    });
    write_framed_json(child.stdin.as_mut().unwrap(), &request).unwrap();
    drop(child.stdin.take());

    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let response = read_framed_json(&mut reader).unwrap();
    let status = child.wait().unwrap();

    assert!(status.success());
    assert_eq!(response["result"], serde_json::json!({"content": "hello"}));
}

fn write_framed_json<W: Write>(writer: &mut W, message: &Value) -> io::Result<()> {
    let payload = serde_json::to_vec(message).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("serialize JSON: {err}"))
    })?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn read_framed_json<R: BufRead>(reader: &mut R) -> io::Result<Value> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing JSON-RPC header"));
        }
        if line == "\r\n" {
            break;
        }
        if let Some(raw) = line.strip_prefix("Content-Length: ") {
            content_length = Some(raw.trim().parse::<usize>().map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid Content-Length: {err}"))
            })?);
        }
    }

    let length = content_length.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length header")
    })?;
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid JSON payload: {err}"))
    })
}
```

- [ ] **Step 6: Run the binary smoke test**

Run: `cargo test -p context-filesystem process_smoke_reads_file_over_stdio`

Expected: PASS.

- [ ] **Step 7: Commit the stdio binary**

```bash
git add crates/drivers/context-filesystem/src/bin/agentenv-fs-mcp.rs \
        crates/drivers/context-filesystem/tests/fs_mcp_stdio.rs
git commit -m "feat: add filesystem MCP stdio server"
```

## Task 8: Update Documentation And Run Workspace Verification

**Files:**
- Modify: `crates/drivers/context-filesystem/README.md`
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `blueprints/claude+filesystem+openshell.yaml`
- Modify: `blueprints/codex+mcp-generic+openshell.yaml`

- [ ] **Step 1: Update filesystem README**

Replace `crates/drivers/context-filesystem/README.md` with:

````markdown
# context-filesystem

Built-in filesystem context driver for agentenv.

Supported config:

```yaml
context:
  driver: filesystem
  mount: ~/projects/myapp
  readonly: false
  exclude:
    - ".git/"
    - "node_modules/"
```

The driver validates the mount, stores an opaque context handle, and exposes a stdio
MCP endpoint command for `agentenv-fs-mcp`. The server exposes read-only tools:
`fs_read`, `fs_grep`, `fs_list`, and `fs_search`.

Exclude patterns are intentionally simple. Values ending in `/` match path prefixes.
Other values match exact path segments or filename substrings.
````

- [ ] **Step 2: Update protocol docs**

In `docs/DRIVER_PROTOCOL.md`, add this paragraph under the `ContextDriver` table:

```markdown
For built-in context drivers, an empty `McpEndpoint.url` with `transport = stdio` is
the no-context sentinel and should be skipped when rendering agent MCP config.
Filesystem context endpoints encode the stdio command in `McpEndpoint.url` until a
future protocol version splits stdio command and arguments into separate fields.
```

- [ ] **Step 3: Update blueprint comments**

In `blueprints/claude+filesystem+openshell.yaml`, update the filesystem context block comment to mention that `exclude` can be added:

```yaml
context:
  driver: filesystem
  mount: ~/projects            # mounted read-write into the sandbox; exposed as MCP
  # exclude:
  #   - ".git/"
  #   - "node_modules/"
```

In `blueprints/codex+mcp-generic+openshell.yaml`, update the context comment to name the optional token:

```yaml
context:
  driver: mcp-generic
  endpoint:
    url: ${MCP_URL}
    transport: http+sse
  credentials:
    MCP_TOKEN:
      source: env
      required: true
```

- [ ] **Step 4: Run formatting**

Run: `cargo fmt`

Expected: command exits with status 0 and no output indicating errors.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Expected: PASS with no warnings.

- [ ] **Step 6: Run the full workspace test suite**

Run: `cargo test --workspace`

Expected: PASS.

- [ ] **Step 7: Commit docs and verification fixes**

If formatting or lint fixes changed code, include those files in this commit. Then run:

```bash
git add crates/drivers/context-filesystem/README.md \
        docs/DRIVER_PROTOCOL.md \
        blueprints/claude+filesystem+openshell.yaml \
        blueprints/codex+mcp-generic+openshell.yaml
git commit -m "docs: document built-in context drivers"
```

## Self-Review Checklist

- [ ] Issue #9 driver scope is covered by Tasks 3, 4, and 5.
- [ ] Filesystem MCP server scope is covered by Tasks 6 and 7.
- [ ] Shared conformance coverage is covered by Task 2.
- [ ] No schema-version bump is required because `ContextDriver` signatures remain unchanged.
- [ ] SSRF validation is preserved for `context-mcp-generic`.
- [ ] Credential values never enter `ContextSpec`, handles, or status strings.
- [ ] Verification commands are listed and expected outputs are explicit.
