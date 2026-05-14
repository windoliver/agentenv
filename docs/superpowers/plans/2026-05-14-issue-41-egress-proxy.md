# Brokered Egress Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #41 in one PR: credentials for OpenAI, Anthropic, GitHub, generic MCP bearer, and generic OCI registries stay in the host process while sandboxes receive unauthenticated local proxy endpoints and dummy credential values.

**Architecture:** Add a core-owned egress proxy planning layer, a hidden `agentenv proxy run` host process, additive protocol capability `supports_host_egress_proxy` in schema v1.3, runtime credential classification, service-specific endpoint rewrites, live policy reload from an atomic JSON policy file, and redacted audit events for every broker decision.

**Tech Stack:** Rust workspace, `tokio`, `axum` for the proxy HTTP server, `reqwest` with existing rustls defaults, `serde_json` for proxy config and live policy, `agentenv-events` SQLite sink for audit, existing `agentenv-credstore` credential resolution.

---

## File Structure

```
crates/agentenv-proto/src/schema_version.rs
crates/agentenv-proto/src/types.rs
crates/agentenv-core/src/lib.rs
crates/agentenv-core/src/egress_proxy.rs
crates/agentenv-core/src/env.rs
crates/agentenv-core/src/runtime.rs
crates/agentenv/src/main.rs
crates/agentenv/src/proxy_cli.rs
crates/sandbox-openshell/src/lib.rs
crates/sandbox-microvm/src/lib.rs
crates/sandbox-remote-ssh/src/lib.rs
docs/DRIVER_PROTOCOL.md
docs/ARCHITECTURE.md
docs/ROADMAP.md
examples/blueprints/brokered-egress.yaml
```

---

## Task 1: Add Schema v1.3 Host Egress Proxy Capability

- [ ] Add failing proto tests for default compatibility and schema version.

Create tests in `crates/agentenv-proto/src/types.rs` near the existing serde compatibility tests:

```rust
#[test]
fn sandbox_capabilities_default_missing_host_egress_proxy_to_false() {
    let json = serde_json::json!({
        "supports_hot_reload_policy": true,
        "supports_filesystem_lockdown": false,
        "supports_syscall_filter": false,
        "supports_native_inference_routing": true,
        "supports_remote_host": false
    });

    let caps: SandboxCapabilities = serde_json::from_value(json).expect("capabilities deserialize");

    assert!(!caps.supports_host_egress_proxy);
}
```

Create a schema version test in `crates/agentenv-proto/src/schema_version.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::SCHEMA_VERSION;

    #[test]
    fn schema_version_is_1_3() {
        assert_eq!(SCHEMA_VERSION, "1.3");
    }
}
```

Run:

```bash
cargo test -p agentenv-proto sandbox_capabilities_default_missing_host_egress_proxy_to_false
cargo test -p agentenv-proto schema_version_is_1_3
```

Expected: the new tests fail because the field and version are not implemented.

- [ ] Implement the additive capability and version bump.

Update `crates/agentenv-proto/src/schema_version.rs`:

```rust
pub const SCHEMA_VERSION: &str = "1.3";
```

Update `SandboxCapabilities` in `crates/agentenv-proto/src/types.rs`:

```rust
#[serde(default)]
pub supports_host_egress_proxy: bool,
```

- [ ] Update protocol docs.

In `docs/DRIVER_PROTOCOL.md`, bump the documented protocol version to `1.3` and add this row to the sandbox capabilities table:

```markdown
| `supports_host_egress_proxy` | bool | Driver can reach a host-owned local proxy endpoint from the sandbox and accepts proxy endpoint metadata/env rewrites. |
```

Document the fallback rule:

```markdown
If `supports_host_egress_proxy` is false, core must not route credentials through the host egress broker for that sandbox. Core either uses legacy env injection for explicitly permitted credentials or fails closed when policy requires brokered egress.
```

- [ ] Verify Task 1.

Run:

```bash
cargo test -p agentenv-proto
```

Expected: all proto tests pass.

Commit:

```bash
git add crates/agentenv-proto/src/schema_version.rs crates/agentenv-proto/src/types.rs docs/DRIVER_PROTOCOL.md
git commit -m "feat(proto): declare host egress proxy capability"
```

---

## Task 2: Add Core Egress Proxy Planning Types

- [ ] Add failing tests for credential classification and route construction.

Create `crates/agentenv-core/src/egress_proxy.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use agentenv_proto::types::{CredentialRequirement, NetworkPolicy};

    fn required(name: &str) -> CredentialRequirement {
        CredentialRequirement {
            name: name.to_owned(),
            required: true,
            description: None,
            source_hint: None,
        }
    }

    #[test]
    fn plan_brokers_provider_credentials_and_leaves_unmatched_env_vars() {
        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31001".parse().unwrap(),
            credential_requirements: vec![required("OPENAI_API_KEY"), required("ANTHROPIC_API_KEY"), required("CUSTOM_TOKEN")],
            network_policy: NetworkPolicy::default(),
            context_mcp: None,
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        assert_eq!(plan.credential_disposition("OPENAI_API_KEY"), Some(CredentialDisposition::Brokered));
        assert_eq!(plan.credential_disposition("ANTHROPIC_API_KEY"), Some(CredentialDisposition::Brokered));
        assert_eq!(plan.credential_disposition("CUSTOM_TOKEN"), Some(CredentialDisposition::SandboxEnv));
        assert!(plan.routes.iter().any(|route| route.service == BrokerService::OpenAi));
        assert!(plan.routes.iter().any(|route| route.service == BrokerService::Anthropic));
    }

    #[test]
    fn plan_rewrites_context_mcp_endpoint_to_proxy_route() {
        let endpoint = McpProxySource {
            route_id: "primary".to_owned(),
            upstream_url: "https://mcp.example.test/rpc".parse().unwrap(),
            token_credential_name: Some("MCP_TOKEN".to_owned()),
        };

        let plan = build_egress_proxy_plan(EgressProxyPlanInput {
            env_name: "demo".to_owned(),
            proxy_base_url: "http://127.0.0.1:31002".parse().unwrap(),
            credential_requirements: vec![required("MCP_TOKEN")],
            network_policy: NetworkPolicy::default(),
            context_mcp: Some(endpoint),
            inference_endpoint: None,
            explicit_routes: ExplicitEgressRoutes::default(),
        })
        .expect("plan builds");

        assert_eq!(plan.credential_disposition("MCP_TOKEN"), Some(CredentialDisposition::Brokered));
        assert_eq!(plan.context_mcp_url().unwrap().as_str(), "http://127.0.0.1:31002/v1/mcp/primary");
    }
}
```

Run:

```bash
cargo test -p agentenv-core egress_proxy::
```

Expected: compile fails because the module and types do not exist.

- [ ] Implement `egress_proxy` module exports.

Update `crates/agentenv-core/src/lib.rs`:

```rust
pub mod egress_proxy;
```

Implement the planning model in `crates/agentenv-core/src/egress_proxy.rs`:

```rust
use std::collections::{BTreeMap, BTreeSet};

use agentenv_proto::types::{CredentialRequirement, NetworkPolicy};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialDisposition {
    Brokered,
    SandboxEnv,
    UnusedOptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrokerService {
    OpenAi,
    Anthropic,
    GitHub,
    Mcp { route_id: String },
    Oci { registry: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRoute {
    pub id: String,
    pub service: BrokerService,
    pub upstream_base_url: Url,
    pub credential_name: String,
    pub request_path_prefix: String,
    pub allowed_hosts: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitEgressRoutes {
    pub github: bool,
    pub oci_registries: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProxySource {
    pub route_id: String,
    pub upstream_url: Url,
    pub token_credential_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EgressProxyPlanInput {
    pub env_name: String,
    pub proxy_base_url: Url,
    pub credential_requirements: Vec<CredentialRequirement>,
    pub network_policy: NetworkPolicy,
    pub context_mcp: Option<McpProxySource>,
    pub inference_endpoint: Option<Url>,
    pub explicit_routes: ExplicitEgressRoutes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressProxyPlan {
    pub env_name: String,
    pub listen_url: Url,
    pub sandbox_env: BTreeMap<String, String>,
    pub routes: Vec<BrokerRoute>,
    pub credential_dispositions: BTreeMap<String, CredentialDisposition>,
    pub rewritten_context_mcp_url: Option<Url>,
    pub redacted_policy_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Error)]
pub enum EgressProxyPlanError {
    #[error("invalid proxy URL: {0}")]
    InvalidProxyUrl(String),
}
```

Add methods:

```rust
impl EgressProxyPlan {
    pub fn credential_disposition(&self, name: &str) -> Option<CredentialDisposition> {
        self.credential_dispositions.get(name).copied()
    }

    pub fn context_mcp_url(&self) -> Option<&Url> {
        self.rewritten_context_mcp_url.as_ref()
    }
}
```

Implement route construction:

```rust
pub fn build_egress_proxy_plan(input: EgressProxyPlanInput) -> Result<EgressProxyPlan, EgressProxyPlanError> {
    let mut routes = Vec::new();
    let mut sandbox_env = BTreeMap::new();
    let mut brokered_names = BTreeSet::new();

    if input.credential_requirements.iter().any(|req| req.name == "OPENAI_API_KEY") {
        brokered_names.insert("OPENAI_API_KEY".to_owned());
        sandbox_env.insert("OPENAI_BASE_URL".to_owned(), format!("{}/v1/openai", input.proxy_base_url.as_str().trim_end_matches('/')));
        sandbox_env.insert("OPENAI_API_KEY".to_owned(), "agentenv-brokered".to_owned());
        routes.push(provider_route("openai", BrokerService::OpenAi, "https://api.openai.com", "OPENAI_API_KEY")?);
    }

    if input.credential_requirements.iter().any(|req| req.name == "ANTHROPIC_API_KEY") {
        brokered_names.insert("ANTHROPIC_API_KEY".to_owned());
        sandbox_env.insert("ANTHROPIC_BASE_URL".to_owned(), format!("{}/v1/anthropic", input.proxy_base_url.as_str().trim_end_matches('/')));
        sandbox_env.insert("ANTHROPIC_API_KEY".to_owned(), "agentenv-brokered".to_owned());
        routes.push(provider_route("anthropic", BrokerService::Anthropic, "https://api.anthropic.com", "ANTHROPIC_API_KEY")?);
    }

    if input.explicit_routes.github {
        brokered_names.insert("GITHUB_TOKEN".to_owned());
        sandbox_env.insert("GITHUB_API_URL".to_owned(), format!("{}/v1/github/api", input.proxy_base_url.as_str().trim_end_matches('/')));
        routes.push(provider_route("github", BrokerService::GitHub, "https://api.github.com", "GITHUB_TOKEN")?);
    }

    let rewritten_context_mcp_url = if let Some(source) = input.context_mcp {
        let credential_name = source.token_credential_name.unwrap_or_else(|| "MCP_TOKEN".to_owned());
        brokered_names.insert(credential_name.clone());
        let route_id = source.route_id;
        routes.push(BrokerRoute {
            id: format!("mcp.{route_id}"),
            service: BrokerService::Mcp { route_id: route_id.clone() },
            upstream_base_url: source.upstream_url,
            credential_name,
            request_path_prefix: format!("/v1/mcp/{route_id}"),
            allowed_hosts: BTreeSet::new(),
        });
        Some(format!("{}/v1/mcp/{route_id}", input.proxy_base_url.as_str().trim_end_matches('/')).parse().map_err(|err| EgressProxyPlanError::InvalidProxyUrl(err.to_string()))?)
    } else {
        None
    };

    for registry in input.explicit_routes.oci_registries {
        let credential_name = format!("oci.{registry}");
        brokered_names.insert(credential_name.clone());
        routes.push(provider_route(&format!("oci.{registry}"), BrokerService::Oci { registry: registry.clone() }, &format!("https://{registry}"), &credential_name)?);
    }

    let credential_dispositions = input
        .credential_requirements
        .into_iter()
        .map(|req| {
            let disposition = if brokered_names.contains(&req.name) {
                CredentialDisposition::Brokered
            } else if req.required {
                CredentialDisposition::SandboxEnv
            } else {
                CredentialDisposition::UnusedOptional
            };
            (req.name, disposition)
        })
        .collect();

    Ok(EgressProxyPlan {
        env_name: input.env_name,
        listen_url: input.proxy_base_url,
        sandbox_env,
        routes,
        credential_dispositions,
        rewritten_context_mcp_url,
        redacted_policy_path: None,
    })
}
```

Add helper:

```rust
fn provider_route(id: &str, service: BrokerService, upstream: &str, credential_name: &str) -> Result<BrokerRoute, EgressProxyPlanError> {
    let upstream_base_url: Url = upstream.parse().map_err(|err| EgressProxyPlanError::InvalidProxyUrl(err.to_string()))?;
    let allowed_hosts = upstream_base_url.host_str().into_iter().map(str::to_owned).collect();

    Ok(BrokerRoute {
        id: id.to_owned(),
        service,
        upstream_base_url,
        credential_name: credential_name.to_owned(),
        request_path_prefix: format!("/v1/{id}"),
        allowed_hosts,
    })
}
```

- [ ] Verify Task 2.

Run:

```bash
cargo test -p agentenv-core egress_proxy::
cargo fmt
```

Expected: egress proxy unit tests pass and formatting changes only touched intended files.

Commit:

```bash
git add crates/agentenv-core/src/lib.rs crates/agentenv-core/src/egress_proxy.rs
git commit -m "feat(core): plan brokered egress routes"
```

---

## Task 3: Persist Egress Proxy State

- [ ] Add failing env state serialization tests.

Add tests near `EnvStateFile` tests in `crates/agentenv-core/src/env.rs`:

```rust
#[test]
fn env_state_serializes_egress_proxy_state_when_present() {
    let mut state = minimal_env_state("demo");
    state.egress_proxy = Some(EgressProxyState {
        pid: Some(1234),
        listen_url: "http://127.0.0.1:31001".parse().unwrap(),
        config_path: "envs/demo/egress-proxy/config.json".into(),
        policy_path: "envs/demo/egress-proxy/policy.json".into(),
        routes: vec!["openai".to_owned(), "anthropic".to_owned()],
    });

    let json = serde_json::to_value(&state).expect("state serializes");

    assert_eq!(json["egress_proxy"]["pid"], 1234);
    assert_eq!(json["egress_proxy"]["routes"], serde_json::json!(["openai", "anthropic"]));
}

#[test]
fn env_state_defaults_missing_egress_proxy_to_none() {
    let json = serde_json::json!({
        "version": "1",
        "name": "demo",
        "phase": "created",
        "created_at": "2026-05-14T00:00:00Z",
        "updated_at": "2026-05-14T00:00:00Z",
        "drivers": {},
        "handles": {},
        "endpoints": {},
        "credential_names": [],
        "health": {},
        "first_enter_hint_shown": false
    });

    let state: EnvStateFile = serde_json::from_value(json).expect("state deserializes");

    assert!(state.egress_proxy.is_none());
}
```

Run:

```bash
cargo test -p agentenv-core env_state_serializes_egress_proxy_state_when_present
cargo test -p agentenv-core env_state_defaults_missing_egress_proxy_to_none
```

Expected: compile fails because `egress_proxy` and `EgressProxyState` do not exist.

- [ ] Add persisted state structs.

Update `crates/agentenv-core/src/env.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressProxyState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub listen_url: url::Url,
    pub config_path: PathBuf,
    pub policy_path: PathBuf,
    pub routes: Vec<String>,
}
```

Add to `EnvStateFile`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub egress_proxy: Option<EgressProxyState>,
```

Update every `EnvStateFile` literal in tests and runtime construction with:

```rust
egress_proxy: None,
```

- [ ] Verify Task 3.

Run:

```bash
cargo test -p agentenv-core env_state_
cargo fmt
```

Expected: env state tests pass.

Commit:

```bash
git add crates/agentenv-core/src/env.rs
git commit -m "feat(core): persist egress proxy state"
```

---

## Task 4: Classify Credentials During Runtime Create

- [ ] Add failing runtime tests for sandbox env redaction.

Add a runtime create test in `crates/agentenv-core/src/runtime.rs` near credential injection tests:

```rust
#[tokio::test]
async fn create_env_with_brokered_openai_omits_real_secret_from_sandbox_env() {
    let fixture = RuntimeFixture::new().await;
    fixture.credentials.insert("OPENAI_API_KEY", "sk-real-secret");
    fixture.agent_driver.add_credential_requirement("OPENAI_API_KEY");
    fixture.sandbox_driver.set_capabilities(|caps| {
        caps.supports_host_egress_proxy = true;
    });

    create_env_with_input(fixture.input("demo")).await.expect("create succeeds");

    let spec = fixture.sandbox_driver.last_create_spec().expect("sandbox create spec");
    assert_eq!(spec.env.get("OPENAI_API_KEY").map(String::as_str), Some("agentenv-brokered"));
    assert_ne!(spec.env.get("OPENAI_API_KEY").map(String::as_str), Some("sk-real-secret"));
    assert!(spec.env.get("OPENAI_BASE_URL").unwrap().contains("/v1/openai"));
}
```

Add a fallback test:

```rust
#[tokio::test]
async fn create_env_fails_closed_when_proxy_required_but_sandbox_lacks_capability() {
    let fixture = RuntimeFixture::new().await;
    fixture.credentials.insert("OPENAI_API_KEY", "sk-real-secret");
    fixture.agent_driver.add_credential_requirement("OPENAI_API_KEY");
    fixture.sandbox_driver.set_capabilities(|caps| {
        caps.supports_host_egress_proxy = false;
    });
    fixture.policy.require_brokered_egress(true);

    let err = create_env_with_input(fixture.input("demo")).await.expect_err("create fails closed");

    assert!(err.to_string().contains("host egress proxy"));
}
```

Run:

```bash
cargo test -p agentenv-core create_env_with_brokered_openai_omits_real_secret_from_sandbox_env
cargo test -p agentenv-core create_env_fails_closed_when_proxy_required_but_sandbox_lacks_capability
```

Expected: compile fails because runtime does not classify credentials through `EgressProxyPlan`.

- [ ] Implement runtime classification.

Replace the direct credential injection loop in `create_env_with_input` with a two-phase plan:

```rust
let egress_proxy_plan = if sandbox_caps.supports_host_egress_proxy {
    Some(build_egress_proxy_plan(EgressProxyPlanInput {
        env_name: input.name.clone(),
        proxy_base_url: allocate_proxy_base_url(&input.name)?,
        credential_requirements: requirements.clone(),
        network_policy: resolved_policy.clone(),
        context_mcp: context_endpoint.as_ref().and_then(McpProxySource::from_endpoint),
        inference_endpoint: inference_endpoint.as_ref().and_then(|endpoint| endpoint.url.parse().ok()),
        explicit_routes: explicit_egress_routes_from_blueprint(&input.blueprint),
    })?)
} else {
    None
};

let mut env = BTreeMap::new();
let mut credential_names = Vec::new();
for requirement in requirements {
    credential_names.push(requirement.name.clone());
    match egress_proxy_plan
        .as_ref()
        .and_then(|plan| plan.credential_disposition(&requirement.name))
        .unwrap_or(CredentialDisposition::SandboxEnv)
    {
        CredentialDisposition::Brokered => {
            emit_runtime_event(
                &event_emitter,
                ActivityKind::CredentialInjected,
                &input.name,
                serde_json::json!({
                    "name": requirement.name,
                    "delivery": "egress_proxy"
                }),
            )
            .await;
        }
        CredentialDisposition::UnusedOptional => {}
        CredentialDisposition::SandboxEnv => {
            if let Some(value) = credentials.resolve(&requirement)? {
                emit_runtime_event(
                    &event_emitter,
                    ActivityKind::CredentialInjected,
                    &input.name,
                    serde_json::json!({
                        "name": requirement.name,
                        "delivery": "sandbox_env"
                    }),
                )
                .await;
                env.insert(requirement.name, value.expose_secret().to_owned());
            } else if requirement.required {
                return Err(RuntimeError::MissingCredential { name: requirement.name });
            }
        }
    }
}

if let Some(plan) = &egress_proxy_plan {
    env.extend(plan.sandbox_env.clone());
}
```

Order runtime create so `resolved_policy`, `context_endpoint`, and `inference_endpoint` exist before the agent sandbox setup is rendered. Use the brokered MCP endpoint when present:

```rust
let context_endpoint_for_agent = egress_proxy_plan
    .as_ref()
    .and_then(|plan| plan.context_mcp_url().cloned())
    .map(|url| context_endpoint.with_url(url))
    .or_else(|| context_endpoint.clone());
```

- [ ] Add fail-closed error variant.

In `RuntimeError`:

```rust
#[error("host egress proxy is required for {service}, but sandbox driver {driver} does not advertise supports_host_egress_proxy")]
HostEgressProxyUnsupported { service: String, driver: String },
```

- [ ] Verify Task 4.

Run:

```bash
cargo test -p agentenv-core create_env_with_brokered_openai_omits_real_secret_from_sandbox_env
cargo test -p agentenv-core create_env_fails_closed_when_proxy_required_but_sandbox_lacks_capability
cargo test -p agentenv-core
cargo fmt
```

Expected: core tests pass and sandbox create specs contain only dummy brokered values for brokered credentials.

Commit:

```bash
git add crates/agentenv-core/src/runtime.rs crates/agentenv-core/src/egress_proxy.rs
git commit -m "feat(core): broker credentials during env create"
```

---

## Task 5: Launch and Stop the Host Proxy Process

- [ ] Add failing process lifecycle tests.

Add tests in `crates/agentenv-core/src/egress_proxy.rs`:

```rust
#[tokio::test]
async fn launcher_writes_redacted_config_and_policy_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan = test_plan_with_openai();
    let credential_names = vec!["OPENAI_API_KEY".to_owned()];

    let launch = prepare_egress_proxy_files(EgressProxyFileInput {
        env_name: "demo".to_owned(),
        env_dir: temp.path().to_path_buf(),
        plan,
        credential_names,
        policy: NetworkPolicy::default(),
    })
    .await
    .expect("files prepared");

    let config = std::fs::read_to_string(&launch.config_path).expect("config readable");
    assert!(config.contains("\"credential_name\":\"OPENAI_API_KEY\""));
    assert!(!config.contains("sk-real-secret"));

    let policy = std::fs::read_to_string(&launch.policy_path).expect("policy readable");
    assert!(policy.contains("\"network\""));
}
```

Add a fake process test using an env override:

```rust
#[tokio::test]
async fn launcher_uses_env_override_for_proxy_binary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fake_bin = write_fake_proxy_script(temp.path());
    std::env::set_var("AGENTENV_EGRESS_PROXY_BIN", &fake_bin);

    let handle = start_egress_proxy_process(EgressProxyProcessInput {
        env_name: "demo".to_owned(),
        listen_url: "http://127.0.0.1:0".parse().unwrap(),
        config_path: temp.path().join("config.json"),
        events_db_path: temp.path().join("events.sqlite"),
    })
    .await
    .expect("process starts");

    stop_egress_proxy_process(handle).await.expect("process stops");
    std::env::remove_var("AGENTENV_EGRESS_PROXY_BIN");
}
```

Run:

```bash
cargo test -p agentenv-core launcher_writes_redacted_config_and_policy_files
cargo test -p agentenv-core launcher_uses_env_override_for_proxy_binary
```

Expected: compile fails because launch helpers do not exist.

- [ ] Implement file preparation and process launch helpers.

In `crates/agentenv-core/src/egress_proxy.rs` add:

```rust
#[derive(Debug, Clone)]
pub struct EgressProxyFileInput {
    pub env_name: String,
    pub env_dir: PathBuf,
    pub plan: EgressProxyPlan,
    pub credential_names: Vec<String>,
    pub policy: NetworkPolicy,
}

#[derive(Debug, Clone)]
pub struct EgressProxyLaunchFiles {
    pub config_path: PathBuf,
    pub policy_path: PathBuf,
}

pub async fn prepare_egress_proxy_files(input: EgressProxyFileInput) -> Result<EgressProxyLaunchFiles, EgressProxyLaunchError> {
    let proxy_dir = input.env_dir.join("egress-proxy");
    tokio::fs::create_dir_all(&proxy_dir).await?;
    let config_path = proxy_dir.join("config.json");
    let policy_path = proxy_dir.join("policy.json");

    let config = EgressProxyConfig {
        env_name: input.env_name,
        listen_url: input.plan.listen_url,
        routes: input.plan.routes,
        credential_names: input.credential_names,
        policy_path: policy_path.clone(),
    };

    atomic_write_json(&config_path, &config).await?;
    atomic_write_json(&policy_path, &input.policy).await?;

    Ok(EgressProxyLaunchFiles { config_path, policy_path })
}
```

Add process helpers:

```rust
pub async fn start_egress_proxy_process(input: EgressProxyProcessInput) -> Result<EgressProxyProcessHandle, EgressProxyLaunchError> {
    let bin = std::env::var_os("AGENTENV_EGRESS_PROXY_BIN")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe()?);

    let mut child = tokio::process::Command::new(bin)
        .arg("proxy")
        .arg("run")
        .arg("--env")
        .arg(&input.env_name)
        .arg("--config")
        .arg(&input.config_path)
        .arg("--events-db")
        .arg(&input.events_db_path)
        .kill_on_drop(true)
        .spawn()?;

    let pid = child.id();
    Ok(EgressProxyProcessHandle { pid, child })
}
```

Add stop:

```rust
pub async fn stop_egress_proxy_process(mut handle: EgressProxyProcessHandle) -> Result<(), EgressProxyLaunchError> {
    if let Some(_pid) = handle.pid {
        handle.child.start_kill()?;
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle.child.wait()).await;
    Ok(())
}
```

- [ ] Integrate runtime rollback and destroy.

In `CreateEnvRollback`, store proxy process handles:

```rust
egress_proxy: Option<EgressProxyProcessHandle>,
```

On create failure after launch:

```rust
if let Some(handle) = rollback.egress_proxy.take() {
    let _ = stop_egress_proxy_process(handle).await;
}
```

In `destroy_env`, read `state.egress_proxy.pid` and best-effort terminate the process using the same process utility. Clear state after sandbox/context/inference cleanup completes.

- [ ] Verify Task 5.

Run:

```bash
cargo test -p agentenv-core launcher_
cargo test -p agentenv-core rollback
cargo fmt
```

Expected: process helper tests pass and rollback tests prove best-effort proxy cleanup.

Commit:

```bash
git add crates/agentenv-core/src/egress_proxy.rs crates/agentenv-core/src/runtime.rs crates/agentenv-core/src/env.rs
git commit -m "feat(core): manage egress proxy lifecycle"
```

---

## Task 6: Implement Hidden Proxy CLI

- [ ] Add failing CLI parser and request transformation tests.

Add tests in `crates/agentenv/src/main.rs` or `crates/agentenv/src/proxy_cli.rs`:

```rust
#[test]
fn proxy_command_parses_run_args() {
    let cli = Cli::try_parse_from([
        "agentenv",
        "proxy",
        "run",
        "--env",
        "demo",
        "--config",
        "/tmp/config.json",
        "--events-db",
        "/tmp/events.sqlite",
    ])
    .expect("proxy command parses");

    assert!(matches!(cli.command, Some(Commands::Proxy(_))));
}
```

Add pure request transform tests in `crates/agentenv/src/proxy_cli.rs`:

```rust
#[test]
fn openai_route_injects_bearer_and_strips_request_identity_headers() {
    let route = test_openai_route("OPENAI_API_KEY");
    let mut request = test_request("/v1/openai/chat/completions");
    request.headers_mut().insert("authorization", HeaderValue::from_static("Bearer sandbox-token"));
    request.headers_mut().insert("x-request-id", HeaderValue::from_static("sandbox-id"));

    let transformed = transform_request_for_route(&route, request, SecretString::from("sk-real")).expect("request transforms");

    assert_eq!(transformed.headers()["authorization"], "Bearer sk-real");
    assert!(!transformed.headers().contains_key("x-request-id"));
    assert_eq!(transformed.uri().path(), "/chat/completions");
}
```

Run:

```bash
cargo test -p agentenv proxy_command_parses_run_args
cargo test -p agentenv openai_route_injects_bearer_and_strips_request_identity_headers
```

Expected: compile fails because the command and transform code do not exist.

- [ ] Add hidden command plumbing.

Update `crates/agentenv/src/main.rs`:

```rust
mod proxy_cli;
```

Add command variants:

```rust
#[derive(Subcommand, Debug)]
enum Commands {
    // existing variants
    #[command(hide = true)]
    Proxy(ProxyArgs),
}

#[derive(clap::Args, Debug)]
struct ProxyArgs {
    #[command(subcommand)]
    command: ProxyCommand,
}

#[derive(Subcommand, Debug)]
enum ProxyCommand {
    Run(ProxyRunArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub(crate) struct ProxyRunArgs {
    #[arg(long)]
    env: String,
    #[arg(long)]
    config: PathBuf,
    #[arg(long = "events-db")]
    events_db: PathBuf,
}
```

Add match arm:

```rust
Some(Commands::Proxy(args)) => proxy_cli::run(args).await,
```

- [ ] Implement proxy server.

Create `crates/agentenv/src/proxy_cli.rs`:

```rust
use std::{net::SocketAddr, sync::Arc, time::Duration};

use agentenv_core::egress_proxy::{BrokerRoute, BrokerService, EgressProxyConfig};
use agentenv_credstore::{CredentialStore, CredentialStoreConfig};
use agentenv_events::{ActivityEvent, ActivityKind, EventEmitter, SqliteSink};
use anyhow::{Context, Result};
use axum::{body::Body, extract::State, http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri}, routing::any, Router};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::RwLock;

pub(crate) async fn run(args: crate::ProxyArgs) -> Result<()> {
    match args.command {
        crate::ProxyCommand::Run(run) => run_proxy(run).await,
    }
}
```

Load config and credential store:

```rust
async fn run_proxy(args: crate::ProxyRunArgs) -> Result<()> {
    let config: EgressProxyConfig = read_json(&args.config).await?;
    let store_config = CredentialStoreConfig::from_root_dir(default_root_dir()?)?;
    let credentials = CredentialStore::from_config(store_config)?;
    let events = EventEmitter::new(SqliteSink::open(&args.events_db).await?);
    let state = Arc::new(ProxyState {
        config: Arc::new(config.clone()),
        policy: Arc::new(RwLock::new(read_json(&config.policy_path).await?)),
        credentials,
        events,
    });

    let addr: SocketAddr = config.listen_url.socket_addrs(|| None)?.into_iter().next().context("proxy listen URL must include a socket address")?;
    let app = Router::new().fallback(any(proxy_handler)).with_state(state);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
```

Transform provider headers:

```rust
fn apply_auth_header(route: &BrokerRoute, headers: &mut HeaderMap, secret: &SecretString) -> Result<()> {
    match &route.service {
        BrokerService::OpenAi | BrokerService::GitHub | BrokerService::Mcp { .. } | BrokerService::Oci { .. } => {
            headers.insert(http::header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", secret.expose_secret()))?);
        }
        BrokerService::Anthropic => {
            headers.insert(HeaderName::from_static("x-api-key"), HeaderValue::from_str(secret.expose_secret())?);
        }
    }
    Ok(())
}
```

Strip request and response identity headers:

```rust
fn strip_identity_headers(headers: &mut HeaderMap) {
    for name in [
        "authorization",
        "x-api-key",
        "x-request-id",
        "x-openai-client-user-agent",
        "anthropic-beta",
        "cookie",
    ] {
        headers.remove(name);
    }
}

fn strip_response_identity_headers(headers: &mut HeaderMap) {
    for name in [
        "www-authenticate",
        "server",
        "x-request-id",
        "openai-organization",
        "openai-processing-ms",
        "anthropic-organization-id",
        "set-cookie",
    ] {
        headers.remove(name);
    }
}
```

Forward through `reqwest` and emit audit:

```rust
async fn proxy_handler(State(state): State<Arc<ProxyState>>, request: Request<Body>) -> Result<Response<Body>, StatusCode> {
    let route = match state.config.match_route(request.uri().path()) {
        Some(route) => route.clone(),
        None => {
            emit_denied(&state, "no_route", request.uri()).await;
            return Err(StatusCode::NOT_FOUND);
        }
    };

    if !policy_allows(&state, &route, request.uri()).await {
        emit_denied(&state, "policy", request.uri()).await;
        return Err(StatusCode::FORBIDDEN);
    }

    let credential = state.credentials.resolve_name(&route.credential_name).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let upstream = transform_request_for_route(&route, request, credential).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let response = state.client.execute(upstream).await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    emit_allowed(&state, &route).await;

    Ok(strip_response(response))
}
```

- [ ] Verify Task 6.

Run:

```bash
cargo test -p agentenv proxy_
cargo test -p agentenv openai_route_injects_bearer_and_strips_request_identity_headers
cargo fmt
```

Expected: CLI parser and request transform tests pass.

Commit:

```bash
git add crates/agentenv/src/main.rs crates/agentenv/src/proxy_cli.rs crates/agentenv-core/src/egress_proxy.rs
git commit -m "feat(cli): run brokered egress proxy"
```

---

## Task 7: Complete Service Route Coverage

- [ ] Add failing tests for Anthropic, GitHub, MCP, and OCI transformations.

Add tests in `crates/agentenv/src/proxy_cli.rs`:

```rust
#[test]
fn anthropic_route_injects_x_api_key() {
    let route = test_anthropic_route("ANTHROPIC_API_KEY");
    let request = test_request("/v1/anthropic/messages");

    let transformed = transform_request_for_route(&route, request, SecretString::from("sk-ant-real")).expect("request transforms");

    assert_eq!(transformed.headers()["x-api-key"], "sk-ant-real");
    assert_eq!(transformed.uri().path(), "/messages");
}

#[test]
fn github_route_injects_bearer_token() {
    let route = test_github_route("GITHUB_TOKEN");
    let request = test_request("/v1/github/api/repos/windoliver/agentenv");

    let transformed = transform_request_for_route(&route, request, SecretString::from("ghp_real")).expect("request transforms");

    assert_eq!(transformed.headers()["authorization"], "Bearer ghp_real");
    assert_eq!(transformed.uri().path(), "/repos/windoliver/agentenv");
}

#[test]
fn mcp_route_injects_bearer_token() {
    let route = test_mcp_route("primary", "MCP_TOKEN");
    let request = test_request("/v1/mcp/primary");

    let transformed = transform_request_for_route(&route, request, SecretString::from("mcp-real")).expect("request transforms");

    assert_eq!(transformed.headers()["authorization"], "Bearer mcp-real");
}

#[test]
fn oci_route_preserves_registry_path_and_injects_bearer() {
    let route = test_oci_route("ghcr.io", "oci.ghcr.io");
    let request = test_request("/v1/oci/ghcr.io/v2/acme/app/manifests/latest");

    let transformed = transform_request_for_route(&route, request, SecretString::from("oci-real")).expect("request transforms");

    assert_eq!(transformed.headers()["authorization"], "Bearer oci-real");
    assert_eq!(transformed.uri().path(), "/v2/acme/app/manifests/latest");
}
```

Run:

```bash
cargo test -p agentenv anthropic_route_injects_x_api_key
cargo test -p agentenv github_route_injects_bearer_token
cargo test -p agentenv mcp_route_injects_bearer_token
cargo test -p agentenv oci_route_preserves_registry_path_and_injects_bearer
```

Expected: route-specific tests fail until all path rewriting rules exist.

- [ ] Implement route path mapping.

Add mapping:

```rust
fn upstream_path(route: &BrokerRoute, request_path: &str) -> Result<String> {
    let stripped = request_path
        .strip_prefix(&route.request_path_prefix)
        .context("request path does not match route prefix")?;

    let path = if stripped.is_empty() { "/" } else { stripped };
    Ok(path.to_owned())
}
```

For OCI, create request prefix `/v1/oci/<registry>` and upstream host `https://<registry>`:

```rust
BrokerService::Oci { registry } => {
    let prefix = format!("/v1/oci/{registry}");
    BrokerRoute {
        id: format!("oci.{registry}"),
        service: BrokerService::Oci { registry: registry.clone() },
        upstream_base_url: format!("https://{registry}").parse()?,
        credential_name,
        request_path_prefix: prefix,
        allowed_hosts,
    }
}
```

- [ ] Add live policy reload and rate limit tests.

Tests:

```rust
#[tokio::test]
async fn policy_reload_blocks_route_after_atomic_file_update() {
    let harness = ProxyHarness::with_openai().await;
    harness.write_policy(NetworkPolicy::allow_host("api.openai.com")).await;
    assert_eq!(harness.request("/v1/openai/models").await.status(), StatusCode::OK);

    harness.write_policy(NetworkPolicy::deny_host("api.openai.com")).await;
    harness.wait_for_policy_reload().await;

    assert_eq!(harness.request("/v1/openai/models").await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn route_rate_limit_denies_excess_requests() {
    let harness = ProxyHarness::with_openai_rate_limit(1).await;

    assert_eq!(harness.request("/v1/openai/models").await.status(), StatusCode::OK);
    assert_eq!(harness.request("/v1/openai/models").await.status(), StatusCode::TOO_MANY_REQUESTS);
}
```

Implement fixed-window counters keyed by route id:

```rust
#[derive(Debug)]
struct FixedWindowLimiter {
    window_started_at: Instant,
    count: u32,
    max_per_minute: u32,
}

impl FixedWindowLimiter {
    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_started_at) >= Duration::from_secs(60) {
            self.window_started_at = now;
            self.count = 0;
        }
        if self.count >= self.max_per_minute {
            return false;
        }
        self.count += 1;
        true
    }
}
```

- [ ] Verify Task 7.

Run:

```bash
cargo test -p agentenv anthropic_route_injects_x_api_key
cargo test -p agentenv github_route_injects_bearer_token
cargo test -p agentenv mcp_route_injects_bearer_token
cargo test -p agentenv oci_route_preserves_registry_path_and_injects_bearer
cargo test -p agentenv policy_reload_blocks_route_after_atomic_file_update
cargo test -p agentenv route_rate_limit_denies_excess_requests
cargo fmt
```

Expected: all service route and policy tests pass.

Commit:

```bash
git add crates/agentenv/src/proxy_cli.rs crates/agentenv-core/src/egress_proxy.rs
git commit -m "feat(proxy): support provider mcp github and oci routes"
```

---

## Task 8: Advertise Sandbox Capabilities

- [ ] Add failing driver capability tests.

Update driver tests:

```rust
#[test]
fn openshell_advertises_host_egress_proxy() {
    let caps = OpenShellDriver::test_capabilities();
    assert!(caps.supports_host_egress_proxy);
}

#[test]
fn remote_sandbox_drivers_do_not_advertise_host_egress_proxy() {
    let remote_caps = RemoteSshDriver::test_capabilities();
    let microvm_caps = MicrovmDriver::test_capabilities();

    assert!(!remote_caps.supports_host_egress_proxy);
    assert!(!microvm_caps.supports_host_egress_proxy);
}
```

Run:

```bash
cargo test -p sandbox-openshell host_egress_proxy
cargo test -p sandbox-remote-ssh host_egress_proxy
cargo test -p sandbox-microvm host_egress_proxy
```

Expected: tests fail until capabilities are set.

- [ ] Implement driver capability declarations.

In `crates/sandbox-openshell/src/lib.rs` initialize:

```rust
supports_host_egress_proxy: true,
```

In remote drivers initialize:

```rust
supports_host_egress_proxy: false,
```

- [ ] Verify Task 8.

Run:

```bash
cargo test -p sandbox-openshell
cargo test -p sandbox-remote-ssh
cargo test -p sandbox-microvm
cargo fmt
```

Expected: sandbox capability tests pass.

Commit:

```bash
git add crates/sandbox-openshell/src/lib.rs crates/sandbox-remote-ssh/src/lib.rs crates/sandbox-microvm/src/lib.rs
git commit -m "feat(drivers): advertise host egress proxy support"
```

---

## Task 9: Document Blueprint Policy and Runtime Behavior

- [ ] Add blueprint example.

Create `examples/blueprints/brokered-egress.yaml`:

```yaml
version: 1
name: brokered-egress-demo
agent:
  kind: codex
context:
  kind: generic-mcp
  endpoint: https://mcp.example.test/rpc
inference:
  provider: openai
policy:
  tier: restricted
  presets: []
  egress_proxy:
    github: true
    oci:
      registries:
        - ghcr.io
    rate_limits:
      openai:
        requests_per_minute: 60
network:
  allow:
    - host: api.openai.com
      ports: [443]
    - host: api.anthropic.com
      ports: [443]
    - host: api.github.com
      ports: [443]
    - host: ghcr.io
      ports: [443]
```

- [ ] Update architecture docs.

Add a short broker section to `docs/ARCHITECTURE.md`:

```markdown
### Host Egress Broker

For sandbox drivers that advertise `supports_host_egress_proxy`, core launches a host-owned proxy and rewrites agent, inference, MCP, GitHub, and OCI endpoints to local unauthenticated URLs. The sandbox receives only dummy credential values for brokered services. The proxy resolves credentials from the host credential store at request time, injects provider-specific auth headers, checks live network policy, applies route rate limits, strips identity-bearing response headers, and emits redacted activity events.
```

Update `docs/ROADMAP.md` H-5 entry to reference issue #41 and mark the brokered egress scope implemented by this PR.

- [ ] Verify Task 9.

Run:

```bash
rg -n "egress_proxy|supports_host_egress_proxy|Host Egress Broker" docs examples crates
cargo fmt --check
```

Expected: docs and example reference the new broker surface consistently.

Commit:

```bash
git add docs/ARCHITECTURE.md docs/ROADMAP.md examples/blueprints/brokered-egress.yaml
git commit -m "docs: document brokered egress proxy"
```

---

## Task 10: Full Verification and PR

- [ ] Run formatting.

```bash
cargo fmt --check
```

Expected: exits `0`.

- [ ] Run clippy with warnings denied.

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: exits `0`.

- [ ] Run the full workspace tests.

```bash
cargo test --workspace
```

Expected: exits `0`.

- [ ] Inspect credential leakage risk.

Run:

```bash
rg -n "OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|MCP_TOKEN|sk-real|ghp_real|oci-real" crates docs examples
```

Expected: only tests, docs examples, route names, and dummy values appear. No runtime state or config writer persists real secret values.

- [ ] Inspect git diff.

```bash
git status --short
git diff --stat main...HEAD
git diff --check
```

Expected: no whitespace errors and the diff only covers issue #41.

- [ ] Open PR.

Use title:

```text
Implement brokered egress proxy for sandbox credentials
```

Use body:

```markdown
## Summary
- adds schema v1.3 `supports_host_egress_proxy` capability
- routes OpenAI, Anthropic, GitHub, generic MCP bearer, and OCI credentials through a host-owned egress proxy
- rewrites sandbox endpoints to dummy unauthenticated local proxy URLs
- adds live policy reload, route rate limits, and redacted allow/deny audit events

## Affected crates
- `agentenv-proto`
- `agentenv-core`
- `agentenv`
- `sandbox-openshell`
- `sandbox-microvm`
- `sandbox-remote-ssh`

## Verification
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

Fixes #41
```

Expected: PR opens from `codex/issue-41-egress-proxy` against the default branch.
