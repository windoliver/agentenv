# Capability Provenance Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #43 in one PR by making the existing MCP confused-deputy guard provenance-aware and capability-scoped, with a Claude-oriented POC that blocks untrusted values from reaching `git.commit` without approval.

**Architecture:** Extend `McpGuardConfig` with provenance policy and tool capability declarations, put lattice and capability evaluation helpers in `agentenv-policy`, and wire the current `agentenv_mcp::guard` evaluator to use those helpers before forwarding `tools/call`. Core continues to rewrite MCP endpoints through the existing stdio guard and egress proxy paths; approvals and events carry redacted provenance evidence.

**Tech Stack:** Rust 2021, `serde`/`schemars` schemas in `agentenv-proto`, MCP JSON-RPC over stdio/HTTP, existing `agentenv_mcp::guard`, `agentenv-approvals`, `agentenv-events`, `cargo test`.

---

## File Structure

- Modify `crates/agentenv-proto/src/types.rs`: add provenance tags, source summaries, tool capability declarations, provenance guard config, safe defaults, and schema tests.
- Modify `crates/agentenv-proto/src/lib.rs`: ensure new schemas are exported through the existing schema export path.
- Create `crates/agentenv-policy/src/provenance.rs`: implement the taint lattice, capability defaults, and policy decisions.
- Modify `crates/agentenv-policy/src/lib.rs`: export the new module.
- Add `crates/agentenv-policy/tests/provenance_policy.rs`: cover lattice and capability decisions.
- Modify `crates/agentenv-mcp/src/guard.rs`: evaluate provenance and produce sanitized forwarded JSON-RPC requests.
- Modify `crates/agentenv/src/mcp_guard_cli.rs`: forward sanitized requests and return structured provenance errors.
- Modify `crates/agentenv/src/proxy_cli.rs`: use sanitized requests, include provenance evidence in approval context, and map provenance reasons to stable reason codes.
- Modify `crates/agentenv-core/src/runtime.rs`: validate `required` provenance mediation and write extended guard config files.
- Modify `crates/drivers/agent-claude/src/lib.rs`: add tests proving Claude consumes mediated endpoints as supplied by core.
- Modify `docs/BLUEPRINTS.md`, `docs/DRIVER_PROTOCOL.md`, and `docs/ARCHITECTURE.md`: document the additive provenance layer.

---

### Task 1: Add Proto Types For Provenance And Tool Capabilities

**Files:**
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-proto/src/lib.rs`
- Test: `crates/agentenv-proto/src/types.rs`

- [ ] **Step 1: Write failing proto tests**

Add these tests to the existing `#[cfg(test)] mod tests` in `crates/agentenv-proto/src/types.rs`:

```rust
#[test]
fn provenance_tag_serializes_stable_values() {
    assert_eq!(
        serde_json::to_value(ProvenanceTag::Trusted).unwrap(),
        serde_json::json!("trusted")
    );
    assert_eq!(
        serde_json::to_value(ProvenanceTag::Tenant).unwrap(),
        serde_json::json!("tenant")
    );
    assert_eq!(
        serde_json::to_value(ProvenanceTag::Untrusted).unwrap(),
        serde_json::json!("untrusted")
    );
}

#[test]
fn mcp_guard_config_parses_provenance_and_tool_capabilities() {
    let yaml = r#"
enabled: true
default_approval: per-call
provenance:
  enabled: true
  required: true
  default_unannotated_source: untrusted
tool_capabilities:
  git.commit:
    caps: [git_write]
    max_input_taint: trusted
    approval: per-call
    argument_policies:
      - pointer: /message
        max_input_taint: trusted
  filesystem.read:
    caps: [read_fs]
    max_input_taint: tenant
    approval: never
"#;

    let config: McpGuardConfig = serde_yaml::from_str(yaml).expect("config parses");

    let provenance = config.provenance.expect("provenance config");
    assert!(provenance.enabled);
    assert!(provenance.required);
    assert_eq!(
        provenance.default_unannotated_source,
        ProvenanceTag::Untrusted
    );

    let git = config
        .tool_capabilities
        .get("git.commit")
        .expect("git.commit declaration");
    assert_eq!(git.caps, vec![ToolCapability::GitWrite]);
    assert_eq!(git.max_input_taint, ProvenanceTag::Trusted);
    assert_eq!(git.approval, McpApprovalMode::PerCall);
    assert_eq!(git.argument_policies[0].pointer, "/message");
    assert_eq!(
        git.argument_policies[0].max_input_taint,
        ProvenanceTag::Trusted
    );
}

#[test]
fn mcp_guard_config_defaults_provenance_to_disabled() {
    let config: McpGuardConfig = serde_yaml::from_str("enabled: true\n").unwrap();

    assert!(config.provenance.is_none());
    assert!(config.tool_capabilities.is_empty());
}
```

- [ ] **Step 2: Run proto tests to verify they fail**

Run:

```bash
cargo test -p agentenv-proto provenance_tag_serializes_stable_values mcp_guard_config_parses_provenance_and_tool_capabilities mcp_guard_config_defaults_provenance_to_disabled
```

Expected: compile failure naming missing `ProvenanceTag`, `ToolCapability`, `McpProvenanceConfig`, `ToolCapabilityDeclaration`, and `ToolArgumentPolicy`.

- [ ] **Step 3: Add the proto types and config fields**

In `crates/agentenv-proto/src/types.rs`, add these definitions near the MCP guard types, after `McpSessionRateLimit`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceTag {
    Trusted,
    Tenant,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSourceKind {
    Operator,
    SignedBlueprint,
    LocalFile,
    LocalRepo,
    Web,
    GithubIssue,
    RemoteMcp,
    ToolResult,
    Approval,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceSummary {
    pub tag: ProvenanceTag,
    pub source_kind: ProvenanceSourceKind,
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapability {
    ReadFs,
    WriteFs,
    Exec,
    GitRead,
    GitWrite,
    Network,
    McpTool,
    CredentialBroker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolArgumentPolicy {
    pub pointer: String,
    pub max_input_taint: ProvenanceTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolCapabilityDeclaration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<ToolCapability>,
    pub max_input_taint: ProvenanceTag,
    #[serde(default = "default_mcp_approval")]
    pub approval: McpApprovalMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argument_policies: Vec<ToolArgumentPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpProvenanceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_unannotated_source")]
    pub default_unannotated_source: ProvenanceTag,
}
```

Add this default helper near `default_mcp_approval`:

```rust
fn default_unannotated_source() -> ProvenanceTag {
    ProvenanceTag::Untrusted
}
```

Extend `McpGuardConfig` with:

```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<McpProvenanceConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_capabilities: BTreeMap<String, ToolCapabilityDeclaration>,
```

- [ ] **Step 4: Export JSON schemas for the new types**

In `crates/agentenv-proto/src/lib.rs`, add schema export entries for:

```rust
export_schema::<ProvenanceSummary>("provenance-summary")?;
export_schema::<ToolCapabilityDeclaration>("tool-capability-declaration")?;
```

If the file uses a macro or list instead of repeated `export_schema` calls, add the two type entries to that list using the same naming convention.

- [ ] **Step 5: Run proto tests to verify they pass**

Run:

```bash
cargo test -p agentenv-proto provenance_tag_serializes_stable_values mcp_guard_config_parses_provenance_and_tool_capabilities mcp_guard_config_defaults_provenance_to_disabled
```

Expected: PASS.

- [ ] **Step 6: Commit proto types**

```bash
git add crates/agentenv-proto/src/types.rs crates/agentenv-proto/src/lib.rs
git commit -m "feat: add provenance capability schemas"
```

---

### Task 2: Implement Provenance Policy Helpers

**Files:**
- Create: `crates/agentenv-policy/src/provenance.rs`
- Modify: `crates/agentenv-policy/src/lib.rs`
- Test: `crates/agentenv-policy/tests/provenance_policy.rs`

- [ ] **Step 1: Write failing provenance policy tests**

Create `crates/agentenv-policy/tests/provenance_policy.rs`:

```rust
use agentenv_policy::provenance::{
    default_tool_declaration, evaluate_capability_policy, join_tags, CapabilityPolicyDecision,
};
use agentenv_proto::{McpApprovalMode, ProvenanceTag, ToolCapability, ToolCapabilityDeclaration};

#[test]
fn joins_use_highest_taint() {
    assert_eq!(
        join_tags([ProvenanceTag::Trusted, ProvenanceTag::Tenant]),
        ProvenanceTag::Tenant
    );
    assert_eq!(
        join_tags([ProvenanceTag::Tenant, ProvenanceTag::Untrusted]),
        ProvenanceTag::Untrusted
    );
}

#[test]
fn git_commit_defaults_to_trusted_only() {
    let declaration = default_tool_declaration("git.commit");

    assert_eq!(declaration.caps, vec![ToolCapability::GitWrite]);
    assert_eq!(declaration.max_input_taint, ProvenanceTag::Trusted);
}

#[test]
fn tenant_can_reach_read_only_filesystem_tool() {
    let declaration = default_tool_declaration("filesystem.read");

    let decision = evaluate_capability_policy(&declaration, ProvenanceTag::Tenant);

    assert_eq!(decision, CapabilityPolicyDecision::Allow);
}

#[test]
fn untrusted_git_write_requires_approval_when_configured() {
    let declaration = ToolCapabilityDeclaration {
        caps: vec![ToolCapability::GitWrite],
        max_input_taint: ProvenanceTag::Trusted,
        approval: McpApprovalMode::PerCall,
        argument_policies: Vec::new(),
    };

    let decision = evaluate_capability_policy(&declaration, ProvenanceTag::Untrusted);

    assert_eq!(decision, CapabilityPolicyDecision::RequestApproval);
}

#[test]
fn untrusted_git_write_denies_when_approval_disabled() {
    let declaration = ToolCapabilityDeclaration {
        caps: vec![ToolCapability::GitWrite],
        max_input_taint: ProvenanceTag::Trusted,
        approval: McpApprovalMode::Never,
        argument_policies: Vec::new(),
    };

    let decision = evaluate_capability_policy(&declaration, ProvenanceTag::Untrusted);

    assert_eq!(decision, CapabilityPolicyDecision::Deny);
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run:

```bash
cargo test -p agentenv-policy --test provenance_policy
```

Expected: compile failure because `agentenv_policy::provenance` does not exist.

- [ ] **Step 3: Implement the provenance helper module**

Create `crates/agentenv-policy/src/provenance.rs`:

```rust
use agentenv_proto::{McpApprovalMode, ProvenanceTag, ToolCapability, ToolCapabilityDeclaration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityPolicyDecision {
    Allow,
    RequestApproval,
    Deny,
}

pub fn join_tags(tags: impl IntoIterator<Item = ProvenanceTag>) -> ProvenanceTag {
    tags.into_iter()
        .max()
        .unwrap_or(ProvenanceTag::Untrusted)
}

pub fn evaluate_capability_policy(
    declaration: &ToolCapabilityDeclaration,
    observed_taint: ProvenanceTag,
) -> CapabilityPolicyDecision {
    if observed_taint <= declaration.max_input_taint {
        return CapabilityPolicyDecision::Allow;
    }

    match declaration.approval {
        McpApprovalMode::PerCall | McpApprovalMode::PerSession => {
            CapabilityPolicyDecision::RequestApproval
        }
        McpApprovalMode::Never => CapabilityPolicyDecision::Deny,
    }
}

pub fn default_tool_declaration(tool_name: &str) -> ToolCapabilityDeclaration {
    let lower = tool_name.to_ascii_lowercase();
    if lower.contains("commit") {
        return declaration(vec![ToolCapability::GitWrite], ProvenanceTag::Trusted);
    }
    if lower.contains("write")
        || lower.contains("create")
        || lower.contains("delete")
        || lower.contains("remove")
        || lower.contains("update")
        || lower.contains("patch")
        || lower.contains("apply")
    {
        return declaration(vec![ToolCapability::WriteFs], ProvenanceTag::Trusted);
    }
    if lower.contains("exec") || lower.contains("shell") || lower.contains("run") {
        return declaration(vec![ToolCapability::Exec], ProvenanceTag::Trusted);
    }
    if lower.contains("fetch")
        || lower.contains("http")
        || lower.contains("web")
        || lower.contains("request")
    {
        return declaration(vec![ToolCapability::Network], ProvenanceTag::Tenant);
    }
    if lower.contains("read")
        || lower.contains("list")
        || lower.contains("search")
        || lower.contains("grep")
    {
        return declaration(vec![ToolCapability::ReadFs], ProvenanceTag::Tenant);
    }

    declaration(vec![ToolCapability::McpTool], ProvenanceTag::Trusted)
}

fn declaration(
    caps: Vec<ToolCapability>,
    max_input_taint: ProvenanceTag,
) -> ToolCapabilityDeclaration {
    ToolCapabilityDeclaration {
        caps,
        max_input_taint,
        approval: McpApprovalMode::PerCall,
        argument_policies: Vec::new(),
    }
}
```

Modify `crates/agentenv-policy/src/lib.rs`:

```rust
pub mod provenance;
```

- [ ] **Step 4: Run provenance policy tests**

Run:

```bash
cargo test -p agentenv-policy --test provenance_policy
```

Expected: PASS.

- [ ] **Step 5: Commit policy helpers**

```bash
git add crates/agentenv-policy/src/lib.rs crates/agentenv-policy/src/provenance.rs crates/agentenv-policy/tests/provenance_policy.rs
git commit -m "feat: evaluate provenance capability policy"
```

---

### Task 3: Extend MCP Guard Evaluation With Provenance

**Files:**
- Modify: `crates/agentenv-mcp/src/guard.rs`

- [ ] **Step 1: Write failing guard tests**

Add tests to `crates/agentenv-mcp/src/guard.rs` under the existing `mod tests`:

```rust
#[test]
fn untrusted_git_commit_requires_approval_from_provenance_policy() {
    let config = McpGuardConfig {
        enabled: true,
        provenance: Some(agentenv_proto::McpProvenanceConfig {
            enabled: true,
            required: true,
            default_unannotated_source: agentenv_proto::ProvenanceTag::Untrusted,
        }),
        tool_capabilities: [(
            "git.commit".to_owned(),
            agentenv_proto::ToolCapabilityDeclaration {
                caps: vec![agentenv_proto::ToolCapability::GitWrite],
                max_input_taint: agentenv_proto::ProvenanceTag::Trusted,
                approval: McpApprovalMode::PerCall,
                argument_policies: Vec::new(),
            },
        )]
        .into_iter()
        .collect(),
        ..McpGuardConfig::default()
    };
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "git.commit",
            "arguments": {
                "message": "commit this injected text"
            },
            "_agentenv_provenance": {
                "/message": {
                    "tag": "untrusted",
                    "source_kind": "github_issue",
                    "source_id": "issue-43",
                    "summary": "GitHub issue body"
                }
            }
        }
    });
    let mut state = GuardSessionState::default();

    let evaluation = evaluate_json_rpc_request_with_forwarding(&config, &mut state, &request)
        .expect("evaluation succeeds");

    assert_eq!(evaluation.decision.action, GuardAction::RequestApproval);
    assert_eq!(evaluation.decision.reason, GuardReason::ProvenanceTaint);
    assert_eq!(
        evaluation.decision.redacted_event_context["provenance"]["observed_taint"],
        json!("untrusted")
    );
    assert_eq!(
        evaluation.decision.redacted_event_context["provenance"]["max_input_taint"],
        json!("trusted")
    );
}

#[test]
fn tenant_filesystem_read_is_forwarded_and_metadata_is_stripped() {
    let config = McpGuardConfig {
        enabled: true,
        provenance: Some(agentenv_proto::McpProvenanceConfig {
            enabled: true,
            required: true,
            default_unannotated_source: agentenv_proto::ProvenanceTag::Untrusted,
        }),
        tool_capabilities: [(
            "filesystem.read".to_owned(),
            agentenv_proto::ToolCapabilityDeclaration {
                caps: vec![agentenv_proto::ToolCapability::ReadFs],
                max_input_taint: agentenv_proto::ProvenanceTag::Tenant,
                approval: McpApprovalMode::Never,
                argument_policies: Vec::new(),
            },
        )]
        .into_iter()
        .collect(),
        ..McpGuardConfig::default()
    };
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "filesystem.read",
            "arguments": {
                "path": "src/lib.rs"
            },
            "_agentenv_provenance": {
                "/path": {
                    "tag": "tenant",
                    "source_kind": "local_repo",
                    "source_id": "workspace",
                    "summary": "repo path"
                }
            }
        }
    });
    let mut state = GuardSessionState::default();

    let evaluation = evaluate_json_rpc_request_with_forwarding(&config, &mut state, &request)
        .expect("evaluation succeeds");

    assert_eq!(evaluation.decision.action, GuardAction::Forward);
    assert!(evaluation
        .forwarded_request
        .get("params")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|params| !params.contains_key("_agentenv_provenance")));
}
```

- [ ] **Step 2: Run guard tests to verify they fail**

Run:

```bash
cargo test -p agentenv-mcp untrusted_git_commit_requires_approval_from_provenance_policy tenant_filesystem_read_is_forwarded_and_metadata_is_stripped
```

Expected: compile failure because `evaluate_json_rpc_request_with_forwarding`, `GuardReason::ProvenanceTaint`, and new config fields are not wired into the guard.

- [ ] **Step 3: Add guard evaluation types**

In `crates/agentenv-mcp/src/guard.rs`, extend imports:

```rust
use agentenv_policy::provenance::{
    default_tool_declaration, evaluate_capability_policy, join_tags, CapabilityPolicyDecision,
};
use agentenv_proto::{
    McpApprovalMode, McpGuardConfig, McpSessionRateLimit, ProvenanceSummary, ProvenanceTag,
};
```

Add this struct near `GuardDecision`:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct GuardEvaluation {
    pub decision: GuardDecision,
    pub forwarded_request: Value,
}
```

Add `ProvenanceTaint` to `GuardReason`:

```rust
    ProvenanceTaint,
```

- [ ] **Step 4: Add provenance-aware evaluator while preserving the old function**

Replace the body of `evaluate_json_rpc_request` with:

```rust
pub fn evaluate_json_rpc_request(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    request: &Value,
) -> Result<GuardDecision, GuardError> {
    evaluate_json_rpc_request_with_forwarding(config, state, request)
        .map(|evaluation| evaluation.decision)
}
```

Add `evaluate_json_rpc_request_with_forwarding` below it:

```rust
pub fn evaluate_json_rpc_request_with_forwarding(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    request: &Value,
) -> Result<GuardEvaluation, GuardError> {
    let base_decision = evaluate_json_rpc_request_without_provenance(config, state, request)?;
    let forwarded_request = strip_agentenv_provenance(request);

    if !matches!(base_decision.action, GuardAction::Forward | GuardAction::RequestApproval) {
        return Ok(GuardEvaluation {
            decision: base_decision,
            forwarded_request,
        });
    }

    let Some(provenance_config) = config.provenance.as_ref().filter(|cfg| cfg.enabled) else {
        return Ok(GuardEvaluation {
            decision: base_decision,
            forwarded_request,
        });
    };

    let Some(tool_name) = base_decision.tool_name.as_deref() else {
        return Ok(GuardEvaluation {
            decision: base_decision,
            forwarded_request,
        });
    };

    let declaration = config
        .tool_capabilities
        .get(tool_name)
        .cloned()
        .unwrap_or_else(|| default_tool_declaration(tool_name));
    let provenance = provenance_from_request(request, provenance_config.default_unannotated_source);
    let observed_taint = join_tags(provenance.iter().map(|summary| summary.tag));
    let policy_decision = evaluate_capability_policy(&declaration, observed_taint);

    let provenance_context = json!({
        "observed_taint": observed_taint,
        "max_input_taint": declaration.max_input_taint,
        "caps": declaration.caps,
        "sources": provenance,
    });

    let mut decision = base_decision;
    decision.redacted_event_context = merge_event_context_with_provenance(
        decision.redacted_event_context,
        provenance_context,
    );

    match policy_decision {
        CapabilityPolicyDecision::Allow => {}
        CapabilityPolicyDecision::RequestApproval => {
            decision.action = GuardAction::RequestApproval;
            decision.reason = GuardReason::ProvenanceTaint;
            decision.approval_mode = declaration.approval;
        }
        CapabilityPolicyDecision::Deny => {
            decision.action = GuardAction::Deny;
            decision.reason = GuardReason::ProvenanceTaint;
        }
    }

    Ok(GuardEvaluation {
        decision,
        forwarded_request,
    })
}
```

Move the current non-provenance evaluator into a helper before adding the new wrapper:

```rust
fn evaluate_json_rpc_request_without_provenance(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    request: &Value,
) -> Result<GuardDecision, GuardError> {
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Ok(not_tool_call_decision(
            config.default_approval.clone(),
            None,
        ));
    };

    if method != "tools/call" {
        return Ok(not_tool_call_decision(
            config.default_approval.clone(),
            Some(method),
        ));
    }

    if !config.enabled {
        return Ok(GuardDecision {
            action: GuardAction::Forward,
            reason: GuardReason::Disabled,
            tool_name: tool_name_from_request(request).ok(),
            matched_policy: None,
            approval_mode: config.default_approval.clone(),
            redacted_event_context: json!({"method": method, "guard": "disabled"}),
        });
    }

    let params = request
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| GuardError::MalformedToolCall("missing params object".to_owned()))?;
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| GuardError::MalformedToolCall("missing params.name".to_owned()))?;
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    let matched = match_policy(config, tool_name);
    let event_context = event_context(tool_name, arguments, &matched);

    if !matched.url_allowlist.is_empty()
        && has_url_allowlist_violation(arguments, &matched.url_allowlist)
    {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::UrlAllowlistViolation,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if contains_credential_like_argument(arguments) {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::CredentialLikeArgument,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if contains_env_var_like_argument(arguments) {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::EnvVarLikeArgument,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if exceeds_rate_limit(state, tool_name, &matched) {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::RateLimited,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if violates_cross_tool_flow(config, state, tool_name) {
        return Ok(decision(
            GuardAction::RequestApproval,
            GuardReason::CrossToolFlow,
            tool_name,
            &matched,
            event_context,
        ));
    }

    let (action, reason) = match matched.approval {
        McpApprovalMode::Never => (GuardAction::Forward, GuardReason::AllowedByPolicy),
        McpApprovalMode::PerCall => (GuardAction::RequestApproval, GuardReason::ApprovalRequired),
        McpApprovalMode::PerSession
            if state.has_session_grant(tool_name, matched.pattern.as_deref()) =>
        {
            (GuardAction::Forward, GuardReason::AllowedByPolicy)
        }
        McpApprovalMode::PerSession => {
            (GuardAction::RequestApproval, GuardReason::ApprovalRequired)
        }
    };

    Ok(decision(action, reason, tool_name, &matched, event_context))
}
```

- [ ] **Step 5: Add provenance parsing and stripping helpers**

Add these helpers in `crates/agentenv-mcp/src/guard.rs`:

```rust
fn provenance_from_request(request: &Value, default_tag: ProvenanceTag) -> Vec<ProvenanceSummary> {
    request
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("_agentenv_provenance"))
        .and_then(Value::as_object)
        .map(|entries| {
            entries
                .values()
                .filter_map(|value| serde_json::from_value::<ProvenanceSummary>(value.clone()).ok())
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            vec![ProvenanceSummary {
                tag: default_tag,
                source_kind: agentenv_proto::ProvenanceSourceKind::Unknown,
                source_id: "unannotated".to_owned(),
                summary: Some("unannotated MCP tool argument".to_owned()),
            }]
        })
}

fn strip_agentenv_provenance(request: &Value) -> Value {
    let mut stripped = request.clone();
    if let Some(params) = stripped.get_mut("params").and_then(Value::as_object_mut) {
        params.remove("_agentenv_provenance");
    }
    stripped
}

fn merge_event_context_with_provenance(mut event_context: Value, provenance: Value) -> Value {
    if let Some(map) = event_context.as_object_mut() {
        map.insert("provenance".to_owned(), provenance);
        event_context
    } else {
        json!({ "provenance": provenance })
    }
}
```

- [ ] **Step 6: Run guard tests**

Run:

```bash
cargo test -p agentenv-mcp untrusted_git_commit_requires_approval_from_provenance_policy tenant_filesystem_read_is_forwarded_and_metadata_is_stripped
```

Expected: PASS.

- [ ] **Step 7: Commit guard evaluation**

```bash
git add crates/agentenv-mcp/src/guard.rs
git commit -m "feat: enforce provenance in mcp guard"
```

---

### Task 4: Use Sanitized Requests In Stdio Guard And HTTP Proxy

**Files:**
- Modify: `crates/agentenv/src/mcp_guard_cli.rs`
- Modify: `crates/agentenv/src/proxy_cli.rs`

- [ ] **Step 1: Write failing stdio guard tests**

In `crates/agentenv/src/mcp_guard_cli.rs`, add tests:

```rust
#[test]
fn provenance_denial_returns_structured_json_rpc_error() {
    let decision = GuardDecision {
        action: GuardAction::Deny,
        reason: GuardReason::ProvenanceTaint,
        tool_name: Some("git.commit".to_owned()),
        matched_policy: Some("git.commit".to_owned()),
        approval_mode: McpApprovalMode::PerCall,
        redacted_event_context: json!({
            "provenance": {
                "observed_taint": "untrusted",
                "max_input_taint": "trusted"
            }
        }),
    };

    let body = guarded_error_response(json!(1), &decision);
    let value: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(value["error"]["code"], json!(-32004));
    assert_eq!(value["error"]["data"]["reason"], json!("mcp_provenance_taint"));
    assert_eq!(value["error"]["data"]["tool_name"], json!("git.commit"));
    assert_eq!(value["error"]["data"]["observed_taint"], json!("untrusted"));
}
```

- [ ] **Step 2: Write failing proxy reason-code test**

In `crates/agentenv/src/proxy_cli.rs`, extend the existing `mcp_guard_reason_code` tests or add:

```rust
#[test]
fn mcp_guard_reason_code_includes_provenance_taint() {
    assert_eq!(
        mcp_guard_reason_code(agentenv_mcp::guard::GuardReason::ProvenanceTaint),
        "mcp_provenance_taint"
    );
}
```

- [ ] **Step 3: Run focused tests to verify they fail**

Run:

```bash
cargo test -p agentenv provenance_denial_returns_structured_json_rpc_error mcp_guard_reason_code_includes_provenance_taint
```

Expected: compile failure because `guarded_error_response` and the new reason-code arm are missing.

- [ ] **Step 4: Use forwarding-aware evaluation in stdio guard**

In `crates/agentenv/src/mcp_guard_cli.rs`, change `evaluate_client_message` to return `agentenv_mcp::guard::GuardEvaluation`:

```rust
pub(crate) fn evaluate_client_message(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    body: &[u8],
) -> agentenv_mcp::guard::GuardEvaluation {
    let request = match serde_json::from_slice::<Value>(body) {
        Ok(request) => request,
        Err(error) => {
            let decision = malformed_decision(format!("invalid JSON-RPC body: {error}"));
            return agentenv_mcp::guard::GuardEvaluation {
                decision,
                forwarded_request: Value::Null,
            };
        }
    };
    match agentenv_mcp::guard::evaluate_json_rpc_request_with_forwarding(config, state, &request) {
        Ok(evaluation) => evaluation,
        Err(error) => {
            let decision = malformed_decision(error.to_string());
            agentenv_mcp::guard::GuardEvaluation {
                decision,
                forwarded_request: request,
            }
        }
    }
}
```

Update the loop in `run_blocking`:

```rust
let evaluation = evaluate_client_message(&config, &mut state, &body);
match evaluation.decision.action {
    GuardAction::Deny | GuardAction::RequestApproval => {
        let id = json_rpc_id(&body);
        let response = guarded_error_response(id, &evaluation.decision);
        write_lsp_message(&mut stdout, &response)?;
        stdout.flush().context("flush guarded MCP response")?;
    }
    GuardAction::Forward | GuardAction::NotToolCall => {
        let forwarded = serde_json::to_vec(&evaluation.forwarded_request)
            .context("serialize guarded MCP request")?;
        write_lsp_message(&mut child_stdin, &forwarded)?;
        child_stdin.flush().context("flush upstream MCP request")?;
        let Some(response) = read_lsp_message(&mut child_stdout)? else {
            break;
        };
        write_lsp_message(&mut stdout, &response)?;
        stdout.flush().context("flush upstream MCP response")?;
    }
}
```

- [ ] **Step 5: Add structured error helper**

Add this function to `crates/agentenv/src/mcp_guard_cli.rs`:

```rust
pub(crate) fn guarded_error_response(id: Value, decision: &GuardDecision) -> Vec<u8> {
    let reason = guard_reason_code(decision.reason);
    let provenance = decision.redacted_event_context.get("provenance");
    let observed_taint = provenance
        .and_then(|value| value.get("observed_taint"))
        .cloned()
        .unwrap_or(Value::Null);
    let max_input_taint = provenance
        .and_then(|value| value.get("max_input_taint"))
        .cloned()
        .unwrap_or(Value::Null);

    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32004,
            "message": "MCP tool call blocked by guard",
            "data": {
                "reason": reason,
                "tool_name": decision.tool_name,
                "observed_taint": observed_taint,
                "max_input_taint": max_input_taint,
            }
        }
    }))
    .unwrap_or_else(|_| {
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"internal error\"}}"
            .to_vec()
    })
}

fn guard_reason_code(reason: GuardReason) -> &'static str {
    match reason {
        GuardReason::Disabled => "mcp_guard_disabled",
        GuardReason::NotToolCall => "mcp_not_tool_call",
        GuardReason::AllowedByPolicy => "mcp_allowed_by_policy",
        GuardReason::ApprovalRequired => "mcp_approval_required",
        GuardReason::UrlAllowlistViolation => "mcp_url_allowlist_violation",
        GuardReason::CredentialLikeArgument => "mcp_credential_like_argument",
        GuardReason::EnvVarLikeArgument => "mcp_env_var_like_argument",
        GuardReason::RateLimited => "mcp_rate_limited",
        GuardReason::CrossToolFlow => "mcp_cross_tool_flow",
        GuardReason::MalformedToolCall => "mcp_malformed_tool_call",
        GuardReason::ProvenanceTaint => "mcp_provenance_taint",
    }
}
```

- [ ] **Step 6: Use forwarding-aware evaluation in proxy**

In `crates/agentenv/src/proxy_cli.rs`, replace:

```rust
agentenv_mcp::guard::evaluate_json_rpc_request(config, guard_state, &json)
```

with:

```rust
agentenv_mcp::guard::evaluate_json_rpc_request_with_forwarding(config, guard_state, &json)
```

Track the returned evaluation:

```rust
let evaluation = match decision {
    Ok(evaluation) => evaluation,
    Err(error) => {
        tracing::warn!(%error, route_id = %route.id, "egress proxy rejected malformed MCP tool call");
        let request = Request::from_parts(parts, Body::from(bytes));
        return Ok((
            Some(text_response(StatusCode::FORBIDDEN, "mcp tool denied\n")),
            request,
        ));
    }
};

emit_mcp_guard_event(state, route, &evaluation.decision);

let action = evaluation.decision.action;
let forwarded_bytes = serde_json::to_vec(&evaluation.forwarded_request)
    .context("serialize guarded MCP request")?;
let request = Request::from_parts(parts, Body::from(forwarded_bytes));
```

Pass `&evaluation.decision` into `response_for_mcp_approval_request`.

- [ ] **Step 7: Add reason-code arm**

In `mcp_guard_reason_code`, add:

```rust
agentenv_mcp::guard::GuardReason::ProvenanceTaint => "mcp_provenance_taint",
```

- [ ] **Step 8: Run focused CLI/proxy tests**

Run:

```bash
cargo test -p agentenv provenance_denial_returns_structured_json_rpc_error mcp_guard_reason_code_includes_provenance_taint
```

Expected: PASS.

- [ ] **Step 9: Commit forwarding and error changes**

```bash
git add crates/agentenv/src/mcp_guard_cli.rs crates/agentenv/src/proxy_cli.rs
git commit -m "feat: forward sanitized mcp guard requests"
```

---

### Task 5: Validate Required Provenance Mediation In Core Runtime

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`
- Test: `crates/agentenv-core/src/runtime.rs`

- [ ] **Step 1: Write failing runtime tests**

In `crates/agentenv-core/src/runtime.rs`, add tests near the existing MCP guard tests:

```rust
#[tokio::test]
async fn create_env_accepts_required_provenance_for_stdio_guarded_context() {
    let root = unique_root("agentenv-required-provenance-stdio");
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
      provenance:
        enabled: true
        required: true
        default_unannotated_source: untrusted
      tool_capabilities:
        git.commit:
          caps: [git_write]
          max_input_taint: trusted
          approval: per-call
"#;
    let tracker = Arc::new(AgentSetupTracker::default());
    let factory = AgentSetupFactory {
        tracker: Arc::clone(&tracker),
    };
    let mut credentials = super::tests_support::EmptyCredentialProvider;

    super::create_env(&options, &factory, &mut credentials, "demo", yaml)
        .await
        .expect("required stdio provenance guard is mediated");

    let endpoint_batches = tracker
        .mcp_config_endpoints
        .lock()
        .expect("mcp config endpoint tracker");
    assert_eq!(endpoint_batches.len(), 1);
    assert!(endpoint_batches[0][0]
        .url
        .contains("agentenv mcp-guard run"));
    assert!(endpoint_batches[0][0].url.contains("--config"));
    assert_eq!(
        endpoint_batches[0][0].transport,
        agentenv_proto::McpTransport::Stdio
    );
}

#[tokio::test]
async fn create_env_rejects_required_provenance_for_ssh_http_context() {
    let root = unique_root("agentenv-required-provenance-ssh-http");
    let options = RuntimeOptions {
        root: root.clone(),
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
  driver: mcp-generic
policy:
  tier: restricted
  presets: []
  mcp:
    confused_deputy_guards:
      enabled: true
      provenance:
        enabled: true
        required: true
"#;
    let tracker = Arc::new(AgentSetupTracker::default());
    tracker
        .supports_host_egress_proxy
        .store(true, Ordering::SeqCst);
    let factory = HttpMcpContextFactory {
        tracker: Arc::clone(&tracker),
        transport: agentenv_proto::McpTransport::SshHttp,
    };
    let mut credentials =
        ResolvingCredentialProvider::with_value("MCP_TOKEN", "mcp-real-provider-secret");

    let err = super::create_env(&options, &factory, &mut credentials, "demo", yaml)
        .await
        .expect_err("required provenance mediation rejects ssh-http");

    assert!(err.to_string().contains("required MCP provenance guard"));
}
```

- [ ] **Step 2: Run runtime tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core create_env_accepts_required_provenance_for_stdio_guarded_context create_env_rejects_required_provenance_for_ssh_http_context
```

Expected: compile failure naming missing `McpProvenanceConfig` fields, or `create_env_rejects_required_provenance_for_ssh_http_context` fails because required provenance validation is not implemented.

- [ ] **Step 3: Add required mediation validation**

In `crates/agentenv-core/src/runtime.rs`, add:

```rust
fn ensure_required_mcp_provenance_mediation(
    guard_config: Option<&agentenv_proto::McpGuardConfig>,
    endpoint: &agentenv_proto::McpEndpoint,
    sandbox_capabilities: &agentenv_proto::Capabilities,
) -> RuntimeResult<()> {
    let Some(provenance) = guard_config
        .and_then(|config| config.provenance.as_ref())
        .filter(|provenance| provenance.enabled && provenance.required)
    else {
        return Ok(());
    };

    let enforceable = match endpoint.transport {
        agentenv_proto::McpTransport::Stdio => true,
        agentenv_proto::McpTransport::Http | agentenv_proto::McpTransport::HttpSse => {
            supports_host_egress_proxy(sandbox_capabilities)
        }
        agentenv_proto::McpTransport::SshHttp => false,
    };

    if enforceable {
        Ok(())
    } else {
        Err(RuntimeError::Driver(DriverError::CapabilityMissing {
            capability: "required MCP provenance guard mediation".to_owned(),
        }))
    }
}
```

Call it immediately after `mcp_guard_config` is parsed and before `build_runtime_egress_proxy_plan`:

```rust
ensure_required_mcp_provenance_mediation(
    mcp_guard_config.as_ref(),
    &context_endpoint,
    &sandbox_init.capabilities,
)?;
```

- [ ] **Step 4: Run runtime tests**

Run:

```bash
cargo test -p agentenv-core create_env_accepts_required_provenance_for_stdio_guarded_context create_env_rejects_required_provenance_for_unmediated_ssh_http_context
```

Expected: PASS.

- [ ] **Step 5: Commit runtime validation**

```bash
git add crates/agentenv-core/src/runtime.rs
git commit -m "feat: require enforceable provenance mediation"
```

---

### Task 6: Add End-To-End Guard Fixtures For The Claude POC

**Files:**
- Modify: `crates/agentenv/tests/cli_behavior.rs`
- Modify: `crates/drivers/agent-claude/src/lib.rs`

- [ ] **Step 1: Write failing CLI E2E test for stdio guard**

In `crates/agentenv/tests/cli_behavior.rs`, add a test next to `mcp_guard_stdio_cli_denies_blocked_tool_call_e2e` using the same stdio framing helpers:

```rust
#[cfg(unix)]
#[test]
fn mcp_guard_stdio_cli_denies_untrusted_git_commit_e2e() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("mcp-guard.json");
    let events_db = temp.path().join("events.db");
    let upstream = temp.path().join("upstream.sh");
    let marker = temp.path().join("forwarded.marker");
    let mut config = mcp_guard_config_for_cli_e2e();
    config.provenance = Some(agentenv_proto::McpProvenanceConfig {
        enabled: true,
        required: true,
        default_unannotated_source: agentenv_proto::ProvenanceTag::Untrusted,
    });
    config.tool_capabilities = BTreeMap::from([(
        "git.commit".to_owned(),
        agentenv_proto::ToolCapabilityDeclaration {
            caps: vec![agentenv_proto::ToolCapability::GitWrite],
            max_input_taint: agentenv_proto::ProvenanceTag::Trusted,
            approval: McpApprovalMode::PerCall,
            argument_policies: Vec::new(),
        },
    )]);
    write_mcp_guard_config(&config_path, config);
    write_mcp_upstream_script(&upstream);

    let mut child = Command::new(agentenv_bin())
        .args([
            "mcp-guard",
            "run",
            "--env",
            "demo",
            "--config",
            config_path.to_str().unwrap(),
            "--events-db",
            events_db.to_str().unwrap(),
            "--stdio-upstream",
            &format!("{} {}", shell_quote(&upstream), shell_quote(&marker)),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let response_rx = spawn_mcp_frame_reader(child.stdout.take().unwrap());
    write_mcp_frame(
        child.stdin.as_mut().unwrap(),
        br#"{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"git.commit","arguments":{"message":"commit text from issue"},"_agentenv_provenance":{"/message":{"tag":"untrusted","source_kind":"github_issue","source_id":"windoliver/agentenv#43","summary":"GitHub issue body"}}}}"#,
    );
    drop(child.stdin.take());

    let response = response_rx.recv_timeout(LOCAL_HTTP_TEST_TIMEOUT).unwrap();
    wait_for_child_exit(&mut child, "mcp-guard provenance denied stdio e2e");
    let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response_json["id"], json!(43));
    assert_eq!(response_json["error"]["code"], json!(-32004));
    assert_eq!(
        response_json["error"]["data"]["reason"],
        json!("mcp_provenance_taint")
    );
    assert!(
        !marker.exists(),
        "denied provenance call must not be forwarded to upstream"
    );
}
```

- [ ] **Step 2: Write failing Claude driver mediation test**

In `crates/drivers/agent-claude/src/lib.rs`, add:

```rust
#[tokio::test]
async fn claude_renders_mediated_endpoint_supplied_by_core() {
    let driver = ClaudeDriver;
    let rendered = driver
        .render_mcp_config(RenderMcpConfigParams {
            endpoints: vec![McpEndpoint {
                transport: McpTransport::Stdio,
                url: "agentenv mcp-guard run --env demo --config /sandbox/.agentenv/mcp-guard/context.json --events-db /sandbox/.agentenv/mcp-guard/events.db --stdio-upstream agentenv-fs-mcp".to_owned(),
                headers: BTreeMap::new(),
            }],
        })
        .await
        .unwrap();

    assert!(rendered.content.contains("agentenv mcp-guard run"));
    assert!(rendered.content.contains("/sandbox/.agentenv/mcp-guard/context.json"));
}
```

- [ ] **Step 3: Run focused POC tests to verify they fail**

Run:

```bash
cargo test -p agentenv mcp_guard_stdio_cli_denies_untrusted_git_commit_e2e
cargo test -p agent-claude claude_renders_mediated_endpoint_supplied_by_core
```

Expected: `mcp_guard_stdio_cli_denies_untrusted_git_commit_e2e` fails before Tasks 3 and 4 because provenance metadata is not evaluated and structured guard error data is absent. `claude_renders_mediated_endpoint_supplied_by_core` exits 0 when the Claude driver preserves stdio endpoint strings; keep that passing test as regression coverage.

- [ ] **Step 4: Run focused POC tests after guard and CLI implementation**

Run:

```bash
cargo test -p agentenv mcp_guard_stdio_cli_denies_untrusted_git_commit_e2e
cargo test -p agent-claude claude_renders_mediated_endpoint_supplied_by_core
```

Expected: PASS.

- [ ] **Step 5: Commit POC tests**

```bash
git add crates/agentenv/tests/cli_behavior.rs crates/drivers/agent-claude/src/lib.rs
git commit -m "test: prove provenance blocks git commit"
```

---

### Task 7: Update Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `docs/BLUEPRINTS.md`

- [ ] **Step 1: Update `docs/ARCHITECTURE.md`**

Under the Policy model or MCP guard sections, add:

```markdown
### Capability / Provenance Policy

Core can mediate MCP tool calls with provenance-aware capability policy. Values are tagged as `trusted`, `tenant`, or `untrusted`; tool declarations state the capabilities a tool can exercise and the maximum input taint it accepts. Before a mediated `tools/call` is forwarded, core evaluates the argument provenance against the declaration and either forwards, denies, or routes the request to approvals.

This is core-owned security infrastructure, not a fifth pluggable axis. Context and agent drivers continue to speak MCP. Core rewrites MCP endpoints through the stdio guard or host egress proxy when a blueprint enables `policy.mcp.confused_deputy_guards`.
```

- [ ] **Step 2: Update `docs/DRIVER_PROTOCOL.md`**

Add this paragraph near the existing MCP endpoint rewrite note:

```markdown
MCP guard mediation may also attach provenance and capability policy. This is additive to the driver protocol: context drivers still return ordinary `McpEndpoint` values, while core synthesizes conservative tool capability declarations when a driver does not provide stronger metadata. If a blueprint marks provenance mediation as required, core fails before sandbox creation when the selected endpoint transport cannot be mediated.
```

- [ ] **Step 3: Update `docs/BLUEPRINTS.md`**

Extend the sample `policy.mcp.confused_deputy_guards` block with:

```yaml
      provenance:
        enabled: true
        required: true
        default_unannotated_source: untrusted
      tool_capabilities:
        git.commit:
          caps: [git_write]
          max_input_taint: trusted
          approval: per-call
```

Add a short paragraph:

```markdown
When provenance is enabled, guarded MCP calls carry redacted source evidence. A write-capable tool such as `git.commit` can be configured to accept only `trusted` input, so content from web fetches, GitHub issues, or remote MCP results is blocked or approval-routed before the tool executes.
```

- [ ] **Step 4: Run doc-adjacent tests**

Run:

```bash
cargo test -p agentenv reference_blueprints_create_status_destroy_roundtrip -- --ignored
```

Expected: ignored or skipped unless the local OpenShell prerequisites are present. If prerequisites are missing, also run:

```bash
cargo test -p agentenv verify_blueprint_succeeds_on_reference_blueprint
```

Expected: PASS.

- [ ] **Step 5: Commit docs**

```bash
git add docs/ARCHITECTURE.md docs/DRIVER_PROTOCOL.md docs/BLUEPRINTS.md
git commit -m "docs: document provenance mcp guard policy"
```

---

### Task 8: Full Verification And PR Preparation

**Files:**
- All changed files

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt
```

Expected: exit 0.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace -- -D warnings
```

Expected: exit 0 with no warnings.

- [ ] **Step 3: Run full workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: exit 0. If `tests/driver-conformance/tests/mock_driver.rs` times out once, rerun the exact target:

```bash
cargo test -p driver-conformance --test mock_driver -- --nocapture
```

Record both outputs in the PR notes. Do not call the full suite passing unless the full suite exits 0.

- [ ] **Step 4: Review changed files**

Run:

```bash
git status --short
base=$(git merge-base origin/main HEAD)
git diff --stat "$base"..HEAD
git diff --check
```

Expected: only issue #43 files are changed; `git diff --check` exits 0.

- [ ] **Step 5: Prepare PR summary**

Use this PR body:

```markdown
## Summary

- Adds provenance tags, tool capability declarations, and schema support for provenance-aware MCP guard policy.
- Extends the existing MCP guard to evaluate argument taint before forwarding capability-bearing `tools/call` requests.
- Wires stdio and HTTP MCP mediation to strip provenance metadata, surface structured errors, and route approval-worthy denials through the existing approvals path.
- Adds a Claude-oriented POC fixture proving untrusted GitHub issue content cannot reach `git.commit` without approval.

## Affected crates

- `agentenv-proto`
- `agentenv-policy`
- `agentenv-core`
- `agentenv-mcp`
- `agentenv-approvals`
- `agentenv-events`
- `agentenv`
- `agent-claude`

## Verification

- `cargo fmt`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`

## Notes

- Provenance policy is core-owned security infrastructure, not a fifth pluggable axis.
- The POC guarantee is enforced at the mediated MCP tool boundary.
```

- [ ] **Step 6: Commit any final formatting/doc fixes**

```bash
git add crates/agentenv-proto/src/types.rs crates/agentenv-proto/src/lib.rs crates/agentenv-policy/src/lib.rs crates/agentenv-policy/src/provenance.rs crates/agentenv-policy/tests/provenance_policy.rs crates/agentenv-mcp/src/guard.rs crates/agentenv/src/mcp_guard_cli.rs crates/agentenv/src/proxy_cli.rs crates/agentenv-core/src/runtime.rs crates/drivers/agent-claude/src/lib.rs docs/ARCHITECTURE.md docs/DRIVER_PROTOCOL.md docs/BLUEPRINTS.md
git commit -m "chore: finalize provenance policy implementation"
```

Skip this commit if there are no unstaged changes after verification.
