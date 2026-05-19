# OTEL GenAI Semantic Conventions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #44 by exporting agentenv activity events as current OpenTelemetry GenAI telemetry, adding blueprint OTLP config, GenAI Prometheus metrics, and a Grafana dashboard in one PR.

**Architecture:** Keep `agentenv-events::ActivityEvent` as the source of truth. Add a focused GenAI semantic mapper in `agentenv-events`, then have OTLP export and Prometheus metrics consume that mapper. Add blueprint `observability.otel.endpoint` as an additive event sink input without changing driver method names or credential transport.

**Tech Stack:** Rust 2021, serde, serde_json, rusqlite JSON queries, tokio, opentelemetry 0.31, opentelemetry_sdk 0.31, opentelemetry-otlp 0.31.1, Prometheus text exposition, Grafana dashboard JSON.

---

## File Structure

- Modify `crates/agentenv-events/Cargo.toml`: enable OTEL `trace` and `logs` features and keep the feature gated behind `otel`.
- Modify `crates/agentenv-events/src/lib.rs`: export the new `genai` module.
- Modify `crates/agentenv-events/src/activity.rs`: add `AgentTurn` and `GenAiModelCall` event kinds and serialization tests.
- Create `crates/agentenv-events/src/genai.rs`: own all GenAI semantic convention normalization and low-cardinality signal mapping.
- Modify `crates/agentenv-events/src/otel.rs`: export spans for GenAI operations and log records for agentenv lifecycle/security events.
- Modify `crates/agentenv-events/src/store.rs`: add GenAI aggregate queries for token usage, operation duration, and tool calls.
- Modify `crates/agentenv-events/src/metrics.rs`: add Prometheus GenAI metric rows and rendering.
- Modify `crates/agentenv-events/README.md`: document OTEL GenAI attributes and Prometheus labels.
- Modify `crates/agentenv-proto/src/types.rs`: add rich activity variants for `agent_turn` and `gen_ai_model_call`.
- Modify generated schema `crates/agentenv-proto/schema/driver-activity-event-params.json` by running the proto build.
- Modify `crates/agentenv-plugin/src/jsonrpc.rs`: convert the new rich activity kinds into `agentenv-events` kinds.
- Modify `crates/agentenv-core/src/blueprint.rs`: add optional `observability.otel.endpoint`.
- Modify `crates/agentenv-core/src/lifecycle.rs`: preserve observability config through blueprint resolve/freeze.
- Modify `crates/agentenv-core/tests/roundtrip.rs`: cover blueprint parsing and round-trip.
- Modify `crates/agentenv/src/main.rs`: add blueprint OTEL endpoint to event dispatcher construction and validate it through SSRF checks.
- Modify `crates/agentenv/tests/cli_behavior.rs`: cover create-time blueprint OTEL sink configuration and unsafe endpoint rejection.
- Modify `docs/ARCHITECTURE.md`: document GenAI observability mapping.
- Modify `docs/DRIVER_PROTOCOL.md`: document the additive rich activity kinds and GenAI metadata fields.
- Modify `crates/agentenv/README.md`: document blueprint and CLI OTEL configuration.
- Create `contrib/grafana/dashboards/agentenv-otel.json`: Prometheus dashboard using emitted metrics only.
- Add or modify tests in the files above.

## Task 1: Add Activity And Protocol GenAI Kinds

**Files:**
- Modify: `crates/agentenv-events/src/activity.rs`
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-plugin/src/jsonrpc.rs`
- Modify: `crates/agentenv-proto/schema/driver-activity-event-params.json`

- [ ] **Step 1: Add failing activity serialization tests**

Add this test to the existing `#[cfg(test)] mod tests` in `crates/agentenv-events/src/activity.rs`:

```rust
#[test]
fn genai_activity_kinds_serialize_to_stable_snake_case() {
    assert_eq!(
        serde_json::to_value(ActivityKind::AgentTurn).unwrap(),
        serde_json::json!("agent_turn")
    );
    assert_eq!(
        serde_json::to_value(ActivityKind::GenAiModelCall).unwrap(),
        serde_json::json!("gen_ai_model_call")
    );
}
```

- [ ] **Step 2: Add failing rich driver conversion test**

Add this test to `mod notification_tests` in `crates/agentenv-plugin/src/jsonrpc.rs`:

```rust
#[test]
fn rich_genai_activity_notification_converts_new_kinds() {
    let raw = json!({
        "jsonrpc": "2.0",
        "method": "event/activity",
        "params": {
            "ts": "2026-05-18T12:00:00Z",
            "kind": "gen_ai_model_call",
            "env": "demo",
            "actor": {"driver": "inference-openai"},
            "subject": {"request_id": "req-otel"},
            "result": "ok",
            "latency_ms": 125,
            "trace_id": "trace-genai",
            "extras": {
                "gen_ai.provider.name": "openai",
                "gen_ai.request.model": "gpt-4.1-mini",
                "gen_ai.usage.input_tokens": 12,
                "gen_ai.usage.output_tokens": 34
            }
        }
    });

    let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
    let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

    assert_eq!(event.kind, agentenv_events::ActivityKind::GenAiModelCall);
    assert_eq!(event.result, agentenv_events::ActivityResult::Ok);
    assert_eq!(event.env.as_deref(), Some("demo"));
    assert_eq!(event.trace_id, "trace-genai");
    assert_eq!(event.extras["gen_ai.provider.name"], json!("openai"));
    assert_eq!(event.extras["gen_ai.request.model"], json!("gpt-4.1-mini"));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events genai_activity_kinds_serialize_to_stable_snake_case
cargo test -p agentenv-plugin rich_genai_activity_notification_converts_new_kinds
```

Expected:

```text
error[E0599]: no variant or associated item named `AgentTurn`
error[E0599]: no variant or associated item named `GenAiModelCall`
```

- [ ] **Step 4: Add event and proto variants**

In `crates/agentenv-events/src/activity.rs`, add the new variants after `McpToolCall`:

```rust
    McpToolCall,
    AgentTurn,
    GenAiModelCall,
    PolicyApplied,
```

In `crates/agentenv-proto/src/types.rs`, add matching rich activity variants after `McpToolCall`:

```rust
    McpToolCall,
    AgentTurn,
    GenAiModelCall,
    PolicyApplied,
```

In `crates/agentenv-plugin/src/jsonrpc.rs`, update `rich_activity_kind_to_event_kind`:

```rust
        agentenv_proto::RichActivityKind::McpToolCall => EventActivityKind::McpToolCall,
        agentenv_proto::RichActivityKind::AgentTurn => EventActivityKind::AgentTurn,
        agentenv_proto::RichActivityKind::GenAiModelCall => EventActivityKind::GenAiModelCall,
        agentenv_proto::RichActivityKind::PolicyApplied => EventActivityKind::PolicyApplied,
```

- [ ] **Step 5: Add proto round-trip test and regenerate schema**

Add this test to `#[cfg(test)] mod tests` in `crates/agentenv-proto/src/types.rs`:

```rust
#[test]
fn rich_activity_genai_kinds_round_trip() {
    let agent_turn: RichActivityKind = serde_json::from_value(serde_json::json!("agent_turn")).unwrap();
    let model_call: RichActivityKind =
        serde_json::from_value(serde_json::json!("gen_ai_model_call")).unwrap();

    assert_eq!(agent_turn, RichActivityKind::AgentTurn);
    assert_eq!(model_call, RichActivityKind::GenAiModelCall);
    assert_eq!(
        serde_json::to_value(RichActivityKind::AgentTurn).unwrap(),
        serde_json::json!("agent_turn")
    );
    assert_eq!(
        serde_json::to_value(RichActivityKind::GenAiModelCall).unwrap(),
        serde_json::json!("gen_ai_model_call")
    );
}
```

Run:

```bash
cargo test -p agentenv-proto rich_activity_genai_kinds_round_trip
```

Expected: PASS and `crates/agentenv-proto/schema/driver-activity-event-params.json` includes `agent_turn` and `gen_ai_model_call`.

- [ ] **Step 6: Run focused tests**

Run:

```bash
cargo test -p agentenv-events genai_activity_kinds_serialize_to_stable_snake_case
cargo test -p agentenv-plugin rich_genai_activity_notification_converts_new_kinds
```

Expected: both commands PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/agentenv-events/src/activity.rs crates/agentenv-proto/src/types.rs crates/agentenv-plugin/src/jsonrpc.rs crates/agentenv-proto/schema/driver-activity-event-params.json
git commit -m "feat: add genai activity event kinds"
```

## Task 2: Add GenAI Semantic Mapping

**Files:**
- Create: `crates/agentenv-events/src/genai.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing mapper tests**

Create `crates/agentenv-events/src/genai.rs` with this test module first:

```rust
use std::collections::BTreeMap;

use serde_json::Value;

use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: ActivityKind) -> ActivityEvent {
        ActivityEvent::new("2026-05-18T12:00:00Z", kind, ActivityResult::Ok, "trace-genai")
            .with_env("demo")
    }

    #[test]
    fn normalizes_legacy_gen_ai_system_to_provider_name() {
        let signal = map_event_to_genai_signal(
            &event(ActivityKind::GenAiModelCall)
                .with_extra("gen_ai.system", serde_json::json!("openai"))
                .with_extra("gen_ai.request.model", serde_json::json!("gpt-4.1-mini")),
        )
        .unwrap();

        assert_eq!(signal.kind, OtelGenAiSignalKind::Span);
        assert_eq!(signal.operation_name.as_deref(), Some("chat"));
        assert_eq!(signal.attributes["gen_ai.provider.name"], OtelAttributeValue::String("openai".to_owned()));
        assert_eq!(signal.attributes["gen_ai.request.model"], OtelAttributeValue::String("gpt-4.1-mini".to_owned()));
        assert!(!signal.attributes.contains_key("gen_ai.system"));
    }

    #[test]
    fn maps_mcp_tool_call_to_execute_tool_span() {
        let signal = map_event_to_genai_signal(
            &event(ActivityKind::McpToolCall)
                .with_subject_value("tool", serde_json::json!("filesystem.read"))
                .with_subject_value("tool_call_id", serde_json::json!("toolu_123")),
        )
        .unwrap();

        assert_eq!(signal.kind, OtelGenAiSignalKind::Span);
        assert_eq!(signal.name, "gen_ai.execute_tool filesystem.read");
        assert_eq!(signal.operation_name.as_deref(), Some("execute_tool"));
        assert_eq!(signal.attributes["gen_ai.tool.name"], OtelAttributeValue::String("filesystem.read".to_owned()));
        assert_eq!(signal.attributes["gen_ai.tool.call.id"], OtelAttributeValue::String("toolu_123".to_owned()));
    }

    #[test]
    fn maps_agent_turn_to_invoke_agent_span() {
        let signal = map_event_to_genai_signal(
            &event(ActivityKind::AgentTurn)
                .with_extra("gen_ai.agent.name", serde_json::json!("codex"))
                .with_latency_ms(250),
        )
        .unwrap();

        assert_eq!(signal.kind, OtelGenAiSignalKind::Span);
        assert_eq!(signal.name, "gen_ai.invoke_agent codex");
        assert_eq!(signal.operation_name.as_deref(), Some("invoke_agent"));
        assert_eq!(signal.duration_ms, Some(250));
        assert_eq!(signal.attributes["gen_ai.agent.name"], OtelAttributeValue::String("codex".to_owned()));
    }

    #[test]
    fn maps_token_usage_as_integer_attributes() {
        let signal = map_event_to_genai_signal(
            &event(ActivityKind::GenAiModelCall)
                .with_extra("gen_ai.provider.name", serde_json::json!("anthropic"))
                .with_extra("gen_ai.request.model", serde_json::json!("claude-sonnet-4-5"))
                .with_extra("gen_ai.usage.input_tokens", serde_json::json!(123))
                .with_extra("gen_ai.usage.output_tokens", serde_json::json!(45))
                .with_extra("gen_ai.response.finish_reasons", serde_json::json!(["stop"])),
        )
        .unwrap();

        assert_eq!(signal.attributes["gen_ai.usage.input_tokens"], OtelAttributeValue::I64(123));
        assert_eq!(signal.attributes["gen_ai.usage.output_tokens"], OtelAttributeValue::I64(45));
        assert_eq!(
            signal.attributes["gen_ai.response.finish_reasons"],
            OtelAttributeValue::StringArray(vec!["stop".to_owned()])
        );
    }
}
```

- [ ] **Step 2: Export the module and verify failure**

Add to `crates/agentenv-events/src/lib.rs`:

```rust
pub mod genai;
```

Run:

```bash
cargo test -p agentenv-events genai::
```

Expected: FAIL with missing `OtelGenAiSignalKind`, `OtelAttributeValue`, and `map_event_to_genai_signal`.

- [ ] **Step 3: Implement mapper types and constants**

Add this code above the test module in `crates/agentenv-events/src/genai.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtelGenAiSignalKind {
    Span,
    SpanEvent,
    LogRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtelSpanKindHint {
    Client,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtelSignalStatus {
    Ok,
    Error,
    Denied,
    PendingApproval,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OtelAttributeValue {
    String(String),
    I64(i64),
    F64(f64),
    Bool(bool),
    StringArray(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct OtelGenAiSignal {
    pub kind: OtelGenAiSignalKind,
    pub name: String,
    pub span_kind: OtelSpanKindHint,
    pub operation_name: Option<String>,
    pub duration_ms: Option<u64>,
    pub status: OtelSignalStatus,
    pub attributes: BTreeMap<String, OtelAttributeValue>,
}

const ATTR_OPERATION_NAME: &str = "gen_ai.operation.name";
const ATTR_PROVIDER_NAME: &str = "gen_ai.provider.name";
const ATTR_REQUEST_MODEL: &str = "gen_ai.request.model";
const ATTR_RESPONSE_MODEL: &str = "gen_ai.response.model";
const ATTR_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
const ATTR_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
const ATTR_FINISH_REASONS: &str = "gen_ai.response.finish_reasons";
const ATTR_TOOL_NAME: &str = "gen_ai.tool.name";
const ATTR_TOOL_CALL_ID: &str = "gen_ai.tool.call.id";
const ATTR_AGENT_NAME: &str = "gen_ai.agent.name";
const ATTR_AGENT_VERSION: &str = "gen_ai.agent.version";
```

- [ ] **Step 4: Implement event mapping**

Add this implementation below the constants:

```rust
pub fn map_event_to_genai_signal(event: &ActivityEvent) -> Option<OtelGenAiSignal> {
    let event = event.clone().redacted();
    let mut attributes = base_attributes(&event);
    let status = signal_status(event.result);

    match event.kind {
        ActivityKind::McpToolCall => {
            let tool = string_from_maps(&event, &[ATTR_TOOL_NAME, "tool", "name"])
                .unwrap_or_else(|| "unknown".to_owned());
            let call_id = string_from_maps(&event, &[ATTR_TOOL_CALL_ID, "tool_call_id", "call_id"]);
            attributes.insert(
                ATTR_OPERATION_NAME.to_owned(),
                OtelAttributeValue::String("execute_tool".to_owned()),
            );
            attributes.insert(ATTR_TOOL_NAME.to_owned(), OtelAttributeValue::String(tool.clone()));
            if let Some(call_id) = call_id {
                attributes.insert(ATTR_TOOL_CALL_ID.to_owned(), OtelAttributeValue::String(call_id));
            }
            Some(OtelGenAiSignal {
                kind: OtelGenAiSignalKind::Span,
                name: format!("gen_ai.execute_tool {tool}"),
                span_kind: OtelSpanKindHint::Internal,
                operation_name: Some("execute_tool".to_owned()),
                duration_ms: event.latency_ms,
                status,
                attributes,
            })
        }
        ActivityKind::AgentTurn => {
            let agent = string_from_maps(&event, &[ATTR_AGENT_NAME, "agent"])
                .or_else(|| event.env.clone())
                .unwrap_or_else(|| "agent".to_owned());
            attributes.insert(
                ATTR_OPERATION_NAME.to_owned(),
                OtelAttributeValue::String("invoke_agent".to_owned()),
            );
            attributes.insert(ATTR_AGENT_NAME.to_owned(), OtelAttributeValue::String(agent.clone()));
            if let Some(version) = string_from_maps(&event, &[ATTR_AGENT_VERSION, "agent_version"]) {
                attributes.insert(ATTR_AGENT_VERSION.to_owned(), OtelAttributeValue::String(version));
            }
            Some(OtelGenAiSignal {
                kind: OtelGenAiSignalKind::Span,
                name: format!("gen_ai.invoke_agent {agent}"),
                span_kind: OtelSpanKindHint::Internal,
                operation_name: Some("invoke_agent".to_owned()),
                duration_ms: event.latency_ms,
                status,
                attributes,
            })
        }
        ActivityKind::GenAiModelCall => {
            copy_genai_attributes(&event, &mut attributes);
            attributes
                .entry(ATTR_OPERATION_NAME.to_owned())
                .or_insert_with(|| OtelAttributeValue::String("chat".to_owned()));
            let operation = attribute_string(&attributes, ATTR_OPERATION_NAME)
                .unwrap_or_else(|| "chat".to_owned());
            Some(OtelGenAiSignal {
                kind: OtelGenAiSignalKind::Span,
                name: format!("gen_ai.{operation}"),
                span_kind: OtelSpanKindHint::Client,
                operation_name: Some(operation),
                duration_ms: event.latency_ms,
                status,
                attributes,
            })
        }
        ActivityKind::ApprovalRequested
        | ActivityKind::ApprovalDecided
        | ActivityKind::EgressDenied
        | ActivityKind::PolicyApplied => {
            add_agentenv_security_attributes(&event, &mut attributes);
            Some(OtelGenAiSignal {
                kind: OtelGenAiSignalKind::LogRecord,
                name: format!("agentenv.{}", activity_kind_name(event.kind)),
                span_kind: OtelSpanKindHint::Internal,
                operation_name: None,
                duration_ms: event.latency_ms,
                status,
                attributes,
            })
        }
        _ => {
            add_agentenv_security_attributes(&event, &mut attributes);
            Some(OtelGenAiSignal {
                kind: OtelGenAiSignalKind::LogRecord,
                name: format!("agentenv.{}", activity_kind_name(event.kind)),
                span_kind: OtelSpanKindHint::Internal,
                operation_name: None,
                duration_ms: event.latency_ms,
                status,
                attributes,
            })
        }
    }
}
```

- [ ] **Step 5: Implement helper functions**

Add these helpers in `crates/agentenv-events/src/genai.rs`:

```rust
fn base_attributes(event: &ActivityEvent) -> BTreeMap<String, OtelAttributeValue> {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "agentenv.event.kind".to_owned(),
        OtelAttributeValue::String(activity_kind_name(event.kind).to_owned()),
    );
    attributes.insert(
        "agentenv.event.result".to_owned(),
        OtelAttributeValue::String(activity_result_name(event.result).to_owned()),
    );
    attributes.insert(
        "agentenv.trace_id".to_owned(),
        OtelAttributeValue::String(event.trace_id.clone()),
    );
    if let Some(env) = &event.env {
        attributes.insert("agentenv.env".to_owned(), OtelAttributeValue::String(env.clone()));
    }
    if let Some(reason) = &event.reason_code {
        attributes.insert(
            "agentenv.reason_code".to_owned(),
            OtelAttributeValue::String(reason.clone()),
        );
    }
    attributes
}

fn copy_genai_attributes(event: &ActivityEvent, attributes: &mut BTreeMap<String, OtelAttributeValue>) {
    copy_string_attr(event, attributes, ATTR_PROVIDER_NAME, &[ATTR_PROVIDER_NAME, "gen_ai.system", "provider"]);
    copy_string_attr(event, attributes, ATTR_OPERATION_NAME, &[ATTR_OPERATION_NAME, "operation"]);
    copy_string_attr(event, attributes, ATTR_REQUEST_MODEL, &[ATTR_REQUEST_MODEL, "model", "request_model"]);
    copy_string_attr(event, attributes, ATTR_RESPONSE_MODEL, &[ATTR_RESPONSE_MODEL, "response_model"]);
    copy_i64_attr(event, attributes, ATTR_INPUT_TOKENS, &[ATTR_INPUT_TOKENS, "input_tokens"]);
    copy_i64_attr(event, attributes, ATTR_OUTPUT_TOKENS, &[ATTR_OUTPUT_TOKENS, "output_tokens"]);
    copy_string_array_attr(event, attributes, ATTR_FINISH_REASONS, &[ATTR_FINISH_REASONS, "finish_reasons"]);
}

fn add_agentenv_security_attributes(event: &ActivityEvent, attributes: &mut BTreeMap<String, OtelAttributeValue>) {
    if event.kind == ActivityKind::EgressDenied {
        attributes.insert("agentenv.egress.denied".to_owned(), OtelAttributeValue::Bool(true));
    }
    if matches!(event.kind, ActivityKind::ApprovalRequested | ActivityKind::ApprovalDecided) {
        if let Some(kind) = string_from_maps(event, &["kind", "approval_kind"]) {
            attributes.insert("agentenv.approval.kind".to_owned(), OtelAttributeValue::String(kind));
        }
        if let Some(request_id) = string_from_maps(event, &["request_id"]) {
            attributes.insert(
                "agentenv.approval.request_id".to_owned(),
                OtelAttributeValue::String(request_id),
            );
        }
    }
    if event.kind == ActivityKind::PolicyApplied {
        let hot_reloaded = bool_from_maps(event, &["hot_reloaded"]).unwrap_or(false);
        attributes.insert("agentenv.policy.reload".to_owned(), OtelAttributeValue::Bool(hot_reloaded));
    }
}

fn copy_string_attr(
    event: &ActivityEvent,
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    canonical: &str,
    keys: &[&str],
) {
    if let Some(value) = string_from_maps(event, keys) {
        attributes.insert(canonical.to_owned(), OtelAttributeValue::String(value));
    }
}

fn copy_i64_attr(
    event: &ActivityEvent,
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    canonical: &str,
    keys: &[&str],
) {
    if let Some(value) = i64_from_maps(event, keys) {
        attributes.insert(canonical.to_owned(), OtelAttributeValue::I64(value));
    }
}

fn copy_string_array_attr(
    event: &ActivityEvent,
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    canonical: &str,
    keys: &[&str],
) {
    if let Some(value) = string_array_from_maps(event, keys) {
        attributes.insert(canonical.to_owned(), OtelAttributeValue::StringArray(value));
    }
}

fn string_from_maps(event: &ActivityEvent, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value_from_event(event, key))
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
}

fn i64_from_maps(event: &ActivityEvent, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| value_from_event(event, key))
        .and_then(Value::as_i64)
}

fn bool_from_maps(event: &ActivityEvent, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| value_from_event(event, key))
        .and_then(Value::as_bool)
}

fn string_array_from_maps(event: &ActivityEvent, keys: &[&str]) -> Option<Vec<String>> {
    keys.iter().find_map(|key| {
        value_from_event(event, key).and_then(|value| {
            value.as_array().map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
        })
    })
}

fn value_from_event<'a>(event: &'a ActivityEvent, key: &str) -> Option<&'a Value> {
    event
        .extras
        .get(key)
        .or_else(|| event.subject.get(key))
        .or_else(|| event.actor.get(key))
}

fn attribute_string(attributes: &BTreeMap<String, OtelAttributeValue>, key: &str) -> Option<String> {
    match attributes.get(key) {
        Some(OtelAttributeValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn signal_status(result: ActivityResult) -> OtelSignalStatus {
    match result {
        ActivityResult::Ok => OtelSignalStatus::Ok,
        ActivityResult::Error => OtelSignalStatus::Error,
        ActivityResult::Denied => OtelSignalStatus::Denied,
        ActivityResult::PendingApproval => OtelSignalStatus::PendingApproval,
    }
}

pub fn activity_kind_name(kind: ActivityKind) -> &'static str {
    match kind {
        ActivityKind::SandboxCreate => "sandbox_create",
        ActivityKind::SandboxDestroy => "sandbox_destroy",
        ActivityKind::Exec => "exec",
        ActivityKind::EgressAllowed => "egress_allowed",
        ActivityKind::EgressDenied => "egress_denied",
        ActivityKind::McpToolCall => "mcp_tool_call",
        ActivityKind::AgentTurn => "agent_turn",
        ActivityKind::GenAiModelCall => "gen_ai_model_call",
        ActivityKind::PolicyApplied => "policy_applied",
        ActivityKind::CredentialInjected => "credential_injected",
        ActivityKind::CredentialSet => "credential_set",
        ActivityKind::CredentialReset => "credential_reset",
        ActivityKind::Auth => "auth",
        ActivityKind::ApprovalRequested => "approval_requested",
        ActivityKind::ApprovalDecided => "approval_decided",
        ActivityKind::SpawnRequested => "spawn_requested",
        ActivityKind::SpawnQueued => "spawn_queued",
        ActivityKind::SpawnAdmitted => "spawn_admitted",
        ActivityKind::SpawnRejected => "spawn_rejected",
        ActivityKind::SpawnStarted => "spawn_started",
        ActivityKind::SpawnReady => "spawn_ready",
        ActivityKind::BuildOneflightHit => "build_oneflight_hit",
        ActivityKind::BuildOneflightMiss => "build_oneflight_miss",
        ActivityKind::BuildQueueDepth => "build_queue_depth",
        ActivityKind::Log => "log",
    }
}

fn activity_result_name(result: ActivityResult) -> &'static str {
    match result {
        ActivityResult::Ok => "ok",
        ActivityResult::Error => "error",
        ActivityResult::Denied => "denied",
        ActivityResult::PendingApproval => "pending_approval",
    }
}
```

- [ ] **Step 6: Run mapper tests**

Run:

```bash
cargo test -p agentenv-events genai::
```

Expected: all GenAI mapper tests PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/agentenv-events/src/lib.rs crates/agentenv-events/src/genai.rs
git commit -m "feat: map activity events to otel genai signals"
```

## Task 3: Add GenAI Prometheus Metrics

**Files:**
- Modify: `crates/agentenv-events/src/store.rs`
- Modify: `crates/agentenv-events/src/metrics.rs`

- [ ] **Step 1: Add failing store aggregate tests**

Add this test to `#[cfg(test)] mod tests` in `crates/agentenv-events/src/store.rs`:

```rust
#[test]
fn sqlite_store_aggregates_genai_usage_duration_and_tool_calls() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "2026-05-18T12:00:00Z",
                ActivityKind::GenAiModelCall,
                "demo",
                ActivityResult::Ok,
            )
            .with_latency_ms(250)
            .with_extra("gen_ai.provider.name", serde_json::json!("openai"))
            .with_extra("gen_ai.operation.name", serde_json::json!("chat"))
            .with_extra("gen_ai.request.model", serde_json::json!("gpt-4.1-mini"))
            .with_extra("gen_ai.usage.input_tokens", serde_json::json!(12))
            .with_extra("gen_ai.usage.output_tokens", serde_json::json!(34)),
            event(
                "2026-05-18T12:00:01Z",
                ActivityKind::McpToolCall,
                "demo",
                ActivityResult::Error,
            )
            .with_subject_value("tool", serde_json::json!("filesystem.read")),
        ])
        .unwrap();

    let usage = store.genai_token_usage_rows().unwrap();
    assert!(usage.iter().any(|row| {
        row.provider == "openai"
            && row.operation == "chat"
            && row.model == "gpt-4.1-mini"
            && row.token_type == "input"
            && row.tokens == 12
    }));
    assert!(usage.iter().any(|row| row.token_type == "output" && row.tokens == 34));

    let duration = store.genai_operation_duration_rows().unwrap();
    assert_eq!(duration[0].duration_ms, 250);

    let tools = store.genai_tool_calls_by_tool_env_result().unwrap();
    assert_eq!(tools[0].tool, "filesystem.read");
    assert_eq!(tools[0].result, ActivityResult::Error);
}
```

- [ ] **Step 2: Run store test to verify failure**

Run:

```bash
cargo test -p agentenv-events sqlite_store_aggregates_genai_usage_duration_and_tool_calls
```

Expected: FAIL with missing aggregate row types and methods.

- [ ] **Step 3: Add store row types**

In `crates/agentenv-events/src/store.rs`, add these structs near `McpToolCount`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenAiTokenUsageRow {
    pub provider: String,
    pub operation: String,
    pub model: String,
    pub token_type: String,
    pub tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenAiOperationDurationRow {
    pub provider: String,
    pub operation: String,
    pub model: String,
    pub duration_ms: u64,
}
```

- [ ] **Step 4: Add store aggregate methods**

Add these methods to `impl SqliteEventStore` after `mcp_tool_calls_by_tool_env_result`:

```rust
pub fn genai_token_usage_rows(&self) -> StoreResult<Vec<GenAiTokenUsageRow>> {
    let conn = self.connection()?;
    let model_call = enum_to_db_string(ActivityKind::GenAiModelCall, "kind")?;
    let mut stmt = conn.prepare(
        r#"
        SELECT
            COALESCE(json_extract(extras_json, '$."gen_ai.provider.name"'), json_extract(extras_json, '$."gen_ai.system"'), 'unknown') AS provider,
            COALESCE(json_extract(extras_json, '$."gen_ai.operation.name"'), 'chat') AS operation,
            COALESCE(json_extract(extras_json, '$."gen_ai.request.model"'), 'unknown') AS model,
            CASE usage.token_type WHEN 'input' THEN 'input' ELSE 'output' END AS token_type,
            usage.tokens
        FROM activity_events
        JOIN (
            SELECT id, 'input' AS token_type,
                   CASE WHEN json_type(extras_json, '$."gen_ai.usage.input_tokens"') = 'integer'
                        THEN json_extract(extras_json, '$."gen_ai.usage.input_tokens"')
                        ELSE 0 END AS tokens
            FROM activity_events
            UNION ALL
            SELECT id, 'output' AS token_type,
                   CASE WHEN json_type(extras_json, '$."gen_ai.usage.output_tokens"') = 'integer'
                        THEN json_extract(extras_json, '$."gen_ai.usage.output_tokens"')
                        ELSE 0 END AS tokens
            FROM activity_events
        ) AS usage ON usage.id = activity_events.id
        WHERE kind = ?1 AND usage.tokens > 0
        ORDER BY provider ASC, operation ASC, model ASC, token_type ASC
        "#,
    )?;
    let rows = stmt.query_map(params![model_call], |row| {
        let tokens = row.get::<_, i64>(4)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            tokens,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (provider, operation, model, token_type, tokens) = row?;
        out.push(GenAiTokenUsageRow {
            provider,
            operation,
            model,
            token_type,
            tokens: count_to_u64(tokens)?,
        });
    }
    Ok(out)
}

pub fn genai_operation_duration_rows(&self) -> StoreResult<Vec<GenAiOperationDurationRow>> {
    let conn = self.connection()?;
    let model_call = enum_to_db_string(ActivityKind::GenAiModelCall, "kind")?;
    let agent_turn = enum_to_db_string(ActivityKind::AgentTurn, "kind")?;
    let tool_call = enum_to_db_string(ActivityKind::McpToolCall, "kind")?;
    let mut stmt = conn.prepare(
        r#"
        SELECT
            COALESCE(json_extract(extras_json, '$."gen_ai.provider.name"'), json_extract(extras_json, '$."gen_ai.system"'), 'agentenv') AS provider,
            COALESCE(json_extract(extras_json, '$."gen_ai.operation.name"'),
                CASE kind
                    WHEN ?2 THEN 'invoke_agent'
                    WHEN ?3 THEN 'execute_tool'
                    ELSE 'chat'
                END
            ) AS operation,
            COALESCE(json_extract(extras_json, '$."gen_ai.request.model"'), 'unknown') AS model,
            latency_ms
        FROM activity_events
        WHERE latency_ms IS NOT NULL
          AND kind IN (?1, ?2, ?3)
        ORDER BY provider ASC, operation ASC, model ASC, latency_ms ASC
        "#,
    )?;
    let rows = stmt.query_map(params![model_call, agent_turn, tool_call], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (provider, operation, model, duration_ms) = row?;
        if duration_ms < 0 {
            return Err(StoreError::NegativeLatency(duration_ms));
        }
        out.push(GenAiOperationDurationRow {
            provider,
            operation,
            model,
            duration_ms: u64::try_from(duration_ms).map_err(|_| StoreError::NegativeLatency(duration_ms))?,
        });
    }
    Ok(out)
}

pub fn genai_tool_calls_by_tool_env_result(&self) -> StoreResult<Vec<McpToolCount>> {
    self.mcp_tool_calls_by_tool_env_result()
}
```

- [ ] **Step 5: Add failing metrics render test**

Add assertions to `prometheus_render_includes_required_series` in `crates/agentenv-events/src/metrics.rs` by inserting the new metric names in the `series` array:

```rust
            "gen_ai_client_token_usage",
            "gen_ai_client_operation_duration",
            "agentenv_gen_ai_tool_calls_total",
```

Add this test to `crates/agentenv-events/src/metrics.rs`:

```rust
#[test]
fn prometheus_render_includes_genai_metrics() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "2026-05-18T12:00:00Z",
                ActivityKind::GenAiModelCall,
                ActivityResult::Ok,
            )
            .with_env("demo")
            .with_latency_ms(250)
            .with_extra("gen_ai.provider.name", serde_json::json!("openai"))
            .with_extra("gen_ai.operation.name", serde_json::json!("chat"))
            .with_extra("gen_ai.request.model", serde_json::json!("gpt-4.1-mini"))
            .with_extra("gen_ai.usage.input_tokens", serde_json::json!(12))
            .with_extra("gen_ai.usage.output_tokens", serde_json::json!(34)),
            event(
                "2026-05-18T12:00:01Z",
                ActivityKind::McpToolCall,
                ActivityResult::Error,
            )
            .with_env("demo")
            .with_subject_value("tool", serde_json::json!("filesystem.read")),
        ])
        .unwrap();

    let snapshot = MetricsSnapshot::from_store(&store, &[]).unwrap();
    let rendered = render_prometheus(&snapshot);

    assert!(rendered.contains("gen_ai_client_token_usage_bucket"));
    assert!(rendered.contains("gen_ai_client_operation_duration_bucket"));
    assert!(rendered.contains("agentenv_gen_ai_tool_calls_total"));
    assert!(rendered.contains("gen_ai_provider_name=\"openai\""));
    assert!(rendered.contains("gen_ai_token_type=\"input\""));
    assert!(rendered.contains("gen_ai_tool_name=\"filesystem.read\""));
}
```

- [ ] **Step 6: Run metrics test to verify failure**

Run:

```bash
cargo test -p agentenv-events prometheus_render_includes_genai_metrics
```

Expected: FAIL because `MetricsSnapshot` has no GenAI fields and the renderer lacks GenAI output.

- [ ] **Step 7: Implement metrics snapshot fields and renderers**

In `crates/agentenv-events/src/metrics.rs`, add row structs:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenAiTokenUsageBucketMetric {
    pub provider: String,
    pub operation: String,
    pub model: String,
    pub token_type: String,
    pub le: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenAiTokenUsageSummaryMetric {
    pub provider: String,
    pub operation: String,
    pub model: String,
    pub token_type: String,
    pub sum: u64,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenAiOperationDurationBucketMetric {
    pub provider: String,
    pub operation: String,
    pub model: String,
    pub le: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenAiOperationDurationSummaryMetric {
    pub provider: String,
    pub operation: String,
    pub model: String,
    pub sum_seconds: f64,
    pub count: u64,
}
```

Add fields to `MetricsSnapshot`:

```rust
    pub genai_token_usage: Vec<GenAiTokenUsageBucketMetric>,
    pub genai_token_usage_summary: Vec<GenAiTokenUsageSummaryMetric>,
    pub genai_operation_duration: Vec<GenAiOperationDurationBucketMetric>,
    pub genai_operation_duration_summary: Vec<GenAiOperationDurationSummaryMetric>,
    pub genai_tool_calls_total: Vec<McpToolMetric>,
```

Add constants:

```rust
const GENAI_TOKEN_BUCKETS: [u64; 14] = [
    1, 4, 16, 64, 256, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576,
    4_194_304, 16_777_216, 67_108_864,
];
```

In `MetricsSnapshot::from_store`, populate the fields:

```rust
let (genai_token_usage, genai_token_usage_summary) =
    genai_token_usage_metrics(store.genai_token_usage_rows()?);
let (genai_operation_duration, genai_operation_duration_summary) =
    genai_operation_duration_metrics(store.genai_operation_duration_rows()?);
let genai_tool_calls_total = store
    .genai_tool_calls_by_tool_env_result()?
    .into_iter()
    .map(|row| McpToolMetric {
        tool: row.tool,
        env: row.env,
        result: activity_result_label(row.result),
        count: row.count,
    })
    .collect();
```

Add the fields to the `Ok(Self { ... })` initializer.

- [ ] **Step 8: Add metric helper functions**

Add these helpers near `latency_metrics`:

```rust
fn genai_token_usage_metrics(
    rows: Vec<crate::store::GenAiTokenUsageRow>,
) -> (Vec<GenAiTokenUsageBucketMetric>, Vec<GenAiTokenUsageSummaryMetric>) {
    let mut grouped: BTreeMap<(String, String, String, String), Vec<u64>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.provider, row.operation, row.model, row.token_type))
            .or_default()
            .push(row.tokens);
    }

    let mut buckets = Vec::new();
    let mut summaries = Vec::new();
    for ((provider, operation, model, token_type), values) in grouped {
        let count = values.len() as u64;
        let sum = values.iter().sum::<u64>();
        summaries.push(GenAiTokenUsageSummaryMetric {
            provider: provider.clone(),
            operation: operation.clone(),
            model: model.clone(),
            token_type: token_type.clone(),
            sum,
            count,
        });
        for boundary in GENAI_TOKEN_BUCKETS {
            buckets.push(GenAiTokenUsageBucketMetric {
                provider: provider.clone(),
                operation: operation.clone(),
                model: model.clone(),
                token_type: token_type.clone(),
                le: boundary.to_string(),
                count: values.iter().filter(|value| **value <= boundary).count() as u64,
            });
        }
        buckets.push(GenAiTokenUsageBucketMetric {
            provider,
            operation,
            model,
            token_type,
            le: "+Inf".to_owned(),
            count,
        });
    }
    (buckets, summaries)
}

fn genai_operation_duration_metrics(
    rows: Vec<crate::store::GenAiOperationDurationRow>,
) -> (
    Vec<GenAiOperationDurationBucketMetric>,
    Vec<GenAiOperationDurationSummaryMetric>,
) {
    let mut grouped: BTreeMap<(String, String, String), Vec<u64>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.provider, row.operation, row.model))
            .or_default()
            .push(row.duration_ms);
    }

    let mut buckets = Vec::new();
    let mut summaries = Vec::new();
    for ((provider, operation, model), values) in grouped {
        let count = values.len() as u64;
        let sum_seconds = values.iter().sum::<u64>() as f64 / 1000.0;
        summaries.push(GenAiOperationDurationSummaryMetric {
            provider: provider.clone(),
            operation: operation.clone(),
            model: model.clone(),
            sum_seconds,
            count,
        });
        for (label, limit_ms) in LATENCY_BUCKET_LABELS.iter().zip(LATENCY_BUCKET_MILLIS) {
            buckets.push(GenAiOperationDurationBucketMetric {
                provider: provider.clone(),
                operation: operation.clone(),
                model: model.clone(),
                le: (*label).to_owned(),
                count: values
                    .iter()
                    .filter(|duration_ms| match limit_ms {
                        Some(limit_ms) => **duration_ms <= limit_ms,
                        None => true,
                    })
                    .count() as u64,
            });
        }
    }
    (buckets, summaries)
}
```

- [ ] **Step 9: Render GenAI metrics**

In `render_prometheus`, after `agentenv_mcp_tool_calls_total`, render:

```rust
render_help_type(
    &mut output,
    "gen_ai_client_token_usage",
    "Token usage from GenAI model calls.",
    "histogram",
);
for row in &snapshot.genai_token_usage {
    render_sample(
        &mut output,
        "gen_ai_client_token_usage_bucket",
        &[
            ("gen_ai_provider_name", Some(row.provider.as_str())),
            ("gen_ai_operation_name", Some(row.operation.as_str())),
            ("gen_ai_request_model", Some(row.model.as_str())),
            ("gen_ai_token_type", Some(row.token_type.as_str())),
            ("le", Some(row.le.as_str())),
        ],
        row.count,
    );
}
for row in &snapshot.genai_token_usage_summary {
    render_sample(
        &mut output,
        "gen_ai_client_token_usage_sum",
        &[
            ("gen_ai_provider_name", Some(row.provider.as_str())),
            ("gen_ai_operation_name", Some(row.operation.as_str())),
            ("gen_ai_request_model", Some(row.model.as_str())),
            ("gen_ai_token_type", Some(row.token_type.as_str())),
        ],
        row.sum,
    );
    render_sample(
        &mut output,
        "gen_ai_client_token_usage_count",
        &[
            ("gen_ai_provider_name", Some(row.provider.as_str())),
            ("gen_ai_operation_name", Some(row.operation.as_str())),
            ("gen_ai_request_model", Some(row.model.as_str())),
            ("gen_ai_token_type", Some(row.token_type.as_str())),
        ],
        row.count,
    );
}

render_help_type(
    &mut output,
    "gen_ai_client_operation_duration",
    "GenAI operation duration in seconds.",
    "histogram",
);
for row in &snapshot.genai_operation_duration {
    render_sample(
        &mut output,
        "gen_ai_client_operation_duration_bucket",
        &[
            ("gen_ai_provider_name", Some(row.provider.as_str())),
            ("gen_ai_operation_name", Some(row.operation.as_str())),
            ("gen_ai_request_model", Some(row.model.as_str())),
            ("le", Some(row.le.as_str())),
        ],
        row.count,
    );
}
for row in &snapshot.genai_operation_duration_summary {
    render_sample_float(
        &mut output,
        "gen_ai_client_operation_duration_sum",
        &[
            ("gen_ai_provider_name", Some(row.provider.as_str())),
            ("gen_ai_operation_name", Some(row.operation.as_str())),
            ("gen_ai_request_model", Some(row.model.as_str())),
        ],
        row.sum_seconds,
    );
    render_sample(
        &mut output,
        "gen_ai_client_operation_duration_count",
        &[
            ("gen_ai_provider_name", Some(row.provider.as_str())),
            ("gen_ai_operation_name", Some(row.operation.as_str())),
            ("gen_ai_request_model", Some(row.model.as_str())),
        ],
        row.count,
    );
}

render_help_type(
    &mut output,
    "agentenv_gen_ai_tool_calls_total",
    "Total GenAI tool calls by tool, environment, and result.",
    "counter",
);
for row in &snapshot.genai_tool_calls_total {
    render_sample(
        &mut output,
        "agentenv_gen_ai_tool_calls_total",
        &[
            ("gen_ai_tool_name", Some(row.tool.as_str())),
            ("env", row.env.as_deref()),
            ("result", Some(row.result.as_str())),
        ],
        row.count,
    );
}
```

- [ ] **Step 10: Run metrics tests**

Run:

```bash
cargo test -p agentenv-events sqlite_store_aggregates_genai_usage_duration_and_tool_calls
cargo test -p agentenv-events prometheus_render_includes_genai_metrics
```

Expected: both commands PASS.

- [ ] **Step 11: Commit**

```bash
git add crates/agentenv-events/src/store.rs crates/agentenv-events/src/metrics.rs
git commit -m "feat: expose genai prometheus metrics"
```

## Task 4: Export GenAI Spans Through OTLP

**Files:**
- Modify: `crates/agentenv-events/Cargo.toml`
- Modify: `crates/agentenv-events/src/sink.rs`
- Modify: `crates/agentenv-events/src/otel.rs`

- [ ] **Step 1: Add failing OTEL mapping export tests**

In `crates/agentenv-events/src/otel.rs`, replace `maps_activity_event_to_otel_log_fields` with:

```rust
#[test]
fn maps_genai_model_call_to_span_signal_fields() {
    let event = ActivityEvent::new(
        "2026-05-18T12:00:00Z",
        ActivityKind::GenAiModelCall,
        ActivityResult::Ok,
        "trace-otel",
    )
    .with_env("demo")
    .with_latency_ms(42)
    .with_extra("gen_ai.provider.name", serde_json::json!("openai"))
    .with_extra("gen_ai.request.model", serde_json::json!("gpt-4.1-mini"))
    .with_extra("gen_ai.usage.input_tokens", serde_json::json!(12));

    let signal = crate::genai::map_event_to_genai_signal(&event).unwrap();

    assert_eq!(signal.kind, crate::genai::OtelGenAiSignalKind::Span);
    assert_eq!(signal.operation_name.as_deref(), Some("chat"));
    assert_eq!(
        signal.attributes["gen_ai.provider.name"],
        crate::genai::OtelAttributeValue::String("openai".to_owned())
    );
    assert_eq!(
        signal.attributes["gen_ai.usage.input_tokens"],
        crate::genai::OtelAttributeValue::I64(12)
    );
}
```

Add this sink construction test:

```rust
#[test]
fn otel_sink_normalizes_grpc_endpoint_for_trace_and_log_exporters() {
    assert_eq!(
        normalize_grpc_endpoint("grpc://collector:4317"),
        "http://collector:4317"
    );
}
```

- [ ] **Step 2: Run OTEL tests to verify failure**

Run:

```bash
cargo test -p agentenv-events --features otel maps_genai_model_call_to_span_signal_fields otel_sink_normalizes_grpc_endpoint_for_trace_and_log_exporters
```

Expected: FAIL because `OtelSink` has no trace exporter/provider fields after dependency features are adjusted.

- [ ] **Step 3: Enable trace features**

In `crates/agentenv-events/Cargo.toml`, change the OTEL feature and OTLP dependency:

```toml
[features]
default = []
otel = ["dep:opentelemetry", "dep:opentelemetry_sdk", "dep:opentelemetry-otlp"]

[dependencies]
opentelemetry = { workspace = true, optional = true, features = ["logs", "trace"] }
opentelemetry_sdk = { workspace = true, optional = true, features = ["logs", "trace"] }
opentelemetry-otlp = { workspace = true, optional = true, features = ["grpc-tonic", "logs", "trace"] }
```

- [ ] **Step 4: Extend `OtelSink` fields**

Update imports in `crates/agentenv-events/src/otel.rs`:

```rust
use opentelemetry::{
    logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity},
    trace::{Span, SpanBuilder, SpanKind, Status, Tracer as _, TracerProvider as _},
    Key, KeyValue,
};
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::{
    logs::{SdkLogger, SdkLoggerProvider, SimpleLogProcessor},
    trace::{SdkTracer, SdkTracerProvider},
};

use crate::genai::{
    map_event_to_genai_signal, OtelAttributeValue, OtelGenAiSignal, OtelGenAiSignalKind,
    OtelSignalStatus, OtelSpanKindHint,
};
```

Change `OtelSink`:

```rust
pub struct OtelSink {
    endpoint: String,
    logger: SdkLogger,
    log_provider: SdkLoggerProvider,
    tracer: SdkTracer,
    trace_provider: SdkTracerProvider,
}
```

- [ ] **Step 5: Build trace and log providers**

Replace `OtelSink::new` with:

```rust
pub fn new(endpoint: impl Into<String>) -> Result<Self, SinkError> {
    let endpoint = endpoint.into();
    let normalized_endpoint = normalize_grpc_endpoint(&endpoint);
    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_export_config(ExportConfig {
            endpoint: Some(normalized_endpoint.clone()),
            protocol: Protocol::Grpc,
            timeout: None,
        })
        .build()?;
    let log_provider = SdkLoggerProvider::builder()
        .with_log_processor(SimpleLogProcessor::new(log_exporter))
        .build();
    let logger = log_provider.logger("agentenv-events");

    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_export_config(ExportConfig {
            endpoint: Some(normalized_endpoint),
            protocol: Protocol::Grpc,
            timeout: None,
        })
        .build()?;
    let trace_provider = SdkTracerProvider::builder()
        .with_simple_exporter(span_exporter)
        .build();
    let tracer = trace_provider.tracer("agentenv-events");

    Ok(Self {
        endpoint,
        logger,
        log_provider,
        tracer,
        trace_provider,
    })
}
```

- [ ] **Step 6: Export spans and logs**

Replace the body of `write_batch` with:

```rust
for event in events {
    if let Some(signal) = map_event_to_genai_signal(&event) {
        match signal.kind {
            OtelGenAiSignalKind::Span => self.emit_span(signal),
            OtelGenAiSignalKind::SpanEvent | OtelGenAiSignalKind::LogRecord => {
                self.emit_log(signal);
            }
        }
    }
}
let _ = (&self.log_provider, &self.trace_provider);
Ok(())
```

Add methods:

```rust
fn emit_span(&self, signal: OtelGenAiSignal) {
    let mut span = SpanBuilder::from_name(signal.name.clone())
        .with_kind(span_kind(signal.span_kind))
        .with_status(span_status(signal.status))
        .start(&self.tracer);
    for attribute in signal_attributes(&signal) {
        span.set_attribute(attribute);
    }
    span.end();
}

fn emit_log(&self, signal: OtelGenAiSignal) {
    let mut record = self.logger.create_log_record();
    record.set_event_name(signal.name.clone());
    record.set_target("agentenv-events");
    record.set_severity_number(severity_number_for_status(signal.status));
    record.set_severity_text(severity_text_for_status(signal.status));
    record.set_body(AnyValue::from(signal.name.clone()));
    record.add_attributes(
        signal
            .attributes
            .into_iter()
            .map(|(key, value)| (Key::new(key), any_value(value))),
    );
    self.logger.emit(record);
}
```

Add helpers:

```rust
fn signal_attributes(signal: &OtelGenAiSignal) -> Vec<KeyValue> {
    signal
        .attributes
        .iter()
        .map(|(key, value)| KeyValue::new(key.clone(), attribute_value(value.clone())))
        .collect()
}

fn attribute_value(value: OtelAttributeValue) -> opentelemetry::Value {
    match value {
        OtelAttributeValue::String(value) => opentelemetry::Value::String(value.into()),
        OtelAttributeValue::I64(value) => opentelemetry::Value::I64(value),
        OtelAttributeValue::F64(value) => opentelemetry::Value::F64(value),
        OtelAttributeValue::Bool(value) => opentelemetry::Value::Bool(value),
        OtelAttributeValue::StringArray(values) => opentelemetry::Value::Array(
            opentelemetry::Array::String(values.into_iter().map(Into::into).collect()),
        ),
    }
}

fn any_value(value: OtelAttributeValue) -> AnyValue {
    match value {
        OtelAttributeValue::String(value) => AnyValue::from(value),
        OtelAttributeValue::I64(value) => AnyValue::from(value),
        OtelAttributeValue::F64(value) => AnyValue::from(value),
        OtelAttributeValue::Bool(value) => AnyValue::from(value),
        OtelAttributeValue::StringArray(values) => {
            AnyValue::ListAny(values.into_iter().map(AnyValue::from).collect())
        }
    }
}

fn span_kind(kind: OtelSpanKindHint) -> SpanKind {
    match kind {
        OtelSpanKindHint::Client => SpanKind::Client,
        OtelSpanKindHint::Internal => SpanKind::Internal,
    }
}

fn span_status(status: OtelSignalStatus) -> Status {
    match status {
        OtelSignalStatus::Ok => Status::Ok,
        OtelSignalStatus::Error => Status::error("error"),
        OtelSignalStatus::Denied => Status::error("denied"),
        OtelSignalStatus::PendingApproval => Status::Unset,
    }
}

fn severity_number_for_status(status: OtelSignalStatus) -> Severity {
    match status {
        OtelSignalStatus::Ok => Severity::Info,
        OtelSignalStatus::PendingApproval => Severity::Warn,
        OtelSignalStatus::Denied | OtelSignalStatus::Error => Severity::Error,
    }
}

fn severity_text_for_status(status: OtelSignalStatus) -> &'static str {
    match status {
        OtelSignalStatus::Ok => "INFO",
        OtelSignalStatus::PendingApproval => "WARN",
        OtelSignalStatus::Denied | OtelSignalStatus::Error => "ERROR",
    }
}
```

- [ ] **Step 7: Keep compatibility field mapper**

Keep `map_event_to_otel_fields` for existing tests by implementing it through the new signal:

```rust
pub fn map_event_to_otel_fields(event: &ActivityEvent) -> BTreeMap<String, String> {
    map_event_to_genai_signal(event)
        .map(|signal| {
            signal
                .attributes
                .into_iter()
                .map(|(key, value)| (key, display_attribute_value(value)))
                .collect()
        })
        .unwrap_or_default()
}

fn display_attribute_value(value: OtelAttributeValue) -> String {
    match value {
        OtelAttributeValue::String(value) => value,
        OtelAttributeValue::I64(value) => value.to_string(),
        OtelAttributeValue::F64(value) => value.to_string(),
        OtelAttributeValue::Bool(value) => value.to_string(),
        OtelAttributeValue::StringArray(values) => values.join(","),
    }
}
```

- [ ] **Step 8: Run OTEL tests**

Run:

```bash
cargo test -p agentenv-events --features otel otel::
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/agentenv-events/Cargo.toml crates/agentenv-events/src/sink.rs crates/agentenv-events/src/otel.rs
git commit -m "feat: export genai telemetry to otlp"
```

## Task 5: Add Blueprint OTEL Configuration

**Files:**
- Modify: `crates/agentenv-core/src/blueprint.rs`
- Modify: `crates/agentenv-core/src/lifecycle.rs`
- Modify: `crates/agentenv-core/tests/roundtrip.rs`
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Add failing blueprint parsing test**

Add this test to `crates/agentenv-core/tests/roundtrip.rs`:

```rust
#[test]
fn blueprint_parses_observability_otel_endpoint() {
    let yaml = r#"
version: "1"
min_agentenv_version: "0.0.1-alpha0"
sandbox: { driver: openshell }
agent: { driver: codex }
context: { driver: none }
policy: { tier: balanced, presets: [] }
observability:
  otel:
    endpoint: grpc://collector.example.com:4317
"#;

    let blueprint = agentenv_core::blueprint::Blueprint::from_yaml(yaml).unwrap();
    assert_eq!(
        blueprint
            .observability
            .as_ref()
            .and_then(|section| section.otel.as_ref())
            .and_then(|otel| otel.endpoint.as_deref()),
        Some("grpc://collector.example.com:4317")
    );
}
```

- [ ] **Step 2: Run parsing test to verify failure**

Run:

```bash
cargo test -p agentenv-core blueprint_parses_observability_otel_endpoint
```

Expected: FAIL because `Blueprint` has no `observability` field.

- [ ] **Step 3: Add blueprint section types**

In `crates/agentenv-core/src/blueprint.rs`, add this field to `Blueprint` after `state`:

```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilitySection>,
```

Add these structs near `StateSection`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObservabilitySection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otel: Option<OtelObservabilitySection>,
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OtelObservabilitySection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}
```

- [ ] **Step 4: Update internal blueprint construction**

Search for `Blueprint {` in tests and support code:

```bash
rg -n "Blueprint \\{" crates/agentenv-core
```

For every literal construction, add:

```rust
        observability: None,
```

Run:

```bash
cargo test -p agentenv-core blueprint_parses_observability_otel_endpoint
```

Expected: PASS.

- [ ] **Step 5: Add failing CLI dispatcher test**

Add this test to `#[cfg(test)] mod tests` in `crates/agentenv/src/main.rs`:

```rust
#[test]
fn blueprint_otel_endpoint_is_loaded_from_yaml() {
    let yaml = r#"
version: "1"
min_agentenv_version: "0.0.1-alpha0"
sandbox: { driver: openshell }
agent: { driver: codex }
context: { driver: none }
policy: { tier: balanced, presets: [] }
observability:
  otel:
    endpoint: grpc://collector.example.com:4317
"#;

    let endpoints = blueprint_otel_sink_args(yaml).unwrap();

    assert_eq!(endpoints, vec!["otel:grpc://collector.example.com:4317"]);
}
```

- [ ] **Step 6: Implement blueprint sink extraction**

In `crates/agentenv/src/main.rs`, add:

```rust
fn blueprint_otel_sink_args(blueprint_yaml: &str) -> Result<Vec<String>> {
    let blueprint = agentenv_core::blueprint::Blueprint::from_yaml(blueprint_yaml)
        .context("parse blueprint observability config")?;
    let Some(endpoint) = blueprint
        .observability
        .and_then(|section| section.otel)
        .and_then(|otel| otel.endpoint)
    else {
        return Ok(Vec::new());
    };
    Ok(vec![format!("otel:{endpoint}")])
}

fn combined_create_sink_args(blueprint_yaml: &str, cli_sink_args: &[String]) -> Result<Vec<String>> {
    let mut sinks = blueprint_otel_sink_args(blueprint_yaml)?;
    sinks.extend(cli_sink_args.iter().cloned());
    Ok(sinks)
}
```

Update `run_create` so it passes combined sinks into `build_event_dispatcher`:

```rust
let sink_args = combined_create_sink_args(&blueprint_yaml, event_sink_args)?;
let dispatcher = build_event_dispatcher(&options, Some(&args.name), &sink_args)?;
```

Keep the exact local variable names from the current `run_create`; only replace the sink argument passed to dispatcher construction.

- [ ] **Step 7: Validate OTEL endpoint through SSRF guard**

Add this function next to `validate_webhook_sink_url`:

```rust
fn validate_otel_sink_endpoint(endpoint: &str) -> Result<()> {
    let authority = endpoint
        .strip_prefix("grpc://")
        .context("OTEL endpoint must use grpc://host:port")?;
    let url = url::Url::parse(&format!("https://{authority}"))
        .with_context(|| format!("invalid OTEL endpoint `{endpoint}`"))?;
    agentenv_core::security::ssrf::validate_outbound(
        &url,
        agentenv_core::security::ssrf::SsrfOptions::default(),
    )
    .with_context(|| format!("OTEL endpoint failed SSRF validation for `{endpoint}`"))?;
    Ok(())
}
```

Update `build_event_dispatcher` arm:

```rust
            SinkConfig::OtelGrpc { endpoint } => {
                validate_otel_sink_endpoint(&endpoint)?;
                sinks.push(agentenv_events::sink::otel_grpc_sink(endpoint)?);
            }
```

- [ ] **Step 8: Add unsafe endpoint CLI test**

Add this test to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn create_rejects_unsafe_blueprint_otel_endpoint() {
    let temp_dir = make_temp_dir("unsafe-blueprint-otel");
    let blueprint = temp_dir.join("agentenv.yaml");
    std::fs::write(
        &blueprint,
        r#"
version: "1"
min_agentenv_version: "0.0.1-alpha0"
sandbox: { driver: openshell }
agent: { driver: codex }
context: { driver: none }
policy: { tier: balanced, presets: [] }
observability:
  otel:
    endpoint: grpc://127.0.0.1:4317
"#,
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("create")
        .arg("demo")
        .arg("--file")
        .arg(&blueprint)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OTEL endpoint failed SSRF validation"), "{stderr}");
}
```

- [ ] **Step 9: Run blueprint and CLI tests**

Run:

```bash
cargo test -p agentenv-core blueprint_parses_observability_otel_endpoint
cargo test -p agentenv blueprint_otel_endpoint_is_loaded_from_yaml
cargo test -p agentenv --test cli_behavior create_rejects_unsafe_blueprint_otel_endpoint
```

Expected: all commands PASS.

- [ ] **Step 10: Commit**

```bash
git add crates/agentenv-core/src/blueprint.rs crates/agentenv-core/src/lifecycle.rs crates/agentenv-core/tests/roundtrip.rs crates/agentenv/src/main.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: configure otel endpoint from blueprint"
```

## Task 6: Add Dashboard And Documentation

**Files:**
- Create: `contrib/grafana/dashboards/agentenv-otel.json`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `crates/agentenv-events/README.md`
- Modify: `crates/agentenv/README.md`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Add dashboard validity test**

Add this test to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn grafana_dashboard_is_valid_json_and_references_emitted_metrics() {
    let dashboard_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contrib/grafana/dashboards/agentenv-otel.json");
    let content = std::fs::read_to_string(&dashboard_path).unwrap();
    let dashboard: serde_json::Value = serde_json::from_str(&content).unwrap();
    let rendered = serde_json::to_string(&dashboard).unwrap();

    for metric in [
        "agentenv_envs_total",
        "agentenv_events_total",
        "gen_ai_client_operation_duration_bucket",
        "gen_ai_client_token_usage_bucket",
        "agentenv_gen_ai_tool_calls_total",
        "agentenv_policy_blocks_total",
        "agentenv_approvals_pending_total",
        "agentenv_event_drops_total",
        "agentenv_event_sink_errors_total",
    ] {
        assert!(rendered.contains(metric), "dashboard missing {metric}");
    }
}
```

- [ ] **Step 2: Run dashboard test to verify failure**

Run:

```bash
cargo test -p agentenv --test cli_behavior grafana_dashboard_is_valid_json_and_references_emitted_metrics
```

Expected: FAIL because the dashboard file does not exist.

- [ ] **Step 3: Create Grafana dashboard JSON**

Create `contrib/grafana/dashboards/agentenv-otel.json`:

```json
{
  "annotations": {
    "list": []
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "links": [],
  "panels": [
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
      "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
      "id": 1,
      "targets": [{"expr": "sum by (status) (agentenv_envs_total)", "legendFormat": "{{status}}", "refId": "A"}],
      "title": "Environments",
      "type": "stat"
    },
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 6, "y": 0},
      "id": 2,
      "targets": [{"expr": "sum by (kind, result) (rate(agentenv_events_total[5m]))", "legendFormat": "{{kind}} {{result}}", "refId": "A"}],
      "title": "Activity Events",
      "type": "timeseries"
    },
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
      "id": 3,
      "targets": [{"expr": "histogram_quantile(0.95, sum by (le, gen_ai_operation_name) (rate(gen_ai_client_operation_duration_bucket[5m])))", "legendFormat": "p95 {{gen_ai_operation_name}}", "refId": "A"}],
      "title": "GenAI Operation Duration p95",
      "type": "timeseries"
    },
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
      "id": 4,
      "targets": [{"expr": "sum by (gen_ai_token_type, gen_ai_request_model) (rate(gen_ai_client_token_usage_sum[5m]))", "legendFormat": "{{gen_ai_request_model}} {{gen_ai_token_type}}", "refId": "A"}],
      "title": "Token Usage",
      "type": "timeseries"
    },
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
      "id": 5,
      "targets": [{"expr": "sum by (gen_ai_tool_name, result) (rate(agentenv_gen_ai_tool_calls_total[5m]))", "legendFormat": "{{gen_ai_tool_name}} {{result}}", "refId": "A"}],
      "title": "Tool Calls",
      "type": "timeseries"
    },
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
      "id": 6,
      "targets": [{"expr": "sum by (driver) (rate(agentenv_policy_blocks_total[5m]))", "legendFormat": "{{driver}}", "refId": "A"}],
      "title": "Egress Denials",
      "type": "timeseries"
    },
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
      "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
      "id": 7,
      "targets": [{"expr": "agentenv_approvals_pending_total", "legendFormat": "pending", "refId": "A"}],
      "title": "Pending Approvals",
      "type": "stat"
    },
    {
      "datasource": "${DS_PROMETHEUS}",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 24},
      "id": 8,
      "targets": [
        {"expr": "sum by (sink) (rate(agentenv_event_drops_total[5m]))", "legendFormat": "drops {{sink}}", "refId": "A"},
        {"expr": "sum by (sink) (rate(agentenv_event_sink_errors_total[5m]))", "legendFormat": "errors {{sink}}", "refId": "B"}
      ],
      "title": "Event Pipeline Health",
      "type": "timeseries"
    }
  ],
  "refresh": "30s",
  "schemaVersion": 39,
  "style": "dark",
  "tags": ["agentenv", "otel", "genai"],
  "templating": {
    "list": [
      {
        "current": {"selected": false, "text": "Prometheus", "value": "Prometheus"},
        "hide": 0,
        "includeAll": false,
        "label": "Prometheus datasource",
        "multi": false,
        "name": "DS_PROMETHEUS",
        "options": [],
        "query": "prometheus",
        "refresh": 1,
        "regex": "",
        "type": "datasource"
      }
    ]
  },
  "time": {"from": "now-6h", "to": "now"},
  "timezone": "browser",
  "title": "agentenv OTEL GenAI",
  "uid": "agentenv-otel-genai",
  "version": 1,
  "weekStart": ""
}
```

- [ ] **Step 4: Update docs**

In `docs/ARCHITECTURE.md`, update the Observability section with:

```markdown
The activity stream also exports an OTEL GenAI view. Native `ActivityEvent`
records remain the source of truth; `agentenv-events` maps agent turns to
`gen_ai.operation.name=invoke_agent`, MCP tool calls to
`gen_ai.operation.name=execute_tool`, and model calls to current GenAI
attributes such as `gen_ai.provider.name`, `gen_ai.request.model`, and
`gen_ai.usage.*`. The old `gen_ai.system` name is accepted as an input alias
and normalized to `gen_ai.provider.name` on export.
```

In `docs/DRIVER_PROTOCOL.md`, add under rich `DriverActivityEventParams`:

```markdown
Schema `1.2` rich activity kind values also include `agent_turn` and
`gen_ai_model_call`. Drivers can attach GenAI metadata through `extras` using
current OpenTelemetry names such as `gen_ai.provider.name`,
`gen_ai.request.model`, `gen_ai.usage.input_tokens`,
`gen_ai.usage.output_tokens`, `gen_ai.response.finish_reasons`,
`gen_ai.tool.name`, and `gen_ai.tool.call.id`. The legacy
`gen_ai.system` key is accepted as an input alias for `gen_ai.provider.name`.
Drivers must not include prompt text, completion text, credentials, or tool
argument payloads in activity metadata.
```

In `crates/agentenv-events/README.md`, add:

```markdown
## OTEL GenAI Mapping

When built with `agentenv-events/otel`, `otel:grpc://host:4317` exports GenAI
operation spans for `agent_turn`, `gen_ai_model_call`, and `mcp_tool_call`
events. The mapper emits current OpenTelemetry GenAI attributes including
`gen_ai.provider.name`, `gen_ai.operation.name`, `gen_ai.request.model`,
`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
`gen_ai.tool.name`, and `gen_ai.tool.call.id`. `gen_ai.system` is accepted only
as an input alias and is normalized to `gen_ai.provider.name`.

Prometheus output uses underscore-safe names:
`gen_ai_client_token_usage_*`, `gen_ai_client_operation_duration_*`, and
`agentenv_gen_ai_tool_calls_total`.
```

In `crates/agentenv/README.md`, add:

````markdown
Blueprints can add an OTLP collector endpoint:

```yaml
observability:
  otel:
    endpoint: grpc://collector.example.com:4317
```

The endpoint is validated through the same outbound URL safety checks as
webhook sinks. CLI sink flags remain available:

```bash
agentenv --events-sink otel:grpc://collector.example.com:4317 create demo
```
````

- [ ] **Step 5: Run docs and dashboard tests**

Run:

```bash
cargo test -p agentenv --test cli_behavior grafana_dashboard_is_valid_json_and_references_emitted_metrics
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add contrib/grafana/dashboards/agentenv-otel.json docs/ARCHITECTURE.md docs/DRIVER_PROTOCOL.md crates/agentenv-events/README.md crates/agentenv/README.md crates/agentenv/tests/cli_behavior.rs
git commit -m "docs: add otel genai dashboard"
```

## Task 7: Final Verification

**Files:**
- Verify all modified files.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt
```

Expected: exits 0 with no stdout.

- [ ] **Step 2: Run focused package tests**

Run:

```bash
cargo test -p agentenv-events
cargo test -p agentenv-events --features otel
cargo test -p agentenv-proto
cargo test -p agentenv-plugin
cargo test -p agentenv-core blueprint observability
cargo test -p agentenv --test cli_behavior metrics
```

Expected: all commands PASS.

- [ ] **Step 3: Run full workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 4: Run clippy**

Run:

```bash
cargo clippy --workspace -- -D warnings
```

Expected: PASS with no warnings.

- [ ] **Step 5: Inspect git status**

Run:

```bash
git status --short
```

Expected: only intentional files are modified, or the worktree is clean after the final commit.

- [ ] **Step 6: Commit verification fixes**

If formatting or clippy changed files, commit them:

```bash
git add .
git commit -m "chore: verify otel genai integration"
```

Expected: either a new commit is created for verification-only changes or Git reports that there is nothing to commit.
