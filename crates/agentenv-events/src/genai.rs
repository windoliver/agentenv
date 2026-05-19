use std::collections::BTreeMap;

use serde_json::Value;

use crate::redaction::redact_string;
use crate::{ActivityEvent, ActivityKind, ActivityResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtelGenAiSignalKind {
    Span,
    SpanEvent,
    LogRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtelSpanKindHint {
    Client,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub span_kind: Option<OtelSpanKindHint>,
    pub operation_name: String,
    pub attributes: BTreeMap<String, OtelAttributeValue>,
    pub status: OtelSignalStatus,
}

pub fn map_event_to_genai_signal(event: &ActivityEvent) -> OtelGenAiSignal {
    let redacted_event = event.clone().redacted();
    let (kind, span_kind, operation_name) = signal_shape(&redacted_event);
    let mut attributes = BTreeMap::new();

    insert_base_attributes(&mut attributes, &redacted_event);
    insert_error_type(&mut attributes, &redacted_event);
    attributes.insert(
        "gen_ai.operation.name".to_owned(),
        OtelAttributeValue::String(operation_name.clone()),
    );
    insert_provider_name(&mut attributes, &redacted_event);

    match redacted_event.kind {
        ActivityKind::McpToolCall => insert_tool_attributes(&mut attributes, &redacted_event),
        ActivityKind::AgentTurn => insert_agent_attributes(&mut attributes, &redacted_event),
        ActivityKind::GenAiModelCall => {
            insert_model_call_attributes(&mut attributes, &redacted_event, event);
        }
        _ => insert_extension_attributes(&mut attributes, &redacted_event),
    }

    OtelGenAiSignal {
        kind,
        name: signal_name(redacted_event.kind, &operation_name, &attributes),
        span_kind,
        operation_name,
        attributes,
        status: status_from_result(redacted_event.result),
    }
}

fn signal_shape(event: &ActivityEvent) -> (OtelGenAiSignalKind, Option<OtelSpanKindHint>, String) {
    match event.kind {
        ActivityKind::McpToolCall => (
            OtelGenAiSignalKind::Span,
            Some(OtelSpanKindHint::Internal),
            "execute_tool".to_owned(),
        ),
        ActivityKind::AgentTurn => (
            OtelGenAiSignalKind::Span,
            Some(OtelSpanKindHint::Internal),
            "invoke_agent".to_owned(),
        ),
        ActivityKind::GenAiModelCall => (
            OtelGenAiSignalKind::Span,
            Some(OtelSpanKindHint::Client),
            normalized_operation_name(string_from_keys(&event.extras, &["gen_ai.operation.name"])),
        ),
        _ => (
            OtelGenAiSignalKind::LogRecord,
            None,
            activity_kind_name(event.kind).to_owned(),
        ),
    }
}

fn signal_name(
    event_kind: ActivityKind,
    operation_name: &str,
    attributes: &BTreeMap<String, OtelAttributeValue>,
) -> String {
    let name_suffix = match event_kind {
        ActivityKind::McpToolCall => string_attr(attributes, "gen_ai.tool.name"),
        ActivityKind::AgentTurn => string_attr(attributes, "gen_ai.agent.name"),
        ActivityKind::GenAiModelCall => string_attr(attributes, "gen_ai.request.model"),
        _ => None,
    };

    name_suffix
        .map(|suffix| format!("{operation_name} {suffix}"))
        .unwrap_or_else(|| operation_name.to_owned())
}

fn insert_base_attributes(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    event: &ActivityEvent,
) {
    attributes.insert(
        "agentenv.event.kind".to_owned(),
        OtelAttributeValue::String(activity_kind_name(event.kind).to_owned()),
    );
    attributes.insert(
        "agentenv.event.result".to_owned(),
        OtelAttributeValue::String(activity_result_name(event.result).to_owned()),
    );
    if !event.trace_id.is_empty() {
        attributes.insert(
            "agentenv.trace_id".to_owned(),
            OtelAttributeValue::String(event.trace_id.clone()),
        );
    }
    if let Some(env) = clean_string(event.env.as_deref()) {
        attributes.insert("agentenv.env".to_owned(), OtelAttributeValue::String(env));
    }
    if let Some(reason_code) = sanitized_reason_code(event) {
        attributes.insert(
            "agentenv.reason_code".to_owned(),
            OtelAttributeValue::String(reason_code),
        );
    }
    if let Some(latency_ms) = event.latency_ms.and_then(|value| i64::try_from(value).ok()) {
        attributes.insert(
            "agentenv.latency_ms".to_owned(),
            OtelAttributeValue::I64(latency_ms),
        );
    }
}

fn insert_error_type(attributes: &mut BTreeMap<String, OtelAttributeValue>, event: &ActivityEvent) {
    match event.result {
        ActivityResult::Error | ActivityResult::Denied => {
            let error_type = sanitized_reason_code(event)
                .filter(|reason_code| is_code_like_error_type(reason_code))
                .unwrap_or_else(|| "_OTHER".to_owned());
            attributes.insert(
                "error.type".to_owned(),
                OtelAttributeValue::String(error_type),
            );
        }
        ActivityResult::Ok | ActivityResult::PendingApproval => {}
    }
}

fn sanitized_reason_code(event: &ActivityEvent) -> Option<String> {
    event.reason_code.as_deref().and_then(|reason_code| {
        let redacted = redact_string(reason_code);
        clean_string(Some(&redacted))
    })
}

fn is_code_like_error_type(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b':'))
}

fn insert_provider_name(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    event: &ActivityEvent,
) {
    if let Some(provider) =
        string_from_keys(&event.extras, &["gen_ai.provider.name", "gen_ai.system"])
            .or_else(|| string_from_keys(&event.subject, &["gen_ai.provider.name"]))
    {
        attributes.insert(
            "gen_ai.provider.name".to_owned(),
            OtelAttributeValue::String(provider),
        );
    }
}

fn insert_tool_attributes(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    event: &ActivityEvent,
) {
    if let Some(tool_name) =
        string_from_event_maps(event, &["gen_ai.tool.name", "tool.name", "name"])
    {
        attributes.insert(
            "gen_ai.tool.name".to_owned(),
            OtelAttributeValue::String(tool_name),
        );
    }
    if let Some(call_id) = string_from_event_maps(event, &["gen_ai.tool.call.id", "call_id"]) {
        attributes.insert(
            "gen_ai.tool.call.id".to_owned(),
            OtelAttributeValue::String(call_id),
        );
    }
}

fn insert_agent_attributes(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    event: &ActivityEvent,
) {
    if let Some(agent_name) = string_from_keys(&event.extras, &["gen_ai.agent.name"])
        .or_else(|| clean_string(event.env.as_deref()))
    {
        attributes.insert(
            "gen_ai.agent.name".to_owned(),
            OtelAttributeValue::String(agent_name),
        );
    }
}

fn insert_model_call_attributes(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    event: &ActivityEvent,
    original_event: &ActivityEvent,
) {
    copy_string_attr(
        attributes,
        "gen_ai.request.model",
        event,
        &["gen_ai.request.model", "request.model", "model"],
    );
    copy_string_attr(
        attributes,
        "gen_ai.response.model",
        event,
        &["gen_ai.response.model", "response.model"],
    );
    copy_i64_attr(
        attributes,
        "gen_ai.usage.input_tokens",
        original_event,
        &[
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.prompt_tokens",
            "input_tokens",
            "prompt_tokens",
        ],
    );
    copy_i64_attr(
        attributes,
        "gen_ai.usage.output_tokens",
        original_event,
        &[
            "gen_ai.usage.output_tokens",
            "gen_ai.usage.completion_tokens",
            "output_tokens",
            "completion_tokens",
        ],
    );
    if let Some(finish_reasons) = string_array_from_event_maps(
        event,
        &[
            "gen_ai.response.finish_reasons",
            "gen_ai.response.finish_reason",
            "finish_reasons",
            "finish_reason",
        ],
    ) {
        attributes.insert(
            "gen_ai.response.finish_reasons".to_owned(),
            OtelAttributeValue::StringArray(finish_reasons),
        );
    }
}

fn insert_extension_attributes(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    event: &ActivityEvent,
) {
    if event.kind == ActivityKind::EgressDenied {
        attributes.insert(
            "agentenv.egress.denied".to_owned(),
            OtelAttributeValue::Bool(true),
        );
    }

    if let Some(request_id) = string_from_keys(&event.subject, &["request_id"]) {
        attributes.insert(
            "agentenv.approval.request_id".to_owned(),
            OtelAttributeValue::String(request_id),
        );
    }
    if let Some(kind) = string_from_keys(&event.subject, &["kind"])
        .or_else(|| string_from_keys(&event.extras, &["approval.kind"]))
    {
        attributes.insert(
            "agentenv.approval.kind".to_owned(),
            OtelAttributeValue::String(kind),
        );
    }
    if let Some(policy_name) = string_from_keys(&event.extras, &["policy.name"]) {
        attributes.insert(
            "agentenv.policy.name".to_owned(),
            OtelAttributeValue::String(policy_name),
        );
    }

    if let Some(default_scope) = string_from_keys(&event.extras, &["default_scope"]) {
        attributes.insert(
            "agentenv.approval.default_scope".to_owned(),
            OtelAttributeValue::String(default_scope),
        );
    }
    if let Some(decision) = string_from_keys(&event.extras, &["decision"]) {
        attributes.insert(
            "agentenv.approval.decision".to_owned(),
            OtelAttributeValue::String(decision),
        );
    }
    if let Some(scope) = string_from_keys(&event.extras, &["scope"]) {
        attributes.insert(
            "agentenv.approval.scope".to_owned(),
            OtelAttributeValue::String(scope),
        );
    }
}

fn copy_string_attr(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    canonical_key: &str,
    event: &ActivityEvent,
    keys: &[&str],
) {
    if let Some(value) = string_from_event_maps(event, keys) {
        attributes.insert(canonical_key.to_owned(), OtelAttributeValue::String(value));
    }
}

fn copy_i64_attr(
    attributes: &mut BTreeMap<String, OtelAttributeValue>,
    canonical_key: &str,
    event: &ActivityEvent,
    keys: &[&str],
) {
    if let Some(value) = i64_from_event_maps(event, keys) {
        attributes.insert(canonical_key.to_owned(), OtelAttributeValue::I64(value));
    }
}

fn string_from_event_maps(event: &ActivityEvent, keys: &[&str]) -> Option<String> {
    string_from_keys(&event.subject, keys).or_else(|| string_from_keys(&event.extras, keys))
}

fn i64_from_event_maps(event: &ActivityEvent, keys: &[&str]) -> Option<i64> {
    i64_from_keys(&event.subject, keys).or_else(|| i64_from_keys(&event.extras, keys))
}

fn string_array_from_event_maps(event: &ActivityEvent, keys: &[&str]) -> Option<Vec<String>> {
    string_array_from_keys(&event.subject, keys)
        .or_else(|| string_array_from_keys(&event.extras, keys))
}

fn string_from_keys(map: &BTreeMap<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(value_as_string))
}

fn i64_from_keys(map: &BTreeMap<String, Value>, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(value_as_i64))
}

fn string_array_from_keys(map: &BTreeMap<String, Value>, keys: &[&str]) -> Option<Vec<String>> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(value_as_string_array))
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(raw) => clean_string(Some(raw)),
        _ => None,
    }
}

fn value_as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok())),
        Value::String(raw) => clean_string(Some(raw)).and_then(|value| value.parse().ok()),
        _ => None,
    }
}

fn value_as_string_array(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Array(values) => {
            let strings = values
                .iter()
                .filter_map(value_as_string)
                .collect::<Vec<_>>();
            (!strings.is_empty()).then_some(strings)
        }
        Value::String(_) => value_as_string(value).map(|value| vec![value]),
        _ => None,
    }
}

fn clean_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "[redacted]")
        .map(str::to_owned)
}

fn string_attr<'a>(
    attributes: &'a BTreeMap<String, OtelAttributeValue>,
    key: &str,
) -> Option<&'a str> {
    match attributes.get(key) {
        Some(OtelAttributeValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn normalized_operation_name(value: Option<String>) -> String {
    match value.as_deref() {
        Some(
            "chat" | "create_agent" | "embeddings" | "execute_tool" | "generate_content"
            | "invoke_agent" | "invoke_workflow" | "retrieval" | "text_completion",
        ) => value.unwrap_or_default(),
        _ => "chat".to_owned(),
    }
}

fn status_from_result(result: ActivityResult) -> OtelSignalStatus {
    match result {
        ActivityResult::Ok => OtelSignalStatus::Ok,
        ActivityResult::Error => OtelSignalStatus::Error,
        ActivityResult::Denied => OtelSignalStatus::Denied,
        ActivityResult::PendingApproval => OtelSignalStatus::PendingApproval,
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

fn activity_kind_name(kind: ActivityKind) -> &'static str {
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{ActivityEvent, ActivityKind, ActivityResult};

    #[test]
    fn gen_ai_system_alias_maps_to_provider_name() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::GenAiModelCall,
            ActivityResult::Ok,
            "trace-genai",
        )
        .with_extra("gen_ai.system", json!("openai"));

        let signal = map_event_to_genai_signal(&event);

        assert_eq!(
            signal.attributes.get("gen_ai.provider.name"),
            Some(&OtelAttributeValue::String("openai".to_owned()))
        );
        assert!(!signal.attributes.contains_key("gen_ai.system"));
    }

    #[test]
    fn mcp_tool_call_maps_to_execute_tool() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::McpToolCall,
            ActivityResult::Ok,
            "trace-tool",
        )
        .with_subject_value("name", json!("repo.search"));

        let signal = map_event_to_genai_signal(&event);

        assert_eq!(signal.kind, OtelGenAiSignalKind::Span);
        assert_eq!(signal.span_kind, Some(OtelSpanKindHint::Internal));
        assert_eq!(signal.name, "execute_tool repo.search");
        assert_eq!(signal.operation_name, "execute_tool");
        assert_eq!(
            signal.attributes.get("gen_ai.operation.name"),
            Some(&OtelAttributeValue::String("execute_tool".to_owned()))
        );
        assert_eq!(
            signal.attributes.get("gen_ai.tool.name"),
            Some(&OtelAttributeValue::String("repo.search".to_owned()))
        );
    }

    #[test]
    fn agent_turn_maps_to_invoke_agent() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::AgentTurn,
            ActivityResult::Ok,
            "trace-agent",
        )
        .with_env("codex");

        let signal = map_event_to_genai_signal(&event);

        assert_eq!(signal.kind, OtelGenAiSignalKind::Span);
        assert_eq!(signal.span_kind, Some(OtelSpanKindHint::Internal));
        assert_eq!(signal.name, "invoke_agent codex");
        assert_eq!(signal.operation_name, "invoke_agent");
        assert_eq!(
            signal.attributes.get("gen_ai.agent.name"),
            Some(&OtelAttributeValue::String("codex".to_owned()))
        );
    }

    #[test]
    fn model_call_maps_token_usage_attributes() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::GenAiModelCall,
            ActivityResult::Ok,
            "trace-model",
        )
        .with_extra("gen_ai.request.model", json!("gpt-4.1"))
        .with_extra("gen_ai.response.model", json!("gpt-4.1-2026-04-14"))
        .with_extra("gen_ai.usage.input_tokens", json!(123))
        .with_extra("gen_ai.usage.output_tokens", json!(45));

        let signal = map_event_to_genai_signal(&event);

        assert_eq!(signal.name, "chat gpt-4.1");
        assert_eq!(
            signal.attributes.get("gen_ai.request.model"),
            Some(&OtelAttributeValue::String("gpt-4.1".to_owned()))
        );
        assert_eq!(
            signal.attributes.get("gen_ai.response.model"),
            Some(&OtelAttributeValue::String("gpt-4.1-2026-04-14".to_owned()))
        );
        assert_eq!(
            signal.attributes.get("gen_ai.usage.input_tokens"),
            Some(&OtelAttributeValue::I64(123))
        );
        assert_eq!(
            signal.attributes.get("gen_ai.usage.output_tokens"),
            Some(&OtelAttributeValue::I64(45))
        );
    }

    #[test]
    fn secret_looking_extra_is_omitted_by_mapper() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::GenAiModelCall,
            ActivityResult::Ok,
            "trace-secret",
        )
        .with_extra("api_key", json!("sk-secret"))
        .with_extra("gen_ai.request.model", json!("gpt-4.1"));

        let signal = map_event_to_genai_signal(&event);
        let rendered = format!("{:?}", signal.attributes);

        assert!(!signal.attributes.contains_key("api_key"));
        assert!(!rendered.contains("sk-secret"));
        assert!(!rendered.contains("[redacted]"));
    }

    #[test]
    fn model_call_defaults_custom_operation_name_to_chat() {
        let custom_operation = "summarize this private customer prompt";
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::GenAiModelCall,
            ActivityResult::Ok,
            "trace-custom-op",
        )
        .with_extra("gen_ai.operation.name", json!(custom_operation))
        .with_extra("gen_ai.request.model", json!("gpt-4.1"));

        let signal = map_event_to_genai_signal(&event);
        let rendered = format!("{:?}", signal);

        assert_eq!(signal.operation_name, "chat");
        assert_eq!(signal.name, "chat gpt-4.1");
        assert_eq!(
            signal.attributes.get("gen_ai.operation.name"),
            Some(&OtelAttributeValue::String("chat".to_owned()))
        );
        assert!(!rendered.contains(custom_operation));
    }

    #[test]
    fn approval_requested_maps_allowlisted_subject_attributes() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::ApprovalRequested,
            ActivityResult::PendingApproval,
            "trace-approval",
        )
        .with_subject_value("request_id", json!("apr-123"))
        .with_subject_value("kind", json!("egress_host"))
        .with_subject_value("subject", json!("https://example.test/path?token=secret"))
        .with_extra("default_scope", json!("session"))
        .with_extra(
            "context",
            json!({"url": "https://example.test/path?token=secret"}),
        );

        let signal = map_event_to_genai_signal(&event);
        let rendered = format!("{:?}", signal.attributes);

        assert_eq!(signal.kind, OtelGenAiSignalKind::LogRecord);
        assert_eq!(
            signal.attributes.get("agentenv.approval.request_id"),
            Some(&OtelAttributeValue::String("apr-123".to_owned()))
        );
        assert_eq!(
            signal.attributes.get("agentenv.approval.kind"),
            Some(&OtelAttributeValue::String("egress_host".to_owned()))
        );
        assert_eq!(
            signal.attributes.get("agentenv.approval.default_scope"),
            Some(&OtelAttributeValue::String("session".to_owned()))
        );
        assert!(!signal.attributes.contains_key("agentenv.approval.context"));
        assert!(!rendered.contains("token=secret"));
    }

    #[test]
    fn scalar_reason_code_is_redacted_before_mapping() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::GenAiModelCall,
            ActivityResult::Ok,
            "trace-reason",
        )
        .with_reason_code("https://user:pass@example.test/path?token=secret#frag");

        let signal = map_event_to_genai_signal(&event);
        let rendered = format!("{:?}", signal.attributes);

        assert_eq!(
            signal.attributes.get("agentenv.reason_code"),
            Some(&OtelAttributeValue::String(
                "https://example.test/path".to_owned()
            ))
        );
        assert!(!rendered.contains("user:pass"));
        assert!(!rendered.contains("token=secret"));
        assert!(!rendered.contains("#frag"));
        assert!(!signal.attributes.contains_key("error.type"));
    }

    #[test]
    fn denied_signal_emits_error_type_from_code_like_reason_code() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-denied-code",
        )
        .with_reason_code("not_in_policy");

        let signal = map_event_to_genai_signal(&event);

        assert_eq!(
            signal.attributes.get("agentenv.reason_code"),
            Some(&OtelAttributeValue::String("not_in_policy".to_owned()))
        );
        assert_eq!(
            signal.attributes.get("error.type"),
            Some(&OtelAttributeValue::String("not_in_policy".to_owned()))
        );
    }

    #[test]
    fn denied_signal_defaults_error_type_for_url_reason_code() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-denied",
        )
        .with_reason_code("https://user:pass@example.test/blocked?token=secret#frag");

        let signal = map_event_to_genai_signal(&event);
        let rendered = format!("{:?}", signal.attributes);

        assert_eq!(
            signal.attributes.get("agentenv.reason_code"),
            Some(&OtelAttributeValue::String(
                "https://example.test/blocked".to_owned()
            ))
        );
        assert_eq!(
            signal.attributes.get("error.type"),
            Some(&OtelAttributeValue::String("_OTHER".to_owned()))
        );
        assert!(!rendered.contains("user:pass"));
        assert!(!rendered.contains("token=secret"));
        assert!(!rendered.contains("#frag"));
    }

    #[test]
    fn error_signal_defaults_error_type_when_reason_code_missing() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::GenAiModelCall,
            ActivityResult::Error,
            "trace-error",
        );

        let signal = map_event_to_genai_signal(&event);

        assert_eq!(
            signal.attributes.get("error.type"),
            Some(&OtelAttributeValue::String("_OTHER".to_owned()))
        );
    }

    #[test]
    fn pending_approval_signal_does_not_emit_error_type() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::ApprovalRequested,
            ActivityResult::PendingApproval,
            "trace-pending",
        )
        .with_reason_code("needs_approval");

        let signal = map_event_to_genai_signal(&event);

        assert!(!signal.attributes.contains_key("error.type"));
    }
}
