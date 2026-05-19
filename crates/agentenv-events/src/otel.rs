use std::collections::BTreeMap;

use opentelemetry::{
    logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity},
    trace::{Span as _, SpanKind, Status, Tracer as _, TracerProvider as _},
    Array, Key, KeyValue, Value,
};
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider, SimpleLogProcessor};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};

use crate::{
    activity::{ActivityEvent, ActivityKind, ActivityResult},
    genai::{
        map_event_to_genai_signal, OtelAttributeValue, OtelGenAiSignalKind, OtelSignalStatus,
        OtelSpanKindHint,
    },
    sink::{EventSink, SinkError},
};

const OTEL_ACTIVITY_EVENT_NAME: &str = "agentenv.activity";

pub fn map_event_to_otel_fields(event: &ActivityEvent) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "agentenv.kind".to_owned(),
        activity_kind_name(event.kind).to_owned(),
    );
    fields.insert(
        "agentenv.result".to_owned(),
        activity_result_name(event.result).to_owned(),
    );
    fields.insert("agentenv.trace_id".to_owned(), event.trace_id.clone());

    if let Some(env) = &event.env {
        fields.insert("agentenv.env".to_owned(), env.clone());
    }
    if let Some(reason_code) = &event.reason_code {
        fields.insert("agentenv.reason_code".to_owned(), reason_code.clone());
    }
    if let Some(latency_ms) = event.latency_ms {
        fields.insert("agentenv.latency_ms".to_owned(), latency_ms.to_string());
    }

    fields
}

pub struct OtelSink {
    endpoint: String,
    logger: SdkLogger,
    log_provider: SdkLoggerProvider,
    tracer: SdkTracer,
    trace_provider: SdkTracerProvider,
}

#[derive(Debug, Clone, PartialEq)]
struct OtelSpanExportPlan {
    name: String,
    kind: SpanKind,
    status: Status,
    attributes: Vec<KeyValue>,
}

impl OtelSink {
    pub fn new(endpoint: impl Into<String>) -> Result<Self, SinkError> {
        let endpoint = endpoint.into();
        let exporter = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_export_config(export_config(&endpoint))
            .build()?;
        let log_provider = SdkLoggerProvider::builder()
            .with_log_processor(SimpleLogProcessor::new(exporter))
            .build();
        let logger = log_provider.logger("agentenv-events");

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_export_config(export_config(&endpoint))
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

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[async_trait::async_trait]
impl EventSink for OtelSink {
    fn name(&self) -> &'static str {
        "otel"
    }

    async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError> {
        for event in events {
            let mut record = self.logger.create_log_record();
            record.set_event_name(OTEL_ACTIVITY_EVENT_NAME);
            record.set_target("agentenv-events");
            record.set_severity_number(severity_number(event.result));
            record.set_severity_text(severity_text(event.result));
            record.set_body(AnyValue::from(activity_kind_name(event.kind)));
            record.add_attributes(
                map_event_to_otel_fields(&event)
                    .into_iter()
                    .map(|(key, value)| (Key::new(key), AnyValue::from(value))),
            );
            record.add_attributes(
                genai_log_attributes(&event)
                    .into_iter()
                    .map(|(key, value)| (Key::new(key), otel_attribute_value_to_any_value(value))),
            );
            self.logger.emit(record);

            if let Some(plan) = genai_span_export_plan(&event) {
                let mut span = self
                    .tracer
                    .span_builder(plan.name)
                    .with_kind(plan.kind)
                    .with_status(plan.status)
                    .with_attributes(plan.attributes)
                    .start(&self.tracer);
                span.end();
            }
        }
        let _ = (&self.log_provider, &self.trace_provider);
        Ok(())
    }
}

fn export_config(endpoint: &str) -> ExportConfig {
    ExportConfig {
        endpoint: Some(normalize_grpc_endpoint(endpoint)),
        protocol: Protocol::Grpc,
        timeout: None,
    }
}

fn genai_span_export_plan(event: &ActivityEvent) -> Option<OtelSpanExportPlan> {
    let signal = map_event_to_genai_signal(event);
    if signal.kind != OtelGenAiSignalKind::Span {
        return None;
    }

    Some(OtelSpanExportPlan {
        name: signal.name,
        kind: span_kind(signal.span_kind),
        status: span_status(signal.status),
        attributes: signal
            .attributes
            .into_iter()
            .map(|(key, value)| otel_attribute_value_to_key_value(key, value))
            .collect(),
    })
}

fn genai_log_attributes(event: &ActivityEvent) -> BTreeMap<String, OtelAttributeValue> {
    let signal = map_event_to_genai_signal(event);
    match signal.kind {
        OtelGenAiSignalKind::Span => BTreeMap::new(),
        OtelGenAiSignalKind::SpanEvent | OtelGenAiSignalKind::LogRecord => {
            let legacy_fields = map_event_to_otel_fields(event);
            signal
                .attributes
                .into_iter()
                .filter(|(key, _)| !legacy_fields.contains_key(key))
                .collect()
        }
    }
}

fn span_kind(kind: Option<OtelSpanKindHint>) -> SpanKind {
    match kind {
        Some(OtelSpanKindHint::Client) => SpanKind::Client,
        Some(OtelSpanKindHint::Internal) | None => SpanKind::Internal,
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

fn otel_attribute_value_to_key_value(key: String, value: OtelAttributeValue) -> KeyValue {
    KeyValue::new(key, otel_attribute_value_to_value(value))
}

fn otel_attribute_value_to_value(value: OtelAttributeValue) -> Value {
    match value {
        OtelAttributeValue::String(value) => Value::String(value.into()),
        OtelAttributeValue::I64(value) => Value::I64(value),
        OtelAttributeValue::F64(value) => Value::F64(value),
        OtelAttributeValue::Bool(value) => Value::Bool(value),
        OtelAttributeValue::StringArray(values) => {
            Value::Array(Array::String(values.into_iter().map(Into::into).collect()))
        }
    }
}

fn otel_attribute_value_to_any_value(value: OtelAttributeValue) -> AnyValue {
    match value {
        OtelAttributeValue::String(value) => AnyValue::from(value),
        OtelAttributeValue::I64(value) => AnyValue::from(value),
        OtelAttributeValue::F64(value) => AnyValue::from(value),
        OtelAttributeValue::Bool(value) => AnyValue::from(value),
        OtelAttributeValue::StringArray(values) => {
            values.into_iter().map(AnyValue::from).collect::<AnyValue>()
        }
    }
}

fn normalize_grpc_endpoint(endpoint: &str) -> String {
    endpoint
        .strip_prefix("grpc://")
        .map(|authority| format!("http://{authority}"))
        .unwrap_or_else(|| endpoint.to_owned())
}

fn severity_number(result: ActivityResult) -> Severity {
    match result {
        ActivityResult::Ok => Severity::Info,
        ActivityResult::PendingApproval => Severity::Warn,
        ActivityResult::Denied | ActivityResult::Error => Severity::Error,
    }
}

fn severity_text(result: ActivityResult) -> &'static str {
    match result {
        ActivityResult::Ok => "INFO",
        ActivityResult::PendingApproval => "WARN",
        ActivityResult::Denied | ActivityResult::Error => "ERROR",
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

#[cfg(all(test, feature = "otel"))]
mod tests {
    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};
    use crate::genai::OtelAttributeValue;
    use opentelemetry::{trace::SpanKind, Value};
    use serde_json::json;

    #[test]
    fn maps_activity_event_to_otel_log_fields() {
        let event = ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::SandboxCreate,
            ActivityResult::Ok,
            "trace-otel",
        )
        .with_env("demo")
        .with_reason_code("created")
        .with_latency_ms(42);

        let mapped = map_event_to_otel_fields(&event);

        assert_eq!(mapped["agentenv.kind"], "sandbox_create");
        assert_eq!(mapped["agentenv.env"], "demo");
        assert_eq!(mapped["agentenv.result"], "ok");
        assert_eq!(mapped["agentenv.reason_code"], "created");
        assert_eq!(mapped["agentenv.trace_id"], "trace-otel");
        assert_eq!(mapped["agentenv.latency_ms"], "42");
    }

    #[test]
    fn maps_build_activity_kinds_to_otel_names() {
        assert_eq!(
            activity_kind_name(ActivityKind::BuildOneflightHit),
            "build_oneflight_hit"
        );
        assert_eq!(
            activity_kind_name(ActivityKind::BuildOneflightMiss),
            "build_oneflight_miss"
        );
        assert_eq!(
            activity_kind_name(ActivityKind::BuildQueueDepth),
            "build_queue_depth"
        );
    }

    #[test]
    fn plans_model_call_genai_span_export() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::GenAiModelCall,
            ActivityResult::Ok,
            "trace-model",
        )
        .with_extra("gen_ai.request.model", json!("gpt-4.1"))
        .with_extra("gen_ai.usage.input_tokens", json!(123))
        .with_extra("gen_ai.usage.output_tokens", json!(45));

        let plan = genai_span_export_plan(&event).expect("model call should be a span");

        assert_eq!(plan.name, "chat gpt-4.1");
        assert_eq!(plan.kind, SpanKind::Client);
        assert_span_attr(
            &plan.attributes,
            "gen_ai.operation.name",
            Value::String("chat".to_owned().into()),
        );
        assert_span_attr(
            &plan.attributes,
            "gen_ai.request.model",
            Value::String("gpt-4.1".to_owned().into()),
        );
        assert_span_attr(
            &plan.attributes,
            "gen_ai.usage.input_tokens",
            Value::I64(123),
        );
        assert_span_attr(
            &plan.attributes,
            "gen_ai.usage.output_tokens",
            Value::I64(45),
        );
    }

    #[test]
    fn plans_mcp_tool_call_genai_span_export() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::McpToolCall,
            ActivityResult::Ok,
            "trace-tool",
        )
        .with_subject_value("name", json!("repo.search"));

        let plan = genai_span_export_plan(&event).expect("tool call should be a span");

        assert_eq!(plan.name, "execute_tool repo.search");
        assert_eq!(plan.kind, SpanKind::Internal);
        assert_span_attr(
            &plan.attributes,
            "gen_ai.operation.name",
            Value::String("execute_tool".to_owned().into()),
        );
        assert_span_attr(
            &plan.attributes,
            "gen_ai.tool.name",
            Value::String("repo.search".to_owned().into()),
        );
    }

    #[test]
    fn maps_non_span_genai_semantic_attributes_for_logs() {
        let event = ActivityEvent::new(
            "2026-05-18T12:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-denied",
        )
        .with_latency_ms(42);

        let attributes = genai_log_attributes(&event);

        assert_eq!(
            attributes.get("agentenv.egress.denied"),
            Some(&OtelAttributeValue::Bool(true))
        );
        assert!(!attributes.contains_key("agentenv.trace_id"));
        assert!(!attributes.contains_key("agentenv.latency_ms"));
    }

    fn assert_span_attr(attributes: &[opentelemetry::KeyValue], key: &str, value: Value) {
        assert_eq!(
            attributes
                .iter()
                .find(|attribute| attribute.key.as_str() == key)
                .map(|attribute| &attribute.value),
            Some(&value)
        );
    }
}
