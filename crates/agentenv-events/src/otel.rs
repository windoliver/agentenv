use std::collections::BTreeMap;

use opentelemetry::{
    logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity},
    Key,
};
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider, SimpleLogProcessor};

use crate::{
    activity::{ActivityEvent, ActivityKind, ActivityResult},
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
    provider: SdkLoggerProvider,
}

impl OtelSink {
    pub fn new(endpoint: impl Into<String>) -> Result<Self, SinkError> {
        let endpoint = endpoint.into();
        let exporter_config = ExportConfig {
            endpoint: Some(normalize_grpc_endpoint(&endpoint)),
            protocol: Protocol::Grpc,
            timeout: None,
        };
        let exporter = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_export_config(exporter_config)
            .build()?;
        let provider = SdkLoggerProvider::builder()
            .with_log_processor(SimpleLogProcessor::new(exporter))
            .build();
        let logger = provider.logger("agentenv-events");

        Ok(Self {
            endpoint,
            logger,
            provider,
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
            self.logger.emit(record);
        }
        let _ = &self.provider;
        Ok(())
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
        ActivityKind::Log => "log",
    }
}

#[cfg(all(test, feature = "otel"))]
mod tests {
    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

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
}
