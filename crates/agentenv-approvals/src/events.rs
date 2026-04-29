use agentenv_events::{ActivityEvent, ActivityKind, ActivityResult};
use serde::Serialize;
use serde_json::Value;

use crate::model::{
    format_rfc3339, ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalRequest,
};

pub fn approval_requested_event(request: &ApprovalRequest) -> ActivityEvent {
    ActivityEvent::new(
        format_rfc3339(request.requested_at),
        ActivityKind::ApprovalRequested,
        ActivityResult::PendingApproval,
        request.created_trace_id.clone(),
    )
    .with_env(request.env.clone())
    .with_subject_value("request_id", Value::String(request.id.clone()))
    .with_subject_value("kind", stable_serde_value(request.kind))
    .with_subject_value("subject", Value::String(request.subject.clone()))
    .with_extra("reason", Value::String(request.reason.clone()))
    .with_extra("context", request.context.clone())
    .with_extra("default_scope", stable_serde_value(request.default_scope))
    .with_extra(
        "expires_at",
        Value::String(format_rfc3339(request.expires_at)),
    )
}

pub fn approval_decided_event(
    request: &ApprovalRequest,
    decision: &ApprovalDecisionRecord,
) -> ActivityEvent {
    let result = match decision.decision {
        ApprovalDecisionValue::Allow => ActivityResult::Ok,
        ApprovalDecisionValue::Deny => ActivityResult::Denied,
    };

    ActivityEvent::new(
        format_rfc3339(decision.decided_at),
        ActivityKind::ApprovalDecided,
        result,
        decision.trace_id.clone(),
    )
    .with_env(request.env.clone())
    .with_subject_value("request_id", Value::String(request.id.clone()))
    .with_subject_value("kind", stable_serde_value(request.kind))
    .with_subject_value("subject", Value::String(request.subject.clone()))
    .with_extra("decision", stable_serde_value(decision.decision))
    .with_extra("scope", stable_serde_value(decision.scope))
    .with_extra("decided_by", Value::String(decision.decided_by.clone()))
    .with_extra(
        "decided_at",
        Value::String(format_rfc3339(decision.decided_at)),
    )
    .with_extra("reason", stable_serde_value(&decision.reason))
    .with_extra("original_context", request.context.clone())
    .with_extra("decision_context", decision.context.clone())
}

fn stable_serde_value(value: impl Serialize) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agentenv_events::{ActivityKind, ActivityResult};
    use serde_json::json;
    use time::OffsetDateTime;

    use crate::model::{
        ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalKind, ApprovalRequest, ApprovalScope,
    };

    use super::*;

    #[test]
    fn request_event_carries_full_audit_context() {
        let request = ApprovalRequest::new(
            "req-1",
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "agent fetch_url",
            json!({"url": "https://api.example.test/v1"}),
            OffsetDateTime::from_unix_timestamp(1_777_443_200).unwrap(),
            ApprovalScope::Session,
            Duration::from_secs(30),
            "trace-request",
        );

        let event = approval_requested_event(&request);

        assert_eq!(event.kind, ActivityKind::ApprovalRequested);
        assert_eq!(event.result, ActivityResult::PendingApproval);
        assert_eq!(event.env.as_deref(), Some("demo"));
        assert_eq!(event.subject["request_id"], json!("req-1"));
        assert_eq!(event.subject["subject"], json!("api.example.test:443"));
        assert_eq!(
            event.extras["context"]["url"],
            json!("https://api.example.test/v1")
        );
        assert_eq!(event.extras["default_scope"], json!("session"));
    }

    #[test]
    fn deny_decision_event_is_denied_result() {
        let request = ApprovalRequest::new(
            "req-1",
            "demo",
            ApprovalKind::McpTool,
            "filesystem.write",
            "unknown MCP tool",
            json!({"tool": "filesystem.write"}),
            OffsetDateTime::from_unix_timestamp(1_777_443_200).unwrap(),
            ApprovalScope::Once,
            Duration::from_secs(30),
            "trace-request",
        );
        let decision = ApprovalDecisionRecord {
            request_id: "req-1".to_owned(),
            decision: ApprovalDecisionValue::Deny,
            scope: ApprovalScope::Once,
            decided_by: "agentenv:auto-deny".to_owned(),
            decided_at: OffsetDateTime::from_unix_timestamp(1_777_443_230).unwrap(),
            reason: Some("auto_deny_timeout".to_owned()),
            context: json!({"source": "auto-deny"}),
            trace_id: "trace-decision".to_owned(),
        };

        let event = approval_decided_event(&request, &decision);

        assert_eq!(event.kind, ActivityKind::ApprovalDecided);
        assert_eq!(event.result, ActivityResult::Denied);
        assert_eq!(event.subject["request_id"], json!("req-1"));
        assert_eq!(
            event.extras["original_context"]["tool"],
            json!("filesystem.write")
        );
        assert_eq!(event.extras["reason"], json!("auto_deny_timeout"));
    }
}
