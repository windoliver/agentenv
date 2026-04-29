use std::time::Duration;

use serde::Serialize;

use crate::model::{format_rfc3339, ApprovalKind, ApprovalRequest};

#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    pub schema: &'static str,
    pub request_id: String,
    pub env: String,
    pub kind: ApprovalKind,
    pub subject: String,
    pub reason: String,
    pub context: serde_json::Value,
    pub requested_at: String,
    pub expires_at: String,
    pub callback_url: Option<String>,
}

impl WebhookPayload {
    pub fn from_request(request: &ApprovalRequest, callback_url: Option<&str>) -> Self {
        Self {
            schema: "agentenv.approvals.webhook.v1",
            request_id: request.id.clone(),
            env: request.env.clone(),
            kind: request.kind,
            subject: request.subject.clone(),
            reason: request.reason.clone(),
            context: request.context.clone(),
            requested_at: format_rfc3339(request.requested_at),
            expires_at: format_rfc3339(request.expires_at),
            callback_url: callback_url.map(str::to_owned),
        }
    }
}

pub fn retry_delay_for_attempt(attempt: u32) -> Duration {
    match attempt {
        0 | 1 => Duration::from_secs(1),
        2 => Duration::from_secs(2),
        3 => Duration::from_secs(4),
        4 => Duration::from_secs(8),
        5 => Duration::from_secs(16),
        _ => Duration::from_secs(30),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;

    use crate::model::{ApprovalKind, ApprovalRequest, ApprovalScope};

    use super::*;

    fn test_request() -> ApprovalRequest {
        ApprovalRequest::new(
            "req-1",
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "network access",
            json!({"url": "https://api.example.test/v1"}),
            OffsetDateTime::from_unix_timestamp(1_777_443_200).unwrap(),
            ApprovalScope::Session,
            Duration::from_secs(30),
            "trace-1",
        )
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(retry_delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(retry_delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(retry_delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(retry_delay_for_attempt(10), Duration::from_secs(30));
    }

    #[test]
    fn webhook_payload_contains_callback_url_when_configured() {
        let payload = WebhookPayload::from_request(
            &test_request(),
            Some("https://approvals.example.test/callback"),
        );

        assert_eq!(payload.request_id, "req-1");
        assert_eq!(
            payload.callback_url.as_deref(),
            Some("https://approvals.example.test/callback")
        );
    }
}
