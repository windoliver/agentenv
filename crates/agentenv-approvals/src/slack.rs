use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

use crate::model::{format_rfc3339, ApprovalKind, ApprovalRequest};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize)]
pub struct SlackApprovalMessage {
    text: String,
    blocks: Vec<SlackBlock>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SlackBlock {
    Header {
        text: SlackText,
    },
    Section {
        text: SlackText,
        fields: Vec<SlackText>,
    },
    Context {
        elements: Vec<SlackText>,
    },
    Actions {
        elements: Vec<SlackButton>,
    },
}

#[derive(Debug, Clone, Serialize)]
struct SlackText {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    emoji: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct SlackButton {
    #[serde(rename = "type")]
    kind: &'static str,
    text: SlackText,
    value: String,
    action_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    style: Option<&'static str>,
}

#[derive(Debug, thiserror::Error)]
pub enum SlackSignatureError {
    #[error("invalid Slack HMAC signing key length")]
    InvalidKeyLength,
}

impl SlackApprovalMessage {
    pub fn from_request(request: &ApprovalRequest, callback_url: Option<&str>) -> Self {
        let mut blocks = vec![
            SlackBlock::Header {
                text: plain_text("agentenv approval requested"),
            },
            SlackBlock::Section {
                text: mrkdwn("agentenv approval requested"),
                fields: vec![
                    field("Env", &request.env),
                    field("Kind", approval_kind_label(request.kind)),
                    field("Subject", &request.subject),
                    field("Expiry", &format_rfc3339(request.expires_at)),
                ],
            },
            SlackBlock::Context {
                elements: vec![mrkdwn(format!(
                    "request id: `{}`",
                    escape_mrkdwn(&request.id)
                ))],
            },
        ];

        if callback_url.is_some() {
            blocks.push(SlackBlock::Actions {
                elements: vec![
                    SlackButton {
                        kind: "button",
                        text: plain_text("Approve"),
                        value: format!("approve:{}", request.id),
                        action_id: "agentenv_approve".to_owned(),
                        style: Some("primary"),
                    },
                    SlackButton {
                        kind: "button",
                        text: plain_text("Deny"),
                        value: format!("deny:{}", request.id),
                        action_id: "agentenv_deny".to_owned(),
                        style: Some("danger"),
                    },
                ],
            });
        } else {
            blocks.push(SlackBlock::Section {
                text: mrkdwn(format!(
                    "Run:\n`agentenv approvals approve {} --env {}`\n`agentenv approvals deny {} --env {}`",
                    escape_mrkdwn(&request.id),
                    escape_mrkdwn(&request.env),
                    escape_mrkdwn(&request.id),
                    escape_mrkdwn(&request.env)
                )),
                fields: Vec::new(),
            });
        }

        Self {
            text: "agentenv approval requested".to_owned(),
            blocks,
        }
    }
}

pub fn verify_slack_signature(
    secret: &str,
    timestamp: i64,
    signature_header: &str,
    raw_body: &[u8],
    now_unix_seconds: i64,
) -> Result<bool, SlackSignatureError> {
    if timestamp.abs_diff(now_unix_seconds) > 300 {
        return Ok(false);
    }

    let Some(signature_hex) = signature_header.strip_prefix("v0=") else {
        return Ok(false);
    };
    let Ok(signature) = hex::decode(signature_hex) else {
        return Ok(false);
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| SlackSignatureError::InvalidKeyLength)?;
    mac.update(b"v0:");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b":");
    mac.update(raw_body);

    Ok(mac.verify_slice(&signature).is_ok())
}

fn plain_text(text: impl Into<String>) -> SlackText {
    SlackText {
        kind: "plain_text",
        text: text.into(),
        emoji: Some(true),
    }
}

fn mrkdwn(text: impl Into<String>) -> SlackText {
    SlackText {
        kind: "mrkdwn",
        text: text.into(),
        emoji: None,
    }
}

fn field(label: &str, value: &str) -> SlackText {
    mrkdwn(format!("*{label}*\n{}", escape_mrkdwn(value)))
}

fn approval_kind_label(kind: ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::EgressHost => "egress_host",
        ApprovalKind::McpTool => "mcp_tool",
        ApprovalKind::ZoneAccess => "zone_access",
        ApprovalKind::PackageInstall => "package_install",
    }
}

fn escape_mrkdwn(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use time::OffsetDateTime;

    use super::*;
    use crate::model::{ApprovalKind, ApprovalRequest, ApprovalScope};

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
    fn slack_message_omits_buttons_without_callback_url() {
        let message = SlackApprovalMessage::from_request(&test_request(), None);
        let rendered = serde_json::to_value(message).unwrap();

        assert!(!rendered.to_string().contains("\"actions\""));
        assert!(rendered
            .to_string()
            .contains("agentenv approvals approve req-1"));
    }

    #[test]
    fn slack_message_includes_approve_and_deny_buttons_with_callback_url() {
        let message = SlackApprovalMessage::from_request(
            &test_request(),
            Some("https://approvals.example.test/slack/interactions"),
        );
        let rendered = serde_json::to_value(message).unwrap().to_string();

        assert!(rendered.contains("approve:req-1"));
        assert!(rendered.contains("deny:req-1"));
    }

    #[test]
    fn slack_signature_rejects_stale_timestamp() {
        let result = verify_slack_signature(
            "secret",
            1_777_443_200,
            "v0=bad",
            b"payload={}",
            1_777_443_900,
        )
        .unwrap();

        assert!(!result);
    }
}
