use std::{sync::Arc, time::Duration};

use serde::Serialize;
use time::OffsetDateTime;

use crate::config::{ApprovalConfig, SlackConfig, WebhookTargetConfig};
use crate::model::{format_rfc3339, ApprovalKind, ApprovalRequest};
use crate::signing::sign_payload;
use crate::slack::SlackApprovalMessage;
use crate::store::{ApprovalDeliveryAttemptRecord, ApprovalStore, ApprovalStoreError};

pub type UrlValidator = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
pub struct ApprovalNotifier {
    config: ApprovalConfig,
    client: reqwest::Client,
    validate_url: UrlValidator,
}

#[derive(Debug, thiserror::Error)]
pub enum ApprovalNotificationError {
    #[error(transparent)]
    Store(#[from] ApprovalStoreError),
    #[error("approval delivery payload JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("approval delivery HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
}

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

impl ApprovalNotifier {
    pub fn from_config(
        config: ApprovalConfig,
        validate_url: UrlValidator,
    ) -> Result<Option<Self>, ApprovalNotificationError> {
        if config.approvals.webhooks.is_empty() && config.approvals.slack.is_none() {
            return Ok(None);
        }

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Some(Self {
            config,
            client,
            validate_url,
        }))
    }

    pub async fn notify_request(
        &self,
        store: &ApprovalStore,
        request: &ApprovalRequest,
    ) -> Result<(), ApprovalNotificationError> {
        for target in self.targets_for_request(request) {
            let target_id = store.insert_delivery_target(
                Some(&request.env),
                target.kind_filter(),
                target.channel(),
                target.url(),
                target.secret_ref(),
            )?;
            let delivery_id = store.enqueue_delivery_attempt(
                &request.id,
                target_id,
                OffsetDateTime::now_utc(),
            )?;
            self.deliver_attempt(store, request, &target, delivery_id, 0)
                .await?;
        }
        Ok(())
    }

    pub async fn retry_due(
        &self,
        store: &ApprovalStore,
        now: OffsetDateTime,
    ) -> Result<usize, ApprovalNotificationError> {
        let attempts = store.due_delivery_attempts(now)?;
        let mut delivered = 0;
        for attempt in attempts {
            let Some(target) = self.target_for_attempt(&attempt) else {
                store.record_delivery_terminal_failure(
                    attempt.id,
                    "delivery target is no longer configured",
                )?;
                continue;
            };
            if attempt.attempt_count >= target.max_attempts() {
                store.record_delivery_terminal_failure(
                    attempt.id,
                    "delivery target reached maximum attempts",
                )?;
                continue;
            }
            self.deliver_attempt(
                store,
                &attempt.request,
                &target,
                attempt.id,
                attempt.attempt_count,
            )
            .await?;
            delivered += 1;
        }
        Ok(delivered)
    }

    fn targets_for_request(&self, request: &ApprovalRequest) -> Vec<DeliveryTarget> {
        let mut targets = Vec::new();
        targets.extend(
            self.config
                .approvals
                .webhooks
                .iter()
                .filter(|target| target.kinds.is_empty() || target.kinds.contains(&request.kind))
                .cloned()
                .map(DeliveryTarget::Webhook),
        );
        if let Some(slack) = &self.config.approvals.slack {
            targets.push(DeliveryTarget::Slack(slack.clone()));
        }
        targets
    }

    fn target_for_attempt(
        &self,
        attempt: &ApprovalDeliveryAttemptRecord,
    ) -> Option<DeliveryTarget> {
        match attempt.target.channel.as_str() {
            "webhook" => self
                .config
                .approvals
                .webhooks
                .iter()
                .find(|target| target.url == attempt.target.url)
                .cloned()
                .map(DeliveryTarget::Webhook),
            "slack" => self
                .config
                .approvals
                .slack
                .as_ref()
                .filter(|target| target.webhook_url == attempt.target.url)
                .cloned()
                .map(DeliveryTarget::Slack),
            _ => None,
        }
    }

    async fn deliver_attempt(
        &self,
        store: &ApprovalStore,
        request: &ApprovalRequest,
        target: &DeliveryTarget,
        delivery_id: i64,
        attempt_count: u32,
    ) -> Result<(), ApprovalNotificationError> {
        let next_attempt = attempt_count.saturating_add(1);
        match self.send_target(request, target, delivery_id).await {
            Ok(()) => store.record_delivery_success(delivery_id)?,
            Err(error) if next_attempt >= target.max_attempts() => {
                store.record_delivery_terminal_failure(delivery_id, &error)?;
            }
            Err(error) => {
                let retry_at = OffsetDateTime::now_utc()
                    + time::Duration::try_from(retry_delay_for_attempt(next_attempt))
                        .unwrap_or(time::Duration::MAX);
                store.record_delivery_failure(delivery_id, retry_at, &error)?;
            }
        }
        Ok(())
    }

    async fn send_target(
        &self,
        request: &ApprovalRequest,
        target: &DeliveryTarget,
        delivery_id: i64,
    ) -> Result<(), String> {
        (self.validate_url)(target.url())?;
        let delivery = target
            .delivery_request(request)
            .map_err(|error| error.to_string())?;
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let delivery_id = delivery_id.to_string();
        let mut builder = self
            .client
            .post(&delivery.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(delivery.body.clone());

        if let Some(secret) = delivery.secret.as_deref() {
            let signature = sign_payload(secret, timestamp, &delivery_id, &delivery.body);
            builder = builder
                .header("x-agentenv-signature", signature.header_value())
                .header("x-agentenv-timestamp", timestamp.to_string())
                .header("x-agentenv-delivery", delivery_id);
        }

        let response = builder.send().await.map_err(|error| error.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("http {}", response.status()))
        }
    }
}

#[derive(Clone)]
enum DeliveryTarget {
    Webhook(WebhookTargetConfig),
    Slack(SlackConfig),
}

struct DeliveryRequest {
    url: String,
    body: Vec<u8>,
    secret: Option<String>,
}

impl DeliveryTarget {
    fn channel(&self) -> &'static str {
        match self {
            Self::Webhook(_) => "webhook",
            Self::Slack(_) => "slack",
        }
    }

    fn url(&self) -> &str {
        match self {
            Self::Webhook(target) => &target.url,
            Self::Slack(target) => &target.webhook_url,
        }
    }

    fn kind_filter(&self) -> &[ApprovalKind] {
        match self {
            Self::Webhook(target) => &target.kinds,
            Self::Slack(_) => &[],
        }
    }

    fn secret_ref(&self) -> Option<&str> {
        match self {
            Self::Webhook(target) => target.secret_ref.as_deref(),
            Self::Slack(_) => None,
        }
    }

    fn max_attempts(&self) -> u32 {
        match self {
            Self::Webhook(target) => target.max_attempts.unwrap_or(6).max(1),
            Self::Slack(_) => 6,
        }
    }

    fn delivery_request(
        &self,
        request: &ApprovalRequest,
    ) -> Result<DeliveryRequest, serde_json::Error> {
        match self {
            Self::Webhook(target) => Ok(DeliveryRequest {
                url: target.url.clone(),
                body: serde_json::to_vec(&WebhookPayload::from_request(
                    request,
                    target.callback_url.as_deref(),
                ))?,
                secret: webhook_secret(target),
            }),
            Self::Slack(target) => {
                let mut body = serde_json::to_value(SlackApprovalMessage::from_request(
                    request,
                    target.callback_url.as_deref(),
                ))?;
                if let (Some(channel), serde_json::Value::Object(fields)) =
                    (target.channel.as_ref(), &mut body)
                {
                    fields.insert(
                        "channel".to_owned(),
                        serde_json::Value::String(channel.clone()),
                    );
                }
                Ok(DeliveryRequest {
                    url: target.webhook_url.clone(),
                    body: serde_json::to_vec(&body)?,
                    secret: None,
                })
            }
        }
    }
}

fn webhook_secret(target: &WebhookTargetConfig) -> Option<String> {
    target
        .secret
        .as_deref()
        .and_then(resolve_inline_or_env_secret)
        .or_else(|| {
            target
                .secret_ref
                .as_deref()
                .and_then(resolve_env_secret_ref)
        })
}

fn resolve_inline_or_env_secret(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(name) = env_placeholder_name(trimmed) {
        return std::env::var(name)
            .ok()
            .filter(|secret| !secret.trim().is_empty());
    }
    if let Some(name) = trimmed.strip_prefix("env:") {
        return std::env::var(name)
            .ok()
            .filter(|secret| !secret.trim().is_empty());
    }
    Some(trimmed.to_owned())
}

fn resolve_env_secret_ref(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let name = env_placeholder_name(trimmed)
        .or_else(|| trimmed.strip_prefix("env:"))
        .unwrap_or(trimmed);
    std::env::var(name)
        .ok()
        .filter(|secret| !secret.trim().is_empty())
}

fn env_placeholder_name(value: &str) -> Option<&str> {
    value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|name| !name.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;

    use serde_json::json;
    use time::OffsetDateTime;

    use crate::config::{ApprovalConfig, ApprovalConfigBody, SlackConfig, WebhookTargetConfig};
    use crate::coordinator::{ApprovalCoordinator, ApprovalCoordinatorConfig};
    use crate::model::{ApprovalKind, ApprovalRequest, ApprovalScope};
    use crate::signing::verify_payload;
    use crate::store::ApprovalStore;

    use super::*;

    fn test_request(id: &str) -> ApprovalRequest {
        ApprovalRequest::new(
            id,
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "network access",
            json!({"url": "https://api.example.test/v1"}),
            OffsetDateTime::from_unix_timestamp(1_777_443_200).unwrap(),
            ApprovalScope::Session,
            Duration::from_secs(30),
            format!("trace-{id}"),
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
            &test_request("req-1"),
            Some("https://approvals.example.test/callback"),
        );

        assert_eq!(payload.request_id, "req-1");
        assert_eq!(
            payload.callback_url.as_deref(),
            Some("https://approvals.example.test/callback")
        );
    }

    #[tokio::test]
    async fn coordinator_posts_signed_webhook_and_records_success() {
        let server = TestHttpServer::new(vec![200]);
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        let coordinator = ApprovalCoordinator::new(ApprovalCoordinatorConfig {
            store,
            events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
            poll_interval: Duration::from_millis(10),
            overlay_path: None,
            proposal_path: None,
            notifications: ApprovalNotifier::from_config(
                webhook_config(server.url(), Some("secret")),
                allow_all_urls(),
            )
            .unwrap()
            .map(std::sync::Arc::new),
        });

        coordinator
            .submit_request(test_request("req-webhook"))
            .await
            .unwrap();

        let captured = server.next_request();
        assert_eq!(captured.method, "POST");
        assert!(captured
            .body
            .contains("\"schema\":\"agentenv.approvals.webhook.v1\""));
        assert!(captured.body.contains("\"request_id\":\"req-webhook\""));

        let signature = captured.header("x-agentenv-signature").unwrap();
        let timestamp = captured
            .header("x-agentenv-timestamp")
            .unwrap()
            .parse::<i64>()
            .unwrap();
        let delivery_id = captured.header("x-agentenv-delivery").unwrap();
        assert!(verify_payload(
            "secret",
            timestamp,
            delivery_id,
            captured.body.as_bytes(),
            signature
        )
        .unwrap());

        let (status, attempt_count) = delivery_state(coordinator.store(), "req-webhook");
        assert_eq!(status, "delivered");
        assert_eq!(attempt_count, 1);
    }

    #[tokio::test]
    async fn coordinator_retries_failed_webhook_delivery() {
        let server = TestHttpServer::new(vec![503, 200]);
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        let coordinator = ApprovalCoordinator::new(ApprovalCoordinatorConfig {
            store,
            events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
            poll_interval: Duration::from_millis(10),
            overlay_path: None,
            proposal_path: None,
            notifications: ApprovalNotifier::from_config(
                webhook_config(server.url(), Some("secret")),
                allow_all_urls(),
            )
            .unwrap()
            .map(std::sync::Arc::new),
        });

        coordinator
            .submit_request(test_request("req-retry"))
            .await
            .unwrap();
        let first = server.next_request();
        assert!(first.body.contains("\"request_id\":\"req-retry\""));
        let (status, attempt_count) = delivery_state(coordinator.store(), "req-retry");
        assert_eq!(status, "pending");
        assert_eq!(attempt_count, 1);

        let retried = coordinator
            .retry_due_deliveries(OffsetDateTime::now_utc() + time::Duration::seconds(2))
            .await
            .unwrap();

        assert_eq!(retried, 1);
        let second = server.next_request();
        assert!(second.body.contains("\"request_id\":\"req-retry\""));
        let (status, attempt_count) = delivery_state(coordinator.store(), "req-retry");
        assert_eq!(status, "delivered");
        assert_eq!(attempt_count, 2);
    }

    #[tokio::test]
    async fn coordinator_posts_configured_slack_message() {
        let server = TestHttpServer::new(vec![200]);
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        let coordinator = ApprovalCoordinator::new(ApprovalCoordinatorConfig {
            store,
            events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
            poll_interval: Duration::from_millis(10),
            overlay_path: None,
            proposal_path: None,
            notifications: ApprovalNotifier::from_config(
                slack_config(server.url()),
                allow_all_urls(),
            )
            .unwrap()
            .map(std::sync::Arc::new),
        });

        coordinator
            .submit_request(test_request("req-slack"))
            .await
            .unwrap();

        let captured = server.next_request();
        assert_eq!(captured.method, "POST");
        assert!(captured
            .body
            .contains("\"channel\":\"#agentenv-approvals\""));
        assert!(captured
            .body
            .contains("\"text\":\"agentenv approval requested\""));
        assert!(captured.body.contains("approve:req-slack"));
        assert!(captured.body.contains("deny:req-slack"));

        let (status, attempt_count) = delivery_state(coordinator.store(), "req-slack");
        assert_eq!(status, "delivered");
        assert_eq!(attempt_count, 1);
    }

    #[tokio::test]
    #[ignore = "requires AGENTENV_EXTERNAL_APPROVAL_WEBHOOK_URL"]
    async fn live_external_approval_webhook_delivery() {
        let Ok(url) = std::env::var("AGENTENV_EXTERNAL_APPROVAL_WEBHOOK_URL") else {
            eprintln!(
                "skipping live external approval webhook test: set AGENTENV_EXTERNAL_APPROVAL_WEBHOOK_URL"
            );
            return;
        };
        if url.trim().is_empty() {
            eprintln!(
                "skipping live external approval webhook test: AGENTENV_EXTERNAL_APPROVAL_WEBHOOK_URL is empty"
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        let coordinator = ApprovalCoordinator::new(ApprovalCoordinatorConfig {
            store,
            events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
            poll_interval: Duration::from_millis(10),
            overlay_path: None,
            proposal_path: None,
            notifications: ApprovalNotifier::from_config(
                webhook_config(url, Some("external-check-secret")),
                allow_all_urls(),
            )
            .unwrap()
            .map(std::sync::Arc::new),
        });

        coordinator
            .submit_request(test_request("req-live-external"))
            .await
            .unwrap();

        let (status, attempt_count) = delivery_state(coordinator.store(), "req-live-external");
        assert_eq!(status, "delivered");
        assert_eq!(attempt_count, 1);
    }

    fn webhook_config(url: String, secret: Option<&str>) -> ApprovalConfig {
        ApprovalConfig {
            approvals: ApprovalConfigBody {
                webhooks: vec![WebhookTargetConfig {
                    url,
                    secret: secret.map(str::to_owned),
                    secret_ref: None,
                    kinds: vec![ApprovalKind::EgressHost],
                    callback_url: Some("https://approvals.example.test/callback".to_owned()),
                    max_attempts: Some(3),
                }],
                slack: None,
                auto_deny_after: Default::default(),
            },
        }
    }

    fn slack_config(url: String) -> ApprovalConfig {
        ApprovalConfig {
            approvals: ApprovalConfigBody {
                webhooks: Vec::new(),
                slack: Some(SlackConfig {
                    webhook_url: url,
                    channel: Some("#agentenv-approvals".to_owned()),
                    signing_secret: None,
                    callback_url: Some("https://approvals.example.test/slack".to_owned()),
                }),
                auto_deny_after: Default::default(),
            },
        }
    }

    fn allow_all_urls() -> UrlValidator {
        std::sync::Arc::new(|_| Ok(()))
    }

    fn delivery_state(store: &ApprovalStore, request_id: &str) -> (String, i64) {
        let attempts = store
            .due_delivery_attempts(OffsetDateTime::now_utc() + time::Duration::days(1))
            .unwrap();
        if let Some(attempt) = attempts
            .iter()
            .find(|attempt| attempt.request.id == request_id)
        {
            return ("pending".to_owned(), i64::from(attempt.attempt_count));
        }

        let conn = rusqlite::Connection::open(store.path_for_test()).unwrap();
        conn.query_row(
            "SELECT status, attempt_count FROM approval_delivery_attempts WHERE request_id = ?1",
            rusqlite::params![request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    struct CapturedRequest {
        method: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    struct TestHttpServer {
        url: String,
        requests: Receiver<CapturedRequest>,
    }

    impl TestHttpServer {
        fn new(statuses: Vec<u16>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let (sender, requests) = mpsc::channel();
            thread::spawn(move || {
                for status in statuses {
                    let (mut stream, _) = listener.accept().unwrap();
                    let captured = read_http_request(&mut stream);
                    sender.send(captured).unwrap();
                    let response = format!(
                        "HTTP/1.1 {status} test\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                }
            });
            Self {
                url: format!("http://{addr}/approval"),
                requests,
            }
        }

        fn url(&self) -> String {
            self.url.clone()
        }

        fn next_request(&self) -> CapturedRequest {
            self.requests.recv_timeout(Duration::from_secs(5)).unwrap()
        }
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> CapturedRequest {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if request_is_complete(&buffer) {
                break;
            }
        }

        let raw = String::from_utf8_lossy(&buffer);
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        let mut lines = head.lines();
        let method = lines
            .next()
            .and_then(|line| line.split_whitespace().next())
            .unwrap()
            .to_owned();
        let headers = lines
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                Some((key.trim().to_owned(), value.trim().to_owned()))
            })
            .collect();
        CapturedRequest {
            method,
            headers,
            body: body.to_owned(),
        }
    }

    fn request_is_complete(buffer: &[u8]) -> bool {
        let raw = String::from_utf8_lossy(buffer);
        let Some((head, body)) = raw.split_once("\r\n\r\n") else {
            return false;
        };
        let content_length = head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        body.len() >= content_length
    }
}
