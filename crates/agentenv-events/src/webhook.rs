use std::sync::Arc;

use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
use url::Url;

use crate::{
    activity::{ActivityEvent, ActivityKind},
    sink::{EventSink, SinkError},
};

const ACTIVITY_SCHEMA: &str = "agentenv.activity.v1";

pub type WebhookUrlValidator = Arc<dyn Fn(&Url) -> Result<(), SinkError> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookConfig {
    pub url: Url,
    pub kinds: Vec<ActivityKind>,
}

impl WebhookConfig {
    pub fn parse(raw: &str) -> Result<Self, WebhookError> {
        let mut url = Url::parse(raw).map_err(|source| WebhookError::InvalidUrl {
            url: raw.to_owned(),
            source,
        })?;

        if url.scheme() != "https" {
            return Err(WebhookError::NonHttpsUrl {
                url: raw.to_owned(),
            });
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(WebhookError::CredentialsInUrl);
        }

        let mut kinds = Vec::new();
        let mut found_kind_filter = false;
        let query_pairs = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        for (key, value) in &query_pairs {
            if key == "kinds" {
                found_kind_filter = true;
                parse_kind_filter(value, &mut kinds)?;
            }
        }

        if found_kind_filter {
            remove_kinds_query_params(&mut url);
        }

        Ok(Self { url, kinds })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("invalid webhook URL `{url}`: {source}")]
    InvalidUrl {
        url: String,
        source: url::ParseError,
    },
    #[error("webhook URL must use https: {url}")]
    NonHttpsUrl { url: String },
    #[error("webhook URL must not include credentials")]
    CredentialsInUrl,
    #[error("invalid webhook kind filter `{kind}`")]
    InvalidKind { kind: String },
}

pub struct WebhookSink {
    config: WebhookConfig,
    client: reqwest::Client,
    validate_url: WebhookUrlValidator,
}

impl WebhookSink {
    pub fn new(config: WebhookConfig, validate_url: WebhookUrlValidator) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static webhook client configuration is valid"),
            validate_url,
        }
    }

    fn filtered_events(&self, events: Vec<ActivityEvent>) -> Vec<ActivityEvent> {
        if self.config.kinds.is_empty() {
            return events;
        }

        events
            .into_iter()
            .filter(|event| self.config.kinds.contains(&event.kind))
            .collect()
    }
}

#[async_trait::async_trait]
impl EventSink for WebhookSink {
    fn name(&self) -> &'static str {
        "webhook"
    }

    async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError> {
        let events = self.filtered_events(events);
        if events.is_empty() {
            return Ok(());
        }

        (self.validate_url)(&self.config.url)?;
        let body = serde_json::to_vec(&WebhookPayload {
            schema: ACTIVITY_SCHEMA,
            events: &events,
        })?;

        self.client
            .post(self.config.url.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[derive(Serialize)]
struct WebhookPayload<'a> {
    schema: &'static str,
    events: &'a [ActivityEvent],
}

fn parse_kind_filter(raw: &str, kinds: &mut Vec<ActivityKind>) -> Result<(), WebhookError> {
    for kind in raw.split(',').filter(|kind| !kind.is_empty()) {
        let parsed =
            serde_json::from_value(serde_json::Value::String(kind.to_owned())).map_err(|_| {
                WebhookError::InvalidKind {
                    kind: kind.to_owned(),
                }
            })?;
        if !kinds.contains(&parsed) {
            kinds.push(parsed);
        }
    }
    Ok(())
}

fn remove_kinds_query_params(url: &mut Url) {
    let retained = url
        .query_pairs()
        .filter(|(key, _)| key != "kinds")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();

    url.set_query(None);
    if !retained.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in retained {
            pairs.append_pair(&key, &value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{ActivityEvent, ActivityKind, ActivityResult};

    use super::*;

    #[test]
    fn webhook_config_rejects_credentials_in_url() {
        let err = WebhookConfig::parse("https://user:pass@example.test/events").unwrap_err();
        assert!(err.to_string().contains("credentials"));
    }

    #[test]
    fn webhook_config_extracts_kind_filter() {
        let config = WebhookConfig::parse(
            "https://example.test/events?kinds=egress_denied,approval_requested",
        )
        .unwrap();

        assert_eq!(config.kinds.len(), 2);
        assert!(config.kinds.contains(&ActivityKind::EgressDenied));
        assert!(config.kinds.contains(&ActivityKind::ApprovalRequested));
    }

    #[tokio::test]
    async fn webhook_sink_noops_when_kind_filter_excludes_all_events() {
        let config = WebhookConfig::parse("https://127.0.0.1:1/events?kinds=egress_denied")
            .expect("valid webhook config");
        let sink = WebhookSink::new(config, Arc::new(|_| Ok(())));
        let event = ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::Log,
            ActivityResult::Ok,
            "trace-webhook",
        );

        sink.write_batch(vec![event]).await.unwrap();
    }

    #[test]
    fn webhook_sink_client_disables_redirects() {
        let config =
            WebhookConfig::parse("https://example.test/events").expect("valid webhook config");
        let sink = WebhookSink::new(config, Arc::new(|_| Ok(())));
        let client_debug = format!("{:?}", sink.client);

        assert!(
            client_debug.contains("redirect_policy: Policy(None)"),
            "webhook client must disable redirects: {client_debug}"
        );
    }

    #[tokio::test]
    async fn webhook_sink_revalidates_url_before_each_send() {
        let config =
            WebhookConfig::parse("https://example.test/events").expect("valid webhook config");
        let sink = WebhookSink::new(
            config,
            Arc::new(|url| Err(SinkError::webhook_validation_failed(url, "blocked"))),
        );
        let event = ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-webhook-validation",
        );

        let error = sink.write_batch(vec![event]).await.unwrap_err();

        assert!(
            error.to_string().contains("blocked"),
            "unexpected error: {error}"
        );
    }
}
