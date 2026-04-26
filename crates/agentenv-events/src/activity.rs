use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::redaction::redact_json_value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    SandboxCreate,
    SandboxDestroy,
    Exec,
    EgressAllowed,
    EgressDenied,
    McpToolCall,
    PolicyApplied,
    CredentialInjected,
    CredentialSet,
    CredentialReset,
    Auth,
    ApprovalRequested,
    ApprovalDecided,
    SpawnRequested,
    SpawnQueued,
    SpawnAdmitted,
    SpawnRejected,
    SpawnStarted,
    SpawnReady,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityResult {
    Ok,
    Error,
    Denied,
    PendingApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Core,
    Cli,
    SandboxDriver,
    AgentDriver,
    ContextDriver,
    InferenceDriver,
    PluginDriver,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub ts: String,
    pub kind: ActivityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subject: BTreeMap<String, Value>,
    pub result: ActivityResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extras: BTreeMap<String, Value>,
}

impl ActivityEvent {
    pub fn new(
        ts: impl Into<String>,
        kind: ActivityKind,
        result: ActivityResult,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            ts: ts.into(),
            kind,
            env: None,
            actor: BTreeMap::new(),
            subject: BTreeMap::new(),
            result,
            latency_ms: None,
            trace_id: trace_id.into(),
            reason_code: None,
            extras: BTreeMap::new(),
        }
    }

    pub fn with_env(mut self, env: impl Into<String>) -> Self {
        self.env = Some(env.into());
        self
    }

    pub fn with_actor_value(mut self, key: impl Into<String>, value: Value) -> Self {
        self.actor.insert(key.into(), value);
        self
    }

    pub fn with_subject_value(mut self, key: impl Into<String>, value: Value) -> Self {
        self.subject.insert(key.into(), value);
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extras.insert(key.into(), value);
        self
    }

    pub fn with_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        self.reason_code = Some(reason_code.into());
        self
    }

    pub fn with_latency_ms(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    pub fn redacted(mut self) -> Self {
        self.actor = redact_event_map(self.actor);
        self.subject = redact_event_map(self.subject);
        self.extras = redact_event_map(self.extras);
        self
    }

    pub fn from_legacy_proto(
        legacy: agentenv_proto::ActivityEventParams,
        trace_id: impl Into<String>,
    ) -> Self {
        let (kind, result) = match legacy.kind {
            agentenv_proto::ActivityKind::EgressDenied => {
                (ActivityKind::EgressDenied, ActivityResult::Denied)
            }
            agentenv_proto::ActivityKind::ApprovalRequested => (
                ActivityKind::ApprovalRequested,
                ActivityResult::PendingApproval,
            ),
            agentenv_proto::ActivityKind::Log => (ActivityKind::Log, ActivityResult::Ok),
        };

        let mut event = ActivityEvent::new(legacy.ts, kind, result, trace_id)
            .with_subject_value("target", Value::String(legacy.subject));
        if let Some(reason) = legacy.reason {
            event = event.with_reason_code(reason);
        }
        if let Some(handle) = legacy.handle {
            event = event.with_subject_value("handle", Value::String(handle));
        }
        event
    }
}

fn redact_event_map(map: BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    let object = map.into_iter().collect();
    match redact_json_value(Value::Object(object)) {
        Value::Object(object) => object.into_iter().collect(),
        _ => BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{ActivityEvent, ActivityKind, ActivityResult};

    #[test]
    fn activity_kind_serializes_to_stable_snake_case() {
        assert_eq!(
            serde_json::to_value(ActivityKind::SandboxCreate).unwrap(),
            serde_json::json!("sandbox_create")
        );
        assert_eq!(
            serde_json::to_value(ActivityKind::SpawnRejected).unwrap(),
            serde_json::json!("spawn_rejected")
        );
        assert_eq!(
            serde_json::to_value(ActivityKind::CredentialReset).unwrap(),
            serde_json::json!("credential_reset")
        );
    }

    #[test]
    fn activity_event_redacts_secret_like_extras() {
        let event = ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::CredentialInjected,
            ActivityResult::Ok,
            "trace-1",
        )
        .with_env("demo")
        .with_subject_value("name", serde_json::json!("OPENAI_API_KEY"))
        .with_extra("token", serde_json::json!("sk-secret-value"))
        .redacted();

        let rendered = serde_json::to_string(&event).unwrap();
        assert!(rendered.contains("OPENAI_API_KEY"));
        assert!(!rendered.contains("sk-secret-value"));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn activity_event_redacts_secret_like_actor_subject_and_extras() {
        let event = ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::CredentialInjected,
            ActivityResult::Ok,
            "trace-1",
        )
        .with_actor_value("authorization", serde_json::json!("Bearer actor-secret"))
        .with_subject_value(
            "url",
            serde_json::json!("https://user:pass@example.test/path?token=secret#frag"),
        )
        .with_subject_value("credential", serde_json::json!("subject-secret"))
        .with_extra("token", serde_json::json!("extra-secret"))
        .redacted();

        let rendered = serde_json::to_string(&event).unwrap();
        assert!(!rendered.contains("actor-secret"));
        assert!(!rendered.contains("subject-secret"));
        assert!(!rendered.contains("extra-secret"));
        assert!(!rendered.contains("user:pass"));
        assert!(!rendered.contains("token=secret"));
        assert_eq!(
            event.actor["authorization"],
            serde_json::json!("[redacted]")
        );
        assert_eq!(event.subject["credential"], serde_json::json!("[redacted]"));
        assert_eq!(event.extras["token"], serde_json::json!("[redacted]"));
        assert_eq!(
            event.subject["url"],
            serde_json::json!("https://example.test/path")
        );
    }

    #[test]
    fn legacy_proto_activity_converts_to_rich_event() {
        let legacy = agentenv_proto::ActivityEventParams {
            kind: agentenv_proto::ActivityKind::EgressDenied,
            subject: "api.example.test:443".to_owned(),
            reason: Some("not_in_policy".to_owned()),
            ts: "2026-04-26T12:00:01Z".to_owned(),
            handle: Some("sb-1".to_owned()),
        };

        let event = ActivityEvent::from_legacy_proto(legacy, "trace-2");

        assert_eq!(event.kind, ActivityKind::EgressDenied);
        assert_eq!(event.result, ActivityResult::Denied);
        assert_eq!(event.reason_code.as_deref(), Some("not_in_policy"));
        assert_eq!(
            event.subject["target"],
            serde_json::json!("api.example.test:443")
        );
        assert_eq!(event.subject["handle"], serde_json::json!("sb-1"));
    }
}
