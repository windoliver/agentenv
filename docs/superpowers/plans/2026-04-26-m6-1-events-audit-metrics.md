# M6-1 Events Audit Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #23: structured activity events, SQLite and optional sinks, tamper-evident audit export/verify, and Prometheus metrics.

**Architecture:** `agentenv-events` becomes the central observability crate and no longer depends on `agentenv-core`, so `agentenv-core` can emit typed events without a dependency cycle. Runtime code emits through an `EventEmitter` abstraction; CLI code constructs the dispatcher and exposes reader/server commands; plugin JSON-RPC notifications convert into the same event model.

**Tech Stack:** Rust 2021, Tokio, serde/serde_json, rusqlite, sha2, hex, ed25519-dalek, hyper, reqwest with rustls, optional opentelemetry/opentelemetry-otlp for gated OTEL tests.

---

## File Structure

Create or modify these files:

- Modify `Cargo.toml`: add workspace dependencies for `rusqlite`, `hyper`, `http-body-util`, `bytes`, `rand_core`, `opentelemetry`, `opentelemetry_sdk`, and `opentelemetry-otlp`.
- Modify `crates/agentenv-events/Cargo.toml`: remove `agentenv-core`, add event, SQLite, signing, HTTP, Tokio, and optional OTEL dependencies.
- Replace `crates/agentenv-events/src/lib.rs`: export modules and keep small compatibility exports only.
- Create `crates/agentenv-events/src/activity.rs`: rich activity model, legacy proto conversion, kind/result enums, redaction entry points.
- Create `crates/agentenv-events/src/redaction.rs`: redacts URL credentials, query strings, fragments, and secret-looking values in JSON extras.
- Create `crates/agentenv-events/src/store.rs`: SQLite schema, append, query, follow cursor, aggregate queries, legacy JSONL fallback helpers.
- Create `crates/agentenv-events/src/sink.rs`: sink URI parser, sink trait, JSONL sink, SQLite sink adapter, webhook sink scaffolding.
- Create `crates/agentenv-events/src/dispatcher.rs`: bounded non-blocking dispatcher, no-op emitter, recording emitter for tests.
- Create `crates/agentenv-events/src/audit.rs`: audit policy, signing key management, hash-chain append, verify, JSONL/CSV export.
- Create `crates/agentenv-events/src/metrics.rs`: Prometheus text rendering from env state plus store aggregates.
- Create `crates/agentenv-events/src/webhook.rs`: SSRF-validated webhook sink using `reqwest`.
- Create `crates/agentenv-events/src/otel.rs`: feature-gated OTEL mapping and exporter sink.
- Modify `crates/agentenv-proto/src/schema_version.rs`: bump schema from `1.0` to `1.1`.
- Modify `crates/agentenv-proto/src/types.rs`: add rich driver activity notification params while preserving legacy params.
- Modify `crates/agentenv-proto/build.rs`: export new driver activity schema.
- Add generated schema `crates/agentenv-proto/schema/driver-activity-event-params.json` through build script output.
- Modify `crates/agentenv-plugin/src/jsonrpc.rs`: expose notification polling/handling instead of silently discarding notifications.
- Modify `crates/agentenv-plugin/src/lib.rs`: export notification helper types.
- Modify `crates/agentenv-core/Cargo.toml`: add `agentenv-events`.
- Modify `crates/agentenv-core/src/runtime.rs`: add observed variants for create/destroy/exec/status/logs and emit lifecycle events.
- Modify `crates/agentenv-core/src/security/ssrf.rs`: move SSRF-to-activity conversion here after dependency inversion.
- Modify `crates/agentenv/Cargo.toml`: add `agentenv-events`, `hyper`, `bytes`, and `http-body-util`.
- Modify `crates/agentenv/src/main.rs`: add global `--events-sink`, logs/store readers, audit commands, stats, metrics server, credential set/reset activity events.
- Modify `crates/agentenv/src/render.rs`: add activity, stats, audit, and metrics rendering helpers if output formatting becomes too large for `main.rs`.
- Modify `crates/agentenv/tests/cli_behavior.rs`: add CLI coverage for logs, stats, audit, and metrics.
- Modify `tests/driver-conformance/src/bin/mock-driver.rs`: emit activity/log notifications for plugin notification tests.
- Modify `tests/driver-conformance/tests/mock_driver.rs`: assert mock driver notifications are converted into persisted activity events.
- Modify `docs/DRIVER_PROTOCOL.md`: document protocol schema `1.1` and rich activity notification compatibility.
- Modify `crates/agentenv-events/README.md`: document event store, sinks, audit, and metrics commands.

## Task 1: Dependency Inversion And Activity Model

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agentenv-events/Cargo.toml`
- Replace: `crates/agentenv-events/src/lib.rs`
- Create: `crates/agentenv-events/src/activity.rs`
- Create: `crates/agentenv-events/src/redaction.rs`
- Modify: `crates/agentenv-core/Cargo.toml`
- Modify: `crates/agentenv-core/src/security/ssrf.rs`

- [ ] **Step 1: Write failing activity and redaction tests**

Add these tests to `crates/agentenv-events/src/activity.rs` inside `#[cfg(test)] mod tests`:

```rust
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
    .with_subject_value("credential", serde_json::json!("OPENAI_API_KEY"))
    .with_extra("token", serde_json::json!("sk-secret-value"))
    .redacted();

    let rendered = serde_json::to_string(&event).unwrap();
    assert!(rendered.contains("OPENAI_API_KEY"));
    assert!(!rendered.contains("sk-secret-value"));
    assert!(rendered.contains("[redacted]"));
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
    assert_eq!(event.subject["target"], serde_json::json!("api.example.test:443"));
    assert_eq!(event.subject["handle"], serde_json::json!("sb-1"));
}
```

Add these tests to `crates/agentenv-events/src/redaction.rs`:

```rust
#[test]
fn redacts_url_credentials_query_and_fragment() {
    let redacted = redact_string("https://user:pass@example.test/path?token=secret#frag");
    assert_eq!(redacted, "https://example.test/path");
}

#[test]
fn redacts_secret_like_json_keys() {
    let value = serde_json::json!({
        "token": "sk-value",
        "nested": {"api_key": "very-secret"},
        "safe": "OPENAI_API_KEY"
    });

    let redacted = redact_json_value(value);

    assert_eq!(redacted["token"], serde_json::json!("[redacted]"));
    assert_eq!(redacted["nested"]["api_key"], serde_json::json!("[redacted]"));
    assert_eq!(redacted["safe"], serde_json::json!("OPENAI_API_KEY"));
}
```

Move the existing SSRF event tests from `crates/agentenv-events/src/lib.rs` into `crates/agentenv-core/src/security/ssrf.rs` and update assertions to use `agentenv_events::activity::ActivityEvent`.

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events activity redaction
cargo test -p agentenv-core ssrf_blocked
```

Expected: tests fail with missing `ActivityEvent`, `ActivityKind`, `ActivityResult`, `redact_string`, `redact_json_value`, and moved SSRF activity helper symbols.

- [ ] **Step 3: Implement activity model and redaction**

In `crates/agentenv-events/src/lib.rs`, use:

```rust
#![forbid(unsafe_code)]

pub mod activity;
pub mod redaction;

pub use activity::{ActivityEvent, ActivityKind, ActivityResult, ActorKind};
```

In `crates/agentenv-events/src/activity.rs`, define:

```rust
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
```

Add builder methods `new`, `with_env`, `with_actor_value`, `with_subject_value`, `with_extra`, `with_reason_code`, `with_latency_ms`, `redacted`, and `from_legacy_proto`.

In `from_legacy_proto`, map:

```rust
agentenv_proto::ActivityKind::EgressDenied => (ActivityKind::EgressDenied, ActivityResult::Denied),
agentenv_proto::ActivityKind::ApprovalRequested => (ActivityKind::ApprovalRequested, ActivityResult::PendingApproval),
agentenv_proto::ActivityKind::Log => (ActivityKind::Log, ActivityResult::Ok),
```

In `crates/agentenv-events/src/redaction.rs`, implement `redact_string` with `url::Url` parsing plus string fallback, and `redact_json_value` recursively redacting values for lowercase keys containing `token`, `secret`, `password`, `api_key`, `apikey`, `authorization`, or `credential`.

Update `crates/agentenv-events/Cargo.toml`:

```toml
[dependencies]
agentenv-proto = { path = "../agentenv-proto" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
url.workspace = true
```

Update `crates/agentenv-core/Cargo.toml`:

```toml
agentenv-events = { path = "../agentenv-events" }
```

Move `ssrf_blocked_event` into `crates/agentenv-core/src/security/ssrf.rs` as `ssrf_blocked_activity_event`, returning `agentenv_events::ActivityEvent`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events activity redaction
cargo test -p agentenv-core ssrf_blocked
```

Expected: both commands pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs crates/agentenv-events/src/activity.rs crates/agentenv-events/src/redaction.rs crates/agentenv-core/Cargo.toml crates/agentenv-core/src/security/ssrf.rs
git commit -m "feat: add activity event model"
```

## Task 2: Protocol Schema 1.1 And Rich Driver Activity Params

**Files:**
- Modify: `crates/agentenv-proto/src/schema_version.rs`
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-proto/build.rs`
- Modify: `crates/agentenv-proto/src/lib.rs`
- Modify: generated schema files under `crates/agentenv-proto/schema/`
- Modify: `docs/DRIVER_PROTOCOL.md`

- [ ] **Step 1: Write failing proto tests**

Add tests to `crates/agentenv-proto/src/lib.rs`:

```rust
#[test]
fn schema_version_is_1_1() {
    assert_eq!(SCHEMA_VERSION, "1.1");
}

#[test]
fn driver_activity_event_accepts_legacy_shape() {
    let event: DriverActivityEventParams = serde_json::from_value(serde_json::json!({
        "kind": "egress_denied",
        "subject": "api.example.test:443",
        "reason": "not_in_policy",
        "ts": "2026-04-26T12:00:00Z",
        "handle": "sb-1"
    }))
    .expect("legacy driver activity event should deserialize");

    assert!(matches!(event, DriverActivityEventParams::Legacy(_)));
}

#[test]
fn driver_activity_event_accepts_rich_shape() {
    let event: DriverActivityEventParams = serde_json::from_value(serde_json::json!({
        "ts": "2026-04-26T12:00:00Z",
        "kind": "sandbox_create",
        "env": "demo",
        "actor": {"driver": "openshell"},
        "subject": {"handle": "sb-1"},
        "result": "ok",
        "latency_ms": 42,
        "trace_id": "trace-1",
        "reason_code": "created",
        "extras": {"phase": "create"}
    }))
    .expect("rich driver activity event should deserialize");

    assert!(matches!(event, DriverActivityEventParams::Rich(_)));
}

#[test]
fn driver_activity_schema_is_exported() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(manifest_dir
        .join("schema/driver-activity-event-params.json")
        .exists());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-proto driver_activity schema_version_is_1_1
```

Expected: tests fail because `SCHEMA_VERSION` is `1.0`, `DriverActivityEventParams` does not exist, and the schema file is missing.

- [ ] **Step 3: Implement proto compatibility**

In `crates/agentenv-proto/src/schema_version.rs`, set:

```rust
pub const SCHEMA_VERSION: &str = "1.1";
```

In `crates/agentenv-proto/src/types.rs`, keep the existing `ActivityEventParams` unchanged and add:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RichActivityKind {
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RichActivityResult {
    Ok,
    Error,
    Denied,
    PendingApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RichActivityEventParams {
    pub ts: String,
    pub kind: RichActivityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subject: BTreeMap<String, Value>,
    pub result: RichActivityResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extras: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(untagged)]
pub enum DriverActivityEventParams {
    Rich(RichActivityEventParams),
    Legacy(ActivityEventParams),
}
```

In `crates/agentenv-proto/build.rs`, add:

```rust
write_schema::<types::DriverActivityEventParams>(&schema_dir, "driver-activity-event-params");
```

Update `docs/DRIVER_PROTOCOL.md` to state that schema `1.1` accepts both legacy and rich `event/activity` params.

- [ ] **Step 4: Run tests and regenerate schemas**

Run:

```bash
cargo test -p agentenv-proto driver_activity schema_version_is_1_1
cargo check -p agentenv-proto
```

Expected: tests pass and `crates/agentenv-proto/schema/driver-activity-event-params.json` is generated.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-proto/src/schema_version.rs crates/agentenv-proto/src/types.rs crates/agentenv-proto/src/lib.rs crates/agentenv-proto/build.rs crates/agentenv-proto/schema docs/DRIVER_PROTOCOL.md
git commit -m "feat: add rich driver activity protocol"
```

## Task 3: SQLite Activity Store And Legacy JSONL Reader

**Files:**
- Modify: `crates/agentenv-events/Cargo.toml`
- Create: `crates/agentenv-events/src/store.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing store tests**

Add to `crates/agentenv-events/src/store.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

    fn event(ts: &str, kind: ActivityKind, env: &str, result: ActivityResult) -> ActivityEvent {
        ActivityEvent::new(ts, kind, result, "trace-store").with_env(env)
    }

    #[test]
    fn sqlite_store_appends_and_filters_by_env_kind_result() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();

        store
            .append_many(&[
                event("2026-04-26T12:00:00Z", ActivityKind::SandboxCreate, "demo", ActivityResult::Ok),
                event("2026-04-26T12:00:01Z", ActivityKind::EgressDenied, "demo", ActivityResult::Denied),
                event("2026-04-26T12:00:02Z", ActivityKind::EgressDenied, "other", ActivityResult::Denied),
            ])
            .unwrap();

        let rows = store
            .query(EventQuery {
                env: Some("demo".to_owned()),
                kind: Some(ActivityKind::EgressDenied),
                result: Some(ActivityResult::Denied),
                after_id: None,
                limit: 100,
            })
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event.env.as_deref(), Some("demo"));
        assert_eq!(rows[0].event.kind, ActivityKind::EgressDenied);
    }

    #[test]
    fn legacy_jsonl_reader_accepts_old_event_shape() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        std::fs::write(
            &path,
            "{\"ts\":\"2026-04-21T00:00:00Z\",\"driver\":\"context\",\"level\":\"info\",\"msg\":\"context ready\"}\n",
        )
        .unwrap();

        let rows = read_legacy_jsonl(&path, None, None).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, ActivityKind::Log);
        assert_eq!(rows[0].actor["driver"], serde_json::json!("context"));
        assert_eq!(rows[0].extras["msg"], serde_json::json!("context ready"));
    }
}
```

Add `tempfile = "=3.16.0"` to `crates/agentenv-events` dev-dependencies.

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events store
```

Expected: tests fail because `store` module, `SqliteEventStore`, `EventQuery`, `append_many`, `query`, and `read_legacy_jsonl` do not exist.

- [ ] **Step 3: Implement SQLite store**

Add to `crates/agentenv-events/Cargo.toml`:

```toml
rusqlite = { workspace = true, features = ["bundled"] }
time = { workspace = true, features = ["formatting"] }

[dev-dependencies]
tempfile = "=3.16.0"
```

In `crates/agentenv-events/src/lib.rs`, export:

```rust
pub mod store;
```

In `crates/agentenv-events/src/store.rs`, implement:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEvent {
    pub id: i64,
    pub event: ActivityEvent,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventQuery {
    pub env: Option<String>,
    pub kind: Option<ActivityKind>,
    pub result: Option<ActivityResult>,
    pub after_id: Option<i64>,
    pub limit: usize,
}

pub struct SqliteEventStore {
    path: PathBuf,
}
```

Use `rusqlite::Connection::open(&self.path)` per operation to avoid sharing a non-Send connection across Tokio tasks. Implement `open`, `migrate`, `append_many`, `query`, `counts_by_kind_result`, and `read_legacy_jsonl`.

Create `activity_events` with the schema from the design. Store `actor_json`, `subject_json`, and `extras_json` as canonical `serde_json::to_string` output. Use query construction with positional params and a hard limit of `limit.clamp(1, 10_000)`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events store
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs crates/agentenv-events/src/store.rs
git commit -m "feat: persist activity events in sqlite"
```

## Task 4: Dispatcher, Sink Parsing, SQLite Sink, And JSONL Sink

**Files:**
- Create: `crates/agentenv-events/src/dispatcher.rs`
- Create: `crates/agentenv-events/src/sink.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing dispatcher and sink tests**

Add to `crates/agentenv-events/src/sink.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sink_uris() {
        assert!(matches!(SinkConfig::parse("sqlite").unwrap(), SinkConfig::DefaultSqlite));
        assert!(matches!(SinkConfig::parse("sqlite:/tmp/events.db").unwrap(), SinkConfig::Sqlite { .. }));
        assert!(matches!(SinkConfig::parse("file:/tmp/events.jsonl").unwrap(), SinkConfig::Jsonl { .. }));
        assert!(matches!(SinkConfig::parse("otel:grpc://collector:4317").unwrap(), SinkConfig::OtelGrpc { .. }));
        assert!(matches!(SinkConfig::parse("webhook:https://example.test/events?kinds=egress_denied").unwrap(), SinkConfig::Webhook { .. }));
    }

    #[test]
    fn rejects_unknown_sink_uri() {
        let err = SinkConfig::parse("syslog:/dev/log").unwrap_err();
        assert!(err.to_string().contains("unsupported events sink"));
    }
}
```

Add to `crates/agentenv-events/src/dispatcher.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

    #[derive(Clone, Default)]
    struct RecordingSink {
        events: Arc<Mutex<Vec<ActivityEvent>>>,
    }

    #[async_trait::async_trait]
    impl EventSink for RecordingSink {
        fn name(&self) -> &'static str {
            "recording"
        }

        async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError> {
            self.events.lock().unwrap().extend(events);
            Ok(())
        }
    }

    fn event(trace: &str) -> ActivityEvent {
        ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::SandboxCreate,
            ActivityResult::Ok,
            trace,
        )
    }

    #[tokio::test]
    async fn dispatcher_delivers_events_to_sink() {
        let sink = RecordingSink::default();
        let seen = sink.events.clone();
        let dispatcher = EventDispatcher::for_test(16, vec![Box::new(sink)]);

        dispatcher.emitter().emit(event("trace-dispatch"));
        dispatcher.flush().await.unwrap();

        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dispatcher_counts_drops_when_queue_is_full() {
        let dispatcher = EventDispatcher::for_test(1, Vec::new());

        dispatcher.emitter().emit(event("trace-1"));
        dispatcher.emitter().emit(event("trace-2"));

        assert_eq!(dispatcher.counters().dropped_events(), 1);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events sink dispatcher
```

Expected: tests fail because sink and dispatcher modules do not exist.

- [ ] **Step 3: Implement sink and dispatcher**

Add dependencies to `crates/agentenv-events/Cargo.toml`:

```toml
async-trait.workspace = true
tokio.workspace = true
```

In `lib.rs`, export:

```rust
pub mod dispatcher;
pub mod sink;

pub use dispatcher::{EventDispatcher, EventEmitter, NoopEventEmitter, RecordingEventEmitter};
pub use sink::{EventSink, SinkConfig, SinkError};
```

Define:

```rust
pub trait EventEmitter: Send + Sync {
    fn emit(&self, event: ActivityEvent);
}

#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    fn name(&self) -> &'static str;
    async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError>;
}
```

Use `tokio::sync::mpsc::channel(capacity)`. `emit` uses `try_send`; on `Full`, increment an `AtomicU64` drop counter. `flush` sends a shutdown message or waits until a shared in-flight counter reaches zero. For this task, make `flush` deterministic by draining all currently queued events before returning.

Implement `SqliteSink` by calling `SqliteEventStore::append_many`. Implement `JsonlSink` by appending one serialized activity event per line with `tokio::fs::OpenOptions`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events sink dispatcher
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs crates/agentenv-events/src/dispatcher.rs crates/agentenv-events/src/sink.rs
git commit -m "feat: dispatch activity events to sinks"
```

## Task 5: Audit Hash Chain, Signing, Export, And Verify

**Files:**
- Modify: `crates/agentenv-events/Cargo.toml`
- Create: `crates/agentenv-events/src/audit.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing audit tests**

Add to `crates/agentenv-events/src/audit.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

    fn denied_event() -> ActivityEvent {
        ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-audit",
        )
        .with_env("demo")
        .with_reason_code("denied_cloud_metadata")
    }

    #[test]
    fn audit_policy_selects_security_sensitive_events() {
        assert!(AuditPolicy::default().includes(&denied_event()));
        let log = ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::Log,
            ActivityResult::Ok,
            "trace-log",
        );
        assert!(!AuditPolicy::default().includes(&log));
    }

    #[test]
    fn audit_store_appends_and_verifies_hash_chain() {
        let temp = tempfile::tempdir().unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit-signing-key")).unwrap();
        let store = AuditStore::open(temp.path().join("events.db")).unwrap();

        store.append(&key, &denied_event()).unwrap();
        store.append(&key, &denied_event().with_reason_code("not_in_policy")).unwrap();

        let report = store.verify().unwrap();
        assert!(report.valid, "{report:?}");
        assert_eq!(report.checked_entries, 2);
    }

    #[test]
    fn audit_verify_detects_modified_entry() {
        let temp = tempfile::tempdir().unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit-signing-key")).unwrap();
        let db = temp.path().join("events.db");
        let store = AuditStore::open(&db).unwrap();
        store.append(&key, &denied_event()).unwrap();

        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE audit_entries SET event_json = ?1 WHERE sequence = 1",
            [serde_json::json!({"tampered": true}).to_string()],
        )
        .unwrap();

        let report = store.verify().unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_sequence, Some(1));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events audit
```

Expected: tests fail because audit types do not exist.

- [ ] **Step 3: Implement audit module**

Add dependencies:

```toml
ed25519-dalek.workspace = true
hex.workspace = true
rand_core = { workspace = true, features = ["getrandom"] }
sha2.workspace = true
```

In `lib.rs`:

```rust
pub mod audit;
```

Implement:

```rust
pub struct AuditPolicy;
pub struct AuditStore {
    path: PathBuf,
}
pub struct AuditSigningKey {
    signing_key: ed25519_dalek::SigningKey,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyReport {
    pub valid: bool,
    pub checked_entries: usize,
    pub first_invalid_sequence: Option<i64>,
}
```

`AuditPolicy::includes` returns true for `Auth`, `CredentialInjected`, `CredentialSet`, `CredentialReset`, `PolicyApplied`, `ApprovalRequested`, `ApprovalDecided`, `EgressDenied`, `SpawnRejected`, failed `SandboxCreate`, and failed `Exec`.

`AuditSigningKey::load_or_create` reads 32 raw bytes from the key path or generates a new `SigningKey` using `rand_core::OsRng`. On Unix set mode `0o600` when creating the file.

`AuditStore::append` creates `audit_entries` and `audit_metadata`, reads the previous hash, canonicalizes `{sequence, ts, prev_hash, event}`, signs the SHA-256 entry hash bytes, and inserts the row.

Use deterministic canonical JSON by serializing a `BTreeMap<&str, serde_json::Value>`.

Implement `verify`, `export_jsonl`, and `export_csv`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events audit
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs crates/agentenv-events/src/audit.rs
git commit -m "feat: add tamper evident audit log"
```

## Task 6: Metrics Aggregation And Prometheus Rendering

**Files:**
- Modify: `crates/agentenv-events/Cargo.toml`
- Create: `crates/agentenv-events/src/metrics.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing metrics tests**

Add to `crates/agentenv-events/src/metrics.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};
    use crate::store::SqliteEventStore;

    #[test]
    fn prometheus_render_includes_required_series() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
        store
            .append_many(&[
                ActivityEvent::new(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::SandboxCreate,
                    ActivityResult::Ok,
                    "trace-metrics",
                )
                .with_env("demo")
                .with_actor_value("driver", serde_json::json!("openshell"))
                .with_latency_ms(42),
                ActivityEvent::new(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::EgressDenied,
                    ActivityResult::Denied,
                    "trace-metrics",
                )
                .with_env("demo")
                .with_actor_value("driver", serde_json::json!("openshell")),
            ])
            .unwrap();

        let snapshot = MetricsSnapshot::from_store(&store, &[EnvMetricRow {
            status: "running".to_owned(),
            count: 1,
        }])
        .unwrap();
        let rendered = render_prometheus(&snapshot);

        assert!(rendered.contains("agentenv_envs_total{status=\"running\"} 1"));
        assert!(rendered.contains("agentenv_events_total{kind=\"sandbox_create\",env=\"demo\",result=\"ok\"} 1"));
        assert!(rendered.contains("agentenv_policy_blocks_total{kind=\"egress_denied\",driver=\"openshell\"} 1"));
        assert!(rendered.contains("agentenv_sandbox_latency_seconds_bucket"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events metrics
```

Expected: tests fail because metrics module and aggregate store queries do not exist.

- [ ] **Step 3: Implement metrics module**

In `lib.rs`:

```rust
pub mod metrics;
```

Implement:

```rust
pub struct EnvMetricRow {
    pub status: String,
    pub count: u64,
}

pub struct MetricsSnapshot {
    pub envs_by_status: Vec<EnvMetricRow>,
    pub events_total: Vec<EventCountMetric>,
    pub policy_blocks_total: Vec<PolicyBlockMetric>,
    pub mcp_tool_calls_total: Vec<McpToolMetric>,
    pub sandbox_latency: Vec<LatencyBucketMetric>,
    pub approvals_pending_total: u64,
    pub event_drops_total: Vec<SinkCounterMetric>,
    pub event_sink_errors_total: Vec<SinkCounterMetric>,
}
```

Add aggregate query helpers in `store.rs` for event counts and latency rows. Render Prometheus text with `# HELP` and `# TYPE` lines for each documented series:

```text
agentenv_envs_total
agentenv_events_total
agentenv_sandbox_latency_seconds_bucket
agentenv_mcp_tool_calls_total
agentenv_policy_blocks_total
agentenv_approvals_pending_total
agentenv_event_drops_total
agentenv_event_sink_errors_total
```

Use fixed latency buckets: `0.005`, `0.01`, `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2.5`, `5`, `10`, `+Inf`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events metrics
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-events/src/lib.rs crates/agentenv-events/src/metrics.rs crates/agentenv-events/src/store.rs
git commit -m "feat: render agentenv prometheus metrics"
```

## Task 7: Core Event Emission

**Files:**
- Modify: `crates/agentenv-core/Cargo.toml`
- Modify: `crates/agentenv-core/src/runtime.rs`
- Modify: `crates/agentenv-core/src/security/ssrf.rs`

- [ ] **Step 1: Write failing runtime emission tests**

Add to `crates/agentenv-core/src/runtime.rs` tests:

```rust
#[tokio::test]
async fn create_env_observed_emits_spawn_lifecycle_events() {
    let root = temp_root("create-observed-events");
    let options = RuntimeOptions {
        root: root.clone(),
        log_level: agentenv_proto::LogLevel::Info,
        non_interactive: true,
    };
    let emitter = agentenv_events::dispatcher::RecordingEventEmitter::default();
    let mut credentials = EmptyCredentials;
    let yaml = minimal_blueprint_yaml();

    let result = super::create_env_observed(
        &options,
        &TinyFactory,
        &mut credentials,
        "demo",
        yaml,
        &emitter,
    )
    .await
    .unwrap();

    assert_eq!(result.admission.status, crate::admission::AdmissionStatus::Accepted);
    let kinds = emitter
        .events()
        .into_iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    assert!(kinds.contains(&agentenv_events::ActivityKind::SpawnRequested));
    assert!(kinds.contains(&agentenv_events::ActivityKind::SpawnAdmitted));
    assert!(kinds.contains(&agentenv_events::ActivityKind::SpawnStarted));
    assert!(kinds.contains(&agentenv_events::ActivityKind::SandboxCreate));
    assert!(kinds.contains(&agentenv_events::ActivityKind::SpawnReady));
}

#[tokio::test]
async fn exec_env_observed_emits_exec_event() {
    let (options, factory) = env_with_running_state("exec-observed-events", "demo");
    let emitter = agentenv_events::dispatcher::RecordingEventEmitter::default();

    super::exec_env_observed(
        &options,
        &factory,
        "demo",
        vec!["echo".to_owned(), "hi".to_owned()],
        &emitter,
    )
    .await
    .unwrap();

    assert!(emitter
        .events()
        .iter()
        .any(|event| event.kind == agentenv_events::ActivityKind::Exec
            && event.result == agentenv_events::ActivityResult::Ok));
}
```

Use existing helper patterns in the runtime test module. If helper names differ, add local helpers with concrete return types in the test module.

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core create_env_observed_emits_spawn_lifecycle_events exec_env_observed_emits_exec_event
```

Expected: tests fail because observed runtime functions do not exist.

- [ ] **Step 3: Implement observed runtime functions**

Add these public functions next to the existing runtime functions:

```rust
pub async fn create_env_observed(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    credentials: &mut dyn CredentialProvider,
    name: &str,
    blueprint_yaml: &str,
    events: &dyn agentenv_events::EventEmitter,
) -> RuntimeResult<CreateResult>
```

```rust
pub async fn exec_env_observed(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    command: Vec<String>,
    events: &dyn agentenv_events::EventEmitter,
) -> RuntimeResult<agentenv_proto::ExecResult>
```

Also add observed variants for `destroy_env`, `status_env`, and `logs_env`. Keep existing public functions unchanged by making them call observed variants with `agentenv_events::NoopEventEmitter`.

Emit events:

1. before create admission: `SpawnRequested`
2. admission rejection: `SpawnRejected` with reason code
3. admission acceptance: `SpawnAdmitted`
4. before resource creation: `SpawnStarted`
5. after sandbox create call: `SandboxCreate`
6. after state publish: `SpawnReady`
7. credential names resolved for injection: `CredentialInjected`
8. destroy success/failure: `SandboxDestroy`
9. exec success/failure: `Exec`

Generate trace IDs with `uuid::Uuid::now_v7().to_string()` using the existing `uuid` workspace dependency.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core create_env_observed_emits_spawn_lifecycle_events exec_env_observed_emits_exec_event
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/Cargo.toml crates/agentenv-core/src/runtime.rs crates/agentenv-core/src/security/ssrf.rs
git commit -m "feat: emit lifecycle activity events"
```

## Task 8: CLI Sinks, Logs, Stats, Audit, And Metrics Serve

**Files:**
- Modify: `crates/agentenv/Cargo.toml`
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/src/render.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI tests**

Add to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn logs_env_kind_json_reads_sqlite_activity_store() {
    let temp_dir = make_temp_dir("logs-sqlite-activity");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    let db = env_dir.join("events.db");
    seed_activity_db(&db, "demo", "egress_denied", "denied", "blocked egress");

    let output = Command::new(agentenv_bin())
        .arg("logs")
        .arg("--env")
        .arg("demo")
        .arg("--kind")
        .arg("egress_denied")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr was: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"kind\":\"egress_denied\""), "stdout was: {stdout}");
    assert!(stdout.contains("\"env\":\"demo\""), "stdout was: {stdout}");
}

#[test]
fn stats_env_prints_activity_summary() {
    let temp_dir = make_temp_dir("stats-activity-summary");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    seed_activity_db(&env_dir.join("events.db"), "demo", "egress_denied", "denied", "blocked egress");

    let output = Command::new(agentenv_bin())
        .arg("stats")
        .arg("--env")
        .arg("demo")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr was: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("egress_denied"));
    assert!(stdout.contains("denied"));
}

#[test]
fn audit_export_and_verify_use_activity_database() {
    let temp_dir = make_temp_dir("audit-export-verify");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    seed_audit_db(&env_dir.join("events.db"), &temp_dir, "demo");

    let verify = Command::new(agentenv_bin())
        .arg("audit")
        .arg("verify")
        .arg("--env")
        .arg("demo")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(verify.status.success(), "stderr was: {}", String::from_utf8_lossy(&verify.stderr));

    let export = Command::new(agentenv_bin())
        .arg("audit")
        .arg("export")
        .arg("--env")
        .arg("demo")
        .arg("--format")
        .arg("jsonl")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(export.status.success(), "stderr was: {}", String::from_utf8_lossy(&export.stderr));
    assert!(String::from_utf8_lossy(&export.stdout).contains("entry_hash"));
}
```

Add helper functions `seed_activity_db` and `seed_audit_db` using `agentenv_events` APIs.

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv logs_env_kind_json_reads_sqlite_activity_store stats_env_prints_activity_summary audit_export_and_verify_use_activity_database
```

Expected: tests fail because CLI commands and dependency wiring do not exist.

- [ ] **Step 3: Implement CLI commands and dispatcher wiring**

Add dependencies to `crates/agentenv/Cargo.toml`:

```toml
agentenv-events = { path = "../agentenv-events" }
bytes.workspace = true
http-body-util.workspace = true
hyper.workspace = true
```

Modify `Cli`:

```rust
struct Cli {
    #[arg(long = "events-sink", global = true)]
    events_sink: Vec<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}
```

Add commands:

```rust
Stats(StatsArgs),
Audit(AuditArgs),
Metrics(MetricsArgs),
```

Add args:

```rust
struct StatsArgs {
    #[arg(long)]
    env: Option<String>,
}

enum AuditCommand {
    Export { from: Option<String>, to: Option<String>, format: AuditFormat, env: Option<String> },
    Verify { env: Option<String> },
}

enum MetricsCommand {
    Serve { #[arg(long, default_value_t = 9180)] port: u16 },
}
```

Change `run_create`, `run_destroy`, and `run_exec` to build an `EventDispatcher` from global sink args and call observed runtime functions. Add credential CLI events for `CredentialSet` and `CredentialReset`.

Change `LogsArgs` to support both `name: Option<String>` and `--env`. Preserve old `--driver` fallback for legacy tests. For new store reads, load `~/.agentenv/envs/<env>/events.db` and query by kind.

Implement `metrics serve` using `hyper` bound to `127.0.0.1:<port>`. The handler returns `agentenv_events::metrics::render_prometheus`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv logs_env_kind_json_reads_sqlite_activity_store stats_env_prints_activity_summary audit_export_and_verify_use_activity_database
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/Cargo.toml crates/agentenv/src/main.rs crates/agentenv/src/render.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: add activity log audit stats cli"
```

## Task 9: Plugin Notification Conversion

**Files:**
- Modify: `crates/agentenv-plugin/Cargo.toml`
- Modify: `crates/agentenv-plugin/src/jsonrpc.rs`
- Modify: `crates/agentenv-plugin/src/lib.rs`
- Modify: `tests/driver-conformance/src/bin/mock-driver.rs`
- Modify: `tests/driver-conformance/tests/mock_driver.rs`

- [ ] **Step 1: Write failing notification tests**

Add to `crates/agentenv-plugin/src/jsonrpc.rs` tests:

```rust
#[test]
fn event_activity_notification_converts_to_activity_event() {
    let raw = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "event/activity",
        "params": {
            "ts": "2026-04-26T12:00:00Z",
            "kind": "mcp_tool_call",
            "env": "demo",
            "actor": {"driver": "nexus"},
            "subject": {"tool": "search"},
            "result": "ok",
            "trace_id": "trace-plugin",
            "extras": {}
        }
    });

    let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
    let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

    assert_eq!(event.kind, agentenv_events::ActivityKind::McpToolCall);
    assert_eq!(event.subject["tool"], serde_json::json!("search"));
}

#[test]
fn malformed_notification_becomes_error_log_event() {
    let raw = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "event/activity",
        "params": {"kind": 7}
    });

    let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
    let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

    assert_eq!(event.kind, agentenv_events::ActivityKind::Log);
    assert_eq!(event.result, agentenv_events::ActivityResult::Error);
    assert_eq!(event.reason_code.as_deref(), Some("invalid_driver_notification"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-plugin notification
```

Expected: tests fail because `notification_to_activity_event` does not exist and `agentenv-plugin` does not depend on `agentenv-events`.

- [ ] **Step 3: Implement notification conversion**

Add dependency:

```toml
agentenv-events = { path = "../agentenv-events" }
```

Implement:

```rust
pub fn notification_to_activity_event(
    notification: RpcNotificationEnvelope,
    fallback_trace_id: &str,
) -> Result<agentenv_events::ActivityEvent, JsonRpcError>
```

For `event/log`, deserialize `agentenv_proto::EventLogParams` and convert to `ActivityKind::Log` with `actor.driver` when `kv.driver` exists. For `event/activity`, deserialize `agentenv_proto::DriverActivityEventParams` and convert legacy/rich shapes. For `event/approval_requested`, deserialize `ApprovalRequestedParams` and convert to `ApprovalRequested` with `PendingApproval`.

Malformed known notifications return an error log activity event rather than `Err`. Unknown notification methods return `Err(JsonRpcError::Protocol(format!("unsupported notification method `{method}`")))`.

Leave full async notification dispatch as a separate code path inside `JsonRpcClient::call_inner`: when a notification is read while waiting for a response, convert it and emit through an optional `EventEmitter` stored on the client. Keep existing clients working by defaulting to `NoopEventEmitter`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-plugin notification
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-plugin/Cargo.toml crates/agentenv-plugin/src/jsonrpc.rs crates/agentenv-plugin/src/lib.rs tests/driver-conformance/src/bin/mock-driver.rs tests/driver-conformance/tests/mock_driver.rs
git commit -m "feat: convert driver notifications to activity events"
```

## Task 10: Webhook Sink With SSRF Validation

**Files:**
- Modify: `crates/agentenv-events/Cargo.toml`
- Create: `crates/agentenv-events/src/webhook.rs`
- Modify: `crates/agentenv-events/src/sink.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing webhook tests**

Add to `crates/agentenv-events/src/webhook.rs`:

```rust
#[cfg(test)]
mod tests {
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events webhook
```

Expected: tests fail because webhook module does not exist.

- [ ] **Step 3: Implement webhook config and sink**

Add dependencies:

```toml
reqwest.workspace = true
```

In `webhook.rs`, implement `WebhookConfig::parse`, `WebhookSink`, filtering by `ActivityKind`, and payload:

```json
{"schema":"agentenv.activity.v1","events":[]}
```

For M6-1, reject URLs with username/password in `agentenv-events` using `url::Url` and call the core SSRF validator from CLI before constructing webhook sinks. This avoids reintroducing an `agentenv-events` to `agentenv-core` dependency.

Add a helper in `agentenv/src/main.rs` that validates webhook sink URLs through `agentenv_core::security::ssrf::validate_outbound` before `EventDispatcher` construction.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events webhook
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs crates/agentenv-events/src/sink.rs crates/agentenv-events/src/webhook.rs crates/agentenv/src/main.rs
git commit -m "feat: add webhook event sink"
```

## Task 11: Feature-Gated OTEL Sink

**Files:**
- Modify: `crates/agentenv-events/Cargo.toml`
- Create: `crates/agentenv-events/src/otel.rs`
- Modify: `crates/agentenv-events/src/sink.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing OTEL mapping test**

Add to `crates/agentenv-events/src/otel.rs`:

```rust
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
        .with_reason_code("created");

        let mapped = map_event_to_otel_fields(&event);

        assert_eq!(mapped["agentenv.kind"], "sandbox_create");
        assert_eq!(mapped["agentenv.env"], "demo");
        assert_eq!(mapped["agentenv.result"], "ok");
        assert_eq!(mapped["agentenv.reason_code"], "created");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-events --features otel otel
```

Expected: tests fail because feature and module do not exist.

- [ ] **Step 3: Implement OTEL mapping and gated sink**

Add to `crates/agentenv-events/Cargo.toml`:

```toml
[features]
default = []
otel = ["dep:opentelemetry", "dep:opentelemetry_sdk", "dep:opentelemetry-otlp"]

[dependencies]
opentelemetry = { workspace = true, optional = true }
opentelemetry_sdk = { workspace = true, optional = true }
opentelemetry-otlp = { workspace = true, optional = true, features = ["grpc-tonic"] }
```

In `lib.rs`:

```rust
#[cfg(feature = "otel")]
pub mod otel;
```

Implement `map_event_to_otel_fields` and `OtelSink`. In non-`otel` builds, `SinkConfig::parse("otel:grpc://collector:4317")` returns a clear `SinkError::UnsupportedFeature { feature: "otel" }`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events --features otel otel
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs crates/agentenv-events/src/otel.rs crates/agentenv-events/src/sink.rs
git commit -m "feat: add otel event sink"
```

## Task 12: Documentation, Gated Checks, And Full Verification

**Files:**
- Modify: `crates/agentenv-events/README.md`
- Modify: `crates/agentenv/README.md`
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `docs/ROADMAP.md` if M6-1 status markers exist

- [ ] **Step 1: Write documentation update**

Update `crates/agentenv-events/README.md` with:

```markdown
# agentenv-events

`agentenv-events` owns activity events, sink dispatch, durable SQLite storage,
audit hash chains, and Prometheus metrics rendering for agentenv.

Default storage:

- per env: `~/.agentenv/envs/<name>/events.db`
- global: `~/.agentenv/events.db`

CLI surfaces:

- `agentenv logs --env <name> --kind <kind> [--follow] [--json]`
- `agentenv stats [--env <name>]`
- `agentenv audit export --from <date> --to <date> --format jsonl|csv`
- `agentenv audit verify [--env <name>]`
- `agentenv metrics serve --port 9180`
```

Update `docs/DRIVER_PROTOCOL.md` notification section with a rich `event/activity` example using `sandbox_create` and `trace_id`.

- [ ] **Step 2: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits with status 0.

- [ ] **Step 3: Run focused crate tests**

Run:

```bash
cargo test -p agentenv-events
cargo test -p agentenv-proto
cargo test -p agentenv-plugin
cargo test -p agentenv-core runtime
cargo test -p agentenv logs stats audit metrics
```

Expected: all commands exit with status 0.

- [ ] **Step 4: Run workspace clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: command exits with status 0.

- [ ] **Step 5: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: command exits with status 0.

- [ ] **Step 6: Run gated optional checks when dependencies are available**

Run:

```bash
AGENTENV_RUN_OTEL_TESTS=1 cargo test -p agentenv-events --features otel otel
AGENTENV_RUN_WEBHOOK_TESTS=1 cargo test -p agentenv-events webhook
AGENTENV_RUN_EVENT_PERF_TESTS=1 cargo test -p agentenv-events dispatcher -- --ignored
```

Expected: commands exit with status 0 when the required collector or local test receiver is configured. If a gated check cannot run in the environment, record the exact missing prerequisite in the final PR notes.

- [ ] **Step 7: Commit documentation and verification fixes**

```bash
git add crates/agentenv-events/README.md crates/agentenv/README.md docs/DRIVER_PROTOCOL.md docs/ROADMAP.md
git commit -m "docs: document event audit metrics workflow"
```

## Self-Review Checklist

Spec coverage:

- Activity event model: Tasks 1, 2, 7, 9.
- SQLite sink and logs follow source: Tasks 3, 4, 8.
- JSONL sink and legacy fallback: Tasks 3, 4, 8.
- OTEL export: Task 11.
- Webhook sink with SSRF validation: Task 10.
- Audit hash chain, signatures, export, verify: Task 5 and Task 8.
- Metrics endpoint and documented series: Task 6 and Task 8.
- CLI integration: Task 8.
- Non-blocking bounded dispatch and drop counters: Task 4 and Task 6.
- Coordinator lifecycle events and reason codes: Task 7.
- Plugin notifications: Task 9.
- Full verification: Task 12.

Dependency graph check:

- `agentenv-events` does not depend on `agentenv-core`.
- `agentenv-core` depends on `agentenv-events`.
- `agentenv` depends on both `agentenv-core` and `agentenv-events`.
- Webhook SSRF validation is performed in `agentenv` before constructing event sinks, avoiding an events-to-core dependency.

Type consistency check:

- Internal type: `agentenv_events::activity::ActivityEvent`.
- Emitter trait: `agentenv_events::dispatcher::EventEmitter`.
- Proto compatibility type: `agentenv_proto::DriverActivityEventParams`.
- Store type: `agentenv_events::store::SqliteEventStore`.
- Audit type: `agentenv_events::audit::AuditStore`.
- Metrics render function: `agentenv_events::metrics::render_prometheus`.
