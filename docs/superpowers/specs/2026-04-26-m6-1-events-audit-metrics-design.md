# M6-1 Design: Activity Events, Audit Log, And Metrics

- Date: 2026-04-26
- Issue: https://github.com/windoliver/agentenv/issues/23
- Milestone: M6 Day-2 operations
- Affected crates: `agentenv-events`, `agentenv-core`, `agentenv`, `agentenv-proto`, `agentenv-plugin`, `agentenv-approvals`

## 1. Context And Goals

Issue #23 adds the observability foundation for Day-2 operations:

1. a structured activity event stream
2. durable default storage
3. optional JSONL, OTEL, and webhook sinks
4. a tamper-evident audit log for security-sensitive events
5. Prometheus-compatible metrics
6. CLI commands for logs, audit export, stats, and metrics serving

The repo already has the right shape for this work:

1. `docs/ARCHITECTURE.md` assigns activity stream, audit, and `/metrics` to `agentenv-events`.
2. `docs/DRIVER_PROTOCOL.md` defines driver notifications for `event/log`, `event/activity`, and `event/approval_requested`.
3. `agentenv-core::env` persists `state.json` and a legacy `events.jsonl`.
4. `agentenv-events` contains the existing SSRF-to-activity conversion surface.
5. `agentenv logs` already has a fallback path for reading activity-like JSON lines.

The goal is to turn `agentenv-events` into the central observability crate without changing the narrow waist. Core lifecycle code emits through a small interface, plugin notifications convert into the same event model, and the CLI configures sinks and readers.

## 2. Scope And Non-Goals

### In scope

1. Add a typed `agentenv-events::activity` model that can represent all issue-required events:
   - `sandbox_create`
   - `sandbox_destroy`
   - `exec`
   - `egress_allowed`
   - `egress_denied`
   - `mcp_tool_call`
   - `policy_applied`
   - `credential_injected`
   - `credential_set`
   - `credential_reset`
   - `auth`
   - `approval_requested`
   - `approval_decided`
   - `spawn_requested`
   - `spawn_queued`
   - `spawn_admitted`
   - `spawn_rejected`
   - `spawn_started`
   - `spawn_ready`
2. Persist events to SQLite by default:
   - per-env: `~/.agentenv/envs/<name>/events.db`
   - cross-env: `~/.agentenv/events.db`
3. Keep JSONL as an optional sink through `--events-sink=file:<path>` and as a compatibility export target.
4. Add OTEL and webhook sinks behind the same sink pipeline.
5. Add a bounded async dispatcher with drop accounting.
6. Add a hash-chained audit log for security-sensitive events.
7. Add `agentenv audit export` and `agentenv audit verify`.
8. Add `agentenv stats [--env <name>]`.
9. Change `agentenv logs` to read from the activity store and support:
   - `agentenv logs [--follow] [--env <name>] [--kind <kind>]`
   - backwards-compatible `agentenv logs <name> [--follow]`
10. Add `agentenv metrics serve --port 9180`.
11. Expose the documented Prometheus series.
12. Wire core operations to emit structured events.
13. Convert driver/plugin notifications into structured events.
14. Add tests for event shape, persistence, audit verification, metrics rendering, backpressure, CLI behavior, and plugin notification conversion.

### Out of scope

1. M6-2 operator TUI.
2. M6-3 approval UI, Slack, and webhook decision routing beyond event emission.
3. Remote multi-user hub mode.
4. A second agent-to-context protocol.
5. Changing credential transport rules. Credential values still never flow through generic driver RPC, state, events, audit logs, metrics, or CLI output.
6. Replacing `tracing`; structured `tracing` remains useful for diagnostics, while activity events remain the durable operator-facing stream.

## 3. Architecture

Use `agentenv-events` as the central observability crate. It owns event schemas, sink dispatch, durable storage, audit chaining, metrics aggregation, and log/stat readers.

`agentenv-core` owns lifecycle decisions and emits events through a trait:

```rust
pub trait EventEmitter: Send + Sync {
    fn emit(&self, event: agentenv_events::activity::ActivityEvent);
}
```

Core receives an emitter in runtime options or lifecycle entrypoints. Production CLI code passes an async dispatcher. Tests can pass a recording emitter or no-op emitter. This keeps lifecycle code testable and avoids making driver RPC wait for sink I/O.

`agentenv-plugin` converts subprocess driver notifications into `ActivityEvent` values before handing them to the same emitter. Built-in drivers continue returning trait results directly; core emits lifecycle events around those calls.

`agentenv` remains CLI glue:

1. parses `--events-sink`
2. builds sink configuration
3. starts and flushes dispatch workers
4. renders logs and stats
5. runs the metrics HTTP server
6. exposes audit commands

## 4. Event Model

The internal activity model is richer than the current `agentenv-proto::ActivityEventParams`.

```json
{
  "ts": "2026-04-16T14:22:00Z",
  "kind": "sandbox_create",
  "env": "myapp",
  "actor": {"user": "alice", "driver": "openshell"},
  "subject": {"handle": "sb-01HXY", "target": "api.github.com:443"},
  "result": "ok",
  "latency_ms": 42,
  "trace_id": "018f...",
  "reason_code": "created",
  "extras": {}
}
```

### Fields

1. `ts`: RFC 3339 UTC timestamp.
2. `kind`: stable snake_case event kind.
3. `env`: optional environment name. Global events use `null`.
4. `actor`: optional actor map with stable keys:
   - `user`: host username when available
   - `driver`: driver name when the event comes from a driver
   - `kind`: `core`, `cli`, `sandbox_driver`, `agent_driver`, `context_driver`, `inference_driver`, or `plugin_driver`
5. `subject`: optional map for resource identifiers:
   - `handle`
   - `target`
   - `tool`
   - `request_id`
   - `command`
6. `result`: `ok`, `error`, `denied`, or `pending_approval`.
7. `latency_ms`: optional elapsed time for measured operations.
8. `trace_id`: generated once per top-level CLI operation and propagated to emitted events.
9. `reason_code`: optional stable machine-readable reason.
10. `extras`: structured non-secret metadata.

### Event kinds

`agentenv-events` defines:

```rust
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
```

`Log` is retained for plain driver log notifications. It is not audit-sensitive by default.

### Result values

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityResult {
    Ok,
    Error,
    Denied,
    PendingApproval,
}
```

### Secret handling

Event construction must pass all user-controlled URLs, command previews, and extras through existing redaction helpers or new `agentenv-events::redaction` helpers before persistence. Tests must assert that credential-looking field names and known secret test strings never appear in SQLite, JSONL, audit export, metrics, stdout, or stderr.

Credential events use names only:

```json
{
  "kind": "credential_injected",
  "subject": {"credential": "OPENAI_API_KEY"},
  "result": "ok",
  "extras": {"required": true, "backend": "keyring"}
}
```

## 5. Protocol Compatibility

The driver protocol already has notifications for logs, activity, and approval requests. Keep those notification method names stable:

1. `event/log`
2. `event/activity`
3. `event/approval_requested`

Current `agentenv-proto::ActivityKind` is too narrow for the full internal activity model. Use this compatibility strategy:

1. Add `DriverActivityEventParams` as an untagged enum with `LegacyActivityEventParams` and `RichActivityEventParams` variants.
2. Keep the existing `ActivityEventParams` fields as the `LegacyActivityEventParams` wire shape:
   - old `kind`
   - old `subject` string
   - old `reason`
   - old `handle`
3. Add `RichActivityEventParams` with the M6 event shape: `ts`, `kind`, `env`, `actor`, `subject`, `result`, `latency_ms`, `trace_id`, `reason_code`, and `extras`.
4. Convert both legacy and rich notifications into the internal `ActivityEvent`.
5. Bump `SCHEMA_VERSION` from `1.0` to `1.1` because generated subprocess-driver notification schemas change.
6. Continue accepting drivers whose protocol major version is `1`.
7. Do not change core-to-driver request methods for M6-1.

The driver protocol remains the narrow waist. No driver receives credentials or direct database handles.

## 6. Sinks And Dispatcher

### Sink configuration

Add sink URI parsing in `agentenv-events`:

1. `sqlite`
2. `sqlite:<path>`
3. `file:<path>`
4. `otel:grpc://collector:4317`
5. `webhook:https://example.test/events?kinds=egress_denied,approval_requested`

Default sink configuration:

1. per-env SQLite when an env is known
2. global SQLite for all events

If no explicit sink is configured, default SQLite is still active. Explicit sinks are additive in M6-1; there is no default-sink opt-out in this issue.

### Dispatcher

The dispatcher uses a bounded channel:

1. `EventDispatcher::new(config)`
2. `EventDispatcher::emitter() -> impl EventEmitter`
3. sink workers run under `tokio::spawn`
4. `emit` performs a non-blocking `try_send`
5. if the channel is full, the new event is dropped
6. drop counters are kept by sink and globally
7. the dispatcher emits a synthetic `log` event with `reason_code = "events_dropped"` when capacity becomes available

The first implementation uses a bounded queue that drops the new event when full. That is deterministic under tests and satisfies backpressure accounting.

### Fire-and-forget behavior

Lifecycle code must not await sink I/O. Commands that create a dispatcher should call `flush` during normal shutdown with a short timeout. A flush failure should be logged to stderr and counted, not turn a successful lifecycle operation into a failure.

For audit-sensitive operations, the event must be enqueued before the command returns. The sink write can still happen asynchronously, but `audit export` must only claim completeness for entries already committed to the audit store.

## 7. SQLite Store

Use `rusqlite` in `agentenv-events` for a small embedded store. It is a Rust dependency, not a new external runtime.

Schema:

```sql
CREATE TABLE activity_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  env TEXT,
  actor_json TEXT NOT NULL,
  subject_json TEXT NOT NULL,
  result TEXT NOT NULL,
  latency_ms INTEGER,
  trace_id TEXT NOT NULL,
  reason_code TEXT,
  extras_json TEXT NOT NULL
);

CREATE INDEX activity_events_ts_idx ON activity_events(ts);
CREATE INDEX activity_events_env_ts_idx ON activity_events(env, ts);
CREATE INDEX activity_events_kind_ts_idx ON activity_events(kind, ts);
CREATE INDEX activity_events_result_ts_idx ON activity_events(result, ts);
```

The per-env database stores only events for that env. The global database stores all events and is the default source for `agentenv logs --env <name>` when the per-env store is missing or stale.

SQLite writes happen in batches:

1. collect up to 128 events or 100 ms
2. write in one transaction
3. retry transient `SQLITE_BUSY` with a short bounded backoff
4. on repeated failure, increment sink error counters and emit one synthetic drop/failure event when possible

## 8. JSONL Sink

The JSONL sink writes one full `ActivityEvent` JSON object per line. It replaces the legacy ad hoc `events.jsonl` writer for new events.

Compatibility:

1. `agentenv logs` can still read old `events.jsonl` files when no SQLite store exists.
2. New `events.jsonl` files use the typed `ActivityEvent` shape.
3. `audit export --format jsonl` is separate from activity JSONL and writes audit entries, not raw activity entries.

## 9. OTEL Sink

The OTEL sink maps activity events to OTEL logs, not spans, because the issue asks for an event stream and not distributed tracing. `trace_id` is included when present.

Implementation choice:

1. Add a feature-gated OTEL module in `agentenv-events`.
2. Use `opentelemetry`, `opentelemetry_sdk`, and `opentelemetry-otlp` with tonic/grpc.
3. Add an integration test that can run against a standard OpenTelemetry Collector when `AGENTENV_RUN_OTEL_TESTS=1` is set.
4. Add a unit-level fake exporter test for normal CI so event-to-OTEL mapping is still covered without a collector.

Acceptance requires end-to-end export with a standard collector, so the implementation plan must include a gated integration test or documented local collector test. The CLI should fail fast on invalid OTEL sink URIs and report sink initialization errors before running the command.

OTEL export is best-effort after initialization. Runtime export failures increment sink error counters and do not fail the lifecycle command.

## 10. Webhook Sink

Webhook sinks post batches of events to a URL after SSRF validation. They support post-filtering by kind:

```text
webhook:https://hooks.example.test/agentenv?kinds=egress_denied,approval_requested
```

Rules:

1. validate the URL through `agentenv-core::security::ssrf`
2. reject embedded credentials
3. only allow `https` by default
4. support configured event kinds
5. redact secrets before enqueue
6. use bounded retries with jitter
7. do not block lifecycle commands

Webhook payload:

```json
{
  "schema": "agentenv.activity.v1",
  "events": []
}
```

## 11. Audit Log

Audit logging is separate from the activity stream but consumes the same event model.

### Audit-sensitive event kinds

The first audit policy includes:

1. `auth`
2. `credential_injected`
3. `credential_set`
4. `credential_reset`
5. `policy_applied`
6. `approval_requested`
7. `approval_decided`
8. `egress_denied`
9. `spawn_rejected`
10. failed `sandbox_create`
11. failed `exec`

The policy should be data-driven inside `agentenv-events::audit` so M6-3 can add approval-specific entries without touching core lifecycle logic.

### Storage

Store audit entries in SQLite tables next to activity events:

```sql
CREATE TABLE audit_entries (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  env TEXT,
  event_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  public_key TEXT NOT NULL
);

CREATE TABLE audit_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

Hash input is canonical JSON:

```json
{
  "sequence": 12,
  "ts": "2026-04-16T14:22:00Z",
  "prev_hash": "hex...",
  "event": {}
}
```

Use SHA-256 for `entry_hash = sha256(canonical_json)`. `prev_hash` for the first entry is 64 zero hex characters.

Every audit entry is signed with Ed25519 using `ed25519-dalek`, which is already in the workspace dependency set. The CLI creates a host-local audit signing key at `~/.agentenv/audit-signing-key` on first audit write, stores it with `0600` permissions on Unix, and writes the hex public key into `audit_metadata` plus each entry. The signing key is host-local operational state, not a driver credential, and it never crosses the driver RPC channel.

### Verification

`agentenv audit verify [--env <name>]` replays entries in sequence order:

1. recompute canonical hashes
2. check `prev_hash` links
3. check monotonic sequence
4. verify Ed25519 signatures against the stored public key
5. report the first broken sequence or signature and return non-zero

`agentenv audit export --from <date> --to <date> [--format jsonl|csv] [--env <name>]` exports entries, including hashes. JSONL is the default. CSV includes flattened high-value fields and an `event_json` column for full fidelity.

## 12. Metrics

`agentenv metrics serve --port 9180` starts a local HTTP server and exposes Prometheus text at `/metrics`.

Use `hyper` as a direct workspace dependency with only the server, HTTP/1, and TCP features needed for a local Prometheus endpoint.

Series:

```text
agentenv_envs_total{status="running"} 1
agentenv_events_total{kind="sandbox_create",env="myapp",result="ok"} 3
agentenv_sandbox_latency_seconds_bucket{op="create",driver="openshell",le="0.005"} 0
agentenv_mcp_tool_calls_total{tool="read_file",env="myapp",result="ok"} 7
agentenv_policy_blocks_total{kind="egress_denied",driver="openshell"} 2
agentenv_approvals_pending_total 1
agentenv_event_drops_total{sink="sqlite"} 0
agentenv_event_sink_errors_total{sink="webhook"} 0
```

The first six series are required by the issue. The last two make backpressure visible.

Data sources:

1. `agentenv_envs_total`: scan env state under `~/.agentenv/envs`.
2. `agentenv_events_total`: aggregate activity store counts.
3. `agentenv_sandbox_latency_seconds_bucket`: derive from events with latency and sandbox operation kind.
4. `agentenv_mcp_tool_calls_total`: aggregate `mcp_tool_call` events.
5. `agentenv_policy_blocks_total`: aggregate denied policy events.
6. `agentenv_approvals_pending_total`: read approval queue state when available; otherwise derive from `approval_requested` minus terminal `approval_decided` events.

Metrics compute on scrape for correctness in M6-1. This issue does not add a metrics cache.

## 13. CLI Behavior

### Global sink flag

Add a global repeatable flag:

```text
agentenv --events-sink sqlite --events-sink file:/tmp/agentenv.jsonl create demo
```

The flag applies to commands that emit events. Reader commands such as `logs`, `audit`, `stats`, and `metrics serve` ignore `--events-sink` and read the configured stores.

### Logs

Preferred M6 syntax:

```text
agentenv logs --env demo --kind egress_denied --follow
```

Backward-compatible M4 syntax remains valid:

```text
agentenv logs demo --follow
```

`logs` reads from SQLite first and falls back to legacy `events.jsonl`. Follow mode polls SQLite by monotonically increasing event id. Output defaults to human-readable rows. M6-1 also adds `--json` for newline-delimited `ActivityEvent` output.

### Stats

```text
agentenv stats --env demo
```

Print:

1. event counts by kind/result
2. policy blocks
3. approval pending count
4. sandbox operation latency summary
5. sink drops and sink errors

### Audit

```text
agentenv audit export --from 2026-04-01 --to 2026-04-26 --format jsonl
agentenv audit verify --env demo
```

### Metrics

```text
agentenv metrics serve --port 9180
```

The server binds to `127.0.0.1` only. M6-1 does not add a public bind-address flag.

## 14. Core Emission Points

Core must emit at least these events:

1. `spawn_requested`: `create` invoked after env name validation.
2. `spawn_queued`: reserved for future queue behavior. Local M6-1 emits it only if an actual queue/backpressure gate exists.
3. `spawn_admitted`: preflight and admission accepted.
4. `spawn_rejected`: preflight, blueprint, credential, policy, or capability rejection.
5. `spawn_started`: resource creation starts.
6. `spawn_ready`: env state committed and ready.
7. `sandbox_create`: sandbox driver create success/failure.
8. `sandbox_destroy`: destroy success/failure.
9. `exec`: command execution success/failure.
10. `policy_applied`: initial policy create and runtime policy apply.
11. `credential_injected`: credential name injected into sandbox environment.
12. `credential_set`: CLI credential storage success/failure.
13. `credential_reset`: CLI credential reset success/failure.
14. `auth`: GitHub, keyring, or local credential backend auth checks when those commands perform them.
15. `approval_requested`: approval requests from drivers or core checks.
16. `approval_decided`: approval decisions through CLI or queue.
17. `egress_denied`: SSRF blocks and driver-denied egress notifications.
18. `mcp_tool_call`: plugin/context notifications when available.

Local create should not invent queue events. The issue comment asks for queue behavior visibility; emitting `spawn_queued` only when a queue actually exists preserves semantics for coordinators.

## 15. Plugin Notification Integration

`agentenv-plugin` currently owns JSON-RPC subprocess communication. M6-1 adds notification handling that parses:

1. `event/log` into `ActivityKind::Log`
2. `event/activity` into the richer activity model
3. `event/approval_requested` into both `ApprovalRequested` activity and approval queue input when M6-3 is present

Malformed notifications should produce a `log` event with `result = "error"` and `reason_code = "invalid_driver_notification"`, not crash core. M6-1 does not add driver-degradation state for repeated malformed notifications.

## 16. Performance

Acceptance asks for no measurable CLI latency overhead over a no-sinks baseline, under 5 ms at p99.

The implementation should include a microbenchmark or ignored integration benchmark that measures:

1. no-op emitter
2. dispatcher with default SQLite sinks under warm database
3. dispatcher with a saturated slow sink

Expected behavior:

1. `emit` p99 stays under 5 ms because it only performs validation/redaction and bounded enqueue.
2. SQLite sink I/O happens outside the lifecycle critical path.
3. slow sinks do not block fast sinks.
4. drop counters increase under saturation.

The benchmark should run outside normal `cargo test` if it is timing-sensitive, but unit tests must cover bounded queue behavior deterministically.

## 17. Error Handling

1. Event construction errors are programmer errors and should be prevented by typed constructors.
2. Sink URI parse errors fail command startup.
3. Sink initialization errors fail command startup.
4. Sink runtime errors are counted and surfaced through metrics/stats.
5. Audit verification failures return non-zero and identify the first broken sequence.
6. Metrics serve returns non-zero if the port cannot bind.
7. Webhook SSRF blocks fail command startup for that sink.

Libraries use `thiserror`. The binary uses `anyhow`.

## 18. Testing Strategy

Follow TDD for implementation. High-value tests:

1. `agentenv-events::activity`
   - event kinds serialize as documented
   - old proto activity shape converts into rich activity events
   - redaction removes credential values from extras and subjects
   - protocol schema version is `1.1`
2. SQLite store
   - appends and reads events by env, kind, result, and cursor
   - writes per-env and global stores
   - migrates schema idempotently
3. Dispatcher
   - non-blocking emit returns quickly
   - bounded queue increments drop count
   - one slow sink does not block another sink
4. Audit
   - audit policy selects security-sensitive events
   - hash chain verifies
   - modified entry fails verification
   - export emits JSONL and CSV
5. Metrics
   - renders all documented series
   - pending approvals derive correctly
   - policy block counters group by kind and driver
6. CLI
   - `logs --env --kind` filters correctly
   - `logs --json` emits newline-delimited events
   - old `logs <name>` still works
   - `stats --env` prints aggregates
   - `audit export` and `audit verify` use stores
   - `metrics serve` responds at `/metrics`
7. Core integration
   - create accepted emits spawn lifecycle events
   - create rejected emits `spawn_rejected` with reason code
   - destroy emits `sandbox_destroy`
   - exec emits `exec`
   - credential injection emits names only
8. Plugin integration
   - `event/log` notification persists as log event
   - `event/activity` notification converts to rich event
   - malformed notification becomes error log event

Run at minimum:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Gated tests:

1. OTEL end-to-end with a collector.
2. Webhook sink with a local HTTP receiver.
3. Performance benchmark for p99 emit latency.

## 19. Acceptance Mapping

1. Every core operation emits a structured event:
   - covered by Sections 4 and 14.
2. SQLite sink persists events and `agentenv logs --follow` streams them:
   - covered by Sections 7 and 13.
3. OTEL export works end-to-end with a standard collector:
   - covered by Sections 9 and 18.
4. Audit log hash-chain verifies and export produces compliance output:
   - covered by Section 11.
5. `/metrics` endpoint exposes documented series and Prometheus scrape validates:
   - covered by Section 12.
6. No measurable CLI latency overhead under 5 ms p99:
   - covered by Sections 6 and 16.
7. Coordinator lifecycle events exist with reason codes:
   - covered by Sections 4 and 14.

## 20. Trade-Offs

1. SQLite as the default store adds a native dependency, but it avoids inventing an indexed log format and supports follow cursors, stats, audit tables, and aggregate metrics cleanly.
2. Keeping internal activity richer than driver protocol activity lets M6-1 satisfy operator needs while preserving protocol compatibility for existing drivers.
3. Dropping new events under queue saturation is simpler than oldest-drop buffering. The behavior is visible through counters and can be changed behind the dispatcher later.
4. Computing metrics on scrape is simpler and more reliable for alpha. A cache can be added if operator scrapes become expensive.
5. Optional audit signatures are deferred, but the schema reserves the field. Hash-chain verification meets the issue's tamper-evidence requirement now.

## 21. Implementation Order

1. Add `agentenv-events::activity` tests and event model.
2. Add SQLite store tests and implementation.
3. Add dispatcher tests and implementation.
4. Add audit tests and implementation.
5. Add metrics render tests and implementation.
6. Add CLI reader command tests and implementation.
7. Add core emission integration tests and implementation.
8. Add plugin notification conversion tests and implementation.
9. Add OTEL and webhook sinks with gated integration tests.
10. Run formatting, clippy, workspace tests, and gated checks where available.
