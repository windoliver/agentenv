# H-8 Design: OTEL GenAI Semantic Conventions For Activity Events

- Date: 2026-05-18
- Issue: https://github.com/windoliver/agentenv/issues/44
- Milestone: M6 Day-2 operations hardening
- Depends on: https://github.com/windoliver/agentenv/issues/23
- Affected crates: `agentenv-events`, `agentenv-core`, `agentenv`, `agentenv-proto`, `agentenv-plugin`

## 1. Context And Goals

Issue #44 aligns the M6-1 activity event stream with OpenTelemetry GenAI
semantic conventions so agentenv telemetry can plug into common observability
stacks without custom adapters.

M6-1 is already present locally:

1. `agentenv-events` owns `ActivityEvent`, async dispatch, SQLite storage,
   audit hash chains, webhook and OTEL sinks, and Prometheus rendering.
2. `agentenv-core` emits lifecycle events through `EventEmitter`.
3. `agentenv-plugin` converts driver notifications into `ActivityEvent`.
4. `agentenv metrics serve` renders existing `agentenv_*` Prometheus series.

This design keeps that architecture. `ActivityEvent` remains the durable native
event format and the OTEL GenAI mapper becomes an export and metrics view over
that model.

The current OpenTelemetry GenAI semantic convention pages are version 1.41.0
and mark these conventions as development. The current attribute names use
`gen_ai.provider.name` and `gen_ai.operation.name`; the older `gen_ai.system`
name in the issue body is treated as an accepted input alias, not the canonical
output name.

## 2. Scope And Non-Goals

### In scope

1. Map agentenv activity events to OTEL GenAI-compatible spans, span events,
   log records, and attributes.
2. Emit OTLP telemetry to `observability.otel.endpoint` from blueprint config.
3. Keep `--events-sink otel:grpc://collector:4317` supported for CLI use.
4. Add GenAI-derived Prometheus metrics alongside existing `agentenv_*` series.
5. Add a default Grafana dashboard at
   `contrib/grafana/dashboards/agentenv-otel.json`.
6. Document supported GenAI attributes, aliases, redaction rules, and limits.
7. Add tests for mapping, configuration, metrics, dashboard validity, and
   backwards compatibility.

### Out of scope

1. Exporting prompt bodies, completion bodies, system instructions, or MCP
   payload contents by default.
2. Replacing the native activity/audit store with OTEL as the source of truth.
3. Adding a second agent-to-context protocol.
4. Requiring every driver to emit OTEL directly.
5. Adding high-cardinality labels such as arbitrary tool arguments, URLs with
   query strings, prompt hashes, or blueprint digests to Prometheus metrics.

## 3. Design Direction

Use the existing `agentenv-events` crate as the central observability boundary.
The full implementation should add a GenAI semantic mapping layer rather than a
parallel telemetry model.

`ActivityEvent` stays the format persisted to SQLite, audit logs, JSONL, and
webhooks. The OTEL layer reads an `ActivityEvent` and produces an
`OtelGenAiSignal` value that contains:

1. a signal kind: span, span event, or log record
2. a span/log name
3. a span kind hint
4. a stable operation name
5. semantic attributes
6. agentenv extension attributes
7. a status derived from `ActivityResult`

This gives tests a stable, SDK-independent target and keeps callers independent
from the exact OpenTelemetry Rust SDK export APIs.

## 4. Event Mapping

### Canonical attributes

The mapper emits current GenAI semantic convention names where available:

| Attribute | Source |
|---|---|
| `gen_ai.operation.name` | derived from activity kind or `extras` |
| `gen_ai.provider.name` | `extras["gen_ai.provider.name"]`, `extras["gen_ai.system"]`, inference driver name, or configured default |
| `gen_ai.request.model` | `extras["gen_ai.request.model"]` or model aliases |
| `gen_ai.response.model` | `extras["gen_ai.response.model"]` |
| `gen_ai.usage.input_tokens` | numeric `extras["gen_ai.usage.input_tokens"]` |
| `gen_ai.usage.output_tokens` | numeric `extras["gen_ai.usage.output_tokens"]` |
| `gen_ai.response.finish_reasons` | string array from `extras` |
| `gen_ai.tool.name` | tool name in subject or extras |
| `gen_ai.tool.call.id` | tool call id in subject or extras |
| `gen_ai.agent.name` | env name or explicit agent name |
| `gen_ai.agent.version` | explicit agent version when present |
| `server.address` / `server.port` | validated endpoint host/port when available |

The mapper also preserves low-cardinality agentenv fields:

| Attribute | Source |
|---|---|
| `agentenv.event.kind` | activity kind |
| `agentenv.event.result` | activity result |
| `agentenv.env` | event env |
| `agentenv.trace_id` | activity trace id |
| `agentenv.reason_code` | reason code |
| `agentenv.egress.denied` | `true` for denied egress |
| `agentenv.approval.kind` | approval kind |
| `agentenv.approval.request_id` | approval request id |
| `agentenv.policy.reload` | `true` for policy reload events |

### Activity kind mapping

| Activity kind | OTEL representation |
|---|---|
| `mcp_tool_call` | span with `gen_ai.operation.name=execute_tool` |
| `agent_turn` | span with `gen_ai.operation.name=invoke_agent` |
| `gen_ai_model_call` | span with request/response model and token attributes |
| `approval_requested` | event/log with `agentenv.approval.*`, result `pending_approval` |
| `approval_decided` | event/log with `agentenv.approval.*` |
| `egress_denied` | event/log with `agentenv.egress.denied=true` |
| `policy_applied` | event/log with `agentenv.policy.reload=true` when hot reloaded |
| other lifecycle events | event/log with `agentenv.*` attributes |

`ActivityKind` does not currently have an explicit `AgentTurn` or `ModelCall`
variant. The PR should add the smallest compatible representation:

1. Add `AgentTurn` and `GenAiModelCall` to `agentenv-events::ActivityKind`.
2. Add matching `RichActivityKind` variants to `agentenv-proto`.
3. Keep legacy driver activity parameters accepted.
4. Allow existing `McpToolCall` events to represent `execute_tool` without
   driver changes.

This is an additive schema change. It does not alter existing method names or
core-to-driver requests.

### Alias handling

The mapper accepts these input aliases in `extras` and normalizes output:

| Input alias | Canonical output |
|---|---|
| `gen_ai.system` | `gen_ai.provider.name` |
| `gen_ai.request.max_tokens` | `gen_ai.request.max_tokens` |
| `gen_ai.usage.input_tokens` | `gen_ai.usage.input_tokens` |
| `gen_ai.usage.output_tokens` | `gen_ai.usage.output_tokens` |
| `gen_ai.tool.call.id` | `gen_ai.tool.call.id` |

Aliases exist for compatibility with older issue text and external emitters.
New agentenv code should use canonical names.

## 5. OTLP Export

The existing `OtelSink` currently exports log records with `agentenv.*`
attributes. The full PR extends this in two layers:

1. `otel::map_event_to_genai_signal(event) -> OtelGenAiSignal`
2. `OtelSink` export of `OtelGenAiSignal` through the OpenTelemetry SDK

The mapper is the stable contract. Tests must assert the span/log names,
operation names, semantic attributes, status, and redaction behavior without a
live collector.

The sink must export true OTLP trace spans for `agent_turn`,
`gen_ai_model_call`, and `mcp_tool_call`. Approval, egress, policy, and other
agentenv security/lifecycle events can be exported as OTLP log records and as
span events when a parent trace context is available. Span export requires
adding the OpenTelemetry trace SDK/exporter features already compatible with the
workspace's pinned OpenTelemetry version.

Exported spans and logs must carry `gen_ai.operation.name`, all available
`gen_ai.*` attributes, status and error fields derived from `ActivityResult`,
and trace correlation through `agentenv.trace_id`.

## 6. Blueprint And CLI Configuration

Add an optional blueprint section:

```yaml
observability:
  otel:
    endpoint: grpc://collector:4317
```

Model changes:

1. Add `ObservabilitySection` to `agentenv-core::blueprint::Blueprint`.
2. Add `OtelObservabilitySection { endpoint: Option<String> }`.
3. Validate OTEL endpoints through the same URL safety path used for webhook
   sinks before network export.
4. Treat blueprint OTEL config as additive to default SQLite storage.
5. Keep `--events-sink otel:grpc://collector:4317` as an explicit CLI sink.

Precedence:

1. CLI `--events-sink` always applies to the current command.
2. Blueprint `observability.otel.endpoint` applies to lifecycle commands that
   load a blueprint, such as `create`.
3. Reader commands such as `logs`, `audit`, `stats`, and `metrics serve` read
   stores and do not export events.

The implementation must not write an env store or emit create-time events until
runtime commit points already used by M6-1 are respected.

## 7. Prometheus Metrics

Keep all existing `agentenv_*` series. Add bounded-cardinality GenAI metrics
derived from persisted events:

1. `gen_ai_client_token_usage_bucket`
2. `gen_ai_client_token_usage_sum`
3. `gen_ai_client_token_usage_count`
4. `gen_ai_client_operation_duration_bucket`
5. `gen_ai_client_operation_duration_sum`
6. `gen_ai_client_operation_duration_count`
7. `agentenv_gen_ai_tool_calls_total`

Prometheus metric and label names use safe underscores while preserving
semantic meaning:

| Prometheus label | Semantic meaning |
|---|---|
| `gen_ai_provider_name` | `gen_ai.provider.name` |
| `gen_ai_operation_name` | `gen_ai.operation.name` |
| `gen_ai_token_type` | `gen_ai.token.type` |
| `gen_ai_request_model` | `gen_ai.request.model` |
| `gen_ai_tool_name` | `gen_ai.tool.name` |
| `env` | agentenv environment |
| `result` | activity result |

Token histograms use the OTEL-recommended token-oriented bucket boundaries:
`1`, `4`, `16`, `64`, `256`, `1024`, `4096`, `16384`, `65536`, `262144`,
`1048576`, `4194304`, `16777216`, and `67108864`. Operation duration uses the
existing duration bucket style so it stays consistent with current
`agentenv_sandbox_latency_seconds` output.

Do not include raw endpoint URLs, request ids, trace ids, prompt hashes, or tool
arguments as Prometheus labels.

## 8. Grafana Dashboard

Add `contrib/grafana/dashboards/agentenv-otel.json` with a Prometheus data
source variable and panels for:

1. known envs by status
2. activity event volume by kind/result
3. GenAI operation duration p95
4. input/output token usage
5. tool call rate and failures
6. egress denials
7. pending approvals and approval decisions
8. event drops and sink errors

The dashboard should use only metrics emitted by `agentenv metrics serve` and
avoid assumptions about a specific backend beyond Prometheus-compatible query
support.

## 9. Redaction And Cardinality

All GenAI mapping happens after `ActivityEvent::redacted()` or applies the same
redaction helpers before export. Credential-looking keys and values must not
appear in:

1. SQLite
2. JSONL
3. audit export
4. OTLP attributes
5. Prometheus metrics
6. CLI output

Prompt and completion content are opt-in only and not part of this issue. The
default implementation exports metadata, counts, status, and timings.

Metric labels must stay low-cardinality. The mapper should include values only
from allowlisted semantic fields.

## 10. Tests

Add focused tests for:

1. `ActivityKind::AgentTurn` and `ActivityKind::GenAiModelCall` serialization.
2. Rich driver activity conversion for new kinds.
3. `gen_ai.system` alias normalization to `gen_ai.provider.name`.
4. `mcp_tool_call` mapping to `execute_tool` with `gen_ai.tool.name`.
5. agent turn mapping to `invoke_agent` with `gen_ai.agent.name`.
6. token usage and duration metric aggregation.
7. OTEL sink URI plus blueprint endpoint configuration.
8. SSRF rejection for unsafe OTEL endpoints.
9. Prometheus render output for the new GenAI series.
10. dashboard JSON parsing and expected metric references.
11. docs examples that avoid old canonical names.

Run at least:

```bash
cargo fmt
cargo test -p agentenv-events
cargo test -p agentenv-proto
cargo test -p agentenv-plugin
cargo test -p agentenv-core blueprint observability
cargo test -p agentenv cli_behavior metrics
cargo clippy --workspace -- -D warnings
```

Before PR handoff, run:

```bash
cargo test --workspace
```

## 11. Documentation

Update:

1. `docs/ARCHITECTURE.md` observability section with OTEL GenAI mapping.
2. `docs/DRIVER_PROTOCOL.md` with additive rich activity kinds and accepted
   GenAI metadata fields.
3. `crates/agentenv-events/README.md` with supported OTEL attributes.
4. `crates/agentenv/README.md` with blueprint and CLI configuration examples.

Docs should explicitly say that agentenv follows the current
`gen_ai.provider.name` convention and accepts `gen_ai.system` only as an input
compatibility alias.

## 12. Trade-Offs

1. Keeping `ActivityEvent` as source of truth avoids duplicate observability
   pipelines, but the mapper must be careful about incomplete metadata.
2. Additive `ActivityKind` and proto variants are low risk, but still require
   schema regeneration and plugin tests.
3. Prometheus cannot represent dotted OTEL attribute names as label keys
   directly, so label names use underscores while documentation maps them back
   to semantic attributes.
4. Adding true OTLP trace export increases dependency surface, but it directly
   satisfies #44 and keeps agent/tool operations usable in trace-first
   backends.

## 13. Acceptance Criteria

1. `agentenv-events` maps native events to current OTEL GenAI semantic spans,
   span events, log records, and attributes.
2. Agent turns produce `gen_ai.operation.name=invoke_agent`.
3. Tool calls produce `gen_ai.operation.name=execute_tool`.
4. Model calls include provider, model, token usage, finish reasons, and status
   when present.
5. Approval, egress, and policy events include `agentenv.*` extension
   attributes.
6. `observability.otel.endpoint` configures OTLP export.
7. `/metrics` exposes existing `agentenv_*` series plus GenAI-derived metrics.
8. `contrib/grafana/dashboards/agentenv-otel.json` is valid JSON and uses
   emitted metrics.
9. Secrets and prompt bodies are not exported by default.
10. `cargo fmt`, `cargo clippy --workspace -- -D warnings`, and
    `cargo test --workspace` pass.

## 14. References

- OpenTelemetry GenAI client spans:
  https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/
- OpenTelemetry GenAI agent and framework spans:
  https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/
- OpenTelemetry GenAI metrics:
  https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/
- OpenTelemetry GenAI attribute registry:
  https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/
