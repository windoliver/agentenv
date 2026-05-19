# agentenv-events

`agentenv-events` owns activity events, sink dispatch, durable SQLite storage,
audit hash chains, webhook and OTEL export, and Prometheus metrics rendering for
agentenv.

Default storage:

- per env: `~/.agentenv/envs/<name>/events.db`
- global: `~/.agentenv/events.db`

CLI surfaces:

- `agentenv logs --env <name> --kind <kind> [--follow] [--json]`
- `agentenv stats [--env <name>]`
- `agentenv audit export [--env <name>] [--from <date>] [--to <date>] --format jsonl|csv`
- `agentenv audit verify [--env <name>]`
- `agentenv metrics serve --port 9180`

Sink URI forms:

- `sqlite` for default global and per-env SQLite storage
- `sqlite:/path/to/events.db`
- `file:/path/to/events.jsonl`
- `webhook:https://example.test/events?kinds=egress_denied,approval_requested`
- `otel:grpc://collector:4317` when built with the `otel` feature

Webhook sinks are validated by the CLI through the shared SSRF guard before
construction, and redirects are disabled. OTEL dependencies are optional so
default builds do not pull in the exporter stack.

## OTEL and GenAI mapping

`ActivityEvent` is the durable source of truth. The OTEL sink exports every
activity event as an `agentenv.activity` log record with `agentenv.kind`,
`agentenv.result`, `agentenv.trace_id`, and optional `agentenv.env`,
`agentenv.reason_code`, and `agentenv.latency_ms` attributes.

GenAI-aware activity uses OTEL GenAI semantic-convention attributes:

- `gen_ai_model_call` maps to a client span. Supported attributes are
  `gen_ai.provider.name`, `gen_ai.operation.name`, `gen_ai.request.model`,
  `gen_ai.response.model`, `gen_ai.usage.input_tokens`,
  `gen_ai.usage.output_tokens`, and `gen_ai.response.finish_reasons`.
- `mcp_tool_call` maps to an internal tool span with `gen_ai.tool.name` and
  optional `gen_ai.tool.call.id`.
- `agent_turn` maps to an internal agent span with `gen_ai.agent.name`.

Canonical OTEL output uses `gen_ai.provider.name`. The mapper accepts
`gen_ai.system` only as an input alias for older event producers. Token aliases
`gen_ai.usage.prompt_tokens` and `gen_ai.usage.completion_tokens` are accepted
as inputs and exported as input/output token usage.

## Prometheus metrics

`agentenv metrics serve` renders these series from the activity store and local
approval state:

- `agentenv_envs_total{status}`
- `agentenv_events_total{kind,env,result}`
- `agentenv_sandbox_latency_seconds_bucket|sum|count{op,driver}`
- `agentenv_mcp_tool_calls_total{tool,env,result}`
- `gen_ai_client_token_usage_bucket|sum|count{gen_ai_provider_name,gen_ai_operation_name,gen_ai_token_type,gen_ai_request_model,env,result}`
- `gen_ai_client_operation_duration_bucket|sum|count{gen_ai_provider_name,gen_ai_operation_name,gen_ai_request_model,env,result}`
- `agentenv_gen_ai_tool_calls_total{gen_ai_tool_name,env,result}`
- `agentenv_policy_blocks_total{kind,driver}`
- `agentenv_approvals_pending_total`
- `agentenv_build_oneflight_hits_total`
- `agentenv_build_oneflight_misses_total`
- `agentenv_build_queue_depth`
- `agentenv_event_drops_total{sink}`
- `agentenv_event_sink_errors_total{sink}`

The GenAI histogram names and labels intentionally match OTEL GenAI Prometheus
conventions where possible; agentenv-specific counters keep operational signals
such as policy blocks and sink health visible. Sink health counters include
zero-valued `sink="sqlite"` samples by default when no drops or write errors
have been observed.

## Redaction and cardinality

Events are redacted before GenAI OTEL export. Prompt-like fields,
response/body-like fields, API keys, tokens, secrets, and credential-looking
values are removed or replaced with redacted values. Raw prompts, responses,
headers, URLs with credentials, and request bodies must not be used as metric
labels.

Metric labels are intentionally bounded to stable identifiers such as env,
event kind, result, provider, operation, request model, token type, tool name,
driver, and sink. Drivers should put high-cardinality or sensitive details in
event payload fields only when they can be safely redacted or omitted from
export.
