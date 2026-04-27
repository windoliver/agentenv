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
