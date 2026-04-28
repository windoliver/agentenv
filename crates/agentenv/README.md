# agentenv

`agentenv` is the CLI entry point for creating, entering, reproducing, observing,
and auditing agent environments.

Day-2 operations:

- `agentenv logs --env <name> --kind <kind> [--follow] [--json]`
- `agentenv stats [--env <name>]`
- `agentenv audit export [--env <name>] [--from <date>] [--to <date>] --format jsonl|csv`
- `agentenv audit verify [--env <name>]`
- `agentenv metrics serve --port 9180`

Activity events are written to global and per-environment SQLite stores by
default. Additional sinks can be attached with repeated `--events-sink` flags:

- `file:/path/to/events.jsonl`
- `sqlite:/path/to/events.db`
- `webhook:https://example.test/events?kinds=egress_denied`
- `otel:grpc://collector:4317` when `agentenv-events/otel` is enabled

Audit-sensitive events are signed synchronously before command success or
failure is reported, so audit write failures are surfaced instead of being hidden
behind the original operation result.
