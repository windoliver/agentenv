# agentenv

`agentenv` is the CLI entry point for creating, entering, reproducing, observing,
and auditing agent environments.

Create with a custom sandbox Dockerfile:

```bash
agentenv create demo --from ./enterprise-sandbox/Containerfile
```

`--from` is equivalent to setting `AGENTENV_FROM_DOCKERFILE` and overlays the
blueprint with:

```yaml
sandbox:
  image:
    source: byo
    dockerfile: /absolute/path/to/Containerfile
```

The Dockerfile parent directory is the build context. The built image digest is
verified against `sandbox.image.expected_digest` when present; otherwise the
computed digest is recorded in the environment lockfile. After local digest
verification, the staged context is handed to OpenShell so its gateway can build
and materialize the sandbox image.

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
