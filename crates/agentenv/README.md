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

## Snapshots

`agentenv snapshot <env> [--output <dir.agentenvsnap>]` captures a stateful
backup of an environment as an unpacked `.agentenvsnap` directory. The snapshot
includes the frozen blueprint, lockfile, workspace state, persisted home when
enabled, resolved policy, event database, a manifest, and an Ed25519 signature.
Credential files and credential-looking values are stripped before the manifest
is written.

`agentenv snapshot verify <dir.agentenvsnap>` recomputes payload digests, checks
the Merkle root, checks the manifest hash, verifies the Ed25519 signature, and
verifies the embedded lockfile.

`agentenv snapshot restore <dir.agentenvsnap> [--as <name>]` verifies the
snapshot, resolves required credentials through the normal env var/keyring
provider path, reproduces the env from the embedded lockfile, and copies the
sanitized workspace and persisted home state into the new sandbox. Use
`--non-interactive` or `AGENTENV_NON_INTERACTIVE=1` to fail cleanly instead of
prompting when required credentials are missing.

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
