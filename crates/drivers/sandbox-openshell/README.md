# sandbox-openshell

Built-in `SandboxDriver` for OpenShell-backed sandboxes.

Behavior:

- Requires `openshell >= 0.0.30` and a working OpenShell gateway for runtime use.
- Creates sandboxes from the `openclaw` image by default unless another image is provided.
- Supports BYO sandbox Dockerfiles through `sandbox.image.source: byo` or
  `agentenv create --from <path>`. The Dockerfile parent directory is copied to
  `~/.agentenv/build/<env>/`, the selected Dockerfile is staged as `Dockerfile`,
  and that staged context is passed to `openshell sandbox create --from`.
- Translates `agentenv` network policy into OpenShell policy documents and supports hot-reload for network and inference policy updates.
- Passes credentials into the sandbox as environment variables only; they do not flow through argv, policy files, or image layers.

BYO Dockerfiles may declare these stable build arguments:

| ARG | Value |
| --- | --- |
| `AGENTENV_VERSION` | Version of the `agentenv` binary building the image. |
| `AGENTENV_AGENT` | Agent driver name, for example `codex` or `claude`. |
| `AGENTENV_MCP_PORT` | MCP HTTP port when the context endpoint uses an HTTP transport. Empty otherwise. |
| `AGENTENV_WORKSPACE_MOUNT` | Sandbox workspace path, currently `/sandbox`. |

The driver also builds the staged context locally so it can inspect the image ID.
If `sandbox.image.expected_digest` is set, the driver compares it with the built
image ID and fails before sandbox creation on mismatch. If omitted, the computed
digest is written to `~/.agentenv/build/<env>/image-digest` for the core to
record in `lock.yaml`.

## Hardening

OpenShell consumes `SandboxSpec.metadata` during `create`. When BYO Dockerfile
metadata includes a selected hardening profile, the driver appends the
corresponding hardening marker and Dockerfile fragment to the staged Dockerfile
before `docker build`. Digest verification and digest recording use the built
image after that fragment is injected, so `sandbox.image.expected_digest` must
match the hardened image.

The driver parses and validates runtime hardening metadata such as ulimits,
core-dump disabling, and user-namespace disabling, but the current OpenShell
implementation does not add unsupported runtime CLI arguments to
`openshell sandbox create`; valid runtime metadata is not currently enforced by
the OpenShell CLI integration. Blueprint lint and preflight currently catch BYO
Dockerfile conflicts such as a root final user, privileged or `cap-add`
references, missing hardening marker, and reintroduction of packages stripped by
the selected profile.

Integration test command:

```bash
AGENTENV_RUN_OPENSHELL_INTEGRATION=1 cargo test -p sandbox-openshell --features integration -- --ignored
```
