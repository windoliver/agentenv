# sandbox-openshell

Built-in `SandboxDriver` for OpenShell-backed sandboxes.

Behavior:

- Requires `openshell >= 0.0.30` and a working OpenShell gateway for runtime use.
- Creates sandboxes from the `openclaw` image by default unless another image is provided.
- Translates `agentenv` network policy into OpenShell policy documents and supports hot-reload for network and inference policy updates.
- Passes credentials into the sandbox as environment variables only; they do not flow through argv, policy files, or image layers.

Integration test command:

```bash
AGENTENV_RUN_OPENSHELL_INTEGRATION=1 cargo test -p sandbox-openshell --features integration -- --ignored
```
