# agent-hermes-py

`agent-hermes-py` is the external Python `AgentDriver` adapter for Nous Research Hermes Agent.

It implements agentenv's JSON-RPC driver protocol over stdio and installs as the `hermes` agent driver under:

```text
~/.agentenv/drivers/agent-hermes/
```

## Install

```bash
external-drivers/agent-hermes-py/scripts/install-driver.sh
```

The installer creates an isolated virtual environment, installs this driver package, installs `hermes-agent[mcp]`, writes `manifest.json`, and atomically replaces the installed driver directory.

## Test

```bash
external-drivers/agent-hermes-py/scripts/run-tests.sh
```

The tests exercise protocol framing, driver methods, packaging files, and the real subprocess entrypoint. They do not require model API credentials.

## Current Host Limit

This package is standalone. The current agentenv core can discover the installed manifest with `agentenv drivers list`, but full `agentenv create` execution still needs subprocess AgentDriver host integration in `agentenv-core`.
