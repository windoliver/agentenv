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

The installer creates an isolated virtual environment, builds wheels for this driver package and Hermes Agent from the official GitHub source, installs those wheels offline into the driver venv, writes `manifest.json`, and atomically replaces the installed driver directory.

By default it builds Hermes from:

```text
hermes-agent[mcp] @ git+https://github.com/NousResearch/hermes-agent.git
```

Set `HERMES_AGENT_PACKAGE` to override the wheel source, for example to pin a release tag:

```bash
HERMES_AGENT_PACKAGE="hermes-agent[mcp] @ git+https://github.com/NousResearch/hermes-agent.git@v2026.4.16" \
  external-drivers/agent-hermes-py/scripts/install-driver.sh
```

## Test

```bash
external-drivers/agent-hermes-py/scripts/run-tests.sh
```

The tests exercise protocol framing, driver methods, packaging files, and the real subprocess entrypoint. They do not require model API credentials.

## agentenv CLI

After installing this driver and a compatible context driver, `agentenv` can discover Hermes with `agentenv drivers list` and run it through the normal environment lifecycle:

```bash
agentenv create research --blueprint blueprints/hermes+nexus+openshell.yaml
agentenv status research
agentenv destroy research --yes
```
