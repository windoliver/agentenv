# context-nexus-py

Python subprocess context driver for agentenv. The installed driver is named
`nexus` and implements the context driver JSON-RPC protocol over stdio.

## Modes

Hub mode validates `hub_url`, declares `NEXUS_TOKEN`, and returns an HTTP MCP
endpoint for the Nexus hub.

Lite mode starts `nexus mcp serve --transport http` against a local data
directory and returns the loopback MCP endpoint.

## Local Install

```bash
AGENTENV_HOME="$HOME/.agentenv" ./scripts/install-driver.sh
agentenv drivers list
```

## Tests

```bash
PYTHONPATH=src python3 -m pytest tests -q
```
