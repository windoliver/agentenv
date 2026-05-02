# Quickstart Example

This project is the smallest local agentenv template. It mounts the current directory as the filesystem context and starts Claude Code in OpenShell.

## Prerequisites

```sh
export ANTHROPIC_API_KEY=sk-ant-example
```

## Lifecycle

```sh
agentenv create quickstart
agentenv enter quickstart
agentenv exec quickstart -- echo ok
agentenv freeze quickstart --output agentenv.lock
agentenv destroy quickstart --yes
```

Run the commands from this directory so `agentenv create` discovers `agentenv.yaml`.
