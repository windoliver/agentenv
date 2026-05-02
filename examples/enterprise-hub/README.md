# Enterprise Hub Example

This template assumes a shared Nexus hub, a company CA, and an internal OpenShell base image.

## Prerequisites

```sh
export ANTHROPIC_API_KEY=sk-ant-example
export NEXUS_HUB_URL=https://nexus.company.com
export NEXUS_TOKEN=nexus-token-example
agentenv drivers list
```

Build and publish the internal base image referenced by `agentenv.yaml`:

```sh
docker build -t registry.internal.example.com/agentenv/company-base:latest .
docker push registry.internal.example.com/agentenv/company-base:latest
```

## Lifecycle

```sh
agentenv create enterprise-hub
agentenv enter enterprise-hub
agentenv freeze enterprise-hub --output agentenv.lock
agentenv destroy enterprise-hub --yes
```

Run the lifecycle commands from this directory so `agentenv create` discovers `agentenv.yaml`.
