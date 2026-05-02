# Enterprise Hub Example

This template assumes a shared Nexus hub, a company CA, and an internal OpenShell base image.

## Prerequisites

```sh
export ANTHROPIC_API_KEY=sk-ant-example
export NEXUS_HUB_URL=https://example.com/nexus
export NEXUS_TOKEN=nexus-token-example
agentenv drivers list
```

Replace `NEXUS_HUB_URL` with your Nexus hub URL before use.

Build and publish the internal base image referenced by `agentenv.yaml`:

```sh
docker build -t registry.internal.example.com/agentenv/company-base:2026.05 .
docker push registry.internal.example.com/agentenv/company-base:2026.05
```

Before creating the environment, replace both the `sandbox.image` reference and `sandbox.digest` in `agentenv.yaml` with the values for your published internal image.

## Lifecycle

```sh
agentenv create enterprise-hub
agentenv enter enterprise-hub
agentenv freeze enterprise-hub --output agentenv.lock
agentenv destroy enterprise-hub --yes
```

Run the lifecycle commands from this directory so `agentenv create` discovers `agentenv.yaml`.
