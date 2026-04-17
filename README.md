# agentenv

> **A declarative environment manager for AI coding agents.**
> Compose a sandbox runtime, an agent, a context backend, and an inference provider into a reproducible, portable environment. One `agentenv.yaml`, one command.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#project-status)

```text
# Declare what you want in agentenv.yaml, then:

$ agentenv create myapp
✓ OpenShell sandbox created
✓ Claude installed + MCP wired
✓ Nexus context connected (zones: eng, ops)
✓ Policy applied: balanced tier + github_read preset

$ agentenv enter myapp
sandbox$ claude  # ready, with company context + policy enforcement
```

---

## What agentenv is

`agentenv` is to AI coding agents what `conda` / `pixi` / `devbox` are to dev environments:

- You declare a composition in `agentenv.yaml` (pinned drivers, policies, credentials sources)
- You run `agentenv create` to materialize it
- You `enter` the environment, run your agent, `freeze` it to a lockfile, or `reproduce` it on a different machine
- When done, `agentenv destroy` tears it all down cleanly

The key insight: **every axis is pluggable**.

```text
                        ┌─────────────────────────┐
                        │    agentenv (core)      │
                        │ blueprint · policy ·    │
                        │ credstore · approvals · │
                        │ events · sessions · CLI │
                        └────────────┬────────────┘
                                     │ narrow waist: JSON-RPC driver protocol
          ┌──────────────┬───────────┼───────────┬──────────────┐
          ▼              ▼           ▼           ▼              ▼
     ┌─────────┐   ┌─────────┐  ┌─────────┐ ┌─────────┐  ┌──────────────┐
     │ Sandbox │   │  Agent  │  │ Context │ │Inference│  │ MCPTransport │
     │ drivers │   │ drivers │  │ drivers │ │ drivers │  │   adapters   │
     ├─────────┤   ├─────────┤  ├─────────┤ ├─────────┤  ├──────────────┤
     │OpenShell│   │ Claude  │  │  Nexus  │ │NVIDIA   │  │ stdio        │
     │Docker*  │   │ Codex   │  │ mcp-gen │ │OpenAI   │  │ http         │
     │E2B*     │   │ Hermes* │  │ fs      │ │Anthropic│  │ http+sse     │
     │         │   │OpenClaw │  │ none    │ │Ollama   │  │ ssh+http     │
     └─────────┘   └─────────┘  └─────────┘ └─────────┘  └──────────────┘

                                                             * post-MVP
```

- **Sandbox** — the isolated runtime (OpenShell, Docker, E2B, Firecracker, ...)
- **Agent** — the AI program that runs inside (Claude Code, Codex, Hermes, OpenClaw, ...)
- **Context** — the knowledge backend the agent calls via MCP (Nexus, any MCP server, filesystem-only, none)
- **Inference** — how model calls are routed (provider + credentials stay on the host)

MCP is the only agent↔context protocol. Everything plugs in around it.

---

## Quickstart

> **Alpha.** Not production-ready. Interfaces may change.

### Install

```bash
curl -LsSf https://raw.githubusercontent.com/windoliver/agentenv/main/install.sh | sh
```

Or with Cargo:

```bash
cargo install agentenv
```

### Minimal `agentenv.yaml`

```yaml
version: 0.1.0

sandbox:
  driver: openshell

agent:
  driver: claude
  credentials:
    ANTHROPIC_API_KEY: { source: env }

context:
  driver: filesystem
  mount: ~/projects/myapp

inference:
  driver: passthrough

policy:
  tier: balanced
```

### Create, enter, destroy

```bash
agentenv create myapp
agentenv enter myapp
agentenv list
agentenv freeze myapp > agentenv.lock
agentenv reproduce agentenv.lock
agentenv destroy myapp
```

---

## How it compares

|                   | `agentenv`       | NemoClaw         | OpenShell       | Docker Compose   |
|-------------------|------------------|------------------|-----------------|------------------|
| **Domain**        | AI agents        | AI agents        | Sandbox runtime | General services |
| **Agent**         | Pluggable        | Fixed (OpenClaw) | Pluggable       | N/A              |
| **Sandbox**       | Pluggable        | Fixed (OpenShell)| Own             | Docker           |
| **Context**       | Pluggable (MCP)  | None             | None            | N/A              |
| **Inference**     | Pluggable        | Routed (OpenShell gateway) | Own gateway | N/A |
| **Declarative**   | `agentenv.yaml`  | Blueprint YAML   | Policy YAML     | `compose.yaml`   |
| **Single binary** | Yes (Rust)       | No (Node+Python) | Yes (Rust)      | Yes (Go)         |
| **Plugin model**  | JSON-RPC subprocess + in-tree | Monolithic | In-tree | External executables |

---

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design:

- Why four pluggable axes (sandbox, agent, context, inference)
- How built-in drivers (Rust trait impls) and external drivers (JSON-RPC subprocesses) share one contract
- MCP as the narrow-waist protocol
- Capability handshake + graceful degradation
- Policy translation layer (generic `NetworkPolicy` → driver-native format)
- Session vs. sandbox distinction, blueprint lifecycle, credstore contract

For the driver protocol spec see [`docs/DRIVER_PROTOCOL.md`](docs/DRIVER_PROTOCOL.md).

For the roadmap see [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Project status

**Alpha — early public preview.** The architecture has been designed against three production references (NVIDIA NemoClaw, NVIDIA OpenShell, and VNC/RFB for the pluggable-narrow-waist pattern). Implementation is in progress. Follow [the umbrella epic](https://github.com/windoliver/agentenv/issues/1) for status.

Community drivers and reference blueprints live in a companion repo: [`windoliver/agentenv-community`](https://github.com/windoliver/agentenv-community).

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). This project is built agent-first — point your coding agent at the repo and let it use the skills in [`.agents/skills/`](.agents/skills/) (coming soon) to explore, prototype, and propose.

## License

MIT. See [`LICENSE`](LICENSE).
