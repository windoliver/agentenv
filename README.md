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

### 1. Install `agentenv`

```bash
curl -LsSf https://raw.githubusercontent.com/windoliver/agentenv/main/install.sh | sh
```

Pinned version:

```bash
curl -LsSf https://raw.githubusercontent.com/windoliver/agentenv/main/install.sh | AGENTENV_VERSION=v0.1.0 sh
```

Binary-only, non-interactive install:

```bash
curl -LsSf https://raw.githubusercontent.com/windoliver/agentenv/main/install.sh | sh -s -- --binary-only --non-interactive
```

The installer resolves a GitHub release for the current OS/arch, verifies the downloaded tarball against a published SHA256 file before install, installs into `~/.agentenv/bin` by default, and can update shell startup files so a fresh login shell can find `agentenv`.

External Python drivers are wired behind `--with-python-drivers`, but they require published driver bundles or an explicit `AGENTENV_PYTHON_DRIVERS_INDEX_URL`. Until those bundles exist, the installer skips them with a warning instead of failing a binary install.

Or with Cargo:

```bash
cargo install agentenv
```

### 2. Write `agentenv.yaml`

This example creates a real OpenShell sandbox, installs Codex inside it, mounts a local project through the filesystem context driver, and passes `OPENAI_API_KEY` from your host environment.

```yaml
version: 0.1.0

sandbox:
  driver: openshell

agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true

context:
  driver: filesystem
  mount: ~/projects/myapp

inference:
  driver: passthrough

policy:
  tier: balanced
```

### 3. Create, enter, inspect, clean up

```bash
export OPENAI_API_KEY=sk-...

agentenv create myapp
agentenv enter myapp
```

Useful lifecycle commands:

```bash
agentenv status myapp
agentenv exec myapp -- printf "hello from sandbox\n"
agentenv logs myapp
agentenv logs myapp --follow
agentenv describe myapp --json
agentenv list
agentenv freeze myapp --blueprint agentenv.yaml --out agentenv.lock
agentenv reproduce agentenv.lock
agentenv destroy myapp --yes
```

If you do not want to keep secrets in shell history, store them once:

```bash
agentenv credentials set OPENAI_API_KEY
agentenv credentials where OPENAI_API_KEY
```

`agentenv create` also prompts for missing required credentials in interactive mode.

### What `agentenv create` sets up for you

For the built-in OpenShell path, the CLI is meant to work without a manual driver setup step:

- Finds host tools in common locations, including `~/.local/bin`, `~/.orbstack/bin`, Homebrew, and Docker Desktop paths.
- Installs the OpenShell CLI into `~/.local/bin` automatically if `openshell` is missing.
- Starts OrbStack or Docker Desktop if the app is installed but the Docker API is not ready.
- Installs the selected agent command inside the sandbox when needed.
- Renders the MCP config and agent entrypoint so `agentenv enter myapp` opens the configured agent environment.
- Applies the declared policy during sandbox creation and wires inference routing after create.

If neither OrbStack nor Docker Desktop is installed, `agentenv create` stops with `container_runtime_missing`. Install one local container runtime once, then rerun the same command. After that, `agentenv` detects and starts it automatically.

### Common fixes

| Symptom | Fix |
|---------|-----|
| `openshell_bootstrap_failed` | Check host network access to GitHub plus `curl` and `sh`, then rerun `agentenv create`. |
| `container_runtime_missing` | Install OrbStack or Docker Desktop once. |
| `container_runtime_unavailable` | Open OrbStack or Docker Desktop and wait until Docker is running, then rerun `agentenv create`. |
| `missing credential OPENAI_API_KEY` | Export it, run `agentenv credentials set OPENAI_API_KEY`, or omit `--non-interactive` and let create prompt. |

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
