# agentenv — Architecture

> **Goal.** A declarative environment manager for AI coding agents. Every axis — sandbox runtime, agent, context backend, inference provider — is pluggable. One `agentenv.yaml` defines a composition; `agentenv create` materializes it; `agentenv freeze` / `reproduce` makes it portable.

## Table of contents

1. [Design principles](#design-principles)
2. [The four pluggable axes](#the-four-pluggable-axes)
3. [Skills as a core-managed resource](#skills-as-a-core-managed-resource)
4. [The narrow waist: MCP](#the-narrow-waist-mcp)
5. [Driver architecture](#driver-architecture)
6. [Blueprint lifecycle](#blueprint-lifecycle)
7. [Policy model](#policy-model)
8. [Credential store](#credential-store)
9. [Sessions vs. sandboxes](#sessions-vs-sandboxes)
10. [Observability & approvals](#observability--approvals)
11. [Crate layout](#crate-layout)
12. [Prior art & what we borrowed](#prior-art--what-we-borrowed)

---

## Design principles

1. **Env manager, not orchestrator.** We compose and materialize environments. We don't schedule workloads across a pool. Closest mental models: `conda env`, `pixi`, `devbox`, `nix-shell`, `docker compose`.

2. **Declarative > imperative.** The `agentenv.yaml` is the artifact users commit. `agentenv create` is a function of that file + driver versions. Re-running on another machine yields the same environment.

3. **Narrow waist.** Everything hourglass-shaped — one protocol (MCP) between agents and context, one driver protocol (JSON-RPC 2.0) between core and drivers. New drivers, new agents, new context backends plug in without touching the waist.

4. **Capability handshake, graceful degradation.** Every driver declares what it supports at startup. The core composes what's possible and surfaces what isn't. If a sandbox driver can't hot-reload policy, policy updates trigger a restart and warn — not an error.

5. **Single static binary.** Install via `curl | sh`, run anywhere, no runtime dependencies. Rust lets us do this.

6. **Polyglot extensibility without ABI pain.** Built-in drivers are Rust trait impls; external drivers are subprocess JSON-RPC peers. Third-party drivers can be written in Python, Go, TypeScript — anything that can speak JSON over stdio.

7. **Safety in depth.** Credentials never live in driver memory; they flow through a central credstore and are injected at sandbox-create time. Outbound URLs pass through SSRF validation. Blueprints are digest-verified before execution.

8. **Security is the sandbox's job, not the agent's.** We delegate kernel-level isolation (namespaces, seccomp, Landlock) to the sandbox driver. We own policy declaration, translation, and approval flow.

---

## The four pluggable axes

```text
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Sandbox  │  │  Agent   │  │ Context  │  │Inference │
│  driver  │  │  driver  │  │  driver  │  │  driver  │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │            │            │            │
     └────────────┴────────────┴────────────┘
                  composes into
                       ▼
              ┌─────────────────┐
              │      an env     │
              └─────────────────┘
```

### `SandboxDriver` — how do we create and run an isolated environment?

Concrete: OpenShell (first-class), microVM/Firecracker on Linux/KVM and Apple Container on macOS (first-class hardening path), Docker (post-MVP), E2B (post-MVP).

Responsibilities:
- Preflight checks (runtime installed, versions compatible)
- `create` / `connect` / `exec` / `copy_in/out` / `status` / `stop` / `destroy`
- Optionally `snapshot` a running sandbox and `fork_from_snapshot` into a new env
- Translate a generic `NetworkPolicy` into its native policy format
- Apply, update, and optionally hot-reload policy
- Surface egress denials into the approvals queue

Capability flags: `supports_hot_reload_policy`, `supports_filesystem_lockdown`, `supports_syscall_filter`, `supports_native_inference_routing`, `supports_remote_host`, `supports_persistent_sessions`, `supports_snapshots`, `supports_fork`.

### `AgentDriver` — what runs inside the sandbox?

Concrete: Claude Code, Codex, OpenClaw (built-in Rust impls); Hermes (subprocess Python driver).

Responsibilities:
- Dockerfile fragments to install the agent in the sandbox base image
- Path + format of the agent's MCP configuration
- Entrypoint script to start the agent
- Credential requirements (API keys, tokens, etc.) declared to the credstore
- In-sandbox health check

Capability flags: `supports_mcp`, `supports_slash_commands`, `supports_tui`, `supports_headless`.

### `ContextDriver` — what knowledge backend the agent talks to?

Concrete: Nexus (subprocess Python driver), generic MCP server, filesystem-only, none. Post-MVP: ChromaDB, Qdrant, LangChain.

Responsibilities:
- Provision the backend (for Nexus hub mode, this may be a no-op pointing at an existing instance; for filesystem-only, it mounts a directory and wraps it as MCP)
- Expose an `MCPEndpoint` the agent can call
- Declare required network rules (e.g., "reach `nexus.company.com:443`")
- Declare credential requirements

Capability flags: `is_remote`, `is_shared`, `supports_zones`, `supports_snapshots`.

### `InferenceDriver` — how model API calls are routed?

Concrete: `passthrough` (agent uses its own API key directly), `openai` / `anthropic` / `ollama` (routed via an in-sandbox `inference.local` endpoint, credentials stay on host).

Optional. When the sandbox driver declares `supports_native_inference_routing = true` (e.g., OpenShell's Privacy Router), we delegate. Otherwise we run an in-sandbox inference proxy process.

Capability flags: `strips_caller_credentials`, `supports_model_switching`.

---

## Skills as a core-managed resource

**Decision.** Skills are a core-managed resource, not a `ContextDriver`
sub-kind and not a fifth pluggable axis.

A skill packages agent behavior: instructions, procedures, metadata, and
support files. Unlike a context backend, a skill does not provision a live MCP
endpoint, own runtime handles, or report health. `agentenv` therefore treats
skills like static artifacts referenced by blueprints, resolved before sandbox
creation, cached under `~/.agentenv/skills/`, verified, and injected into the
sandbox or agent configuration during `create`.

Core owns the skill lifecycle:

- Resolve blueprint skill references or CLI handles to exact artifact versions.
- Fetch from trusted sources such as local paths, HTTP, OCI, or git through
  lightweight registry adapters.
- Verify digests, signatures, versions, and revocation policy before injection.
- Cache immutable artifacts and record exact pins in `agentenv.lock`.
- Expose only the selected skill bundle to the sandbox; credential values do
  not flow through skill fetching or generic driver RPC.

Registry adapters are not JSON-RPC drivers. They are core-managed fetch and
verify backends, analogous to package registries in Cargo, npm, and pip. If a
registry adapter needs network access, its URLs pass through the SSRF validator
and its output becomes an artifact pin in the lockfile.

At runtime, agents discover skills through the conventions their `AgentDriver`
supports. Agent drivers may render config or install steps that point the agent
at injected skill directories, but they do not resolve trust, fetch artifacts,
or verify signatures themselves. `ContextDriver` remains the MCP
knowledge-backend axis.

---

## The narrow waist: MCP

Every `ContextDriver` produces an `MCPEndpoint`. Every `AgentDriver` consumes one. Neither side knows what the other is. This is *the* architectural decision that keeps combinations from exploding — and it's the same reason RFB kept VNC alive for three decades.

```text
Agent (inside sandbox)  ──── MCP ────▶  Context driver endpoint
                         narrow waist
```

### Transport adapters

MCP runs over several transports; drivers shouldn't know or care. We abstract them:

```text
┌───────────────────────────┐
│ agent inside sandbox      │  speaks MCP
└──────────────┬────────────┘
               │
   ┌───────────▼───────────┐
   │   MCPTransport layer  │
   ├───────────────────────┤
   │ stdio                 │  in-sandbox process
   │ http                  │  in-sandbox HTTP server / local hub
   │ http+sse              │  streaming contexts
   │ ssh+http              │  remote sandbox ↔ host context
   └───────────────────────┘
```

This is the same pattern VNC uses (RFB over TCP / TLS / SSH / WebSocket). Transport is orthogonal to content.

---

## Driver architecture

### Two classes of driver, one contract

```text
┌──────────────────────────────────────────────────────────┐
│                agentenv core (Rust, one binary)          │
│                                                          │
│  ┌───────────────┐    ┌───────────────────────────────┐  │
│  │ Built-in      │    │ Subprocess plugin host        │  │
│  │ drivers       │    │                               │  │
│  │               │    │ Spawns process ──► stdio      │  │
│  │ Rust trait    │    │ JSON-RPC 2.0 with LSP framing │  │
│  │ impls, zero   │    │ (Content-Length: N\r\n\r\n)   │  │
│  │ overhead      │    │                               │  │
│  └───────┬───────┘    └───────────────┬───────────────┘  │
│          │                            │                  │
│          └────────────┬───────────────┘                  │
│                       │                                  │
│                       ▼                                  │
│            one shared `Driver` contract                  │
│            (trait methods == RPC methods)                │
└──────────────────────────────────────────────────────────┘
```

- **Built-in drivers** are Rust structs implementing the `SandboxDriver` / `AgentDriver` / `ContextDriver` / `InferenceDriver` traits. Linked into the main binary. No spawn overhead. Used for first-party drivers we want to ship and guarantee.
- **Subprocess drivers** are any-language executables that speak JSON-RPC 2.0 over stdio. Discovered at startup by scanning `~/.agentenv/drivers/*/manifest.json`. Used for polyglot third-party drivers, including Python drivers for Nexus and Hermes that ship with us.

The trait methods and the JSON-RPC methods are **identical in name and signature** — defined once in `agentenv-proto` as serde types with auto-generated JSON Schema. There is one mental model, two execution paths.

### Why subprocess (and not WASM / dylib / PATH subcommands)?

| Approach | Why not |
|---|---|
| Dynamic libraries (`cdylib`) | Rust has no stable ABI; same-compiler-only; kills third-party extensibility. |
| WASM components | Driver code needs to spawn processes, touch the filesystem, hit the network — every one of these is a new host-API binding to negotiate. High friction for our use case. |
| External binaries on PATH (cargo/kubectl-style) | No lifecycle, no capability handshake, no structured state. Too loose. |
| **Subprocess + JSON-RPC** | **Zero ABI friction, polyglot, fault-isolated, structured, proven.** Used by LSP, DAP, MCP, Nushell plugins, tree-sitter, containerd runtime shims. |

### Protocol sketch

See [`DRIVER_PROTOCOL.md`](DRIVER_PROTOCOL.md) for the full spec. Shape:

```text
→ initialize      {schema_version, core_version}
← initialize/result {driver: {name, version, kind, capabilities}}

→ preflight       {}
← preflight/result {ok: bool, issues: [...]}

→ create          {spec: {...}}
← create/result   {handle: "sb-01HXY..."}

→ status          {handle}
← status/result   {phase, healthy, last_ping}

→ apply_policy    {handle, policy: NetworkPolicy}
← apply_policy/result {hot_reloaded: bool}

→ destroy         {handle}
← destroy/result  {ok}

▷ event           {kind: "egress_denied" | "log" | "approval_requested", ...}
```

Notifications (`▷`) are push-only from driver to core.

---

## Blueprint lifecycle

```text
┌─────────┐   ┌────────┐   ┌──────┐   ┌───────┐   ┌────────┐
│ resolve │──▶│ verify │──▶│ plan │──▶│ apply │──▶│ status │
└─────────┘   └────────┘   └──────┘   └───────┘   └────────┘
```

1. **resolve** — parse `agentenv.yaml`, check `min_agentenv_version`, look up each driver by name in the registry (built-in or subprocess), pin versions, and resolve skill handles to exact artifact refs.
2. **verify** — check digest pins (drivers, images, skills, blueprints referenced by URL), validate `agentenv.lock` if present, and reject untrusted or revoked skill artifacts.
3. **plan** — ask each driver to describe what it will create/update, include core-owned skill fetch/cache/injection actions, print a human-readable plan, and fail fast on capability mismatches.
4. **apply** — execute the plan. Core fetches and injects verified skill artifacts; each driver produces resources and declares ownership.
5. **status** — report current state; streamed into `agentenv describe`.

`freeze` writes `agentenv.lock` with exact driver versions, image digests, skill artifact pins, and blueprint hash. `reproduce` rebuilds from a lockfile on any machine.

---

## Policy model

One generic `NetworkPolicy` model in core, driver-specific translators in `agentenv-policy/translators/`.

```text
user-facing                    core model                 sandbox-native

┌─────────────────┐         ┌──────────────┐         ┌─────────────────┐
│ tier: balanced  │         │NetworkPolicy │         │ OpenShell YAML  │
│ presets:        │  →→→→   │  allow[]     │  →→→→   │   (via openshell│
│   - github_read │         │  deny[]      │         │    policy set)  │
│   - npm_read    │         │  approval[]  │         │                 │
│ overrides: ...  │         │              │         │ or Docker       │
└─────────────────┘         └──────────────┘         │   iptables+     │
                                                     │   seccomp       │
                                                     └─────────────────┘
```

Four policy domains, each with hot-reload semantics (borrowed from OpenShell):

| Domain | Hot-reloadable? |
|---|---|
| Filesystem | No — locked at create |
| Process / syscalls | No — locked at create |
| Network | Yes — via driver `apply_policy` |
| Inference routing | Yes — via driver `apply_policy` |

Tiers + presets (borrowed from NemoClaw):

| Tier | Default posture |
|---|---|
| `restricted` | Only the context backend and inference |
| `balanced` (default) | Dev tooling (pkg registries, github read), no messaging |
| `open` | Broad access; use only for research/exploration envs |

Presets can be added at create or runtime via `agentenv policy-add <preset>`, subject to the sandbox driver's hot-reload capability.

---

## Credential store

Drivers **never** touch credentials directly. They declare requirements; the core credstore owns the lifecycle:

1. At `create` time, core reads the blueprint's credential spec and asks each driver for credential requirements. Agent drivers receive the `AgentSpec` so requirements can depend on typed agent config; context and inference drivers use empty params.
2. Core resolves each requirement from: OS keyring (preferred), `~/.agentenv/credentials.json` (fallback), or env var (explicit, one-shot).
3. Core injects credentials into the sandbox driver's `create` call as env vars — the sandbox driver passes them to the container runtime, which injects at process-start time.
4. Credentials never appear on disk inside the sandbox filesystem.

Sensitive flows:
- `agentenv credentials list` shows names, not values.
- `agentenv credentials reset <name>` removes a stored credential; next `create` re-prompts.
- `agentenv freeze` **strips credential values** from the lockfile (preserves references only).

This is the same pattern OpenShell Providers use, applied consistently across all driver kinds.

---

## Sessions vs. sandboxes

A **sandbox** is the long-lived resource (container / VM / E2B box). A **session** is a live attach to a running sandbox (shell + agent TUI + log stream). Sessions can detach and reattach; the sandbox keeps running.

```text
agentenv create myapp          # creates a sandbox
agentenv enter myapp           # creates a foreground session
agentenv enter myapp --detach  # creates a detached session
agentenv enter myapp --new     # creates an additional session
agentenv resume myapp          # reattaches the default detached session
agentenv sessions list myapp   # shows session status
agentenv sessions kill 01HXY   # kills one session only
```

This matters for agents running long tasks: closing your laptop doesn't kill the agent.

---

## Observability & approvals

### Activity event stream

Every core operation emits a structured event (append-only JSONL). Sinks: SQLite (default), OTEL export, file, webhook. Used by:

- `agentenv logs --follow` — streaming view
- `agentenv term` — ratatui-based operator TUI (k9s/openshell-term style)
- `/metrics` — Prometheus-compatible
- `agentenv audit export` — tamper-evident hash-chained log for compliance

### Approvals

When a driver blocks something (unlisted egress, unknown MCP tool, new zone access), it emits an approval request. The core routes to:

- `agentenv approvals` TUI — one-key approve/deny on the host
- Web dashboard — remote review
- Webhook / Slack — async approvals
- CLI non-interactive — `agentenv approvals approve <req-id>`

Decisions scope to `once` / `session` / `persist-sandbox` / `propose-for-baseline`.

---

## Crate layout

```text
agentenv/
├── Cargo.toml                  # workspace
├── crates/
│   ├── agentenv/               # bin — main CLI (clap)
│   ├── agentenv-core/          # lib — blueprint, sessions, registry, traits
│   ├── agentenv-proto/         # serde types + JSON Schema for driver RPC
│   ├── agentenv-policy/        # NetworkPolicy model + translators
│   ├── agentenv-credstore/     # OS keyring + JSON fallback + injection
│   ├── agentenv-approvals/     # queue + TUI client + webhooks
│   ├── agentenv-events/        # activity stream + audit + /metrics
│   ├── agentenv-mcp/           # MCP client + transport adapters
│   ├── agentenv-plugin/        # subprocess driver host
│   ├── drivers/
│   │   ├── sandbox-openshell/  # built-in, first-class
│   │   ├── sandbox-microvm/    # built-in, Firecracker + Apple Container
│   │   ├── sandbox-docker/     # built-in, post-MVP
│   │   ├── agent-claude/       # built-in
│   │   ├── agent-codex/        # built-in
│   │   ├── agent-openclaw/     # built-in
│   │   ├── context-mcp-generic/# built-in
│   │   ├── context-filesystem/ # built-in
│   │   ├── context-none/       # built-in
│   │   ├── inference-openai/   # built-in
│   │   ├── inference-anthropic/# built-in
│   │   ├── inference-ollama/   # built-in
│   │   └── inference-passthrough/ # built-in
│   └── tui/                    # agentenv term
├── external-drivers/           # shipped with us, installed to ~/.agentenv/drivers/
│   ├── context-nexus-py/       # Python, JSON-RPC subprocess
│   └── agent-hermes-py/        # Python, JSON-RPC subprocess
├── blueprints/                 # reference agentenv.yaml files
├── install.sh / uninstall.sh
└── docs/
```

---

## Prior art & what we borrowed

| Source | What we borrowed |
|---|---|
| **NVIDIA NemoClaw** | Blueprint lifecycle (resolve→verify→plan→apply→status); digest verification; policy tier + preset model; `--from Dockerfile` BYO; credential stripping on snapshot/freeze. |
| **NVIDIA OpenShell** | Four-component control plane as a concept (gateway, sandbox, policy engine, privacy router); four policy domains with hot-reload semantics; Provider pattern for credentials; declarative YAML policy; `openshell term` TUI inspiration. |
| **VNC / RFB** | The narrow-waist protocol idea (RFB ↔ MCP); capability negotiation at handshake; transport-adapter pattern (TCP/TLS/SSH/WS ↔ stdio/HTTP/SSE/ssh+http); asymmetric direction (server produces, client consumes ↔ context produces, agent consumes); extensions as opt-in, not core. |
| **LSP / Nushell plugins** | JSON-RPC 2.0 framing over stdio; built-in + external-subprocess peer pattern; initialize-response capability declaration. |
| **conda / pixi / devbox / nix-shell** | Env-manager CLI shape (`create` / `enter` / `list` / `destroy` / `freeze` / `reproduce`); lockfiles for reproducibility; committed config at project root. |
| **docker-compose** | `compose.yaml`-style single-file declaration; `up` / `down` commands; service composition as the primary abstraction. |
| **uv / ruff / mise** | Rust single-binary distribution story; `curl \| sh` installer; fast cold-start expectation for CLI tools. |
| **Anthropic Skills / agent-skills discovery** | Skill bundle shape, progressive disclosure, and discovery vocabulary; `agentenv` treats skills as core-managed artifacts rather than drivers. |

---

## Non-goals

- We don't run the context backend. Nexus, Chroma, etc. run themselves. We connect to them.
- We don't train or host models. The inference driver is a thin router.
- We don't orchestrate fleets. One user, many envs. Multi-user enterprise deployment is a separate concern (a hub mode for the *context* backend — which is exactly what Nexus does).
- We don't reinvent sandboxing. OpenShell / E2B / Docker own kernel-level isolation. We orchestrate policy and composition.
