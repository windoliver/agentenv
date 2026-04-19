# Built-in Agent Drivers Design

Date: 2026-04-18
Issue: [#8](https://github.com/windoliver/agentenv/issues/8)
Milestone: M2-2
Status: Approved for planning

## Summary

Implement the built-in `AgentDriver` surface for Claude, Codex, and OpenClaw with a shared `agentenv-core::agent_common` layer and thin per-agent crates. Keep the user-facing scope from issue `#8` intact, including config rendering, credential declaration, entrypoint generation, and health-check coverage, but make two explicit protocol changes where the current `v0.1` draft is not expressive enough:

1. `credential_requirements` becomes `AgentSpec`-aware so OpenClaw can require the correct provider key.
2. Agent health checking becomes declarative and core-executed, so drivers describe the probe and the core runs it inside the sandbox through the sandbox driver.

This keeps the architecture aligned with the repo's narrow-waist design: drivers stay declarative about agent-specific behavior, and the core remains responsible for orchestration across the four axes.

## Context And Constraints

- `docs/ARCHITECTURE.md` defines agent drivers as responsible for install fragments, MCP config path and format, entrypoint rendering, credential requirements, and in-sandbox health checking.
- `docs/DRIVER_PROTOCOL.md` and `crates/agentenv-proto` currently expose a static `credential_requirements({})` method and an agent-owned `health_check({handle})` method.
- `crates/drivers/agent-claude`, `agent-codex`, and `agent-openclaw` are still scaffolds, so the design can establish a consistent shape before behavior hardens.
- `AGENTS.md` requires that method-signature changes be treated as schema-version bumps.
- The referenced blueprints already assume `claude`, `codex`, and `openclaw` are first-class built-in agents.

## Affected Crates And Docs

- `crates/agentenv-core`
- `crates/agentenv-proto`
- `crates/drivers/agent-claude`
- `crates/drivers/agent-codex`
- `crates/drivers/agent-openclaw`
- `tests/driver-conformance`
- `docs/DRIVER_PROTOCOL.md`
- `blueprints/openclaw+nexus+openshell.yaml`

## Goals

- Implement the built-in drivers for Claude, Codex, and OpenClaw with a shared internal shape.
- Keep agent-specific differences isolated to the per-agent crates.
- Preserve the full issue scope, including provider-sensitive OpenClaw credential behavior.
- Define a testing strategy that works now and becomes end-to-end once `sandbox-openshell` can create and execute inside a sandbox.

## Non-Goals

- General blueprint-schema redesign beyond what is required for agent-driver config parsing.
- New agent types beyond Claude, Codex, and OpenClaw.
- Sandbox runtime implementation in this issue.
- New shortcuts that bypass the `AgentDriver` trait or JSON-RPC protocol surface.

## Design

### 1. Shared Architecture

Add `agentenv-core::agent_common` as the reusable layer for built-in agent drivers. It owns:

- default `AgentCapabilities`
- MCP config rendering helpers for each upstream agent's documented MCP config shape
- helpers for install-step rendering
- helpers for credential requirement construction
- helpers for declarative version probes
- shared validation and error formatting utilities

Each per-agent crate stays thin and declarative. It defines a descriptor-like static configuration covering:

- binary name
- package install command
- MCP config path
- supported entrypoint forms
- credential policy
- any serializer override if the agent needs a slightly different MCP config wrapper

This split keeps the common logic in one place without introducing a fifth pluggable axis. The `AgentDriver` trait remains the only contract consumed by the rest of the system.

### 2. Typed Agent Configs

`agentenv-proto::AgentSpec` remains the transport shape, but built-in drivers must stop treating `AgentSpec.config` as an unstructured bag. Each built-in driver deserializes `config` into a typed local config and rejects unknown or contradictory keys with actionable errors.

Common config:

- `mode = "tui" | "headless"`
- default: `tui`

OpenClaw-specific config:

- `provider = "openai" | "anthropic"` optional
- `model` optional

Resolution rules:

1. Explicit `provider` wins.
2. If `provider` is absent and `model` is prefixed with `openai/` or `anthropic/`, infer the provider from the prefix.
3. If both are absent, default to `openai` for the first cut so the current reference blueprint remains valid.
4. If `provider` conflicts with an inferable `model` prefix, fail validation.

Although the first-cut default remains `openai`, the reference OpenClaw blueprint should be updated to set `provider` explicitly for clarity.

### 3. Per-Agent Behavior

Claude:

- binary: `claude`
- MCP config path: `~/.claude/agentenv-mcp.json`, loaded with `claude --mcp-config`
- credential: `ANTHROPIC_API_KEY`
- capabilities: `supports_mcp`, `supports_slash_commands`, `supports_tui`, `supports_headless`

Codex:

- binary: `codex`
- MCP config path: `~/.codex/config.toml`, using Codex `[mcp_servers.*]` TOML tables
- credential: `OPENAI_API_KEY`
- capabilities: same as Claude

OpenClaw:

- binary: `openclaw`
- MCP config path: `~/.openclaw/openclaw.json`, using OpenClaw's `mcp.servers` config shape
- credentials: exactly one of `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`, resolved from the typed config
- capabilities: same as Claude

The OpenClaw MCP path matches the requirement written in issue `#8`. The per-agent descriptor should own that path so any future upstream correction remains isolated to one crate.

### 4. Entrypoint Model

Entrypoints stay agent-owned and spec-aware through `render_entrypoint(spec)`.

Behavioral contract:

- `mode = "tui"` renders the normal interactive entrypoint.
- `mode = "headless"` renders the non-TUI entrypoint for the requested agent version.
- If a requested mode is not supported by the installed upstream CLI, `preflight` must fail with a clear remediation message instead of silently degrading.

This matters most for Codex and OpenClaw because upstream CLI details may evolve independently of `agentenv`. The driver should therefore encode the current best-known command form in one place and make unsupported mode requests fail fast.

### 5. Protocol Changes

Issue `#8` needs one intentional schema-version bump from `0.1` to `0.2` because the current `v0.1` draft cannot express the accepted behavior cleanly.

#### 5.1 `credential_requirements` becomes spec-aware

Change the agent-driver method from a static call to a spec-aware call:

- from: `credential_requirements({})`
- to: `credential_requirements(AgentSpec)`

Rationale:

- Claude and Codex still return fixed results.
- OpenClaw can now declare exactly one provider key instead of over-requesting both secrets or hiding state outside the method surface.

#### 5.2 Replace agent-owned `health_check(handle)` with a declarative probe

Remove agent-owned sandbox execution from the agent driver contract and replace it with a declarative method:

- `health_check_probe(AgentSpec) -> AgentHealthCheckProbe`

Recommended `AgentHealthCheckProbe` fields:

- `cmd: String`
- `tty: bool`
- `env: BTreeMap<String, String>`
- `success_exit_codes: Vec<i32>`

Execution model:

1. The agent driver declares the probe, typically a version command.
2. The core executes that probe inside the sandbox via `SandboxDriver::exec`.
3. The core translates the exec result into the final health outcome surfaced to users.

This keeps built-in and future subprocess drivers on the same contract. It avoids a built-in-only shortcut where Rust drivers could reach into sandbox internals that external drivers cannot access.

### 6. Failure Handling

Fail early and specifically for:

- invalid or unknown config keys
- contradictory OpenClaw `provider` and `model`
- missing required credentials
- requested `headless` mode not supported by the installed upstream CLI
- missing binary after install
- probe command execution failure

Credential errors must name the required variable without ever exposing its value. Probe failures should distinguish:

- binary missing
- binary present but not executable
- probe command returned a non-success status

### 7. Testing Strategy

Use three layers of coverage.

#### 7.1 Protocol conformance

Each agent driver must pass the shared conformance suite from `tests/driver-conformance`, covering:

- `initialize`
- `preflight`
- unknown method handling
- `shutdown`
- schema-version mismatch

#### 7.2 Unit and golden tests

Each driver crate should test:

- typed config parsing
- OpenClaw provider resolution
- credential requirement selection
- install-step rendering
- MCP config rendering
- entrypoint rendering
- probe declaration rendering

Golden-style tests are appropriate for rendered JSON config and entrypoint shell content so behavior stays readable during review.

#### 7.3 Gated integration tests

Add real OpenShell-backed integration tests that are written now but gated on the availability of working `sandbox-openshell create + exec` support.

Those tests should verify:

- the install step produces a runnable agent binary in a fresh sandbox
- the MCP config is materialized at the expected path
- the declared health-check probe succeeds inside that sandbox

This preserves the full acceptance criteria from issue `#8` without falsely coupling progress on the agent drivers to the unfinished sandbox runtime.

### 8. Blueprint And Documentation Updates

Update the OpenClaw reference blueprint to set `agent.config.provider` explicitly. Document the new config contract and protocol bump in:

- `docs/DRIVER_PROTOCOL.md`
- `agentenv-proto` JSON schemas
- per-agent README files
- `tests/driver-conformance`, so the shared suite validates the `0.2` contract rather than the old `0.1` method surface

The protocol update should call out that changing the method signature is a `0.2` schema-version bump rather than a compatible extension.

## Trade-Offs

Benefits:

- OpenClaw's provider-sensitive behavior becomes explicit and testable.
- Shared logic stays centralized without making the crates opaque.
- Health checking remains portable across built-in and subprocess drivers.
- Runtime-backed tests can be prepared immediately and activated once M2-1 lands.

Costs:

- `agentenv-proto` and `docs/DRIVER_PROTOCOL.md` must change during an issue that is nominally about concrete drivers.
- The health-check change moves one responsibility from agent drivers into core orchestration.
- Implementers must keep per-agent upstream CLI details current over time.

## References

- [Issue #8](https://github.com/windoliver/agentenv/issues/8)
- [Architecture](../../ARCHITECTURE.md)
- [Driver Protocol](../../DRIVER_PROTOCOL.md)
- [Roadmap](../../ROADMAP.md)
- [NVIDIA/NemoClaw](https://github.com/NVIDIA/NemoClaw)
- [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes)
- [derailed/k9s](https://github.com/derailed/k9s)
