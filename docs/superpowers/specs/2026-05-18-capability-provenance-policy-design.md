# Capability Provenance Policy Design

Date: 2026-05-18
Issue: [#43](https://github.com/windoliver/agentenv/issues/43)
Milestone: Hardening
Status: Approved for planning

## Summary

Implement the full issue #43 scope in one PR by extending the existing MCP tool-call guard into a provenance-aware capability reference monitor. The PR should add a structured provenance lattice, static tool capability declarations, policy evaluation over tainted argument values, approval integration for blocked-but-reviewable calls, and a Claude-oriented proof of concept that demonstrates the key containment invariant: untrusted content cannot reach write-capable operations such as `git.commit` without an operator-approved exception.

This is not a new pluggable axis. It is core-owned security infrastructure that sits beside the existing policy, approvals, events, MCP mediation, egress proxy, and agent-driver integration points.

## Affected Crates And Docs

- `crates/agentenv-proto`
- `crates/agentenv-policy`
- `crates/agentenv-core`
- `crates/agentenv-mcp`
- `crates/agentenv-approvals`
- `crates/agentenv-events`
- `crates/agentenv`
- `crates/drivers/agent-claude`
- `tests/driver-conformance`
- `docs/ARCHITECTURE.md`
- `docs/DRIVER_PROTOCOL.md`
- `docs/BLUEPRINTS.md`

## Context

The current repo already has the right enforcement path for the first useful version:

- `policy.mcp.confused_deputy_guards` in blueprints.
- `agentenv_mcp::guard` for MCP `tools/call` decisions.
- `agentenv mcp-guard run` for stdio MCP endpoint wrapping.
- Host egress proxy mediation for HTTP and HTTP+SSE MCP endpoints.
- Approval queue support for `mcp_tool`, `egress_host`, `zone_access`, and `package_install`.
- Rich activity events for MCP tool calls and approval decisions.

Issue #43 should build on that surface. The existing guard decides from tool names, argument shapes, URL allowlists, rate limits, and coarse read-to-write flow windows. The new work makes that guard evidence-based by attaching provenance to values and making tool capability policy explicit.

## Goals

1. Add a provenance tag model and graph that can represent trusted, tenant, and untrusted sources.
2. Add tool capability declarations that describe what a tool can do and the maximum taint accepted by its input arguments.
3. Evaluate MCP tool calls by walking argument provenance before execution.
4. Reuse the existing approvals queue for operator-reviewed exceptions.
5. Ship a Claude proof of concept that uses the mediated MCP path and demonstrates that untrusted GitHub issue or web/MCP content cannot flow into a write-capable tool call without approval.
6. Preserve graceful degradation through explicit blueprint requirements and driver/guard capability checks.

## Non-Goals

- No fifth pluggable axis.
- No second serialization format.
- No prompt-only security boundary.
- No full general-purpose program synthesis runtime beyond what is needed to demonstrate the planner/executor split.
- No credential flow through generic driver RPC.
- No broad rewrite of the existing MCP guard, egress proxy, or approvals queue.

## Prior Art

The design borrows the security invariant from CaMeL: trusted planning chooses control flow, while untrusted values can be filled in only where policy permits them. It borrows the enforcement shape from provenance-carrying agent systems: values carry source labels, derived values inherit taint from their inputs, and a reference monitor checks policy immediately before a capability-bearing action executes.

The implementation should remain pragmatic for this repo. The first PR proves the invariant at the tool boundary, where `agentenv` already has mediation, rather than trying to replace the upstream agent runtime.

## Provenance Model

### Tags

Add a small ordered lattice:

- `trusted`: operator instructions, signed blueprints, lockfiles after verification, self-authored agentenv code, and explicitly approved values.
- `tenant`: the user's own repository and files exposed through the filesystem context.
- `untrusted`: web fetches, open GitHub issues, generic remote MCP tool results, network responses, and any source whose trust level is unknown.

Ordering is:

```text
trusted < tenant < untrusted
```

The join of multiple input values is the maximum taint. Missing provenance fails closed to `untrusted` for write-capable tools and to `tenant` for read-only local operations only when the source is explicitly a local filesystem context.

### Graph

`agentenv-core` owns an env/session-scoped provenance graph. Each node records:

- stable node id
- tag
- source kind
- source summary safe for audit logs
- optional parent node ids
- created timestamp
- redacted value summary or digest

The graph must never persist raw secret-bearing values. Event and approval payloads carry summaries, taint, source kind, and node ids, not unredacted argument bodies.

### Propagation

Tool call arguments can reference prior outputs by value or by structured provenance references. The first implementation should support both:

- direct structured metadata carried through mediated MCP results when available
- fallback taint inference from recent guarded tool results when a client cannot preserve references explicitly

The explicit metadata path is preferred and should become the primary API. The fallback path exists for the Claude POC because upstream agent CLIs may not preserve arbitrary provenance metadata in their own reasoning state.

## Tool Capability Declarations

Add a serializable descriptor shape for tools exposed through MCP mediation:

```rust
pub struct ToolCapabilityDeclaration {
    pub tool_name: String,
    pub caps: Vec<ToolCapability>,
    pub max_input_taint: ProvenanceTag,
    pub argument_policies: Vec<ToolArgumentPolicy>,
    pub approval: CapabilityApprovalMode,
}
```

Initial capabilities:

- `read_fs`
- `write_fs`
- `exec`
- `git_read`
- `git_write`
- `network`
- `mcp_tool`
- `credential_broker`

Initial default policy:

- Read-only filesystem and git-read tools accept up to `tenant`.
- Display, summarize, and transform-only tools may accept `untrusted` when they have no write, exec, credential, or network side effects.
- Network fetch tools accept `trusted` or `tenant` URLs only unless a URL allowlist policy permits `untrusted`.
- Write, exec, git-write, and credential-bearing tools accept only `trusted` by default.
- Unknown tools with side effects are treated as write-capable and require `trusted` input or approval.
- Unknown tools without a side-effect declaration require approval when provenance is `tenant` or `untrusted`.

Capability declarations should live in the mediated tool descriptor layer, not in agent prompts. Context drivers may provide declarations later, but core must be able to synthesize conservative declarations for existing tools.

## Policy Evaluation

Extend `agentenv_mcp::guard` with a provenance-aware evaluator. The evaluator input is:

- current `McpGuardConfig`
- tool capability declaration
- JSON-RPC `tools/call` request
- current `GuardSessionState`
- provenance graph lookup

The evaluator output extends the current `GuardDecision` with:

- observed argument taint
- maximum allowed taint
- capability set
- source node ids
- redacted source summaries
- policy rule id or synthesized default label

Decision rules:

1. If the request is not a `tools/call`, forward it.
2. If the guard is disabled, forward it and emit a guard-disabled event.
3. If the tool has existing guard denials such as URL allowlist violation, credential-like argument, env-var-like argument, or rate limit violation, deny before provenance approval.
4. Compute argument taint from explicit provenance metadata, graph lookup, and fallback source inference.
5. If taint is at or below `max_input_taint`, forward and record an audit-safe provenance summary.
6. If taint exceeds `max_input_taint` and the declaration allows approval, create an approval request.
7. If taint exceeds `max_input_taint` and approval is not allowed, deny with a structured policy error.

Approvals can grant `once`, `session`, `persist-sandbox`, or `propose-for-baseline`, matching the current approval model. Persisted grants store policy evidence and matching criteria, not raw untrusted content.

## Blueprint Shape

Extend the existing `policy.mcp.confused_deputy_guards` block instead of adding another top-level policy namespace:

```yaml
policy:
  tier: restricted
  mcp:
    confused_deputy_guards:
      enabled: true
      provenance:
        enabled: true
        required: true
        default_unannotated_source: untrusted
      tool_capabilities:
        "filesystem.read":
          caps: [read_fs]
          max_input_taint: tenant
          approval: never
        "web.fetch":
          caps: [network]
          max_input_taint: tenant
          approval: per-call
        "git.commit":
          caps: [git_write]
          max_input_taint: trusted
          approval: per-call
```

`required: true` means environment creation fails if core cannot mediate the selected context endpoint or the selected agent cannot be configured through the mediated endpoint path. `required: false` means the guard degrades to current behavior and emits a warning event when provenance metadata cannot be enforced.

## Claude Proof Of Concept

Claude remains a normal built-in `AgentDriver`. The POC uses the existing mediation path:

- Core rewrites the context `McpEndpoint` before passing it to `agent-claude`.
- Stdio endpoints use `agentenv mcp-guard run`.
- HTTP and HTTP+SSE endpoints use the host egress proxy MCP route.
- The Claude driver renders its MCP config using the rewritten endpoint.

The POC fixture should include a write-capable synthetic tool named `git.commit` and an untrusted synthetic source such as a GitHub issue body. A malicious issue body that attempts to set a commit message or body must be blocked or routed to approval before the tool executes.

This demonstrates the dual-LLM pattern at the boundary agentenv controls:

- The planner-visible state is abstract: tool names, capabilities, source ids, and taint summaries.
- The executor-visible values are concrete but cannot alter which capability-bearing tool is being invoked.
- Core is the reference monitor and blocks concrete untrusted values from crossing into write-capable tool calls unless the selected plan and policy permit it.

The PR should not claim to implement a complete independent planner/executor runtime for Claude. It should document the boundary guarantee precisely and test it.

## Driver And Protocol Impact

This should be mostly additive to schema version `1.3` unless an existing RPC method signature must change. Additive changes:

- provenance tag schema
- tool capability declaration schema
- provenance summary schema for guard decisions and events
- optional provenance support flag in guard config or agent capabilities
- optional approval context fields

Do not require context drivers to change immediately. Core can synthesize conservative declarations for current context drivers and treat remote MCP results as `untrusted`.

If agent capabilities are extended, missing fields must default to `false` for compatibility. If a blueprint marks provenance policy as required and the selected agent cannot be routed through a mediated endpoint, create/preflight returns a capability error before sandbox creation.

## Events And Approvals

Add event context to MCP tool-call and approval events:

- `tool_name`
- `caps`
- `observed_taint`
- `max_input_taint`
- `source_node_ids`
- `source_summaries`
- `policy_rule`
- `decision`

Approval requests should use `ApprovalKind::McpTool` and include the same context. If future work needs a more precise kind, add it as an additive enum variant, but the first PR can reuse `mcp_tool`.

Audit logs must redact tool arguments using the existing redaction path. Provenance evidence should make decisions explainable without exposing raw prompt-injection content or credentials.

## Error Handling

Blocked tool calls return a JSON-RPC error to the agent with:

- stable error code
- short user-facing message
- structured machine-readable reason
- tool name
- observed taint
- maximum allowed taint
- policy rule id

The error must not include raw untrusted content. A typical message is:

```text
MCP tool call blocked by provenance policy: git.commit received untrusted input but allows only trusted input
```

Guard internals should distinguish:

- malformed request
- missing provenance
- taint exceeds threshold
- unsupported required mediation
- approval denied
- approval unavailable

## Testing Strategy

### Unit Tests

`agentenv-policy`:

- provenance lattice ordering
- taint joins
- missing-provenance defaults
- capability policy decisions
- approval versus hard-deny behavior

`agentenv-mcp`:

- explicit provenance metadata is read from tool results
- JSON argument paths map to provenance summaries
- untrusted to `git.commit` is blocked
- tenant to read-only tools is allowed
- session approval grants allow a repeated matching call
- persisted grants match only the approved policy evidence

### Proto And Schema Tests

`agentenv-proto`:

- provenance tags serialize as stable snake-case values
- capability declarations round trip through JSON and YAML
- optional capability fields default safely for older descriptors
- generated schemas include the new types

### Core Runtime Tests

`agentenv-core`:

- `create` rewrites Claude's context endpoint through mediation when provenance policy is enabled
- `required: true` fails before sandbox create when mediation is impossible
- guard config files include provenance policy and capability declarations
- approval context includes taint evidence and redacts raw arguments

### CLI And POC Tests

`agentenv`:

- `agentenv mcp-guard run` denies an untrusted `git.commit` fixture before the upstream tool receives it
- HTTP proxy MCP guard denies the same fixture
- approval-denied path returns a stable JSON-RPC error
- approval-allowed path forwards exactly once or for the session according to scope

`agent-claude`:

- rendered MCP config uses the mediated endpoint supplied by core
- provenance-required configs are accepted only when mediation is available

The full PR must pass:

```bash
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Implementation Boundaries

Keep the implementation incremental inside the single PR:

1. Add schema and policy primitives.
2. Extend the existing guard evaluator.
3. Wire core runtime config and endpoint rewrite paths.
4. Add approvals/events evidence.
5. Add the Claude POC fixture.
6. Update docs and reference blueprint comments.

Each step should be independently testable. The PR can contain multiple commits, but the final branch should ship the complete issue #43 scope.

## Risks And Trade-Offs

- Provenance through opaque model reasoning is not perfect. The POC guarantee is at the tool boundary, not inside Claude's private chain of thought or prompt state.
- Fallback taint inference is conservative and may create false positives. That is acceptable for hardening; trusted explicit provenance metadata can reduce friction later.
- Conservative synthesized tool declarations may require approvals for tools that are actually safe. The alternative is silent under-enforcement, which is worse for this security feature.
- Persisted approval grants must be narrowly matched. Broad grants can recreate the confused-deputy risk the feature is meant to contain.

## Acceptance Criteria

- The design, implementation, and tests land in one PR for issue #43.
- Provenance tags and tool capability declarations exist in typed Rust and exported schemas.
- MCP guard decisions use provenance taint and capability thresholds.
- Untrusted content from a synthetic GitHub issue or remote MCP result cannot reach `git.commit` without approval.
- Approval events include redacted provenance evidence.
- Claude uses the mediated MCP path for the POC.
- Existing blueprints still work when provenance policy is disabled.
- Required provenance policy fails closed when mediation cannot be enforced.

## References

- [Issue #43](https://github.com/windoliver/agentenv/issues/43)
- [Architecture](../../ARCHITECTURE.md)
- [Driver Protocol](../../DRIVER_PROTOCOL.md)
- [Blueprints](../../BLUEPRINTS.md)
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813)
- [Provenance-Carrying Agent Systems / FORGE](https://arxiv.org/abs/2602.16708)
