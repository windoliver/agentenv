# H-6 Design: MCP Confused-Deputy Tool-Call Guards

Date: 2026-05-15
Issue: [#42](https://github.com/windoliver/agentenv/issues/42)
Label: hardening

## Summary

Issue #42 adds a core-owned mediation layer between agents and MCP context
servers so prompt-injected tool calls cannot silently use ambient MCP authority.
The full-scope implementation covers both URL-based MCP transports and stdio MCP
servers:

- HTTP and HTTP+SSE MCP endpoints are mediated in the existing host egress proxy.
- Stdio MCP endpoints are mediated by an `agentenv mcp-guard run` wrapper that
  spawns the original command and relays JSON-RPC frames.

The guard evaluates MCP tool calls, emits redacted audit events, enforces
per-tool policy, blocks credential-looking arguments from logs, flags
credential-looking values in tool arguments, and routes approval-required calls
through the existing approvals queue.

The GitHub app available in this workspace could not post the required issue
approach comment because GitHub returned `403 Resource not accessible by
integration`. Before implementation starts, a maintainer must either post the
approach from this spec on issue #42 or explicitly accept this spec as the
approach record.

## Affected Crates And Docs

- `crates/agentenv-core`
- `crates/agentenv-mcp`
- `crates/agentenv`
- `crates/agentenv-events`
- `crates/agentenv-approvals`
- `docs/ARCHITECTURE.md`
- `docs/DRIVER_PROTOCOL.md`
- `docs/BLUEPRINTS.md`
- reference blueprints that should demonstrate MCP guard configuration

No driver protocol schema bump is expected. Context drivers still return
`McpEndpoint`; agent drivers still consume `McpEndpoint`; runtime rewrites the
endpoint passed between them.

## Goals

1. Mediate all agent-visible MCP tool calls before they reach a context server.
2. Preserve MCP as the agent-to-context narrow waist.
3. Preserve JSON-RPC as the core-to-driver narrow waist.
4. Support exact and wildcard per-tool policy.
5. Support approval modes `never`, `per-call`, and `per-session`.
6. Redact credential-like values from logged tool arguments.
7. Detect environment-variable-looking and credential-looking argument values.
8. Enforce URL allowlists for URL-looking arguments.
9. Emit redacted `mcp_tool_call` activity events for allowed, denied, and
   approval-pending calls.
10. Reuse the existing approvals queue for blocked MCP calls.
11. Track session-local read-to-write flows and require approval when a recent
    read-like tool call is followed by a write-like or external tool call.

## Non-Goals

- Inferring arbitrary model-turn taint outside the guarded MCP session.
- Adding a new driver kind or fifth pluggable axis.
- Changing MCP server implementations.
- Changing the driver protocol method signatures.
- Supporting non-MCP HTTP traffic in the MCP guard.
- Guaranteeing semantic classification of every third-party tool name. The first
  implementation uses explicit policy plus conservative name-based read/write
  classification.

## Chosen Approach

Implement a core-owned MCP guard that rewrites the MCP endpoint passed from the
context driver to the agent driver.

For HTTP and HTTP+SSE endpoints, `agentenv-core` extends the existing egress
proxy plan with an MCP guard config. The `agentenv proxy run` process inspects
JSON-RPC request bodies on MCP routes before forwarding upstream. It evaluates
tool calls and either forwards, denies, or submits an approval request and waits
for the decision.

For stdio endpoints, `agentenv-core` rewrites the endpoint command to:

```text
agentenv mcp-guard run --env <name> --config <host-config-path> --stdio-upstream <encoded-command>
```

The wrapper runs inside the sandbox, starts the original stdio MCP command as a
child process, and relays JSON-RPC messages between the agent and the upstream
server. The wrapper contains only non-secret policy and approval endpoint
metadata. It writes no credentials and logs only redacted request metadata.

## Policy Configuration

MCP guard configuration lives under the existing blueprint `policy` section as
core-parsed extra YAML:

```yaml
policy:
  mcp:
    confused_deputy_guards:
      enabled: true
      default_approval: per-call
      tool_policies:
        "filesystem.read":
          approval: never
          rate_limit: 50/session
        "web.fetch":
          approval: per-call
          url_allowlist: ["api.github.com", "crates.io"]
          redact_args: true
        "*.write":
          approval: per-session
      cross_tool_flows:
        forbid_read_to_write_turns: 5
```

### Supported Fields

- `enabled`: defaults to `false` for compatibility. When false, runtime leaves
  MCP endpoints unchanged except for existing egress proxy credential brokering.
- `default_approval`: one of `never`, `per-call`, or `per-session`. This applies
  when no exact or wildcard tool policy matches.
- `tool_policies`: map of exact tool names or one-segment wildcard patterns such
  as `*.write` and `filesystem.*`.
- `approval`: overrides the default approval mode for a matching tool.
- `rate_limit`: optional `<number>/session` call cap for a matching tool.
- `url_allowlist`: optional host allowlist applied to string arguments that parse
  as URLs or contain URL-looking text.
- `redact_args`: when true, logged arguments are always summarized rather than
  field-by-field redacted.
- `cross_tool_flows.forbid_read_to_write_turns`: when set, a read-like tool call
  records session-local provenance for N subsequent tool calls. A write-like or
  external tool call inside that window requires approval.

Invalid guard config fails blueprint verification with a precise field path.

## Tool Evaluation

`agentenv-mcp` owns the policy model and pure evaluator:

- Parse MCP JSON-RPC requests and identify tool-call requests. The first
  supported canonical method is `tools/call`, with the tool name read from
  `params.name`.
- Leave non-tool JSON-RPC methods untouched.
- Match tool policies in this order: exact tool name, most-specific wildcard,
  default policy.
- Reject malformed policy and malformed tool-call params before forwarding.
- Apply URL allowlists to URL-looking string values found anywhere in JSON
  arguments.
- Detect credential-like argument keys such as `token`, `password`, `secret`,
  `api_key`, `authorization`, and `credential`.
- Detect environment-variable-looking string values such as `OPENAI_API_KEY`,
  `GITHUB_TOKEN`, and `${MCP_TOKEN}`.
- Redact logs with the existing event redaction behavior plus MCP-specific URL
  query and fragment stripping.
- Track per-session rate counters.
- Track recent read-like calls for session-local read-to-write approval.

Tool classification is conservative:

- Read-like names contain or end with `read`, `get`, `list`, `search`, `fetch`,
  `query`, or `download`.
- Write-like names contain or end with `write`, `create`, `update`, `delete`,
  `remove`, `send`, `post`, `put`, `patch`, `upload`, or `publish`.
- External-like names include URL arguments or host/network markers.
- Explicit tool policy can override these classifications in a later extension,
  but this PR keeps the YAML surface focused on the issue examples.

## Approvals

The guard creates `ApprovalRequest` records with:

- `kind`: `mcp_tool`
- `subject`: the MCP tool name
- `reason`: a stable reason code such as `approval_required`,
  `url_allowlist_violation`, `credential_like_argument`, `rate_limited`, or
  `cross_tool_flow`
- `context`: redacted method, tool name, matched policy, argument summary,
  transport, endpoint route id, and flow reason
- `default_scope`: `once` for `per-call`, `session` for `per-session`

For HTTP MCP routes, the proxy process can open the env-scoped approval store
and wait for decisions directly, matching the existing egress proxy process
model.

For stdio MCP routes, the wrapper can use the same env-scoped store path and
approval coordinator configuration because it is launched by `agentenv` with the
env name and root path. The wrapper sends no driver RPC and stores no secrets.

Allowed session approvals are enforced by the guard evaluator using its local
session grant cache. Persisted approval decisions remain recorded in the
approval store and overlay/proposal files through the existing coordinator side
effects.

## HTTP And HTTP+SSE Flow

1. Context driver returns an HTTP or HTTP+SSE `McpEndpoint`.
2. Runtime validates and plans the existing egress proxy route.
3. Runtime attaches MCP guard config to the route when guards are enabled.
4. Agent receives the rewritten proxy URL and no upstream credential headers.
5. Proxy receives MCP JSON-RPC requests on `/v1/mcp/<route>`.
6. Proxy evaluates tool-call requests before credential injection.
7. Proxy forwards allowed requests upstream with brokered auth.
8. Proxy emits redacted `mcp_tool_call` and egress events.

HTTP+SSE response streaming stays unchanged. The guard only inspects incoming
client-to-server request bodies. Streaming response bodies are not parsed for
taint in this PR.

## Stdio Flow

1. Context driver returns a stdio `McpEndpoint` whose `url` field contains the
   command to run.
2. Runtime rewrites the command to `agentenv mcp-guard run`.
3. Runtime writes a host-side guard config next to other agent assets and copies
   it into the sandbox with mode `0600`.
4. The wrapper decodes the original command, starts it as a child process, and
   relays LSP-style JSON-RPC frames.
5. The wrapper evaluates outbound `tools/call` requests before writing them to
   the child process.
6. The wrapper forwards non-tool requests and upstream responses unchanged.
7. The wrapper exits when either side closes or when the child process exits.

The wrapper must preserve MCP framing exactly. Invalid frame headers or invalid
JSON-RPC messages are denied with a JSON-RPC error response to the agent and are
not forwarded upstream.

## Error Handling

- Policy parse errors fail blueprint verification.
- Missing approval store access fails closed for approval-required tool calls.
- Approval timeout returns a JSON-RPC error to the agent and emits
  `approval_decided` through the existing auto-deny path.
- URL allowlist violations return a JSON-RPC error and emit a denied
  `mcp_tool_call` event.
- Credential-like argument detection requires approval by default. If the
  matching tool policy uses `approval: never`, the event is flagged but the call
  is allowed.
- Rate-limit violations deny without approval unless a matching policy explicitly
  uses `approval: per-call` or `per-session`.
- Stdio child process failure returns a clear JSON-RPC internal error for the
  in-flight request and exits after flushing events.
- HTTP upstream failures preserve the existing egress proxy behavior.

## Event Model

Every evaluated tool call emits a redacted `ActivityEvent`:

- `kind`: `mcp_tool_call`
- `result`: `ok`, `denied`, `pending_approval`, or `error`
- `actor.kind`: `mcp_guard`
- `subject.tool`: tool name
- `subject.transport`: `stdio`, `http`, or `http+sse`
- `subject.route_id`: proxy route id when present
- `reason_code`: stable guard decision reason
- `extras.arg_summary`: object with redacted keys, URL origins, and flags
- `extras.policy`: matched policy pattern and approval mode

The event payload must never include raw credential values, raw URL query
strings, raw URL fragments, or original authorization headers.

## Security Notes

- The guard is fail-closed when it cannot parse enabled policy or cannot reach
  the approval store for a call requiring approval.
- The stdio wrapper cannot protect data that an MCP server sends directly to the
  agent and the agent later copies into a non-MCP channel. That needs broader
  turn-level provenance and is outside this PR.
- The read-to-write guard is session-local and MCP-only. It catches the issue's
  cross-MCP tool chaining pattern when both calls pass through the guard.
- The existing host egress proxy remains responsible for credential injection
  and upstream SSRF validation.
- Context drivers do not receive or store approval decisions.

## Testing Strategy

Testing follows TDD per behavior slice.

### `agentenv-mcp`

- Policy YAML deserializes valid config and rejects unknown fields.
- Exact match beats wildcard match.
- Most-specific wildcard beats broad wildcard.
- Default approval applies when no policy matches.
- URL allowlist detects URL-looking nested argument strings.
- Secret-like keys and env-var-looking values are flagged.
- Redaction removes credential keys, URL query strings, URL fragments, and
  authorization-like values.
- Rate limits are counted per session.
- Recent read-like calls trigger write-like approval inside the configured
  window.

### `agentenv`

- HTTP MCP proxy route denies URL allowlist violations before credential
  resolution.
- HTTP MCP proxy route emits redacted `mcp_tool_call` events.
- HTTP MCP proxy route forwards allowed tool calls with brokered credentials.
- Stdio guard relays non-tool JSON-RPC messages unchanged.
- Stdio guard blocks or approval-gates tool calls before writing to upstream.
- Stdio guard returns JSON-RPC errors for malformed frames.

### `agentenv-core`

- Runtime rewrites HTTP MCP endpoints with guard config when enabled.
- Runtime rewrites stdio MCP commands to the guard wrapper when enabled.
- Runtime leaves endpoints unchanged when guard config is disabled.
- Runtime copies guard config into the sandbox and passes no secrets.
- Blueprint verification rejects invalid `policy.mcp` config.

### Workspace Verification

Final verification commands:

```bash
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Rollout And Compatibility

The feature is disabled unless `policy.mcp.confused_deputy_guards.enabled` is
true. Existing blueprints and lockfiles continue to work unchanged.

Reference blueprints should add commented examples rather than enabling guards
by default. A later hardening profile can enable a safe default once enough
third-party MCP tool naming patterns are known.

## Trade-Offs

The chosen design adds mediation in core runtime instead of drivers. That keeps
security policy centralized and avoids multiplying behavior across agent and
context drivers, but it makes runtime responsible for command rewriting and
proxy configuration.

The stdio guard wrapper is more work than the HTTP-only path, but it is required
for full issue coverage because the filesystem context and many local MCP
servers use stdio.

Session-local read-to-write flow tracking is intentionally narrower than full
taint propagation. It is enforceable with the data agentenv already controls and
does not pretend to solve arbitrary prompt-level provenance.
