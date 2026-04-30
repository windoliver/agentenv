# M6-3 Approvals Queue Design

Issue: https://github.com/windoliver/agentenv/issues/25

## Summary

M6-3 completes the operator-in-the-loop approval flow. When a driver blocks an operation, it emits `event/approval_requested`; core records the request, notifies configured operator channels, waits for a decision or timeout, sends `approval/decision` back to the driver, and records the decision in the activity and audit streams.

The implementation should use a layered design:

1. `agentenv-approvals` owns the approval domain model, durable queue store, decision transitions, delivery retry state, auto-deny, scope side effects, and notification payloads.
2. `agentenv-plugin` and built-in drivers use a shared approval coordinator to submit requests and wait for decisions.
3. `agentenv` exposes the operator surfaces: `agentenv approvals ...`, `agentenv approvals serve`, and `agentenv term`.
4. `tui` contains reusable approval pane state, key handling, and rendering.
5. `agentenv-events` remains append-only activity, audit, metrics, and webhook event infrastructure.

## Affected Crates

- `crates/agentenv-approvals`: new approval model, SQLite store, coordinator, auto-deny, webhook and Slack notification helpers.
- `crates/agentenv-proto`: extend approval kind coverage and keep `ApprovalRequestedParams` / `ApprovalDecisionParams` as the wire contract.
- `crates/agentenv-plugin`: route `event/approval_requested` through the coordinator and send `approval/decision` notifications back to subprocess drivers.
- `crates/agentenv-core`: expose runtime paths and driver-facing hooks needed by built-in drivers and policy overlay application.
- `crates/agentenv`: add CLI commands, config loading, callback serving, event/audit wiring, and operator TUI entrypoint.
- `crates/tui`: add approval pane state, rendering, and keybindings.
- `crates/agentenv-events`: update metrics to prefer approval queue truth while preserving derived-event fallback.
- `docs/DRIVER_PROTOCOL.md`: document the additive approval kind variants and clarify `approval/decision` as a core-to-driver notification.

## Goals

- A driver request pauses the offending operation until allow, deny, or auto-deny.
- Operators can list, watch, approve, and deny requests from CLI.
- `agentenv term` provides one-key approve and deny.
- Webhook notifications are SSRF-validated, HMAC-signed, and retried with backoff.
- Slack notifications support one-click approve and deny when callback serving is configured.
- Scope semantics are enforced:
  - `once` unblocks one request only.
  - `session` grants are in memory and lost on restart.
  - `persist-sandbox` grants survive restart through an env-scoped overlay.
  - `propose-for-baseline` appends a proposal file and does not alter policy automatically.
- Every decision appears in the audit log with request context, decider, scope, timestamp, and reason.

## Non-Goals

- No multi-user hub or RBAC model. The decider identity is the local user or the verified callback principal.
- No web dashboard. The callback server is a small decision intake endpoint, not a management UI.
- No second serialization format. Queue rows store JSON context in SQLite; operator config and proposals use YAML, matching existing project conventions.
- No credential flow through driver RPC. Webhook and Slack secrets are host config inputs, never driver parameters.

## Domain Model

`agentenv-approvals` defines the canonical request and decision types:

```rust
pub struct ApprovalRequest {
    pub id: String,
    pub env: String,
    pub kind: ApprovalKind,
    pub subject: String,
    pub reason: String,
    pub context: serde_json::Value,
    pub requested_at: OffsetDateTime,
    pub default_scope: Scope,
    pub auto_deny_after: Duration,
    pub status: ApprovalStatus,
}

pub enum ApprovalKind {
    EgressHost,
    McpTool,
    ZoneAccess,
    PackageInstall,
    Other(String),
}

pub enum Scope {
    Once,
    Session,
    PersistSandbox,
    ProposeForBaseline,
}

pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}
```

`agentenv-proto::ApprovalKind` should add `PackageInstall` and `Other { value: String }` equivalents. This is additive for schema `1.1`; it does not change method signatures.

`ApprovalRequestedParams` does not include `env`, so the coordinator injects the runtime env name before persisting. Drivers should not be trusted to self-label an environment.

## Storage

Approval queue state should use approval-specific tables in the existing env event database at `~/.agentenv/envs/<env>/events.db`. Keeping the queue beside M6-1 activity data avoids another secured file while still separating mutable approval state from append-only activity rows.

Tables:

- `approval_requests`
  - `id TEXT PRIMARY KEY`
  - `env TEXT NOT NULL`
  - `kind TEXT NOT NULL`
  - `subject TEXT NOT NULL`
  - `reason TEXT NOT NULL`
  - `context_json TEXT NOT NULL`
  - `requested_at TEXT NOT NULL`
  - `default_scope TEXT NOT NULL`
  - `auto_deny_after_ms INTEGER NOT NULL`
  - `status TEXT NOT NULL`
  - `driver_name TEXT`
  - `driver_request_handle TEXT`
  - `expires_at TEXT NOT NULL`
  - `created_trace_id TEXT NOT NULL`

- `approval_decisions`
  - `request_id TEXT PRIMARY KEY`
  - `decision TEXT NOT NULL`
  - `scope TEXT NOT NULL`
  - `decided_by TEXT NOT NULL`
  - `decided_at TEXT NOT NULL`
  - `reason TEXT`
  - `context_json TEXT NOT NULL`
  - `trace_id TEXT NOT NULL`

- `approval_delivery_targets`
  - `id INTEGER PRIMARY KEY AUTOINCREMENT`
  - `env TEXT`
  - `kind_filter_json TEXT NOT NULL`
  - `channel TEXT NOT NULL`
  - `url TEXT NOT NULL`
  - `secret_ref TEXT`

- `approval_delivery_attempts`
  - `id INTEGER PRIMARY KEY AUTOINCREMENT`
  - `request_id TEXT NOT NULL`
  - `target_id INTEGER NOT NULL`
  - `status TEXT NOT NULL`
  - `attempt_count INTEGER NOT NULL`
  - `next_attempt_at TEXT NOT NULL`
  - `last_error TEXT`
  - `last_attempt_at TEXT`

Transitions are strict:

- `Pending -> Approved`
- `Pending -> Denied`
- `Pending -> Expired`

The store rejects a second terminal decision for the same request. Decision insertion, request status update, and delivery retry state changes happen in SQLite transactions.

## Coordinator

The coordinator is the central API used by CLI, TUI, plugin host, built-in drivers, webhook callbacks, Slack callbacks, and auto-deny.

Core operations:

- `submit_request(request, driver_channel)`: persist pending request, emit `ApprovalRequested`, enqueue notifications, and register the live driver waiter.
- `wait_for_decision(request_id)`: wait until a terminal decision exists or auto-deny fires.
- `decide(request_id, decision)`: atomically store terminal decision, apply scope side effects, emit `ApprovalDecided`, audit it, and wake live waiters.
- `list_pending(filter)`: return pending requests ordered by age.
- `watch(filter)`: stream pending and terminal updates.
- `expire_due(now)`: mark due requests as denied or expired with reason `auto_deny_timeout` and wake waiters with deny.

The coordinator can run in two modes:

- In-process mode for commands currently talking to drivers.
- Store-only mode for independent CLI/TUI/callback processes that decide requests already persisted by another process.

The waiting driver process polls or receives store notifications for decisions. Polling is acceptable for v1 if bounded to a short interval, because approvals are human-scale operations and the DB is local.

## Driver Flow

### Subprocess Drivers

`JsonRpcClient::request` already reads notifications while waiting for a response. When it sees `event/approval_requested`, it should:

1. Deserialize `ApprovalRequestedParams`.
2. Create an `ApprovalRequest` with runtime env injected.
3. Call `ApprovalCoordinator::submit_request`.
4. Wait for a decision or auto-deny.
5. Send a JSON-RPC notification to the driver:

```json
{
  "jsonrpc": "2.0",
  "method": "approval/decision",
  "params": {
    "request_id": "req_01HXYZ",
    "decision": "allow",
    "scope": "session",
    "decided_by": "alice",
    "decided_at": "2026-04-29T12:34:56Z"
  }
}
```

6. Continue waiting for the original driver response.

If auto-deny fires, send `decision: "deny"` and set a clear denial reason in the local event/audit context. The driver should surface the operation error in its original response.

### Built-In Drivers

Built-in drivers should not synthesize JSON-RPC notifications. `agentenv-core` exposes an `ApprovalRequester` trait backed by the same coordinator:

```rust
#[async_trait::async_trait]
pub trait ApprovalRequester: Send + Sync {
    async fn request_approval(&self, request: ApprovalRequestInput) -> ApprovalDecisionResult;
}
```

Drivers that can block on egress, MCP tools, zones, or package installs call this trait. Missing approval support degrades to deny in non-interactive mode and an actionable `CapabilityMissing` or `ApprovalUnavailable` error in interactive mode.

## Scope Semantics

### Once

`once` records only the terminal decision for the request. It does not create a reusable grant.

### Session

`session` records the decision for audit, then stores an in-memory grant keyed by `(env, sandbox_handle, kind, subject, context_matcher)`. The grant is not persisted. Restarting `agentenv`, the sandbox, or the driver process loses the grant.

### Persist Sandbox

`persist-sandbox` records the decision, appends a durable env-scoped approval grant, and applies policy updates when possible.

File: `~/.agentenv/envs/<env>/approval-policy-overlay.yaml`

```yaml
version: 1
grants:
  - id: req_01HXYZ
    kind: egress_host
    subject: api.stripe.com:443
    context_matcher:
      url: https://api.stripe.com/v1/charges
    created_by: alice
    created_at: "2026-04-29T12:34:56Z"
    reason: incident response debugging
```

For `egress_host`, the runtime converts the grant to `NetworkPolicy.network.allow` and calls `apply_policy` when the sandbox driver supports hot reload. If hot reload is unavailable, the decision still persists and the operator is told the sandbox must be recreated before the policy effect is active.

For non-network approval kinds, the overlay is enforced by the coordinator. If a future driver request matches a persisted grant, the coordinator immediately returns allow and emits an `ApprovalDecided` event with reason `persisted_grant`.

### Propose For Baseline

`propose-for-baseline` records the decision and appends review material to:

`~/.agentenv/envs/<env>/proposals.yaml`

The proposal includes the request, context, decider, and suggested policy shape. It does not alter runtime policy and does not update shared presets automatically.

## Operator CLI

Add:

```text
agentenv approvals list [--env <name>] [--json]
agentenv approvals watch [--env <name>] [--json]
agentenv approvals approve <req-id> [--scope once|session|persist-sandbox|propose-for-baseline] [--reason <text>]
agentenv approvals deny <req-id> [--reason <text>]
agentenv approvals serve [--addr 127.0.0.1:9181]
```

`list` prints request id, env, kind, subject, age, expiry, default scope, and reason. `watch` tails pending requests and terminal updates. `approve` uses the request default scope when `--scope` is omitted and uses the explicit operator scope when provided.

`serve` exposes local decision intake endpoints for webhook and Slack integrations:

- `POST /approvals/<req-id>/decision`
- `POST /slack/interactions`
- `GET /healthz`

The server binds to loopback by default. Binding to a non-loopback address requires an explicit flag and should print a warning because this exposes a decision surface.

## TUI

`agentenv term` should include an approvals pane even if the broader M6-2 TUI is minimal in this branch.

Keybindings:

- `A`: open approvals pane.
- `a`: approve selected request with its default scope.
- `s`: open scope picker, then approve.
- `d`: deny selected request.
- `r`: refresh.
- `q` or `Esc`: close pane.

The pane shows:

- request id
- env
- kind
- subject
- reason
- requested age
- expiry countdown
- default scope
- selected scope

The `tui` crate should expose pure state and reducer functions so tests can validate one-key behavior without terminal snapshot brittleness.

## Webhook Notifications

Config in `~/.agentenv/config.yaml`:

```yaml
approvals:
  webhooks:
    - url: https://approvals.company.com/agentenv
      secret: ${WEBHOOK_SECRET}
      kinds: [egress_host, zone_access]
  auto_deny_after:
    egress_host: 30s
    mcp_tool: 60s
    zone_access: 60s
    package_install: 120s
```

Webhook POSTs are validated through the existing SSRF validator before send and again before retry. Payloads are HMAC-SHA256 signed:

```text
x-agentenv-signature: sha256=<hex>
x-agentenv-timestamp: <unix-seconds>
x-agentenv-delivery: <delivery-id>
```

The signed payload includes request id, env, kind, subject, reason, context, requested_at, expires_at, callback URL if configured, and schema version.

Retry behavior:

- First retry after 1 second.
- Then 2, 4, 8, 16, and 30 seconds.
- Stop after the request reaches a terminal status or after the configured maximum attempts.
- Record each failure in `approval_delivery_attempts`.

## Slack Integration

Config:

```yaml
approvals:
  slack:
    webhook_url: https://hooks.slack.com/services/...
    channel: "#agentenv-approvals"
    signing_secret: ${SLACK_SIGNING_SECRET}
    callback_url: https://approvals.example.com/slack/interactions
```

Slack notifications are Block Kit messages with approve and deny buttons. Button `value` fields contain the request id, decision, and scope choice token. The callback endpoint verifies Slack's timestamp and signature before calling the same coordinator `decide` API as CLI/TUI.

If `callback_url` is absent, Slack messages still include the request context and CLI command snippets, but buttons are not emitted. That keeps notification useful without implying one-click approval is configured.

## Auto-Deny

Every request has `auto_deny_after`. The default is 60 seconds, overridden by config per kind. The coordinator computes `expires_at = requested_at + auto_deny_after`.

Auto-deny uses a periodic scan in the waiting process and in `agentenv approvals serve`. When a pending request is due:

1. Store a deny decision with `decided_by = "agentenv:auto-deny"`.
2. Use scope `once`.
3. Set reason `auto_deny_timeout`.
4. Emit and audit `ApprovalDecided`.
5. Wake live waiters and send deny back to drivers.

Pending operations surface a clear error through the driver response. Core should render this as an approval denial, not as a transport failure.

## Audit And Metrics

On request:

- Emit `ActivityKind::ApprovalRequested` with result `PendingApproval`.
- Include request id, env, kind, subject, reason, context, default scope, requested_at, and expires_at.

On decision:

- Emit `ActivityKind::ApprovalDecided`.
- Result is `Ok` for allow and `Denied` for deny or auto-deny.
- Include request id, decision, scope, decided_by, decided_at, reason, and original request context.

`AuditPolicy` already includes approval requests and decisions. The implementation must ensure decision events carry full context before audit signing.

Metrics should prefer approval tables for pending counts. If the DB has no approval tables, preserve the existing derived count from `ApprovalRequested` minus terminal `ApprovalDecided` events.

## Error Handling

- Invalid request id: CLI returns a clear not-found error and non-zero exit.
- Duplicate decision: return the stored terminal decision and do not emit a second audit event.
- Expired request decided manually: return an error explaining it auto-denied or expired.
- Webhook URL fails SSRF validation: skip delivery, record delivery error, keep request pending.
- Slack signature verification fails: reject callback with HTTP 401 and do not write a decision.
- Policy hot reload unavailable for `persist-sandbox`: persist the grant, emit a warning activity event, and tell the operator recreate is required.
- Store unavailable while driver waits: deny by default in non-interactive mode; in interactive mode surface `ApprovalUnavailable`.

## Testing Strategy

Unit tests:

- Approval model serializes stable snake_case values.
- SQLite migrations create request, decision, and delivery tables.
- Pending requests list in age order.
- Only valid terminal transitions are accepted.
- Duplicate decisions do not write duplicate audit events.
- Auto-deny marks due requests and wakes waiters.
- Session grants are not reloaded from disk.
- Persist-sandbox grants are loaded after restart.
- Proposal writes include full request context.
- HMAC signing and verification are stable.
- Webhook retry scheduling follows bounded backoff.
- Slack signature verification accepts valid requests and rejects stale or invalid ones.
- TUI reducer maps `a`, `d`, and `s` to the correct approval actions.

CLI tests:

- `agentenv approvals list --json` prints pending requests.
- `agentenv approvals approve <req-id> --scope session` records an allow decision.
- `agentenv approvals deny <req-id> --reason ...` records deny with reason.
- `agentenv approvals watch --json` emits pending and decided updates.
- `agentenv approvals serve` exposes `/healthz` and rejects unsigned decisions.

Integration tests:

- A fake subprocess driver emits `event/approval_requested`, waits, receives `approval/decision`, then completes the original operation.
- Auto-deny sends deny back to the fake driver and the operation surfaces a clear approval error.
- Webhook delivery sends an HMAC-signed payload and retries after a simulated failure.
- Persist-sandbox approval writes overlay policy and calls `apply_policy` for hot-reload capable sandbox drivers.
- `agentenv term` approval pane can approve and deny through the same coordinator used by CLI.

Verification commands:

```bash
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Implementation Order

1. Build `agentenv-approvals` model, store, migrations, transitions, and tests.
2. Add activity/audit conversion helpers for request and decision events.
3. Add CLI `agentenv approvals list|watch|approve|deny`.
4. Add coordinator wait, auto-deny, and store polling.
5. Wire subprocess driver notifications to coordinator and send `approval/decision`.
6. Add built-in driver `ApprovalRequester` surface.
7. Implement persisted grants, proposal writes, and policy overlay application.
8. Add webhook config, HMAC signing, delivery store, and retry loop.
9. Add `agentenv approvals serve` callback intake.
10. Add Slack Block Kit notification and verified callback handling.
11. Add TUI approval pane and minimal `agentenv term` entrypoint if M6-2 is not already present.
12. Update metrics fallback and docs.

## Open Design Decisions Resolved

- Queue state uses tables in the env event DB, not a separate approvals DB.
- `approval/decision` is a JSON-RPC notification, not a request requiring a response.
- Slack one-click buttons require `callback_url`; without it Slack is notification-only.
- Persisted non-network grants are enforced by the coordinator on future approval requests.
- Auto-deny stores a deny decision rather than a distinct terminal status for operator clarity; `Expired` remains available for abandoned rows discovered after no live waiter exists.
