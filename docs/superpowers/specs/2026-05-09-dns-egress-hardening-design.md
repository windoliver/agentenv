# H-4 Design: DNS Egress Hardening

- Date: 2026-05-09
- Issue: https://github.com/windoliver/agentenv/issues/40
- Milestone: M5 packaging, DX, and security
- Depends on: https://github.com/windoliver/agentenv/issues/21 and https://github.com/windoliver/agentenv/issues/7
- Affected crates: `agentenv-proto`, `agentenv-policy`, `agentenv-core`, `agentenv`, `sandbox-openshell`, `sandbox-microvm`, `sandbox-remote-ssh`
- Affected docs: `docs/DRIVER_PROTOCOL.md`, `docs/BLUEPRINTS.md`

## 1. Context And Goals

Issue #40 extends the M5-5 SSRF gate from agentenv-owned HTTP URL validation into DNS-layer egress control for sandboxes. M5-5 already gives core a central `agentenv-core::security::ssrf` validator with DNS resolution, pinned IP results, IP category checks, cloud metadata denial, and audit-ready block events. That protects outbound URLs agentenv itself consumes, but it does not stop a sandboxed agent from using DNS as an exfiltration channel.

The goal is to make DNS egress policy part of the environment contract. The first full-scope implementation must:

- allow only configured DNS resolver upstreams.
- block direct DNS, DoT, and DoH egress except through the vetted resolver path.
- make the sandbox use a driver-managed local DNS guard through `/etc/resolv.conf`.
- validate and log DNS answers, including CNAME chains and A/AAAA responses.
- pin resolved IPs for proxied connections to reduce rebinding risk.
- fail closed on sandbox drivers that cannot enforce DNS egress control.

This design keeps agentenv as an environment manager, not an orchestrator. DNS policy lives in the shared policy model, while each sandbox driver declares whether it can enforce it.

## 2. Recommended Architecture

Use the shared `NetworkPolicy` model as the source of truth for DNS egress. Do not hide DNS settings in `SandboxSpec.metadata` as an OpenShell-only convention.

This requires an additive driver protocol change:

- bump `agentenv-proto::SCHEMA_VERSION` from `1.1` to `1.2`.
- add `supports_dns_egress_control: bool` to `SandboxCapabilities`, defaulting to `false` when absent.
- extend `NetworkAccessPolicy` with a DNS block.

The DNS block should use explicit, typed fields:

```yaml
policy:
  tier: restricted
  presets: []
  dns:
    resolvers_allowed:
      - 1.1.1.1
      - 8.8.8.8
    doh_upstreams_allowed:
      - https://cloudflare-dns.com/dns-query
      - https://dns.google/dns-query
    dot_upstreams_allowed:
      - 1.1.1.1:853
    log_all_queries: true
    pin_resolved_ips: true
```

`resolvers_allowed` are classic DNS resolver upstreams. Entries may be IP literals or hostnames. Hostname resolver entries must pass SSRF validation and resolve to public IPs unless a future explicit private-network opt-in is added.

`doh_upstreams_allowed` are HTTPS DNS-over-HTTPS endpoints. They must pass the existing SSRF validator and must not contain credentials, query secrets, or fragments.

`dot_upstreams_allowed` are DNS-over-TLS endpoints. They should be parsed as `host:port`, with port defaulting to `853` only if omitted by the user-facing config parser. Hostnames pass the same SSRF/IP-category checks as other resolver names.

`log_all_queries` controls query and answer logging. `pin_resolved_ips` controls connection-time validation against the DNS guard's answer cache.

## 3. Components

### 3.1 Blueprint And Resolved Policy

Extend `crate::blueprint::PolicySection` with an optional `dns` field. The user-facing field is under `policy.dns` because it is part of egress policy, not a sandbox driver option.

Extend `agentenv_proto::NetworkAccessPolicy` with:

```rust
#[serde(default)]
pub dns: DnsPolicy,
```

and define:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct DnsPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers_allowed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub doh_upstreams_allowed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dot_upstreams_allowed: Vec<String>,
    #[serde(default)]
    pub log_all_queries: bool,
    #[serde(default)]
    pub pin_resolved_ips: bool,
}
```

The default value is empty and preserves existing behavior. A DNS policy is considered active when any resolver/upstream list is non-empty, `log_all_queries` is true, or `pin_resolved_ips` is true.

`agentenv-core` must carry the resolved DNS policy into lockfiles and environment state exactly like existing network allow/deny/approval rules. Portable lockfile recomputation must include DNS policy so `freeze` and `reproduce` stay byte-stable.

### 3.2 Core Policy Engine

`agentenv-policy` composes DNS policy inside the network domain:

- `restricted`, `balanced`, and `open` baselines start with empty DNS policy.
- built-in presets remain unchanged in the first implementation.
- explicit `policy.dns` values merge into the resolved network policy after presets.
- list fields are sorted and deduplicated deterministically.

DNS changes are hot-reloadable because they live under the network domain. `compose_policy` and `classify_policy_update` should treat DNS-only changes like other network-only changes.

### 3.3 Runtime Capability Checks

Runtime must reject active DNS policy when the selected sandbox driver does not advertise DNS egress control.

`sandbox-openshell` returns:

```rust
supports_dns_egress_control: true
```

`sandbox-microvm` and `sandbox-remote-ssh` return:

```rust
supports_dns_egress_control: false
```

This is a fail-closed behavior. Runtime must return a clear capability error before `create` or `apply_policy` instead of silently dropping DNS controls.

### 3.4 OpenShell Translation

OpenShell remains responsible for normal sandbox egress. Existing OpenShell policy translation continues to produce endpoint policy YAML for allowed HTTPS destinations.

DNS-specific enforcement is realized by `sandbox-openshell` as driver-managed material derived from the shared `NetworkPolicy`:

- regular OpenShell policy YAML still controls agent-visible HTTP/TLS egress.
- direct DNS/DoT/DoH attempts from agent-visible processes are blocked by generated sandbox policy where OpenShell can express those denials.
- resolver upstreams are not appended to the agent-visible `network.allow` set.
- DNS guard configuration is generated from `policy.network.dns`.

This keeps the shared contract in `NetworkPolicy` while allowing OpenShell-specific implementation details to stay inside the translator/driver boundary.

### 3.5 OpenShell DNS Guard

Add an OpenShell DNS guard lifecycle in `sandbox-openshell`. The guard is a small driver-managed helper process inside the sandbox. It listens on sandbox-local DNS, forwards only to configured resolver upstreams, logs DNS answers, and maintains pinned answer state.

On sandbox creation, `sandbox-openshell` must:

- create the sandbox with the existing OpenShell network policy.
- upload or install DNS guard assets and config.
- rewrite sandbox `/etc/resolv.conf` to point only at the DNS guard listener.
- start the DNS guard before agent installation or agent use.
- roll back the sandbox if guard setup fails.

On policy hot reload, `sandbox-openshell` must:

- apply the regular OpenShell network policy as today.
- rewrite the DNS guard config when `policy.network.dns` changes.
- reload or restart the guard.
- preserve the previous policy if DNS guard reload fails and return a policy translation/application error.

The guard accepts only sandbox-local DNS requests. It forwards to:

- classic resolver upstreams in `resolvers_allowed`.
- vetted DoH endpoints in `doh_upstreams_allowed`.
- vetted DoT endpoints in `dot_upstreams_allowed`.

The guard must not expose a generic HTTP proxy, and it must not make DoH/DoT upstreams available to agent-visible processes as normal network destinations.

### 3.6 Connection Pinning

`pin_resolved_ips` is enforced at connection mediation time, not by trusting the agent process.

The DNS guard records recent answers keyed by queried hostname and qtype. Records include:

- original query name.
- qtype.
- CNAME chain.
- final A/AAAA answer set.
- upstream resolver.
- TTL and observed time.

When the OpenShell egress proxy later sees a connection for a policy-allowed hostname, it validates the target IP against the fresh pinned answer set from the guard. If there is no fresh pin, the answer set changed outside the guard, or the target IP is private/metadata/otherwise denied, the connection is rejected as a DNS rebinding violation.

For the first implementation, the pin store can be local to the driver-managed guard/proxy integration and does not need a new cross-driver protocol method. A future driver with native DNS control can implement equivalent semantics internally as long as the behavior matches the shared policy contract.

## 4. Validation Semantics

### 4.1 DNS Policy Validation

Core validates DNS policy before sending it to a sandbox driver:

- empty DNS policy is valid and preserves legacy behavior.
- active DNS policy requires sandbox support.
- resolver hostnames are SSRF-validated with `allow_private = false`.
- resolver IP literals are checked with the same IP classification and cloud metadata deny logic used by M5-5.
- DoH URLs must be `https`, host-bearing, credential-free, query-free, and fragment-free.
- DoT entries must have a valid host and port.
- wildcard resolver entries are invalid.

Errors should identify the exact field path, such as `policy.dns.doh_upstreams_allowed[0]`.

### 4.2 DNS Query Admission

The guard allows queries only for names that are justified by the resolved network policy:

- exact allowed hosts in `network.allow`.
- CNAME chain members discovered while resolving an allowed host.
- implementation-required bootstrap names explicitly derived from context and inference endpoints.

The guard denies unrelated domains, including DNS tunneling attempts such as base32-encoded data under attacker-controlled domains.

When a query is denied, the driver emits an `egress_denied` activity event with a DNS-specific reason code.

### 4.3 DoH And DoT Handling

Agent-visible policy must not permit arbitrary DoH or DoT destinations. The guard may reach configured DoH/DoT upstreams as part of resolver operation, but those upstreams are not normal sandbox egress approvals.

The OpenShell driver should materialize direct-deny behavior for:

- outbound UDP/TCP port `53` except the local guard path.
- outbound TCP port `853` except guard-owned DoT upstream traffic.
- direct HTTPS requests to known DoH endpoint hosts unless they are guard-owned upstream traffic.

If OpenShell cannot express one of these direct-deny rules in its current policy schema, the driver must still enforce what it can and surface the limitation in a deterministic test-backed diagnostic rather than silently claiming complete enforcement.

### 4.4 CNAME And Rebinding Handling

The guard resolves the full CNAME chain. Every chain member and final answer is logged when `log_all_queries` is true.

Final A/AAAA answers pass the existing SSRF IP checks:

- loopback.
- link-local.
- private.
- multicast.
- broadcast.
- reserved.
- documentation.
- unspecified.
- IPv4-mapped IPv6 equivalents.
- cloud metadata endpoints.
- configured extra deny CIDRs where future config supplies them.

With `pin_resolved_ips = true`, a proxied connection is allowed only when its target IP is in the fresh answer set for the hostname. A changed answer set, missing pin, expired pin, or denied IP category blocks the connection.

## 5. Activity Events And Logs

DNS guard events should use the existing activity event stream rather than a new logging protocol.

For denied DNS activity:

- `kind`: `egress_denied`
- `result`: `denied`
- `subject`: sandbox handle plus sanitized query name
- `reason_code`: stable DNS-specific labels such as `dns_query_not_allowed`, `dns_answer_denied`, `dns_rebinding_detected`, or `dns_resolver_not_allowed`

When `log_all_queries` is true, driver-local query logs should include:

- sandbox handle.
- query name.
- qtype.
- upstream resolver.
- CNAME chain.
- A/AAAA answers.
- TTL.
- action.
- reason.

Activity summaries must sanitize and bound query text. Full query logs remain driver-local until M6 audit export surfaces are used.

## 6. Error Model

Libraries continue to use `thiserror`; binaries use `anyhow`.

Add typed error cases where they naturally belong:

- policy validation errors for malformed DNS policy entries.
- capability errors when DNS policy is active but the sandbox driver lacks support.
- OpenShell translation errors for DNS controls the driver cannot materialize.
- DNS guard setup/reload errors with enough context to distinguish upload, resolv.conf, start, reload, and rollback failures.

Errors must not include credential values or unsanitized query strings.

## 7. Testing Strategy

Follow TDD for every behavior change.

Protocol tests:

- `SCHEMA_VERSION` is `1.2`.
- `SandboxCapabilities` defaults missing `supports_dns_egress_control` to `false`.
- `NetworkPolicy` JSON round-trips with `network.dns`.
- static JSON schema files include `dns-policy` and the new sandbox capability field.

Policy tests:

- `compose_policy` preserves empty DNS defaults.
- explicit DNS policy merges into the resolved policy.
- DNS lists sort and deduplicate.
- DNS-only policy changes classify as hot-reloadable.
- portable lockfiles round-trip and recompute DNS policy.

Core runtime tests:

- active DNS policy fails on `sandbox-microvm`.
- active DNS policy fails on `sandbox-remote-ssh`.
- empty DNS policy remains accepted on drivers without DNS egress control.
- active DNS policy passes through to `sandbox-openshell`.

SSRF and DNS policy validation tests:

- public resolver IP is accepted.
- loopback, private, link-local, and cloud metadata resolver IPs are rejected.
- DoH endpoint with credentials, query, or fragment is rejected.
- DoT entry with malformed host or invalid port is rejected.

OpenShell translator and driver tests:

- DNS guard config is generated from `policy.network.dns`.
- resolver upstreams are excluded from agent-visible allow rules.
- create uploads guard config, rewrites `/etc/resolv.conf`, starts the guard, and applies policy.
- create rolls back the sandbox if DNS guard setup fails.
- apply policy reloads the DNS guard on DNS changes.
- apply policy keeps the prior policy when DNS guard reload fails.
- unsupported DNS materialization returns a clear translation error.

DNS guard unit tests:

- allowed host query returns public answers and records pins.
- unrelated tunnel-like query is denied.
- CNAME chain is logged.
- private final answer is denied.
- DoH upstream allowlist is enforced.
- DoT upstream allowlist is enforced.
- rebinding pin mismatch blocks the connection.

Run at minimum:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 8. Acceptance Mapping

- DoH to arbitrary resolver is blocked because agent-visible policy does not allow DoH endpoints and the guard can reach only vetted DoH upstreams.
- DNS tunneling is blocked because the guard admits queries only for policy-justified hostnames and discovered CNAME chain members.
- CNAME chaining is controlled because the guard resolves and logs the full CNAME chain and validates final A/AAAA answers.
- DNS rebinding is mitigated because resolved IPs are pinned and checked at connection time when `pin_resolved_ips` is true.
- Resolver allowlists are enforced by DNS guard upstream selection and sandbox policy blocking direct DNS/DoT/DoH paths.
- Auditability is covered by DNS query logs and `egress_denied` activity events.
- Capability handshake is respected because unsupported sandbox drivers fail closed.

## 9. Trade-Offs

Putting DNS policy in `NetworkPolicy` means this issue changes the driver schema. That is the right trade-off because DNS egress is part of the shared sandbox contract, not an OpenShell-only detail.

The DNS guard is driver-managed rather than a fifth pluggable axis. That preserves the four-axis architecture and lets each sandbox driver enforce the same policy through its native isolation mechanisms.

OpenShell policy translation remains split between ordinary endpoint policy YAML and DNS guard material. This reflects the current OpenShell policy surface while keeping the agentenv policy model explicit and testable.

The first implementation can keep DNS guard query logs driver-local. M6 audit/export work can later lift those logs into durable audit storage without changing the DNS policy shape.

## 10. Implementation Order

1. Add protocol fields and schema `1.2` tests in `agentenv-proto`.
2. Add blueprint DNS parsing and policy model composition tests.
3. Add policy validation helpers for resolver, DoH, and DoT entries.
4. Add runtime capability checks and fail-closed tests.
5. Add lockfile and portable lockfile DNS round-trip coverage.
6. Add OpenShell DNS guard config generation tests and implementation.
7. Add OpenShell create/apply guard lifecycle tests and implementation.
8. Add DNS guard unit tests and implementation.
9. Update `docs/DRIVER_PROTOCOL.md` and `docs/BLUEPRINTS.md`.
10. Run formatting, clippy, and workspace tests.
