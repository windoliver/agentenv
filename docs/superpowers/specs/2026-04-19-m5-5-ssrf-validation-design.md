# M5-5 Design: SSRF Validation for Outbound URLs

- Date: 2026-04-19
- Issue: https://github.com/windoliver/agentenv/issues/21
- Milestone: M5 Packaging, DX, and security
- Affected crates: `agentenv-core`, `agentenv-mcp`, `agentenv-credstore`, `agentenv-events`

## 1. Context and Goals

Issue #21 closes the SSRF surface before `v0.1` by ensuring every outbound URL consumed by `agentenv` flows through one central validator. The implementation must cover blueprint references, MCP endpoints, webhook targets, federation URLs, inference upstreams, driver registry fetches, and credential curl-probe validators as those paths exist or are introduced.

The design keeps `agentenv`'s security logic in core, preserves MCP and JSON-RPC as the narrow waist, and avoids driver-specific shortcuts. Callers may wrap the validator with transport-specific helpers, but the decision logic lives in one place.

## 2. Scope and Non-Goals

### In scope

1. A central `agentenv-core::security::ssrf` module exposing:
   - `validate_outbound(url: &Url, opts: SsrfOptions) -> Result<ValidatedUrl, SsrfBlocked>`
   - options for allowed schemes, private-network opt-in, extra deny CIDRs, resolver selection, and redirect limits
   - DNS resolution with pinned IP results
   - IP normalization and category checks
   - static cloud metadata deny entries
2. Blueprint verification that validates known URL-bearing fields after interpolation.
3. MCP endpoint validation helpers for HTTP-like MCP transports.
4. Credential curl-probe validation before outbound HTTP.
5. Redirect-chain validation for helper-managed fetches.
6. Audit-ready activity events for every blocked SSRF decision.
7. Unit and integration tests covering the issue acceptance criteria.

### Out of scope

1. Durable audit log storage, export, and `/metrics`; those remain M6 concerns.
2. New driver protocol methods or schema-version bumps.
3. A new pluggable axis or alternate serialization format.
4. Runtime dependencies outside Rust core crates.

## 3. Architecture

### 3.1 Central validator

Add `agentenv-core::security::ssrf` as the source of truth for outbound URL decisions. The module owns:

1. `SsrfOptions`
   - default schemes: `http`, `https`
   - opt-in `allow_ssh_http`
   - `allow_private`, default `false`
   - `extra_deny_cidrs`
   - `max_redirects`, default `3`
   - DNS resolver choice
2. `ValidatedUrl`
   - normalized original `Url`
   - resolved and policy-checked pinned IP set
3. `SsrfBlocked`
   - typed block reason
   - normalized URL string where safe
   - host and resolved IP when available
4. Resolver abstraction
   - system resolver for production
   - fake resolver for deterministic tests
5. CIDR and IP classification helpers
   - normalize IPv4-mapped IPv6 before any checks
   - apply category and cloud metadata deny logic consistently

The pure validator handles a single URL decision. Fetch helpers build on top of it for redirect chains and HTTP connection behavior.

### 3.2 Blueprint integration

`agentenv-core::lifecycle::verify_blueprint_yaml` validates URL-bearing blueprint fields after parsing and interpolation and before returning success. The collector is explicit rather than a broad string scan. It should validate:

1. `context.endpoint.url`
2. `context.hub_url`
3. known inference upstream/base URL fields when present
4. URL-like policy override strings in `allow`, `deny`, and `approval`
5. future blueprint reference and registry URL fields when present

Opaque driver-specific strings are not treated as URLs unless the field name is known to carry a URL. This avoids false positives while still securing declared outbound surfaces.

### 3.3 MCP integration

`agentenv-mcp` exposes a small adapter API, for example:

```rust
pub fn validate_mcp_endpoint(
    endpoint: &agentenv_proto::McpEndpoint,
    opts: &SsrfOptions,
) -> Result<ValidatedMcpEndpoint, SsrfBlocked>;
```

The helper validates `http`, `http+sse`, and opt-in `ssh+http` endpoints. `stdio` endpoints are skipped because they are not outbound URLs. The returned value carries pinned IP information for callers that perform the connection.

### 3.4 Credential curl-probe integration

`agentenv-credstore` validates `ValidatorSpec::CurlProbe { url }` before sending a request. Unsafe probe URLs are blocked before any HTTP call. If full pinned-IP `reqwest` connection support is too intrusive in the first implementation step, the plan must still block unsafe targets before send and keep the pinned-fetch implementation inside the issue scope rather than silently dropping it.

### 3.5 Events integration

`agentenv-events` gets a minimal activity event surface for SSRF block decisions. `SsrfBlocked` can be converted to an `ActivityKind::EgressDenied` record with:

1. subject: the blocked URL or host
2. reason: the typed block reason
3. timestamp
4. optional handle or source path when the caller has one

Storage and export are intentionally deferred to M6, but M5 must produce the event object so operators can later see blocked attempts.

## 4. Validation Semantics

### 4.1 URL checks

The validator uses the `url` crate. It blocks:

1. unsupported schemes
2. missing host
3. embedded username or password
4. invalid ports
5. unresolvable hostnames
6. resolved IPs denied by category, cloud metadata rules, or extra CIDRs

Default allowed schemes are `http` and `https`. `ssh+http` is accepted only when `allow_ssh_http` is set.

### 4.2 DNS and pinning

Validation resolves the hostname and stores the resolved IPs in `ValidatedUrl`. Callers that fetch over HTTP must connect to one of the pinned IPs while preserving the original host for HTTP `Host` and TLS SNI semantics.

The first implementation includes the system resolver and a resolver trait for deterministic tests. The config model may include `cloudflare` and `google` resolver choices, but unsupported resolver choices must return typed configuration errors until they are implemented.

### 4.3 IP deny logic

The deny list is on by default and includes:

1. loopback: `127.0.0.0/8`, `::1`
2. link-local: `169.254.0.0/16`, `fe80::/10`
3. private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, unless `allow_private` is true
4. multicast
5. broadcast
6. reserved and documentation ranges
7. unspecified addresses
8. IPv4-mapped IPv6 equivalents of denied IPv4 addresses
9. static cloud metadata endpoints for AWS, GCP, Azure, and OCI
10. configured `security.ssrf.extra_deny_cidrs`

Extra CIDRs are evaluated after IP normalization and before allow.

### 4.4 Redirect validation

Redirect validation belongs to a helper that wraps fetches. Each `Location` hop is parsed, validated with the same options, resolved, pinned, and counted against `max_redirects`. The default maximum is `3`. A redirect to a denied target returns `SsrfBlocked` and emits an audit-ready event.

## 5. Configuration

Add an SSRF configuration model matching the issue shape:

```yaml
security:
  ssrf:
    allow_private: false
    extra_deny_cidrs:
      - "10.100.0.0/16"
    max_redirects: 3
    dns_resolver: system
```

For the current scaffold, config may be introduced as typed core structures before a full user config loader exists. Public APIs should accept `SsrfOptions` directly so CLI and future config loading can wire values without changing the validator.

## 6. Error Model

Use `thiserror` in libraries. `SsrfBlocked` should distinguish at least:

1. unsupported scheme
2. missing host
3. credentials in URL
4. DNS resolution failure
5. denied IP category
6. denied cloud metadata endpoint
7. denied extra CIDR
8. redirect limit exceeded
9. malformed redirect
10. unsupported DNS resolver configuration

Errors should include enough structured context for tests, CLI messages, and audit events without exposing secrets from URL credentials.

## 7. Testing Strategy

Follow TDD for each behavior:

1. Validator unit tests:
   - accepts public `http` and `https`
   - rejects unsupported schemes
   - rejects embedded credentials
   - rejects loopback, link-local, private-by-default, multicast, broadcast, reserved, documentation, unspecified, and cloud metadata targets
   - accepts private IPs only when `allow_private` is true
   - normalizes IPv4-mapped IPv6 before checks
   - rejects configured extra deny CIDRs
2. Fake resolver tests:
   - deterministic hostname-to-IP behavior
   - hostname resolving to both allowed and denied IPs blocks
   - DNS rebinding mitigation is visible through pinned IP results
3. Blueprint tests:
   - unsafe `context.endpoint.url` is rejected
   - unsafe `context.hub_url` is rejected
   - safe reference blueprints still verify
4. MCP tests:
   - `stdio` transport skips validation
   - `http` and `http+sse` validate
   - `ssh+http` requires opt-in
5. Credential tests:
   - unsafe curl-probe URL is blocked before sending a request
6. Redirect tests:
   - safe redirect chain validates
   - redirect to cloud metadata is blocked
   - more than three redirects fails by default

Run at minimum:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 8. Acceptance Mapping

1. `validate_outbound` exists and is called from outbound code paths:
   - covered by Sections 3.1 through 3.4.
2. Cloud metadata endpoints blocked by default:
   - covered by Sections 4.3 and 7.1.
3. DNS rebinding mitigated:
   - covered by Sections 4.2 and 7.2.
4. IPv6 and IPv4-mapped IPv6 handled:
   - covered by Sections 4.3 and 7.1.
5. Redirect chain re-validated:
   - covered by Sections 4.4 and 7.6.
6. Configurable extra deny CIDRs work:
   - covered by Sections 4.3, 5, and 7.1.
7. Blocks emit auditable events:
   - covered by Sections 3.5 and 6.
8. OWASP-style SSRF vectors pass:
   - covered by the validator tests in Section 7.

## 9. Trade-Offs

1. Keeping SSRF in `agentenv-core` avoids a new crate while the repo is still mostly scaffolded. If the security surface grows significantly, it can be moved to a dedicated crate without changing the public validator shape.
2. Explicit blueprint URL collection is safer than scanning every string because driver-specific values can be opaque identifiers rather than URLs.
3. The pure validator remains small and deterministic; redirect and pinned-fetch behavior lives in helpers that need network stack awareness.
4. Audit event generation is implemented now, but durable storage waits for the planned M6 event stream work.

## 10. Implementation Order

1. Add URL and CIDR dependencies needed by `agentenv-core`.
2. Add failing unit tests for `security::ssrf`.
3. Implement the minimal validator and fake resolver support.
4. Add tests and implementation for extra CIDRs, IPv4-mapped IPv6, and cloud metadata blocks.
5. Add blueprint URL validation tests and lifecycle integration.
6. Add MCP adapter tests and implementation.
7. Add credstore curl-probe block-before-send tests and implementation.
8. Add event conversion tests and implementation.
9. Add redirect helper tests and implementation.
10. Run workspace formatting, clippy, and tests.
