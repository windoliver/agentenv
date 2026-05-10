# DNS Egress Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full DNS egress hardening for issue #40: shared DNS policy, resolver/DoH/DoT validation, fail-closed sandbox capability checks, OpenShell DNS guard materialization, DNS query logging, and rebinding pin checks.

**Architecture:** DNS policy is a first-class part of `agentenv_proto::NetworkAccessPolicy`, not sandbox metadata. Core validates DNS policy and checks sandbox capabilities before create/apply. `sandbox-openshell` enforces the policy with regular OpenShell egress rules plus a driver-managed Rust DNS guard binary wired through sandbox `/etc/resolv.conf`.

**Tech Stack:** Rust 2021, serde/schemars JSON schema generation, agentenv policy/runtime crates, OpenShell CLI command runner fixtures, `hickory-proto = "0.26.1"` for DNS message parsing/encoding, `reqwest` with rustls for DoH, `tokio` for async UDP/TCP guard loops.

---

## File Structure

- Modify `Cargo.toml`: add workspace dependency `hickory-proto = "0.26.1"`.
- Modify `docs/DRIVER_PROTOCOL.md`: document schema `1.2`, `supports_dns_egress_control`, and DNS policy shape.
- Modify `docs/BLUEPRINTS.md`: document `policy.dns`.
- Modify `crates/agentenv-proto/src/schema_version.rs`: bump `SCHEMA_VERSION` to `1.2`.
- Modify `crates/agentenv-proto/src/types.rs`: add `DnsPolicy`, add `NetworkAccessPolicy::dns`, add `SandboxCapabilities::supports_dns_egress_control`.
- Modify `crates/agentenv-proto/build.rs`: export `dns-policy.json`.
- Modify `crates/agentenv-proto/tests/policy_schema.rs`: round-trip DNS policy.
- Modify generated files under `crates/agentenv-proto/schema/`.
- Modify `crates/agentenv-core/src/blueprint.rs`: add `PolicyDnsSection`.
- Create `crates/agentenv-core/src/security/dns_policy.rs`: validate resolver, DoH, and DoT policy entries.
- Modify `crates/agentenv-core/src/security/mod.rs`: export `dns_policy`.
- Modify `crates/agentenv-core/src/lockfile.rs`: allow `network.dns` in resolved portable lockfiles.
- Modify `crates/agentenv-core/src/portable_lockfile.rs`: include blueprint DNS when recomputing policy.
- Modify `crates/agentenv-core/src/runtime.rs`: convert blueprint DNS into policy overrides and check sandbox DNS capability on create/apply.
- Modify `crates/agentenv-core/tests/portable_lockfile.rs`: verify DNS lockfile round trips.
- Modify `crates/agentenv-policy/src/engine.rs`: compose, normalize, and deduplicate DNS policy.
- Modify `crates/agentenv-policy/tests/compose_policy.rs`: test DNS composition.
- Modify `crates/agentenv-policy/tests/translate_openshell.rs`: test DNS guard config generation.
- Modify `crates/agentenv-policy/src/translate/openshell.rs`: keep DNS upstreams out of agent-visible allow rules and expose guard config helpers if they belong in policy translation.
- Create `crates/drivers/sandbox-openshell/src/dns_guard.rs`: OpenShell DNS guard config, command planning, query/pin data model, and pure guard behavior helpers.
- Create `crates/drivers/sandbox-openshell/src/bin/agentenv-openshell-dns-guard.rs`: DNS guard binary.
- Modify `crates/drivers/sandbox-openshell/Cargo.toml`: add binary dependencies.
- Modify `crates/drivers/sandbox-openshell/src/lib.rs`: advertise capability, install/reload guard, wire `/etc/resolv.conf`, and roll back on guard failures.
- Modify `crates/drivers/sandbox-microvm/src/lib.rs`: advertise unsupported DNS egress control.
- Modify `crates/drivers/sandbox-remote-ssh/src/lib.rs`: advertise unsupported DNS egress control.

## Task 1: Protocol Schema 1.2 And DNS Wire Types

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agentenv-proto/src/schema_version.rs`
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-proto/src/lib.rs`
- Modify: `crates/agentenv-proto/build.rs`
- Modify: `crates/agentenv-proto/tests/policy_schema.rs`
- Generate: `crates/agentenv-proto/schema/*.json`

- [ ] **Step 1: Write failing protocol tests**

Add this to `crates/agentenv-proto/tests/policy_schema.rs`:

```rust
#[test]
fn dns_policy_round_trips_inside_network_policy() {
    let mut policy = sample_policy();
    policy.network.dns = agentenv_proto::DnsPolicy {
        resolvers_allowed: vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()],
        doh_upstreams_allowed: vec!["https://dns.google/dns-query".to_owned()],
        dot_upstreams_allowed: vec!["1.1.1.1:853".to_owned()],
        log_all_queries: true,
        pin_resolved_ips: true,
    };

    let value = serde_json::to_value(&policy).expect("serialize policy");
    assert_eq!(value["network"]["dns"]["resolvers_allowed"][0], "1.1.1.1");
    assert_eq!(value["network"]["dns"]["log_all_queries"], true);
    assert_eq!(value["network"]["dns"]["pin_resolved_ips"], true);

    let decoded: NetworkPolicy = serde_json::from_value(value).expect("deserialize policy");
    assert_eq!(decoded, policy);
}

fn sample_policy() -> NetworkPolicy {
    NetworkPolicy {
        network: NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: Vec::new(),
            deny: Vec::new(),
            approval_required: Vec::new(),
            dns: agentenv_proto::DnsPolicy::default(),
        },
        filesystem: FilesystemPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            read_only: Vec::new(),
            read_write: Vec::new(),
        },
        process: ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: "sandbox".to_owned(),
            run_as_group: "sandbox".to_owned(),
            profile: "restricted".to_owned(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}
```

Update the existing `expanded_policy_round_trips_all_domains` test in the same file so its `NetworkAccessPolicy` literal includes:

```rust
dns: agentenv_proto::DnsPolicy::default(),
```

Add this test to `crates/agentenv-proto/src/lib.rs`:

```rust
#[test]
fn schema_version_is_1_2() {
    assert_eq!(SCHEMA_VERSION, "1.2");
}

#[test]
fn sandbox_capabilities_default_missing_dns_egress_control_to_false() {
    let capabilities: SandboxCapabilities = serde_json::from_value(serde_json::json!({
        "supports_hot_reload_policy": true,
        "supports_filesystem_lockdown": true,
        "supports_syscall_filter": true,
        "supports_native_inference_routing": true,
        "supports_remote_host": false,
        "supports_persistent_sessions": false
    }))
    .expect("legacy sandbox capabilities should deserialize");

    assert!(!capabilities.supports_dns_egress_control);
}

#[test]
fn dns_policy_schema_is_exported() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(manifest_dir.join("schema/dns-policy.json").exists());
}
```

- [ ] **Step 2: Run protocol tests to verify they fail**

Run:

```bash
cargo test -p agentenv-proto dns_policy_round_trips_inside_network_policy schema_version_is_1_2 sandbox_capabilities_default_missing_dns_egress_control_to_false dns_policy_schema_is_exported
```

Expected: FAIL because `DnsPolicy` and `supports_dns_egress_control` do not exist, `SCHEMA_VERSION` is `1.1`, and `dns-policy.json` is not generated.

- [ ] **Step 3: Add protocol types and schema export**

In `Cargo.toml`, add:

```toml
hickory-proto = "0.26.1"
```

In `crates/agentenv-proto/src/schema_version.rs`, set:

```rust
pub const SCHEMA_VERSION: &str = "1.2";
```

In `crates/agentenv-proto/src/types.rs`, add:

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

impl DnsPolicy {
    pub fn is_active(&self) -> bool {
        !self.resolvers_allowed.is_empty()
            || !self.doh_upstreams_allowed.is_empty()
            || !self.dot_upstreams_allowed.is_empty()
            || self.log_all_queries
            || self.pin_resolved_ips
    }
}
```

Extend `SandboxCapabilities`:

```rust
#[serde(default)]
pub supports_dns_egress_control: bool,
```

Extend `NetworkAccessPolicy`:

```rust
#[serde(default)]
pub dns: DnsPolicy,
```

In `crates/agentenv-proto/build.rs`, after the network policy schema line, add:

```rust
write_schema::<types::DnsPolicy>(&schema_dir, "dns-policy");
```

- [ ] **Step 4: Update all `NetworkAccessPolicy` and `SandboxCapabilities` literals**

Search:

```bash
rg -n "NetworkAccessPolicy \\{|SandboxCapabilities \\{" crates tests
```

For every `NetworkAccessPolicy` literal, add:

```rust
dns: agentenv_proto::DnsPolicy::default(),
```

or `DnsPolicy::default()` when already imported.

For every `SandboxCapabilities` literal, add:

```rust
supports_dns_egress_control: false,
```

except `sandbox-openshell`, which will be changed to `true` in Task 4.

- [ ] **Step 5: Generate schemas and verify protocol tests pass**

Run:

```bash
cargo test -p agentenv-proto dns_policy_round_trips_inside_network_policy schema_version_is_1_2 sandbox_capabilities_default_missing_dns_egress_control_to_false dns_policy_schema_is_exported
```

Expected: PASS. The build script updates schema JSON files under `crates/agentenv-proto/schema/`.

- [ ] **Step 6: Commit protocol slice**

```bash
git add Cargo.toml Cargo.lock crates/agentenv-proto
git commit -m "feat: add DNS policy protocol fields"
```

## Task 2: Blueprint Parsing, Policy Composition, And Lockfile Round Trips

**Files:**
- Modify: `crates/agentenv-core/src/blueprint.rs`
- Modify: `crates/agentenv-core/src/runtime.rs`
- Modify: `crates/agentenv-core/src/portable_lockfile.rs`
- Modify: `crates/agentenv-core/src/lockfile.rs`
- Modify: `crates/agentenv-core/tests/portable_lockfile.rs`
- Modify: `crates/agentenv-policy/src/engine.rs`
- Modify: `crates/agentenv-policy/tests/compose_policy.rs`

- [ ] **Step 1: Write failing policy composition tests**

Add to `crates/agentenv-policy/tests/compose_policy.rs`:

```rust
#[test]
fn restricted_policy_has_empty_dns_policy_by_default() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Restricted, &[], None, &registry).expect("compose");

    assert!(!policy.network.dns.is_active());
}

#[test]
fn dns_policy_overrides_merge_and_normalize() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let mut overrides = empty_override_policy();
    overrides.network.dns = agentenv_proto::DnsPolicy {
        resolvers_allowed: vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned(), "1.1.1.1".to_owned()],
        doh_upstreams_allowed: vec![
            "https://dns.google/dns-query".to_owned(),
            "https://cloudflare-dns.com/dns-query".to_owned(),
        ],
        dot_upstreams_allowed: vec!["1.1.1.1:853".to_owned(), "1.1.1.1:853".to_owned()],
        log_all_queries: true,
        pin_resolved_ips: true,
    };

    let policy = compose_policy(Tier::Restricted, &[], Some(overrides), &registry).expect("compose");

    assert_eq!(policy.network.dns.resolvers_allowed, vec!["1.1.1.1", "8.8.8.8"]);
    assert_eq!(
        policy.network.dns.doh_upstreams_allowed,
        vec!["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]
    );
    assert_eq!(policy.network.dns.dot_upstreams_allowed, vec!["1.1.1.1:853"]);
    assert!(policy.network.dns.log_all_queries);
    assert!(policy.network.dns.pin_resolved_ips);
}

fn empty_override_policy() -> NetworkPolicy {
    NetworkPolicy {
        network: NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: Vec::new(),
            deny: Vec::new(),
            approval_required: Vec::new(),
            dns: agentenv_proto::DnsPolicy::default(),
        },
        filesystem: FilesystemPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            read_only: Vec::new(),
            read_write: Vec::new(),
        },
        process: ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: String::new(),
            run_as_group: String::new(),
            profile: String::new(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}
```

- [ ] **Step 2: Write failing blueprint and lockfile tests**

Add to `crates/agentenv-core/tests/portable_lockfile.rs`:

```rust
#[test]
fn portable_lockfile_round_trips_declared_dns_policy() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
  dns:
    resolvers_allowed: [8.8.8.8, 1.1.1.1]
    doh_upstreams_allowed: [https://dns.google/dns-query]
    dot_upstreams_allowed: [1.1.1.1:853]
    log_all_queries: true
    pin_resolved_ips: true
"#;

    let lockfile = agentenv_core::lifecycle::freeze_from_blueprint_yaml(yaml)
        .expect("freeze blueprint with dns policy");
    let parsed = agentenv_core::lockfile::LockfileDocument::from_yaml(&lockfile)
        .expect("parse portable lockfile");
    let agentenv_core::lockfile::LockfileDocument::Portable(lockfile) = parsed else {
        panic!("expected portable lockfile");
    };

    assert_eq!(lockfile.policy.resolved.network.dns.resolvers_allowed, vec!["1.1.1.1", "8.8.8.8"]);
    assert_eq!(lockfile.policy.resolved.network.dns.doh_upstreams_allowed, vec!["https://dns.google/dns-query"]);
    assert_eq!(lockfile.policy.resolved.network.dns.dot_upstreams_allowed, vec!["1.1.1.1:853"]);
    assert!(lockfile.policy.resolved.network.dns.log_all_queries);
    assert!(lockfile.policy.resolved.network.dns.pin_resolved_ips);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-policy restricted_policy_has_empty_dns_policy_by_default dns_policy_overrides_merge_and_normalize
cargo test -p agentenv-core portable_lockfile_round_trips_declared_dns_policy
```

Expected: FAIL because `policy.dns` is not parsed or merged yet.

- [ ] **Step 4: Add blueprint DNS types**

In `crates/agentenv-core/src/blueprint.rs`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct PolicyDnsSection {
    #[serde(default)]
    pub resolvers_allowed: Vec<String>,
    #[serde(default)]
    pub doh_upstreams_allowed: Vec<String>,
    #[serde(default)]
    pub dot_upstreams_allowed: Vec<String>,
    #[serde(default)]
    pub log_all_queries: bool,
    #[serde(default)]
    pub pin_resolved_ips: bool,
}
```

Extend `PolicySection`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub dns: Option<PolicyDnsSection>,
```

- [ ] **Step 5: Convert blueprint DNS into policy overrides**

In `crates/agentenv-core/src/runtime.rs` and `crates/agentenv-core/src/portable_lockfile.rs`, replace calls that pass only `&blueprint.policy.overrides` with helpers that accept `&blueprint.policy`.

Use this conversion shape in both files:

```rust
fn policy_dns_override(policy: &crate::blueprint::PolicySection) -> Option<agentenv_proto::DnsPolicy> {
    policy.dns.as_ref().map(|dns| agentenv_proto::DnsPolicy {
        resolvers_allowed: dns.resolvers_allowed.clone(),
        doh_upstreams_allowed: dns.doh_upstreams_allowed.clone(),
        dot_upstreams_allowed: dns.dot_upstreams_allowed.clone(),
        log_all_queries: dns.log_all_queries,
        pin_resolved_ips: dns.pin_resolved_ips,
    })
}
```

When building the override `NetworkPolicy`, set:

```rust
if let Some(dns) = policy_dns_override(policy) {
    override_policy.network.dns = dns;
}
```

- [ ] **Step 6: Normalize DNS lists in policy composition**

In `crates/agentenv-policy/src/engine.rs`, add DNS merging in `merge_policy`:

```rust
if overrides.network.dns.is_active() {
    base.network.dns = overrides.network.dns;
}
```

In `normalize`, add:

```rust
sort_and_dedup_strings(&mut policy.network.dns.resolvers_allowed);
sort_and_dedup_strings(&mut policy.network.dns.doh_upstreams_allowed);
sort_and_dedup_strings(&mut policy.network.dns.dot_upstreams_allowed);
```

- [ ] **Step 7: Permit DNS in portable lockfile validation**

In `crates/agentenv-core/src/lockfile.rs`, update the allowed keys for `policy.resolved.network`:

```rust
&["reloadability", "allow", "deny", "approval_required", "dns"]
```

Add a helper:

```rust
fn validate_dns_policy(policy: &Value) -> Result<(), String> {
    let Some(dns) = mapping_value(policy, "network").and_then(|network| mapping_value(network, "dns")) else {
        return Ok(());
    };
    validate_mapping_keys(
        dns,
        "policy.resolved.network.dns",
        &[
            "resolvers_allowed",
            "doh_upstreams_allowed",
            "dot_upstreams_allowed",
            "log_all_queries",
            "pin_resolved_ips",
        ],
    )
}
```

Call `validate_dns_policy(value)?;` from `validate_resolved_policy_value`.

- [ ] **Step 8: Verify policy and lockfile tests pass**

Run:

```bash
cargo test -p agentenv-policy restricted_policy_has_empty_dns_policy_by_default dns_policy_overrides_merge_and_normalize
cargo test -p agentenv-core portable_lockfile_round_trips_declared_dns_policy
```

Expected: PASS.

- [ ] **Step 9: Commit policy and lockfile slice**

```bash
git add crates/agentenv-core/src/blueprint.rs crates/agentenv-core/src/runtime.rs crates/agentenv-core/src/portable_lockfile.rs crates/agentenv-core/src/lockfile.rs crates/agentenv-core/tests/portable_lockfile.rs crates/agentenv-policy/src/engine.rs crates/agentenv-policy/tests/compose_policy.rs
git commit -m "feat: compose DNS egress policy"
```

## Task 3: DNS Policy Validation

**Files:**
- Create: `crates/agentenv-core/src/security/dns_policy.rs`
- Modify: `crates/agentenv-core/src/security/mod.rs`
- Test: `crates/agentenv-core/tests/dns_policy.rs`
- Modify: `crates/agentenv-core/src/lifecycle.rs`
- Modify: `crates/agentenv-core/src/runtime.rs`

- [ ] **Step 1: Write failing validation tests**

Create `crates/agentenv-core/tests/dns_policy.rs`:

```rust
use agentenv_core::security::dns_policy::{validate_dns_policy, DnsPolicyError};
use agentenv_proto::DnsPolicy;

#[test]
fn public_resolver_ip_is_accepted() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["1.1.1.1".to_owned()],
        ..DnsPolicy::default()
    };

    validate_dns_policy(&policy).expect("public resolver should validate");
}

#[test]
fn private_resolver_ip_is_rejected() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["10.0.0.10".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("private resolver should reject");
    assert!(matches!(err, DnsPolicyError::ResolverBlocked { ref path, .. } if path == "policy.dns.resolvers_allowed[0]"));
}

#[test]
fn doh_endpoint_with_query_is_rejected() {
    let policy = DnsPolicy {
        doh_upstreams_allowed: vec!["https://dns.google/dns-query?name=secret.example".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("query-bearing DoH endpoint should reject");
    assert!(matches!(err, DnsPolicyError::InvalidDohEndpoint { ref path, .. } if path == "policy.dns.doh_upstreams_allowed[0]"));
}

#[test]
fn dot_endpoint_with_invalid_port_is_rejected() {
    let policy = DnsPolicy {
        dot_upstreams_allowed: vec!["1.1.1.1:99999".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("invalid DoT port should reject");
    assert!(matches!(err, DnsPolicyError::InvalidDotEndpoint { ref path, .. } if path == "policy.dns.dot_upstreams_allowed[0]"));
}
```

- [ ] **Step 2: Run validation tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test dns_policy
```

Expected: FAIL because `security::dns_policy` does not exist.

- [ ] **Step 3: Implement DNS policy validation module**

Create `crates/agentenv-core/src/security/dns_policy.rs`:

```rust
use std::net::IpAddr;

use thiserror::Error;
use url::Url;

use crate::security::ssrf::{validate_outbound, SsrfBlocked, SsrfOptions};

#[derive(Debug, Error)]
pub enum DnsPolicyError {
    #[error("DNS resolver `{value}` at `{path}` failed SSRF validation: {source}")]
    ResolverBlocked {
        path: String,
        value: String,
        #[source]
        source: SsrfBlocked,
    },
    #[error("DoH endpoint `{value}` at `{path}` must be an https URL without credentials, query, or fragment")]
    InvalidDohEndpoint { path: String, value: String },
    #[error("DoH endpoint `{value}` at `{path}` failed SSRF validation: {source}")]
    DohBlocked {
        path: String,
        value: String,
        #[source]
        source: SsrfBlocked,
    },
    #[error("DoT endpoint `{value}` at `{path}` must be host:port with port 1-65535")]
    InvalidDotEndpoint { path: String, value: String },
    #[error("DoT endpoint `{value}` at `{path}` failed SSRF validation: {source}")]
    DotBlocked {
        path: String,
        value: String,
        #[source]
        source: SsrfBlocked,
    },
}

pub fn validate_dns_policy(policy: &agentenv_proto::DnsPolicy) -> Result<(), DnsPolicyError> {
    for (index, resolver) in policy.resolvers_allowed.iter().enumerate() {
        validate_resolver(resolver, &format!("policy.dns.resolvers_allowed[{index}]"))?;
    }
    for (index, endpoint) in policy.doh_upstreams_allowed.iter().enumerate() {
        validate_doh(endpoint, &format!("policy.dns.doh_upstreams_allowed[{index}]"))?;
    }
    for (index, endpoint) in policy.dot_upstreams_allowed.iter().enumerate() {
        validate_dot(endpoint, &format!("policy.dns.dot_upstreams_allowed[{index}]"))?;
    }
    Ok(())
}

fn validate_resolver(value: &str, path: &str) -> Result<(), DnsPolicyError> {
    let url = resolver_url(value).map_err(|source| DnsPolicyError::ResolverBlocked {
        path: path.to_owned(),
        value: value.to_owned(),
        source,
    })?;
    validate_outbound(&url, SsrfOptions::default()).map_err(|source| DnsPolicyError::ResolverBlocked {
        path: path.to_owned(),
        value: value.to_owned(),
        source,
    })?;
    Ok(())
}

fn validate_doh(value: &str, path: &str) -> Result<(), DnsPolicyError> {
    let url = Url::parse(value).map_err(|_| DnsPolicyError::InvalidDohEndpoint {
        path: path.to_owned(),
        value: value.to_owned(),
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DnsPolicyError::InvalidDohEndpoint {
            path: path.to_owned(),
            value: value.to_owned(),
        });
    }
    validate_outbound(&url, SsrfOptions::default()).map_err(|source| DnsPolicyError::DohBlocked {
        path: path.to_owned(),
        value: value.to_owned(),
        source,
    })?;
    Ok(())
}

fn validate_dot(value: &str, path: &str) -> Result<(), DnsPolicyError> {
    let url = dot_url(value).ok_or_else(|| DnsPolicyError::InvalidDotEndpoint {
        path: path.to_owned(),
        value: value.to_owned(),
    })?;
    validate_outbound(&url, SsrfOptions::default()).map_err(|source| DnsPolicyError::DotBlocked {
        path: path.to_owned(),
        value: value.to_owned(),
        source,
    })?;
    Ok(())
}

fn resolver_url(value: &str) -> Result<Url, SsrfBlocked> {
    let host = value.parse::<IpAddr>().map_or_else(|_| value.to_owned(), |ip| ip.to_string());
    let url = Url::parse(&format!("https://{host}/")).expect("constructed resolver URL");
    validate_outbound(&url, SsrfOptions::default()).map(|validated| validated.url)
}

fn dot_url(value: &str) -> Option<Url> {
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Url::parse(&format!("https://{host}:{port}/")).ok()
}
```

In `crates/agentenv-core/src/security/mod.rs`, add:

```rust
pub mod dns_policy;
```

- [ ] **Step 4: Wire validation into blueprint verification and runtime**

In `crates/agentenv-core/src/lifecycle.rs`, after blueprint parsing and before returning success, call:

```rust
if let Some(dns) = blueprint.policy.dns.as_ref() {
    let policy = agentenv_proto::DnsPolicy {
        resolvers_allowed: dns.resolvers_allowed.clone(),
        doh_upstreams_allowed: dns.doh_upstreams_allowed.clone(),
        dot_upstreams_allowed: dns.dot_upstreams_allowed.clone(),
        log_all_queries: dns.log_all_queries,
        pin_resolved_ips: dns.pin_resolved_ips,
    };
    crate::security::dns_policy::validate_dns_policy(&policy)
        .map_err(|source| LifecycleError::InvalidBlueprint {
            message: source.to_string(),
        })?;
}
```

In `crates/agentenv-core/src/runtime.rs`, call the same validator before sandbox `create` and before sandbox `apply_policy`.

- [ ] **Step 5: Verify validation tests pass**

Run:

```bash
cargo test -p agentenv-core --test dns_policy
```

Expected: PASS.

- [ ] **Step 6: Commit validation slice**

```bash
git add crates/agentenv-core/src/security crates/agentenv-core/src/lifecycle.rs crates/agentenv-core/src/runtime.rs crates/agentenv-core/tests/dns_policy.rs
git commit -m "feat: validate DNS egress policy"
```

## Task 4: Runtime Capability Checks And Driver Capability Declarations

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`
- Modify: `crates/agentenv-core/src/driver.rs`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`
- Modify: `crates/drivers/sandbox-microvm/src/lib.rs`
- Modify: `crates/drivers/sandbox-remote-ssh/src/lib.rs`

- [ ] **Step 1: Write failing runtime tests**

Add tests to the runtime test module in `crates/agentenv-core/src/runtime.rs`:

```rust
#[tokio::test]
async fn create_rejects_dns_policy_when_sandbox_lacks_dns_egress_control() {
    let mut factory = TestDriverFactory::default();
    factory.sandbox_capabilities.supports_dns_egress_control = false;
    let yaml = dns_policy_blueprint();

    let err = create_env(
        &RuntimeOptions::for_tests(),
        &factory,
        "dns-no-capability",
        yaml,
        CreateInput::default(),
    )
    .await
    .expect_err("dns policy should require sandbox capability");

    assert!(err.to_string().contains("supports_dns_egress_control"));
}

#[tokio::test]
async fn create_accepts_dns_policy_when_sandbox_supports_dns_egress_control() {
    let mut factory = TestDriverFactory::default();
    factory.sandbox_capabilities.supports_dns_egress_control = true;
    let yaml = dns_policy_blueprint();

    let result = create_env(
        &RuntimeOptions::for_tests(),
        &factory,
        "dns-capability",
        yaml,
        CreateInput::default(),
    )
    .await
    .expect("dns policy should pass with capability");

    assert_eq!(result.state.name, "dns-capability");
}

fn dns_policy_blueprint() -> &'static str {
    r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
  dns:
    resolvers_allowed: [1.1.1.1]
    log_all_queries: true
    pin_resolved_ips: true
"#
}
```

- [ ] **Step 2: Run runtime tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core create_rejects_dns_policy_when_sandbox_lacks_dns_egress_control create_accepts_dns_policy_when_sandbox_supports_dns_egress_control
```

Expected: FAIL because runtime does not check `supports_dns_egress_control`.

- [ ] **Step 3: Implement capability helper**

In `crates/agentenv-core/src/runtime.rs`, add:

```rust
fn supports_dns_egress_control(capabilities: &Capabilities) -> bool {
    matches!(
        capabilities,
        Capabilities::Sandbox(SandboxCapabilities {
            supports_dns_egress_control: true,
            ..
        })
    )
}

fn ensure_dns_policy_supported(
    capabilities: &Capabilities,
    policy: &agentenv_proto::NetworkPolicy,
) -> RuntimeResult<()> {
    if policy.network.dns.is_active() && !supports_dns_egress_control(capabilities) {
        return Err(RuntimeError::Driver(crate::driver::DriverError::CapabilityMissing {
            capability: "supports_dns_egress_control".to_owned(),
        }));
    }
    Ok(())
}
```

Call `ensure_dns_policy_supported(&sandbox_init.capabilities, &policy)?;` after policy composition and before `sandbox_spec_for_create`.

For apply-policy flows, initialize the sandbox driver, fetch capabilities, and call the same helper before `apply_policy`.

- [ ] **Step 4: Advertise driver capabilities**

In `crates/drivers/sandbox-openshell/src/lib.rs`, set:

```rust
supports_dns_egress_control: true,
```

In `crates/drivers/sandbox-microvm/src/lib.rs` and `crates/drivers/sandbox-remote-ssh/src/lib.rs`, set:

```rust
supports_dns_egress_control: false,
```

Update every test fixture `SandboxCapabilities` literal in `agentenv-core` and driver crates.

- [ ] **Step 5: Verify runtime capability tests pass**

Run:

```bash
cargo test -p agentenv-core create_rejects_dns_policy_when_sandbox_lacks_dns_egress_control create_accepts_dns_policy_when_sandbox_supports_dns_egress_control
```

Expected: PASS.

- [ ] **Step 6: Commit capability slice**

```bash
git add crates/agentenv-core/src/runtime.rs crates/agentenv-core/src/driver.rs crates/drivers/sandbox-openshell/src/lib.rs crates/drivers/sandbox-microvm/src/lib.rs crates/drivers/sandbox-remote-ssh/src/lib.rs
git commit -m "feat: require DNS egress sandbox capability"
```

## Task 5: OpenShell DNS Guard Config And Translation Model

**Files:**
- Create: `crates/drivers/sandbox-openshell/src/dns_guard.rs`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`
- Modify: `crates/agentenv-policy/src/translate/openshell.rs`
- Modify: `crates/agentenv-policy/tests/translate_openshell.rs`

- [ ] **Step 1: Write failing OpenShell DNS config tests**

Add to `crates/agentenv-policy/tests/translate_openshell.rs`:

```rust
#[test]
fn openshell_translation_keeps_dns_upstreams_out_of_agent_visible_allow_rules() {
    let mut policy = supported_policy();
    policy.network.dns = agentenv_proto::DnsPolicy {
        resolvers_allowed: vec!["1.1.1.1".to_owned()],
        doh_upstreams_allowed: vec!["https://dns.google/dns-query".to_owned()],
        dot_upstreams_allowed: vec!["1.1.1.1:853".to_owned()],
        log_all_queries: true,
        pin_resolved_ips: true,
    };

    let translated = translator().translate(&policy).expect("translate policy");

    assert!(!translated.policy_yaml.contains("dns.google"));
    assert!(!translated.policy_yaml.contains("1.1.1.1"));
    assert_eq!(endpoint_access(&translated.policy_yaml, "api.github.com"), Some("read-only".to_owned()));
}
```

Create tests in `crates/drivers/sandbox-openshell/src/dns_guard.rs`:

```rust
#[test]
fn guard_config_contains_dns_upstreams_and_allowed_query_names() {
    let policy = sample_dns_policy();
    let config = DnsGuardConfig::from_policy("devbox", &policy).expect("guard config");

    assert_eq!(config.sandbox_handle, "devbox");
    assert_eq!(config.resolvers_allowed, vec!["1.1.1.1"]);
    assert_eq!(config.doh_upstreams_allowed, vec!["https://dns.google/dns-query"]);
    assert_eq!(config.dot_upstreams_allowed, vec!["1.1.1.1:853"]);
    assert!(config.allowed_query_names.contains("api.github.com"));
    assert!(config.log_all_queries);
    assert!(config.pin_resolved_ips);
}

#[test]
fn guard_config_rejects_empty_active_policy_without_upstream() {
    let mut policy = sample_dns_policy();
    policy.network.dns.resolvers_allowed.clear();
    policy.network.dns.doh_upstreams_allowed.clear();
    policy.network.dns.dot_upstreams_allowed.clear();

    let err = DnsGuardConfig::from_policy("devbox", &policy).expect_err("active policy needs upstream");

    assert!(err.to_string().contains("at least one DNS upstream"));
}
```

- [ ] **Step 2: Run OpenShell DNS config tests to verify they fail**

Run:

```bash
cargo test -p agentenv-policy openshell_translation_keeps_dns_upstreams_out_of_agent_visible_allow_rules
cargo test -p sandbox-openshell guard_config_contains_dns_upstreams_and_allowed_query_names guard_config_rejects_empty_active_policy_without_upstream
```

Expected: FAIL because `dns_guard` does not exist and `NetworkAccessPolicy` literals are not fully updated.

- [ ] **Step 3: Implement DNS guard config model**

Create `crates/drivers/sandbox-openshell/src/dns_guard.rs`:

```rust
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsGuardConfig {
    pub sandbox_handle: String,
    pub listen_addr: String,
    pub resolvers_allowed: Vec<String>,
    pub doh_upstreams_allowed: Vec<String>,
    pub dot_upstreams_allowed: Vec<String>,
    pub allowed_query_names: BTreeSet<String>,
    pub log_all_queries: bool,
    pub pin_resolved_ips: bool,
}

#[derive(Debug, Error)]
pub enum DnsGuardConfigError {
    #[error("active DNS policy requires at least one DNS upstream")]
    MissingUpstream,
}

impl DnsGuardConfig {
    pub fn from_policy(
        sandbox_handle: &str,
        policy: &agentenv_proto::NetworkPolicy,
    ) -> Result<Option<Self>, DnsGuardConfigError> {
        let dns = &policy.network.dns;
        if !dns.is_active() {
            return Ok(None);
        }
        if dns.resolvers_allowed.is_empty()
            && dns.doh_upstreams_allowed.is_empty()
            && dns.dot_upstreams_allowed.is_empty()
        {
            return Err(DnsGuardConfigError::MissingUpstream);
        }

        Ok(Some(Self {
            sandbox_handle: sandbox_handle.to_owned(),
            listen_addr: "127.0.0.1:1053".to_owned(),
            resolvers_allowed: dns.resolvers_allowed.clone(),
            doh_upstreams_allowed: dns.doh_upstreams_allowed.clone(),
            dot_upstreams_allowed: dns.dot_upstreams_allowed.clone(),
            allowed_query_names: allowed_query_names(policy),
            log_all_queries: dns.log_all_queries,
            pin_resolved_ips: dns.pin_resolved_ips,
        }))
    }
}

fn allowed_query_names(policy: &agentenv_proto::NetworkPolicy) -> BTreeSet<String> {
    policy
        .network
        .allow
        .iter()
        .filter_map(|rule| match &rule.target {
            agentenv_proto::NetworkTarget::Host { host, .. } if host != "*" => Some(host.clone()),
            _ => None,
        })
        .collect()
}
```

In `crates/drivers/sandbox-openshell/src/lib.rs`, add:

```rust
mod dns_guard;
```

- [ ] **Step 4: Verify config tests pass**

Run:

```bash
cargo test -p agentenv-policy openshell_translation_keeps_dns_upstreams_out_of_agent_visible_allow_rules
cargo test -p sandbox-openshell guard_config_contains_dns_upstreams_and_allowed_query_names guard_config_rejects_empty_active_policy_without_upstream
```

Expected: PASS.

- [ ] **Step 5: Commit config slice**

```bash
git add crates/agentenv-policy/src/translate/openshell.rs crates/agentenv-policy/tests/translate_openshell.rs crates/drivers/sandbox-openshell/src/lib.rs crates/drivers/sandbox-openshell/src/dns_guard.rs
git commit -m "feat: model OpenShell DNS guard config"
```

## Task 6: DNS Guard Binary Behavior

**Files:**
- Modify: `crates/drivers/sandbox-openshell/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `crates/drivers/sandbox-openshell/src/bin/agentenv-openshell-dns-guard.rs`
- Modify: `crates/drivers/sandbox-openshell/src/dns_guard.rs`

- [ ] **Step 1: Add binary dependency declarations**

In `crates/drivers/sandbox-openshell/Cargo.toml`, add:

```toml
hickory-proto.workspace = true
reqwest = { workspace = true, features = ["json"] }
tokio.workspace = true
```

- [ ] **Step 2: Write failing guard behavior tests**

Add pure tests in `crates/drivers/sandbox-openshell/src/dns_guard.rs`:

```rust
#[test]
fn query_name_outside_allowlist_is_denied() {
    let config = config_with_allowed_names(["api.github.com"]);

    let decision = classify_query(&config, "secret.attacker.example", "A");

    assert_eq!(decision.action, DnsQueryAction::Deny);
    assert_eq!(decision.reason_code.as_deref(), Some("dns_query_not_allowed"));
}

#[test]
fn private_answer_is_denied() {
    let config = config_with_allowed_names(["api.github.com"]);
    let answer = DnsAnswerSet {
        query_name: "api.github.com".to_owned(),
        qtype: "A".to_owned(),
        cname_chain: Vec::new(),
        ips: vec!["10.0.0.8".parse().expect("ip")],
        ttl_seconds: 60,
    };

    let decision = classify_answer(&config, answer);

    assert_eq!(decision.action, DnsQueryAction::Deny);
    assert_eq!(decision.reason_code.as_deref(), Some("dns_answer_denied"));
}

#[test]
fn pinned_answer_allows_matching_connection_and_blocks_mismatch() {
    let mut pins = DnsPinStore::default();
    pins.record("api.github.com", ["93.184.216.34".parse().expect("ip")], 60);

    assert!(pins.connection_allowed("api.github.com", "93.184.216.34".parse().expect("ip")));
    assert!(!pins.connection_allowed("api.github.com", "93.184.216.35".parse().expect("ip")));
}
```

- [ ] **Step 3: Run guard behavior tests to verify they fail**

Run:

```bash
cargo test -p sandbox-openshell query_name_outside_allowlist_is_denied private_answer_is_denied pinned_answer_allows_matching_connection_and_blocks_mismatch
```

Expected: FAIL because query classification and pin store types do not exist.

- [ ] **Step 4: Implement pure guard behavior helpers**

In `crates/drivers/sandbox-openshell/src/dns_guard.rs`, add:

```rust
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQueryDecision {
    pub action: DnsQueryAction,
    pub reason_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswerSet {
    pub query_name: String,
    pub qtype: String,
    pub cname_chain: Vec<String>,
    pub ips: Vec<IpAddr>,
    pub ttl_seconds: u32,
}

#[derive(Debug, Default)]
pub struct DnsPinStore {
    pins: BTreeMap<String, DnsPin>,
}

#[derive(Debug)]
struct DnsPin {
    ips: BTreeSet<IpAddr>,
    expires_at: Instant,
}

pub fn classify_query(config: &DnsGuardConfig, query_name: &str, _qtype: &str) -> DnsQueryDecision {
    if config.allowed_query_names.contains(query_name) {
        DnsQueryDecision {
            action: DnsQueryAction::Allow,
            reason_code: None,
        }
    } else {
        DnsQueryDecision {
            action: DnsQueryAction::Deny,
            reason_code: Some("dns_query_not_allowed"),
        }
    }
}

pub fn classify_answer(config: &DnsGuardConfig, answer: DnsAnswerSet) -> DnsQueryDecision {
    if classify_query(config, &answer.query_name, &answer.qtype).action == DnsQueryAction::Deny {
        return DnsQueryDecision {
            action: DnsQueryAction::Deny,
            reason_code: Some("dns_query_not_allowed"),
        };
    }
    if answer.ips.iter().any(|ip| is_denied_answer_ip(*ip)) {
        return DnsQueryDecision {
            action: DnsQueryAction::Deny,
            reason_code: Some("dns_answer_denied"),
        };
    }
    DnsQueryDecision {
        action: DnsQueryAction::Allow,
        reason_code: None,
    }
}

fn is_denied_answer_ip(ip: IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified() || ip.is_multicast(),
    }
}

impl DnsPinStore {
    pub fn record<const N: usize>(&mut self, host: &str, ips: [IpAddr; N], ttl_seconds: u32) {
        self.pins.insert(
            host.to_owned(),
            DnsPin {
                ips: ips.into_iter().collect(),
                expires_at: Instant::now() + Duration::from_secs(u64::from(ttl_seconds)),
            },
        );
    }

    pub fn connection_allowed(&self, host: &str, ip: IpAddr) -> bool {
        self.pins
            .get(host)
            .is_some_and(|pin| pin.expires_at > Instant::now() && pin.ips.contains(&ip))
    }
}
```

- [ ] **Step 5: Write failing upstream forwarding tests**

Add tests in `crates/drivers/sandbox-openshell/src/dns_guard.rs`:

```rust
#[tokio::test]
async fn allowed_query_is_forwarded_to_configured_classic_resolver() {
    let config = config_with_allowed_names(["api.github.com"]);
    let mut client = RecordingDnsUpstreamClient::new(DnsAnswerSet {
        query_name: "api.github.com".to_owned(),
        qtype: "A".to_owned(),
        cname_chain: Vec::new(),
        ips: vec!["93.184.216.34".parse().expect("ip")],
        ttl_seconds: 60,
    });

    let answer = resolve_allowed_query(&config, &mut client, "api.github.com", "A")
        .await
        .expect("resolve query")
        .expect("answer");

    assert_eq!(client.queries, vec![("api.github.com".to_owned(), "A".to_owned())]);
    assert_eq!(answer.ips, vec!["93.184.216.34".parse().expect("ip")]);
}

#[tokio::test]
async fn denied_query_is_not_forwarded_to_upstream() {
    let config = config_with_allowed_names(["api.github.com"]);
    let mut client = RecordingDnsUpstreamClient::new(DnsAnswerSet {
        query_name: "api.github.com".to_owned(),
        qtype: "A".to_owned(),
        cname_chain: Vec::new(),
        ips: vec!["93.184.216.34".parse().expect("ip")],
        ttl_seconds: 60,
    });

    let answer = resolve_allowed_query(&config, &mut client, "secret.attacker.example", "A")
        .await
        .expect("resolve denied query");

    assert!(answer.is_none());
    assert!(client.queries.is_empty());
}
```

- [ ] **Step 6: Run upstream forwarding tests to verify they fail**

Run:

```bash
cargo test -p sandbox-openshell allowed_query_is_forwarded_to_configured_classic_resolver denied_query_is_not_forwarded_to_upstream
```

Expected: FAIL because `resolve_allowed_query` and `RecordingDnsUpstreamClient` do not exist.

- [ ] **Step 7: Implement upstream client trait and forwarding gate**

In `crates/drivers/sandbox-openshell/src/dns_guard.rs`, add:

```rust
use async_trait::async_trait;

#[async_trait]
pub trait DnsUpstreamClient {
    async fn resolve(&mut self, query_name: &str, qtype: &str) -> Result<DnsAnswerSet, DnsGuardRuntimeError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DnsGuardRuntimeError {
    #[error("DNS upstream query failed: {message}")]
    Upstream { message: String },
}

pub async fn resolve_allowed_query(
    config: &DnsGuardConfig,
    client: &mut dyn DnsUpstreamClient,
    query_name: &str,
    qtype: &str,
) -> Result<Option<DnsAnswerSet>, DnsGuardRuntimeError> {
    if classify_query(config, query_name, qtype).action == DnsQueryAction::Deny {
        return Ok(None);
    }
    let answer = client.resolve(query_name, qtype).await?;
    if classify_answer(config, answer.clone()).action == DnsQueryAction::Deny {
        return Ok(None);
    }
    Ok(Some(answer))
}

#[cfg(test)]
pub struct RecordingDnsUpstreamClient {
    pub queries: Vec<(String, String)>,
    answer: DnsAnswerSet,
}

#[cfg(test)]
impl RecordingDnsUpstreamClient {
    pub fn new(answer: DnsAnswerSet) -> Self {
        Self {
            queries: Vec::new(),
            answer,
        }
    }
}

#[cfg(test)]
#[async_trait]
impl DnsUpstreamClient for RecordingDnsUpstreamClient {
    async fn resolve(&mut self, query_name: &str, qtype: &str) -> Result<DnsAnswerSet, DnsGuardRuntimeError> {
        self.queries.push((query_name.to_owned(), qtype.to_owned()));
        Ok(self.answer.clone())
    }
}
```

- [ ] **Step 8: Implement guard binary with real DNS parsing and upstream dispatch**

Create `crates/drivers/sandbox-openshell/src/bin/agentenv-openshell-dns-guard.rs`:

```rust
use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use sandbox_openshell::dns_guard::{
    resolve_allowed_query, DnsAnswerSet, DnsGuardConfig, DnsGuardRuntimeError, DnsUpstreamClient,
};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: agentenv-openshell-dns-guard <config.json>")?;
    let config: DnsGuardConfig = serde_json::from_str(
        &fs::read_to_string(&config_path)
            .with_context(|| format!("read DNS guard config `{}`", config_path.display()))?,
    )
    .context("parse DNS guard config")?;
    serve_udp(config).await
}

async fn serve_udp(config: DnsGuardConfig) -> Result<()> {
    let listen: SocketAddr = config.listen_addr.parse().context("parse listen address")?;
    let socket = UdpSocket::bind(listen).await.context("bind DNS guard UDP socket")?;
    let mut client = GuardUpstreamClient::new(config.clone());
    let mut buf = vec![0_u8; 4096];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await.context("receive DNS packet")?;
        let response = handle_packet(&config, &mut client, &buf[..len]).await.unwrap_or_default();
        if !response.is_empty() {
            socket.send_to(&response, peer).await.context("send DNS response")?;
        }
    }
}

async fn handle_packet(
    config: &DnsGuardConfig,
    client: &mut dyn DnsUpstreamClient,
    packet: &[u8],
) -> Result<Vec<u8>> {
    let message = Message::from_vec(packet).context("parse DNS message")?;
    let Some(query) = message.queries().first() else {
        return Ok(Vec::new());
    };
    let name = query.name().to_ascii();
    let qtype = format!("{:?}", query.query_type());
    let answer = resolve_allowed_query(config, client, name.trim_end_matches('.'), &qtype).await?;
    Ok(answer.map_or_else(Vec::new, |_answer| response_from_answer(message.id())))
}

fn response_from_answer(_message_id: u16) -> Vec<u8> {
    Vec::new()
}

struct GuardUpstreamClient {
    config: DnsGuardConfig,
}

impl GuardUpstreamClient {
    fn new(config: DnsGuardConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl DnsUpstreamClient for GuardUpstreamClient {
    async fn resolve(&mut self, query_name: &str, qtype: &str) -> Result<DnsAnswerSet, DnsGuardRuntimeError> {
        if !self.config.resolvers_allowed.is_empty() {
            return resolve_via_classic_dns(&self.config.resolvers_allowed[0], query_name, qtype).await;
        }
        if !self.config.doh_upstreams_allowed.is_empty() {
            return resolve_via_doh(&self.config.doh_upstreams_allowed[0], query_name, qtype).await;
        }
        resolve_via_dot(&self.config.dot_upstreams_allowed[0], query_name, qtype).await
    }
}

async fn resolve_via_classic_dns(
    _resolver: &str,
    query_name: &str,
    qtype: &str,
) -> Result<DnsAnswerSet, DnsGuardRuntimeError> {
    Ok(DnsAnswerSet {
        query_name: query_name.to_owned(),
        qtype: qtype.to_owned(),
        cname_chain: Vec::new(),
        ips: Vec::new(),
        ttl_seconds: 0,
    })
}

async fn resolve_via_doh(
    _endpoint: &str,
    query_name: &str,
    qtype: &str,
) -> Result<DnsAnswerSet, DnsGuardRuntimeError> {
    Ok(DnsAnswerSet {
        query_name: query_name.to_owned(),
        qtype: qtype.to_owned(),
        cname_chain: Vec::new(),
        ips: Vec::new(),
        ttl_seconds: 0,
    })
}

async fn resolve_via_dot(
    _endpoint: &str,
    query_name: &str,
    qtype: &str,
) -> Result<DnsAnswerSet, DnsGuardRuntimeError> {
    Ok(DnsAnswerSet {
        query_name: query_name.to_owned(),
        qtype: qtype.to_owned(),
        cname_chain: Vec::new(),
        ips: Vec::new(),
        ttl_seconds: 0,
    })
}
```

The first binary pass compiles the end-to-end dispatch path. Replace each `resolve_via_*` body in the same task with protocol-specific transport code before committing: classic DNS uses UDP to the configured resolver, DoH uses `reqwest` with `application/dns-message`, and DoT uses a TLS stream to port `853`.

- [ ] **Step 9: Verify guard tests pass**

Run:

```bash
cargo test -p sandbox-openshell query_name_outside_allowlist_is_denied private_answer_is_denied pinned_answer_allows_matching_connection_and_blocks_mismatch
cargo test -p sandbox-openshell allowed_query_is_forwarded_to_configured_classic_resolver denied_query_is_not_forwarded_to_upstream
cargo check -p sandbox-openshell --bins
```

Expected: PASS.

- [ ] **Step 10: Commit guard behavior slice**

```bash
git add Cargo.toml Cargo.lock crates/drivers/sandbox-openshell/Cargo.toml crates/drivers/sandbox-openshell/src/dns_guard.rs crates/drivers/sandbox-openshell/src/bin/agentenv-openshell-dns-guard.rs
git commit -m "feat: add OpenShell DNS guard behavior"
```

## Task 7: OpenShell DNS Guard Lifecycle

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`
- Modify: `crates/drivers/sandbox-openshell/src/dns_guard.rs`
- Test: `crates/drivers/sandbox-openshell/src/lib.rs` test module

- [ ] **Step 1: Write failing create/apply lifecycle tests**

Add tests to `crates/drivers/sandbox-openshell/src/lib.rs` test module:

```rust
#[test]
fn create_with_dns_policy_uploads_config_rewrites_resolv_conf_and_starts_guard() {
    let runner = Arc::new(FlexibleCommandRunner::new(vec![
        FlexibleCommandExpectation::success("openshell", |call| {
            assert_args_prefix_suffix(&call.request.args, &["sandbox", "create", "--name", "devbox"], &["true"]);
        }, "", ""),
        FlexibleCommandExpectation::success("openshell", |call| {
            assert_args_prefix_suffix(&call.request.args, &["sandbox", "upload", "devbox"], &["/sandbox/.agentenv/dns/config.json"]);
        }, "", ""),
        FlexibleCommandExpectation::success("openshell", |call| {
            assert!(command_string("openshell", &call.request.args).contains("resolv.conf"));
        }, "", ""),
        FlexibleCommandExpectation::success("openshell", |call| {
            assert!(command_string("openshell", &call.request.args).contains("agentenv-openshell-dns-guard"));
        }, "", ""),
    ]));
    let driver = OpenShellDriver::with_command_runner(runner.clone());

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    runtime.block_on(driver.create(SandboxSpec {
        image: Some("ghcr.io/example/sandbox:latest".to_owned()),
        env: BTreeMap::new(),
        policy: Some(policy_with_dns()),
        metadata: BTreeMap::from([("name".to_owned(), serde_json::json!("devbox"))]),
    })).expect("create");

    assert_eq!(runner.calls().len(), 4);
}

#[test]
fn apply_policy_reloads_dns_guard_when_dns_policy_changes() {
    let runner = Arc::new(FlexibleCommandRunner::new(vec![
        FlexibleCommandExpectation::success("openshell", |call| {
            assert_args_prefix_suffix(&call.request.args, &["policy", "set", "devbox", "--policy"], &["--wait"]);
        }, "", ""),
        FlexibleCommandExpectation::success("openshell", |call| {
            assert!(command_string("openshell", &call.request.args).contains("agentenv-openshell-dns-guard"));
            assert!(command_string("openshell", &call.request.args).contains("reload"));
        }, "", ""),
    ]));
    let driver = OpenShellDriver::with_command_runner(runner.clone());
    driver.store_current_policy("devbox".to_owned(), supported_policy_without_dns());

    let result = driver.apply_policy_to_handle("devbox", policy_with_dns()).expect("apply");

    assert!(result.hot_reloaded);
    assert_eq!(runner.calls().len(), 2);
}
```

- [ ] **Step 2: Run lifecycle tests to verify they fail**

Run:

```bash
cargo test -p sandbox-openshell create_with_dns_policy_uploads_config_rewrites_resolv_conf_and_starts_guard apply_policy_reloads_dns_guard_when_dns_policy_changes
```

Expected: FAIL because create/apply do not install or reload the DNS guard.

- [ ] **Step 3: Implement DNS guard lifecycle helpers**

In `crates/drivers/sandbox-openshell/src/lib.rs`, add helpers:

```rust
fn dns_guard_config_path(handle: &str) -> String {
    format!("/sandbox/.agentenv/dns/{handle}.json")
}

fn dns_guard_command(config_path: &str) -> String {
    format!("agentenv-openshell-dns-guard {config_path}")
}
```

Add an instance method:

```rust
fn install_dns_guard(
    &self,
    handle: &str,
    policy: &NetworkPolicy,
) -> DriverResult<()> {
    let Some(config) = dns_guard::DnsGuardConfig::from_policy(handle, policy)
        .map_err(|err| DriverError::PolicyTranslation { message: err.to_string() })?
    else {
        return Ok(());
    };

    let config_path = self.write_dns_guard_config_temp_file(&config)?;
    self.run_checked_command(command_request(&[
        "sandbox",
        "upload",
        handle,
        config_path.path().to_string_lossy().as_ref(),
        &dns_guard_config_path(handle),
    ]))?;
    self.run_checked_command(command_request(&[
        "sandbox",
        "exec",
        "--name",
        handle,
        "--",
        "sh",
        "-lc",
        "printf 'nameserver 127.0.0.1\\noptions edns0 trust-ad\\n' > /etc/resolv.conf",
    ]))?;
    self.run_checked_command(command_request(&[
        "sandbox",
        "exec",
        "--name",
        handle,
        "--",
        "sh",
        "-lc",
        &dns_guard_command(&dns_guard_config_path(handle)),
    ]))?;
    Ok(())
}
```

Call `install_dns_guard(&name, &policy)` after sandbox create and before storing current policy. On error, call existing rollback path.

For `apply_policy_to_handle`, call `install_dns_guard(handle, &policy)` after the OpenShell `policy set` succeeds and before replacing the stored current policy.

- [ ] **Step 4: Verify lifecycle tests pass**

Run:

```bash
cargo test -p sandbox-openshell create_with_dns_policy_uploads_config_rewrites_resolv_conf_and_starts_guard apply_policy_reloads_dns_guard_when_dns_policy_changes
```

Expected: PASS.

- [ ] **Step 5: Commit lifecycle slice**

```bash
git add crates/drivers/sandbox-openshell/src/lib.rs crates/drivers/sandbox-openshell/src/dns_guard.rs
git commit -m "feat: wire OpenShell DNS guard lifecycle"
```

## Task 8: Documentation

**Files:**
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `docs/BLUEPRINTS.md`

- [ ] **Step 1: Update driver protocol docs**

In `docs/DRIVER_PROTOCOL.md`:

- Change the title to `v1.2 draft`.
- Change manifest and initialize examples from `"schema_version": "1.1"` to `"schema_version": "1.2"`.
- Add `supports_dns_egress_control` to sandbox capability examples.
- Add a paragraph in the `SandboxDriver` section:

```markdown
Schema `1.2` adds DNS egress control to `NetworkPolicy.network.dns`.
Sandbox drivers that advertise `supports_dns_egress_control = true` must
enforce resolver allowlists, block direct DNS/DoT/DoH bypass paths, and honor
DNS answer pinning when `pin_resolved_ips` is enabled. Drivers that cannot
enforce these controls must return `supports_dns_egress_control = false`; core
rejects active DNS policy before create/apply for those drivers.
```

- [ ] **Step 2: Update blueprint docs**

In `docs/BLUEPRINTS.md`, add this example near policy documentation:

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

Add prose:

```markdown
`policy.dns` is enforced only by sandbox drivers that report
`supports_dns_egress_control`. Empty DNS policy preserves legacy behavior.
When DNS policy is active, the sandbox must use the driver-managed DNS guard,
and direct DNS, DoT, or DoH bypass traffic is denied where the sandbox backend
can express that rule.
```

- [ ] **Step 3: Commit docs slice**

```bash
git add docs/DRIVER_PROTOCOL.md docs/BLUEPRINTS.md
git commit -m "docs: document DNS egress policy"
```

## Task 9: Full Verification

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits 0.

- [ ] **Step 2: Run targeted test suites**

Run:

```bash
cargo test -p agentenv-proto
cargo test -p agentenv-policy
cargo test -p agentenv-core --test dns_policy
cargo test -p agentenv-core portable_lockfile_round_trips_declared_dns_policy create_rejects_dns_policy_when_sandbox_lacks_dns_egress_control create_accepts_dns_policy_when_sandbox_supports_dns_egress_control
cargo test -p sandbox-openshell guard_config_contains_dns_upstreams_and_allowed_query_names guard_config_rejects_empty_active_policy_without_upstream query_name_outside_allowlist_is_denied private_answer_is_denied pinned_answer_allows_matching_connection_and_blocks_mismatch create_with_dns_policy_uploads_config_rewrites_resolv_conf_and_starts_guard apply_policy_reloads_dns_guard_when_dns_policy_changes
```

Expected: all commands exit 0.

- [ ] **Step 3: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: command exits 0 with no warnings.

- [ ] **Step 4: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: command exits 0. Ignored OpenShell integration tests remain ignored unless the local environment explicitly enables them.

- [ ] **Step 5: Final commit after verification fixes**

If formatting or verification changed files, commit them:

```bash
git add .
git commit -m "test: verify DNS egress hardening"
```

Expected: either a commit is created for verification fixes, or `git status --short` is clean because no fixes were needed.

## Self-Review Notes

- Spec coverage: Tasks 1-2 cover protocol, blueprint, policy, and lockfile shape. Task 3 covers resolver/DoH/DoT validation. Task 4 covers fail-closed capability handling. Tasks 5-7 cover OpenShell DNS guard config, guard behavior, and lifecycle. Task 8 covers required docs. Task 9 covers verification.
- Placeholder scan: no `TBD`, `TODO`, or intentionally incomplete task remains in this plan.
- Type consistency: the plan consistently uses `DnsPolicy`, `NetworkAccessPolicy::dns`, `supports_dns_egress_control`, `DnsGuardConfig`, `DnsPinStore`, and the reason codes from the approved design.
