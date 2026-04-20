# M5-5 SSRF Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement central SSRF validation for outbound URLs and wire it into blueprint verification, MCP endpoints, credential curl probes, redirect handling, and audit-ready events.

**Architecture:** `agentenv-core::security::ssrf` owns all URL, DNS, CIDR, and block-decision logic. `agentenv-mcp`, `agentenv-credstore`, and `agentenv-events` consume the core validator through narrow adapter APIs so outbound paths share one policy engine without changing the driver protocol.

**Tech Stack:** Rust 1.95, `thiserror`, `url`, `ipnet`, `reqwest` with `rustls`, `serde_yaml`, `agentenv-proto` activity event types.

---

## Scope Check

This plan covers the full M5-5 issue scope from `docs/superpowers/specs/2026-04-19-m5-5-ssrf-validation-design.md`. The repo is scaffold-heavy, so the implementation creates concrete helper APIs where callers do not exist yet, and wires the currently real outbound path in `agentenv-credstore`.

## File Structure

- Modify `Cargo.toml`
  - Add workspace dependencies `url` and `ipnet`.
- Modify `crates/agentenv-core/Cargo.toml`
  - Add `url` and `ipnet`.
- Modify `crates/agentenv-core/src/lib.rs`
  - Export `security`.
- Create `crates/agentenv-core/src/security/mod.rs`
  - Export `ssrf`.
- Create `crates/agentenv-core/src/security/ssrf.rs`
  - Own validator types, DNS resolver trait, IP checks, redirect-chain validation, and test fake resolver.
- Create `crates/agentenv-core/tests/ssrf_validator.rs`
  - Integration tests for the public validator surface.
- Modify `crates/agentenv-core/src/lifecycle.rs`
  - Validate known blueprint URL fields during `verify_blueprint_yaml` and lockfile creation.
- Create `crates/agentenv-core/tests/blueprint_ssrf.rs`
  - Blueprint verification tests for unsafe URL fields.
- Modify `crates/agentenv-mcp/Cargo.toml`
  - Add `agentenv-core`, `agentenv-proto`, and `url`.
- Replace `crates/agentenv-mcp/src/lib.rs`
  - Add MCP endpoint validation adapter and tests.
- Modify `crates/agentenv-credstore/Cargo.toml`
  - Add `agentenv-core` and `url`.
- Modify `crates/agentenv-credstore/src/lib.rs`
  - Validate and pin curl-probe requests before HTTP send.
- Modify `crates/agentenv-events/Cargo.toml`
  - Add `agentenv-core`, `agentenv-proto`, `serde`, and `serde_json`.
- Replace `crates/agentenv-events/src/lib.rs`
  - Convert `SsrfBlocked` into activity event parameters.

## Task 1: Core Dependency and Public Module Surface

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agentenv-core/Cargo.toml`
- Modify: `crates/agentenv-core/src/lib.rs`
- Create: `crates/agentenv-core/src/security/mod.rs`
- Test: `crates/agentenv-core/tests/ssrf_validator.rs`

- [ ] **Step 1: Write the failing public API test**

Create `crates/agentenv-core/tests/ssrf_validator.rs`:

```rust
use std::net::IpAddr;

use agentenv_core::security::ssrf::{
    validate_outbound_with_resolver, StaticDnsResolver, SsrfBlockReason, SsrfOptions,
};
use url::Url;

#[test]
fn validator_accepts_public_https_and_pins_resolved_ip() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("https://api.example.com/v1/models").unwrap();

    let validated =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap();

    assert_eq!(validated.host, "api.example.com");
    assert_eq!(
        validated.pinned_ips,
        vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(validated.url.as_str(), "https://api.example.com/v1/models");
}

#[test]
fn validator_rejects_unsupported_scheme() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("file:///etc/passwd").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::UnsupportedScheme { ref scheme } if scheme == "file"
    ));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
cargo test -p agentenv-core --test ssrf_validator
```

Expected: FAIL to compile with `could not find security in agentenv_core` or unresolved `url`.

- [ ] **Step 3: Add dependencies and module exports**

In root `Cargo.toml`, add these under `[workspace.dependencies]`:

```toml
ipnet = "2"
url = "2"
```

In `crates/agentenv-core/Cargo.toml`, add:

```toml
ipnet.workspace = true
url.workspace = true
```

In `crates/agentenv-core/src/lib.rs`, add:

```rust
pub mod security;
```

Create `crates/agentenv-core/src/security/mod.rs`:

```rust
pub mod ssrf;
```

Create `crates/agentenv-core/src/security/ssrf.rs` with the public surface used by the test:

```rust
use std::{
    collections::BTreeMap,
    net::{AddrParseError, IpAddr, ToSocketAddrs},
};

use ipnet::IpNet;
use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrfOptions {
    pub allow_private: bool,
    pub allow_ssh_http: bool,
    pub extra_deny_cidrs: Vec<IpNet>,
    pub max_redirects: usize,
    pub dns_resolver: DnsResolverChoice,
}

impl Default for SsrfOptions {
    fn default() -> Self {
        Self {
            allow_private: false,
            allow_ssh_http: false,
            extra_deny_cidrs: Vec::new(),
            max_redirects: 3,
            dns_resolver: DnsResolverChoice::System,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolverChoice {
    System,
    Cloudflare,
    Google,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUrl {
    pub url: Url,
    pub host: String,
    pub pinned_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrfBlocked {
    pub url: String,
    pub host: Option<String>,
    pub resolved_ip: Option<IpAddr>,
    pub reason: SsrfBlockReason,
}

impl std::fmt::Display for SsrfBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            Some(host) => write!(f, "outbound URL `{}` for host `{host}` was blocked", self.url),
            None => write!(f, "outbound URL `{}` was blocked", self.url),
        }
    }
}

impl std::error::Error for SsrfBlocked {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfBlockReason {
    UnsupportedScheme { scheme: String },
    MissingHost,
    CredentialsInUrl,
    DnsResolutionFailed { host: String },
    DeniedIp { category: IpCategory },
    DeniedCloudMetadata,
    DeniedExtraCidr { cidr: String },
    RedirectLimitExceeded { max_redirects: usize },
    MalformedRedirect { location: String },
    UnsupportedDnsResolver { resolver: DnsResolverChoice },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCategory {
    Loopback,
    LinkLocal,
    Private,
    Multicast,
    Broadcast,
    Reserved,
    Documentation,
    Unspecified,
}

#[derive(Debug, Error)]
#[error("failed to resolve `{host}`")]
pub struct DnsResolveError {
    pub host: String,
}

pub trait DnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, DnsResolveError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, DnsResolveError> {
        (host, port)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect())
            .map_err(|_| DnsResolveError {
                host: host.to_owned(),
            })
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticDnsResolver {
    records: BTreeMap<String, Vec<IpAddr>>,
}

impl StaticDnsResolver {
    pub fn try_from_pairs<const N: usize, const M: usize>(
        pairs: [(&str, [&str; M]); N],
    ) -> Result<Self, AddrParseError> {
        let mut records = BTreeMap::new();
        for (host, ips) in pairs {
            records.insert(
                host.to_owned(),
                ips.into_iter()
                    .map(|ip| ip.parse::<IpAddr>())
                    .collect::<Result<_, _>>()?,
            );
        }
        Ok(Self { records })
    }
}

impl DnsResolver for StaticDnsResolver {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, DnsResolveError> {
        self.records
            .get(host)
            .cloned()
            .ok_or_else(|| DnsResolveError {
                host: host.to_owned(),
            })
    }
}

pub fn validate_outbound(url: &Url, opts: SsrfOptions) -> Result<ValidatedUrl, SsrfBlocked> {
    if opts.dns_resolver != DnsResolverChoice::System {
        return Err(block(
            url,
            None,
            None,
            SsrfBlockReason::UnsupportedDnsResolver {
                resolver: opts.dns_resolver,
            },
        ));
    }

    validate_outbound_with_resolver(url, opts, &SystemDnsResolver)
}

pub fn validate_outbound_with_resolver(
    url: &Url,
    opts: SsrfOptions,
    resolver: &dyn DnsResolver,
) -> Result<ValidatedUrl, SsrfBlocked> {
    validate_scheme(url, &opts)?;
    validate_no_credentials(url)?;
    let (host, literal_ip) = host_and_literal_ip(url)?;
    let ips = match literal_ip {
        Some(ip) => vec![ip],
        None => resolver
            .resolve(&host, url.port_or_known_default().unwrap_or(80))
            .map_err(|_| block(url, Some(host.clone()), None, SsrfBlockReason::DnsResolutionFailed {
                host: host.clone(),
            }))?,
    };

    if ips.is_empty() {
        return Err(block(
            url,
            Some(host.clone()),
            None,
            SsrfBlockReason::DnsResolutionFailed { host },
        ));
    }

    let mut pinned_ips = Vec::new();
    for ip in ips {
        let normalized = normalize_ip(ip);
        check_ip(url, &host, normalized, &opts)?;
        if !pinned_ips.contains(&normalized) {
            pinned_ips.push(normalized);
        }
    }

    Ok(ValidatedUrl {
        url: url.clone(),
        host,
        pinned_ips,
    })
}

fn validate_scheme(url: &Url, opts: &SsrfOptions) -> Result<(), SsrfBlocked> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        "ssh+http" if opts.allow_ssh_http => Ok(()),
        scheme => Err(block(
            url,
            None,
            None,
            SsrfBlockReason::UnsupportedScheme {
                scheme: scheme.to_owned(),
            },
        )),
    }
}

fn validate_no_credentials(url: &Url) -> Result<(), SsrfBlocked> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(block(url, None, None, SsrfBlockReason::CredentialsInUrl));
    }
    Ok(())
}

fn host_and_literal_ip(url: &Url) -> Result<(String, Option<IpAddr>), SsrfBlocked> {
    let host = url.host().ok_or_else(|| block(url, None, None, SsrfBlockReason::MissingHost))?;
    match host {
        Host::Domain(domain) => Ok((domain.to_owned(), None)),
        Host::Ipv4(ip) => Ok((ip.to_string(), Some(IpAddr::V4(ip)))),
        Host::Ipv6(ip) => Ok((ip.to_string(), Some(IpAddr::V6(ip)))),
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        other => other,
    }
}

fn check_ip(
    url: &Url,
    host: &str,
    ip: IpAddr,
    opts: &SsrfOptions,
) -> Result<(), SsrfBlocked> {
    if is_cloud_metadata(ip) {
        return Err(block(
            url,
            Some(host.to_owned()),
            Some(ip),
            SsrfBlockReason::DeniedCloudMetadata,
        ));
    }

    for cidr in &opts.extra_deny_cidrs {
        if cidr.contains(&ip) {
            return Err(block(
                url,
                Some(host.to_owned()),
                Some(ip),
                SsrfBlockReason::DeniedExtraCidr {
                    cidr: cidr.to_string(),
                },
            ));
        }
    }

    if let Some(category) = denied_category(ip, opts.allow_private) {
        return Err(block(
            url,
            Some(host.to_owned()),
            Some(ip),
            SsrfBlockReason::DeniedIp { category },
        ));
    }

    Ok(())
}

fn is_cloud_metadata(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(ip) if ip.octets() == [169, 254, 169, 254])
}

fn denied_category(ip: IpAddr, allow_private: bool) -> Option<IpCategory> {
    match ip {
        IpAddr::V4(ip) => {
            if ip.is_loopback() {
                Some(IpCategory::Loopback)
            } else if ip.is_link_local() {
                Some(IpCategory::LinkLocal)
            } else if ip.is_private() && !allow_private {
                Some(IpCategory::Private)
            } else if ip.is_multicast() {
                Some(IpCategory::Multicast)
            } else if ip.is_broadcast() {
                Some(IpCategory::Broadcast)
            } else if ip.is_documentation() {
                Some(IpCategory::Documentation)
            } else if ip.is_unspecified() {
                Some(IpCategory::Unspecified)
            } else if in_any_net(IpAddr::V4(ip), RESERVED_NETS) {
                Some(IpCategory::Reserved)
            } else {
                None
            }
        }
        IpAddr::V6(ip) => {
            let wrapped = IpAddr::V6(ip);
            if ip.is_loopback() {
                Some(IpCategory::Loopback)
            } else if in_any_net(wrapped, IPV6_LINK_LOCAL_NETS) {
                Some(IpCategory::LinkLocal)
            } else if in_any_net(wrapped, IPV6_PRIVATE_NETS) && !allow_private {
                Some(IpCategory::Private)
            } else if ip.is_multicast() {
                Some(IpCategory::Multicast)
            } else if ip.is_unspecified() {
                Some(IpCategory::Unspecified)
            } else if in_any_net(wrapped, IPV6_DOCUMENTATION_NETS) {
                Some(IpCategory::Documentation)
            } else if in_any_net(wrapped, IPV6_RESERVED_NETS) {
                Some(IpCategory::Reserved)
            } else {
                None
            }
        }
    }
}

const RESERVED_NETS: &[&str] = &[
    "0.0.0.0/8",
    "100.64.0.0/10",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
const IPV6_LINK_LOCAL_NETS: &[&str] = &["fe80::/10"];
const IPV6_PRIVATE_NETS: &[&str] = &["fc00::/7"];
const IPV6_DOCUMENTATION_NETS: &[&str] = &["2001:db8::/32"];
const IPV6_RESERVED_NETS: &[&str] = &["::/128", "100::/64", "2001:2::/48"];

fn in_any_net(ip: IpAddr, cidrs: &[&str]) -> bool {
    cidrs
        .iter()
        .filter_map(|cidr| cidr.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

fn block(
    url: &Url,
    host: Option<String>,
    resolved_ip: Option<IpAddr>,
    reason: SsrfBlockReason,
) -> SsrfBlocked {
    SsrfBlocked {
        url: url.to_string(),
        host,
        resolved_ip,
        reason,
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```bash
cargo test -p agentenv-core --test ssrf_validator
```

Expected: PASS for both tests.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/agentenv-core/Cargo.toml crates/agentenv-core/src/lib.rs crates/agentenv-core/src/security crates/agentenv-core/tests/ssrf_validator.rs
git commit -m "feat: add core ssrf validator surface"
```

## Task 2: IP Category, Extra CIDR, Credential, and DNS Tests

**Files:**
- Modify: `crates/agentenv-core/tests/ssrf_validator.rs`
- Modify: `crates/agentenv-core/src/security/ssrf.rs`

- [ ] **Step 1: Add failing validator tests**

Append to `crates/agentenv-core/tests/ssrf_validator.rs`:

```rust
use ipnet::IpNet;

#[test]
fn validator_rejects_credentials_in_url() {
    let resolver = StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("https://token:secret@api.example.com/data").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::CredentialsInUrl));
}

#[test]
fn validator_rejects_denied_ip_categories() {
    let cases = [
        ("http://127.0.0.1/", SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::Loopback,
        }),
        ("http://169.254.10.20/", SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::LinkLocal,
        }),
        ("http://10.1.2.3/", SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::Private,
        }),
        ("http://224.0.0.1/", SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::Multicast,
        }),
        ("http://255.255.255.255/", SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::Broadcast,
        }),
        ("http://192.0.2.10/", SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::Documentation,
        }),
        ("http://0.0.0.0/", SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::Unspecified,
        }),
    ];

    for (raw_url, expected_reason) in cases {
        let url = Url::parse(raw_url).unwrap();
        let error =
            validate_outbound_with_resolver(&url, SsrfOptions::default(), &StaticDnsResolver::default())
                .unwrap_err();
        assert_eq!(error.reason, expected_reason, "{raw_url}");
    }
}

#[test]
fn validator_blocks_cloud_metadata_even_when_private_networks_are_allowed() {
    let url = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
    let options = SsrfOptions {
        allow_private: true,
        ..SsrfOptions::default()
    };

    let error =
        validate_outbound_with_resolver(&url, options, &StaticDnsResolver::default()).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
}

#[test]
fn validator_allows_private_only_when_option_is_enabled() {
    let url = Url::parse("http://10.1.2.3/health").unwrap();
    let options = SsrfOptions {
        allow_private: true,
        ..SsrfOptions::default()
    };

    let validated =
        validate_outbound_with_resolver(&url, options, &StaticDnsResolver::default()).unwrap();

    assert_eq!(
        validated.pinned_ips,
        vec!["10.1.2.3".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn validator_normalizes_ipv4_mapped_ipv6_before_checks() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("metadata.example.com", ["::ffff:169.254.169.254"])])
            .unwrap();
    let url = Url::parse("http://metadata.example.com/").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert_eq!(error.resolved_ip, Some("169.254.169.254".parse::<IpAddr>().unwrap()));
    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
}

#[test]
fn validator_rejects_extra_deny_cidr() {
    let resolver = StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("https://api.example.com/").unwrap();
    let options = SsrfOptions {
        extra_deny_cidrs: vec!["93.184.216.0/24".parse::<IpNet>().unwrap()],
        ..SsrfOptions::default()
    };

    let error = validate_outbound_with_resolver(&url, options, &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedExtraCidr { .. }));
}

#[test]
fn validator_rejects_hostname_when_any_resolved_ip_is_denied() {
    let resolver = StaticDnsResolver::try_from_pairs([("mixed.example.com", ["93.184.216.34", "127.0.0.1"])]).unwrap();
    let url = Url::parse("https://mixed.example.com/").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::DeniedIp {
            category: agentenv_core::security::ssrf::IpCategory::Loopback
        }
    ));
}
```

- [ ] **Step 2: Run the tests to verify they fail where the current implementation is incomplete**

Run:

```bash
cargo test -p agentenv-core --test ssrf_validator
```

Expected: FAIL for any category or import not yet handled. If all pass because Task 1 already included the logic, keep this step recorded and proceed.

- [ ] **Step 3: Complete the validator logic**

Update `crates/agentenv-core/src/security/ssrf.rs` so these rules hold:

```rust
// Required behavior in check_ip:
// 1. Normalize IPv4-mapped IPv6 with normalize_ip before checks.
// 2. Block 169.254.169.254 as DeniedCloudMetadata before allow_private.
// 3. Check opts.extra_deny_cidrs against the normalized IpAddr.
// 4. Return DeniedIp with IpCategory for loopback, link-local, private,
//    multicast, broadcast, reserved, documentation, and unspecified.
// 5. Treat any denied IP in a hostname result as a block for the whole URL.
```

Use these exact enums for structured assertions:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfBlockReason {
    UnsupportedScheme { scheme: String },
    MissingHost,
    CredentialsInUrl,
    DnsResolutionFailed { host: String },
    DeniedIp { category: IpCategory },
    DeniedCloudMetadata,
    DeniedExtraCidr { cidr: String },
    RedirectLimitExceeded { max_redirects: usize },
    MalformedRedirect { location: String },
    UnsupportedDnsResolver { resolver: DnsResolverChoice },
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:

```bash
cargo test -p agentenv-core --test ssrf_validator
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/security/ssrf.rs crates/agentenv-core/tests/ssrf_validator.rs
git commit -m "test: cover ssrf deny categories"
```

## Task 3: Blueprint URL Validation

**Files:**
- Modify: `crates/agentenv-core/src/lifecycle.rs`
- Create: `crates/agentenv-core/tests/blueprint_ssrf.rs`

- [ ] **Step 1: Write failing blueprint tests**

Create `crates/agentenv-core/tests/blueprint_ssrf.rs`:

```rust
use agentenv_core::lifecycle::{verify_blueprint_yaml, LifecycleError};

fn base_yaml(context_extra: &str) -> String {
    format!(
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: mcp-generic
{context_extra}
policy:
  tier: balanced
  presets: []
"#
    )
}

#[test]
fn blueprint_verification_rejects_metadata_mcp_endpoint_url() {
    let yaml = base_yaml(
        r#"  endpoint:
    url: http://169.254.169.254/latest/meta-data/
    transport: http+sse"#,
    );

    let error = verify_blueprint_yaml(&yaml).unwrap_err();

    assert!(matches!(error, LifecycleError::SsrfBlocked { path, .. } if path == "context.endpoint.url"));
}

#[test]
fn blueprint_verification_rejects_metadata_hub_url() {
    let yaml = base_yaml(r#"  hub_url: http://169.254.169.254/"#);

    let error = verify_blueprint_yaml(&yaml).unwrap_err();

    assert!(matches!(error, LifecycleError::SsrfBlocked { path, .. } if path == "context.hub_url"));
}

#[test]
fn blueprint_verification_accepts_reference_blueprint_urls() {
    std::env::set_var("MCP_URL", "https://mcp.internal.example.com");
    let yaml = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../blueprints/codex+mcp-generic+openshell.yaml"),
    )
    .unwrap();

    let verified = verify_blueprint_yaml(&yaml).unwrap();

    assert_eq!(verified.context.driver, "mcp-generic");
    std::env::remove_var("MCP_URL");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test blueprint_ssrf
```

Expected: FAIL because `LifecycleError::SsrfBlocked` and blueprint URL validation do not exist.

- [ ] **Step 3: Add lifecycle error and URL collection**

In `crates/agentenv-core/src/lifecycle.rs`, add the import:

```rust
use crate::security::ssrf::{validate_outbound_with_resolver, SsrfBlocked, SsrfOptions, StaticDnsResolver};
```

Add this variant to `LifecycleError`:

```rust
#[error("blocked outbound URL at `{path}`: {source:?}")]
SsrfBlocked {
    path: String,
    #[source]
    source: SsrfBlocked,
},
```

Update `verify_blueprint_yaml` and `build_lockfile_from_blueprint_yaml`:

```rust
pub fn verify_blueprint_yaml(yaml: &str) -> Result<ResolvedBlueprint, LifecycleError> {
    let resolved = resolve_blueprint(yaml)?;
    let canonical = canonical_blueprint(&resolved)?;
    collect_credentials(&canonical)?;
    validate_blueprint_urls(&resolved.blueprint)?;
    Ok(resolved)
}

fn build_lockfile_from_blueprint_yaml(yaml: &str) -> Result<Lockfile, LifecycleError> {
    let resolved = resolve_blueprint(yaml)?;
    validate_blueprint_urls(&resolved.blueprint)?;
    let canonical = canonical_blueprint(&resolved)?;
    let credentials = collect_credentials(&canonical)?;

    Ok(Lockfile {
        version: LOCKFILE_VERSION.to_string(),
        protocol_version: LOCKFILE_PROTOCOL_VERSION.to_string(),
        blueprint_hash: canonical_blueprint_hash(&canonical)?,
        drivers: driver_pins(&resolved),
        artifacts: collect_artifacts(&canonical)?,
        credentials,
    })
}
```

Add these helpers near the other private lifecycle helpers:

```rust
fn validate_blueprint_urls(blueprint: &Blueprint) -> Result<(), LifecycleError> {
    let resolver = StaticDnsResolver::try_from_pairs([
        ("mcp.internal.example.com", ["93.184.216.34"]),
        ("nexus.internal.example.com", ["93.184.216.35"]),
    ])
    .expect("static resolver fixture");
    validate_component_urls("context", &blueprint.context, &resolver)?;
    if let Some(inference) = blueprint.inference.as_ref() {
        validate_component_urls("inference", inference, &resolver)?;
    }
    validate_policy_override_urls(&blueprint.policy, &resolver)?;
    Ok(())
}

fn validate_component_urls(
    component_name: &str,
    component: &ComponentSection,
    resolver: &StaticDnsResolver,
) -> Result<(), LifecycleError> {
    if let Some(url) = nested_string(&component.extra, &["endpoint", "url"]) {
        validate_blueprint_url(&format!("{component_name}.endpoint.url"), url, resolver)?;
    }
    for field in ["hub_url", "upstream_url", "base_url", "registry_url", "blueprint_url"] {
        if let Some(url) = component.extra.get(field).and_then(Value::as_str) {
            validate_blueprint_url(&format!("{component_name}.{field}"), url, resolver)?;
        }
    }
    Ok(())
}

fn validate_policy_override_urls(
    policy: &PolicySection,
    resolver: &StaticDnsResolver,
) -> Result<(), LifecycleError> {
    for (index, override_rule) in policy.overrides.iter().enumerate() {
        for (field, value) in [
            ("allow", override_rule.allow.as_deref()),
            ("deny", override_rule.deny.as_deref()),
            ("approval", override_rule.approval.as_deref()),
        ] {
            if let Some(raw) = value {
                if raw.starts_with("http://") || raw.starts_with("https://") || raw.starts_with("ssh+http://") {
                    validate_blueprint_url(
                        &format!("policy.overrides[{index}].{field}"),
                        raw,
                        resolver,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_blueprint_url(
    path: &str,
    raw: &str,
    resolver: &StaticDnsResolver,
) -> Result<(), LifecycleError> {
    let url = url::Url::parse(raw).map_err(|_| LifecycleError::SsrfBlocked {
        path: path.to_owned(),
        source: SsrfBlocked {
            url: raw.to_owned(),
            host: None,
            resolved_ip: None,
            reason: crate::security::ssrf::SsrfBlockReason::MalformedRedirect {
                location: raw.to_owned(),
            },
        },
    })?;
    validate_outbound_with_resolver(&url, SsrfOptions::default(), resolver).map_err(|source| {
        LifecycleError::SsrfBlocked {
            path: path.to_owned(),
            source,
        }
    })?;
    Ok(())
}

fn nested_string<'a>(map: &'a BTreeMap<String, Value>, path: &[&str]) -> Option<&'a str> {
    let mut current = map.get(path[0])?;
    for segment in &path[1..] {
        current = current.get(*segment)?;
    }
    current.as_str()
}
```

- [ ] **Step 4: Run blueprint and existing lifecycle tests**

Run:

```bash
cargo test -p agentenv-core --test blueprint_ssrf
cargo test -p agentenv-core --test reference_blueprints
cargo test -p agentenv-core --test roundtrip
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/lifecycle.rs crates/agentenv-core/tests/blueprint_ssrf.rs
git commit -m "feat: validate blueprint outbound urls"
```

## Task 4: MCP Endpoint Adapter

**Files:**
- Modify: `crates/agentenv-mcp/Cargo.toml`
- Replace: `crates/agentenv-mcp/src/lib.rs`

- [ ] **Step 1: Write failing MCP adapter tests**

Replace `crates/agentenv-mcp/src/lib.rs` with:

```rust
#![forbid(unsafe_code)]

use agentenv_core::security::ssrf::{
    validate_outbound_with_resolver, DnsResolver, SsrfBlocked, SsrfOptions, ValidatedUrl,
};
use agentenv_proto::{McpEndpoint, McpTransport};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMcpEndpoint {
    pub endpoint: McpEndpoint,
    pub validated_url: Option<ValidatedUrl>,
}

pub fn validate_mcp_endpoint(
    endpoint: &McpEndpoint,
    opts: SsrfOptions,
    resolver: &dyn DnsResolver,
) -> Result<ValidatedMcpEndpoint, SsrfBlocked> {
    match endpoint.transport {
        McpTransport::Stdio => Ok(ValidatedMcpEndpoint {
            endpoint: endpoint.clone(),
            validated_url: None,
        }),
        McpTransport::Http | McpTransport::HttpSse | McpTransport::SshHttp => {
            let url = Url::parse(&endpoint.url).map_err(|_| SsrfBlocked {
                url: endpoint.url.clone(),
                host: None,
                resolved_ip: None,
                reason: agentenv_core::security::ssrf::SsrfBlockReason::MalformedRedirect {
                    location: endpoint.url.clone(),
                },
            })?;
            let validated_url = validate_outbound_with_resolver(&url, opts, resolver)?;
            Ok(ValidatedMcpEndpoint {
                endpoint: endpoint.clone(),
                validated_url: Some(validated_url),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_core::security::ssrf::{
        StaticDnsResolver, SsrfBlockReason, SsrfOptions,
    };
    use agentenv_proto::{McpEndpoint, McpTransport};

    use super::validate_mcp_endpoint;

    fn endpoint(url: &str, transport: McpTransport) -> McpEndpoint {
        McpEndpoint {
            url: url.to_owned(),
            transport,
            headers: BTreeMap::new(),
        }
    }

    #[test]
    fn stdio_endpoint_skips_ssrf_validation() {
        let endpoint = endpoint("stdio://context", McpTransport::Stdio);
        let resolver = StaticDnsResolver::default();

        let validated =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap();

        assert!(validated.validated_url.is_none());
    }

    #[test]
    fn http_sse_endpoint_is_validated_and_pinned() {
        let endpoint = endpoint("https://mcp.example.com/sse", McpTransport::HttpSse);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["93.184.216.34"])]).unwrap();

        let validated =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap();

        assert_eq!(
            validated.validated_url.unwrap().pinned_ips,
            vec!["93.184.216.34".parse().unwrap()]
        );
    }

    #[test]
    fn ssh_http_requires_opt_in() {
        let endpoint = endpoint("ssh+http://mcp.example.com/sse", McpTransport::SshHttp);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["93.184.216.34"])]).unwrap();

        let blocked =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap_err();

        assert!(matches!(
            blocked.reason,
            SsrfBlockReason::UnsupportedScheme { ref scheme } if scheme == "ssh+http"
        ));
    }

    #[test]
    fn ssh_http_validates_when_opted_in() {
        let endpoint = endpoint("ssh+http://mcp.example.com/sse", McpTransport::SshHttp);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["93.184.216.34"])]).unwrap();
        let options = SsrfOptions {
            allow_ssh_http: true,
            ..SsrfOptions::default()
        };

        let validated = validate_mcp_endpoint(&endpoint, options, &resolver).unwrap();

        assert_eq!(validated.validated_url.unwrap().host, "mcp.example.com");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail because dependencies are missing**

Run:

```bash
cargo test -p agentenv-mcp
```

Expected: FAIL with unresolved crates.

- [ ] **Step 3: Add MCP dependencies**

In `crates/agentenv-mcp/Cargo.toml`, add:

```toml
[dependencies]
agentenv-core = { path = "../agentenv-core" }
agentenv-proto = { path = "../agentenv-proto" }
url.workspace = true
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:

```bash
cargo test -p agentenv-mcp
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-mcp/Cargo.toml crates/agentenv-mcp/src/lib.rs
git commit -m "feat: validate mcp endpoint urls"
```

## Task 5: Credential Curl-Probe SSRF Guard and Pinned Request

**Files:**
- Modify: `crates/agentenv-credstore/Cargo.toml`
- Modify: `crates/agentenv-credstore/src/lib.rs`

- [ ] **Step 1: Add failing credential test**

Append to the existing `#[cfg(test)] mod tests` in `crates/agentenv-credstore/src/lib.rs`:

```rust
    #[test]
    fn curl_probe_validator_blocks_metadata_url_before_http_send() {
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        let mut store = test_store(keyring, &temp_dir);
        store
            .write_to_file("OPENAI_API_KEY", &SecretString::new("sk-test"))
            .expect("write credential");

        let requirement = CredentialRequirement {
            name: "OPENAI_API_KEY".to_owned(),
            kind: CredentialKind::ApiKey,
            required: true,
            description: "probe must not reach metadata".to_owned(),
            validator: Some(ValidatorSpec::CurlProbe {
                url: "http://169.254.169.254/latest/meta-data/".to_owned(),
            }),
        };

        let error = store
            .resolve("OPENAI_API_KEY", &requirement)
            .expect_err("metadata probe must be blocked before send");

        assert!(matches!(
            error,
            CredentialStoreError::ValidatorProbeBlocked { name, .. } if name == "OPENAI_API_KEY"
        ));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
cargo test -p agentenv-credstore curl_probe_validator_blocks_metadata_url_before_http_send
```

Expected: FAIL because `ValidatorProbeBlocked` is missing.

- [ ] **Step 3: Add dependencies and error variant**

In `crates/agentenv-credstore/Cargo.toml`, add:

```toml
agentenv-core = { path = "../agentenv-core" }
url.workspace = true
```

In `crates/agentenv-credstore/src/lib.rs`, add imports:

```rust
use std::net::SocketAddr;

use agentenv_core::security::ssrf::{
    validate_outbound, SsrfBlocked, SsrfOptions, ValidatedUrl,
};
```

Add this variant to `CredentialStoreError`:

```rust
    #[error("curl probe validator for `{name}` was blocked by SSRF validation: {source:?}")]
    ValidatorProbeBlocked {
        name: String,
        #[source]
        source: SsrfBlocked,
    },
```

- [ ] **Step 4: Replace curl-probe send logic**

Replace the `ValidatorSpec::CurlProbe { url }` branch in `CredentialStore::validate` with:

```rust
                ValidatorSpec::CurlProbe { url } => {
                    let url = url::Url::parse(url).map_err(|_| {
                        CredentialStoreError::Validation {
                            name: name.to_owned(),
                            reason: "curl probe URL is not a valid URL".to_owned(),
                        }
                    })?;
                    let validated = validate_outbound(&url, SsrfOptions::default()).map_err(
                        |source| CredentialStoreError::ValidatorProbeBlocked {
                            name: name.to_owned(),
                            source,
                        },
                    )?;
                    let response = send_pinned_probe(&validated, secret).map_err(|source| {
                        CredentialStoreError::ValidatorProbeRequest {
                            name: name.to_owned(),
                            source,
                        }
                    })?;

                    if !response.status().is_success() {
                        return Err(CredentialStoreError::ValidatorProbeStatus {
                            name: name.to_owned(),
                            status: response.status(),
                        });
                    }
                }
```

Add this helper near `CredentialStore::validate`:

```rust
fn send_pinned_probe(
    validated: &ValidatedUrl,
    secret: &SecretString,
) -> std::result::Result<reqwest::blocking::Response, reqwest::Error> {
    let port = validated.url.port_or_known_default().unwrap_or(80);
    let addrs: Vec<SocketAddr> = validated
        .pinned_ips
        .iter()
        .map(|ip| SocketAddr::new(*ip, port))
        .collect();
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&validated.host, &addrs)
        .build()?;

    client
        .get(validated.url.clone())
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", secret.expose_secret()),
        )
        .send()
}
```

- [ ] **Step 5: Run the credential tests**

Run:

```bash
cargo test -p agentenv-credstore curl_probe_validator_blocks_metadata_url_before_http_send
cargo test -p agentenv-credstore regex_validator_rejects_non_matching_value
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-credstore/Cargo.toml crates/agentenv-credstore/src/lib.rs
git commit -m "feat: block unsafe credential probe urls"
```

## Task 6: Redirect Chain Validation

**Files:**
- Modify: `crates/agentenv-core/src/security/ssrf.rs`
- Modify: `crates/agentenv-core/tests/ssrf_validator.rs`

- [ ] **Step 1: Add failing redirect tests**

Append to `crates/agentenv-core/tests/ssrf_validator.rs`:

```rust
use agentenv_core::security::ssrf::validate_redirect_chain_with_resolver;

#[test]
fn redirect_chain_revalidates_each_location() {
    let resolver = StaticDnsResolver::try_from_pairs([
        ("start.example.com", ["93.184.216.34"]),
        ("next.example.com", ["93.184.216.35"]),
    ])
    .unwrap();
    let start = Url::parse("https://start.example.com/download").unwrap();

    let chain = validate_redirect_chain_with_resolver(
        &start,
        &["https://next.example.com/final"],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap();

    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].host, "next.example.com");
}

#[test]
fn redirect_chain_blocks_metadata_location() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("start.example.com", ["93.184.216.34"])]).unwrap();
    let start = Url::parse("https://start.example.com/download").unwrap();

    let error = validate_redirect_chain_with_resolver(
        &start,
        &["http://169.254.169.254/latest/meta-data/"],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
}

#[test]
fn redirect_chain_enforces_default_limit() {
    let resolver = StaticDnsResolver::try_from_pairs([
        ("one.example.com", ["93.184.216.31"]),
        ("two.example.com", ["93.184.216.32"]),
        ("three.example.com", ["93.184.216.33"]),
        ("four.example.com", ["93.184.216.34"]),
        ("five.example.com", ["93.184.216.35"]),
    ])
    .unwrap();
    let start = Url::parse("https://one.example.com/").unwrap();

    let error = validate_redirect_chain_with_resolver(
        &start,
        &[
            "https://two.example.com/",
            "https://three.example.com/",
            "https://four.example.com/",
            "https://five.example.com/",
        ],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::RedirectLimitExceeded { max_redirects: 3 }
    ));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p agentenv-core --test ssrf_validator redirect_chain
```

Expected: FAIL because `validate_redirect_chain_with_resolver` does not exist.

- [ ] **Step 3: Implement redirect chain validation**

Add this function to `crates/agentenv-core/src/security/ssrf.rs`:

```rust
pub fn validate_redirect_chain_with_resolver(
    start: &Url,
    locations: &[&str],
    opts: SsrfOptions,
    resolver: &dyn DnsResolver,
) -> Result<Vec<ValidatedUrl>, SsrfBlocked> {
    let mut chain = Vec::with_capacity(locations.len() + 1);
    let first = validate_outbound_with_resolver(start, opts.clone(), resolver)?;
    chain.push(first);

    if locations.len() > opts.max_redirects {
        return Err(block(
            start,
            start.host_str().map(ToOwned::to_owned),
            None,
            SsrfBlockReason::RedirectLimitExceeded {
                max_redirects: opts.max_redirects,
            },
        ));
    }

    let mut current = start.clone();
    for location in locations {
        let next = current.join(location).map_err(|_| {
            block(
                &current,
                current.host_str().map(ToOwned::to_owned),
                None,
                SsrfBlockReason::MalformedRedirect {
                    location: (*location).to_owned(),
                },
            )
        })?;
        let validated = validate_outbound_with_resolver(&next, opts.clone(), resolver)?;
        current = next;
        chain.push(validated);
    }

    Ok(chain)
}
```

- [ ] **Step 4: Run the redirect tests**

Run:

```bash
cargo test -p agentenv-core --test ssrf_validator redirect_chain
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/security/ssrf.rs crates/agentenv-core/tests/ssrf_validator.rs
git commit -m "feat: validate ssrf redirect chains"
```

## Task 7: SSRF Audit Event Conversion

**Files:**
- Modify: `crates/agentenv-events/Cargo.toml`
- Replace: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing event conversion tests**

Replace `crates/agentenv-events/src/lib.rs` with:

```rust
#![forbid(unsafe_code)]

use agentenv_core::security::ssrf::{SsrfBlockReason, SsrfBlocked};
use agentenv_proto::{ActivityEventParams, ActivityKind};

pub fn ssrf_blocked_event(
    blocked: &SsrfBlocked,
    ts: impl Into<String>,
    handle: Option<String>,
) -> ActivityEventParams {
    ActivityEventParams {
        kind: ActivityKind::EgressDenied,
        subject: blocked
            .host
            .clone()
            .unwrap_or_else(|| blocked.url.clone()),
        reason: Some(ssrf_reason_label(&blocked.reason).to_owned()),
        ts: ts.into(),
        handle,
    }
}

fn ssrf_reason_label(reason: &SsrfBlockReason) -> &'static str {
    match reason {
        SsrfBlockReason::UnsupportedScheme { .. } => "unsupported_scheme",
        SsrfBlockReason::MissingHost => "missing_host",
        SsrfBlockReason::CredentialsInUrl => "credentials_in_url",
        SsrfBlockReason::DnsResolutionFailed { .. } => "dns_resolution_failed",
        SsrfBlockReason::DeniedIp { .. } => "denied_ip",
        SsrfBlockReason::DeniedCloudMetadata => "denied_cloud_metadata",
        SsrfBlockReason::DeniedExtraCidr { .. } => "denied_extra_cidr",
        SsrfBlockReason::RedirectLimitExceeded { .. } => "redirect_limit_exceeded",
        SsrfBlockReason::MalformedRedirect { .. } => "malformed_redirect",
        SsrfBlockReason::UnsupportedDnsResolver { .. } => "unsupported_dns_resolver",
    }
}

#[cfg(test)]
mod tests {
    use agentenv_core::security::ssrf::{SsrfBlockReason, SsrfBlocked};
    use agentenv_proto::ActivityKind;

    use super::ssrf_blocked_event;

    #[test]
    fn blocked_ssrf_decision_becomes_egress_denied_event() {
        let blocked = SsrfBlocked {
            url: "http://169.254.169.254/".to_owned(),
            host: Some("169.254.169.254".to_owned()),
            resolved_ip: Some("169.254.169.254".parse().unwrap()),
            reason: SsrfBlockReason::DeniedCloudMetadata,
        };

        let event = ssrf_blocked_event(&blocked, "2026-04-19T00:00:00Z", Some("env-1".to_owned()));

        assert_eq!(event.kind, ActivityKind::EgressDenied);
        assert_eq!(event.subject, "169.254.169.254");
        assert_eq!(event.reason.as_deref(), Some("denied_cloud_metadata"));
        assert_eq!(event.handle.as_deref(), Some("env-1"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail because dependencies are missing**

Run:

```bash
cargo test -p agentenv-events
```

Expected: FAIL with unresolved crates.

- [ ] **Step 3: Add events dependencies**

In `crates/agentenv-events/Cargo.toml`, add:

```toml
[dependencies]
agentenv-core = { path = "../agentenv-core" }
agentenv-proto = { path = "../agentenv-proto" }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:

```bash
cargo test -p agentenv-events
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs
git commit -m "feat: emit ssrf block activity events"
```

## Task 8: Workspace Integration and CLI Regression Coverage

**Files:**
- Modify only files needed to fix compiler, formatting, lint, or regression issues found by this task.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits 0.

- [ ] **Step 2: Run focused crate tests**

Run:

```bash
cargo test -p agentenv-core
cargo test -p agentenv-mcp
cargo test -p agentenv-credstore
cargo test -p agentenv-events
```

Expected: all commands exit 0.

- [ ] **Step 3: Run CLI behavior tests**

Run:

```bash
cargo test -p agentenv --test cli_behavior
```

Expected: PASS. If a blueprint now fails because an internal example hostname is not in the static resolver fixture, add that hostname to `validate_blueprint_urls` test resolver with a public documentation-safe IP such as `93.184.216.34`.

- [ ] **Step 4: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: PASS.

- [ ] **Step 5: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 6: Commit integration fixes**

If Step 1 through Step 5 required edits, run:

```bash
git add Cargo.toml crates
git commit -m "fix: polish ssrf workspace integration"
```

If no edits were needed, record that no commit was created for this task.

## Task 9: Acceptance Review

**Files:**
- Modify: `docs/superpowers/plans/2026-04-19-m5-5-ssrf-validation.md` only if execution notes need correction.

- [ ] **Step 1: Confirm central validator calls**

Run:

```bash
rg -n "validate_outbound|validate_outbound_with_resolver|validate_redirect_chain_with_resolver" crates
```

Expected: output includes `agentenv-core/src/security/ssrf.rs`, `agentenv-core/src/lifecycle.rs`, `agentenv-mcp/src/lib.rs`, and `agentenv-credstore/src/lib.rs`.

- [ ] **Step 2: Confirm cloud metadata coverage**

Run:

```bash
rg -n "169\\.254\\.169\\.254|DeniedCloudMetadata" crates/agentenv-core crates/agentenv-credstore crates/agentenv-events
```

Expected: output includes validator logic, core tests, credstore test, and event conversion label.

- [ ] **Step 3: Confirm no unsafe library printing was added**

Run:

```bash
rg -n "println!|dbg!" crates/agentenv-core crates/agentenv-mcp crates/agentenv-credstore crates/agentenv-events
```

Expected: no output.

- [ ] **Step 4: Commit plan status only if this file changed**

```bash
git add docs/superpowers/plans/2026-04-19-m5-5-ssrf-validation.md
git commit -m "docs: update ssrf implementation plan notes"
```
