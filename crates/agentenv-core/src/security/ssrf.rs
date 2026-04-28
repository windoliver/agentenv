use std::{
    collections::BTreeMap,
    net::{AddrParseError, IpAddr, Ipv6Addr, ToSocketAddrs},
};

use ipnet::IpNet;
use thiserror::Error;
use url::{Host, Url};

use agentenv_events::{ActivityEvent, ActivityKind, ActivityResult};

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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("outbound URL `{url}` was blocked")]
pub struct SsrfBlocked {
    pub url: String,
    pub host: Option<String>,
    pub resolved_ip: Option<IpAddr>,
    pub reason: SsrfBlockReason,
}

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

pub fn sanitize_untrusted_url_text(raw: &str) -> String {
    sanitize_url_like_text(raw)
}

pub fn ssrf_blocked_activity_event(
    blocked: &SsrfBlocked,
    ts: impl Into<String>,
    handle: Option<String>,
    trace_id: impl Into<String>,
) -> ActivityEvent {
    let target = match blocked.host.as_deref() {
        Some(host) => host.to_owned(),
        None => sanitize_untrusted_url_text(&blocked.url),
    };
    let mut event = ActivityEvent::new(
        ts,
        ActivityKind::EgressDenied,
        ActivityResult::Denied,
        trace_id,
    )
    .with_subject_value("target", serde_json::json!(target))
    .with_reason_code(ssrf_block_reason_label(&blocked.reason));

    if let Some(handle) = handle {
        event = event.with_subject_value("handle", serde_json::json!(handle));
    }

    event
}

fn ssrf_block_reason_label(reason: &SsrfBlockReason) -> &'static str {
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
            .map_err(|_| {
                block(
                    url,
                    Some(host.clone()),
                    None,
                    SsrfBlockReason::DnsResolutionFailed { host: host.clone() },
                )
            })?,
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

pub fn validate_redirect_chain_with_resolver(
    start: &Url,
    locations: &[&str],
    opts: SsrfOptions,
    resolver: &dyn DnsResolver,
) -> Result<Vec<ValidatedUrl>, SsrfBlocked> {
    let mut chain = Vec::with_capacity(locations.len() + 1);
    let start_validated = validate_outbound_with_resolver(start, opts.clone(), resolver)?;
    chain.push(start_validated);

    if locations.len() > opts.max_redirects {
        return Err(block(
            start,
            None,
            None,
            SsrfBlockReason::RedirectLimitExceeded {
                max_redirects: opts.max_redirects,
            },
        ));
    }

    let mut current = start.clone();
    for location in locations.iter().copied() {
        let next = current.join(location).map_err(|_| {
            block(
                &current,
                None,
                None,
                SsrfBlockReason::MalformedRedirect {
                    location: sanitize_malformed_redirect_location(location),
                },
            )
        })?;
        let validated = validate_outbound_with_resolver(&next, opts.clone(), resolver)?;
        current = validated.url.clone();
        chain.push(validated);
    }

    Ok(chain)
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
    let host = url
        .host()
        .ok_or_else(|| block(url, None, None, SsrfBlockReason::MissingHost))?;
    match host {
        Host::Domain(domain) => Ok((domain.to_owned(), None)),
        Host::Ipv4(ip) => Ok((ip.to_string(), Some(IpAddr::V4(ip)))),
        Host::Ipv6(ip) => Ok((ip.to_string(), Some(IpAddr::V6(ip)))),
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        other => other,
    }
}

fn check_ip(url: &Url, host: &str, ip: IpAddr, opts: &SsrfOptions) -> Result<(), SsrfBlocked> {
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
    match ip {
        IpAddr::V4(ip) => CLOUD_METADATA_IPV4_OCTETS
            .iter()
            .any(|octets| ip.octets() == *octets),
        IpAddr::V6(ip) => ip == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x0254),
    }
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

static RESERVED_NETS_PARSED: std::sync::LazyLock<Vec<IpNet>> =
    std::sync::LazyLock::new(|| parse_cidrs(RESERVED_NETS, "reserved"));
static IPV6_LINK_LOCAL_NETS_PARSED: std::sync::LazyLock<Vec<IpNet>> =
    std::sync::LazyLock::new(|| parse_cidrs(IPV6_LINK_LOCAL_NETS, "ipv6_link_local"));
static IPV6_PRIVATE_NETS_PARSED: std::sync::LazyLock<Vec<IpNet>> =
    std::sync::LazyLock::new(|| parse_cidrs(IPV6_PRIVATE_NETS, "ipv6_private"));
static IPV6_DOCUMENTATION_NETS_PARSED: std::sync::LazyLock<Vec<IpNet>> =
    std::sync::LazyLock::new(|| parse_cidrs(IPV6_DOCUMENTATION_NETS, "ipv6_documentation"));
static IPV6_RESERVED_NETS_PARSED: std::sync::LazyLock<Vec<IpNet>> =
    std::sync::LazyLock::new(|| parse_cidrs(IPV6_RESERVED_NETS, "ipv6_reserved"));

fn in_any_net(ip: IpAddr, cidrs: &[&str]) -> bool {
    if std::ptr::eq(cidrs, RESERVED_NETS) {
        return RESERVED_NETS_PARSED.iter().any(|net| net.contains(&ip));
    }
    if std::ptr::eq(cidrs, IPV6_LINK_LOCAL_NETS) {
        return IPV6_LINK_LOCAL_NETS_PARSED
            .iter()
            .any(|net| net.contains(&ip));
    }
    if std::ptr::eq(cidrs, IPV6_PRIVATE_NETS) {
        return IPV6_PRIVATE_NETS_PARSED.iter().any(|net| net.contains(&ip));
    }
    if std::ptr::eq(cidrs, IPV6_DOCUMENTATION_NETS) {
        return IPV6_DOCUMENTATION_NETS_PARSED
            .iter()
            .any(|net| net.contains(&ip));
    }
    if std::ptr::eq(cidrs, IPV6_RESERVED_NETS) {
        return IPV6_RESERVED_NETS_PARSED
            .iter()
            .any(|net| net.contains(&ip));
    }

    for net in parse_cidrs(cidrs, "custom") {
        if net.contains(&ip) {
            return true;
        }
    }
    false
}

fn parse_cidrs(cidrs: &[&str], context: &str) -> Vec<IpNet> {
    let mut parsed = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        match cidr.parse::<IpNet>() {
            Ok(net) => parsed.push(net),
            Err(error) => panic!("invalid {context} SSRF CIDR `{cidr}`: {error}"),
        }
    }
    parsed
}

fn block(
    url: &Url,
    host: Option<String>,
    resolved_ip: Option<IpAddr>,
    reason: SsrfBlockReason,
) -> SsrfBlocked {
    SsrfBlocked {
        url: sanitize_url(url),
        host,
        resolved_ip,
        reason,
    }
}

const CLOUD_METADATA_IPV4_OCTETS: &[[u8; 4]] = &[
    [169, 254, 169, 254],
    [168, 63, 129, 16],
    [100, 100, 100, 200],
];

fn sanitize_url(url: &Url) -> String {
    let mut sanitized = url.clone();

    if sanitized.set_username("").is_err() {
        // ignore; this can fail for hostless URLs and non-hierarchical schemes.
    };
    let _ = sanitized.set_password(None);
    sanitized.set_query(None);
    sanitized.set_fragment(None);

    sanitized.to_string()
}

fn sanitize_url_like_text(raw: &str) -> String {
    let mut sanitized = match raw.find(['?', '#']) {
        Some(index) => raw[..index].to_owned(),
        None => raw.to_owned(),
    };

    let authority_start = if let Some(scheme_end) = sanitized.find("://") {
        Some(scheme_end + "://".len())
    } else if sanitized.starts_with("//") {
        Some("//".len())
    } else {
        None
    };

    if let Some(authority_start) = authority_start {
        let authority_end = sanitized[authority_start..]
            .find('/')
            .map(|index| authority_start + index)
            .unwrap_or(sanitized.len());

        if let Some(at_offset) = sanitized[authority_start..authority_end].rfind('@') {
            let credential_end = authority_start + at_offset + 1;
            sanitized.replace_range(authority_start..credential_end, "");
        }
    }

    sanitized
}

fn sanitize_malformed_redirect_location(location: &str) -> String {
    sanitize_untrusted_url_text(location)
}

#[cfg(test)]
mod tests {
    use agentenv_events::activity::{ActivityEvent, ActivityKind, ActivityResult};
    use serde_json::json;

    use super::{ssrf_blocked_activity_event, SsrfBlockReason, SsrfBlocked};

    #[test]
    fn ssrf_blocked_denied_cloud_metadata_becomes_egress_denied_activity_event() {
        let blocked = SsrfBlocked {
            url: "http://169.254.169.254/latest/meta-data".to_owned(),
            host: Some("169.254.169.254".to_owned()),
            resolved_ip: None,
            reason: SsrfBlockReason::DeniedCloudMetadata,
        };

        let event: ActivityEvent = ssrf_blocked_activity_event(
            &blocked,
            "2026-04-19T12:34:56Z",
            Some("sandbox-123".to_owned()),
            "trace-1",
        );

        assert_eq!(event.kind, ActivityKind::EgressDenied);
        assert_eq!(event.result, ActivityResult::Denied);
        assert_eq!(event.subject["target"], json!("169.254.169.254"));
        assert_eq!(event.subject["handle"], json!("sandbox-123"));
        assert_eq!(event.reason_code, Some("denied_cloud_metadata".to_owned()));
        assert_eq!(event.ts, "2026-04-19T12:34:56Z");
        assert_eq!(event.trace_id, "trace-1");
    }

    #[test]
    fn ssrf_blocked_missing_host_falls_back_to_sanitized_url_subject() {
        let blocked = SsrfBlocked {
            url: "http:///path".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::MissingHost,
        };

        let event = ssrf_blocked_activity_event(&blocked, "2026-04-19T12:34:57Z", None, "trace-2");

        assert_eq!(event.kind, ActivityKind::EgressDenied);
        assert_eq!(event.subject["target"], json!("http:///path"));
        assert_eq!(event.reason_code, Some("missing_host".to_owned()));
        assert_eq!(event.ts, "2026-04-19T12:34:57Z");
        assert!(!event.subject.contains_key("handle"));
    }

    #[test]
    fn ssrf_blocked_credentials_in_url_reason_uses_stable_label() {
        let blocked = SsrfBlocked {
            url: "https://example.test/private".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::CredentialsInUrl,
        };

        let event = ssrf_blocked_activity_event(&blocked, "2026-04-19T12:34:58Z", None, "trace-3");

        assert_eq!(
            event.subject["target"],
            json!("https://example.test/private")
        );
        assert_eq!(event.reason_code, Some("credentials_in_url".to_owned()));
    }

    #[test]
    fn ssrf_blocked_fallback_subject_redacts_credentials_query_and_fragment() {
        let blocked = SsrfBlocked {
            url: "https://user:pass@example.test/private?token=secret#frag".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::CredentialsInUrl,
        };

        let event = ssrf_blocked_activity_event(&blocked, "2026-04-19T12:34:59Z", None, "trace-4");
        let subject = event.subject["target"].as_str().unwrap();

        assert_eq!(subject, "https://example.test/private");
        for redacted in ["user", "pass", "token", "secret", "?", "#"] {
            assert!(
                !subject.contains(redacted),
                "fallback subject leaked `{redacted}` in `{subject}`"
            );
        }
    }

    #[test]
    fn ssrf_blocked_fallback_subject_redacts_scheme_relative_credentials() {
        let blocked = SsrfBlocked {
            url: "//user:pass@example.test/private?token=secret#frag".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::CredentialsInUrl,
        };

        let event = ssrf_blocked_activity_event(&blocked, "2026-04-19T12:35:00Z", None, "trace-5");
        let subject = event.subject["target"].as_str().unwrap();

        assert_eq!(subject, "//example.test/private");
        for redacted in ["user", "pass", "token", "secret", "?", "#"] {
            assert!(
                !subject.contains(redacted),
                "fallback subject leaked `{redacted}` in `{subject}`"
            );
        }
    }
}
