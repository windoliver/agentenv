use std::{
    collections::BTreeMap,
    net::{AddrParseError, IpAddr, Ipv6Addr, ToSocketAddrs},
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
        return IPV6_RESERVED_NETS_PARSED.iter().any(|net| net.contains(&ip));
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
