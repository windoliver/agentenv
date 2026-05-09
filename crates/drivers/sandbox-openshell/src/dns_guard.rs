use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::LazyLock,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use ipnet::IpNet;
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

#[async_trait]
pub trait DnsUpstreamClient {
    async fn resolve(
        &mut self,
        query_name: &str,
        qtype: &str,
    ) -> Result<DnsAnswerSet, DnsGuardRuntimeError>;
}

#[derive(Debug, Error)]
pub enum DnsGuardRuntimeError {
    #[error("DNS upstream query failed: {message}")]
    Upstream { message: String },
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
            agentenv_proto::NetworkTarget::Host { host, .. } if host != "*" => {
                Some(normalize_dns_name(host))
            }
            _ => None,
        })
        .collect()
}

fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
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

pub fn is_denied_answer_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_private()
                || RESERVED_NETS_PARSED.iter().any(|net| net.contains(&ip))
        }
        IpAddr::V6(ipv6) => {
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                return is_denied_answer_ip(IpAddr::V4(ipv4));
            }
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.is_multicast()
                || IPV6_DENIED_NETS_PARSED.iter().any(|net| net.contains(&ip))
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

const IPV6_DENIED_NETS: &[&str] = &[
    "fe80::/10",
    "fc00::/7",
    "2001:db8::/32",
    "::/128",
    "100::/64",
    "2001:2::/48",
];

static RESERVED_NETS_PARSED: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| parse_cidrs(RESERVED_NETS, "reserved"));
static IPV6_DENIED_NETS_PARSED: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| parse_cidrs(IPV6_DENIED_NETS, "ipv6_denied"));

fn parse_cidrs(cidrs: &[&str], context: &str) -> Vec<IpNet> {
    cidrs
        .iter()
        .map(|cidr| match cidr.parse::<IpNet>() {
            Ok(net) => net,
            Err(error) => panic!("invalid {context} DNS guard CIDR `{cidr}`: {error}"),
        })
        .collect()
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
    async fn resolve(
        &mut self,
        query_name: &str,
        qtype: &str,
    ) -> Result<DnsAnswerSet, DnsGuardRuntimeError> {
        self.queries.push((query_name.to_owned(), qtype.to_owned()));
        Ok(self.answer.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentenv_proto::{
        DnsPolicy, FilesystemPolicy, HttpAccessLevel, InferencePolicy, NetworkAccessPolicy,
        NetworkPolicy, NetworkRule, NetworkTarget, PolicyReloadability, ProcessPolicy,
    };

    #[test]
    fn guard_config_contains_dns_upstreams_and_allowed_query_names() {
        let policy = sample_dns_policy();
        let config = DnsGuardConfig::from_policy("devbox", &policy)
            .expect("guard config")
            .expect("active dns config");

        assert_eq!(config.sandbox_handle, "devbox");
        assert_eq!(config.resolvers_allowed, vec!["1.1.1.1"]);
        assert_eq!(
            config.doh_upstreams_allowed,
            vec!["https://dns.google/dns-query"]
        );
        assert_eq!(config.dot_upstreams_allowed, vec!["1.1.1.1:853"]);
        assert!(config.allowed_query_names.contains("api.github.com"));
        assert!(config.log_all_queries);
        assert!(config.pin_resolved_ips);
    }

    #[test]
    fn guard_config_normalizes_policy_query_names_once() {
        let mut policy = sample_dns_policy();
        let NetworkTarget::Host { host, .. } = &mut policy.network.allow[0].target else {
            panic!("sample policy host target");
        };
        *host = "API.GitHub.COM.".to_owned();

        let config = DnsGuardConfig::from_policy("devbox", &policy)
            .expect("guard config")
            .expect("active dns config");

        assert!(config.allowed_query_names.contains("api.github.com"));
        assert_eq!(
            classify_query(&config, "api.github.com", "A").action,
            DnsQueryAction::Allow
        );
    }

    #[test]
    fn guard_config_rejects_empty_active_policy_without_upstream() {
        let mut policy = sample_dns_policy();
        policy.network.dns.resolvers_allowed.clear();
        policy.network.dns.doh_upstreams_allowed.clear();
        policy.network.dns.dot_upstreams_allowed.clear();

        let err = DnsGuardConfig::from_policy("devbox", &policy)
            .expect_err("active policy needs upstream");

        assert!(err.to_string().contains("at least one DNS upstream"));
    }

    #[test]
    fn guard_config_returns_none_for_inactive_dns_policy() {
        let mut policy = sample_dns_policy();
        policy.network.dns = DnsPolicy::default();

        let config = DnsGuardConfig::from_policy("devbox", &policy).expect("guard config");

        assert!(config.is_none());
    }

    #[test]
    fn query_name_outside_allowlist_is_denied() {
        let config = config_with_allowed_names(["api.github.com"]);

        let decision = classify_query(&config, "secret.attacker.example", "A");

        assert_eq!(decision.action, DnsQueryAction::Deny);
        assert_eq!(decision.reason_code, Some("dns_query_not_allowed"));
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
        assert_eq!(decision.reason_code, Some("dns_answer_denied"));
    }

    #[test]
    fn ipv6_ula_answer_is_denied() {
        let config = config_with_allowed_names(["api.github.com"]);
        let answer = answer_with_ip("api.github.com", "AAAA", "fd00::1");

        let decision = classify_answer(&config, answer);

        assert_eq!(decision.action, DnsQueryAction::Deny);
        assert_eq!(decision.reason_code, Some("dns_answer_denied"));
    }

    #[test]
    fn ipv6_link_local_answer_is_denied() {
        let config = config_with_allowed_names(["api.github.com"]);
        let answer = answer_with_ip("api.github.com", "AAAA", "fe80::1");

        let decision = classify_answer(&config, answer);

        assert_eq!(decision.action, DnsQueryAction::Deny);
        assert_eq!(decision.reason_code, Some("dns_answer_denied"));
    }

    #[test]
    fn ipv4_mapped_ipv6_private_answer_is_denied() {
        let config = config_with_allowed_names(["api.github.com"]);
        let answer = answer_with_ip("api.github.com", "AAAA", "::ffff:10.0.0.1");

        let decision = classify_answer(&config, answer);

        assert_eq!(decision.action, DnsQueryAction::Deny);
        assert_eq!(decision.reason_code, Some("dns_answer_denied"));
    }

    #[test]
    fn ipv4_documentation_and_cgnat_answers_are_denied() {
        let config = config_with_allowed_names(["api.github.com"]);

        for ip in ["192.0.2.1", "100.64.0.1"] {
            let answer = answer_with_ip("api.github.com", "A", ip);

            let decision = classify_answer(&config, answer);

            assert_eq!(
                decision.action,
                DnsQueryAction::Deny,
                "{ip} should be denied"
            );
            assert_eq!(decision.reason_code, Some("dns_answer_denied"));
        }
    }

    #[test]
    fn pinned_answer_allows_matching_connection_and_blocks_mismatch() {
        let mut pins = DnsPinStore::default();
        pins.record("api.github.com", ["93.184.216.34".parse().expect("ip")], 60);

        assert!(pins.connection_allowed("api.github.com", "93.184.216.34".parse().expect("ip")));
        assert!(!pins.connection_allowed("api.github.com", "93.184.216.35".parse().expect("ip")));
    }

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

        assert_eq!(
            client.queries,
            vec![("api.github.com".to_owned(), "A".to_owned())]
        );
        assert_eq!(
            answer.ips,
            vec!["93.184.216.34".parse::<IpAddr>().expect("ip")]
        );
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

    fn sample_dns_policy() -> NetworkPolicy {
        NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: vec![NetworkRule {
                    target: NetworkTarget::Host {
                        host: "api.github.com".to_owned(),
                        port: Some(443),
                        scheme: Some("https".to_owned()),
                        http_access: Some(HttpAccessLevel::ReadOnly),
                    },
                }],
                deny: Vec::new(),
                approval_required: Vec::new(),
                dns: DnsPolicy {
                    resolvers_allowed: vec!["1.1.1.1".to_owned()],
                    doh_upstreams_allowed: vec!["https://dns.google/dns-query".to_owned()],
                    dot_upstreams_allowed: vec!["1.1.1.1:853".to_owned()],
                    log_all_queries: true,
                    pin_resolved_ips: true,
                },
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
                profile: "balanced".to_owned(),
                allow_syscalls: Vec::new(),
                deny_syscalls: Vec::new(),
            },
            inference: InferencePolicy {
                reloadability: PolicyReloadability::HotReload,
                routes: Vec::new(),
            },
        }
    }

    fn config_with_allowed_names<const N: usize>(names: [&str; N]) -> DnsGuardConfig {
        DnsGuardConfig {
            sandbox_handle: "devbox".to_owned(),
            listen_addr: "127.0.0.1:1053".to_owned(),
            resolvers_allowed: vec!["1.1.1.1".to_owned()],
            doh_upstreams_allowed: Vec::new(),
            dot_upstreams_allowed: Vec::new(),
            allowed_query_names: names.into_iter().map(str::to_owned).collect(),
            log_all_queries: false,
            pin_resolved_ips: false,
        }
    }

    fn answer_with_ip(query_name: &str, qtype: &str, ip: &str) -> DnsAnswerSet {
        DnsAnswerSet {
            query_name: query_name.to_owned(),
            qtype: qtype.to_owned(),
            cname_chain: Vec::new(),
            ips: vec![ip.parse().expect("ip")],
            ttl_seconds: 60,
        }
    }
}
