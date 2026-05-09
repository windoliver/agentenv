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
}
