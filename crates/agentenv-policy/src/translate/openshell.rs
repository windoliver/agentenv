use std::collections::BTreeMap;

use agentenv_proto::{HttpAccessLevel, NetworkPolicy, NetworkRule, NetworkTarget};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenShellTranslator {
    binary_paths: Vec<String>,
}

impl OpenShellTranslator {
    pub fn new<I, S>(binary_paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            binary_paths: binary_paths.into_iter().map(Into::into).collect(),
        }
    }
}

impl super::PolicyTranslator for OpenShellTranslator {
    fn translate(&self, policy: &NetworkPolicy) -> crate::PolicyResult<super::TranslatedPolicy> {
        reject_unsupported_process(policy)?;
        reject_direct_dns_bypass(policy)?;
        reject_unsupported_network_rules(policy)?;

        let document = OpenShellDocument {
            version: 1,
            filesystem_policy: FilesystemPolicyDocument {
                include_workdir: true,
                read_only: openshell_filesystem_paths(
                    &policy.filesystem.read_only,
                    &policy.process.run_as_user,
                )?,
                read_write: openshell_filesystem_paths(
                    &policy.filesystem.read_write,
                    &policy.process.run_as_user,
                )?,
            },
            landlock: LandlockDocument {
                compatibility: "best_effort",
            },
            process: ProcessDocument {
                run_as_user: policy.process.run_as_user.clone(),
                run_as_group: policy.process.run_as_group.clone(),
            },
            network_policies: build_network_policies(
                &policy.network.allow,
                &policy.network.approval_required,
                &self.binary_paths,
            )?,
        };

        let policy_yaml = serde_yaml::to_string(&document).map_err(|err| {
            crate::PolicyError::TranslationUnsupported {
                translator: "openshell",
                message: err.to_string(),
            }
        })?;

        Ok(super::TranslatedPolicy {
            format: "openshell",
            policy_yaml,
            inference_update: policy
                .inference
                .routes
                .first()
                .map(|route| super::InferenceUpdate {
                    provider: route.provider.clone(),
                    model: route.model.clone(),
                    timeout_seconds: route.timeout_seconds,
                }),
        })
    }
}

fn openshell_filesystem_paths(
    paths: &[String],
    run_as_user: &str,
) -> crate::PolicyResult<Vec<String>> {
    paths
        .iter()
        .map(|path| openshell_filesystem_path(path, run_as_user))
        .collect()
}

fn openshell_filesystem_path(path: &str, run_as_user: &str) -> crate::PolicyResult<String> {
    if path == "$HOME" {
        return openshell_home_path(run_as_user);
    }
    if let Some(rest) = path.strip_prefix("$HOME/") {
        return Ok(format!("{}/{}", openshell_home_path(run_as_user)?, rest));
    }
    Ok(path.to_owned())
}

fn openshell_home_path(run_as_user: &str) -> crate::PolicyResult<String> {
    let user = run_as_user.trim();
    if user.is_empty() || matches!(user, "root" | "0") {
        return Ok("/root".to_owned());
    }
    if user
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return Ok(format!("/home/{user}"));
    }

    Err(crate::PolicyError::TranslationUnsupported {
        translator: "openshell",
        message: format!("unsupported run_as_user for $HOME filesystem path: {run_as_user}"),
    })
}

fn reject_unsupported_process(policy: &NetworkPolicy) -> crate::PolicyResult<()> {
    if !policy.process.profile.is_empty()
        && !matches!(
            policy.process.profile.as_str(),
            "restricted" | "balanced" | "open"
        )
    {
        return Err(crate::PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!(
                "unsupported process.profile value: {}",
                policy.process.profile
            ),
        });
    }

    if !policy.process.allow_syscalls.is_empty() {
        return Err(crate::PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!(
                "unsupported process.allow_syscalls values: {:?}",
                policy.process.allow_syscalls
            ),
        });
    }

    if !policy.process.deny_syscalls.is_empty() {
        return Err(crate::PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!(
                "unsupported process.deny_syscalls values: {:?}",
                policy.process.deny_syscalls
            ),
        });
    }

    Ok(())
}

fn reject_unsupported_network_rules(policy: &NetworkPolicy) -> crate::PolicyResult<()> {
    if let Some(rule) = policy.network.deny.first() {
        return Err(unsupported_rule("deny", rule));
    }

    Ok(())
}

fn reject_direct_dns_bypass(policy: &NetworkPolicy) -> crate::PolicyResult<()> {
    if !policy.network.dns.is_active() {
        return Ok(());
    }

    let doh_hosts = direct_doh_bypass_hosts(policy);
    for rule in &policy.network.allow {
        let NetworkTarget::Host {
            host, port, scheme, ..
        } = &rule.target
        else {
            continue;
        };

        if matches!(port, Some(53 | 853)) {
            return Err(crate::PolicyError::TranslationUnsupported {
                translator: "openshell",
                message: format!(
                    "direct DNS/DoT bypass cannot be agent-visible with active DNS policy: {:?}",
                    rule.target
                ),
            });
        }

        if scheme.as_deref() == Some("https")
            && port == &Some(443)
            && doh_hosts
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(host))
        {
            return Err(crate::PolicyError::TranslationUnsupported {
                translator: "openshell",
                message: format!(
                    "direct DoH bypass host cannot be agent-visible with active DNS policy: {host}"
                ),
            });
        }
    }

    Ok(())
}

fn direct_doh_bypass_hosts(policy: &NetworkPolicy) -> Vec<String> {
    let mut hosts = vec![
        "cloudflare-dns.com".to_owned(),
        "dns.google".to_owned(),
        "dns.quad9.net".to_owned(),
    ];
    for endpoint in &policy.network.dns.doh_upstreams_allowed {
        if let Some(host) = https_url_host(endpoint) {
            if !hosts.iter().any(|candidate| candidate == &host) {
                hosts.push(host);
            }
        }
    }
    hosts
}

fn https_url_host(endpoint: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("https://")?;
    if rest.starts_with('[') {
        let (host, _) = rest.split_once(']')?;
        return Some(host.trim_start_matches('[').to_ascii_lowercase());
    }
    let host = rest
        .split(['/', ':'])
        .next()
        .filter(|host| !host.is_empty())?;
    Some(host.to_ascii_lowercase())
}

fn unsupported_rule(kind: &str, rule: &NetworkRule) -> crate::PolicyError {
    crate::PolicyError::TranslationUnsupported {
        translator: "openshell",
        message: format!("unsupported {kind} rule: {:?}", rule.target),
    }
}

fn build_network_policies(
    allow_rules: &[NetworkRule],
    approval_required_rules: &[NetworkRule],
    binary_paths: &[String],
) -> crate::PolicyResult<BTreeMap<String, OpenShellNetworkPolicy>> {
    let mut entries = BTreeMap::new();
    let binaries = build_binaries(binary_paths);
    let mut host_to_key = BTreeMap::new();

    for (index, rule) in allow_rules.iter().enumerate() {
        let (host, endpoint) = build_endpoint(rule)?;
        let key = format!("rule_{index}");
        entries.insert(
            key.clone(),
            OpenShellNetworkPolicy {
                name: format!("rule-{index}"),
                endpoints: vec![endpoint],
                binaries: binaries.clone(),
            },
        );
        host_to_key.insert(host, key);
    }

    for rule in approval_required_rules {
        let (host, deny_rule) = build_deny_rule(rule)?;
        let entry = entries
            .get_mut(host_to_key.get(&host).ok_or_else(|| {
                crate::PolicyError::TranslationUnsupported {
                    translator: "openshell",
                    message: format!("approval_required rule has no matching allow host: {host}"),
                }
            })?)
            .ok_or_else(|| crate::PolicyError::TranslationUnsupported {
                translator: "openshell",
                message: format!("approval_required rule has no matching network policy: {host}"),
            })?;

        entry.endpoints[0].deny_rules.push(deny_rule);
    }

    Ok(entries)
}

fn build_endpoint(rule: &NetworkRule) -> crate::PolicyResult<(String, EndpointDocument)> {
    match &rule.target {
        NetworkTarget::Host {
            host,
            port,
            scheme,
            http_access,
        } => {
            if host == "*" {
                return Err(crate::PolicyError::TranslationUnsupported {
                    translator: "openshell",
                    message: format!("unsupported wildcard host: {:?}", rule.target),
                });
            }

            if scheme.as_deref() != Some("https") {
                return Err(crate::PolicyError::TranslationUnsupported {
                    translator: "openshell",
                    message: format!("unsupported host scheme: {:?}", rule.target),
                });
            }

            if port != &Some(443) {
                return Err(crate::PolicyError::TranslationUnsupported {
                    translator: "openshell",
                    message: format!("unsupported host port: {:?}", rule.target),
                });
            }

            Ok((
                host.clone(),
                endpoint_document(host, http_access.unwrap_or(HttpAccessLevel::ReadOnly)),
            ))
        }
        _ => Err(crate::PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!("unsupported allow rule: {:?}", rule.target),
        }),
    }
}

fn endpoint_document(host: &str, access: HttpAccessLevel) -> EndpointDocument {
    if host == "registry.npmjs.org" && access == HttpAccessLevel::Full {
        return EndpointDocument {
            host: host.to_owned(),
            port: 443,
            protocol: None,
            enforcement: None,
            access: None,
            deny_rules: Vec::new(),
        };
    }

    EndpointDocument {
        host: host.to_owned(),
        port: 443,
        protocol: Some("rest"),
        enforcement: Some("enforce"),
        access: Some(openshell_access(access)),
        deny_rules: Vec::new(),
    }
}

fn build_deny_rule(rule: &NetworkRule) -> crate::PolicyResult<(String, DenyRuleDocument)> {
    match &rule.target {
        NetworkTarget::HttpMethodPath { host, method, path } => {
            let host = host
                .as_ref()
                .ok_or_else(|| crate::PolicyError::TranslationUnsupported {
                    translator: "openshell",
                    message: format!(
                        "approval_required host is required for openshell translation: {:?}",
                        rule.target
                    ),
                })?;

            Ok((
                host.clone(),
                DenyRuleDocument {
                    method: method.clone(),
                    path: path.clone(),
                },
            ))
        }
        _ => Err(crate::PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!("unsupported approval_required rule: {:?}", rule.target),
        }),
    }
}

fn build_binaries(binary_paths: &[String]) -> Vec<BinaryDocument> {
    binary_paths
        .iter()
        .cloned()
        .map(|path| BinaryDocument { path })
        .collect()
}

fn openshell_access(access: HttpAccessLevel) -> &'static str {
    match access {
        HttpAccessLevel::ReadOnly => "read-only",
        HttpAccessLevel::ReadWrite => "read-write",
        HttpAccessLevel::Full => "full",
    }
}

#[derive(Debug, Serialize)]
struct OpenShellDocument {
    version: u8,
    filesystem_policy: FilesystemPolicyDocument,
    landlock: LandlockDocument,
    process: ProcessDocument,
    network_policies: BTreeMap<String, OpenShellNetworkPolicy>,
}

#[derive(Debug, Serialize)]
struct FilesystemPolicyDocument {
    include_workdir: bool,
    read_only: Vec<String>,
    read_write: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LandlockDocument {
    compatibility: &'static str,
}

#[derive(Debug, Serialize)]
struct ProcessDocument {
    run_as_user: String,
    run_as_group: String,
}

#[derive(Debug, Clone, Serialize)]
struct OpenShellNetworkPolicy {
    name: String,
    endpoints: Vec<EndpointDocument>,
    binaries: Vec<BinaryDocument>,
}

#[derive(Debug, Clone, Serialize)]
struct EndpointDocument {
    host: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enforcement: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny_rules: Vec<DenyRuleDocument>,
}

#[derive(Debug, Clone, Serialize)]
struct DenyRuleDocument {
    method: String,
    path: String,
}

#[derive(Debug, Clone, Serialize)]
struct BinaryDocument {
    path: String,
}
