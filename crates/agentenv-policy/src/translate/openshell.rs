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
        reject_unsupported_network_rules(policy)?;

        let document = OpenShellDocument {
            version: 1,
            filesystem_policy: FilesystemPolicyDocument {
                include_workdir: true,
                read_only: policy.filesystem.read_only.clone(),
                read_write: policy.filesystem.read_write.clone(),
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
                EndpointDocument {
                    host: host.clone(),
                    port: 443,
                    protocol: "rest",
                    enforcement: "enforce",
                    access: openshell_access(http_access.unwrap_or(HttpAccessLevel::ReadOnly)),
                    deny_rules: Vec::new(),
                },
            ))
        }
        _ => Err(crate::PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!("unsupported allow rule: {:?}", rule.target),
        }),
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
    protocol: &'static str,
    enforcement: &'static str,
    access: &'static str,
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
