use std::collections::BTreeMap;

use agentenv_proto::{NetworkPolicy, NetworkRule, NetworkTarget};
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
            network_policies: build_network_policies(&policy.network.allow, &self.binary_paths)?,
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
    if !policy.process.profile.is_empty() {
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

    if let Some(rule) = policy.network.approval_required.first() {
        return Err(unsupported_rule("approval_required", rule));
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
    binary_paths: &[String],
) -> crate::PolicyResult<BTreeMap<String, OpenShellNetworkPolicy>> {
    let mut entries = BTreeMap::new();
    let binaries = build_binaries(binary_paths);

    for (index, rule) in allow_rules.iter().enumerate() {
        let endpoint = build_endpoint(rule)?;
        entries.insert(
            format!("rule_{index}"),
            OpenShellNetworkPolicy {
                name: format!("rule-{index}"),
                endpoints: vec![endpoint],
                binaries: binaries.clone(),
            },
        );
    }

    Ok(entries)
}

fn build_endpoint(rule: &NetworkRule) -> crate::PolicyResult<EndpointDocument> {
    match &rule.target {
        NetworkTarget::Host { host, port, scheme } => {
            if host == "*" {
                return Err(crate::PolicyError::TranslationUnsupported {
                    translator: "openshell",
                    message: format!("unsupported wildcard host: {:?}", rule.target),
                });
            }

            if matches!(scheme.as_deref(), Some(value) if value != "https") {
                return Err(crate::PolicyError::TranslationUnsupported {
                    translator: "openshell",
                    message: format!("unsupported host scheme: {:?}", rule.target),
                });
            }

            Ok(EndpointDocument {
                host: host.clone(),
                port: port.unwrap_or(443),
                protocol: "rest",
                enforcement: "enforce",
                access: "read-only",
            })
        }
        _ => Err(crate::PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!("unsupported allow rule: {:?}", rule.target),
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
}

#[derive(Debug, Clone, Serialize)]
struct BinaryDocument {
    path: String,
}
