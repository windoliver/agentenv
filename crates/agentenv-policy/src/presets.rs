use std::collections::BTreeMap;

use agentenv_proto::{HttpAccessLevel, NetworkRule, NetworkTarget};
use once_cell::sync::Lazy;
use serde::Deserialize;

use crate::{model::NetworkPolicy, PolicyError, PolicyResult, PresetAccess, PresetSelection};

static BUILTIN_PRESETS: Lazy<&'static str> = Lazy::new(|| include_str!("../presets/builtin.yaml"));

#[derive(Debug, Deserialize)]
struct PresetFile {
    presets: BTreeMap<String, PresetDefinition>,
}

#[derive(Debug, Deserialize)]
struct PresetDefinition {
    #[serde(default)]
    read: Option<PresetNetworkBlock>,
    #[serde(default, rename = "readwrite")]
    read_write: Option<PresetNetworkBlock>,
}

#[derive(Debug, Default, Deserialize)]
struct PresetNetworkBlock {
    #[serde(default)]
    allow: Vec<PresetRule>,
    #[serde(default)]
    deny: Vec<PresetRule>,
    #[serde(default)]
    approval_required: Vec<PresetRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PresetRule {
    Host {
        host: String,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        scheme: Option<String>,
    },
    Cidr {
        cidr: String,
    },
    Port {
        port: u16,
        #[serde(default)]
        protocol: Option<String>,
    },
    UrlPattern {
        pattern: String,
    },
    HttpMethodPath {
        #[serde(default)]
        host: Option<String>,
        method: String,
        path: String,
    },
}

impl PresetRule {
    fn into_network_rule(self, access: PresetAccess) -> NetworkRule {
        let target = match self {
            Self::Host { host, port, scheme } => NetworkTarget::Host {
                host,
                port,
                scheme,
                http_access: Some(match access {
                    PresetAccess::Read => HttpAccessLevel::ReadOnly,
                    PresetAccess::ReadWrite => HttpAccessLevel::ReadWrite,
                }),
            },
            Self::Cidr { cidr } => NetworkTarget::Cidr { cidr },
            Self::Port { port, protocol } => NetworkTarget::Port { port, protocol },
            Self::UrlPattern { pattern } => NetworkTarget::UrlPattern { pattern },
            Self::HttpMethodPath { host, method, path } => {
                NetworkTarget::HttpMethodPath { host, method, path }
            }
        };

        NetworkRule { target }
    }
}

#[derive(Debug)]
pub struct PresetRegistry {
    presets: BTreeMap<String, PresetDefinition>,
}

impl PresetRegistry {
    pub fn load_builtin() -> PolicyResult<Self> {
        let parsed: PresetFile =
            serde_yaml::from_str(*BUILTIN_PRESETS).map_err(|err| PolicyError::PresetRegistry {
                message: err.to_string(),
            })?;

        Ok(Self {
            presets: parsed.presets,
        })
    }

    pub fn merge_into(
        &self,
        policy: &mut NetworkPolicy,
        preset: &PresetSelection,
    ) -> PolicyResult<()> {
        let definition =
            self.presets
                .get(&preset.name)
                .ok_or_else(|| PolicyError::UnknownPreset {
                    name: preset.name.clone(),
                    available: self.presets.keys().cloned().collect::<Vec<_>>().join(", "),
                })?;

        let block = match preset.access {
            PresetAccess::Read => definition.read.as_ref(),
            PresetAccess::ReadWrite => definition.read_write.as_ref(),
        }
        .ok_or_else(|| PolicyError::UnsupportedPresetAccess {
            name: preset.name.clone(),
            access: match preset.access {
                PresetAccess::Read => "read".to_owned(),
                PresetAccess::ReadWrite => "readwrite".to_owned(),
            },
        })?;

        merge_rules(
            &mut policy.network.allow,
            &mut policy.network.approval_required,
            &mut policy.network.deny,
            &block.allow,
            preset.access,
        );
        merge_rules(
            &mut policy.network.approval_required,
            &mut policy.network.allow,
            &mut policy.network.deny,
            &block.approval_required,
            preset.access,
        );
        merge_rules(
            &mut policy.network.deny,
            &mut policy.network.allow,
            &mut policy.network.approval_required,
            &block.deny,
            preset.access,
        );

        Ok(())
    }
}

fn merge_rules(
    target: &mut Vec<NetworkRule>,
    other_a: &mut Vec<NetworkRule>,
    other_b: &mut Vec<NetworkRule>,
    new_rules: &[PresetRule],
    access: PresetAccess,
) {
    for rule in new_rules
        .iter()
        .cloned()
        .map(|rule| rule.into_network_rule(access))
    {
        remove_conflicting_rule(other_a, &rule);
        remove_conflicting_rule(other_b, &rule);
        remove_conflicting_rule(target, &rule);
        target.push(rule);
    }
}

fn remove_conflicting_rule(rules: &mut Vec<NetworkRule>, incoming: &NetworkRule) {
    let incoming_key = rule_sort_key(incoming);
    rules.retain(|rule| rule_sort_key(rule) != incoming_key);
}

fn rule_sort_key(rule: &NetworkRule) -> String {
    match &rule.target {
        NetworkTarget::Host {
            host, port, scheme, ..
        } => format!(
            "host|{}|{}|{}",
            scheme.as_deref().unwrap_or_default(),
            host,
            port.map(|value| value.to_string())
                .as_deref()
                .unwrap_or_default()
        ),
        NetworkTarget::Cidr { cidr } => format!("cidr|{cidr}"),
        NetworkTarget::Port { port, protocol } => {
            format!("port|{}|{port}", protocol.as_deref().unwrap_or_default())
        }
        NetworkTarget::UrlPattern { pattern } => format!("url_pattern|{pattern}"),
        NetworkTarget::HttpMethodPath { host, method, path } => format!(
            "http_method_path|{}|{}|{}",
            host.as_deref().unwrap_or_default(),
            method,
            path
        ),
    }
}
