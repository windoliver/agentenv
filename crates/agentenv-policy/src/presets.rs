use std::collections::BTreeMap;

use agentenv_proto::{NetworkRule, NetworkTarget};
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
    fn into_network_rule(self) -> NetworkRule {
        let target = match self {
            Self::Host { host, port, scheme } => NetworkTarget::Host { host, port, scheme },
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
            PresetAccess::ReadWrite => definition.read_write.as_ref().or(definition.read.as_ref()),
        }
        .ok_or_else(|| PolicyError::UnsupportedPresetAccess {
            name: preset.name.clone(),
            access: match preset.access {
                PresetAccess::Read => "read".to_owned(),
                PresetAccess::ReadWrite => "readwrite".to_owned(),
            },
        })?;

        policy.network.allow.extend(
            block
                .allow
                .iter()
                .cloned()
                .map(PresetRule::into_network_rule),
        );
        policy.network.deny.extend(
            block
                .deny
                .iter()
                .cloned()
                .map(PresetRule::into_network_rule),
        );
        policy.network.approval_required.extend(
            block
                .approval_required
                .iter()
                .cloned()
                .map(PresetRule::into_network_rule),
        );

        Ok(())
    }
}
