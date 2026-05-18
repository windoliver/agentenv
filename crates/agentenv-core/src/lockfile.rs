use std::collections::{BTreeMap, BTreeSet};

use agentenv_proto::{assert_compatible_schema_version, NetworkPolicy};
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;
use thiserror::Error;

use crate::digest::{parse_sha256_digest, parse_sha256_hex, DigestError};

const SUPPORTED_LOCKFILE_VERSION: &str = "0.1.0";
const SUPPORTED_PROTOCOL_VERSION: &str = "0.1";
const PORTABLE_LOCKFILE_V2_VERSION: &str = "0.2.0";
pub const PORTABLE_LOCKFILE_VERSION: &str = "0.3.0";

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum LockfileDocument {
    Legacy(Lockfile),
    Portable(PortableLockfile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    pub version: String,
    pub protocol_version: String,
    pub blueprint_hash: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub drivers: BTreeMap<String, DriverPin>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifacts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverPin {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableLockfile {
    pub version: String,
    pub driver_protocol_version: String,
    pub name: String,
    pub blueprint_hash: String,
    pub composition: PortableComposition,
    pub policy: PortablePolicy,
    pub drivers: BTreeMap<String, PortableDriverPin>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<SkillPin>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifacts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableComposition {
    pub version: String,
    pub min_agentenv_version: String,
    pub sandbox: PortableComponent,
    pub agent: PortableComponent,
    pub context: PortableComponent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<PortableComponent>,
    pub policy: crate::blueprint::PolicySection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<crate::blueprint::StateSection>,
    #[serde(
        default,
        skip_serializing_if = "crate::blueprint::SkillsSection::is_empty"
    )]
    pub skills: crate::blueprint::SkillsSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<crate::blueprint::ObservabilitySection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableComponent {
    pub driver: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePolicy {
    pub declared: crate::blueprint::PolicySection,
    pub resolved: NetworkPolicy,
}

impl<'de> Deserialize<'de> for PortablePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPortablePolicy {
            declared: crate::blueprint::PolicySection,
            resolved: Value,
        }

        let raw = RawPortablePolicy::deserialize(deserializer)?;
        validate_resolved_policy_value(&raw.resolved).map_err(serde::de::Error::custom)?;
        let resolved = serde_yaml::from_value(raw.resolved).map_err(serde::de::Error::custom)?;
        Ok(Self {
            declared: raw.declared,
            resolved,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableDriverPin {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub source: DriverSourcePin,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPin {
    pub name: String,
    pub version: String,
    pub source: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverSourcePin {
    BuiltIn,
    Installed,
    Override,
}

impl DriverSourcePin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::Installed => "installed",
            Self::Override => "override",
        }
    }
}

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to parse lockfile YAML: {0}")]
    ParseYaml(serde_yaml::Error),
    #[error("failed to deserialize lockfile data: {0}")]
    Deserialize(serde_yaml::Error),
    #[error("failed to serialize lockfile data: {0}")]
    Serialize(serde_yaml::Error),
    #[error("invalid blueprint hash: {source}")]
    InvalidBlueprintHash {
        #[source]
        source: DigestError,
    },
    #[error("invalid artifact digest for `{name}`: {source}")]
    InvalidArtifactDigest {
        name: String,
        #[source]
        source: DigestError,
    },
    #[error("duplicate skill pin `{name}` version `{version}` from `{skill_source}`")]
    DuplicateSkillPin {
        name: String,
        version: String,
        skill_source: String,
    },
    #[error("unsupported lockfile version `{version}`")]
    UnsupportedVersion { version: String },
    #[error("unsupported protocol version `{version}`")]
    UnsupportedProtocolVersion { version: String },
    #[error("missing required driver pin `{role}`")]
    MissingRequiredDriverPin { role: String },
    #[error("unsupported credential source `{credential_source}` for `{name}`")]
    UnsupportedCredentialSource {
        name: String,
        credential_source: String,
    },
    #[error("invalid credential reference for `{name}`: lockfiles only support reference-only credentials")]
    MissingCredentialReference { name: String },
}

impl Lockfile {
    pub fn from_yaml(yaml: &str) -> Result<Self, LockfileError> {
        let lockfile: Self = serde_yaml::from_str(yaml).map_err(LockfileError::Deserialize)?;
        lockfile.validate()?;
        Ok(lockfile)
    }

    pub fn to_yaml_deterministic(&self) -> Result<String, LockfileError> {
        self.validate()?;
        serde_yaml::to_string(self).map_err(LockfileError::Serialize)
    }

    pub fn validate_no_secret_values(&self) -> Result<(), LockfileError> {
        validate_credentials(&self.credentials)
    }

    fn validate(&self) -> Result<(), LockfileError> {
        if self.version != SUPPORTED_LOCKFILE_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                version: self.version.clone(),
            });
        }

        if self.protocol_version != SUPPORTED_PROTOCOL_VERSION {
            return Err(LockfileError::UnsupportedProtocolVersion {
                version: self.protocol_version.clone(),
            });
        }

        parse_sha256_hex(&self.blueprint_hash)
            .map_err(|source| LockfileError::InvalidBlueprintHash { source })?;

        for role in ["sandbox", "agent", "context"] {
            if !self.drivers.contains_key(role) {
                return Err(LockfileError::MissingRequiredDriverPin {
                    role: role.to_string(),
                });
            }
        }

        for (name, digest) in &self.artifacts {
            parse_sha256_digest(digest).map_err(|source| LockfileError::InvalidArtifactDigest {
                name: name.clone(),
                source,
            })?;
        }

        self.validate_no_secret_values()
    }
}

impl LockfileDocument {
    pub fn from_yaml(yaml: &str) -> Result<Self, LockfileError> {
        let value: Value = serde_yaml::from_str(yaml).map_err(LockfileError::ParseYaml)?;
        let version = value
            .as_mapping()
            .and_then(|map| map.get(Value::String("version".to_owned())))
            .and_then(Value::as_str)
            .ok_or_else(|| LockfileError::UnsupportedVersion {
                version: "<missing>".to_owned(),
            })?;

        match version {
            SUPPORTED_LOCKFILE_VERSION => Ok(Self::Legacy(Lockfile::from_yaml(yaml)?)),
            version if is_supported_portable_lockfile_version(version) => {
                let lockfile: PortableLockfile =
                    serde_yaml::from_value(value).map_err(LockfileError::Deserialize)?;
                lockfile.validate()?;
                Ok(Self::Portable(lockfile))
            }
            other => Err(LockfileError::UnsupportedVersion {
                version: other.to_owned(),
            }),
        }
    }
}

impl PortableLockfile {
    pub fn to_yaml_deterministic(&self) -> Result<String, LockfileError> {
        let mut lockfile = self.clone();
        lockfile.version = PORTABLE_LOCKFILE_VERSION.to_owned();
        lockfile.skills.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.version.cmp(&right.version))
                .then_with(|| left.source.cmp(&right.source))
        });
        lockfile.validate()?;
        serde_yaml::to_string(&lockfile).map_err(LockfileError::Serialize)
    }

    pub fn validate(&self) -> Result<(), LockfileError> {
        if !is_supported_portable_lockfile_version(&self.version) {
            return Err(LockfileError::UnsupportedVersion {
                version: self.version.clone(),
            });
        }

        assert_compatible_schema_version(&self.driver_protocol_version).map_err(|_| {
            LockfileError::UnsupportedProtocolVersion {
                version: self.driver_protocol_version.clone(),
            }
        })?;

        parse_sha256_hex(&self.blueprint_hash)
            .map_err(|source| LockfileError::InvalidBlueprintHash { source })?;

        for role in ["sandbox", "agent", "context"] {
            if !self.drivers.contains_key(role) {
                return Err(LockfileError::MissingRequiredDriverPin {
                    role: role.to_owned(),
                });
            }
        }

        for (name, digest) in &self.artifacts {
            parse_sha256_digest(digest).map_err(|source| LockfileError::InvalidArtifactDigest {
                name: name.clone(),
                source,
            })?;
        }

        for (role, driver) in &self.drivers {
            parse_sha256_digest(&driver.digest).map_err(|source| {
                LockfileError::InvalidArtifactDigest {
                    name: format!("{role}-driver"),
                    source,
                }
            })?;
        }

        validate_skill_pins(&self.skills)?;

        validate_credentials(&self.composition.sandbox.credentials)?;
        validate_credentials(&self.composition.agent.credentials)?;
        validate_credentials(&self.composition.context.credentials)?;
        if let Some(inference) = &self.composition.inference {
            validate_credentials(&inference.credentials)?;
        }

        validate_credentials(&self.credentials)
    }
}

fn is_supported_portable_lockfile_version(version: &str) -> bool {
    matches!(
        version,
        PORTABLE_LOCKFILE_V2_VERSION | PORTABLE_LOCKFILE_VERSION
    )
}

fn validate_skill_pins(skills: &[SkillPin]) -> Result<(), LockfileError> {
    let mut seen = BTreeSet::new();
    for skill in skills {
        parse_sha256_digest(&skill.digest).map_err(|source| {
            LockfileError::InvalidArtifactDigest {
                name: format!("skill:{}:{}", skill.name, skill.version),
                source,
            }
        })?;
        let key = (
            skill.name.clone(),
            skill.version.clone(),
            skill.source.clone(),
        );
        if !seen.insert(key) {
            return Err(LockfileError::DuplicateSkillPin {
                name: skill.name.clone(),
                version: skill.version.clone(),
                skill_source: skill.source.clone(),
            });
        }
    }
    Ok(())
}

fn validate_credentials(
    credentials: &BTreeMap<String, CredentialRef>,
) -> Result<(), LockfileError> {
    for (name, credential) in credentials {
        match credential.source.as_str() {
            "env" | "credstore" => {}
            source => {
                return Err(LockfileError::UnsupportedCredentialSource {
                    name: name.clone(),
                    credential_source: source.to_string(),
                });
            }
        }

        if credential.reference.is_none() {
            return Err(LockfileError::MissingCredentialReference { name: name.clone() });
        }
    }

    Ok(())
}

fn validate_resolved_policy_value(value: &Value) -> Result<(), String> {
    validate_mapping_keys(
        value,
        "policy.resolved",
        &["network", "filesystem", "process", "inference"],
    )?;
    validate_child_mapping_keys(
        value,
        "network",
        "policy.resolved.network",
        &["reloadability", "allow", "deny", "approval_required", "dns"],
    )?;
    validate_rule_list(value, "network", "allow", "policy.resolved.network.allow")?;
    validate_rule_list(value, "network", "deny", "policy.resolved.network.deny")?;
    validate_rule_list(
        value,
        "network",
        "approval_required",
        "policy.resolved.network.approval_required",
    )?;
    validate_network_dns_policy(value)?;
    validate_child_mapping_keys(
        value,
        "filesystem",
        "policy.resolved.filesystem",
        &["reloadability", "read_only", "read_write"],
    )?;
    validate_child_mapping_keys(
        value,
        "process",
        "policy.resolved.process",
        &[
            "reloadability",
            "run_as_user",
            "run_as_group",
            "profile",
            "allow_syscalls",
            "deny_syscalls",
        ],
    )?;
    validate_child_mapping_keys(
        value,
        "inference",
        "policy.resolved.inference",
        &["reloadability", "routes"],
    )?;
    validate_inference_routes(value)?;
    Ok(())
}

fn validate_network_dns_policy(policy: &Value) -> Result<(), String> {
    let Some(value) =
        mapping_value(policy, "network").and_then(|network| mapping_value(network, "dns"))
    else {
        return Ok(());
    };

    validate_mapping_keys(
        value,
        "policy.resolved.network.dns",
        &[
            "resolvers_allowed",
            "doh_upstreams_allowed",
            "dot_upstreams_allowed",
            "log_all_queries",
            "pin_resolved_ips",
        ],
    )
}

fn validate_mapping_keys(value: &Value, path: &str, allowed: &[&str]) -> Result<(), String> {
    let Some(mapping) = value.as_mapping() else {
        return Ok(());
    };

    for key in mapping.keys() {
        let Some(key) = key.as_str() else {
            return Err(format!("{path} contains a non-string key"));
        };
        if !allowed.contains(&key) {
            return Err(format!("unexpected resolved policy field `{path}.{key}`"));
        }
    }

    Ok(())
}

fn validate_child_mapping_keys(
    parent: &Value,
    child: &str,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let Some(value) = mapping_value(parent, child) else {
        return Ok(());
    };
    validate_mapping_keys(value, path, allowed)
}

fn validate_rule_list(
    policy: &Value,
    section: &str,
    field: &str,
    path: &str,
) -> Result<(), String> {
    let Some(value) =
        mapping_value(policy, section).and_then(|section| mapping_value(section, field))
    else {
        return Ok(());
    };
    let Value::Sequence(rules) = value else {
        return Ok(());
    };

    for (index, rule) in rules.iter().enumerate() {
        let rule_path = format!("{path}[{index}]");
        validate_mapping_keys(rule, &rule_path, &["target"])?;
        let Some(target) = mapping_value(rule, "target") else {
            continue;
        };
        validate_network_target(target, &format!("{rule_path}.target"))?;
    }

    Ok(())
}

fn validate_network_target(target: &Value, path: &str) -> Result<(), String> {
    let kind = mapping_value(target, "kind").and_then(Value::as_str);
    let allowed = match kind {
        Some("host") => &["kind", "host", "port", "scheme", "http_access"][..],
        Some("cidr") => &["kind", "cidr"][..],
        Some("port") => &["kind", "port", "protocol"][..],
        Some("url_pattern") => &["kind", "pattern"][..],
        Some("http_method_path") => &["kind", "host", "method", "path"][..],
        _ => return validate_mapping_keys(target, path, &["kind"]),
    };
    validate_mapping_keys(target, path, allowed)
}

fn validate_inference_routes(policy: &Value) -> Result<(), String> {
    let Some(value) =
        mapping_value(policy, "inference").and_then(|inference| mapping_value(inference, "routes"))
    else {
        return Ok(());
    };
    let Value::Sequence(routes) = value else {
        return Ok(());
    };

    for (index, route) in routes.iter().enumerate() {
        validate_mapping_keys(
            route,
            &format!("policy.resolved.inference.routes[{index}]"),
            &[
                "matcher",
                "provider",
                "model",
                "base_url",
                "timeout_seconds",
            ],
        )?;
    }

    Ok(())
}

fn mapping_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
}
