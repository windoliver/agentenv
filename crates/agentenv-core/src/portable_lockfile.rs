use std::collections::BTreeMap;

use agentenv_policy::{compose_policy, PresetRegistry, PresetSelection, Tier};
use agentenv_proto::{NetworkPolicy, NetworkRule, NetworkTarget, SCHEMA_VERSION};
use thiserror::Error;

use crate::{
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    lifecycle::{
        portable_blueprint_hash, portable_canonical_blueprint, portable_collect_artifacts,
        verify_blueprint_yaml_with_registry,
    },
    lockfile::{
        CredentialRef, DriverSourcePin, PortableDriverPin, PortableLockfile, PortablePolicy,
    },
    registry::{DriverKind, DriverRegistry},
};

#[derive(Debug, Clone)]
pub struct PortableLockfileInput {
    pub name: String,
    pub blueprint_yaml: String,
    pub driver_artifacts: Vec<DriverArtifact>,
}

#[derive(Debug, Error)]
pub enum PortableLockfileError {
    #[error(transparent)]
    Lifecycle(#[from] crate::lifecycle::LifecycleError),
    #[error(transparent)]
    Lockfile(#[from] crate::lockfile::LockfileError),
    #[error(transparent)]
    Policy(#[from] agentenv_policy::PolicyError),
    #[error("missing artifact for {kind} driver `{name}` version `{version}`")]
    MissingDriverArtifact {
        kind: DriverKind,
        name: String,
        version: String,
    },
    #[error("ambiguous artifacts for {kind} driver `{name}` version `{version}`")]
    AmbiguousDriverArtifact {
        kind: DriverKind,
        name: String,
        version: String,
    },
}

pub fn build_portable_lockfile(
    input: PortableLockfileInput,
) -> Result<PortableLockfile, PortableLockfileError> {
    let registry = registry_from_artifacts(&input.driver_artifacts);
    let resolved = verify_blueprint_yaml_with_registry(&input.blueprint_yaml, &registry)?;
    let composition = portable_canonical_blueprint(&resolved)?;
    let blueprint_hash = portable_blueprint_hash(&composition)?;
    let policy = PortablePolicy {
        declared: composition.policy.clone(),
        resolved: compose_policy(
            parse_tier(&composition.policy.tier)?,
            &parse_presets(&composition.policy.presets)?,
            policy_overrides(&composition.policy.overrides),
            &PresetRegistry::load_builtin()?,
        )?,
    };
    let credentials = collect_portable_credentials(&composition);
    let artifacts = portable_collect_artifacts(&composition)?;

    Ok(PortableLockfile {
        version: crate::lockfile::PORTABLE_LOCKFILE_VERSION.to_owned(),
        driver_protocol_version: SCHEMA_VERSION.to_owned(),
        name: input.name,
        blueprint_hash,
        composition,
        policy,
        drivers: driver_pins(&resolved, &input.driver_artifacts)?,
        artifacts,
        credentials,
    })
}

fn registry_from_artifacts(artifacts: &[DriverArtifact]) -> DriverRegistry {
    let mut registry = DriverRegistry::default();
    for artifact in artifacts {
        registry.register_version(
            artifact.kind,
            artifact.name.clone(),
            artifact.version.clone(),
        );
    }
    registry
}

pub fn build_portable_lockfile_from_blueprint(
    input: PortableLockfileInput,
) -> Result<PortableLockfile, PortableLockfileError> {
    build_portable_lockfile(input)
}

fn driver_pins(
    resolved: &crate::lifecycle::ResolvedBlueprint,
    artifacts: &[DriverArtifact],
) -> Result<BTreeMap<String, PortableDriverPin>, PortableLockfileError> {
    let mut pins = BTreeMap::new();
    insert_driver_pin(&mut pins, "agent", &resolved.agent, artifacts)?;
    insert_driver_pin(&mut pins, "context", &resolved.context, artifacts)?;
    insert_driver_pin(&mut pins, "sandbox", &resolved.sandbox, artifacts)?;
    if let Some(inference) = &resolved.inference {
        insert_driver_pin(&mut pins, "inference", inference, artifacts)?;
    }
    Ok(pins)
}

fn insert_driver_pin(
    pins: &mut BTreeMap<String, PortableDriverPin>,
    role: &str,
    component: &crate::lifecycle::ResolvedComponent,
    artifacts: &[DriverArtifact],
) -> Result<(), PortableLockfileError> {
    let matches = artifacts
        .iter()
        .filter(|item| {
            item.kind == component.kind
                && item.name == component.driver
                && item.version == component.version
        })
        .collect::<Vec<_>>();

    let artifact = match matches.as_slice() {
        [artifact] => *artifact,
        [] => {
            return Err(PortableLockfileError::MissingDriverArtifact {
                kind: component.kind,
                name: component.driver.clone(),
                version: component.version.to_string(),
            });
        }
        _ => {
            return Err(PortableLockfileError::AmbiguousDriverArtifact {
                kind: component.kind,
                name: component.driver.clone(),
                version: component.version.to_string(),
            });
        }
    };

    pins.insert(
        role.to_owned(),
        PortableDriverPin {
            kind: component.kind.to_string(),
            name: component.driver.clone(),
            version: component.version.to_string(),
            source: source_pin(artifact.source),
            digest: artifact.digest.clone(),
        },
    );
    Ok(())
}

fn source_pin(source: DriverSource) -> DriverSourcePin {
    match source {
        DriverSource::BuiltIn => DriverSourcePin::BuiltIn,
        DriverSource::InstalledSubprocess => DriverSourcePin::Installed,
        DriverSource::DevelopmentOverride => DriverSourcePin::Override,
    }
}

fn collect_portable_credentials(
    composition: &crate::lockfile::PortableComposition,
) -> BTreeMap<String, CredentialRef> {
    let mut credentials = BTreeMap::new();
    credentials.extend(composition.sandbox.credentials.clone());
    credentials.extend(composition.agent.credentials.clone());
    credentials.extend(composition.context.credentials.clone());
    if let Some(inference) = &composition.inference {
        credentials.extend(inference.credentials.clone());
    }
    credentials
}

fn parse_tier(value: &str) -> Result<Tier, agentenv_policy::PolicyError> {
    match value {
        "restricted" => Ok(Tier::Restricted),
        "balanced" => Ok(Tier::Balanced),
        "open" => Ok(Tier::Open),
        other => Err(agentenv_policy::PolicyError::PresetRegistry {
            message: format!("unknown policy tier `{other}`"),
        }),
    }
}

fn parse_presets(values: &[String]) -> Result<Vec<PresetSelection>, agentenv_policy::PolicyError> {
    values
        .iter()
        .map(|value| PresetSelection::from_slug(value))
        .collect()
}

fn policy_overrides(overrides: &[crate::blueprint::PolicyOverride]) -> Option<NetworkPolicy> {
    if overrides.is_empty() {
        return None;
    }

    let mut policy = empty_policy_override();
    for item in overrides {
        if let Some(allow) = item.allow.as_ref() {
            policy.network.allow.push(policy_override_network_rule(
                allow,
                PolicyOverrideTargetKind::AllowOrDeny,
            ));
        }
        if let Some(deny) = item.deny.as_ref() {
            policy.network.deny.push(policy_override_network_rule(
                deny,
                PolicyOverrideTargetKind::AllowOrDeny,
            ));
        }
        if let Some(approval) = item.approval.as_ref() {
            policy
                .network
                .approval_required
                .push(policy_override_network_rule(
                    approval,
                    PolicyOverrideTargetKind::Approval,
                ));
        }
    }

    Some(policy)
}

enum PolicyOverrideTargetKind {
    AllowOrDeny,
    Approval,
}

fn policy_override_network_rule(pattern: &str, kind: PolicyOverrideTargetKind) -> NetworkRule {
    if let Ok(url) = url::Url::parse(pattern) {
        if matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
        {
            if let Some(host) = url.host_str() {
                return NetworkRule {
                    target: match kind {
                        PolicyOverrideTargetKind::AllowOrDeny => NetworkTarget::Host {
                            host: host.to_owned(),
                            port: url.port_or_known_default(),
                            scheme: Some(url.scheme().to_owned()),
                            http_access: None,
                        },
                        PolicyOverrideTargetKind::Approval => NetworkTarget::HttpMethodPath {
                            host: Some(host.to_owned()),
                            method: "*".to_owned(),
                            path: url.path().to_owned(),
                        },
                    },
                };
            }
        }
    }

    url_pattern_rule(pattern)
}

fn empty_policy_override() -> NetworkPolicy {
    NetworkPolicy {
        network: agentenv_proto::NetworkAccessPolicy {
            reloadability: agentenv_proto::PolicyReloadability::HotReload,
            allow: Vec::new(),
            deny: Vec::new(),
            approval_required: Vec::new(),
        },
        filesystem: agentenv_proto::FilesystemPolicy {
            reloadability: agentenv_proto::PolicyReloadability::LockedAtCreate,
            read_only: Vec::new(),
            read_write: Vec::new(),
        },
        process: agentenv_proto::ProcessPolicy {
            reloadability: agentenv_proto::PolicyReloadability::LockedAtCreate,
            run_as_user: String::new(),
            run_as_group: String::new(),
            profile: String::new(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: agentenv_proto::InferencePolicy {
            reloadability: agentenv_proto::PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}

fn url_pattern_rule(pattern: &str) -> NetworkRule {
    NetworkRule {
        target: NetworkTarget::UrlPattern {
            pattern: pattern.to_owned(),
        },
    }
}
