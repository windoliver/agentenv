use std::collections::BTreeMap;

use agentenv_policy::{compose_policy, PresetRegistry, PresetSelection, Tier};
use agentenv_proto::{NetworkPolicy, NetworkRule, NetworkTarget, SCHEMA_VERSION};
use semver::Version;
use thiserror::Error;

use crate::{
    driver_artifact::DriverArtifact,
    driver_catalog::DriverSource,
    lifecycle::{
        portable_blueprint_hash, portable_canonical_blueprint, portable_collect_artifacts,
        verify_blueprint_yaml_with_registry,
    },
    lockfile::{
        CredentialRef, DriverSourcePin, LockfileDocument, PortableDriverPin, PortableLockfile,
        PortablePolicy,
    },
    registry::{DriverKind, DriverRegistry},
};

#[derive(Debug, Clone)]
pub struct PortableLockfileInput {
    pub name: String,
    pub blueprint_yaml: String,
    pub driver_artifacts: Vec<DriverArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortableVerifyIssueKind {
    LegacyLockfile,
    BlueprintHashMismatch,
    CompositionInvalid,
    DriverPinMismatch,
    MissingDriverArtifact,
    DriverDigestMismatch,
    ArtifactMapMismatch,
    CredentialMapMismatch,
    PolicyDeclarationMismatch,
    PolicyDrift,
    PolicyRecomputeFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableVerifyIssue {
    pub kind: PortableVerifyIssueKind,
    pub role: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortableVerifyReport {
    pub errors: Vec<PortableVerifyIssue>,
    pub warnings: Vec<PortableVerifyIssue>,
}

impl PortableVerifyReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn is_clean(&self) -> bool {
        self.errors.is_empty() && self.warnings.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum PortableLockfileError {
    #[error(transparent)]
    Lifecycle(#[from] crate::lifecycle::LifecycleError),
    #[error(transparent)]
    Lockfile(#[from] crate::lockfile::LockfileError),
    #[error(transparent)]
    Hardening(#[from] crate::hardening::HardeningError),
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
    let mut composition = portable_canonical_blueprint(&resolved)?;
    lock_default_sandbox_hardening(&mut composition);
    let blueprint_hash = portable_blueprint_hash(&composition)?;
    let policy = PortablePolicy {
        declared: composition.policy.clone(),
        resolved: resolved_policy_for_composition(&composition)?,
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
        skills: Vec::new(),
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

pub fn verify_portable_lockfile_yaml(
    lockfile_yaml: &str,
    driver_artifacts: &[DriverArtifact],
) -> Result<PortableVerifyReport, PortableLockfileError> {
    let document = LockfileDocument::from_yaml(lockfile_yaml)?;
    let lockfile = match document {
        LockfileDocument::Legacy(_) => {
            return Ok(PortableVerifyReport {
                errors: Vec::new(),
                warnings: vec![PortableVerifyIssue {
                    kind: PortableVerifyIssueKind::LegacyLockfile,
                    role: None,
                    message: "legacy 0.1.0 lockfiles are not self-contained for reproduction"
                        .to_owned(),
                }],
            });
        }
        LockfileDocument::Portable(lockfile) => lockfile,
    };

    let mut report = PortableVerifyReport::default();
    verify_blueprint_hash(&lockfile, &mut report);
    verify_composition(&lockfile, driver_artifacts, &mut report);
    verify_driver_pins(&lockfile, driver_artifacts, &mut report);
    verify_artifacts(&lockfile, &mut report);
    verify_credentials(&lockfile, &mut report);
    verify_policy(&lockfile, &mut report);
    Ok(report)
}

fn verify_blueprint_hash(lockfile: &PortableLockfile, report: &mut PortableVerifyReport) {
    match portable_blueprint_hash(&lockfile.composition) {
        Ok(actual) if actual == lockfile.blueprint_hash => {}
        Ok(actual) => report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::BlueprintHashMismatch,
            role: None,
            message: format!(
                "portable blueprint hash mismatch: expected `{}`, computed `{actual}`",
                lockfile.blueprint_hash
            ),
        }),
        Err(error) => report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::BlueprintHashMismatch,
            role: None,
            message: format!("failed to recompute portable blueprint hash: {error}"),
        }),
    }
}

fn verify_composition(
    lockfile: &PortableLockfile,
    driver_artifacts: &[DriverArtifact],
    report: &mut PortableVerifyReport,
) {
    let result = blueprint_yaml_from_portable_composition(&lockfile.composition).and_then(|yaml| {
        let registry = registry_from_artifacts(driver_artifacts);
        let resolved = verify_blueprint_yaml_with_registry(&yaml, &registry)?;
        portable_canonical_blueprint(&resolved)
    });

    match result {
        Ok(composition) if composition == lockfile.composition => {}
        Ok(_) => report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::CompositionInvalid,
            role: None,
            message: "portable composition does not round-trip through blueprint resolution"
                .to_owned(),
        }),
        Err(error) => report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::CompositionInvalid,
            role: None,
            message: format!("portable composition is invalid: {error}"),
        }),
    }
}

fn verify_driver_pins(
    lockfile: &PortableLockfile,
    driver_artifacts: &[DriverArtifact],
    report: &mut PortableVerifyReport,
) {
    let expected = expected_driver_pins(lockfile);

    for role in lockfile.drivers.keys() {
        if !expected.contains_key(role.as_str()) {
            report.errors.push(PortableVerifyIssue {
                kind: PortableVerifyIssueKind::DriverPinMismatch,
                role: Some(role.clone()),
                message: format!("unexpected driver pin role `{role}`"),
            });
        }
    }

    for (role, expected_pin) in expected {
        let Some(pin) = lockfile.drivers.get(role) else {
            report.errors.push(PortableVerifyIssue {
                kind: PortableVerifyIssueKind::DriverPinMismatch,
                role: Some(role.to_owned()),
                message: format!("missing driver pin for composition role `{role}`"),
            });
            continue;
        };

        if pin.kind != expected_pin.kind.to_string()
            || pin.name != expected_pin.name
            || pin.version != expected_pin.version
        {
            report.errors.push(PortableVerifyIssue {
                kind: PortableVerifyIssueKind::DriverPinMismatch,
                role: Some(role.to_owned()),
                message: format!(
                    "driver pin for role `{role}` does not match composition: expected {} driver `{}` version `{}`, found {} driver `{}` version `{}`",
                    expected_pin.kind,
                    expected_pin.name,
                    expected_pin.version,
                    pin.kind,
                    pin.name,
                    pin.version
                ),
            });
            continue;
        }

        verify_driver_artifact(role, pin, driver_artifacts, report);
    }
}

fn verify_driver_artifact(
    role: &str,
    pin: &PortableDriverPin,
    driver_artifacts: &[DriverArtifact],
    report: &mut PortableVerifyReport,
) {
    let role = role.to_owned();
    let Some(kind) = parse_driver_kind(&pin.kind) else {
        report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::MissingDriverArtifact,
            role: Some(role.clone()),
            message: format!(
                "pinned {role} driver has unsupported kind `{}` and cannot be matched",
                pin.kind
            ),
        });
        return;
    };

    let Ok(version) = Version::parse(&pin.version) else {
        report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::MissingDriverArtifact,
            role: Some(role.clone()),
            message: format!(
                "pinned {role} driver `{}` has invalid version `{}` and cannot be matched",
                pin.name, pin.version
            ),
        });
        return;
    };

    let artifact = driver_artifacts.iter().find(|artifact| {
        artifact.kind == kind
            && artifact.name == pin.name
            && artifact.version == version
            && source_pin(artifact.source) == pin.source
    });

    let Some(artifact) = artifact else {
        report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::MissingDriverArtifact,
            role: Some(role.clone()),
            message: format!(
                "missing local artifact for {role} driver `{}` version `{}` from `{}`",
                pin.name,
                pin.version,
                pin.source.as_str()
            ),
        });
        return;
    };

    if artifact.digest != pin.digest {
        report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::DriverDigestMismatch,
            role: Some(role.clone()),
            message: format!(
                "digest mismatch for {role} driver `{}` version `{}`: expected `{}`, found `{}`",
                pin.name, pin.version, pin.digest, artifact.digest
            ),
        });
    }
}

struct ExpectedDriverPin<'a> {
    kind: DriverKind,
    name: &'a str,
    version: &'a str,
}

fn expected_driver_pins(
    lockfile: &PortableLockfile,
) -> BTreeMap<&'static str, ExpectedDriverPin<'_>> {
    let mut expected = BTreeMap::new();
    expected.insert(
        "agent",
        ExpectedDriverPin {
            kind: DriverKind::Agent,
            name: &lockfile.composition.agent.driver,
            version: &lockfile.composition.agent.version,
        },
    );
    expected.insert(
        "context",
        ExpectedDriverPin {
            kind: DriverKind::Context,
            name: &lockfile.composition.context.driver,
            version: &lockfile.composition.context.version,
        },
    );
    expected.insert(
        "sandbox",
        ExpectedDriverPin {
            kind: DriverKind::Sandbox,
            name: &lockfile.composition.sandbox.driver,
            version: &lockfile.composition.sandbox.version,
        },
    );
    if let Some(inference) = &lockfile.composition.inference {
        expected.insert(
            "inference",
            ExpectedDriverPin {
                kind: DriverKind::Inference,
                name: &inference.driver,
                version: &inference.version,
            },
        );
    }
    expected
}

fn verify_policy(lockfile: &PortableLockfile, report: &mut PortableVerifyReport) {
    if lockfile.policy.declared != lockfile.composition.policy {
        report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::PolicyDeclarationMismatch,
            role: None,
            message: "policy.declared does not match composition.policy".to_owned(),
        });
        return;
    }

    let recomputed = resolved_policy_for_composition(&lockfile.composition);

    match recomputed {
        Ok(policy) if policy == lockfile.policy.resolved => {}
        Ok(_) => report.warnings.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::PolicyDrift,
            role: None,
            message: "recomputed policy differs from the policy pinned in the lockfile".to_owned(),
        }),
        Err(error) => report.warnings.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::PolicyRecomputeFailed,
            role: None,
            message: format!("failed to recompute declared policy: {error}"),
        }),
    }
}

fn verify_artifacts(lockfile: &PortableLockfile, report: &mut PortableVerifyReport) {
    match portable_collect_artifacts(&lockfile.composition) {
        Ok(expected) if expected == lockfile.artifacts => {}
        Ok(expected) => report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::ArtifactMapMismatch,
            role: None,
            message: format!(
                "artifact map does not match composition: expected {} artifact(s), found {}",
                expected.len(),
                lockfile.artifacts.len()
            ),
        }),
        Err(error) => report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::ArtifactMapMismatch,
            role: None,
            message: format!("failed to derive artifact map from composition: {error}"),
        }),
    }
}

fn verify_credentials(lockfile: &PortableLockfile, report: &mut PortableVerifyReport) {
    let expected = collect_portable_credentials(&lockfile.composition);
    if expected != lockfile.credentials {
        report.errors.push(PortableVerifyIssue {
            kind: PortableVerifyIssueKind::CredentialMapMismatch,
            role: None,
            message: format!(
                "credential map does not match composition: expected {} credential(s), found {}",
                expected.len(),
                lockfile.credentials.len()
            ),
        });
    }
}

fn parse_driver_kind(value: &str) -> Option<DriverKind> {
    match value {
        "sandbox" => Some(DriverKind::Sandbox),
        "agent" => Some(DriverKind::Agent),
        "context" => Some(DriverKind::Context),
        "inference" => Some(DriverKind::Inference),
        _ => None,
    }
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

fn lock_default_sandbox_hardening(composition: &mut crate::lockfile::PortableComposition) {
    if matches!(
        composition.sandbox.extra.get("hardening"),
        None | Some(serde_yaml::Value::Null)
    ) {
        composition.sandbox.extra.insert(
            "hardening".to_owned(),
            serde_yaml::Value::String(crate::hardening::DEFAULT_HARDENING_PROFILE.to_owned()),
        );
    }
}

fn resolved_policy_for_composition(
    composition: &crate::lockfile::PortableComposition,
) -> Result<NetworkPolicy, PortableLockfileError> {
    let mut policy = compose_policy(
        parse_tier(&composition.policy.tier)?,
        &parse_presets(&composition.policy.presets)?,
        policy_overrides(&composition.policy.overrides),
        &PresetRegistry::load_builtin()?,
    )?;
    apply_portable_hardening_to_policy(&mut policy, composition)?;
    Ok(policy)
}

fn apply_portable_hardening_to_policy(
    policy: &mut NetworkPolicy,
    composition: &crate::lockfile::PortableComposition,
) -> Result<(), PortableLockfileError> {
    let sandbox = blueprint_component_from_portable(&composition.sandbox);
    if !crate::hardening::sandbox_hardening_declared(&sandbox) {
        return Ok(());
    }

    let resolved = crate::hardening::resolve_sandbox_hardening(&sandbox)?;
    let persist_home = composition
        .state
        .as_ref()
        .and_then(|state| state.persist_home)
        .unwrap_or(false);
    crate::hardening::apply_resolved_hardening_to_policy(policy, &resolved, persist_home)?;
    Ok(())
}

fn blueprint_yaml_from_portable_composition(
    composition: &crate::lockfile::PortableComposition,
) -> Result<String, crate::lifecycle::LifecycleError> {
    let blueprint = crate::blueprint::Blueprint {
        version: composition.version.clone(),
        min_agentenv_version: composition.min_agentenv_version.clone(),
        sandbox: blueprint_component_from_portable(&composition.sandbox),
        agent: blueprint_component_from_portable(&composition.agent),
        context: blueprint_component_from_portable(&composition.context),
        inference: composition
            .inference
            .as_ref()
            .map(blueprint_component_from_portable),
        policy: composition.policy.clone(),
        state: composition.state.clone(),
    };

    serde_yaml::to_string(&blueprint)
        .map_err(crate::lifecycle::LifecycleError::CanonicalBlueprintSerialize)
}

fn blueprint_component_from_portable(
    component: &crate::lockfile::PortableComponent,
) -> crate::blueprint::ComponentSection {
    crate::blueprint::ComponentSection {
        driver: component.driver.clone(),
        version: Some(component.version.clone()),
        credentials: if component.credentials.is_empty() {
            None
        } else {
            Some(
                component
                    .credentials
                    .iter()
                    .map(|(name, credential)| {
                        (
                            name.clone(),
                            crate::blueprint::CredentialRef {
                                source: credential.source.clone(),
                                required: credential.required,
                                value: credential.reference.clone(),
                                extra: BTreeMap::new(),
                            },
                        )
                    })
                    .collect(),
            )
        },
        extra: component.extra.clone(),
    }
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
