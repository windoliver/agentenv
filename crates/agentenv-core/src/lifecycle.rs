use std::collections::BTreeMap;

use semver::Version;
use thiserror::Error;

use crate::{
    blueprint::{Blueprint, ComponentSection, CredentialRef as BlueprintCredentialRef},
    digest::{parse_sha256_digest, sha256_hex, DigestError},
    error::BlueprintError,
    lockfile::{
        CredentialRef as LockfileCredentialRef, DriverPin, LockedBlueprint, LockedComponent,
        Lockfile, LockfileError,
    },
    registry::{DriverKind, DriverRegistry, RegistryError},
};

const LOCKFILE_VERSION: &str = "0.1.0";
const LOCKFILE_PROTOCOL_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedComponent {
    pub kind: DriverKind,
    pub driver: String,
    pub version: Version,
}

#[derive(Debug, Clone)]
pub struct ResolvedBlueprint {
    pub blueprint: Blueprint,
    pub sandbox: ResolvedComponent,
    pub agent: ResolvedComponent,
    pub context: ResolvedComponent,
    pub inference: Option<ResolvedComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvDescription {
    pub name: String,
    pub blueprint_hash: String,
    pub drivers: BTreeMap<String, DriverPin>,
    pub artifacts: BTreeMap<String, String>,
    pub credentials: BTreeMap<String, LockfileCredentialRef>,
    pub resolved_blueprint: Option<LockedBlueprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvState {
    name: String,
    lockfile: Lockfile,
}

impl EnvState {
    pub fn describe(&self) -> EnvDescription {
        EnvDescription {
            name: self.name.clone(),
            blueprint_hash: self.lockfile.blueprint_hash.clone(),
            drivers: self.lockfile.drivers.clone(),
            artifacts: self.lockfile.artifacts.clone(),
            credentials: self.lockfile.credentials.clone(),
            resolved_blueprint: self.lockfile.resolved_blueprint.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error(transparent)]
    Blueprint(#[from] BlueprintError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error(transparent)]
    Lockfile(#[from] LockfileError),
    #[error("missing digest for `{path}`")]
    MissingDigest { path: String },
    #[error("invalid digest for `{path}`: {source}")]
    InvalidDigest {
        path: String,
        #[source]
        source: DigestError,
    },
    #[error(
        "conflicting credential reference `{name}` between `{first_path}` and `{second_path}`"
    )]
    ConflictingCredential {
        name: String,
        first_path: String,
        second_path: String,
    },
}

pub fn resolve_blueprint(yaml: &str) -> Result<ResolvedBlueprint, ResolveError> {
    let registry = DriverRegistry::default();
    resolve_blueprint_with_registry(yaml, &registry)
}

pub fn resolve_blueprint_with_registry(
    yaml: &str,
    registry: &DriverRegistry,
) -> Result<ResolvedBlueprint, ResolveError> {
    let blueprint = Blueprint::from_yaml(yaml)?;
    let sandbox = resolve_component(registry, DriverKind::Sandbox, &blueprint.sandbox)?;
    let agent = resolve_component(registry, DriverKind::Agent, &blueprint.agent)?;
    let context = resolve_component(registry, DriverKind::Context, &blueprint.context)?;
    let inference = blueprint
        .inference
        .as_ref()
        .map(|component| resolve_component(registry, DriverKind::Inference, component))
        .transpose()?;

    Ok(ResolvedBlueprint {
        blueprint,
        sandbox,
        agent,
        context,
        inference,
    })
}

pub fn verify_blueprint_yaml(yaml: &str) -> Result<ResolvedBlueprint, LifecycleError> {
    let resolved = resolve_blueprint(yaml)?;
    validate_and_lock_blueprint(&resolved)?;
    Ok(resolved)
}

pub fn freeze_from_blueprint_yaml(yaml: &str) -> Result<String, LifecycleError> {
    let lockfile = build_lockfile_from_blueprint_yaml(yaml)?;
    lockfile.to_yaml_deterministic().map_err(Into::into)
}

pub fn create_from_blueprint_yaml(name: &str, yaml: &str) -> Result<EnvState, LifecycleError> {
    let lockfile = build_lockfile_from_blueprint_yaml(yaml)?;
    Ok(EnvState {
        name: name.to_string(),
        lockfile,
    })
}

pub fn freeze_env(env: &EnvState) -> Result<String, LifecycleError> {
    env.lockfile.to_yaml_deterministic().map_err(Into::into)
}

pub fn reproduce_from_lockfile(
    name: &str,
    lockfile_yaml: &str,
) -> Result<EnvState, LifecycleError> {
    let lockfile = Lockfile::from_yaml(lockfile_yaml)?;
    Ok(EnvState {
        name: name.to_string(),
        lockfile,
    })
}

fn build_lockfile_from_blueprint_yaml(yaml: &str) -> Result<Lockfile, LifecycleError> {
    let resolved = resolve_blueprint(yaml)?;
    let locked_blueprint = validate_and_lock_blueprint(&resolved)?;
    let drivers = driver_pins(&resolved);
    let credentials = collect_credentials(&locked_blueprint)?;

    Ok(Lockfile {
        version: LOCKFILE_VERSION.to_string(),
        protocol_version: LOCKFILE_PROTOCOL_VERSION.to_string(),
        blueprint_hash: sha256_hex(yaml.as_bytes()),
        drivers,
        artifacts: collect_artifacts(&locked_blueprint)?,
        credentials,
        resolved_blueprint: Some(locked_blueprint),
    })
}

fn resolve_component(
    registry: &DriverRegistry,
    kind: DriverKind,
    component: &ComponentSection,
) -> Result<ResolvedComponent, ResolveError> {
    let version = registry.pin(kind, &component.driver, component.version.as_deref())?;

    Ok(ResolvedComponent {
        kind,
        driver: component.driver.clone(),
        version,
    })
}

fn validate_and_lock_blueprint(
    resolved: &ResolvedBlueprint,
) -> Result<LockedBlueprint, LifecycleError> {
    let blueprint = &resolved.blueprint;
    verify_component_digest("sandbox", &blueprint.sandbox)?;
    verify_component_digest("agent", &blueprint.agent)?;
    verify_component_digest("context", &blueprint.context)?;

    if let Some(inference) = blueprint.inference.as_ref() {
        verify_component_digest("inference", inference)?;
    }

    let sandbox = lock_component(&resolved.sandbox, &blueprint.sandbox);
    let agent = lock_component(&resolved.agent, &blueprint.agent);
    let context = lock_component(&resolved.context, &blueprint.context);
    let inference = resolved
        .inference
        .as_ref()
        .zip(blueprint.inference.as_ref())
        .map(|(resolved_component, component)| lock_component(resolved_component, component));

    let locked_blueprint = LockedBlueprint {
        version: blueprint.version.clone(),
        min_agentenv_version: blueprint.min_agentenv_version.clone(),
        sandbox,
        agent,
        context,
        inference,
        policy: blueprint.policy.clone(),
        state: blueprint.state.clone(),
    };

    collect_credentials(&locked_blueprint)?;
    Ok(locked_blueprint)
}

fn verify_component_digest(path: &str, component: &ComponentSection) -> Result<(), LifecycleError> {
    if component.extra.contains_key("image") {
        let digest =
            component
                .extra
                .get("digest")
                .ok_or_else(|| LifecycleError::MissingDigest {
                    path: format!("{path}.digest"),
                })?;
        let digest = digest
            .as_str()
            .ok_or_else(|| LifecycleError::MissingDigest {
                path: format!("{path}.digest"),
            })?;

        parse_sha256_digest(digest).map_err(|source| LifecycleError::InvalidDigest {
            path: format!("{path}.digest"),
            source,
        })?;
    }

    Ok(())
}

fn driver_pins(resolved: &ResolvedBlueprint) -> BTreeMap<String, DriverPin> {
    let mut pins = BTreeMap::new();
    pins.insert("agent".to_string(), driver_pin(&resolved.agent));
    pins.insert("context".to_string(), driver_pin(&resolved.context));
    pins.insert("sandbox".to_string(), driver_pin(&resolved.sandbox));

    if let Some(inference) = resolved.inference.as_ref() {
        pins.insert("inference".to_string(), driver_pin(inference));
    }

    pins
}

fn driver_pin(component: &ResolvedComponent) -> DriverPin {
    DriverPin {
        name: component.driver.clone(),
        version: component.version.to_string(),
    }
}

fn collect_artifacts(
    blueprint: &LockedBlueprint,
) -> Result<BTreeMap<String, String>, LifecycleError> {
    let mut artifacts = BTreeMap::new();

    if let Some((name, digest)) = explicit_image_artifact("sandbox", &blueprint.sandbox)? {
        artifacts.insert(name, digest);
    }
    if let Some((name, digest)) = explicit_image_artifact("agent", &blueprint.agent)? {
        artifacts.insert(name, digest);
    }
    if let Some((name, digest)) = explicit_image_artifact("context", &blueprint.context)? {
        artifacts.insert(name, digest);
    }
    if let Some(inference) = blueprint.inference.as_ref() {
        if let Some((name, digest)) = explicit_image_artifact("inference", inference)? {
            artifacts.insert(name, digest);
        }
    }

    Ok(artifacts)
}

fn explicit_image_artifact(
    role: &str,
    component: &LockedComponent,
) -> Result<Option<(String, String)>, LifecycleError> {
    if !component.extra.contains_key("image") {
        return Ok(None);
    }

    let digest = component
        .extra
        .get("digest")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LifecycleError::MissingDigest {
            path: format!("{role}.digest"),
        })?;

    parse_sha256_digest(digest).map_err(|source| LifecycleError::InvalidDigest {
        path: format!("{role}.digest"),
        source,
    })?;

    Ok(Some((format!("{role}-image"), digest.to_string())))
}

fn lock_component(resolved: &ResolvedComponent, component: &ComponentSection) -> LockedComponent {
    LockedComponent {
        driver: resolved.driver.clone(),
        version: resolved.version.to_string(),
        credentials: component
            .credentials
            .as_ref()
            .map(|credentials| {
                credentials
                    .iter()
                    .map(|(name, credential)| (name.clone(), freeze_credential(name, credential)))
                    .collect()
            })
            .unwrap_or_default(),
        extra: component.extra.clone(),
    }
}

fn collect_credentials(
    blueprint: &LockedBlueprint,
) -> Result<BTreeMap<String, LockfileCredentialRef>, LifecycleError> {
    let mut deduped = BTreeMap::new();

    extend_credentials(&mut deduped, "sandbox", &blueprint.sandbox.credentials)?;
    extend_credentials(&mut deduped, "agent", &blueprint.agent.credentials)?;
    extend_credentials(&mut deduped, "context", &blueprint.context.credentials)?;

    if let Some(inference) = blueprint.inference.as_ref() {
        extend_credentials(&mut deduped, "inference", &inference.credentials)?;
    }

    Ok(deduped
        .into_iter()
        .map(|(name, (credential, _path))| (name, credential))
        .collect())
}

fn extend_credentials(
    credentials: &mut BTreeMap<String, (LockfileCredentialRef, String)>,
    component_name: &str,
    component_credentials: &BTreeMap<String, LockfileCredentialRef>,
) -> Result<(), LifecycleError> {
    for (name, credential) in component_credentials {
        let path = format!("{component_name}.credentials.{name}");
        if let Some((existing, first_path)) = credentials.get(name) {
            if existing != credential {
                return Err(LifecycleError::ConflictingCredential {
                    name: name.clone(),
                    first_path: first_path.clone(),
                    second_path: path,
                });
            }
            continue;
        }

        credentials.insert(name.clone(), (credential.clone(), path));
    }

    Ok(())
}

fn freeze_credential(name: &str, credential: &BlueprintCredentialRef) -> LockfileCredentialRef {
    LockfileCredentialRef {
        source: credential.source.clone(),
        reference: inferred_reference(name, credential),
        required: credential.required,
        value: None,
        extra: credential.extra.clone(),
    }
}

fn inferred_reference(name: &str, credential: &BlueprintCredentialRef) -> Option<String> {
    match credential.source.as_str() {
        "env" | "credstore" => Some(name.to_string()),
        _ => None,
    }
}
