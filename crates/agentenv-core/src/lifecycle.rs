use std::collections::BTreeMap;

use semver::Version;
use serde::Serialize;
use serde_yaml::{Mapping, Value};
use thiserror::Error;

use crate::{
    blueprint::{
        Blueprint, ComponentSection, CredentialRef as BlueprintCredentialRef, PolicySection,
        StateSection,
    },
    digest::{parse_sha256_digest, sha256_hex, DigestError},
    error::BlueprintError,
    lockfile::{CredentialRef as LockfileCredentialRef, DriverPin, Lockfile, LockfileError},
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
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct CanonicalBlueprint {
    version: String,
    min_agentenv_version: String,
    sandbox: CanonicalComponent,
    agent: CanonicalComponent,
    context: CanonicalComponent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inference: Option<CanonicalComponent>,
    policy: PolicySection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<StateSection>,
}

#[derive(Debug, Clone, Serialize)]
struct CanonicalComponent {
    driver: String,
    version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    credentials: BTreeMap<String, LockfileCredentialRef>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    extra: BTreeMap<String, Value>,
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
    #[error("failed to serialize canonical resolved blueprint: {0}")]
    CanonicalBlueprintSerialize(serde_yaml::Error),
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
    let canonical = canonical_blueprint(&resolved)?;
    collect_credentials(&canonical)?;
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
    let canonical = canonical_blueprint(&resolved)?;
    let credentials = collect_credentials(&canonical)?;

    Ok(Lockfile {
        version: LOCKFILE_VERSION.to_string(),
        protocol_version: LOCKFILE_PROTOCOL_VERSION.to_string(),
        blueprint_hash: canonical_blueprint_hash(&canonical)?,
        drivers: driver_pins(&resolved),
        artifacts: collect_artifacts(&canonical)?,
        credentials,
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

fn canonical_blueprint(resolved: &ResolvedBlueprint) -> Result<CanonicalBlueprint, LifecycleError> {
    let blueprint = &resolved.blueprint;
    verify_component_digest("sandbox", &blueprint.sandbox)?;
    verify_component_digest("agent", &blueprint.agent)?;
    verify_component_digest("context", &blueprint.context)?;

    if let Some(inference) = blueprint.inference.as_ref() {
        verify_component_digest("inference", inference)?;
    }

    Ok(CanonicalBlueprint {
        version: blueprint.version.clone(),
        min_agentenv_version: blueprint.min_agentenv_version.clone(),
        sandbox: canonical_component(&resolved.sandbox, &blueprint.sandbox),
        agent: canonical_component(&resolved.agent, &blueprint.agent),
        context: canonical_component(&resolved.context, &blueprint.context),
        inference: resolved
            .inference
            .as_ref()
            .zip(blueprint.inference.as_ref())
            .map(|(resolved_component, component)| {
                canonical_component(resolved_component, component)
            }),
        policy: blueprint.policy.clone(),
        state: blueprint.state.clone(),
    })
}

fn canonical_component(
    resolved: &ResolvedComponent,
    component: &ComponentSection,
) -> CanonicalComponent {
    CanonicalComponent {
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

fn canonical_blueprint_hash(blueprint: &CanonicalBlueprint) -> Result<String, LifecycleError> {
    let value =
        serde_yaml::to_value(blueprint).map_err(LifecycleError::CanonicalBlueprintSerialize)?;
    let rendered = serde_yaml::to_string(&canonicalize_yaml_value(value))
        .map_err(LifecycleError::CanonicalBlueprintSerialize)?;
    Ok(sha256_hex(rendered.as_bytes()))
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
    blueprint: &CanonicalBlueprint,
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
    component: &CanonicalComponent,
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

fn collect_credentials(
    blueprint: &CanonicalBlueprint,
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
        extra: credential.extra.clone(),
    }
}

fn inferred_reference(name: &str, credential: &BlueprintCredentialRef) -> Option<String> {
    match credential.source.as_str() {
        "env" | "credstore" => Some(name.to_string()),
        _ => None,
    }
}

fn canonicalize_yaml_value(value: Value) -> Value {
    match value {
        Value::Sequence(items) => Value::Sequence(
            items
                .into_iter()
                .map(canonicalize_yaml_value)
                .collect::<Vec<_>>(),
        ),
        Value::Mapping(map) => {
            let mut entries = map
                .into_iter()
                .map(|(key, value)| {
                    let canonical_key = canonicalize_yaml_value(key);
                    let canonical_value = canonicalize_yaml_value(value);
                    (canonical_key, canonical_value)
                })
                .collect::<Vec<_>>();
            entries.sort_by(|(left_key, _), (right_key, _)| {
                canonical_yaml_sort_key(left_key).cmp(&canonical_yaml_sort_key(right_key))
            });

            let mut canonical = Mapping::new();
            for (key, value) in entries {
                canonical.insert(key, value);
            }

            Value::Mapping(canonical)
        }
        Value::Tagged(tagged) => Value::Tagged(Box::new(serde_yaml::value::TaggedValue {
            tag: tagged.tag,
            value: canonicalize_yaml_value(tagged.value),
        })),
        other => other,
    }
}

fn canonical_yaml_sort_key(value: &Value) -> String {
    match value {
        Value::Null => "n:null".to_string(),
        Value::Bool(boolean) => format!("b:{boolean}"),
        Value::Number(number) => format!("d:{number}"),
        Value::String(string) => format!("s:{string}"),
        Value::Sequence(items) => {
            let mut rendered = String::from("q:[");
            for item in items {
                rendered.push_str(&canonical_yaml_sort_key(item));
                rendered.push(',');
            }
            rendered.push(']');
            rendered
        }
        Value::Mapping(map) => {
            let mut rendered = String::from("m:{");
            for (key, value) in map {
                rendered.push_str(&canonical_yaml_sort_key(key));
                rendered.push('=');
                rendered.push_str(&canonical_yaml_sort_key(value));
                rendered.push(',');
            }
            rendered.push('}');
            rendered
        }
        Value::Tagged(tagged) => {
            format!(
                "t:{}:{}",
                tagged.tag,
                canonical_yaml_sort_key(&tagged.value)
            )
        }
    }
}
