use semver::Version;
use thiserror::Error;

use crate::{
    blueprint::{Blueprint, ComponentSection},
    error::BlueprintError,
    registry::{DriverKind, DriverRegistry, RegistryError},
};

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

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error(transparent)]
    Blueprint(#[from] BlueprintError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
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
