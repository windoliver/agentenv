use std::collections::BTreeMap;

use agentenv_policy::{
    apply_hardening_to_policy, hardening_metadata, resolve_hardening_profile, HardeningProfile,
    PolicyError,
};
use thiserror::Error;

use crate::blueprint::ComponentSection;

const DEFAULT_HARDENING_PROFILE: &str = "baseline";

#[derive(Debug, Clone)]
pub struct ResolvedHardening {
    pub profile: HardeningProfile,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum HardeningError {
    #[error("invalid sandbox.hardening: expected non-empty string profile name or null")]
    InvalidType,
    #[error("invalid sandbox.hardening: expected non-empty string profile name")]
    EmptyName,
    #[error("invalid sandbox.hardening `{name}`: {source}")]
    Resolve {
        name: String,
        #[source]
        source: PolicyError,
    },
    #[error("invalid sandbox.hardening `{name}` metadata: {source}")]
    Metadata {
        name: String,
        #[source]
        source: PolicyError,
    },
    #[error("failed to apply sandbox.hardening `{name}`: {source}")]
    Apply {
        name: String,
        #[source]
        source: PolicyError,
    },
}

pub type HardeningResult<T> = Result<T, HardeningError>;

pub fn resolve_sandbox_hardening(sandbox: &ComponentSection) -> HardeningResult<ResolvedHardening> {
    let name = sandbox_hardening_profile_name(sandbox)?;
    let profile = resolve_hardening_profile(&name).map_err(|source| HardeningError::Resolve {
        name: name.clone(),
        source,
    })?;
    let metadata = hardening_metadata(&profile).map_err(|source| HardeningError::Metadata {
        name: name.clone(),
        source,
    })?;

    Ok(ResolvedHardening { profile, metadata })
}

pub fn apply_resolved_hardening_to_policy(
    policy: &mut agentenv_proto::NetworkPolicy,
    resolved: &ResolvedHardening,
    persist_home: bool,
) -> HardeningResult<()> {
    apply_hardening_to_policy(policy, &resolved.profile, persist_home).map_err(|source| {
        HardeningError::Apply {
            name: resolved.profile.name.clone(),
            source,
        }
    })
}

fn sandbox_hardening_profile_name(sandbox: &ComponentSection) -> HardeningResult<String> {
    match sandbox.extra.get("hardening") {
        None | Some(serde_yaml::Value::Null) => Ok(DEFAULT_HARDENING_PROFILE.to_owned()),
        Some(serde_yaml::Value::String(name)) if name.trim().is_empty() => {
            Err(HardeningError::EmptyName)
        }
        Some(serde_yaml::Value::String(name)) => Ok(name.clone()),
        Some(_) => Err(HardeningError::InvalidType),
    }
}
