use std::{collections::BTreeMap, fmt};

use semver::{Version, VersionReq};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriverKind {
    Sandbox,
    Agent,
    Context,
    Inference,
}

impl fmt::Display for DriverKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Sandbox => "sandbox",
            Self::Agent => "agent",
            Self::Context => "context",
            Self::Inference => "inference",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid version `{version}` for {kind} driver `{name}`: {source}")]
    InvalidVersion {
        kind: DriverKind,
        name: String,
        version: String,
        #[source]
        source: semver::Error,
    },
    #[error("invalid semver requirement `{requirement}` for {kind} driver `{name}`: {source}")]
    InvalidSemverRequirement {
        kind: DriverKind,
        name: String,
        requirement: String,
        #[source]
        source: semver::Error,
    },
    #[error("unknown driver `{name}` for {kind}")]
    UnknownDriver { kind: DriverKind, name: String },
    #[error(
        "no registered version for {kind} driver `{name}` satisfies requirement `{requirement}`"
    )]
    NoMatchingVersion {
        kind: DriverKind,
        name: String,
        requirement: String,
    },
}

#[derive(Debug, Clone)]
pub struct DriverRegistry {
    entries: BTreeMap<(DriverKind, String), Vec<Version>>,
}

impl DriverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        kind: DriverKind,
        name: impl Into<String>,
        version: impl AsRef<str>,
    ) -> Result<(), RegistryError> {
        let name = name.into();
        let version_str = version.as_ref();
        let parsed =
            Version::parse(version_str).map_err(|source| RegistryError::InvalidVersion {
                kind,
                name: name.clone(),
                version: version_str.to_string(),
                source,
            })?;

        self.register_version(kind, name, parsed);
        Ok(())
    }

    pub fn register_version(
        &mut self,
        kind: DriverKind,
        name: impl Into<String>,
        version: Version,
    ) {
        let versions = self.entries.entry((kind, name.into())).or_default();
        versions.push(version);
        versions.sort();
        versions.dedup();
    }

    pub fn pin(
        &self,
        kind: DriverKind,
        name: &str,
        requirement: Option<&str>,
    ) -> Result<Version, RegistryError> {
        let versions = self.entries.get(&(kind, name.to_string())).ok_or_else(|| {
            RegistryError::UnknownDriver {
                kind,
                name: name.to_string(),
            }
        })?;

        let requirement = match requirement {
            Some(requirement) => Some(VersionReq::parse(requirement).map_err(|source| {
                RegistryError::InvalidSemverRequirement {
                    kind,
                    name: name.to_string(),
                    requirement: requirement.to_string(),
                    source,
                }
            })?),
            None => None,
        };

        versions
            .iter()
            .rev()
            .find(|version| match requirement.as_ref() {
                Some(req) => req.matches(version),
                None => true,
            })
            .cloned()
            .ok_or_else(|| RegistryError::NoMatchingVersion {
                kind,
                name: name.to_string(),
                requirement: requirement
                    .map(|req| req.to_string())
                    .unwrap_or_else(|| "*".to_string()),
            })
    }
}

impl Default for DriverRegistry {
    fn default() -> Self {
        let mut registry = Self {
            entries: BTreeMap::new(),
        };

        registry.register_version(DriverKind::Sandbox, "openshell", Version::new(0, 0, 30));
        registry.register_version(DriverKind::Sandbox, "openshell", Version::new(0, 0, 31));

        for version in [Version::new(0, 0, 1), Version::new(0, 0, 2)] {
            registry.register_version(DriverKind::Agent, "claude", version.clone());
            registry.register_version(DriverKind::Agent, "codex", version.clone());
            registry.register_version(DriverKind::Agent, "hermes", version.clone());
            registry.register_version(DriverKind::Agent, "openclaw", version.clone());
            registry.register_version(DriverKind::Context, "filesystem", version.clone());
            registry.register_version(DriverKind::Context, "mcp-generic", version.clone());
            registry.register_version(DriverKind::Context, "nexus", version.clone());
            registry.register_version(DriverKind::Inference, "passthrough", version.clone());
        }

        registry
    }
}

#[cfg(test)]
mod tests {
    use super::{DriverKind, DriverRegistry};

    #[test]
    fn pin_returns_highest_matching_version() {
        let mut registry = DriverRegistry::new();
        registry
            .register(DriverKind::Agent, "codex", "0.0.1")
            .unwrap();
        registry
            .register(DriverKind::Agent, "codex", "0.0.3")
            .unwrap();
        registry
            .register(DriverKind::Agent, "codex", "0.0.2")
            .unwrap();

        let version = registry
            .pin(DriverKind::Agent, "codex", Some(">=0.0.1,<0.0.3"))
            .unwrap();

        assert_eq!(version.to_string(), "0.0.2");
    }
}
