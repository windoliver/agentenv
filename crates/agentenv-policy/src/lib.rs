#![forbid(unsafe_code)]

pub mod engine;
pub mod error;
pub mod hardening;
pub mod model;
pub mod presets;
pub mod translate;

pub use crate::engine::{compose_policy, Tier};
pub use crate::error::{PolicyError, PolicyResult};
pub use crate::hardening::{
    apply_hardening_to_policy, builtin_hardening_profile, hardening_metadata,
    resolve_hardening_profile, HardeningCapabilities, HardeningDockerfile, HardeningMounts,
    HardeningPackages, HardeningProfile, HardeningTmpfsMount, HardeningUlimits,
};
pub use crate::model::{PresetAccess, PresetSelection};
pub use crate::presets::PresetRegistry;
pub use crate::translate::{
    DockerTranslator, InferenceUpdate, OpenShellTranslator, PolicyTranslator, TranslatedPolicy,
};

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "agentenv-policy";

#[cfg(test)]
mod tests {
    use crate::{model::NetworkPolicy, PolicyError, PresetAccess, PresetSelection};

    #[test]
    fn preset_selection_parses_slug_and_requires_recreate_errors_are_readable() {
        let selection = PresetSelection::from_slug("github_readwrite").expect("parse slug");
        assert_eq!(selection.name, "github");
        assert_eq!(selection.access, PresetAccess::ReadWrite);

        let err = PolicyError::requires_recreate(["filesystem", "process"]);
        assert_eq!(
            err.to_string(),
            "policy update requires recreate for domains: filesystem, process"
        );

        assert!(PresetSelection::from_slug("_read").is_err());
        assert!(PresetSelection::from_slug("_readwrite").is_err());
        assert!(PresetSelection::from_slug("github").is_err());

        let _: Option<NetworkPolicy> = None;
    }
}
