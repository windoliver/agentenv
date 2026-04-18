#![forbid(unsafe_code)]

pub mod error;
pub mod model;

pub mod engine {}
pub mod presets {}
pub mod translate {}

pub use crate::error::{PolicyError, PolicyResult};
pub use crate::model::{PresetAccess, PresetSelection};

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "agentenv-policy";

#[cfg(test)]
mod tests {
    use crate::{PolicyError, PresetAccess, PresetSelection};

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
    }
}
