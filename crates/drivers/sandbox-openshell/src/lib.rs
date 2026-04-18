#![forbid(unsafe_code)]

use agentenv_policy::{OpenShellTranslator, PolicyError, PolicyTranslator, TranslatedPolicy};

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "sandbox-openshell";

const DEFAULT_OPEN_SHELL_BINARY_PATHS: [&str; 3] = [
    "/usr/local/bin/claude",
    "/usr/local/bin/codex",
    "/usr/bin/curl",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateDisposition {
    HotReload,
}

pub fn classify_policy_update(
    current: &agentenv_proto::NetworkPolicy,
    next: &agentenv_proto::NetworkPolicy,
) -> Result<UpdateDisposition, PolicyError> {
    let mut locked_domains = Vec::new();
    if current.filesystem != next.filesystem {
        locked_domains.push("filesystem");
    }
    if current.process != next.process {
        locked_domains.push("process");
    }

    if locked_domains.is_empty() {
        Ok(UpdateDisposition::HotReload)
    } else {
        Err(PolicyError::RequiresRecreate {
            domains: locked_domains.join(", "),
        })
    }
}

pub fn translate_for_openshell(
    policy: &agentenv_proto::NetworkPolicy,
) -> Result<TranslatedPolicy, PolicyError> {
    OpenShellTranslator::new(DEFAULT_OPEN_SHELL_BINARY_PATHS).translate(policy)
}
