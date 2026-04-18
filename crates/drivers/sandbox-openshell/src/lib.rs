#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use agentenv_policy::{OpenShellTranslator, PolicyError, PolicyTranslator, TranslatedPolicy};

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "sandbox-openshell";

const DEFAULT_OPEN_SHELL_AGENT_BINARIES: [&str; 3] = ["claude", "codex", "openclaw"];
const DEFAULT_OPEN_SHELL_SUPPORT_BINARIES: [&str; 1] = ["curl"];

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
    translate_for_openshell_with_binaries(policy, resolve_default_open_shell_binary_paths()?)
}

pub fn translate_for_openshell_with_binaries<I, S>(
    policy: &agentenv_proto::NetworkPolicy,
    binaries: I,
) -> Result<TranslatedPolicy, PolicyError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    OpenShellTranslator::new(binaries).translate(policy)
}

fn resolve_default_open_shell_binary_paths() -> Result<Vec<String>, PolicyError> {
    let resolved: Vec<(&'static str, String)> = DEFAULT_OPEN_SHELL_AGENT_BINARIES
        .iter()
        .chain(DEFAULT_OPEN_SHELL_SUPPORT_BINARIES.iter())
        .copied()
        .filter_map(|binary| resolve_binary_on_path(binary).map(|path| (binary, path)))
        .collect();

    let binaries: Vec<String> = resolved.iter().map(|(_, path)| path.clone()).collect();
    let has_agent_binary = resolved
        .iter()
        .any(|(binary, _)| DEFAULT_OPEN_SHELL_AGENT_BINARIES.contains(binary));

    if !has_agent_binary {
        Err(PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!(
                "could not resolve any default OpenShell agent binaries on PATH (looked for: {})",
                DEFAULT_OPEN_SHELL_AGENT_BINARIES.join(", ")
            ),
        })
    } else {
        Ok(binaries)
    }
}

fn resolve_binary_on_path(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for candidate in executable_candidates(&dir, binary) {
            if is_executable_candidate(&candidate) {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }

    None
}

#[cfg(not(windows))]
fn executable_candidates(dir: &Path, binary: &str) -> Vec<PathBuf> {
    vec![dir.join(binary)]
}

#[cfg(not(windows))]
fn is_executable_candidate(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    candidate
        .metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn executable_candidates(dir: &Path, binary: &str) -> Vec<PathBuf> {
    if Path::new(binary).extension().is_some() {
        return vec![dir.join(binary)];
    }

    let path_ext = std::env::var_os("PATHEXT")
        .unwrap_or_else(|| std::ffi::OsString::from(".COM;.EXE;.BAT;.CMD"));
    path_ext
        .to_string_lossy()
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| dir.join(format!("{binary}{ext}")))
        .collect()
}

#[cfg(windows)]
fn is_executable_candidate(candidate: &Path) -> bool {
    candidate.is_file()
}
