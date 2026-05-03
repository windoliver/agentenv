use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use agentenv_policy::{
    apply_hardening_to_policy, hardening_metadata, resolve_hardening_profile, HardeningProfile,
    PolicyError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    blueprint::{Blueprint, ComponentSection},
    runtime::RuntimeError,
};

const DEFAULT_HARDENING_PROFILE: &str = "baseline";
const DOCKERFILE_UNREADABLE: &str = "dockerfile_unreadable";
const DOCKERFILE_USER_ROOT: &str = "dockerfile_user_root";
const DOCKERFILE_PRIVILEGED: &str = "dockerfile_privileged";
const DOCKERFILE_CAP_ADD: &str = "dockerfile_cap_add";
const DOCKERFILE_MISSING_HARDENING_MARKER: &str = "dockerfile_missing_hardening_marker";
const DOCKERFILE_REINTRODUCES_STRIPPED_PACKAGE: &str = "dockerfile_reintroduces_stripped_package";

#[derive(Debug, Clone)]
pub struct ResolvedHardening {
    pub profile: HardeningProfile,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningLintReport {
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<HardeningLintDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningLintDiagnostic {
    pub severity: HardeningLintSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HardeningLintSeverity {
    Info,
    Warning,
    Error,
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

pub fn lint_blueprint_hardening(
    blueprint_yaml: &str,
    cwd: &Path,
) -> Result<HardeningLintReport, RuntimeError> {
    let blueprint = Blueprint::from_yaml(blueprint_yaml)?;
    lint_sandbox_hardening(&blueprint.sandbox, cwd)
}

pub(crate) fn lint_sandbox_hardening(
    sandbox: &ComponentSection,
    cwd: &Path,
) -> Result<HardeningLintReport, RuntimeError> {
    let resolved = resolve_sandbox_hardening(sandbox)?;
    let dockerfile = byo_dockerfile_path(&sandbox.extra).map(|path| resolve_path(cwd, &path));
    let diagnostics = dockerfile
        .as_deref()
        .map(|path| lint_dockerfile(path, &resolved.profile))
        .unwrap_or_default();

    Ok(HardeningLintReport {
        profile: resolved.profile.name,
        dockerfile,
        diagnostics,
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

fn byo_dockerfile_path(sandbox_extra: &BTreeMap<String, serde_yaml::Value>) -> Option<PathBuf> {
    let image = sandbox_extra.get("image")?.as_mapping()?;
    if yaml_mapping_string(image, "source") != Some("byo") {
        return None;
    }
    yaml_mapping_string(image, "dockerfile").map(PathBuf::from)
}

fn yaml_mapping_string<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    mapping
        .get(serde_yaml::Value::String(key.to_owned()))
        .and_then(serde_yaml::Value::as_str)
}

fn resolve_path(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn lint_dockerfile(path: &Path, profile: &HardeningProfile) -> Vec<HardeningLintDiagnostic> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(source) => {
            return vec![diagnostic(
                HardeningLintSeverity::Error,
                DOCKERFILE_UNREADABLE,
                format!(
                    "could not read BYO Dockerfile `{}`: {source}",
                    path.display()
                ),
                None,
                Some("Check the Dockerfile path and permissions before creating the environment"),
            )];
        }
    };

    let analysis = analyze_dockerfile(&contents, profile);
    let mut diagnostics = Vec::new();

    if let Some((line, user)) = analysis.final_root_user {
        diagnostics.push(diagnostic(
            root_user_severity(profile),
            DOCKERFILE_USER_ROOT,
            format!(
                "BYO Dockerfile `{}` leaves the final image user as `{user}` for hardening profile `{}`",
                path.display(),
                profile.name
            ),
            Some(line),
            Some("Set a non-root final USER that matches the sandbox policy"),
        ));
    }

    if let Some(line) = analysis.first_privileged_line {
        diagnostics.push(diagnostic(
            HardeningLintSeverity::Warning,
            DOCKERFILE_PRIVILEGED,
            format!(
                "BYO Dockerfile `{}` references `--privileged`, which conflicts with sandbox isolation expectations",
                path.display()
            ),
            Some(line),
            Some("Remove privileged container nesting from the sandbox image build"),
        ));
    }

    if let Some(line) = analysis.first_cap_add_line {
        diagnostics.push(diagnostic(
            HardeningLintSeverity::Warning,
            DOCKERFILE_CAP_ADD,
            format!(
                "BYO Dockerfile `{}` references capability additions, which may conflict with hardening profile `{}`",
                path.display(),
                profile.name
            ),
            Some(line),
            Some("Move Linux capability requirements into agentenv policy instead of the image"),
        ));
    }

    if !analysis.marker_present {
        diagnostics.push(diagnostic(
            HardeningLintSeverity::Warning,
            DOCKERFILE_MISSING_HARDENING_MARKER,
            format!(
                "BYO Dockerfile `{}` does not declare hardening marker `{}`",
                path.display(),
                profile.dockerfile.marker
            ),
            None,
            Some(
                "Apply the selected hardening profile fragment or declare its marker in the image",
            ),
        ));
    }

    if !analysis.reintroduced_packages.is_empty() {
        let packages = analysis
            .reintroduced_packages
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let line = analysis.reintroduced_packages.values().copied().min();
        diagnostics.push(diagnostic(
            package_reintroduction_severity(profile),
            DOCKERFILE_REINTRODUCES_STRIPPED_PACKAGE,
            format!(
                "BYO Dockerfile `{}` installs package(s) stripped by hardening profile `{}`: {packages}",
                path.display(),
                profile.name
            ),
            line,
            Some("Remove package installation or choose a hardening profile that permits these tools"),
        ));
    }

    diagnostics
}

#[derive(Debug, Default)]
struct DockerfileAnalysis {
    final_root_user: Option<(usize, String)>,
    first_privileged_line: Option<usize>,
    first_cap_add_line: Option<usize>,
    marker_present: bool,
    reintroduced_packages: BTreeMap<String, usize>,
}

fn analyze_dockerfile(contents: &str, profile: &HardeningProfile) -> DockerfileAnalysis {
    let stripped_packages = profile
        .packages
        .strip
        .iter()
        .map(|package| normalize_package_token(package))
        .collect::<BTreeSet<_>>();
    let mut analysis = DockerfileAnalysis::default();

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let Some(active) = active_dockerfile_line(line) else {
            continue;
        };
        let lower = active.to_ascii_lowercase();

        if active.contains(&profile.dockerfile.marker) {
            analysis.marker_present = true;
        }
        if lower.contains("--privileged") && analysis.first_privileged_line.is_none() {
            analysis.first_privileged_line = Some(line_number);
        }
        if (lower.contains("cap_add") || lower.contains("cap-add"))
            && analysis.first_cap_add_line.is_none()
        {
            analysis.first_cap_add_line = Some(line_number);
        }
        if let Some(user) = final_user_from_line(active) {
            analysis.final_root_user = if matches!(user.as_str(), "root" | "0") {
                Some((line_number, user))
            } else {
                None
            };
        }

        for package in installed_packages_from_line(active) {
            let normalized = normalize_package_token(&package);
            if stripped_packages.contains(&normalized) {
                analysis
                    .reintroduced_packages
                    .entry(normalized)
                    .or_insert(line_number);
            }
        }
    }

    analysis
}

fn active_dockerfile_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        None
    } else {
        Some(trimmed)
    }
}

fn final_user_from_line(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let instruction = parts.next()?;
    if !instruction.eq_ignore_ascii_case("USER") {
        return None;
    }
    parts.next().map(|user| {
        user.trim_matches(|ch| ch == '"' || ch == '\'')
            .split(':')
            .next()
            .unwrap_or(user)
            .to_ascii_lowercase()
    })
}

fn installed_packages_from_line(line: &str) -> Vec<String> {
    let mut parts = line.splitn(2, char::is_whitespace);
    let instruction = parts.next().unwrap_or_default();
    if !instruction.eq_ignore_ascii_case("RUN") {
        return Vec::new();
    }
    let command = parts.next().unwrap_or_default();
    let tokens = dockerfile_command_tokens(command);
    let mut packages = Vec::new();

    for index in 0..tokens.len().saturating_sub(1) {
        let token = tokens[index].as_str();
        let next = tokens[index + 1].as_str();
        let package_start = match (token, next) {
            ("apk", "add") | ("apt-get", "install") | ("apt", "install") => index + 2,
            _ => continue,
        };
        packages.extend(package_tokens_after_install(&tokens[package_start..]));
    }

    packages
}

fn dockerfile_command_tokens(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '(' | ')'))
                .to_ascii_lowercase()
        })
        .filter(|token| !token.is_empty())
        .collect()
}

fn package_tokens_after_install(tokens: &[String]) -> Vec<String> {
    let mut packages = Vec::new();
    for token in tokens {
        if matches!(token.as_str(), "&&" | "||" | "|" | ";" | "\\") {
            break;
        }
        let cleaned = token.trim_end_matches([',', ';', '\\']);
        let ends_command = token.len() != cleaned.len();
        if !cleaned.is_empty() && !cleaned.starts_with('-') {
            packages.push(cleaned.to_owned());
        }
        if ends_command {
            break;
        }
    }
    packages
}

fn normalize_package_token(package: &str) -> String {
    package
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ';' | '\\'))
        .split(['=', '<', '>'])
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn root_user_severity(profile: &HardeningProfile) -> HardeningLintSeverity {
    if profile.name == "open" {
        HardeningLintSeverity::Warning
    } else {
        HardeningLintSeverity::Error
    }
}

fn package_reintroduction_severity(profile: &HardeningProfile) -> HardeningLintSeverity {
    if profile.name == "strict" {
        HardeningLintSeverity::Error
    } else {
        HardeningLintSeverity::Warning
    }
}

fn diagnostic(
    severity: HardeningLintSeverity,
    code: &str,
    message: String,
    line: Option<usize>,
    remediation: Option<&str>,
) -> HardeningLintDiagnostic {
    HardeningLintDiagnostic {
        severity,
        code: code.to_owned(),
        message,
        line,
        remediation: remediation.map(ToOwned::to_owned),
    }
}
