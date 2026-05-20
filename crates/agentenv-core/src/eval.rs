use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("failed to parse eval suite YAML: {0}")]
    ParseYaml(#[from] serde_yaml::Error),
    #[error("eval suite kind must be `eval-suite`, got `{0}`")]
    InvalidKind(String),
    #[error("eval suite must declare at least one runner")]
    MissingRunner,
    #[error("eval suite metadata.name must not be empty")]
    EmptyName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalSuite {
    pub version: String,
    pub kind: EvalSuiteKind,
    pub metadata: EvalMetadata,
    #[serde(default)]
    pub target: EvalTarget,
    pub runners: Vec<EvalRunner>,
    #[serde(default)]
    pub cases: Vec<EvalCase>,
}

impl EvalSuite {
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.kind != EvalSuiteKind::EvalSuite {
            return Err(EvalError::InvalidKind(self.kind.as_str().to_owned()));
        }
        if self.metadata.name.trim().is_empty() {
            return Err(EvalError::EmptyName);
        }
        if self.runners.is_empty() {
            return Err(EvalError::MissingRunner);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvalSuiteKind {
    EvalSuite,
}

impl EvalSuiteKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EvalSuite => "eval-suite",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalTarget {
    #[serde(default)]
    pub lifecycle: EvalLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_name: Option<String>,
    #[serde(default)]
    pub requires: EvalTargetRequires,
}

impl Default for EvalTarget {
    fn default() -> Self {
        Self {
            lifecycle: EvalLifecycle::Ephemeral,
            env_name: None,
            requires: EvalTargetRequires::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvalLifecycle {
    #[default]
    Ephemeral,
    Existing,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalTargetRequires {
    #[serde(default)]
    pub agent_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRunner {
    pub id: String,
    #[serde(rename = "type")]
    pub runner_type: EvalRunnerType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvalRunnerType {
    Promptfoo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCase {
    pub id: String,
    #[serde(default)]
    pub input: BTreeMap<String, Value>,
    #[serde(default)]
    pub expected: BTreeMap<String, Value>,
    #[serde(default)]
    pub assertions: Vec<EvalAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalAssertion {
    Contains { value: String },
    NotContains { value: String },
    MatchesRegex { value: String },
    NotMatchesRegex { value: String },
    JsonPathEquals { path: String, value: Value },
    ExitCode { value: i32 },
}

pub fn load_eval_suite_from_yaml(yaml: &str) -> Result<EvalSuite, EvalError> {
    let suite: EvalSuite = serde_yaml::from_str(yaml)?;
    suite.validate()?;
    Ok(suite)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalPlan {
    pub suite_name: String,
    pub blueprint_path: PathBuf,
    pub run_dir: PathBuf,
    pub env_name: String,
    pub runners: Vec<EvalRunnerPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalRunnerPlan {
    pub id: String,
    pub runner_type: EvalRunnerType,
    pub command: String,
    pub config: Option<PathBuf>,
    pub output: PathBuf,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum EvalPlanError {
    #[error("{field} path `{path}` must be relative")]
    AbsolutePath { field: &'static str, path: String },
    #[error("{field} path `{path}` escapes {base}")]
    EscapesBaseDirectory {
        field: &'static str,
        path: String,
        base: &'static str,
    },
    #[error("metadata.name `{name}` must be a safe directory name")]
    InvalidSuiteName { name: String },
    #[error("runner `{runner}` must declare config for promptfoo")]
    MissingPromptfooConfig { runner: String },
    #[error(
        "target lifecycle `ephemeral` is not wired yet; pass `--env <name>` or use `target.lifecycle: existing`"
    )]
    EphemeralUnsupported,
}

pub struct EvalPlanInput<'a> {
    pub suite: EvalSuite,
    pub suite_path: &'a Path,
    pub blueprint_path: &'a Path,
    pub run_root: &'a Path,
    pub env_override: Option<&'a str>,
    pub output_override: Option<&'a Path>,
    pub run_id: &'a str,
}

pub fn build_eval_plan(input: EvalPlanInput<'_>) -> Result<EvalPlan, EvalPlanError> {
    if input.suite.target.lifecycle == EvalLifecycle::Ephemeral && input.env_override.is_none() {
        return Err(EvalPlanError::EphemeralUnsupported);
    }

    let suite_root = input
        .suite_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let suite_name = input.suite.metadata.name.clone();
    validate_suite_directory_name(&suite_name)?;
    let run_dir = input
        .output_override
        .and_then(Path::parent)
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| input.run_root.join(&suite_name).join(input.run_id));
    let env_name = input
        .env_override
        .map(ToOwned::to_owned)
        .or_else(|| input.suite.target.env_name.clone())
        .unwrap_or_else(|| format!("eval-{}-{}", sanitize_name(&suite_name), input.run_id));

    let mut runners = Vec::new();
    for runner in input.suite.runners {
        let command = runner
            .command
            .clone()
            .unwrap_or_else(|| match runner.runner_type {
                EvalRunnerType::Promptfoo => "promptfoo".to_owned(),
            });
        let config = match runner.runner_type {
            EvalRunnerType::Promptfoo => {
                let config = runner.config.as_deref().ok_or_else(|| {
                    EvalPlanError::MissingPromptfooConfig {
                        runner: runner.id.clone(),
                    }
                })?;
                Some(resolve_suite_relative_path(
                    "runner.config",
                    suite_root,
                    config,
                )?)
            }
        };
        let output = match runner.output.as_deref() {
            Some(path) => resolve_run_relative_path("runner.output", &run_dir, path)?,
            None => run_dir.join("promptfoo-results.json"),
        };
        runners.push(EvalRunnerPlan {
            id: runner.id,
            runner_type: runner.runner_type,
            command,
            config,
            output,
            env: runner.env,
        });
    }

    Ok(EvalPlan {
        suite_name,
        blueprint_path: input.blueprint_path.to_path_buf(),
        run_dir,
        env_name,
        runners,
    })
}

fn resolve_suite_relative_path(
    field: &'static str,
    root: &Path,
    raw: &str,
) -> Result<PathBuf, EvalPlanError> {
    reject_unsafe_relative(field, raw, "suite root")?;
    Ok(root.join(raw))
}

fn resolve_run_relative_path(
    field: &'static str,
    run_dir: &Path,
    raw: &str,
) -> Result<PathBuf, EvalPlanError> {
    reject_unsafe_relative(field, raw, "run dir")?;
    Ok(run_dir.join(raw))
}

fn reject_unsafe_relative(
    field: &'static str,
    raw: &str,
    base: &'static str,
) -> Result<(), EvalPlanError> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(EvalPlanError::AbsolutePath {
            field,
            path: raw.to_owned(),
        });
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    }) {
        return Err(EvalPlanError::EscapesBaseDirectory {
            field,
            path: raw.to_owned(),
            base,
        });
    }
    Ok(())
}

fn validate_suite_directory_name(name: &str) -> Result<(), EvalPlanError> {
    let path = Path::new(name);
    let mut components = path.components();
    let is_single_normal_component =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !is_single_normal_component || name.contains('/') || name.contains('\\') {
        return Err(EvalPlanError::InvalidSuiteName {
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn sanitize_name(name: &str) -> String {
    let mut sanitized = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            sanitized.push(ch);
        } else {
            sanitized.push('-');
        }
    }
    sanitized.trim_matches('-').to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvalRunnerStatus {
    Passed,
    Failed,
    InfrastructureError,
}

pub fn eval_status_from_runners(statuses: &[EvalRunnerStatus]) -> EvalRunnerStatus {
    if statuses.contains(&EvalRunnerStatus::InfrastructureError) {
        return EvalRunnerStatus::InfrastructureError;
    }
    if statuses.contains(&EvalRunnerStatus::Failed) {
        return EvalRunnerStatus::Failed;
    }
    EvalRunnerStatus::Passed
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalReport {
    pub suite: String,
    pub blueprint: PathBuf,
    pub status: EvalRunnerStatus,
    pub run_id: String,
    pub report_path: PathBuf,
    pub runners: Vec<EvalRunnerReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalRunnerReport {
    pub id: String,
    #[serde(rename = "type")]
    pub runner_type: EvalRunnerType,
    pub status: EvalRunnerStatus,
    pub exit_code: Option<i32>,
    pub artifact: PathBuf,
}
