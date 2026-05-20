use std::{collections::BTreeMap, path::PathBuf};

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
