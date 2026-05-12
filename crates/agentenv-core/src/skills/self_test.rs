use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use sha2::{Digest, Sha256};

use super::{manifest::normalize_bundle_path, SkillError};

const SKILL_TEST_FILE: &str = "skill-test.yaml";
const SKILL_MD_FILE: &str = "SKILL.md";
const SKILL_YAML_FILE: &str = "skill.yaml";
const DEFAULT_TIMEOUT_SECONDS: u64 = 120;
const LEGACY_TIMEOUT_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkillSelfTestRunner {
    Agentenv,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillSelfTestSpec {
    pub runner: SkillSelfTestRunner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blueprint: Option<PathBuf>,
    pub assertions: Vec<SkillSelfTestAssertion>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SkillSelfTestAssertion {
    CommandExitsZero {
        cmd: String,
    },
    FileExists {
        path: PathBuf,
    },
    AgentProduces {
        prompt: String,
        expect_tokens_matching: Vec<String>,
        min_match_ratio: f64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfTestDocument {
    self_test: RawSelfTestSpec,
}

#[derive(Debug, Deserialize)]
struct FrontmatterSelfTestDocument {
    self_test: RawSelfTestSpec,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelfTestSpec {
    runner: Option<String>,
    blueprint: Option<String>,
    assertions: Option<Vec<SkillSelfTestAssertion>>,
    timeout_seconds: Option<u64>,
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSkillYaml {
    self_test: Option<RawSelfTestSpec>,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

pub fn load_skill_self_test_spec(root: impl AsRef<Path>) -> Result<SkillSelfTestSpec, SkillError> {
    let root = root.as_ref();
    let mut specs = Vec::new();

    if let Some(spec) = load_from_skill_test_yaml(root)? {
        specs.push(("skill-test.yaml", spec));
    }
    if let Some(spec) = load_from_skill_md_frontmatter(root)? {
        specs.push(("SKILL.md", spec));
    }
    if let Some(spec) = load_from_skill_yaml(root)? {
        specs.push(("skill.yaml", spec));
    }

    let Some((_, first)) = specs.first().cloned() else {
        return Err(SkillError::MissingSelfTest);
    };
    let first_digest = normalized_self_test_digest(&first)?;
    for (source, spec) in specs.iter().skip(1) {
        if first_digest != normalized_self_test_digest(spec)? {
            return Err(SkillError::ConflictingSelfTestDeclarations {
                declaration_source: (*source).to_owned(),
            });
        }
    }
    Ok(first)
}

pub fn normalized_self_test_digest(spec: &SkillSelfTestSpec) -> Result<String, SkillError> {
    let bytes = serde_json::to_vec(spec).map_err(|source| SkillError::InvalidSelfTest {
        message: format!("failed to serialize normalized self-test: {source}"),
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn load_from_skill_test_yaml(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_TEST_FILE);
    let Some(content) = read_optional_file(&path)? else {
        return Ok(None);
    };
    let document =
        serde_yaml::from_str::<SelfTestDocument>(&content).map_err(|source| SkillError::Yaml {
            path: path.clone(),
            source,
        })?;
    normalize_raw_self_test(document.self_test, false).map(Some)
}

fn load_from_skill_yaml(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_YAML_FILE);
    let Some(content) = read_optional_file(&path)? else {
        return Ok(None);
    };
    let document =
        serde_yaml::from_str::<RawSkillYaml>(&content).map_err(|source| SkillError::Yaml {
            path: path.clone(),
            source,
        })?;
    document
        .self_test
        .map(|raw| normalize_raw_self_test(raw, true))
        .transpose()
}

fn load_from_skill_md_frontmatter(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_MD_FILE);
    let Some(content) = read_optional_file(&path)? else {
        return Ok(None);
    };
    let Some(frontmatter) = yaml_frontmatter(&content) else {
        return Ok(None);
    };
    if !frontmatter_contains_self_test_key(frontmatter) {
        return Ok(None);
    }
    let document =
        serde_yaml::from_str::<FrontmatterSelfTestDocument>(frontmatter).map_err(|source| {
            SkillError::Yaml {
                path: path.clone(),
                source,
            }
        })?;
    normalize_raw_self_test(document.self_test, false).map(Some)
}

fn yaml_frontmatter(content: &str) -> Option<&str> {
    let content = content.strip_prefix("---")?;
    let content = content
        .strip_prefix("\r\n")
        .or_else(|| content.strip_prefix('\n'))?;
    let marker = content.find("\n---")?;
    Some(&content[..marker])
}

fn frontmatter_contains_self_test_key(frontmatter: &str) -> bool {
    frontmatter.lines().any(|line| {
        if line.starts_with(char::is_whitespace) {
            return false;
        }
        let Some((key, _)) = line.split_once(':') else {
            return false;
        };
        let key = key.trim();
        matches!(key, "self_test" | "'self_test'" | "\"self_test\"")
    })
}

fn normalize_raw_self_test(
    raw: RawSelfTestSpec,
    allow_legacy_command: bool,
) -> Result<SkillSelfTestSpec, SkillError> {
    if raw.command.is_some() && !allow_legacy_command {
        return Err(SkillError::InvalidSelfTest {
            message: "`command` self-test shorthand is only supported in skill.yaml".to_owned(),
        });
    }
    if raw.command.is_some() && raw.assertions.is_some() {
        return Err(SkillError::InvalidSelfTest {
            message: "`command` self-test shorthand cannot be combined with assertions".to_owned(),
        });
    }
    if raw.command.is_some() && raw.blueprint.is_some() {
        return Err(SkillError::InvalidSelfTest {
            message: "`command` self-test shorthand cannot be combined with blueprint".to_owned(),
        });
    }

    let legacy_command = raw.command;
    let is_legacy_command = legacy_command.is_some();
    let runner = match raw.runner.as_deref().unwrap_or("agentenv") {
        "agentenv" => SkillSelfTestRunner::Agentenv,
        runner => {
            return Err(SkillError::InvalidSelfTest {
                message: format!("unsupported self-test runner `{runner}`"),
            });
        }
    };
    let blueprint = raw
        .blueprint
        .map(|blueprint| normalize_bundle_path(Path::new(&blueprint)))
        .transpose()?;
    let mut assertions = if let Some(command) = legacy_command {
        vec![SkillSelfTestAssertion::CommandExitsZero { cmd: command }]
    } else {
        raw.assertions.ok_or_else(|| SkillError::InvalidSelfTest {
            message: "self-test assertions are required".to_owned(),
        })?
    };

    if assertions.is_empty() {
        return Err(SkillError::InvalidSelfTest {
            message: "self-test assertions must not be empty".to_owned(),
        });
    }
    for assertion in &mut assertions {
        validate_assertion(assertion)?;
    }

    let timeout_seconds = if is_legacy_command {
        LEGACY_TIMEOUT_SECONDS
    } else {
        raw.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS)
    };
    if timeout_seconds == 0 {
        return Err(SkillError::InvalidSelfTest {
            message: "self-test timeout_seconds must be greater than 0".to_owned(),
        });
    }

    Ok(SkillSelfTestSpec {
        runner,
        blueprint,
        assertions,
        timeout_seconds,
    })
}

fn validate_assertion(assertion: &mut SkillSelfTestAssertion) -> Result<(), SkillError> {
    match assertion {
        SkillSelfTestAssertion::CommandExitsZero { cmd } => {
            if cmd.trim().is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "command_exits_zero assertion requires a non-empty cmd".to_owned(),
                });
            }
        }
        SkillSelfTestAssertion::FileExists { path } => {
            *path = normalize_bundle_path(path)?;
        }
        SkillSelfTestAssertion::AgentProduces {
            prompt,
            expect_tokens_matching,
            min_match_ratio,
        } => {
            if prompt.trim().is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces assertion requires a non-empty prompt".to_owned(),
                });
            }
            if expect_tokens_matching.is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces assertion requires expected tokens".to_owned(),
                });
            }
            if expect_tokens_matching
                .iter()
                .any(|token| token.trim().is_empty())
            {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces expected tokens must not be empty".to_owned(),
                });
            }
            if !min_match_ratio.is_finite() || *min_match_ratio < 0.0 || *min_match_ratio > 1.0 {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces min_match_ratio must be between 0.0 and 1.0"
                        .to_owned(),
                });
            }
        }
    }

    Ok(())
}

fn read_optional_file(path: &Path) -> Result<Option<String>, SkillError> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}
