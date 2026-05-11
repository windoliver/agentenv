use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use super::model::{ProposalEmitInput, ProposalEmitOutput};
use crate::skills::{load_skill_manifest, validate_skill_name, SkillError};

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct ProposalYaml<'a> {
    schema_version: &'static str,
    status: &'static str,
    blueprint_id: &'a str,
    occurrences: usize,
    novelty: f32,
    utility: f32,
    self_test_score: f32,
    created_at: &'a str,
    generated_by: GeneratedBy<'a>,
}

#[derive(Serialize)]
struct GeneratedBy<'a> {
    agentenv_version: &'a str,
}

#[derive(Serialize)]
struct SkillMdFrontmatter<'a> {
    name: &'a str,
    description: &'a str,
    version: &'static str,
    tags: &'static [&'static str],
    #[serde(rename = "agentenv-proposal")]
    agentenv_proposal: bool,
    #[serde(rename = "agentenv-schema")]
    agentenv_schema: &'static str,
}

#[derive(Serialize)]
struct SkillYaml<'a> {
    name: &'a str,
    version: &'static str,
    description: &'a str,
    entry: &'static str,
    files: &'static [&'static str],
    self_test: SkillYamlSelfTest<'a>,
    agentenv_proposal: bool,
    agentenv_schema: &'static str,
}

#[derive(Serialize)]
struct SkillYamlSelfTest<'a> {
    command: &'a str,
}

pub fn emit_proposal(input: ProposalEmitInput) -> Result<ProposalEmitOutput, SkillError> {
    validate_skill_name(&input.generalization.name)?;
    let output = input.output_root.join(&input.generalization.name);
    let staging = create_unique_staging_dir(&input.output_root, &input.generalization.name)?;

    if let Err(error) = write_validate_and_publish(&input, &staging, &output) {
        cleanup_dir(&staging);
        return Err(error);
    }

    Ok(ProposalEmitOutput {
        name: input.generalization.name,
        path: output,
        novelty: input.score.novelty,
        utility: input.score.utility,
        final_score: input.score.final_score,
        self_test_score: input.self_test.score,
    })
}

fn create_unique_staging_dir(output_root: &Path, name: &str) -> Result<PathBuf, SkillError> {
    fs::create_dir_all(output_root).map_err(|source| SkillError::Io {
        path: output_root.to_path_buf(),
        source,
    })?;

    for _ in 0..16 {
        let staging = output_root.join(format!(".{name}.staging-{}", unique_staging_suffix()));
        match fs::create_dir(&staging) {
            Ok(()) => return Ok(staging),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(SkillError::Io {
                    path: staging,
                    source,
                });
            }
        }
    }

    Err(SkillError::InvalidConfig {
        message: format!("could not allocate a unique staging directory for proposal `{name}`"),
    })
}

fn unique_staging_suffix() -> String {
    let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}-{counter}", std::process::id())
}

fn write_validate_and_publish(
    input: &ProposalEmitInput,
    staging: &Path,
    output: &Path,
) -> Result<(), SkillError> {
    write_and_validate_staging(input, staging)?;
    publish_staging(staging, output)
}

fn write_and_validate_staging(input: &ProposalEmitInput, staging: &Path) -> Result<(), SkillError> {
    fs::create_dir(staging.join("traces")).map_err(|source| SkillError::Io {
        path: staging.join("traces"),
        source,
    })?;

    let skill_md_path = staging.join("SKILL.md");
    let skill_yaml_path = staging.join("skill.yaml");
    let proposal_yaml_path = staging.join("proposal.yaml");
    let self_test_path = staging.join("self-test.json");
    let provenance_path = staging.join("traces/provenance.json");

    write_file(&skill_md_path, render_skill_md(input, &skill_md_path)?)?;
    write_file(
        &skill_yaml_path,
        render_skill_yaml(input, &skill_yaml_path)?,
    )?;
    write_file(
        &proposal_yaml_path,
        render_proposal_yaml(input, &proposal_yaml_path)?,
    )?;
    write_file(
        &self_test_path,
        json_pretty(&input.self_test, &self_test_path)?,
    )?;
    write_file(
        &provenance_path,
        json_pretty(&input.candidate, &provenance_path)?,
    )?;

    load_skill_manifest(staging)?;
    Ok(())
}

fn publish_staging(staging: &Path, output: &Path) -> Result<(), SkillError> {
    match fs::create_dir(output) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(SkillError::InvalidConfig {
                message: format!("proposal output `{}` already exists", output.display()),
            });
        }
        Err(source) => {
            return Err(SkillError::Io {
                path: output.to_path_buf(),
                source,
            });
        }
    }

    if let Err(error) = move_staged_entries(staging, output) {
        cleanup_dir(output);
        return Err(error);
    }
    if let Err(error) = fs::remove_dir(staging) {
        cleanup_dir(output);
        return Err(SkillError::Io {
            path: staging.to_path_buf(),
            source: error,
        });
    }

    Ok(())
}

fn move_staged_entries(staging: &Path, output: &Path) -> Result<(), SkillError> {
    let entries = fs::read_dir(staging).map_err(|source| SkillError::Io {
        path: staging.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| SkillError::Io {
            path: staging.to_path_buf(),
            source,
        })?;
        let from = entry.path();
        let to = output.join(entry.file_name());
        if to.exists() {
            return Err(SkillError::InvalidConfig {
                message: format!("proposal output path `{}` already exists", to.display()),
            });
        }
        fs::rename(&from, &to).map_err(|source| SkillError::Io { path: to, source })?;
    }
    Ok(())
}

fn cleanup_dir(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn render_skill_md(input: &ProposalEmitInput, path: &Path) -> Result<String, SkillError> {
    let frontmatter = SkillMdFrontmatter {
        name: &input.generalization.name,
        description: &input.generalization.description,
        version: "0.1.0",
        tags: &["agentenv-proposed", "trace-derived"],
        agentenv_proposal: true,
        agentenv_schema: "0.1",
    };
    let mut frontmatter =
        serde_yaml::to_string(&frontmatter).map_err(|source| SkillError::Serde {
            path: path.to_path_buf(),
            source,
        })?;
    if let Some(stripped) = frontmatter.strip_prefix("---\n") {
        frontmatter = stripped.to_owned();
    }
    if !frontmatter.ends_with('\n') {
        frontmatter.push('\n');
    }

    Ok(format!(
        "---\n{}---\n\n# {}\n\n{}\n",
        frontmatter, input.generalization.name, input.generalization.skill_md_body
    ))
}

fn render_skill_yaml(input: &ProposalEmitInput, path: &Path) -> Result<String, SkillError> {
    let value = SkillYaml {
        name: &input.generalization.name,
        version: "0.1.0",
        description: &input.generalization.description,
        entry: "SKILL.md",
        files: &[
            "SKILL.md",
            "proposal.yaml",
            "self-test.json",
            "traces/provenance.json",
        ],
        self_test: SkillYamlSelfTest {
            command: &input.generalization.self_test.command,
        },
        agentenv_proposal: true,
        agentenv_schema: "0.1",
    };
    serde_yaml::to_string(&value).map_err(|source| SkillError::Serde {
        path: path.to_path_buf(),
        source,
    })
}

fn render_proposal_yaml(input: &ProposalEmitInput, path: &Path) -> Result<String, SkillError> {
    let value = ProposalYaml {
        schema_version: "0.1",
        status: "proposed",
        blueprint_id: &input.candidate.blueprint_id,
        occurrences: input.candidate.occurrences,
        novelty: input.score.novelty,
        utility: input.score.utility,
        self_test_score: input.self_test.score,
        created_at: &input.created_at,
        generated_by: GeneratedBy {
            agentenv_version: &input.agentenv_version,
        },
    };
    serde_yaml::to_string(&value).map_err(|source| SkillError::Serde {
        path: path.to_path_buf(),
        source,
    })
}

fn write_file(path: &Path, content: String) -> Result<(), SkillError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SkillError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, content).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn json_pretty<T: Serialize>(value: &T, path: &Path) -> Result<String, SkillError> {
    serde_json::to_string_pretty(value).map_err(|source| SkillError::InvalidConfig {
        message: format!("failed to serialize `{}`: {source}", path.display()),
    })
}
