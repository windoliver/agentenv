use std::{fs, path::Path};

use serde::Serialize;

use super::model::{ProposalEmitInput, ProposalEmitOutput};
use crate::skills::{load_skill_manifest, validate_skill_name, SkillError};

#[derive(Serialize)]
struct ProposalYaml<'a> {
    schema_version: &'static str,
    status: &'static str,
    blueprint_id: &'a str,
    occurrences: usize,
    novelty: f32,
    utility: f32,
    self_test_score: f32,
    generated_by: GeneratedBy<'a>,
}

#[derive(Serialize)]
struct GeneratedBy<'a> {
    agentenv_version: &'a str,
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
    ensure_output_missing(&output)?;

    let staging = input
        .output_root
        .join(format!(".{}.staging", input.generalization.name));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|source| SkillError::Io {
            path: staging.clone(),
            source,
        })?;
    }
    fs::create_dir_all(staging.join("traces")).map_err(|source| SkillError::Io {
        path: staging.clone(),
        source,
    })?;

    write_file(&staging.join("SKILL.md"), render_skill_md(&input))?;
    write_file(&staging.join("skill.yaml"), render_skill_yaml(&input)?)?;
    write_file(
        &staging.join("proposal.yaml"),
        render_proposal_yaml(&input)?,
    )?;
    write_file(
        &staging.join("self-test.json"),
        json_pretty(&input.self_test, &staging.join("self-test.json"))?,
    )?;
    write_file(
        &staging.join("traces/provenance.json"),
        json_pretty(&input.candidate, &staging.join("traces/provenance.json"))?,
    )?;

    load_skill_manifest(&staging)?;
    fs::rename(&staging, &output).map_err(|source| SkillError::Io {
        path: output.clone(),
        source,
    })?;

    Ok(ProposalEmitOutput {
        name: input.generalization.name,
        path: output,
        novelty: input.score.novelty,
        self_test_score: input.self_test.score,
    })
}

fn ensure_output_missing(output: &Path) -> Result<(), SkillError> {
    match fs::symlink_metadata(output) {
        Ok(_) => Err(SkillError::InvalidConfig {
            message: format!("proposal output `{}` already exists", output.display()),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SkillError::Io {
            path: output.to_path_buf(),
            source,
        }),
    }
}

fn render_skill_md(input: &ProposalEmitInput) -> String {
    format!(
        "---\nname: {}\ndescription: {}\nversion: 0.1.0\ntags: [agentenv-proposed, trace-derived]\nagentenv-proposal: true\nagentenv-schema: \"0.1\"\n---\n\n# {}\n\n{}\n",
        input.generalization.name,
        input.generalization.description,
        input.generalization.name,
        input.generalization.skill_md_body
    )
}

fn render_skill_yaml(input: &ProposalEmitInput) -> Result<String, SkillError> {
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
        path: input.output_root.join("skill.yaml"),
        source,
    })
}

fn render_proposal_yaml(input: &ProposalEmitInput) -> Result<String, SkillError> {
    let value = ProposalYaml {
        schema_version: "0.1",
        status: "proposed",
        blueprint_id: &input.candidate.blueprint_id,
        occurrences: input.candidate.occurrences,
        novelty: input.score.novelty,
        utility: input.score.utility,
        self_test_score: input.self_test.score,
        generated_by: GeneratedBy {
            agentenv_version: &input.agentenv_version,
        },
    };
    serde_yaml::to_string(&value).map_err(|source| SkillError::Serde {
        path: input.output_root.join("proposal.yaml"),
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
