use super::model::{ReferenceDocument, SkillBundleMetadata};
use serde::Serialize;

pub(crate) const AGENTENV_BUNDLE_SCHEMA: &str = "0.1";

#[derive(Debug, Serialize)]
struct SkillFrontmatter<'a> {
    name: &'a str,
    description: &'a str,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<&'a str>,
    #[serde(rename = "agentenv-bundle")]
    agentenv_bundle: bool,
    #[serde(rename = "agentenv-schema")]
    agentenv_schema: &'static str,
}

#[derive(Debug, Serialize)]
struct SkillYaml<'a> {
    name: &'a str,
    version: String,
    description: &'a str,
    entry: &'static str,
    files: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<&'a str>,
    agentenv_bundle: bool,
    agentenv_schema: &'static str,
}

pub(crate) fn render_skill_md(
    metadata: &SkillBundleMetadata,
    env_name: &str,
    has_reference: bool,
) -> Result<String, serde_yaml::Error> {
    let frontmatter = SkillFrontmatter {
        name: &metadata.name,
        description: &metadata.description,
        version: metadata.version.to_string(),
        author: metadata.author.as_deref(),
        license: metadata.license.as_deref(),
        tags: metadata.tags.iter().map(String::as_str).collect(),
        agentenv_bundle: true,
        agentenv_schema: AGENTENV_BUNDLE_SCHEMA,
    };
    let frontmatter = serde_yaml::to_string(&frontmatter)?;

    let mut body = vec![
        format!("# {}", metadata.name),
        String::new(),
        format!(
            "This skill reconstructs the `{env_name}` development environment with `agentenv`."
        ),
        String::new(),
        "## Bootstrap".to_owned(),
        String::new(),
        "Run this from the skill directory:".to_owned(),
        String::new(),
        "```bash".to_owned(),
        "scripts/bootstrap.sh".to_owned(),
        "```".to_owned(),
        String::new(),
        "The script verifies `agentenv.lock` and reproduces the environment with:".to_owned(),
        String::new(),
        "```bash".to_owned(),
        "agentenv verify agentenv.lock".to_owned(),
        format!("agentenv reproduce agentenv.lock --name {env_name}"),
        "```".to_owned(),
        String::new(),
        "## Included Files".to_owned(),
        String::new(),
        "- `blueprint.yaml` is the frozen blueprint used to create the environment.".to_owned(),
        "- `agentenv.lock` pins drivers, artifacts, policy, and credential references.".to_owned(),
    ];
    if has_reference {
        body.push("- `references/architecture.md` contains copied project architecture notes when available.".to_owned());
    }

    Ok(format!("---\n{}---\n\n{}\n", frontmatter, body.join("\n")))
}

pub(crate) fn render_skill_yaml(
    metadata: &SkillBundleMetadata,
    has_reference: bool,
) -> Result<String, serde_yaml::Error> {
    let mut files = vec![
        "SKILL.md",
        "blueprint.yaml",
        "agentenv.lock",
        "scripts/**",
        ".agentenv/**",
    ];
    if has_reference {
        files.push("references/**");
    }

    let skill_yaml = SkillYaml {
        name: &metadata.name,
        version: metadata.version.to_string(),
        description: &metadata.description,
        entry: "SKILL.md",
        files,
        tags: metadata.tags.iter().map(String::as_str).collect(),
        agentenv_bundle: true,
        agentenv_schema: AGENTENV_BUNDLE_SCHEMA,
    };
    serde_yaml::to_string(&skill_yaml)
}

pub(crate) fn render_bootstrap(env_name: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
BUNDLE_DIR="$(cd "${{SCRIPT_DIR}}/.." && pwd)"
ENV_NAME="${{AGENTENV_ENV_NAME:-{env_name}}}"

cd "${{BUNDLE_DIR}}"
agentenv verify agentenv.lock
agentenv reproduce agentenv.lock --name "${{ENV_NAME}}"
"#
    )
}

pub(crate) fn render_reference(document: &ReferenceDocument) -> String {
    format!(
        "# Project Architecture\n\nSource: `{}`\n\n{}",
        document.source_relative_path,
        ensure_trailing_newline(&document.content)
    )
}

pub(crate) fn ensure_trailing_newline(input: &str) -> String {
    if input.ends_with('\n') {
        input.to_owned()
    } else {
        format!("{input}\n")
    }
}
