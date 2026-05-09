use super::model::{ReferenceDocument, SkillBundleMetadata};

pub(crate) const AGENTENV_BUNDLE_SCHEMA: &str = "0.1";

pub(crate) fn render_skill_md(
    metadata: &SkillBundleMetadata,
    env_name: &str,
    has_reference: bool,
) -> String {
    let mut frontmatter = Vec::new();
    frontmatter.push("---".to_owned());
    frontmatter.push(format!("name: {}", metadata.name));
    frontmatter.push(format!(
        "description: {}",
        yaml_string(&metadata.description)
    ));
    frontmatter.push(format!("version: {}", metadata.version));
    if let Some(author) = metadata.author.as_deref() {
        frontmatter.push(format!("author: {}", yaml_string(author)));
    }
    if let Some(license) = metadata.license.as_deref() {
        frontmatter.push(format!("license: {}", yaml_string(license)));
    }
    if !metadata.tags.is_empty() {
        frontmatter.push(format!("tags: [{}]", metadata.tags.join(", ")));
    }
    frontmatter.push("agentenv-bundle: true".to_owned());
    frontmatter.push(format!("agentenv-schema: \"{}\"", AGENTENV_BUNDLE_SCHEMA));
    frontmatter.push("---".to_owned());

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

    format!("{}\n\n{}\n", frontmatter.join("\n"), body.join("\n"))
}

pub(crate) fn render_skill_yaml(metadata: &SkillBundleMetadata, has_reference: bool) -> String {
    let mut files = vec![
        "  - SKILL.md".to_owned(),
        "  - blueprint.yaml".to_owned(),
        "  - agentenv.lock".to_owned(),
        "  - scripts/**".to_owned(),
        "  - .agentenv/**".to_owned(),
    ];
    if has_reference {
        files.push("  - references/**".to_owned());
    }

    let mut yaml = vec![
        format!("name: {}", metadata.name),
        format!("version: {}", metadata.version),
        format!("description: {}", yaml_string(&metadata.description)),
        "entry: SKILL.md".to_owned(),
        "files:".to_owned(),
    ];
    yaml.extend(files);
    if !metadata.tags.is_empty() {
        yaml.push("tags:".to_owned());
        yaml.extend(metadata.tags.iter().map(|tag| format!("  - {tag}")));
    }
    yaml.push("agentenv_bundle: true".to_owned());
    yaml.push(format!("agentenv_schema: \"{}\"", AGENTENV_BUNDLE_SCHEMA));
    yaml.push(String::new());
    yaml.join("\n")
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

fn yaml_string(value: &str) -> String {
    if is_plain_yaml_scalar(value) {
        value.to_owned()
    } else {
        serde_yaml::to_string(value)
            .map(|serialized| {
                serialized
                    .trim()
                    .trim_start_matches("---")
                    .trim()
                    .trim_end_matches("...")
                    .trim()
                    .to_owned()
            })
            .unwrap_or_else(|_| format!("{value:?}"))
    }
}

fn is_plain_yaml_scalar(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with([
            '-', '?', ':', '@', '`', '&', '*', '#', '!', '|', '>', '{', '[',
        ])
        && !value.contains('\n')
        && !value.contains(": ")
        && !matches!(
            value,
            "true" | "false" | "null" | "~" | "True" | "False" | "NULL"
        )
}
