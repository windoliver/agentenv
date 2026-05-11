use std::collections::BTreeSet;

use async_trait::async_trait;

use super::model::SkillGeneralization;
use crate::skills::{validate_skill_name, SkillError};

#[async_trait]
pub trait SkillGeneralizer: Send + Sync {
    async fn generalize(
        &self,
        request: SkillGeneralizationRequest,
    ) -> Result<SkillGeneralization, SkillError>;
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SkillGeneralizationRequest {
    pub schema_version: String,
    pub candidate_json: serde_json::Value,
    pub existing_skill_summaries: Vec<String>,
}

pub fn validate_generalization(
    generalization: &SkillGeneralization,
    allowed_tools: &[String],
) -> Result<(), SkillError> {
    validate_skill_name(&generalization.name)?;
    require_non_empty("description", &generalization.description)?;
    reject_secret_text(&generalization.description)?;
    require_non_empty("skill_md_body", &generalization.skill_md_body)?;
    reject_secret_text(&generalization.skill_md_body)?;

    let allowed_tools = allowed_tools.iter().cloned().collect::<BTreeSet<_>>();
    let mut variables = BTreeSet::new();
    for variable in &generalization.template_variables {
        validate_skill_name(&variable.name)?;
        if !variables.insert(variable.name.clone()) {
            return Err(SkillError::InvalidConfig {
                message: format!(
                    "template variable `{}` is declared more than once",
                    variable.name
                ),
            });
        }
        require_non_empty("template variable description", &variable.description)?;
        reject_secret_text(&variable.description)?;
        reject_secret_text(&variable.example)?;
    }

    let mut referenced_variables =
        template_variables_in("skill_md_body", &generalization.skill_md_body)?;
    for step in &generalization.procedure_steps {
        require_non_empty("procedure step instruction", &step.instruction)?;
        reject_secret_text(&step.instruction)?;
        referenced_variables.extend(template_variables_in(
            "procedure step instruction",
            &step.instruction,
        )?);
        if let Some(tool) = &step.tool {
            if !allowed_tools.contains(tool) {
                return Err(SkillError::InvalidConfig {
                    message: format!("generalized step references unknown tool `{tool}`"),
                });
            }
        }
    }
    for variable in &referenced_variables {
        if !variables.contains(variable) {
            return Err(SkillError::InvalidConfig {
                message: format!("template variable `{variable}` is not declared"),
            });
        }
    }
    for variable in &variables {
        if !referenced_variables.contains(variable) {
            return Err(SkillError::InvalidConfig {
                message: format!("template variable `{variable}` is not referenced"),
            });
        }
    }
    require_non_empty("self-test command", &generalization.self_test.command)?;
    reject_secret_text(&generalization.self_test.command)?;
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), SkillError> {
    if value.trim().is_empty() {
        return Err(SkillError::InvalidConfig {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn reject_secret_text(value: &str) -> Result<(), SkillError> {
    let lowered = value.to_ascii_lowercase();
    if lowered.contains("sk-")
        || lowered.contains("bearer ")
        || lowered.contains("token ")
        || lowered.contains("token:")
        || lowered.contains("api_key")
        || lowered.contains("password")
    {
        return Err(SkillError::InvalidConfig {
            message: "generalized skill text contains secret-like content".to_owned(),
        });
    }
    Ok(())
}

fn template_variables_in(field: &str, value: &str) -> Result<BTreeSet<String>, SkillError> {
    let mut variables = BTreeSet::new();
    let mut remainder = value;
    while let Some(start) = remainder.find("{{") {
        let after_start = &remainder[start + 2..];
        let Some(end) = after_start.find("}}") else {
            return Err(SkillError::InvalidConfig {
                message: format!("{field} contains an unclosed template marker"),
            });
        };
        let variable = &after_start[..end];
        validate_skill_name(variable).map_err(|_| SkillError::InvalidConfig {
            message: format!("{field} contains invalid template marker `{{{{{variable}}}}}`"),
        })?;
        variables.insert(variable.to_owned());
        remainder = &after_start[end + 2..];
    }
    Ok(variables)
}
