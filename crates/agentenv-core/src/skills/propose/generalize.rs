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
    require_non_empty("skill_md_body", &generalization.skill_md_body)?;
    reject_secret_text(&generalization.skill_md_body)?;

    let allowed_tools = allowed_tools.iter().cloned().collect::<BTreeSet<_>>();
    let variables = generalization
        .template_variables
        .iter()
        .map(|variable| variable.name.clone())
        .collect::<BTreeSet<_>>();
    for variable in &generalization.template_variables {
        validate_skill_name(&variable.name)?;
        require_non_empty("template variable description", &variable.description)?;
    }
    for step in &generalization.procedure_steps {
        require_non_empty("procedure step instruction", &step.instruction)?;
        reject_secret_text(&step.instruction)?;
        if let Some(tool) = &step.tool {
            if !allowed_tools.contains(tool) {
                return Err(SkillError::InvalidConfig {
                    message: format!("generalized step references unknown tool `{tool}`"),
                });
            }
        }
    }
    for variable in variables {
        let marker = format!("{{{{{variable}}}}}");
        let referenced = generalization.skill_md_body.contains(&marker)
            || generalization
                .procedure_steps
                .iter()
                .any(|step| step.instruction.contains(&marker));
        if !referenced {
            return Err(SkillError::InvalidConfig {
                message: format!("template variable `{variable}` is not referenced"),
            });
        }
    }
    require_non_empty("self-test command", &generalization.self_test.command)?;
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
    if lowered.contains("sk-") || lowered.contains("bearer ") || lowered.contains("token ") {
        return Err(SkillError::InvalidConfig {
            message: "generalized skill text contains secret-like content".to_owned(),
        });
    }
    Ok(())
}
