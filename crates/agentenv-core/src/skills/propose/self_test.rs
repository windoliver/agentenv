use std::collections::BTreeSet;

use super::model::{ProposalSelfTestInput, ProposalSelfTestReport};
use crate::skills::SkillError;

pub fn evaluate_self_test(
    input: ProposalSelfTestInput,
) -> Result<ProposalSelfTestReport, SkillError> {
    if !(0.0..=1.0).contains(&input.min_score) {
        return Err(SkillError::InvalidConfig {
            message: "min self-test score must be between 0.0 and 1.0".to_owned(),
        });
    }
    if input.procedure_steps.is_empty() {
        return Err(SkillError::InvalidConfig {
            message: "self-test requires at least one procedure step".to_owned(),
        });
    }

    let source_tools = input.source_tools.iter().cloned().collect::<BTreeSet<_>>();
    let covered_source_tools = input
        .procedure_steps
        .iter()
        .filter_map(|step| step.tool.as_ref())
        .filter(|tool| source_tools.contains(*tool))
        .cloned()
        .collect::<BTreeSet<_>>();
    let unknown_step_tools = input
        .procedure_steps
        .iter()
        .filter_map(|step| step.tool.as_ref())
        .filter(|tool| !source_tools.contains(*tool))
        .cloned()
        .collect::<BTreeSet<_>>();
    let total_steps = source_tools.len() as u32;
    let matched_steps = covered_source_tools.len() as u32;

    let all_text = input
        .procedure_steps
        .iter()
        .map(|step| step.instruction.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let total_variables = input.template_variables.len() as u32;
    let matched_variables = input
        .template_variables
        .iter()
        .filter(|variable| all_text.contains(&format!("{{{{{}}}}}", variable.name)))
        .count() as u32;

    let step_score = ratio(matched_steps, total_steps);
    let variable_score = ratio(matched_variables, total_variables);
    let score = ((step_score * 0.7) + (variable_score * 0.3)).clamp(0.0, 1.0);
    let mut failures = Vec::new();
    if matched_steps != total_steps {
        failures.push("not every source tool is covered by a procedure step".to_owned());
    }
    if !unknown_step_tools.is_empty() {
        failures.push(format!(
            "generated step references tool outside source trace tools: {}",
            unknown_step_tools
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if matched_variables != total_variables {
        failures.push("not every template variable is referenced by a step".to_owned());
    }

    Ok(ProposalSelfTestReport {
        score,
        passed: failures.is_empty() && score >= input.min_score,
        matched_steps,
        total_steps,
        matched_variables,
        total_variables,
        failures,
    })
}

fn ratio(matched: u32, total: u32) -> f32 {
    if total == 0 {
        1.0
    } else {
        matched as f32 / total as f32
    }
}
