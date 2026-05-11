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

    let source_tool_names = input.source_tools.iter().cloned().collect::<BTreeSet<_>>();
    let generated_tools = input
        .procedure_steps
        .iter()
        .filter_map(|step| step.tool.as_ref())
        .cloned()
        .collect::<Vec<_>>();
    let unknown_step_tools = input
        .procedure_steps
        .iter()
        .filter_map(|step| step.tool.as_ref())
        .filter(|tool| !source_tool_names.contains(*tool))
        .cloned()
        .collect::<BTreeSet<_>>();
    let matched_steps = ordered_match_count(&input.source_tools, &generated_tools) as u32;
    let total_steps = input.source_tools.len() as u32;

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
        failures.push(
            "not every source tool sequence occurrence is covered by a procedure step".to_owned(),
        );
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

fn ordered_match_count(source_tools: &[String], generated_tools: &[String]) -> usize {
    let mut lengths = vec![vec![0usize; generated_tools.len() + 1]; source_tools.len() + 1];
    for (source_index, source_tool) in source_tools.iter().enumerate() {
        for (generated_index, generated_tool) in generated_tools.iter().enumerate() {
            lengths[source_index + 1][generated_index + 1] = if source_tool == generated_tool {
                lengths[source_index][generated_index] + 1
            } else {
                lengths[source_index][generated_index + 1]
                    .max(lengths[source_index + 1][generated_index])
            };
        }
    }
    lengths[source_tools.len()][generated_tools.len()]
}

fn ratio(matched: u32, total: u32) -> f32 {
    if total == 0 {
        1.0
    } else {
        matched as f32 / total as f32
    }
}
