use std::collections::BTreeSet;

use super::{
    emit_proposal, evaluate_self_test, extract_candidates, score_proposal, validate_generalization,
    CandidateExtractionOptions, ProposalEmitInput, ProposalScoreInput, ProposalSelfTestInput,
    ProposeRunInput, ProposeRunOutput, SkillGeneralizationRequest, SkillGeneralizer,
};
use crate::skills::SkillError;

pub struct ProposedSkillService {
    generalizer: Box<dyn SkillGeneralizer>,
}

impl ProposedSkillService {
    pub fn new(generalizer: Box<dyn SkillGeneralizer>) -> Self {
        Self { generalizer }
    }

    pub async fn run(&self, input: ProposeRunInput) -> Result<ProposeRunOutput, SkillError> {
        validate_min_novelty(input.min_novelty)?;
        let candidates = extract_candidates(
            &input.traces,
            CandidateExtractionOptions {
                blueprint_id: input.blueprint_id.clone(),
                min_occurrences: input.min_occurrences,
            },
        )?;
        let mut proposals = Vec::new();
        let mut warnings = Vec::new();
        let mut emitted_names = BTreeSet::new();
        for candidate in candidates {
            let request = SkillGeneralizationRequest {
                schema_version: "0.1".to_owned(),
                candidate_json: serde_json::to_value(&candidate).map_err(|source| {
                    SkillError::InvalidConfig {
                        message: format!("failed to encode proposal candidate: {source}"),
                    }
                })?,
                existing_skill_summaries: input
                    .existing_skills
                    .iter()
                    .map(|skill| skill.name.clone())
                    .collect(),
            };
            let generalization = self.generalizer.generalize(request).await?;
            let allowed_tools = candidate
                .sequence
                .iter()
                .map(|call| call.tool.clone())
                .collect::<Vec<_>>();
            validate_generalization(&generalization, &allowed_tools)?;
            let score = score_proposal(ProposalScoreInput {
                name: generalization.name.clone(),
                description: generalization.description.clone(),
                procedure_text: generalization.skill_md_body.clone(),
                fingerprint: candidate.fingerprint.clone(),
                occurrences: candidate.occurrences,
                existing_skills: input.existing_skills.clone(),
                backend: super::NoveltyBackend::Local,
            })?;
            if score.novelty < input.min_novelty {
                warnings.push(format!(
                    "skipped `{}` because novelty {} is below {}",
                    generalization.name, score.novelty, input.min_novelty
                ));
                continue;
            }
            let self_test = evaluate_self_test(ProposalSelfTestInput {
                source_tools: allowed_tools,
                procedure_steps: generalization.procedure_steps.clone(),
                template_variables: generalization.template_variables.clone(),
                min_score: input.min_self_test_score,
            })?;
            if !self_test.passed {
                warnings.push(self_test_warning(
                    &generalization.name,
                    self_test.score,
                    input.min_self_test_score,
                    &self_test.failures,
                ));
                continue;
            }
            if !emitted_names.insert(generalization.name.clone()) {
                warnings.push(format!(
                    "skipped `{}` because duplicate generated name was already proposed",
                    generalization.name
                ));
                continue;
            }
            proposals.push(emit_proposal(ProposalEmitInput {
                output_root: input.output_root.clone(),
                candidate,
                generalization,
                score,
                self_test,
                agentenv_version: input.agentenv_version.clone(),
                created_at: input.created_at.clone(),
            })?);
        }
        Ok(ProposeRunOutput {
            proposals,
            warnings,
        })
    }
}

fn validate_min_novelty(min_novelty: f32) -> Result<(), SkillError> {
    if !min_novelty.is_finite() || !(0.0..=1.0).contains(&min_novelty) {
        return Err(SkillError::InvalidConfig {
            message: "min novelty must be a finite value between 0.0 and 1.0".to_owned(),
        });
    }
    Ok(())
}

fn self_test_warning(
    name: &str,
    score: f32,
    min_self_test_score: f32,
    failures: &[String],
) -> String {
    let score_below_threshold = score < min_self_test_score;
    match (failures.is_empty(), score_below_threshold) {
        (true, true) => format!(
            "skipped `{name}` because self-test score {score} is below {min_self_test_score}"
        ),
        (true, false) => format!("skipped `{name}` because self-test did not pass"),
        (false, true) => format!(
            "skipped `{name}` because self-test failed: {}; score {score} is below {min_self_test_score}",
            failures.join("; ")
        ),
        (false, false) => format!(
            "skipped `{name}` because self-test failed: {}",
            failures.join("; ")
        ),
    }
}
