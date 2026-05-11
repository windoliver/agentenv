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
        let candidates = extract_candidates(
            &input.traces,
            CandidateExtractionOptions {
                blueprint_id: input.blueprint_id.clone(),
                min_occurrences: input.min_occurrences,
            },
        )?;
        let mut proposals = Vec::new();
        let mut warnings = Vec::new();
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
                warnings.push(format!(
                    "skipped `{}` because self-test score {} is below {}",
                    generalization.name, self_test.score, input.min_self_test_score
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
