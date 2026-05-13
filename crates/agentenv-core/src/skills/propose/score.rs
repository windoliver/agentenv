use std::collections::BTreeSet;

use super::model::{ProposalScore, ProposalScoreInput, SkillMatch};
use crate::skills::SkillError;

pub fn score_proposal(input: ProposalScoreInput) -> Result<ProposalScore, SkillError> {
    let mut best: Option<SkillMatch> = None;
    let mut novelty = 0.9f32;
    let mut reasons = Vec::new();

    for existing in &input.existing_skills {
        if existing.fingerprint.as_deref() == Some(input.fingerprint.as_str()) {
            novelty = 0.0;
            best = Some(SkillMatch {
                name: existing.name.clone(),
                similarity: 1.0,
                reason: "exact fingerprint match".to_owned(),
            });
            reasons.push("duplicate of existing skill".to_owned());
            break;
        }
        let similarity = jaccard(&input.procedure_text, &existing.procedure_text)
            .max(jaccard(&input.description, &existing.description));
        if best
            .as_ref()
            .is_none_or(|current| similarity > current.similarity)
        {
            best = Some(SkillMatch {
                name: existing.name.clone(),
                similarity,
                reason: "local semantic similarity".to_owned(),
            });
        }
    }

    if novelty != 0.0 {
        if let Some(best) = &best {
            novelty = if best.similarity >= 0.85 {
                reasons.push("minor variation of existing skill".to_owned());
                0.3
            } else if best.similarity >= 0.45 {
                reasons.push("distinct variant of existing skill family".to_owned());
                0.6
            } else {
                reasons.push("new capability category".to_owned());
                0.9
            };
        } else {
            reasons.push("no existing skill matches".to_owned());
        }
    }

    let utility = ((input.occurrences as f32) / 5.0).clamp(0.0, 1.0);
    let final_score = (novelty * 0.7) + (utility * 0.3);
    Ok(ProposalScore {
        novelty,
        utility,
        final_score,
        nearest_matches: best.into_iter().collect(),
        reasons,
    })
}

fn jaccard(left: &str, right: &str) -> f32 {
    let left = tokens(left);
    let right = tokens(right);
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let intersection = left.intersection(&right).count() as f32;
    let union = left.union(&right).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}
