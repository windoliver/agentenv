mod extract;
mod generalize;
mod model;
mod score;

pub use extract::{extract_candidates, normalize_args_shape};
pub use generalize::{validate_generalization, SkillGeneralizationRequest, SkillGeneralizer};
pub use model::{
    CandidateExtractionOptions, CandidateToolCall, ExistingSkillSummary, NoveltyBackend,
    ProcedureStep, ProposalCandidate, ProposalScore, ProposalScoreInput, ProposedSelfTest,
    SkillGeneralization, SkillMatch, TemplateVariable,
};
pub use score::score_proposal;
