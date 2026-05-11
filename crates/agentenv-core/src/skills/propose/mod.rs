mod extract;
mod generalize;
mod model;
mod score;
mod self_test;

pub use extract::{extract_candidates, normalize_args_shape};
pub use generalize::{validate_generalization, SkillGeneralizationRequest, SkillGeneralizer};
pub use model::{
    CandidateExtractionOptions, CandidateToolCall, ExistingSkillSummary, NoveltyBackend,
    ProcedureStep, ProposalCandidate, ProposalScore, ProposalScoreInput, ProposalSelfTestInput,
    ProposalSelfTestReport, ProposedSelfTest, SkillGeneralization, SkillMatch, TemplateVariable,
};
pub use score::score_proposal;
pub use self_test::evaluate_self_test;
