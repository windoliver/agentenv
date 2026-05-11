mod extract;
mod generalize;
mod model;

pub use extract::{extract_candidates, normalize_args_shape};
pub use generalize::{validate_generalization, SkillGeneralizationRequest, SkillGeneralizer};
pub use model::{
    CandidateExtractionOptions, CandidateToolCall, ProcedureStep, ProposalCandidate,
    ProposedSelfTest, SkillGeneralization, TemplateVariable,
};
