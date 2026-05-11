use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposalCandidate {
    pub name_seed: String,
    pub blueprint_id: String,
    pub fingerprint: String,
    pub occurrences: usize,
    pub sequence: Vec<CandidateToolCall>,
    pub source_trace_ids: Vec<String>,
    pub redaction_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateToolCall {
    pub tool: String,
    pub args_shape: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateExtractionOptions {
    pub blueprint_id: String,
    pub min_occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillGeneralization {
    pub name: String,
    pub description: String,
    pub template_variables: Vec<TemplateVariable>,
    pub procedure_steps: Vec<ProcedureStep>,
    pub self_test: ProposedSelfTest,
    pub skill_md_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
    pub example: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureStep {
    pub tool: Option<String>,
    pub instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedSelfTest {
    pub command: String,
}
