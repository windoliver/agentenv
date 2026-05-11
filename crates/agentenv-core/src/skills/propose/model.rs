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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposalScore {
    pub novelty: f32,
    pub utility: f32,
    pub final_score: f32,
    pub nearest_matches: Vec<SkillMatch>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillMatch {
    pub name: String,
    pub similarity: f32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingSkillSummary {
    pub name: String,
    pub description: String,
    pub procedure_text: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoveltyBackend {
    Local,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposalScoreInput {
    pub name: String,
    pub description: String,
    pub procedure_text: String,
    pub fingerprint: String,
    pub occurrences: usize,
    pub existing_skills: Vec<ExistingSkillSummary>,
    pub backend: NoveltyBackend,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposalSelfTestInput {
    pub source_tools: Vec<String>,
    pub procedure_steps: Vec<ProcedureStep>,
    pub template_variables: Vec<TemplateVariable>,
    pub min_score: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposalSelfTestReport {
    pub score: f32,
    pub passed: bool,
    pub matched_steps: u32,
    pub total_steps: u32,
    pub matched_variables: u32,
    pub total_variables: u32,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProposalEmitInput {
    pub output_root: std::path::PathBuf,
    pub candidate: ProposalCandidate,
    pub generalization: SkillGeneralization,
    pub score: ProposalScore,
    pub self_test: ProposalSelfTestReport,
    pub agentenv_version: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposalEmitOutput {
    pub name: String,
    pub path: std::path::PathBuf,
    pub novelty: f32,
    pub self_test_score: f32,
}
