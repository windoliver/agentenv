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
