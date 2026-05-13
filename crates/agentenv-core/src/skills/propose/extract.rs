use std::collections::{BTreeMap, BTreeSet};

use agentenv_events::TraceRun;
use serde_json::Value;

use super::model::{CandidateExtractionOptions, CandidateToolCall, ProposalCandidate};
use crate::skills::SkillError;

pub fn normalize_args_shape(value: &Value) -> Value {
    normalize_value(value).0
}

pub fn extract_candidates(
    traces: &[TraceRun],
    options: CandidateExtractionOptions,
) -> Result<Vec<ProposalCandidate>, SkillError> {
    if options.min_occurrences < 2 {
        return Err(SkillError::InvalidConfig {
            message: "min occurrences must be at least 2".to_owned(),
        });
    }

    let mut groups: BTreeMap<String, (Vec<CandidateToolCall>, BTreeSet<String>, usize)> =
        BTreeMap::new();
    for trace in traces {
        if trace.blueprint_id != options.blueprint_id || trace.calls.is_empty() {
            continue;
        }
        let mut redactions = 0usize;
        let sequence = trace
            .calls
            .iter()
            .map(|call| {
                let (args_shape, count) = normalize_value(&call.args);
                redactions += count;
                CandidateToolCall {
                    tool: call.tool.clone(),
                    args_shape,
                }
            })
            .collect::<Vec<_>>();
        let fingerprint = fingerprint_for(&sequence)?;
        let entry = groups
            .entry(fingerprint)
            .or_insert_with(|| (sequence, BTreeSet::new(), 0));
        entry.1.insert(trace.trace_id.clone());
        entry.2 += redactions;
    }

    let mut candidates = Vec::new();
    for (fingerprint, (sequence, trace_ids, redaction_count)) in groups {
        if trace_ids.len() < options.min_occurrences {
            continue;
        }
        let source_trace_ids = trace_ids.into_iter().collect::<Vec<_>>();
        let name_seed = sequence
            .iter()
            .map(|call| call.tool.replace('_', "-"))
            .collect::<Vec<_>>()
            .join("-");
        candidates.push(ProposalCandidate {
            name_seed,
            blueprint_id: options.blueprint_id.clone(),
            fingerprint,
            occurrences: source_trace_ids.len(),
            sequence,
            source_trace_ids,
            redaction_count,
        });
    }
    candidates.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then(left.fingerprint.cmp(&right.fingerprint))
    });
    Ok(candidates)
}

fn normalize_value(value: &Value) -> (Value, usize) {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            let mut redactions = 0usize;
            for (key, value) in map {
                if is_secret_key(key) {
                    out.insert(key.clone(), Value::String("[redacted]".to_owned()));
                    redactions += 1;
                } else {
                    let (normalized, count) = normalize_value(value);
                    out.insert(key.clone(), normalized);
                    redactions += count;
                }
            }
            (Value::Object(out), redactions)
        }
        Value::Array(values) => {
            let mut redactions = 0usize;
            let values = values
                .iter()
                .map(|value| {
                    let (normalized, count) = normalize_value(value);
                    redactions += count;
                    normalized
                })
                .collect();
            (Value::Array(values), redactions)
        }
        Value::String(text) if looks_like_path(text) => {
            (Value::String("string:path".to_owned()), 0)
        }
        Value::String(text) if looks_like_url(text) => (Value::String("string:url".to_owned()), 0),
        Value::String(_) => (Value::String("string".to_owned()), 0),
        Value::Number(_) => (Value::String("number".to_owned()), 0),
        Value::Bool(_) => (Value::String("bool".to_owned()), 0),
        Value::Null => (Value::String("null".to_owned()), 0),
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("token")
        || key.contains("secret")
        || key.contains("authorization")
        || key.contains("password")
}

fn looks_like_path(text: &str) -> bool {
    text.starts_with('/') || text.contains(".rs") || text.contains(".md") || text.contains(".toml")
}

fn looks_like_url(text: &str) -> bool {
    text.starts_with("http://") || text.starts_with("https://")
}

fn fingerprint_for(sequence: &[CandidateToolCall]) -> Result<String, SkillError> {
    serde_json::to_string(sequence).map_err(|source| SkillError::InvalidConfig {
        message: format!("failed to fingerprint proposal candidate: {source}"),
    })
}
