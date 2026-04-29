use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{format_rfc3339, ApprovalDecisionRecord, ApprovalKind, ApprovalRequest, ApprovalScope};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalPolicyOverlay {
    pub version: u32,
    pub grants: Vec<ApprovalGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalGrant {
    pub id: String,
    pub kind: ApprovalKind,
    pub subject: String,
    pub context_matcher: serde_json::Value,
    pub created_by: String,
    pub created_at: String,
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApprovalPolicyError {
    #[error("failed to read or write approval policy file `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse or serialize approval policy YAML at `{path}`: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct BaselineProposal {
    request_id: String,
    env: String,
    kind: ApprovalKind,
    subject: String,
    request_reason: String,
    request_context: serde_json::Value,
    decision_scope: ApprovalScope,
    decided_by: String,
    decided_at: String,
    decision_reason: Option<String>,
    decision_context: serde_json::Value,
    trace_id: String,
}

impl ApprovalGrant {
    pub fn from_request_and_decision(
        request: &ApprovalRequest,
        decision: &ApprovalDecisionRecord,
    ) -> Self {
        Self {
            id: request.id.clone(),
            kind: request.kind,
            subject: request.subject.clone(),
            context_matcher: request.context.clone(),
            created_by: decision.decided_by.clone(),
            created_at: format_rfc3339(decision.decided_at),
            reason: decision.reason.clone(),
        }
    }
}

pub fn read_overlay(path: &Path) -> Result<ApprovalPolicyOverlay, ApprovalPolicyError> {
    match fs::read(path) {
        Ok(bytes) => serde_yaml::from_slice(&bytes).map_err(|source| ApprovalPolicyError::Yaml {
            path: path.to_owned(),
            source,
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(ApprovalPolicyOverlay {
            version: 1,
            grants: Vec::new(),
        }),
        Err(source) => Err(ApprovalPolicyError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

pub fn append_overlay_grant(path: &Path, grant: &ApprovalGrant) -> Result<(), ApprovalPolicyError> {
    let mut overlay = read_overlay(path)?;
    overlay.grants.push(grant.clone());
    write_yaml_atomic(path, &overlay)
}

pub fn append_baseline_proposal(
    path: &Path,
    request: &ApprovalRequest,
    decision: &ApprovalDecisionRecord,
) -> Result<(), ApprovalPolicyError> {
    let mut proposals = read_baseline_proposals(path)?;
    proposals.push(BaselineProposal::from_request_and_decision(
        request, decision,
    ));
    write_yaml_atomic(path, &proposals)
}

impl BaselineProposal {
    fn from_request_and_decision(
        request: &ApprovalRequest,
        decision: &ApprovalDecisionRecord,
    ) -> Self {
        Self {
            request_id: request.id.clone(),
            env: request.env.clone(),
            kind: request.kind,
            subject: request.subject.clone(),
            request_reason: request.reason.clone(),
            request_context: request.context.clone(),
            decision_scope: decision.scope,
            decided_by: decision.decided_by.clone(),
            decided_at: format_rfc3339(decision.decided_at),
            decision_reason: decision.reason.clone(),
            decision_context: decision.context.clone(),
            trace_id: decision.trace_id.clone(),
        }
    }
}

fn read_baseline_proposals(path: &Path) -> Result<Vec<BaselineProposal>, ApprovalPolicyError> {
    match fs::read(path) {
        Ok(bytes) => serde_yaml::from_slice(&bytes).map_err(|source| ApprovalPolicyError::Yaml {
            path: path.to_owned(),
            source,
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(ApprovalPolicyError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

fn write_yaml_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), ApprovalPolicyError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| ApprovalPolicyError::Io {
        path: parent.to_owned(),
        source,
    })?;

    let rendered = serde_yaml::to_string(value).map_err(|source| ApprovalPolicyError::Yaml {
        path: path.to_owned(),
        source,
    })?;
    let temp_path = temp_path_for(path)?;
    fs::write(&temp_path, rendered).map_err(|source| ApprovalPolicyError::Io {
        path: temp_path.clone(),
        source,
    })?;
    fs::rename(&temp_path, path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        ApprovalPolicyError::Io {
            path: path.to_owned(),
            source,
        }
    })
}

fn temp_path_for(path: &Path) -> Result<PathBuf, ApprovalPolicyError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| ApprovalPolicyError::Io {
            path: path.to_owned(),
            source: std::io::Error::other(source),
        })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("approval-policy");
    Ok(path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        timestamp.as_nanos()
    )))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use time::OffsetDateTime;

    use super::*;
    use crate::{
        ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalKind, ApprovalRequest,
        ApprovalScope, ApprovalStatus,
    };

    fn fixed_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_777_443_200).unwrap()
    }

    fn test_request() -> ApprovalRequest {
        ApprovalRequest {
            id: "req-1".to_owned(),
            env: "demo".to_owned(),
            kind: ApprovalKind::EgressHost,
            subject: "api.example.test:443".to_owned(),
            reason: "network access".to_owned(),
            context: json!({"url": "https://api.example.test/v1"}),
            requested_at: fixed_time(),
            default_scope: ApprovalScope::Session,
            auto_deny_after_ms: Duration::from_secs(30).as_millis() as u64,
            status: ApprovalStatus::Pending,
            driver_name: Some("openshell".to_owned()),
            driver_request_handle: Some("driver-req-1".to_owned()),
            expires_at: fixed_time() + time::Duration::seconds(30),
            created_trace_id: "trace-req-1".to_owned(),
        }
    }

    fn test_allow_decision() -> ApprovalDecisionRecord {
        ApprovalDecisionRecord {
            request_id: "req-1".to_owned(),
            decision: ApprovalDecisionValue::Allow,
            scope: ApprovalScope::ProposeForBaseline,
            decided_by: "alice".to_owned(),
            decided_at: fixed_time() + time::Duration::seconds(5),
            reason: Some("approved for baseline".to_owned()),
            context: json!({"source": "test"}),
            trace_id: "trace-decision".to_owned(),
        }
    }

    #[test]
    fn persist_sandbox_overlay_round_trips_grants() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("approval-policy-overlay.yaml");
        let grant =
            ApprovalGrant::from_request_and_decision(&test_request(), &test_allow_decision());

        append_overlay_grant(&path, &grant).unwrap();
        let loaded = read_overlay(&path).unwrap();

        assert_eq!(loaded.grants.len(), 1);
        assert_eq!(loaded.grants[0].id, "req-1");
        assert_eq!(loaded.grants[0].kind, ApprovalKind::EgressHost);
    }

    #[test]
    fn baseline_proposal_includes_request_context() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("proposals.yaml");

        append_baseline_proposal(&path, &test_request(), &test_allow_decision()).unwrap();
        let rendered = std::fs::read_to_string(path).unwrap();

        assert!(rendered.contains("req-1"));
        assert!(rendered.contains("https://api.example.test/v1"));
        assert!(rendered.contains("propose-for-baseline"));
    }
}
