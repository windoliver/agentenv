use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, PrimitiveDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    EgressHost,
    McpTool,
    ZoneAccess,
    PackageInstall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalScope {
    Once,
    Session,
    PersistSandbox,
    ProposeForBaseline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionValue {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub env: String,
    pub kind: ApprovalKind,
    pub subject: String,
    pub reason: String,
    pub context: Value,
    pub requested_at: OffsetDateTime,
    pub default_scope: ApprovalScope,
    pub auto_deny_after_ms: u64,
    pub status: ApprovalStatus,
    pub driver_name: Option<String>,
    pub driver_request_handle: Option<String>,
    pub expires_at: OffsetDateTime,
    pub created_trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecisionRecord {
    pub request_id: String,
    pub decision: ApprovalDecisionValue,
    pub scope: ApprovalScope,
    pub decided_by: String,
    pub decided_at: OffsetDateTime,
    pub reason: Option<String>,
    pub context: Value,
    pub trace_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalRequestFilter {
    pub env: Option<String>,
    pub status: Option<ApprovalStatus>,
}

impl ApprovalRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        env: impl Into<String>,
        kind: ApprovalKind,
        subject: impl Into<String>,
        reason: impl Into<String>,
        context: Value,
        requested_at: OffsetDateTime,
        default_scope: ApprovalScope,
        auto_deny_after: Duration,
        created_trace_id: impl Into<String>,
    ) -> Self {
        let expires_at = saturating_expires_at(requested_at, auto_deny_after);
        Self {
            id: id.into(),
            env: env.into(),
            kind,
            subject: subject.into(),
            reason: reason.into(),
            context,
            requested_at,
            default_scope,
            auto_deny_after_ms: auto_deny_after.as_millis().try_into().unwrap_or(u64::MAX),
            status: ApprovalStatus::Pending,
            driver_name: None,
            driver_request_handle: None,
            expires_at,
            created_trace_id: created_trace_id.into(),
        }
    }

    pub fn expires_at_rfc3339(&self) -> String {
        format_rfc3339(self.expires_at)
    }
}

pub fn format_rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("RFC3339 format always succeeds")
}

fn saturating_expires_at(
    requested_at: OffsetDateTime,
    auto_deny_after: Duration,
) -> OffsetDateTime {
    requested_at
        .checked_add(auto_deny_after.try_into().unwrap_or(time::Duration::MAX))
        .unwrap_or_else(|| PrimitiveDateTime::MAX.assume_utc())
}

impl From<agentenv_proto::ApprovalKind> for ApprovalKind {
    fn from(value: agentenv_proto::ApprovalKind) -> Self {
        match value {
            agentenv_proto::ApprovalKind::EgressHost => Self::EgressHost,
            agentenv_proto::ApprovalKind::McpTool => Self::McpTool,
            agentenv_proto::ApprovalKind::ZoneAccess => Self::ZoneAccess,
            agentenv_proto::ApprovalKind::PackageInstall => Self::PackageInstall,
        }
    }
}

impl From<ApprovalDecisionValue> for agentenv_proto::ApprovalDecision {
    fn from(value: ApprovalDecisionValue) -> Self {
        match value {
            ApprovalDecisionValue::Allow => Self::Allow,
            ApprovalDecisionValue::Deny => Self::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    #[test]
    fn approval_kind_serializes_stable_names() {
        assert_eq!(
            serde_json::to_value(ApprovalKind::EgressHost).unwrap(),
            json!("egress_host")
        );
        assert_eq!(
            serde_json::to_value(ApprovalKind::McpTool).unwrap(),
            json!("mcp_tool")
        );
        assert_eq!(
            serde_json::to_value(ApprovalKind::ZoneAccess).unwrap(),
            json!("zone_access")
        );
        assert_eq!(
            serde_json::to_value(ApprovalKind::PackageInstall).unwrap(),
            json!("package_install")
        );
    }

    #[test]
    fn request_computes_expiry_from_request_time() {
        let requested_at = OffsetDateTime::parse(
            "2026-04-29T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let request = ApprovalRequest::new(
            "req_1",
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "network access",
            json!({"url": "https://api.example.test/v1"}),
            requested_at,
            ApprovalScope::Session,
            Duration::from_secs(30),
            "trace-1",
        );

        assert_eq!(request.expires_at_rfc3339(), "2026-04-29T12:00:30Z");
        assert_eq!(request.status, ApprovalStatus::Pending);
    }

    #[test]
    fn request_expiry_saturates_when_ttl_overflows() {
        let request = ApprovalRequest::new(
            "req_overflow",
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "network access",
            json!({}),
            time::PrimitiveDateTime::MAX.assume_utc(),
            ApprovalScope::Session,
            Duration::from_nanos(1),
            "trace-overflow",
        );

        assert_eq!(
            request.expires_at,
            time::PrimitiveDateTime::MAX.assume_utc()
        );
        assert_eq!(request.status, ApprovalStatus::Pending);
    }

    #[test]
    fn proto_package_install_maps_into_domain_kind() {
        let kind = ApprovalKind::from(agentenv_proto::ApprovalKind::PackageInstall);
        assert_eq!(kind, ApprovalKind::PackageInstall);
    }
}
