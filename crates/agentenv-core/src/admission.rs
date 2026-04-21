use agentenv_proto::{IssueSeverity, PreflightIssue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionStatus {
    Accepted,
    Queued,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    Created,
    Destroyed,
    InvalidBlueprint,
    EnvExists,
    EnvNotFound,
    PreflightFailed,
    MissingCredential,
    CapabilityMissing,
    DriverUnhealthy,
    DriverCommandFailed,
    CleanupFailed,
    NonInteractivePromptRequired,
    ReproduceBlueprintMissing,
}

impl ReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Destroyed => "destroyed",
            Self::InvalidBlueprint => "invalid_blueprint",
            Self::EnvExists => "env_exists",
            Self::EnvNotFound => "env_not_found",
            Self::PreflightFailed => "preflight_failed",
            Self::MissingCredential => "missing_credential",
            Self::CapabilityMissing => "capability_missing",
            Self::DriverUnhealthy => "driver_unhealthy",
            Self::DriverCommandFailed => "driver_command_failed",
            Self::CleanupFailed => "cleanup_failed",
            Self::NonInteractivePromptRequired => "non_interactive_prompt_required",
            Self::ReproduceBlueprintMissing => "reproduce_blueprint_missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    Success,
    GenericFailure,
    Usage,
    TerminalFailure,
    PreflightFailed,
    MissingCredential,
    RetryableFailure,
    Unhealthy,
}

impl ExitClass {
    pub fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::GenericFailure => 1,
            Self::Usage => 2,
            Self::TerminalFailure => 10,
            Self::PreflightFailed => 11,
            Self::MissingCredential => 12,
            Self::RetryableFailure => 20,
            Self::Unhealthy => 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub kind: String,
    pub driver: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<PreflightIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReport {
    pub status: AdmissionStatus,
    pub reason_code: ReasonCode,
    pub env: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<PreflightCheck>,
}

impl AdmissionReport {
    pub fn accepted(env: impl Into<String>) -> Self {
        Self {
            status: AdmissionStatus::Accepted,
            reason_code: ReasonCode::Created,
            env: env.into(),
            checks: Vec::new(),
        }
    }

    pub fn rejected(env: impl Into<String>, reason_code: ReasonCode) -> Self {
        Self {
            status: AdmissionStatus::Rejected,
            reason_code,
            env: env.into(),
            checks: Vec::new(),
        }
    }

    pub fn from_checks(env: impl Into<String>, checks: Vec<PreflightCheck>) -> Self {
        let has_error = checks.iter().any(|check| {
            !check.ok
                || check
                    .issues
                    .iter()
                    .any(|issue| issue.severity == IssueSeverity::Error)
        });

        Self {
            status: if has_error {
                AdmissionStatus::Rejected
            } else {
                AdmissionStatus::Accepted
            },
            reason_code: if has_error {
                ReasonCode::PreflightFailed
            } else {
                ReasonCode::Created
            },
            env: env.into(),
            checks,
        }
    }

    pub fn exit_class(&self) -> ExitClass {
        match self.reason_code {
            ReasonCode::Created | ReasonCode::Destroyed => ExitClass::Success,
            ReasonCode::PreflightFailed => ExitClass::PreflightFailed,
            ReasonCode::MissingCredential => ExitClass::MissingCredential,
            ReasonCode::DriverCommandFailed | ReasonCode::CleanupFailed => {
                ExitClass::RetryableFailure
            }
            ReasonCode::DriverUnhealthy => ExitClass::Unhealthy,
            _ => ExitClass::TerminalFailure,
        }
    }
}

#[cfg(test)]
mod tests {
    use agentenv_proto::{IssueSeverity, PreflightIssue};

    use super::{
        AdmissionReport, AdmissionStatus, ExitClass, PreflightCheck, ReasonCode,
    };

    #[test]
    fn preflight_errors_reject_admission() {
        let report = AdmissionReport::from_checks(
            "demo",
            vec![PreflightCheck {
                kind: "sandbox".to_owned(),
                driver: "openshell".to_owned(),
                ok: false,
                issues: vec![PreflightIssue {
                    severity: IssueSeverity::Error,
                    code: "openshell_missing".to_owned(),
                    message: "OpenShell binary not found".to_owned(),
                    remediation: Some("Install OpenShell".to_owned()),
                }],
            }],
        );

        assert_eq!(report.status, AdmissionStatus::Rejected);
        assert_eq!(report.reason_code, ReasonCode::PreflightFailed);
        assert_eq!(report.exit_class(), ExitClass::PreflightFailed);
    }

    #[test]
    fn clean_preflight_accepts_admission() {
        let report = AdmissionReport::from_checks(
            "demo",
            vec![PreflightCheck {
                kind: "agent".to_owned(),
                driver: "codex".to_owned(),
                ok: true,
                issues: Vec::new(),
            }],
        );

        assert_eq!(report.status, AdmissionStatus::Accepted);
        assert_eq!(report.reason_code, ReasonCode::Created);
        assert_eq!(report.exit_class(), ExitClass::Success);
    }

    #[test]
    fn reason_codes_are_stable_snake_case() {
        assert_eq!(ReasonCode::MissingCredential.as_str(), "missing_credential");
        assert_eq!(
            ReasonCode::ReproduceBlueprintMissing.as_str(),
            "reproduce_blueprint_missing"
        );
        assert_eq!(ExitClass::MissingCredential.code(), 12);
        assert_eq!(ExitClass::RetryableFailure.code(), 20);
    }
}
