use agentenv_approvals::{format_rfc3339, ApprovalKind, ApprovalRequest, ApprovalScope};
use agentenv_core::{
    admission::{AdmissionReport, ExitClass, ReasonCode},
    driver::DriverError,
    env::EnvError,
    runtime::{EnvDescription, EnvListRow, EnvStatusSummary, RuntimeError, SessionListRow},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub reason_code: &'static str,
    pub message: String,
}

pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn print_error_json(error: &RuntimeError) {
    print_error_body_json(reason_for_error(error), error.to_string());
}

pub fn print_error_body_json(reason_code: ReasonCode, message: impl Into<String>) {
    let body = ErrorBody {
        reason_code: reason_code.as_str(),
        message: message.into(),
    };
    eprintln!(
        "{}",
        serde_json::to_string(&body).unwrap_or_else(|_| {
            "{\"reason_code\":\"driver_command_failed\",\"message\":\"failed to serialize error\"}"
                .to_owned()
        })
    );
}

pub fn reason_for_error(error: &RuntimeError) -> ReasonCode {
    match error {
        RuntimeError::Env(EnvError::NotFound { .. })
        | RuntimeError::SandboxHandleNotFound { .. } => ReasonCode::EnvNotFound,
        RuntimeError::Env(EnvError::AlreadyExists { .. }) => ReasonCode::EnvExists,
        RuntimeError::Env(EnvError::InvalidName { .. }) => ReasonCode::InvalidBlueprint,
        RuntimeError::MissingCredential { .. } => ReasonCode::MissingCredential,
        RuntimeError::UnsupportedDriver { .. } | RuntimeError::MissingSelectedDriver { .. } => {
            ReasonCode::CapabilityMissing
        }
        RuntimeError::Lifecycle(_)
        | RuntimeError::Blueprint(_)
        | RuntimeError::Hardening(_)
        | RuntimeError::DnsPolicy(_)
        | RuntimeError::InvalidPolicyTier { .. } => ReasonCode::InvalidBlueprint,
        RuntimeError::Lockfile(_)
        | RuntimeError::PortableLockfile(_)
        | RuntimeError::Snapshot(_)
        | RuntimeError::ApprovalConfig(_)
        | RuntimeError::LegacyLockfileReproduce
        | RuntimeError::PortableLockfileVerification { .. }
        | RuntimeError::FrozenLockfileDriverMismatch { .. } => ReasonCode::InvalidBlueprint,
        RuntimeError::Driver(error) => reason_for_driver_error(error),
        RuntimeError::Env(EnvError::Io { .. })
        | RuntimeError::Env(EnvError::Json { .. })
        | RuntimeError::ApprovalNotification(_)
        | RuntimeError::DriverArtifact(_)
        | RuntimeError::CommandStatus { .. }
        | RuntimeError::MissingSandboxHandle { .. }
        | RuntimeError::ComponentConfigConversion { .. }
        | RuntimeError::InvalidDriverHandshake { .. }
        | RuntimeError::StateNameMismatch { .. } => ReasonCode::DriverCommandFailed,
    }
}

fn reason_for_driver_error(error: &DriverError) -> ReasonCode {
    match error {
        DriverError::CapabilityMissing { .. } | DriverError::SchemaVersion(_) => {
            ReasonCode::CapabilityMissing
        }
        DriverError::PreflightFailed { .. } => ReasonCode::PreflightFailed,
        DriverError::CleanupFailed { .. } => ReasonCode::CleanupFailed,
        DriverError::InvalidConfig { .. } | DriverError::InvalidInput { .. } => {
            ReasonCode::InvalidBlueprint
        }
        DriverError::InvalidHandle { .. }
        | DriverError::CommandSpawn { .. }
        | DriverError::CommandFailed { .. }
        | DriverError::Subprocess { .. }
        | DriverError::ApprovalUnavailable { .. }
        | DriverError::PolicyTranslation { .. }
        | DriverError::PolicyRequiresRecreate { .. } => ReasonCode::DriverCommandFailed,
    }
}

pub fn exit_for_error(error: &RuntimeError) -> ExitClass {
    exit_for_reason(reason_for_error(error))
}

pub fn exit_for_reason(reason_code: ReasonCode) -> ExitClass {
    match reason_code {
        ReasonCode::EnvNotFound
        | ReasonCode::EnvExists
        | ReasonCode::InvalidBlueprint
        | ReasonCode::CapabilityMissing
        | ReasonCode::ReproduceBlueprintMissing => ExitClass::TerminalFailure,
        ReasonCode::NonInteractivePromptRequired => ExitClass::Usage,
        ReasonCode::MissingCredential => ExitClass::MissingCredential,
        ReasonCode::PreflightFailed => ExitClass::PreflightFailed,
        ReasonCode::DriverCommandFailed | ReasonCode::CleanupFailed => ExitClass::RetryableFailure,
        _ => ExitClass::GenericFailure,
    }
}

#[derive(Debug, Serialize)]
pub struct ListJson {
    pub envs: Vec<EnvListRow>,
}

#[derive(Debug, Serialize)]
pub struct SessionsJson {
    pub sessions: Vec<SessionListRow>,
}

#[derive(Debug, Serialize)]
pub struct ApprovalsListJson {
    pub approvals: Vec<ApprovalRowJson>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRowJson {
    pub env: String,
    pub request_id: String,
    pub kind: ApprovalKind,
    pub subject: String,
    pub reason: String,
    pub requested_at: String,
    pub expires_at: String,
    pub default_scope: ApprovalScope,
}

impl ApprovalRowJson {
    pub fn from_request(request: &ApprovalRequest) -> Self {
        Self {
            env: request.env.clone(),
            request_id: request.id.clone(),
            kind: request.kind,
            subject: request.subject.clone(),
            reason: request.reason.clone(),
            requested_at: format_rfc3339(request.requested_at),
            expires_at: format_rfc3339(request.expires_at),
            default_scope: request.default_scope,
        }
    }
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct StatusJson {
    pub healthy: bool,
    pub status: EnvStatusSummary,
}

pub fn print_list_text(rows: &[EnvListRow]) {
    println!(
        "{:<20} {:<14} {:<14} {:<18} {:<18} {:<10} CREATED",
        "NAME", "AGENT", "SANDBOX", "CONTEXT", "INFERENCE", "STATUS"
    );
    for row in rows {
        println!(
            "{:<20} {:<14} {:<14} {:<18} {:<18} {:<10} {}",
            row.name,
            row.agent,
            row.sandbox,
            row.context,
            row.inference.as_deref().unwrap_or("-"),
            row.status,
            row.created_at
        );
    }
}

pub fn print_sessions_text(rows: &[SessionListRow]) {
    println!(
        "{:<20} {:<26} {:<20} {:<10} {:<28} UPDATED",
        "ENV", "SESSION", "NAME", "STATUS", "COMMAND"
    );
    for row in rows {
        println!(
            "{:<20} {:<26} {:<20} {:<10} {:<28} {}",
            row.env,
            row.session_id,
            row.name,
            format!("{:?}", row.status).to_lowercase(),
            row.command,
            row.updated_at
        );
    }
}

pub fn print_approval_rows_text(rows: &[ApprovalRowJson]) {
    println!(
        "{:<20} {:<26} {:<16} {:<24} {:<24} {:<22} REQUESTED",
        "ENV", "REQUEST", "KIND", "SUBJECT", "REASON", "DEFAULT_SCOPE"
    );
    for row in rows {
        println!(
            "{:<20} {:<26} {:<16} {:<24} {:<24} {:<22} {}",
            row.env,
            row.request_id,
            approval_kind_label(row.kind),
            truncate_table_cell(&row.subject, 24),
            truncate_table_cell(&row.reason, 24),
            approval_scope_label(row.default_scope),
            row.requested_at
        );
    }
}

pub fn print_describe_text(description: &EnvDescription) {
    println!("Name: {}", description.state.name);
    println!("Phase: {:?}", description.state.phase);
    println!("Agent: {}", description.state.drivers.agent.name);
    println!("Sandbox: {}", description.state.drivers.sandbox.name);
    println!("Context: {}", description.state.drivers.context.name);
    if let Some(inference) = description.state.drivers.inference.as_ref() {
        println!("Inference: {}", inference.name);
    }
    println!(
        "Credentials: {}",
        description.state.credential_names.join(", ")
    );
}

#[allow(dead_code)]
pub fn print_admission_text(report: &AdmissionReport) {
    println!("{}: {}", report.env, report.reason_code.as_str());
    for check in &report.checks {
        for issue in &check.issues {
            println!(
                "{} {} {}: {}",
                admission_issue_severity(&issue.severity),
                check.driver,
                issue.code,
                issue.message
            );
            if let Some(remediation) = issue.remediation.as_deref() {
                println!("  remediation: {remediation}");
            }
        }
    }
}

fn admission_issue_severity(severity: &agentenv_proto::IssueSeverity) -> &'static str {
    match severity {
        agentenv_proto::IssueSeverity::Info => "info",
        agentenv_proto::IssueSeverity::Warning => "warning",
        agentenv_proto::IssueSeverity::Error => "error",
    }
}

fn approval_kind_label(kind: ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::EgressHost => "egress_host",
        ApprovalKind::McpTool => "mcp_tool",
        ApprovalKind::ZoneAccess => "zone_access",
        ApprovalKind::PackageInstall => "package_install",
    }
}

fn approval_scope_label(scope: ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "once",
        ApprovalScope::Session => "session",
        ApprovalScope::PersistSandbox => "persist-sandbox",
        ApprovalScope::ProposeForBaseline => "propose-for-baseline",
    }
}

fn truncate_table_cell(value: &str, width: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(width).collect();
    if chars.next().is_some() {
        truncated
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use agentenv_core::{
        admission::ExitClass, driver::DriverError, runtime::RuntimeError,
        security::dns_policy::DnsPolicyError,
    };

    use super::{exit_for_error, reason_for_error};

    #[test]
    fn preflight_driver_error_keeps_preflight_exit_class() {
        let error = RuntimeError::Driver(DriverError::PreflightFailed {
            message: "missing runtime".to_owned(),
        });

        assert_eq!(reason_for_error(&error).as_str(), "preflight_failed");
        assert_eq!(exit_for_error(&error), ExitClass::PreflightFailed);
    }

    #[test]
    fn dns_policy_error_renders_as_invalid_blueprint() {
        let error = RuntimeError::DnsPolicy(DnsPolicyError::InvalidDohEndpoint {
            path: "policy.dns.doh_upstreams_allowed[0]".to_owned(),
            value: "http://dns.example/dns-query".to_owned(),
        });

        assert_eq!(reason_for_error(&error).as_str(), "invalid_blueprint");
        assert_eq!(exit_for_error(&error), ExitClass::TerminalFailure);
    }
}
