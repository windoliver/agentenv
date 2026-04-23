use agentenv_core::{
    admission::{AdmissionReport, ExitClass, ReasonCode},
    driver::DriverError,
    env::EnvError,
    runtime::{EnvDescription, EnvListRow, EnvStatusSummary, RuntimeError},
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
        RuntimeError::Env(EnvError::NotFound { .. }) => ReasonCode::EnvNotFound,
        RuntimeError::Env(EnvError::AlreadyExists { .. }) => ReasonCode::EnvExists,
        RuntimeError::Env(EnvError::InvalidName { .. }) => ReasonCode::InvalidBlueprint,
        RuntimeError::MissingCredential { .. } => ReasonCode::MissingCredential,
        RuntimeError::UnsupportedDriver { .. } | RuntimeError::MissingSelectedDriver { .. } => {
            ReasonCode::CapabilityMissing
        }
        RuntimeError::Lifecycle(_) | RuntimeError::InvalidPolicyTier { .. } => {
            ReasonCode::InvalidBlueprint
        }
        RuntimeError::Lockfile(_)
        | RuntimeError::PortableLockfile(_)
        | RuntimeError::FrozenLockfileDriverMismatch { .. } => ReasonCode::InvalidBlueprint,
        RuntimeError::Driver(error) => reason_for_driver_error(error),
        RuntimeError::Env(EnvError::Io { .. })
        | RuntimeError::Env(EnvError::Json { .. })
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
}

#[cfg(test)]
mod tests {
    use agentenv_core::{admission::ExitClass, driver::DriverError, runtime::RuntimeError};

    use super::{exit_for_error, reason_for_error};

    #[test]
    fn preflight_driver_error_keeps_preflight_exit_class() {
        let error = RuntimeError::Driver(DriverError::PreflightFailed {
            message: "missing runtime".to_owned(),
        });

        assert_eq!(reason_for_error(&error).as_str(), "preflight_failed");
        assert_eq!(exit_for_error(&error), ExitClass::PreflightFailed);
    }
}
