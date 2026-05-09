use agentenv_proto::{
    assert_compatible_schema_version, AgentSpec, ApplyPolicyParams, ApplyPolicyResult,
    AttachSessionParams, ConnectParams, ContextHandleRequest, ContextSpec, ContextStatus,
    CreateSessionParams, CredentialRequirementsParams, CredentialRequirementsResult, DestroyParams,
    EmptyResult, EndpointInSandboxResult, ExecParams, ExecResult, InferenceHandleRequest,
    InferenceSpec, InitializeParams, InitializeResult, InstallStepsResult, KillSessionParams,
    ListSessionsParams, ListSessionsResult, LogsParams, LogsResult, LogsStreamParams,
    McpConfigPathParams, McpConfigPathResult, McpEndpoint, PreflightParams, PreflightResult,
    RenderEntrypointResult, RenderMcpConfigParams, RenderMcpConfigResult,
    RequiredNetworkRulesResult, SandboxHandle, SandboxSpec, SandboxStatus, SandboxStatusParams,
    SchemaVersionError, SessionHandle, ShellHandle, ShutdownParams, StopParams,
};
use async_trait::async_trait;
use std::{fmt, time::Duration};
use time::OffsetDateTime;

pub type DriverResult<T> = Result<T, DriverError>;

#[derive(Debug)]
pub enum DriverError {
    SchemaVersion(SchemaVersionError),
    CapabilityMissing {
        capability: String,
    },
    InvalidConfig {
        field: String,
        message: String,
    },
    InvalidHandle {
        handle: String,
        message: String,
    },
    PreflightFailed {
        message: String,
    },
    CommandSpawn {
        command: String,
        source: std::io::Error,
    },
    CommandFailed {
        command: String,
        status: Option<i32>,
        stdout: String,
        stderr: String,
    },
    Subprocess {
        driver: String,
        message: String,
    },
    PolicyTranslation {
        message: String,
    },
    PolicyRequiresRecreate {
        domains: String,
    },
    ApprovalUnavailable {
        request_id: String,
        message: String,
    },
    CleanupFailed {
        message: String,
    },
    InvalidInput {
        message: String,
    },
}

pub fn ensure_protocol_compatible(result: &InitializeResult) -> DriverResult<()> {
    assert_compatible_schema_version(&result.driver.protocol_version)
        .map_err(DriverError::SchemaVersion)?;
    Ok(())
}

pub fn require_capability(capability: &str, supported: bool) -> DriverResult<()> {
    if supported {
        Ok(())
    } else {
        Err(DriverError::CapabilityMissing {
            capability: capability.to_owned(),
        })
    }
}

pub fn persistent_sessions_missing() -> DriverError {
    DriverError::CapabilityMissing {
        capability: "supports_persistent_sessions".to_owned(),
    }
}

impl DriverError {
    fn status_label(status: Option<i32>) -> String {
        match status {
            Some(status) => format!("status {status}"),
            None => "unknown status".to_owned(),
        }
    }

    fn trimmed_output(output: &str) -> String {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            String::new()
        } else {
            trimmed.to_owned()
        }
    }
}

impl From<SchemaVersionError> for DriverError {
    fn from(value: SchemaVersionError) -> Self {
        Self::SchemaVersion(value)
    }
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverError::SchemaVersion(err) => fmt::Display::fmt(err, f),
            DriverError::CapabilityMissing { capability } => {
                write!(f, "driver is missing capability `{capability}`")
            }
            DriverError::InvalidConfig { field, message } => {
                write!(f, "invalid driver config field `{field}`: {message}")
            }
            DriverError::InvalidHandle { handle, message } => {
                write!(f, "invalid inference handle `{handle}`: {message}")
            }
            DriverError::PreflightFailed { message } => {
                write!(f, "preflight failed: {message}")
            }
            DriverError::CommandSpawn { command, source } => {
                write!(f, "failed to spawn command `{command}`: {source}")
            }
            DriverError::CommandFailed {
                command,
                status,
                stdout,
                stderr,
            } => {
                let rendered = Self::trimmed_output(stderr);
                let rendered = if rendered.is_empty() {
                    let stdout = Self::trimmed_output(stdout);
                    if stdout.is_empty() {
                        "<empty stderr>".to_owned()
                    } else {
                        stdout
                    }
                } else {
                    rendered
                };

                write!(
                    f,
                    "command `{command}` failed with {}: {}",
                    Self::status_label(*status),
                    rendered
                )
            }
            DriverError::Subprocess { driver, message } => {
                write!(f, "subprocess driver `{driver}` failed: {message}")
            }
            DriverError::PolicyTranslation { message } => {
                write!(f, "policy translation failed: {message}")
            }
            DriverError::PolicyRequiresRecreate { domains } => {
                write!(f, "policy update requires recreate for domains: {domains}")
            }
            DriverError::ApprovalUnavailable {
                request_id,
                message,
            } => {
                write!(f, "approval request `{request_id}` unavailable: {message}")
            }
            DriverError::CleanupFailed { message } => {
                write!(f, "driver cleanup failed: {message}")
            }
            DriverError::InvalidInput { message } => {
                write!(f, "invalid driver input: {message}")
            }
        }
    }
}

impl std::error::Error for DriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DriverError::SchemaVersion(err) => Some(err),
            DriverError::CommandSpawn { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[async_trait]
pub trait SandboxDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn create(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle>;
    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle>;
    async fn create_session(&self, _params: CreateSessionParams) -> DriverResult<SessionHandle> {
        Err(persistent_sessions_missing())
    }
    async fn attach_session(&self, _params: AttachSessionParams) -> DriverResult<ExecResult> {
        Err(persistent_sessions_missing())
    }
    async fn list_sessions(&self, _params: ListSessionsParams) -> DriverResult<ListSessionsResult> {
        Err(persistent_sessions_missing())
    }
    async fn kill_session(&self, _params: KillSessionParams) -> DriverResult<EmptyResult> {
        Err(persistent_sessions_missing())
    }
    async fn exec(&self, params: ExecParams) -> DriverResult<ExecResult>;
    async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult>;
    async fn copy_out(&self, params: agentenv_proto::CopyOutParams) -> DriverResult<EmptyResult>;
    async fn apply_policy(&self, params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult>;
    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus>;
    async fn logs(&self, params: LogsParams) -> DriverResult<LogsResult>;
    async fn logs_stream(&self, params: LogsStreamParams) -> DriverResult<EmptyResult>;
    async fn stop(&self, params: StopParams) -> DriverResult<EmptyResult>;
    async fn destroy(&self, params: DestroyParams) -> DriverResult<EmptyResult>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[async_trait]
pub trait ApprovalRequester: Send + Sync {
    async fn request_approval(
        &self,
        request: agentenv_approvals::ApprovalRequest,
    ) -> DriverResult<agentenv_approvals::ApprovalDecisionRecord>;
}

#[async_trait]
impl ApprovalRequester for agentenv_approvals::ApprovalCoordinator {
    async fn request_approval(
        &self,
        request: agentenv_approvals::ApprovalRequest,
    ) -> DriverResult<agentenv_approvals::ApprovalDecisionRecord> {
        let request_id = request.id.clone();
        let expires_at = request.expires_at;
        self.submit_request(request)
            .await
            .map_err(|err| DriverError::ApprovalUnavailable {
                request_id: request_id.clone(),
                message: err.to_string(),
            })?;
        wait_for_approval_decision_or_expire(self, &request_id, expires_at).await
    }
}

async fn wait_for_approval_decision_or_expire(
    coordinator: &agentenv_approvals::ApprovalCoordinator,
    request_id: &str,
    expires_at: OffsetDateTime,
) -> DriverResult<agentenv_approvals::ApprovalDecisionRecord> {
    match tokio::time::timeout(
        duration_until_utc(expires_at),
        coordinator.wait_for_decision(request_id),
    )
    .await
    {
        Ok(decision) => decision.map_err(|err| approval_unavailable(request_id, err)),
        Err(_) => {
            if OffsetDateTime::now_utc() < expires_at {
                tokio::time::sleep(duration_until_utc(expires_at)).await;
            }
            coordinator
                .expire_due(OffsetDateTime::now_utc())
                .await
                .map_err(|err| approval_unavailable(request_id, err))?;
            coordinator
                .store()
                .get_decision(request_id)
                .map_err(|err| approval_unavailable(request_id, err))?
                .ok_or_else(|| DriverError::ApprovalUnavailable {
                    request_id: request_id.to_owned(),
                    message: "approval expired without a recorded decision".to_owned(),
                })
        }
    }
}

fn duration_until_utc(deadline: OffsetDateTime) -> Duration {
    let now = OffsetDateTime::now_utc();
    if deadline <= now {
        Duration::ZERO
    } else {
        (deadline - now).try_into().unwrap_or(Duration::MAX)
    }
}

fn approval_unavailable(request_id: &str, err: impl std::error::Error) -> DriverError {
    DriverError::ApprovalUnavailable {
        request_id: request_id.to_owned(),
        message: err.to_string(),
    }
}

#[async_trait]
pub trait AgentDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn install_steps(&self, spec: AgentSpec) -> DriverResult<InstallStepsResult>;
    async fn mcp_config_path(
        &self,
        params: McpConfigPathParams,
    ) -> DriverResult<McpConfigPathResult>;
    async fn render_mcp_config(
        &self,
        params: RenderMcpConfigParams,
    ) -> DriverResult<RenderMcpConfigResult>;
    async fn render_entrypoint(&self, spec: AgentSpec) -> DriverResult<RenderEntrypointResult>;
    async fn credential_requirements(
        &self,
        spec: AgentSpec,
    ) -> DriverResult<CredentialRequirementsResult>;
    async fn health_check_probe(
        &self,
        spec: AgentSpec,
    ) -> DriverResult<agentenv_proto::AgentHealthCheckProbe>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[async_trait]
pub trait ContextDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn provision(&self, spec: ContextSpec) -> DriverResult<agentenv_proto::ContextHandle>;
    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint>;
    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult>;
    async fn credential_requirements(
        &self,
        params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult>;
    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus>;
    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[async_trait]
pub trait InferenceDriver: Send + Sync {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult>;
    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult>;
    async fn provision(&self, spec: InferenceSpec)
        -> DriverResult<agentenv_proto::InferenceHandle>;
    async fn endpoint_in_sandbox(
        &self,
        params: InferenceHandleRequest,
    ) -> DriverResult<EndpointInSandboxResult>;
    async fn credential_requirements(
        &self,
        params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult>;
    async fn teardown(&self, params: InferenceHandleRequest) -> DriverResult<EmptyResult>;
    async fn shutdown(&mut self, params: ShutdownParams) -> DriverResult<EmptyResult>;
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use agentenv_proto::{
        schema_version_major, ApplyPolicyParams, ApplyPolicyResult, Capabilities, ConnectParams,
        CopyInParams, CopyOutParams, DestroyParams, DriverInfo, DriverKind, EmptyResult,
        ExecParams, ExecResult, InitializeParams, InitializeResult, LogsParams, LogsResult,
        LogsStreamParams, PreflightParams, PreflightResult, SandboxCapabilities, SandboxHandle,
        SandboxPhase, SandboxSpec, SandboxStatus, SandboxStatusParams, ShellHandle, ShutdownParams,
        StopParams, SCHEMA_VERSION,
    };

    use super::{
        ensure_protocol_compatible, require_capability, ApprovalRequester, DriverError,
        DriverResult, SandboxDriver,
    };

    fn temp_db_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.db", std::process::id()))
    }

    struct MinimalSandboxDriver;

    #[async_trait::async_trait]
    impl SandboxDriver for MinimalSandboxDriver {
        async fn initialize(
            &mut self,
            _params: InitializeParams,
        ) -> DriverResult<InitializeResult> {
            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "minimal-sandbox".to_owned(),
                    kind: DriverKind::Sandbox,
                    version: "0.0.1".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: false,
                    supports_persistent_sessions: false,
                    supports_dns_egress_control: false,
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn create(&self, _spec: SandboxSpec) -> DriverResult<SandboxHandle> {
            Ok(SandboxHandle {
                handle: "sb-1".to_owned(),
            })
        }

        async fn connect(&self, _params: ConnectParams) -> DriverResult<ShellHandle> {
            Ok(ShellHandle {
                session_id: "session-1".to_owned(),
                tty: true,
                working_dir: None,
            })
        }

        async fn exec(&self, _params: ExecParams) -> DriverResult<ExecResult> {
            Ok(ExecResult {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }

        async fn copy_in(&self, _params: CopyInParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn copy_out(&self, _params: CopyOutParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn apply_policy(
            &self,
            _params: ApplyPolicyParams,
        ) -> DriverResult<ApplyPolicyResult> {
            Ok(ApplyPolicyResult { hot_reloaded: true })
        }

        async fn status(&self, _params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
            Ok(SandboxStatus {
                phase: SandboxPhase::Running,
                healthy: true,
                last_ping: None,
            })
        }

        async fn logs(&self, _params: LogsParams) -> DriverResult<LogsResult> {
            Ok(LogsResult {
                entries: Vec::new(),
            })
        }

        async fn logs_stream(&self, _params: LogsStreamParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn stop(&self, _params: StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn destroy(&self, _params: DestroyParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }
    }

    #[tokio::test]
    async fn sandbox_session_methods_default_to_capability_missing() {
        let driver = MinimalSandboxDriver;
        let err = driver
            .create_session(agentenv_proto::CreateSessionParams {
                handle: "sb-1".to_owned(),
                name: "demo".to_owned(),
                command: "agentenv-agent".to_owned(),
                detached: true,
                metadata: Default::default(),
            })
            .await
            .expect_err("default session implementation should reject");

        assert!(
            matches!(err, DriverError::CapabilityMissing { capability } if capability == "supports_persistent_sessions")
        );
    }

    #[test]
    fn compatibility_guard_rejects_mismatched_protocol_major() {
        let mismatched_protocol_version = format!(
            "{}.0",
            schema_version_major(SCHEMA_VERSION).expect("schema version should parse") + 1
        );
        let result = InitializeResult {
            driver: DriverInfo {
                name: "mock".to_owned(),
                kind: DriverKind::Sandbox,
                version: "0.0.1".to_owned(),
                protocol_version: mismatched_protocol_version,
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: true,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: true,
                supports_remote_host: false,
                supports_persistent_sessions: false,
                supports_dns_egress_control: false,
            }),
        };

        let err = ensure_protocol_compatible(&result).expect_err("major mismatch should fail");
        assert!(err.to_string().contains("upgrade the driver or the core"));
    }

    #[test]
    fn compatibility_guard_accepts_matching_protocol_version() {
        let result = InitializeResult {
            driver: DriverInfo {
                name: "mock".to_owned(),
                kind: DriverKind::Sandbox,
                version: "0.0.1".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: true,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: true,
                supports_remote_host: false,
                supports_persistent_sessions: false,
                supports_dns_egress_control: false,
            }),
        };

        ensure_protocol_compatible(&result).expect("matching schema version should pass");
    }

    #[test]
    fn capability_guard_returns_expected_error() {
        let err = require_capability("supports_hot_reload_policy", false)
            .expect_err("unsupported capability should fail");

        assert!(matches!(err, DriverError::CapabilityMissing { .. }));
    }

    #[test]
    fn approval_unavailable_error_mentions_request() {
        let error = DriverError::ApprovalUnavailable {
            request_id: "req-1".to_owned(),
            message: "approval coordinator not configured".to_owned(),
        };

        assert!(error.to_string().contains("req-1"));
        assert!(error
            .to_string()
            .contains("approval coordinator not configured"));
    }

    #[tokio::test]
    async fn approval_requester_auto_denies_expired_request() {
        let store =
            agentenv_approvals::ApprovalStore::open(temp_db_path("approval-requester")).unwrap();
        let coordinator = agentenv_approvals::ApprovalCoordinator::new(
            agentenv_approvals::ApprovalCoordinatorConfig {
                store,
                events: std::sync::Arc::new(agentenv_events::NoopEventEmitter),
                poll_interval: Duration::from_millis(1),
                overlay_path: None,
                proposal_path: None,
                notifications: None,
            },
        );
        let request = agentenv_approvals::ApprovalRequest::new(
            "req-expired",
            "demo",
            agentenv_approvals::ApprovalKind::EgressHost,
            "example.com",
            "network request",
            serde_json::json!({}),
            time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
            agentenv_approvals::ApprovalScope::Once,
            Duration::ZERO,
            "trace-expired",
        );

        let decision = coordinator.request_approval(request).await.unwrap();

        assert_eq!(
            decision.decision,
            agentenv_approvals::ApprovalDecisionValue::Deny
        );
        assert_eq!(decision.decided_by, "agentenv:auto-deny");
    }

    #[test]
    fn command_failed_error_includes_command_status_and_trimmed_stderr() {
        let err = DriverError::CommandFailed {
            command: "openshell gateway status".to_owned(),
            status: Some(2),
            stdout: "gateway stdout\n".to_owned(),
            stderr: "gateway down\n".to_owned(),
        };

        let rendered = err.to_string();

        assert!(rendered.contains("openshell gateway status"));
        assert!(rendered.contains("status 2"));
        assert!(rendered.contains("gateway down"));
    }

    #[test]
    fn invalid_input_error_names_the_bad_field() {
        let err = DriverError::InvalidInput {
            message: "metadata.name must be a string".to_owned(),
        };

        assert!(err.to_string().contains("metadata.name"));
    }

    #[test]
    fn command_failed_error_uses_stdout_when_stderr_is_empty() {
        let err = DriverError::CommandFailed {
            command: "openshell sandbox get devbox".to_owned(),
            status: Some(1),
            stdout: "sandbox not found\n".to_owned(),
            stderr: "\n".to_owned(),
        };

        let rendered = err.to_string();

        assert!(rendered.contains("sandbox not found"));
    }

    #[test]
    fn schema_version_error_converts_to_driver_error() {
        let err: DriverError = agentenv_proto::assert_compatible_schema_version("2.0")
            .expect_err("schema should mismatch")
            .into();

        assert!(err.to_string().contains("upgrade the driver or the core"));
    }

    #[test]
    fn invalid_config_error_includes_field_and_message() {
        let err = DriverError::InvalidConfig {
            field: "base_url".to_owned(),
            message: "must be a valid http or https URL".to_owned(),
        };

        assert_eq!(
            err.to_string(),
            "invalid driver config field `base_url`: must be a valid http or https URL"
        );
    }

    #[test]
    fn invalid_handle_error_includes_handle_and_message() {
        let err = DriverError::InvalidHandle {
            handle: "openai|not-a-url".to_owned(),
            message: "expected prefix `openai|`".to_owned(),
        };

        assert_eq!(
            err.to_string(),
            "invalid inference handle `openai|not-a-url`: expected prefix `openai|`"
        );
    }
}
