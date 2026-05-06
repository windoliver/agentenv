#![forbid(unsafe_code)]

use agentenv_core::driver::{
    persistent_sessions_missing, DriverError, DriverResult, SandboxDriver,
};
use agentenv_proto::{
    assert_compatible_schema_version, ApplyPolicyParams, ApplyPolicyResult, AttachSessionParams,
    Capabilities, ConnectParams, CopyInParams, CopyOutParams, CreateSessionParams, DestroyParams,
    DriverInfo, DriverKind, EmptyResult, ExecParams, ExecResult, InitializeParams,
    InitializeResult, KillSessionParams, ListSessionsParams, ListSessionsResult, LogsParams,
    LogsResult, LogsStreamParams, PreflightParams, PreflightResult, SandboxCapabilities,
    SandboxHandle, SandboxSpec, SandboxStatus, SandboxStatusParams, SessionHandle, ShellHandle,
    ShutdownParams, StopParams, SCHEMA_VERSION,
};

const DRIVER_NAME: &str = "remote-ssh";
const REMOTE_LOGS_CAPABILITY: &str = "remote_logs";
const POLICY_CAPABILITY: &str = "supports_hot_reload_policy";

#[derive(Debug, Default)]
pub struct RemoteSshDriver {
    _private: (),
}

fn policy_missing() -> DriverError {
    DriverError::CapabilityMissing {
        capability: POLICY_CAPABILITY.to_owned(),
    }
}

fn remote_logs_missing() -> DriverError {
    DriverError::CapabilityMissing {
        capability: REMOTE_LOGS_CAPABILITY.to_owned(),
    }
}

fn invalid_handle(handle: String, message: impl Into<String>) -> DriverError {
    DriverError::InvalidHandle {
        handle,
        message: message.into(),
    }
}

#[async_trait::async_trait]
impl SandboxDriver for RemoteSshDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        assert_compatible_schema_version(&params.schema_version)?;
        Ok(InitializeResult {
            driver: DriverInfo {
                name: DRIVER_NAME.to_owned(),
                kind: DriverKind::Sandbox,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: false,
                supports_filesystem_lockdown: false,
                supports_syscall_filter: false,
                supports_native_inference_routing: false,
                supports_remote_host: true,
                supports_persistent_sessions: false,
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
        Err(DriverError::InvalidInput {
            message: "metadata.host is required".to_owned(),
        })
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        Err(invalid_handle(
            params.handle,
            "remote-ssh handle parsing is not implemented",
        ))
    }

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

    async fn exec(&self, params: ExecParams) -> DriverResult<ExecResult> {
        Err(invalid_handle(
            params.handle,
            "remote-ssh handle parsing is not implemented",
        ))
    }

    async fn copy_in(&self, params: CopyInParams) -> DriverResult<EmptyResult> {
        Err(invalid_handle(
            params.handle,
            "remote-ssh handle parsing is not implemented",
        ))
    }

    async fn copy_out(&self, params: CopyOutParams) -> DriverResult<EmptyResult> {
        Err(invalid_handle(
            params.handle,
            "remote-ssh handle parsing is not implemented",
        ))
    }

    async fn apply_policy(&self, _params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult> {
        Err(policy_missing())
    }

    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        Err(invalid_handle(
            params.handle,
            "remote-ssh handle parsing is not implemented",
        ))
    }

    async fn logs(&self, _params: LogsParams) -> DriverResult<LogsResult> {
        Err(remote_logs_missing())
    }

    async fn logs_stream(&self, _params: LogsStreamParams) -> DriverResult<EmptyResult> {
        Err(remote_logs_missing())
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

#[cfg(test)]
mod tests {
    use agentenv_core::driver::SandboxDriver;
    use agentenv_proto::{Capabilities, DriverKind, InitializeParams, LogLevel, SCHEMA_VERSION};

    use super::RemoteSshDriver;

    #[tokio::test]
    async fn remote_ssh_driver_initializes_with_conservative_capabilities() {
        let mut driver = RemoteSshDriver::default();

        let result = driver
            .initialize(InitializeParams {
                schema_version: SCHEMA_VERSION.to_owned(),
                core_version: "0.0.1-test".to_owned(),
                workdir: "/tmp/agentenv-remote-ssh-test".to_owned(),
                log_level: LogLevel::Info,
            })
            .await
            .expect("initialize remote ssh driver");

        assert_eq!(result.driver.name, "remote-ssh");
        assert_eq!(result.driver.kind, DriverKind::Sandbox);
        assert_eq!(result.driver.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(result.driver.protocol_version, SCHEMA_VERSION);

        let Capabilities::Sandbox(capabilities) = result.capabilities else {
            panic!("remote-ssh should report sandbox capabilities");
        };
        assert!(!capabilities.supports_hot_reload_policy);
        assert!(!capabilities.supports_filesystem_lockdown);
        assert!(!capabilities.supports_syscall_filter);
        assert!(!capabilities.supports_native_inference_routing);
        assert!(capabilities.supports_remote_host);
        assert!(!capabilities.supports_persistent_sessions);
    }
}
