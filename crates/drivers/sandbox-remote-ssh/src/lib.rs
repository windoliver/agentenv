#![forbid(unsafe_code)]

use std::{collections::BTreeMap, io, process::Command, sync::Arc};

use agentenv_core::driver::{
    persistent_sessions_missing, DriverError, DriverResult, SandboxDriver,
};
use agentenv_proto::{
    assert_compatible_schema_version, ApplyPolicyParams, ApplyPolicyResult, AttachSessionParams,
    Capabilities, ConnectParams, CopyInParams, CopyOutParams, CreateSessionParams, DestroyParams,
    DriverInfo, DriverKind, EmptyResult, ExecParams, ExecResult, InitializeParams,
    InitializeResult, IssueSeverity, KillSessionParams, ListSessionsParams, ListSessionsResult,
    LogsParams, LogsResult, LogsStreamParams, PreflightIssue, PreflightParams, PreflightResult,
    SandboxCapabilities, SandboxHandle, SandboxSpec, SandboxStatus, SandboxStatusParams,
    SessionHandle, ShellHandle, ShutdownParams, StopParams, SCHEMA_VERSION,
};

const DRIVER_NAME: &str = "remote-ssh";
const REMOTE_LOGS_CAPABILITY: &str = "remote_logs";
const POLICY_CAPABILITY: &str = "supports_hot_reload_policy";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandRequest {
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandOutput {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, request: &CommandRequest) -> io::Result<CommandOutput>;

    #[allow(dead_code)]
    fn status(&self, program: &str, request: &CommandRequest) -> io::Result<Option<i32>> {
        self.run(program, request).map(|output| output.status)
    }
}

#[derive(Debug, Default)]
struct ProcessCommandRunner;

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, program: &str, request: &CommandRequest) -> io::Result<CommandOutput> {
        let output = Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .output()?;
        Ok(CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn status(&self, program: &str, request: &CommandRequest) -> io::Result<Option<i32>> {
        Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .status()
            .map(|status| status.code())
    }
}

fn command_request(args: &[&str]) -> CommandRequest {
    CommandRequest {
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env: BTreeMap::new(),
    }
}

fn preflight_failure(code: &str, message: String, remediation: Option<String>) -> PreflightResult {
    PreflightResult {
        ok: false,
        issues: vec![PreflightIssue {
            severity: IssueSeverity::Error,
            code: code.to_owned(),
            message,
            remediation,
        }],
    }
}

pub struct RemoteSshDriver {
    ssh_binary: String,
    scp_binary: String,
    runner: Arc<dyn CommandRunner>,
}

impl Default for RemoteSshDriver {
    fn default() -> Self {
        Self {
            ssh_binary: "ssh".to_owned(),
            scp_binary: "scp".to_owned(),
            runner: Arc::new(ProcessCommandRunner),
        }
    }
}

#[cfg(test)]
impl RemoteSshDriver {
    fn with_command_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            ssh_binary: "ssh".to_owned(),
            scp_binary: "scp".to_owned(),
            runner,
        }
    }
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
        if let Err(source) = self.runner.run(&self.ssh_binary, &command_request(&["-V"])) {
            return Ok(preflight_failure(
                "remote_ssh_missing_ssh",
                format!(
                    "SSH binary `{}` is not available: {source}",
                    self.ssh_binary
                ),
                Some(format!(
                    "Install OpenSSH and ensure `{}` is on PATH",
                    self.ssh_binary
                )),
            ));
        }

        if let Err(source) = self.runner.run(&self.scp_binary, &command_request(&["-V"])) {
            return Ok(preflight_failure(
                "remote_ssh_missing_scp",
                format!(
                    "SCP binary `{}` is not available: {source}",
                    self.scp_binary
                ),
                Some(format!(
                    "Install OpenSSH and ensure `{}` is on PATH",
                    self.scp_binary
                )),
            ));
        }

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
    use std::{
        collections::{BTreeMap, VecDeque},
        io,
        sync::{Arc, Mutex},
    };

    use agentenv_core::driver::SandboxDriver;
    use agentenv_proto::{
        Capabilities, DriverKind, InitializeParams, LogLevel, PreflightParams, SCHEMA_VERSION,
    };

    use super::RemoteSshDriver;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CommandRequest {
        args: Vec<String>,
        env: BTreeMap<String, String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CommandOutput {
        status: Option<i32>,
        stdout: String,
        stderr: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CommandCall {
        program: String,
        request: CommandRequest,
    }

    #[derive(Debug, Clone)]
    enum CommandScriptResult {
        Output(CommandOutput),
        Error {
            kind: io::ErrorKind,
            message: String,
        },
    }

    #[derive(Debug, Clone)]
    struct CommandScript {
        program: String,
        request: CommandRequest,
        result: CommandScriptResult,
    }

    #[derive(Debug)]
    struct RecordingCommandRunner {
        scripts: Mutex<VecDeque<CommandScript>>,
        calls: Mutex<Vec<CommandCall>>,
    }

    impl RecordingCommandRunner {
        fn new(scripts: Vec<CommandScript>) -> Self {
            Self {
                scripts: Mutex::new(scripts.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<CommandCall> {
            self.calls.lock().expect("calls mutex").clone()
        }
    }

    fn command_request(args: &[&str]) -> CommandRequest {
        CommandRequest {
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            env: BTreeMap::new(),
        }
    }

    impl CommandScript {
        fn output(
            program: &str,
            args: &[&str],
            status: Option<i32>,
            stdout: &str,
            stderr: &str,
        ) -> Self {
            Self {
                program: program.to_owned(),
                request: command_request(args),
                result: CommandScriptResult::Output(CommandOutput {
                    status,
                    stdout: stdout.to_owned(),
                    stderr: stderr.to_owned(),
                }),
            }
        }

        fn failure(program: &str, args: &[&str], kind: io::ErrorKind, message: &str) -> Self {
            Self {
                program: program.to_owned(),
                request: command_request(args),
                result: CommandScriptResult::Error {
                    kind,
                    message: message.to_owned(),
                },
            }
        }
    }

    impl super::CommandRunner for RecordingCommandRunner {
        fn run(
            &self,
            program: &str,
            request: &super::CommandRequest,
        ) -> io::Result<super::CommandOutput> {
            self.calls.lock().expect("calls mutex").push(CommandCall {
                program: program.to_owned(),
                request: CommandRequest {
                    args: request.args.clone(),
                    env: request.env.clone(),
                },
            });
            let script = self
                .scripts
                .lock()
                .expect("scripts mutex")
                .pop_front()
                .expect("unexpected command");
            assert_eq!(script.program, program);
            assert_eq!(script.request.args, request.args);
            assert_eq!(script.request.env, request.env);
            match script.result {
                CommandScriptResult::Output(output) => Ok(super::CommandOutput {
                    status: output.status,
                    stdout: output.stdout,
                    stderr: output.stderr,
                }),
                CommandScriptResult::Error { kind, message } => Err(io::Error::new(kind, message)),
            }
        }

        fn status(
            &self,
            program: &str,
            request: &super::CommandRequest,
        ) -> io::Result<Option<i32>> {
            self.run(program, request).map(|output| output.status)
        }
    }

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

    #[tokio::test]
    async fn preflight_checks_ssh_and_scp_executables() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::output("ssh", &["-V"], Some(0), "", "OpenSSH_9.9\n"),
            CommandScript::output("scp", &["-V"], Some(1), "", "usage: scp\n"),
        ]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight");

        assert!(result.ok);
        assert!(result.issues.is_empty());
        assert_eq!(
            runner.calls(),
            vec![
                CommandCall {
                    program: "ssh".to_owned(),
                    request: command_request(&["-V"])
                },
                CommandCall {
                    program: "scp".to_owned(),
                    request: command_request(&["-V"])
                },
            ]
        );
    }

    #[tokio::test]
    async fn preflight_reports_missing_ssh() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::failure(
            "ssh",
            &["-V"],
            io::ErrorKind::NotFound,
            "ssh not found",
        )]));
        let driver = RemoteSshDriver::with_command_runner(runner);

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight");

        assert!(!result.ok);
        assert_eq!(result.issues[0].code, "remote_ssh_missing_ssh");
        assert!(result.issues[0].message.contains("ssh"));
    }
}
