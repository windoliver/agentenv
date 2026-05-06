#![forbid(unsafe_code)]

use std::{collections::BTreeMap, io, path::PathBuf, process::Command, sync::Arc};

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
use serde_json::Value;
use url::Url;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteSshTarget {
    host: String,
    user: String,
    port: u16,
    identity_file: Option<String>,
    jump_host: Option<String>,
    enforce_remote_firewall: bool,
}

impl RemoteSshTarget {
    fn from_metadata(metadata: &BTreeMap<String, Value>) -> DriverResult<Self> {
        let host = required_metadata_string(metadata, "host")?;
        let user = required_metadata_string(metadata, "user")?;
        validate_remote_ssh_user(&user, "metadata.user")?;
        let port = metadata_port(metadata)?;
        let identity_file =
            optional_metadata_string(metadata, "identity_file")?.map(expand_leading_home);
        let jump_host = optional_metadata_string(metadata, "jump_host")?;
        let enforce_remote_firewall =
            optional_metadata_bool(metadata, "enforce_remote_firewall")?.unwrap_or(false);

        Ok(Self {
            host,
            user,
            port,
            identity_file,
            jump_host,
            enforce_remote_firewall,
        })
    }

    fn to_handle(&self) -> DriverResult<String> {
        let base = format!("remote-ssh://{}@{}:{}", self.user, self.host, self.port);
        let mut url = Url::parse(&base).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to build remote-ssh handle: {source}"),
        })?;
        if self.identity_file.is_some() || self.jump_host.is_some() {
            let mut pairs = url.query_pairs_mut();
            if let Some(identity_file) = self.identity_file.as_deref() {
                pairs.append_pair("identity_file", identity_file);
            }
            if let Some(jump_host) = self.jump_host.as_deref() {
                pairs.append_pair("jump_host", jump_host);
            }
        }
        Ok(url.to_string())
    }

    fn from_handle(handle: &str) -> DriverResult<Self> {
        let url = Url::parse(handle)
            .map_err(|source| invalid_handle(handle.to_owned(), source.to_string()))?;
        if url.scheme() != "remote-ssh" {
            return Err(invalid_handle(
                handle.to_owned(),
                "expected remote-ssh scheme",
            ));
        }
        if url.password().is_some() {
            return Err(invalid_handle(
                handle.to_owned(),
                "passwords are not supported in remote-ssh handles",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| invalid_handle(handle.to_owned(), "missing host"))?
            .to_owned();
        let user = url.username();
        if user.is_empty() {
            return Err(invalid_handle(handle.to_owned(), "missing user"));
        }
        validate_remote_ssh_user(user, "handle username")
            .map_err(|err| invalid_handle(handle.to_owned(), err.to_string()))?;
        let mut identity_file = None;
        let mut jump_host = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "identity_file" => identity_file = Some(value.into_owned()),
                "jump_host" => jump_host = Some(value.into_owned()),
                _ => {}
            }
        }
        Ok(Self {
            host,
            user: user.to_owned(),
            port: url.port().unwrap_or(22),
            identity_file,
            jump_host,
            enforce_remote_firewall: false,
        })
    }
}

fn validate_remote_ssh_user(user: &str, label: &str) -> DriverResult<()> {
    if user.chars().any(is_unsupported_remote_ssh_user_char) {
        return Err(DriverError::InvalidInput {
            message: format!("{label} contains unsupported characters"),
        });
    }

    Ok(())
}

fn is_unsupported_remote_ssh_user_char(ch: char) -> bool {
    ch.is_control()
        || ch.is_whitespace()
        || matches!(ch, '@' | ':' | '/' | '?' | '#' | '[' | ']' | '%')
}

fn required_metadata_string(metadata: &BTreeMap<String, Value>, key: &str) -> DriverResult<String> {
    match metadata.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        Some(Value::String(_)) | None => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} is required"),
        }),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be a string when set"),
        }),
    }
}

fn optional_metadata_string(
    metadata: &BTreeMap<String, Value>,
    key: &str,
) -> DriverResult<Option<String>> {
    match metadata.get(key) {
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be a string when set"),
        }),
    }
}

fn optional_metadata_bool(
    metadata: &BTreeMap<String, Value>,
    key: &str,
) -> DriverResult<Option<bool>> {
    match metadata.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be a boolean when set"),
        }),
    }
}

fn metadata_port(metadata: &BTreeMap<String, Value>) -> DriverResult<u16> {
    match metadata.get("port") {
        None | Some(Value::Null) => Ok(22),
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| DriverError::InvalidInput {
                message: "metadata.port must be in range 1..=65535".to_owned(),
            }),
        Some(Value::String(value)) => value
            .parse::<u16>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| DriverError::InvalidInput {
                message: "metadata.port must be a numeric string in range 1..=65535".to_owned(),
            }),
        Some(_) => Err(DriverError::InvalidInput {
            message: "metadata.port must be an integer or numeric string when set".to_owned(),
        }),
    }
}

fn expand_leading_home(value: String) -> String {
    let Some(rest) = value.strip_prefix("~/") else {
        return value;
    };
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(rest).to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("~/{rest}"))
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

    async fn create(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        let target = RemoteSshTarget::from_metadata(&spec.metadata)?;
        if target.enforce_remote_firewall {
            return Err(policy_missing());
        }

        Ok(SandboxHandle {
            handle: target.to_handle()?,
        })
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        let _target = RemoteSshTarget::from_handle(&params.handle)?;
        Err(invalid_handle(
            params.handle,
            "remote-ssh connect is not implemented",
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
        let _target = RemoteSshTarget::from_handle(&params.handle)?;
        Err(invalid_handle(
            params.handle,
            "remote-ssh exec is not implemented",
        ))
    }

    async fn copy_in(&self, params: CopyInParams) -> DriverResult<EmptyResult> {
        let _target = RemoteSshTarget::from_handle(&params.handle)?;
        Err(invalid_handle(
            params.handle,
            "remote-ssh copy_in is not implemented",
        ))
    }

    async fn copy_out(&self, params: CopyOutParams) -> DriverResult<EmptyResult> {
        let _target = RemoteSshTarget::from_handle(&params.handle)?;
        Err(invalid_handle(
            params.handle,
            "remote-ssh copy_out is not implemented",
        ))
    }

    async fn apply_policy(&self, _params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult> {
        Err(policy_missing())
    }

    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        let _target = RemoteSshTarget::from_handle(&params.handle)?;
        Err(invalid_handle(
            params.handle,
            "remote-ssh status is not implemented",
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

    use serde_json::json;

    use super::{RemoteSshDriver, RemoteSshTarget};

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

    #[test]
    fn target_from_metadata_accepts_required_fields_and_defaults_port() {
        let metadata = BTreeMap::from([
            ("host".to_owned(), json!("dev-vm.example.com")),
            ("user".to_owned(), json!("alice")),
        ]);

        let target = RemoteSshTarget::from_metadata(&metadata).expect("target");

        assert_eq!(target.host, "dev-vm.example.com");
        assert_eq!(target.user, "alice");
        assert_eq!(target.port, 22);
        assert_eq!(target.identity_file, None);
        assert_eq!(target.jump_host, None);
        assert!(!target.enforce_remote_firewall);
    }

    #[test]
    fn target_from_metadata_accepts_string_port_identity_and_jump_host() {
        let metadata = BTreeMap::from([
            ("host".to_owned(), json!("dev-vm.example.com")),
            ("user".to_owned(), json!("alice")),
            ("port".to_owned(), json!("2222")),
            ("identity_file".to_owned(), json!("~/.ssh/id_ed25519")),
            ("jump_host".to_owned(), json!("bastion.example.com")),
            ("enforce_remote_firewall".to_owned(), json!(false)),
        ]);

        let target = RemoteSshTarget::from_metadata(&metadata).expect("target");

        assert_eq!(target.port, 2222);
        assert!(target
            .identity_file
            .as_ref()
            .expect("identity")
            .ends_with(".ssh/id_ed25519"));
        assert_eq!(target.jump_host.as_deref(), Some("bastion.example.com"));
    }

    #[test]
    fn target_from_metadata_rejects_missing_host_user_bad_port_and_bad_firewall_type() {
        for metadata in [
            BTreeMap::from([("user".to_owned(), json!("alice"))]),
            BTreeMap::from([("host".to_owned(), json!("dev-vm.example.com"))]),
            BTreeMap::from([
                ("host".to_owned(), json!("dev-vm.example.com")),
                ("user".to_owned(), json!("alice")),
                ("port".to_owned(), json!(70000)),
            ]),
            BTreeMap::from([
                ("host".to_owned(), json!("dev-vm.example.com")),
                ("user".to_owned(), json!("alice")),
                ("enforce_remote_firewall".to_owned(), json!("yes")),
            ]),
        ] {
            let err = RemoteSshTarget::from_metadata(&metadata).expect_err("metadata should fail");
            assert!(err.to_string().contains("metadata."));
        }
    }

    #[test]
    fn target_from_metadata_rejects_username_that_cannot_round_trip_in_handle() {
        let metadata = BTreeMap::from([
            ("host".to_owned(), json!("dev-vm.example.com")),
            ("user".to_owned(), json!("alice@example.com")),
        ]);

        let err = RemoteSshTarget::from_metadata(&metadata).expect_err("metadata should fail");

        assert!(err.to_string().contains("metadata.user"));
    }

    #[test]
    fn uri_handle_round_trips_target_fields() {
        let target = RemoteSshTarget {
            host: "dev-vm.example.com".to_owned(),
            user: "alice".to_owned(),
            port: 2222,
            identity_file: Some("/Users/alice/.ssh/id_ed25519".to_owned()),
            jump_host: Some("bastion.example.com".to_owned()),
            enforce_remote_firewall: false,
        };

        let handle = target.to_handle().expect("handle");
        let parsed = RemoteSshTarget::from_handle(&handle).expect("parse handle");

        assert_eq!(parsed, target);
    }

    #[test]
    fn uri_handle_omits_query_when_no_optional_fields_are_set() {
        let target = RemoteSshTarget {
            host: "dev-vm.example.com".to_owned(),
            user: "alice".to_owned(),
            port: 22,
            identity_file: None,
            jump_host: None,
            enforce_remote_firewall: false,
        };

        let handle = target.to_handle().expect("handle");

        assert_eq!(handle, "remote-ssh://alice@dev-vm.example.com:22");
        assert!(!handle.ends_with('?'));
    }

    #[test]
    fn uri_handle_rejects_encoded_username_delimiters() {
        let err =
            RemoteSshTarget::from_handle("remote-ssh://alice%40example.com@dev-vm.example.com:22")
                .expect_err("handle should fail");

        assert!(err.to_string().contains("username"));
    }

    #[test]
    fn uri_handle_rejects_password_authority() {
        let err = RemoteSshTarget::from_handle("remote-ssh://alice:secret@dev-vm.example.com:22")
            .expect_err("handle should fail");

        assert!(err.to_string().contains("password"));
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
