#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

#[cfg(test)]
use std::collections::VecDeque;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde_json::Value;

use agentenv_core::driver::{DriverError, DriverResult, SandboxDriver};
use agentenv_policy::{OpenShellTranslator, PolicyError, PolicyTranslator, TranslatedPolicy};
use agentenv_proto::{
    assert_compatible_schema_version, ApplyPolicyParams, ApplyPolicyResult, Capabilities,
    ConnectParams, CopyInParams, CopyOutParams, DestroyParams, DriverInfo, DriverKind, EmptyResult,
    ExecParams, ExecResult, InitializeParams, InitializeResult, IssueSeverity, LogsParams,
    LogsResult, LogsStreamParams, NetworkPolicy, PreflightIssue, PreflightParams, PreflightResult,
    SandboxCapabilities, SandboxHandle, SandboxSpec, SandboxStatus, SandboxStatusParams,
    ShellHandle, ShutdownParams, StopParams, SCHEMA_VERSION,
};
use semver::Version;
use uuid::Uuid;

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "sandbox-openshell";

const DEFAULT_OPEN_SHELL_AGENT_BINARIES: [&str; 3] = ["claude", "codex", "openclaw"];
const DEFAULT_OPEN_SHELL_SUPPORT_BINARIES: [&str; 1] = ["curl"];
const OPEN_SHELL_BINARY: &str = "openshell";
const MINIMUM_SUPPORTED_OPEN_SHELL_VERSION: Version = Version::new(0, 0, 30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateDisposition {
    HotReload,
}

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
    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<()>;
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

    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<()> {
        let _child = Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .spawn()?;

        Ok(())
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct CommandScript {
    program: String,
    request: CommandRequest,
    result: CommandScriptResult,
}

#[cfg(test)]
#[derive(Debug, Clone)]
enum CommandScriptResult {
    Output(CommandOutput),
    Error {
        kind: io::ErrorKind,
        message: String,
    },
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandCall {
    program: String,
    request: CommandRequest,
}

#[cfg(test)]
#[derive(Debug)]
struct RecordingCommandRunner {
    scripts: Mutex<VecDeque<CommandScript>>,
    calls: Mutex<Vec<CommandCall>>,
    spawn_calls: Mutex<Vec<CommandCall>>,
}

#[cfg(test)]
impl RecordingCommandRunner {
    fn new(scripts: Vec<CommandScript>) -> Self {
        Self {
            scripts: Mutex::new(scripts.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
            spawn_calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<CommandCall> {
        self.calls.lock().expect("calls mutex").clone()
    }

    fn spawn_calls(&self) -> Vec<CommandCall> {
        self.spawn_calls.lock().expect("spawn calls mutex").clone()
    }
}

#[cfg(test)]
impl CommandScript {
    fn success(program: &str, args: &[&str], stdout: &str, stderr: &str) -> Self {
        Self {
            program: program.to_owned(),
            request: command_request(args),
            result: CommandScriptResult::Output(CommandOutput {
                status: Some(0),
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
}

#[cfg(test)]
impl CommandRunner for RecordingCommandRunner {
    fn run(&self, program: &str, request: &CommandRequest) -> io::Result<CommandOutput> {
        self.calls.lock().expect("calls mutex").push(CommandCall {
            program: program.to_owned(),
            request: request.clone(),
        });

        let script = self
            .scripts
            .lock()
            .expect("scripts mutex")
            .pop_front()
            .expect("unexpected command invocation");

        assert_eq!(script.program, program);
        assert_eq!(script.request, *request);

        match script.result {
            CommandScriptResult::Output(output) => Ok(output),
            CommandScriptResult::Error { kind, message } => Err(io::Error::new(kind, message)),
        }
    }

    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<()> {
        self.spawn_calls
            .lock()
            .expect("spawn calls mutex")
            .push(CommandCall {
                program: program.to_owned(),
                request: request.clone(),
            });

        let script = self
            .scripts
            .lock()
            .expect("scripts mutex")
            .pop_front()
            .expect("unexpected command invocation");

        assert_eq!(script.program, program);
        assert_eq!(script.request, *request);

        match script.result {
            CommandScriptResult::Output(_) => Ok(()),
            CommandScriptResult::Error { kind, message } => Err(io::Error::new(kind, message)),
        }
    }
}

pub struct OpenShellDriver {
    binary: String,
    runner: Arc<dyn CommandRunner>,
    current_policies: Mutex<BTreeMap<String, NetworkPolicy>>,
}

impl Default for OpenShellDriver {
    fn default() -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner: Arc::new(ProcessCommandRunner),
            current_policies: Mutex::new(BTreeMap::new()),
        }
    }
}

#[cfg(test)]
impl OpenShellDriver {
    fn with_command_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner,
            current_policies: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl SandboxDriver for OpenShellDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        assert_compatible_schema_version(&params.schema_version)?;

        Ok(InitializeResult {
            driver: DriverInfo {
                name: OPEN_SHELL_BINARY.to_owned(),
                kind: DriverKind::Sandbox,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: true,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: true,
                supports_remote_host: true,
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        let version_output = match self.run_command_request(command_request(&["--version"])) {
            Ok(output) => output,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(preflight_failure(
                    "openshell_missing",
                    format!(
                        "OpenShell CLI binary `{}` was not found on PATH",
                        self.binary
                    ),
                    Some(format!(
                        "Install OpenShell and ensure `{}` is available on your PATH",
                        self.binary
                    )),
                ));
            }
            Err(err) => {
                return Ok(preflight_failure(
                    "openshell_version_failed",
                    format!("failed to run `{}` --version: {err}", self.binary),
                    None,
                ));
            }
        };

        if version_output.status.is_none_or(|status| status != 0) {
            return Ok(preflight_failure(
                "openshell_version_failed",
                format!(
                    "`{}` --version failed with {}: {}",
                    self.binary,
                    status_label(version_output.status),
                    render_command_output(&version_output)
                ),
                None,
            ));
        }

        let parsed_version = extract_semver_token(&version_output.stdout)
            .or_else(|| extract_semver_token(&version_output.stderr));
        let Some(parsed_version) = parsed_version else {
            return Ok(preflight_failure(
                "openshell_version_unparseable",
                format!(
                    "could not parse an OpenShell version from `{}` --version output: {}",
                    self.binary,
                    render_command_output(&version_output)
                ),
                None,
            ));
        };

        if parsed_version < MINIMUM_SUPPORTED_OPEN_SHELL_VERSION {
            return Ok(preflight_failure(
                "openshell_version_too_old",
                format!(
                    "OpenShell CLI version {parsed_version} is too old; require >= {}",
                    MINIMUM_SUPPORTED_OPEN_SHELL_VERSION
                ),
                Some(format!(
                    "Install OpenShell {} or newer and retry",
                    MINIMUM_SUPPORTED_OPEN_SHELL_VERSION
                )),
            ));
        }

        let gateway_output = match self.run_command_request(command_request(&["gateway", "status"]))
        {
            Ok(output) => output,
            Err(err) => {
                return Ok(preflight_failure(
                    "openshell_gateway_down",
                    format!("failed to run `{} gateway status`: {err}", self.binary),
                    None,
                ));
            }
        };

        if gateway_output.status.is_none_or(|status| status != 0) {
            return Ok(preflight_failure(
                "openshell_gateway_down",
                format!(
                    "`{} gateway status` failed with {}: {}",
                    self.binary,
                    status_label(gateway_output.status),
                    render_command_output(&gateway_output)
                ),
                None,
            ));
        }

        Ok(PreflightResult {
            ok: true,
            issues: Vec::new(),
        })
    }

    async fn create(&self, _spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        let spec = _spec;
        let policy = spec.policy;
        let image = spec.image.unwrap_or_else(|| "openclaw".to_owned());
        let name = match spec.metadata.get("name") {
            Some(Value::String(value)) if !value.is_empty() => value.clone(),
            Some(Value::String(_)) | None => format!("agentenv-{}", Uuid::new_v4()),
            Some(_) => {
                return Err(DriverError::InvalidInput {
                    message: "metadata.name must be a string when set".to_owned(),
                });
            }
        };
        let remote = match spec.metadata.get("remote") {
            Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
            Some(Value::String(_)) | None => None,
            Some(_) => {
                return Err(DriverError::InvalidInput {
                    message: "metadata.remote must be a string when set".to_owned(),
                });
            }
        };

        let mut args = vec![
            "sandbox".to_owned(),
            "create".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--keep".to_owned(),
            "--no-auto-providers".to_owned(),
            "--from".to_owned(),
            image,
        ];
        if let Some(remote) = remote {
            args.push("--remote".to_owned());
            args.push(remote);
        }

        let request = CommandRequest {
            args,
            env: spec.env,
        };
        let _output = self.run_checked_command(request)?;

        if let Some(policy) = policy {
            self.apply_policy_to_handle(&name, policy)?;
        }

        Ok(SandboxHandle { handle: name })
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        let request = command_request(&["sandbox", "connect", &params.handle, "--", "true"]);
        let _output = self.run_checked_command(request)?;

        Ok(ShellHandle {
            session_id: params.handle,
            tty: true,
            working_dir: Some("/sandbox".to_owned()),
        })
    }

    async fn exec(&self, params: ExecParams) -> DriverResult<ExecResult> {
        let request = CommandRequest {
            args: vec![
                "sandbox".to_owned(),
                "connect".to_owned(),
                params.handle,
                "--".to_owned(),
                params.cmd,
            ],
            env: params.env,
        };
        let command = command_string(&self.binary, &request.args);
        let output =
            self.run_command_request(request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                })?;

        Ok(ExecResult {
            status: output.status.unwrap_or(1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    async fn copy_in(&self, params: CopyInParams) -> DriverResult<EmptyResult> {
        let request = command_request(&[
            "sandbox",
            "upload",
            &params.handle,
            &params.src_host_path,
            &params.dst_sandbox_path,
        ]);
        let _output = self.run_checked_command(request)?;

        Ok(EmptyResult::default())
    }

    async fn copy_out(&self, params: CopyOutParams) -> DriverResult<EmptyResult> {
        let request = command_request(&[
            "sandbox",
            "download",
            &params.handle,
            &params.src_sandbox_path,
            &params.dst_host_path,
        ]);
        let _output = self.run_checked_command(request)?;

        Ok(EmptyResult::default())
    }

    async fn apply_policy(&self, params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult> {
        let ApplyPolicyParams { handle, policy } = params;
        self.apply_policy_to_handle(&handle, policy)
    }

    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        let request = command_request(&["sandbox", "get", &params.handle]);
        let output = self.run_checked_command(request)?;
        let phase = classify_status_phase(&output.stdout);

        Ok(SandboxStatus {
            healthy: phase == agentenv_proto::SandboxPhase::Running,
            phase,
            last_ping: None,
        })
    }

    async fn logs(&self, params: LogsParams) -> DriverResult<LogsResult> {
        let mut args = vec!["logs".to_owned(), params.handle];
        if params.follow {
            args.push("--tail".to_owned());
        }
        if let Some(since) = params.since {
            args.push("--since".to_owned());
            args.push(since);
        }
        let output = self.run_checked_command(CommandRequest {
            args,
            env: BTreeMap::new(),
        })?;

        Ok(LogsResult {
            entries: parse_log_entries(&output.stdout),
        })
    }

    async fn logs_stream(&self, params: LogsStreamParams) -> DriverResult<EmptyResult> {
        let mut args = vec!["logs".to_owned(), params.handle, "--tail".to_owned()];
        if let Some(since) = params.since {
            args.push("--since".to_owned());
            args.push(since);
        }
        self.spawn_checked_command(CommandRequest {
            args,
            env: BTreeMap::new(),
        })?;

        Ok(EmptyResult::default())
    }

    async fn stop(&self, params: StopParams) -> DriverResult<EmptyResult> {
        let request = command_request(&["sandbox", "stop", &params.handle]);
        let _output = self.run_checked_command(request)?;

        Ok(EmptyResult::default())
    }

    async fn destroy(&self, params: DestroyParams) -> DriverResult<EmptyResult> {
        let request = command_request(&["sandbox", "delete", &params.handle]);
        let _output = self.run_checked_command(request)?;

        match self.current_policies.lock() {
            Ok(mut policies) => {
                policies.remove(&params.handle);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&params.handle);
            }
        }

        Ok(EmptyResult::default())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        match self.current_policies.lock() {
            Ok(mut policies) => policies.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
        Ok(EmptyResult::default())
    }
}

impl OpenShellDriver {
    fn run_command_request(&self, request: CommandRequest) -> io::Result<CommandOutput> {
        self.runner.run(&self.binary, &request)
    }

    fn spawn_command_request(&self, request: CommandRequest) -> io::Result<()> {
        self.runner.spawn(&self.binary, &request)
    }

    fn run_checked_command(&self, request: CommandRequest) -> Result<CommandOutput, DriverError> {
        let command = command_string(&self.binary, &request.args);
        let output =
            self.run_command_request(request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                })?;

        if output.status.is_none_or(|status| status != 0) {
            return Err(DriverError::CommandFailed {
                command,
                status: output.status,
                stdout: output.stdout,
                stderr: output.stderr,
            });
        }

        Ok(output)
    }

    fn spawn_checked_command(&self, request: CommandRequest) -> Result<(), DriverError> {
        let command = command_string(&self.binary, &request.args);
        self.spawn_command_request(request)
            .map_err(|source| DriverError::CommandSpawn { command, source })
    }

    fn current_policy_for_handle(&self, handle: &str) -> Option<NetworkPolicy> {
        match self.current_policies.lock() {
            Ok(policies) => policies.get(handle).cloned(),
            Err(poisoned) => poisoned.into_inner().get(handle).cloned(),
        }
    }

    fn store_current_policy(&self, handle: String, policy: NetworkPolicy) {
        match self.current_policies.lock() {
            Ok(mut policies) => {
                policies.insert(handle, policy);
            }
            Err(poisoned) => {
                poisoned.into_inner().insert(handle, policy);
            }
        }
    }

    fn apply_policy_to_handle(
        &self,
        handle: &str,
        policy: NetworkPolicy,
    ) -> DriverResult<ApplyPolicyResult> {
        if let Some(current) = self.current_policy_for_handle(handle) {
            classify_policy_update(&current, &policy).map_err(|err| {
                DriverError::PolicyTranslation {
                    message: err.to_string(),
                }
            })?;
        }

        let translated =
            translate_for_openshell(&policy).map_err(|err| DriverError::PolicyTranslation {
                message: err.to_string(),
            })?;
        let temp_policy_file = TempPolicyFile::write(&translated.policy_yaml).map_err(|err| {
            DriverError::PolicyTranslation {
                message: format!("failed to write translated policy to temp file: {err}"),
            }
        })?;

        let policy_args = vec![
            "policy".to_owned(),
            "set".to_owned(),
            handle.to_owned(),
            "--policy".to_owned(),
            temp_policy_file.path().to_string_lossy().into_owned(),
            "--wait".to_owned(),
        ];
        self.run_policy_command(CommandRequest {
            args: policy_args,
            env: BTreeMap::new(),
        })?;

        if let Some(inference_update) = translated.inference_update {
            let mut args = vec![
                "inference".to_owned(),
                "set".to_owned(),
                "--provider".to_owned(),
                inference_update.provider,
                "--model".to_owned(),
                inference_update.model,
            ];
            if let Some(timeout_seconds) = inference_update.timeout_seconds {
                args.push("--timeout".to_owned());
                args.push(timeout_seconds.to_string());
            }

            self.run_policy_command(CommandRequest {
                args,
                env: BTreeMap::new(),
            })?;
        }

        self.store_current_policy(handle.to_owned(), policy);

        Ok(ApplyPolicyResult { hot_reloaded: true })
    }

    fn run_policy_command(&self, request: CommandRequest) -> Result<CommandOutput, DriverError> {
        let command = command_string(&self.binary, &request.args);
        let output =
            self.run_command_request(request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                })?;

        if output.status.is_none_or(|status| status != 0) {
            return Err(DriverError::CommandFailed {
                command,
                status: output.status,
                stdout: output.stdout,
                stderr: output.stderr,
            });
        }

        Ok(output)
    }
}

struct TempPolicyFile {
    path: PathBuf,
}

impl TempPolicyFile {
    fn write(policy_yaml: &str) -> io::Result<Self> {
        let path =
            std::env::temp_dir().join(format!("sandbox-openshell-policy-{}.yaml", Uuid::new_v4()));
        let guard = Self { path };

        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }

        let mut file = options.open(guard.path())?;
        file.write_all(policy_yaml.as_bytes())?;
        file.flush()?;

        Ok(guard)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPolicyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn command_request(args: &[&str]) -> CommandRequest {
    command_request_with_env(args, BTreeMap::new())
}

fn command_request_with_env(args: &[&str], env: BTreeMap<String, String>) -> CommandRequest {
    CommandRequest {
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env,
    }
}

fn command_string(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn classify_status_phase(stdout: &str) -> agentenv_proto::SandboxPhase {
    let lower = stdout.to_lowercase();
    if lower.contains("destroyed") || lower.contains("deleted") {
        agentenv_proto::SandboxPhase::Destroyed
    } else if lower.contains("stopped") {
        agentenv_proto::SandboxPhase::Stopped
    } else if lower.contains("error") || lower.contains("failed") {
        agentenv_proto::SandboxPhase::Error
    } else {
        agentenv_proto::SandboxPhase::Running
    }
}

fn parse_log_entries(stdout: &str) -> Vec<agentenv_proto::LogEntry> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                None
            } else {
                Some(parse_log_entry(line))
            }
        })
        .collect()
}

fn parse_log_entry(line: &str) -> agentenv_proto::LogEntry {
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(line) {
        let level = map
            .get("level")
            .and_then(Value::as_str)
            .map(parse_log_level)
            .unwrap_or(agentenv_proto::LogLevel::Info);
        let ts = map
            .get("ts")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let msg = map
            .get("msg")
            .or_else(|| map.get("message"))
            .and_then(Value::as_str)
            .unwrap_or(line)
            .to_owned();
        let mut kv = map
            .get("kv")
            .and_then(Value::as_object)
            .map(|kv| {
                kv.iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        if log_line_has_denial_signal(line) {
            kv.insert("egress_denied".to_owned(), Value::Bool(true));
        }

        return agentenv_proto::LogEntry { level, ts, msg, kv };
    }

    let ts = parsed_log_timestamp(line).unwrap_or_default();
    let msg = parsed_log_message(line);
    let level = parse_log_level_from_text(line);
    let mut kv = BTreeMap::new();
    if log_line_has_denial_signal(line) {
        kv.insert("egress_denied".to_owned(), Value::Bool(true));
    }

    agentenv_proto::LogEntry { level, ts, msg, kv }
}

fn parsed_log_timestamp(line: &str) -> Option<String> {
    let (first, rest) = line.split_once(' ')?;
    if looks_like_timestamp(first) && !rest.is_empty() {
        Some(first.to_owned())
    } else {
        None
    }
}

fn parsed_log_message(line: &str) -> String {
    if let Some((first, rest)) = line.split_once(' ') {
        if looks_like_timestamp(first) {
            let rest = rest.trim_start();
            if let Some((token, message)) = rest.split_once(' ') {
                if let Some(_level) = parse_log_level_token(token) {
                    return message.trim_start().to_owned();
                }
            }
            return rest.to_owned();
        }
    }

    if let Some((token, message)) = line.split_once(' ') {
        if parse_log_level_token(token).is_some() {
            return message.trim_start().to_owned();
        }
    }

    line.to_owned()
}

fn parse_log_level_from_text(line: &str) -> agentenv_proto::LogLevel {
    if let Some((first, rest)) = line.split_once(' ') {
        if looks_like_timestamp(first) {
            if let Some((token, _)) = rest.trim_start().split_once(' ') {
                if let Some(level) = parse_log_level_token(token) {
                    return level;
                }
            }
        } else if let Some(level) = parse_log_level_token(first) {
            return level;
        }
    }

    let upper = line.to_ascii_uppercase();
    if upper.contains("FATAL") || upper.contains("ERROR") {
        agentenv_proto::LogLevel::Error
    } else if upper.contains("WARN")
        || upper.contains("MED")
        || upper.contains("HIGH")
        || upper.contains("CRIT")
    {
        agentenv_proto::LogLevel::Warn
    } else {
        agentenv_proto::LogLevel::Info
    }
}

fn parse_log_level(level: &str) -> agentenv_proto::LogLevel {
    parse_log_level_token(level).unwrap_or(agentenv_proto::LogLevel::Info)
}

fn parse_log_level_token(token: &str) -> Option<agentenv_proto::LogLevel> {
    match token.to_ascii_uppercase().as_str() {
        "TRACE" => Some(agentenv_proto::LogLevel::Trace),
        "DEBUG" => Some(agentenv_proto::LogLevel::Debug),
        "INFO" => Some(agentenv_proto::LogLevel::Info),
        "WARN" | "WARNING" | "MED" | "HIGH" | "CRIT" | "CRITICAL" => {
            Some(agentenv_proto::LogLevel::Warn)
        }
        "ERROR" | "ERR" | "FATAL" => Some(agentenv_proto::LogLevel::Error),
        _ => None,
    }
}

fn looks_like_timestamp(token: &str) -> bool {
    token.contains('T') && token.contains(':')
}

fn log_line_has_denial_signal(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    upper.contains("DENIED") || upper.contains("BLOCKED") || upper.contains("ACTION=DENY")
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

fn status_label(status: Option<i32>) -> String {
    match status {
        Some(status) => format!("status {status}"),
        None => "unknown status".to_owned(),
    }
}

fn render_command_output(output: &CommandOutput) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_owned();
    }

    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_owned();
    }

    status_label(output.status)
}

fn extract_semver_token(text: &str) -> Option<Version> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+')))
        .filter_map(|token| {
            let token = token.trim_start_matches('v');
            if token.is_empty() {
                None
            } else {
                Version::parse(token).ok()
            }
        })
        .next()
}

pub fn classify_policy_update(
    current: &agentenv_proto::NetworkPolicy,
    next: &agentenv_proto::NetworkPolicy,
) -> Result<UpdateDisposition, PolicyError> {
    let mut locked_domains = Vec::new();
    if current.filesystem != next.filesystem {
        locked_domains.push("filesystem");
    }
    if current.process != next.process {
        locked_domains.push("process");
    }

    if locked_domains.is_empty() {
        Ok(UpdateDisposition::HotReload)
    } else {
        Err(PolicyError::RequiresRecreate {
            domains: locked_domains.join(", "),
        })
    }
}

pub fn translate_for_openshell(
    policy: &agentenv_proto::NetworkPolicy,
) -> Result<TranslatedPolicy, PolicyError> {
    translate_for_openshell_with_binaries(policy, resolve_default_open_shell_binary_paths()?)
}

pub fn translate_for_openshell_with_binaries<I, S>(
    policy: &agentenv_proto::NetworkPolicy,
    binaries: I,
) -> Result<TranslatedPolicy, PolicyError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    OpenShellTranslator::new(binaries).translate(policy)
}

fn resolve_default_open_shell_binary_paths() -> Result<Vec<String>, PolicyError> {
    let resolved: Vec<(&'static str, String)> = DEFAULT_OPEN_SHELL_AGENT_BINARIES
        .iter()
        .chain(DEFAULT_OPEN_SHELL_SUPPORT_BINARIES.iter())
        .copied()
        .filter_map(|binary| resolve_binary_on_path(binary).map(|path| (binary, path)))
        .collect();

    let binaries: Vec<String> = resolved.iter().map(|(_, path)| path.clone()).collect();
    let has_agent_binary = resolved
        .iter()
        .any(|(binary, _)| DEFAULT_OPEN_SHELL_AGENT_BINARIES.contains(binary));

    if !has_agent_binary {
        Err(PolicyError::TranslationUnsupported {
            translator: "openshell",
            message: format!(
                "could not resolve any default OpenShell agent binaries on PATH (looked for: {})",
                DEFAULT_OPEN_SHELL_AGENT_BINARIES.join(", ")
            ),
        })
    } else {
        Ok(binaries)
    }
}

fn resolve_binary_on_path(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for candidate in executable_candidates(&dir, binary) {
            if is_executable_candidate(&candidate) {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }

    None
}

#[cfg(not(windows))]
fn executable_candidates(dir: &Path, binary: &str) -> Vec<PathBuf> {
    vec![dir.join(binary)]
}

#[cfg(not(windows))]
fn is_executable_candidate(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    candidate
        .metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn executable_candidates(dir: &Path, binary: &str) -> Vec<PathBuf> {
    if Path::new(binary).extension().is_some() {
        return vec![dir.join(binary)];
    }

    let path_ext = std::env::var_os("PATHEXT")
        .unwrap_or_else(|| std::ffi::OsString::from(".COM;.EXE;.BAT;.CMD"));
    path_ext
        .to_string_lossy()
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| dir.join(format!("{binary}{ext}")))
        .collect()
}

#[cfg(windows)]
fn is_executable_candidate(candidate: &Path) -> bool {
    candidate.is_file()
}

#[cfg(test)]
mod driver_tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        ffi::OsString,
        io,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use agentenv_core::driver::SandboxDriver;
    use agentenv_proto::{
        Capabilities, CopyInParams, CopyOutParams, DestroyParams, DriverKind, ExecParams,
        InitializeParams, LogLevel, LogsParams, LogsStreamParams, PreflightParams, SandboxHandle,
        SandboxSpec, SandboxStatusParams, StopParams, SCHEMA_VERSION,
    };
    use semver::Version;
    use serde_json::{json, Value};

    use driver_conformance::assert_sandbox_driver_contract;

    use super::{
        command_request, command_request_with_env, extract_semver_token, CommandCall,
        CommandOutput, CommandRunner, CommandScript, CommandScriptResult, OpenShellDriver,
        RecordingCommandRunner,
    };

    #[derive(Debug, Default)]
    struct CapturingCommandRunner {
        calls: Mutex<Vec<CommandCall>>,
        spawn_calls: Mutex<Vec<CommandCall>>,
    }

    static PATH_LOCK: Mutex<()> = Mutex::new(());

    struct PathRestoreGuard {
        original: Option<OsString>,
    }

    impl Drop for PathRestoreGuard {
        fn drop(&mut self) {
            if let Some(original) = self.original.take() {
                std::env::set_var("PATH", original);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }

    struct FlexibleCommandExpectation {
        program: String,
        verify: Box<dyn Fn(&CommandCall) + Send + Sync>,
        result: CommandScriptResult,
    }

    struct FlexibleCommandRunner {
        expectations: Mutex<VecDeque<FlexibleCommandExpectation>>,
        calls: Mutex<Vec<CommandCall>>,
        spawn_calls: Mutex<Vec<CommandCall>>,
    }

    impl CapturingCommandRunner {
        fn calls(&self) -> Vec<CommandCall> {
            self.calls.lock().expect("calls mutex").clone()
        }
    }

    impl CommandRunner for CapturingCommandRunner {
        fn run(
            &self,
            program: &str,
            request: &super::CommandRequest,
        ) -> io::Result<super::CommandOutput> {
            self.calls.lock().expect("calls mutex").push(CommandCall {
                program: program.to_owned(),
                request: request.clone(),
            });

            Ok(super::CommandOutput {
                status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            })
        }

        fn spawn(&self, program: &str, request: &super::CommandRequest) -> io::Result<()> {
            self.spawn_calls
                .lock()
                .expect("spawn calls mutex")
                .push(CommandCall {
                    program: program.to_owned(),
                    request: request.clone(),
                });

            Ok(())
        }
    }

    impl FlexibleCommandRunner {
        fn new(expectations: Vec<FlexibleCommandExpectation>) -> Self {
            Self {
                expectations: Mutex::new(expectations.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
                spawn_calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<CommandCall> {
            self.calls.lock().expect("calls mutex").clone()
        }

        #[allow(dead_code)]
        fn spawn_calls(&self) -> Vec<CommandCall> {
            self.spawn_calls.lock().expect("spawn calls mutex").clone()
        }
    }

    impl FlexibleCommandExpectation {
        fn success(
            program: &str,
            verify: impl Fn(&CommandCall) + Send + Sync + 'static,
            stdout: &str,
            stderr: &str,
        ) -> Self {
            Self {
                program: program.to_owned(),
                verify: Box::new(verify),
                result: CommandScriptResult::Output(CommandOutput {
                    status: Some(0),
                    stdout: stdout.to_owned(),
                    stderr: stderr.to_owned(),
                }),
            }
        }

        fn output(
            program: &str,
            verify: impl Fn(&CommandCall) + Send + Sync + 'static,
            status: Option<i32>,
            stdout: &str,
            stderr: &str,
        ) -> Self {
            Self {
                program: program.to_owned(),
                verify: Box::new(verify),
                result: CommandScriptResult::Output(CommandOutput {
                    status,
                    stdout: stdout.to_owned(),
                    stderr: stderr.to_owned(),
                }),
            }
        }

        fn error(
            program: &str,
            verify: impl Fn(&CommandCall) + Send + Sync + 'static,
            kind: io::ErrorKind,
            message: &str,
        ) -> Self {
            Self {
                program: program.to_owned(),
                verify: Box::new(verify),
                result: CommandScriptResult::Error {
                    kind,
                    message: message.to_owned(),
                },
            }
        }
    }

    impl CommandRunner for FlexibleCommandRunner {
        fn run(
            &self,
            program: &str,
            request: &super::CommandRequest,
        ) -> io::Result<super::CommandOutput> {
            let call = CommandCall {
                program: program.to_owned(),
                request: request.clone(),
            };
            self.calls.lock().expect("calls mutex").push(call.clone());

            let expectation = self
                .expectations
                .lock()
                .expect("expectations mutex")
                .pop_front()
                .expect("unexpected command invocation");

            assert_eq!(expectation.program, program);
            (expectation.verify)(&call);

            match expectation.result {
                CommandScriptResult::Output(output) => Ok(output),
                CommandScriptResult::Error { kind, message } => Err(io::Error::new(kind, message)),
            }
        }

        fn spawn(&self, program: &str, request: &super::CommandRequest) -> io::Result<()> {
            let call = CommandCall {
                program: program.to_owned(),
                request: request.clone(),
            };
            self.spawn_calls
                .lock()
                .expect("spawn calls mutex")
                .push(call.clone());

            let expectation = self
                .expectations
                .lock()
                .expect("expectations mutex")
                .pop_front()
                .expect("unexpected command invocation");

            assert_eq!(expectation.program, program);
            (expectation.verify)(&call);

            match expectation.result {
                CommandScriptResult::Output(_) => Ok(()),
                CommandScriptResult::Error { kind, message } => Err(io::Error::new(kind, message)),
            }
        }
    }

    fn set_fake_openshell_path() -> (PathBuf, PathRestoreGuard) {
        use std::time::{SystemTime, UNIX_EPOCH};

        let tempdir = std::env::temp_dir().join(format!(
            "sandbox-openshell-lib-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&tempdir).expect("create tempdir");
        for binary in ["claude", "curl"] {
            write_fake_binary(&tempdir, binary, true);
        }

        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", &tempdir);

        (
            tempdir,
            PathRestoreGuard {
                original: original_path,
            },
        )
    }

    fn write_fake_binary(dir: &Path, binary: &str, executable: bool) {
        let path = binary_path(dir, binary);
        std::fs::write(&path, "").expect("create fake binary");

        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = if executable { 0o755 } else { 0o644 };
            let permissions = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(&path, permissions).expect("set fake binary permissions");
        }

        #[cfg(windows)]
        let _ = executable;
    }

    fn binary_path(dir: &Path, binary: &str) -> PathBuf {
        #[cfg(windows)]
        {
            dir.join(format!("{binary}.exe"))
        }

        #[cfg(not(windows))]
        {
            dir.join(binary)
        }
    }

    fn assert_args_prefix_suffix(args: &[String], prefix: &[&str], suffix: &[&str]) {
        let expected_prefix: Vec<String> = prefix.iter().map(|value| (*value).to_owned()).collect();
        let expected_suffix: Vec<String> = suffix.iter().map(|value| (*value).to_owned()).collect();

        assert!(
            args.starts_with(&expected_prefix),
            "args {:?} did not start with {:?}",
            args,
            expected_prefix
        );
        assert!(
            args.ends_with(&expected_suffix),
            "args {:?} did not end with {:?}",
            args,
            expected_suffix
        );
    }

    #[tokio::test]
    async fn openshell_driver_initializes_with_required_capabilities() {
        let mut driver = OpenShellDriver::default();

        let result = driver
            .initialize(InitializeParams {
                schema_version: SCHEMA_VERSION.to_owned(),
                core_version: "0.0.1-test".to_owned(),
                workdir: "/tmp/agentenv-test".to_owned(),
                log_level: LogLevel::Info,
            })
            .await
            .expect("initialize");

        assert_eq!(result.driver.name, "openshell");
        assert_eq!(result.driver.kind, DriverKind::Sandbox);
        assert_eq!(result.driver.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(result.driver.protocol_version, SCHEMA_VERSION);

        let Capabilities::Sandbox(capabilities) = result.capabilities else {
            panic!("openshell should report sandbox capabilities");
        };

        assert!(capabilities.supports_hot_reload_policy);
        assert!(capabilities.supports_filesystem_lockdown);
        assert!(capabilities.supports_syscall_filter);
        assert!(capabilities.supports_native_inference_routing);
        assert!(capabilities.supports_remote_host);
    }

    #[test]
    fn apply_policy_writes_temp_policy_runs_policy_set_and_removes_file() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (policy, tempdir, _path_guard) = {
            let registry = PresetRegistry::load_builtin().expect("load presets");
            let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
            let (tempdir, path_guard) = set_fake_openshell_path();
            (policy, tempdir, path_guard)
        };
        let capture = Arc::new(Mutex::new(None::<PathBuf>));
        let capture_for_check = capture.clone();
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "openshell",
                move |call| {
                    assert_args_prefix_suffix(
                        &call.request.args,
                        &["policy", "set", "devbox", "--policy"],
                        &["--wait"],
                    );
                    let policy_path = PathBuf::from(
                        call.request
                            .args
                            .get(4)
                            .expect("policy path should be present"),
                    );
                    *capture_for_check.lock().expect("capture mutex") = Some(policy_path);
                },
                "",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime
            .block_on(async {
                driver
                    .apply_policy(agentenv_proto::ApplyPolicyParams {
                        handle: "devbox".to_owned(),
                        policy,
                    })
                    .await
            })
            .expect("apply_policy");

        assert!(result.hot_reloaded);
        assert_eq!(runner.calls().len(), 1);
        let policy_path = capture
            .lock()
            .expect("capture mutex")
            .clone()
            .expect("policy path should be captured");
        assert!(!policy_path.exists(), "temp policy file should be removed");
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn apply_policy_rejects_locked_domain_change_before_running_command() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (policy, tempdir, _path_guard) = {
            let registry = PresetRegistry::load_builtin().expect("load presets");
            let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
            let (tempdir, path_guard) = set_fake_openshell_path();
            (policy, tempdir, path_guard)
        };
        let mut next = policy.clone();
        next.process.run_as_user = "agent".to_owned();
        let runner = Arc::new(RecordingCommandRunner::new(vec![]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());
        driver
            .current_policies
            .lock()
            .expect("policies mutex")
            .insert("devbox".to_owned(), policy);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = runtime
            .block_on(async {
                driver
                    .apply_policy(agentenv_proto::ApplyPolicyParams {
                        handle: "devbox".to_owned(),
                        policy: next,
                    })
                    .await
            })
            .expect_err("apply_policy should reject locked-domain changes");

        assert!(err.to_string().contains("process"));
        assert!(runner.calls().is_empty());
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn apply_policy_also_applies_inference_update() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (mut policy, tempdir, _path_guard) = {
            let registry = PresetRegistry::load_builtin().expect("load presets");
            let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
            let (tempdir, path_guard) = set_fake_openshell_path();
            (policy, tempdir, path_guard)
        };
        policy
            .inference
            .routes
            .push(agentenv_proto::InferenceRoute {
                matcher: "default".to_owned(),
                provider: "openai".to_owned(),
                model: "gpt-5".to_owned(),
                base_url: Some("https://api.openai.com/v1".to_owned()),
                timeout_seconds: Some(30),
            });

        let capture = Arc::new(Mutex::new(None::<PathBuf>));
        let capture_for_check = capture.clone();
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "openshell",
                move |call| {
                    assert_args_prefix_suffix(
                        &call.request.args,
                        &["policy", "set", "devbox", "--policy"],
                        &["--wait"],
                    );
                    let policy_path = PathBuf::from(
                        call.request
                            .args
                            .get(4)
                            .expect("policy path should be present"),
                    );
                    *capture_for_check.lock().expect("capture mutex") = Some(policy_path);
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                |call| {
                    assert_eq!(
                        call.request.args,
                        vec![
                            "inference".to_owned(),
                            "set".to_owned(),
                            "--provider".to_owned(),
                            "openai".to_owned(),
                            "--model".to_owned(),
                            "gpt-5".to_owned(),
                            "--timeout".to_owned(),
                            "30".to_owned(),
                        ]
                    );
                },
                "",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime
            .block_on(async {
                driver
                    .apply_policy(agentenv_proto::ApplyPolicyParams {
                        handle: "devbox".to_owned(),
                        policy,
                    })
                    .await
            })
            .expect("apply_policy");

        assert!(result.hot_reloaded);
        assert_eq!(runner.calls().len(), 2);
        assert!(!capture
            .lock()
            .expect("capture mutex")
            .as_ref()
            .expect("policy path")
            .exists());
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn create_applies_initial_policy_after_sandbox_create() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (policy, tempdir, _path_guard) = {
            let registry = PresetRegistry::load_builtin().expect("load presets");
            let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
            let (tempdir, path_guard) = set_fake_openshell_path();
            (policy, tempdir, path_guard)
        };
        let capture = Arc::new(Mutex::new(None::<PathBuf>));
        let capture_for_check = capture.clone();
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "openshell",
                |call| {
                    assert_eq!(
                        call.request,
                        command_request(&[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--keep",
                            "--no-auto-providers",
                            "--from",
                            "openclaw",
                        ])
                    );
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                move |call| {
                    assert_args_prefix_suffix(
                        &call.request.args,
                        &["policy", "set", "devbox", "--policy"],
                        &["--wait"],
                    );
                    let policy_path = PathBuf::from(
                        call.request
                            .args
                            .get(4)
                            .expect("policy path should be present"),
                    );
                    *capture_for_check.lock().expect("capture mutex") = Some(policy_path);
                },
                "",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: Some(policy.clone()),
                        metadata: BTreeMap::from([("name".to_owned(), json!("devbox"))]),
                    })
                    .await
            })
            .expect("create");

        assert_eq!(result.handle, "devbox");
        assert_eq!(runner.calls().len(), 2);
        let stored_policy = driver
            .current_policies
            .lock()
            .expect("policies mutex")
            .get("devbox")
            .cloned()
            .expect("policy should be stored");
        assert_eq!(stored_policy, policy);
        assert!(!capture
            .lock()
            .expect("capture mutex")
            .as_ref()
            .expect("policy path")
            .exists());
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn apply_policy_removes_temp_file_when_policy_set_fails() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (policy, tempdir, _path_guard) = {
            let registry = PresetRegistry::load_builtin().expect("load presets");
            let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
            let (tempdir, path_guard) = set_fake_openshell_path();
            (policy, tempdir, path_guard)
        };
        let capture = Arc::new(Mutex::new(None::<PathBuf>));
        let capture_for_check = capture.clone();
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::output(
                "openshell",
                move |call| {
                    assert_args_prefix_suffix(
                        &call.request.args,
                        &["policy", "set", "devbox", "--policy"],
                        &["--wait"],
                    );
                    let policy_path = PathBuf::from(
                        call.request
                            .args
                            .get(4)
                            .expect("policy path should be present"),
                    );
                    *capture_for_check.lock().expect("capture mutex") = Some(policy_path);
                },
                Some(1),
                "",
                "policy set failed",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = runtime
            .block_on(async {
                driver
                    .apply_policy(agentenv_proto::ApplyPolicyParams {
                        handle: "devbox".to_owned(),
                        policy,
                    })
                    .await
            })
            .expect_err("apply_policy should fail");

        match err {
            agentenv_core::driver::DriverError::CommandFailed { command, .. } => {
                assert!(command.contains("policy set"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
        assert_eq!(runner.calls().len(), 1);
        assert!(!capture
            .lock()
            .expect("capture mutex")
            .as_ref()
            .expect("policy path")
            .exists());
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn apply_policy_maps_policy_command_spawn_error_to_command_spawn() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (policy, tempdir, _path_guard) = {
            let registry = PresetRegistry::load_builtin().expect("load presets");
            let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");
            let (tempdir, path_guard) = set_fake_openshell_path();
            (policy, tempdir, path_guard)
        };
        let capture = Arc::new(Mutex::new(None::<PathBuf>));
        let capture_for_check = capture.clone();
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::error(
                "openshell",
                move |call| {
                    assert_args_prefix_suffix(
                        &call.request.args,
                        &["policy", "set", "devbox", "--policy"],
                        &["--wait"],
                    );
                    let policy_path = PathBuf::from(
                        call.request
                            .args
                            .get(4)
                            .expect("policy path should be present"),
                    );
                    *capture_for_check.lock().expect("capture mutex") = Some(policy_path);
                },
                io::ErrorKind::BrokenPipe,
                "spawn failed",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = runtime
            .block_on(async {
                driver
                    .apply_policy(agentenv_proto::ApplyPolicyParams {
                        handle: "devbox".to_owned(),
                        policy,
                    })
                    .await
            })
            .expect_err("apply_policy should fail");

        match err {
            agentenv_core::driver::DriverError::CommandSpawn { command, .. } => {
                assert!(command.contains("policy set"));
            }
            other => panic!("expected CommandSpawn, got {other:?}"),
        }
        assert_eq!(runner.calls().len(), 1);
        assert!(!capture
            .lock()
            .expect("capture mutex")
            .as_ref()
            .expect("policy path")
            .exists());
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[tokio::test]
    async fn preflight_passes_when_cli_version_and_gateway_are_valid() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::success("openshell", &["--version"], "openshell 0.0.31", ""),
            CommandScript::success("openshell", &["gateway", "status"], "", ""),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

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
                    program: "openshell".to_owned(),
                    request: command_request(&["--version"]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["gateway", "status"]),
                },
            ]
        );
    }

    #[tokio::test]
    async fn openshell_driver_satisfies_sandbox_conformance_contract() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::success("openshell", &["--version"], "openshell 0.0.31", ""),
            CommandScript::success("openshell", &["gateway", "status"], "", ""),
        ]));
        let mut driver = OpenShellDriver::with_command_runner(runner.clone());

        let init = driver
            .initialize(InitializeParams {
                schema_version: SCHEMA_VERSION.to_owned(),
                core_version: "0.0.1".to_owned(),
                workdir: "/tmp/agentenv".to_owned(),
                log_level: LogLevel::Info,
            })
            .await
            .unwrap();

        assert_eq!(init.driver.kind, DriverKind::Sandbox);
        let Capabilities::Sandbox(capabilities) = init.capabilities else {
            panic!("openshell should report sandbox capabilities");
        };
        assert!(capabilities.supports_hot_reload_policy);
        assert!(capabilities.supports_filesystem_lockdown);
        assert!(capabilities.supports_syscall_filter);
        assert!(capabilities.supports_native_inference_routing);
        assert!(capabilities.supports_remote_host);

        assert_sandbox_driver_contract(&mut driver).await.unwrap();

        assert_eq!(
            runner.calls(),
            vec![
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["--version"]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["gateway", "status"]),
                },
            ]
        );
    }

    #[tokio::test]
    async fn preflight_reports_missing_cli() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::failure(
            "openshell",
            &["--version"],
            io::ErrorKind::NotFound,
            "openshell was not found",
        )]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight");

        assert!(!result.ok);
        let issue = result
            .issues
            .iter()
            .find(|issue| issue.code == "openshell_missing")
            .expect("missing-cli issue");
        assert!(issue.message.contains("not found"));
        assert!(issue
            .remediation
            .as_deref()
            .expect("remediation")
            .contains("PATH"));
        assert_eq!(
            runner.calls(),
            vec![CommandCall {
                program: "openshell".to_owned(),
                request: command_request(&["--version"]),
            }]
        );
    }

    #[tokio::test]
    async fn preflight_rejects_old_cli_version() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "openshell",
            &["--version"],
            Some(0),
            "openshell v0.0.29 build 7",
            "",
        )]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight");

        assert!(!result.ok);
        let issue = result
            .issues
            .iter()
            .find(|issue| issue.code == "openshell_version_too_old")
            .expect("old-version issue");
        assert!(issue.message.contains("0.0.30"));
        assert_eq!(
            runner.calls(),
            vec![CommandCall {
                program: "openshell".to_owned(),
                request: command_request(&["--version"]),
            }]
        );
    }

    #[tokio::test]
    async fn preflight_reports_gateway_down() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::success("openshell", &["--version"], "openshell 0.0.31", ""),
            CommandScript::output(
                "openshell",
                &["gateway", "status"],
                Some(1),
                "",
                "gateway not running",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight");

        assert!(!result.ok);
        let issue = result
            .issues
            .iter()
            .find(|issue| issue.code == "openshell_gateway_down")
            .expect("gateway issue");
        assert!(issue.message.contains("gateway not running"));
        assert_eq!(
            runner.calls(),
            vec![
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["--version"]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["gateway", "status"]),
                },
            ]
        );
    }

    #[test]
    fn create_uses_explicit_name_image_remote_and_env_only_credentials() {
        let env = BTreeMap::from([("OPENAI_API_KEY".to_owned(), "secret".to_owned())]);
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript {
            program: "openshell".to_owned(),
            request: command_request_with_env(
                &[
                    "sandbox",
                    "create",
                    "--name",
                    "named-sandbox",
                    "--keep",
                    "--no-auto-providers",
                    "--from",
                    "custom-image",
                    "--remote",
                    "tcp://sandbox.example",
                ],
                env.clone(),
            ),
            result: CommandScriptResult::Output(CommandOutput {
                status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            }),
        }]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: Some("custom-image".to_owned()),
                        env: env.clone(),
                        policy: None,
                        metadata: BTreeMap::from([
                            ("name".to_owned(), json!("named-sandbox")),
                            ("remote".to_owned(), json!("tcp://sandbox.example")),
                        ]),
                    })
                    .await
            })
            .expect("create");

        assert_eq!(
            result,
            SandboxHandle {
                handle: "named-sandbox".to_owned()
            }
        );
        assert_eq!(
            runner.calls(),
            vec![CommandCall {
                program: "openshell".to_owned(),
                request: command_request_with_env(
                    &[
                        "sandbox",
                        "create",
                        "--name",
                        "named-sandbox",
                        "--keep",
                        "--no-auto-providers",
                        "--from",
                        "custom-image",
                        "--remote",
                        "tcp://sandbox.example",
                    ],
                    env
                ),
            }]
        );
    }

    #[test]
    fn create_uses_openclaw_default_image_and_generated_name() {
        let runner = Arc::new(CapturingCommandRunner::default());
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: None,
                        metadata: BTreeMap::new(),
                    })
                    .await
            })
            .expect("create");

        assert!(result.handle.starts_with("agentenv-"));
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "openshell");
        assert_eq!(
            calls[0].request,
            command_request(&[
                "sandbox",
                "create",
                "--name",
                &result.handle,
                "--keep",
                "--no-auto-providers",
                "--from",
                "openclaw",
            ])
        );
    }

    #[test]
    fn create_rejects_non_string_metadata_name() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![]));
        let driver = OpenShellDriver::with_command_runner(runner);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: None,
                        metadata: BTreeMap::from([("name".to_owned(), Value::from(1))]),
                    })
                    .await
            })
            .expect_err("create should reject non-string metadata.name");

        assert!(err.to_string().contains("metadata.name"));
    }

    #[test]
    fn exec_returns_status_stdout_and_stderr() {
        let env = BTreeMap::from([("TOKEN".to_owned(), "secret".to_owned())]);
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript {
            program: "openshell".to_owned(),
            request: command_request_with_env(
                &["sandbox", "connect", "sb-1", "--", "echo hi"],
                env.clone(),
            ),
            result: CommandScriptResult::Output(CommandOutput {
                status: Some(7),
                stdout: "stdout payload".to_owned(),
                stderr: "stderr payload".to_owned(),
            }),
        }]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime
            .block_on(async {
                driver
                    .exec(ExecParams {
                        handle: "sb-1".to_owned(),
                        cmd: "echo hi".to_owned(),
                        tty: false,
                        env: env.clone(),
                    })
                    .await
            })
            .expect("exec");

        assert_eq!(result.status, 7);
        assert_eq!(result.stdout, "stdout payload");
        assert_eq!(result.stderr, "stderr payload");
        assert_eq!(
            runner.calls(),
            vec![CommandCall {
                program: "openshell".to_owned(),
                request: command_request_with_env(
                    &["sandbox", "connect", "sb-1", "--", "echo hi"],
                    env,
                ),
            }]
        );
    }

    #[test]
    fn copy_status_logs_stream_stop_and_destroy_use_expected_commands() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::success(
                "openshell",
                &["sandbox", "upload", "sb-1", "/host/in.txt", "/sandbox/in.txt"],
                "",
                "",
            ),
            CommandScript::success(
                "openshell",
                &["sandbox", "download", "sb-1", "/sandbox/out.txt", "/host/out.txt"],
                "",
                "",
            ),
            CommandScript::output("openshell", &["sandbox", "get", "sb-1"], Some(0), "deleted", ""),
            CommandScript::output(
                "openshell",
                &["logs", "sb-1", "--since", "2026-04-19T00:00:00Z"],
                Some(0),
                "2026-04-19T00:00:00Z WARN action=deny DENIED outbound to api.example.com\nplain info line",
                "",
            ),
            CommandScript::success(
                "openshell",
                &["logs", "sb-1", "--tail", "--since", "2026-04-19T00:00:00Z"],
                "",
                "",
            ),
            CommandScript::success("openshell", &["sandbox", "stop", "sb-1"], "", ""),
            CommandScript::success("openshell", &["sandbox", "delete", "sb-1"], "", ""),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            driver
                .copy_in(CopyInParams {
                    handle: "sb-1".to_owned(),
                    src_host_path: "/host/in.txt".to_owned(),
                    dst_sandbox_path: "/sandbox/in.txt".to_owned(),
                })
                .await
                .expect("copy_in");
            driver
                .copy_out(CopyOutParams {
                    handle: "sb-1".to_owned(),
                    src_sandbox_path: "/sandbox/out.txt".to_owned(),
                    dst_host_path: "/host/out.txt".to_owned(),
                })
                .await
                .expect("copy_out");
            let status = driver
                .status(SandboxStatusParams {
                    handle: "sb-1".to_owned(),
                })
                .await
                .expect("status");
            assert_eq!(status.phase, agentenv_proto::SandboxPhase::Destroyed);
            assert!(!status.healthy);

            let logs = driver
                .logs(LogsParams {
                    handle: "sb-1".to_owned(),
                    since: Some("2026-04-19T00:00:00Z".to_owned()),
                    follow: false,
                })
                .await
                .expect("logs");
            assert_eq!(logs.entries.len(), 2);
            assert_eq!(logs.entries[0].level, LogLevel::Warn);
            assert_eq!(
                logs.entries[0].kv.get("egress_denied"),
                Some(&Value::Bool(true))
            );

            driver
                .logs_stream(LogsStreamParams {
                    handle: "sb-1".to_owned(),
                    since: Some("2026-04-19T00:00:00Z".to_owned()),
                })
                .await
                .expect("logs_stream");
            driver
                .stop(StopParams {
                    handle: "sb-1".to_owned(),
                })
                .await
                .expect("stop");
            driver
                .destroy(DestroyParams {
                    handle: "sb-1".to_owned(),
                })
                .await
                .expect("destroy");
        });

        assert_eq!(
            runner.calls(),
            vec![
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&[
                        "sandbox",
                        "upload",
                        "sb-1",
                        "/host/in.txt",
                        "/sandbox/in.txt",
                    ]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&[
                        "sandbox",
                        "download",
                        "sb-1",
                        "/sandbox/out.txt",
                        "/host/out.txt",
                    ]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["sandbox", "get", "sb-1"]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["logs", "sb-1", "--since", "2026-04-19T00:00:00Z"]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["sandbox", "stop", "sb-1"]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["sandbox", "delete", "sb-1"]),
                },
            ]
        );
        assert_eq!(
            runner.spawn_calls(),
            vec![CommandCall {
                program: "openshell".to_owned(),
                request: command_request(&[
                    "logs",
                    "sb-1",
                    "--tail",
                    "--since",
                    "2026-04-19T00:00:00Z"
                ]),
            }]
        );
    }

    #[test]
    fn logs_denied_lines_set_egress_denied_kv() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "openshell",
            &["logs", "sb-2"],
            Some(0),
            "2026-04-19T00:00:00Z INFO action=deny BLOCKED outbound",
            "",
        )]));
        let driver = OpenShellDriver::with_command_runner(runner);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let logs = runtime
            .block_on(async {
                driver
                    .logs(LogsParams {
                        handle: "sb-2".to_owned(),
                        since: None,
                        follow: false,
                    })
                    .await
            })
            .expect("logs");

        assert_eq!(logs.entries.len(), 1);
        assert_eq!(logs.entries[0].level, LogLevel::Info);
        assert_eq!(
            logs.entries[0].kv.get("egress_denied"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn semver_can_be_parsed_from_noisy_output() {
        let parsed = extract_semver_token("stderr: openshell build output v0.0.31+build.7 done")
            .expect("semver token");

        assert_eq!(parsed, Version::parse("0.0.31+build.7").expect("version"));
    }
}
