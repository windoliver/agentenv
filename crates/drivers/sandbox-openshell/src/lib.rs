#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io,
    io::Write,
    path::Component,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

#[cfg(test)]
use std::collections::VecDeque;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use agentenv_core::{
    digest::parse_sha256_digest,
    driver::{DriverError, DriverResult, SandboxDriver},
};
use agentenv_events::{
    ActivityEvent, ActivityKind, ActivityResult, EventEmitter, NoopEventEmitter,
};
use agentenv_policy::{
    InferenceUpdate, OpenShellTranslator, PolicyError, PolicyTranslator, TranslatedPolicy,
};
use agentenv_proto::{
    assert_compatible_schema_version, ApplyPolicyParams, ApplyPolicyResult, AttachSessionParams,
    Capabilities, ConnectParams, CopyInParams, CopyOutParams, CreateSessionParams, DestroyParams,
    DriverInfo, DriverKind, EmptyResult, ExecParams, ExecResult, InitializeParams,
    InitializeResult, IssueSeverity, KillSessionParams, ListSessionsParams, ListSessionsResult,
    LogsParams, LogsResult, LogsStreamParams, NetworkPolicy, PreflightIssue, PreflightParams,
    PreflightResult, SandboxCapabilities, SandboxHandle, SandboxSpec, SandboxStatus,
    SandboxStatusParams, SessionHandle, SessionStatus, ShellHandle, ShutdownParams, StopParams,
    SCHEMA_VERSION,
};
use semver::Version;
use uuid::Uuid;

mod build_cache;

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "sandbox-openshell";

const DEFAULT_OPEN_SHELL_AGENT_BINARIES: [&str; 3] = ["claude", "codex", "openclaw"];
const DEFAULT_OPEN_SHELL_SUPPORT_BINARIES: [&str; 1] = ["curl"];
const DEFAULT_OPEN_SHELL_NPM_INSTALL_BINARIES: [&str; 4] = [
    "/usr/local/bin/npm",
    "/usr/local/bin/node",
    "/usr/bin/npm",
    "/usr/bin/node",
];
const OPEN_SHELL_BINARY: &str = "openshell";
const OPEN_SHELL_INSTALL_URL: &str =
    "https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh";
const MINIMUM_SUPPORTED_OPEN_SHELL_VERSION: Version = Version::new(0, 0, 30);
const CONTAINER_RUNTIME_WAIT_ATTEMPTS: usize = 30;
const SANDBOX_WORKING_DIR: &str = "/sandbox";
const UNKNOWN_SESSION_COMMAND: &str = "agentenv-agent";
const TMUX_AGENTENV_HANDLE_OPTION: &str = "@agentenv_handle";
const TMUX_AGENTENV_COMMAND_OPTION: &str = "@agentenv_command";
const TMUX_AGENTENV_SESSION_NAME_OPTION: &str = "@agentenv_session_name";
const TMUX_SESSION_FORMAT: &str =
    "#{session_name}\t#{session_attached}\t#{session_created}\t#{@agentenv_handle}\t#{@agentenv_session_name}\t#{@agentenv_command}";

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

    fn uses_host_environment(&self) -> bool {
        false
    }

    fn status(&self, program: &str, request: &CommandRequest) -> io::Result<Option<i32>> {
        self.run(program, request).map(|output| output.status)
    }

    #[allow(dead_code)]
    fn spawn(&self, program: &str, request: &CommandRequest)
        -> io::Result<Box<dyn SpawnedCommand>>;
}

trait SpawnedCommand: Send {
    fn terminate(&mut self) -> io::Result<()>;
}

#[derive(Debug, Default)]
struct ProcessCommandRunner;

struct ProcessSpawnedCommand {
    child: Child,
}

impl CommandRunner for ProcessCommandRunner {
    fn uses_host_environment(&self) -> bool {
        true
    }

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

    fn spawn(
        &self,
        program: &str,
        request: &CommandRequest,
    ) -> io::Result<Box<dyn SpawnedCommand>> {
        let child = Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .spawn()?;

        Ok(Box::new(ProcessSpawnedCommand { child }))
    }
}

impl SpawnedCommand for ProcessSpawnedCommand {
    fn terminate(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }

        match self.child.kill() {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::InvalidInput => {}
            Err(err) => return Err(err),
        }
        let _ = self.child.wait();
        Ok(())
    }
}

#[cfg(test)]
struct NoopSpawnedCommand;

#[cfg(test)]
impl SpawnedCommand for NoopSpawnedCommand {
    fn terminate(&mut self) -> io::Result<()> {
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
    status_calls: Mutex<Vec<CommandCall>>,
}

#[cfg(test)]
impl RecordingCommandRunner {
    fn new(scripts: Vec<CommandScript>) -> Self {
        Self {
            scripts: Mutex::new(scripts.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
            spawn_calls: Mutex::new(Vec::new()),
            status_calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<CommandCall> {
        self.calls.lock().expect("calls mutex").clone()
    }

    fn spawn_calls(&self) -> Vec<CommandCall> {
        self.spawn_calls.lock().expect("spawn calls mutex").clone()
    }

    fn status_calls(&self) -> Vec<CommandCall> {
        self.status_calls
            .lock()
            .expect("status calls mutex")
            .clone()
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

    fn spawn(
        &self,
        program: &str,
        request: &CommandRequest,
    ) -> io::Result<Box<dyn SpawnedCommand>> {
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
            CommandScriptResult::Output(_) => Ok(Box::new(NoopSpawnedCommand)),
            CommandScriptResult::Error { kind, message } => Err(io::Error::new(kind, message)),
        }
    }

    fn status(&self, program: &str, request: &CommandRequest) -> io::Result<Option<i32>> {
        self.status_calls
            .lock()
            .expect("status calls mutex")
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
            CommandScriptResult::Output(output) => Ok(output.status),
            CommandScriptResult::Error { kind, message } => Err(io::Error::new(kind, message)),
        }
    }
}

pub struct OpenShellDriver {
    binary: String,
    runner: Arc<dyn CommandRunner>,
    host_bootstrap: bool,
    runtime_app_override: Option<String>,
    workdir: Mutex<PathBuf>,
    current_policies: Mutex<BTreeMap<String, NetworkPolicy>>,
    log_streams: Mutex<Vec<LogStream>>,
    events: Arc<dyn EventEmitter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ByoDockerfileConfig {
    dockerfile: PathBuf,
    expected_digest: Option<String>,
    agentenv_version: String,
    agent: String,
    mcp_port: String,
    workspace_mount: String,
    build_seed: Option<String>,
}

struct LogStream {
    handle: String,
    command: Box<dyn SpawnedCommand>,
}

impl Default for OpenShellDriver {
    fn default() -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner: Arc::new(ProcessCommandRunner),
            host_bootstrap: true,
            runtime_app_override: None,
            workdir: Mutex::new(default_agentenv_workdir()),
            current_policies: Mutex::new(BTreeMap::new()),
            log_streams: Mutex::new(Vec::new()),
            events: Arc::new(NoopEventEmitter),
        }
    }
}

impl OpenShellDriver {
    pub fn with_event_emitter(mut self, events: Arc<dyn EventEmitter>) -> Self {
        self.events = events;
        self
    }
}

#[cfg(test)]
impl OpenShellDriver {
    fn with_command_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner,
            host_bootstrap: false,
            runtime_app_override: None,
            workdir: Mutex::new(default_agentenv_workdir()),
            current_policies: Mutex::new(BTreeMap::new()),
            log_streams: Mutex::new(Vec::new()),
            events: Arc::new(NoopEventEmitter),
        }
    }

    fn with_command_runner_and_workdir(runner: Arc<dyn CommandRunner>, workdir: &Path) -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner,
            host_bootstrap: false,
            runtime_app_override: None,
            workdir: Mutex::new(workdir.to_path_buf()),
            current_policies: Mutex::new(BTreeMap::new()),
            log_streams: Mutex::new(Vec::new()),
            events: Arc::new(NoopEventEmitter),
        }
    }

    #[cfg(test)]
    fn with_host_command_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner,
            host_bootstrap: true,
            runtime_app_override: None,
            workdir: Mutex::new(default_agentenv_workdir()),
            current_policies: Mutex::new(BTreeMap::new()),
            log_streams: Mutex::new(Vec::new()),
            events: Arc::new(NoopEventEmitter),
        }
    }

    #[cfg(test)]
    fn with_host_command_runner_and_runtime_app(
        runner: Arc<dyn CommandRunner>,
        runtime_app: impl Into<String>,
    ) -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner,
            host_bootstrap: true,
            runtime_app_override: Some(runtime_app.into()),
            workdir: Mutex::new(default_agentenv_workdir()),
            current_policies: Mutex::new(BTreeMap::new()),
            log_streams: Mutex::new(Vec::new()),
            events: Arc::new(NoopEventEmitter),
        }
    }
}

impl Drop for OpenShellDriver {
    fn drop(&mut self) {
        let _ = self.terminate_all_log_streams();
    }
}

#[async_trait::async_trait]
impl SandboxDriver for OpenShellDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        assert_compatible_schema_version(&params.schema_version)?;
        self.set_workdir(PathBuf::from(params.workdir));

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
                supports_persistent_sessions: true,
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        let version_output = match self.run_command_request(command_request(&["--version"])) {
            Ok(output) => output,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if self.host_bootstrap {
                    if let Err(install_error) = self.install_openshell_cli() {
                        return Ok(preflight_failure(
                            "openshell_bootstrap_failed",
                            format!(
                                "OpenShell CLI binary `{}` was not found and automatic install failed: {install_error}",
                                self.binary
                            ),
                            Some(
                                "Check that `curl`, `sh`, and network access to github.com are available, then retry `agentenv create`"
                                    .to_owned(),
                            ),
                        ));
                    }
                    match self.run_command_request(command_request(&["--version"])) {
                        Ok(output) => output,
                        Err(retry_err) => {
                            return Ok(preflight_failure(
                                "openshell_bootstrap_failed",
                                format!(
                                    "OpenShell was installed but `{}` --version still failed: {retry_err}",
                                    self.binary
                                ),
                                Some("Ensure `~/.local/bin/openshell` is executable, then retry `agentenv create`".to_owned()),
                            ));
                        }
                    }
                } else {
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

        let gateway_output = match self.run_command_request(command_request(&["status"])) {
            Ok(output) => output,
            Err(err) => {
                return Ok(preflight_failure(
                    "openshell_gateway_down",
                    format!("failed to run `{} status`: {err}", self.binary),
                    None,
                ));
            }
        };

        if gateway_output.status.is_none_or(|status| status != 0) {
            return Ok(preflight_failure(
                "openshell_gateway_down",
                format!(
                    "`{} status` failed with {}: {}",
                    self.binary,
                    status_label(gateway_output.status),
                    render_command_output(&gateway_output)
                ),
                None,
            ));
        }

        if self.host_bootstrap {
            if let Err(issue) = self.ensure_container_runtime_ready() {
                return Ok(issue);
            }
        }

        Ok(PreflightResult {
            ok: true,
            issues: Vec::new(),
        })
    }

    async fn create(&self, _spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        let spec = _spec;
        let name = match spec.metadata.get("name") {
            Some(Value::String(value)) if !value.is_empty() => value.clone(),
            Some(Value::String(_)) | None => format!("agentenv-{}", Uuid::new_v4()),
            Some(_) => {
                return Err(DriverError::InvalidInput {
                    message: "metadata.name must be a string when set".to_owned(),
                });
            }
        };
        let image = match byo_dockerfile_config(&spec.metadata)? {
            Some(config) => self.prepare_byo_dockerfile_context(&name, &config)?,
            None => spec.image.unwrap_or_else(|| "openclaw".to_owned()),
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

        let initial_policy = spec
            .policy
            .map(|policy| {
                self.write_policy_temp_file(&policy)
                    .map(|(temp_policy_file, inference_update)| {
                        (policy, temp_policy_file, inference_update)
                    })
            })
            .transpose()?;

        let mut args = vec![
            "sandbox".to_owned(),
            "create".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--no-auto-providers".to_owned(),
            "--from".to_owned(),
            image,
        ];
        if let Some(remote) = remote {
            args.push("--remote".to_owned());
            args.push(remote);
        }
        if let Some((_, temp_policy_file, _)) = &initial_policy {
            args.push("--policy".to_owned());
            args.push(temp_policy_file.path().to_string_lossy().into_owned());
        }
        args.push("--".to_owned());
        args.push("true".to_owned());

        let request = CommandRequest {
            args,
            env: spec.env,
        };
        let _output = self.run_checked_command(request)?;

        if let Some((policy, _temp_policy_file, inference_update)) = initial_policy {
            if let Some(inference_update) = inference_update {
                if let Err(err) = self.run_inference_update(inference_update) {
                    return Err(self.rollback_created_sandbox(&name, err));
                }
            }
            self.store_current_policy(name.clone(), policy);
        }

        Ok(SandboxHandle { handle: name })
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        let request = command_request(&["sandbox", "exec", "--name", &params.handle, "--", "true"]);
        let _output = self.run_checked_command(request)?;

        Ok(ShellHandle {
            session_id: params.handle,
            tty: true,
            working_dir: Some("/sandbox".to_owned()),
        })
    }

    async fn create_session(&self, params: CreateSessionParams) -> DriverResult<SessionHandle> {
        let CreateSessionParams {
            handle,
            name,
            command,
            detached: _,
            metadata: _,
        } = params;
        validate_session_display_name(&name)?;
        let session_id = generate_tmux_session_id(&handle);

        self.ensure_host_tmux_available()?;

        let tmux_command = self.openshell_session_command(&handle, &command);
        let new_session = command_request(&["new-session", "-d", "-s", &session_id, &tmux_command]);
        self.run_checked_host_command("tmux", new_session)?;
        self.set_tmux_session_option(&session_id, TMUX_AGENTENV_HANDLE_OPTION, &handle)?;
        self.set_tmux_session_option(&session_id, TMUX_AGENTENV_SESSION_NAME_OPTION, &name)?;
        self.set_tmux_session_option(&session_id, TMUX_AGENTENV_COMMAND_OPTION, &command)?;
        let now = now_timestamp_string();

        Ok(SessionHandle {
            session_id,
            name,
            status: SessionStatus::Detached,
            created_at: now.clone(),
            updated_at: now,
            command,
            working_dir: Some(SANDBOX_WORKING_DIR.to_owned()),
        })
    }

    async fn attach_session(&self, params: AttachSessionParams) -> DriverResult<ExecResult> {
        let session_id = validate_tmux_session_id(&params.session_id)?;
        self.ensure_host_tmux_available()?;
        self.ensure_tmux_session_owned_by_handle(&params.handle, &session_id)?;
        let target = tmux_exact_target(&session_id);
        let request = command_request(&["attach-session", "-t", &target]);
        let command = command_string("tmux", &request.args);
        let status = self
            .run_interactive_host_request("tmux", request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command.clone(),
                source,
            })?;

        Ok(ExecResult {
            status: status.unwrap_or(1),
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    async fn list_sessions(&self, params: ListSessionsParams) -> DriverResult<ListSessionsResult> {
        self.ensure_host_tmux_available()?;
        let request = command_request(&["list-sessions", "-F", TMUX_SESSION_FORMAT]);
        let command = command_string("tmux", &request.args);
        let output =
            self.run_host_command("tmux", request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                })?;
        if output.status.is_none_or(|status| status != 0) {
            if tmux_list_sessions_is_empty(&output) {
                return Ok(ListSessionsResult {
                    sessions: Vec::new(),
                });
            }

            return Err(DriverError::CommandFailed {
                command,
                status: output.status,
                stdout: output.stdout,
                stderr: output.stderr,
            });
        }

        Ok(ListSessionsResult {
            sessions: parse_tmux_sessions(&params.handle, &output.stdout),
        })
    }

    async fn kill_session(&self, params: KillSessionParams) -> DriverResult<EmptyResult> {
        let session_id = validate_tmux_session_id(&params.session_id)?;
        self.ensure_host_tmux_available()?;
        self.ensure_tmux_session_owned_by_handle(&params.handle, &session_id)?;
        let target = tmux_exact_target(&session_id);
        self.run_checked_host_command("tmux", command_request(&["kill-session", "-t", &target]))?;

        Ok(EmptyResult::default())
    }

    async fn exec(&self, params: ExecParams) -> DriverResult<ExecResult> {
        let request = CommandRequest {
            args: vec![
                "sandbox".to_owned(),
                "exec".to_owned(),
                "--name".to_owned(),
                params.handle,
                "--".to_owned(),
                "sh".to_owned(),
                "-lc".to_owned(),
                params.cmd,
            ],
            env: params.env,
        };
        let command = command_string(&self.binary, &request.args);
        if params.tty {
            let status = self.run_interactive_request(request).map_err(|source| {
                DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                }
            })?;
            return Ok(ExecResult {
                status: status.unwrap_or(1),
                stdout: String::new(),
                stderr: String::new(),
            });
        }
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
        if params.follow {
            return Err(DriverError::InvalidInput {
                message:
                    "logs.follow is not supported by logs(); use logs_stream for streaming logs"
                        .to_owned(),
            });
        }

        let mut args = vec!["logs".to_owned(), params.handle];
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
        let handle = params.handle;
        let mut args = vec!["logs".to_owned(), handle.clone(), "--tail".to_owned()];
        if let Some(since) = params.since {
            args.push("--since".to_owned());
            args.push(since);
        }
        let command = self.spawn_checked_command(CommandRequest {
            args,
            env: BTreeMap::new(),
        })?;
        self.store_log_stream(handle, command);

        Ok(EmptyResult::default())
    }

    async fn stop(&self, params: StopParams) -> DriverResult<EmptyResult> {
        let request = command_request(&["sandbox", "stop", &params.handle]);
        let _output = self.run_checked_command(request)?;
        self.terminate_log_streams_for_handle(&params.handle)?;

        Ok(EmptyResult::default())
    }

    async fn destroy(&self, params: DestroyParams) -> DriverResult<EmptyResult> {
        let _output = self.delete_sandbox(&params.handle)?;
        self.remove_current_policy(&params.handle);
        self.terminate_log_streams_for_handle(&params.handle)?;

        Ok(EmptyResult::default())
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        let stream_cleanup = self.terminate_all_log_streams();
        self.clear_current_policies();
        match stream_cleanup {
            Ok(()) => {
                self.emit_shutdown_event(ActivityResult::Ok, "openshell_shutdown", None);
                Ok(EmptyResult::default())
            }
            Err(err) => {
                let message = err.to_string();
                self.emit_shutdown_event(
                    ActivityResult::Error,
                    "openshell_shutdown_cleanup_failed",
                    Some(message),
                );
                Err(err)
            }
        }
    }
}

impl OpenShellDriver {
    fn emit_shutdown_event(
        &self,
        result: ActivityResult,
        reason_code: &'static str,
        error: Option<String>,
    ) {
        let mut event = ActivityEvent::new(
            now_timestamp_string(),
            ActivityKind::Log,
            result,
            format!("openshell-shutdown-{}", Uuid::new_v4()),
        )
        .with_actor_value("driver", serde_json::json!("openshell"))
        .with_subject_value("operation", serde_json::json!("shutdown"))
        .with_extra("cleanup", serde_json::json!("log_streams"))
        .with_reason_code(reason_code);

        if let Some(error) = error {
            event = event.with_extra("error", serde_json::json!(error));
        }

        self.events.emit(event);
    }

    fn set_workdir(&self, workdir: PathBuf) {
        match self.workdir.lock() {
            Ok(mut current) => *current = workdir,
            Err(poisoned) => *poisoned.into_inner() = workdir,
        }
    }

    fn workdir(&self) -> PathBuf {
        match self.workdir.lock() {
            Ok(current) => current.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn prepare_byo_dockerfile_context(
        &self,
        name: &str,
        config: &ByoDockerfileConfig,
    ) -> DriverResult<String> {
        let dockerfile =
            fs::canonicalize(&config.dockerfile).map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to resolve BYO Dockerfile `{}`: {source}",
                    config.dockerfile.display()
                ),
            })?;
        if !dockerfile.is_file() {
            return Err(DriverError::InvalidInput {
                message: format!("BYO Dockerfile `{}` is not a file", dockerfile.display()),
            });
        }
        let context_dir = dockerfile
            .parent()
            .ok_or_else(|| DriverError::InvalidInput {
                message: format!(
                    "BYO Dockerfile `{}` has no parent directory",
                    dockerfile.display()
                ),
            })?;
        let build_name = sanitize_build_name(name);
        let cache = build_cache::BuildCache::new(self.workdir(), self.events.as_ref());
        let key_stage_dir = self
            .workdir()
            .join("build")
            .join(format!("{build_name}-key"));
        stage_build_context(context_dir, &dockerfile, &key_stage_dir)?;
        let key_stage_guard = TempBuildStage::new(key_stage_dir.clone());
        let context_digest = build_cache::BuildCache::digest_staged_context(&key_stage_dir)?;
        let input = build_cache::BuildInput {
            env_name: name.to_owned(),
            dockerfile: config.dockerfile.clone(),
            staged_context: key_stage_dir.clone(),
            context_digest,
            expected_digest: config.expected_digest.clone(),
            agentenv_version: config.agentenv_version.clone(),
            agent: config.agent.clone(),
            mcp_port: config.mcp_port.clone(),
            workspace_mount: config.workspace_mount.clone(),
            seed: config.build_seed.clone(),
        };
        if let Some(materialized) = cache.materialize_cached(&input, self.runner.as_ref())? {
            let _ = (&materialized.image_digest, &materialized.tag);
            return Ok(materialized.image_ref);
        }
        key_stage_guard.cleanup();

        let stage_dir = self.workdir().join("build").join(&build_name);
        stage_build_context(context_dir, &dockerfile, &stage_dir)?;

        let tag = format!("agentenv-byo-{build_name}:latest");
        let dockerfile_arg = stage_dir.join("Dockerfile").display().to_string();
        let stage_arg = stage_dir.display().to_string();
        let build_args = vec![
            "build".to_owned(),
            "--file".to_owned(),
            dockerfile_arg,
            "--tag".to_owned(),
            tag.clone(),
            "--build-arg".to_owned(),
            format!("AGENTENV_VERSION={}", config.agentenv_version),
            "--build-arg".to_owned(),
            format!("AGENTENV_AGENT={}", config.agent),
            "--build-arg".to_owned(),
            format!("AGENTENV_MCP_PORT={}", config.mcp_port),
            "--build-arg".to_owned(),
            format!("AGENTENV_WORKSPACE_MOUNT={}", config.workspace_mount),
            stage_arg.clone(),
        ];
        self.run_checked_host_command(
            "docker",
            CommandRequest {
                args: build_args,
                env: BTreeMap::new(),
            },
        )?;

        let output = self.run_checked_host_command(
            "docker",
            command_request(&["image", "inspect", "--format", "{{.Id}}", &tag]),
        )?;
        let digest = output.stdout.trim();
        parse_sha256_digest(digest).map_err(|source| DriverError::InvalidInput {
            message: format!("Docker image `{tag}` returned invalid digest `{digest}`: {source}"),
        })?;
        if let Some(expected) = config.expected_digest.as_deref() {
            parse_sha256_digest(expected).map_err(|source| DriverError::InvalidInput {
                message: format!("expected BYO image digest `{expected}` is invalid: {source}"),
            })?;
            if expected != digest {
                return Err(DriverError::InvalidInput {
                    message: format!(
                        "BYO image digest mismatch for `{}`: expected `{expected}`, got `{digest}`",
                        config.dockerfile.display()
                    ),
                });
            }
        }
        fs::write(stage_dir.join("image-digest"), format!("{digest}\n")).map_err(|source| {
            DriverError::InvalidInput {
                message: format!(
                    "failed to record BYO image digest under `{}`: {source}",
                    stage_dir.display()
                ),
            }
        })?;

        Ok(stage_arg)
    }

    fn run_command_request(&self, request: CommandRequest) -> io::Result<CommandOutput> {
        self.run_host_command(&self.binary, request)
    }

    fn ensure_host_tmux_available(&self) -> DriverResult<()> {
        let request = command_request(&["-V"]);
        let command = command_string("tmux", &request.args);
        let output =
            self.run_host_command("tmux", request)
                .map_err(|source| match source.kind() {
                    io::ErrorKind::NotFound => agentenv_core::driver::persistent_sessions_missing(),
                    _ => DriverError::CommandSpawn { command, source },
                })?;
        if output.status.is_some_and(|status| status == 0) {
            return Ok(());
        }

        Err(agentenv_core::driver::persistent_sessions_missing())
    }

    fn openshell_session_command(&self, handle: &str, command: &str) -> String {
        let openshell = self.effective_program(&self.binary);
        format!(
            "{} sandbox exec --name {} --workdir {} --tty -- sh -lc {}",
            shell_quote(&openshell),
            shell_quote(handle),
            shell_quote(SANDBOX_WORKING_DIR),
            shell_quote(command)
        )
    }

    fn set_tmux_session_option(
        &self,
        session_id: &str,
        option: &str,
        value: &str,
    ) -> DriverResult<()> {
        let target = tmux_exact_target(session_id);
        self.run_checked_host_command(
            "tmux",
            command_request(&["set-option", "-t", &target, option, value]),
        )?;
        Ok(())
    }

    fn ensure_tmux_session_owned_by_handle(
        &self,
        handle: &str,
        session_id: &str,
    ) -> DriverResult<()> {
        let target = tmux_exact_target(session_id);
        let request = command_request(&[
            "display-message",
            "-p",
            "-t",
            &target,
            "#{@agentenv_handle}",
        ]);
        let command = command_string("tmux", &request.args);
        let output =
            self.run_host_command("tmux", request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                })?;
        if output.status.is_none_or(|status| status != 0) {
            return Err(DriverError::InvalidHandle {
                handle: session_id.to_owned(),
                message: "session not found".to_owned(),
            });
        }
        if output.stdout.trim() != handle {
            return Err(DriverError::InvalidHandle {
                handle: session_id.to_owned(),
                message: "session is not owned by this sandbox".to_owned(),
            });
        }
        Ok(())
    }

    fn run_interactive_request(&self, request: CommandRequest) -> io::Result<Option<i32>> {
        let program = self.effective_program(&self.binary);
        let request = self.prepare_host_request(request);
        self.runner.status(&program, &request)
    }

    fn run_interactive_host_request(
        &self,
        program: &str,
        request: CommandRequest,
    ) -> io::Result<Option<i32>> {
        let program = self.effective_program(program);
        let request = self.prepare_host_request(request);
        self.runner.status(&program, &request)
    }

    fn spawn_command_request(
        &self,
        request: CommandRequest,
    ) -> io::Result<Box<dyn SpawnedCommand>> {
        let program = self.effective_program(&self.binary);
        let request = self.prepare_host_request(request);
        self.runner.spawn(&program, &request)
    }

    fn run_host_command(
        &self,
        program: &str,
        request: CommandRequest,
    ) -> io::Result<CommandOutput> {
        let program = self.effective_program(program);
        let request = self.prepare_host_request(request);
        self.runner.run(&program, &request)
    }

    fn run_checked_host_command(
        &self,
        program: &str,
        request: CommandRequest,
    ) -> DriverResult<CommandOutput> {
        let command = command_string(program, &request.args);
        let output = self.run_host_command(program, request).map_err(|source| {
            DriverError::CommandSpawn {
                command: command.clone(),
                source,
            }
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

    fn effective_program(&self, program: &str) -> String {
        if !self.host_bootstrap || !self.runner.uses_host_environment() {
            return program.to_owned();
        }
        resolve_executable(program, &host_path_entries()).unwrap_or_else(|| program.to_owned())
    }

    fn prepare_host_request(&self, mut request: CommandRequest) -> CommandRequest {
        if !self.host_bootstrap {
            return request;
        }
        let path = host_command_path(&request.env);
        request.env.insert("PATH".to_owned(), path);
        request
    }

    fn install_openshell_cli(&self) -> Result<(), DriverError> {
        let request = install_openshell_command_request();
        let output = self
            .run_host_command("sh", request.clone())
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string("sh", &request.args),
                source,
            })?;
        if output.status.is_none_or(|status| status != 0) {
            return Err(DriverError::CommandFailed {
                command: command_string("sh", &request.args),
                status: output.status,
                stdout: output.stdout,
                stderr: output.stderr,
            });
        }
        Ok(())
    }

    fn ensure_container_runtime_ready(&self) -> Result<(), PreflightResult> {
        if self.docker_info_ok() {
            return Ok(());
        }

        if !self.launchable_container_runtime_exists() {
            return Err(preflight_failure(
                "container_runtime_missing",
                "No local container runtime was found for OpenShell sandbox creation".to_owned(),
                Some(
                    "Install OrbStack or Docker Desktop once, then retry `agentenv create`; agentenv will auto-detect common runtime paths afterward"
                        .to_owned(),
                ),
            ));
        }

        let runtime_app = self.preferred_runtime_app();
        let launch = self.run_host_command("open", command_request(&["-a", runtime_app.as_str()]));
        if let Err(err) = launch {
            return Err(preflight_failure(
                "container_runtime_unavailable",
                format!("failed to launch {runtime_app}: {err}"),
                Some("Start OrbStack or Docker Desktop, then retry `agentenv create`".to_owned()),
            ));
        }

        for _ in 0..CONTAINER_RUNTIME_WAIT_ATTEMPTS {
            if self.docker_info_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }

        Err(preflight_failure(
            "container_runtime_unavailable",
            "Container runtime was launched but Docker did not become ready".to_owned(),
            Some("Open OrbStack or Docker Desktop and wait until it reports running, then retry `agentenv create`".to_owned()),
        ))
    }

    fn docker_info_ok(&self) -> bool {
        match self.run_host_command(
            "docker",
            command_request(&["info", "--format", "{{.ServerVersion}}"]),
        ) {
            Ok(output) => output.status == Some(0),
            Err(_) => false,
        }
    }

    fn preferred_runtime_app(&self) -> String {
        if let Some(app) = self.configured_runtime_app() {
            return app;
        }
        if orb_stack_app_exists() {
            "OrbStack".to_owned()
        } else {
            "Docker".to_owned()
        }
    }

    fn launchable_container_runtime_exists(&self) -> bool {
        self.configured_runtime_app().is_some() || orb_stack_app_exists() || docker_app_exists()
    }

    fn configured_runtime_app(&self) -> Option<String> {
        self.runtime_app_override
            .clone()
            .or_else(configured_runtime_app)
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

    fn spawn_checked_command(
        &self,
        request: CommandRequest,
    ) -> Result<Box<dyn SpawnedCommand>, DriverError> {
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

    fn remove_current_policy(&self, handle: &str) {
        match self.current_policies.lock() {
            Ok(mut policies) => {
                policies.remove(handle);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(handle);
            }
        }
    }

    fn clear_current_policies(&self) {
        match self.current_policies.lock() {
            Ok(mut policies) => policies.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }

    fn store_log_stream(&self, handle: String, command: Box<dyn SpawnedCommand>) {
        match self.log_streams.lock() {
            Ok(mut streams) => {
                streams.push(LogStream { handle, command });
            }
            Err(poisoned) => {
                poisoned.into_inner().push(LogStream { handle, command });
            }
        }
    }

    fn terminate_log_streams_for_handle(&self, handle: &str) -> DriverResult<()> {
        let result = match self.log_streams.lock() {
            Ok(mut streams) => terminate_matching_log_streams(&mut streams, handle),
            Err(poisoned) => {
                let mut streams = poisoned.into_inner();
                terminate_matching_log_streams(&mut streams, handle)
            }
        };

        if let Some(message) = result {
            Err(DriverError::CleanupFailed {
                message: format!("failed to terminate log stream for `{handle}`: {message}"),
            })
        } else {
            Ok(())
        }
    }

    fn terminate_all_log_streams(&self) -> DriverResult<()> {
        let result = match self.log_streams.lock() {
            Ok(mut streams) => terminate_all_log_streams(&mut streams),
            Err(poisoned) => {
                let mut streams = poisoned.into_inner();
                terminate_all_log_streams(&mut streams)
            }
        };

        if let Some(message) = result {
            Err(DriverError::CleanupFailed {
                message: format!("failed to terminate log stream: {message}"),
            })
        } else {
            Ok(())
        }
    }

    fn delete_sandbox(&self, handle: &str) -> Result<CommandOutput, DriverError> {
        self.run_checked_command(command_request(&["sandbox", "delete", handle]))
    }

    fn rollback_created_sandbox(&self, handle: &str, primary: DriverError) -> DriverError {
        match self.delete_sandbox(handle) {
            Ok(_) => primary,
            Err(cleanup) => DriverError::CleanupFailed {
                message: format!(
                    "failed to roll back sandbox `{handle}` after create failed ({primary}); rollback also failed: {cleanup}"
                ),
            },
        }
    }

    fn write_policy_temp_file(
        &self,
        policy: &NetworkPolicy,
    ) -> DriverResult<(TempPolicyFile, Option<InferenceUpdate>)> {
        let translated = translate_policy_for_openshell(policy).map_err(|err| {
            DriverError::PolicyTranslation {
                message: err.to_string(),
            }
        })?;
        let temp_policy_file = TempPolicyFile::write(&translated.policy_yaml).map_err(|err| {
            DriverError::PolicyTranslation {
                message: format!("failed to write translated policy to temp file: {err}"),
            }
        })?;

        Ok((temp_policy_file, translated.inference_update))
    }

    fn run_inference_update(&self, inference_update: InferenceUpdate) -> DriverResult<()> {
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
        Ok(())
    }

    fn apply_policy_to_handle(
        &self,
        handle: &str,
        policy: NetworkPolicy,
    ) -> DriverResult<ApplyPolicyResult> {
        if let Some(current) = self.current_policy_for_handle(handle) {
            classify_policy_update(&current, &policy).map_err(driver_error_from_policy_error)?;
        }

        let (temp_policy_file, inference_update) = self.write_policy_temp_file(&policy)?;

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

        if let Some(inference_update) = inference_update {
            self.run_inference_update(inference_update)?;
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

fn terminate_matching_log_streams(streams: &mut Vec<LogStream>, handle: &str) -> Option<String> {
    let mut next = Vec::with_capacity(streams.len());
    let mut first_error = None;
    for mut stream in streams.drain(..) {
        if stream.handle == handle {
            match stream.command.terminate() {
                Ok(()) => {}
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err.to_string());
                    }
                    next.push(stream);
                }
            }
        } else {
            next.push(stream);
        }
    }
    *streams = next;
    first_error
}

fn terminate_all_log_streams(streams: &mut Vec<LogStream>) -> Option<String> {
    let mut next = Vec::with_capacity(streams.len());
    let mut first_error = None;
    for mut stream in streams.drain(..) {
        match stream.command.terminate() {
            Ok(()) => {}
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err.to_string());
                }
                next.push(stream);
            }
        }
    }
    *streams = next;
    first_error
}

fn driver_error_from_policy_error(err: PolicyError) -> DriverError {
    match err {
        PolicyError::RequiresRecreate { domains } => {
            DriverError::PolicyRequiresRecreate { domains }
        }
        other => DriverError::PolicyTranslation {
            message: other.to_string(),
        },
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

struct TempBuildStage {
    path: Option<PathBuf>,
}

impl TempBuildStage {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn cleanup(mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

impl Drop for TempBuildStage {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
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

fn byo_dockerfile_config(
    metadata: &BTreeMap<String, Value>,
) -> DriverResult<Option<ByoDockerfileConfig>> {
    let Some(dockerfile) = optional_metadata_string(metadata, "byo_dockerfile")? else {
        return Ok(None);
    };

    Ok(Some(ByoDockerfileConfig {
        dockerfile: PathBuf::from(dockerfile),
        expected_digest: optional_metadata_string(metadata, "byo_expected_digest")?,
        agentenv_version: optional_metadata_string(metadata, "agentenv_version")?
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned()),
        agent: optional_metadata_string(metadata, "agentenv_agent")?.unwrap_or_default(),
        mcp_port: optional_metadata_string(metadata, "agentenv_mcp_port")?.unwrap_or_default(),
        workspace_mount: optional_metadata_string(metadata, "agentenv_workspace_mount")?
            .unwrap_or_else(|| SANDBOX_WORKING_DIR.to_owned()),
        build_seed: optional_metadata_string(metadata, "agentenv_build_seed")?,
    }))
}

fn optional_metadata_string(
    metadata: &BTreeMap<String, Value>,
    key: &str,
) -> DriverResult<Option<String>> {
    match metadata.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be a string when set"),
        }),
    }
}

fn default_agentenv_workdir() -> PathBuf {
    std::env::var_os("AGENTENV_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".agentenv")))
        .unwrap_or_else(|| PathBuf::from(".agentenv"))
}

fn sanitize_build_name(name: &str) -> String {
    let mut output = String::new();
    for byte in name.bytes() {
        let ch = byte.to_ascii_lowercase() as char;
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_') {
            output.push(ch);
        } else {
            output.push('-');
        }
    }
    let trimmed = output.trim_matches('-');
    if trimmed.is_empty() {
        "sandbox".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn stage_build_context(
    context_dir: &Path,
    dockerfile: &Path,
    stage_dir: &Path,
) -> DriverResult<()> {
    if stage_dir.exists() {
        fs::remove_dir_all(stage_dir).map_err(|source| DriverError::InvalidInput {
            message: format!(
                "failed to clear staged BYO build context `{}`: {source}",
                stage_dir.display()
            ),
        })?;
    }
    copy_dir_contents(context_dir, stage_dir).map_err(|source| DriverError::InvalidInput {
        message: format!(
            "failed to stage BYO build context `{}` to `{}`: {source}",
            context_dir.display(),
            stage_dir.display()
        ),
    })?;
    fs::copy(dockerfile, stage_dir.join("Dockerfile")).map_err(|source| {
        DriverError::InvalidInput {
            message: format!(
                "failed to stage BYO Dockerfile `{}`: {source}",
                dockerfile.display()
            ),
        }
    })?;
    Ok(())
}

fn copy_dir_contents(src: &Path, dst: &Path) -> io::Result<()> {
    let dockerignore = DockerIgnore::load(src)?;
    fs::create_dir_all(dst)?;
    let _ = copy_dir_contents_inner(src, dst, Path::new(""), &dockerignore, false, true)?;
    Ok(())
}

fn copy_dir_contents_inner(
    src: &Path,
    dst: &Path,
    relative: &Path,
    dockerignore: &DockerIgnore,
    parent_ignored: bool,
    create_current: bool,
) -> io::Result<bool> {
    if create_current {
        fs::create_dir_all(dst)?;
    }
    let mut copied_any = create_current;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let file_type = metadata.file_type();
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let relative_path = if relative.as_os_str().is_empty() {
            PathBuf::from(entry.file_name())
        } else {
            relative.join(entry.file_name())
        };
        let is_dir = file_type.is_dir();
        let ignored = dockerignore.is_ignored(&relative_path, is_dir, parent_ignored);
        if file_type.is_dir() {
            if ignored && !dockerignore.may_reinclude_descendant(&relative_path) {
                continue;
            }
            if copy_dir_contents_inner(
                &src_path,
                &dst_path,
                &relative_path,
                dockerignore,
                ignored,
                !ignored,
            )? {
                copied_any = true;
            }
        } else if ignored {
            continue;
        } else if file_type.is_symlink() {
            fs::create_dir_all(dst)?;
            copy_symlink(&src_path, &dst_path)?;
            copied_any = true;
        } else if file_type.is_file() {
            fs::create_dir_all(dst)?;
            fs::copy(&src_path, &dst_path)?;
            copied_any = true;
        }
    }
    Ok(copied_any)
}

#[derive(Debug, Clone, Default)]
struct DockerIgnore {
    rules: Vec<DockerIgnoreRule>,
}

#[derive(Debug, Clone)]
struct DockerIgnoreRule {
    pattern: String,
    negated: bool,
    has_slash: bool,
}

impl DockerIgnore {
    fn load(context_dir: &Path) -> io::Result<Self> {
        match fs::read_to_string(context_dir.join(".dockerignore")) {
            Ok(contents) => Ok(Self::parse(&contents)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(source),
        }
    }

    fn parse(contents: &str) -> Self {
        let rules = contents
            .lines()
            .filter_map(DockerIgnoreRule::parse)
            .collect();
        Self { rules }
    }

    fn is_ignored(&self, relative_path: &Path, is_dir: bool, parent_ignored: bool) -> bool {
        let Some(relative_path) = normalized_relative_path(relative_path) else {
            return parent_ignored;
        };
        let mut ignored = parent_ignored;
        for rule in &self.rules {
            if rule.matches(&relative_path, is_dir) {
                ignored = !rule.negated;
            }
        }
        ignored
    }

    fn may_reinclude_descendant(&self, relative_dir: &Path) -> bool {
        let Some(relative_dir) = normalized_relative_path(relative_dir) else {
            return false;
        };
        self.rules
            .iter()
            .any(|rule| rule.negated && rule.may_match_descendant(&relative_dir))
    }
}

impl DockerIgnoreRule {
    fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (negated, pattern) = line
            .strip_prefix('!')
            .map(|pattern| (true, pattern.trim()))
            .unwrap_or((false, line));
        let pattern = clean_dockerignore_pattern(pattern)?;
        let has_slash = pattern.contains('/');
        Some(Self {
            pattern,
            negated,
            has_slash,
        })
    }

    fn matches(&self, relative_path: &str, _is_dir: bool) -> bool {
        dockerignore_pattern_matches(&self.pattern, self.has_slash, relative_path)
    }

    fn may_match_descendant(&self, relative_dir: &str) -> bool {
        if !self.has_slash {
            return true;
        }
        self.pattern.starts_with(&format!("{relative_dir}/"))
            || self.pattern == relative_dir
            || self.pattern.contains("**")
    }
}

fn clean_dockerignore_pattern(pattern: &str) -> Option<String> {
    let pattern = pattern.trim().trim_matches('/');
    if pattern.is_empty() || pattern == "." {
        return None;
    }
    let mut parts = Vec::new();
    let normalized = pattern.replace('\\', "/");
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                let _ = parts.pop();
            }
            part => parts.push(part),
        }
    }
    let pattern = parts.join("/");
    (!pattern.is_empty() && pattern != ".").then_some(pattern)
}

fn normalized_relative_path(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn dockerignore_pattern_matches(pattern: &str, has_slash: bool, relative_path: &str) -> bool {
    if !has_slash {
        return relative_path
            .split('/')
            .any(|part| wildcard_matches(pattern, part));
    }

    let pattern_parts = pattern.split('/').collect::<Vec<_>>();
    let path_parts = relative_path.split('/').collect::<Vec<_>>();
    dockerignore_segments_match(&pattern_parts, &path_parts)
}

fn dockerignore_segments_match(pattern: &[&str], path: &[&str]) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }
    if pattern[0] == "**" {
        return dockerignore_segments_match(&pattern[1..], path)
            || (!path.is_empty() && dockerignore_segments_match(pattern, &path[1..]));
    }
    !path.is_empty()
        && wildcard_matches(pattern[0], path[0])
        && dockerignore_segments_match(&pattern[1..], &path[1..])
}

fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let text = text.chars().collect::<Vec<_>>();
    let mut matches = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    matches[0][0] = true;
    for i in 1..=pattern.len() {
        if pattern[i - 1] == '*' {
            matches[i][0] = matches[i - 1][0];
        }
    }
    for i in 1..=pattern.len() {
        for j in 1..=text.len() {
            matches[i][j] = match pattern[i - 1] {
                '*' => matches[i - 1][j] || matches[i][j - 1],
                '?' => matches[i - 1][j - 1],
                ch => ch == text[j - 1] && matches[i - 1][j - 1],
            };
        }
    }
    matches[pattern.len()][text.len()]
}

#[cfg(unix)]
fn copy_symlink(src: &Path, dst: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(fs::read_link(src)?, dst)
}

#[cfg(windows)]
fn copy_symlink(src: &Path, dst: &Path) -> io::Result<()> {
    let target = fs::read_link(src)?;
    if fs::metadata(src)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        std::os::windows::fs::symlink_dir(target, dst)
    } else {
        std::os::windows::fs::symlink_file(target, dst)
    }
}

fn install_openshell_command_request() -> CommandRequest {
    let script = format!(
        "mkdir -p \"$HOME/.local/bin\" && curl -LsSf {OPEN_SHELL_INSTALL_URL} | OPENSHELL_INSTALL_DIR=\"$HOME/.local/bin\" sh"
    );
    command_request(&["-c", &script])
}

fn host_command_path(request_env: &BTreeMap<String, String>) -> String {
    let base = request_env
        .get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    let mut entries = host_path_entries();
    entries.extend(std::env::split_paths(&base));
    dedup_join_paths(entries).unwrap_or(base)
}

fn host_path_entries() -> Vec<PathBuf> {
    let mut entries = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        entries.push(home.join(".local/bin"));
        entries.push(home.join(".orbstack/bin"));
    }
    entries.extend([
        PathBuf::from("/Applications/OrbStack.app/Contents/MacOS/xbin"),
        PathBuf::from("/Applications/OrbStack.app/Contents/MacOS/bin"),
        PathBuf::from("/Applications/Docker.app/Contents/Resources/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/opt/homebrew/bin"),
    ]);
    entries
}

fn dedup_join_paths(entries: Vec<PathBuf>) -> Option<String> {
    let mut seen = Vec::<PathBuf>::new();
    for entry in entries {
        if !entry.as_os_str().is_empty() && !seen.contains(&entry) {
            seen.push(entry);
        }
    }
    std::env::join_paths(seen)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn resolve_executable(program: &str, extra_path_entries: &[PathBuf]) -> Option<String> {
    if program.contains(std::path::MAIN_SEPARATOR) {
        let candidate = PathBuf::from(program);
        return is_executable_candidate(&candidate).then(|| program.to_owned());
    }

    let mut entries = extra_path_entries.to_vec();
    if let Some(path) = std::env::var_os("PATH") {
        entries.extend(std::env::split_paths(&path));
    }
    for dir in entries {
        for candidate in executable_candidates(&dir, program) {
            if is_executable_candidate(&candidate) {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn configured_runtime_app() -> Option<String> {
    std::env::var("AGENTENV_OPENSHELL_RUNTIME_APP")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn orb_stack_app_exists() -> bool {
    Path::new("/Applications/OrbStack.app").exists()
        || std::env::var_os("HOME")
            .map(PathBuf::from)
            .is_some_and(|home| home.join("Applications/OrbStack.app").exists())
}

fn docker_app_exists() -> bool {
    Path::new("/Applications/Docker.app").exists()
        || std::env::var_os("HOME")
            .map(PathBuf::from)
            .is_some_and(|home| home.join("Applications/Docker.app").exists())
}

fn command_string(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_session_display_name(name: &str) -> DriverResult<()> {
    if name.is_empty() {
        return Err(DriverError::InvalidInput {
            message: "session name must not be empty".to_owned(),
        });
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DriverError::InvalidInput {
            message: "session name may only contain ASCII letters, digits, '-', '_' or '.'"
                .to_owned(),
        });
    }

    Ok(())
}

fn validate_tmux_session_id(session_id: &str) -> DriverResult<String> {
    validate_session_display_name(session_id)?;
    Ok(session_id.to_owned())
}

fn generate_tmux_session_id(handle: &str) -> String {
    format!(
        "agentenv-{}-{}",
        tmux_scope_label(handle),
        Uuid::new_v4().simple()
    )
}

fn tmux_scope_label(handle: &str) -> String {
    let mut label = String::new();
    for byte in handle.bytes().take(32) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            label.push(char::from(byte));
        } else {
            label.push('-');
        }
    }
    if label.is_empty() {
        "sandbox".to_owned()
    } else {
        label
    }
}

fn tmux_exact_target(session_id: &str) -> String {
    format!("={session_id}:")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn now_timestamp_string() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn tmux_epoch_seconds_to_rfc3339(value: &str) -> Option<String> {
    let seconds = value.parse::<i64>().ok()?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn tmux_list_sessions_is_empty(output: &CommandOutput) -> bool {
    let output = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
    output.contains("no server running")
        || output.contains("failed to connect to server")
        || output.contains("no sessions")
}

fn parse_tmux_sessions(handle: &str, stdout: &str) -> Vec<SessionHandle> {
    stdout
        .lines()
        .filter_map(|line| parse_tmux_session(handle, line))
        .collect()
}

fn parse_tmux_session(handle: &str, line: &str) -> Option<SessionHandle> {
    let mut fields = line.splitn(6, '\t');
    let tmux_name = fields.next()?.trim();
    let attached = fields.next()?.trim();
    let created_at = fields.next()?.trim();
    let owner_handle = fields.next()?.trim();
    let display_name_or_command = fields.next().unwrap_or_default().trim();
    let command = fields.next().map(str::trim);
    let (display_name, command) = match command {
        Some(command) => (display_name_or_command, command),
        None => ("", display_name_or_command),
    };
    if owner_handle != handle || created_at.is_empty() {
        return None;
    }

    let session_id = validate_tmux_session_id(tmux_name).ok()?;
    let attached_count = attached.parse::<u64>().ok()?;
    let timestamp = tmux_epoch_seconds_to_rfc3339(created_at)?;
    let status = if attached_count > 0 {
        SessionStatus::Attached
    } else {
        SessionStatus::Detached
    };

    Some(SessionHandle {
        session_id: session_id.clone(),
        name: if display_name.is_empty() {
            session_id.clone()
        } else {
            display_name.to_owned()
        },
        status,
        created_at: timestamp.clone(),
        updated_at: timestamp,
        command: if command.is_empty() {
            UNKNOWN_SESSION_COMMAND.to_owned()
        } else {
            command.to_owned()
        },
        working_dir: Some(SANDBOX_WORKING_DIR.to_owned()),
    })
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

fn translate_policy_for_openshell(policy: &NetworkPolicy) -> Result<TranslatedPolicy, PolicyError> {
    if policy.network.allow.is_empty() && policy.network.approval_required.is_empty() {
        return translate_for_openshell_with_binaries(policy, std::iter::empty::<String>());
    }

    let mut binaries = resolve_default_open_shell_binary_paths()?;
    if policy_allows_full_npm_registry(policy) {
        binaries.extend(
            DEFAULT_OPEN_SHELL_NPM_INSTALL_BINARIES
                .iter()
                .map(|path| (*path).to_owned()),
        );
    }
    translate_for_openshell_with_binaries(policy, binaries)
}

fn policy_allows_full_npm_registry(policy: &NetworkPolicy) -> bool {
    policy.network.allow.iter().any(|rule| {
        matches!(
            &rule.target,
            agentenv_proto::NetworkTarget::Host {
                host,
                port: Some(443),
                scheme: Some(scheme),
                http_access: Some(agentenv_proto::HttpAccessLevel::Full),
            } if host == "registry.npmjs.org" && scheme == "https"
        )
    })
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
        AttachSessionParams, Capabilities, CopyInParams, CopyOutParams, CreateSessionParams,
        DestroyParams, DriverKind, ExecParams, InitializeParams, KillSessionParams,
        ListSessionsParams, LogLevel, LogsParams, LogsStreamParams, PreflightParams, SandboxHandle,
        SandboxSpec, SandboxStatusParams, SessionStatus, StopParams, SCHEMA_VERSION,
    };
    use semver::Version;
    use serde_json::{json, Value};

    use driver_conformance::assert_sandbox_driver_contract;

    use super::{
        command_request, command_request_with_env, extract_semver_token, shell_quote, CommandCall,
        CommandOutput, CommandRunner, CommandScript, CommandScriptResult, OpenShellDriver,
        RecordingCommandRunner, OPEN_SHELL_INSTALL_URL, SANDBOX_WORKING_DIR,
        TMUX_AGENTENV_COMMAND_OPTION, TMUX_AGENTENV_HANDLE_OPTION,
        TMUX_AGENTENV_SESSION_NAME_OPTION, TMUX_SESSION_FORMAT,
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

    #[derive(Debug)]
    struct StreamCleanupRunner {
        calls: Mutex<Vec<CommandCall>>,
        spawn_calls: Mutex<Vec<CommandCall>>,
        terminations: Arc<Mutex<usize>>,
        termination_failures_remaining: Arc<Mutex<usize>>,
    }

    struct TrackingSpawnedCommand {
        terminations: Arc<Mutex<usize>>,
        failures_remaining: Arc<Mutex<usize>>,
    }

    impl CapturingCommandRunner {
        fn calls(&self) -> Vec<CommandCall> {
            self.calls.lock().expect("calls mutex").clone()
        }
    }

    impl StreamCleanupRunner {
        fn new() -> Self {
            Self::new_with_termination_failures(0)
        }

        fn new_with_termination_failures(failures_remaining: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                spawn_calls: Mutex::new(Vec::new()),
                terminations: Arc::new(Mutex::new(0)),
                termination_failures_remaining: Arc::new(Mutex::new(failures_remaining)),
            }
        }

        fn calls(&self) -> Vec<CommandCall> {
            self.calls.lock().expect("calls mutex").clone()
        }

        fn spawn_calls(&self) -> Vec<CommandCall> {
            self.spawn_calls.lock().expect("spawn calls mutex").clone()
        }

        fn terminations(&self) -> usize {
            *self.terminations.lock().expect("terminations mutex")
        }
    }

    impl super::SpawnedCommand for TrackingSpawnedCommand {
        fn terminate(&mut self) -> io::Result<()> {
            *self.terminations.lock().expect("terminations mutex") += 1;
            let mut failures = self
                .failures_remaining
                .lock()
                .expect("failures remaining mutex");
            if *failures > 0 {
                *failures -= 1;
                return Err(io::Error::other("terminate failed"));
            }
            Ok(())
        }
    }

    impl CommandRunner for StreamCleanupRunner {
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

        fn spawn(
            &self,
            program: &str,
            request: &super::CommandRequest,
        ) -> io::Result<Box<dyn super::SpawnedCommand>> {
            self.spawn_calls
                .lock()
                .expect("spawn calls mutex")
                .push(CommandCall {
                    program: program.to_owned(),
                    request: request.clone(),
                });

            Ok(Box::new(TrackingSpawnedCommand {
                terminations: self.terminations.clone(),
                failures_remaining: self.termination_failures_remaining.clone(),
            }))
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

        fn spawn(
            &self,
            program: &str,
            request: &super::CommandRequest,
        ) -> io::Result<Box<dyn super::SpawnedCommand>> {
            self.spawn_calls
                .lock()
                .expect("spawn calls mutex")
                .push(CommandCall {
                    program: program.to_owned(),
                    request: request.clone(),
                });

            Ok(Box::new(super::NoopSpawnedCommand))
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

        fn spawn(
            &self,
            program: &str,
            request: &super::CommandRequest,
        ) -> io::Result<Box<dyn super::SpawnedCommand>> {
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
                CommandScriptResult::Output(_) => Ok(Box::new(super::NoopSpawnedCommand)),
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

    fn set_empty_path() -> (PathBuf, PathRestoreGuard) {
        use std::time::{SystemTime, UNIX_EPOCH};

        let tempdir = std::env::temp_dir().join(format!(
            "sandbox-openshell-empty-path-lib-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&tempdir).expect("create tempdir");

        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", &tempdir);

        (
            tempdir,
            PathRestoreGuard {
                original: original_path,
            },
        )
    }

    fn unique_tempdir(prefix: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};

        let tempdir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&tempdir).expect("create tempdir");
        tempdir
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

    fn tmux_available_script() -> CommandScript {
        CommandScript::success("tmux", &["-V"], "tmux 3.5a\n", "")
    }

    fn tmux_available_expectation() -> FlexibleCommandExpectation {
        FlexibleCommandExpectation::success(
            "tmux",
            |call| {
                assert_eq!(call.request.args, vec!["-V".to_owned()]);
            },
            "tmux 3.5a\n",
            "",
        )
    }

    fn tmux_missing_script() -> CommandScript {
        CommandScript::output("tmux", &["-V"], Some(127), "", "tmux: not found")
    }

    fn tmux_new_generated_session_expectation(
        captured_session_id: Arc<Mutex<Option<String>>>,
        handle: &str,
        command: &str,
    ) -> FlexibleCommandExpectation {
        let handle = handle.to_owned();
        let command = command.to_owned();
        FlexibleCommandExpectation::success(
            "tmux",
            move |call| {
                assert_eq!(call.request.args.len(), 5);
                assert_eq!(call.request.args[0], "new-session");
                assert_eq!(call.request.args[1], "-d");
                assert_eq!(call.request.args[2], "-s");

                let session_id = call.request.args[3].clone();
                let prefix = format!("agentenv-{}-", super::tmux_scope_label(&handle));
                assert!(
                    session_id.starts_with(&prefix),
                    "generated session id {session_id:?} should start with {prefix:?}"
                );
                assert_eq!(session_id.len(), prefix.len() + 32);
                assert!(
                    session_id[prefix.len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()),
                    "generated session id {session_id:?} should end with a uuid"
                );

                let tmux_command = format!(
                    "{} sandbox exec --name {} --workdir {} --tty -- sh -lc {}",
                    shell_quote("openshell"),
                    shell_quote(&handle),
                    shell_quote(SANDBOX_WORKING_DIR),
                    shell_quote(&command)
                );
                assert_eq!(call.request.args[4], tmux_command);
                *captured_session_id
                    .lock()
                    .expect("captured session id mutex") = Some(session_id);
            },
            "",
            "",
        )
    }

    fn tmux_set_generated_option_expectation(
        captured_session_id: Arc<Mutex<Option<String>>>,
        option: &str,
        value: &str,
    ) -> FlexibleCommandExpectation {
        let option = option.to_owned();
        let value = value.to_owned();
        FlexibleCommandExpectation::success(
            "tmux",
            move |call| {
                let session_id = captured_session_id
                    .lock()
                    .expect("captured session id mutex")
                    .clone()
                    .expect("generated tmux session id should be captured first");
                let target = super::tmux_exact_target(&session_id);
                assert_eq!(
                    call.request.args,
                    vec![
                        "set-option".to_owned(),
                        "-t".to_owned(),
                        target,
                        option.clone(),
                        value.clone(),
                    ]
                );
            },
            "",
            "",
        )
    }

    fn tmux_owner_script(session_id: &str, handle: &str) -> CommandScript {
        let target = super::tmux_exact_target(session_id);
        let stdout = format!("{handle}\n");
        CommandScript::success(
            "tmux",
            &[
                "display-message",
                "-p",
                "-t",
                &target,
                "#{@agentenv_handle}",
            ],
            &stdout,
            "",
        )
    }

    fn tmux_attach_script(session_id: &str) -> CommandScript {
        let target = super::tmux_exact_target(session_id);
        CommandScript::success("tmux", &["attach-session", "-t", &target], "", "")
    }

    fn tmux_kill_script(session_id: &str) -> CommandScript {
        let target = super::tmux_exact_target(session_id);
        CommandScript::success("tmux", &["kill-session", "-t", &target], "", "")
    }

    fn tmux_list_sessions_script(stdout: &str, status: Option<i32>, stderr: &str) -> CommandScript {
        CommandScript::output(
            "tmux",
            &["list-sessions", "-F", TMUX_SESSION_FORMAT],
            status,
            stdout,
            stderr,
        )
    }

    fn assert_persistent_sessions_missing(err: agentenv_core::driver::DriverError) {
        match err {
            agentenv_core::driver::DriverError::CapabilityMissing { capability } => {
                assert_eq!(capability, "supports_persistent_sessions");
            }
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }
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
        assert!(capabilities.supports_persistent_sessions);
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
    fn full_npm_registry_policy_includes_sandbox_installer_binaries() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};
        use agentenv_proto::{HttpAccessLevel, NetworkRule, NetworkTarget};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (_tempdir, _path_guard) = set_fake_openshell_path();
        let registry = PresetRegistry::load_builtin().expect("load presets");
        let mut policy = compose_policy(Tier::Restricted, &[], None, &registry).expect("compose");
        policy.network.allow.push(NetworkRule {
            target: NetworkTarget::Host {
                host: "registry.npmjs.org".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: Some(HttpAccessLevel::Full),
            },
        });

        let translated = super::translate_policy_for_openshell(&policy).expect("translate policy");

        assert!(translated.policy_yaml.contains("/usr/local/bin/npm"));
        assert!(translated.policy_yaml.contains("/usr/local/bin/node"));
    }

    #[test]
    fn apply_policy_allows_empty_network_policy_without_host_agent_binaries() {
        use agentenv_policy::{compose_policy, PresetRegistry, Tier};

        let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
        let (policy, tempdir, _path_guard) = {
            let registry = PresetRegistry::load_builtin().expect("load presets");
            let policy = compose_policy(Tier::Restricted, &[], None, &registry).expect("compose");
            assert!(policy.network.allow.is_empty());
            assert!(policy.network.approval_required.is_empty());
            let (tempdir, path_guard) = set_empty_path();
            (policy, tempdir, path_guard)
        };
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "openshell",
                |call| {
                    assert_args_prefix_suffix(
                        &call.request.args,
                        &["policy", "set", "devbox", "--policy"],
                        &["--wait"],
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
        assert_eq!(runner.calls().len(), 1);
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

        match err {
            agentenv_core::driver::DriverError::PolicyRequiresRecreate { domains } => {
                assert_eq!(domains, "process");
            }
            other => panic!("expected PolicyRequiresRecreate, got {other:?}"),
        }
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
    fn create_passes_initial_policy_to_sandbox_create() {
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
                        &[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--no-auto-providers",
                            "--from",
                            "openclaw",
                            "--policy",
                        ],
                        &["--", "true"],
                    );
                    let policy_path = PathBuf::from(
                        call.request
                            .args
                            .get(8)
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
        assert_eq!(runner.calls().len(), 1);
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
    fn create_rolls_back_sandbox_when_initial_inference_update_fails() {
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
                        &[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--no-auto-providers",
                            "--from",
                            "openclaw",
                            "--policy",
                        ],
                        &["--", "true"],
                    );
                    let policy_path = PathBuf::from(
                        call.request
                            .args
                            .get(8)
                            .expect("policy path should be present"),
                    );
                    *capture_for_check.lock().expect("capture mutex") = Some(policy_path);
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::output(
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
                Some(1),
                "",
                "inference set failed",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                |call| {
                    assert_eq!(
                        call.request,
                        command_request(&["sandbox", "delete", "devbox"])
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
        let err = runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: Some(policy),
                        metadata: BTreeMap::from([("name".to_owned(), json!("devbox"))]),
                    })
                    .await
            })
            .expect_err("create should fail when initial inference update fails");

        match err {
            agentenv_core::driver::DriverError::CommandFailed { command, .. } => {
                assert!(command.contains("inference set"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
        assert_eq!(runner.calls().len(), 3);
        assert!(driver.current_policy_for_handle("devbox").is_none());
        assert!(!capture
            .lock()
            .expect("capture mutex")
            .as_ref()
            .expect("policy path")
            .exists());
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn create_reports_cleanup_failure_when_initial_inference_rollback_fails() {
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
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "openshell",
                |call| {
                    assert_args_prefix_suffix(
                        &call.request.args,
                        &[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--no-auto-providers",
                            "--from",
                            "openclaw",
                            "--policy",
                        ],
                        &["--", "true"],
                    );
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::output(
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
                Some(1),
                "",
                "inference set failed",
            ),
            FlexibleCommandExpectation::output(
                "openshell",
                |call| {
                    assert_eq!(
                        call.request,
                        command_request(&["sandbox", "delete", "devbox"])
                    );
                },
                Some(1),
                "",
                "delete failed",
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
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: Some(policy),
                        metadata: BTreeMap::from([("name".to_owned(), json!("devbox"))]),
                    })
                    .await
            })
            .expect_err("create should fail when inference update and rollback fail");

        match err {
            agentenv_core::driver::DriverError::CleanupFailed { message } => {
                assert!(message.contains("inference set failed"));
                assert!(message.contains("delete failed"));
            }
            other => panic!("expected CleanupFailed, got {other:?}"),
        }
        assert_eq!(runner.calls().len(), 3);
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
    async fn preflight_passes_when_cli_version_and_status_are_valid() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::success("openshell", &["--version"], "openshell 0.0.31", ""),
            CommandScript::success("openshell", &["status"], "", ""),
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
                    request: command_request(&["status"]),
                },
            ]
        );
    }

    #[tokio::test]
    async fn openshell_driver_satisfies_sandbox_conformance_contract() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::success("openshell", &["--version"], "openshell 0.0.31", ""),
            CommandScript::success("openshell", &["status"], "", ""),
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
        assert!(capabilities.supports_persistent_sessions);

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
                    request: command_request(&["status"]),
                },
            ]
        );
    }

    #[tokio::test]
    async fn openshell_create_session_uses_host_tmux_when_available() {
        let captured_session_id = Arc::new(Mutex::new(None::<String>));
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            tmux_available_expectation(),
            tmux_new_generated_session_expectation(
                captured_session_id.clone(),
                "sb-1",
                "agentenv-agent",
            ),
            tmux_set_generated_option_expectation(
                captured_session_id.clone(),
                TMUX_AGENTENV_HANDLE_OPTION,
                "sb-1",
            ),
            tmux_set_generated_option_expectation(
                captured_session_id.clone(),
                TMUX_AGENTENV_SESSION_NAME_OPTION,
                "sh-1",
            ),
            tmux_set_generated_option_expectation(
                captured_session_id.clone(),
                TMUX_AGENTENV_COMMAND_OPTION,
                "agentenv-agent",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner);

        let session = driver
            .create_session(CreateSessionParams {
                handle: "sb-1".to_owned(),
                name: "sh-1".to_owned(),
                command: "agentenv-agent".to_owned(),
                detached: true,
                metadata: BTreeMap::new(),
            })
            .await
            .unwrap();

        assert_eq!(
            captured_session_id
                .lock()
                .expect("captured session id mutex")
                .as_ref(),
            Some(&session.session_id)
        );
        assert!(session.session_id.starts_with("agentenv-sb-1-"));
        assert_eq!(session.name, "sh-1");
        assert_eq!(session.status, agentenv_proto::SessionStatus::Detached);
    }

    #[tokio::test]
    async fn openshell_create_session_allows_dot_names_and_reports_detached() {
        let captured_session_id = Arc::new(Mutex::new(None::<String>));
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            tmux_available_expectation(),
            tmux_new_generated_session_expectation(
                captured_session_id.clone(),
                "sb-1",
                "agentenv-agent",
            ),
            tmux_set_generated_option_expectation(
                captured_session_id.clone(),
                TMUX_AGENTENV_HANDLE_OPTION,
                "sb-1",
            ),
            tmux_set_generated_option_expectation(
                captured_session_id.clone(),
                TMUX_AGENTENV_SESSION_NAME_OPTION,
                "demo.env",
            ),
            tmux_set_generated_option_expectation(
                captured_session_id.clone(),
                TMUX_AGENTENV_COMMAND_OPTION,
                "agentenv-agent",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner);

        let session = driver
            .create_session(CreateSessionParams {
                handle: "sb-1".to_owned(),
                name: "demo.env".to_owned(),
                command: "agentenv-agent".to_owned(),
                detached: false,
                metadata: BTreeMap::new(),
            })
            .await
            .unwrap();

        assert_eq!(
            captured_session_id
                .lock()
                .expect("captured session id mutex")
                .as_ref(),
            Some(&session.session_id)
        );
        assert!(session.session_id.starts_with("agentenv-sb-1-"));
        assert_eq!(session.name, "demo.env");
        assert_eq!(session.status, SessionStatus::Detached);
    }

    #[tokio::test]
    async fn openshell_attach_session_attaches_tmux_interactively() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            tmux_available_script(),
            tmux_owner_script("agentenv-sb-1-session", "sb-1"),
            tmux_attach_script("agentenv-sb-1-session"),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner);
        let result = driver
            .attach_session(AttachSessionParams {
                handle: "sb-1".to_owned(),
                session_id: "agentenv-sb-1-session".to_owned(),
            })
            .await
            .unwrap();

        assert_eq!(result.status, 0);
    }

    #[tokio::test]
    async fn openshell_create_session_reports_missing_tmux_capability() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![tmux_missing_script()]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let err = driver
            .create_session(CreateSessionParams {
                handle: "sb-1".to_owned(),
                name: "sh-1".to_owned(),
                command: "agentenv-agent".to_owned(),
                detached: true,
                metadata: BTreeMap::new(),
            })
            .await
            .expect_err("create_session should report missing tmux capability");

        assert_persistent_sessions_missing(err);
        assert_eq!(runner.calls().len(), 1);
    }

    #[tokio::test]
    async fn openshell_attach_session_reports_missing_tmux_capability() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![tmux_missing_script()]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let err = driver
            .attach_session(AttachSessionParams {
                handle: "sb-1".to_owned(),
                session_id: "sh-1".to_owned(),
            })
            .await
            .expect_err("attach_session should report missing tmux capability");

        assert_persistent_sessions_missing(err);
        assert_eq!(runner.calls().len(), 1);
        assert!(runner.status_calls().is_empty());
    }

    #[tokio::test]
    async fn openshell_list_sessions_reports_missing_tmux_capability() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![tmux_missing_script()]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let err = driver
            .list_sessions(ListSessionsParams {
                handle: "sb-1".to_owned(),
            })
            .await
            .expect_err("list_sessions should report missing tmux capability");

        assert_persistent_sessions_missing(err);
        assert_eq!(runner.calls().len(), 1);
    }

    #[tokio::test]
    async fn openshell_kill_session_reports_missing_tmux_capability() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![tmux_missing_script()]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let err = driver
            .kill_session(KillSessionParams {
                handle: "sb-1".to_owned(),
                session_id: "sh-1".to_owned(),
            })
            .await
            .expect_err("kill_session should report missing tmux capability");

        assert_persistent_sessions_missing(err);
        assert_eq!(runner.calls().len(), 1);
    }

    #[tokio::test]
    async fn openshell_rejects_invalid_session_names_before_running_commands() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        for name in ["", "bad name", "bad/session", "not-ascii-\u{e9}"] {
            let err = driver
                .create_session(CreateSessionParams {
                    handle: "sb-1".to_owned(),
                    name: name.to_owned(),
                    command: "agentenv-agent".to_owned(),
                    detached: true,
                    metadata: BTreeMap::new(),
                })
                .await
                .expect_err("create_session should reject invalid name");
            match err {
                agentenv_core::driver::DriverError::InvalidInput { message } => {
                    assert!(message.contains("session"));
                }
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }

        assert!(runner.calls().is_empty());
        assert!(runner.status_calls().is_empty());
    }

    #[tokio::test]
    async fn openshell_list_sessions_parses_tmux_rows_and_skips_malformed_rows() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            tmux_available_script(),
            tmux_list_sessions_script(
                "agentenv-sb-1-aaa\t0\t1714000000\tsb-1\tsh-1\tagentenv-agent\nagentenv-sb-1-bbb\t2\t1714000010\tsb-1\tsh_2\tagentenv-agent\nother\t0\t1714000015\tsb-2\tother\tagentenv-agent\nmalformed\nagentenv-sb-1-bad-count\tmany\t1714000020\tsb-1\tbad-count\tagentenv-agent\nbad/name\t0\t1714000030\tsb-1\tbad-name\tagentenv-agent\nagentenv-sb-1-bad-ts\t0\tnot-a-ts\tsb-1\tbad-ts\tagentenv-agent\nagentenv-sb-1-legacy\t0\t1714000040\tsb-1\t\tagentenv-agent\n",
                Some(0),
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner);

        let result = driver
            .list_sessions(ListSessionsParams {
                handle: "sb-1".to_owned(),
            })
            .await
            .expect("list_sessions");

        assert_eq!(result.sessions.len(), 3);
        assert_eq!(result.sessions[0].session_id, "agentenv-sb-1-aaa");
        assert_eq!(result.sessions[0].name, "sh-1");
        assert_eq!(result.sessions[0].status, SessionStatus::Detached);
        assert_eq!(result.sessions[0].command, "agentenv-agent");
        assert_eq!(result.sessions[0].created_at, "2024-04-24T23:06:40Z");
        assert_eq!(result.sessions[0].updated_at, "2024-04-24T23:06:40Z");
        assert_eq!(result.sessions[1].session_id, "agentenv-sb-1-bbb");
        assert_eq!(result.sessions[1].name, "sh_2");
        assert_eq!(result.sessions[1].status, SessionStatus::Attached);
        assert_eq!(result.sessions[1].created_at, "2024-04-24T23:06:50Z");
        assert_eq!(result.sessions[2].session_id, "agentenv-sb-1-legacy");
        assert_eq!(result.sessions[2].name, "agentenv-sb-1-legacy");
    }

    #[tokio::test]
    async fn openshell_list_sessions_treats_missing_tmux_server_as_empty() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            tmux_available_script(),
            tmux_list_sessions_script("", Some(1), "no server running on /tmp/tmux-1000/default"),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner);

        let result = driver
            .list_sessions(ListSessionsParams {
                handle: "sb-1".to_owned(),
            })
            .await
            .expect("list_sessions");

        assert!(result.sessions.is_empty());
    }

    #[tokio::test]
    async fn openshell_list_sessions_preserves_unrelated_command_errors() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            tmux_available_script(),
            tmux_list_sessions_script("", Some(2), "tmux failed to format sessions"),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner);

        let err = driver
            .list_sessions(ListSessionsParams {
                handle: "sb-1".to_owned(),
            })
            .await
            .expect_err("list_sessions should preserve unrelated command errors");

        assert!(matches!(
            err,
            agentenv_core::driver::DriverError::CommandFailed {
                status: Some(2),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn openshell_kill_session_uses_tmux_kill_session() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            tmux_available_script(),
            tmux_owner_script("agentenv-sb-1-session", "sb-1"),
            tmux_kill_script("agentenv-sb-1-session"),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        driver
            .kill_session(KillSessionParams {
                handle: "sb-1".to_owned(),
                session_id: "agentenv-sb-1-session".to_owned(),
            })
            .await
            .expect("kill_session");

        assert_eq!(runner.calls().len(), 3);
    }

    #[tokio::test]
    async fn openshell_attach_session_rejects_unowned_tmux_session() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            tmux_available_script(),
            tmux_owner_script("agentenv-sb-1-session", "sb-2"),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let err = driver
            .attach_session(AttachSessionParams {
                handle: "sb-1".to_owned(),
                session_id: "agentenv-sb-1-session".to_owned(),
            })
            .await
            .expect_err("attach_session should reject unowned tmux sessions");

        match err {
            agentenv_core::driver::DriverError::InvalidHandle { handle, message } => {
                assert_eq!(handle, "agentenv-sb-1-session");
                assert!(message.contains("not owned"));
            }
            other => panic!("expected InvalidHandle, got {other:?}"),
        }
        assert_eq!(runner.calls().len(), 2);
        assert!(runner.status_calls().is_empty());
    }

    #[tokio::test]
    async fn openshell_kill_session_rejects_unowned_tmux_session() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            tmux_available_script(),
            tmux_owner_script("agentenv-sb-1-session", "sb-2"),
        ]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let err = driver
            .kill_session(KillSessionParams {
                handle: "sb-1".to_owned(),
                session_id: "agentenv-sb-1-session".to_owned(),
            })
            .await
            .expect_err("kill_session should reject unowned tmux sessions");

        match err {
            agentenv_core::driver::DriverError::InvalidHandle { handle, message } => {
                assert_eq!(handle, "agentenv-sb-1-session");
                assert!(message.contains("not owned"));
            }
            other => panic!("expected InvalidHandle, got {other:?}"),
        }
        assert_eq!(runner.calls().len(), 2);
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
    async fn preflight_installs_missing_openshell_and_retries_with_local_runtime_path() {
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::error(
                "openshell",
                |call| assert_eq!(call.request.args, vec!["--version"]),
                io::ErrorKind::NotFound,
                "openshell was not found",
            ),
            FlexibleCommandExpectation::success(
                "sh",
                |call| {
                    assert_eq!(call.request.args[0], "-c");
                    assert!(call.request.args[1].contains(OPEN_SHELL_INSTALL_URL));
                    assert!(call.request.args[1].contains("OPENSHELL_INSTALL_DIR"));
                    assert!(call.request.env.contains_key("PATH"));
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                |call| assert_eq!(call.request.args, vec!["--version"]),
                "openshell 0.0.34",
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                |call| assert_eq!(call.request.args, vec!["status"]),
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "docker",
                |call| {
                    assert_eq!(
                        call.request.args,
                        vec!["info", "--format", "{{.ServerVersion}}"]
                    )
                },
                "29.4.0",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_host_command_runner(runner.clone());

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight");

        assert!(result.ok);
        assert!(result.issues.is_empty());
        assert_eq!(runner.calls().len(), 5);
    }

    #[tokio::test]
    async fn preflight_launches_configured_runtime_when_docker_is_not_ready() {
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "openshell",
                |call| assert_eq!(call.request.args, vec!["--version"]),
                "openshell 0.0.34",
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                |call| assert_eq!(call.request.args, vec!["status"]),
                "",
                "",
            ),
            FlexibleCommandExpectation::output(
                "docker",
                |call| {
                    assert_eq!(
                        call.request.args,
                        vec!["info", "--format", "{{.ServerVersion}}"]
                    )
                },
                Some(1),
                "",
                "Cannot connect to Docker daemon",
            ),
            FlexibleCommandExpectation::success(
                "open",
                |call| assert_eq!(call.request.args, vec!["-a", "OrbStack"]),
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "docker",
                |call| {
                    assert_eq!(
                        call.request.args,
                        vec!["info", "--format", "{{.ServerVersion}}"]
                    )
                },
                "29.4.0",
                "",
            ),
        ]));
        let driver =
            OpenShellDriver::with_host_command_runner_and_runtime_app(runner.clone(), "OrbStack");

        let result = driver
            .preflight(PreflightParams::default())
            .await
            .expect("preflight");

        assert!(result.ok);
        assert!(result.issues.is_empty());
        assert_eq!(runner.calls().len(), 5);
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
    async fn preflight_reports_status_failure() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::success("openshell", &["--version"], "openshell 0.0.31", ""),
            CommandScript::output(
                "openshell",
                &["status"],
                Some(1),
                "",
                "gateway status failed",
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
        assert!(issue.message.contains("gateway status failed"));
        assert_eq!(
            runner.calls(),
            vec![
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["--version"]),
                },
                CommandCall {
                    program: "openshell".to_owned(),
                    request: command_request(&["status"]),
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
                    "--no-auto-providers",
                    "--from",
                    "custom-image",
                    "--remote",
                    "tcp://sandbox.example",
                    "--",
                    "true",
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
                        "--no-auto-providers",
                        "--from",
                        "custom-image",
                        "--remote",
                        "tcp://sandbox.example",
                        "--",
                        "true",
                    ],
                    env
                ),
            }]
        );
    }

    #[test]
    fn create_reuses_valid_byo_build_cache() {
        let tempdir = unique_tempdir("sandbox-openshell-byo-cache-hit");
        let workdir = tempdir.join(".agentenv");
        let dockerfile_dir = tempdir.join("enterprise-sandbox");
        std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
        let dockerfile = dockerfile_dir.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write source Dockerfile");
        let key_stage_dir = workdir.join("build").join("devbox-key");
        super::stage_build_context(&dockerfile_dir, &dockerfile, &key_stage_dir)
            .expect("stage key context");
        let context_digest = super::build_cache::BuildCache::digest_staged_context(&key_stage_dir)
            .expect("context digest");
        let noop = agentenv_events::NoopEventEmitter;
        let cache = super::build_cache::BuildCache::new(workdir.clone(), &noop);
        let input = super::build_cache::BuildInput {
            env_name: "devbox".to_owned(),
            dockerfile: dockerfile.clone(),
            staged_context: key_stage_dir.clone(),
            context_digest: context_digest.clone(),
            expected_digest: None,
            agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            agent: "codex".to_owned(),
            mcp_port: "3333".to_owned(),
            workspace_mount: "/sandbox".to_owned(),
            seed: Some(
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_owned(),
            ),
        };
        let cache_key = cache.build_key(&input).expect("build key");
        let cache_dir = cache.cache_dir(&cache_key);
        let context_dir = cache_dir.join("context");
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");
        std::fs::rename(&key_stage_dir, &context_dir).expect("move staged context to cache");
        let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        std::fs::write(cache_dir.join("image-digest"), format!("{digest}\n"))
            .expect("write digest");
        std::fs::write(
            cache_dir.join("metadata.json"),
            serde_json::json!({
                "version": 1,
                "build_key": cache_key,
                "driver": "openshell",
                "driver_version": env!("CARGO_PKG_VERSION"),
                "image_ref": context_dir.display().to_string(),
                "image_digest": digest,
                "created_at": "2026-05-06T12:00:00Z",
                "source": {
                    "dockerfile": dockerfile.display().to_string(),
                    "context_digest": context_digest
                }
            })
            .to_string(),
        )
        .expect("write metadata");

        let tag = super::build_cache::tag_for_key(&cache_key);
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(
                        call.request.args,
                        vec![
                            "image".to_owned(),
                            "inspect".to_owned(),
                            "--format".to_owned(),
                            "{{.Id}}".to_owned(),
                            tag.to_owned(),
                        ]
                    );
                },
                &format!("{digest}\n"),
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                {
                    let context_arg = context_dir.display().to_string();
                    move |call| {
                        assert_eq!(
                            call.request,
                            command_request(&[
                                "sandbox",
                                "create",
                                "--name",
                                "devbox",
                                "--no-auto-providers",
                                "--from",
                                &context_arg,
                                "--",
                                "true",
                            ])
                        );
                    }
                },
                "",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: None,
                        metadata: BTreeMap::from([
                            ("name".to_owned(), json!("devbox")),
                            (
                                "byo_dockerfile".to_owned(),
                                json!(dockerfile.display().to_string()),
                            ),
                            ("agentenv_agent".to_owned(), json!("codex")),
                            ("agentenv_mcp_port".to_owned(), json!("3333")),
                            ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                            (
                                "agentenv_version".to_owned(),
                                json!(env!("CARGO_PKG_VERSION")),
                            ),
                            (
                                "agentenv_build_oneflight".to_owned(),
                                json!("byo-openshell-v1"),
                            ),
                            ("agentenv_build_seed_version".to_owned(), json!("1")),
                            (
                                "agentenv_build_seed".to_owned(),
                                json!(
                                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                ),
                            ),
                        ]),
                    })
                    .await
            })
            .expect("create");

        assert_eq!(runner.calls().len(), 2);
        assert_eq!(
            std::fs::read_to_string(workdir.join("build").join("devbox").join("image-digest"))
                .expect("per env digest"),
            format!("{digest}\n")
        );
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn create_ignores_malformed_byo_build_cache_metadata_and_builds() {
        let tempdir = unique_tempdir("sandbox-openshell-byo-cache-malformed");
        let workdir = tempdir.join(".agentenv");
        let dockerfile_dir = tempdir.join("enterprise-sandbox");
        std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
        let dockerfile = dockerfile_dir.join("Dockerfile");
        std::fs::write(
            &dockerfile,
            "FROM alpine:3.20\nARG AGENTENV_VERSION\nRUN test -n \"$AGENTENV_VERSION\"\n",
        )
        .expect("write source Dockerfile");
        std::fs::write(dockerfile_dir.join("internal-cli"), "demo").expect("write context file");
        let key_stage_dir = workdir.join("build").join("devbox-key");
        super::stage_build_context(&dockerfile_dir, &dockerfile, &key_stage_dir)
            .expect("stage key context");
        let context_digest = super::build_cache::BuildCache::digest_staged_context(&key_stage_dir)
            .expect("context digest");
        let noop = agentenv_events::NoopEventEmitter;
        let cache = super::build_cache::BuildCache::new(workdir.clone(), &noop);
        let input = super::build_cache::BuildInput {
            env_name: "devbox".to_owned(),
            dockerfile: dockerfile.clone(),
            staged_context: key_stage_dir.clone(),
            context_digest,
            expected_digest: None,
            agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            agent: "codex".to_owned(),
            mcp_port: "3333".to_owned(),
            workspace_mount: "/sandbox".to_owned(),
            seed: Some(
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_owned(),
            ),
        };
        let cache_key = cache.build_key(&input).expect("build key");
        let cache_dir = cache.cache_dir(&cache_key);
        std::fs::create_dir_all(cache_dir.join("context")).expect("create cache context");
        std::fs::write(cache_dir.join("metadata.json"), "{").expect("write malformed metadata");
        std::fs::write(
            cache_dir.join("image-digest"),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
        )
        .expect("write digest");
        std::fs::remove_dir_all(&key_stage_dir).expect("remove key stage setup");

        let stage_dir = workdir.join("build").join("devbox");
        let stage_dockerfile = stage_dir.join("Dockerfile");
        let stage_dir_arg = stage_dir.display().to_string();
        let tag = "agentenv-byo-devbox:latest";
        let digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let expected_build_args = vec![
            "build".to_owned(),
            "--file".to_owned(),
            stage_dockerfile.display().to_string(),
            "--tag".to_owned(),
            tag.to_owned(),
            "--build-arg".to_owned(),
            format!("AGENTENV_VERSION={}", env!("CARGO_PKG_VERSION")),
            "--build-arg".to_owned(),
            "AGENTENV_AGENT=codex".to_owned(),
            "--build-arg".to_owned(),
            "AGENTENV_MCP_PORT=3333".to_owned(),
            "--build-arg".to_owned(),
            "AGENTENV_WORKSPACE_MOUNT=/sandbox".to_owned(),
            stage_dir_arg.clone(),
        ];
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(call.request.args, expected_build_args);
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(
                        call.request.args,
                        vec![
                            "image".to_owned(),
                            "inspect".to_owned(),
                            "--format".to_owned(),
                            "{{.Id}}".to_owned(),
                            tag.to_owned(),
                        ]
                    );
                },
                &format!("{digest}\n"),
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                move |call| {
                    assert_eq!(
                        call.request,
                        command_request(&[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--no-auto-providers",
                            "--from",
                            &stage_dir_arg,
                            "--",
                            "true",
                        ])
                    );
                },
                "",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: None,
                        metadata: BTreeMap::from([
                            ("name".to_owned(), json!("devbox")),
                            (
                                "byo_dockerfile".to_owned(),
                                json!(dockerfile.display().to_string()),
                            ),
                            ("agentenv_agent".to_owned(), json!("codex")),
                            ("agentenv_mcp_port".to_owned(), json!("3333")),
                            ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                            (
                                "agentenv_version".to_owned(),
                                json!(env!("CARGO_PKG_VERSION")),
                            ),
                            (
                                "agentenv_build_seed".to_owned(),
                                json!(
                                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                ),
                            ),
                        ]),
                    })
                    .await
            })
            .expect("create");

        assert_eq!(runner.calls().len(), 3);
        assert_eq!(
            std::fs::read_to_string(stage_dir.join("image-digest")).expect("digest file"),
            format!("{digest}\n")
        );
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn create_ignores_tampered_byo_build_cache_context_and_builds() {
        let tempdir = unique_tempdir("sandbox-openshell-byo-cache-tampered-context");
        let workdir = tempdir.join(".agentenv");
        let dockerfile_dir = tempdir.join("enterprise-sandbox");
        std::fs::create_dir_all(&dockerfile_dir).expect("create source context");
        let dockerfile = dockerfile_dir.join("Dockerfile");
        std::fs::write(
            &dockerfile,
            "FROM alpine:3.20\nARG AGENTENV_VERSION\nRUN test -n \"$AGENTENV_VERSION\"\n",
        )
        .expect("write source Dockerfile");
        std::fs::write(dockerfile_dir.join("internal-cli"), "demo").expect("write context file");
        let key_stage_dir = workdir.join("build").join("devbox-key");
        super::stage_build_context(&dockerfile_dir, &dockerfile, &key_stage_dir)
            .expect("stage key context");
        let context_digest = super::build_cache::BuildCache::digest_staged_context(&key_stage_dir)
            .expect("context digest");
        let noop = agentenv_events::NoopEventEmitter;
        let cache = super::build_cache::BuildCache::new(workdir.clone(), &noop);
        let input = super::build_cache::BuildInput {
            env_name: "devbox".to_owned(),
            dockerfile: dockerfile.clone(),
            staged_context: key_stage_dir.clone(),
            context_digest: context_digest.clone(),
            expected_digest: None,
            agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            agent: "codex".to_owned(),
            mcp_port: "3333".to_owned(),
            workspace_mount: "/sandbox".to_owned(),
            seed: Some(
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_owned(),
            ),
        };
        let cache_key = cache.build_key(&input).expect("build key");
        let cache_dir = cache.cache_dir(&cache_key);
        let context_dir = cache_dir.join("context");
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");
        std::fs::rename(&key_stage_dir, &context_dir).expect("move staged context to cache");
        std::fs::write(context_dir.join("internal-cli"), "tampered").expect("tamper context");
        let cached_digest =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        std::fs::write(cache_dir.join("image-digest"), format!("{cached_digest}\n"))
            .expect("write digest");
        std::fs::write(
            cache_dir.join("metadata.json"),
            serde_json::json!({
                "version": 1,
                "build_key": cache_key,
                "driver": "openshell",
                "driver_version": env!("CARGO_PKG_VERSION"),
                "image_ref": context_dir.display().to_string(),
                "image_digest": cached_digest,
                "created_at": "2026-05-06T12:00:00Z",
                "source": {
                    "dockerfile": dockerfile.display().to_string(),
                    "context_digest": context_digest
                }
            })
            .to_string(),
        )
        .expect("write metadata");

        let stage_dir = workdir.join("build").join("devbox");
        let stage_dockerfile = stage_dir.join("Dockerfile");
        let stage_dir_arg = stage_dir.display().to_string();
        let tag = "agentenv-byo-devbox:latest";
        let digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let expected_build_args = vec![
            "build".to_owned(),
            "--file".to_owned(),
            stage_dockerfile.display().to_string(),
            "--tag".to_owned(),
            tag.to_owned(),
            "--build-arg".to_owned(),
            format!("AGENTENV_VERSION={}", env!("CARGO_PKG_VERSION")),
            "--build-arg".to_owned(),
            "AGENTENV_AGENT=codex".to_owned(),
            "--build-arg".to_owned(),
            "AGENTENV_MCP_PORT=3333".to_owned(),
            "--build-arg".to_owned(),
            "AGENTENV_WORKSPACE_MOUNT=/sandbox".to_owned(),
            stage_dir_arg.clone(),
        ];
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(call.request.args, expected_build_args);
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(
                        call.request.args,
                        vec![
                            "image".to_owned(),
                            "inspect".to_owned(),
                            "--format".to_owned(),
                            "{{.Id}}".to_owned(),
                            tag.to_owned(),
                        ]
                    );
                },
                &format!("{digest}\n"),
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                move |call| {
                    assert_eq!(
                        call.request,
                        command_request(&[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--no-auto-providers",
                            "--from",
                            &stage_dir_arg,
                            "--",
                            "true",
                        ])
                    );
                },
                "",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(async {
                driver
                    .create(SandboxSpec {
                        image: None,
                        env: BTreeMap::new(),
                        policy: None,
                        metadata: BTreeMap::from([
                            ("name".to_owned(), json!("devbox")),
                            (
                                "byo_dockerfile".to_owned(),
                                json!(dockerfile.display().to_string()),
                            ),
                            ("agentenv_agent".to_owned(), json!("codex")),
                            ("agentenv_mcp_port".to_owned(), json!("3333")),
                            ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                            (
                                "agentenv_version".to_owned(),
                                json!(env!("CARGO_PKG_VERSION")),
                            ),
                            (
                                "agentenv_build_seed".to_owned(),
                                json!(
                                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                ),
                            ),
                        ]),
                    })
                    .await
            })
            .expect("create");

        assert_eq!(runner.calls().len(), 3);
        assert_eq!(
            std::fs::read_to_string(stage_dir.join("image-digest")).expect("digest file"),
            format!("{digest}\n")
        );
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn staged_context_digest_changes_for_empty_directories() {
        let tempdir = unique_tempdir("sandbox-openshell-context-digest-empty-dir");
        let context_dir = tempdir.join("context");
        std::fs::create_dir_all(&context_dir).expect("create context");
        std::fs::write(context_dir.join("file.txt"), "demo").expect("write file");
        let before = super::build_cache::BuildCache::digest_staged_context(&context_dir)
            .expect("digest before");

        std::fs::create_dir(context_dir.join("empty-dir")).expect("create empty dir");
        let after = super::build_cache::BuildCache::digest_staged_context(&context_dir)
            .expect("digest after");

        assert_ne!(before, after);
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn create_builds_byo_dockerfile_and_uses_staged_context() {
        let tempdir = unique_tempdir("sandbox-openshell-byo-build");
        let context_dir = tempdir.join("enterprise-sandbox");
        std::fs::create_dir_all(&context_dir).expect("create context");
        let dockerfile = context_dir.join("Containerfile.agentenv");
        std::fs::write(
            &dockerfile,
            "FROM alpine:3.20\nARG AGENTENV_VERSION\nRUN test -n \"$AGENTENV_VERSION\"\n",
        )
        .expect("write Dockerfile");
        std::fs::write(context_dir.join("internal-cli"), "demo").expect("write context file");
        let workdir = tempdir.join(".agentenv");
        let stage_dir = workdir.join("build").join("devbox");
        let stage_dockerfile = stage_dir.join("Dockerfile");
        let stage_dir_arg = stage_dir.display().to_string();
        let tag = "agentenv-byo-devbox:latest";
        let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let expected_build_args = vec![
            "build".to_owned(),
            "--file".to_owned(),
            stage_dockerfile.display().to_string(),
            "--tag".to_owned(),
            tag.to_owned(),
            "--build-arg".to_owned(),
            format!("AGENTENV_VERSION={}", env!("CARGO_PKG_VERSION")),
            "--build-arg".to_owned(),
            "AGENTENV_AGENT=codex".to_owned(),
            "--build-arg".to_owned(),
            "AGENTENV_MCP_PORT=3333".to_owned(),
            "--build-arg".to_owned(),
            "AGENTENV_WORKSPACE_MOUNT=/sandbox".to_owned(),
            stage_dir_arg.clone(),
        ];
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(call.request.args, expected_build_args);
                },
                "",
                "",
            ),
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(
                        call.request.args,
                        vec![
                            "image".to_owned(),
                            "inspect".to_owned(),
                            "--format".to_owned(),
                            "{{.Id}}".to_owned(),
                            tag.to_owned(),
                        ]
                    );
                },
                &format!("{digest}\n"),
                "",
            ),
            FlexibleCommandExpectation::success(
                "openshell",
                move |call| {
                    assert_eq!(
                        call.request,
                        command_request(&[
                            "sandbox",
                            "create",
                            "--name",
                            "devbox",
                            "--no-auto-providers",
                            "--from",
                            &stage_dir_arg,
                            "--",
                            "true",
                        ])
                    );
                },
                "",
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

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
                        metadata: BTreeMap::from([
                            ("name".to_owned(), json!("devbox")),
                            (
                                "byo_dockerfile".to_owned(),
                                json!(dockerfile.display().to_string()),
                            ),
                            ("agentenv_agent".to_owned(), json!("codex")),
                            ("agentenv_mcp_port".to_owned(), json!("3333")),
                            ("agentenv_workspace_mount".to_owned(), json!("/sandbox")),
                            (
                                "agentenv_version".to_owned(),
                                json!(env!("CARGO_PKG_VERSION")),
                            ),
                        ]),
                    })
                    .await
            })
            .expect("create");

        assert_eq!(result.handle, "devbox");
        assert_eq!(runner.calls().len(), 3);
        assert_eq!(
            std::fs::read_to_string(&stage_dockerfile).expect("staged Dockerfile"),
            std::fs::read_to_string(&dockerfile).expect("source Dockerfile")
        );
        assert!(stage_dir.join("internal-cli").is_file());
        assert_eq!(
            std::fs::read_to_string(stage_dir.join("image-digest")).expect("digest file"),
            format!("{digest}\n")
        );
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[test]
    fn create_rejects_byo_dockerfile_digest_mismatch_before_openshell_create() {
        let tempdir = unique_tempdir("sandbox-openshell-byo-digest-mismatch");
        let context_dir = tempdir.join("enterprise-sandbox");
        std::fs::create_dir_all(&context_dir).expect("create context");
        let dockerfile = context_dir.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write Dockerfile");
        let workdir = tempdir.join(".agentenv");
        let tag = "agentenv-byo-devbox:latest";
        let actual = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let expected = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let runner = Arc::new(FlexibleCommandRunner::new(vec![
            FlexibleCommandExpectation::success("docker", |_| {}, "", ""),
            FlexibleCommandExpectation::success(
                "docker",
                move |call| {
                    assert_eq!(
                        call.request.args,
                        vec![
                            "image".to_owned(),
                            "inspect".to_owned(),
                            "--format".to_owned(),
                            "{{.Id}}".to_owned(),
                            tag.to_owned(),
                        ]
                    );
                },
                &format!("{actual}\n"),
                "",
            ),
        ]));
        let driver = OpenShellDriver::with_command_runner_and_workdir(runner.clone(), &workdir);

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
                        metadata: BTreeMap::from([
                            ("name".to_owned(), json!("devbox")),
                            (
                                "byo_dockerfile".to_owned(),
                                json!(dockerfile.display().to_string()),
                            ),
                            ("byo_expected_digest".to_owned(), json!(expected)),
                        ]),
                    })
                    .await
            })
            .expect_err("digest mismatch should reject create");

        assert!(err.to_string().contains("digest mismatch"));
        assert_eq!(runner.calls().len(), 2);
        assert!(!workdir
            .join("build")
            .join("devbox")
            .join("image-digest")
            .exists());
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
    }

    #[cfg(unix)]
    #[test]
    fn stage_build_context_honors_dockerignore_and_preserves_symlinks() {
        let tempdir = unique_tempdir("sandbox-openshell-stage-context");
        let context_dir = tempdir.join("enterprise-sandbox");
        std::fs::create_dir_all(context_dir.join("ignored-dir")).expect("create context");
        let dockerfile = context_dir.join("Containerfile.agentenv");
        std::fs::write(&dockerfile, "FROM alpine:3.20\n").expect("write Dockerfile");
        std::fs::write(
            context_dir.join(".dockerignore"),
            "secret.txt\nignored-dir\n*.log\n!keep.log\n",
        )
        .expect("write dockerignore");
        std::fs::write(context_dir.join("secret.txt"), "secret").expect("write secret");
        std::fs::write(context_dir.join("ignored-dir").join("hidden.txt"), "hidden")
            .expect("write ignored file");
        std::fs::write(context_dir.join("app.log"), "ignored").expect("write ignored log");
        std::fs::write(context_dir.join("keep.log"), "included").expect("write included log");
        std::fs::write(context_dir.join("real.txt"), "real").expect("write symlink target");
        std::os::unix::fs::symlink("real.txt", context_dir.join("linked-real"))
            .expect("create symlink");
        let stage_dir = tempdir.join(".agentenv").join("build").join("devbox");

        super::stage_build_context(&context_dir, &dockerfile, &stage_dir).expect("stage context");

        assert!(stage_dir.join("Dockerfile").is_file());
        assert!(stage_dir.join("keep.log").is_file());
        assert!(stage_dir.join("real.txt").is_file());
        assert!(!stage_dir.join("secret.txt").exists());
        assert!(!stage_dir.join("ignored-dir").join("hidden.txt").exists());
        assert!(!stage_dir.join("app.log").exists());
        assert!(std::fs::symlink_metadata(stage_dir.join("linked-real"))
            .expect("staged symlink metadata")
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_link(stage_dir.join("linked-real")).expect("staged symlink target"),
            PathBuf::from("real.txt")
        );
        std::fs::remove_dir_all(tempdir).expect("remove tempdir");
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
                "--no-auto-providers",
                "--from",
                "openclaw",
                "--",
                "true",
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
                &[
                    "sandbox", "exec", "--name", "sb-1", "--", "sh", "-lc", "echo hi",
                ],
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
                    &["sandbox", "exec", "--name", "sb-1", "--", "sh", "-lc", "echo hi",],
                    env,
                ),
            }]
        );
    }

    #[test]
    fn exec_with_tty_uses_interactive_status_path() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "openshell",
            &[
                "sandbox",
                "exec",
                "--name",
                "sb-1",
                "--",
                "sh",
                "-lc",
                "/usr/local/bin/agentenv-agent",
            ],
            Some(3),
            "",
            "",
        )]));
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
                        cmd: "/usr/local/bin/agentenv-agent".to_owned(),
                        tty: true,
                        env: BTreeMap::new(),
                    })
                    .await
            })
            .expect("exec");

        assert_eq!(result.status, 3);
        assert_eq!(result.stdout, "");
        assert_eq!(result.stderr, "");
        assert!(runner.calls().is_empty());
        assert_eq!(
            runner.status_calls(),
            vec![CommandCall {
                program: "openshell".to_owned(),
                request: command_request(&[
                    "sandbox",
                    "exec",
                    "--name",
                    "sb-1",
                    "--",
                    "sh",
                    "-lc",
                    "/usr/local/bin/agentenv-agent",
                ]),
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
    fn logs_stream_process_is_terminated_on_destroy() {
        let runner = Arc::new(StreamCleanupRunner::new());
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            driver
                .logs_stream(LogsStreamParams {
                    handle: "sb-1".to_owned(),
                    since: Some("2026-04-19T00:00:00Z".to_owned()),
                })
                .await
                .expect("logs_stream");
            assert_eq!(runner.terminations(), 0);

            driver
                .destroy(DestroyParams {
                    handle: "sb-1".to_owned(),
                })
                .await
                .expect("destroy");
        });

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
        assert_eq!(
            runner.calls(),
            vec![CommandCall {
                program: "openshell".to_owned(),
                request: command_request(&["sandbox", "delete", "sb-1"]),
            }]
        );
        assert_eq!(runner.terminations(), 1);
    }

    #[test]
    fn failed_log_stream_termination_is_reported_and_retained_for_retry() {
        let runner = Arc::new(StreamCleanupRunner::new_with_termination_failures(1));
        let mut driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            driver
                .logs_stream(LogsStreamParams {
                    handle: "sb-1".to_owned(),
                    since: None,
                })
                .await
                .expect("logs_stream");

            let err = driver
                .destroy(DestroyParams {
                    handle: "sb-1".to_owned(),
                })
                .await
                .expect_err("destroy should report log stream cleanup failure");
            match err {
                agentenv_core::driver::DriverError::CleanupFailed { message } => {
                    assert!(message.contains("terminate failed"));
                }
                other => panic!("expected CleanupFailed, got {other:?}"),
            }
            assert_eq!(runner.terminations(), 1);

            driver
                .shutdown(agentenv_proto::ShutdownParams::default())
                .await
                .expect("shutdown should retry retained log stream");
        });

        assert_eq!(runner.terminations(), 2);
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
    fn logs_rejects_follow_in_non_streaming_path() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::success(
            "openshell",
            &["logs", "sb-2", "--tail"],
            "",
            "",
        )]));
        let driver = OpenShellDriver::with_command_runner(runner.clone());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = runtime
            .block_on(async {
                driver
                    .logs(LogsParams {
                        handle: "sb-2".to_owned(),
                        since: None,
                        follow: true,
                    })
                    .await
            })
            .expect_err("follow logs should use logs_stream");

        match err {
            agentenv_core::driver::DriverError::InvalidInput { message } => {
                assert!(message.contains("logs_stream"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn semver_can_be_parsed_from_noisy_output() {
        let parsed = extract_semver_token("stderr: openshell build output v0.0.31+build.7 done")
            .expect("semver token");

        assert_eq!(parsed, Version::parse("0.0.31+build.7").expect("version"));
    }
}
