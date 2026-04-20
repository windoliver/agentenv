#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

#[cfg(test)]
use std::{collections::VecDeque, sync::Mutex};

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
    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<std::process::Child>;
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

    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<std::process::Child> {
        Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .spawn()
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
}

#[cfg(test)]
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

    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<std::process::Child> {
        panic!(
            "spawn was not expected in tests for program `{program}` with args {:?}",
            request.args
        );
    }
}

pub struct OpenShellDriver {
    binary: String,
    runner: Arc<dyn CommandRunner>,
    current_policies: BTreeMap<String, NetworkPolicy>,
}

impl Default for OpenShellDriver {
    fn default() -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner: Arc::new(ProcessCommandRunner),
            current_policies: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
impl OpenShellDriver {
    fn with_command_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            binary: OPEN_SHELL_BINARY.to_owned(),
            runner,
            current_policies: BTreeMap::new(),
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
        let version_output = match self.run_command(&["--version"]) {
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

        let gateway_output = match self.run_command(&["gateway", "status"]) {
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
        Err(invalid_input("create"))
    }

    async fn connect(&self, _params: ConnectParams) -> DriverResult<ShellHandle> {
        Err(invalid_input("connect"))
    }

    async fn exec(&self, _params: ExecParams) -> DriverResult<ExecResult> {
        Err(invalid_input("exec"))
    }

    async fn copy_in(&self, _params: CopyInParams) -> DriverResult<EmptyResult> {
        Err(invalid_input("copy_in"))
    }

    async fn copy_out(&self, _params: CopyOutParams) -> DriverResult<EmptyResult> {
        Err(invalid_input("copy_out"))
    }

    async fn apply_policy(&self, _params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult> {
        Err(invalid_input("apply_policy"))
    }

    async fn status(&self, _params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        Err(invalid_input("status"))
    }

    async fn logs(&self, _params: LogsParams) -> DriverResult<LogsResult> {
        Err(invalid_input("logs"))
    }

    async fn logs_stream(&self, _params: LogsStreamParams) -> DriverResult<EmptyResult> {
        Err(invalid_input("logs_stream"))
    }

    async fn stop(&self, _params: StopParams) -> DriverResult<EmptyResult> {
        Err(invalid_input("stop"))
    }

    async fn destroy(&self, _params: DestroyParams) -> DriverResult<EmptyResult> {
        Err(invalid_input("destroy"))
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        self.current_policies.clear();
        Ok(EmptyResult::default())
    }
}

impl OpenShellDriver {
    fn run_command(&self, args: &[&str]) -> io::Result<CommandOutput> {
        self.runner.run(&self.binary, &command_request(args))
    }
}

fn command_request(args: &[&str]) -> CommandRequest {
    CommandRequest {
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env: BTreeMap::new(),
    }
}

fn invalid_input(method: &str) -> DriverError {
    DriverError::InvalidInput {
        message: format!("openshell {method} is not implemented yet"),
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
    use std::{io, sync::Arc};

    use agentenv_core::driver::SandboxDriver;
    use agentenv_proto::{
        Capabilities, DriverKind, InitializeParams, LogLevel, PreflightParams, SCHEMA_VERSION,
    };
    use semver::Version;

    use super::{
        command_request, extract_semver_token, CommandCall, CommandScript, OpenShellDriver,
        RecordingCommandRunner,
    };

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
    fn semver_can_be_parsed_from_noisy_output() {
        let parsed = extract_semver_token("stderr: openshell build output v0.0.31+build.7 done")
            .expect("semver token");

        assert_eq!(parsed, Version::parse("0.0.31+build.7").expect("version"));
    }
}
