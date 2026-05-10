#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

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
const REMOTE_ENV_DIR: &str = "/sandbox/.agentenv/env";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandRequest {
    args: Vec<String>,
    env: BTreeMap<String, String>,
    stdin: Option<String>,
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
        let mut command = Command::new(program);
        command.args(&request.args).envs(&request.env);
        if request.stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(stdin) = request.stdin.as_deref() {
            let mut child_stdin = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stdin unavailable"))?;
            if let Err(err) = child_stdin.write_all(stdin.as_bytes()) {
                let _ = child.wait();
                return Err(err);
            }
        }
        let output = child.wait_with_output()?;
        Ok(CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn status(&self, program: &str, request: &CommandRequest) -> io::Result<Option<i32>> {
        debug_assert!(request.stdin.is_none());
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
        stdin: None,
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

fn target_arg(target: &RemoteSshTarget) -> String {
    format!("{}@{}", target.user, target.host)
}

fn ssh_base_args(target: &RemoteSshTarget) -> Vec<String> {
    let mut args = vec![
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=10".to_owned(),
        "-o".to_owned(),
        "ServerAliveInterval=15".to_owned(),
        "-o".to_owned(),
        "ServerAliveCountMax=2".to_owned(),
        "-p".to_owned(),
        target.port.to_string(),
    ];
    if let Some(identity_file) = target.identity_file.as_deref() {
        args.push("-i".to_owned());
        args.push(identity_file.to_owned());
    }
    if let Some(jump_host) = target.jump_host.as_deref() {
        args.push("-J".to_owned());
        args.push(jump_host.to_owned());
    }
    args.push(target_arg(target));
    args
}

fn remote_shell_command(
    cmd: &str,
    env_file: Option<&str>,
    env: &BTreeMap<String, String>,
) -> DriverResult<String> {
    for key in env.keys() {
        validate_remote_env_key(key)?;
    }
    if let Some(env_file) = env_file {
        validate_remote_env_file_path(env_file)?;
    }

    let mut prefix = "cd /sandbox".to_owned();
    if let Some(env_file) = env_file {
        prefix.push_str(" && . ");
        prefix.push_str(&shell_single_quote(env_file));
    }

    if env.is_empty() {
        return Ok(format!("{prefix} && {cmd}"));
    }

    let assignments = env
        .iter()
        .map(|(key, value)| format!("{key}={}", shell_single_quote(value)))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!(
        "{prefix} && env {assignments} sh -lc {}",
        shell_single_quote(cmd)
    ))
}

fn validate_remote_env_key(key: &str) -> DriverResult<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(DriverError::InvalidInput {
            message: "env. is not a valid remote environment variable name".to_owned(),
        });
    };
    let valid_first = first.is_ascii_alphabetic() || first == '_';
    let valid_rest = chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    if !valid_first || !valid_rest {
        return Err(DriverError::InvalidInput {
            message: format!("env.{key} is not a valid remote environment variable name"),
        });
    }

    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn remote_env_file_content(env: &BTreeMap<String, String>) -> DriverResult<String> {
    let mut content = String::new();
    for (key, value) in env {
        validate_remote_env_key(key)?;
        content.push_str("export ");
        content.push_str(key);
        content.push('=');
        content.push_str(&shell_single_quote(value));
        content.push('\n');
    }
    Ok(content)
}

fn remote_env_file_path(name: &str) -> DriverResult<String> {
    validate_remote_env_name(name)?;
    Ok(format!("{REMOTE_ENV_DIR}/{name}.env"))
}

fn validate_remote_env_name(name: &str) -> DriverResult<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.starts_with('-')
        || name
            .chars()
            .any(|ch| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-' | '.'))
    {
        return Err(DriverError::InvalidInput {
            message: "metadata.name contains unsupported characters for a remote env file"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_remote_env_file_path(path: &str) -> DriverResult<()> {
    let Some(name) = path.strip_prefix("/sandbox/.agentenv/env/") else {
        return Err(DriverError::InvalidInput {
            message: "remote-ssh env_file must be under /sandbox/.agentenv/env".to_owned(),
        });
    };
    let Some(name) = name.strip_suffix(".env") else {
        return Err(DriverError::InvalidInput {
            message: "remote-ssh env_file must end with .env".to_owned(),
        });
    };
    validate_remote_env_name(name)
}

fn remote_ssh_command(shell_body: &str) -> String {
    format!("sh -lc {}", shell_single_quote(shell_body))
}

fn scp_base_args(target: &RemoteSshTarget) -> Vec<String> {
    let mut args = vec!["-P".to_owned(), target.port.to_string()];
    if let Some(identity_file) = target.identity_file.as_deref() {
        args.push("-i".to_owned());
        args.push(identity_file.to_owned());
    }
    if let Some(jump_host) = target.jump_host.as_deref() {
        args.push("-J".to_owned());
        args.push(jump_host.to_owned());
    }
    args
}

fn remote_path(target: &RemoteSshTarget, path: &str) -> String {
    format!("{}:{path}", target_arg(target))
}

fn validate_host_copy_path(field: &str, path: &str) -> DriverResult<()> {
    if path.is_empty() {
        return Err(DriverError::InvalidInput {
            message: format!("{field} must not be empty"),
        });
    }
    if path.starts_with('-') {
        return Err(DriverError::InvalidInput {
            message: format!("{field} must not start with '-'"),
        });
    }
    if path.contains(':') {
        return Err(DriverError::InvalidInput {
            message: format!("{field} must not contain ':'"),
        });
    }

    Ok(())
}

fn validate_sandbox_copy_path(field: &str, path: &str) -> DriverResult<()> {
    let inside_sandbox = path == "/sandbox" || path.starts_with("/sandbox/");
    let valid_chars = path
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-'));
    let has_parent_component = path.split('/').any(|component| component == "..");
    if !inside_sandbox || !valid_chars || has_parent_component {
        return Err(DriverError::InvalidInput {
            message: format!("{field} must be a conservative path under /sandbox"),
        });
    }

    Ok(())
}

fn ssh_request(target: &RemoteSshTarget, remote_args: &[&str]) -> CommandRequest {
    let mut args = ssh_base_args(target);
    args.push("--".to_owned());
    args.extend(remote_args.iter().map(|arg| (*arg).to_owned()));
    CommandRequest {
        args,
        env: BTreeMap::new(),
        stdin: None,
    }
}

fn command_string(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_failed(program: &str, request: &CommandRequest, output: CommandOutput) -> DriverError {
    DriverError::CommandFailed {
        command: command_string(program, &request.args),
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn ensure_identity_file_exists(target: &RemoteSshTarget) -> DriverResult<()> {
    let Some(path) = target.identity_file.as_deref() else {
        return Ok(());
    };
    let path = std::path::Path::new(path);
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.identity_file `{}` is not a file", path.display()),
        }),
        Err(source) => Err(DriverError::InvalidInput {
            message: format!(
                "metadata.identity_file `{}` is not readable: {source}",
                path.display()
            ),
        }),
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
    env_file: Option<String>,
    enforce_remote_firewall: bool,
}

impl RemoteSshTarget {
    fn from_metadata(metadata: &BTreeMap<String, Value>) -> DriverResult<Self> {
        let host = required_metadata_string(metadata, "host")?;
        validate_remote_ssh_host(&host, "metadata.host")?;
        let user = required_metadata_string(metadata, "user")?;
        validate_remote_ssh_user(&user, "metadata.user")?;
        let port = metadata_port(metadata)?;
        let identity_file =
            optional_metadata_string(metadata, "identity_file")?.map(expand_leading_home);
        let jump_host = optional_metadata_string(metadata, "jump_host")?;
        if let Some(jump_host) = jump_host.as_deref() {
            validate_remote_ssh_host(jump_host, "metadata.jump_host")?;
        }
        let env_file = optional_metadata_string(metadata, "name")?
            .map(|name| remote_env_file_path(&name))
            .transpose()?;
        let enforce_remote_firewall =
            optional_metadata_bool(metadata, "enforce_remote_firewall")?.unwrap_or(false);

        Ok(Self {
            host,
            user,
            port,
            identity_file,
            jump_host,
            env_file,
            enforce_remote_firewall,
        })
    }

    fn to_handle(&self) -> DriverResult<String> {
        validate_remote_ssh_user(&self.user, "remote-ssh username")?;
        validate_remote_ssh_host(&self.host, "remote-ssh host")?;
        if let Some(jump_host) = self.jump_host.as_deref() {
            validate_remote_ssh_host(jump_host, "jump_host")?;
        }
        let base = format!("remote-ssh://{}@{}:{}", self.user, self.host, self.port);
        let mut url = Url::parse(&base).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to build remote-ssh handle: {source}"),
        })?;
        if self.identity_file.is_some() || self.jump_host.is_some() || self.env_file.is_some() {
            let mut pairs = url.query_pairs_mut();
            if let Some(identity_file) = self.identity_file.as_deref() {
                pairs.append_pair("identity_file", identity_file);
            }
            if let Some(jump_host) = self.jump_host.as_deref() {
                pairs.append_pair("jump_host", jump_host);
            }
            if let Some(env_file) = self.env_file.as_deref() {
                pairs.append_pair("env_file", env_file);
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
        if !url.path().is_empty() {
            return Err(invalid_handle(
                handle.to_owned(),
                "remote-ssh handles do not support a path",
            ));
        }
        if url.fragment().is_some() {
            return Err(invalid_handle(
                handle.to_owned(),
                "remote-ssh handles do not support a fragment",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| invalid_handle(handle.to_owned(), "missing host"))?
            .to_owned();
        validate_remote_ssh_host(&host, "handle host")
            .map_err(|err| invalid_handle(handle.to_owned(), err.to_string()))?;
        let user = url.username();
        if user.is_empty() {
            return Err(invalid_handle(handle.to_owned(), "missing user"));
        }
        validate_remote_ssh_user(user, "handle username")
            .map_err(|err| invalid_handle(handle.to_owned(), err.to_string()))?;
        let mut identity_file = None;
        let mut jump_host = None;
        let mut env_file = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "identity_file" => identity_file = Some(value.into_owned()),
                "jump_host" => {
                    let value = value.into_owned();
                    validate_remote_ssh_host(&value, "jump_host")
                        .map_err(|err| invalid_handle(handle.to_owned(), err.to_string()))?;
                    jump_host = Some(value);
                }
                "env_file" => {
                    let value = value.into_owned();
                    validate_remote_env_file_path(&value)
                        .map_err(|err| invalid_handle(handle.to_owned(), err.to_string()))?;
                    env_file = Some(value);
                }
                _ => {
                    return Err(invalid_handle(
                        handle.to_owned(),
                        format!("unsupported remote-ssh handle query key `{key}`"),
                    ));
                }
            }
        }
        let port = url.port().unwrap_or(22);
        if port == 0 {
            return Err(invalid_handle(
                handle.to_owned(),
                "port must be in range 1..=65535",
            ));
        }

        Ok(Self {
            host,
            user: user.to_owned(),
            port,
            identity_file,
            jump_host,
            env_file,
            enforce_remote_firewall: false,
        })
    }
}

fn validate_remote_ssh_user(user: &str, label: &str) -> DriverResult<()> {
    if user.is_empty()
        || user.starts_with('-')
        || !user.chars().all(is_supported_remote_ssh_user_char)
    {
        return Err(DriverError::InvalidInput {
            message: format!("{label} contains unsupported characters"),
        });
    }

    Ok(())
}

fn is_supported_remote_ssh_user_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')
}

fn validate_remote_ssh_host(host: &str, label: &str) -> DriverResult<()> {
    let valid_chars = host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'));
    let valid_shape = !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'));

    if !valid_chars || !valid_shape {
        return Err(DriverError::InvalidInput {
            message: format!("{label} contains unsupported characters or label syntax"),
        });
    }

    Ok(())
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
                supports_dns_egress_control: false,
                supports_snapshots: false,
                supports_fork: false,
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
        if target.enforce_remote_firewall || spec.policy.is_some() {
            return Err(policy_missing());
        }
        if !spec.env.is_empty() && target.env_file.is_none() {
            return Err(DriverError::InvalidInput {
                message: "metadata.name is required when SandboxSpec.env is non-empty".to_owned(),
            });
        }
        let env_file_content = remote_env_file_content(&spec.env)?;
        ensure_identity_file_exists(&target)?;

        for remote_command in [
            "true".to_owned(),
            remote_ssh_command("mkdir -p /sandbox/.agentenv/bin && test -w /sandbox"),
        ] {
            let request = ssh_request(&target, &[remote_command.as_str()]);
            let output = self
                .runner
                .run(&self.ssh_binary, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(&self.ssh_binary, &request.args),
                    source,
                })?;
            if output.status != Some(0) {
                return Err(command_failed(&self.ssh_binary, &request, output));
            }
        }

        if let Some(env_file) = target.env_file.as_deref() {
            let quoted_env_file = shell_single_quote(env_file);
            let remote_command = remote_ssh_command(&format!(
                "mkdir -p {REMOTE_ENV_DIR} && umask 077 && cat > {quoted_env_file} && chmod 600 {quoted_env_file}"
            ));
            let mut request = ssh_request(&target, &[remote_command.as_str()]);
            request.stdin = Some(env_file_content);
            let output = self
                .runner
                .run(&self.ssh_binary, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(&self.ssh_binary, &request.args),
                    source,
                })?;
            if output.status != Some(0) {
                return Err(command_failed(&self.ssh_binary, &request, output));
            }
        }

        Ok(SandboxHandle {
            handle: target.to_handle()?,
        })
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        let target = RemoteSshTarget::from_handle(&params.handle)?;
        let request = ssh_request(&target, &["true"]);
        let output = self
            .runner
            .run(&self.ssh_binary, &request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string(&self.ssh_binary, &request.args),
                source,
            })?;
        if output.status != Some(0) {
            return Err(command_failed(&self.ssh_binary, &request, output));
        }

        Ok(ShellHandle {
            session_id: params.handle,
            tty: true,
            working_dir: Some("/sandbox".to_owned()),
        })
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
        let target = RemoteSshTarget::from_handle(&params.handle)?;
        let remote_cmd =
            remote_shell_command(&params.cmd, target.env_file.as_deref(), &params.env)?;
        let request = CommandRequest {
            args: {
                let mut args = ssh_base_args(&target);
                if params.tty {
                    args.insert(args.len() - 1, "-tt".to_owned());
                }
                args.push("--".to_owned());
                args.push(remote_ssh_command(&remote_cmd));
                args
            },
            env: BTreeMap::new(),
            stdin: None,
        };
        let command = command_string(&self.ssh_binary, &request.args);

        if params.tty {
            let status = self
                .runner
                .status(&self.ssh_binary, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                })?;
            return Ok(ExecResult {
                status: status.unwrap_or(1),
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        let output = self
            .runner
            .run(&self.ssh_binary, &request)
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
        let target = RemoteSshTarget::from_handle(&params.handle)?;
        validate_host_copy_path("src_host_path", &params.src_host_path)?;
        validate_sandbox_copy_path("dst_sandbox_path", &params.dst_sandbox_path)?;
        let mut args = scp_base_args(&target);
        args.push("--".to_owned());
        args.push(params.src_host_path);
        args.push(remote_path(&target, &params.dst_sandbox_path));
        let request = CommandRequest {
            args,
            env: BTreeMap::new(),
            stdin: None,
        };
        let output = self
            .runner
            .run(&self.scp_binary, &request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string(&self.scp_binary, &request.args),
                source,
            })?;
        if output.status != Some(0) {
            return Err(command_failed(&self.scp_binary, &request, output));
        }

        Ok(EmptyResult::default())
    }

    async fn copy_out(&self, params: CopyOutParams) -> DriverResult<EmptyResult> {
        let target = RemoteSshTarget::from_handle(&params.handle)?;
        validate_sandbox_copy_path("src_sandbox_path", &params.src_sandbox_path)?;
        validate_host_copy_path("dst_host_path", &params.dst_host_path)?;
        let mut args = scp_base_args(&target);
        args.push("--".to_owned());
        args.push(remote_path(&target, &params.src_sandbox_path));
        args.push(params.dst_host_path);
        let request = CommandRequest {
            args,
            env: BTreeMap::new(),
            stdin: None,
        };
        let output = self
            .runner
            .run(&self.scp_binary, &request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string(&self.scp_binary, &request.args),
                source,
            })?;
        if output.status != Some(0) {
            return Err(command_failed(&self.scp_binary, &request, output));
        }

        Ok(EmptyResult::default())
    }

    async fn apply_policy(&self, _params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult> {
        Err(policy_missing())
    }

    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        let target = RemoteSshTarget::from_handle(&params.handle)?;
        let request = ssh_request(&target, &["true"]);
        let output = self
            .runner
            .run(&self.ssh_binary, &request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string(&self.ssh_binary, &request.args),
                source,
            })?;
        let healthy = output.status == Some(0);
        Ok(SandboxStatus {
            phase: if healthy {
                agentenv_proto::SandboxPhase::Running
            } else {
                agentenv_proto::SandboxPhase::Error
            },
            healthy,
            last_ping: None,
        })
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

    use agentenv_core::driver::{DriverError, SandboxDriver};
    use agentenv_proto::{
        Capabilities, ConnectParams, CopyInParams, CopyOutParams, DriverKind, ExecParams,
        FilesystemPolicy, InferencePolicy, InitializeParams, LogLevel, NetworkAccessPolicy,
        NetworkPolicy, PolicyReloadability, PreflightParams, ProcessPolicy, SandboxSpec,
        SandboxStatusParams, SCHEMA_VERSION,
    };

    use serde_json::json;

    use super::{RemoteSshDriver, RemoteSshTarget, POLICY_CAPABILITY};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CommandRequest {
        args: Vec<String>,
        env: BTreeMap<String, String>,
        stdin: Option<String>,
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
            stdin: None,
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

        fn output_with_stdin(
            program: &str,
            args: &[&str],
            stdin: &str,
            status: Option<i32>,
            stdout: &str,
            stderr: &str,
        ) -> Self {
            Self {
                program: program.to_owned(),
                request: CommandRequest {
                    args: args.iter().map(|arg| (*arg).to_owned()).collect(),
                    env: BTreeMap::new(),
                    stdin: Some(stdin.to_owned()),
                },
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
                    stdin: request.stdin.clone(),
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
            assert_eq!(script.request.stdin, request.stdin);
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
        assert_eq!(target.env_file, None);
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
    fn target_from_metadata_derives_env_file_from_env_name() {
        let metadata = BTreeMap::from([
            ("name".to_owned(), json!("demo")),
            ("host".to_owned(), json!("dev-vm.example.com")),
            ("user".to_owned(), json!("alice")),
        ]);

        let target = RemoteSshTarget::from_metadata(&metadata).expect("target");

        assert_eq!(
            target.env_file.as_deref(),
            Some("/sandbox/.agentenv/env/demo.env")
        );
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
    fn target_from_metadata_rejects_non_conservative_username_characters() {
        let metadata = BTreeMap::from([
            ("host".to_owned(), json!("dev-vm.example.com")),
            ("user".to_owned(), json!("a;b")),
        ]);

        let err = RemoteSshTarget::from_metadata(&metadata).expect_err("metadata should fail");

        assert!(err.to_string().contains("metadata.user"));
    }

    #[test]
    fn target_from_metadata_rejects_option_shaped_username() {
        let metadata = BTreeMap::from([
            ("host".to_owned(), json!("dev-vm.example.com")),
            ("user".to_owned(), json!("-Jbastion")),
        ]);

        let err = RemoteSshTarget::from_metadata(&metadata).expect_err("metadata should fail");

        assert!(err.to_string().contains("metadata.user"));
    }

    #[test]
    fn target_from_metadata_rejects_host_delimiters() {
        for host in [
            "dev-vm.example.com?identity_file=/tmp/key",
            "alice@dev-vm.example.com",
        ] {
            let metadata = BTreeMap::from([
                ("host".to_owned(), json!(host)),
                ("user".to_owned(), json!("alice")),
            ]);

            let err = RemoteSshTarget::from_metadata(&metadata).expect_err("metadata should fail");

            assert!(err.to_string().contains("metadata.host"));
        }
    }

    #[test]
    fn target_from_metadata_rejects_invalid_jump_host() {
        for jump_host in ["user@bastion.example.com", "bastion:2222"] {
            let metadata = BTreeMap::from([
                ("host".to_owned(), json!("dev-vm.example.com")),
                ("user".to_owned(), json!("alice")),
                ("jump_host".to_owned(), json!(jump_host)),
            ]);

            let err = RemoteSshTarget::from_metadata(&metadata).expect_err("metadata should fail");

            assert!(err.to_string().contains("metadata.jump_host"));
        }
    }

    #[test]
    fn uri_handle_round_trips_target_fields() {
        let target = RemoteSshTarget {
            host: "dev-vm.example.com".to_owned(),
            user: "alice".to_owned(),
            port: 2222,
            identity_file: Some("/Users/alice/.ssh/id_ed25519".to_owned()),
            jump_host: Some("bastion.example.com".to_owned()),
            env_file: Some("/sandbox/.agentenv/env/demo.env".to_owned()),
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
            env_file: None,
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
    fn uri_handle_rejects_option_shaped_username() {
        let err = RemoteSshTarget::from_handle("remote-ssh://-Jbastion@dev-vm.example.com:22")
            .expect_err("handle should fail");

        assert!(err.to_string().contains("username"));
    }

    #[test]
    fn uri_handle_rejects_percent_encoded_username_characters() {
        let err = RemoteSshTarget::from_handle("remote-ssh://a%3Bb@dev-vm.example.com:22")
            .expect_err("handle should fail");

        assert!(err.to_string().contains("username"));
    }

    #[test]
    fn uri_handle_rejects_invalid_host_labels() {
        let err = RemoteSshTarget::from_handle("remote-ssh://alice@-dev-vm.example.com:22")
            .expect_err("handle should fail");

        assert!(err.to_string().contains("host"));
    }

    #[test]
    fn uri_handle_rejects_port_zero() {
        let err = RemoteSshTarget::from_handle("remote-ssh://alice@dev-vm.example.com:0")
            .expect_err("handle should fail");

        assert!(err.to_string().contains("port"));
    }

    #[test]
    fn uri_handle_rejects_invalid_jump_host_query() {
        let err = RemoteSshTarget::from_handle(
            "remote-ssh://alice@dev-vm.example.com:22?jump_host=-bastion.example.com",
        )
        .expect_err("handle should fail");

        assert!(err.to_string().contains("jump_host"));
    }

    #[test]
    fn uri_handle_rejects_invalid_jump_host_before_serializing() {
        let target = RemoteSshTarget {
            host: "dev-vm.example.com".to_owned(),
            user: "alice".to_owned(),
            port: 22,
            identity_file: None,
            jump_host: Some("bastion:2222".to_owned()),
            env_file: None,
            enforce_remote_firewall: false,
        };

        let err = target.to_handle().expect_err("handle should fail");

        assert!(err.to_string().contains("jump_host"));
    }

    #[test]
    fn uri_handle_rejects_unknown_query_keys() {
        let err = RemoteSshTarget::from_handle(
            "remote-ssh://alice@dev-vm.example.com:22?password=secret",
        )
        .expect_err("handle should fail");

        assert!(err.to_string().contains("query") || err.to_string().contains("password"));
    }

    #[test]
    fn uri_handle_rejects_path_and_fragment() {
        for (handle, expected) in [
            ("remote-ssh://alice@dev-vm.example.com:22/tmp", "path"),
            ("remote-ssh://alice@dev-vm.example.com:22#frag", "fragment"),
        ] {
            let err = RemoteSshTarget::from_handle(handle).expect_err("handle should fail");

            assert!(err.to_string().contains(expected));
        }
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

    #[tokio::test]
    async fn create_probes_remote_and_returns_uri_handle() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::output(
                "ssh",
                &[
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "ServerAliveInterval=15",
                    "-o",
                    "ServerAliveCountMax=2",
                    "-p",
                    "2222",
                    "-J",
                    "bastion.example.com",
                    "alice@dev-vm.example.com",
                    "--",
                    "true",
                ],
                Some(0),
                "",
                "",
            ),
            CommandScript::output(
                "ssh",
                &[
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "ServerAliveInterval=15",
                    "-o",
                    "ServerAliveCountMax=2",
                    "-p",
                    "2222",
                    "-J",
                    "bastion.example.com",
                    "alice@dev-vm.example.com",
                    "--",
                    "sh -lc 'mkdir -p /sandbox/.agentenv/bin && test -w /sandbox'",
                ],
                Some(0),
                "",
                "",
            ),
        ]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let handle = driver
            .create(SandboxSpec {
                image: None,
                env: BTreeMap::new(),
                policy: None,
                metadata: BTreeMap::from([
                    ("host".to_owned(), json!("dev-vm.example.com")),
                    ("user".to_owned(), json!("alice")),
                    ("port".to_owned(), json!(2222)),
                    ("jump_host".to_owned(), json!("bastion.example.com")),
                ]),
            })
            .await
            .expect("create remote ssh sandbox")
            .handle;

        assert!(handle.starts_with("remote-ssh://alice@dev-vm.example.com:2222"));
        assert!(handle.contains("jump_host=bastion.example.com"));
        assert_eq!(runner.calls().len(), 2);
    }

    #[tokio::test]
    async fn create_rejects_remote_firewall_before_running_ssh() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let err = driver
            .create(SandboxSpec {
                image: None,
                env: BTreeMap::new(),
                policy: None,
                metadata: BTreeMap::from([
                    ("host".to_owned(), json!("dev-vm.example.com")),
                    ("user".to_owned(), json!("alice")),
                    ("enforce_remote_firewall".to_owned(), json!(true)),
                ]),
            })
            .await
            .expect_err("firewall enforcement is not supported");

        match err {
            DriverError::CapabilityMissing { capability } => {
                assert_eq!(capability, POLICY_CAPABILITY)
            }
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn create_rejects_policy_before_running_ssh() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::output("ssh", &["unused"], Some(0), "", ""),
            CommandScript::output("ssh", &["unused"], Some(0), "", ""),
        ]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let err = driver
            .create(SandboxSpec {
                image: None,
                env: BTreeMap::new(),
                policy: Some(sample_policy()),
                metadata: BTreeMap::from([
                    ("host".to_owned(), json!("dev-vm.example.com")),
                    ("user".to_owned(), json!("alice")),
                ]),
            })
            .await
            .expect_err("remote ssh must not silently accept unenforced policies");

        match err {
            DriverError::CapabilityMissing { capability } => {
                assert_eq!(capability, POLICY_CAPABILITY)
            }
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn create_writes_spec_env_and_returns_env_file_handle() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::output(
                "ssh",
                &[
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "ServerAliveInterval=15",
                    "-o",
                    "ServerAliveCountMax=2",
                    "-p",
                    "22",
                    "alice@dev-vm.example.com",
                    "--",
                    "true",
                ],
                Some(0),
                "",
                "",
            ),
            CommandScript::output(
                "ssh",
                &[
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "ServerAliveInterval=15",
                    "-o",
                    "ServerAliveCountMax=2",
                    "-p",
                    "22",
                    "alice@dev-vm.example.com",
                    "--",
                    "sh -lc 'mkdir -p /sandbox/.agentenv/bin && test -w /sandbox'",
                ],
                Some(0),
                "",
                "",
            ),
            CommandScript::output_with_stdin(
                "ssh",
                &[
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "ServerAliveInterval=15",
                    "-o",
                    "ServerAliveCountMax=2",
                    "-p",
                    "22",
                    "alice@dev-vm.example.com",
                    "--",
                    "sh -lc 'mkdir -p /sandbox/.agentenv/env && umask 077 && cat > '\\''/sandbox/.agentenv/env/demo.env'\\'' && chmod 600 '\\''/sandbox/.agentenv/env/demo.env'\\'''",
                ],
                "export OPENAI_API_KEY='sk test'\nexport QUOTE='a'\\''b'\n",
                Some(0),
                "",
                "",
            ),
        ]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let handle = driver
            .create(SandboxSpec {
                image: None,
                env: BTreeMap::from([
                    ("OPENAI_API_KEY".to_owned(), "sk test".to_owned()),
                    ("QUOTE".to_owned(), "a'b".to_owned()),
                ]),
                policy: None,
                metadata: BTreeMap::from([
                    ("name".to_owned(), json!("demo")),
                    ("host".to_owned(), json!("dev-vm.example.com")),
                    ("user".to_owned(), json!("alice")),
                ]),
            })
            .await
            .expect("create remote ssh sandbox")
            .handle;

        assert!(handle.contains("env_file="), "handle: {handle}");
        assert_eq!(runner.calls().len(), 3);
    }

    #[tokio::test]
    async fn connect_probes_remote_and_returns_sandbox_working_dir() {
        let handle = "remote-ssh://alice@dev-vm.example.com:22";
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-p",
                "22",
                "alice@dev-vm.example.com",
                "--",
                "true",
            ],
            Some(0),
            "",
            "",
        )]));
        let driver = RemoteSshDriver::with_command_runner(runner);

        let shell = driver
            .connect(ConnectParams {
                handle: handle.to_owned(),
            })
            .await
            .expect("connect");

        assert_eq!(shell.session_id, handle);
        assert!(shell.tty);
        assert_eq!(shell.working_dir.as_deref(), Some("/sandbox"));
    }

    #[tokio::test]
    async fn exec_runs_remote_shell_from_sandbox_workdir() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-p",
                "22",
                "alice@dev-vm.example.com",
                "--",
                "sh -lc 'cd /sandbox && echo hi'",
            ],
            Some(7),
            "stdout payload",
            "stderr payload",
        )]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let result = driver
            .exec(ExecParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                cmd: "echo hi".to_owned(),
                tty: false,
                env: BTreeMap::new(),
            })
            .await
            .expect("exec");

        assert_eq!(result.status, 7);
        assert_eq!(result.stdout, "stdout payload");
        assert_eq!(result.stderr, "stderr payload");
        assert_eq!(runner.calls().len(), 1);
    }

    #[tokio::test]
    async fn exec_injects_env_into_remote_shell_not_host_process() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-p",
                "22",
                "alice@dev-vm.example.com",
                "--",
                "sh -lc 'cd /sandbox && env FOO='\\''bar baz'\\'' sh -lc '\\''echo \"$FOO\"'\\'''",
            ],
            Some(0),
            "bar baz\n",
            "",
        )]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let result = driver
            .exec(ExecParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                cmd: "echo \"$FOO\"".to_owned(),
                tty: false,
                env: BTreeMap::from([("FOO".to_owned(), "bar baz".to_owned())]),
            })
            .await
            .expect("exec");

        assert_eq!(result.status, 0);
        assert_eq!(result.stdout, "bar baz\n");
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].request.env.is_empty());
        let separator = calls[0]
            .request
            .args
            .iter()
            .position(|arg| arg == "--")
            .expect("ssh separator");
        let remote_args = &calls[0].request.args[(separator + 1)..];
        assert_eq!(remote_args.len(), 1);
        assert!(remote_args[0].starts_with("sh -lc '"));
        assert!(remote_args[0].contains("env FOO='\\''bar baz'\\''"));
        assert!(remote_args[0].contains("sh -lc '\\''echo \"$FOO\"'\\''"));
    }

    #[tokio::test]
    async fn exec_sources_create_env_file_before_per_command_env() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-p",
                "22",
                "alice@dev-vm.example.com",
                "--",
                "sh -lc 'cd /sandbox && . '\\''/sandbox/.agentenv/env/demo.env'\\'' && env OPENAI_API_KEY='\\''override'\\'' sh -lc '\\''printf \"%s\" \"$OPENAI_API_KEY\"'\\'''",
            ],
            Some(0),
            "override",
            "",
        )]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let result = driver
            .exec(ExecParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22?env_file=%2Fsandbox%2F.agentenv%2Fenv%2Fdemo.env".to_owned(),
                cmd: "printf \"%s\" \"$OPENAI_API_KEY\"".to_owned(),
                tty: false,
                env: BTreeMap::from([("OPENAI_API_KEY".to_owned(), "override".to_owned())]),
            })
            .await
            .expect("exec");

        assert_eq!(result.status, 0);
        assert_eq!(result.stdout, "override");
        assert!(runner.calls()[0].request.env.is_empty());
    }

    fn sample_policy() -> NetworkPolicy {
        NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: Vec::new(),
                deny: Vec::new(),
                approval_required: Vec::new(),
                dns: agentenv_proto::DnsPolicy::default(),
            },
            filesystem: FilesystemPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                read_only: vec!["/usr".to_owned()],
                read_write: vec!["/sandbox".to_owned()],
            },
            process: ProcessPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                run_as_user: "sandbox".to_owned(),
                run_as_group: "sandbox".to_owned(),
                profile: "restricted".to_owned(),
                allow_syscalls: Vec::new(),
                deny_syscalls: Vec::new(),
            },
            inference: InferencePolicy {
                reloadability: PolicyReloadability::HotReload,
                routes: Vec::new(),
            },
        }
    }

    #[tokio::test]
    async fn exec_tty_requests_remote_pty_and_single_remote_command_arg() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-p",
                "22",
                "-tt",
                "alice@dev-vm.example.com",
                "--",
                "sh -lc 'cd /sandbox && bash'",
            ],
            Some(23),
            "ignored stdout",
            "ignored stderr",
        )]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let result = driver
            .exec(ExecParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                cmd: "bash".to_owned(),
                tty: true,
                env: BTreeMap::new(),
            })
            .await
            .expect("exec tty");

        assert_eq!(result.status, 23);
        assert_eq!(result.stdout, "");
        assert_eq!(result.stderr, "");
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].request.env.is_empty());
        let separator = calls[0]
            .request
            .args
            .iter()
            .position(|arg| arg == "--")
            .expect("ssh separator");
        assert_eq!(
            &calls[0].request.args[(separator + 1)..],
            &["sh -lc 'cd /sandbox && bash'".to_owned()]
        );
    }

    #[tokio::test]
    async fn exec_rejects_invalid_env_key_before_running_ssh() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        let err = driver
            .exec(ExecParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                cmd: "true".to_owned(),
                tty: false,
                env: BTreeMap::from([("BAD-NAME".to_owned(), "value".to_owned())]),
            })
            .await
            .expect_err("invalid env key should be rejected");

        assert!(err.to_string().contains("env.BAD-NAME"));
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn copy_in_and_copy_out_use_scp_with_port_identity_and_jump_host() {
        let handle = "remote-ssh://alice@dev-vm.example.com:2222?identity_file=/Users/alice/.ssh/id_ed25519&jump_host=bastion.example.com";
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::output(
                "scp",
                &[
                    "-P",
                    "2222",
                    "-i",
                    "/Users/alice/.ssh/id_ed25519",
                    "-J",
                    "bastion.example.com",
                    "--",
                    "/host/in.txt",
                    "alice@dev-vm.example.com:/sandbox/in.txt",
                ],
                Some(0),
                "",
                "",
            ),
            CommandScript::output(
                "scp",
                &[
                    "-P",
                    "2222",
                    "-i",
                    "/Users/alice/.ssh/id_ed25519",
                    "-J",
                    "bastion.example.com",
                    "--",
                    "alice@dev-vm.example.com:/sandbox/out.txt",
                    "/host/out.txt",
                ],
                Some(0),
                "",
                "",
            ),
        ]));
        let driver = RemoteSshDriver::with_command_runner(runner.clone());

        driver
            .copy_in(CopyInParams {
                handle: handle.to_owned(),
                src_host_path: "/host/in.txt".to_owned(),
                dst_sandbox_path: "/sandbox/in.txt".to_owned(),
            })
            .await
            .expect("copy_in");
        driver
            .copy_out(CopyOutParams {
                handle: handle.to_owned(),
                src_sandbox_path: "/sandbox/out.txt".to_owned(),
                dst_host_path: "/host/out.txt".to_owned(),
            })
            .await
            .expect("copy_out");

        assert_eq!(runner.calls().len(), 2);
    }

    #[tokio::test]
    async fn copy_in_rejects_option_shaped_or_remote_host_path_before_scp() {
        for src_host_path in ["-oProxyCommand=evil", "otherhost:/tmp/x"] {
            let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
                "scp",
                &[
                    "-P",
                    "22",
                    src_host_path,
                    "alice@dev-vm.example.com:/sandbox/in.txt",
                ],
                Some(0),
                "",
                "",
            )]));
            let driver = RemoteSshDriver::with_command_runner(runner.clone());

            let err = driver
                .copy_in(CopyInParams {
                    handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                    src_host_path: src_host_path.to_owned(),
                    dst_sandbox_path: "/sandbox/in.txt".to_owned(),
                })
                .await
                .expect_err("invalid src_host_path should be rejected");

            assert!(err.to_string().contains("src_host_path"));
            assert!(runner.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn copy_out_rejects_option_shaped_or_remote_host_path_before_scp() {
        for dst_host_path in ["-oProxyCommand=evil", "otherhost:/tmp/x"] {
            let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
                "scp",
                &[
                    "-P",
                    "22",
                    "alice@dev-vm.example.com:/sandbox/out.txt",
                    dst_host_path,
                ],
                Some(0),
                "",
                "",
            )]));
            let driver = RemoteSshDriver::with_command_runner(runner.clone());

            let err = driver
                .copy_out(CopyOutParams {
                    handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                    src_sandbox_path: "/sandbox/out.txt".to_owned(),
                    dst_host_path: dst_host_path.to_owned(),
                })
                .await
                .expect_err("invalid dst_host_path should be rejected");

            assert!(err.to_string().contains("dst_host_path"));
            assert!(runner.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn copy_rejects_unsafe_sandbox_path_before_scp() {
        let copy_in_runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "scp",
            &[
                "-P",
                "22",
                "/host/in.txt",
                "alice@dev-vm.example.com:/sandbox/in file.txt",
            ],
            Some(0),
            "",
            "",
        )]));
        let copy_in_driver = RemoteSshDriver::with_command_runner(copy_in_runner.clone());

        let copy_in_err = copy_in_driver
            .copy_in(CopyInParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                src_host_path: "/host/in.txt".to_owned(),
                dst_sandbox_path: "/sandbox/in file.txt".to_owned(),
            })
            .await
            .expect_err("unsafe dst_sandbox_path should be rejected");

        assert!(copy_in_err.to_string().contains("dst_sandbox_path"));
        assert!(copy_in_runner.calls().is_empty());

        let copy_out_runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "scp",
            &[
                "-P",
                "22",
                "alice@dev-vm.example.com:/sandbox/*.txt",
                "/host/out.txt",
            ],
            Some(0),
            "",
            "",
        )]));
        let copy_out_driver = RemoteSshDriver::with_command_runner(copy_out_runner.clone());

        let copy_out_err = copy_out_driver
            .copy_out(CopyOutParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
                src_sandbox_path: "/sandbox/*.txt".to_owned(),
                dst_host_path: "/host/out.txt".to_owned(),
            })
            .await
            .expect_err("unsafe src_sandbox_path should be rejected");

        assert!(copy_out_err.to_string().contains("src_sandbox_path"));
        assert!(copy_out_runner.calls().is_empty());
    }

    #[tokio::test]
    async fn remote_ssh_driver_satisfies_sandbox_conformance_contract() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![
            CommandScript::output("ssh", &["-V"], Some(0), "", "OpenSSH_9.9\n"),
            CommandScript::output("scp", &["-V"], Some(1), "", "usage: scp\n"),
        ]));
        let mut driver = RemoteSshDriver::with_command_runner(runner);

        driver_conformance::assert_sandbox_driver_contract(&mut driver)
            .await
            .expect("remote ssh driver should satisfy in-process conformance");
    }

    #[tokio::test]
    async fn status_reports_unhealthy_on_nonzero_ssh_probe() {
        let runner = Arc::new(RecordingCommandRunner::new(vec![CommandScript::output(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-p",
                "22",
                "alice@dev-vm.example.com",
                "--",
                "true",
            ],
            Some(255),
            "",
            "connection refused",
        )]));
        let driver = RemoteSshDriver::with_command_runner(runner);

        let status = driver
            .status(SandboxStatusParams {
                handle: "remote-ssh://alice@dev-vm.example.com:22".to_owned(),
            })
            .await
            .expect("status");

        assert_eq!(status.phase, agentenv_proto::SandboxPhase::Error);
        assert!(!status.healthy);
    }
}
