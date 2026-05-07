#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

use agentenv_core::driver::{
    persistent_sessions_missing, DriverError, DriverResult, SandboxDriver,
};
use agentenv_proto::{
    assert_compatible_schema_version, ApplyPolicyParams, ApplyPolicyResult, AttachSessionParams,
    Capabilities, ConnectParams, CopyInParams, CopyOutParams, CreateSessionParams, DestroyParams,
    DriverInfo, DriverKind, EmptyResult, ExecParams, ExecResult, InitializeParams,
    InitializeResult, IssueSeverity, KillSessionParams, ListSessionsParams, ListSessionsResult,
    LogEntry, LogLevel, LogsParams, LogsResult, LogsStreamParams, PreflightIssue, PreflightParams,
    PreflightResult, SandboxCapabilities, SandboxHandle, SandboxPhase, SandboxSpec, SandboxStatus,
    SandboxStatusParams, SessionHandle, ShellHandle, ShutdownParams, StopParams, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

const DRIVER_NAME: &str = "microvm";
const DEFAULT_RUNTIME: &str = "firecracker";
const FIRECRACKER_BINARY: &str = "firecracker";
const SSH_BINARY: &str = "ssh";
const SCP_BINARY: &str = "scp";
const MICROVM_SSH_CAPABILITY: &str = "microvm_ssh";
const MICROVM_POLICY_CAPABILITY: &str = "microvm_policy_translation";
const UNSUPPORTED_RUNTIME_CAPABILITY: &str = "microvm_runtime";
const DEFAULT_KERNEL_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";

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

    fn status(&self, program: &str, request: &CommandRequest) -> io::Result<Option<i32>> {
        self.run(program, request).map(|output| output.status)
    }

    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<u32>;
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

    fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<u32> {
        debug_assert!(request.stdin.is_none());
        let child = Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(child.id())
    }
}

fn command_request(args: &[&str]) -> CommandRequest {
    CommandRequest {
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
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

fn capability_missing(capability: &str) -> DriverError {
    DriverError::CapabilityMissing {
        capability: capability.to_owned(),
    }
}

pub struct MicroVmDriver {
    firecracker_binary: String,
    ssh_binary: String,
    scp_binary: String,
    runner: Arc<dyn CommandRunner>,
    host: HostChecks,
    workdir: Mutex<Option<PathBuf>>,
}

impl Default for MicroVmDriver {
    fn default() -> Self {
        Self {
            firecracker_binary: FIRECRACKER_BINARY.to_owned(),
            ssh_binary: SSH_BINARY.to_owned(),
            scp_binary: SCP_BINARY.to_owned(),
            runner: Arc::new(ProcessCommandRunner),
            host: HostChecks::detect(),
            workdir: Mutex::new(None),
        }
    }
}

#[cfg(test)]
impl MicroVmDriver {
    fn for_tests<T>(runner: Arc<T>, is_linux: bool, has_kvm: bool) -> Self
    where
        T: CommandRunner + 'static,
    {
        Self {
            firecracker_binary: FIRECRACKER_BINARY.to_owned(),
            ssh_binary: SSH_BINARY.to_owned(),
            scp_binary: SCP_BINARY.to_owned(),
            runner,
            host: HostChecks { is_linux, has_kvm },
            workdir: Mutex::new(None),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HostChecks {
    is_linux: bool,
    has_kvm: bool,
}

impl HostChecks {
    fn detect() -> Self {
        Self {
            is_linux: std::env::consts::OS == "linux",
            has_kvm: Path::new("/dev/kvm").exists(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MicroVmRuntime {
    Firecracker,
    AppleContainer,
    Kata,
}

impl MicroVmRuntime {
    fn parse(value: Option<&Value>) -> DriverResult<Self> {
        let runtime = match value {
            None | Some(Value::Null) => DEFAULT_RUNTIME,
            Some(Value::String(value)) if value == "firecracker" => "firecracker",
            Some(Value::String(value)) if value == "apple-container" => "apple-container",
            Some(Value::String(value)) if value == "kata" => "kata",
            Some(Value::String(value)) => {
                return Err(DriverError::InvalidInput {
                    message: format!("metadata.runtime `{value}` is not supported"),
                });
            }
            Some(_) => {
                return Err(DriverError::InvalidInput {
                    message: "metadata.runtime must be a string when set".to_owned(),
                });
            }
        };
        Ok(match runtime {
            "firecracker" => Self::Firecracker,
            "apple-container" => Self::AppleContainer,
            "kata" => Self::Kata,
            _ => unreachable!("runtime was normalized above"),
        })
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::AppleContainer => "apple-container",
            Self::Kata => "kata",
        }
    }

    fn ensure_implemented(&self) -> DriverResult<()> {
        match self {
            Self::Firecracker => Ok(()),
            Self::AppleContainer | Self::Kata => Err(capability_missing(&format!(
                "{UNSUPPORTED_RUNTIME_CAPABILITY}:{}",
                self.label()
            ))),
        }
    }
}

#[derive(Debug, Clone)]
struct FirecrackerSpec {
    name: String,
    kernel: String,
    rootfs: String,
    kernel_args: String,
    memory_mb: u32,
    cpus: u8,
    tap: Option<String>,
    ssh: Option<SshTarget>,
}

impl FirecrackerSpec {
    fn from_sandbox_spec(spec: SandboxSpec) -> DriverResult<Self> {
        if spec.policy.is_some() {
            return Err(capability_missing(MICROVM_POLICY_CAPABILITY));
        }
        if !spec.env.is_empty() {
            return Err(DriverError::InvalidInput {
                message: "SandboxSpec.env is not supported by sandbox-microvm without a guest env injection path".to_owned(),
            });
        }
        let runtime = MicroVmRuntime::parse(spec.metadata.get("runtime"))?;
        runtime.ensure_implemented()?;

        let name = optional_metadata_string(&spec.metadata, "name")?
            .unwrap_or_else(|| format!("agentenv-{}", uuid_like_suffix()));
        validate_name(&name, "metadata.name")?;
        let kernel = required_metadata_string(&spec.metadata, "kernel")?;
        let rootfs = optional_metadata_string(&spec.metadata, "rootfs")?
            .or(spec.image)
            .ok_or_else(|| DriverError::InvalidInput {
                message: "metadata.rootfs or SandboxSpec.image is required for firecracker"
                    .to_owned(),
            })?;
        let kernel_args = optional_metadata_string(&spec.metadata, "kernel_args")?
            .unwrap_or_else(|| DEFAULT_KERNEL_ARGS.to_owned());
        let memory_mb = metadata_u32(&spec.metadata, "memory_mb", 2048)?;
        let cpus = metadata_u8(&spec.metadata, "cpus", 2)?;
        let tap = optional_metadata_string(&spec.metadata, "tap")?;
        if let Some(tap) = tap.as_deref() {
            validate_tap(tap)?;
        }
        let ssh = SshTarget::from_metadata(&spec.metadata)?;

        Ok(Self {
            name,
            kernel,
            rootfs,
            kernel_args,
            memory_mb,
            cpus,
            tap,
            ssh,
        })
    }

    fn config(&self) -> FirecrackerConfig {
        FirecrackerConfig {
            boot_source: BootSource {
                kernel_image_path: self.kernel.clone(),
                boot_args: self.kernel_args.clone(),
            },
            drives: vec![Drive {
                drive_id: "rootfs".to_owned(),
                path_on_host: self.rootfs.clone(),
                is_root_device: true,
                is_read_only: false,
            }],
            machine_config: MachineConfig {
                vcpu_count: self.cpus,
                mem_size_mib: self.memory_mb,
                smt: false,
            },
            network_interfaces: self
                .tap
                .as_ref()
                .map(|tap| {
                    vec![NetworkInterface {
                        iface_id: "eth0".to_owned(),
                        host_dev_name: tap.clone(),
                    }]
                })
                .unwrap_or_default(),
        }
    }
}

fn uuid_like_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SshTarget {
    host: String,
    user: String,
    port: u16,
    identity_file: Option<String>,
}

impl SshTarget {
    fn from_metadata(metadata: &BTreeMap<String, Value>) -> DriverResult<Option<Self>> {
        let host = optional_metadata_string(metadata, "ssh_host")?;
        let Some(host) = host else {
            return Ok(None);
        };
        validate_host(&host, "metadata.ssh_host")?;
        let user =
            optional_metadata_string(metadata, "ssh_user")?.unwrap_or_else(|| "root".to_owned());
        validate_user(&user, "metadata.ssh_user")?;
        let port = metadata_u16(metadata, "ssh_port", 22)?;
        let identity_file = optional_metadata_string(metadata, "ssh_identity_file")?;
        Ok(Some(Self {
            host,
            user,
            port,
            identity_file,
        }))
    }

    fn to_query(&self, url: &mut Url) {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("ssh_host", &self.host);
        pairs.append_pair("ssh_user", &self.user);
        pairs.append_pair("ssh_port", &self.port.to_string());
        if let Some(identity_file) = self.identity_file.as_deref() {
            pairs.append_pair("ssh_identity_file", identity_file);
        }
    }

    fn from_query(url: &Url, handle: &str) -> DriverResult<Option<Self>> {
        let mut host = None;
        let mut user = None;
        let mut port = None;
        let mut identity_file = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "ssh_host" => host = Some(value.into_owned()),
                "ssh_user" => user = Some(value.into_owned()),
                "ssh_port" => port = Some(value.into_owned()),
                "ssh_identity_file" => identity_file = Some(value.into_owned()),
                _ => {}
            }
        }
        let Some(host) = host else {
            return Ok(None);
        };
        validate_host(&host, "handle ssh_host")
            .map_err(|err| invalid_handle(handle, err.to_string()))?;
        let user = user.unwrap_or_else(|| "root".to_owned());
        validate_user(&user, "handle ssh_user")
            .map_err(|err| invalid_handle(handle, err.to_string()))?;
        let port = match port {
            Some(value) => value
                .parse::<u16>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    invalid_handle(handle, "handle ssh_port must be in range 1..=65535")
                })?,
            None => 22,
        };
        Ok(Some(Self {
            host,
            user,
            port,
            identity_file,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MicroVmHandle {
    runtime: MicroVmRuntime,
    name: String,
    workdir: PathBuf,
    api_sock: PathBuf,
    pid_file: PathBuf,
    ssh: Option<SshTarget>,
}

impl MicroVmHandle {
    fn new(runtime: MicroVmRuntime, spec: &FirecrackerSpec, workdir: PathBuf) -> Self {
        Self {
            runtime,
            name: spec.name.clone(),
            api_sock: workdir.join("api.sock"),
            pid_file: workdir.join("firecracker.pid"),
            workdir,
            ssh: spec.ssh.clone(),
        }
    }

    fn to_handle(&self) -> DriverResult<String> {
        let base = format!("microvm://{}/{}", self.runtime.label(), self.name);
        let mut url = Url::parse(&base).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to build microvm handle: {source}"),
        })?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("workdir", &self.workdir.to_string_lossy());
            pairs.append_pair("api_sock", &self.api_sock.to_string_lossy());
            pairs.append_pair("pid_file", &self.pid_file.to_string_lossy());
        }
        if let Some(ssh) = self.ssh.as_ref() {
            ssh.to_query(&mut url);
        }
        Ok(url.to_string())
    }

    fn from_handle(handle: &str) -> DriverResult<Self> {
        let url =
            Url::parse(handle).map_err(|source| invalid_handle(handle, source.to_string()))?;
        if url.scheme() != "microvm" {
            return Err(invalid_handle(handle, "expected microvm scheme"));
        }
        let runtime = match url.host_str() {
            Some("firecracker") => MicroVmRuntime::Firecracker,
            Some("apple-container") => MicroVmRuntime::AppleContainer,
            Some("kata") => MicroVmRuntime::Kata,
            Some(other) => {
                return Err(invalid_handle(
                    handle,
                    format!("unsupported runtime `{other}`"),
                ))
            }
            None => return Err(invalid_handle(handle, "missing runtime")),
        };
        let name = url.path().trim_start_matches('/').to_owned();
        validate_name(&name, "handle name")
            .map_err(|err| invalid_handle(handle, err.to_string()))?;
        let query = query_map(&url);
        let workdir = required_query_path(&query, handle, "workdir")?;
        let api_sock = query
            .get("api_sock")
            .map(PathBuf::from)
            .unwrap_or_else(|| workdir.join("api.sock"));
        let pid_file = query
            .get("pid_file")
            .map(PathBuf::from)
            .unwrap_or_else(|| workdir.join("firecracker.pid"));
        let ssh = SshTarget::from_query(&url, handle)?;
        Ok(Self {
            runtime,
            name,
            workdir,
            api_sock,
            pid_file,
            ssh,
        })
    }

    fn ssh(&self) -> DriverResult<&SshTarget> {
        self.ssh
            .as_ref()
            .ok_or_else(|| capability_missing(MICROVM_SSH_CAPABILITY))
    }
}

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn required_query_path(
    query: &BTreeMap<String, String>,
    handle: &str,
    key: &str,
) -> DriverResult<PathBuf> {
    query
        .get(key)
        .map(PathBuf::from)
        .ok_or_else(|| invalid_handle(handle, format!("missing {key} query parameter")))
}

fn invalid_handle(handle: &str, message: impl Into<String>) -> DriverError {
    DriverError::InvalidHandle {
        handle: handle.to_owned(),
        message: message.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FirecrackerConfig {
    #[serde(rename = "boot-source")]
    boot_source: BootSource,
    drives: Vec<Drive>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
    #[serde(
        rename = "network-interfaces",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    network_interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BootSource {
    kernel_image_path: String,
    boot_args: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Drive {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MachineConfig {
    vcpu_count: u8,
    mem_size_mib: u32,
    smt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetworkInterface {
    iface_id: String,
    host_dev_name: String,
}

fn required_metadata_string(metadata: &BTreeMap<String, Value>, key: &str) -> DriverResult<String> {
    optional_metadata_string(metadata, key)?.ok_or_else(|| DriverError::InvalidInput {
        message: format!("metadata.{key} is required"),
    })
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

fn metadata_u32(metadata: &BTreeMap<String, Value>, key: &str, default: u32) -> DriverResult<u32> {
    match metadata.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| DriverError::InvalidInput {
                message: format!("metadata.{key} must be in range 1..=4294967295"),
            }),
        Some(Value::String(value)) => value
            .parse::<u32>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| DriverError::InvalidInput {
                message: format!("metadata.{key} must be a positive integer"),
            }),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be an integer or numeric string when set"),
        }),
    }
}

fn metadata_u16(metadata: &BTreeMap<String, Value>, key: &str, default: u16) -> DriverResult<u16> {
    let value = metadata_u32(metadata, key, u32::from(default))?;
    u16::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| DriverError::InvalidInput {
            message: format!("metadata.{key} must be in range 1..=65535"),
        })
}

fn metadata_u8(metadata: &BTreeMap<String, Value>, key: &str, default: u8) -> DriverResult<u8> {
    let value = metadata_u32(metadata, key, u32::from(default))?;
    u8::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| DriverError::InvalidInput {
            message: format!("metadata.{key} must be in range 1..=255"),
        })
}

fn validate_name(name: &str, label: &str) -> DriverResult<()> {
    if name.is_empty()
        || name.starts_with('-')
        || name
            .chars()
            .any(|ch| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-' | '.'))
    {
        return Err(DriverError::InvalidInput {
            message: format!("{label} contains unsupported characters"),
        });
    }
    Ok(())
}

fn validate_tap(tap: &str) -> DriverResult<()> {
    if tap.is_empty()
        || tap.starts_with('-')
        || tap
            .chars()
            .any(|ch| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-' | '.'))
    {
        return Err(DriverError::InvalidInput {
            message: "metadata.tap contains unsupported characters".to_owned(),
        });
    }
    Ok(())
}

fn validate_user(user: &str, label: &str) -> DriverResult<()> {
    if user.is_empty()
        || user.starts_with('-')
        || user
            .chars()
            .any(|ch| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-' | '.'))
    {
        return Err(DriverError::InvalidInput {
            message: format!("{label} contains unsupported characters"),
        });
    }
    Ok(())
}

fn validate_host(host: &str, label: &str) -> DriverResult<()> {
    let valid_chars = host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'));
    let valid_shape = !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .split('.')
            .all(|part| !part.is_empty() && !part.starts_with('-') && !part.ends_with('-'));
    if !valid_chars || !valid_shape {
        return Err(DriverError::InvalidInput {
            message: format!("{label} contains unsupported characters or label syntax"),
        });
    }
    Ok(())
}

fn ensure_workdir(parent: &Path, name: &str) -> DriverResult<PathBuf> {
    let dir = parent.join(name);
    fs::create_dir_all(&dir).map_err(|source| DriverError::InvalidInput {
        message: format!(
            "failed to create microvm workdir `{}`: {source}",
            dir.display()
        ),
    })?;
    Ok(dir)
}

fn write_json(path: &Path, value: &impl Serialize) -> DriverResult<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| DriverError::InvalidInput {
        message: format!("failed to serialize firecracker config: {source}"),
    })?;
    fs::write(path, bytes).map_err(|source| DriverError::InvalidInput {
        message: format!("failed to write `{}`: {source}", path.display()),
    })
}

fn write_pid(path: &Path, pid: u32) -> DriverResult<()> {
    fs::write(path, format!("{pid}\n")).map_err(|source| DriverError::InvalidInput {
        message: format!("failed to write `{}`: {source}", path.display()),
    })
}

fn read_pid(path: &Path) -> DriverResult<u32> {
    let content = fs::read_to_string(path).map_err(|source| DriverError::InvalidHandle {
        handle: path.display().to_string(),
        message: format!("failed to read pid file: {source}"),
    })?;
    content
        .trim()
        .parse::<u32>()
        .map_err(|source| DriverError::InvalidHandle {
            handle: path.display().to_string(),
            message: format!("invalid pid file: {source}"),
        })
}

fn ssh_args(target: &SshTarget) -> Vec<String> {
    let mut args = vec![
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-p".to_owned(),
        target.port.to_string(),
    ];
    if let Some(identity_file) = target.identity_file.as_deref() {
        args.push("-i".to_owned());
        args.push(identity_file.to_owned());
    }
    args.push(format!("{}@{}", target.user, target.host));
    args
}

fn scp_args(target: &SshTarget) -> Vec<String> {
    let mut args = vec!["-P".to_owned(), target.port.to_string()];
    if let Some(identity_file) = target.identity_file.as_deref() {
        args.push("-i".to_owned());
        args.push(identity_file.to_owned());
    }
    args
}

fn remote_path(target: &SshTarget, path: &str) -> String {
    format!("{}@{}:{path}", target.user, target.host)
}

fn validate_copy_path(field: &str, path: &str) -> DriverResult<()> {
    if path.is_empty() || path.starts_with('-') {
        return Err(DriverError::InvalidInput {
            message: format!("{field} must not be empty or start with '-'"),
        });
    }
    Ok(())
}

fn log_entries_for_handle(handle: &MicroVmHandle) -> Vec<LogEntry> {
    let mut entries = Vec::new();
    for file in ["firecracker.stdout", "firecracker.stderr"] {
        let path = handle.workdir.join(file);
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        if content.trim().is_empty() {
            continue;
        }
        entries.push(LogEntry {
            level: if file.ends_with("stderr") {
                LogLevel::Warn
            } else {
                LogLevel::Info
            },
            ts: String::new(),
            msg: content,
            kv: BTreeMap::from([("path".to_owned(), Value::String(path.display().to_string()))]),
        });
    }
    entries
}

#[async_trait::async_trait]
impl SandboxDriver for MicroVmDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        assert_compatible_schema_version(&params.schema_version)?;
        *self.workdir.lock().map_err(|_| DriverError::InvalidInput {
            message: "microvm workdir lock poisoned".to_owned(),
        })? = Some(PathBuf::from(params.workdir).join("microvm"));

        Ok(InitializeResult {
            driver: DriverInfo {
                name: DRIVER_NAME.to_owned(),
                kind: DriverKind::Sandbox,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: false,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: false,
                supports_remote_host: false,
                supports_persistent_sessions: false,
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        if !self.host.is_linux {
            return Ok(preflight_failure(
                "microvm_linux_required",
                "Firecracker microVMs require a Linux host".to_owned(),
                Some("Use a Linux host with KVM, or select a different sandbox runtime".to_owned()),
            ));
        }
        if !self.host.has_kvm {
            return Ok(preflight_failure(
                "microvm_kvm_missing",
                "/dev/kvm is not available on this host".to_owned(),
                Some(
                    "Enable KVM virtualization and ensure the current user can access /dev/kvm"
                        .to_owned(),
                ),
            ));
        }
        if let Err(source) = self
            .runner
            .run(&self.firecracker_binary, &command_request(&["--version"]))
        {
            return Ok(preflight_failure(
                "microvm_firecracker_missing",
                format!(
                    "Firecracker binary `{}` is not available: {source}",
                    self.firecracker_binary
                ),
                Some("Install Firecracker and ensure it is on PATH".to_owned()),
            ));
        }
        Ok(PreflightResult {
            ok: true,
            issues: Vec::new(),
        })
    }

    async fn create(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        let spec = FirecrackerSpec::from_sandbox_spec(spec)?;
        let parent = self
            .workdir
            .lock()
            .map_err(|_| DriverError::InvalidInput {
                message: "microvm workdir lock poisoned".to_owned(),
            })?
            .clone()
            .ok_or_else(|| DriverError::InvalidInput {
                message: "microvm driver must be initialized before create".to_owned(),
            })?;
        let workdir = ensure_workdir(&parent, &spec.name)?;
        let handle = MicroVmHandle::new(MicroVmRuntime::Firecracker, &spec, workdir.clone());
        let config_path = workdir.join("firecracker.json");
        write_json(&config_path, &spec.config())?;

        let request = CommandRequest {
            args: vec![
                "--api-sock".to_owned(),
                handle.api_sock.to_string_lossy().into_owned(),
                "--config-file".to_owned(),
                config_path.to_string_lossy().into_owned(),
            ],
            env: BTreeMap::new(),
            stdin: None,
        };
        let pid = self
            .runner
            .spawn(&self.firecracker_binary, &request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string(&self.firecracker_binary, &request.args),
                source,
            })?;
        write_pid(&handle.pid_file, pid)?;

        Ok(SandboxHandle {
            handle: handle.to_handle()?,
        })
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        let ssh = handle.ssh()?;
        let mut args = ssh_args(ssh);
        args.push("--".to_owned());
        args.push("true".to_owned());
        let request = CommandRequest {
            args,
            env: BTreeMap::new(),
            stdin: None,
        };
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
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        let ssh = handle.ssh()?;
        let mut args = ssh_args(ssh);
        args.push("--".to_owned());
        args.push(params.cmd);
        let request = CommandRequest {
            args,
            env: params.env,
            stdin: None,
        };
        let output = self
            .runner
            .run(&self.ssh_binary, &request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string(&self.ssh_binary, &request.args),
                source,
            })?;
        Ok(ExecResult {
            status: output.status.unwrap_or(1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    async fn copy_in(&self, params: CopyInParams) -> DriverResult<EmptyResult> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        let ssh = handle.ssh()?;
        validate_copy_path("src_host_path", &params.src_host_path)?;
        validate_copy_path("dst_sandbox_path", &params.dst_sandbox_path)?;
        let mut args = scp_args(ssh);
        args.push("--".to_owned());
        args.push(params.src_host_path);
        args.push(remote_path(ssh, &params.dst_sandbox_path));
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
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        let ssh = handle.ssh()?;
        validate_copy_path("src_sandbox_path", &params.src_sandbox_path)?;
        validate_copy_path("dst_host_path", &params.dst_host_path)?;
        let mut args = scp_args(ssh);
        args.push("--".to_owned());
        args.push(remote_path(ssh, &params.src_sandbox_path));
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
        Err(capability_missing(MICROVM_POLICY_CAPABILITY))
    }

    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        handle.runtime.ensure_implemented()?;
        let pid = read_pid(&handle.pid_file)?;
        let request = CommandRequest {
            args: vec!["-0".to_owned(), pid.to_string()],
            env: BTreeMap::new(),
            stdin: None,
        };
        let status =
            self.runner
                .status("kill", &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string("kill", &request.args),
                    source,
                })?;
        let healthy = status == Some(0);
        Ok(SandboxStatus {
            phase: if healthy {
                SandboxPhase::Running
            } else {
                SandboxPhase::Error
            },
            healthy,
            last_ping: None,
        })
    }

    async fn logs(&self, params: LogsParams) -> DriverResult<LogsResult> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        Ok(LogsResult {
            entries: log_entries_for_handle(&handle),
        })
    }

    async fn logs_stream(&self, _params: LogsStreamParams) -> DriverResult<EmptyResult> {
        Err(capability_missing("microvm_log_stream"))
    }

    async fn stop(&self, params: StopParams) -> DriverResult<EmptyResult> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        let pid = read_pid(&handle.pid_file)?;
        let request = CommandRequest {
            args: vec![pid.to_string()],
            env: BTreeMap::new(),
            stdin: None,
        };
        let output =
            self.runner
                .run("kill", &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string("kill", &request.args),
                    source,
                })?;
        if output.status != Some(0) {
            return Err(command_failed("kill", &request, output));
        }
        let _ = fs::remove_file(&handle.pid_file);
        Ok(EmptyResult::default())
    }

    async fn destroy(&self, params: DestroyParams) -> DriverResult<EmptyResult> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        if handle.pid_file.exists() {
            let _ = self
                .stop(StopParams {
                    handle: params.handle,
                })
                .await;
        }
        for path in [
            handle.workdir.join("firecracker.json"),
            handle.api_sock,
            handle.pid_file,
            handle.workdir.join("firecracker.stdout"),
            handle.workdir.join("firecracker.stderr"),
        ] {
            let _ = fs::remove_file(path);
        }
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
        path::Path,
        sync::{Arc, Mutex},
    };

    use agentenv_core::driver::{DriverError, SandboxDriver};
    use agentenv_proto::{
        Capabilities, ConnectParams, DriverKind, InitializeParams, LogLevel, PreflightParams,
        SandboxSpec, SCHEMA_VERSION,
    };
    use serde_json::json;

    use super::{CommandOutput, CommandRequest, FirecrackerConfig, MicroVmDriver};

    #[derive(Debug, Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<CommandRequest>>,
        outputs: Mutex<VecDeque<io::Result<CommandOutput>>>,
        spawned: Mutex<Vec<CommandRequest>>,
    }

    impl RecordingRunner {
        fn calls(&self) -> Vec<CommandRequest> {
            self.calls.lock().unwrap().clone()
        }

        fn spawned(&self) -> Vec<CommandRequest> {
            self.spawned.lock().unwrap().clone()
        }
    }

    impl super::CommandRunner for RecordingRunner {
        fn run(&self, _program: &str, request: &CommandRequest) -> io::Result<CommandOutput> {
            self.calls.lock().unwrap().push(request.clone());
            self.outputs.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(CommandOutput {
                    status: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }

        fn spawn(&self, _program: &str, request: &CommandRequest) -> io::Result<u32> {
            self.spawned.lock().unwrap().push(request.clone());
            Ok(4242)
        }
    }

    fn init_params(workdir: &Path) -> InitializeParams {
        InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1".to_owned(),
            workdir: workdir.to_string_lossy().into_owned(),
            log_level: LogLevel::Info,
        }
    }

    #[tokio::test]
    async fn initialize_declares_microvm_capabilities() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests(Arc::clone(&runner), true, true);

        let result = driver.initialize(init_params(temp.path())).await.unwrap();

        assert_eq!(result.driver.name, "microvm");
        assert_eq!(result.driver.kind, DriverKind::Sandbox);
        match result.capabilities {
            Capabilities::Sandbox(capabilities) => {
                assert!(!capabilities.supports_hot_reload_policy);
                assert!(capabilities.supports_filesystem_lockdown);
                assert!(capabilities.supports_syscall_filter);
                assert!(!capabilities.supports_native_inference_routing);
                assert!(!capabilities.supports_remote_host);
                assert!(!capabilities.supports_persistent_sessions);
            }
            other => panic!("expected sandbox capabilities, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn preflight_requires_linux_kvm_and_firecracker() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests(Arc::clone(&runner), false, true);
        driver.initialize(init_params(temp.path())).await.unwrap();

        let preflight = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(!preflight.ok);
        assert_eq!(preflight.issues[0].code, "microvm_linux_required");
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn create_firecracker_writes_config_and_spawns_process() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests(Arc::clone(&runner), true, true);
        driver.initialize(init_params(temp.path())).await.unwrap();

        let handle = driver
            .create(SandboxSpec {
                image: None,
                env: BTreeMap::new(),
                policy: None,
                metadata: BTreeMap::from([
                    ("name".to_owned(), json!("fc-test")),
                    ("runtime".to_owned(), json!("firecracker")),
                    (
                        "kernel".to_owned(),
                        json!("/var/lib/agentenv/kernel/vmlinux"),
                    ),
                    ("rootfs".to_owned(), json!("/var/lib/agentenv/rootfs.ext4")),
                    ("memory_mb".to_owned(), json!(1024)),
                    ("cpus".to_owned(), json!(2)),
                    ("tap".to_owned(), json!("tap-agentenv0")),
                ]),
            })
            .await
            .unwrap();

        assert!(handle.handle.starts_with("microvm://firecracker/fc-test?"));
        let spawned = runner.spawned();
        assert_eq!(spawned.len(), 1);
        assert_eq!(spawned[0].args[0], "--api-sock");
        assert_eq!(spawned[0].args[2], "--config-file");

        let config_path = Path::new(&spawned[0].args[3]);
        let config: FirecrackerConfig =
            serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
        assert_eq!(
            config.boot_source.kernel_image_path,
            "/var/lib/agentenv/kernel/vmlinux"
        );
        assert_eq!(
            config.drives[0].path_on_host,
            "/var/lib/agentenv/rootfs.ext4"
        );
        assert_eq!(config.machine_config.mem_size_mib, 1024);
        assert_eq!(config.machine_config.vcpu_count, 2);
        assert_eq!(config.network_interfaces[0].host_dev_name, "tap-agentenv0");
    }

    #[tokio::test]
    async fn create_rejects_non_firecracker_runtime_explicitly() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests(Arc::clone(&runner), true, true);
        driver.initialize(init_params(temp.path())).await.unwrap();

        let err = driver
            .create(SandboxSpec {
                image: None,
                env: BTreeMap::new(),
                policy: None,
                metadata: BTreeMap::from([
                    ("name".to_owned(), json!("kata-test")),
                    ("runtime".to_owned(), json!("kata")),
                ]),
            })
            .await
            .unwrap_err();

        assert!(matches!(err, DriverError::CapabilityMissing { .. }));
        assert!(runner.spawned().is_empty());
    }

    #[tokio::test]
    async fn connect_requires_ssh_metadata_in_handle() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests(Arc::clone(&runner), true, true);
        driver.initialize(init_params(temp.path())).await.unwrap();

        let err = driver
            .connect(ConnectParams {
                handle: "microvm://firecracker/fc-test?workdir=/tmp/fc-test".to_owned(),
            })
            .await
            .unwrap_err();

        assert!(matches!(err, DriverError::CapabilityMissing { .. }));
    }

    #[tokio::test]
    async fn conformance_contract_passes_with_fake_host() {
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests(Arc::clone(&runner), true, true);

        driver_conformance::assert_sandbox_driver_contract(&mut driver)
            .await
            .unwrap();
    }
}
