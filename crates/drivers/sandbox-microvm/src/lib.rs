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
    LogEntry, LogLevel, LogsParams, LogsResult, LogsStreamParams, NetworkPolicy, PreflightIssue,
    PreflightParams, PreflightResult, SandboxCapabilities, SandboxHandle, SandboxPhase,
    SandboxSpec, SandboxStatus, SandboxStatusParams, SessionHandle, ShellHandle, ShutdownParams,
    StopParams, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

const DRIVER_NAME: &str = "microvm";
const DEFAULT_RUNTIME: &str = "firecracker";
const FIRECRACKER_BINARY: &str = "firecracker";
const APPLE_CONTAINER_BINARY: &str = "container";
const SSH_BINARY: &str = "ssh";
const SCP_BINARY: &str = "scp";
const MICROVM_SSH_CAPABILITY: &str = "microvm_ssh";
const MICROVM_POLICY_CAPABILITY: &str = "microvm_policy_translation";
const UNSUPPORTED_RUNTIME_CAPABILITY: &str = "microvm_runtime";
const DEFAULT_KERNEL_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";
const SANDBOX_MOUNT: &str = "/sandbox";
const GUEST_ENV_DIR: &str = "/sandbox/.agentenv/env";
const DEFAULT_APPLE_CONTAINER_COMMAND: &str = "trap : TERM INT; sleep infinity & wait";

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

fn preflight_issue(
    severity: IssueSeverity,
    code: &str,
    message: String,
    remediation: Option<String>,
) -> PreflightIssue {
    PreflightIssue {
        severity,
        code: code.to_owned(),
        message,
        remediation,
    }
}

fn capability_missing(capability: &str) -> DriverError {
    DriverError::CapabilityMissing {
        capability: capability.to_owned(),
    }
}

pub struct MicroVmDriver {
    firecracker_binary: String,
    apple_container_binary: String,
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
            apple_container_binary: APPLE_CONTAINER_BINARY.to_owned(),
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
        Self::for_tests_host(
            runner,
            HostChecks {
                is_linux,
                is_macos: false,
                is_apple_silicon: false,
                has_kvm,
            },
        )
    }

    fn for_tests_host<T>(runner: Arc<T>, host: HostChecks) -> Self
    where
        T: CommandRunner + 'static,
    {
        Self {
            firecracker_binary: FIRECRACKER_BINARY.to_owned(),
            apple_container_binary: APPLE_CONTAINER_BINARY.to_owned(),
            ssh_binary: SSH_BINARY.to_owned(),
            scp_binary: SCP_BINARY.to_owned(),
            runner,
            host,
            workdir: Mutex::new(None),
        }
    }
}

impl MicroVmDriver {
    fn firecracker_preflight_issue(&self) -> Option<PreflightIssue> {
        if !self.host.is_linux {
            return Some(preflight_issue(
                IssueSeverity::Error,
                "microvm_linux_required",
                "Firecracker microVMs require a Linux host".to_owned(),
                Some(
                    "Use a Linux host with KVM, or select runtime: apple-container on macOS"
                        .to_owned(),
                ),
            ));
        }
        if !self.host.has_kvm {
            return Some(preflight_issue(
                IssueSeverity::Error,
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
            return Some(preflight_issue(
                IssueSeverity::Error,
                "microvm_firecracker_missing",
                format!(
                    "Firecracker binary `{}` is not available: {source}",
                    self.firecracker_binary
                ),
                Some("Install Firecracker and ensure it is on PATH".to_owned()),
            ));
        }
        None
    }

    fn apple_container_preflight_issue(&self) -> Option<PreflightIssue> {
        if !self.host.is_macos {
            return Some(preflight_issue(
                IssueSeverity::Error,
                "microvm_apple_container_macos_required",
                "Apple Container microVMs require macOS".to_owned(),
                Some("Use runtime: firecracker on a Linux/KVM host".to_owned()),
            ));
        }
        if !self.host.is_apple_silicon {
            return Some(preflight_issue(
                IssueSeverity::Error,
                "microvm_apple_container_silicon_required",
                "Apple Container requires Apple silicon".to_owned(),
                Some(
                    "Use a Mac with Apple silicon, or use runtime: firecracker on Linux/KVM"
                        .to_owned(),
                ),
            ));
        }

        let request = command_request(&["system", "status", "--format", "json"]);
        match self.runner.run(&self.apple_container_binary, &request) {
            Ok(output) if output.status == Some(0) => None,
            Ok(output) => Some(preflight_issue(
                IssueSeverity::Error,
                "microvm_apple_container_not_running",
                "Apple Container system service is not running".to_owned(),
                Some(format!(
                    "Run `{} system start` and retry. stdout: {} stderr: {}",
                    self.apple_container_binary, output.stdout, output.stderr
                )),
            )),
            Err(source) => Some(preflight_issue(
                IssueSeverity::Error,
                "microvm_apple_container_missing",
                format!(
                    "Apple Container CLI `{}` is not available: {source}",
                    self.apple_container_binary
                ),
                Some("Install Apple Container from https://github.com/apple/container/releases and run `container system start`".to_owned()),
            )),
        }
    }

    fn workdir_parent(&self) -> DriverResult<PathBuf> {
        self.workdir
            .lock()
            .map_err(|_| DriverError::InvalidInput {
                message: "microvm workdir lock poisoned".to_owned(),
            })?
            .clone()
            .ok_or_else(|| DriverError::InvalidInput {
                message: "microvm driver must be initialized before create".to_owned(),
            })
    }

    fn ensure_firecracker_create_host(&self) -> DriverResult<()> {
        if let Some(issue) = self.firecracker_preflight_issue() {
            return Err(DriverError::InvalidInput {
                message: issue.message,
            });
        }
        Ok(())
    }

    fn ensure_apple_container_create_host(&self) -> DriverResult<()> {
        if let Some(issue) = self.apple_container_preflight_issue() {
            return Err(DriverError::InvalidInput {
                message: issue.message,
            });
        }
        Ok(())
    }

    async fn create_firecracker(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        self.ensure_firecracker_create_host()?;
        let spec = FirecrackerSpec::from_sandbox_spec(spec)?;
        let parent = self.workdir_parent()?;
        let workdir = ensure_workdir(&parent, &spec.name)?;
        let handle = MicroVmHandle::new_firecracker(&spec, workdir.clone());
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

    async fn create_apple_container(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        self.ensure_apple_container_create_host()?;
        let spec = AppleContainerSpec::from_sandbox_spec(spec)?;
        let parent = self.workdir_parent()?;
        let workdir = ensure_apple_workdir(&parent, &spec)?;
        let handle = MicroVmHandle::new_apple_container(&spec, workdir.clone());
        let request = apple_container_run_request(&spec, &workdir);
        let output = self
            .runner
            .run(&self.apple_container_binary, &request)
            .map_err(|source| DriverError::CommandSpawn {
                command: command_string(&self.apple_container_binary, &request.args),
                source,
            })?;
        if output.status != Some(0) {
            return Err(command_failed(
                &self.apple_container_binary,
                &request,
                output,
            ));
        }

        Ok(SandboxHandle {
            handle: handle.to_handle()?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct HostChecks {
    is_linux: bool,
    is_macos: bool,
    is_apple_silicon: bool,
    has_kvm: bool,
}

impl HostChecks {
    fn detect() -> Self {
        Self {
            is_linux: std::env::consts::OS == "linux",
            is_macos: std::env::consts::OS == "macos",
            is_apple_silicon: std::env::consts::ARCH == "aarch64",
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
        validate_create_policy(spec.policy.as_ref())?;
        if !spec.env.is_empty() {
            return Err(DriverError::InvalidInput {
                message: "SandboxSpec.env is not supported by sandbox-microvm without a guest env injection path".to_owned(),
            });
        }

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

#[derive(Debug, Clone)]
struct AppleContainerSpec {
    name: String,
    image: String,
    command: String,
    memory_mb: u32,
    cpus: u8,
    platform: Option<String>,
    arch: Option<String>,
    kernel: Option<String>,
    env: BTreeMap<String, String>,
    guest_env_file: Option<String>,
}

impl AppleContainerSpec {
    fn from_sandbox_spec(spec: SandboxSpec) -> DriverResult<Self> {
        validate_create_policy(spec.policy.as_ref())?;
        let name = optional_metadata_string(&spec.metadata, "name")?
            .unwrap_or_else(|| format!("agentenv-{}", uuid_like_suffix()));
        validate_name(&name, "metadata.name")?;
        let image = optional_metadata_string(&spec.metadata, "image")?
            .or(spec.image)
            .ok_or_else(|| DriverError::InvalidInput {
                message: "SandboxSpec.image or metadata.image is required for apple-container"
                    .to_owned(),
            })?;
        let command = optional_metadata_string(&spec.metadata, "command")?
            .unwrap_or_else(|| DEFAULT_APPLE_CONTAINER_COMMAND.to_owned());
        let memory_mb = metadata_u32(&spec.metadata, "memory_mb", 2048)?;
        let cpus = metadata_u8(&spec.metadata, "cpus", 2)?;
        let platform = optional_metadata_string(&spec.metadata, "platform")?;
        let arch = optional_metadata_string(&spec.metadata, "arch")?;
        let kernel = optional_metadata_string(&spec.metadata, "kernel")?;
        validate_env(&spec.env)?;
        let guest_env_file = (!spec.env.is_empty()).then(|| format!("{GUEST_ENV_DIR}/{name}.env"));

        Ok(Self {
            name,
            image,
            command,
            memory_mb,
            cpus,
            platform,
            arch,
            kernel,
            env: spec.env,
            guest_env_file,
        })
    }
}

fn apple_container_run_request(spec: &AppleContainerSpec, workdir: &Path) -> CommandRequest {
    let mut args = vec![
        "run".to_owned(),
        "--detach".to_owned(),
        "--name".to_owned(),
        spec.name.clone(),
        "--cpus".to_owned(),
        spec.cpus.to_string(),
        "--memory".to_owned(),
        format!("{}M", spec.memory_mb),
        "--mount".to_owned(),
        format!(
            "type=bind,source={},target={SANDBOX_MOUNT}",
            sandbox_dir(workdir).to_string_lossy()
        ),
    ];
    if !spec.env.is_empty() {
        args.push("--env-file".to_owned());
        args.push(workdir.join("container.env").to_string_lossy().into_owned());
    }
    if let Some(platform) = spec.platform.as_deref() {
        args.push("--platform".to_owned());
        args.push(platform.to_owned());
    }
    if let Some(arch) = spec.arch.as_deref() {
        args.push("--arch".to_owned());
        args.push(arch.to_owned());
    }
    if let Some(kernel) = spec.kernel.as_deref() {
        args.push("--kernel".to_owned());
        args.push(kernel.to_owned());
    }
    args.push(spec.image.clone());
    args.push("sh".to_owned());
    args.push("-lc".to_owned());
    args.push(spec.command.clone());
    CommandRequest {
        args,
        env: BTreeMap::new(),
        stdin: None,
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
    env_file: Option<String>,
}

impl MicroVmHandle {
    fn new_firecracker(spec: &FirecrackerSpec, workdir: PathBuf) -> Self {
        Self {
            runtime: MicroVmRuntime::Firecracker,
            name: spec.name.clone(),
            api_sock: workdir.join("api.sock"),
            pid_file: workdir.join("firecracker.pid"),
            workdir,
            ssh: spec.ssh.clone(),
            env_file: None,
        }
    }

    fn new_apple_container(spec: &AppleContainerSpec, workdir: PathBuf) -> Self {
        Self {
            runtime: MicroVmRuntime::AppleContainer,
            name: spec.name.clone(),
            api_sock: workdir.join("api.sock"),
            pid_file: workdir.join("container.pid"),
            workdir,
            ssh: None,
            env_file: spec.guest_env_file.clone(),
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
        if let Some(env_file) = self.env_file.as_deref() {
            url.query_pairs_mut().append_pair("env_file", env_file);
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
        let env_file = query.get("env_file").cloned();
        if let Some(env_file) = env_file.as_deref() {
            validate_guest_env_file_path(env_file)
                .map_err(|err| invalid_handle(handle, err.to_string()))?;
        }
        Ok(Self {
            runtime,
            name,
            workdir,
            api_sock,
            pid_file,
            ssh,
            env_file,
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

fn validate_create_policy(policy: Option<&NetworkPolicy>) -> DriverResult<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if !policy.network.allow.is_empty()
        || !policy.network.deny.is_empty()
        || !policy.network.approval_required.is_empty()
        || !policy.inference.routes.is_empty()
    {
        return Err(capability_missing(MICROVM_POLICY_CAPABILITY));
    }
    Ok(())
}

fn validate_env(env: &BTreeMap<String, String>) -> DriverResult<()> {
    for (key, value) in env {
        validate_env_key(key)?;
        if value.contains('\0') || value.contains('\n') || value.contains('\r') {
            return Err(DriverError::InvalidInput {
                message: format!("env.{key} must not contain NUL or newline characters"),
            });
        }
    }
    Ok(())
}

fn validate_env_key(key: &str) -> DriverResult<()> {
    let valid = !key.is_empty()
        && !key.starts_with(|ch: char| ch.is_ascii_digit())
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    if !valid {
        return Err(DriverError::InvalidInput {
            message: format!("env key `{key}` is not a portable shell identifier"),
        });
    }
    Ok(())
}

fn validate_guest_env_file_path(path: &str) -> DriverResult<()> {
    if !path.starts_with(GUEST_ENV_DIR) || !path.ends_with(".env") {
        return Err(DriverError::InvalidInput {
            message: format!("env_file must be under {GUEST_ENV_DIR} and end with .env"),
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

fn sandbox_dir(workdir: &Path) -> PathBuf {
    workdir.join("sandbox")
}

fn ensure_apple_workdir(parent: &Path, spec: &AppleContainerSpec) -> DriverResult<PathBuf> {
    let workdir = ensure_workdir(parent, &spec.name)?;
    let sandbox = sandbox_dir(&workdir);
    fs::create_dir_all(&sandbox).map_err(|source| DriverError::InvalidInput {
        message: format!(
            "failed to create apple-container sandbox dir `{}`: {source}",
            sandbox.display()
        ),
    })?;
    if !spec.env.is_empty() {
        let env_dir = sandbox.join(".agentenv").join("env");
        fs::create_dir_all(&env_dir).map_err(|source| DriverError::InvalidInput {
            message: format!(
                "failed to create apple-container env dir `{}`: {source}",
                env_dir.display()
            ),
        })?;
        fs::write(
            env_dir.join(format!("{}.env", spec.name)),
            shell_env_file(&spec.env)?,
        )
        .map_err(|source| DriverError::InvalidInput {
            message: format!("failed to write guest env file: {source}"),
        })?;
        fs::write(
            workdir.join("container.env"),
            container_env_file(&spec.env)?,
        )
        .map_err(|source| DriverError::InvalidInput {
            message: format!("failed to write container env file: {source}"),
        })?;
    }
    Ok(workdir)
}

fn container_env_file(env: &BTreeMap<String, String>) -> DriverResult<String> {
    validate_env(env)?;
    Ok(env
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect())
}

fn shell_env_file(env: &BTreeMap<String, String>) -> DriverResult<String> {
    validate_env(env)?;
    Ok(env
        .iter()
        .map(|(key, value)| format!("export {key}={}\n", shell_single_quote(value)))
        .collect())
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

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn shell_command(
    cmd: &str,
    env_file: Option<&str>,
    env: &BTreeMap<String, String>,
) -> DriverResult<String> {
    validate_env(env)?;
    if let Some(env_file) = env_file {
        validate_guest_env_file_path(env_file)?;
    }

    let mut prefix = format!("cd {SANDBOX_MOUNT}");
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

fn validate_copy_path(field: &str, path: &str) -> DriverResult<()> {
    if path.is_empty() || path.starts_with('-') {
        return Err(DriverError::InvalidInput {
            message: format!("{field} must not be empty or start with '-'"),
        });
    }
    Ok(())
}

fn mounted_sandbox_path(handle: &MicroVmHandle, path: &str) -> DriverResult<PathBuf> {
    validate_copy_path("sandbox_path", path)?;
    if path != SANDBOX_MOUNT && !path.starts_with("/sandbox/") {
        return Err(DriverError::InvalidInput {
            message: format!("apple-container copy paths must be under {SANDBOX_MOUNT}"),
        });
    }
    let relative = path
        .strip_prefix(SANDBOX_MOUNT)
        .ok_or_else(|| DriverError::InvalidInput {
            message: format!("apple-container copy paths must be under {SANDBOX_MOUNT}"),
        })?
        .trim_start_matches('/');
    let relative_path = Path::new(relative);
    if relative_path.components().any(|component| {
        !matches!(
            component,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    }) {
        return Err(DriverError::InvalidInput {
            message: "apple-container copy paths must not escape /sandbox".to_owned(),
        });
    }
    Ok(sandbox_dir(&handle.workdir).join(relative_path))
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
        let mut firecracker_issue = self.firecracker_preflight_issue();
        let mut apple_container_issue = self.apple_container_preflight_issue();
        let ok = firecracker_issue.is_none() || apple_container_issue.is_none();
        let mut issues = Vec::new();
        for issue in [&mut firecracker_issue, &mut apple_container_issue]
            .into_iter()
            .flatten()
        {
            if ok {
                issue.severity = IssueSeverity::Warning;
            }
            issues.push(issue.clone());
        }
        Ok(PreflightResult { ok, issues })
    }

    async fn create(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        match MicroVmRuntime::parse(spec.metadata.get("runtime"))? {
            MicroVmRuntime::Firecracker => self.create_firecracker(spec).await,
            MicroVmRuntime::AppleContainer => self.create_apple_container(spec).await,
            MicroVmRuntime::Kata => Err(capability_missing(&format!(
                "{UNSUPPORTED_RUNTIME_CAPABILITY}:kata"
            ))),
        }
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        let (program, request) = match handle.runtime {
            MicroVmRuntime::Firecracker => {
                let ssh = handle.ssh()?;
                let mut args = ssh_args(ssh);
                args.push("--".to_owned());
                args.push("true".to_owned());
                (
                    self.ssh_binary.as_str(),
                    CommandRequest {
                        args,
                        env: BTreeMap::new(),
                        stdin: None,
                    },
                )
            }
            MicroVmRuntime::AppleContainer => (
                self.apple_container_binary.as_str(),
                CommandRequest {
                    args: vec!["exec".to_owned(), handle.name.clone(), "true".to_owned()],
                    env: BTreeMap::new(),
                    stdin: None,
                },
            ),
            MicroVmRuntime::Kata => {
                return Err(capability_missing(&format!(
                    "{UNSUPPORTED_RUNTIME_CAPABILITY}:kata"
                )))
            }
        };
        let output =
            self.runner
                .run(program, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(program, &request.args),
                    source,
                })?;
        if output.status != Some(0) {
            return Err(command_failed(program, &request, output));
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
        let command = shell_command(&params.cmd, handle.env_file.as_deref(), &params.env)?;
        let (program, request) = match handle.runtime {
            MicroVmRuntime::Firecracker => {
                let ssh = handle.ssh()?;
                let mut args = ssh_args(ssh);
                if params.tty {
                    args.insert(0, "-tt".to_owned());
                }
                args.push("--".to_owned());
                args.push(command);
                (
                    self.ssh_binary.as_str(),
                    CommandRequest {
                        args,
                        env: BTreeMap::new(),
                        stdin: None,
                    },
                )
            }
            MicroVmRuntime::AppleContainer => {
                let mut args = vec!["exec".to_owned()];
                if params.tty {
                    args.push("--tty".to_owned());
                    args.push("--interactive".to_owned());
                }
                args.push(handle.name.clone());
                args.push("sh".to_owned());
                args.push("-lc".to_owned());
                args.push(command);
                (
                    self.apple_container_binary.as_str(),
                    CommandRequest {
                        args,
                        env: BTreeMap::new(),
                        stdin: None,
                    },
                )
            }
            MicroVmRuntime::Kata => {
                return Err(capability_missing(&format!(
                    "{UNSUPPORTED_RUNTIME_CAPABILITY}:kata"
                )))
            }
        };
        if params.tty {
            let status = self.runner.status(program, &request).map_err(|source| {
                DriverError::CommandSpawn {
                    command: command_string(program, &request.args),
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
            self.runner
                .run(program, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(program, &request.args),
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
        validate_copy_path("src_host_path", &params.src_host_path)?;
        validate_copy_path("dst_sandbox_path", &params.dst_sandbox_path)?;
        if handle.runtime == MicroVmRuntime::AppleContainer {
            let dst = mounted_sandbox_path(&handle, &params.dst_sandbox_path)?;
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).map_err(|source| DriverError::InvalidInput {
                    message: format!("failed to create `{}`: {source}", parent.display()),
                })?;
            }
            fs::copy(&params.src_host_path, &dst).map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to copy `{}` to `{}`: {source}",
                    params.src_host_path,
                    dst.display()
                ),
            })?;
            return Ok(EmptyResult::default());
        }
        let ssh = handle.ssh()?;
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
        validate_copy_path("src_sandbox_path", &params.src_sandbox_path)?;
        validate_copy_path("dst_host_path", &params.dst_host_path)?;
        if handle.runtime == MicroVmRuntime::AppleContainer {
            let src = mounted_sandbox_path(&handle, &params.src_sandbox_path)?;
            if let Some(parent) = Path::new(&params.dst_host_path).parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|source| DriverError::InvalidInput {
                        message: format!("failed to create `{}`: {source}", parent.display()),
                    })?;
                }
            }
            fs::copy(&src, &params.dst_host_path).map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to copy `{}` to `{}`: {source}",
                    src.display(),
                    params.dst_host_path
                ),
            })?;
            return Ok(EmptyResult::default());
        }
        let ssh = handle.ssh()?;
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
        let (program, request) = match handle.runtime {
            MicroVmRuntime::Firecracker => {
                let pid = read_pid(&handle.pid_file)?;
                (
                    "kill",
                    CommandRequest {
                        args: vec!["-0".to_owned(), pid.to_string()],
                        env: BTreeMap::new(),
                        stdin: None,
                    },
                )
            }
            MicroVmRuntime::AppleContainer => (
                self.apple_container_binary.as_str(),
                CommandRequest {
                    args: vec!["exec".to_owned(), handle.name.clone(), "true".to_owned()],
                    env: BTreeMap::new(),
                    stdin: None,
                },
            ),
            MicroVmRuntime::Kata => {
                return Err(capability_missing(&format!(
                    "{UNSUPPORTED_RUNTIME_CAPABILITY}:kata"
                )))
            }
        };
        let status =
            self.runner
                .status(program, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(program, &request.args),
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
        if handle.runtime == MicroVmRuntime::AppleContainer {
            let request = CommandRequest {
                args: vec!["logs".to_owned(), handle.name.clone()],
                env: BTreeMap::new(),
                stdin: None,
            };
            let output = self
                .runner
                .run(&self.apple_container_binary, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(&self.apple_container_binary, &request.args),
                    source,
                })?;
            if output.status != Some(0) {
                return Err(command_failed(
                    &self.apple_container_binary,
                    &request,
                    output,
                ));
            }
            return Ok(LogsResult {
                entries: vec![LogEntry {
                    level: LogLevel::Info,
                    ts: String::new(),
                    msg: output.stdout,
                    kv: BTreeMap::from([(
                        "runtime".to_owned(),
                        Value::String("apple-container".to_owned()),
                    )]),
                }],
            });
        }
        Ok(LogsResult {
            entries: log_entries_for_handle(&handle),
        })
    }

    async fn logs_stream(&self, _params: LogsStreamParams) -> DriverResult<EmptyResult> {
        Err(capability_missing("microvm_log_stream"))
    }

    async fn stop(&self, params: StopParams) -> DriverResult<EmptyResult> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        let (program, request) = match handle.runtime {
            MicroVmRuntime::Firecracker => {
                let pid = read_pid(&handle.pid_file)?;
                (
                    "kill",
                    CommandRequest {
                        args: vec![pid.to_string()],
                        env: BTreeMap::new(),
                        stdin: None,
                    },
                )
            }
            MicroVmRuntime::AppleContainer => (
                self.apple_container_binary.as_str(),
                CommandRequest {
                    args: vec!["stop".to_owned(), handle.name.clone()],
                    env: BTreeMap::new(),
                    stdin: None,
                },
            ),
            MicroVmRuntime::Kata => {
                return Err(capability_missing(&format!(
                    "{UNSUPPORTED_RUNTIME_CAPABILITY}:kata"
                )))
            }
        };
        let output =
            self.runner
                .run(program, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(program, &request.args),
                    source,
                })?;
        if output.status != Some(0) {
            return Err(command_failed(program, &request, output));
        }
        let _ = fs::remove_file(&handle.pid_file);
        Ok(EmptyResult::default())
    }

    async fn destroy(&self, params: DestroyParams) -> DriverResult<EmptyResult> {
        let handle = MicroVmHandle::from_handle(&params.handle)?;
        if handle.runtime == MicroVmRuntime::AppleContainer {
            let request = CommandRequest {
                args: vec!["delete".to_owned(), "--force".to_owned(), handle.name],
                env: BTreeMap::new(),
                stdin: None,
            };
            let output = self
                .runner
                .run(&self.apple_container_binary, &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command_string(&self.apple_container_binary, &request.args),
                    source,
                })?;
            if output.status != Some(0) {
                return Err(command_failed(
                    &self.apple_container_binary,
                    &request,
                    output,
                ));
            }
            let _ = fs::remove_dir_all(handle.workdir);
            return Ok(EmptyResult::default());
        }
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
        Capabilities, ConnectParams, CopyInParams, CopyOutParams, DriverKind, ExecParams,
        FilesystemPolicy, InferencePolicy, InitializeParams, LogLevel, NetworkAccessPolicy,
        NetworkPolicy, NetworkRule, NetworkTarget, PolicyReloadability, PreflightParams,
        ProcessPolicy, SandboxSpec, SCHEMA_VERSION,
    };
    use serde_json::json;

    use super::{CommandOutput, CommandRequest, FirecrackerConfig, HostChecks, MicroVmDriver};

    #[derive(Debug, Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<CommandRequest>>,
        call_programs: Mutex<Vec<String>>,
        outputs: Mutex<VecDeque<io::Result<CommandOutput>>>,
        spawned: Mutex<Vec<CommandRequest>>,
        spawn_programs: Mutex<Vec<String>>,
    }

    impl RecordingRunner {
        fn new(outputs: Vec<io::Result<CommandOutput>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<CommandRequest> {
            self.calls.lock().unwrap().clone()
        }

        fn call_programs(&self) -> Vec<String> {
            self.call_programs.lock().unwrap().clone()
        }

        fn spawned(&self) -> Vec<CommandRequest> {
            self.spawned.lock().unwrap().clone()
        }
    }

    impl super::CommandRunner for RecordingRunner {
        fn run(&self, program: &str, request: &CommandRequest) -> io::Result<CommandOutput> {
            self.call_programs.lock().unwrap().push(program.to_owned());
            self.calls.lock().unwrap().push(request.clone());
            self.outputs.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(CommandOutput {
                    status: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }

        fn spawn(&self, program: &str, request: &CommandRequest) -> io::Result<u32> {
            self.spawn_programs.lock().unwrap().push(program.to_owned());
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

    fn apple_host() -> HostChecks {
        HostChecks {
            is_linux: false,
            is_macos: true,
            is_apple_silicon: true,
            has_kvm: false,
        }
    }

    fn restricted_policy() -> NetworkPolicy {
        NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: Vec::new(),
                deny: Vec::new(),
                approval_required: Vec::new(),
            },
            filesystem: FilesystemPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                read_only: vec!["/usr".to_owned(), "/lib".to_owned(), "/etc".to_owned()],
                read_write: vec!["/sandbox".to_owned(), "/tmp".to_owned()],
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
    async fn preflight_accepts_apple_container_on_apple_silicon_macos() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests_host(Arc::clone(&runner), apple_host());
        driver.initialize(init_params(temp.path())).await.unwrap();

        let preflight = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(preflight.ok);
        assert_eq!(
            preflight.issues[0].severity,
            agentenv_proto::IssueSeverity::Warning
        );
        assert_eq!(runner.call_programs(), vec!["container".to_owned()]);
        assert_eq!(
            runner.calls()[0].args,
            vec![
                "system".to_owned(),
                "status".to_owned(),
                "--format".to_owned(),
                "json".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn preflight_rejects_macos_when_apple_container_cli_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::new(vec![Err(io::Error::new(
            io::ErrorKind::NotFound,
            "container missing",
        ))]));
        let mut driver = MicroVmDriver::for_tests_host(Arc::clone(&runner), apple_host());
        driver.initialize(init_params(temp.path())).await.unwrap();

        let preflight = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(!preflight.ok);
        assert!(preflight
            .issues
            .iter()
            .any(|issue| issue.code == "microvm_linux_required"));
        assert!(preflight
            .issues
            .iter()
            .any(|issue| issue.code == "microvm_apple_container_missing"));
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
    async fn create_apple_container_mounts_sandbox_and_runs_keepalive() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests_host(Arc::clone(&runner), apple_host());
        driver.initialize(init_params(temp.path())).await.unwrap();

        let handle = driver
            .create(SandboxSpec {
                image: Some("ubuntu:24.04".to_owned()),
                env: BTreeMap::from([("OPENAI_API_KEY".to_owned(), "test-key".to_owned())]),
                policy: Some(restricted_policy()),
                metadata: BTreeMap::from([
                    ("name".to_owned(), json!("apple-test")),
                    ("runtime".to_owned(), json!("apple-container")),
                    ("memory_mb".to_owned(), json!(1024)),
                    ("cpus".to_owned(), json!(2)),
                ]),
            })
            .await
            .unwrap();

        assert!(handle
            .handle
            .starts_with("microvm://apple-container/apple-test?"));
        assert!(handle.handle.contains("env_file="), "handle: {handle:?}");
        let calls = runner.calls();
        assert_eq!(
            runner.call_programs(),
            vec!["container".to_owned(), "container".to_owned()]
        );
        assert_eq!(calls[1].args[0], "run");
        assert!(calls[1].args.contains(&"--detach".to_owned()));
        assert!(calls[1].args.contains(&"--env-file".to_owned()));
        assert!(calls[1]
            .args
            .iter()
            .any(|arg| arg.starts_with("type=bind,source=") && arg.ends_with(",target=/sandbox")));
        assert_eq!(calls[1].args[calls[1].args.len() - 4], "ubuntu:24.04");
        assert_eq!(calls[1].args[calls[1].args.len() - 3], "sh");
        assert_eq!(calls[1].args[calls[1].args.len() - 2], "-lc");
        assert_eq!(
            calls[1].args[calls[1].args.len() - 1],
            "trap : TERM INT; sleep infinity & wait"
        );

        let env_file = temp
            .path()
            .join("microvm")
            .join("apple-test")
            .join("sandbox")
            .join(".agentenv")
            .join("env")
            .join("apple-test.env");
        let env_file_content = std::fs::read_to_string(env_file).unwrap();
        assert!(env_file_content.contains("export OPENAI_API_KEY='test-key'"));
    }

    #[tokio::test]
    async fn create_rejects_network_policy_before_launch() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests_host(Arc::clone(&runner), apple_host());
        driver.initialize(init_params(temp.path())).await.unwrap();
        let mut policy = restricted_policy();
        policy.network.allow.push(NetworkRule {
            target: NetworkTarget::Host {
                host: "example.com".to_owned(),
                port: Some(443),
                scheme: Some("https".to_owned()),
                http_access: None,
            },
        });

        let err = driver
            .create(SandboxSpec {
                image: Some("ubuntu:24.04".to_owned()),
                env: BTreeMap::new(),
                policy: Some(policy),
                metadata: BTreeMap::from([
                    ("name".to_owned(), json!("apple-test")),
                    ("runtime".to_owned(), json!("apple-container")),
                ]),
            })
            .await
            .unwrap_err();

        assert!(matches!(err, DriverError::CapabilityMissing { .. }));
        assert_eq!(runner.calls().len(), 1, "only preflight should run");
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
    async fn apple_container_exec_sources_env_file_and_runs_in_sandbox() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests_host(Arc::clone(&runner), apple_host());
        driver.initialize(init_params(temp.path())).await.unwrap();
        let handle = format!(
            "microvm://apple-container/apple-test?workdir={}&env_file=%2Fsandbox%2F.agentenv%2Fenv%2Fapple-test.env",
            temp.path().join("microvm").join("apple-test").display()
        );

        let result = driver
            .exec(ExecParams {
                handle,
                cmd: "codex --version".to_owned(),
                tty: false,
                env: BTreeMap::from([("EXTRA".to_owned(), "value".to_owned())]),
            })
            .await
            .unwrap();

        assert_eq!(result.status, 0);
        assert_eq!(runner.call_programs(), vec!["container".to_owned()]);
        let args = &runner.calls()[0].args;
        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "apple-test");
        assert_eq!(args[2], "sh");
        assert_eq!(args[3], "-lc");
        assert!(args[4].contains("cd /sandbox && . '/sandbox/.agentenv/env/apple-test.env'"));
        assert!(args[4].contains("env EXTRA='value' sh -lc 'codex --version'"));
    }

    #[tokio::test]
    async fn apple_container_copy_uses_mounted_sandbox_directory() {
        let temp = tempfile::tempdir().unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut driver = MicroVmDriver::for_tests_host(Arc::clone(&runner), apple_host());
        driver.initialize(init_params(temp.path())).await.unwrap();
        let workdir = temp.path().join("microvm").join("apple-test");
        let host_src = temp.path().join("entrypoint");
        std::fs::write(&host_src, "#!/bin/sh\n").unwrap();
        let handle = format!(
            "microvm://apple-container/apple-test?workdir={}",
            workdir.display()
        );

        driver
            .copy_in(CopyInParams {
                handle: handle.clone(),
                src_host_path: host_src.display().to_string(),
                dst_sandbox_path: "/sandbox/.agentenv/bin/agentenv-agent".to_owned(),
            })
            .await
            .unwrap();
        let mounted = workdir
            .join("sandbox")
            .join(".agentenv")
            .join("bin")
            .join("agentenv-agent");
        assert_eq!(std::fs::read_to_string(&mounted).unwrap(), "#!/bin/sh\n");

        let host_dst = temp.path().join("copied-out");
        driver
            .copy_out(CopyOutParams {
                handle,
                src_sandbox_path: "/sandbox/.agentenv/bin/agentenv-agent".to_owned(),
                dst_host_path: host_dst.display().to_string(),
            })
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(host_dst).unwrap(), "#!/bin/sh\n");
        assert!(runner.calls().is_empty());
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
