# Sandbox OpenShell Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the full M2-1 built-in OpenShell sandbox driver for issue #7.

**Architecture:** `sandbox-openshell` becomes a real `SandboxDriver` implementation over the OpenShell CLI. The crate uses an internal command-runner seam for deterministic tests, stores current policy per handle for hot-reload validation, and keeps the public protocol unchanged.

**Tech Stack:** Rust 2021, `async-trait`, `thiserror`, `semver`, `uuid`, `serde_json`, `agentenv-core` driver traits, `agentenv-proto` schema types, `agentenv-policy` OpenShell translator, Cargo workspace tests.

---

## File Structure

- Modify `crates/agentenv-core/src/driver.rs`: add driver error variants needed by real built-in drivers.
- Modify `crates/drivers/sandbox-openshell/Cargo.toml`: add runtime and test dependencies for the driver implementation.
- Modify `crates/drivers/sandbox-openshell/src/lib.rs`: keep existing policy helper exports and add the OpenShell driver, command runner, CLI argument construction, preflight, lifecycle methods, policy application, status parsing, log parsing, and unit tests.
- Modify `tests/driver-conformance/src/lib.rs`: add an in-process sandbox driver conformance helper.
- Create `crates/drivers/sandbox-openshell/tests/integration.rs`: ignored, feature-gated OpenShell end-to-end tests.
- Modify `crates/drivers/sandbox-openshell/README.md`: document driver behavior, integration gate, and local OpenShell requirements.

## Task 1: Add Core Driver Error Surface and Crate Dependencies

**Files:**
- Modify: `crates/agentenv-core/src/driver.rs`
- Modify: `crates/drivers/sandbox-openshell/Cargo.toml`

- [ ] **Step 1: Write failing core error tests**

Add these tests inside `#[cfg(test)] mod tests` in `crates/agentenv-core/src/driver.rs`:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p agentenv-core command_failed_error_includes_command_status_and_trimmed_stderr invalid_input_error_names_the_bad_field`

Expected: FAIL because `DriverError::CommandFailed` and `DriverError::InvalidInput` do not exist.

- [ ] **Step 3: Implement error variants**

Update `DriverError` in `crates/agentenv-core/src/driver.rs`:

```rust
#[derive(Debug, Error)]
pub enum DriverError {
    #[error(transparent)]
    SchemaVersion(#[from] SchemaVersionError),
    #[error("driver is missing capability `{capability}`")]
    CapabilityMissing { capability: String },
    #[error("preflight failed: {message}")]
    PreflightFailed { message: String },
    #[error("failed to spawn command `{command}`: {source}")]
    CommandSpawn {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "command `{command}` failed with {status_label}: {stderr_trimmed}",
        status_label = status_label(*status),
        stderr_trimmed = trim_for_error(stderr)
    )]
    CommandFailed {
        command: String,
        status: Option<i32>,
        stdout: String,
        stderr: String,
    },
    #[error("policy translation failed: {message}")]
    PolicyTranslation { message: String },
    #[error("invalid driver input: {message}")]
    InvalidInput { message: String },
}

fn status_label(status: Option<i32>) -> String {
    match status {
        Some(code) => format!("status {code}"),
        None => "unknown status".to_owned(),
    }
}

fn trim_for_error(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "<empty stderr>".to_owned()
    } else {
        trimmed.chars().take(500).collect()
    }
}
```

- [ ] **Step 4: Add sandbox driver dependencies**

Update `crates/drivers/sandbox-openshell/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-policy = { path = "../../agentenv-policy" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true
semver = "1"
serde_json.workspace = true
thiserror.workspace = true
uuid.workspace = true

[dev-dependencies]
driver-conformance = { path = "../../../tests/driver-conformance" }
tokio = { version = "1", features = ["macros", "rt"] }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p agentenv-core command_failed_error_includes_command_status_and_trimmed_stderr invalid_input_error_names_the_bad_field`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-core/src/driver.rs crates/drivers/sandbox-openshell/Cargo.toml
git commit -m "feat: add driver command error surface"
```

## Task 2: Add Command Runner, Driver Skeleton, Initialize, and Preflight

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing tests for initialize and preflight**

Add a `#[cfg(test)] mod driver_tests` to `crates/drivers/sandbox-openshell/src/lib.rs` with these tests:

```rust
#[tokio::test]
async fn openshell_driver_initializes_with_required_capabilities() {
    let runner = RecordingRunner::default();
    let mut driver = OpenShellDriver::with_runner("openshell", runner);

    let result = driver
        .initialize(InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1-test".to_owned(),
            workdir: "/tmp/agentenv-test".to_owned(),
            log_level: LogLevel::Info,
        })
        .await
        .unwrap();

    assert_eq!(result.driver.name, "openshell");
    assert_eq!(result.driver.kind, DriverKind::Sandbox);
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
    let runner = RecordingRunner::new([
        scripted_ok(["--version"], "openshell 0.0.30\n"),
        scripted_ok(["gateway", "status"], "gateway running\n"),
    ]);
    let driver = OpenShellDriver::with_runner("openshell", runner.clone());

    let result = driver.preflight(PreflightParams::default()).await.unwrap();

    assert!(result.ok);
    assert!(result.issues.is_empty());
    assert_eq!(runner.commands(), vec![
        vec!["--version".to_owned()],
        vec!["gateway".to_owned(), "status".to_owned()],
    ]);
}

#[tokio::test]
async fn preflight_reports_missing_cli() {
    let runner = RecordingRunner::new([scripted_spawn_error(
        ["--version"],
        std::io::ErrorKind::NotFound,
        "openshell missing",
    )]);
    let driver = OpenShellDriver::with_runner("openshell", runner);

    let result = driver.preflight(PreflightParams::default()).await.unwrap();

    assert!(!result.ok);
    assert_eq!(result.issues[0].code, "openshell_missing");
    assert!(result.issues[0].message.contains("not found"));
}

#[tokio::test]
async fn preflight_rejects_old_cli_version() {
    let runner = RecordingRunner::new([scripted_ok(["--version"], "openshell 0.0.29\n")]);
    let driver = OpenShellDriver::with_runner("openshell", runner);

    let result = driver.preflight(PreflightParams::default()).await.unwrap();

    assert!(!result.ok);
    assert_eq!(result.issues[0].code, "openshell_version_too_old");
    assert!(result.issues[0].message.contains("0.0.30"));
}

#[tokio::test]
async fn preflight_reports_gateway_down() {
    let runner = RecordingRunner::new([
        scripted_ok(["--version"], "openshell 0.0.30\n"),
        scripted_fail(["gateway", "status"], 1, "", "gateway unavailable\n"),
    ]);
    let driver = OpenShellDriver::with_runner("openshell", runner);

    let result = driver.preflight(PreflightParams::default()).await.unwrap();

    assert!(!result.ok);
    assert_eq!(result.issues[0].code, "openshell_gateway_down");
    assert!(result.issues[0].message.contains("gateway unavailable"));
}
```

Include test imports:

```rust
use agentenv_core::driver::SandboxDriver;
use agentenv_proto::{
    Capabilities, DriverKind, InitializeParams, LogLevel, PreflightParams, SCHEMA_VERSION,
};
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sandbox-openshell openshell_driver_initializes_with_required_capabilities preflight_passes_when_cli_version_and_gateway_are_valid`

Expected: FAIL because `OpenShellDriver`, `RecordingRunner`, and scripted runner helpers do not exist.

- [ ] **Step 3: Implement command runner and preflight**

Add these imports near the top of `crates/drivers/sandbox-openshell/src/lib.rs`:

```rust
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use agentenv_core::driver::{DriverError, DriverResult, SandboxDriver};
use agentenv_proto::{
    assert_compatible_schema_version, Capabilities, DriverInfo, DriverKind, EmptyResult,
    InitializeParams, InitializeResult, IssueSeverity, PreflightIssue, PreflightParams,
    PreflightResult, SandboxCapabilities, SCHEMA_VERSION,
};
use async_trait::async_trait;
use semver::Version;
```

Add these types below the existing constants:

```rust
const DRIVER_NAME: &str = "openshell";
const MIN_OPEN_SHELL_VERSION: &str = "0.0.30";

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
    fn run(&self, program: &str, request: CommandRequest) -> Result<CommandOutput, CommandRunError>;
    fn spawn(&self, program: &str, request: CommandRequest) -> Result<(), CommandRunError>;
}

#[derive(Debug)]
enum CommandRunError {
    Spawn(std::io::Error),
}

#[derive(Debug, Default)]
struct ProcessCommandRunner;

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, program: &str, request: CommandRequest) -> Result<CommandOutput, CommandRunError> {
        let output = Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .output()
            .map_err(CommandRunError::Spawn)?;

        Ok(CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn spawn(&self, program: &str, request: CommandRequest) -> Result<(), CommandRunError> {
        Command::new(program)
            .args(&request.args)
            .envs(&request.env)
            .spawn()
            .map(|_| ())
            .map_err(CommandRunError::Spawn)
    }
}

#[derive(Clone)]
pub struct OpenShellDriver {
    openshell_bin: String,
    runner: Arc<dyn CommandRunner>,
    current_policies: Arc<Mutex<BTreeMap<String, agentenv_proto::NetworkPolicy>>>,
}

impl Default for OpenShellDriver {
    fn default() -> Self {
        Self {
            openshell_bin: "openshell".to_owned(),
            runner: Arc::new(ProcessCommandRunner),
            current_policies: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl OpenShellDriver {
    #[cfg(test)]
    fn with_runner(binary: impl Into<String>, runner: RecordingRunner) -> Self {
        Self {
            openshell_bin: binary.into(),
            runner: Arc::new(runner),
            current_policies: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn command(&self, args: impl IntoIterator<Item = impl Into<String>>) -> CommandRequest {
        CommandRequest {
            args: args.into_iter().map(Into::into).collect(),
            env: BTreeMap::new(),
        }
    }

    fn run(&self, request: CommandRequest) -> Result<CommandOutput, DriverError> {
        let command = render_command(&self.openshell_bin, &request.args);
        self.runner
            .run(&self.openshell_bin, request)
            .map_err(|err| command_run_error(command, err))
    }
}
```

Add helper functions:

```rust
fn command_run_error(command: String, err: CommandRunError) -> DriverError {
    match err {
        CommandRunError::Spawn(source) => DriverError::CommandSpawn { command, source },
    }
}

fn render_command(program: &str, args: &[String]) -> String {
    std::iter::once(program.to_owned())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_succeeded(output: &CommandOutput) -> bool {
    output.status == Some(0)
}

fn parse_openshell_version(raw: &str) -> Option<Version> {
    raw.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '+'))
        .find_map(|token| Version::parse(token).ok())
}

fn preflight_issue(
    code: impl Into<String>,
    message: impl Into<String>,
    remediation: Option<String>,
) -> PreflightIssue {
    PreflightIssue {
        severity: IssueSeverity::Error,
        code: code.into(),
        message: message.into(),
        remediation,
    }
}
```

Implement the initial trait:

```rust
#[async_trait]
impl SandboxDriver for OpenShellDriver {
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
                supports_hot_reload_policy: true,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: true,
                supports_remote_host: true,
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        let version_output = match self.run(self.command(["--version"])) {
            Ok(output) => output,
            Err(DriverError::CommandSpawn { .. }) => {
                return Ok(PreflightResult {
                    ok: false,
                    issues: vec![preflight_issue(
                        "openshell_missing",
                        "OpenShell binary was not found on PATH",
                        Some("Install OpenShell and ensure `openshell` is on PATH.".to_owned()),
                    )],
                });
            }
            Err(err) => {
                return Ok(PreflightResult {
                    ok: false,
                    issues: vec![preflight_issue(
                        "openshell_version_failed",
                        err.to_string(),
                        Some("Run `openshell --version` manually for details.".to_owned()),
                    )],
                });
            }
        };

        let version = match parse_openshell_version(&version_output.stdout)
            .or_else(|| parse_openshell_version(&version_output.stderr))
        {
            Some(version) => version,
            None => {
                return Ok(PreflightResult {
                    ok: false,
                    issues: vec![preflight_issue(
                        "openshell_version_unparseable",
                        format!(
                            "could not parse OpenShell version from `{}`",
                            version_output.stdout.trim()
                        ),
                        Some("Upgrade OpenShell to a release that prints a semver version.".to_owned()),
                    )],
                });
            }
        };

        let min_version = Version::parse(MIN_OPEN_SHELL_VERSION)
            .expect("minimum OpenShell version must be semver");
        if version < min_version {
            return Ok(PreflightResult {
                ok: false,
                issues: vec![preflight_issue(
                    "openshell_version_too_old",
                    format!("OpenShell {version} is older than required {MIN_OPEN_SHELL_VERSION}"),
                    Some(format!("Upgrade OpenShell to >= {MIN_OPEN_SHELL_VERSION}.")),
                )],
            });
        }

        let gateway = self.run(self.command(["gateway", "status"]))?;
        if !command_succeeded(&gateway) {
            return Ok(PreflightResult {
                ok: false,
                issues: vec![preflight_issue(
                    "openshell_gateway_down",
                    gateway.stderr.trim().to_owned(),
                    Some("Start or repair the OpenShell gateway and retry.".to_owned()),
                )],
            });
        }

        Ok(PreflightResult {
            ok: true,
            issues: Vec::new(),
        })
    }

    async fn create(&self, _spec: agentenv_proto::SandboxSpec) -> DriverResult<agentenv_proto::SandboxHandle> {
        Err(DriverError::InvalidInput { message: "create is not wired yet".to_owned() })
    }

    async fn connect(&self, _params: agentenv_proto::ConnectParams) -> DriverResult<agentenv_proto::ShellHandle> {
        Err(DriverError::InvalidInput { message: "connect is not wired yet".to_owned() })
    }

    async fn exec(&self, _params: agentenv_proto::ExecParams) -> DriverResult<agentenv_proto::ExecResult> {
        Err(DriverError::InvalidInput { message: "exec is not wired yet".to_owned() })
    }

    async fn copy_in(&self, _params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
        Err(DriverError::InvalidInput { message: "copy_in is not wired yet".to_owned() })
    }

    async fn copy_out(&self, _params: agentenv_proto::CopyOutParams) -> DriverResult<EmptyResult> {
        Err(DriverError::InvalidInput { message: "copy_out is not wired yet".to_owned() })
    }

    async fn apply_policy(&self, _params: agentenv_proto::ApplyPolicyParams) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
        Err(DriverError::InvalidInput { message: "apply_policy is not wired yet".to_owned() })
    }

    async fn status(&self, _params: agentenv_proto::SandboxStatusParams) -> DriverResult<agentenv_proto::SandboxStatus> {
        Err(DriverError::InvalidInput { message: "status is not wired yet".to_owned() })
    }

    async fn logs(&self, _params: agentenv_proto::LogsParams) -> DriverResult<agentenv_proto::LogsResult> {
        Err(DriverError::InvalidInput { message: "logs is not wired yet".to_owned() })
    }

    async fn logs_stream(&self, _params: agentenv_proto::LogsStreamParams) -> DriverResult<EmptyResult> {
        Err(DriverError::InvalidInput { message: "logs_stream is not wired yet".to_owned() })
    }

    async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
        Err(DriverError::InvalidInput { message: "stop is not wired yet".to_owned() })
    }

    async fn destroy(&self, _params: agentenv_proto::DestroyParams) -> DriverResult<EmptyResult> {
        Err(DriverError::InvalidInput { message: "destroy is not wired yet".to_owned() })
    }

    async fn shutdown(&mut self, _params: agentenv_proto::ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult::default())
    }
}
```

Add the recording test runner in the test module:

```rust
#[derive(Clone, Default)]
struct RecordingRunner {
    scripts: Arc<Mutex<Vec<ScriptedCommand>>>,
    calls: Arc<Mutex<Vec<CommandRequest>>>,
}

#[derive(Debug)]
struct ScriptedCommand {
    args: Vec<String>,
    result: Result<CommandOutput, ScriptedSpawnError>,
}

#[derive(Debug)]
struct ScriptedSpawnError {
    kind: std::io::ErrorKind,
    message: String,
}

impl RecordingRunner {
    fn new<const N: usize>(scripts: [ScriptedCommand; N]) -> Self {
        Self {
            scripts: Arc::new(Mutex::new(scripts.into_iter().collect())),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.args.clone())
            .collect()
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, _program: &str, request: CommandRequest) -> Result<CommandOutput, CommandRunError> {
        self.calls.lock().unwrap().push(request.clone());
        let script = self.scripts.lock().unwrap().remove(0);
        assert_eq!(request.args, script.args);
        script.result.map_err(|err| {
            CommandRunError::Spawn(std::io::Error::new(err.kind, err.message))
        })
    }

    fn spawn(&self, program: &str, request: CommandRequest) -> Result<(), CommandRunError> {
        self.run(program, request).map(|_| ())
    }
}

fn scripted_ok<const N: usize>(args: [&str; N], stdout: &str) -> ScriptedCommand {
    ScriptedCommand {
        args: args.into_iter().map(str::to_owned).collect(),
        result: Ok(CommandOutput {
            status: Some(0),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }),
    }
}

fn scripted_fail<const N: usize>(
    args: [&str; N],
    status: i32,
    stdout: &str,
    stderr: &str,
) -> ScriptedCommand {
    ScriptedCommand {
        args: args.into_iter().map(str::to_owned).collect(),
        result: Ok(CommandOutput {
            status: Some(status),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        }),
    }
}

fn scripted_spawn_error<const N: usize>(
    args: [&str; N],
    kind: std::io::ErrorKind,
    message: &str,
) -> ScriptedCommand {
    ScriptedCommand {
        args: args.into_iter().map(str::to_owned).collect(),
        result: Err(ScriptedSpawnError {
            kind,
            message: message.to_owned(),
        }),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sandbox-openshell preflight`

Expected: PASS for the new preflight tests.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat: initialize openshell sandbox driver"
```

## Task 3: Implement Sandbox Lifecycle Command Mapping

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing tests for lifecycle methods**

Add tests for command mapping:

```rust
#[tokio::test]
async fn create_uses_explicit_name_image_remote_and_env_only_credentials() {
    let secret = "secret-value-not-in-argv";
    let runner = RecordingRunner::new([scripted_ok(
        ["sandbox", "create", "--name", "devbox", "--keep", "--no-auto-providers", "--from", "ubuntu:24.04", "--remote", "alice@example.com"],
        "created devbox\n",
    )]);
    let driver = OpenShellDriver::with_runner("openshell", runner.clone());
    let mut metadata = BTreeMap::new();
    metadata.insert("name".to_owned(), serde_json::json!("devbox"));
    metadata.insert("remote".to_owned(), serde_json::json!("alice@example.com"));
    let mut env = BTreeMap::new();
    env.insert("OPENAI_API_KEY".to_owned(), secret.to_owned());

    let handle = driver
        .create(SandboxSpec {
            image: Some("ubuntu:24.04".to_owned()),
            env,
            policy: None,
            metadata,
        })
        .await
        .unwrap();

    assert_eq!(handle.handle, "devbox");
    let calls = runner.calls();
    assert_eq!(calls[0].env.get("OPENAI_API_KEY"), Some(&secret.to_owned()));
    assert!(!calls[0].args.iter().any(|arg| arg.contains(secret)));
}

#[tokio::test]
async fn create_uses_openclaw_default_image_and_generated_name() {
    let runner = RecordingRunner::new([ScriptedCommand {
        args: Vec::new(),
        result: Ok(CommandOutput {
            status: Some(0),
            stdout: "created\n".to_owned(),
            stderr: String::new(),
        }),
    }]);
    let driver = OpenShellDriver::with_runner("openshell", runner.clone());

    let handle = driver
        .create(SandboxSpec {
            image: None,
            env: BTreeMap::new(),
            policy: None,
            metadata: BTreeMap::new(),
        })
        .await
        .unwrap();

    assert!(handle.handle.starts_with("agentenv-"));
    let args = runner.commands()[0].clone();
    assert_eq!(args[0..2], ["sandbox".to_owned(), "create".to_owned()]);
    assert!(args.contains(&"--name".to_owned()));
    assert!(args.contains(&handle.handle));
    assert!(args.contains(&"--from".to_owned()));
    assert!(args.contains(&"openclaw".to_owned()));
}

#[tokio::test]
async fn exec_returns_status_stdout_and_stderr() {
    let runner = RecordingRunner::new([scripted_fail(
        ["sandbox", "connect", "devbox", "--", "whoami"],
        7,
        "sandbox\n",
        "warning\n",
    )]);
    let driver = OpenShellDriver::with_runner("openshell", runner);

    let result = driver
        .exec(ExecParams {
            handle: "devbox".to_owned(),
            cmd: "whoami".to_owned(),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .unwrap();

    assert_eq!(result.status, 7);
    assert_eq!(result.stdout, "sandbox\n");
    assert_eq!(result.stderr, "warning\n");
}

#[tokio::test]
async fn copy_status_logs_stream_stop_and_destroy_use_expected_commands() {
    let runner = RecordingRunner::new([
        scripted_ok(["sandbox", "connect", "devbox", "--", "true"], ""),
        scripted_ok(["sandbox", "upload", "devbox", "./src", "/sandbox/src"], ""),
        scripted_ok(["sandbox", "download", "devbox", "/sandbox/out", "./out"], ""),
        scripted_ok(["sandbox", "get", "devbox"], "status: running\n"),
        scripted_ok(["logs", "devbox", "--since", "5m"], "[1775014132.690] [sandbox] [INFO ] message\n"),
        scripted_ok(["logs", "devbox", "--tail", "--since", "5m"], ""),
        scripted_ok(["sandbox", "stop", "devbox"], ""),
        scripted_ok(["sandbox", "delete", "devbox"], ""),
    ]);
    let driver = OpenShellDriver::with_runner("openshell", runner.clone());

    let shell = driver.connect(ConnectParams { handle: "devbox".to_owned() }).await.unwrap();
    assert_eq!(shell.session_id, "devbox");
    driver.copy_in(CopyInParams { handle: "devbox".to_owned(), src_host_path: "./src".to_owned(), dst_sandbox_path: "/sandbox/src".to_owned() }).await.unwrap();
    driver.copy_out(CopyOutParams { handle: "devbox".to_owned(), src_sandbox_path: "/sandbox/out".to_owned(), dst_host_path: "./out".to_owned() }).await.unwrap();
    let status = driver.status(SandboxStatusParams { handle: "devbox".to_owned() }).await.unwrap();
    assert_eq!(status.phase, SandboxPhase::Running);
    let logs = driver.logs(LogsParams { handle: "devbox".to_owned(), since: Some("5m".to_owned()), follow: false }).await.unwrap();
    assert_eq!(logs.entries.len(), 1);
    driver.logs_stream(LogsStreamParams { handle: "devbox".to_owned(), since: Some("5m".to_owned()) }).await.unwrap();
    driver.stop(StopParams { handle: "devbox".to_owned() }).await.unwrap();
    driver.destroy(DestroyParams { handle: "devbox".to_owned() }).await.unwrap();
}
```

Add imports in the test module:

```rust
use agentenv_proto::{
    ConnectParams, CopyInParams, CopyOutParams, DestroyParams, ExecParams, LogsParams,
    LogsStreamParams, SandboxPhase, SandboxSpec, SandboxStatusParams, StopParams,
};
```

Add `calls()` to `RecordingRunner`:

```rust
fn calls(&self) -> Vec<CommandRequest> {
    self.calls.lock().unwrap().clone()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sandbox-openshell create_uses_explicit_name_image_remote_and_env_only_credentials exec_returns_status_stdout_and_stderr copy_status_logs_stream_stop_and_destroy_use_expected_commands`

Expected: FAIL because lifecycle methods still return `InvalidInput`.

- [ ] **Step 3: Implement lifecycle methods**

Add helpers:

```rust
fn metadata_string(
    metadata: &BTreeMap<String, serde_json::Value>,
    key: &str,
) -> DriverResult<Option<String>> {
    match metadata.get(key) {
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.clone()))
        }
        Some(serde_json::Value::String(_)) | None => Ok(None),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be a string"),
        }),
    }
}

fn sandbox_name(spec: &agentenv_proto::SandboxSpec) -> DriverResult<String> {
    Ok(metadata_string(&spec.metadata, "name")?
        .unwrap_or_else(|| format!("agentenv-{}", uuid::Uuid::new_v4().simple())))
}

fn success_or_command_error(
    command: String,
    output: CommandOutput,
) -> DriverResult<CommandOutput> {
    if command_succeeded(&output) {
        Ok(output)
    } else {
        Err(DriverError::CommandFailed {
            command,
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn parse_status(output: &str) -> agentenv_proto::SandboxStatus {
    let lower = output.to_ascii_lowercase();
    let phase = if lower.contains("destroyed") || lower.contains("deleted") {
        agentenv_proto::SandboxPhase::Destroyed
    } else if lower.contains("stopped") {
        agentenv_proto::SandboxPhase::Stopped
    } else if lower.contains("error") || lower.contains("failed") {
        agentenv_proto::SandboxPhase::Error
    } else {
        agentenv_proto::SandboxPhase::Running
    };

    agentenv_proto::SandboxStatus {
        healthy: matches!(phase, agentenv_proto::SandboxPhase::Running),
        phase,
        last_ping: None,
    }
}

fn parse_log_line(line: &str) -> agentenv_proto::LogEntry {
    let level = if line.contains("[ERROR") || line.contains("[FATAL") {
        agentenv_proto::LogLevel::Error
    } else if line.contains("[WARN") || line.contains("[MED") || line.contains("[HIGH") || line.contains("[CRIT") {
        agentenv_proto::LogLevel::Warn
    } else {
        agentenv_proto::LogLevel::Info
    };
    let mut kv = BTreeMap::new();
    if line.contains("DENIED") || line.contains("BLOCKED") || line.contains("action=deny") {
        kv.insert("egress_denied".to_owned(), serde_json::Value::Bool(true));
    }

    agentenv_proto::LogEntry {
        level,
        ts: String::new(),
        msg: line.to_owned(),
        kv,
    }
}
```

Replace lifecycle stubs with implementations that use `success_or_command_error`:

```rust
async fn create(&self, spec: agentenv_proto::SandboxSpec) -> DriverResult<agentenv_proto::SandboxHandle> {
    let name = sandbox_name(&spec)?;
    let image = spec.image.clone().unwrap_or_else(|| "openclaw".to_owned());
    let mut request = self.command([
        "sandbox".to_owned(),
        "create".to_owned(),
        "--name".to_owned(),
        name.clone(),
        "--keep".to_owned(),
        "--no-auto-providers".to_owned(),
        "--from".to_owned(),
        image,
    ]);
    if let Some(remote) = metadata_string(&spec.metadata, "remote")? {
        request.args.push("--remote".to_owned());
        request.args.push(remote);
    }
    request.env.extend(spec.env.clone());

    let command = render_command(&self.openshell_bin, &request.args);
    let output = self.run(request)?;
    success_or_command_error(command, output)?;

    if let Some(policy) = spec.policy {
        self.apply_policy(agentenv_proto::ApplyPolicyParams {
            handle: name.clone(),
            policy,
        })
        .await?;
    }

    Ok(agentenv_proto::SandboxHandle { handle: name })
}

async fn connect(&self, params: agentenv_proto::ConnectParams) -> DriverResult<agentenv_proto::ShellHandle> {
    let request = self.command(["sandbox", "connect", params.handle.as_str(), "--", "true"]);
    let command = render_command(&self.openshell_bin, &request.args);
    success_or_command_error(command, self.run(request)?)?;
    Ok(agentenv_proto::ShellHandle {
        session_id: params.handle,
        tty: true,
        working_dir: Some("/sandbox".to_owned()),
    })
}

async fn exec(&self, params: agentenv_proto::ExecParams) -> DriverResult<agentenv_proto::ExecResult> {
    let mut request = self.command(["sandbox", "connect", params.handle.as_str(), "--", params.cmd.as_str()]);
    request.env.extend(params.env);
    let output = self.run(request)?;
    Ok(agentenv_proto::ExecResult {
        status: output.status.unwrap_or(1),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}
```

Implement `copy_in`, `copy_out`, `status`, `logs`, `logs_stream`, `stop`, and `destroy` with the command mappings from the spec:

```rust
async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
    let request = self.command(["sandbox", "upload", params.handle.as_str(), params.src_host_path.as_str(), params.dst_sandbox_path.as_str()]);
    let command = render_command(&self.openshell_bin, &request.args);
    success_or_command_error(command, self.run(request)?)?;
    Ok(EmptyResult::default())
}

async fn copy_out(&self, params: agentenv_proto::CopyOutParams) -> DriverResult<EmptyResult> {
    let request = self.command(["sandbox", "download", params.handle.as_str(), params.src_sandbox_path.as_str(), params.dst_host_path.as_str()]);
    let command = render_command(&self.openshell_bin, &request.args);
    success_or_command_error(command, self.run(request)?)?;
    Ok(EmptyResult::default())
}

async fn status(&self, params: agentenv_proto::SandboxStatusParams) -> DriverResult<agentenv_proto::SandboxStatus> {
    let request = self.command(["sandbox", "get", params.handle.as_str()]);
    let command = render_command(&self.openshell_bin, &request.args);
    let output = success_or_command_error(command, self.run(request)?)?;
    Ok(parse_status(&output.stdout))
}

async fn logs(&self, params: agentenv_proto::LogsParams) -> DriverResult<agentenv_proto::LogsResult> {
    let mut request = self.command(["logs", params.handle.as_str()]);
    if params.follow {
        request.args.push("--tail".to_owned());
    }
    if let Some(since) = params.since {
        request.args.push("--since".to_owned());
        request.args.push(since);
    }
    let command = render_command(&self.openshell_bin, &request.args);
    let output = success_or_command_error(command, self.run(request)?)?;
    Ok(agentenv_proto::LogsResult {
        entries: output.stdout.lines().map(parse_log_line).collect(),
    })
}

async fn logs_stream(&self, params: agentenv_proto::LogsStreamParams) -> DriverResult<EmptyResult> {
    let mut request = self.command(["logs", params.handle.as_str(), "--tail"]);
    if let Some(since) = params.since {
        request.args.push("--since".to_owned());
        request.args.push(since);
    }
    let command = render_command(&self.openshell_bin, &request.args);
    self.runner
        .spawn(&self.openshell_bin, request)
        .map_err(|err| command_run_error(command, err))?;
    Ok(EmptyResult::default())
}

async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
    let request = self.command(["sandbox", "stop", params.handle.as_str()]);
    let command = render_command(&self.openshell_bin, &request.args);
    success_or_command_error(command, self.run(request)?)?;
    Ok(EmptyResult::default())
}

async fn destroy(&self, params: agentenv_proto::DestroyParams) -> DriverResult<EmptyResult> {
    let request = self.command(["sandbox", "delete", params.handle.as_str()]);
    let command = render_command(&self.openshell_bin, &request.args);
    success_or_command_error(command, self.run(request)?)?;
    self.current_policies.lock().unwrap().remove(&params.handle);
    Ok(EmptyResult::default())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sandbox-openshell create_uses exec_returns copy_status`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat: map openshell sandbox lifecycle commands"
```

## Task 4: Implement Policy Hot Reload and Inference Updates

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing tests for policy application**

Add these tests:

```rust
#[tokio::test]
async fn apply_policy_writes_temp_policy_runs_policy_set_and_removes_file() {
    let policy = test_policy_with_host("api.github.com");
    let runner = RecordingRunner::new([ScriptedCommand {
        args: Vec::new(),
        result: Ok(CommandOutput {
            status: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        }),
    }]);
    let driver = OpenShellDriver::with_runner("openshell", runner.clone());

    let result = driver
        .apply_policy(ApplyPolicyParams {
            handle: "devbox".to_owned(),
            policy,
        })
        .await
        .unwrap();

    assert!(result.hot_reloaded);
    let args = runner.commands()[0].clone();
    assert_eq!(args[0..4], ["policy".to_owned(), "set".to_owned(), "devbox".to_owned(), "--policy".to_owned()]);
    assert!(args.ends_with(&["--wait".to_owned()]));
    let policy_path = args[4].clone();
    assert!(!std::path::Path::new(&policy_path).exists());
}

#[tokio::test]
async fn apply_policy_rejects_locked_domain_change_before_running_command() {
    let current = test_policy_with_host("api.github.com");
    let mut next = current.clone();
    next.filesystem.read_write.push("/var/tmp".to_owned());
    let runner = RecordingRunner::default();
    let driver = OpenShellDriver::with_runner("openshell", runner.clone());
    driver
        .current_policies
        .lock()
        .unwrap()
        .insert("devbox".to_owned(), current);

    let err = driver
        .apply_policy(ApplyPolicyParams {
            handle: "devbox".to_owned(),
            policy: next,
        })
        .await
        .expect_err("locked domain changes should fail");

    assert!(err.to_string().contains("filesystem"));
    assert!(runner.commands().is_empty());
}

#[tokio::test]
async fn apply_policy_also_applies_inference_update() {
    let mut policy = test_policy_with_host("api.github.com");
    policy.inference.routes.push(agentenv_proto::InferenceRoute {
        matcher: "default".to_owned(),
        provider: "nvidia-prod".to_owned(),
        model: "nvidia/nemotron".to_owned(),
        base_url: None,
        timeout_seconds: Some(300),
    });
    let runner = RecordingRunner::new([
        ScriptedCommand {
            args: Vec::new(),
            result: Ok(CommandOutput { status: Some(0), stdout: String::new(), stderr: String::new() }),
        },
        scripted_ok(["inference", "set", "--provider", "nvidia-prod", "--model", "nvidia/nemotron", "--timeout", "300"], ""),
    ]);
    let driver = OpenShellDriver::with_runner("openshell", runner.clone());

    driver
        .apply_policy(ApplyPolicyParams {
            handle: "devbox".to_owned(),
            policy,
        })
        .await
        .unwrap();

    assert_eq!(runner.commands().len(), 2);
}
```

Add imports:

```rust
use agentenv_proto::{ApplyPolicyParams, HttpAccessLevel, NetworkRule, NetworkTarget, PolicyReloadability};
```

Add test helper:

```rust
fn test_policy_with_host(host: &str) -> agentenv_proto::NetworkPolicy {
    agentenv_proto::NetworkPolicy {
        network: agentenv_proto::NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: vec![NetworkRule {
                target: NetworkTarget::Host {
                    host: host.to_owned(),
                    port: Some(443),
                    scheme: Some("https".to_owned()),
                    http_access: Some(HttpAccessLevel::ReadOnly),
                },
            }],
            deny: Vec::new(),
            approval_required: Vec::new(),
        },
        filesystem: agentenv_proto::FilesystemPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            read_only: vec!["/usr".to_owned()],
            read_write: vec!["/sandbox".to_owned(), "/tmp".to_owned()],
        },
        process: agentenv_proto::ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: "sandbox".to_owned(),
            run_as_group: "sandbox".to_owned(),
            profile: "balanced".to_owned(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: agentenv_proto::InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sandbox-openshell apply_policy`

Expected: FAIL because `apply_policy` still returns `InvalidInput`.

- [ ] **Step 3: Implement policy application**

Add imports:

```rust
use std::fs::{self, OpenOptions};
use std::io::Write;
```

Add helper functions:

```rust
fn write_temp_policy(handle: &str, policy_yaml: &str) -> DriverResult<std::path::PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "agentenv-openshell-policy-{handle}-{}.yaml",
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&path).map_err(|source| DriverError::CommandSpawn {
        command: format!("write policy {}", path.display()),
        source,
    })?;
    file.write_all(policy_yaml.as_bytes()).map_err(|source| DriverError::CommandSpawn {
        command: format!("write policy {}", path.display()),
        source,
    })?;
    Ok(path)
}

fn map_policy_error(err: agentenv_policy::PolicyError) -> DriverError {
    DriverError::PolicyTranslation {
        message: err.to_string(),
    }
}
```

Replace the `apply_policy` stub:

```rust
async fn apply_policy(&self, params: agentenv_proto::ApplyPolicyParams) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
    if let Some(current) = self.current_policies.lock().unwrap().get(&params.handle).cloned() {
        classify_policy_update(&current, &params.policy).map_err(map_policy_error)?;
    }

    let translated = translate_for_openshell(&params.policy).map_err(map_policy_error)?;
    let policy_path = write_temp_policy(&params.handle, &translated.policy_yaml)?;
    let policy_path_string = policy_path.to_string_lossy().into_owned();
    let request = self.command([
        "policy".to_owned(),
        "set".to_owned(),
        params.handle.clone(),
        "--policy".to_owned(),
        policy_path_string,
        "--wait".to_owned(),
    ]);
    let command = render_command(&self.openshell_bin, &request.args);
    let policy_result = success_or_command_error(command, self.run(request)?);
    let _ = fs::remove_file(&policy_path);
    policy_result?;

    if let Some(inference) = translated.inference_update {
        let mut args = vec![
            "inference".to_owned(),
            "set".to_owned(),
            "--provider".to_owned(),
            inference.provider,
            "--model".to_owned(),
            inference.model,
        ];
        if let Some(timeout) = inference.timeout_seconds {
            args.push("--timeout".to_owned());
            args.push(timeout.to_string());
        }
        let request = self.command(args);
        let command = render_command(&self.openshell_bin, &request.args);
        success_or_command_error(command, self.run(request)?)?;
    }

    self.current_policies
        .lock()
        .unwrap()
        .insert(params.handle, params.policy);

    Ok(agentenv_proto::ApplyPolicyResult { hot_reloaded: true })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sandbox-openshell apply_policy`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat: apply openshell policies"
```

## Task 5: Add Sandbox Driver Conformance Coverage

**Files:**
- Modify: `tests/driver-conformance/src/lib.rs`
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing conformance helper tests**

Add `SandboxDriver` imports in `tests/driver-conformance/src/lib.rs` tests:

```rust
use agentenv_core::driver::{AgentDriver, DriverResult, SandboxDriver};
```

Add a fake sandbox driver and tests in `tests/driver-conformance/src/lib.rs`:

```rust
#[derive(Default)]
struct FakeSandboxDriver {
    init_kind: Option<DriverKind>,
    init_capabilities: Option<Capabilities>,
    preflight_ok: bool,
}

#[async_trait]
impl SandboxDriver for FakeSandboxDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(InitializeResult {
            driver: DriverInfo {
                name: "fake-sandbox".to_owned(),
                kind: self.init_kind.clone().unwrap_or(DriverKind::Sandbox),
                version: "0.0.1".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: self.init_capabilities.clone().unwrap_or_else(|| {
                Capabilities::Sandbox(SandboxCapabilities {
                    supports_hot_reload_policy: true,
                    supports_filesystem_lockdown: true,
                    supports_syscall_filter: true,
                    supports_native_inference_routing: true,
                    supports_remote_host: true,
                })
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(PreflightResult { ok: self.preflight_ok, issues: Vec::new() })
    }

    async fn create(&self, _spec: agentenv_proto::SandboxSpec) -> DriverResult<agentenv_proto::SandboxHandle> { unreachable!() }
    async fn connect(&self, _params: agentenv_proto::ConnectParams) -> DriverResult<agentenv_proto::ShellHandle> { unreachable!() }
    async fn exec(&self, _params: agentenv_proto::ExecParams) -> DriverResult<agentenv_proto::ExecResult> { unreachable!() }
    async fn copy_in(&self, _params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> { unreachable!() }
    async fn copy_out(&self, _params: agentenv_proto::CopyOutParams) -> DriverResult<EmptyResult> { unreachable!() }
    async fn apply_policy(&self, _params: agentenv_proto::ApplyPolicyParams) -> DriverResult<agentenv_proto::ApplyPolicyResult> { unreachable!() }
    async fn status(&self, _params: agentenv_proto::SandboxStatusParams) -> DriverResult<agentenv_proto::SandboxStatus> { unreachable!() }
    async fn logs(&self, _params: agentenv_proto::LogsParams) -> DriverResult<agentenv_proto::LogsResult> { unreachable!() }
    async fn logs_stream(&self, _params: agentenv_proto::LogsStreamParams) -> DriverResult<EmptyResult> { unreachable!() }
    async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> { unreachable!() }
    async fn destroy(&self, _params: agentenv_proto::DestroyParams) -> DriverResult<EmptyResult> { unreachable!() }
    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> { Ok(EmptyResult::default()) }
}

#[tokio::test]
async fn sandbox_driver_contract_accepts_sandbox_capabilities() {
    let mut driver = FakeSandboxDriver { preflight_ok: true, ..FakeSandboxDriver::default() };

    assert_sandbox_driver_contract(&mut driver).await.unwrap();
}

#[tokio::test]
async fn sandbox_driver_contract_rejects_non_sandbox_kind() {
    let mut driver = FakeSandboxDriver {
        init_kind: Some(DriverKind::Agent),
        preflight_ok: true,
        ..FakeSandboxDriver::default()
    };

    let err = assert_sandbox_driver_contract(&mut driver).await.unwrap_err();

    assert!(err.to_string().contains("DriverKind::Sandbox"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p driver-conformance sandbox_driver_contract`

Expected: FAIL because `assert_sandbox_driver_contract` does not exist.

- [ ] **Step 3: Implement conformance helper**

Add to `tests/driver-conformance/src/lib.rs` next to `assert_agent_driver_contract`:

```rust
pub async fn assert_sandbox_driver_contract<D: agentenv_core::driver::SandboxDriver>(
    driver: &mut D,
) -> anyhow::Result<()> {
    let init = driver
        .initialize(agentenv_proto::InitializeParams {
            schema_version: agentenv_proto::SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1".to_owned(),
            workdir: "/tmp/agentenv".to_owned(),
            log_level: agentenv_proto::LogLevel::Info,
        })
        .await?;

    agentenv_core::driver::ensure_protocol_compatible(&init)?;
    anyhow::ensure!(
        init.driver.kind == DriverKind::Sandbox,
        "initialize must report DriverKind::Sandbox"
    );

    let Capabilities::Sandbox(capabilities) = init.capabilities else {
        anyhow::bail!("initialize must report Capabilities::Sandbox");
    };
    anyhow::ensure!(
        capabilities.supports_hot_reload_policy,
        "OpenShell conformance requires hot reload capability"
    );

    let preflight = driver
        .preflight(agentenv_proto::PreflightParams::default())
        .await?;
    anyhow::ensure!(preflight.ok, "preflight must pass");

    Ok(())
}
```

Add OpenShell conformance test in `sandbox-openshell`:

```rust
#[tokio::test]
async fn openshell_driver_satisfies_sandbox_conformance_contract() {
    let runner = RecordingRunner::new([
        scripted_ok(["--version"], "openshell 0.0.30\n"),
        scripted_ok(["gateway", "status"], "gateway running\n"),
    ]);
    let mut driver = OpenShellDriver::with_runner("openshell", runner);

    driver_conformance::assert_sandbox_driver_contract(&mut driver)
        .await
        .unwrap();
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p driver-conformance sandbox_driver_contract && cargo test -p sandbox-openshell conformance`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/driver-conformance/src/lib.rs crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "test: add sandbox driver conformance"
```

## Task 6: Add Gated OpenShell Integration Tests and README

**Files:**
- Create: `crates/drivers/sandbox-openshell/tests/integration.rs`
- Modify: `crates/drivers/sandbox-openshell/Cargo.toml`
- Modify: `crates/drivers/sandbox-openshell/README.md`

- [ ] **Step 1: Add integration feature**

Add to `crates/drivers/sandbox-openshell/Cargo.toml`:

```toml
[features]
integration = []
```

- [ ] **Step 2: Write ignored integration tests**

Create `crates/drivers/sandbox-openshell/tests/integration.rs`:

```rust
#![cfg(feature = "integration")]

use std::collections::BTreeMap;

use agentenv_core::driver::SandboxDriver;
use agentenv_proto::{
    ApplyPolicyParams, DestroyParams, ExecParams, HttpAccessLevel, LogsParams, NetworkRule,
    NetworkTarget, PolicyReloadability, SandboxSpec,
};
use sandbox_openshell::OpenShellDriver;

const RUN_ENV: &str = "AGENTENV_RUN_OPENSHELL_INTEGRATION";

#[tokio::test]
#[ignore = "requires OpenShell >= 0.0.30, Docker, and a working gateway"]
async fn openshell_create_exec_policy_logs_and_destroy_flow() {
    if std::env::var_os(RUN_ENV).is_none() {
        eprintln!("skipping OpenShell integration; set {RUN_ENV}=1");
        return;
    }

    let driver = OpenShellDriver::default();
    let name = format!("agentenv-it-{}", uuid::Uuid::new_v4().simple());
    let mut metadata = BTreeMap::new();
    metadata.insert("name".to_owned(), serde_json::json!(name));
    let handle = driver
        .create(SandboxSpec {
            image: Some("openclaw".to_owned()),
            env: BTreeMap::new(),
            policy: None,
            metadata,
        })
        .await
        .expect("create sandbox");

    let flow = async {
        let whoami = driver
            .exec(ExecParams {
                handle: handle.handle.clone(),
                cmd: "whoami".to_owned(),
                tty: false,
                env: BTreeMap::new(),
            })
            .await
            .expect("exec whoami");
        assert_eq!(whoami.status, 0);

        let blocked = driver
            .exec(ExecParams {
                handle: handle.handle.clone(),
                cmd: "curl -s https://api.github.com/zen".to_owned(),
                tty: false,
                env: BTreeMap::new(),
            })
            .await
            .expect("exec blocked curl");
        assert_ne!(blocked.status, 0);

        driver
            .apply_policy(ApplyPolicyParams {
                handle: handle.handle.clone(),
                policy: github_read_policy(),
            })
            .await
            .expect("apply github read policy");

        let allowed = driver
            .exec(ExecParams {
                handle: handle.handle.clone(),
                cmd: "curl -s https://api.github.com/zen".to_owned(),
                tty: false,
                env: BTreeMap::new(),
            })
            .await
            .expect("exec allowed curl");
        assert_eq!(allowed.status, 0);

        let logs = driver
            .logs(LogsParams {
                handle: handle.handle.clone(),
                since: Some("5m".to_owned()),
                follow: false,
            })
            .await
            .expect("read logs");
        assert!(logs.entries.iter().any(|entry| entry.msg.contains("api.github.com")));
    };

    let result = flow.await;
    driver
        .destroy(DestroyParams {
            handle: handle.handle,
        })
        .await
        .expect("destroy sandbox");
    result
}

#[tokio::test]
#[ignore = "requires OpenShell >= 0.0.30, Docker, and a working gateway"]
async fn credentials_do_not_appear_in_sandbox_filesystem() {
    if std::env::var_os(RUN_ENV).is_none() {
        eprintln!("skipping OpenShell credential integration; set {RUN_ENV}=1");
        return;
    }

    let driver = OpenShellDriver::default();
    let marker = format!("agentenv-secret-{}", uuid::Uuid::new_v4().simple());
    let name = format!("agentenv-secret-it-{}", uuid::Uuid::new_v4().simple());
    let mut metadata = BTreeMap::new();
    metadata.insert("name".to_owned(), serde_json::json!(name));
    let mut env = BTreeMap::new();
    env.insert("AGENTENV_SECRET_MARKER".to_owned(), marker.clone());
    let handle = driver
        .create(SandboxSpec {
            image: Some("openclaw".to_owned()),
            env,
            policy: None,
            metadata,
        })
        .await
        .expect("create sandbox");

    let grep = driver
        .exec(ExecParams {
            handle: handle.handle.clone(),
            cmd: format!("grep -R {marker} /sandbox /var/log /tmp 2>/dev/null"),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("grep secret marker");

    driver
        .destroy(DestroyParams {
            handle: handle.handle,
        })
        .await
        .expect("destroy sandbox");

    assert_ne!(grep.status, 0);
    assert!(!grep.stdout.contains(&marker));
}

fn github_read_policy() -> agentenv_proto::NetworkPolicy {
    agentenv_proto::NetworkPolicy {
        network: agentenv_proto::NetworkAccessPolicy {
            reloadability: PolicyReloadability::HotReload,
            allow: vec![NetworkRule {
                target: NetworkTarget::Host {
                    host: "api.github.com".to_owned(),
                    port: Some(443),
                    scheme: Some("https".to_owned()),
                    http_access: Some(HttpAccessLevel::ReadOnly),
                },
            }],
            deny: Vec::new(),
            approval_required: Vec::new(),
        },
        filesystem: agentenv_proto::FilesystemPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            read_only: vec!["/usr".to_owned(), "/lib".to_owned(), "/proc".to_owned()],
            read_write: vec!["/sandbox".to_owned(), "/tmp".to_owned()],
        },
        process: agentenv_proto::ProcessPolicy {
            reloadability: PolicyReloadability::LockedAtCreate,
            run_as_user: "sandbox".to_owned(),
            run_as_group: "sandbox".to_owned(),
            profile: "balanced".to_owned(),
            allow_syscalls: Vec::new(),
            deny_syscalls: Vec::new(),
        },
        inference: agentenv_proto::InferencePolicy {
            reloadability: PolicyReloadability::HotReload,
            routes: Vec::new(),
        },
    }
}
```

- [ ] **Step 3: Update README**

Replace `crates/drivers/sandbox-openshell/README.md` with:

```markdown
# sandbox-openshell

Built-in `SandboxDriver` for NVIDIA OpenShell.

The driver shells out to the `openshell` CLI, requires OpenShell `>= 0.0.30`, and maps the `agentenv` sandbox protocol to OpenShell sandbox lifecycle commands. Credentials from `SandboxSpec.env` are injected as process environment variables only; they are not written to image layers, policy files, or command arguments.

## Integration Tests

Unit tests use a recording command runner and do not require OpenShell.

Real end-to-end tests are gated because they require OpenShell, Docker, and a working gateway:

```bash
AGENTENV_RUN_OPENSHELL_INTEGRATION=1 cargo test -p sandbox-openshell --features integration -- --ignored
```

The integration flow creates a sandbox, executes `whoami`, verifies default-deny networking, hot-reloads a GitHub read policy, verifies a permitted `curl`, checks logs, and destroys the sandbox.
```

- [ ] **Step 4: Run tests to verify ignored integration compiles**

Run: `cargo test -p sandbox-openshell --features integration --no-run`

Expected: PASS. The OpenShell CLI is not required for `--no-run`.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-openshell/Cargo.toml crates/drivers/sandbox-openshell/README.md crates/drivers/sandbox-openshell/tests/integration.rs
git commit -m "test: add openshell integration scaffolding"
```

## Task 7: Final Verification

**Files:**
- Modify after failures only: files touched by previous tasks

- [ ] **Step 1: Run formatting**

Run: `cargo fmt`

Expected: command exits 0.

- [ ] **Step 2: Run focused tests**

Run: `cargo test -p agentenv-core -p driver-conformance -p sandbox-openshell`

Expected: all non-ignored tests pass.

- [ ] **Step 3: Run integration compile check**

Run: `cargo test -p sandbox-openshell --features integration --no-run`

Expected: test binaries build without requiring OpenShell.

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`

Expected: all non-ignored workspace tests pass.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Expected: clippy exits 0 with no warnings.

- [ ] **Step 6: Inspect final diff**

Run: `git diff --stat HEAD`

Expected: diff only includes files named in this plan.

- [ ] **Step 7: Commit verification fixes if needed**

If Step 1 through Step 6 required code changes:

```bash
git add crates/agentenv-core/src/driver.rs crates/drivers/sandbox-openshell tests/driver-conformance/src/lib.rs
git commit -m "fix: verify openshell sandbox driver"
```

If no changes were required, do not create an empty commit.

## Self-Review

- Spec coverage: every method in issue #7 is mapped to a task. Capability declaration is covered in Task 2, lifecycle commands in Task 3, policy and inference in Task 4, conformance in Task 5, integration and credential grep in Task 6, and final cargo verification in Task 7.
- Red-flag scan: the plan contains no deferred markers, incomplete file paths, or unnamed tests.
- Type consistency: all test and implementation snippets use current `agentenv_proto` type names and the existing `agentenv_core::driver::SandboxDriver` trait method names.
