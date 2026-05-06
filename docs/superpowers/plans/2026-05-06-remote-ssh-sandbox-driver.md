# Remote SSH Sandbox Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a built-in `remote-ssh` sandbox driver that connects agentenv to pre-provisioned VMs over host `ssh` and `scp`.

**Architecture:** Create `crates/drivers/sandbox-remote-ssh` as an in-process `SandboxDriver` implementation. The driver parses SSH config from `SandboxSpec.metadata` at `create`, persists non-secret target data in a URI handle, and reparses that handle for `exec`, `copy_in`, `copy_out`, `status`, `connect`, `stop`, and `destroy` across fresh CLI processes. Wire the new aliases through the built-in registry and factory, and pass generic sandbox blueprint extras into sandbox metadata without changing the driver protocol.

**Tech Stack:** Rust 2021, `agentenv-core`, `agentenv-proto`, `async-trait`, `url`, mocked command runners, `driver-conformance`, Tokio tests.

---

## File Structure

- `crates/drivers/sandbox-remote-ssh/Cargo.toml`: new crate manifest and dependencies.
- `crates/drivers/sandbox-remote-ssh/README.md`: short driver description and integration test command.
- `crates/drivers/sandbox-remote-ssh/src/lib.rs`: driver implementation, command runner, target parsing, handle parsing, and unit tests.
- `crates/drivers/sandbox-remote-ssh/tests/integration.rs`: ignored live SSH integration flow.
- `Cargo.toml`: workspace member registration.
- `crates/agentenv/Cargo.toml`: binary crate dependency on `sandbox-remote-ssh`.
- `crates/agentenv/src/builtin_factory.rs`: alias resolution for `remote-ssh` and `sandbox-remote-ssh`, including pinned builds.
- `crates/agentenv-core/src/driver_catalog.rs`: built-in driver registry aliases.
- `crates/agentenv-core/src/runtime.rs`: generic sandbox extra metadata propagation and runtime tests.

## Task 1: Scaffold Crate And Initialization

**Files:**
- Create: `crates/drivers/sandbox-remote-ssh/Cargo.toml`
- Create: `crates/drivers/sandbox-remote-ssh/README.md`
- Create: `crates/drivers/sandbox-remote-ssh/src/lib.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Add the new workspace member and manifest**

In root `Cargo.toml`, add the crate beside `sandbox-openshell`:

```toml
    "crates/drivers/sandbox-openshell",
    "crates/drivers/sandbox-remote-ssh",
```

Create `crates/drivers/sandbox-remote-ssh/Cargo.toml`:

```toml
[package]
name = "sandbox-remote-ssh"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
homepage.workspace = true
authors.workspace = true
readme = "README.md"
description = "Remote SSH sandbox driver for pre-provisioned VMs"

[features]
integration = []

[dependencies]
agentenv-core = { path = "../../agentenv-core" }
agentenv-proto = { path = "../../agentenv-proto" }
async-trait.workspace = true
serde_json.workspace = true
url.workspace = true
uuid.workspace = true

[dev-dependencies]
driver-conformance = { path = "../../../tests/driver-conformance" }
tokio = { version = "1", features = ["macros", "rt"] }
```

Create `crates/drivers/sandbox-remote-ssh/README.md`:

```markdown
# sandbox-remote-ssh

Built-in `SandboxDriver` for pre-provisioned remote VMs reachable through SSH.

The driver does not provision, stop, or power off VMs. It expects the remote
user to have a writable `/sandbox` directory and basic POSIX shell tools.

Run live integration tests with:

```bash
AGENTENV_RUN_REMOTE_SSH_INTEGRATION=1 \
AGENTENV_REMOTE_SSH_HOST=dev-vm.example.com \
AGENTENV_REMOTE_SSH_USER=alice \
AGENTENV_REMOTE_SSH_IDENTITY_FILE=/Users/alice/.ssh/id_ed25519 \
cargo test -p sandbox-remote-ssh --features integration -- --ignored
```
```

- [ ] **Step 2: Write the failing initialization test**

Create `crates/drivers/sandbox-remote-ssh/src/lib.rs` with this test module and no `RemoteSshDriver` definition yet:

```rust
#![forbid(unsafe_code)]

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
```

- [ ] **Step 3: Run the test to verify it fails**

Run:

```bash
cargo test -p sandbox-remote-ssh remote_ssh_driver_initializes_with_conservative_capabilities
```

Expected: FAIL to compile with an unresolved import or undeclared type for `RemoteSshDriver`.

- [ ] **Step 4: Implement the minimal driver skeleton**

Add these imports, constants, struct, helpers, and trait implementation above the test module:

```rust
use std::collections::BTreeMap;

use agentenv_core::driver::{persistent_sessions_missing, DriverError, DriverResult, SandboxDriver};
use agentenv_proto::{
    assert_compatible_schema_version, ApplyPolicyParams, ApplyPolicyResult, AttachSessionParams,
    Capabilities, ConnectParams, CopyInParams, CopyOutParams, CreateSessionParams, DestroyParams,
    DriverInfo, DriverKind, EmptyResult, ExecParams, ExecResult, InitializeParams,
    InitializeResult, KillSessionParams, ListSessionsParams, ListSessionsResult, LogsParams,
    LogsResult, LogsStreamParams, PreflightParams, PreflightResult, SandboxCapabilities,
    SandboxHandle, SandboxSpec, SandboxStatus, SandboxStatusParams, SessionHandle,
    ShellHandle, ShutdownParams, StopParams, SCHEMA_VERSION,
};

const DRIVER_NAME: &str = "remote-ssh";
const REMOTE_LOGS_CAPABILITY: &str = "remote_logs";
const POLICY_CAPABILITY: &str = "supports_hot_reload_policy";

#[derive(Debug, Default)]
pub struct RemoteSshDriver;

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
        Ok(PreflightResult { ok: true, issues: Vec::new() })
    }

    async fn create(&self, _spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        Err(DriverError::InvalidInput {
            message: "metadata.host is required".to_owned(),
        })
    }

    async fn connect(&self, params: ConnectParams) -> DriverResult<ShellHandle> {
        Err(invalid_handle(params.handle, "remote-ssh handle parsing is not implemented"))
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
        Err(invalid_handle(params.handle, "remote-ssh handle parsing is not implemented"))
    }

    async fn copy_in(&self, params: CopyInParams) -> DriverResult<EmptyResult> {
        Err(invalid_handle(params.handle, "remote-ssh handle parsing is not implemented"))
    }

    async fn copy_out(&self, params: CopyOutParams) -> DriverResult<EmptyResult> {
        Err(invalid_handle(params.handle, "remote-ssh handle parsing is not implemented"))
    }

    async fn apply_policy(&self, _params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult> {
        Err(policy_missing())
    }

    async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        Err(invalid_handle(params.handle, "remote-ssh handle parsing is not implemented"))
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
```

Remove the unused `BTreeMap` import if the compiler flags it before Task 2 uses it.

- [ ] **Step 5: Run the test to verify it passes**

Run:

```bash
cargo test -p sandbox-remote-ssh remote_ssh_driver_initializes_with_conservative_capabilities
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/drivers/sandbox-remote-ssh
git commit -m "feat: scaffold remote ssh sandbox driver"
```

## Task 2: Command Runner And Preflight

**Files:**
- Modify: `crates/drivers/sandbox-remote-ssh/src/lib.rs`

- [ ] **Step 1: Write failing preflight tests**

Add these tests inside `mod tests`:

```rust
use std::{collections::{BTreeMap, VecDeque}, io, sync::{Arc, Mutex}};

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
    Error { kind: io::ErrorKind, message: String },
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

impl CommandScript {
    fn output(program: &str, args: &[&str], status: Option<i32>, stdout: &str, stderr: &str) -> Self {
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
    fn run(&self, program: &str, request: &super::CommandRequest) -> io::Result<super::CommandOutput> {
        self.calls.lock().expect("calls mutex").push(CommandCall {
            program: program.to_owned(),
            request: CommandRequest {
                args: request.args.clone(),
                env: request.env.clone(),
            },
        });
        let script = self.scripts.lock().expect("scripts mutex").pop_front().expect("unexpected command");
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

    fn status(&self, program: &str, request: &super::CommandRequest) -> io::Result<Option<i32>> {
        self.run(program, request).map(|output| output.status)
    }
}

#[tokio::test]
async fn preflight_checks_ssh_and_scp_executables() {
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::output("ssh", &["-V"], Some(0), "", "OpenSSH_9.9\n"),
        CommandScript::output("scp", &["-V"], Some(1), "", "usage: scp\n"),
    ]));
    let driver = RemoteSshDriver::with_command_runner(runner.clone());

    let result = driver.preflight(PreflightParams::default()).await.expect("preflight");

    assert!(result.ok);
    assert!(result.issues.is_empty());
    assert_eq!(
        runner.calls(),
        vec![
            CommandCall { program: "ssh".to_owned(), request: command_request(&["-V"]) },
            CommandCall { program: "scp".to_owned(), request: command_request(&["-V"]) },
        ]
    );
}

#[tokio::test]
async fn preflight_reports_missing_ssh() {
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::failure("ssh", &["-V"], io::ErrorKind::NotFound, "ssh not found"),
    ]));
    let driver = RemoteSshDriver::with_command_runner(runner);

    let result = driver.preflight(PreflightParams::default()).await.expect("preflight");

    assert!(!result.ok);
    assert_eq!(result.issues[0].code, "remote_ssh_missing_ssh");
    assert!(result.issues[0].message.contains("ssh"));
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cargo test -p sandbox-remote-ssh preflight_
```

Expected: FAIL to compile because `CommandRunner`, `CommandRequest`, `CommandOutput`, `RemoteSshDriver::with_command_runner`, and `command_request` do not exist.

- [ ] **Step 3: Implement command runner and preflight**

Add these definitions above `RemoteSshDriver`:

```rust
use std::{
    io,
    process::Command,
    sync::Arc,
};

use agentenv_proto::{IssueSeverity, PreflightIssue};

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
```

Replace `RemoteSshDriver` with:

```rust
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
```

Replace `preflight` with:

```rust
async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
    if let Err(source) = self.runner.run(&self.ssh_binary, &command_request(&["-V"])) {
        return Ok(preflight_failure(
            "remote_ssh_missing_ssh",
            format!("SSH binary `{}` is not available: {source}", self.ssh_binary),
            Some(format!("Install OpenSSH and ensure `{}` is on PATH", self.ssh_binary)),
        ));
    }

    if let Err(source) = self.runner.run(&self.scp_binary, &command_request(&["-V"])) {
        return Ok(preflight_failure(
            "remote_ssh_missing_scp",
            format!("SCP binary `{}` is not available: {source}", self.scp_binary),
            Some(format!("Install OpenSSH and ensure `{}` is on PATH", self.scp_binary)),
        ));
    }

    Ok(PreflightResult { ok: true, issues: Vec::new() })
}
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
cargo test -p sandbox-remote-ssh preflight_
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-remote-ssh/src/lib.rs
git commit -m "feat: add remote ssh preflight checks"
```

## Task 3: Metadata Parsing And URI Handles

**Files:**
- Modify: `crates/drivers/sandbox-remote-ssh/src/lib.rs`

- [ ] **Step 1: Write failing config and handle tests**

Add these tests:

```rust
use serde_json::json;

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
    assert!(target.identity_file.as_ref().expect("identity").ends_with(".ssh/id_ed25519"));
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
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cargo test -p sandbox-remote-ssh target_from_metadata
cargo test -p sandbox-remote-ssh uri_handle_round_trips_target_fields
```

Expected: FAIL because `RemoteSshTarget` and its methods do not exist.

- [ ] **Step 3: Implement target parsing and handle serialization**

Add this struct and methods:

```rust
use std::path::PathBuf;

use serde_json::Value;
use url::Url;

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
        let port = metadata_port(metadata)?;
        let identity_file = optional_metadata_string(metadata, "identity_file")?
            .map(expand_leading_home);
        let jump_host = optional_metadata_string(metadata, "jump_host")?;
        let enforce_remote_firewall = optional_metadata_bool(metadata, "enforce_remote_firewall")?
            .unwrap_or(false);

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
        {
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
        let url = Url::parse(handle).map_err(|source| invalid_handle(handle.to_owned(), source.to_string()))?;
        if url.scheme() != "remote-ssh" {
            return Err(invalid_handle(handle.to_owned(), "expected remote-ssh scheme"));
        }
        let host = url.host_str().ok_or_else(|| invalid_handle(handle.to_owned(), "missing host"))?.to_owned();
        let user = url.username();
        if user.is_empty() {
            return Err(invalid_handle(handle.to_owned(), "missing user"));
        }
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

fn optional_metadata_string(metadata: &BTreeMap<String, Value>, key: &str) -> DriverResult<Option<String>> {
    match metadata.get(key) {
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(DriverError::InvalidInput {
            message: format!("metadata.{key} must be a string when set"),
        }),
    }
}

fn optional_metadata_bool(metadata: &BTreeMap<String, Value>, key: &str) -> DriverResult<Option<bool>> {
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
        Some(Value::String(value)) => value.parse::<u16>().ok().filter(|value| *value > 0).ok_or_else(|| {
            DriverError::InvalidInput {
                message: "metadata.port must be a numeric string in range 1..=65535".to_owned(),
            }
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
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
cargo test -p sandbox-remote-ssh target_from_metadata
cargo test -p sandbox-remote-ssh uri_handle_round_trips_target_fields
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-remote-ssh/src/lib.rs
git commit -m "feat: parse remote ssh target metadata"
```

## Task 4: Create, Connect, Status, Logs, Stop, Destroy

**Files:**
- Modify: `crates/drivers/sandbox-remote-ssh/src/lib.rs`

- [ ] **Step 1: Write failing create and status tests**

Add tests:

```rust
#[tokio::test]
async fn create_probes_remote_and_returns_uri_handle() {
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::output("ssh", &["-o", "BatchMode=yes", "-p", "2222", "-J", "bastion.example.com", "alice@dev-vm.example.com", "--", "true"], Some(0), "", ""),
        CommandScript::output("ssh", &["-o", "BatchMode=yes", "-p", "2222", "-J", "bastion.example.com", "alice@dev-vm.example.com", "--", "sh", "-lc", "mkdir -p /sandbox/.agentenv/bin && test -w /sandbox"], Some(0), "", ""),
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
        DriverError::CapabilityMissing { capability } => assert_eq!(capability, POLICY_CAPABILITY),
        other => panic!("expected CapabilityMissing, got {other:?}"),
    }
    assert!(runner.calls().is_empty());
}

#[tokio::test]
async fn connect_probes_remote_and_returns_sandbox_working_dir() {
    let handle = "remote-ssh://alice@dev-vm.example.com:22";
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::output("ssh", &["-o", "BatchMode=yes", "-p", "22", "alice@dev-vm.example.com", "--", "true"], Some(0), "", ""),
    ]));
    let driver = RemoteSshDriver::with_command_runner(runner);

    let shell = driver.connect(ConnectParams { handle: handle.to_owned() }).await.expect("connect");

    assert_eq!(shell.session_id, handle);
    assert!(shell.tty);
    assert_eq!(shell.working_dir.as_deref(), Some("/sandbox"));
}

#[tokio::test]
async fn status_reports_unhealthy_on_nonzero_ssh_probe() {
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::output("ssh", &["-o", "BatchMode=yes", "-p", "22", "alice@dev-vm.example.com", "--", "true"], Some(255), "", "connection refused"),
    ]));
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
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cargo test -p sandbox-remote-ssh create_probes_remote_and_returns_uri_handle
cargo test -p sandbox-remote-ssh connect_probes_remote_and_returns_sandbox_working_dir
cargo test -p sandbox-remote-ssh status_reports_unhealthy_on_nonzero_ssh_probe
```

Expected: FAIL because `create`, `connect`, and `status` still return stub errors.

- [ ] **Step 3: Implement SSH helpers and lifecycle methods**

Add helpers:

```rust
fn target_arg(target: &RemoteSshTarget) -> String {
    format!("{}@{}", target.user, target.host)
}

fn ssh_base_args(target: &RemoteSshTarget) -> Vec<String> {
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
    if let Some(jump_host) = target.jump_host.as_deref() {
        args.push("-J".to_owned());
        args.push(jump_host.to_owned());
    }
    args.push(target_arg(target));
    args
}

fn ssh_request(target: &RemoteSshTarget, remote_args: &[&str]) -> CommandRequest {
    let mut args = ssh_base_args(target);
    args.push("--".to_owned());
    args.extend(remote_args.iter().map(|arg| (*arg).to_owned()));
    CommandRequest { args, env: BTreeMap::new() }
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
            message: format!("metadata.identity_file `{}` is not readable: {source}", path.display()),
        }),
    }
}
```

Replace `create`, `connect`, `status`, `logs`, `logs_stream`, `stop`, and `destroy` with:

```rust
async fn create(&self, spec: SandboxSpec) -> DriverResult<SandboxHandle> {
    let target = RemoteSshTarget::from_metadata(&spec.metadata)?;
    if target.enforce_remote_firewall {
        return Err(policy_missing());
    }
    ensure_identity_file_exists(&target)?;

    for remote_args in [
        vec!["true"],
        vec!["sh", "-lc", "mkdir -p /sandbox/.agentenv/bin && test -w /sandbox"],
    ] {
        let request = ssh_request(&target, &remote_args);
        let output = self.runner.run(&self.ssh_binary, &request).map_err(|source| {
            DriverError::CommandSpawn {
                command: command_string(&self.ssh_binary, &request.args),
                source,
            }
        })?;
        if output.status.is_none_or(|status| status != 0) {
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
    let output = self.runner.run(&self.ssh_binary, &request).map_err(|source| {
        DriverError::CommandSpawn {
            command: command_string(&self.ssh_binary, &request.args),
            source,
        }
    })?;
    if output.status.is_none_or(|status| status != 0) {
        return Err(command_failed(&self.ssh_binary, &request, output));
    }

    Ok(ShellHandle {
        session_id: params.handle,
        tty: true,
        working_dir: Some("/sandbox".to_owned()),
    })
}

async fn status(&self, params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
    let target = RemoteSshTarget::from_handle(&params.handle)?;
    let request = ssh_request(&target, &["true"]);
    let output = self.runner.run(&self.ssh_binary, &request).map_err(|source| {
        DriverError::CommandSpawn {
            command: command_string(&self.ssh_binary, &request.args),
            source,
        }
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
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
cargo test -p sandbox-remote-ssh create_
cargo test -p sandbox-remote-ssh connect_
cargo test -p sandbox-remote-ssh status_
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-remote-ssh/src/lib.rs
git commit -m "feat: create and probe remote ssh sandboxes"
```

## Task 5: Exec And File Copy Operations

**Files:**
- Modify: `crates/drivers/sandbox-remote-ssh/src/lib.rs`

- [ ] **Step 1: Write failing exec and copy tests**

Add tests:

```rust
#[tokio::test]
async fn exec_runs_remote_shell_from_sandbox_workdir() {
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::output("ssh", &["-o", "BatchMode=yes", "-p", "22", "alice@dev-vm.example.com", "--", "sh", "-lc", "cd /sandbox && echo hi"], Some(7), "stdout payload", "stderr payload"),
    ]));
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
async fn copy_in_and_copy_out_use_scp_with_port_identity_and_jump_host() {
    let handle = "remote-ssh://alice@dev-vm.example.com:2222?identity_file=/Users/alice/.ssh/id_ed25519&jump_host=bastion.example.com";
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::output("scp", &["-P", "2222", "-i", "/Users/alice/.ssh/id_ed25519", "-J", "bastion.example.com", "/host/in.txt", "alice@dev-vm.example.com:/sandbox/in.txt"], Some(0), "", ""),
        CommandScript::output("scp", &["-P", "2222", "-i", "/Users/alice/.ssh/id_ed25519", "-J", "bastion.example.com", "alice@dev-vm.example.com:/sandbox/out.txt", "/host/out.txt"], Some(0), "", ""),
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
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cargo test -p sandbox-remote-ssh exec_runs_remote_shell_from_sandbox_workdir
cargo test -p sandbox-remote-ssh copy_in_and_copy_out_use_scp_with_port_identity_and_jump_host
```

Expected: FAIL because `exec`, `copy_in`, and `copy_out` still return stub errors.

- [ ] **Step 3: Implement exec and scp helpers**

Add helpers:

```rust
fn remote_shell_command(cmd: &str) -> String {
    format!("cd /sandbox && {cmd}")
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
```

Replace `exec`, `copy_in`, and `copy_out`:

```rust
async fn exec(&self, params: ExecParams) -> DriverResult<ExecResult> {
    let target = RemoteSshTarget::from_handle(&params.handle)?;
    let remote_cmd = remote_shell_command(&params.cmd);
    let request = CommandRequest {
        args: {
            let mut args = ssh_base_args(&target);
            args.push("--".to_owned());
            args.extend(["sh", "-lc", remote_cmd.as_str()].iter().map(|arg| (*arg).to_owned()));
            args
        },
        env: params.env,
    };
    let command = command_string(&self.ssh_binary, &request.args);

    if params.tty {
        let status = self.runner.status(&self.ssh_binary, &request).map_err(|source| {
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

    let output = self.runner.run(&self.ssh_binary, &request).map_err(|source| {
        DriverError::CommandSpawn {
            command: command.clone(),
            source,
        }
    })?;
    Ok(ExecResult {
        status: output.status.unwrap_or(1),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

async fn copy_in(&self, params: CopyInParams) -> DriverResult<EmptyResult> {
    let target = RemoteSshTarget::from_handle(&params.handle)?;
    let mut args = scp_base_args(&target);
    args.push(params.src_host_path);
    args.push(remote_path(&target, &params.dst_sandbox_path));
    let request = CommandRequest { args, env: BTreeMap::new() };
    let output = self.runner.run(&self.scp_binary, &request).map_err(|source| {
        DriverError::CommandSpawn {
            command: command_string(&self.scp_binary, &request.args),
            source,
        }
    })?;
    if output.status.is_none_or(|status| status != 0) {
        return Err(command_failed(&self.scp_binary, &request, output));
    }
    Ok(EmptyResult::default())
}

async fn copy_out(&self, params: CopyOutParams) -> DriverResult<EmptyResult> {
    let target = RemoteSshTarget::from_handle(&params.handle)?;
    let mut args = scp_base_args(&target);
    args.push(remote_path(&target, &params.src_sandbox_path));
    args.push(params.dst_host_path);
    let request = CommandRequest { args, env: BTreeMap::new() };
    let output = self.runner.run(&self.scp_binary, &request).map_err(|source| {
        DriverError::CommandSpawn {
            command: command_string(&self.scp_binary, &request.args),
            source,
        }
    })?;
    if output.status.is_none_or(|status| status != 0) {
        return Err(command_failed(&self.scp_binary, &request, output));
    }
    Ok(EmptyResult::default())
}
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
cargo test -p sandbox-remote-ssh exec_
cargo test -p sandbox-remote-ssh copy_
```

Expected: PASS.

- [ ] **Step 5: Add conformance test**

Add:

```rust
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
```

Run:

```bash
cargo test -p sandbox-remote-ssh remote_ssh_driver_satisfies_sandbox_conformance_contract
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/drivers/sandbox-remote-ssh/src/lib.rs
git commit -m "feat: execute and copy over remote ssh"
```

## Task 6: Built-In Registry And Runtime Metadata

**Files:**
- Modify: `crates/agentenv-core/src/driver_catalog.rs`
- Modify: `crates/agentenv-core/src/runtime.rs`

- [ ] **Step 1: Write failing registry test**

In `crates/agentenv-core/src/registry.rs`, add this test near `default_registry_uses_shared_builtin_aliases`:

```rust
#[test]
fn default_registry_uses_remote_ssh_builtin_aliases() {
    let registry = DriverRegistry::default();

    assert!(registry.pin(DriverKind::Sandbox, "remote-ssh", None).is_ok());
    assert!(registry.pin(DriverKind::Sandbox, "sandbox-remote-ssh", None).is_ok());
}
```

- [ ] **Step 2: Run registry test to verify failure**

Run:

```bash
cargo test -p agentenv-core default_registry_uses_remote_ssh_builtin_aliases
```

Expected: FAIL with unknown sandbox driver `remote-ssh`.

- [ ] **Step 3: Register remote-ssh aliases**

In `crates/agentenv-core/src/driver_catalog.rs`, add the new sandbox spec after OpenShell:

```rust
    BuiltInDriverSpec {
        kind: DriverKind::Sandbox,
        names: &["remote-ssh", "sandbox-remote-ssh"],
    },
```

- [ ] **Step 4: Run registry test to verify pass**

Run:

```bash
cargo test -p agentenv-core default_registry_uses_remote_ssh_builtin_aliases
```

Expected: PASS.

- [ ] **Step 5: Write failing runtime metadata test**

In `crates/agentenv-core/src/runtime.rs`, add this test near `create_env_passes_byo_dockerfile_metadata_to_sandbox`:

```rust
#[tokio::test]
async fn create_env_passes_generic_sandbox_extra_metadata_to_sandbox() {
    let root = unique_root("agentenv-create-remote-ssh-metadata");
    let options = RuntimeOptions {
        root,
        log_level: LogLevel::Info,
        non_interactive: true,
    };
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: remote-ssh
  host: dev-vm.example.com
  user: alice
  port: 2222
  identity_file: ~/.ssh/id_ed25519
  jump_host: bastion.example.com
  enforce_remote_firewall: false
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
    let tracker = Arc::new(AgentSetupTracker::default());
    let mut credentials = super::tests_support::EmptyCredentialProvider;

    super::create_env(
        &options,
        &AgentSetupFactory {
            tracker: Arc::clone(&tracker),
        },
        &mut credentials,
        "demo",
        yaml,
    )
    .await
    .unwrap();

    let specs = tracker.create_specs.lock().expect("create spec tracker");
    assert_eq!(specs.len(), 1);
    let metadata = &specs[0].metadata;
    assert_eq!(metadata["name"], serde_json::json!("demo"));
    assert_eq!(metadata["host"], serde_json::json!("dev-vm.example.com"));
    assert_eq!(metadata["user"], serde_json::json!("alice"));
    assert_eq!(metadata["port"], serde_json::json!(2222));
    assert_eq!(metadata["identity_file"], serde_json::json!("~/.ssh/id_ed25519"));
    assert_eq!(metadata["jump_host"], serde_json::json!("bastion.example.com"));
    assert_eq!(metadata["enforce_remote_firewall"], serde_json::json!(false));
    assert!(!metadata.contains_key("image"));
}
```

- [ ] **Step 6: Run runtime metadata test to verify failure**

Run:

```bash
cargo test -p agentenv-core create_env_passes_generic_sandbox_extra_metadata_to_sandbox
```

Expected: FAIL because `host`, `user`, `port`, `identity_file`, `jump_host`, and `enforce_remote_firewall` are not present in `SandboxSpec.metadata`.

- [ ] **Step 7: Pass non-image sandbox extras into metadata**

In `sandbox_spec_for_create`, after the initial `metadata` map is created and before `let image = match sandbox_extra.get("image")`, add:

```rust
    for (key, value) in sandbox_extra {
        if key == "image" {
            continue;
        }
        let value = serde_json::to_value(value)
            .map_err(|source| RuntimeError::ComponentConfigConversion {
                key: key.clone(),
                source,
            })?;
        metadata.insert(key.clone(), value);
    }
```

Keep the existing `image` match unchanged.

- [ ] **Step 8: Run tests to verify pass and preserve OpenShell BYO behavior**

Run:

```bash
cargo test -p agentenv-core create_env_passes_generic_sandbox_extra_metadata_to_sandbox
cargo test -p agentenv-core create_env_passes_byo_dockerfile_metadata_to_sandbox
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/agentenv-core/src/driver_catalog.rs crates/agentenv-core/src/registry.rs crates/agentenv-core/src/runtime.rs
git commit -m "feat: pass sandbox extras for remote ssh"
```

## Task 7: Built-In Factory Wiring

**Files:**
- Modify: `crates/agentenv/Cargo.toml`
- Modify: `crates/agentenv/src/builtin_factory.rs`

- [ ] **Step 1: Add failing factory tests**

In `crates/agentenv/src/builtin_factory.rs`, add this test near `builds_supported_reference_driver_set`:

```rust
#[test]
fn builds_remote_ssh_sandbox_aliases() {
    for sandbox in ["remote-ssh", "sandbox-remote-ssh"] {
        let selection = DriverSelection {
            sandbox: sandbox.to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: Some("passthrough".to_owned()),
        };

        let set = BuiltInDriverFactory.build(&selection).unwrap();
        drop(set);
    }
}
```

Add this pinned-build test near `pinned_build_rejects_non_builtin_sandbox_pin`:

```rust
#[test]
fn pinned_build_accepts_remote_ssh_sandbox_alias() {
    let selection = DriverSelection {
        sandbox: "remote-ssh".to_owned(),
        agent: "codex".to_owned(),
        context: "filesystem".to_owned(),
        inference: None,
    };
    let pins = pin_set(
        "sandbox",
        ProtoDriverKind::Sandbox,
        "remote-ssh",
        env!("CARGO_PKG_VERSION"),
        DriverSourcePin::BuiltIn,
    );

    let set = BuiltInDriverFactory.build_pinned(&selection, &pins).unwrap();
    drop(set);
}
```

- [ ] **Step 2: Run factory tests to verify failure**

Run:

```bash
cargo test -p agentenv builds_remote_ssh_sandbox_aliases
cargo test -p agentenv pinned_build_accepts_remote_ssh_sandbox_alias
```

Expected: FAIL because `remote-ssh` is unsupported in `BuiltInDriverFactory`.

- [ ] **Step 3: Add the dependency and factory branches**

In `crates/agentenv/Cargo.toml`, add:

```toml
sandbox-remote-ssh = { path = "../drivers/sandbox-remote-ssh" }
```

In `build_driver_set_with_context`, update the sandbox match:

```rust
        sandbox: match selection.sandbox.as_str() {
            "openshell" | "sandbox-openshell" => {
                Box::new(sandbox_openshell::OpenShellDriver::default())
            }
            "remote-ssh" | "sandbox-remote-ssh" => {
                Box::new(sandbox_remote_ssh::RemoteSshDriver::default())
            }
            other => {
```

In `build_pinned_sandbox`, add:

```rust
        "remote-ssh" | "sandbox-remote-ssh" => {
            validate_builtin_pin(
                "sandbox",
                agentenv_proto::DriverKind::Sandbox,
                &["remote-ssh", "sandbox-remote-ssh"],
                pin,
            )?;
            Ok(Box::new(sandbox_remote_ssh::RemoteSshDriver::default()))
        }
```

- [ ] **Step 4: Run factory tests to verify pass**

Run:

```bash
cargo test -p agentenv builds_remote_ssh_sandbox_aliases
cargo test -p agentenv pinned_build_accepts_remote_ssh_sandbox_alias
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/Cargo.toml crates/agentenv/src/builtin_factory.rs
git commit -m "feat: wire remote ssh built-in driver"
```

## Task 8: Live Integration Test And Final Verification

**Files:**
- Create: `crates/drivers/sandbox-remote-ssh/tests/integration.rs`
- Modify: `crates/drivers/sandbox-remote-ssh/src/lib.rs` only if final compile fixes are needed.

- [ ] **Step 1: Add ignored integration test**

Create `crates/drivers/sandbox-remote-ssh/tests/integration.rs`:

```rust
#![cfg(feature = "integration")]

use std::{collections::BTreeMap, env, fs};

use agentenv_core::driver::SandboxDriver;
use agentenv_proto::{
    CopyInParams, CopyOutParams, DestroyParams, ExecParams, SandboxSpec, SandboxStatusParams,
};
use sandbox_remote_ssh::RemoteSshDriver;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a reachable SSH host configured through AGENTENV_REMOTE_SSH_*"]
async fn remote_ssh_create_exec_copy_status_destroy_flow() {
    if !should_run_integration() {
        eprintln!("skipping remote SSH integration test: set AGENTENV_RUN_REMOTE_SSH_INTEGRATION=1");
        return;
    }

    let host = env::var("AGENTENV_REMOTE_SSH_HOST").expect("remote host");
    let user = env::var("AGENTENV_REMOTE_SSH_USER").expect("remote user");
    let port = env::var("AGENTENV_REMOTE_SSH_PORT").unwrap_or_else(|_| "22".to_owned());
    let identity_file = env::var("AGENTENV_REMOTE_SSH_IDENTITY_FILE").ok();
    let jump_host = env::var("AGENTENV_REMOTE_SSH_JUMP_HOST").ok();

    let mut metadata = BTreeMap::from([
        ("host".to_owned(), serde_json::json!(host)),
        ("user".to_owned(), serde_json::json!(user)),
        ("port".to_owned(), serde_json::json!(port)),
    ]);
    if let Some(identity_file) = identity_file {
        metadata.insert("identity_file".to_owned(), serde_json::json!(identity_file));
    }
    if let Some(jump_host) = jump_host {
        metadata.insert("jump_host".to_owned(), serde_json::json!(jump_host));
    }

    let driver = RemoteSshDriver::default();
    let handle = driver
        .create(SandboxSpec {
            image: None,
            env: BTreeMap::new(),
            policy: None,
            metadata,
        })
        .await
        .expect("create remote ssh sandbox")
        .handle;

    let marker = format!("agentenv-remote-ssh-{}", Uuid::new_v4());
    let exec = driver
        .exec(ExecParams {
            handle: handle.clone(),
            cmd: format!("printf '%s\\n' {marker}"),
            tty: false,
            env: BTreeMap::new(),
        })
        .await
        .expect("exec marker");
    assert_eq!(exec.status, 0, "stdout={} stderr={}", exec.stdout, exec.stderr);
    assert!(exec.stdout.contains(&marker));

    let tempdir = env::temp_dir().join(format!("agentenv-remote-ssh-it-{}", Uuid::new_v4()));
    fs::create_dir_all(&tempdir).expect("create tempdir");
    let src = tempdir.join("in.txt");
    let dst = tempdir.join("out.txt");
    fs::write(&src, format!("{marker}\\n")).expect("write source");
    let remote_path = format!("/sandbox/.agentenv/{}.txt", marker);

    driver
        .copy_in(CopyInParams {
            handle: handle.clone(),
            src_host_path: src.display().to_string(),
            dst_sandbox_path: remote_path.clone(),
        })
        .await
        .expect("copy_in");
    driver
        .copy_out(CopyOutParams {
            handle: handle.clone(),
            src_sandbox_path: remote_path,
            dst_host_path: dst.display().to_string(),
        })
        .await
        .expect("copy_out");
    assert_eq!(fs::read_to_string(&dst).expect("read output"), format!("{marker}\\n"));

    let status = driver
        .status(SandboxStatusParams {
            handle: handle.clone(),
        })
        .await
        .expect("status");
    assert!(status.healthy);

    driver
        .destroy(DestroyParams { handle })
        .await
        .expect("destroy no-op");
    fs::remove_dir_all(&tempdir).expect("remove tempdir");
}

fn should_run_integration() -> bool {
    matches!(
        env::var("AGENTENV_RUN_REMOTE_SSH_INTEGRATION").as_deref(),
        Ok("1")
    )
}
```

- [ ] **Step 2: Verify ignored integration test compiles but does not run by default**

Run:

```bash
cargo test -p sandbox-remote-ssh --features integration -- --list
```

Expected: output lists `remote_ssh_create_exec_copy_status_destroy_flow`.

- [ ] **Step 3: Run focused crate tests**

Run:

```bash
cargo test -p sandbox-remote-ssh
```

Expected: PASS.

- [ ] **Step 4: Run workspace verification**

Run:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

Expected: all commands pass without a live SSH VM.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-remote-ssh
git commit -m "test: add remote ssh integration harness"
```

## Self-Review Checklist

- Spec coverage: Tasks 1-5 cover the new driver contract; Task 6 covers registry and runtime metadata; Task 7 covers factory selection; Task 8 covers live integration and final verification.
- No protocol changes: no task modifies `agentenv-proto` or driver method signatures.
- Policy honesty: Task 1 initializes policy support as false; Task 4 rejects `enforce_remote_firewall`; Task 5 keeps `apply_policy` capability-missing.
- Persistence: Task 3 URI handles carry non-secret target data so fresh CLI processes can reconnect.
- Existing behavior: Task 6 runs the existing BYO Dockerfile metadata test after adding generic sandbox extras.
