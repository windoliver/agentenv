# M4-3 Session Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement persistent sandbox sessions for issue #16: detach, resume, multiple sessions, session listing, session killing, and graceful capability degradation.

**Architecture:** Add first-class session operations to the sandbox driver protocol and keep the durable-session backend inside each sandbox driver. Core owns `sessions.json` metadata and CLI behavior, while drivers own creating, attaching, listing, and killing sessions in the sandbox.

**Tech Stack:** Rust 2021, `async-trait`, `serde`, `schemars`, `clap`, existing agentenv runtime and driver traits, OpenShell command-runner harness.

---

## File Structure

- Modify `crates/agentenv-proto/src/schema_version.rs`: bump `SCHEMA_VERSION` to `1.1`.
- Modify `crates/agentenv-proto/src/types.rs`: add session capability, session status enum, session param/result structs.
- Modify `crates/agentenv-proto/build.rs`: export session schemas.
- Modify `crates/agentenv-proto/src/lib.rs`: update schema version test and add session defaults test.
- Modify generated schema files under `crates/agentenv-proto/schema/`.
- Modify `crates/agentenv-core/src/driver.rs`: add default sandbox session trait methods returning `CapabilityMissing`.
- Create `crates/agentenv-core/src/sessions.rs`: `sessions.json` model, atomic read/write helpers, reconciliation helpers, and session lookup helpers.
- Modify `crates/agentenv-core/src/lib.rs`: export `sessions`.
- Modify `crates/agentenv-core/src/runtime.rs`: add session runtime APIs and update `enter_env`/`destroy_env`.
- Modify `crates/agentenv/src/main.rs`: add CLI flags and commands: `enter --new`, `resume`, `sessions list`, `sessions kill`.
- Modify `crates/agentenv/src/render.rs`: render session rows and JSON.
- Modify `crates/drivers/sandbox-openshell/src/lib.rs`: implement tmux-backed session driver methods.
- Modify `tests/driver-conformance/src/lib.rs`: update sandbox capability fixtures and assert the default session methods return `CapabilityMissing`.
- Modify `docs/DRIVER_PROTOCOL.md`: document protocol v1.1 session methods.
- Modify `docs/ARCHITECTURE.md`: add the new `enter --new`, `sessions list`, and `sessions kill` examples.
- Modify `crates/agentenv/tests/cli_behavior.rs`: CLI parse/render behavior for session commands.

## Task 1: Protocol Session Types

**Files:**
- Modify: `crates/agentenv-proto/src/schema_version.rs`
- Modify: `crates/agentenv-proto/src/types.rs`
- Modify: `crates/agentenv-proto/build.rs`
- Modify: `crates/agentenv-proto/src/lib.rs`
- Generated: `crates/agentenv-proto/schema/*.json`

- [ ] **Step 1: Write failing proto tests**

Add these tests to `crates/agentenv-proto/src/lib.rs`:

```rust
#[test]
fn schema_version_is_1_1() {
    assert_eq!(SCHEMA_VERSION, "1.1");
}

#[test]
fn sandbox_capabilities_default_missing_persistent_sessions_to_false() {
    let capabilities: SandboxCapabilities = serde_json::from_value(serde_json::json!({
        "supports_hot_reload_policy": true,
        "supports_filesystem_lockdown": true,
        "supports_syscall_filter": true,
        "supports_native_inference_routing": true,
        "supports_remote_host": false
    }))
    .expect("legacy sandbox capabilities should deserialize");

    assert!(!capabilities.supports_persistent_sessions);
}

#[test]
fn session_handle_round_trips() {
    let handle = SessionHandle {
        session_id: "01HSESSION".to_owned(),
        name: "demo".to_owned(),
        status: SessionStatus::Detached,
        created_at: "2026-04-24T17:00:00Z".to_owned(),
        updated_at: "2026-04-24T17:01:00Z".to_owned(),
        command: "/sandbox/.agentenv/bin/agentenv-agent".to_owned(),
        working_dir: Some("/sandbox".to_owned()),
    };

    let encoded = serde_json::to_value(&handle).expect("serialize session handle");
    assert_eq!(encoded["status"], "detached");
    let decoded: SessionHandle = serde_json::from_value(encoded).expect("deserialize session handle");
    assert_eq!(decoded, handle);
}
```

Update the `use super::{...}` list in that test module to include:

```rust
SandboxCapabilities, SessionHandle, SessionStatus
```

- [ ] **Step 2: Run proto tests and verify they fail**

Run:

```bash
cargo test -p agentenv-proto schema_version_is_1_1 sandbox_capabilities_default_missing_persistent_sessions_to_false session_handle_round_trips
```

Expected: fail because `SCHEMA_VERSION` is still `1.0`, `supports_persistent_sessions` does not exist, and session types do not exist.

- [ ] **Step 3: Add protocol types**

In `crates/agentenv-proto/src/schema_version.rs`, change:

```rust
pub const SCHEMA_VERSION: &str = "1.0";
```

to:

```rust
pub const SCHEMA_VERSION: &str = "1.1";
```

In `crates/agentenv-proto/src/types.rs`, add the capability field:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SandboxCapabilities {
    pub supports_hot_reload_policy: bool,
    pub supports_filesystem_lockdown: bool,
    pub supports_syscall_filter: bool,
    pub supports_native_inference_routing: bool,
    pub supports_remote_host: bool,
    #[serde(default)]
    pub supports_persistent_sessions: bool,
}
```

Below `ShellHandle`, add:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Starting,
    Attached,
    Detached,
    Exited,
    Killed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CreateSessionParams {
    pub handle: String,
    pub name: String,
    pub command: String,
    pub detached: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AttachSessionParams {
    pub handle: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct KillSessionParams {
    pub handle: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListSessionsParams {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SessionHandle {
    pub session_id: String,
    pub name: String,
    pub status: SessionStatus,
    pub created_at: String,
    pub updated_at: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListSessionsResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<SessionHandle>,
}
```

In `crates/agentenv-proto/build.rs`, add schema exports after `ShellHandle`:

```rust
write_schema::<types::CreateSessionParams>(&schema_dir, "create-session-params");
write_schema::<types::AttachSessionParams>(&schema_dir, "attach-session-params");
write_schema::<types::KillSessionParams>(&schema_dir, "kill-session-params");
write_schema::<types::ListSessionsParams>(&schema_dir, "list-sessions-params");
write_schema::<types::SessionHandle>(&schema_dir, "session-handle");
write_schema::<types::ListSessionsResult>(&schema_dir, "list-sessions-result");
```

- [ ] **Step 4: Run proto tests and regenerate schemas**

Run:

```bash
cargo test -p agentenv-proto schema_version_is_1_1 sandbox_capabilities_default_missing_persistent_sessions_to_false session_handle_round_trips
cargo test -p agentenv-proto
```

Expected: proto tests pass and generated schema files are updated.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-proto
git commit -m "feat(proto): add sandbox session types"
```

## Task 2: Sandbox Driver Trait Session Surface

**Files:**
- Modify: `crates/agentenv-core/src/driver.rs`
- Modify: sandbox capability fixtures in `crates/agentenv-core/src/runtime.rs`, `crates/drivers/sandbox-openshell/src/lib.rs`, and `tests/driver-conformance/src/lib.rs`

- [ ] **Step 1: Write failing driver default test**

In `crates/agentenv-core/src/driver.rs`, add this test to the existing `#[cfg(test)] mod tests`:

```rust
#[tokio::test]
async fn sandbox_session_methods_default_to_capability_missing() {
    let driver = MinimalSandboxDriver;
    let err = driver
        .create_session(agentenv_proto::CreateSessionParams {
            handle: "sb-1".to_owned(),
            name: "demo".to_owned(),
            command: "agentenv-agent".to_owned(),
            detached: true,
            metadata: Default::default(),
        })
        .await
        .expect_err("default session implementation should reject");

    assert!(matches!(err, DriverError::CapabilityMissing { capability } if capability == "supports_persistent_sessions"));
}
```

Add this `MinimalSandboxDriver` inside the same test module when the file does not already have a sandbox test double:

```rust
struct MinimalSandboxDriver;

#[async_trait::async_trait]
impl SandboxDriver for MinimalSandboxDriver {
    async fn initialize(&mut self, _params: InitializeParams) -> DriverResult<InitializeResult> {
        Ok(InitializeResult {
            driver: DriverInfo {
                name: "minimal".to_owned(),
                kind: DriverKind::Sandbox,
                version: "0.0.1".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: false,
                supports_filesystem_lockdown: false,
                supports_syscall_filter: false,
                supports_native_inference_routing: false,
                supports_remote_host: false,
                supports_persistent_sessions: false,
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(PreflightResult { ok: true, issues: Vec::new() })
    }

    async fn create(&self, _spec: SandboxSpec) -> DriverResult<SandboxHandle> {
        Ok(SandboxHandle { handle: "sb-1".to_owned() })
    }

    async fn connect(&self, _params: ConnectParams) -> DriverResult<ShellHandle> {
        Ok(ShellHandle { session_id: "sh-1".to_owned(), tty: true, working_dir: None })
    }

    async fn exec(&self, _params: ExecParams) -> DriverResult<ExecResult> {
        Ok(ExecResult { status: 0, stdout: String::new(), stderr: String::new() })
    }

    async fn copy_in(&self, _params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult {})
    }

    async fn copy_out(&self, _params: agentenv_proto::CopyOutParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult {})
    }

    async fn apply_policy(&self, _params: ApplyPolicyParams) -> DriverResult<ApplyPolicyResult> {
        Ok(ApplyPolicyResult { hot_reloaded: false })
    }

    async fn status(&self, _params: SandboxStatusParams) -> DriverResult<SandboxStatus> {
        Ok(SandboxStatus { phase: agentenv_proto::SandboxPhase::Running, healthy: true, last_ping: None })
    }

    async fn logs(&self, _params: LogsParams) -> DriverResult<LogsResult> {
        Ok(LogsResult { entries: Vec::new() })
    }

    async fn logs_stream(&self, _params: LogsStreamParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult {})
    }

    async fn stop(&self, _params: StopParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult {})
    }

    async fn destroy(&self, _params: DestroyParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult {})
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult {})
    }
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test -p agentenv-core sandbox_session_methods_default_to_capability_missing
```

Expected: fail because `SandboxDriver::create_session` does not exist.

- [ ] **Step 3: Add default trait methods**

Update imports in `crates/agentenv-core/src/driver.rs` to include:

```rust
AttachSessionParams, CreateSessionParams, KillSessionParams, ListSessionsParams,
ListSessionsResult, SessionHandle,
```

Add a helper near `require_capability`:

```rust
pub fn persistent_sessions_missing() -> DriverError {
    DriverError::CapabilityMissing {
        capability: "supports_persistent_sessions".to_owned(),
    }
}
```

Add default methods to `SandboxDriver` after `connect`:

```rust
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
```

Update all `SandboxCapabilities` literals in tests and drivers to include:

```rust
supports_persistent_sessions: false,
```

Use `true` only for `OpenShellDriver::initialize` after Task 6 implements methods.

- [ ] **Step 4: Run core driver test**

Run:

```bash
cargo test -p agentenv-core sandbox_session_methods_default_to_capability_missing
```

Expected: pass.

- [ ] **Step 5: Compile affected crates**

Run:

```bash
cargo check -p agentenv-core -p sandbox-openshell -p driver-conformance
```

Expected: pass after all `SandboxCapabilities` literals are updated.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-core/src/driver.rs crates/agentenv-core/src/runtime.rs crates/drivers/sandbox-openshell/src/lib.rs tests/driver-conformance/src/lib.rs
git commit -m "feat(core): add sandbox session driver surface"
```

## Task 3: Core Session Metadata

**Files:**
- Create: `crates/agentenv-core/src/sessions.rs`
- Modify: `crates/agentenv-core/src/lib.rs`

- [ ] **Step 1: Write failing session metadata tests**

Create `crates/agentenv-core/src/sessions.rs` with the module skeleton and tests first:

```rust
use std::{collections::BTreeMap, path::PathBuf};

use agentenv_proto::SessionStatus;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("session `{session_id}` not found")]
    NotFound { session_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStateFile {
    pub version: String,
    pub env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_session_id: Option<String>,
    #[serde(default)]
    pub sessions: Vec<PersistedSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSession {
    pub id: String,
    pub driver_session_id: String,
    pub name: String,
    pub status: SessionStatus,
    pub command: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_session_file_uses_env_name() {
        let file = empty_session_file("demo");
        assert_eq!(file.env, "demo");
        assert!(file.sessions.is_empty());
    }
}
```

Add `pub mod sessions;` to `crates/agentenv-core/src/lib.rs`.

- [ ] **Step 2: Run failing test**

Run:

```bash
cargo test -p agentenv-core empty_session_file_uses_env_name
```

Expected: fail because `empty_session_file` does not exist.

- [ ] **Step 3: Implement metadata helpers**

Add to `crates/agentenv-core/src/sessions.rs`:

```rust
pub const SESSION_STATE_VERSION: &str = "0.1.0";

pub fn empty_session_file(env: &str) -> SessionStateFile {
    SessionStateFile {
        version: SESSION_STATE_VERSION.to_owned(),
        env: env.to_owned(),
        default_session_id: None,
        sessions: Vec::new(),
    }
}

pub fn sessions_path(paths: &crate::env::EnvPaths) -> PathBuf {
    paths.env_dir().join("sessions.json")
}
```

Add tests for round-trip and lookup:

```rust
#[test]
fn session_file_round_trips() {
    let root = std::env::temp_dir().join(format!("agentenv-sessions-{}", std::process::id()));
    let paths = crate::env::EnvPaths::new(root, crate::env::validate_env_name("demo").unwrap());
    std::fs::create_dir_all(paths.env_dir()).unwrap();
    let mut file = empty_session_file("demo");
    file.default_session_id = Some("s1".to_owned());
    file.sessions.push(PersistedSession {
        id: "s1".to_owned(),
        driver_session_id: "tmux-s1".to_owned(),
        name: "demo".to_owned(),
        status: SessionStatus::Detached,
        command: "agentenv-agent".to_owned(),
        created_at: "2026-04-24T17:00:00Z".to_owned(),
        updated_at: "2026-04-24T17:00:00Z".to_owned(),
        working_dir: Some("/sandbox".to_owned()),
        metadata: BTreeMap::new(),
    });

    write_sessions(&paths, &file).unwrap();
    assert_eq!(read_sessions(&paths, "demo").unwrap(), file);
}
```

Implement read and atomic write:

```rust
pub fn read_sessions(paths: &crate::env::EnvPaths, env: &str) -> Result<SessionStateFile, crate::env::EnvError> {
    let path = sessions_path(paths);
    match crate::env::read_regular_file(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| crate::env::EnvError::Json { path, source }),
        Err(crate::env::EnvError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(empty_session_file(env))
        }
        Err(error) => Err(error),
    }
}

pub fn write_sessions(paths: &crate::env::EnvPaths, sessions: &SessionStateFile) -> Result<(), crate::env::EnvError> {
    let path = sessions_path(paths);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| crate::env::EnvError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let rendered = serde_json::to_string_pretty(sessions).map_err(|source| crate::env::EnvError::Json {
        path: path.clone(),
        source,
    })?;
    let temp_path = path.with_file_name(format!(
        ".sessions.json.{}.tmp",
        std::process::id()
    ));
    std::fs::write(&temp_path, rendered).map_err(|source| crate::env::EnvError::Io {
        path: temp_path.clone(),
        source,
    })?;
    std::fs::rename(&temp_path, &path).map_err(|source| {
        let _ = std::fs::remove_file(&temp_path);
        crate::env::EnvError::Io { path, source }
    })
}
```

- [ ] **Step 4: Add reconciliation helpers**

Add:

```rust
pub fn upsert_session(file: &mut SessionStateFile, session: PersistedSession, make_default: bool) {
    if let Some(existing) = file.sessions.iter_mut().find(|item| item.id == session.id) {
        *existing = session;
    } else {
        file.sessions.push(session);
    }
    if make_default || file.default_session_id.is_none() {
        file.default_session_id = file.sessions.last().map(|item| item.id.clone());
    }
}

pub fn find_session<'a>(file: &'a SessionStateFile, session_id: &str) -> Result<&'a PersistedSession, SessionStoreError> {
    file.sessions
        .iter()
        .find(|session| session.id == session_id || session.driver_session_id == session_id)
        .ok_or_else(|| SessionStoreError::NotFound {
            session_id: session_id.to_owned(),
        })
}

pub fn is_live_status(status: &SessionStatus) -> bool {
    matches!(
        status,
        SessionStatus::Starting | SessionStatus::Attached | SessionStatus::Detached
    )
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p agentenv-core sessions::
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-core/src/lib.rs crates/agentenv-core/src/sessions.rs
git commit -m "feat(core): persist session metadata"
```

## Task 4: Runtime Session Operations

**Files:**
- Modify: `crates/agentenv-core/src/runtime.rs`
- Modify: `crates/agentenv-core/src/sessions.rs` if helper refinements are needed

- [ ] **Step 1: Write failing runtime tests**

Add tests to `crates/agentenv-core/src/runtime.rs`:

```rust
#[tokio::test]
async fn enter_detach_creates_and_persists_default_session() {
    let (options, factory) = session_test_runtime("enter-detach-session").await;
    let result = super::enter_env(&options, &factory, "demo", true, false).await.unwrap();
    let super::EnterResult::Detached(shell) = result else {
        panic!("expected detached session");
    };
    assert_eq!(shell.session_id, "sh-1");

    let env_name = crate::env::validate_env_name("demo").unwrap();
    let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
    let sessions = crate::sessions::read_sessions(&paths, "demo").unwrap();
    assert_eq!(sessions.default_session_id.as_deref(), Some("sh-1"));
    assert_eq!(sessions.sessions.len(), 1);
}

#[tokio::test]
async fn resume_env_attaches_default_session() {
    let (options, factory) = session_test_runtime("resume-default-session").await;
    super::enter_env(&options, &factory, "demo", true, false).await.unwrap();
    let result = super::resume_env(&options, &factory, "demo", None).await.unwrap();
    assert_eq!(result.status, 0);
}

#[tokio::test]
async fn enter_detach_without_session_support_returns_capability_missing() {
    let (options, factory) = command_test_runtime("enter-detach-unsupported").await;
    let err = super::enter_env(&options, &factory, "demo", true, false)
        .await
        .expect_err("unsupported detached enter should fail");

    assert!(matches!(
        err,
        RuntimeError::Driver(crate::driver::DriverError::CapabilityMissing { capability })
            if capability == "supports_persistent_sessions"
    ));
}
```

This changes `enter_env` signature to include `new_session: bool`:

```rust
enter_env(options, factory, name, detach, new_session)
```

Add this session-capable test runtime next to `command_test_runtime`:

```rust
async fn session_test_runtime(label: &str) -> (RuntimeOptions, SessionFactory) {
    let root = unique_root(&format!("agentenv-session-{label}"));
    let options = RuntimeOptions {
        root: root.clone(),
        log_level: LogLevel::Info,
        non_interactive: true,
    };
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#;
    let mut credentials = super::tests_support::EmptyCredentialProvider;
    super::create_env(&options, &SessionFactory, &mut credentials, "demo", yaml)
        .await
        .unwrap();

    (options, SessionFactory)
}

struct SessionFactory;

impl DriverFactory for SessionFactory {
    fn build(&self, _selection: &super::DriverSelection) -> super::RuntimeResult<DriverSet> {
        Ok(DriverSet {
            sandbox: Box::new(SessionSandboxDriver),
            agent: Box::new(super::tests_support::TinyAgentDriver),
            context: Box::new(TinyContextDriver),
            inference: None,
        })
    }
}

struct SessionSandboxDriver;

#[async_trait]
impl SandboxDriver for SessionSandboxDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        let mut result = TinySandboxDriver.initialize(params).await?;
        if let Capabilities::Sandbox(capabilities) = &mut result.capabilities {
            capabilities.supports_persistent_sessions = true;
        }
        Ok(result)
    }

    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
        TinySandboxDriver.preflight(params).await
    }

    async fn create(&self, spec: agentenv_proto::SandboxSpec) -> DriverResult<agentenv_proto::SandboxHandle> {
        TinySandboxDriver.create(spec).await
    }

    async fn connect(&self, params: agentenv_proto::ConnectParams) -> DriverResult<agentenv_proto::ShellHandle> {
        TinySandboxDriver.connect(params).await
    }

    async fn create_session(&self, params: agentenv_proto::CreateSessionParams) -> DriverResult<agentenv_proto::SessionHandle> {
        Ok(agentenv_proto::SessionHandle {
            session_id: "sh-1".to_owned(),
            name: params.name,
            status: if params.detached {
                agentenv_proto::SessionStatus::Detached
            } else {
                agentenv_proto::SessionStatus::Attached
            },
            created_at: "2026-04-24T17:00:00Z".to_owned(),
            updated_at: "2026-04-24T17:00:00Z".to_owned(),
            command: params.command,
            working_dir: Some("/sandbox".to_owned()),
        })
    }

    async fn attach_session(&self, _params: agentenv_proto::AttachSessionParams) -> DriverResult<agentenv_proto::ExecResult> {
        Ok(agentenv_proto::ExecResult {
            status: 0,
            stdout: "attached\n".to_owned(),
            stderr: String::new(),
        })
    }

    async fn list_sessions(&self, _params: agentenv_proto::ListSessionsParams) -> DriverResult<agentenv_proto::ListSessionsResult> {
        Ok(agentenv_proto::ListSessionsResult { sessions: Vec::new() })
    }

    async fn kill_session(&self, _params: agentenv_proto::KillSessionParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult {})
    }

    async fn exec(&self, params: agentenv_proto::ExecParams) -> DriverResult<agentenv_proto::ExecResult> {
        TinySandboxDriver.exec(params).await
    }

    async fn copy_in(&self, params: agentenv_proto::CopyInParams) -> DriverResult<EmptyResult> {
        TinySandboxDriver.copy_in(params).await
    }

    async fn copy_out(&self, params: agentenv_proto::CopyOutParams) -> DriverResult<EmptyResult> {
        TinySandboxDriver.copy_out(params).await
    }

    async fn apply_policy(&self, params: agentenv_proto::ApplyPolicyParams) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
        TinySandboxDriver.apply_policy(params).await
    }

    async fn status(&self, params: agentenv_proto::SandboxStatusParams) -> DriverResult<agentenv_proto::SandboxStatus> {
        TinySandboxDriver.status(params).await
    }

    async fn logs(&self, params: agentenv_proto::LogsParams) -> DriverResult<agentenv_proto::LogsResult> {
        TinySandboxDriver.logs(params).await
    }

    async fn logs_stream(&self, params: agentenv_proto::LogsStreamParams) -> DriverResult<EmptyResult> {
        TinySandboxDriver.logs_stream(params).await
    }

    async fn stop(&self, params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
        TinySandboxDriver.stop(params).await
    }

    async fn destroy(&self, params: agentenv_proto::DestroyParams) -> DriverResult<EmptyResult> {
        TinySandboxDriver.destroy(params).await
    }

    async fn shutdown(&mut self, params: agentenv_proto::ShutdownParams) -> DriverResult<EmptyResult> {
        let mut inner = TinySandboxDriver;
        inner.shutdown(params).await
    }
}
```

- [ ] **Step 2: Run failing runtime tests**

Run:

```bash
cargo test -p agentenv-core enter_detach_creates_and_persists_default_session resume_env_attaches_default_session
```

Expected: fail because `enter_env` does not accept `new_session` and `resume_env` does not exist.

- [ ] **Step 3: Add runtime result and row types**

Near existing runtime structs, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionListRow {
    pub env: String,
    pub session_id: String,
    pub name: String,
    pub status: agentenv_proto::SessionStatus,
    pub command: String,
    pub updated_at: String,
}
```

- [ ] **Step 4: Update `enter_env`**

Change signature:

```rust
pub async fn enter_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    detach: bool,
    new_session: bool,
) -> RuntimeResult<EnterResult>
```

Implementation strategy:

```rust
let state = describe_env(options, name)?.state;
let selection = selection_from_state(&state);
let handle = required_sandbox_handle(&state, name)?;
let mut set = factory.build(&selection)?;
let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
let supports_sessions = match init.capabilities {
    Capabilities::Sandbox(capabilities) => capabilities.supports_persistent_sessions,
    _ => false,
};

if !supports_sessions {
    if detach || new_session {
        return Err(RuntimeError::Driver(crate::driver::persistent_sessions_missing()));
    }
    let result = set.sandbox.exec(agentenv_proto::ExecParams {
        handle,
        cmd: AGENT_ENTRYPOINT_PATH.to_owned(),
        tty: true,
        env: BTreeMap::new(),
    }).await?;
    return Ok(EnterResult::Attached(result));
}
```

Then for session-supported drivers:

```rust
let env_name = crate::env::validate_env_name(name)?;
let paths = crate::env::EnvPaths::new(options.root.clone(), env_name);
let mut sessions = crate::sessions::read_sessions(&paths, name)?;
let existing_default = sessions
    .default_session_id
    .as_deref()
    .and_then(|id| crate::sessions::find_session(&sessions, id).ok())
    .filter(|session| crate::sessions::is_live_status(&session.status))
    .cloned();

let persisted = if !new_session {
    existing_default
} else {
    None
};

let driver_session_id = if let Some(session) = persisted {
    session.driver_session_id
} else {
    let created = set.sandbox.create_session(agentenv_proto::CreateSessionParams {
        handle: handle.clone(),
        name: next_session_name(name, &sessions),
        command: AGENT_ENTRYPOINT_PATH.to_owned(),
        detached: detach,
        metadata: BTreeMap::new(),
    }).await?;
    persist_driver_session(&paths, &mut sessions, created, !new_session || sessions.default_session_id.is_none())?;
    sessions.default_session_id.clone().unwrap_or_default()
};

if detach {
    return Ok(EnterResult::Detached(agentenv_proto::ShellHandle {
        session_id: driver_session_id,
        tty: true,
        working_dir: Some("/sandbox".to_owned()),
    }));
}

let result = set.sandbox.attach_session(agentenv_proto::AttachSessionParams {
    handle,
    session_id: driver_session_id,
}).await?;
Ok(EnterResult::Attached(result))
```

Implement helper functions in runtime:

```rust
fn next_session_name(env: &str, sessions: &crate::sessions::SessionStateFile) -> String {
    if sessions.sessions.is_empty() {
        env.to_owned()
    } else {
        format!("{env}-{}", sessions.sessions.len() + 1)
    }
}
```

and:

```rust
fn persisted_from_driver_session(session: agentenv_proto::SessionHandle) -> crate::sessions::PersistedSession {
    crate::sessions::PersistedSession {
        id: session.session_id.clone(),
        driver_session_id: session.session_id,
        name: session.name,
        status: session.status,
        command: session.command,
        created_at: session.created_at,
        updated_at: session.updated_at,
        working_dir: session.working_dir,
        metadata: BTreeMap::new(),
    }
}
```

- [ ] **Step 5: Add resume/list/kill runtime APIs**

Add:

```rust
pub async fn resume_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    name: &str,
    session_id: Option<&str>,
) -> RuntimeResult<agentenv_proto::ExecResult> {
    let state = describe_env(options, name)?.state;
    let selection = selection_from_state(&state);
    let handle = required_sandbox_handle(&state, name)?;
    let mut set = factory.build(&selection)?;
    let init = initialize_sandbox_driver(options, set.sandbox.as_mut()).await?;
    let supports_sessions = matches!(
        init.capabilities,
        Capabilities::Sandbox(agentenv_proto::SandboxCapabilities { supports_persistent_sessions: true, .. })
    );
    if !supports_sessions {
        return Err(RuntimeError::Driver(crate::driver::persistent_sessions_missing()));
    }
    let paths = crate::env::EnvPaths::new(options.root.clone(), crate::env::validate_env_name(name)?);
    let sessions = crate::sessions::read_sessions(&paths, name)?;
    let selected = match session_id {
        Some(id) => crate::sessions::find_session(&sessions, id)?,
        None => {
            let default_id = sessions.default_session_id.clone().ok_or_else(|| {
                RuntimeError::Driver(crate::driver::DriverError::InvalidHandle {
                    handle: name.to_owned(),
                    message: "no default session exists".to_owned(),
                })
            })?;
            crate::sessions::find_session(&sessions, &default_id)?
        }
    };
    set.sandbox.attach_session(agentenv_proto::AttachSessionParams {
        handle,
        session_id: selected.driver_session_id.clone(),
    }).await.map_err(Into::into)
}
```

Add `From<SessionStoreError> for RuntimeError` or map it explicitly to `DriverError::InvalidHandle`.

Also add:

```rust
pub async fn list_sessions_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    env: Option<&str>,
) -> RuntimeResult<Vec<SessionListRow>>
```

and:

```rust
pub async fn kill_session_env(
    options: &RuntimeOptions,
    factory: &dyn DriverFactory,
    session_id: &str,
) -> RuntimeResult<()>
```

Use `list_envs(options)` to scan all envs when `env` is `None` or when finding the owner for `kill`.

- [ ] **Step 6: Update destroy cleanup**

At the start of `destroy_env`, after initializing the sandbox and before `destroy`, add best-effort session cleanup:

```rust
let session_file = crate::sessions::read_sessions(&paths, name).unwrap_or_else(|_| crate::sessions::empty_session_file(name));
for session in session_file.sessions.iter().filter(|session| crate::sessions::is_live_status(&session.status)) {
    let _ = set.sandbox.kill_session(agentenv_proto::KillSessionParams {
        handle: handle.clone(),
        session_id: session.driver_session_id.clone(),
    }).await;
}
```

Do not fail destroy if an individual session kill fails; sandbox destroy remains authoritative.

- [ ] **Step 7: Run runtime tests**

Run:

```bash
cargo test -p agentenv-core enter_detach_creates_and_persists_default_session resume_env_attaches_default_session
cargo test -p agentenv-core runtime::tests
```

Expected: pass.

- [ ] **Step 8: Commit**

```bash
git add crates/agentenv-core/src/runtime.rs crates/agentenv-core/src/sessions.rs
git commit -m "feat(core): manage persistent sandbox sessions"
```

## Task 5: CLI Session Commands

**Files:**
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/src/render.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI tests**

Add tests in `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn resume_missing_env_uses_stable_error() {
    let temp_dir = make_temp_dir("resume-missing");
    let output = Command::new(agentenv_bin())
        .arg("resume")
        .arg("missing")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("env `missing` not found"));
}

#[test]
fn sessions_list_json_returns_empty_when_registry_missing() {
    let temp_dir = make_temp_dir("sessions-list-empty");
    let output = Command::new(agentenv_bin())
        .arg("sessions")
        .arg("list")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["sessions"].as_array().unwrap().len(), 0);
}
```

- [ ] **Step 2: Run failing CLI tests**

Run:

```bash
cargo test -p agentenv resume_missing_env_uses_stable_error sessions_list_json_returns_empty_when_registry_missing
```

Expected: fail because commands do not exist.

- [ ] **Step 3: Add CLI args**

In `Commands`, add:

```rust
Resume(ResumeArgs),
Sessions(SessionsArgs),
```

Update `EnterArgs`:

```rust
#[derive(Debug, Args)]
struct EnterArgs {
    name: String,
    #[arg(long)]
    detach: bool,
    #[arg(long)]
    new: bool,
}
```

Add:

```rust
#[derive(Debug, Args)]
struct ResumeArgs {
    name: String,
    session_id: Option<String>,
}

#[derive(Debug, Args)]
struct SessionsArgs {
    #[command(subcommand)]
    command: SessionsCommand,
}

#[derive(Debug, Subcommand)]
enum SessionsCommand {
    List(SessionsListArgs),
    Kill(SessionsKillArgs),
}

#[derive(Debug, Args)]
struct SessionsListArgs {
    env: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SessionsKillArgs {
    session_id: String,
}
```

Wire match arms:

```rust
Some(Commands::Resume(args)) => run_resume(args).await,
Some(Commands::Sessions(args)) => run_sessions(args).await,
```

- [ ] **Step 4: Implement CLI runners**

Update `run_enter` call:

```rust
&args.name,
args.detach,
args.new,
```

Add:

```rust
async fn run_resume(args: ResumeArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let result = agentenv_core::runtime::resume_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        args.session_id.as_deref(),
    )
    .await?;
    process::exit(result.status);
}

async fn run_sessions(args: SessionsArgs) -> Result<()> {
    match args.command {
        SessionsCommand::List(args) => run_sessions_list(args).await,
        SessionsCommand::Kill(args) => run_sessions_kill(args).await,
    }
}

async fn run_sessions_list(args: SessionsListArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let rows = agentenv_core::runtime::list_sessions_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        args.env.as_deref(),
    )
    .await?;
    if args.json {
        render::print_json(&render::SessionsJson { sessions: rows })?;
    } else {
        render::print_sessions_text(&rows);
    }
    Ok(())
}

async fn run_sessions_kill(args: SessionsKillArgs) -> Result<()> {
    let options = runtime_options(true)?;
    agentenv_core::runtime::kill_session_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.session_id,
    )
    .await?;
    println!("killed: {}", args.session_id);
    Ok(())
}
```

- [ ] **Step 5: Add render helpers**

In `crates/agentenv/src/render.rs`, add:

```rust
use agentenv_core::runtime::SessionListRow;

#[derive(Debug, Serialize)]
pub struct SessionsJson {
    pub sessions: Vec<SessionListRow>,
}

pub fn print_sessions_text(rows: &[SessionListRow]) {
    println!(
        "{:<20} {:<26} {:<20} {:<10} {:<28} UPDATED",
        "ENV", "SESSION", "NAME", "STATUS", "COMMAND"
    );
    for row in rows {
        println!(
            "{:<20} {:<26} {:<20} {:<10} {:<28} {}",
            row.env,
            row.session_id,
            row.name,
            format!("{:?}", row.status).to_lowercase(),
            row.command,
            row.updated_at
        );
    }
}
```

- [ ] **Step 6: Run CLI tests**

Run:

```bash
cargo test -p agentenv resume_missing_env_uses_stable_error sessions_list_json_returns_empty_when_registry_missing
cargo test -p agentenv cli_behavior
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add crates/agentenv/src/main.rs crates/agentenv/src/render.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat(cli): add session commands"
```

## Task 6: OpenShell Session Backend

**Files:**
- Modify: `crates/drivers/sandbox-openshell/src/lib.rs`

- [ ] **Step 1: Write failing OpenShell tests**

Add tests near existing OpenShell driver tests:

```rust
#[tokio::test]
async fn openshell_create_session_uses_tmux_when_available() {
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::success("openshell", &["sandbox", "exec", "--name", "sb-1", "--", "sh", "-lc", "command -v tmux >/dev/null 2>&1"], "", ""),
        CommandScript::success("openshell", &["sandbox", "exec", "--name", "sb-1", "--", "sh", "-lc", "tmux new-session -d -s sh-1 -c /sandbox 'agentenv-agent'"], "", ""),
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

    assert_eq!(session.session_id, "sh-1");
    assert_eq!(session.status, agentenv_proto::SessionStatus::Detached);
}

#[tokio::test]
async fn openshell_attach_session_attaches_tmux_interactively() {
    let runner = Arc::new(RecordingCommandRunner::new(vec![
        CommandScript::success("openshell", &["sandbox", "exec", "--name", "sb-1", "--", "sh", "-lc", "tmux attach-session -t sh-1"], "", ""),
    ]));
    let driver = OpenShellDriver::with_command_runner(runner);
    let result = driver
        .attach_session(AttachSessionParams {
            handle: "sb-1".to_owned(),
            session_id: "sh-1".to_owned(),
        })
        .await
        .unwrap();

    assert_eq!(result.status, 0);
}
```

Import the new proto types in the test module.

- [ ] **Step 2: Run failing tests**

Run:

```bash
cargo test -p sandbox-openshell openshell_create_session_uses_tmux_when_available openshell_attach_session_attaches_tmux_interactively
```

Expected: fail because methods are not overridden and OpenShell capability is false.

- [ ] **Step 3: Implement tmux session methods**

Update imports:

```rust
AttachSessionParams, CreateSessionParams, KillSessionParams, ListSessionsParams,
ListSessionsResult, SessionHandle, SessionStatus,
```

Set OpenShell initialize capability:

```rust
supports_persistent_sessions: true,
```

Add helper:

```rust
fn tmux_session_id(name: &str) -> DriverResult<String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DriverError::InvalidInput {
            message: format!("invalid session name `{name}`"),
        });
    }
    Ok(name.to_owned())
}
```

Add method implementations:

```rust
async fn create_session(&self, params: CreateSessionParams) -> DriverResult<SessionHandle> {
    let session_id = tmux_session_id(&params.name)?;
    let check_tmux = format!("command -v tmux >/dev/null 2>&1");
    let check = self.run_command_request(CommandRequest {
        args: vec![
            "sandbox".to_owned(),
            "exec".to_owned(),
            "--name".to_owned(),
            params.handle.clone(),
            "--".to_owned(),
            "sh".to_owned(),
            "-lc".to_owned(),
            check_tmux,
        ],
        env: BTreeMap::new(),
    }).map_err(|source| DriverError::CommandSpawn {
        command: format!("{} sandbox exec --name {} -- sh -lc command -v tmux", self.binary, params.handle),
        source,
    })?;
    if check.status.unwrap_or(1) != 0 {
        return Err(DriverError::CapabilityMissing {
            capability: "supports_persistent_sessions".to_owned(),
        });
    }
    let command = format!(
        "tmux new-session -d -s {} -c /sandbox {}",
        session_id,
        shell_quote(&params.command)
    );
    let output = self.run_checked_command(CommandRequest {
        args: vec![
            "sandbox".to_owned(),
            "exec".to_owned(),
            "--name".to_owned(),
            params.handle,
            "--".to_owned(),
            "sh".to_owned(),
            "-lc".to_owned(),
            command,
        ],
        env: BTreeMap::new(),
    })?;
    let now = crate_now_utc_string();
    Ok(SessionHandle {
        session_id,
        name: params.name,
        status: if params.detached { SessionStatus::Detached } else { SessionStatus::Attached },
        created_at: now.clone(),
        updated_at: now,
        command: params.command,
        working_dir: Some("/sandbox".to_owned()),
    })
}
```

Use the existing `shell_quote` helper from runtime as local OpenShell helper if one does not exist.

Implement attach:

```rust
async fn attach_session(&self, params: AttachSessionParams) -> DriverResult<ExecResult> {
    let session_id = tmux_session_id(&params.session_id)?;
    let request = CommandRequest {
        args: vec![
            "sandbox".to_owned(),
            "exec".to_owned(),
            "--name".to_owned(),
            params.handle,
            "--".to_owned(),
            "sh".to_owned(),
            "-lc".to_owned(),
            format!("tmux attach-session -t {}", session_id),
        ],
        env: BTreeMap::new(),
    };
    let status = self.run_interactive_request(request).map_err(|source| DriverError::CommandSpawn {
        command: "openshell sandbox exec tmux attach-session".to_owned(),
        source,
    })?;
    Ok(ExecResult {
        status: status.unwrap_or(1),
        stdout: String::new(),
        stderr: String::new(),
    })
}
```

Implement kill:

```rust
async fn kill_session(&self, params: KillSessionParams) -> DriverResult<EmptyResult> {
    let session_id = tmux_session_id(&params.session_id)?;
    let _ = self.run_checked_command(CommandRequest {
        args: vec![
            "sandbox".to_owned(),
            "exec".to_owned(),
            "--name".to_owned(),
            params.handle,
            "--".to_owned(),
            "sh".to_owned(),
            "-lc".to_owned(),
            format!("tmux kill-session -t {}", session_id),
        ],
        env: BTreeMap::new(),
    })?;
    Ok(EmptyResult {})
}
```

Implement list with tab-separated parsing:

```rust
async fn list_sessions(&self, params: ListSessionsParams) -> DriverResult<ListSessionsResult> {
    let output = self.run_checked_command(CommandRequest {
        args: vec![
            "sandbox".to_owned(),
            "exec".to_owned(),
            "--name".to_owned(),
            params.handle,
            "--".to_owned(),
            "sh".to_owned(),
            "-lc".to_owned(),
            "tmux list-sessions -F '#{session_name}\t#{session_attached}\t#{session_created}'".to_owned(),
        ],
        env: BTreeMap::new(),
    })?;
    let sessions = output.stdout.lines().filter_map(parse_tmux_session_line).collect();
    Ok(ListSessionsResult { sessions })
}
```

- [ ] **Step 4: Run OpenShell tests**

Run:

```bash
cargo test -p sandbox-openshell openshell_create_session_uses_tmux_when_available openshell_attach_session_attaches_tmux_interactively
cargo test -p sandbox-openshell
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/drivers/sandbox-openshell/src/lib.rs
git commit -m "feat(openshell): support persistent sessions"
```

## Task 7: Protocol and Architecture Docs

**Files:**
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Update driver protocol docs**

In `docs/DRIVER_PROTOCOL.md`, update the title to:

```markdown
# agentenv Driver Protocol (v1.1 draft)
```

Add `supports_persistent_sessions` to the sandbox initialize response example.

Add sandbox methods:

```markdown
| `create_session` | `CreateSessionParams` | `SessionHandle` |
| `attach_session` | `AttachSessionParams` | `ExecResult` |
| `list_sessions` | `ListSessionsParams` | `ListSessionsResult` |
| `kill_session` | `KillSessionParams` | `{}` |
```

Add a short note:

```markdown
Persistent sessions are optional. Core checks `supports_persistent_sessions`
before calling session methods. Drivers that cannot provide durable attach,
detach, resume, and single-session kill semantics return `CapabilityMissing`
for these methods.
```

- [ ] **Step 2: Update architecture docs**

In `docs/ARCHITECTURE.md`, extend the Sessions vs. Sandboxes example:

```text
agentenv enter myapp --new     # creates an additional session
agentenv resume myapp          # reattaches the default detached session
agentenv sessions list myapp   # shows session status
agentenv sessions kill 01HXY   # kills one session only
```

- [ ] **Step 3: Commit**

```bash
git add docs/DRIVER_PROTOCOL.md docs/ARCHITECTURE.md
git commit -m "docs: document session protocol"
```

## Task 8: Full Verification

**Files:**
- All modified files.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt
```

Expected: no errors.

- [ ] **Step 2: Clippy**

Run:

```bash
cargo clippy --workspace -- -D warnings
```

Expected: no warnings.

- [ ] **Step 3: Tests**

Run:

```bash
cargo test --workspace
```

Expected: all non-ignored tests pass.

- [ ] **Step 4: Inspect generated/schema changes**

Run:

```bash
git status --short
git diff --stat
```

Expected: only intended source, docs, test, and generated schema files are modified.

- [ ] **Step 5: Final commit if verification required fixes**

If formatting or verification fixes changed files:

```bash
git add .
git commit -m "test: verify persistent sessions"
```

If no files changed after verification, do not create an empty commit.
