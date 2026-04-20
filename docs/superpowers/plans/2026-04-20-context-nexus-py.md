# Context Nexus Python Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #12 by adding a Python `context-nexus-py` subprocess driver plus the minimal Rust subprocess context-driver host needed to exercise it.

**Architecture:** `agentenv-plugin` becomes the production JSON-RPC stdio host for subprocess drivers and exposes a `SubprocessContextDriver` that implements `agentenv_core::driver::ContextDriver`. `external-drivers/context-nexus-py` provides the `nexus` context driver process, with hub mode returning a remote MCP endpoint and lite mode starting a local Nexus MCP HTTP process.

**Tech Stack:** Rust 2021, `tokio::process`, `async-trait`, `serde_json`, `thiserror`, `agentenv-core` driver traits, `agentenv-proto` protocol types, Python 3.11+ standard library, shell installer tests.

---

## File Structure

- Create `crates/agentenv-plugin/src/jsonrpc.rs`: LSP-style JSON-RPC framing, envelopes, async subprocess client, request timeout, shutdown, notification skipping.
- Create `crates/agentenv-plugin/src/context.rs`: manifest-backed `SubprocessContextDriver` that maps `ContextDriver` trait methods to JSON-RPC requests.
- Modify `crates/agentenv-plugin/src/lib.rs`: export `JsonRpcClient`, `JsonRpcError`, `SubprocessContextDriver`, and construction helpers.
- Modify `crates/agentenv-plugin/Cargo.toml`: add `agentenv-core`, `agentenv-proto`, `async-trait`, `serde`, `serde_json`, `thiserror`, and `tokio` dependencies.
- Modify `tests/driver-conformance/src/lib.rs`: add subprocess context-driver conformance helpers.
- Modify `tests/driver-conformance/src/main.rs`: add `--context` mode for context-driver conformance.
- Create `external-drivers/context-nexus-py/pyproject.toml`: Python package metadata and console script.
- Create `external-drivers/context-nexus-py/README.md`: usage, modes, tests, and install notes.
- Create `external-drivers/context-nexus-py/manifest.json.in`: install-time manifest template.
- Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/__init__.py`: version export.
- Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/__main__.py`: module entrypoint.
- Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/protocol.py`: protocol constants and JSON result builders.
- Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/jsonrpc.py`: stdio frame server.
- Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/nexus.py`: Nexus process and URL helpers.
- Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/driver.py`: driver method implementation and handle state.
- Create `external-drivers/context-nexus-py/tests/test_jsonrpc.py`: Python JSON-RPC server tests.
- Create `external-drivers/context-nexus-py/tests/test_driver_methods.py`: Python driver behavior tests.
- Create `external-drivers/context-nexus-py/tests/fixtures/fake_nexus.py`: fake Nexus CLI fixture for lite mode.
- Create `external-drivers/context-nexus-py/scripts/install-driver.sh`: isolated venv installer for local development and bundles.
- Create `external-drivers/context-nexus-py/scripts/build-bundle.sh`: deterministic tarball builder for repo installer path.
- Modify `install.sh`: keep index install path and support prebuilt local Python driver bundles.
- Modify `tests/install/test_install.sh`: verify bundle extraction and `context-nexus` installed layout.
- Modify `docs/DRIVER_PROTOCOL.md`: document that context subprocess conformance is implemented and that credentials remain env-injected.

## Task 1: Rust Plugin Dependencies and JSON-RPC Framing

**Files:**
- Modify: `crates/agentenv-plugin/Cargo.toml`
- Modify: `crates/agentenv-plugin/src/lib.rs`
- Create: `crates/agentenv-plugin/src/jsonrpc.rs`

- [ ] **Step 1: Write failing JSON-RPC framing tests**

Create `crates/agentenv-plugin/src/jsonrpc.rs` with the test module first:

```rust
#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::{read_framed_json_blocking, write_framed_json_blocking, RpcResponseEnvelope};

    #[test]
    fn jsonrpc_frame_roundtrip_preserves_payload() {
        let mut bytes = Vec::new();
        let message = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {"ok": true}
        });

        write_framed_json_blocking(&mut bytes, &message).unwrap();
        let decoded = read_framed_json_blocking(&mut Cursor::new(bytes)).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn response_envelope_rejects_missing_result_and_error() {
        let raw = json!({"jsonrpc": "2.0", "id": 1});
        let envelope: RpcResponseEnvelope = serde_json::from_value(raw).unwrap();

        assert!(envelope.result.is_none());
        assert!(envelope.error.is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-plugin jsonrpc_frame_roundtrip_preserves_payload response_envelope_rejects_missing_result_and_error
```

Expected: FAIL because `serde_json`, `RpcResponseEnvelope`, and framing helpers are not defined in `agentenv-plugin`.

- [ ] **Step 3: Add crate dependencies**

Update `crates/agentenv-plugin/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../agentenv-core" }
agentenv-proto = { path = "../agentenv-proto" }
async-trait.workspace = true
serde.workspace = true
serde_json.workspace = true
semver = "1"
thiserror.workspace = true
tokio.workspace = true
```

- [ ] **Step 4: Implement blocking framing helpers and envelopes**

Add this implementation above the tests in `crates/agentenv-plugin/src/jsonrpc.rs`:

```rust
use std::io::{BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JsonRpcError {
    #[error("I/O error while handling JSON-RPC frame: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON-RPC payload: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing Content-Length header")]
    MissingContentLength,
    #[error("invalid Content-Length header `{0}`")]
    InvalidContentLength(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcResponseEnvelope {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcNotificationEnvelope {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

pub fn write_framed_json_blocking<W, T>(writer: &mut W, message: &T) -> Result<(), JsonRpcError>
where
    W: Write,
    T: Serialize,
{
    let payload = serde_json::to_vec(message)?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_framed_json_blocking<R>(reader: &mut R) -> Result<Value, JsonRpcError>
where
    R: BufRead + Read,
{
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Err(JsonRpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading JSON-RPC headers",
            )));
        }
        if line == "\r\n" {
            break;
        }
        if let Some(raw) = line.strip_prefix("Content-Length: ") {
            let trimmed = raw.trim();
            content_length = Some(
                trimmed
                    .parse::<usize>()
                    .map_err(|_| JsonRpcError::InvalidContentLength(trimmed.to_owned()))?,
            );
        }
    }

    let content_length = content_length.ok_or(JsonRpcError::MissingContentLength)?;
    let mut payload = vec![0_u8; content_length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}
```

- [ ] **Step 5: Export the module**

Update `crates/agentenv-plugin/src/lib.rs`:

```rust
#![forbid(unsafe_code)]

pub mod jsonrpc;

pub use jsonrpc::{
    read_framed_json_blocking, write_framed_json_blocking, JsonRpcError, RpcErrorObject,
    RpcNotificationEnvelope, RpcResponseEnvelope,
};
```

- [ ] **Step 6: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-plugin jsonrpc_frame_roundtrip_preserves_payload response_envelope_rejects_missing_result_and_error
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/agentenv-plugin/Cargo.toml crates/agentenv-plugin/src/lib.rs crates/agentenv-plugin/src/jsonrpc.rs Cargo.lock
git commit -m "feat: add json-rpc framing for subprocess drivers"
```

## Task 2: Async JSON-RPC Subprocess Client

**Files:**
- Modify: `crates/agentenv-plugin/src/jsonrpc.rs`

- [ ] **Step 1: Write failing async client tests**

Append these tests to `crates/agentenv-plugin/src/jsonrpc.rs`:

```rust
#[cfg(test)]
mod async_client_tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use serde_json::json;

    use super::{JsonRpcClient, JsonRpcClientConfig};

    #[tokio::test]
    async fn jsonrpc_client_returns_method_result() {
        let driver = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/mock-driver");
        assert!(driver.is_file(), "run `cargo build -p driver-conformance --bin mock-driver` first");

        let mut client = JsonRpcClient::spawn(JsonRpcClientConfig {
            binary: driver,
            args: Vec::new(),
            env: Default::default(),
            timeout: Duration::from_secs(5),
        })
        .await
        .unwrap();

        let result: agentenv_proto::PreflightResult =
            client.call("preflight", &agentenv_proto::PreflightParams::default()).await.unwrap();

        assert!(result.ok);
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn jsonrpc_client_surfaces_driver_error_code() {
        let driver = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/mock-driver");
        assert!(driver.is_file(), "run `cargo build -p driver-conformance --bin mock-driver` first");

        let mut client = JsonRpcClient::spawn(JsonRpcClientConfig {
            binary: driver,
            args: Vec::new(),
            env: Default::default(),
            timeout: Duration::from_secs(5),
        })
        .await
        .unwrap();

        let err = client.call::<_, serde_json::Value>("driver/unknown", &json!({})).await.unwrap_err();

        assert!(err.to_string().contains("-32601"));
        client.shutdown().await.unwrap();
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Build the mock driver and run plugin tests:

```bash
cargo build -p driver-conformance --bin mock-driver
cargo test -p agentenv-plugin jsonrpc_client_returns_method_result jsonrpc_client_surfaces_driver_error_code
```

Expected: FAIL because `JsonRpcClient` and `JsonRpcClientConfig` do not exist.

- [ ] **Step 3: Implement async subprocess client**

Add these public types and methods to `crates/agentenv-plugin/src/jsonrpc.rs`:

```rust
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct JsonRpcClientConfig {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
}

pub struct JsonRpcClient {
    child: Child,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    next_id: AtomicU64,
    timeout: Duration,
}

impl JsonRpcClient {
    pub async fn spawn(config: JsonRpcClientConfig) -> Result<Self, JsonRpcError> {
        let mut command = Command::new(&config.binary);
        command.args(&config.args);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::inherit());
        command.env_clear();
        command.env("PATH", std::env::var("PATH").unwrap_or_default());
        for (key, value) in &config.env {
            command.env(key, value);
        }

        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| {
            JsonRpcError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "driver stdin was unavailable",
            ))
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            JsonRpcError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "driver stdout was unavailable",
            ))
        })?;

        Ok(Self {
            child,
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicU64::new(1),
            timeout: config.timeout,
        })
    }

    pub async fn call<P, R>(&self, method: &str, params: &P) -> Result<R, JsonRpcError>
    where
        P: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let fut = async {
            {
                let mut stdin = self.stdin.lock().await;
                write_framed_json_async(&mut *stdin, &request).await?;
            }

            loop {
                let raw = {
                    let mut stdout = self.stdout.lock().await;
                    read_framed_json_async(&mut *stdout).await?
                };
                if raw.get("method").is_some() && raw.get("id").is_none() {
                    continue;
                }
                let response: RpcResponseEnvelope = serde_json::from_value(raw)?;
                if response.id != serde_json::json!(id) {
                    return Err(JsonRpcError::Protocol(format!(
                        "received response id {} while waiting for {}",
                        response.id, id
                    )));
                }
                if let Some(error) = response.error {
                    return Err(JsonRpcError::Remote {
                        code: error.code,
                        message: error.message,
                    });
                }
                let result = response
                    .result
                    .ok_or_else(|| JsonRpcError::Protocol(format!("missing result for `{method}`")))?;
                return Ok(serde_json::from_value(result)?);
            }
        };

        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| JsonRpcError::Timeout(method.to_owned()))?
    }

    pub async fn shutdown(&mut self) -> Result<(), JsonRpcError> {
        let _result: agentenv_proto::EmptyResult =
            self.call("shutdown", &agentenv_proto::ShutdownParams {}).await?;
        let _ = tokio::time::timeout(self.timeout, self.child.wait()).await;
        Ok(())
    }
}
```

Also extend `JsonRpcError`:

```rust
#[error("JSON-RPC protocol error: {0}")]
Protocol(String),
#[error("JSON-RPC request `{0}` timed out")]
Timeout(String),
#[error("remote JSON-RPC error {code}: {message}")]
Remote { code: i64, message: String },
```

Add async framing helpers:

```rust
async fn write_framed_json_async<W, T>(writer: &mut W, message: &T) -> Result<(), JsonRpcError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(message)?;
    writer
        .write_all(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes())
        .await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_framed_json_async<R>(reader: &mut R) -> Result<Value, JsonRpcError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            return Err(JsonRpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading JSON-RPC headers",
            )));
        }
        if line == "\r\n" {
            break;
        }
        if let Some(raw) = line.strip_prefix("Content-Length: ") {
            let trimmed = raw.trim();
            content_length = Some(
                trimmed
                    .parse::<usize>()
                    .map_err(|_| JsonRpcError::InvalidContentLength(trimmed.to_owned()))?,
            );
        }
    }

    let content_length = content_length.ok_or(JsonRpcError::MissingContentLength)?;
    let mut payload = vec![0_u8; content_length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}
```

- [ ] **Step 4: Export client types**

Update `crates/agentenv-plugin/src/lib.rs`:

```rust
pub use jsonrpc::{
    read_framed_json_blocking, write_framed_json_blocking, JsonRpcClient, JsonRpcClientConfig,
    JsonRpcError, RpcErrorObject, RpcNotificationEnvelope, RpcResponseEnvelope,
};
```

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
cargo build -p driver-conformance --bin mock-driver
cargo test -p agentenv-plugin jsonrpc
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/agentenv-plugin/src/jsonrpc.rs crates/agentenv-plugin/src/lib.rs
git commit -m "feat: add async json-rpc subprocess client"
```

## Task 3: Rust Subprocess Context Driver Adapter

**Files:**
- Create: `crates/agentenv-plugin/src/context.rs`
- Modify: `crates/agentenv-plugin/src/lib.rs`
- Modify: `crates/agentenv-core/src/driver.rs`

- [ ] **Step 1: Write failing adapter tests**

Create `crates/agentenv-plugin/src/context.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use agentenv_core::driver::ContextDriver;
    use agentenv_core::driver_catalog::{DiscoveredDriver, DriverSource};
    use agentenv_core::registry::DriverKind as CatalogKind;
    use agentenv_proto::{
        Capabilities, ContextCapabilities, DriverInfo, DriverKind, InitializeParams,
        InitializeResult, LogLevel, SCHEMA_VERSION,
    };
    use semver::Version;
    use serde_json::Value;

    use super::SubprocessContextDriver;

    fn mock_entry() -> DiscoveredDriver {
        DiscoveredDriver {
            kind: CatalogKind::Context,
            name: "nexus".to_owned(),
            version: Version::parse("0.1.0").unwrap(),
            source: DriverSource::DevelopmentOverride,
            description: None,
            binary: Some(PathBuf::from("driver")),
            manifest_path: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            capabilities_preview: Value::Null,
        }
    }

    #[tokio::test]
    async fn constructor_rejects_built_in_entries_without_binary() {
        let mut entry = mock_entry();
        entry.binary = None;

        let err = SubprocessContextDriver::from_discovered(entry, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("binary"));
    }

    #[test]
    fn initialize_result_validator_accepts_context_driver() {
        let init = InitializeResult {
            driver: DriverInfo {
                name: "nexus".to_owned(),
                kind: DriverKind::Context,
                version: "0.1.0".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Context(ContextCapabilities {
                is_remote: true,
                is_shared: true,
                supports_zones: true,
                supports_snapshots: true,
            }),
        };

        super::validate_context_initialize(&init).unwrap();
    }

    #[test]
    fn initialize_result_validator_rejects_agent_driver() {
        let init = InitializeResult {
            driver: DriverInfo {
                name: "bad".to_owned(),
                kind: DriverKind::Agent,
                version: "0.1.0".to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Context(ContextCapabilities {
                is_remote: true,
                is_shared: true,
                supports_zones: true,
                supports_snapshots: true,
            }),
        };

        let err = super::validate_context_initialize(&init).unwrap_err();
        assert!(err.to_string().contains("context"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p agentenv-plugin constructor_rejects_built_in_entries_without_binary initialize_result_validator_accepts_context_driver initialize_result_validator_rejects_agent_driver
```

Expected: FAIL because `context.rs`, `SubprocessContextDriver`, and `validate_context_initialize` are not implemented.

- [ ] **Step 3: Add a driver error variant for subprocess protocol failures**

Modify `DriverError` in `crates/agentenv-core/src/driver.rs`:

```rust
Subprocess {
    driver: String,
    message: String,
},
```

Add display branch:

```rust
DriverError::Subprocess { driver, message } => {
    write!(f, "subprocess driver `{driver}` failed: {message}")
}
```

- [ ] **Step 4: Implement the context adapter**

Add this implementation to `crates/agentenv-plugin/src/context.rs`:

```rust
use std::time::Duration;

use agentenv_core::driver::{ensure_protocol_compatible, ContextDriver, DriverError, DriverResult};
use agentenv_core::driver_catalog::DiscoveredDriver;
use agentenv_proto::{
    Capabilities, ContextHandle, ContextHandleRequest, ContextSpec, ContextStatus,
    CredentialRequirementsParams, CredentialRequirementsResult, EmptyResult, InitializeParams,
    InitializeResult, McpEndpoint, PreflightParams, PreflightResult, RequiredNetworkRulesResult,
    ShutdownParams,
};
use async_trait::async_trait;

use crate::jsonrpc::{JsonRpcClient, JsonRpcClientConfig, JsonRpcError};

pub struct SubprocessContextDriver {
    name: String,
    client: JsonRpcClient,
}

impl SubprocessContextDriver {
    pub async fn from_discovered(entry: DiscoveredDriver, timeout: Duration) -> DriverResult<Self> {
        let binary = entry.binary.clone().ok_or_else(|| DriverError::Subprocess {
            driver: entry.name.clone(),
            message: "discovered subprocess driver did not include a binary".to_owned(),
        })?;
        let client = JsonRpcClient::spawn(JsonRpcClientConfig {
            binary,
            args: entry.args,
            env: entry.env,
            timeout,
        })
        .await
        .map_err(|err| map_jsonrpc_error(&entry.name, err))?;

        Ok(Self {
            name: entry.name,
            client,
        })
    }
}

pub fn validate_context_initialize(result: &InitializeResult) -> DriverResult<()> {
    ensure_protocol_compatible(result)?;
    if result.driver.kind != agentenv_proto::DriverKind::Context {
        return Err(DriverError::Subprocess {
            driver: result.driver.name.clone(),
            message: format!("initialize reported {:?}; expected context", result.driver.kind),
        });
    }
    if !matches!(result.capabilities, Capabilities::Context(_)) {
        return Err(DriverError::Subprocess {
            driver: result.driver.name.clone(),
            message: "initialize did not report context capabilities".to_owned(),
        });
    }
    Ok(())
}

fn map_jsonrpc_error(driver: &str, err: JsonRpcError) -> DriverError {
    DriverError::Subprocess {
        driver: driver.to_owned(),
        message: err.to_string(),
    }
}

#[async_trait]
impl ContextDriver for SubprocessContextDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        let result: InitializeResult = self
            .client
            .call("initialize", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))?;
        validate_context_initialize(&result)?;
        Ok(result)
    }

    async fn preflight(&self, params: PreflightParams) -> DriverResult<PreflightResult> {
        self.client
            .call("preflight", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn provision(&self, spec: ContextSpec) -> DriverResult<ContextHandle> {
        self.client
            .call("provision", &spec)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn mcp_endpoint(&self, params: ContextHandleRequest) -> DriverResult<McpEndpoint> {
        self.client
            .call("mcp_endpoint", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn required_network_rules(
        &self,
        params: ContextHandleRequest,
    ) -> DriverResult<RequiredNetworkRulesResult> {
        self.client
            .call("required_network_rules", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn credential_requirements(
        &self,
        params: CredentialRequirementsParams,
    ) -> DriverResult<CredentialRequirementsResult> {
        self.client
            .call("credential_requirements", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn status(&self, params: ContextHandleRequest) -> DriverResult<ContextStatus> {
        self.client
            .call("status", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn teardown(&self, params: ContextHandleRequest) -> DriverResult<EmptyResult> {
        self.client
            .call("teardown", &params)
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        self.client
            .shutdown()
            .await
            .map_err(|err| map_jsonrpc_error(&self.name, err))?;
        Ok(EmptyResult::default())
    }
}
```

- [ ] **Step 5: Export the adapter**

Update `crates/agentenv-plugin/src/lib.rs`:

```rust
pub mod context;
pub mod jsonrpc;

pub use context::{validate_context_initialize, SubprocessContextDriver};
pub use jsonrpc::{
    read_framed_json_blocking, write_framed_json_blocking, JsonRpcClient, JsonRpcClientConfig,
    JsonRpcError, RpcErrorObject, RpcNotificationEnvelope, RpcResponseEnvelope,
};
```

- [ ] **Step 6: Run tests to verify they pass**

Run:

```bash
cargo test -p agentenv-plugin context
cargo test -p agentenv-core subprocess
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/agentenv-core/src/driver.rs crates/agentenv-plugin/src/context.rs crates/agentenv-plugin/src/lib.rs
git commit -m "feat: add subprocess context driver adapter"
```

## Task 4: Python Package Skeleton and JSON-RPC Server

**Files:**
- Create: `external-drivers/context-nexus-py/pyproject.toml`
- Create: `external-drivers/context-nexus-py/src/agentenv_context_nexus/__init__.py`
- Create: `external-drivers/context-nexus-py/src/agentenv_context_nexus/__main__.py`
- Create: `external-drivers/context-nexus-py/src/agentenv_context_nexus/protocol.py`
- Create: `external-drivers/context-nexus-py/src/agentenv_context_nexus/jsonrpc.py`
- Create: `external-drivers/context-nexus-py/tests/test_jsonrpc.py`

- [ ] **Step 1: Write failing Python JSON-RPC tests**

Create `external-drivers/context-nexus-py/tests/test_jsonrpc.py`:

```python
import io

from agentenv_context_nexus.jsonrpc import read_message, write_message


def test_frame_roundtrip_preserves_message():
    stream = io.BytesIO()
    write_message(stream, {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    stream.seek(0)

    assert read_message(stream) == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}


def test_read_message_rejects_missing_content_length():
    stream = io.BytesIO(b"\r\n{}")

    try:
        read_message(stream)
    except ValueError as exc:
        assert "Content-Length" in str(exc)
    else:
        raise AssertionError("missing Content-Length should fail")
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cd external-drivers/context-nexus-py
python3 -m pytest tests/test_jsonrpc.py -q
```

Expected: FAIL because the package and modules do not exist.

- [ ] **Step 3: Add Python package metadata**

Create `external-drivers/context-nexus-py/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "agentenv-context-nexus"
version = "0.1.0"
description = "agentenv Nexus context subprocess driver"
requires-python = ">=3.11"
readme = "README.md"

[project.scripts]
agentenv-driver-nexus = "agentenv_context_nexus.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]
```

Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/__init__.py`:

```python
__version__ = "0.1.0"
```

Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/protocol.py`:

```python
SCHEMA_VERSION = "1.0"
JSON_RPC_METHOD_NOT_FOUND = -32601
JSON_RPC_INVALID_PARAMS = -32602
JSON_RPC_INTERNAL_ERROR = -32603
ERROR_SCHEMA_VERSION_INCOMPATIBLE = -32002
ERROR_RESOURCE_NOT_FOUND = -32003


def success(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error(request_id, code, message, data=None):
    payload = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    if data is not None:
        payload["error"]["data"] = data
    return payload
```

- [ ] **Step 4: Implement Python framing**

Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/jsonrpc.py`:

```python
import json
import sys


def read_message(stream):
    content_length = None
    while True:
        line = stream.readline()
        if line == b"":
            raise EOFError("unexpected EOF while reading JSON-RPC headers")
        if line == b"\r\n":
            break
        if line.startswith(b"Content-Length: "):
            raw = line[len(b"Content-Length: ") :].strip()
            try:
                content_length = int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid Content-Length header {raw!r}") from exc
    if content_length is None:
        raise ValueError("missing Content-Length header")
    payload = stream.read(content_length)
    if len(payload) != content_length:
        raise EOFError("unexpected EOF while reading JSON-RPC payload")
    return json.loads(payload.decode("utf-8"))


def write_message(stream, message):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
    stream.write(payload)
    stream.flush()


class JsonRpcServer:
    def __init__(self, handler):
        self._handler = handler

    def serve(self, stdin=None, stdout=None):
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        while True:
            try:
                request = read_message(stdin)
            except EOFError:
                return
            response = self._handler.handle(request)
            if response is not None:
                write_message(stdout, response)
            if request.get("method") == "shutdown" and "error" not in response:
                return
```

Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/__main__.py`:

```python
from agentenv_context_nexus.driver import NexusContextDriver
from agentenv_context_nexus.jsonrpc import JsonRpcServer


def main():
    JsonRpcServer(NexusContextDriver()).serve()


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
cd external-drivers/context-nexus-py
PYTHONPATH=src python3 -m pytest tests/test_jsonrpc.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add external-drivers/context-nexus-py/pyproject.toml external-drivers/context-nexus-py/src external-drivers/context-nexus-py/tests/test_jsonrpc.py
git commit -m "feat: scaffold nexus python json-rpc driver"
```

## Task 5: Python Nexus Driver Methods

**Files:**
- Create: `external-drivers/context-nexus-py/src/agentenv_context_nexus/driver.py`
- Create: `external-drivers/context-nexus-py/src/agentenv_context_nexus/nexus.py`
- Create: `external-drivers/context-nexus-py/tests/test_driver_methods.py`

- [ ] **Step 1: Write failing driver method tests**

Create `external-drivers/context-nexus-py/tests/test_driver_methods.py`:

```python
from agentenv_context_nexus.driver import NexusContextDriver
from agentenv_context_nexus.protocol import ERROR_SCHEMA_VERSION_INCOMPATIBLE


def call(driver, method, params):
    return driver.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def test_initialize_reports_context_capabilities():
    response = call(
        NexusContextDriver(),
        "initialize",
        {"schema_version": "1.0", "core_version": "0.0.1", "workdir": "/tmp/agentenv", "log_level": "info"},
    )

    assert response["result"]["driver"]["name"] == "nexus"
    assert response["result"]["driver"]["kind"] == "context"
    assert response["result"]["capabilities"]["supports_zones"] is True


def test_initialize_rejects_schema_major_mismatch():
    response = call(
        NexusContextDriver(),
        "initialize",
        {"schema_version": "2.0", "core_version": "0.0.1", "workdir": "/tmp/agentenv", "log_level": "info"},
    )

    assert response["error"]["code"] == ERROR_SCHEMA_VERSION_INCOMPATIBLE


def test_credential_requirements_declares_nexus_token():
    response = call(NexusContextDriver(), "credential_requirements", {})

    requirement = response["result"]["requirements"][0]
    assert requirement["name"] == "NEXUS_TOKEN"
    assert requirement["kind"] == "token"
    assert requirement["required"] is False


def test_hub_provision_requires_hub_url():
    response = call(NexusContextDriver(), "provision", {"config": {"mode": "hub"}})

    assert response["error"]["code"] == -32602
    assert "hub_url" in response["error"]["message"]


def test_hub_network_rules_parse_host_scheme_and_port():
    driver = NexusContextDriver()
    provision = call(
        driver,
        "provision",
        {"config": {"mode": "hub", "hub_url": "https://nexus.example.com:8443", "zones": ["eng"]}},
    )
    handle = provision["result"]["handle"]

    response = call(driver, "required_network_rules", {"handle": handle})

    target = response["result"]["rules"][0]["target"]
    assert target["kind"] == "host"
    assert target["host"] == "nexus.example.com"
    assert target["scheme"] == "https"
    assert target["port"] == 8443


def test_hub_mcp_endpoint_uses_hub_url_without_headers():
    driver = NexusContextDriver()
    provision = call(driver, "provision", {"config": {"mode": "hub", "hub_url": "https://nexus.example.com"}})
    handle = provision["result"]["handle"]

    response = call(driver, "mcp_endpoint", {"handle": handle})

    assert response["result"]["url"] == "https://nexus.example.com"
    assert response["result"]["transport"] == "http"
    assert response["result"]["headers"] == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cd external-drivers/context-nexus-py
PYTHONPATH=src python3 -m pytest tests/test_driver_methods.py -q
```

Expected: FAIL because `NexusContextDriver` is not implemented.

- [ ] **Step 3: Implement Nexus helpers**

Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/nexus.py`:

```python
import hashlib
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ParsedUrl:
    url: str
    scheme: str
    host: str
    port: int | None


def parse_http_url(raw):
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("hub_url must use http or https")
    if not parsed.hostname:
        raise ValueError("hub_url must include a host")
    return ParsedUrl(url=raw.rstrip("/"), scheme=parsed.scheme, host=parsed.hostname, port=parsed.port)


def stable_hub_handle(hub_url, zones):
    digest = hashlib.sha256((hub_url + "|" + ",".join(zones)).encode("utf-8")).hexdigest()[:16]
    return f"nexus-hub-{digest}"


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def nexus_cli_available():
    return shutil.which("nexus") is not None


def start_lite_process(data_dir, port, extra_env=None):
    env = os.environ.copy()
    env["NEXUS_DATA_DIR"] = data_dir
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        ["nexus", "mcp", "serve", "--transport", "http", "--host", "127.0.0.1", "--port", str(port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
    )
```

- [ ] **Step 4: Implement driver methods**

Create `external-drivers/context-nexus-py/src/agentenv_context_nexus/driver.py`:

```python
import os
import tempfile
import uuid
from dataclasses import dataclass

from agentenv_context_nexus import __version__
from agentenv_context_nexus.nexus import find_free_port, nexus_cli_available, parse_http_url, stable_hub_handle, start_lite_process
from agentenv_context_nexus.protocol import (
    ERROR_RESOURCE_NOT_FOUND,
    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
    JSON_RPC_INTERNAL_ERROR,
    JSON_RPC_INVALID_PARAMS,
    JSON_RPC_METHOD_NOT_FOUND,
    SCHEMA_VERSION,
    error,
    success,
)


@dataclass
class HandleState:
    mode: str
    endpoint_url: str
    zones: list[str]
    parsed_url: object | None = None
    process: object | None = None
    data_dir: str | None = None


class NexusContextDriver:
    def __init__(self):
        self._handles = {}
        self._workdir = tempfile.gettempdir()

    def handle(self, request):
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        try:
            if method == "initialize":
                return self._initialize(request_id, params)
            if method == "preflight":
                return self._preflight(request_id)
            if method == "provision":
                return self._provision(request_id, params)
            if method == "mcp_endpoint":
                return self._mcp_endpoint(request_id, params)
            if method == "required_network_rules":
                return self._required_network_rules(request_id, params)
            if method == "credential_requirements":
                return self._credential_requirements(request_id)
            if method == "status":
                return self._status(request_id, params)
            if method == "teardown":
                return self._teardown(request_id, params)
            if method == "shutdown":
                return self._shutdown(request_id)
            return error(request_id, JSON_RPC_METHOD_NOT_FOUND, f"method `{method}` not found")
        except ValueError as exc:
            return error(request_id, JSON_RPC_INVALID_PARAMS, str(exc))
        except Exception as exc:
            return error(request_id, JSON_RPC_INTERNAL_ERROR, str(exc))

    def _initialize(self, request_id, params):
        schema_version = str(params.get("schema_version", ""))
        if schema_version.split(".", 1)[0] != SCHEMA_VERSION.split(".", 1)[0]:
            return error(
                request_id,
                ERROR_SCHEMA_VERSION_INCOMPATIBLE,
                "driver and core major schema versions match is required",
            )
        self._workdir = params.get("workdir") or self._workdir
        return success(
            request_id,
            {
                "driver": {
                    "name": "nexus",
                    "kind": "context",
                    "version": __version__,
                    "protocol_version": SCHEMA_VERSION,
                },
                "capabilities": {
                    "is_remote": True,
                    "is_shared": True,
                    "supports_zones": True,
                    "supports_snapshots": True,
                },
            },
        )

    def _preflight(self, request_id):
        if nexus_cli_available():
            return success(request_id, {"ok": True, "issues": []})
        return success(
            request_id,
            {
                "ok": False,
                "issues": [
                    {
                        "severity": "error",
                        "code": "nexus_cli_missing",
                        "message": "Nexus CLI was not found in the driver environment",
                        "remediation": "Install the Nexus package into the context-nexus driver venv.",
                    }
                ],
            },
        )

    def _provision(self, request_id, params):
        config = params.get("config") or {}
        mode = config.get("mode", "lite")
        zones = config.get("zones") or []
        if not isinstance(zones, list) or not all(isinstance(zone, str) for zone in zones):
            raise ValueError("zones must be a list of strings")
        if mode == "hub":
            hub_url = config.get("hub_url")
            if not isinstance(hub_url, str) or not hub_url.strip():
                raise ValueError("hub_url is required in hub mode")
            parsed = parse_http_url(hub_url)
            handle = stable_hub_handle(parsed.url, zones)
            self._handles[handle] = HandleState("hub", parsed.url, zones, parsed_url=parsed)
            return success(request_id, {"handle": handle})
        if mode == "lite":
            data_dir = config.get("data_dir") or os.path.join(self._workdir, "nexus-data")
            port = int(config.get("mcp_port") or find_free_port())
            os.makedirs(data_dir, exist_ok=True)
            process = start_lite_process(data_dir, port)
            handle = f"nexus-lite-{uuid.uuid4().hex[:16]}"
            self._handles[handle] = HandleState(
                "lite",
                f"http://127.0.0.1:{port}",
                zones,
                process=process,
                data_dir=data_dir,
            )
            return success(request_id, {"handle": handle})
        raise ValueError("mode must be hub or lite")

    def _lookup(self, params):
        handle = params.get("handle")
        if handle not in self._handles:
            raise KeyError(handle)
        return handle, self._handles[handle]

    def _mcp_endpoint(self, request_id, params):
        try:
            _handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        return success(request_id, {"url": state.endpoint_url, "transport": "http", "headers": {}})

    def _required_network_rules(self, request_id, params):
        try:
            _handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        if state.mode == "lite":
            return success(request_id, {"rules": []})
        parsed = state.parsed_url
        return success(
            request_id,
            {
                "rules": [
                    {
                        "target": {
                            "kind": "host",
                            "host": parsed.host,
                            "port": parsed.port,
                            "scheme": parsed.scheme,
                        }
                    }
                ]
            },
        )

    def _credential_requirements(self, request_id):
        return success(
            request_id,
            {
                "requirements": [
                    {
                        "name": "NEXUS_TOKEN",
                        "description": "Nexus hub API token",
                        "kind": "token",
                        "required": False,
                    }
                ]
            },
        )

    def _status(self, request_id, params):
        try:
            _handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        if state.process is None:
            return success(request_id, {"healthy": True, "detail": "hub mode"})
        code = state.process.poll()
        if code is None:
            return success(request_id, {"healthy": True, "detail": "lite MCP process running"})
        return success(request_id, {"healthy": False, "detail": f"lite MCP process exited with {code}"})

    def _teardown(self, request_id, params):
        try:
            handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        if state.process is not None and state.process.poll() is None:
            state.process.terminate()
            state.process.wait(timeout=5)
        self._handles.pop(handle, None)
        return success(request_id, {})

    def _shutdown(self, request_id):
        for handle in list(self._handles):
            self._teardown(request_id, {"handle": handle})
        return success(request_id, {})
```

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
cd external-drivers/context-nexus-py
PYTHONPATH=src python3 -m pytest tests/test_driver_methods.py -q
```

Expected: PASS except lite-mode tests, which are added in the next task.

- [ ] **Step 6: Commit**

```bash
git add external-drivers/context-nexus-py/src/agentenv_context_nexus/driver.py external-drivers/context-nexus-py/src/agentenv_context_nexus/nexus.py external-drivers/context-nexus-py/tests/test_driver_methods.py
git commit -m "feat: implement nexus context driver methods"
```

## Task 6: Lite Mode Fake Nexus Fixture

**Files:**
- Create: `external-drivers/context-nexus-py/tests/fixtures/fake_nexus.py`
- Modify: `external-drivers/context-nexus-py/tests/test_driver_methods.py`

- [ ] **Step 1: Write failing lite mode test**

Append to `external-drivers/context-nexus-py/tests/test_driver_methods.py`:

```python
import os
import stat


def test_lite_mode_starts_fake_nexus_process(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_nexus = fake_bin / "nexus"
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "fake_nexus.py")
    fake_nexus.write_text(f"#!/bin/sh\nexec python3 {fixture} \"$@\"\n", encoding="utf-8")
    fake_nexus.chmod(fake_nexus.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ.get('PATH', '')}")

    driver = NexusContextDriver()
    driver.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"schema_version": "1.0", "workdir": str(tmp_path), "core_version": "0.0.1", "log_level": "info"}}
    )

    provision = call(driver, "provision", {"config": {"mode": "lite", "data_dir": str(tmp_path / "data")}})
    handle = provision["result"]["handle"]

    endpoint = call(driver, "mcp_endpoint", {"handle": handle})["result"]
    status = call(driver, "status", {"handle": handle})["result"]
    teardown = call(driver, "teardown", {"handle": handle})

    assert endpoint["url"].startswith("http://127.0.0.1:")
    assert status["healthy"] is True
    assert teardown["result"] == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd external-drivers/context-nexus-py
PYTHONPATH=src python3 -m pytest tests/test_driver_methods.py::test_lite_mode_starts_fake_nexus_process -q
```

Expected: FAIL because `tests/fixtures/fake_nexus.py` does not exist.

- [ ] **Step 3: Add fake Nexus fixture**

Create `external-drivers/context-nexus-py/tests/fixtures/fake_nexus.py`:

```python
import signal
import sys
import time


running = True


def stop(_signum, _frame):
    global running
    running = False


def main():
    if sys.argv[1:2] == ["--version"]:
        print("nexus 0.0.0-test")
        return 0
    if sys.argv[1:4] != ["mcp", "serve", "--transport"]:
        print(f"unexpected fake nexus args: {sys.argv[1:]}", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        time.sleep(0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cd external-drivers/context-nexus-py
PYTHONPATH=src python3 -m pytest tests -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add external-drivers/context-nexus-py/tests/test_driver_methods.py external-drivers/context-nexus-py/tests/fixtures/fake_nexus.py
git commit -m "test: cover nexus lite mode with fake cli"
```

## Task 7: Python Driver Manifest, README, and Installer Scripts

**Files:**
- Create: `external-drivers/context-nexus-py/README.md`
- Create: `external-drivers/context-nexus-py/manifest.json.in`
- Create: `external-drivers/context-nexus-py/scripts/install-driver.sh`
- Create: `external-drivers/context-nexus-py/scripts/build-bundle.sh`

- [ ] **Step 1: Write failing install smoke command**

Run:

```bash
cd external-drivers/context-nexus-py
AGENTENV_HOME="$(mktemp -d)/.agentenv" ./scripts/install-driver.sh
```

Expected: FAIL because `scripts/install-driver.sh` does not exist.

- [ ] **Step 2: Add manifest template**

Create `external-drivers/context-nexus-py/manifest.json.in`:

```json
{
  "schema_version": "1.0",
  "name": "nexus",
  "kind": "context",
  "version": "0.1.0",
  "description": "Nexus context backend driver",
  "binary": "./bin/agentenv-driver-nexus",
  "args": [],
  "env": {},
  "capabilities_preview": {
    "is_remote": true,
    "is_shared": true,
    "supports_zones": true,
    "supports_snapshots": true
  }
}
```

- [ ] **Step 3: Add install script**

Create `external-drivers/context-nexus-py/scripts/install-driver.sh`:

```sh
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
: "${HOME:?HOME must be set}"

AGENTENV_HOME="${AGENTENV_HOME:-$HOME/.agentenv}"
INSTALL_ROOT="${AGENTENV_HOME}/drivers/context-nexus"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-context-nexus.XXXXXX")

cleanup() {
    rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT INT TERM

python_bin="${PYTHON:-python3}"
staged="${TMP_ROOT}/context-nexus"
mkdir -p "${staged}/bin" "${staged}/wheels"

"${python_bin}" -m venv "${staged}/venv"
"${staged}/venv/bin/python" -m pip install --upgrade pip >/dev/null
"${staged}/venv/bin/python" -m pip install "${DRIVER_ROOT}" >/dev/null

cat > "${staged}/bin/agentenv-driver-nexus" <<'EOF'
#!/bin/sh
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
exec "${SCRIPT_DIR}/../venv/bin/python" -m agentenv_context_nexus "$@"
EOF
chmod +x "${staged}/bin/agentenv-driver-nexus"

cp "${DRIVER_ROOT}/manifest.json.in" "${staged}/manifest.json"
mkdir -p "$(dirname "${INSTALL_ROOT}")"
backup="${INSTALL_ROOT}.backup.$$"
rm -rf "${backup}"
if [ -e "${INSTALL_ROOT}" ]; then
    mv "${INSTALL_ROOT}" "${backup}"
fi
if mv "${staged}" "${INSTALL_ROOT}"; then
    rm -rf "${backup}"
else
    rm -rf "${INSTALL_ROOT}"
    if [ -e "${backup}" ]; then
        mv "${backup}" "${INSTALL_ROOT}"
    fi
    exit 1
fi
printf '%s\n' "${INSTALL_ROOT}"
```

- [ ] **Step 4: Add bundle script**

Create `external-drivers/context-nexus-py/scripts/build-bundle.sh`:

```sh
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
OUT_DIR="${1:-${DRIVER_ROOT}/dist}"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-context-nexus-bundle.XXXXXX")

cleanup() {
    rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT INT TERM

mkdir -p "${OUT_DIR}" "${TMP_ROOT}/context-nexus"
cp -R "${DRIVER_ROOT}/pyproject.toml" "${DRIVER_ROOT}/README.md" "${DRIVER_ROOT}/manifest.json.in" "${DRIVER_ROOT}/src" "${DRIVER_ROOT}/scripts" "${TMP_ROOT}/context-nexus/"
(cd "${TMP_ROOT}" && tar -czf "${OUT_DIR}/context-nexus.tar.gz" context-nexus)
printf '%s\n' "${OUT_DIR}/context-nexus.tar.gz"
```

Mark both scripts executable:

```bash
chmod +x external-drivers/context-nexus-py/scripts/install-driver.sh external-drivers/context-nexus-py/scripts/build-bundle.sh
```

- [ ] **Step 5: Add README**

Create `external-drivers/context-nexus-py/README.md`:

```markdown
# context-nexus-py

Python subprocess context driver for agentenv. The installed driver is named
`nexus` and implements the context driver JSON-RPC protocol over stdio.

## Modes

Hub mode validates `hub_url`, declares `NEXUS_TOKEN`, and returns an HTTP MCP
endpoint for the Nexus hub.

Lite mode starts `nexus mcp serve --transport http` against a local data
directory and returns the loopback MCP endpoint.

## Local Install

```bash
AGENTENV_HOME="$HOME/.agentenv" ./scripts/install-driver.sh
agentenv drivers list
```

## Tests

```bash
PYTHONPATH=src python3 -m pytest tests -q
```
```

- [ ] **Step 6: Run install smoke command**

Run:

```bash
tmp_home=$(mktemp -d)
cd external-drivers/context-nexus-py
AGENTENV_HOME="${tmp_home}/.agentenv" ./scripts/install-driver.sh
test -x "${tmp_home}/.agentenv/drivers/context-nexus/bin/agentenv-driver-nexus"
test -f "${tmp_home}/.agentenv/drivers/context-nexus/manifest.json"
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add external-drivers/context-nexus-py/README.md external-drivers/context-nexus-py/manifest.json.in external-drivers/context-nexus-py/scripts
git commit -m "feat: package context nexus python driver"
```

## Task 8: Driver Conformance for Context Subprocesses

**Files:**
- Modify: `tests/driver-conformance/src/lib.rs`
- Modify: `tests/driver-conformance/src/main.rs`

- [ ] **Step 1: Write failing context conformance helper test**

Append a unit test to `tests/driver-conformance/src/lib.rs`:

```rust
#[test]
fn context_conformance_hub_spec_contains_required_config() {
    let spec = nexus_hub_conformance_spec();

    assert_eq!(spec.config["mode"], serde_json::json!("hub"));
    assert_eq!(spec.config["hub_url"], serde_json::json!("https://nexus.example.test"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p driver-conformance context_conformance_hub_spec_contains_required_config
```

Expected: FAIL because `nexus_hub_conformance_spec` does not exist.

- [ ] **Step 3: Add context conformance helpers**

Add imports near the top of `tests/driver-conformance/src/lib.rs`:

```rust
use agentenv_proto::{
    ContextHandleRequest, ContextSpec, CredentialRequirementsParams, McpTransport, NetworkTarget,
};
```

Add these functions:

```rust
pub fn nexus_hub_conformance_spec() -> ContextSpec {
    let mut config = std::collections::BTreeMap::new();
    config.insert("mode".to_owned(), serde_json::json!("hub"));
    config.insert(
        "hub_url".to_owned(),
        serde_json::json!("https://nexus.example.test"),
    );
    config.insert("zones".to_owned(), serde_json::json!(["eng"]));
    ContextSpec { config }
}

pub fn run_context_suite(driver_path: &Path) -> Result<()> {
    let mut client = RpcClient::spawn(driver_path)?;
    let initialize_result: InitializeResult = client.call_success(
        1,
        "initialize",
        &InitializeParams {
            schema_version: SCHEMA_VERSION.to_owned(),
            core_version: "0.0.1".to_owned(),
            workdir: "/tmp/agentenv".to_owned(),
            log_level: agentenv_proto::LogLevel::Info,
        },
    )?;

    assert_compatible_schema_version(&initialize_result.driver.protocol_version)
        .context("initialize result must report a compatible protocol version")?;
    if initialize_result.driver.kind != DriverKind::Context {
        bail!("initialize must report DriverKind::Context");
    }
    if !matches!(initialize_result.capabilities, Capabilities::Context(_)) {
        bail!("initialize must report context capabilities");
    }

    let credentials: agentenv_proto::CredentialRequirementsResult =
        client.call_success(2, "credential_requirements", &CredentialRequirementsParams {})?;
    if !credentials
        .requirements
        .iter()
        .any(|requirement| requirement.name == "NEXUS_TOKEN")
    {
        bail!("context driver must declare NEXUS_TOKEN");
    }

    let handle: agentenv_proto::ContextHandle =
        client.call_success(3, "provision", &nexus_hub_conformance_spec())?;
    let endpoint: agentenv_proto::McpEndpoint = client.call_success(
        4,
        "mcp_endpoint",
        &ContextHandleRequest {
            handle: handle.handle.clone(),
        },
    )?;
    if endpoint.transport != McpTransport::Http {
        bail!("nexus context endpoint must use HTTP transport");
    }

    let rules: agentenv_proto::RequiredNetworkRulesResult = client.call_success(
        5,
        "required_network_rules",
        &ContextHandleRequest {
            handle: handle.handle.clone(),
        },
    )?;
    if !rules.rules.iter().any(|rule| {
        matches!(
            &rule.target,
            NetworkTarget::Host { host, .. } if host == "nexus.example.test"
        )
    }) {
        bail!("hub mode must emit a network rule for nexus.example.test");
    }

    let status: agentenv_proto::ContextStatus = client.call_success(
        6,
        "status",
        &ContextHandleRequest {
            handle: handle.handle.clone(),
        },
    )?;
    if !status.healthy {
        bail!("context status must be healthy after hub provision");
    }

    let _: EmptyResult = client.call_success(
        7,
        "teardown",
        &ContextHandleRequest {
            handle: handle.handle,
        },
    )?;
    let _: EmptyResult = client.call_success(8, "shutdown", &agentenv_proto::ShutdownParams {})?;
    let status = client.wait_for_exit()?;
    if !status.success() {
        bail!("driver exited with status {status}");
    }
    Ok(())
}
```

- [ ] **Step 4: Add CLI mode**

Modify `tests/driver-conformance/src/main.rs`:

```rust
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().context("usage: driver-conformance [--context] <driver-path>")?;
    if first == "--context" {
        let driver_path = args
            .next()
            .map(PathBuf::from)
            .context("usage: driver-conformance --context <driver-path>")?;
        driver_conformance::run_context_suite(&driver_path)?;
        driver_conformance::run_schema_mismatch_suite(&driver_path)?;
        return Ok(());
    }

    let driver_path = PathBuf::from(first);
    driver_conformance::run_standard_suite(&driver_path)?;
    driver_conformance::run_schema_mismatch_suite(&driver_path)?;
    Ok(())
}
```

- [ ] **Step 5: Run conformance tests**

Run:

```bash
cargo test -p driver-conformance context_conformance_hub_spec_contains_required_config
cargo run -p driver-conformance -- --context external-drivers/context-nexus-py/.venv/bin/agentenv-driver-nexus
```

If no venv exists, use:

```bash
cd external-drivers/context-nexus-py
python3 -m venv .venv
.venv/bin/python -m pip install .
cd ../..
cargo run -p driver-conformance -- --context external-drivers/context-nexus-py/.venv/bin/agentenv-driver-nexus
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add tests/driver-conformance/src/lib.rs tests/driver-conformance/src/main.rs
git commit -m "test: add context subprocess conformance suite"
```

## Task 9: Top-Level Installer Coverage

**Files:**
- Modify: `install.sh`
- Modify: `tests/install/test_install.sh`

- [ ] **Step 1: Write failing installer test for context-nexus bundle layout**

Append to `tests/install/test_install.sh` before `main()`:

```sh
test_install_python_drivers_installs_context_nexus_bundle() {
    tmp_root=$(mktemp -d)

    mkdir -p "${tmp_root}/bundle/context-nexus/bin" "${tmp_root}/bundle/context-nexus/venv"
    printf '{"name":"nexus","kind":"context"}\n' > "${tmp_root}/bundle/context-nexus/manifest.json"
    printf '#!/bin/sh\n' > "${tmp_root}/bundle/context-nexus/bin/agentenv-driver-nexus"
    chmod +x "${tmp_root}/bundle/context-nexus/bin/agentenv-driver-nexus"
    (cd "${tmp_root}/bundle" && tar -czf "${tmp_root}/context-nexus.tar.gz" context-nexus)

    expected_hash=$(sha256_file "${tmp_root}/context-nexus.tar.gz")
    printf 'context-nexus|file://%s/context-nexus.tar.gz|%s\n' "${tmp_root}" "${expected_hash}" > "${tmp_root}/drivers.index"

    TMP_ROOT="${tmp_root}/tmp"
    mkdir -p "${TMP_ROOT}"
    AGENTENV_HOME="${tmp_root}/home/.agentenv"
    WITH_PYTHON_DRIVERS=1
    PYTHON_DRIVERS_INDEX_URL="file://${tmp_root}/drivers.index"

    install_python_drivers

    test -f "${AGENTENV_HOME}/drivers/context-nexus/manifest.json" || fail "context-nexus manifest missing"
    test -x "${AGENTENV_HOME}/drivers/context-nexus/bin/agentenv-driver-nexus" || fail "context-nexus launcher missing"
    assert_eq "installed 1 bundle(s)" "${PYTHON_DRIVER_STATUS}" "python driver install status"

    rm -rf "${tmp_root}"
    pass
}
```

Add the call in `main()`:

```sh
test_install_python_drivers_installs_context_nexus_bundle
```

- [ ] **Step 2: Run test to verify existing behavior**

Run:

```bash
sh tests/install/test_install.sh
```

Expected: PASS or FAIL. If it passes, keep the test and do not modify `install.sh` for this task. If it fails because the tarball contains a single top-level `context-nexus/` directory, proceed to Step 3.

- [ ] **Step 3: Support single-root driver bundle extraction**

Modify `install_python_drivers` in `install.sh` after tar extraction:

```sh
        tar -xzf "${archive_path}" -C "${staged_driver_dir}" || die "Could not extract Python driver bundle for ${driver_name}"
        if [ ! -f "${staged_driver_dir}/manifest.json" ] && [ -f "${staged_driver_dir}/${driver_name}/manifest.json" ]; then
            inner_dir="${staged_driver_dir}/${driver_name}"
            flattened_dir="${TMP_ROOT}/${driver_name}.flattened"
            rm -rf "${flattened_dir}"
            mv "${inner_dir}" "${flattened_dir}"
            rm -rf "${staged_driver_dir}"
            mv "${flattened_dir}" "${staged_driver_dir}"
        fi
        [ -f "${staged_driver_dir}/manifest.json" ] || die "Python driver ${driver_name} did not contain manifest.json"
```

- [ ] **Step 4: Run installer tests**

Run:

```bash
sh tests/install/test_install.sh
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add install.sh tests/install/test_install.sh
git commit -m "test: cover context nexus python driver bundle install"
```

## Task 10: Documentation and Protocol Notes

**Files:**
- Modify: `docs/DRIVER_PROTOCOL.md`
- Modify: `blueprints/openclaw+nexus+openshell.yaml`
- Modify: `blueprints/hermes+nexus+openshell.yaml`

- [ ] **Step 1: Write documentation diff**

Update `docs/DRIVER_PROTOCOL.md` under the `ContextDriver` section with:

```markdown
For subprocess context drivers, the core sends the same method names over
JSON-RPC. Credentials are declared through `credential_requirements` and are not
included in generic method params. Driver-specific launchers receive credentials
only through their process environment when the lifecycle layer injects them.
```

Update the Nexus reference blueprints by adding an explicit comment under
`context.driver: nexus`:

```yaml
  # External subprocess driver installed at ~/.agentenv/drivers/context-nexus/.
```

- [ ] **Step 2: Verify docs contain the intended text**

Run:

```bash
rg -n "subprocess context drivers|context-nexus" docs/DRIVER_PROTOCOL.md blueprints/openclaw+nexus+openshell.yaml blueprints/hermes+nexus+openshell.yaml
```

Expected: output includes all three files.

- [ ] **Step 3: Commit**

```bash
git add docs/DRIVER_PROTOCOL.md blueprints/openclaw+nexus+openshell.yaml blueprints/hermes+nexus+openshell.yaml
git commit -m "docs: document nexus subprocess context driver"
```

## Task 11: Final Verification

**Files:**
- No source edits expected.

- [ ] **Step 1: Run Python tests**

Run:

```bash
cd external-drivers/context-nexus-py
PYTHONPATH=src python3 -m pytest tests -q
```

Expected: PASS.

- [ ] **Step 2: Run Python package install smoke test**

Run:

```bash
tmp_home=$(mktemp -d)
cd external-drivers/context-nexus-py
AGENTENV_HOME="${tmp_home}/.agentenv" ./scripts/install-driver.sh
"${tmp_home}/.agentenv/drivers/context-nexus/bin/agentenv-driver-nexus" </dev/null >/tmp/context-nexus-driver.out
test -f "${tmp_home}/.agentenv/drivers/context-nexus/manifest.json"
```

Expected: PASS. The launcher may exit immediately on EOF.

- [ ] **Step 3: Run context conformance**

Run:

```bash
cd external-drivers/context-nexus-py
python3 -m venv .venv
.venv/bin/python -m pip install .
cd ../..
cargo run -p driver-conformance -- --context external-drivers/context-nexus-py/.venv/bin/agentenv-driver-nexus
```

Expected: PASS.

- [ ] **Step 4: Run Rust tests**

Run:

```bash
cargo test -p agentenv-plugin
cargo test -p driver-conformance
cargo test -p agentenv --test cli_behavior drivers_list_includes_override_manifest
```

Expected: PASS.

- [ ] **Step 5: Run installer tests**

Run:

```bash
sh tests/install/test_install.sh
```

Expected: PASS.

- [ ] **Step 6: Run workspace formatting, clippy, and tests**

Run:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 7: Inspect git status**

Run:

```bash
git status --short
```

Expected: only intentional files are modified or untracked.

- [ ] **Step 8: Commit any final verification fixes**

If verification required small fixes, commit them:

```bash
git add <fixed-files>
git commit -m "fix: verify context nexus python driver"
```

Expected: commit created only when fixes were needed.
