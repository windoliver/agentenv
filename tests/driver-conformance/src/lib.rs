use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

use agentenv_proto::{
    assert_compatible_schema_version, schema_version_major, Capabilities, DriverKind, EmptyResult,
    InitializeParams, InitializeResult, PreflightParams, PreflightResult,
    ERROR_SCHEMA_VERSION_INCOMPATIBLE, JSON_RPC_METHOD_NOT_FOUND, SCHEMA_VERSION,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcRequestEnvelope {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcError {
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
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcNotificationEnvelope {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

pub fn write_framed_json<W: Write, T: Serialize>(writer: &mut W, message: &T) -> Result<()> {
    let payload = serde_json::to_vec(message).context("serialize framed JSON-RPC message")?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())
        .context("write JSON-RPC headers")?;
    writer
        .write_all(&payload)
        .context("write JSON-RPC payload")?;
    writer.flush().context("flush JSON-RPC writer")?;
    Ok(())
}

pub fn read_framed_json<R: BufRead>(reader: &mut R) -> Result<Value> {
    let mut content_length = None;

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .context("read JSON-RPC header line")?;
        if read == 0 {
            bail!("unexpected EOF while reading JSON-RPC headers");
        }

        if line == "\r\n" {
            break;
        }

        if let Some(value) = line.strip_prefix("Content-Length: ") {
            let raw = value.trim();
            content_length = Some(
                raw.parse::<usize>()
                    .with_context(|| format!("parse Content-Length header `{raw}`"))?,
            );
        }
    }

    let content_length = content_length.ok_or_else(|| anyhow!("missing Content-Length header"))?;
    let mut payload = vec![0_u8; content_length];
    reader
        .read_exact(&mut payload)
        .context("read JSON-RPC payload")?;

    serde_json::from_slice(&payload).context("decode JSON-RPC payload")
}

pub struct RpcClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl RpcClient {
    pub fn spawn(driver_path: &Path) -> Result<Self> {
        let mut child = Command::new(driver_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("spawn driver `{}`", driver_path.display()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("driver stdin pipe was not available"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("driver stdout pipe was not available"))?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    pub fn call_success<P, R>(&mut self, id: u64, method: &str, params: &P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let response = self.call(id, method, params)?;
        if let Some(error) = response.error {
            bail!(
                "unexpected JSON-RPC error {}: {}",
                error.code,
                error.message
            );
        }

        serde_json::from_value(
            response
                .result
                .ok_or_else(|| anyhow!("missing JSON-RPC result for `{method}`"))?,
        )
        .with_context(|| format!("decode JSON-RPC result for `{method}`"))
    }

    pub fn call_error<P>(&mut self, id: u64, method: &str, params: &P) -> Result<RpcError>
    where
        P: Serialize,
    {
        let response = self.call(id, method, params)?;
        response
            .error
            .ok_or_else(|| anyhow!("expected JSON-RPC error for `{method}`"))
    }

    pub fn wait_for_exit(&mut self) -> Result<ExitStatus> {
        self.child.wait().context("wait for driver to exit")
    }

    fn call<P>(&mut self, id: u64, method: &str, params: &P) -> Result<RpcResponseEnvelope>
    where
        P: Serialize,
    {
        let expected_id = json!(id);
        let request = json!({
            "jsonrpc": "2.0",
            "id": expected_id,
            "method": method,
            "params": params,
        });

        write_framed_json(&mut self.stdin, &request)?;
        read_response_envelope(&mut self.stdout, &request["id"])
    }
}

impl Drop for RpcClient {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn read_response_envelope<R: BufRead>(
    reader: &mut R,
    expected_id: &Value,
) -> Result<RpcResponseEnvelope> {
    loop {
        let raw = read_framed_json(reader)?;

        if raw.get("method").is_some() && raw.get("id").is_none() {
            let notification: RpcNotificationEnvelope =
                serde_json::from_value(raw).context("decode JSON-RPC notification envelope")?;
            if notification.jsonrpc != "2.0" {
                bail!(
                    "received JSON-RPC notification with unsupported version `{}`",
                    notification.jsonrpc
                );
            }
            continue;
        }

        let response: RpcResponseEnvelope =
            serde_json::from_value(raw).context("decode JSON-RPC response envelope")?;
        if response.jsonrpc != "2.0" {
            bail!(
                "received JSON-RPC response with unsupported version `{}`",
                response.jsonrpc
            );
        }
        if response.id != *expected_id {
            let actual = serde_json::to_string(&response.id).context("encode response id")?;
            let expected = serde_json::to_string(expected_id).context("encode request id")?;
            bail!("received JSON-RPC response id {actual} while waiting for request id {expected}");
        }

        return Ok(response);
    }
}

pub fn run_standard_suite(driver_path: &Path) -> Result<()> {
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

    let preflight: PreflightResult =
        client.call_success(2, "preflight", &PreflightParams::default())?;
    if !preflight.ok {
        bail!("preflight returned `ok = false` unexpectedly");
    }

    let unknown_method = client.call_error(3, "driver/unknown", &json!({}))?;
    if unknown_method.code != JSON_RPC_METHOD_NOT_FOUND {
        bail!(
            "unknown method returned {}, expected {}",
            unknown_method.code,
            JSON_RPC_METHOD_NOT_FOUND
        );
    }

    let _: EmptyResult = client.call_success(4, "shutdown", &agentenv_proto::ShutdownParams {})?;
    let status = client.wait_for_exit()?;
    if !status.success() {
        bail!("driver exited with status {status}");
    }

    Ok(())
}

pub async fn assert_agent_driver_contract<D: agentenv_core::driver::AgentDriver>(
    driver: &mut D,
    spec: agentenv_proto::AgentSpec,
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
        init.driver.kind == DriverKind::Agent,
        "initialize must report DriverKind::Agent"
    );
    anyhow::ensure!(
        matches!(init.capabilities, Capabilities::Agent(_)),
        "initialize must report Capabilities::Agent"
    );

    let preflight = driver
        .preflight(agentenv_proto::PreflightParams::default())
        .await?;
    anyhow::ensure!(preflight.ok, "preflight must pass");

    let credentials = driver.credential_requirements(spec.clone()).await?;
    anyhow::ensure!(
        credentials
            .requirements
            .iter()
            .all(|requirement| !requirement.name.trim().is_empty()),
        "credential name must not be empty"
    );

    let probe = driver.health_check_probe(spec).await?;
    anyhow::ensure!(
        !probe.cmd.trim().is_empty(),
        "health probe command must not be empty"
    );
    anyhow::ensure!(
        !probe.success_exit_codes.is_empty(),
        "health probe must declare at least one success exit code"
    );

    Ok(())
}

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
    anyhow::ensure!(
        matches!(init.capabilities, Capabilities::Sandbox(_)),
        "initialize must report Capabilities::Sandbox"
    );

    let Capabilities::Sandbox(capabilities) = &init.capabilities else {
        unreachable!("capabilities shape was already validated")
    };
    anyhow::ensure!(
        capabilities.supports_hot_reload_policy,
        "initialize must report supports_hot_reload_policy = true"
    );

    let preflight = driver
        .preflight(agentenv_proto::PreflightParams::default())
        .await?;
    anyhow::ensure!(preflight.ok, "preflight must pass");

    Ok(())
}

pub fn run_schema_mismatch_suite(driver_path: &Path) -> Result<()> {
    let mismatched_schema_version = format!(
        "{}.0",
        schema_version_major(SCHEMA_VERSION).expect("schema version should parse") + 1
    );
    let mut client = RpcClient::spawn(driver_path)?;
    let error = client.call_error(
        1,
        "initialize",
        &InitializeParams {
            schema_version: mismatched_schema_version,
            core_version: "0.0.1".to_owned(),
            workdir: "/tmp/agentenv".to_owned(),
            log_level: agentenv_proto::LogLevel::Info,
        },
    )?;

    if error.code != ERROR_SCHEMA_VERSION_INCOMPATIBLE {
        bail!(
            "schema mismatch returned {}, expected {}",
            error.code,
            ERROR_SCHEMA_VERSION_INCOMPATIBLE
        );
    }

    if !error.message.contains("major schema versions match") {
        bail!("schema mismatch error did not include a remediation hint");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufReader, Cursor};
    use std::sync::Mutex;

    use agentenv_core::driver::{AgentDriver, DriverResult, SandboxDriver};
    use agentenv_proto::{
        AgentCapabilities, AgentHealthCheckProbe, AgentSpec, Capabilities, CredentialKind,
        CredentialRequirement, CredentialRequirementsResult, DriverInfo, DriverKind, EmptyResult,
        InitializeParams, InitializeResult, InstallStepsResult, McpConfigPathParams,
        McpConfigPathResult, PreflightParams, PreflightResult, RenderEntrypointResult,
        RenderMcpConfigParams, RenderMcpConfigResult, SandboxCapabilities, ShutdownParams,
        SCHEMA_VERSION,
    };
    use async_trait::async_trait;

    use super::{
        assert_agent_driver_contract, assert_sandbox_driver_contract, read_response_envelope,
        write_framed_json,
    };
    use serde_json::json;

    #[test]
    fn response_reader_skips_notifications() {
        let mut payload = Vec::new();
        write_framed_json(
            &mut payload,
            &json!({
                "jsonrpc": "2.0",
                "method": "event/log",
                "params": {
                    "level": "info",
                    "ts": "2026-04-17T00:00:00Z",
                    "msg": "notification",
                    "kv": {}
                }
            }),
        )
        .expect("serialize notification");
        write_framed_json(
            &mut payload,
            &json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": {
                    "ok": true,
                    "issues": []
                }
            }),
        )
        .expect("serialize response");

        let mut reader = BufReader::new(Cursor::new(payload));
        let response =
            read_response_envelope(&mut reader, &json!(7)).expect("notification should be skipped");

        assert_eq!(response.id, json!(7));
    }

    #[test]
    fn response_reader_rejects_wrong_response_id() {
        let mut payload = Vec::new();
        write_framed_json(
            &mut payload,
            &json!({
                "jsonrpc": "2.0",
                "id": 99,
                "result": {
                    "ok": true,
                    "issues": []
                }
            }),
        )
        .expect("serialize mismatched response");

        let mut reader = BufReader::new(Cursor::new(payload));
        let err =
            read_response_envelope(&mut reader, &json!(7)).expect_err("mismatched ids should fail");

        assert!(err.to_string().contains("request id 7"));
    }

    #[test]
    fn response_reader_rejects_unsupported_jsonrpc_version() {
        let mut payload = Vec::new();
        write_framed_json(
            &mut payload,
            &json!({
                "jsonrpc": "1.0",
                "id": 7,
                "result": {
                    "ok": true,
                    "issues": []
                }
            }),
        )
        .expect("serialize unsupported jsonrpc response");

        let mut reader = BufReader::new(Cursor::new(payload));
        let err = read_response_envelope(&mut reader, &json!(7))
            .expect_err("unsupported jsonrpc versions should fail");

        assert!(err.to_string().contains("unsupported version `1.0`"));
    }

    #[derive(Default)]
    struct FakeAgentDriver {
        calls: Mutex<FakeAgentDriverCalls>,
        init_kind: Option<DriverKind>,
        init_capabilities: Option<Capabilities>,
        credential_name: Option<String>,
        health_cmd: Option<String>,
        health_success_exit_codes: Option<Vec<i32>>,
    }

    #[derive(Default)]
    struct FakeAgentDriverCalls {
        initialized: bool,
        preflight_checked: bool,
        credential_requirements_checked: bool,
        health_probe_checked: bool,
    }

    #[async_trait]
    impl AgentDriver for FakeAgentDriver {
        async fn initialize(
            &mut self,
            _params: InitializeParams,
        ) -> DriverResult<InitializeResult> {
            self.calls.lock().unwrap().initialized = true;

            Ok(InitializeResult {
                driver: DriverInfo {
                    name: "fake-agent".to_owned(),
                    kind: self.init_kind.clone().unwrap_or(DriverKind::Agent),
                    version: "0.0.1".to_owned(),
                    protocol_version: SCHEMA_VERSION.to_owned(),
                },
                capabilities: self.init_capabilities.clone().unwrap_or_else(|| {
                    Capabilities::Agent(AgentCapabilities {
                        supports_mcp: true,
                        supports_slash_commands: false,
                        supports_tui: true,
                        supports_headless: true,
                    })
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            self.calls.lock().unwrap().preflight_checked = true;

            Ok(PreflightResult {
                ok: true,
                issues: Vec::new(),
            })
        }

        async fn install_steps(&self, _spec: AgentSpec) -> DriverResult<InstallStepsResult> {
            Ok(InstallStepsResult { steps: Vec::new() })
        }

        async fn mcp_config_path(
            &self,
            _params: McpConfigPathParams,
        ) -> DriverResult<McpConfigPathResult> {
            Ok(McpConfigPathResult {
                path: "/tmp/mcp.json".to_owned(),
            })
        }

        async fn render_mcp_config(
            &self,
            _params: RenderMcpConfigParams,
        ) -> DriverResult<RenderMcpConfigResult> {
            Ok(RenderMcpConfigResult {
                content: "{}".to_owned(),
            })
        }

        async fn render_entrypoint(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<RenderEntrypointResult> {
            Ok(RenderEntrypointResult {
                content: "exec fake-agent".to_owned(),
            })
        }

        async fn credential_requirements(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<CredentialRequirementsResult> {
            self.calls.lock().unwrap().credential_requirements_checked = true;

            Ok(CredentialRequirementsResult {
                requirements: self
                    .credential_name
                    .clone()
                    .map(|name| {
                        vec![CredentialRequirement {
                            name,
                            kind: CredentialKind::ApiKey,
                            required: true,
                            description: "Fake credential.".to_owned(),
                            validator: None,
                        }]
                    })
                    .unwrap_or_default(),
            })
        }

        async fn health_check_probe(
            &self,
            _spec: AgentSpec,
        ) -> DriverResult<AgentHealthCheckProbe> {
            self.calls.lock().unwrap().health_probe_checked = true;

            Ok(AgentHealthCheckProbe {
                cmd: self
                    .health_cmd
                    .clone()
                    .unwrap_or_else(|| "fake-agent --version".to_owned()),
                tty: false,
                env: BTreeMap::new(),
                success_exit_codes: self
                    .health_success_exit_codes
                    .clone()
                    .unwrap_or_else(|| vec![0]),
            })
        }

        async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }
    }

    #[tokio::test]
    async fn agent_driver_contract_exercises_lifecycle_checks() {
        let mut driver = FakeAgentDriver::default();

        assert_agent_driver_contract(
            &mut driver,
            AgentSpec {
                version: None,
                config: BTreeMap::new(),
            },
        )
        .await
        .expect("fake agent should satisfy the in-process conformance contract");

        let calls = driver.calls.lock().unwrap();
        assert!(calls.initialized);
        assert!(calls.preflight_checked);
        assert!(calls.credential_requirements_checked);
        assert!(calls.health_probe_checked);
    }

    #[tokio::test]
    async fn agent_driver_contract_rejects_non_agent_initialize_kind() {
        let mut driver = FakeAgentDriver {
            init_kind: Some(DriverKind::Sandbox),
            ..FakeAgentDriver::default()
        };

        let err = assert_agent_driver_contract(
            &mut driver,
            AgentSpec {
                version: None,
                config: BTreeMap::new(),
            },
        )
        .await
        .expect_err("agent conformance should reject non-agent driver kinds");

        assert!(err.to_string().contains("DriverKind::Agent"));
    }

    #[tokio::test]
    async fn agent_driver_contract_rejects_non_agent_capabilities() {
        let mut driver = FakeAgentDriver {
            init_capabilities: Some(Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: false,
                supports_filesystem_lockdown: false,
                supports_syscall_filter: false,
                supports_native_inference_routing: false,
                supports_remote_host: false,
            })),
            ..FakeAgentDriver::default()
        };

        let err = assert_agent_driver_contract(
            &mut driver,
            AgentSpec {
                version: None,
                config: BTreeMap::new(),
            },
        )
        .await
        .expect_err("agent conformance should reject non-agent capability shapes");

        assert!(err.to_string().contains("Capabilities::Agent"));
    }

    #[tokio::test]
    async fn agent_driver_contract_rejects_empty_credential_names() {
        let mut driver = FakeAgentDriver {
            credential_name: Some(String::new()),
            ..FakeAgentDriver::default()
        };

        let err = assert_agent_driver_contract(
            &mut driver,
            AgentSpec {
                version: None,
                config: BTreeMap::new(),
            },
        )
        .await
        .expect_err("agent conformance should reject empty credential names");

        assert!(err.to_string().contains("credential name"));
    }

    #[tokio::test]
    async fn agent_driver_contract_rejects_empty_health_probe_cmd() {
        let mut driver = FakeAgentDriver {
            health_cmd: Some(String::new()),
            ..FakeAgentDriver::default()
        };

        let err = assert_agent_driver_contract(
            &mut driver,
            AgentSpec {
                version: None,
                config: BTreeMap::new(),
            },
        )
        .await
        .expect_err("agent conformance should reject empty health probe commands");

        assert!(err.to_string().contains("health probe command"));
    }

    #[tokio::test]
    async fn agent_driver_contract_rejects_empty_health_probe_success_codes() {
        let mut driver = FakeAgentDriver {
            health_success_exit_codes: Some(Vec::new()),
            ..FakeAgentDriver::default()
        };

        let err = assert_agent_driver_contract(
            &mut driver,
            AgentSpec {
                version: None,
                config: BTreeMap::new(),
            },
        )
        .await
        .expect_err("agent conformance should reject empty health probe success codes");

        assert!(err.to_string().contains("success exit code"));
    }

    struct FakeSandboxDriver {
        calls: Mutex<FakeSandboxDriverCalls>,
        init_kind: Option<DriverKind>,
        init_capabilities: Option<Capabilities>,
        preflight_ok: bool,
    }

    #[derive(Default)]
    struct FakeSandboxDriverCalls {
        initialized: bool,
        preflight_checked: bool,
    }

    impl Default for FakeSandboxDriver {
        fn default() -> Self {
            Self {
                calls: Mutex::new(FakeSandboxDriverCalls::default()),
                init_kind: None,
                init_capabilities: None,
                preflight_ok: true,
            }
        }
    }

    #[async_trait]
    impl SandboxDriver for FakeSandboxDriver {
        async fn initialize(
            &mut self,
            _params: InitializeParams,
        ) -> DriverResult<InitializeResult> {
            self.calls.lock().unwrap().initialized = true;

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
                        supports_remote_host: false,
                    })
                }),
            })
        }

        async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
            self.calls.lock().unwrap().preflight_checked = true;

            Ok(PreflightResult {
                ok: self.preflight_ok,
                issues: Vec::new(),
            })
        }

        async fn create(
            &self,
            _spec: agentenv_proto::SandboxSpec,
        ) -> DriverResult<agentenv_proto::SandboxHandle> {
            Ok(agentenv_proto::SandboxHandle {
                handle: "fake-sandbox".to_owned(),
            })
        }

        async fn connect(
            &self,
            _params: agentenv_proto::ConnectParams,
        ) -> DriverResult<agentenv_proto::ShellHandle> {
            Ok(agentenv_proto::ShellHandle {
                session_id: "fake-session".to_owned(),
                tty: true,
                working_dir: Some("/tmp".to_owned()),
            })
        }

        async fn exec(
            &self,
            _params: agentenv_proto::ExecParams,
        ) -> DriverResult<agentenv_proto::ExecResult> {
            Ok(agentenv_proto::ExecResult {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }

        async fn copy_in(
            &self,
            _params: agentenv_proto::CopyInParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn copy_out(
            &self,
            _params: agentenv_proto::CopyOutParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn apply_policy(
            &self,
            _params: agentenv_proto::ApplyPolicyParams,
        ) -> DriverResult<agentenv_proto::ApplyPolicyResult> {
            Ok(agentenv_proto::ApplyPolicyResult { hot_reloaded: true })
        }

        async fn status(
            &self,
            _params: agentenv_proto::SandboxStatusParams,
        ) -> DriverResult<agentenv_proto::SandboxStatus> {
            Ok(agentenv_proto::SandboxStatus {
                phase: agentenv_proto::SandboxPhase::Running,
                healthy: true,
                last_ping: None,
            })
        }

        async fn logs(
            &self,
            _params: agentenv_proto::LogsParams,
        ) -> DriverResult<agentenv_proto::LogsResult> {
            Ok(agentenv_proto::LogsResult {
                entries: Vec::new(),
            })
        }

        async fn logs_stream(
            &self,
            _params: agentenv_proto::LogsStreamParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn stop(&self, _params: agentenv_proto::StopParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn destroy(
            &self,
            _params: agentenv_proto::DestroyParams,
        ) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }

        async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
            Ok(EmptyResult::default())
        }
    }

    #[tokio::test]
    async fn sandbox_driver_contract_accepts_sandbox_capabilities() {
        let mut driver = FakeSandboxDriver::default();

        assert_sandbox_driver_contract(&mut driver)
            .await
            .expect("fake sandbox should satisfy the in-process conformance contract");

        let calls = driver.calls.lock().unwrap();
        assert!(calls.initialized);
        assert!(calls.preflight_checked);
    }

    #[tokio::test]
    async fn sandbox_driver_contract_rejects_non_sandbox_kind() {
        let mut driver = FakeSandboxDriver {
            init_kind: Some(DriverKind::Agent),
            ..FakeSandboxDriver::default()
        };

        let err = assert_sandbox_driver_contract(&mut driver)
            .await
            .expect_err("sandbox conformance should reject non-sandbox driver kinds");

        assert!(err.to_string().contains("DriverKind::Sandbox"));
    }

    #[tokio::test]
    async fn sandbox_driver_contract_rejects_non_sandbox_capabilities() {
        let mut driver = FakeSandboxDriver {
            init_capabilities: Some(Capabilities::Agent(AgentCapabilities {
                supports_mcp: true,
                supports_slash_commands: false,
                supports_tui: true,
                supports_headless: true,
            })),
            ..FakeSandboxDriver::default()
        };

        let err = assert_sandbox_driver_contract(&mut driver)
            .await
            .expect_err("sandbox conformance should reject non-sandbox capability shapes");

        assert!(err.to_string().contains("Capabilities::Sandbox"));
    }

    #[tokio::test]
    async fn sandbox_driver_contract_rejects_hot_reload_disabled() {
        let mut driver = FakeSandboxDriver {
            init_capabilities: Some(Capabilities::Sandbox(SandboxCapabilities {
                supports_hot_reload_policy: false,
                supports_filesystem_lockdown: true,
                supports_syscall_filter: true,
                supports_native_inference_routing: true,
                supports_remote_host: false,
            })),
            ..FakeSandboxDriver::default()
        };

        let err = assert_sandbox_driver_contract(&mut driver)
            .await
            .expect_err(
                "sandbox conformance should reject non-hot-reloadable sandbox capabilities",
            );

        assert!(
            err.to_string().contains("hot reload")
                || err.to_string().contains("supports_hot_reload_policy")
        );
    }

    #[tokio::test]
    async fn sandbox_driver_contract_rejects_failed_preflight() {
        let mut driver = FakeSandboxDriver {
            preflight_ok: false,
            ..FakeSandboxDriver::default()
        };

        let err = assert_sandbox_driver_contract(&mut driver)
            .await
            .expect_err("sandbox conformance should reject failed preflight");

        assert!(err.to_string().contains("preflight"));
    }
}
