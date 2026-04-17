use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

use agentenv_proto::{
    assert_compatible_schema_version, EmptyResult, InitializeParams, InitializeResult,
    PreflightParams, PreflightResult, ERROR_SCHEMA_VERSION_INCOMPATIBLE, JSON_RPC_METHOD_NOT_FOUND,
    SCHEMA_VERSION,
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

pub fn run_schema_mismatch_suite(driver_path: &Path) -> Result<()> {
    let mut client = RpcClient::spawn(driver_path)?;
    let error = client.call_error(
        1,
        "initialize",
        &InitializeParams {
            schema_version: "1.0".to_owned(),
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
    use std::io::{BufReader, Cursor};

    use super::{read_response_envelope, write_framed_json};
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
}
