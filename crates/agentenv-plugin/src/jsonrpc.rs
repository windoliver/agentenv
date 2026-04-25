use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agentenv_proto::ShutdownParams;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_HEADER_LINES: usize = 32;

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
    #[error("duplicate Content-Length header")]
    DuplicateContentLength,
    #[error("invalid JSON-RPC response: {0}")]
    InvalidResponse(String),
    #[error("JSON-RPC frame length {length} exceeds maximum {max}")]
    FrameTooLarge { length: usize, max: usize },
    #[error("JSON-RPC header line length {length} exceeds maximum {max}")]
    HeaderTooLarge { length: usize, max: usize },
    #[error("JSON-RPC frame has too many headers: {count} > {max}")]
    TooManyHeaders { count: usize, max: usize },
    #[error("JSON-RPC protocol error: {0}")]
    Protocol(String),
    #[error("JSON-RPC request `{0}` timed out")]
    Timeout(String),
    #[error("remote JSON-RPC error {code}: {message}")]
    Remote { code: i64, message: String },
}

#[derive(Debug, Clone)]
pub struct JsonRpcClientConfig {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
}

pub struct JsonRpcClient {
    child: Mutex<Option<Child>>,
    rpc: Mutex<()>,
    state: Mutex<ClientState>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    next_id: AtomicU64,
    timeout: Duration,
}

#[derive(Debug)]
enum ClientState {
    Open,
    Closed,
    Poisoned(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RpcResponseEnvelope {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcResponseEnvelopeRaw {
    jsonrpc: String,
    id: Value,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcErrorObject>,
}

impl RpcResponseEnvelope {
    pub fn validate_result_state(&self) -> Result<(), JsonRpcError> {
        match (self.result.as_ref(), self.error.as_ref()) {
            (Some(_), Some(_)) => Err(JsonRpcError::InvalidResponse(
                "response cannot contain both `result` and `error`".to_owned(),
            )),
            (None, None) => Err(JsonRpcError::InvalidResponse(
                "response must contain either `result` or `error`".to_owned(),
            )),
            _ => Ok(()),
        }
    }
}

impl<'de> Deserialize<'de> for RpcResponseEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RpcResponseEnvelopeRaw::deserialize(deserializer)?;
        if raw.jsonrpc != "2.0" {
            return Err(serde::de::Error::custom("jsonrpc must equal \"2.0\""));
        }
        match (raw.result.as_ref(), raw.error.as_ref()) {
            (Some(_), Some(_)) => Err(serde::de::Error::custom(
                "response cannot contain both `result` and `error`",
            )),
            (None, None) => Err(serde::de::Error::custom(
                "response must contain either `result` or `error`",
            )),
            _ => Ok(Self {
                jsonrpc: raw.jsonrpc,
                id: raw.id,
                result: raw.result,
                error: raw.error,
            }),
        }
    }
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
    let mut header_count = 0usize;
    loop {
        let line = read_bounded_header_line(reader, DEFAULT_MAX_HEADER_BYTES)?;
        let Some(line) = line else {
            break;
        };
        header_count += 1;
        if header_count > DEFAULT_MAX_HEADER_LINES {
            return Err(JsonRpcError::TooManyHeaders {
                count: header_count,
                max: DEFAULT_MAX_HEADER_LINES,
            });
        }
        let line = String::from_utf8(line).map_err(|err| {
            JsonRpcError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        })?;
        if let Some(raw) = line.strip_prefix("Content-Length: ") {
            let trimmed = raw.trim_end_matches("\r\n").trim();
            if content_length.is_some() {
                return Err(JsonRpcError::DuplicateContentLength);
            }
            content_length = Some(
                trimmed
                    .parse::<usize>()
                    .map_err(|_| JsonRpcError::InvalidContentLength(trimmed.to_owned()))?,
            );
        }
    }

    let content_length = content_length.ok_or(JsonRpcError::MissingContentLength)?;
    if content_length > DEFAULT_MAX_FRAME_BYTES {
        return Err(JsonRpcError::FrameTooLarge {
            length: content_length,
            max: DEFAULT_MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0_u8; content_length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn read_bounded_header_line<R>(
    reader: &mut R,
    max_header_bytes: usize,
) -> Result<Option<Vec<u8>>, JsonRpcError>
where
    R: BufRead,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Err(JsonRpcError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading JSON-RPC headers",
                )));
            }
            return Err(JsonRpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading JSON-RPC header line",
            )));
        }

        let newline_index = available.iter().position(|byte| *byte == b'\n');
        let chunk_len = newline_index.map_or(available.len(), |idx| idx + 1);
        if line.len() + chunk_len > max_header_bytes {
            return Err(JsonRpcError::HeaderTooLarge {
                length: line.len() + chunk_len,
                max: max_header_bytes,
            });
        }

        line.extend_from_slice(&available[..chunk_len]);
        reader.consume(chunk_len);

        if matches!(line.as_slice(), b"\r\n" | b"\n") {
            return Ok(None);
        }
        if newline_index.is_some() {
            return Ok(Some(line));
        }
    }
}

impl JsonRpcClient {
    pub async fn spawn(config: JsonRpcClientConfig) -> Result<Self, JsonRpcError> {
        let mut command = Command::new(&config.binary);
        command.args(&config.args);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::inherit());
        command.kill_on_drop(true);
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
            child: Mutex::new(Some(child)),
            rpc: Mutex::new(()),
            state: Mutex::new(ClientState::Open),
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
        let _rpc_guard = self.rpc.lock().await;
        self.ensure_open().await?;
        match tokio::time::timeout(self.timeout, self.call_inner(method, params)).await {
            Ok(result) => result,
            Err(_) => {
                self.poison_and_terminate(format!("request `{method}` timed out"))
                    .await?;
                Err(JsonRpcError::Timeout(method.to_owned()))
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), JsonRpcError> {
        let _rpc_guard = self.rpc.lock().await;
        self.ensure_open().await?;
        let shutdown_result = tokio::time::timeout(
            self.timeout,
            self.call_inner::<_, agentenv_proto::EmptyResult>("shutdown", &ShutdownParams {}),
        )
        .await;
        match shutdown_result {
            Ok(Ok(_result)) => {}
            Ok(Err(err)) => {
                self.poison_and_terminate(format!("shutdown rpc failed: {err}"))
                    .await
                    .ok();
                return Err(err);
            }
            Err(_) => {
                self.poison_and_terminate("shutdown timed out".to_owned())
                    .await?;
                return Err(JsonRpcError::Timeout("shutdown".to_owned()));
            }
        };

        let mut child = self.take_child().await?;
        let wait_result = tokio::time::timeout(self.timeout, child.wait()).await;
        let status = match wait_result {
            Ok(status) => status?,
            Err(_) => {
                self.set_state(ClientState::Poisoned("shutdown timed out".to_owned()))
                    .await;
                Self::kill_and_reap_child(&mut child).await?;
                return Err(JsonRpcError::Timeout("shutdown".to_owned()));
            }
        };
        self.set_state(ClientState::Closed).await;
        if !status.success() {
            return Err(JsonRpcError::Protocol(format!(
                "driver exited with non-zero status after shutdown: {status}"
            )));
        }
        Ok(())
    }

    async fn call_inner<P, R>(&self, method: &str, params: &P) -> Result<R, JsonRpcError>
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
            if response.id.as_u64() != Some(id) {
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
    }

    async fn ensure_open(&self) -> Result<(), JsonRpcError> {
        let state = self.state.lock().await;
        match &*state {
            ClientState::Open => Ok(()),
            ClientState::Closed => Err(JsonRpcError::Protocol(
                "JSON-RPC client is closed".to_owned(),
            )),
            ClientState::Poisoned(reason) => Err(JsonRpcError::Protocol(format!(
                "JSON-RPC client is poisoned: {reason}"
            ))),
        }
    }

    async fn set_state(&self, new_state: ClientState) {
        let mut state = self.state.lock().await;
        *state = new_state;
    }

    async fn take_child(&self) -> Result<Child, JsonRpcError> {
        self.child
            .lock()
            .await
            .take()
            .ok_or_else(|| JsonRpcError::Protocol("driver already shut down".to_owned()))
    }

    async fn poison_and_terminate(&self, reason: String) -> Result<(), JsonRpcError> {
        self.set_state(ClientState::Poisoned(reason)).await;
        self.terminate_child().await
    }

    async fn terminate_child(&self) -> Result<(), JsonRpcError> {
        if let Some(mut child) = self.child.lock().await.take() {
            Self::kill_and_reap_child(&mut child).await?;
        }
        Ok(())
    }

    async fn kill_and_reap_child(child: &mut Child) -> Result<(), JsonRpcError> {
        if child.try_wait()?.is_some() {
            let _ = child.wait().await?;
            return Ok(());
        }
        child.start_kill()?;
        let _ = child.wait().await?;
        Ok(())
    }
}

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
    let mut header_count = 0usize;
    loop {
        let line = read_bounded_header_line_async(reader, DEFAULT_MAX_HEADER_BYTES).await?;
        let Some(line) = line else {
            break;
        };
        header_count += 1;
        if header_count > DEFAULT_MAX_HEADER_LINES {
            return Err(JsonRpcError::TooManyHeaders {
                count: header_count,
                max: DEFAULT_MAX_HEADER_LINES,
            });
        }
        let line = String::from_utf8(line).map_err(|err| {
            JsonRpcError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        })?;
        if let Some(raw) = line.strip_prefix("Content-Length: ") {
            let trimmed = raw.trim_end_matches("\r\n").trim();
            if content_length.is_some() {
                return Err(JsonRpcError::DuplicateContentLength);
            }
            content_length = Some(
                trimmed
                    .parse::<usize>()
                    .map_err(|_| JsonRpcError::InvalidContentLength(trimmed.to_owned()))?,
            );
        }
    }

    let content_length = content_length.ok_or(JsonRpcError::MissingContentLength)?;
    if content_length > DEFAULT_MAX_FRAME_BYTES {
        return Err(JsonRpcError::FrameTooLarge {
            length: content_length,
            max: DEFAULT_MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0_u8; content_length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

async fn read_bounded_header_line_async<R>(
    reader: &mut R,
    max_header_bytes: usize,
) -> Result<Option<Vec<u8>>, JsonRpcError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Err(JsonRpcError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading JSON-RPC headers",
                )));
            }
            return Err(JsonRpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading JSON-RPC header line",
            )));
        }

        let newline_index = available.iter().position(|byte| *byte == b'\n');
        let chunk_len = newline_index.map_or(available.len(), |idx| idx + 1);
        if line.len() + chunk_len > max_header_bytes {
            return Err(JsonRpcError::HeaderTooLarge {
                length: line.len() + chunk_len,
                max: max_header_bytes,
            });
        }

        line.extend_from_slice(&available[..chunk_len]);
        reader.consume(chunk_len);

        if matches!(line.as_slice(), b"\r\n" | b"\n") {
            return Ok(None);
        }
        if newline_index.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::{
        read_framed_json_blocking, write_framed_json_blocking, JsonRpcError, RpcResponseEnvelope,
        DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_HEADER_LINES,
    };

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
        let err = serde_json::from_value::<RpcResponseEnvelope>(raw).unwrap_err();

        assert!(err.is_data());
    }

    #[test]
    fn response_envelope_rejects_both_result_and_error() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"ok": true},
            "error": {"code": -1, "message": "bad"}
        });
        let err = serde_json::from_value::<RpcResponseEnvelope>(raw).unwrap_err();

        assert!(err.is_data());
    }

    #[test]
    fn response_envelope_rejects_wrong_jsonrpc_version() {
        let raw = json!({
            "jsonrpc": "1.0",
            "id": 1,
            "result": {"ok": true}
        });
        let err = serde_json::from_value::<RpcResponseEnvelope>(raw).unwrap_err();

        assert!(err.is_data());
    }

    #[test]
    fn read_framed_json_rejects_frames_above_default_max_before_payload_allocation() {
        let length = DEFAULT_MAX_FRAME_BYTES + 1;
        let framed = format!("Content-Length: {length}\r\n\r\n");
        let err = read_framed_json_blocking(&mut Cursor::new(framed.into_bytes())).unwrap_err();

        assert!(matches!(
            err,
            JsonRpcError::FrameTooLarge {
                length: _,
                max: DEFAULT_MAX_FRAME_BYTES
            }
        ));
    }

    #[test]
    fn read_framed_json_rejects_overlong_header_line() {
        let line = "a".repeat(DEFAULT_MAX_HEADER_BYTES + 1);
        let framed = format!("{line}\r\n\r\n");
        let err = read_framed_json_blocking(&mut Cursor::new(framed.into_bytes())).unwrap_err();

        assert!(matches!(
            err,
            JsonRpcError::HeaderTooLarge {
                length: _,
                max: DEFAULT_MAX_HEADER_BYTES
            }
        ));
    }

    #[test]
    fn read_framed_json_rejects_too_many_headers() {
        let mut framed = String::new();
        for _ in 0..(DEFAULT_MAX_HEADER_LINES + 1) {
            framed.push_str("X-Test: ok\r\n");
        }
        framed.push_str("\r\n");
        let err = read_framed_json_blocking(&mut Cursor::new(framed.into_bytes())).unwrap_err();

        assert!(matches!(
            err,
            JsonRpcError::TooManyHeaders {
                count: _,
                max: DEFAULT_MAX_HEADER_LINES
            }
        ));
    }

    #[test]
    fn read_framed_json_rejects_duplicate_content_length_headers() {
        let framed = concat!(
            "Content-Length: 1\r\n",
            "Content-Length: 2\r\n",
            "\r\n",
            "0"
        );
        let err = read_framed_json_blocking(&mut Cursor::new(framed.as_bytes())).unwrap_err();

        assert!(matches!(err, JsonRpcError::DuplicateContentLength));
    }
}

#[cfg(test)]
mod async_client_tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::{JsonRpcClient, JsonRpcClientConfig};

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn jsonrpc_client_returns_method_result() {
        let mut client = spawn_fixture_client("normal", Duration::from_secs(5), &[]).await;

        let result: agentenv_proto::PreflightResult = client
            .call("preflight", &agentenv_proto::PreflightParams::default())
            .await
            .unwrap();

        assert!(result.ok);
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn jsonrpc_client_surfaces_driver_error_code() {
        let mut client = spawn_fixture_client("normal", Duration::from_secs(5), &[]).await;

        let err = client
            .call::<_, serde_json::Value>("driver/unknown", &json!({}))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("-32601"));
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn jsonrpc_client_drops_child_process_on_drop() {
        let pid_file = temp_fixture_path("drop");
        let client = spawn_fixture_client(
            "idle",
            Duration::from_secs(5),
            &[(
                "JSONRPC_FIXTURE_PID_FILE",
                pid_file.to_string_lossy().as_ref(),
            )],
        )
        .await;
        wait_for_file(&pid_file).await;
        let pid = read_fixture_pid(&pid_file);

        drop(client);

        assert_process_exits(pid).await;
    }

    #[tokio::test]
    async fn jsonrpc_client_poisons_after_request_timeout() {
        let client = spawn_fixture_client("slow_preflight", Duration::from_millis(100), &[]).await;

        let err = client
            .call::<_, agentenv_proto::PreflightResult>(
                "preflight",
                &agentenv_proto::PreflightParams::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, super::JsonRpcError::Timeout(ref method) if method == "preflight"));

        let poisoned = client
            .call::<_, agentenv_proto::PreflightResult>(
                "preflight",
                &agentenv_proto::PreflightParams::default(),
            )
            .await
            .unwrap_err();
        assert!(
            poisoned.to_string().contains("poisoned") || poisoned.to_string().contains("closed")
        );
    }

    #[tokio::test]
    async fn jsonrpc_client_shutdown_timeout_kills_and_reaps_child() {
        let pid_file = temp_fixture_path("shutdown-timeout");
        let mut client = spawn_fixture_client(
            "shutdown_hang",
            Duration::from_millis(100),
            &[(
                "JSONRPC_FIXTURE_PID_FILE",
                pid_file.to_string_lossy().as_ref(),
            )],
        )
        .await;
        wait_for_file(&pid_file).await;
        let pid = read_fixture_pid(&pid_file);

        let err = client.shutdown().await.unwrap_err();
        assert!(matches!(err, super::JsonRpcError::Timeout(ref method) if method == "shutdown"));
        assert_process_exits(pid).await;
    }

    #[tokio::test]
    async fn jsonrpc_client_shutdown_reports_nonzero_exit_status() {
        let mut client =
            spawn_fixture_client("shutdown_nonzero", Duration::from_secs(5), &[]).await;
        let err = client.shutdown().await.unwrap_err();
        assert!(err.to_string().contains("exit status"));
        assert!(err.to_string().contains("non-zero") || err.to_string().contains("status"));
    }

    #[tokio::test]
    async fn jsonrpc_client_shutdown_reaps_child_on_shutdown_rpc_failure() {
        let pid_file = temp_fixture_path("shutdown-rpc-failure");
        let mut client = spawn_fixture_client(
            "shutdown_invalid_then_hang",
            Duration::from_millis(200),
            &[(
                "JSONRPC_FIXTURE_PID_FILE",
                pid_file.to_string_lossy().as_ref(),
            )],
        )
        .await;
        wait_for_file(&pid_file).await;
        let pid = read_fixture_pid(&pid_file);

        let err = client.shutdown().await.unwrap_err();
        assert!(
            err.to_string().contains("invalid JSON-RPC payload")
                || err.to_string().contains("JSON-RPC")
        );
        assert_process_exits(pid).await;

        let poisoned = client
            .call::<_, agentenv_proto::PreflightResult>(
                "preflight",
                &agentenv_proto::PreflightParams::default(),
            )
            .await
            .unwrap_err();
        assert!(
            poisoned.to_string().contains("poisoned") || poisoned.to_string().contains("closed")
        );
    }

    #[tokio::test]
    async fn jsonrpc_client_serializes_concurrent_calls() {
        let driver = write_racy_driver_script();

        let client = Arc::new(
            JsonRpcClient::spawn(JsonRpcClientConfig {
                binary: python_fixture_binary(),
                args: python_fixture_args(&driver),
                env: Default::default(),
                timeout: Duration::from_secs(5),
            })
            .await
            .unwrap(),
        );

        let first = client.clone();
        let second = client.clone();
        let (left, right) = tokio::join!(
            async move {
                first
                    .call::<_, agentenv_proto::PreflightResult>(
                        "preflight",
                        &agentenv_proto::PreflightParams::default(),
                    )
                    .await
            },
            async move {
                second
                    .call::<_, agentenv_proto::PreflightResult>(
                        "preflight",
                        &agentenv_proto::PreflightParams::default(),
                    )
                    .await
            }
        );

        assert!(left.unwrap().ok);
        assert!(right.unwrap().ok);

        let mut client =
            Arc::try_unwrap(client).unwrap_or_else(|_| panic!("all Arc clones dropped after join"));
        client.shutdown().await.unwrap();
    }

    async fn spawn_fixture_client(
        mode: &str,
        timeout: Duration,
        env_pairs: &[(&str, &str)],
    ) -> JsonRpcClient {
        let driver = write_fixture_script();
        let mut env = std::collections::BTreeMap::new();
        env.insert("JSONRPC_FIXTURE_MODE".to_owned(), mode.to_owned());
        for (key, value) in env_pairs {
            env.insert((*key).to_owned(), (*value).to_owned());
        }

        JsonRpcClient::spawn(JsonRpcClientConfig {
            binary: python_fixture_binary(),
            args: python_fixture_args(&driver),
            env,
            timeout,
        })
        .await
        .unwrap()
    }

    fn write_fixture_script() -> PathBuf {
        let path = temp_fixture_artifact_path("fixture", "py");
        let script = r#"#!/usr/bin/env python3
import json
import os
import sys
import time

MODE = os.environ.get("JSONRPC_FIXTURE_MODE", "normal")
PID_FILE = os.environ.get("JSONRPC_FIXTURE_PID_FILE")

def write_pid():
    if PID_FILE:
        with open(PID_FILE, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
            handle.flush()

def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\n", b"\r\n"):
            break
        key, value = line.decode("utf-8").split(":", 1)
        headers[key.strip().lower()] = value.strip()
    length = int(headers["content-length"])
    body = sys.stdin.buffer.read(length)
    return json.loads(body)

def write_message(message):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8"))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()

def response(request):
    if request["method"] == "preflight":
        if MODE == "slow_preflight":
            time.sleep(1.0)
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"ok": True, "issues": []},
        }
    if request["method"] == "shutdown":
        if MODE == "shutdown_invalid_then_hang":
            sys.stdout.buffer.write(b"Content-Length: 2\r\n\r\n{")
            sys.stdout.buffer.flush()
            while True:
                time.sleep(1.0)
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {},
        }
    return {
        "jsonrpc": "2.0",
        "id": request["id"],
        "error": {"code": -32601, "message": "method not found"},
    }

write_pid()

while True:
    request = read_message()
    if request is None:
        break
    write_message(response(request))
    if request["method"] == "shutdown":
        if MODE == "shutdown_hang":
            while True:
                time.sleep(1.0)
        if MODE == "shutdown_nonzero":
            sys.exit(7)
        break
    if MODE == "idle":
        while True:
            time.sleep(1.0)
"#;
        write_executable_fixture(&path, script);
        path
    }

    fn temp_fixture_path(label: &str) -> PathBuf {
        temp_fixture_artifact_path(label, "pid")
    }

    fn read_fixture_pid(path: &Path) -> u32 {
        let pid = fs::read_to_string(path).unwrap();
        pid.trim().parse::<u32>().unwrap()
    }

    fn python_fixture_binary() -> PathBuf {
        PathBuf::from("python3")
    }

    fn python_fixture_args(script: &Path) -> Vec<String> {
        vec![script.to_string_lossy().into_owned()]
    }

    async fn wait_for_file(path: &Path) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if path.is_file() {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("fixture file {} was not created", path.display());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn assert_process_exits(pid: u32) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !process_is_alive(pid) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("process {} did not exit in time", pid);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn process_is_alive(pid: u32) -> bool {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("kill -0 {} >/dev/null 2>&1", pid))
            .status()
            .unwrap();
        status.success()
    }

    fn write_racy_driver_script() -> PathBuf {
        let path = temp_fixture_artifact_path("racy", "py");
        let script = r#"#!/usr/bin/env python3
import json
import select
import sys

def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\n", b"\r\n"):
            break
        key, value = line.decode("utf-8").split(":", 1)
        headers[key.strip().lower()] = value.strip()
    length = int(headers["content-length"])
    body = sys.stdin.buffer.read(length)
    return json.loads(body)

def write_message(message):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8"))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()

def response(request):
    if request["method"] == "preflight":
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"ok": True, "issues": []},
        }
    if request["method"] == "shutdown":
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {},
        }
    return {
        "jsonrpc": "2.0",
        "id": request["id"],
        "error": {"code": -32601, "message": "method not found"},
    }

first = read_message()
if first is None:
    sys.exit(0)

if first["method"] == "preflight":
    if select.select([sys.stdin], [], [], 0.1)[0]:
        second = read_message()
        if second is not None:
            write_message(response(second))
        write_message(response(first))
    else:
        write_message(response(first))
else:
    write_message(response(first))

while True:
    next_request = read_message()
    if next_request is None:
        break
    write_message(response(next_request))
    if next_request["method"] == "shutdown":
        break
"#;
        write_executable_fixture(&path, script);
        path
    }

    fn temp_fixture_artifact_path(label: &str, extension: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentenv-jsonrpc-{}-{}-{}-{}.{}",
            label,
            std::process::id(),
            sequence,
            unique,
            extension
        ))
    }

    fn write_executable_fixture(path: &Path, script: &str) {
        fs::write(path, script).unwrap();
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms).unwrap();
        }
    }
}
