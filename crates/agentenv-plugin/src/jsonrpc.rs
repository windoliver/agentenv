use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentenv_events::{
    ActivityEvent, ActivityKind as EventActivityKind, ActivityResult as EventActivityResult,
    EventEmitter, NoopEventEmitter,
};
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
    #[error("approval coordinator error: {0}")]
    Approval(#[from] agentenv_approvals::ApprovalCoordinatorError),
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
    event_emitter: Arc<dyn EventEmitter>,
    approval_coordinator: Option<agentenv_approvals::ApprovalCoordinator>,
    env_name: Option<String>,
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

#[derive(Serialize)]
struct RpcNotificationWithParams<T> {
    jsonrpc: &'static str,
    method: &'static str,
    params: T,
}

pub fn notification_to_activity_event(
    notification: RpcNotificationEnvelope,
    fallback_trace_id: &str,
) -> Result<ActivityEvent, JsonRpcError> {
    let RpcNotificationEnvelope {
        jsonrpc,
        method,
        params,
    } = notification;
    if jsonrpc != "2.0" {
        return Err(JsonRpcError::Protocol(format!(
            "unsupported notification JSON-RPC version `{jsonrpc}`"
        )));
    }

    match method.as_str() {
        "event/log" => convert_known_notification::<agentenv_proto::EventLogParams>(
            &method,
            params,
            fallback_trace_id,
            |params| event_log_params_to_activity_event(params, fallback_trace_id),
        ),
        "event/activity" => {
            convert_known_notification::<agentenv_proto::DriverActivityEventParams>(
                &method,
                params,
                fallback_trace_id,
                |params| driver_activity_params_to_activity_event(params, fallback_trace_id),
            )
        }
        "event/approval_requested" => convert_known_notification::<
            agentenv_proto::ApprovalRequestedParams,
        >(&method, params, fallback_trace_id, |params| {
            approval_requested_params_to_activity_event(params, fallback_trace_id)
        }),
        method => Err(JsonRpcError::Protocol(format!(
            "unsupported notification method `{method}`"
        ))),
    }
}

fn convert_known_notification<T>(
    method: &str,
    params: Value,
    fallback_trace_id: &str,
    convert: impl FnOnce(T) -> ActivityEvent,
) -> Result<ActivityEvent, JsonRpcError>
where
    T: DeserializeOwned,
{
    match serde_json::from_value::<T>(params.clone()) {
        Ok(params) => Ok(convert(params)),
        Err(err) => Ok(invalid_notification_event(
            method,
            params,
            fallback_trace_id,
            &err,
        )),
    }
}

fn event_log_params_to_activity_event(
    params: agentenv_proto::EventLogParams,
    fallback_trace_id: &str,
) -> ActivityEvent {
    let agentenv_proto::EventLogParams { level, ts, msg, kv } = params;
    let mut event = ActivityEvent::new(
        ts,
        EventActivityKind::Log,
        EventActivityResult::Ok,
        fallback_trace_id,
    )
    .with_subject_value("msg", Value::String(msg.clone()))
    .with_extra("msg", Value::String(msg))
    .with_extra("level", Value::String(log_level_name(&level).to_owned()));

    for (key, value) in kv {
        if key == "driver" {
            if let Some(driver) = value.as_str() {
                event = event.with_actor_value("driver", Value::String(driver.to_owned()));
            }
            event = event.with_extra(key, value);
        } else if key == "env" {
            if let Some(env) = value.as_str() {
                event = event.with_env(env.to_owned());
            }
            event = event.with_extra(key, value);
        } else if is_log_subject_key(&key) {
            event = event
                .with_subject_value(key.clone(), value.clone())
                .with_extra(key, value);
        } else {
            event = event.with_extra(key, value);
        }
    }

    event
}

fn driver_activity_params_to_activity_event(
    params: agentenv_proto::DriverActivityEventParams,
    fallback_trace_id: &str,
) -> ActivityEvent {
    match params {
        agentenv_proto::DriverActivityEventParams::Legacy(params) => {
            ActivityEvent::from_legacy_proto(params, fallback_trace_id)
        }
        agentenv_proto::DriverActivityEventParams::Rich(params) => {
            rich_activity_params_to_activity_event(params)
        }
    }
}

fn rich_activity_params_to_activity_event(
    params: agentenv_proto::RichActivityEventParams,
) -> ActivityEvent {
    let agentenv_proto::RichActivityEventParams {
        ts,
        kind,
        env,
        actor,
        subject,
        result,
        latency_ms,
        trace_id,
        reason_code,
        extras,
    } = params;
    let mut event = ActivityEvent::new(
        ts,
        rich_activity_kind_to_event_kind(kind),
        rich_activity_result_to_event_result(result),
        trace_id,
    );
    event.env = env;
    event.actor = actor;
    event.subject = subject;
    event.latency_ms = latency_ms;
    event.reason_code = reason_code;
    event.extras = extras;
    event
}

fn approval_requested_params_to_activity_event(
    params: agentenv_proto::ApprovalRequestedParams,
    fallback_trace_id: &str,
) -> ActivityEvent {
    let mut event = ActivityEvent::new(
        now_event_ts(),
        EventActivityKind::ApprovalRequested,
        EventActivityResult::PendingApproval,
        fallback_trace_id,
    )
    .with_subject_value("request_id", Value::String(params.request_id))
    .with_subject_value(
        "kind",
        Value::String(approval_kind_name(&params.kind).to_owned()),
    )
    .with_subject_value("subject", Value::String(params.subject))
    .with_subject_value("reason", Value::String(params.reason))
    .with_extra(
        "context",
        Value::Object(params.context.into_iter().collect()),
    );

    if let Some(default_ttl) = params.default_ttl {
        event = event.with_extra("default_ttl", Value::String(default_ttl));
    }

    event
}

pub(crate) fn approval_request_from_params(
    env: impl Into<String>,
    params: agentenv_proto::ApprovalRequestedParams,
    trace_id: impl Into<String>,
) -> Result<agentenv_approvals::ApprovalRequest, JsonRpcError> {
    let requested_at = time::OffsetDateTime::now_utc();
    Ok(agentenv_approvals::ApprovalRequest::new(
        params.request_id,
        env,
        agentenv_approvals::ApprovalKind::from(params.kind),
        params.subject,
        params.reason,
        Value::Object(params.context.into_iter().collect()),
        requested_at,
        approval_scope_from_default_ttl(params.default_ttl.as_deref()),
        Duration::from_secs(300),
        trace_id,
    ))
}

pub(crate) fn approval_decision_notification(
    params: agentenv_proto::ApprovalDecisionParams,
) -> Result<String, JsonRpcError> {
    Ok(serde_json::to_string(
        &approval_decision_notification_envelope(params),
    )?)
}

fn approval_decision_notification_envelope(
    params: agentenv_proto::ApprovalDecisionParams,
) -> RpcNotificationWithParams<agentenv_proto::ApprovalDecisionParams> {
    RpcNotificationWithParams {
        jsonrpc: "2.0",
        method: "approval/decision",
        params,
    }
}

fn approval_decision_params_from_record(
    decision: agentenv_approvals::ApprovalDecisionRecord,
) -> agentenv_proto::ApprovalDecisionParams {
    agentenv_proto::ApprovalDecisionParams {
        request_id: decision.request_id,
        decision: agentenv_proto::ApprovalDecision::from(decision.decision),
        scope: approval_scope_to_proto(decision.scope),
        decided_by: decision.decided_by,
        decided_at: agentenv_approvals::format_rfc3339(decision.decided_at),
    }
}

fn approval_scope_from_default_ttl(default_ttl: Option<&str>) -> agentenv_approvals::ApprovalScope {
    match default_ttl {
        Some("once") => agentenv_approvals::ApprovalScope::Once,
        Some("persist-sandbox") => agentenv_approvals::ApprovalScope::PersistSandbox,
        Some("propose-for-baseline") => agentenv_approvals::ApprovalScope::ProposeForBaseline,
        Some("session") | None => agentenv_approvals::ApprovalScope::Session,
        Some(_) => agentenv_approvals::ApprovalScope::Session,
    }
}

fn approval_scope_to_proto(
    scope: agentenv_approvals::ApprovalScope,
) -> agentenv_proto::ApprovalScope {
    match scope {
        agentenv_approvals::ApprovalScope::Once => agentenv_proto::ApprovalScope::Once,
        agentenv_approvals::ApprovalScope::Session => agentenv_proto::ApprovalScope::Session,
        agentenv_approvals::ApprovalScope::PersistSandbox => {
            agentenv_proto::ApprovalScope::PersistSandbox
        }
        agentenv_approvals::ApprovalScope::ProposeForBaseline => {
            agentenv_proto::ApprovalScope::ProposeForBaseline
        }
    }
}

fn invalid_notification_event(
    method: &str,
    params: Value,
    fallback_trace_id: &str,
    error: &dyn std::fmt::Display,
) -> ActivityEvent {
    ActivityEvent::new(
        notification_error_timestamp(&params),
        EventActivityKind::Log,
        EventActivityResult::Error,
        fallback_trace_id,
    )
    .with_reason_code("invalid_driver_notification")
    .with_subject_value("method", Value::String(method.to_owned()))
    .with_extra("error", Value::String(error.to_string()))
    .with_extra("params", params)
}

fn notification_error_timestamp(params: &Value) -> String {
    params
        .get("ts")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(now_event_ts)
}

fn log_level_name(level: &agentenv_proto::LogLevel) -> &'static str {
    match level {
        agentenv_proto::LogLevel::Trace => "trace",
        agentenv_proto::LogLevel::Debug => "debug",
        agentenv_proto::LogLevel::Info => "info",
        agentenv_proto::LogLevel::Warn => "warn",
        agentenv_proto::LogLevel::Error => "error",
    }
}

fn approval_kind_name(kind: &agentenv_proto::ApprovalKind) -> &'static str {
    match kind {
        agentenv_proto::ApprovalKind::EgressHost => "egress_host",
        agentenv_proto::ApprovalKind::McpTool => "mcp_tool",
        agentenv_proto::ApprovalKind::ZoneAccess => "zone_access",
        agentenv_proto::ApprovalKind::PackageInstall => "package_install",
    }
}

fn is_log_subject_key(key: &str) -> bool {
    matches!(
        key,
        "handle" | "target" | "subject" | "request_id" | "tool" | "resource"
    )
}

fn rich_activity_kind_to_event_kind(kind: agentenv_proto::RichActivityKind) -> EventActivityKind {
    match kind {
        agentenv_proto::RichActivityKind::SandboxCreate => EventActivityKind::SandboxCreate,
        agentenv_proto::RichActivityKind::SandboxDestroy => EventActivityKind::SandboxDestroy,
        agentenv_proto::RichActivityKind::Exec => EventActivityKind::Exec,
        agentenv_proto::RichActivityKind::EgressAllowed => EventActivityKind::EgressAllowed,
        agentenv_proto::RichActivityKind::EgressDenied => EventActivityKind::EgressDenied,
        agentenv_proto::RichActivityKind::McpToolCall => EventActivityKind::McpToolCall,
        agentenv_proto::RichActivityKind::PolicyApplied => EventActivityKind::PolicyApplied,
        agentenv_proto::RichActivityKind::CredentialInjected => {
            EventActivityKind::CredentialInjected
        }
        agentenv_proto::RichActivityKind::CredentialSet => EventActivityKind::CredentialSet,
        agentenv_proto::RichActivityKind::CredentialReset => EventActivityKind::CredentialReset,
        agentenv_proto::RichActivityKind::Auth => EventActivityKind::Auth,
        agentenv_proto::RichActivityKind::ApprovalRequested => EventActivityKind::ApprovalRequested,
        agentenv_proto::RichActivityKind::ApprovalDecided => EventActivityKind::ApprovalDecided,
        agentenv_proto::RichActivityKind::SpawnRequested => EventActivityKind::SpawnRequested,
        agentenv_proto::RichActivityKind::SpawnQueued => EventActivityKind::SpawnQueued,
        agentenv_proto::RichActivityKind::SpawnAdmitted => EventActivityKind::SpawnAdmitted,
        agentenv_proto::RichActivityKind::SpawnRejected => EventActivityKind::SpawnRejected,
        agentenv_proto::RichActivityKind::SpawnStarted => EventActivityKind::SpawnStarted,
        agentenv_proto::RichActivityKind::SpawnReady => EventActivityKind::SpawnReady,
        agentenv_proto::RichActivityKind::Log => EventActivityKind::Log,
    }
}

fn rich_activity_result_to_event_result(
    result: agentenv_proto::RichActivityResult,
) -> EventActivityResult {
    match result {
        agentenv_proto::RichActivityResult::Ok => EventActivityResult::Ok,
        agentenv_proto::RichActivityResult::Error => EventActivityResult::Error,
        agentenv_proto::RichActivityResult::Denied => EventActivityResult::Denied,
        agentenv_proto::RichActivityResult::PendingApproval => EventActivityResult::PendingApproval,
    }
}

fn now_event_ts() -> String {
    match time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339) {
        Ok(value) => value,
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
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
            event_emitter: Arc::new(NoopEventEmitter),
            approval_coordinator: None,
            env_name: None,
            next_id: AtomicU64::new(1),
            timeout: config.timeout,
        })
    }

    pub fn set_event_emitter<E>(&mut self, event_emitter: E)
    where
        E: EventEmitter + 'static,
    {
        self.event_emitter = Arc::new(event_emitter);
    }

    pub fn set_event_emitter_arc(&mut self, event_emitter: Arc<dyn EventEmitter>) {
        self.event_emitter = event_emitter;
    }

    pub fn set_approval_coordinator(
        &mut self,
        env_name: impl Into<String>,
        coordinator: agentenv_approvals::ApprovalCoordinator,
    ) {
        self.env_name = Some(env_name.into());
        self.approval_coordinator = Some(coordinator);
    }

    pub fn with_event_emitter<E>(mut self, event_emitter: E) -> Self
    where
        E: EventEmitter + 'static,
    {
        self.set_event_emitter(event_emitter);
        self
    }

    pub fn with_event_emitter_arc(mut self, event_emitter: Arc<dyn EventEmitter>) -> Self {
        self.set_event_emitter_arc(event_emitter);
        self
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
        let fallback_trace_id = format!("jsonrpc-{id}");
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
                let notification: RpcNotificationEnvelope = serde_json::from_value(raw)?;
                self.handle_notification(notification, &fallback_trace_id)
                    .await?;
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

    async fn handle_notification(
        &self,
        notification: RpcNotificationEnvelope,
        fallback_trace_id: &str,
    ) -> Result<(), JsonRpcError> {
        if notification.method == "event/approval_requested" {
            if let (Some(coordinator), Some(env_name)) =
                (&self.approval_coordinator, &self.env_name)
            {
                return self
                    .handle_approval_requested_notification(
                        notification,
                        fallback_trace_id,
                        env_name,
                        coordinator,
                    )
                    .await;
            }
        }

        let event = notification_to_activity_event(notification, fallback_trace_id)?;
        self.event_emitter.emit(event.redacted());
        Ok(())
    }

    async fn handle_approval_requested_notification(
        &self,
        notification: RpcNotificationEnvelope,
        fallback_trace_id: &str,
        env_name: &str,
        coordinator: &agentenv_approvals::ApprovalCoordinator,
    ) -> Result<(), JsonRpcError> {
        let event = notification_to_activity_event(notification.clone(), fallback_trace_id)?;
        let params: agentenv_proto::ApprovalRequestedParams =
            match serde_json::from_value(notification.params) {
                Ok(params) => params,
                Err(_) => {
                    self.event_emitter.emit(event.redacted());
                    return Ok(());
                }
            };
        let request_id = params.request_id.clone();
        let request = approval_request_from_params(env_name, params, fallback_trace_id)?;

        coordinator.submit_request(request).await?;
        let decision = coordinator.wait_for_decision(&request_id).await?;
        let params = approval_decision_params_from_record(decision);
        let notification = approval_decision_notification(params)?;
        {
            let mut stdin = self.stdin.lock().await;
            write_framed_json_bytes_async(&mut *stdin, notification.as_bytes()).await?;
        }
        self.event_emitter.emit(event.redacted());
        Ok(())
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
    write_framed_json_bytes_async(writer, &payload).await
}

async fn write_framed_json_bytes_async<W>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), JsonRpcError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    writer
        .write_all(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes())
        .await?;
    writer.write_all(payload).await?;
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
        approval_decision_notification, approval_request_from_params,
        notification_to_activity_event, read_framed_json_blocking, write_framed_json_blocking,
        JsonRpcError, RpcNotificationEnvelope, RpcResponseEnvelope, DEFAULT_MAX_FRAME_BYTES,
        DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_HEADER_LINES,
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

    #[test]
    fn event_activity_notification_converts_to_activity_event() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/activity",
            "params": {
                "ts": "2026-04-26T12:00:00Z",
                "kind": "mcp_tool_call",
                "env": "demo",
                "actor": {"driver": "nexus"},
                "subject": {"tool": "search"},
                "result": "ok",
                "trace_id": "trace-plugin",
                "extras": {}
            }
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

        assert_eq!(event.kind, agentenv_events::ActivityKind::McpToolCall);
        assert_eq!(event.subject["tool"], json!("search"));
    }

    #[test]
    fn malformed_notification_becomes_error_log_event() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/activity",
            "params": {"kind": 7}
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

        assert_eq!(event.kind, agentenv_events::ActivityKind::Log);
        assert_eq!(event.result, agentenv_events::ActivityResult::Error);
        assert_eq!(
            event.reason_code.as_deref(),
            Some("invalid_driver_notification")
        );
    }

    #[test]
    fn event_log_notification_preserves_log_fields_and_driver_actor() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/log",
            "params": {
                "level": "warn",
                "ts": "2026-04-26T12:00:01Z",
                "msg": "policy applied",
                "kv": {
                    "driver": "openshell",
                    "handle": "sb-1",
                    "rule_count": 42
                }
            }
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

        assert_eq!(event.kind, agentenv_events::ActivityKind::Log);
        assert_eq!(event.result, agentenv_events::ActivityResult::Ok);
        assert_eq!(event.trace_id, "fallback-trace");
        assert_eq!(event.actor["driver"], json!("openshell"));
        assert_eq!(event.subject["msg"], json!("policy applied"));
        assert_eq!(event.subject["handle"], json!("sb-1"));
        assert_eq!(event.extras["level"], json!("warn"));
        assert_eq!(event.extras["rule_count"], json!(42));
    }

    #[test]
    fn legacy_event_activity_notification_uses_fallback_trace() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/activity",
            "params": {
                "kind": "egress_denied",
                "subject": "api.example.test:443",
                "reason": "not_in_policy",
                "ts": "2026-04-26T12:00:02Z",
                "handle": "sb-1"
            }
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

        assert_eq!(event.kind, agentenv_events::ActivityKind::EgressDenied);
        assert_eq!(event.result, agentenv_events::ActivityResult::Denied);
        assert_eq!(event.trace_id, "fallback-trace");
        assert_eq!(event.reason_code.as_deref(), Some("not_in_policy"));
        assert_eq!(event.subject["target"], json!("api.example.test:443"));
        assert_eq!(event.subject["handle"], json!("sb-1"));
    }

    #[test]
    fn approval_requested_notification_preserves_structured_fields() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/approval_requested",
            "params": {
                "request_id": "req-1",
                "kind": "egress_host",
                "subject": "api.example.test:443",
                "reason": "agent requested network",
                "context": {"url": "https://api.example.test/v1"},
                "default_ttl": "session"
            }
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

        assert_eq!(event.kind, agentenv_events::ActivityKind::ApprovalRequested);
        assert_eq!(
            event.result,
            agentenv_events::ActivityResult::PendingApproval
        );
        assert_eq!(event.trace_id, "fallback-trace");
        assert_eq!(event.subject["request_id"], json!("req-1"));
        assert_eq!(event.subject["kind"], json!("egress_host"));
        assert_eq!(event.subject["subject"], json!("api.example.test:443"));
        assert_eq!(event.subject["reason"], json!("agent requested network"));
        assert_eq!(
            event.extras["context"]["url"],
            json!("https://api.example.test/v1")
        );
        assert_eq!(event.extras["default_ttl"], json!("session"));
    }

    #[test]
    fn approval_requested_notification_converts_to_domain_request() {
        let params = agentenv_proto::ApprovalRequestedParams {
            request_id: "req-1".to_owned(),
            kind: agentenv_proto::ApprovalKind::EgressHost,
            subject: "api.example.test:443".to_owned(),
            reason: "network".to_owned(),
            context: std::collections::BTreeMap::new(),
            default_ttl: Some("session".to_owned()),
        };

        let request = approval_request_from_params("demo", params, "trace-1").unwrap();

        assert_eq!(request.env, "demo");
        assert_eq!(request.id, "req-1");
        assert_eq!(request.kind, agentenv_approvals::ApprovalKind::EgressHost);
        assert_eq!(
            request.default_scope,
            agentenv_approvals::ApprovalScope::Session
        );
        assert_eq!(request.created_trace_id, "trace-1");
    }

    #[test]
    fn approval_decision_notification_serializes_as_jsonrpc_notification() {
        let body = approval_decision_notification(agentenv_proto::ApprovalDecisionParams {
            request_id: "req-1".to_owned(),
            decision: agentenv_proto::ApprovalDecision::Allow,
            scope: agentenv_proto::ApprovalScope::Session,
            decided_by: "alice".to_owned(),
            decided_at: "2026-04-29T12:00:00Z".to_owned(),
        })
        .unwrap();

        assert!(body.contains("\"method\":\"approval/decision\""));
        assert!(body.contains("\"request_id\":\"req-1\""));
    }

    #[test]
    fn approval_requested_notification_preserves_package_install_kind() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/approval_requested",
            "params": {
                "request_id": "req-package",
                "kind": "package_install",
                "subject": "ripgrep",
                "reason": "agent requested package install",
                "context": {"package": "ripgrep"}
            }
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

        assert_eq!(event.kind, agentenv_events::ActivityKind::ApprovalRequested);
        assert_eq!(event.subject["kind"], json!("package_install"));
    }

    #[test]
    fn generated_notification_timestamp_is_rfc3339_utc() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/approval_requested",
            "params": {
                "request_id": "req-1",
                "kind": "egress_host",
                "subject": "api.example.test:443",
                "reason": "agent requested network",
                "context": {}
            }
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let event = notification_to_activity_event(notification, "fallback-trace").unwrap();

        assert!(!event.ts.starts_with("unix:"));
        assert!(event.ts.contains('T'));
        assert!(event.ts.ends_with('Z'));
    }

    #[test]
    fn unknown_notification_method_returns_protocol_error() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "event/unknown",
            "params": {}
        });

        let notification: RpcNotificationEnvelope = serde_json::from_value(raw).unwrap();
        let err = notification_to_activity_event(notification, "fallback-trace").unwrap_err();

        assert!(
            matches!(err, JsonRpcError::Protocol(message) if message.contains("event/unknown"))
        );
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

    #[tokio::test]
    async fn jsonrpc_client_emits_notification_seen_before_response() {
        let mut client =
            spawn_fixture_client("notification_before_preflight", Duration::from_secs(5), &[])
                .await;
        let emitter = agentenv_events::RecordingEventEmitter::default();
        client.set_event_emitter(emitter.clone());

        let result: agentenv_proto::PreflightResult = client
            .call("preflight", &agentenv_proto::PreflightParams::default())
            .await
            .unwrap();

        assert!(result.ok);
        let recorded = emitter.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, agentenv_events::ActivityKind::McpToolCall);
        assert_eq!(recorded[0].trace_id, "trace-fixture");
        assert_eq!(recorded[0].subject["tool"], json!("search"));
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn approval_requested_notification_waits_and_sends_decision() {
        let store_path = temp_fixture_artifact_path("approvals", "db");
        let store = agentenv_approvals::ApprovalStore::open(&store_path).unwrap();
        let coordinator = agentenv_approvals::ApprovalCoordinator::new(
            agentenv_approvals::ApprovalCoordinatorConfig {
                store,
                events: Arc::new(agentenv_events::NoopEventEmitter),
                poll_interval: Duration::from_millis(10),
                overlay_path: None,
                proposal_path: None,
            },
        );
        let decision_file = temp_fixture_path("approval-decision");
        let mut client = spawn_fixture_client(
            "approval_before_preflight",
            Duration::from_secs(5),
            &[(
                "JSONRPC_FIXTURE_DECISION_FILE",
                decision_file.to_string_lossy().as_ref(),
            )],
        )
        .await;
        client.set_approval_coordinator("demo", coordinator.clone());

        let decider = tokio::spawn({
            let coordinator = coordinator.clone();
            async move {
                wait_for_approval_request(&coordinator, "req-1").await;
                coordinator
                    .decide(agentenv_approvals::ApprovalDecisionRecord {
                        request_id: "req-1".to_owned(),
                        decision: agentenv_approvals::ApprovalDecisionValue::Allow,
                        scope: agentenv_approvals::ApprovalScope::Session,
                        decided_by: "alice".to_owned(),
                        decided_at: time::OffsetDateTime::UNIX_EPOCH,
                        reason: None,
                        context: json!({}),
                        trace_id: "trace-approval".to_owned(),
                    })
                    .await
                    .unwrap();
            }
        });

        let result: agentenv_proto::PreflightResult = client
            .call("preflight", &agentenv_proto::PreflightParams::default())
            .await
            .unwrap();

        assert!(result.ok);
        decider.await.unwrap();
        let recorded = fs::read_to_string(&decision_file).unwrap();
        let decision: serde_json::Value = serde_json::from_str(&recorded).unwrap();
        assert_eq!(decision["method"], json!("approval/decision"));
        assert_eq!(decision["params"]["request_id"], json!("req-1"));
        assert_eq!(decision["params"]["decision"], json!("allow"));
        assert_eq!(decision["params"]["scope"], json!("session"));
        assert_eq!(decision["params"]["decided_by"], json!("alice"));
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
        if MODE == "notification_before_preflight":
            write_message({
                "jsonrpc": "2.0",
                "method": "event/activity",
                "params": {
                    "ts": "2026-04-26T12:00:03Z",
                    "kind": "mcp_tool_call",
                    "env": "demo",
                    "actor": {"driver": "fixture"},
                    "subject": {"tool": "search"},
                    "result": "ok",
                    "trace_id": "trace-fixture",
                    "extras": {},
                },
            })
        if MODE == "approval_before_preflight":
            write_message({
                "jsonrpc": "2.0",
                "method": "event/approval_requested",
                "params": {
                    "request_id": "req-1",
                    "kind": "egress_host",
                    "subject": "api.example.test:443",
                    "reason": "network",
                    "context": {},
                    "default_ttl": "session",
                },
            })
            decision = read_message()
            decision_file = os.environ["JSONRPC_FIXTURE_DECISION_FILE"]
            with open(decision_file, "w", encoding="utf-8") as handle:
                json.dump(decision, handle, separators=(",", ":"))
                handle.flush()
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

    async fn wait_for_approval_request(
        coordinator: &agentenv_approvals::ApprovalCoordinator,
        request_id: &str,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if coordinator
                .store()
                .get_request(request_id)
                .unwrap()
                .is_some()
            {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("approval request {request_id} was not submitted");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
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
