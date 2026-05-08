use std::io::{BufReader, BufWriter};

use agentenv_proto::{
    assert_compatible_schema_version, Capabilities, DriverInfo, DriverKind, EmptyResult,
    InitializeParams, InitializeResult, PreflightParams, PreflightResult, SandboxCapabilities,
    ERROR_SCHEMA_VERSION_INCOMPATIBLE, JSON_RPC_METHOD_NOT_FOUND, SCHEMA_VERSION,
};
use anyhow::{Context, Result};
use driver_conformance::{
    read_framed_json, write_framed_json, RpcError, RpcRequestEnvelope, RpcResponseEnvelope,
};
use serde::de::DeserializeOwned;
use serde_json::{json, to_value, Value};

fn main() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    loop {
        let raw = match read_framed_json(&mut reader) {
            Ok(value) => value,
            Err(err) if err.to_string().contains("unexpected EOF") => break,
            Err(err) => return Err(err),
        };
        let request: RpcRequestEnvelope =
            serde_json::from_value(raw).context("decode JSON-RPC request")?;
        let should_exit = request.method == "shutdown";
        for notification in notifications_for_request(&request) {
            write_framed_json(&mut writer, &notification)?;
        }
        let response = handle_request(request)?;
        write_framed_json(&mut writer, &response)?;
        if should_exit && response.error.is_none() {
            break;
        }
    }

    Ok(())
}

fn notifications_for_request(request: &RpcRequestEnvelope) -> Vec<Value> {
    if request.method != "preflight" {
        return Vec::new();
    }

    vec![
        json!({
            "jsonrpc": "2.0",
            "method": "event/log",
            "params": {
                "level": "info",
                "ts": "2026-04-26T12:00:00Z",
                "msg": "mock preflight completed",
                "kv": {
                    "driver": "mock-driver",
                    "phase": "preflight"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "event/activity",
            "params": {
                "ts": "2026-04-26T12:00:00Z",
                "kind": "sandbox_create",
                "actor": {"driver": "mock-driver"},
                "subject": {"phase": "preflight"},
                "result": "ok",
                "trace_id": "trace-mock-driver",
                "extras": {"source": "driver-conformance"}
            }
        }),
    ]
}

fn handle_request(request: RpcRequestEnvelope) -> Result<RpcResponseEnvelope> {
    match request.method.as_str() {
        "initialize" => {
            let params: InitializeParams = decode_params(&request.params)?;
            let response = match assert_compatible_schema_version(&params.schema_version) {
                Ok(()) => success(
                    request.id,
                    InitializeResult {
                        driver: DriverInfo {
                            name: "mock-driver".to_owned(),
                            kind: DriverKind::Sandbox,
                            version: "0.0.1".to_owned(),
                            protocol_version: SCHEMA_VERSION.to_owned(),
                        },
                        capabilities: Capabilities::Sandbox(SandboxCapabilities {
                            supports_hot_reload_policy: true,
                            supports_filesystem_lockdown: true,
                            supports_syscall_filter: true,
                            supports_native_inference_routing: false,
                            supports_remote_host: false,
                            supports_persistent_sessions: false,
                            supports_snapshots: false,
                            supports_fork: false,
                        }),
                    },
                )?,
                Err(err) => error(
                    request.id,
                    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
                    err.to_string(),
                    Some(to_value(err).context("encode schema mismatch error payload")?),
                ),
            };

            Ok(response)
        }
        "preflight" => {
            let _: PreflightParams = decode_params(&request.params)?;
            success(
                request.id,
                PreflightResult {
                    ok: true,
                    issues: Vec::new(),
                },
            )
        }
        "shutdown" => success(request.id, EmptyResult {}),
        _ => Ok(error(
            request.id,
            JSON_RPC_METHOD_NOT_FOUND,
            format!("method `{}` not found", request.method),
            None,
        )),
    }
}

fn decode_params<T: DeserializeOwned>(value: &Value) -> Result<T> {
    serde_json::from_value(value.clone()).context("decode JSON-RPC params")
}

fn success<T: serde::Serialize>(id: Value, result: T) -> Result<RpcResponseEnvelope> {
    Ok(RpcResponseEnvelope {
        jsonrpc: "2.0".to_owned(),
        id,
        result: Some(to_value(result).context("encode JSON-RPC result")?),
        error: None,
    })
}

fn error(id: Value, code: i64, message: String, data: Option<Value>) -> RpcResponseEnvelope {
    RpcResponseEnvelope {
        jsonrpc: "2.0".to_owned(),
        id,
        result: None,
        error: Some(RpcError {
            code,
            message,
            data,
        }),
    }
}
