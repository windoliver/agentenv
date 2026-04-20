use std::io::{BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

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
    #[error("invalid JSON-RPC response: {0}")]
    InvalidResponse(String),
    #[error("JSON-RPC frame length {length} exceeds maximum {max}")]
    FrameTooLarge { length: usize, max: usize },
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::{
        read_framed_json_blocking, write_framed_json_blocking, JsonRpcError,
        RpcResponseEnvelope, DEFAULT_MAX_FRAME_BYTES,
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
        let envelope: RpcResponseEnvelope = serde_json::from_value(raw).unwrap();

        let err = envelope.validate_result_state().unwrap_err();
        assert!(matches!(err, JsonRpcError::InvalidResponse(_)));
    }

    #[test]
    fn response_envelope_rejects_both_result_and_error() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"ok": true},
            "error": {"code": -1, "message": "bad"}
        });
        let envelope: RpcResponseEnvelope = serde_json::from_value(raw).unwrap();

        let err = envelope.validate_result_state().unwrap_err();
        assert!(matches!(err, JsonRpcError::InvalidResponse(_)));
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
}
