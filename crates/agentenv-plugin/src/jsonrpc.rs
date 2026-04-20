use std::io::{BufRead, Read, Write};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

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
