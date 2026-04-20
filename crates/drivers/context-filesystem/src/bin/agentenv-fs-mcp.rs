use std::{
    env,
    io::{self, BufRead, BufReader, Write},
    path::PathBuf,
};

use context_filesystem::{FilesystemMcpServer, ToolCall};
use serde_json::{json, Value};

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

fn main() {
    let args: Vec<String> = env::args().collect();
    let Ok(config) = parse_args(&args) else {
        eprintln!("usage: agentenv-fs-mcp --root <path> [--readonly] [--exclude <pattern>]...");
        std::process::exit(2);
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    while let Ok(request) = read_framed_json(&mut reader) {
        let response = handle_request(
            config.root.clone(),
            config.readonly,
            config.exclude.clone(),
            request,
        );
        if write_framed_json(&mut writer, &response).is_err() {
            break;
        }
    }
}

#[derive(Debug, Clone)]
struct CliConfig {
    root: PathBuf,
    readonly: bool,
    exclude: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<CliConfig, String> {
    let mut root = None;
    let mut readonly = false;
    let mut exclude = Vec::new();
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--root" => {
                index += 1;
                root = Some(PathBuf::from(required_value(args, index, "--root")?));
            }
            "--readonly" => readonly = true,
            "--exclude" => {
                index += 1;
                exclude.push(required_value(args, index, "--exclude")?);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
        index += 1;
    }

    Ok(CliConfig {
        root: root.ok_or_else(|| "--root is required".to_owned())?,
        readonly,
        exclude,
    })
}

fn required_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    let value = args
        .get(index)
        .ok_or_else(|| format!("{flag} requires a value"))?;
    if value.trim().is_empty() || is_flag_token(value) {
        return Err(format!("{flag} requires a value"));
    }
    Ok(value.clone())
}

fn is_flag_token(value: &str) -> bool {
    matches!(value, "--root" | "--readonly" | "--exclude")
}

pub fn handle_request(
    root: PathBuf,
    readonly: bool,
    exclude: Vec<String>,
    request: Value,
) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");

    match method {
        "initialize" => success(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentenv-fs-mcp", "version": env!("CARGO_PKG_VERSION")}
            }),
        ),
        "tools/list" => match FilesystemMcpServer::new(root, readonly, exclude) {
            Ok(server) => success(id, json!({"tools": server.tools_list()})),
            Err(err) => error(id, -32603, err.to_string()),
        },
        "tools/call" => {
            let Some(params) = request.get("params") else {
                return error(id, -32602, "missing params".to_owned());
            };
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return error(id, -32602, "missing tool name".to_owned());
            };
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match FilesystemMcpServer::new(root, readonly, exclude).and_then(|server| {
                server.call_tool(ToolCall {
                    name: name.to_owned(),
                    arguments,
                })
            }) {
                Ok(result) => success(id, result),
                Err(err) => error(id, -32602, err.to_string()),
            }
        }
        _ => error(id, -32601, format!("unknown method `{method}`")),
    }
}

fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

pub fn write_framed_json<W: Write>(writer: &mut W, message: &Value) -> io::Result<()> {
    let payload = serde_json::to_vec(message).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("serialize JSON: {err}"))
    })?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()
}

pub fn read_framed_json<R: BufRead>(reader: &mut R) -> io::Result<Value> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing JSON-RPC header",
            ));
        }
        if line == "\r\n" {
            break;
        }
        if let Some(raw) = line.strip_prefix("Content-Length: ") {
            content_length = Some(raw.trim().parse::<usize>().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Content-Length: {err}"),
                )
            })?);
        }
    }

    let length = content_length.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length header")
    })?;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Content-Length too large: {length} bytes"),
        ));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid JSON payload: {err}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use serde_json::json;

    use super::{handle_request, parse_args, read_framed_json, write_framed_json, MAX_FRAME_BYTES};

    #[test]
    fn framed_json_round_trips() {
        let mut bytes = Vec::new();
        write_framed_json(&mut bytes, &json!({"jsonrpc": "2.0", "id": 1})).unwrap();
        let mut reader = BufReader::new(Cursor::new(bytes));

        let value = read_framed_json(&mut reader).unwrap();

        assert_eq!(value, json!({"jsonrpc": "2.0", "id": 1}));
    }

    #[test]
    fn read_framed_json_rejects_oversized_content_length() {
        let too_large = MAX_FRAME_BYTES + 1;
        let bytes = format!("Content-Length: {too_large}\r\n\r\n");
        let mut reader = BufReader::new(Cursor::new(bytes.into_bytes()));

        let err = read_framed_json(&mut reader).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn parse_args_rejects_root_followed_by_flag_token() {
        let args = vec![
            "agentenv-fs-mcp".to_owned(),
            "--root".to_owned(),
            "--readonly".to_owned(),
        ];

        let err = parse_args(&args).unwrap_err();

        assert!(err.contains("--root"));
    }

    #[test]
    fn parse_args_rejects_exclude_followed_by_flag_token() {
        let args = vec![
            "agentenv-fs-mcp".to_owned(),
            "--root".to_owned(),
            ".".to_owned(),
            "--exclude".to_owned(),
            "--readonly".to_owned(),
        ];

        let err = parse_args(&args).unwrap_err();

        assert!(err.contains("--exclude"));
    }

    #[test]
    fn initialize_request_returns_server_info() {
        let tmp = tempfile::tempdir().unwrap();
        let response = handle_request(
            tmp.path().to_path_buf(),
            true,
            Vec::new(),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }),
        );

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["serverInfo"]["name"], "agentenv-fs-mcp");
    }

    #[test]
    fn tools_call_fs_read_returns_json_rpc_result() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("note.txt"), "hello").unwrap();
        let response = handle_request(
            tmp.path().to_path_buf(),
            true,
            Vec::new(),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "fs_read",
                    "arguments": {"path": "note.txt"}
                }
            }),
        );

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 2);
        assert_eq!(response["result"], json!({"content": "hello"}));
    }
}
