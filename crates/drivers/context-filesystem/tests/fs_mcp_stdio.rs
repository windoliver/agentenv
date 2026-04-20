use std::io::{self, BufRead, BufReader, Write};

use serde_json::Value;

#[test]
fn process_smoke_reads_file_over_stdio() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("note.txt"), "hello").unwrap();
    let binary = env!("CARGO_BIN_EXE_agentenv-fs-mcp");
    let mut child = std::process::Command::new(binary)
        .arg("--root")
        .arg(tmp.path())
        .arg("--readonly")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "fs_read", "arguments": {"path": "note.txt"}}
    });
    write_framed_json(child.stdin.as_mut().unwrap(), &request).unwrap();
    drop(child.stdin.take());

    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let response = read_framed_json(&mut reader).unwrap();
    let status = child.wait().unwrap();

    assert!(status.success());
    assert_eq!(response["result"], serde_json::json!({"content": "hello"}));
}

fn write_framed_json<W: Write>(writer: &mut W, message: &Value) -> io::Result<()> {
    let payload = serde_json::to_vec(message).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("serialize JSON: {err}"))
    })?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn read_framed_json<R: BufRead>(reader: &mut R) -> io::Result<Value> {
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
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid JSON payload: {err}"),
        )
    })
}
