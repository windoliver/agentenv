use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    process::{Command, Stdio},
};

use agentenv_mcp::guard::{GuardAction, GuardDecision, GuardReason, GuardSessionState};
use agentenv_proto::{McpApprovalMode, McpGuardConfig};
use anyhow::{Context, Result};
use serde_json::{json, Value};

pub(crate) async fn run(args: crate::McpGuardArgs) -> Result<()> {
    match args.command {
        crate::McpGuardCommand::Run(args) => {
            tokio::task::spawn_blocking(move || run_blocking(args))
                .await
                .context("join MCP stdio guard task")?
        }
    }
}

fn run_blocking(args: crate::McpGuardRunArgs) -> Result<()> {
    let _events_db = args.events_db;
    let config: McpGuardConfig = serde_json::from_slice(
        &fs::read(&args.config)
            .with_context(|| format!("read MCP guard config `{}`", args.config.display()))?,
    )
    .with_context(|| format!("parse MCP guard config `{}`", args.config.display()))?;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&args.stdio_upstream)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn MCP stdio upstream `{}`", args.stdio_upstream))?;
    let mut child_stdin = child.stdin.take().context("open upstream stdin")?;
    let child_stdout = child.stdout.take().context("open upstream stdout")?;
    let mut child_stdout = BufReader::new(child_stdout);
    let stdin = io::stdin();
    let mut stdin = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut state = GuardSessionState::default();

    while let Some(body) = read_lsp_message(&mut stdin)? {
        let decision = evaluate_client_message(&config, &mut state, &body);
        match decision.action {
            GuardAction::Deny | GuardAction::RequestApproval => {
                let id = json_rpc_id(&body);
                let response = json_rpc_error_response(id, -32004, "MCP tool call denied by guard");
                write_lsp_message(&mut stdout, &response)?;
                stdout.flush().context("flush guarded MCP response")?;
            }
            GuardAction::Forward | GuardAction::NotToolCall => {
                write_lsp_message(&mut child_stdin, &body)?;
                child_stdin.flush().context("flush upstream MCP request")?;
                let Some(response) = read_lsp_message(&mut child_stdout)? else {
                    break;
                };
                write_lsp_message(&mut stdout, &response)?;
                stdout.flush().context("flush upstream MCP response")?;
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

pub(crate) fn read_lsp_message<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut content_length = None;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .context("read MCP frame header")?;
        if bytes == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .context("parse MCP frame content length")?,
                );
            }
        }
    }

    let length = content_length.context("MCP frame missing Content-Length header")?;
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .context("read MCP frame body")?;
    Ok(Some(body))
}

pub(crate) fn write_lsp_message<W: Write>(writer: &mut W, body: &[u8]) -> Result<()> {
    write!(writer, "Content-Length: {}\r\n\r\n", body.len()).context("write MCP frame header")?;
    writer.write_all(body).context("write MCP frame body")?;
    Ok(())
}

pub(crate) fn evaluate_client_message(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    body: &[u8],
) -> GuardDecision {
    let request = match serde_json::from_slice::<Value>(body) {
        Ok(request) => request,
        Err(error) => {
            return malformed_decision(format!("invalid JSON-RPC body: {error}"));
        }
    };
    match agentenv_mcp::guard::evaluate_json_rpc_request(config, state, &request) {
        Ok(decision) => decision,
        Err(error) => malformed_decision(error.to_string()),
    }
}

pub(crate) fn json_rpc_error_response(id: Value, code: i64, message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    }))
    .unwrap_or_else(|_| {
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"internal error\"}}"
            .to_vec()
    })
}

fn malformed_decision(message: String) -> GuardDecision {
    GuardDecision {
        action: GuardAction::Deny,
        reason: GuardReason::MalformedToolCall,
        tool_name: None,
        matched_policy: None,
        approval_mode: McpApprovalMode::Never,
        redacted_event_context: json!({ "error": message }),
    }
}

fn json_rpc_id(body: &[u8]) -> Value {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsp_message_round_trips_body() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let mut out = Vec::new();
        write_lsp_message(&mut out, body).unwrap();

        let decoded = read_lsp_message(&mut std::io::BufReader::new(out.as_slice()))
            .unwrap()
            .unwrap();

        assert_eq!(decoded, body);
    }
}
