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
        let evaluation = evaluate_client_message(&config, &mut state, &body);
        match evaluation.decision.action {
            GuardAction::Deny | GuardAction::RequestApproval => {
                let id = json_rpc_id(&body);
                let response = guarded_error_response(id, &evaluation.decision);
                write_lsp_message(&mut stdout, &response)?;
                stdout.flush().context("flush guarded MCP response")?;
            }
            GuardAction::Forward | GuardAction::NotToolCall => {
                let forwarded = serde_json::to_vec(&evaluation.forwarded_request)
                    .context("serialize guarded MCP request")?;
                write_lsp_message(&mut child_stdin, &forwarded)?;
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
) -> agentenv_mcp::guard::GuardEvaluation {
    let request = match serde_json::from_slice::<Value>(body) {
        Ok(request) => request,
        Err(error) => {
            let decision = malformed_decision(format!("invalid JSON-RPC body: {error}"));
            return agentenv_mcp::guard::GuardEvaluation {
                decision,
                forwarded_request: Value::Null,
            };
        }
    };
    match agentenv_mcp::guard::evaluate_json_rpc_request_with_forwarding(config, state, &request) {
        Ok(evaluation) => evaluation,
        Err(error) => {
            let decision = malformed_decision(error.to_string());
            agentenv_mcp::guard::GuardEvaluation {
                decision,
                forwarded_request: request,
            }
        }
    }
}

pub(crate) fn guarded_error_response(id: Value, decision: &GuardDecision) -> Vec<u8> {
    let reason = guard_reason_code(decision.reason);
    let provenance = decision.redacted_event_context.get("provenance");
    let observed_taint = provenance
        .and_then(|value| value.get("observed_taint"))
        .cloned()
        .unwrap_or(Value::Null);
    let max_input_taint = provenance
        .and_then(|value| value.get("max_input_taint"))
        .cloned()
        .unwrap_or(Value::Null);

    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32004,
            "message": "MCP tool call blocked by guard",
            "data": {
                "reason": reason,
                "tool_name": decision.tool_name,
                "observed_taint": observed_taint,
                "max_input_taint": max_input_taint,
            }
        }
    }))
    .unwrap_or_else(|_| {
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"internal error\"}}"
            .to_vec()
    })
}

fn guard_reason_code(reason: GuardReason) -> &'static str {
    match reason {
        GuardReason::Disabled => "mcp_guard_disabled",
        GuardReason::NotToolCall => "mcp_not_tool_call",
        GuardReason::AllowedByPolicy => "mcp_allowed_by_policy",
        GuardReason::ApprovalRequired => "mcp_approval_required",
        GuardReason::UrlAllowlistViolation => "mcp_url_allowlist_violation",
        GuardReason::CredentialLikeArgument => "mcp_credential_like_argument",
        GuardReason::EnvVarLikeArgument => "mcp_env_var_like_argument",
        GuardReason::RateLimited => "mcp_rate_limited",
        GuardReason::CrossToolFlow => "mcp_cross_tool_flow",
        GuardReason::MalformedToolCall => "mcp_malformed_tool_call",
        GuardReason::ProvenanceTaint => "mcp_provenance_taint",
    }
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

    #[test]
    fn provenance_denial_returns_structured_json_rpc_error() {
        let decision = GuardDecision {
            action: GuardAction::Deny,
            reason: GuardReason::ProvenanceTaint,
            tool_name: Some("git.commit".to_owned()),
            matched_policy: Some("git.commit".to_owned()),
            approval_mode: McpApprovalMode::PerCall,
            redacted_event_context: json!({
                "provenance": {
                    "observed_taint": "untrusted",
                    "max_input_taint": "trusted"
                }
            }),
        };

        let body = guarded_error_response(json!(1), &decision);
        let value: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["error"]["code"], json!(-32004));
        assert_eq!(
            value["error"]["data"]["reason"],
            json!("mcp_provenance_taint")
        );
        assert_eq!(value["error"]["data"]["tool_name"], json!("git.commit"));
        assert_eq!(value["error"]["data"]["observed_taint"], json!("untrusted"));
    }

    #[test]
    fn evaluate_client_message_returns_sanitized_forwarded_request_for_allowed_provenance() {
        let config = McpGuardConfig {
            enabled: true,
            provenance: Some(agentenv_proto::McpProvenanceConfig {
                enabled: true,
                required: true,
                default_unannotated_source: agentenv_proto::ProvenanceTag::Untrusted,
            }),
            tool_capabilities: [(
                "filesystem.read".to_owned(),
                agentenv_proto::ToolCapabilityDeclaration {
                    caps: vec![agentenv_proto::ToolCapability::ReadFs],
                    max_input_taint: agentenv_proto::ProvenanceTag::Tenant,
                    approval: McpApprovalMode::Never,
                    argument_policies: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
            ..McpGuardConfig::default()
        };
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "filesystem.read",
                "arguments": {
                    "path": "src/lib.rs"
                },
                "_agentenv_provenance": {
                    "/path": {
                        "tag": "tenant",
                        "source_kind": "local_repo",
                        "source_id": "workspace",
                        "summary": "repo path"
                    }
                }
            }
        }))
        .unwrap();
        let mut state = GuardSessionState::default();

        let evaluation = evaluate_client_message(&config, &mut state, &body);

        assert_eq!(evaluation.decision.action, GuardAction::Forward);
        assert!(evaluation
            .forwarded_request
            .get("params")
            .and_then(Value::as_object)
            .is_some_and(|params| !params.contains_key("_agentenv_provenance")));
    }
}
