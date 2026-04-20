use std::fs;
use std::path::Path;

use schemars::{schema_for, JsonSchema};

#[allow(dead_code)]
#[path = "src/types.rs"]
mod types;

fn main() {
    println!("cargo:rerun-if-changed=src/types.rs");
    println!("cargo:rerun-if-changed=src/schema_version.rs");

    let schema_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema");
    fs::create_dir_all(&schema_dir).expect("create schema directory");

    write_schema::<types::InitializeParams>(&schema_dir, "initialize-params");
    write_schema::<types::InitializeResult>(&schema_dir, "initialize-result");
    write_schema::<types::PreflightParams>(&schema_dir, "preflight-params");
    write_schema::<types::PreflightResult>(&schema_dir, "preflight-result");
    write_schema::<types::ShutdownParams>(&schema_dir, "shutdown-params");
    write_schema::<types::EmptyResult>(&schema_dir, "empty-result");
    write_schema::<types::Capabilities>(&schema_dir, "capabilities");
    // Canonical policy model surfaces.
    write_schema::<types::NetworkPolicy>(&schema_dir, "network-policy");
    write_schema::<types::McpEndpoint>(&schema_dir, "mcp-endpoint");
    write_schema::<types::SandboxSpec>(&schema_dir, "sandbox-spec");
    write_schema::<types::SandboxHandle>(&schema_dir, "sandbox-handle");
    write_schema::<types::ConnectParams>(&schema_dir, "connect-params");
    write_schema::<types::ShellHandle>(&schema_dir, "shell-handle");
    write_schema::<types::ExecParams>(&schema_dir, "exec-params");
    write_schema::<types::ExecResult>(&schema_dir, "exec-result");
    write_schema::<types::CopyInParams>(&schema_dir, "copy-in-params");
    write_schema::<types::CopyOutParams>(&schema_dir, "copy-out-params");
    write_schema::<types::ApplyPolicyParams>(&schema_dir, "apply-policy-params");
    write_schema::<types::ApplyPolicyResult>(&schema_dir, "apply-policy-result");
    write_schema::<types::SandboxStatusParams>(&schema_dir, "sandbox-status-params");
    write_schema::<types::SandboxStatus>(&schema_dir, "sandbox-status");
    write_schema::<types::LogsParams>(&schema_dir, "logs-params");
    write_schema::<types::LogsResult>(&schema_dir, "logs-result");
    write_schema::<types::LogsStreamParams>(&schema_dir, "logs-stream-params");
    write_schema::<types::StopParams>(&schema_dir, "stop-params");
    write_schema::<types::DestroyParams>(&schema_dir, "destroy-params");
    write_schema::<types::AgentSpec>(&schema_dir, "agent-spec");
    write_schema::<types::InstallStepsResult>(&schema_dir, "install-steps-result");
    write_schema::<types::McpConfigPathParams>(&schema_dir, "mcp-config-path-params");
    write_schema::<types::McpConfigPathResult>(&schema_dir, "mcp-config-path-result");
    write_schema::<types::RenderMcpConfigParams>(&schema_dir, "render-mcp-config-params");
    write_schema::<types::RenderMcpConfigResult>(&schema_dir, "render-mcp-config-result");
    write_schema::<types::RenderEntrypointResult>(&schema_dir, "render-entrypoint-result");
    write_schema::<types::CredentialRequirementsParams>(
        &schema_dir,
        "credential-requirements-params",
    );
    write_schema::<types::AgentSpec>(&schema_dir, "agent-credential-requirements-params");
    write_schema::<types::CredentialRequirementsResult>(
        &schema_dir,
        "credential-requirements-result",
    );
    write_schema::<types::AgentHealthCheckProbe>(&schema_dir, "agent-health-check-probe");
    write_schema::<types::ContextSpec>(&schema_dir, "context-spec");
    write_schema::<types::ContextHandle>(&schema_dir, "context-handle");
    write_schema::<types::ContextHandleRequest>(&schema_dir, "context-handle-request");
    write_schema::<types::RequiredNetworkRulesResult>(&schema_dir, "required-network-rules-result");
    write_schema::<types::ContextStatus>(&schema_dir, "context-status");
    write_schema::<types::InferenceSpec>(&schema_dir, "inference-spec");
    write_schema::<types::InferenceHandle>(&schema_dir, "inference-handle");
    write_schema::<types::InferenceHandleRequest>(&schema_dir, "inference-handle-request");
    write_schema::<types::EndpointInSandboxResult>(&schema_dir, "endpoint-in-sandbox-result");
    write_schema::<types::EventLogParams>(&schema_dir, "event-log-params");
    write_schema::<types::ActivityEventParams>(&schema_dir, "activity-event-params");
    write_schema::<types::ApprovalRequestedParams>(&schema_dir, "approval-requested-params");
    write_schema::<types::ApprovalDecisionParams>(&schema_dir, "approval-decision-params");
}

fn write_schema<T: JsonSchema>(schema_dir: &Path, name: &str) {
    let schema = schema_for!(T);
    let content = format!(
        "{}\n",
        serde_json::to_string_pretty(&schema).expect("serialize schema")
    );
    let path = schema_dir.join(format!("{name}.json"));

    if fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
        fs::write(path, content).expect("write schema file");
    }
}
