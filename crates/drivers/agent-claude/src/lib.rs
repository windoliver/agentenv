#![forbid(unsafe_code)]

use agentenv_core::agent_common::{version_probe, AgentMode, SharedAgentConfig};
use agentenv_core::driver::{AgentDriver, DriverError, DriverResult};
use agentenv_proto::{
    assert_compatible_schema_version, AgentCapabilities, AgentHealthCheckProbe, AgentSpec,
    Capabilities, CredentialKind, CredentialRequirement, CredentialRequirementsResult,
    DockerfileFragment, DriverInfo, DriverKind, EmptyResult, InitializeParams, InitializeResult,
    InstallStepsResult, McpConfigPathParams, McpConfigPathResult, McpTransport, PreflightParams,
    PreflightResult, RenderEntrypointResult, RenderMcpConfigParams, RenderMcpConfigResult,
    ShutdownParams, SCHEMA_VERSION,
};
use async_trait::async_trait;
use serde_json::{Map, Value};

const DRIVER_NAME: &str = "claude";
const CLAUDE_MCP_CONFIG_PATH: &str = "~/.claude/mcp_servers.json";
const CLAUDE_PACKAGE: &str = "@anthropic-ai/claude-code";

#[derive(Debug, Clone, Default)]
pub struct ClaudeDriver;

#[async_trait]
impl AgentDriver for ClaudeDriver {
    async fn initialize(&mut self, params: InitializeParams) -> DriverResult<InitializeResult> {
        assert_compatible_schema_version(&params.schema_version)?;

        Ok(InitializeResult {
            driver: DriverInfo {
                name: DRIVER_NAME.to_owned(),
                kind: DriverKind::Agent,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: SCHEMA_VERSION.to_owned(),
            },
            capabilities: Capabilities::Agent(AgentCapabilities {
                supports_mcp: true,
                supports_slash_commands: true,
                supports_tui: true,
                supports_headless: true,
            }),
        })
    }

    async fn preflight(&self, _params: PreflightParams) -> DriverResult<PreflightResult> {
        Ok(PreflightResult {
            ok: true,
            issues: Vec::new(),
        })
    }

    async fn install_steps(&self, _spec: AgentSpec) -> DriverResult<InstallStepsResult> {
        Ok(InstallStepsResult {
            steps: vec![DockerfileFragment {
                name: Some("install-claude".to_owned()),
                content: format!("RUN npm install -g {CLAUDE_PACKAGE}"),
            }],
        })
    }

    async fn mcp_config_path(
        &self,
        _params: McpConfigPathParams,
    ) -> DriverResult<McpConfigPathResult> {
        Ok(McpConfigPathResult {
            path: CLAUDE_MCP_CONFIG_PATH.to_owned(),
        })
    }

    async fn render_mcp_config(
        &self,
        params: RenderMcpConfigParams,
    ) -> DriverResult<RenderMcpConfigResult> {
        let mut mcp_servers = Map::new();

        for (index, endpoint) in params.endpoints.into_iter().enumerate() {
            let mut server = Map::new();
            match endpoint.transport {
                McpTransport::Stdio => {
                    server.insert("command".to_owned(), Value::String(endpoint.url));
                }
                McpTransport::Http | McpTransport::HttpSse | McpTransport::SshHttp => {
                    server.insert("url".to_owned(), Value::String(endpoint.url));
                    server.insert(
                        "transport".to_owned(),
                        Value::String(transport_name(endpoint.transport).to_owned()),
                    );
                }
            }

            if !endpoint.headers.is_empty() {
                server.insert(
                    "headers".to_owned(),
                    serde_json::to_value(endpoint.headers)
                        .unwrap_or_else(|_| Value::Object(Map::new())),
                );
            }

            mcp_servers.insert(format!("endpoint_{index}"), Value::Object(server));
        }

        let mut config = Map::new();
        config.insert("mcpServers".to_owned(), Value::Object(mcp_servers));

        let content = serde_json::to_string_pretty(&Value::Object(config))
            .unwrap_or_else(|_| "{\"mcpServers\":{}}".to_owned());

        Ok(RenderMcpConfigResult { content })
    }

    async fn render_entrypoint(&self, spec: AgentSpec) -> DriverResult<RenderEntrypointResult> {
        let config = shared_config(spec)?;
        let command = match config.mode {
            AgentMode::Tui => "claude",
            AgentMode::Headless => "claude --headless",
        };

        Ok(RenderEntrypointResult {
            content: format!("#!/usr/bin/env sh\nset -eu\nexec {command} \"$@\"\n"),
        })
    }

    async fn credential_requirements(
        &self,
        _spec: AgentSpec,
    ) -> DriverResult<CredentialRequirementsResult> {
        Ok(CredentialRequirementsResult {
            requirements: vec![CredentialRequirement {
                name: "ANTHROPIC_API_KEY".to_owned(),
                kind: CredentialKind::ApiKey,
                required: true,
                description: "Anthropic API key used by Claude Code.".to_owned(),
                validator: None,
            }],
        })
    }

    async fn health_check_probe(&self, _spec: AgentSpec) -> DriverResult<AgentHealthCheckProbe> {
        Ok(version_probe(DRIVER_NAME))
    }

    async fn shutdown(&mut self, _params: ShutdownParams) -> DriverResult<EmptyResult> {
        Ok(EmptyResult::default())
    }
}

fn shared_config(spec: AgentSpec) -> DriverResult<SharedAgentConfig> {
    let config_value = Value::Object(spec.config.into_iter().collect());
    serde_json::from_value(config_value).map_err(|err| DriverError::CapabilityMissing {
        capability: format!("valid shared agent config ({err})"),
    })
}

fn transport_name(transport: McpTransport) -> &'static str {
    match transport {
        McpTransport::Stdio => "stdio",
        McpTransport::Http => "http",
        McpTransport::HttpSse => "http+sse",
        McpTransport::SshHttp => "ssh+http",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_core::driver::AgentDriver;
    use agentenv_proto::{
        AgentSpec, Capabilities, CredentialKind, DriverKind, InitializeParams, LogLevel,
        McpConfigPathParams, McpEndpoint, McpTransport, PreflightParams, RenderMcpConfigParams,
        SCHEMA_VERSION,
    };
    use serde_json::Value;

    use super::ClaudeDriver;

    fn agent_spec(config: BTreeMap<String, Value>) -> AgentSpec {
        AgentSpec {
            version: None,
            config,
        }
    }

    #[tokio::test]
    async fn claude_driver_satisfies_agent_conformance_contract() {
        let mut driver = ClaudeDriver::default();

        driver_conformance::assert_agent_driver_contract(&mut driver, agent_spec(BTreeMap::new()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn claude_driver_initializes_with_agent_capabilities() {
        let mut driver = ClaudeDriver::default();

        let result = driver
            .initialize(InitializeParams {
                schema_version: SCHEMA_VERSION.to_owned(),
                core_version: "0.0.1-test".to_owned(),
                workdir: "/tmp/agentenv-test".to_owned(),
                log_level: LogLevel::Info,
            })
            .await
            .unwrap();

        assert_eq!(result.driver.name, "claude");
        assert_eq!(result.driver.kind, DriverKind::Agent);
        assert_eq!(result.driver.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(result.driver.protocol_version, SCHEMA_VERSION);

        let Capabilities::Agent(capabilities) = result.capabilities else {
            panic!("claude should report agent capabilities");
        };
        assert!(capabilities.supports_mcp);
        assert!(capabilities.supports_slash_commands);
        assert!(capabilities.supports_tui);
        assert!(capabilities.supports_headless);
    }

    #[tokio::test]
    async fn claude_driver_preflight_has_no_issues_for_now() {
        let driver = ClaudeDriver::default();

        let result = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(result.ok);
        assert!(result.issues.is_empty());
    }

    #[tokio::test]
    async fn claude_driver_reports_install_step_and_mcp_path() {
        let driver = ClaudeDriver::default();
        let spec = agent_spec(BTreeMap::new());

        let install_steps = driver.install_steps(spec).await.unwrap();
        let mcp_path = driver
            .mcp_config_path(McpConfigPathParams::default())
            .await
            .unwrap();

        assert_eq!(install_steps.steps.len(), 1);
        assert_eq!(
            install_steps.steps[0].content,
            "RUN npm install -g @anthropic-ai/claude-code"
        );
        assert_eq!(mcp_path.path, "~/.claude/mcp_servers.json");
    }

    #[tokio::test]
    async fn claude_driver_reports_anthropic_credential_and_probe() {
        let driver = ClaudeDriver::default();
        let spec = agent_spec(BTreeMap::new());

        let credentials = driver.credential_requirements(spec.clone()).await.unwrap();
        let probe = driver.health_check_probe(spec).await.unwrap();

        assert_eq!(credentials.requirements.len(), 1);
        assert_eq!(credentials.requirements[0].name, "ANTHROPIC_API_KEY");
        assert_eq!(credentials.requirements[0].kind, CredentialKind::ApiKey);
        assert!(credentials.requirements[0].required);
        assert_eq!(probe.cmd, "claude --version");
    }

    #[tokio::test]
    async fn claude_driver_renders_tui_entrypoint_by_default() {
        let driver = ClaudeDriver::default();
        let spec = agent_spec(BTreeMap::new());

        let entrypoint = driver.render_entrypoint(spec).await.unwrap();

        assert_eq!(
            entrypoint.content,
            "#!/usr/bin/env sh\nset -eu\nexec claude \"$@\"\n"
        );
    }

    #[tokio::test]
    async fn claude_driver_renders_headless_entrypoint() {
        let driver = ClaudeDriver::default();
        let spec = agent_spec(BTreeMap::from([(
            "mode".to_owned(),
            serde_json::json!("headless"),
        )]));

        let entrypoint = driver.render_entrypoint(spec).await.unwrap();

        assert_eq!(
            entrypoint.content,
            "#!/usr/bin/env sh\nset -eu\nexec claude --headless \"$@\"\n"
        );
    }

    #[tokio::test]
    async fn claude_driver_rejects_invalid_entrypoint_config() {
        let driver = ClaudeDriver::default();
        let spec = agent_spec(BTreeMap::from([(
            "mode".to_owned(),
            serde_json::json!("headles"),
        )]));

        let err = driver
            .render_entrypoint(spec)
            .await
            .expect_err("invalid mode should not fall back to TUI");

        assert!(err.to_string().contains("valid shared agent config"));
    }

    #[tokio::test]
    async fn claude_driver_renders_deterministic_mcp_json() {
        let driver = ClaudeDriver::default();

        let rendered = driver
            .render_mcp_config(RenderMcpConfigParams {
                endpoints: vec![
                    McpEndpoint {
                        url: "agentenv-context".to_owned(),
                        transport: McpTransport::Stdio,
                        headers: BTreeMap::new(),
                    },
                    McpEndpoint {
                        url: "https://context.example.test/mcp".to_owned(),
                        transport: McpTransport::HttpSse,
                        headers: BTreeMap::from([
                            ("Authorization".to_owned(), "Bearer test".to_owned()),
                            ("X-Agentenv".to_owned(), "true".to_owned()),
                        ]),
                    },
                ],
            })
            .await
            .unwrap();

        let parsed: Value = serde_json::from_str(&rendered.content).unwrap();
        assert_eq!(
            parsed,
            serde_json::json!({
                "mcpServers": {
                    "endpoint_0": {
                        "command": "agentenv-context"
                    },
                    "endpoint_1": {
                        "headers": {
                            "Authorization": "Bearer test",
                            "X-Agentenv": "true"
                        },
                        "transport": "http+sse",
                        "url": "https://context.example.test/mcp"
                    }
                }
            })
        );
        assert_eq!(
            rendered.content,
            "{\n  \"mcpServers\": {\n    \"endpoint_0\": {\n      \"command\": \"agentenv-context\"\n    },\n    \"endpoint_1\": {\n      \"headers\": {\n        \"Authorization\": \"Bearer test\",\n        \"X-Agentenv\": \"true\"\n      },\n      \"transport\": \"http+sse\",\n      \"url\": \"https://context.example.test/mcp\"\n    }\n  }\n}"
        );
    }
}
