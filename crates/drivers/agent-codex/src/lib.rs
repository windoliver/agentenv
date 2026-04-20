#![forbid(unsafe_code)]

use agentenv_core::agent_common::{npm_package_spec, version_probe, AgentMode, SharedAgentConfig};
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
use serde_json::Value;

const DRIVER_NAME: &str = "codex";
const CODEX_MCP_CONFIG_PATH: &str = "~/.codex/config.toml";
const CODEX_PACKAGE: &str = "@openai/codex";

#[derive(Debug, Clone, Default)]
pub struct CodexDriver;

#[async_trait]
impl AgentDriver for CodexDriver {
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

    async fn install_steps(&self, spec: AgentSpec) -> DriverResult<InstallStepsResult> {
        let package = npm_package_spec(CODEX_PACKAGE, spec.version.as_deref())
            .map_err(|err| DriverError::CapabilityMissing { capability: err })?;

        Ok(InstallStepsResult {
            steps: vec![DockerfileFragment {
                name: Some("install-codex".to_owned()),
                content: format!("RUN npm install -g {package}"),
            }],
        })
    }

    async fn mcp_config_path(
        &self,
        _params: McpConfigPathParams,
    ) -> DriverResult<McpConfigPathResult> {
        Ok(McpConfigPathResult {
            path: CODEX_MCP_CONFIG_PATH.to_owned(),
        })
    }

    async fn render_mcp_config(
        &self,
        params: RenderMcpConfigParams,
    ) -> DriverResult<RenderMcpConfigResult> {
        let mut content = String::new();

        for (index, endpoint) in params.endpoints.into_iter().enumerate() {
            if index > 0 {
                content.push('\n');
            }

            content.push_str(&format!("[mcp_servers.endpoint_{index}]\n"));
            match endpoint.transport {
                McpTransport::Stdio => {
                    content.push_str("command = ");
                    push_toml_string(&mut content, &endpoint.url);
                    content.push('\n');
                }
                McpTransport::Http => {
                    content.push_str("url = ");
                    push_toml_string(&mut content, &endpoint.url);
                    content.push('\n');
                }
                transport @ (McpTransport::HttpSse | McpTransport::SshHttp) => {
                    return Err(DriverError::CapabilityMissing {
                        capability: format!(
                            "codex mcp transport {}",
                            mcp_transport_name(transport)
                        ),
                    });
                }
            }

            if !endpoint.headers.is_empty() {
                content.push_str("http_headers = { ");
                for (header_index, (key, value)) in endpoint.headers.iter().enumerate() {
                    if header_index > 0 {
                        content.push_str(", ");
                    }
                    push_toml_string(&mut content, key);
                    content.push_str(" = ");
                    push_toml_string(&mut content, value);
                }
                content.push_str(" }\n");
            }
        }

        Ok(RenderMcpConfigResult { content })
    }

    async fn render_entrypoint(&self, spec: AgentSpec) -> DriverResult<RenderEntrypointResult> {
        let config = shared_config(spec)?;
        let command = match config.mode {
            AgentMode::Tui => "codex",
            AgentMode::Headless => "codex exec",
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
                name: "OPENAI_API_KEY".to_owned(),
                kind: CredentialKind::ApiKey,
                required: true,
                description: "OpenAI API key used by Codex.".to_owned(),
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

fn push_toml_string(content: &mut String, value: &str) {
    content.push('"');
    for ch in value.chars() {
        match ch {
            '"' => content.push_str("\\\""),
            '\\' => content.push_str("\\\\"),
            '\n' => content.push_str("\\n"),
            '\r' => content.push_str("\\r"),
            '\t' => content.push_str("\\t"),
            _ => content.push(ch),
        }
    }
    content.push('"');
}

fn mcp_transport_name(transport: McpTransport) -> &'static str {
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

    use super::CodexDriver;

    fn agent_spec(config: BTreeMap<String, Value>) -> AgentSpec {
        AgentSpec {
            version: None,
            config,
        }
    }

    #[tokio::test]
    async fn codex_driver_satisfies_agent_conformance_contract() {
        let mut driver = CodexDriver;

        driver_conformance::assert_agent_driver_contract(&mut driver, agent_spec(BTreeMap::new()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn codex_driver_initializes_with_agent_capabilities() {
        let mut driver = CodexDriver;

        let result = driver
            .initialize(InitializeParams {
                schema_version: SCHEMA_VERSION.to_owned(),
                core_version: "0.0.1-test".to_owned(),
                workdir: "/tmp/agentenv-test".to_owned(),
                log_level: LogLevel::Info,
            })
            .await
            .unwrap();

        assert_eq!(result.driver.name, "codex");
        assert_eq!(result.driver.kind, DriverKind::Agent);
        assert_eq!(result.driver.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(result.driver.protocol_version, SCHEMA_VERSION);

        let Capabilities::Agent(capabilities) = result.capabilities else {
            panic!("codex should report agent capabilities");
        };
        assert!(capabilities.supports_mcp);
        assert!(capabilities.supports_slash_commands);
        assert!(capabilities.supports_tui);
        assert!(capabilities.supports_headless);
    }

    #[tokio::test]
    async fn codex_driver_preflight_has_no_issues_for_now() {
        let driver = CodexDriver;

        let result = driver.preflight(PreflightParams::default()).await.unwrap();

        assert!(result.ok);
        assert!(result.issues.is_empty());
    }

    #[tokio::test]
    async fn codex_driver_reports_install_step_and_mcp_path() {
        let driver = CodexDriver;
        let spec = agent_spec(BTreeMap::new());

        let install_steps = driver.install_steps(spec).await.unwrap();
        let mcp_path = driver
            .mcp_config_path(McpConfigPathParams::default())
            .await
            .unwrap();

        assert_eq!(install_steps.steps.len(), 1);
        assert_eq!(
            install_steps.steps[0].content,
            "RUN npm install -g @openai/codex"
        );
        assert_eq!(mcp_path.path, "~/.codex/config.toml");
    }

    #[tokio::test]
    async fn codex_driver_pins_requested_package_version() {
        let driver = CodexDriver;
        let spec = AgentSpec {
            version: Some("0.53.0".to_owned()),
            config: BTreeMap::new(),
        };

        let install_steps = driver.install_steps(spec).await.unwrap();

        assert_eq!(
            install_steps.steps[0].content,
            "RUN npm install -g @openai/codex@0.53.0"
        );
    }

    #[tokio::test]
    async fn codex_driver_reports_openai_credential_and_probe() {
        let driver = CodexDriver;
        let spec = AgentSpec {
            version: None,
            config: BTreeMap::new(),
        };

        let credentials = driver.credential_requirements(spec.clone()).await.unwrap();
        let probe = driver.health_check_probe(spec).await.unwrap();

        assert_eq!(credentials.requirements.len(), 1);
        assert_eq!(credentials.requirements[0].name, "OPENAI_API_KEY");
        assert_eq!(credentials.requirements[0].kind, CredentialKind::ApiKey);
        assert!(credentials.requirements[0].required);
        assert_eq!(probe.cmd, "codex --version");
    }

    #[tokio::test]
    async fn codex_driver_renders_tui_entrypoint_by_default() {
        let driver = CodexDriver;
        let spec = agent_spec(BTreeMap::new());

        let entrypoint = driver.render_entrypoint(spec).await.unwrap();

        assert_eq!(
            entrypoint.content,
            "#!/usr/bin/env sh\nset -eu\nexec codex \"$@\"\n"
        );
    }

    #[tokio::test]
    async fn codex_driver_renders_headless_entrypoint() {
        let driver = CodexDriver;
        let spec = AgentSpec {
            version: None,
            config: BTreeMap::from([("mode".to_owned(), serde_json::json!("headless"))]),
        };

        let entrypoint = driver.render_entrypoint(spec).await.unwrap();
        assert!(entrypoint.content.contains("codex exec"));
        assert_eq!(
            entrypoint.content,
            "#!/usr/bin/env sh\nset -eu\nexec codex exec \"$@\"\n"
        );
    }

    #[tokio::test]
    async fn codex_driver_rejects_invalid_entrypoint_config() {
        let driver = CodexDriver;
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
    async fn codex_driver_rejects_unknown_entrypoint_config() {
        let driver = CodexDriver;
        let spec = agent_spec(BTreeMap::from([(
            "unexpected".to_owned(),
            serde_json::json!(true),
        )]));

        let err = driver
            .render_entrypoint(spec)
            .await
            .expect_err("unknown config keys should not fall back to TUI");

        assert!(err.to_string().contains("valid shared agent config"));
    }

    #[tokio::test]
    async fn codex_driver_renders_deterministic_mcp_toml() {
        let driver = CodexDriver;

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
                        transport: McpTransport::Http,
                        headers: BTreeMap::from([
                            ("Authorization".to_owned(), "Bearer test".to_owned()),
                            ("X-Agentenv".to_owned(), "true".to_owned()),
                        ]),
                    },
                ],
            })
            .await
            .unwrap();

        assert_eq!(
            rendered.content,
            "[mcp_servers.endpoint_0]\ncommand = \"agentenv-context\"\n\n[mcp_servers.endpoint_1]\nurl = \"https://context.example.test/mcp\"\nhttp_headers = { \"Authorization\" = \"Bearer test\", \"X-Agentenv\" = \"true\" }\n"
        );
    }

    #[tokio::test]
    async fn codex_driver_rejects_non_streamable_remote_mcp_transports() {
        let driver = CodexDriver;

        for transport in [McpTransport::HttpSse, McpTransport::SshHttp] {
            let err = driver
                .render_mcp_config(RenderMcpConfigParams {
                    endpoints: vec![McpEndpoint {
                        url: "https://context.example.test/mcp".to_owned(),
                        transport,
                        headers: BTreeMap::new(),
                    }],
                })
                .await
                .expect_err("codex should reject non-streamable HTTP transports");

            assert!(err.to_string().contains("codex mcp transport"));
        }
    }
}
