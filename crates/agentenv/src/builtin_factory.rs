use agentenv_core::{
    driver::InferenceDriver,
    runtime::{DriverFactory, DriverSelection, DriverSet, RuntimeError, RuntimeResult},
};

#[allow(dead_code)]
pub struct BuiltInDriverFactory;

impl DriverFactory for BuiltInDriverFactory {
    fn build(&self, selection: &DriverSelection) -> RuntimeResult<DriverSet> {
        Ok(DriverSet {
            sandbox: match selection.sandbox.as_str() {
                "openshell" | "sandbox-openshell" => {
                    Box::new(sandbox_openshell::OpenShellDriver::default())
                }
                other => {
                    return Err(RuntimeError::UnsupportedDriver {
                        kind: "sandbox",
                        name: other.to_owned(),
                    });
                }
            },
            agent: match selection.agent.as_str() {
                "claude" | "agent-claude" => Box::new(agent_claude::ClaudeDriver),
                "codex" | "agent-codex" => Box::new(agent_codex::CodexDriver),
                "openclaw" | "agent-openclaw" => Box::new(agent_openclaw::OpenClawDriver),
                other => {
                    return Err(RuntimeError::UnsupportedDriver {
                        kind: "agent",
                        name: other.to_owned(),
                    });
                }
            },
            context: match selection.context.as_str() {
                "filesystem" | "context-filesystem" => {
                    Box::new(context_filesystem::FilesystemContextDriver::default())
                }
                "mcp-generic" | "context-mcp-generic" => {
                    Box::new(context_mcp_generic::GenericMcpContextDriver::default())
                }
                "none" | "context-none" => Box::new(context_none::NoneContextDriver),
                other => {
                    return Err(RuntimeError::UnsupportedDriver {
                        kind: "context",
                        name: other.to_owned(),
                    });
                }
            },
            inference: match selection.inference.as_deref() {
                None => None,
                Some("passthrough" | "inference-passthrough") => {
                    Some(Box::new(inference_passthrough::PassthroughInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some("openai" | "inference-openai") => {
                    Some(Box::new(inference_openai::OpenAiInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some("anthropic" | "inference-anthropic") => {
                    Some(Box::new(inference_anthropic::AnthropicInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some("ollama" | "inference-ollama") => {
                    Some(Box::new(inference_ollama::OllamaInferenceDriver)
                        as Box<dyn InferenceDriver>)
                }
                Some(other) => {
                    return Err(RuntimeError::UnsupportedDriver {
                        kind: "inference",
                        name: other.to_owned(),
                    });
                }
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use agentenv_core::runtime::{DriverFactory, DriverSelection};

    use super::BuiltInDriverFactory;

    #[test]
    fn builds_supported_reference_driver_set() {
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "codex".to_owned(),
            context: "filesystem".to_owned(),
            inference: Some("passthrough".to_owned()),
        };

        let set = BuiltInDriverFactory.build(&selection).unwrap();
        drop(set);
    }

    #[test]
    fn unsupported_external_driver_is_explicit() {
        let selection = DriverSelection {
            sandbox: "openshell".to_owned(),
            agent: "hermes".to_owned(),
            context: "nexus".to_owned(),
            inference: None,
        };

        let err = BuiltInDriverFactory.build(&selection).unwrap_err();
        assert!(err.to_string().contains("unsupported driver"));
    }
}
