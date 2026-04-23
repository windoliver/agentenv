use std::collections::BTreeMap;

use agentenv_proto::{AgentHealthCheckProbe, McpEndpoint, McpTransport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    #[default]
    Tui,
    Headless,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SharedAgentConfig {
    pub mode: AgentMode,
}

pub fn npm_package_spec(package: &str, version: Option<&str>) -> Result<String, String> {
    match version.filter(|value| !value.is_empty()) {
        Some(version) if is_safe_npm_version(version) => Ok(format!("{package}@{version}")),
        Some(version) => Err(format!("safe npm package version `{version}`")),
        None => Ok(package.to_owned()),
    }
}

pub fn npm_global_install_command(package: &str) -> String {
    format!(
        "npm install -g --no-audit --fetch-retries=5 --fetch-retry-mintimeout=2000 --fetch-retry-maxtimeout=20000 {package}"
    )
}

pub fn version_probe(binary: &str) -> AgentHealthCheckProbe {
    AgentHealthCheckProbe {
        cmd: format!("{binary} --version"),
        tty: false,
        env: BTreeMap::new(),
        success_exit_codes: vec![0],
    }
}

pub fn is_no_context_mcp_endpoint(endpoint: &McpEndpoint) -> bool {
    endpoint.transport == McpTransport::Stdio && endpoint.url.trim().is_empty()
}

fn is_safe_npm_version(version: &str) -> bool {
    version.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'~')
    })
}

#[cfg(test)]
mod tests {
    use super::{
        npm_global_install_command, npm_package_spec, version_probe, AgentMode, SharedAgentConfig,
    };

    #[test]
    fn shared_agent_config_defaults_to_tui() {
        let cfg = SharedAgentConfig::default();
        assert_eq!(cfg.mode, AgentMode::Tui);
    }

    #[test]
    fn version_probe_is_non_tty_and_accepts_exit_code_zero() {
        let probe = version_probe("claude");
        assert_eq!(probe.cmd, "claude --version");
        assert!(!probe.tty);
        assert_eq!(probe.success_exit_codes, vec![0]);
    }

    #[test]
    fn npm_package_spec_appends_safe_versions() {
        assert_eq!(
            npm_package_spec("@openai/codex", Some("0.53.0-beta.1+build")).unwrap(),
            "@openai/codex@0.53.0-beta.1+build"
        );
        assert_eq!(
            npm_package_spec("@openai/codex", None).unwrap(),
            "@openai/codex"
        );
    }

    #[test]
    fn npm_package_spec_rejects_shell_metacharacters() {
        let err = npm_package_spec("@openai/codex", Some("1.2.3;curl")).unwrap_err();

        assert!(err.contains("safe npm package version"));
    }

    #[test]
    fn npm_global_install_command_uses_retryable_non_auditing_install() {
        assert_eq!(
            npm_global_install_command("@openai/codex"),
            "npm install -g --no-audit --fetch-retries=5 --fetch-retry-mintimeout=2000 --fetch-retry-maxtimeout=20000 @openai/codex"
        );
    }
}
