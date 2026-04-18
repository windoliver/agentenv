use std::collections::BTreeMap;

use agentenv_proto::AgentHealthCheckProbe;
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

pub fn version_probe(binary: &str) -> AgentHealthCheckProbe {
    AgentHealthCheckProbe {
        cmd: format!("{binary} --version"),
        tty: false,
        env: BTreeMap::new(),
        success_exit_codes: vec![0],
    }
}

#[cfg(test)]
mod tests {
    use super::{version_probe, AgentMode, SharedAgentConfig};

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
}
