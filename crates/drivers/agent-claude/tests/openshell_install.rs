use std::collections::BTreeMap;

use agent_claude::ClaudeDriver;
use agentenv_core::driver::AgentDriver;
use agentenv_proto::AgentSpec;

#[tokio::test]
#[ignore = "enable once sandbox-openshell implements create + exec"]
async fn claude_install_and_probe_work_in_fresh_sandbox() {
    let driver = ClaudeDriver::default();
    let spec = AgentSpec {
        version: None,
        config: BTreeMap::new(),
    };

    let install = driver.install_steps(spec.clone()).await.unwrap();
    let probe = driver.health_check_probe(spec).await.unwrap();

    assert!(!install.steps.is_empty());
    assert_eq!(probe.cmd, "claude --version");
}
