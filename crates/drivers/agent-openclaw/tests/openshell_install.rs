use std::collections::BTreeMap;

use agent_openclaw::OpenClawDriver;
use agentenv_core::driver::AgentDriver;
use agentenv_proto::AgentSpec;

#[tokio::test]
#[ignore = "enable once sandbox-openshell implements create + exec"]
async fn openclaw_install_and_probe_work_in_fresh_sandbox() {
    let driver = OpenClawDriver::default();
    let spec = AgentSpec {
        version: None,
        config: BTreeMap::new(),
    };

    let install = driver.install_steps(spec.clone()).await.unwrap();
    let probe = driver.health_check_probe(spec).await.unwrap();

    assert!(!install.steps.is_empty());
    assert_eq!(probe.cmd, "openclaw --version");
}
