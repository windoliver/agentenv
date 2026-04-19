const RUN_OPEN_SHELL_TESTS_ENV: &str = "AGENTENV_RUN_OPEN_SHELL_TESTS";

#[tokio::test]
#[ignore = "enable once sandbox-openshell implements create + exec"]
async fn openclaw_install_and_probe_work_in_fresh_sandbox() {
    if std::env::var_os(RUN_OPEN_SHELL_TESTS_ENV).is_none() {
        eprintln!(
            "skipping OpenClaw OpenShell install/probe activation test; set \
             {RUN_OPEN_SHELL_TESTS_ENV} once sandbox-openshell create + exec exists"
        );
        return;
    }

    panic!(
        "{RUN_OPEN_SHELL_TESTS_ENV} is set, but OpenShell create+exec wiring is not implemented \
         yet; connect sandbox-openshell create + exec here once M2-1 lands"
    );
}
