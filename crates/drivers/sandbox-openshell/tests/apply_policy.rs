use agentenv_policy::{compose_policy, PresetRegistry, Tier};
use sandbox_openshell::{classify_policy_update, translate_for_openshell, UpdateDisposition};

#[test]
fn filesystem_or_process_changes_require_recreate() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let current = compose_policy(Tier::Restricted, &[], None, &registry).expect("compose");
    let mut next = current.clone();
    next.filesystem.read_write.push("/var/tmp".to_owned());

    let err =
        classify_policy_update(&current, &next).expect_err("filesystem changes must recreate");
    assert!(err.to_string().contains("filesystem"));
}

#[test]
fn network_and_inference_changes_hot_reload() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let current = compose_policy(Tier::Restricted, &[], None, &registry).expect("compose");
    let mut next = current.clone();
    next.network.allow.push(agentenv_proto::NetworkRule {
        target: agentenv_proto::NetworkTarget::Host {
            host: "api.github.com".to_owned(),
            port: Some(443),
            scheme: Some("https".to_owned()),
        },
    });

    assert_eq!(
        classify_policy_update(&current, &next).unwrap(),
        UpdateDisposition::HotReload
    );
    assert_eq!(translate_for_openshell(&next).unwrap().format, "openshell");
}

#[test]
#[ignore = "requires openshell CLI on PATH and OPENSHELL_TEST_SANDBOX to be set"]
fn translated_policy_is_accepted_by_real_openshell_cli() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let sandbox = std::env::var("OPENSHELL_TEST_SANDBOX").expect("sandbox name");
    let registry = agentenv_policy::PresetRegistry::load_builtin().expect("load presets");
    let policy =
        agentenv_policy::compose_policy(agentenv_policy::Tier::Balanced, &[], None, &registry)
            .expect("compose");

    let translated = sandbox_openshell::translate_for_openshell(&policy).expect("translate");
    let tempdir = std::env::temp_dir().join(format!(
        "sandbox-openshell-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&tempdir).expect("create tempdir");
    let policy_path = tempdir.join("policy.yaml");
    std::fs::write(&policy_path, translated.policy_yaml).expect("write policy");

    let output = std::process::Command::new("openshell")
        .args(["policy", "set", &sandbox, "--policy"])
        .arg(&policy_path)
        .arg("--wait")
        .output()
        .expect("run openshell");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(&tempdir).expect("remove tempdir");
}
