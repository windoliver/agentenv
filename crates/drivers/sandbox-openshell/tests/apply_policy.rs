use agentenv_policy::{compose_policy, PresetRegistry, Tier};
use sandbox_openshell::{
    classify_policy_update, translate_for_openshell, translate_for_openshell_with_binaries,
    UpdateDisposition,
};

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
fn process_changes_require_recreate() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let current = compose_policy(Tier::Restricted, &[], None, &registry).expect("compose");
    let mut next = current.clone();
    next.process.run_as_user = "agent".to_owned();

    let err = classify_policy_update(&current, &next).expect_err("process changes must recreate");
    assert!(err.to_string().contains("process"));
}

#[test]
fn network_changes_hot_reload() {
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
fn inference_changes_hot_reload() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let current = compose_policy(Tier::Restricted, &[], None, &registry).expect("compose");
    let mut next = current.clone();
    next.inference.routes.push(agentenv_proto::InferenceRoute {
        matcher: "default".to_owned(),
        provider: "openai".to_owned(),
        model: "gpt-5".to_owned(),
        base_url: Some("https://api.openai.com/v1".to_owned()),
        timeout_seconds: Some(30),
    });

    assert_eq!(
        classify_policy_update(&current, &next).unwrap(),
        UpdateDisposition::HotReload
    );
}

#[test]
fn translation_accepts_explicit_binary_overrides() {
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");

    let translated = translate_for_openshell_with_binaries(&policy, ["/custom/bin/openclaw"])
        .expect("translate policy");

    assert!(translated.policy_yaml.contains("/custom/bin/openclaw"));
    assert!(!translated.policy_yaml.contains("/usr/local/bin/claude"));
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
