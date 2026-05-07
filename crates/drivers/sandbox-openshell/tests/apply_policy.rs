use agentenv_policy::{compose_policy, PresetRegistry, Tier};
use sandbox_openshell::{
    classify_policy_update, translate_for_openshell, translate_for_openshell_with_binaries,
    UpdateDisposition,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static PATH_LOCK: Mutex<()> = Mutex::new(());

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
            http_access: None,
        },
    });

    assert_eq!(
        classify_policy_update(&current, &next).unwrap(),
        UpdateDisposition::HotReload
    );
    assert_eq!(
        translate_for_openshell_with_binaries(&next, ["/custom/bin/claude"])
            .unwrap()
            .format,
        "openshell"
    );
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
fn default_translation_uses_binaries_resolved_from_path() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");

    let tempdir = std::env::temp_dir().join(format!(
        "sandbox-openshell-path-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&tempdir).expect("create tempdir");

    for binary in ["claude", "codex", "openclaw", "curl"] {
        write_fake_binary(&tempdir, binary, true);
    }

    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", &tempdir);
    let translated =
        translate_for_openshell(&policy).expect("translate with PATH-resolved binaries");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    for binary in ["claude", "codex", "openclaw", "curl"] {
        assert!(
            translated
                .policy_yaml
                .contains(binary_path(&tempdir, binary).to_string_lossy().as_ref()),
            "expected translated policy to use PATH-resolved binary for {binary}"
        );
    }
    assert!(!translated.policy_yaml.contains("/usr/local/bin/claude"));

    std::fs::remove_dir_all(&tempdir).expect("remove tempdir");
}

#[test]
fn default_translation_fails_when_no_known_binaries_are_on_path() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");

    let tempdir = std::env::temp_dir().join(format!(
        "sandbox-openshell-empty-path-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&tempdir).expect("create tempdir");

    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", &tempdir);
    let err =
        translate_for_openshell(&policy).expect_err("translation should fail without binaries");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    assert!(err.to_string().contains("PATH"));
    assert!(err.to_string().contains("openshell"));

    std::fs::remove_dir_all(&tempdir).expect("remove tempdir");
}

#[test]
fn default_translation_fails_when_only_curl_is_on_path() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");

    let tempdir = std::env::temp_dir().join(format!(
        "sandbox-openshell-curl-only-path-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&tempdir).expect("create tempdir");
    write_fake_binary(&tempdir, "curl", true);

    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", &tempdir);
    let err = translate_for_openshell(&policy)
        .expect_err("translation should fail without agent binaries");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    assert!(err.to_string().contains("agent binaries"));
    assert!(err.to_string().contains("claude"));

    std::fs::remove_dir_all(&tempdir).expect("remove tempdir");
}

#[test]
fn default_translation_skips_non_executable_shadow_paths() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let _path_lock = PATH_LOCK.lock().expect("lock PATH for test");
    let registry = PresetRegistry::load_builtin().expect("load presets");
    let policy = compose_policy(Tier::Balanced, &[], None, &registry).expect("compose");

    let root = std::env::temp_dir().join(format!(
        "sandbox-openshell-shadow-path-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos()
    ));
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir_all(&first).expect("create first tempdir");
    std::fs::create_dir_all(&second).expect("create second tempdir");

    write_fake_binary(&first, "claude", false);
    write_fake_binary(&second, "claude", true);

    let original_path = std::env::var_os("PATH");
    let joined_path =
        std::env::join_paths([first.as_path(), second.as_path()]).expect("join PATH entries");
    std::env::set_var("PATH", joined_path);
    let translated =
        translate_for_openshell(&policy).expect("translation should use executable shadow target");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    assert!(translated
        .policy_yaml
        .contains(binary_path(&second, "claude").to_string_lossy().as_ref()));
    assert!(!translated
        .policy_yaml
        .contains(binary_path(&first, "claude").to_string_lossy().as_ref()));

    std::fs::remove_dir_all(&root).expect("remove tempdir");
}

#[test]
#[ignore = "requires openshell CLI on PATH and a working gateway"]
fn translated_policy_is_accepted_by_real_openshell_cli() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let registry = agentenv_policy::PresetRegistry::load_builtin().expect("load presets");
    let policy =
        agentenv_policy::compose_policy(agentenv_policy::Tier::Balanced, &[], None, &registry)
            .expect("compose");

    let translated = sandbox_openshell::translate_for_openshell(&policy).expect("translate");
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos()
    );
    let tempdir = std::env::temp_dir().join(format!("sandbox-openshell-test-{suffix}"));
    std::fs::create_dir_all(&tempdir).expect("create tempdir");
    let policy_path = tempdir.join("policy.yaml");
    std::fs::write(&policy_path, translated.policy_yaml).expect("write policy");

    let sandbox = format!("agentenv-policy-test-{suffix}");
    let create_output = std::process::Command::new("openshell")
        .args([
            "sandbox",
            "create",
            "--name",
            &sandbox,
            "--no-auto-providers",
            "--from",
            "openclaw",
            "--policy",
        ])
        .arg(&policy_path)
        .args(["--", "true"])
        .output()
        .expect("create openshell sandbox");

    if !create_output.status.success() {
        let _ = std::process::Command::new("openshell")
            .args(["sandbox", "delete", &sandbox])
            .output();
    }
    assert!(
        create_output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&create_output.stdout),
        String::from_utf8_lossy(&create_output.stderr)
    );

    let output = std::process::Command::new("openshell")
        .args(["policy", "set", &sandbox, "--policy"])
        .arg(&policy_path)
        .arg("--wait")
        .output()
        .expect("run openshell");

    let cleanup_output = std::process::Command::new("openshell")
        .args(["sandbox", "delete", &sandbox])
        .output()
        .expect("delete openshell sandbox");
    assert!(
        cleanup_output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&cleanup_output.stdout),
        String::from_utf8_lossy(&cleanup_output.stderr)
    );

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(&tempdir).expect("remove tempdir");
}

fn write_fake_binary(dir: &Path, binary: &str, executable: bool) {
    let path = binary_path(dir, binary);
    std::fs::write(&path, "").expect("create fake binary");

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = if executable { 0o755 } else { 0o644 };
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&path, permissions).expect("set fake binary permissions");
    }

    #[cfg(windows)]
    let _ = executable;
}

fn binary_path(dir: &Path, binary: &str) -> PathBuf {
    #[cfg(windows)]
    {
        dir.join(format!("{binary}.exe"))
    }

    #[cfg(not(windows))]
    {
        dir.join(binary)
    }
}
