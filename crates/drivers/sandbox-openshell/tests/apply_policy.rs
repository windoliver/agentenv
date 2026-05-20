use agentenv_policy::{compose_policy, PresetRegistry, Tier};
use sandbox_openshell::{
    classify_policy_update, translate_for_openshell, translate_for_openshell_with_binaries,
    UpdateDisposition,
};
use std::{
    io::{self, Read},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{mpsc, Mutex},
    thread,
    time::{Duration, Instant},
};

static PATH_LOCK: Mutex<()> = Mutex::new(());
const OPEN_SHELL_COMMAND_TIMEOUT_ENV: &str = "AGENTENV_OPENSHELL_COMMAND_TIMEOUT_MS";
const DEFAULT_LIVE_CLI_TIMEOUT: Duration = Duration::from_secs(300);
const PROCESS_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(25);

struct ProcessOutputReader {
    receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
}

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

    if !openshell_gateway_available() {
        return;
    }

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
    let mut create_command = Command::new("openshell");
    create_command
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
        .args(["--", "true"]);
    let create_output = match run_command_with_timeout(create_command) {
        Ok(output) => output,
        Err(error) => {
            let _ = delete_sandbox(&sandbox);
            panic!("create openshell sandbox: {error}");
        }
    };

    if !create_output.status.success() {
        let _ = delete_sandbox(&sandbox);
    }
    assert!(
        create_output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&create_output.stdout),
        String::from_utf8_lossy(&create_output.stderr)
    );

    let mut policy_command = Command::new("openshell");
    policy_command
        .args(["policy", "set", &sandbox, "--policy"])
        .arg(&policy_path)
        .arg("--wait");
    let output = run_command_with_timeout(policy_command);

    let cleanup_output = delete_sandbox(&sandbox).expect("delete openshell sandbox");
    assert!(
        cleanup_output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&cleanup_output.stdout),
        String::from_utf8_lossy(&cleanup_output.stderr)
    );

    let output = output.expect("run openshell");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(&tempdir).expect("remove tempdir");
}

fn openshell_gateway_available() -> bool {
    let mut command = Command::new("openshell");
    command.arg("status");
    match run_command_with_timeout(command) {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            eprintln!(
                "skipping real OpenShell policy test: `openshell status` failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
        Err(err) => {
            eprintln!(
                "skipping real OpenShell policy test: could not run `openshell status`: {err}"
            );
            false
        }
    }
}

fn delete_sandbox(sandbox: &str) -> io::Result<Output> {
    let mut command = Command::new("openshell");
    command.args(["sandbox", "delete", sandbox]);
    run_command_with_timeout(command)
}

fn run_command_with_timeout(mut command: Command) -> io::Result<Output> {
    let timeout = live_cli_timeout();
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("failed to capture stdout for live OpenShell command"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to capture stderr for live OpenShell command"))?;
    let stdout_reader = read_process_output(stdout);
    let stderr_reader = read_process_output(stderr);
    let started = Instant::now();

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        if started.elapsed() >= timeout {
            terminate_timed_out_process(&mut child);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("live OpenShell command timed out after {timeout:?}"),
            ));
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        thread::sleep(PROCESS_COMMAND_POLL_INTERVAL.min(remaining));
    };

    let Some(stdout) = collect_process_output_before_timeout(stdout_reader, started, timeout)?
    else {
        terminate_timed_out_process(&mut child);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("live OpenShell command timed out after {timeout:?}"),
        ));
    };
    let Some(stderr) = collect_process_output_before_timeout(stderr_reader, started, timeout)?
    else {
        terminate_timed_out_process(&mut child);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("live OpenShell command timed out after {timeout:?}"),
        ));
    };

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_process_output<R>(mut reader: R) -> ProcessOutputReader
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut output = Vec::new();
        let result = reader.read_to_end(&mut output).map(|_| output);
        let _ = sender.send(result);
    });
    ProcessOutputReader { receiver }
}

fn collect_process_output_before_timeout(
    reader: ProcessOutputReader,
    started: Instant,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
        return Ok(None);
    };
    if remaining.is_zero() {
        return Ok(None);
    }

    match reader.receiver.recv_timeout(remaining) {
        Ok(result) => result.map(Some),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
            "command output reader thread stopped early",
        )),
    }
}

fn terminate_timed_out_process(child: &mut std::process::Child) {
    let process_group_id = child.id() as i32;
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg("--")
        .arg(format!("-{process_group_id}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

fn live_cli_timeout() -> Duration {
    std::env::var(OPEN_SHELL_COMMAND_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_LIVE_CLI_TIMEOUT)
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
