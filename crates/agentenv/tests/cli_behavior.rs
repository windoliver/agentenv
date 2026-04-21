use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn agentenv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentenv")
}

#[test]
fn freeze_fails_without_blueprint_or_default_file() {
    let temp_dir = make_temp_dir("freeze-missing-blueprint");

    let output = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no blueprint provided"),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn verify_blueprint_succeeds_on_reference_blueprint() {
    let output = Command::new(agentenv_bin())
        .arg("verify-blueprint")
        .arg(fixture_blueprint())
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Blueprint verified"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn drivers_list_includes_built_in_drivers() {
    let temp_dir = make_temp_dir("drivers-list-builtins");

    let output = process::Command::new(agentenv_bin())
        .arg("drivers")
        .arg("list")
        .env("HOME", &temp_dir)
        .env_remove("AGENTENV_DRIVER_PATH")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("KIND"));
    assert!(stdout.contains("agent"));
    assert!(stdout.contains("codex"));
    assert!(stdout.contains("built-in"));

    let expected_kind_col = format!("{:<10}", "agent");
    let version = env!("CARGO_PKG_VERSION");
    let expected_codex_row = format!(
        "{:<10} {:<24} {:<14} {:<10} -",
        "agent", "agent-codex", version, "built-in"
    );

    let codex_row = stdout
        .lines()
        .find(|line| {
            line.contains("agent-codex") && line.contains("built-in") && line.ends_with("-")
        })
        .expect("missing codex built-in row");

    assert!(codex_row.starts_with(&expected_kind_col));
    assert_eq!(codex_row, expected_codex_row);
}

#[test]
fn drivers_list_includes_override_manifest() {
    let temp_dir = make_temp_dir("drivers-list-override");
    let driver_root = temp_dir.join("context-nexus-py");
    fs::create_dir_all(driver_root.join("bin")).unwrap();
    fs::write(driver_root.join("bin/driver"), "").unwrap();
    fs::write(
        driver_root.join("manifest.json"),
        r#"{
          "schema_version": "1.0",
          "name": "nexus",
          "kind": "context",
          "version": "0.2.0",
          "binary": "./bin/driver"
        }"#,
    )
    .unwrap();

    let output = process::Command::new(agentenv_bin())
        .arg("drivers")
        .arg("list")
        .env("HOME", temp_dir.join("home"))
        .env("AGENTENV_DRIVER_PATH", &driver_root)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("context"));
    assert!(stdout.contains("nexus"));
    assert!(stdout.contains("0.2.0"));
    assert!(stdout.contains("override"));
    assert!(stdout.contains("bin/driver"));
}

#[test]
fn create_accepts_non_interactive_env_one() {
    let temp_dir = make_temp_dir("create-non-interactive-env");

    let output = process::Command::new(agentenv_bin())
        .arg("create")
        .arg("demo")
        .env("HOME", temp_dir.join("home"))
        .env("AGENTENV_NON_INTERACTIVE", "1")
        .output()
        .unwrap();

    assert_ne!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no blueprint provided"));
    assert!(!stderr.contains("invalid value"));
}

#[test]
fn create_json_missing_blueprint_uses_stable_error() {
    let temp_dir = make_temp_dir("create-json-missing-blueprint");

    let output = process::Command::new(agentenv_bin())
        .arg("create")
        .arg("demo")
        .arg("--json")
        .arg("--non-interactive")
        .env("HOME", temp_dir.join("home"))
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["reason_code"], "invalid_blueprint");
}

#[test]
fn create_preflight_json_invalid_blueprint_uses_stable_error() {
    let temp_dir = make_temp_dir("create-preflight-json-invalid");
    let blueprint = temp_dir.join("agentenv.yaml");
    fs::write(&blueprint, "version: [").unwrap();

    let output = process::Command::new(agentenv_bin())
        .arg("create")
        .arg("demo")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--preflight-only")
        .arg("--json")
        .arg("--non-interactive")
        .env("HOME", temp_dir.join("home"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["reason_code"], "invalid_blueprint");
}

#[test]
fn list_json_returns_empty_rows_when_registry_missing() {
    let temp_dir = make_temp_dir("list-json-empty");

    let output = Command::new(agentenv_bin())
        .arg("list")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["envs"].as_array().unwrap().len(), 0);
}

#[test]
fn list_json_registry_error_uses_stable_error() {
    let temp_dir = make_temp_dir("list-json-corrupt");
    let env_dir = temp_dir.join(".agentenv").join("envs").join("demo");
    fs::create_dir_all(&env_dir).unwrap();
    fs::write(env_dir.join("state.json"), "{").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("list")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["reason_code"], "driver_command_failed");
}

#[test]
fn describe_json_missing_env_uses_stable_error() {
    let temp_dir = make_temp_dir("describe-json-missing");

    let output = Command::new(agentenv_bin())
        .arg("describe")
        .arg("missing")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["reason_code"], "env_not_found");
}

#[test]
fn create_preflight_json_reports_unsupported_external_driver() {
    let temp_dir = make_temp_dir("create-preflight-unsupported");
    let blueprint = temp_dir.join("agentenv.yaml");
    fs::write(
        &blueprint,
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: hermes
context:
  driver: nexus
policy:
  tier: restricted
  presets: []
"#,
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("create")
        .arg("demo")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--preflight-only")
        .arg("--json")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("capability_missing") || stderr.contains("unsupported driver"));
}

#[test]
fn exec_requires_command_after_separator() {
    let output = Command::new(agentenv_bin())
        .arg("exec")
        .arg("demo")
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[test]
fn create_reproduce_json_reports_missing_blueprint_content() {
    let temp_dir = make_temp_dir("create-reproduce-missing-blueprint");
    let lockfile = temp_dir.join("demo.lock.yaml");
    fs::write(
        &lockfile,
        r#"
version: 0.1.0
protocol_version: "0.1"
blueprint_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
drivers:
  sandbox:
    name: openshell
    version: 0.0.1-alpha0
  agent:
    name: codex
    version: 0.0.1-alpha0
  context:
    name: filesystem
    version: 0.0.1-alpha0
"#,
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("create")
        .arg("demo")
        .arg("--reproduce")
        .arg(&lockfile)
        .arg("--json")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["reason_code"], "reproduce_blueprint_missing");
    assert_eq!(output.status.code(), Some(10));
}

#[test]
fn logs_context_driver_falls_back_to_events_jsonl() {
    let temp_dir = make_temp_dir("logs-context-events");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    fs::write(
        env_dir.join("events.jsonl"),
        r#"{"ts":"2026-04-21T00:00:00Z","driver":"context","level":"info","msg":"context ready"}"#,
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("logs")
        .arg("demo")
        .arg("--driver")
        .arg("context")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("context ready"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn logs_context_follow_streams_appended_events_jsonl() {
    let temp_dir = make_temp_dir("logs-context-follow-events");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    let events_path = env_dir.join("events.jsonl");
    fs::write(&events_path, "").unwrap();

    let mut child = Command::new(agentenv_bin())
        .arg("logs")
        .arg("demo")
        .arg("--driver")
        .arg("context")
        .arg("--follow")
        .env("HOME", &temp_dir)
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().unwrap().is_none(),
        "logs --follow exited before new events were appended"
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&events_path)
        .unwrap()
        .write_all(
            b"{\"ts\":\"2026-04-21T00:00:01Z\",\"driver\":\"context\",\"level\":\"info\",\"msg\":\"context followed\"}\n",
        )
        .unwrap();
    thread::sleep(Duration::from_millis(400));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    assert!(
        String::from_utf8_lossy(&output.stdout).contains("context followed"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn destroy_prompts_when_yes_is_absent() {
    let temp_dir = make_temp_dir("destroy-prompt");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");

    let mut child = Command::new(agentenv_bin())
        .arg("destroy")
        .arg("demo")
        .env("HOME", &temp_dir)
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"demo\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!env_dir.exists());
}

#[test]
fn destroy_non_interactive_without_yes_uses_stable_reason() {
    let temp_dir = make_temp_dir("destroy-non-interactive-no-yes");

    let output = Command::new(agentenv_bin())
        .arg("destroy")
        .arg("demo")
        .env("HOME", &temp_dir)
        .env("AGENTENV_NON_INTERACTIVE", "1")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["reason_code"], "non_interactive_prompt_required");
}

#[test]
fn destroy_purge_credentials_removes_state_credentials() {
    let temp_dir = make_temp_dir("destroy-purge-scoped");
    let credential_name = format!("AGENTENV_SCOPED_TOKEN_{}", unique_suffix());
    write_minimal_env_state_with_credentials(&temp_dir, "demo", &[credential_name.as_str()]);
    fs::write(
        temp_dir.join(".agentenv").join("credentials.json"),
        serde_json::json!({
            "values": {
                credential_name.clone(): "secret"
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("destroy")
        .arg("demo")
        .arg("--yes")
        .arg("--purge-credentials")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let list = Command::new(agentenv_bin())
        .arg("credentials")
        .arg("list")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&list.stdout).contains(&credential_name),
        "stdout was: {}",
        String::from_utf8_lossy(&list.stdout)
    );
}

#[test]
fn drivers_list_reports_malformed_manifest_path() {
    let temp_dir = make_temp_dir("drivers-list-bad-manifest");
    let driver_root = temp_dir.join("bad-driver");
    fs::create_dir_all(&driver_root).unwrap();
    fs::write(driver_root.join("manifest.json"), "{not-json").unwrap();

    let output = process::Command::new(agentenv_bin())
        .arg("drivers")
        .arg("list")
        .env("HOME", temp_dir.join("home"))
        .env("AGENTENV_DRIVER_PATH", &driver_root)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("manifest.json"), "stderr was: {stderr}");
    assert!(stderr.contains("invalid JSON"), "stderr was: {stderr}");
}

#[test]
fn freeze_with_blueprint_and_out_writes_lockfile() {
    let temp_dir = make_temp_dir("freeze-out");
    let lockfile = temp_dir.join("demo.lock.yaml");

    let output = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--blueprint")
        .arg(fixture_blueprint())
        .arg("--out")
        .arg(&lockfile)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        lockfile.is_file(),
        "missing lockfile: {}",
        lockfile.display()
    );

    let rendered = fs::read_to_string(&lockfile).unwrap();
    assert!(rendered.contains("version: 0.1.0"));
    assert!(rendered.contains("blueprint_hash:"));
}

#[test]
fn reproduce_succeeds_from_generated_lockfile() {
    let temp_dir = make_temp_dir("reproduce-lockfile");
    let lockfile = temp_dir.join("demo.lock.yaml");

    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--blueprint")
        .arg(fixture_blueprint())
        .arg("--out")
        .arg(&lockfile)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        freeze.status.success(),
        "freeze stderr: {}",
        String::from_utf8_lossy(&freeze.stderr)
    );

    let reproduce = Command::new(agentenv_bin())
        .arg("reproduce")
        .arg(&lockfile)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(reproduce.status.success());
    assert!(
        String::from_utf8_lossy(&reproduce.stdout)
            .contains("Lockfile reproduced successfully for environment `demo`"),
        "stdout was: {}",
        String::from_utf8_lossy(&reproduce.stdout)
    );
}

#[test]
#[ignore = "requires OpenShell and external reference blueprint dependencies"]
fn reference_blueprints_create_status_destroy_roundtrip() {
    if std::env::var_os("AGENTENV_RUN_OPEN_SHELL_TESTS").is_none() {
        eprintln!("set AGENTENV_RUN_OPEN_SHELL_TESTS=1 to run OpenShell CLI integration");
        return;
    }

    for blueprint in [
        "blueprints/claude+filesystem+openshell.yaml",
        "blueprints/codex+mcp-generic+openshell.yaml",
        "blueprints/openclaw+nexus+openshell.yaml",
        "blueprints/hermes+nexus+openshell.yaml",
    ] {
        let temp_dir = make_temp_dir("reference-blueprint");
        let name = blueprint
            .rsplit('/')
            .next()
            .unwrap()
            .replace(".yaml", "")
            .replace('+', "-");
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(blueprint);

        let create = Command::new(agentenv_bin())
            .arg("create")
            .arg(&name)
            .arg("--blueprint")
            .arg(&path)
            .arg("--non-interactive")
            .env("HOME", &temp_dir)
            .output()
            .unwrap();
        if !create.status.success() {
            let stderr = String::from_utf8_lossy(&create.stderr);
            if reference_blueprint_skip_reason(&stderr) {
                continue;
            }
            panic!("create failed for {blueprint}: {stderr}");
        }

        let status = Command::new(agentenv_bin())
            .arg("status")
            .arg(&name)
            .env("HOME", &temp_dir)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "status stderr: {}",
            String::from_utf8_lossy(&status.stderr)
        );

        let destroy = Command::new(agentenv_bin())
            .arg("destroy")
            .arg(&name)
            .arg("--yes")
            .env("HOME", &temp_dir)
            .output()
            .unwrap();
        assert!(
            destroy.status.success(),
            "destroy stderr: {}",
            String::from_utf8_lossy(&destroy.stderr)
        );
    }
}

fn fixture_blueprint() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../blueprints/claude+filesystem+openshell.yaml")
}

fn reference_blueprint_skip_reason(stderr: &str) -> bool {
    [
        "unsupported driver",
        "OpenShell binary not found",
        "gateway",
        "missing credential",
        "missing_credential",
    ]
    .iter()
    .any(|needle| stderr.contains(needle))
}

fn make_temp_dir(prefix: &str) -> PathBuf {
    let unique = format!("{prefix}-{}", unique_suffix());
    let path = std::env::temp_dir().join(unique);
    fs::create_dir_all(&path).unwrap();
    path
}

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn write_minimal_env_state(home: &Path, name: &str) -> PathBuf {
    write_minimal_env_state_with_credentials(home, name, &[])
}

fn write_minimal_env_state_with_credentials(
    home: &Path,
    name: &str,
    credential_names: &[&str],
) -> PathBuf {
    let env_dir = home.join(".agentenv").join("envs").join(name);
    fs::create_dir_all(&env_dir).unwrap();
    fs::write(
        env_dir.join("state.json"),
        serde_json::json!({
            "version": "0.1.0",
            "name": name,
            "phase": "running",
            "created_at": "2026-04-21T00:00:00Z",
            "updated_at": "2026-04-21T00:00:00Z",
            "drivers": {
                "sandbox": {"name": "openshell", "version": "0.0.1-alpha0"},
                "agent": {"name": "codex", "version": "0.0.1-alpha0"},
                "context": {"name": "filesystem", "version": "0.0.1-alpha0"}
            },
            "handles": {},
            "endpoints": {},
            "credential_names": credential_names,
            "first_enter_hint_shown": false
        })
        .to_string(),
    )
    .unwrap();
    fs::write(env_dir.join("blueprint.yaml"), "version: 0.1.0\n").unwrap();
    fs::write(env_dir.join("lock.yaml"), "version: 0.1.0\n").unwrap();
    env_dir
}
