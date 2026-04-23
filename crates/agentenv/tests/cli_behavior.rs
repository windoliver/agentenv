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
fn freeze_persisted_env_writes_default_lockfile() {
    let temp_dir = make_temp_dir("freeze-persisted-default");
    write_minimal_env_state(&temp_dir, "demo");

    let output = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Lockfile written"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let rendered = fs::read_to_string(temp_dir.join("agentenv.lock")).unwrap();
    assert!(rendered.contains("version: 0.2.0"));
    assert!(rendered.contains("name: demo"));
}

#[test]
fn reproduce_portable_lockfile_reports_missing_required_credential() {
    let temp_dir = make_temp_dir("reproduce-portable-missing-credential");
    let env_dir = write_minimal_env_state_with_credentials(&temp_dir, "demo", &["OPENAI_API_KEY"]);
    fs::write(
        env_dir.join("blueprint.yaml"),
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#,
    )
    .unwrap();

    let lockfile = temp_dir.join("agentenv.lock");
    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--output")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        freeze.status.success(),
        "freeze failed: {}",
        output_summary(&freeze)
    );

    let output = Command::new(agentenv_bin())
        .arg("reproduce")
        .arg(&lockfile)
        .arg("--name")
        .arg("demo-copy")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .env_remove("OPENAI_API_KEY")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OPENAI_API_KEY"), "stderr was: {stderr}");
    assert!(
        stderr.contains("missing credential") || stderr.contains("missing_credential"),
        "stderr was: {stderr}"
    );
    assert!(
        !stderr.contains("unknown field `driver_protocol_version`"),
        "portable lockfile was parsed as legacy: {stderr}"
    );
}

#[test]
fn reproduce_portable_lockfile_honors_required_credential_reference() {
    let temp_dir = make_temp_dir("reproduce-portable-credential-reference");
    let env_dir = write_minimal_env_state_with_credentials(&temp_dir, "demo", &["OPENAI_API_KEY"]);
    fs::write(
        env_dir.join("blueprint.yaml"),
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      value: CUSTOM_OPENAI_KEY
      required: true
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#,
    )
    .unwrap();

    let lockfile = temp_dir.join("agentenv.lock");
    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--output")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        freeze.status.success(),
        "freeze failed: {}",
        output_summary(&freeze)
    );
    let rendered = fs::read_to_string(&lockfile).unwrap();
    assert!(rendered.contains("OPENAI_API_KEY"));
    assert!(rendered.contains("reference: CUSTOM_OPENAI_KEY"));

    let missing = Command::new(agentenv_bin())
        .arg("reproduce")
        .arg(&lockfile)
        .arg("--name")
        .arg("demo-missing-reference")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .env_remove("OPENAI_API_KEY")
        .env_remove("CUSTOM_OPENAI_KEY")
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let missing_stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        missing_stderr.contains("CUSTOM_OPENAI_KEY"),
        "stderr was: {missing_stderr}"
    );

    fs::create_dir_all(
        temp_dir
            .join(".agentenv")
            .join("envs")
            .join("demo-reference-present"),
    )
    .unwrap();
    let present = Command::new(agentenv_bin())
        .arg("reproduce")
        .arg(&lockfile)
        .arg("--name")
        .arg("demo-reference-present")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .env_remove("OPENAI_API_KEY")
        .env("CUSTOM_OPENAI_KEY", "sk-reference-present")
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    let present_stderr = String::from_utf8_lossy(&present.stderr);
    assert!(
        !present_stderr.contains("missing credential `OPENAI_API_KEY`"),
        "credential precheck used the lockfile key instead of reference: {present_stderr}"
    );
    assert!(
        present_stderr.contains("already exists"),
        "expected reproduce to pass credential precheck and fail on existing env: {present_stderr}"
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
fn freeze_persisted_env_output_dash_prints_lockfile_without_dash_file() {
    let temp_dir = make_temp_dir("freeze-persisted-stdout");
    write_minimal_env_state(&temp_dir, "demo");

    let output = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--output")
        .arg("-")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("version: 0.2.0"), "stdout was: {stdout}");
    assert!(stdout.contains("name: demo"), "stdout was: {stdout}");
    assert!(
        !temp_dir.join("-").exists(),
        "`--output -` unexpectedly created a file named `-`"
    );
}

#[test]
fn verify_accepts_generated_portable_lockfile() {
    let temp_dir = make_temp_dir("verify-portable-lockfile");
    write_minimal_env_state(&temp_dir, "demo");

    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        freeze.status.success(),
        "freeze stderr: {}",
        String::from_utf8_lossy(&freeze.stderr)
    );

    let verify = Command::new(agentenv_bin())
        .arg("verify")
        .arg("agentenv.lock")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        verify.status.success(),
        "verify stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("Lockfile verified"),
        "stdout was: {}",
        String::from_utf8_lossy(&verify.stdout)
    );
}

#[test]
#[ignore = "requires real OpenShell, gateway, Docker, and OPENAI_API_KEY"]
fn codex_filesystem_openshell_real_cli_lifecycle() {
    if std::env::var_os("AGENTENV_RUN_OPEN_SHELL_TESTS").is_none() {
        eprintln!("set AGENTENV_RUN_OPEN_SHELL_TESTS=1 to run OpenShell CLI integration");
        return;
    }
    require_env_var("OPENAI_API_KEY");
    require_openai_api_key_usable();

    let temp_dir = make_temp_dir("codex-filesystem-openshell-real");
    let home = temp_dir.join("home");
    let mount = home.join("projects");
    fs::create_dir_all(&mount).unwrap();
    fs::write(mount.join("README.md"), "agentenv real e2e\n").unwrap();
    let blueprint = temp_dir.join("codex-filesystem-openshell.yaml");
    fs::write(
        &blueprint,
        format!(
            r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
  credentials:
    OPENAI_API_KEY:
      source: env
      required: true
context:
  driver: filesystem
  mount: {}
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
state:
  persist_home: true
"#,
            mount.display()
        ),
    )
    .unwrap();

    let name = "codex-filesystem-openshell-real";
    let mut created = false;
    let result = (|| -> Result<(), String> {
        let create = agentenv_with_home(&home)
            .arg("create")
            .arg(name)
            .arg("--blueprint")
            .arg(&blueprint)
            .arg("--non-interactive")
            .output()
            .unwrap();
        require_agentenv_success("create", &create)?;
        created = true;

        let status = agentenv_with_home(&home)
            .arg("status")
            .arg(name)
            .arg("--json")
            .output()
            .unwrap();
        require_agentenv_success("status --json", &status)?;
        let status_json: serde_json::Value =
            serde_json::from_slice(&status.stdout).map_err(|err| {
                format!(
                    "status JSON parse failed: {err}\n{}",
                    output_summary(&status)
                )
            })?;
        if status_json["healthy"] != serde_json::Value::Bool(true) {
            return Err(format!(
                "status JSON did not report healthy=true:\n{}",
                String::from_utf8_lossy(&status.stdout)
            ));
        }

        let logs = agentenv_with_home(&home)
            .arg("logs")
            .arg(name)
            .output()
            .unwrap();
        require_agentenv_success("logs", &logs)?;

        let exec = agentenv_with_home(&home)
            .arg("exec")
            .arg(name)
            .arg("--")
            .arg("printf")
            .arg("agentenv-real-e2e-ok")
            .output()
            .unwrap();
        require_agentenv_success("exec", &exec)?;
        if String::from_utf8_lossy(&exec.stdout) != "agentenv-real-e2e-ok" {
            return Err(format!("exec output mismatch:\n{}", output_summary(&exec)));
        }

        let enter = agentenv_with_home(&home)
            .arg("enter")
            .arg(name)
            .arg("--detach")
            .output()
            .unwrap();
        require_agentenv_success("enter --detach", &enter)?;
        if String::from_utf8_lossy(&enter.stdout).trim().is_empty() {
            return Err(format!(
                "enter --detach did not print a shell session:\n{}",
                output_summary(&enter)
            ));
        }

        let describe = agentenv_with_home(&home)
            .arg("describe")
            .arg(name)
            .arg("--json")
            .output()
            .unwrap();
        require_agentenv_success("describe --json", &describe)?;
        let describe_json: serde_json::Value =
            serde_json::from_slice(&describe.stdout).map_err(|err| {
                format!(
                    "describe JSON parse failed: {err}\n{}",
                    output_summary(&describe)
                )
            })?;
        if describe_json["state"]["drivers"]["agent"]["name"]
            != serde_json::Value::String("codex".to_owned())
        {
            return Err(format!(
                "describe JSON did not report codex agent:\n{}",
                String::from_utf8_lossy(&describe.stdout)
            ));
        }

        let list = agentenv_with_home(&home)
            .arg("list")
            .arg("--json")
            .output()
            .unwrap();
        require_agentenv_success("list --json", &list)?;
        let list_json: serde_json::Value = serde_json::from_slice(&list.stdout)
            .map_err(|err| format!("list JSON parse failed: {err}\n{}", output_summary(&list)))?;
        let listed = list_json["envs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"] == serde_json::Value::String(name.to_owned()));
        if !listed {
            return Err(format!(
                "list JSON did not include environment `{name}`:\n{}",
                String::from_utf8_lossy(&list.stdout)
            ));
        }

        let destroy = agentenv_with_home(&home)
            .arg("destroy")
            .arg(name)
            .arg("--yes")
            .output()
            .unwrap();
        require_agentenv_success("destroy", &destroy)?;
        created = false;
        if home.join(".agentenv").join("envs").join(name).exists() {
            return Err("destroy succeeded but env registry directory still exists".to_owned());
        }

        Ok(())
    })();

    if created {
        let _ = agentenv_with_home(&home)
            .arg("destroy")
            .arg(name)
            .arg("--yes")
            .output();
    }

    if let Err(message) = result {
        panic!("{message}");
    }
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
        fs::create_dir_all(temp_dir.join("projects")).unwrap();
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
            .env("AGENTENV_DISABLE_KEYRING", "1")
            .output()
            .unwrap();
        if !create.status.success() {
            let output = output_summary(&create);
            if reference_blueprint_skip_reason(&output) {
                continue;
            }
            panic!("create failed for {blueprint}: {output}");
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

fn agentenv_with_home(home: &Path) -> Command {
    let mut command = Command::new(agentenv_bin());
    command
        .env("HOME", home)
        .env("AGENTENV_DISABLE_KEYRING", "1");
    command
}

fn require_env_var(name: &str) {
    if std::env::var_os(name).is_none() {
        panic!("{name} must be set for real OpenShell E2E");
    }
}

fn require_openai_api_key_usable() {
    let key = std::env::var("OPENAI_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("OPENAI_API_KEY must be non-empty for real OpenShell E2E");
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("OpenAI probe client should build");
    let response = client
        .get("https://api.openai.com/v1/models")
        .bearer_auth(key.trim())
        .send()
        .unwrap_or_else(|err| panic!("OpenAI API key probe failed to send request: {err}"));
    if !response.status().is_success() {
        panic!("OpenAI API key probe returned HTTP {}", response.status());
    }
}

fn require_agentenv_success(label: &str, output: &process::Output) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed:\n{}", output_summary(output)))
    }
}

fn output_summary(output: &process::Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_owned()),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn reference_blueprint_skip_reason(stderr: &str) -> bool {
    [
        "unsupported driver",
        "OpenShell binary not found",
        "OpenShell CLI binary",
        "openshell_missing",
        "preflight_failed",
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
    let driver_version = env!("CARGO_PKG_VERSION");
    fs::write(
        env_dir.join("state.json"),
        serde_json::json!({
            "version": "0.1.0",
            "name": name,
            "phase": "running",
            "created_at": "2026-04-21T00:00:00Z",
            "updated_at": "2026-04-21T00:00:00Z",
            "drivers": {
                "sandbox": {"name": "openshell", "version": driver_version},
                "agent": {"name": "codex", "version": driver_version},
                "context": {"name": "filesystem", "version": driver_version},
                "inference": {"name": "passthrough", "version": driver_version}
            },
            "handles": {},
            "endpoints": {},
            "credential_names": credential_names,
            "first_enter_hint_shown": false
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        env_dir.join("blueprint.yaml"),
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
inference:
  driver: passthrough
policy:
  tier: balanced
  presets: []
"#,
    )
    .unwrap();
    fs::write(
        env_dir.join("lock.yaml"),
        r#"
version: 0.1.0
protocol_version: "0.1"
blueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736
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
    env_dir
}
