use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use agentenv_events::{
    audit::{AuditSigningKey, AuditStore},
    store::{EventQuery, SqliteEventStore},
    ActivityEvent, ActivityKind, ActivityResult,
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
    let present_summary = output_summary(&present);
    let present_output = format!(
        "{}{}",
        String::from_utf8_lossy(&present.stdout),
        String::from_utf8_lossy(&present.stderr)
    );
    assert!(
        !present_output.contains("missing credential `OPENAI_API_KEY`"),
        "reproduce used the lockfile key instead of the credential reference: {present_summary}"
    );
    assert!(
        present.status.success()
            || present_output.contains("OpenShell")
            || present_output.contains("openshell")
            || present_output.contains("preflight")
            || present_output.contains("capability")
            || present_output.contains("sandbox")
            || present_output.contains("invalid driver config")
            || present_output.contains("mount")
            || present_output.contains("created"),
        "expected reproduce to pass credential resolution and reach create/preflight: {present_summary}"
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
fn logs_env_kind_json_reads_sqlite_activity_store() {
    let temp_dir = make_temp_dir("logs-env-kind-json");
    write_minimal_env_state(&temp_dir, "demo");
    seed_activity_db(
        &temp_dir,
        "demo",
        &[
            activity_event(
                "2026-04-21T00:00:00Z",
                ActivityKind::EgressDenied,
                ActivityResult::Denied,
                "trace-denied",
            )
            .with_subject_value("target", serde_json::json!("api.example.test:443")),
            activity_event(
                "2026-04-21T00:00:01Z",
                ActivityKind::Log,
                ActivityResult::Ok,
                "trace-log",
            )
            .with_subject_value("message", serde_json::json!("ordinary log")),
        ],
    );

    let output = Command::new(agentenv_bin())
        .arg("logs")
        .arg("--env")
        .arg("demo")
        .arg("--kind")
        .arg("egress_denied")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        1,
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(lines[0]["kind"], "egress_denied");
    assert_eq!(lines[0]["result"], "denied");
    assert_eq!(lines[0]["trace_id"], "trace-denied");
}

#[test]
fn env_scoped_logs_merge_global_and_per_env_activity() {
    let temp_dir = make_temp_dir("logs-env-global-plus-per-env");
    write_minimal_env_state(&temp_dir, "demo");
    seed_global_activity_db(
        &temp_dir,
        &[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::SandboxCreate,
            ActivityResult::Ok,
            "trace-global-create",
        )],
    );
    seed_activity_db(
        &temp_dir,
        "demo",
        &[activity_event(
            "2026-04-21T00:00:01Z",
            ActivityKind::Exec,
            ActivityResult::Ok,
            "trace-per-env-exec",
        )],
    );

    let output = Command::new(agentenv_bin())
        .arg("logs")
        .arg("--env")
        .arg("demo")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trace-global-create"),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains("trace-per-env-exec"),
        "stdout was: {stdout}"
    );
}

#[test]
fn env_scoped_logs_parse_legacy_jsonl_fallback() {
    let temp_dir = make_temp_dir("logs-env-legacy-jsonl");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    fs::write(
        env_dir.join("events.jsonl"),
        "{\"ts\":\"2026-04-21T00:00:00Z\",\"driver\":\"context\",\"level\":\"info\",\"msg\":\"legacy context event\"}\n",
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("logs")
        .arg("--env")
        .arg("demo")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        1,
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(lines[0]["kind"], "log");
    assert_eq!(lines[0]["extras"]["msg"], "legacy context event");
}

#[test]
fn stats_env_prints_activity_summary() {
    let temp_dir = make_temp_dir("stats-env-summary");
    write_minimal_env_state(&temp_dir, "demo");
    seed_activity_db(
        &temp_dir,
        "demo",
        &[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-denied",
        )
        .with_actor_value("driver", serde_json::json!("openshell"))],
    );

    let output = Command::new(agentenv_bin())
        .arg("stats")
        .arg("--env")
        .arg("demo")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("egress_denied"), "stdout was: {stdout}");
    assert!(stdout.contains("denied"), "stdout was: {stdout}");
}

#[test]
fn stats_without_env_reads_global_activity_summary() {
    let temp_dir = make_temp_dir("stats-global-summary");
    seed_global_activity_db(
        &temp_dir,
        &[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-global-denied",
        )
        .with_actor_value("driver", serde_json::json!("openshell"))],
    );

    let output = Command::new(agentenv_bin())
        .arg("stats")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("global"), "stdout was: {stdout}");
    assert!(stdout.contains("egress_denied"), "stdout was: {stdout}");
    assert!(stdout.contains("denied"), "stdout was: {stdout}");
}

#[test]
fn env_scoped_audit_export_reads_global_audit_entries() {
    let temp_dir = make_temp_dir("audit-env-global-export");
    write_minimal_env_state(&temp_dir, "demo");
    seed_global_audit_db(
        &temp_dir,
        &[
            activity_event(
                "2026-04-21T00:00:00Z",
                ActivityKind::CredentialInjected,
                ActivityResult::Ok,
                "trace-demo-credential",
            )
            .with_subject_value("name", serde_json::json!("OPENAI_API_KEY")),
            activity_event(
                "2026-04-21T00:00:01Z",
                ActivityKind::CredentialInjected,
                ActivityResult::Ok,
                "trace-other-credential",
            )
            .with_env("other")
            .with_subject_value("name", serde_json::json!("OTHER_API_KEY")),
        ],
    );

    let export = Command::new(agentenv_bin())
        .arg("audit")
        .arg("export")
        .arg("--env")
        .arg("demo")
        .arg("--format")
        .arg("jsonl")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        export.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let stdout = String::from_utf8_lossy(&export.stdout);
    assert!(
        stdout.contains("trace-demo-credential"),
        "stdout was: {stdout}"
    );
    assert!(
        !stdout.contains("trace-other-credential"),
        "stdout was: {stdout}"
    );
}

#[test]
fn audit_export_and_verify_use_activity_database() {
    let temp_dir = make_temp_dir("audit-export-verify");
    write_minimal_env_state(&temp_dir, "demo");
    seed_audit_db(
        &temp_dir,
        "demo",
        &[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-audit-denied",
        )],
    );

    let export = Command::new(agentenv_bin())
        .arg("audit")
        .arg("export")
        .arg("--env")
        .arg("demo")
        .arg("--format")
        .arg("jsonl")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        export.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let exported = String::from_utf8_lossy(&export.stdout);
    assert!(exported.contains("egress_denied"), "stdout was: {exported}");
    assert!(
        exported.contains("trace-audit-denied"),
        "stdout was: {exported}"
    );

    let verify = Command::new(agentenv_bin())
        .arg("audit")
        .arg("verify")
        .arg("--env")
        .arg("demo")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        verify.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("valid"), "stdout was: {stdout}");
    assert!(stdout.contains("1"), "stdout was: {stdout}");
}

#[test]
fn audit_export_and_verify_without_env_use_global_activity_database() {
    let temp_dir = make_temp_dir("audit-global-export-verify");
    seed_global_audit_db(
        &temp_dir,
        &[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::CredentialReset,
            ActivityResult::Ok,
            "trace-global-audit",
        )
        .with_subject_value("name", serde_json::json!("OPENAI_API_KEY"))],
    );

    let export = Command::new(agentenv_bin())
        .arg("audit")
        .arg("export")
        .arg("--format")
        .arg("jsonl")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        export.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let exported = String::from_utf8_lossy(&export.stdout);
    assert!(
        exported.contains("trace-global-audit"),
        "stdout was: {exported}"
    );
    assert!(
        exported.contains("credential_reset"),
        "stdout was: {exported}"
    );

    let verify = Command::new(agentenv_bin())
        .arg("audit")
        .arg("verify")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        verify.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("valid"), "stdout was: {stdout}");
    assert!(stdout.contains("1"), "stdout was: {stdout}");
}

#[test]
fn audit_export_range_filters_activity_database() {
    let temp_dir = make_temp_dir("audit-export-range");
    write_minimal_env_state(&temp_dir, "demo");
    seed_audit_db(
        &temp_dir,
        "demo",
        &[
            activity_event(
                "2026-04-21T00:00:00Z",
                ActivityKind::EgressDenied,
                ActivityResult::Denied,
                "trace-audit-first",
            ),
            activity_event(
                "2026-04-21T00:00:01Z",
                ActivityKind::CredentialReset,
                ActivityResult::Ok,
                "trace-audit-second",
            )
            .with_subject_value("name", serde_json::json!("OPENAI_API_KEY")),
        ],
    );

    let export = Command::new(agentenv_bin())
        .arg("audit")
        .arg("export")
        .arg("--env")
        .arg("demo")
        .arg("--format")
        .arg("jsonl")
        .arg("--from")
        .arg("2026-04-21T00:00:01Z")
        .arg("--to")
        .arg("2026-04-21T00:00:01Z")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        export.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let stdout = String::from_utf8_lossy(&export.stdout);
    assert!(
        stdout.contains("trace-audit-second"),
        "stdout was: {stdout}"
    );
    assert!(
        !stdout.contains("trace-audit-first"),
        "stdout was: {stdout}"
    );
}

#[test]
fn credential_set_explicit_file_sink_still_writes_default_sqlite_and_audit() {
    let temp_dir = make_temp_dir("credential-set-additive-sink-audit");
    let credential_name = format!("AGENTENV_AUDIT_TOKEN_{}", unique_suffix());
    let source_env = format!("{credential_name}_SOURCE");
    let secret_value = "sk-secret-do-not-leak";
    let jsonl_path = temp_dir.join("explicit-events.jsonl");

    let output = Command::new(agentenv_bin())
        .arg("--events-sink")
        .arg(format!("file:{}", jsonl_path.display()))
        .arg("credentials")
        .arg("set")
        .arg(&credential_name)
        .arg("--from-env")
        .arg(&source_env)
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env(&source_env, secret_value)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file_events = fs::read_to_string(&jsonl_path).unwrap();
    assert!(
        file_events.contains("credential_set"),
        "events file was: {file_events}"
    );
    assert!(
        file_events.contains(&credential_name),
        "events file was: {file_events}"
    );
    assert!(
        !file_events.contains(secret_value),
        "events file leaked credential value: {file_events}"
    );

    let global_store =
        SqliteEventStore::open(temp_dir.join(".agentenv").join("events.db")).unwrap();
    let events = global_store
        .query(EventQuery {
            kind: Some(ActivityKind::CredentialSet),
            limit: 10,
            ..EventQuery::default()
        })
        .unwrap();
    assert!(
        events
            .iter()
            .any(|row| row.event.subject.get("name") == Some(&serde_json::json!(credential_name))),
        "global activity DB did not contain credential_set for {credential_name:?}"
    );
    let rendered_events = events
        .iter()
        .map(|row| serde_json::to_string(&row.event).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !rendered_events.contains(secret_value),
        "activity DB leaked credential value: {rendered_events}"
    );

    let mut audit_jsonl = Vec::new();
    AuditStore::open(temp_dir.join(".agentenv").join("events.db"))
        .unwrap()
        .export_jsonl(&mut audit_jsonl)
        .unwrap();
    let audit_jsonl = String::from_utf8(audit_jsonl).unwrap();
    assert!(audit_jsonl.contains("credential_set"), "{audit_jsonl}");
    assert!(audit_jsonl.contains(&credential_name), "{audit_jsonl}");
    assert!(
        !audit_jsonl.contains(secret_value),
        "audit log leaked credential value: {audit_jsonl}"
    );
}

#[test]
fn credential_reset_writes_global_audit_entry_before_success() {
    let temp_dir = make_temp_dir("credential-reset-audit");
    let credential_name = format!("AGENTENV_RESET_AUDIT_TOKEN_{}", unique_suffix());
    fs::create_dir_all(temp_dir.join(".agentenv")).unwrap();
    fs::write(
        temp_dir.join(".agentenv").join("credentials.json"),
        serde_json::json!({
            "values": {
                credential_name.clone(): "sk-reset-secret-do-not-leak"
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("credentials")
        .arg("reset")
        .arg(&credential_name)
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut audit_jsonl = Vec::new();
    AuditStore::open(temp_dir.join(".agentenv").join("events.db"))
        .unwrap()
        .export_jsonl(&mut audit_jsonl)
        .unwrap();
    let audit_jsonl = String::from_utf8(audit_jsonl).unwrap();
    assert!(audit_jsonl.contains("credential_reset"), "{audit_jsonl}");
    assert!(audit_jsonl.contains(&credential_name), "{audit_jsonl}");
    assert!(
        !audit_jsonl.contains("sk-reset-secret-do-not-leak"),
        "audit log leaked credential value: {audit_jsonl}"
    );
}

#[test]
fn create_json_existing_env_reports_audit_write_failure() {
    let temp_dir = make_temp_dir("create-json-audit-failure");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    let key_path = temp_dir.join(".agentenv").join("audit-signing-key");
    fs::write(&key_path, b"short").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = Command::new(agentenv_bin())
        .arg("create")
        .arg("demo")
        .arg("--blueprint")
        .arg(env_dir.join("blueprint.yaml"))
        .arg("--json")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit"), "stderr was: {stderr}");
    assert!(
        stderr.contains("original command error"),
        "stderr was: {stderr}"
    );
    assert!(stderr.contains("already exists"), "stderr was: {stderr}");
}

#[test]
fn logs_env_json_reads_global_activity_store_when_env_store_absent() {
    let temp_dir = make_temp_dir("logs-global-fallback");
    write_minimal_env_state(&temp_dir, "demo");
    seed_global_activity_db(
        &temp_dir,
        &[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-global-log",
        )
        .with_subject_value("target", serde_json::json!("api.example.test:443"))],
    );

    let output = Command::new(agentenv_bin())
        .arg("logs")
        .arg("--env")
        .arg("demo")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        1,
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(lines[0]["kind"], "egress_denied");
    assert_eq!(lines[0]["trace_id"], "trace-global-log");
}

#[test]
fn logs_env_kind_follow_polls_empty_sqlite_activity_store() {
    let temp_dir = make_temp_dir("logs-follow-empty-sqlite");
    write_minimal_env_state(&temp_dir, "demo");
    let db_path = env_activity_db_path(&temp_dir, "demo");
    SqliteEventStore::open(&db_path).unwrap();

    let mut child = Command::new(agentenv_bin())
        .arg("logs")
        .arg("--env")
        .arg("demo")
        .arg("--kind")
        .arg("egress_denied")
        .arg("--json")
        .arg("--follow")
        .env("HOME", &temp_dir)
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().unwrap().is_none(),
        "logs --follow exited before SQLite events were appended"
    );
    let store = SqliteEventStore::open(&db_path).unwrap();
    store
        .append_many(&[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::EgressDenied,
            ActivityResult::Denied,
            "trace-follow-sqlite",
        )
        .with_subject_value("target", serde_json::json!("api.example.test:443"))])
        .unwrap();

    thread::sleep(Duration::from_millis(600));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trace-follow-sqlite"),
        "stdout was: {stdout}\nstderr was: {}",
        String::from_utf8_lossy(&output.stderr)
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
fn freeze_and_verify_do_not_print_known_secret() {
    let temp_dir = make_temp_dir("freeze-verify-secret-redaction");
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
      note: sk-known-secret
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

    let lockfile = temp_dir.join("secret-free.agentenv.lock");
    let freeze = Command::new(agentenv_bin())
        .arg("freeze")
        .arg("demo")
        .arg("--output")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .env_remove("OPENAI_API_KEY")
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        freeze.status.success(),
        "freeze failed: {}",
        output_summary(&freeze)
    );
    let freeze_output = output_summary(&freeze);
    assert!(
        !freeze_output.contains("sk-known-secret"),
        "freeze output leaked secret metadata:\n{freeze_output}"
    );

    let rendered = fs::read_to_string(&lockfile).unwrap();
    assert!(
        !rendered.contains("sk-known-secret"),
        "lockfile leaked secret metadata:\n{rendered}"
    );

    let verify = Command::new(agentenv_bin())
        .arg("verify")
        .arg(&lockfile)
        .env("HOME", &temp_dir)
        .env_remove("OPENAI_API_KEY")
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "verify failed: {}",
        output_summary(&verify)
    );
    let verify_output = output_summary(&verify);
    assert!(
        !verify_output.contains("sk-known-secret"),
        "verify output leaked secret metadata:\n{verify_output}"
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

fn activity_event(
    ts: &str,
    kind: ActivityKind,
    result: ActivityResult,
    trace_id: &str,
) -> ActivityEvent {
    ActivityEvent::new(ts, kind, result, trace_id).with_env("demo")
}

fn seed_activity_db(home: &Path, env: &str, events: &[ActivityEvent]) {
    let db_path = env_activity_db_path(home, env);
    let store = SqliteEventStore::open(db_path).unwrap();
    store.append_many(events).unwrap();
}

fn env_activity_db_path(home: &Path, env: &str) -> PathBuf {
    home.join(".agentenv")
        .join("envs")
        .join(env)
        .join("events.db")
}

fn seed_global_activity_db(home: &Path, events: &[ActivityEvent]) {
    let db_path = home.join(".agentenv").join("events.db");
    let store = SqliteEventStore::open(db_path).unwrap();
    store.append_many(events).unwrap();
}

fn seed_audit_db(home: &Path, env: &str, events: &[ActivityEvent]) {
    let env_dir = home.join(".agentenv").join("envs").join(env);
    let store = AuditStore::open(env_dir.join("events.db")).unwrap();
    let key = AuditSigningKey::load_or_create(env_dir.join("audit.key")).unwrap();
    for event in events {
        store.append(&key, event).unwrap();
    }
}

fn seed_global_audit_db(home: &Path, events: &[ActivityEvent]) {
    let store = AuditStore::open(home.join(".agentenv").join("events.db")).unwrap();
    let key = AuditSigningKey::load_or_create(home.join(".agentenv").join("audit.key")).unwrap();
    for event in events {
        store.append(&key, event).unwrap();
    }
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
