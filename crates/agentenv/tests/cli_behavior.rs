use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{self, Command},
    sync::{Mutex, MutexGuard},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use agentenv_approvals::{
    sign_payload, ApprovalKind, ApprovalRequest, ApprovalScope, ApprovalStore,
};
use agentenv_events::{
    audit::{AuditSigningKey, AuditStore},
    store::{EventQuery, SqliteEventStore},
    ActivityEvent, ActivityKind, ActivityResult,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

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
    write_failing_openshell_cli(&temp_dir);

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
fn cli_includes_commands() {
    let output = Command::new(agentenv_bin()).arg("--help").output().unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let blueprint = stdout
        .find("blueprint")
        .unwrap_or_else(|| panic!("stdout was: {stdout}"));
    let credentials = stdout
        .find("credentials")
        .unwrap_or_else(|| panic!("stdout was: {stdout}"));
    assert!(
        blueprint < credentials,
        "`blueprint` should be listed before `credentials`; stdout was: {stdout}"
    );
}

#[test]
fn cli_help_includes_skills_command() {
    let output = Command::new(agentenv_bin()).arg("--help").output().unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("skills"), "stdout was: {stdout}");
}

#[test]
fn skills_help_lists_lifecycle_subcommands() {
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "search", "add", "install", "list", "info", "remove", "publish", "verify",
    ] {
        assert!(
            stdout.contains(command),
            "missing {command}; stdout was: {stdout}"
        );
    }
}

#[test]
fn skills_install_list_info_verify_and_remove_local_bundle() {
    let temp_dir = make_temp_dir("skills-cli-local");
    let bundle = temp_dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), "# CLI Skill\n").unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: cli-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    )
    .unwrap();

    let install = Command::new(agentenv_bin())
        .arg("skills")
        .arg("install")
        .arg("--from")
        .arg(&bundle)
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(install.status.success(), "{}", output_summary(&install));

    let list = Command::new(agentenv_bin())
        .arg("skills")
        .arg("list")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(list.status.success(), "{}", output_summary(&list));
    let json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(json["skills"][0]["name"], "cli-skill");

    let info = Command::new(agentenv_bin())
        .arg("skills")
        .arg("info")
        .arg("cli-skill")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(info.status.success(), "{}", output_summary(&info));
    let info_json: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info_json["name"], "cli-skill");

    let verify = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("cli-skill")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", output_summary(&verify));

    let remove = Command::new(agentenv_bin())
        .arg("skills")
        .arg("remove")
        .arg("cli-skill")
        .arg("--yes")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(remove.status.success(), "{}", output_summary(&remove));
}

#[test]
fn skills_search_add_and_publish_use_filesystem_registry_config() {
    let temp_dir = make_temp_dir("skills-cli-registry");
    let registry = temp_dir.join("registry");
    let bundle = temp_dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), "# Registry Skill\n").unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: registry-skill\nversion: 0.1.0\ndescription: Registry demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    )
    .unwrap();
    fs::write(
        temp_dir.join("agentenv.yaml"),
        format!(
            "version: 0.1.0\nmin_agentenv_version: 0.0.1-alpha0\nsandbox: {{ driver: openshell }}\nagent: {{ driver: codex }}\ncontext: {{ driver: filesystem, mount: . }}\npolicy: {{ tier: balanced, presets: [] }}\nskills:\n  registries:\n    - name: local-dev\n      type: filesystem\n      path: {}\n",
            registry.display()
        ),
    )
    .unwrap();

    let publish = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&bundle)
        .arg("--registry")
        .arg("local-dev")
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(publish.status.success(), "{}", output_summary(&publish));

    let search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("registry")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(search.status.success(), "{}", output_summary(&search));
    assert!(String::from_utf8_lossy(&search.stdout).contains("registry-skill"));

    let add = Command::new(agentenv_bin())
        .arg("skills")
        .arg("add")
        .arg("registry-skill@0.1.0")
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(add.status.success(), "{}", output_summary(&add));
}

#[test]
fn skills_registry_cli_path_override_publishes_searches_and_adds() {
    let temp_dir = make_temp_dir("skills-cli-registry-override");
    let registry = temp_dir.join("registry");
    let bundle = temp_dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), "# Override Skill\n").unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: override-skill\nversion: 0.1.0\ndescription: Override demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    )
    .unwrap();

    let publish = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&bundle)
        .arg("--registry")
        .arg(&registry)
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(publish.status.success(), "{}", output_summary(&publish));
    let publish_json: serde_json::Value = serde_json::from_slice(&publish.stdout).unwrap();
    assert_eq!(publish_json["name"], "override-skill");
    assert_eq!(publish_json["registry"], "cli");

    let search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("override")
        .arg("--registry")
        .arg(&registry)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(search.status.success(), "{}", output_summary(&search));
    let search_json: serde_json::Value = serde_json::from_slice(&search.stdout).unwrap();
    assert_eq!(search_json["skills"][0]["name"], "override-skill");
    assert_eq!(search_json["skills"][0]["registry"], "cli");

    let add = Command::new(agentenv_bin())
        .arg("skills")
        .arg("add")
        .arg("override-skill@0.1.0")
        .arg("--registry")
        .arg(&registry)
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(add.status.success(), "{}", output_summary(&add));
    let add_json: serde_json::Value = serde_json::from_slice(&add.stdout).unwrap();
    assert_eq!(add_json["name"], "override-skill");
    assert_eq!(add_json["source_type"], "filesystem");
    assert_eq!(
        add_json["source_label"],
        "filesystem:cli:override-skill@0.1.0"
    );
}

#[test]
fn skills_registry_config_precedence_is_user_project_then_cli() {
    let temp_dir = make_temp_dir("skills-cli-registry-precedence");
    let user_registry = temp_dir.join("user-registry");
    let project_registry = temp_dir.join("project-registry");
    let cli_registry = temp_dir.join("cli-registry");
    write_filesystem_registry_skill(
        &user_registry,
        "user-precedence-skill",
        "0.1.0",
        "Precedence demo",
    );
    write_filesystem_registry_skill(
        &project_registry,
        "project-precedence-skill",
        "0.1.0",
        "Precedence demo",
    );
    write_filesystem_registry_skill(
        &cli_registry,
        "cli-precedence-skill",
        "0.1.0",
        "Precedence demo",
    );

    fs::create_dir_all(temp_dir.join(".config/agentenv")).unwrap();
    fs::write(
        temp_dir.join(".config/agentenv/config.toml"),
        format!(
            "[skills]\nregistry_order = [\"shared\"]\n\n[[skills.registries]]\nname = \"shared\"\ntype = \"filesystem\"\npath = '{}'\n",
            user_registry.display()
        ),
    )
    .unwrap();
    fs::write(
        temp_dir.join("agentenv.yaml"),
        format!(
            "skills:\n  registry_order:\n    - shared\n  registries:\n    - name: shared\n      type: filesystem\n      path: {}\n",
            project_registry.display()
        ),
    )
    .unwrap();
    let no_project_dir = temp_dir.join("no-project");
    fs::create_dir_all(&no_project_dir).unwrap();

    let user_search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("precedence")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&no_project_dir)
        .output()
        .unwrap();
    assert!(
        user_search.status.success(),
        "{}",
        output_summary(&user_search)
    );
    assert_skill_search_names(&user_search.stdout, &["user-precedence-skill"]);

    let project_search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("precedence")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        project_search.status.success(),
        "{}",
        output_summary(&project_search)
    );
    assert_skill_search_names(&project_search.stdout, &["project-precedence-skill"]);

    let cli_search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("precedence")
        .arg("--registry")
        .arg(&cli_registry)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        cli_search.status.success(),
        "{}",
        output_summary(&cli_search)
    );
    assert_skill_search_names(&cli_search.stdout, &["cli-precedence-skill"]);
}

#[test]
fn blueprint_lint_reports_json_diagnostics() {
    let temp_dir = make_temp_dir("blueprint-lint-json-diagnostics");
    let dockerfile = temp_dir.join("Dockerfile");
    fs::write(
        &dockerfile,
        r#"
FROM alpine:3.20
RUN apk add --no-cache curl
USER root
"#,
    )
    .unwrap();
    let blueprint = temp_dir.join("agentenv.yaml");
    fs::write(
        &blueprint,
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
  hardening: strict
  image:
    source: byo
    dockerfile: Dockerfile
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
inference:
  driver: passthrough
policy:
  tier: restricted
  presets: []
"#,
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("blueprint")
        .arg("lint")
        .arg(&blueprint)
        .arg("--json")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("JSON parse failed: {err}\n{}", output_summary(&output)));
    assert_eq!(json["profile"], "strict");
    let codes = json["diagnostics"]
        .as_array()
        .expect("diagnostics should be an array")
        .iter()
        .filter_map(|diagnostic| diagnostic["code"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("dockerfile_user_root"), "codes: {codes:?}");
    assert!(
        codes.contains("dockerfile_reintroduces_stripped_package"),
        "codes: {codes:?}"
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
fn resume_missing_env_uses_stable_error() {
    let temp_dir = make_temp_dir("resume-missing");
    let output = Command::new(agentenv_bin())
        .arg("resume")
        .arg("missing")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("env `missing` not found"));
}

#[test]
fn sessions_list_json_returns_empty_when_registry_missing() {
    let temp_dir = make_temp_dir("sessions-list-empty");
    let output = Command::new(agentenv_bin())
        .arg("sessions")
        .arg("list")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["sessions"].as_array().unwrap().len(), 0);
}

#[test]
fn sessions_list_json_missing_env_uses_stable_error() {
    let temp_dir = make_temp_dir("sessions-list-json-missing");
    let output = Command::new(agentenv_bin())
        .arg("sessions")
        .arg("list")
        .arg("missing")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(10));
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["reason_code"], "env_not_found");
}

#[test]
fn enter_help_includes_new_flag() {
    let output = Command::new(agentenv_bin())
        .arg("enter")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("--new"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn sessions_help_includes_list_and_kill_commands() {
    let output = Command::new(agentenv_bin())
        .arg("sessions")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("list"), "stdout was: {stdout}");
    assert!(stdout.contains("kill"), "stdout was: {stdout}");
}

#[test]
fn snapshot_help_includes_create_verify_and_restore_usage() {
    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[ENV]"), "stdout was: {stdout}");
    assert!(stdout.contains("--output"), "stdout was: {stdout}");
    assert!(stdout.contains("verify"), "stdout was: {stdout}");
    assert!(stdout.contains("restore"), "stdout was: {stdout}");
}

#[test]
fn snapshot_verify_missing_dir_fails_cleanly() {
    let temp_dir = make_temp_dir("snapshot-verify-missing");
    let missing = temp_dir.join("missing.agentenvsnap");

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("verify")
        .arg(&missing)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("snapshot"), "stderr was: {stderr}");
    assert!(
        stderr.contains("missing.agentenvsnap") || stderr.contains("manifest.json"),
        "stderr was: {stderr}"
    );
}

#[test]
fn snapshot_restore_missing_dir_with_as_fails_before_env_creation() {
    let temp_dir = make_temp_dir("snapshot-restore-missing");
    let missing = temp_dir.join("missing.agentenvsnap");

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("restore")
        .arg(&missing)
        .arg("--as")
        .arg("restored")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("snapshot"), "stderr was: {stderr}");
    assert!(
        stderr.contains("missing.agentenvsnap") || stderr.contains("manifest.json"),
        "stderr was: {stderr}"
    );
    assert!(
        !temp_dir
            .join(".agentenv")
            .join("envs")
            .join("restored")
            .exists(),
        "restore created env state before verifying the missing snapshot"
    );
}

#[test]
fn snapshot_restore_non_interactive_flag_reports_missing_credential() {
    let temp_dir = make_temp_dir("snapshot-restore-non-interactive-flag");
    let snapshot_dir =
        write_minimal_signed_snapshot_with_credentials(&temp_dir, "demo", &["OPENAI_API_KEY"]);

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("restore")
        .arg(&snapshot_dir)
        .arg("--as")
        .arg("restored")
        .arg("--non-interactive")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env_remove("OPENAI_API_KEY")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_ne!(output.status.code(), Some(2), "{}", output_summary(&output));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OPENAI_API_KEY"), "stderr was: {stderr}");
    assert!(
        stderr.contains("missing credential") || stderr.contains("missing_credential"),
        "stderr was: {stderr}"
    );
    assert!(
        !stderr.contains("failed to prompt"),
        "restore prompted despite --non-interactive: {stderr}"
    );
    assert!(
        !temp_dir
            .join(".agentenv")
            .join("envs")
            .join("restored")
            .exists(),
        "restore created env state before rejecting missing credential"
    );
}

#[test]
fn snapshot_restore_non_interactive_env_reports_missing_credential() {
    let temp_dir = make_temp_dir("snapshot-restore-non-interactive-env");
    let snapshot_dir =
        write_minimal_signed_snapshot_with_credentials(&temp_dir, "demo", &["OPENAI_API_KEY"]);

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("restore")
        .arg(&snapshot_dir)
        .arg("--as")
        .arg("restored")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_NON_INTERACTIVE", "1")
        .env_remove("OPENAI_API_KEY")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_ne!(output.status.code(), Some(2), "{}", output_summary(&output));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OPENAI_API_KEY"), "stderr was: {stderr}");
    assert!(
        stderr.contains("missing credential") || stderr.contains("missing_credential"),
        "stderr was: {stderr}"
    );
    assert!(
        !stderr.contains("failed to prompt"),
        "restore prompted despite AGENTENV_NON_INTERACTIVE=1: {stderr}"
    );
    assert!(
        !temp_dir
            .join(".agentenv")
            .join("envs")
            .join("restored")
            .exists(),
        "restore created env state before rejecting missing credential"
    );
}

#[test]
fn snapshot_output_before_verify_is_rejected_by_parser() {
    let temp_dir = make_temp_dir("snapshot-output-before-verify");

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("--output")
        .arg("ignored.agentenvsnap")
        .arg("verify")
        .arg("missing.agentenvsnap")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--output"), "stderr was: {stderr}");
    assert!(stderr.contains("<ENV>"), "stderr was: {stderr}");
}

#[test]
fn snapshot_output_before_restore_is_rejected_by_parser() {
    let temp_dir = make_temp_dir("snapshot-output-before-restore");

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("--output")
        .arg("-")
        .arg("restore")
        .arg("missing.agentenvsnap")
        .arg("--as")
        .arg("restored")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--output"), "stderr was: {stderr}");
    assert!(stderr.contains("<ENV>"), "stderr was: {stderr}");
    assert!(
        !temp_dir
            .join(".agentenv")
            .join("envs")
            .join("restored")
            .exists(),
        "restore created env state after parser rejection"
    );
}

#[test]
fn snapshot_create_rejects_stdout_output() {
    let temp_dir = make_temp_dir("snapshot-output-dash");

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("demo")
        .arg("--output")
        .arg("-")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--output -"), "stderr was: {stderr}");
    assert!(stderr.contains("not supported"), "stderr was: {stderr}");
    assert!(!temp_dir.join("-").exists());
}

#[test]
fn snapshot_verify_prints_signed_snapshot_summary() {
    let temp_dir = make_temp_dir("snapshot-verify-success");
    let snapshot_dir = write_minimal_signed_snapshot(&temp_dir, "demo");

    let output = Command::new(agentenv_bin())
        .arg("snapshot")
        .arg("verify")
        .arg(&snapshot_dir)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Snapshot verified"), "stdout was: {stdout}");
    assert!(stdout.contains("demo.agentenvsnap"), "stdout was: {stdout}");
    assert!(stdout.contains("files:"), "stdout was: {stdout}");
    assert!(stdout.contains("merkle root:"), "stdout was: {stdout}");
    assert!(
        stdout.contains("signature: verified"),
        "stdout was: {stdout}"
    );
}

#[test]
fn term_help_lists_flags_and_key_bindings() {
    let output = Command::new(agentenv_bin())
        .arg("term")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--no-color"), "stdout was: {stdout}");
    assert!(stdout.contains("--remote"), "stdout was: {stdout}");
    assert!(stdout.contains("[Tab] switch pane"), "stdout was: {stdout}");
    assert!(
        stdout.contains("[j]/[k] move selection"),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains("[a]/[y] allow selected approval"),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains("[d]/[n] deny selected approval"),
        "stdout was: {stdout}"
    );
    assert!(stdout.contains(":destroy <env>"), "stdout was: {stdout}");
}

#[test]
fn term_remote_reports_unsupported_until_daemon_exists() {
    let temp_dir = make_temp_dir("term-remote-unsupported");
    let output = Command::new(agentenv_bin())
        .arg("term")
        .arg("--remote")
        .arg("http://127.0.0.1:9898")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("remote term requires"),
        "stderr was: {stderr}"
    );
}

#[test]
fn term_launches_and_quits_from_pty() {
    let temp_dir = make_temp_dir("term-pty-quit");
    write_minimal_env_state(&temp_dir, "demo");

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let reader_thread = thread::spawn(move || {
        let mut buffer = [0; 4096];
        let mut captured = Vec::new();
        while let Ok(bytes_read) = reader.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }
            let remaining = 16_384_usize.saturating_sub(captured.len());
            if remaining > 0 {
                captured.extend_from_slice(&buffer[..bytes_read.min(remaining)]);
            }
        }
        captured
    });
    let mut cmd = CommandBuilder::new(agentenv_bin());
    cmd.arg("term");
    cmd.env("HOME", temp_dir.display().to_string());
    cmd.env("NO_COLOR", "1");

    let mut child = pair.slave.spawn_command(cmd).unwrap();
    let mut writer = pair.master.take_writer().unwrap();

    thread::sleep(Duration::from_millis(500));
    writer.write_all(b"q").unwrap();
    writer.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let process_id = child.process_id();
            let kill_result = child.kill();
            let reap_result = child.wait();
            drop(writer);
            drop(pair);
            let pty_output = reader_thread.join().unwrap();
            panic!(
                "term did not exit within 5s after `q`; pid: {process_id:?}; kill: {kill_result:?}; reap: {reap_result:?}; pty output:\n{}",
                String::from_utf8_lossy(&pty_output)
            );
        }
        thread::sleep(Duration::from_millis(50));
    };

    drop(writer);
    drop(pair);
    let _pty_output = reader_thread.join().unwrap();
    assert!(status.success(), "term exited with {status:?}");
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
    let stdout_path = temp_dir.join("logs-context-follow.stdout");
    let stderr_path = temp_dir.join("logs-context-follow.stderr");
    fs::write(&events_path, "").unwrap();

    let mut child = Command::new(agentenv_bin())
        .arg("logs")
        .arg("demo")
        .arg("--driver")
        .arg("context")
        .arg("--follow")
        .env("HOME", &temp_dir)
        .stdout(process::Stdio::from(
            fs::File::create(&stdout_path).unwrap(),
        ))
        .stderr(process::Stdio::from(
            fs::File::create(&stderr_path).unwrap(),
        ))
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

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stdout = String::new();
    while Instant::now() < deadline {
        stdout = fs::read_to_string(&stdout_path).unwrap_or_default();
        if stdout.contains("context followed") {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!(
                "logs --follow exited before appended event was printed; status: {status}; stdout: {stdout}; stderr: {stderr}"
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        stdout.contains("context followed"),
        "stdout was: {stdout}; stderr was: {}",
        fs::read_to_string(&stderr_path).unwrap_or_default()
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
fn env_scoped_stats_reads_global_activity_when_per_env_store_exists() {
    let temp_dir = make_temp_dir("stats-env-global-plus-per-env");
    write_minimal_env_state(&temp_dir, "demo");
    seed_global_activity_db(
        &temp_dir,
        &[
            activity_event(
                "2026-04-21T00:00:00Z",
                ActivityKind::SandboxCreate,
                ActivityResult::Ok,
                "trace-global-create",
            )
            .with_actor_value("driver", serde_json::json!("openshell"))
            .with_latency_ms(10),
            activity_event(
                "2026-04-21T00:00:02Z",
                ActivityKind::SandboxDestroy,
                ActivityResult::Ok,
                "trace-other-destroy",
            )
            .with_env("other")
            .with_actor_value("driver", serde_json::json!("openshell"))
            .with_latency_ms(30),
        ],
    );
    seed_activity_db(
        &temp_dir,
        "demo",
        &[activity_event(
            "2026-04-21T00:00:01Z",
            ActivityKind::Exec,
            ActivityResult::Ok,
            "trace-per-env-exec",
        )
        .with_actor_value("driver", serde_json::json!("openshell"))
        .with_latency_ms(20)],
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
    assert!(stdout.contains("sandbox_create"), "stdout was: {stdout}");
    assert!(!stdout.contains("sandbox_destroy"), "stdout was: {stdout}");
    assert!(stdout.contains("latency: count=1"), "stdout was: {stdout}");
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
fn approvals_list_json_prints_pending_requests() {
    let temp = tempfile::tempdir().unwrap();
    seed_pending_approval(temp.path(), "demo", "req-1");

    let mut cmd = assert_cmd::Command::cargo_bin("agentenv").unwrap();
    cmd.env("HOME", temp.path())
        .args(["approvals", "list", "--env", "demo", "--json"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"request_id\": \"req-1\""));
}

#[test]
fn approvals_approve_records_decision() {
    let temp = tempfile::tempdir().unwrap();
    seed_pending_approval(temp.path(), "demo", "req-1");

    assert_cmd::Command::cargo_bin("agentenv")
        .unwrap()
        .env("HOME", temp.path())
        .args([
            "approvals",
            "approve",
            "req-1",
            "--env",
            "demo",
            "--scope",
            "session",
            "--reason",
            "ok",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("approved: req-1"));
}

#[test]
fn approvals_approve_writes_decision_event_to_explicit_sink() {
    let temp = tempfile::tempdir().unwrap();
    let events_path = temp.path().join("approval-events.jsonl");
    seed_pending_approval(temp.path(), "demo", "req-1");

    assert_cmd::Command::cargo_bin("agentenv")
        .unwrap()
        .env("HOME", temp.path())
        .arg("--events-sink")
        .arg(format!("file:{}", events_path.display()))
        .args([
            "approvals",
            "approve",
            "req-1",
            "--env",
            "demo",
            "--reason",
            "ok",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("approved: req-1"));

    let events = fs::read_to_string(&events_path).unwrap();
    assert!(events.contains("approval_decided"), "events were: {events}");
    assert!(events.contains("req-1"), "events were: {events}");
}

#[test]
fn approvals_deny_records_reason() {
    let temp = tempfile::tempdir().unwrap();
    seed_pending_approval(temp.path(), "demo", "req-1");

    assert_cmd::Command::cargo_bin("agentenv")
        .unwrap()
        .env("HOME", temp.path())
        .args([
            "approvals",
            "deny",
            "req-1",
            "--env",
            "demo",
            "--reason",
            "no",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("denied: req-1"));
}

#[test]
fn approvals_approve_fails_when_request_was_already_denied() {
    let temp = tempfile::tempdir().unwrap();
    seed_pending_approval(temp.path(), "demo", "req-1");

    assert_cmd::Command::cargo_bin("agentenv")
        .unwrap()
        .env("HOME", temp.path())
        .args([
            "approvals",
            "deny",
            "req-1",
            "--env",
            "demo",
            "--reason",
            "no",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("denied: req-1"));

    assert_cmd::Command::cargo_bin("agentenv")
        .unwrap()
        .env("HOME", temp.path())
        .args([
            "approvals",
            "approve",
            "req-1",
            "--env",
            "demo",
            "--reason",
            "ok",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("already decided as deny"));
}

#[test]
fn approvals_watch_once_json_prints_pending_requests() {
    let temp = tempfile::tempdir().unwrap();
    seed_pending_approval(temp.path(), "demo", "req-1");

    assert_cmd::Command::cargo_bin("agentenv")
        .unwrap()
        .env("HOME", temp.path())
        .args(["approvals", "watch", "--env", "demo", "--json", "--once"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"request_id\": \"req-1\""));
}

#[test]
fn term_once_prints_pending_approvals_across_envs() {
    let temp = tempfile::tempdir().unwrap();
    write_minimal_env_state(temp.path(), "demo");
    write_minimal_env_state(temp.path(), "tools");
    seed_pending_approval(temp.path(), "demo", "req-1");
    seed_pending_approval(temp.path(), "tools", "req-2");

    let output = Command::new(agentenv_bin())
        .arg("term")
        .arg("--once")
        .env("HOME", temp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("req-1"), "stdout was: {stdout}");
    assert!(stdout.contains("req-2"), "stdout was: {stdout}");
    assert!(stdout.contains("demo"), "stdout was: {stdout}");
    assert!(stdout.contains("tools"), "stdout was: {stdout}");
    assert!(stdout.contains("egress_host"), "stdout was: {stdout}");
    assert!(stdout.contains("network access"), "stdout was: {stdout}");
    assert!(stdout.contains("session"), "stdout was: {stdout}");
}

#[test]
fn term_once_does_not_create_missing_approval_database() {
    let temp = tempfile::tempdir().unwrap();
    write_minimal_env_state(temp.path(), "demo");
    let db_path = env_activity_db_path(temp.path(), "demo");
    assert!(!db_path.exists());

    let output = Command::new(agentenv_bin())
        .arg("term")
        .arg("--once")
        .env("HOME", temp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !db_path.exists(),
        "read-only term --once created {}",
        db_path.display()
    );
}

#[test]
fn approvals_serve_healthz_responds_ok() {
    let temp = tempfile::tempdir().unwrap();
    let port = reserve_tcp_port();
    let _server = spawn_approvals_server(temp.path(), port);

    wait_for_http_ok(port, "/healthz");
}

#[test]
fn approvals_serve_unsigned_decision_callback_returns_401_without_deciding() {
    let temp = tempfile::tempdir().unwrap();
    let port = reserve_tcp_port();
    write_approval_callback_config(temp.path(), "callback-test-secret");
    write_minimal_env_state(temp.path(), "demo");
    seed_pending_approval(temp.path(), "demo", "req-unsigned");
    let _server = spawn_approvals_server(temp.path(), port);
    wait_for_http_ok(port, "/healthz");
    let body = decision_callback_body("req-unsigned");

    let response = post_decision_callback(port, "req-unsigned", body, None);

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_no_approval_decision(temp.path(), "demo", "req-unsigned");
}

#[test]
fn approvals_serve_mismatched_signed_request_id_rejects_without_deciding_url_request() {
    let temp = tempfile::tempdir().unwrap();
    let port = reserve_tcp_port();
    let secret = "callback-test-secret";
    write_approval_callback_config(temp.path(), secret);
    write_minimal_env_state(temp.path(), "demo");
    seed_pending_approval(temp.path(), "demo", "req-url");
    seed_pending_approval(temp.path(), "demo", "req-body");
    let _server = spawn_approvals_server(temp.path(), port);
    wait_for_http_ok(port, "/healthz");
    let body = decision_callback_body("req-body");
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let headers = signed_callback_headers(secret, timestamp, "delivery-mismatch", body.as_bytes());

    let response = post_decision_callback(port, "req-url", body, Some(headers));

    assert!(!response.status().is_success());
    assert_no_approval_decision(temp.path(), "demo", "req-url");
    assert_no_approval_decision(temp.path(), "demo", "req-body");
}

#[test]
fn approvals_serve_stale_signed_decision_callback_returns_401_without_deciding() {
    let temp = tempfile::tempdir().unwrap();
    let port = reserve_tcp_port();
    let secret = "callback-test-secret";
    write_approval_callback_config(temp.path(), secret);
    write_minimal_env_state(temp.path(), "demo");
    seed_pending_approval(temp.path(), "demo", "req-stale");
    let _server = spawn_approvals_server(temp.path(), port);
    wait_for_http_ok(port, "/healthz");
    let body = decision_callback_body("req-stale");
    let timestamp = OffsetDateTime::now_utc().unix_timestamp() - 600;
    let headers = signed_callback_headers(secret, timestamp, "delivery-stale", body.as_bytes());

    let response = post_decision_callback(port, "req-stale", body, Some(headers));

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_no_approval_decision(temp.path(), "demo", "req-stale");
}

#[test]
fn approvals_serve_valid_signed_decision_callback_records_decision() {
    let temp = tempfile::tempdir().unwrap();
    let port = reserve_tcp_port();
    let secret = "callback-test-secret";
    write_approval_callback_config(temp.path(), secret);
    write_minimal_env_state(temp.path(), "demo");
    seed_pending_approval(temp.path(), "demo", "req-valid");
    let _server = spawn_approvals_server(temp.path(), port);
    wait_for_http_ok(port, "/healthz");
    let body = decision_callback_body("req-valid");
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let headers = signed_callback_headers(secret, timestamp, "delivery-valid", body.as_bytes());

    let response = post_decision_callback(port, "req-valid", body, Some(headers));

    assert!(response.status().is_success(), "HTTP {}", response.status());
    let store = ApprovalStore::open(env_activity_db_path(temp.path(), "demo")).unwrap();
    let decision = store.get_decision("req-valid").unwrap().unwrap();
    assert_eq!(
        decision.decision,
        agentenv_approvals::ApprovalDecisionValue::Allow
    );
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
fn env_scoped_audit_verify_reports_zero_for_missing_env_entries() {
    let temp_dir = make_temp_dir("audit-env-verify-zero");
    seed_global_audit_db(
        &temp_dir,
        &[activity_event(
            "2026-04-21T00:00:00Z",
            ActivityKind::CredentialInjected,
            ActivityResult::Ok,
            "trace-other-credential",
        )
        .with_env("other")
        .with_subject_value("name", serde_json::json!("OTHER_API_KEY"))],
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
    assert!(
        stdout.contains("valid: 0 entries checked"),
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
fn uninstall_delegates_all_flags_to_configured_script() {
    let temp_dir = make_temp_dir("uninstall-delegates-flags");
    let script = temp_dir.join("uninstall.sh");
    let args_file = temp_dir.join("args.txt");
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
for arg in "$@"; do
    printf '%s\n' "$arg"
done > "$AGENTENV_UNINSTALL_ARGS_OUT"
"#,
    )
    .unwrap();
    make_executable(&script);

    let output = Command::new(agentenv_bin())
        .arg("uninstall")
        .arg("-y")
        .arg("--dry-run")
        .arg("--keep-openshell")
        .arg("--keep-drivers")
        .arg("--keep-credentials")
        .arg("--keep-data")
        .arg("--delete-models")
        .env("AGENTENV_UNINSTALL_SCRIPT", &script)
        .env("AGENTENV_UNINSTALL_ARGS_OUT", &args_file)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let args: Vec<_> = fs::read_to_string(args_file)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        args,
        [
            "--yes",
            "--keep-openshell",
            "--keep-drivers",
            "--keep-credentials",
            "--keep-data",
            "--delete-models",
            "--dry-run",
        ]
    );
}

#[test]
fn uninstall_propagates_script_exit_status() {
    let temp_dir = make_temp_dir("uninstall-propagates-status");
    let script = temp_dir.join("uninstall.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
exit 7
"#,
    )
    .unwrap();
    make_executable(&script);

    let output = Command::new(agentenv_bin())
        .arg("uninstall")
        .arg("--yes")
        .env("AGENTENV_UNINSTALL_SCRIPT", &script)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn uninstall_does_not_discover_script_from_current_dir() {
    let temp_dir = make_temp_dir("uninstall-ignore-cwd-script");
    let script = temp_dir.join("uninstall.sh");
    let marker = temp_dir.join("executed.txt");
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
printf executed > "$AGENTENV_UNINSTALL_MARKER"
"#,
    )
    .unwrap();
    make_executable(&script);

    let output = Command::new(agentenv_bin())
        .arg("uninstall")
        .arg("--dry-run")
        .current_dir(&temp_dir)
        .env(
            "AGENTENV_RELEASE_BASE_URL",
            "file:///agentenv-missing-release",
        )
        .env("AGENTENV_VERSION", "v-missing")
        .env("AGENTENV_UNINSTALL_MARKER", &marker)
        .env_remove("AGENTENV_UNINSTALL_SCRIPT")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "cwd uninstall.sh was executed: {}",
        output_summary(&output)
    );
}

#[test]
fn uninstall_cleans_up_hosted_fallback_temp_dir() {
    let temp_dir = make_temp_dir("uninstall-cleanup-hosted");
    let version = "v-cleanup";
    let hosted_dir = temp_dir.join("releases").join("download").join(version);
    fs::create_dir_all(&hosted_dir).unwrap();
    let hosted_script = hosted_dir.join("uninstall.sh");
    let hosted_script_body = r#"#!/bin/sh
set -eu
dirname "$0" > "$AGENTENV_UNINSTALL_DIR_OUT"
"#;
    fs::write(&hosted_script, hosted_script_body).unwrap();
    fs::write(
        hosted_dir.join("uninstall.sh.sha256"),
        format!(
            "{}  uninstall.sh\n",
            hex::encode(Sha256::digest(hosted_script_body.as_bytes()))
        ),
    )
    .unwrap();

    let work_dir = temp_dir.join("work");
    fs::create_dir_all(&work_dir).unwrap();
    let download_parent = temp_dir.join("tmp");
    fs::create_dir_all(&download_parent).unwrap();
    let download_dir_file = temp_dir.join("download-dir.txt");

    let output = Command::new(agentenv_bin())
        .arg("uninstall")
        .arg("--dry-run")
        .current_dir(&work_dir)
        .env(
            "AGENTENV_RELEASE_BASE_URL",
            format!(
                "file://{}",
                temp_dir.join("releases").join("download").display()
            ),
        )
        .env("AGENTENV_VERSION", format!("refs/tags/{version}"))
        .env("AGENTENV_UNINSTALL_DIR_OUT", &download_dir_file)
        .env("TMPDIR", &download_parent)
        .env_remove("AGENTENV_UNINSTALL_SCRIPT")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let download_dir = PathBuf::from(fs::read_to_string(download_dir_file).unwrap().trim());
    assert!(
        !download_dir.exists(),
        "download directory was not cleaned up: {}",
        download_dir.display()
    );
}

#[test]
fn uninstall_rejects_checksum_mismatch_and_cleans_up_download_dir() {
    let temp_dir = make_temp_dir("uninstall-checksum-mismatch");
    let version = "v-bad-checksum";
    let hosted_dir = temp_dir.join("releases").join("download").join(version);
    fs::create_dir_all(&hosted_dir).unwrap();
    let hosted_script = hosted_dir.join("uninstall.sh");
    fs::write(
        &hosted_script,
        r#"#!/bin/sh
set -eu
printf executed > "$AGENTENV_UNINSTALL_MARKER"
"#,
    )
    .unwrap();
    fs::write(
        hosted_dir.join("uninstall.sh.sha256"),
        "0000000000000000000000000000000000000000000000000000000000000000  uninstall.sh\n",
    )
    .unwrap();

    let work_dir = temp_dir.join("work");
    fs::create_dir_all(&work_dir).unwrap();
    let download_parent = temp_dir.join("tmp");
    fs::create_dir_all(&download_parent).unwrap();
    let marker = temp_dir.join("executed.txt");
    let before = agentenv_uninstall_temp_dirs(&download_parent);

    let output = Command::new(agentenv_bin())
        .arg("uninstall")
        .arg("--dry-run")
        .current_dir(&work_dir)
        .env(
            "AGENTENV_RELEASE_BASE_URL",
            format!(
                "file://{}",
                temp_dir.join("releases").join("download").display()
            ),
        )
        .env("AGENTENV_VERSION", version)
        .env("AGENTENV_UNINSTALL_MARKER", &marker)
        .env("TMPDIR", &download_parent)
        .env_remove("AGENTENV_UNINSTALL_SCRIPT")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "checksum-mismatched uninstall script was executed: {}",
        output_summary(&output)
    );
    let after = agentenv_uninstall_temp_dirs(&download_parent);
    let leaked: Vec<_> = after.difference(&before).collect();
    assert!(
        leaked.is_empty(),
        "download temp dirs leaked after checksum failure: {leaked:?}\n{}",
        output_summary(&output)
    );
}

#[test]
fn uninstall_discovers_sibling_script_next_to_current_exe() {
    let temp_dir = make_temp_dir("uninstall-sibling-script");
    let bin_dir = temp_dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let copied_bin = bin_dir.join("agentenv");
    fs::copy(agentenv_bin(), &copied_bin).unwrap();
    make_executable(&copied_bin);

    let script = bin_dir.join("uninstall.sh");
    let args_file = temp_dir.join("args.txt");
    let env_file = temp_dir.join("env.txt");
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
for arg in "$@"; do
    printf '%s\n' "$arg"
done > "$AGENTENV_UNINSTALL_ARGS_OUT"
{
    printf 'AGENTENV_BIN=%s\n' "${AGENTENV_BIN-}"
    printf 'AGENTENV_INSTALL_DIR=%s\n' "${AGENTENV_INSTALL_DIR-}"
} > "$AGENTENV_UNINSTALL_ENV_OUT"
"#,
    )
    .unwrap();
    make_executable(&script);

    let output = Command::new(&copied_bin)
        .arg("uninstall")
        .arg("--dry-run")
        .env("AGENTENV_UNINSTALL_ARGS_OUT", &args_file)
        .env("AGENTENV_UNINSTALL_ENV_OUT", &env_file)
        .env_remove("AGENTENV_UNINSTALL_SCRIPT")
        .env_remove("AGENTENV_BIN")
        .env_remove("AGENTENV_INSTALL_DIR")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let args: Vec<_> = fs::read_to_string(args_file)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(args, ["--dry-run"]);
    let env = fs::read_to_string(env_file).unwrap();
    assert!(
        env.contains(&format!("AGENTENV_BIN={}", copied_bin.display())),
        "env was: {env}"
    );
    assert!(
        env.contains(&format!("AGENTENV_INSTALL_DIR={}", bin_dir.display())),
        "env was: {env}"
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

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}

fn write_filesystem_registry_skill(registry: &Path, name: &str, version: &str, description: &str) {
    let bundle = registry.join("bundles").join(name).join(version);
    fs::create_dir_all(&bundle).unwrap();
    fs::write(
        bundle.join("SKILL.md"),
        format!("# {description}\n\n{name}\n"),
    )
    .unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        format!(
            "name: {name}\nversion: {version}\ndescription: {description}\nentry: SKILL.md\nfiles:\n  - SKILL.md\n"
        ),
    )
    .unwrap();
    fs::write(
        registry.join("index.yaml"),
        format!(
            "skills:\n  - name: {name}\n    version: {version}\n    description: {description}\n    registry: local\n"
        ),
    )
    .unwrap();
}

fn assert_skill_search_names(stdout: &[u8], expected: &[&str]) {
    let json: serde_json::Value = serde_json::from_slice(stdout).unwrap();
    let names = json["skills"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skill| skill["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        expected,
        "stdout was: {}",
        String::from_utf8_lossy(stdout)
    );
}

fn write_failing_openshell_cli(home: &Path) {
    let bin_dir = home.join(".local").join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let openshell = bin_dir.join("openshell");
    fs::write(
        &openshell,
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf 'openshell 0.0.30\n'
  exit 0
fi
if [ "$1" = "status" ]; then
  printf 'gateway down\n' >&2
  exit 1
fi
printf 'unexpected openshell test command: %s\n' "$*" >&2
exit 1
"#,
    )
    .unwrap();
    make_executable(&openshell);
}

fn agentenv_uninstall_temp_dirs(root: &Path) -> BTreeSet<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name()?.to_str()?;
            name.starts_with("agentenv-uninstall-").then_some(path)
        })
        .collect()
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

fn write_minimal_signed_snapshot(root: &Path, source_env: &str) -> PathBuf {
    write_minimal_signed_snapshot_with_credentials(root, source_env, &[])
}

fn write_minimal_signed_snapshot_with_credentials(
    root: &Path,
    source_env: &str,
    credential_names: &[&str],
) -> PathBuf {
    let snapshot_dir = root.join(format!("{source_env}.agentenvsnap"));
    fs::create_dir_all(snapshot_dir.join("workspace")).unwrap();
    fs::write(snapshot_dir.join("workspace").join("README.md"), "hello\n").unwrap();
    let blueprint_yaml = r#"
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
"#;
    fs::write(snapshot_dir.join("blueprint.yaml"), blueprint_yaml).unwrap();
    let mut discovery_config = agentenv_core::driver_catalog::DriverDiscoveryConfig::from_env();
    discovery_config.installed_root = root.join("drivers");
    let driver_artifacts =
        agentenv_core::driver_artifact::discover_driver_artifacts(discovery_config, None).unwrap();
    let lockfile = agentenv_core::portable_lockfile::build_portable_lockfile(
        agentenv_core::portable_lockfile::PortableLockfileInput {
            name: source_env.to_owned(),
            blueprint_yaml: blueprint_yaml.to_owned(),
            driver_artifacts,
        },
    )
    .unwrap();
    fs::write(
        snapshot_dir.join("lock.yaml"),
        lockfile.to_yaml_deterministic().unwrap(),
    )
    .unwrap();
    fs::write(
        snapshot_dir.join("policy.yaml"),
        serde_yaml::to_string(&lockfile.policy.resolved).unwrap(),
    )
    .unwrap();
    let credential_requirements = credential_names
        .iter()
        .map(
            |name| agentenv_core::snapshot::SnapshotCredentialRequirement {
                name: (*name).to_owned(),
                source: "env".to_owned(),
                reference: Some((*name).to_owned()),
                required: Some(true),
            },
        )
        .collect();
    let manifest = agentenv_core::snapshot::manifest_for_snapshot_dir(
        &snapshot_dir,
        source_env,
        credential_requirements,
        Vec::new(),
    )
    .unwrap();
    agentenv_core::snapshot::write_signed_manifest(
        &snapshot_dir,
        &root.join("snapshot-signing.key"),
        &manifest,
    )
    .unwrap();
    snapshot_dir
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

fn seed_pending_approval(home: &Path, env: &str, request_id: &str) {
    let db_path = env_activity_db_path(home, env);
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let store = ApprovalStore::open(db_path).unwrap();
    let requested_at = OffsetDateTime::from_unix_timestamp(1_777_000_000).unwrap();
    let request = ApprovalRequest::new(
        request_id,
        env,
        ApprovalKind::EgressHost,
        "api.example.test:443",
        "network access",
        json!({"url": "https://api.example.test/v1"}),
        requested_at,
        ApprovalScope::Session,
        Duration::from_secs(300),
        "trace-approval-1",
    );
    store.insert_request(&request).unwrap();
}

fn reserve_tcp_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct ApprovalsServerChild {
    child: process::Child,
    _guard: MutexGuard<'static, ()>,
}

static APPROVALS_SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

impl Drop for ApprovalsServerChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_approvals_server(home: &Path, port: u16) -> ApprovalsServerChild {
    let guard = APPROVALS_SERVER_TEST_LOCK.lock().unwrap();
    let child = Command::new(agentenv_bin())
        .env("HOME", home)
        .args(["approvals", "serve", "--addr", &format!("127.0.0.1:{port}")])
        .spawn()
        .unwrap();
    ApprovalsServerChild {
        child,
        _guard: guard,
    }
}

fn wait_for_http_ok(port: u16, path: &str) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}{path}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last_error = None;

    while std::time::Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => last_error = Some(format!("HTTP {}", response.status())),
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(50));
    }

    panic!(
        "timed out waiting for {url}: {}",
        last_error.unwrap_or_else(|| "no attempts were made".to_owned())
    );
}

fn write_approval_callback_config(home: &Path, secret: &str) {
    let config_dir = home.join(".agentenv");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.yaml"),
        format!(
            r#"
approvals:
  webhooks:
    - url: https://approvals.example.test/agentenv
      secret: {secret}
"#
        ),
    )
    .unwrap();
}

fn decision_callback_body(request_id: &str) -> String {
    serde_json::json!({
        "request_id": request_id,
        "decision": "allow",
        "scope": "session",
        "decided_by": "review-test",
        "reason": "approved"
    })
    .to_string()
}

fn signed_callback_headers(
    secret: &str,
    timestamp: i64,
    delivery_id: &str,
    body: &[u8],
) -> Vec<(&'static str, String)> {
    let signature = sign_payload(secret, timestamp, delivery_id, body);
    vec![
        ("x-agentenv-signature", signature.header_value().to_owned()),
        ("x-agentenv-timestamp", timestamp.to_string()),
        ("x-agentenv-delivery", delivery_id.to_owned()),
    ]
}

fn post_decision_callback(
    port: u16,
    request_id: &str,
    body: String,
    headers: Option<Vec<(&'static str, String)>>,
) -> reqwest::blocking::Response {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut request = client
        .post(format!(
            "http://127.0.0.1:{port}/approvals/{request_id}/decision"
        ))
        .header("content-type", "application/json")
        .body(body);
    for (name, value) in headers.unwrap_or_default() {
        request = request.header(name, value);
    }
    request.send().unwrap()
}

fn assert_no_approval_decision(home: &Path, env: &str, request_id: &str) {
    let store = ApprovalStore::open(env_activity_db_path(home, env)).unwrap();
    assert!(
        store.get_decision(request_id).unwrap().is_none(),
        "approval request `{request_id}` unexpectedly has a decision"
    );
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
