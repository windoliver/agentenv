use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use agentenv_approvals::{
    sign_payload, ApprovalKind, ApprovalRequest, ApprovalScope, ApprovalStore,
};
use agentenv_core::skills::{compute_bundle_digest, load_skill_manifest, signature_payload};
use agentenv_events::{
    audit::{AuditSigningKey, AuditStore},
    store::{EventQuery, SqliteEventStore},
    ActivityEvent, ActivityKind, ActivityResult,
};
use ed25519_dalek::{Signer, SigningKey};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const LOCAL_HTTP_TEST_TIMEOUT: Duration = Duration::from_secs(30);
const PTY_QUIT_TIMEOUT: Duration = Duration::from_secs(15);

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
fn bundle_help_lists_as_skill_and_out_flags() {
    let temp_dir = make_temp_dir("bundle-help");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("--help")
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
    assert!(stdout.contains("--as-skill"), "stdout was: {stdout}");
    assert!(stdout.contains("--out"), "stdout was: {stdout}");
    assert!(stdout.contains("--env"), "stdout was: {stdout}");
}

#[test]
fn bundle_as_skill_requires_out_flag() {
    let temp_dir = make_temp_dir("bundle-missing-out");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("demo")
        .arg("--as-skill")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bundle --as-skill requires --out <dir>"),
        "stderr was: {stderr}"
    );
}

#[test]
fn bundle_rejects_missing_as_skill_flag() {
    let temp_dir = make_temp_dir("bundle-missing-as-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("demo")
        .arg("--out")
        .arg(temp_dir.join("bundle-out"))
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bundle currently supports only --as-skill"),
        "stderr was: {stderr}"
    );
}

#[test]
fn bundle_as_skill_rejects_missing_env() {
    let temp_dir = make_temp_dir("bundle-missing-env");
    let out_dir = temp_dir.join("bundle-out");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("missing-env")
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing-env"), "stderr was: {stderr}");
}

#[test]
fn bundle_directory_source_loads_architecture_reference() {
    let temp_dir = make_temp_dir("bundle-reference-doc");
    write_minimal_env_state(&temp_dir, "demo");
    let project_dir = temp_dir.join("demo");
    fs::create_dir_all(project_dir.join("docs")).unwrap();
    fs::write(
        project_dir.join("docs").join("ARCHITECTURE.md"),
        "# Architecture\n\nReference details\n",
    )
    .unwrap();
    let out_dir = fs::canonicalize(&temp_dir).unwrap().join("demo-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg(&project_dir)
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let reference = fs::read_to_string(out_dir.join("references/architecture.md")).unwrap();
    assert!(reference.contains("Source: `docs/ARCHITECTURE.md`"));
    assert!(reference.contains("Reference details"));
}

#[test]
fn bundle_as_skill_exports_existing_env_with_project_reference() {
    let temp_dir = make_temp_dir("bundle-project-reference");
    write_minimal_env_state(&temp_dir, "demo");
    let project_dir = temp_dir.join("demo");
    fs::create_dir_all(project_dir.join("docs")).unwrap();
    fs::write(
        project_dir.join("docs").join("ARCHITECTURE.md"),
        "# Architecture\n\nProject reference details\n",
    )
    .unwrap();
    run_git(&project_dir, &["init"]);
    run_git(&project_dir, &["config", "user.name", "Detected Author"]);
    run_git(
        &project_dir,
        &["config", "user.email", "detected@example.com"],
    );
    run_git(&project_dir, &["add", "docs/ARCHITECTURE.md"]);
    run_git(
        &project_dir,
        &["commit", "-m", "Add architecture reference"],
    );
    let expected_commit = git_stdout(&project_dir, &["rev-parse", "HEAD"]);
    let out_dir = fs::canonicalize(&temp_dir)
        .unwrap()
        .join("demo-project-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg(&project_dir)
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .arg("--author")
        .arg("Alice Example")
        .arg("--license")
        .arg("MIT")
        .arg("--tag")
        .arg("rust")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("SKILL.md").is_file());
    assert!(out_dir.join("skill.yaml").is_file());
    let skill = fs::read_to_string(out_dir.join("SKILL.md")).unwrap();
    assert!(
        skill.contains("author: Alice Example"),
        "SKILL.md was: {skill}"
    );
    assert!(skill.contains("license: MIT"), "SKILL.md was: {skill}");
    assert!(skill.contains("- rust"), "SKILL.md was: {skill}");
    let reference = fs::read_to_string(out_dir.join("references/architecture.md")).unwrap();
    assert!(reference.contains("Source: `docs/ARCHITECTURE.md`"));
    assert!(reference.contains("Project reference details"));
    let provenance: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(out_dir.join(".agentenv/provenance.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        provenance["source"]["project_git_commit"].as_str(),
        Some(expected_commit.as_str())
    );
    assert_eq!(
        provenance["source"]["project_git_dirty"].as_bool(),
        Some(false)
    );
}

#[test]
fn bundle_metadata_detection_uses_local_git_author_and_cargo_license() {
    let temp_dir = make_temp_dir("bundle-detected-metadata");
    write_minimal_env_state(&temp_dir, "demo");
    let project_dir = temp_dir.join("demo");
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(
        project_dir.join("Cargo.toml"),
        "[package]\nname = 'demo'\nversion = '0.1.0'\nlicense = 'Apache-2.0'\n",
    )
    .unwrap();
    run_git(&project_dir, &["init"]);
    run_git(&project_dir, &["config", "user.name", "Detected Author"]);
    let out_dir = fs::canonicalize(&temp_dir)
        .unwrap()
        .join("demo-detected-metadata-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg(&project_dir)
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let skill = fs::read_to_string(out_dir.join("SKILL.md")).unwrap();
    assert!(
        skill.contains("author: Detected Author"),
        "SKILL.md was: {skill}"
    );
    assert!(
        skill.contains("license: Apache-2.0"),
        "SKILL.md was: {skill}"
    );
}

#[test]
fn bundle_metadata_detection_ignores_global_git_author_for_non_git_project() {
    let temp_dir = make_temp_dir("bundle-ignore-global-git-author");
    write_minimal_env_state(&temp_dir, "demo");
    let project_dir = temp_dir.join("demo");
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(project_dir.join("LICENSE-MIT"), "MIT License\n").unwrap();
    let git_config = Command::new("git")
        .args(["config", "--global", "user.name", "Global Author"])
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        git_config.status.success(),
        "git config --global failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&git_config.stdout),
        String::from_utf8_lossy(&git_config.stderr)
    );
    let out_dir = fs::canonicalize(&temp_dir)
        .unwrap()
        .join("demo-license-file-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg(&project_dir)
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let skill = fs::read_to_string(out_dir.join("SKILL.md")).unwrap();
    assert!(!skill.contains("Global Author"), "SKILL.md was: {skill}");
    assert!(skill.contains("license: MIT"), "SKILL.md was: {skill}");
}

#[test]
fn bundle_dot_source_derives_env_from_current_directory() {
    let temp_dir = make_temp_dir("bundle-dot-source");
    write_minimal_env_state(&temp_dir, "demo");
    let project_dir = temp_dir.join("demo");
    fs::create_dir_all(&project_dir).unwrap();
    let out_dir = fs::canonicalize(&temp_dir).unwrap().join("demo-dot-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg(".")
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .env("HOME", &temp_dir)
        .current_dir(&project_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("SKILL.md").is_file());
}

#[cfg(unix)]
#[test]
fn bundle_directory_source_skips_symlinked_reference_document() {
    use std::os::unix::fs::symlink;

    let temp_dir = make_temp_dir("bundle-symlink-reference");
    write_minimal_env_state(&temp_dir, "demo");
    let project_dir = temp_dir.join("demo");
    fs::create_dir_all(project_dir.join("docs")).unwrap();
    let outside_reference = temp_dir.join("outside-architecture.md");
    fs::write(&outside_reference, "# Outside\n\nDo not copy\n").unwrap();
    symlink(
        &outside_reference,
        project_dir.join("docs").join("ARCHITECTURE.md"),
    )
    .unwrap();
    let out_dir = fs::canonicalize(&temp_dir)
        .unwrap()
        .join("demo-symlink-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg(&project_dir)
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!out_dir.join("references/architecture.md").exists());
}

#[test]
fn bundle_json_outputs_digest_summary() {
    let temp_dir = make_temp_dir("bundle-json-summary");
    write_minimal_env_state(&temp_dir, "demo");
    let out_dir = fs::canonicalize(&temp_dir).unwrap().join("demo-json-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("demo")
        .arg("--as-skill")
        .arg("--out")
        .arg(&out_dir)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env_remove("AGENTENV_DRIVER_PATH")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        summary["output_dir"].as_str(),
        Some(out_dir.to_str().unwrap())
    );
    assert_eq!(summary["skill_name"].as_str(), Some("demo"));
    assert_eq!(summary["version"].as_str(), Some("1.0.0"));
    assert!(summary["bundle_digest"].as_str().is_some());
    assert!(summary["blueprint_digest"].as_str().is_some());
    assert!(summary["lockfile_digest"].as_str().is_some());
}

#[test]
fn bundle_as_skill_json_output_installs_as_local_skill() {
    let temp_dir = make_temp_dir("bundle-json-install");
    write_minimal_env_state(&temp_dir, "demo");
    let output_dir = fs::canonicalize(&temp_dir).unwrap().join("demo-skill");

    let output = Command::new(agentenv_bin())
        .arg("bundle")
        .arg("demo")
        .arg("--as-skill")
        .arg("--out")
        .arg(&output_dir)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env_remove("AGENTENV_DRIVER_PATH")
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        output.stdout.ends_with(b"\n"),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let keys = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "blueprint_digest",
            "bundle_digest",
            "lockfile_digest",
            "output_dir",
            "skill_name",
            "version",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(json["output_dir"], output_dir.to_str().unwrap());
    assert_eq!(json["skill_name"], "demo");
    assert_eq!(json["version"], "1.0.0");
    assert!(json["bundle_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(json["blueprint_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(json["lockfile_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let install = Command::new(agentenv_bin())
        .arg("skills")
        .arg("install")
        .arg("--from")
        .arg(&output_dir)
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env_remove("AGENTENV_DRIVER_PATH")
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );

    let verify = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("demo")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn fork_reports_capability_missing_for_openshell() {
    let temp_dir = make_temp_dir("fork-openshell-unsupported");
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    let state_path = env_dir.join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state["handles"]["sandbox"] = serde_json::Value::String("openshell://demo".to_owned());
    fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let output = Command::new(agentenv_bin())
        .arg("fork")
        .arg("demo")
        .arg("--name")
        .arg("experiment")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("supports_snapshots"),
        "stderr was: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn fork_microvm_cli_clones_env_with_fake_firecracker_api() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = PathBuf::from(format!("/tmp/ae-fc-{}", unique_suffix()));
    fs::create_dir_all(&temp_dir).unwrap();
    let agentenv_root = temp_dir.join(".agentenv");
    let source_workdir = agentenv_root.join("microvm").join("demo");
    let child_workdir = agentenv_root.join("microvm").join("experiment");
    fs::create_dir_all(&source_workdir).unwrap();
    fs::create_dir_all(&child_workdir).unwrap();
    let source_api_sock = source_workdir.join("api.sock");
    let child_api_sock = child_workdir.join("api.sock");
    let source_server = spawn_fake_firecracker_api(&source_api_sock, 3);
    let child_server = spawn_fake_firecracker_api(&child_api_sock, 1);

    let rootfs = temp_dir.join("rootfs.ext4");
    fs::write(&rootfs, "rootfs").unwrap();
    let env_dir = write_minimal_env_state(&temp_dir, "demo");
    fs::write(
        env_dir.join("blueprint.yaml"),
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: microvm
  runtime: firecracker
  kernel: /var/lib/agentenv/kernel/vmlinux
  rootfs: /var/lib/agentenv/rootfs.ext4
agent:
  driver: codex
context:
  driver: filesystem
  mount: .
policy:
  tier: restricted
  presets: []
"#,
    )
    .unwrap();
    let state_path = env_dir.join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state["drivers"]["sandbox"]["name"] = serde_json::Value::String("microvm".to_owned());
    let source_handle = format!(
        "microvm://firecracker/demo?workdir={}&api_sock={}&pid_file={}&rootfs={}&tap=tap-source",
        source_workdir.display(),
        source_api_sock.display(),
        source_workdir.join("firecracker.pid").display(),
        rootfs.display(),
    );
    state["handles"]["sandbox"] = serde_json::Value::String(source_handle.clone());
    fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let fake_bin = temp_dir.join("bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let firecracker = fake_bin.join("firecracker");
    fs::write(&firecracker, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&firecracker).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&firecracker, perms).unwrap();
    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let test_path = format!("{}:{}", fake_bin.display(), original_path.to_string_lossy());

    let output = Command::new(agentenv_bin())
        .arg("fork")
        .arg(&source_handle)
        .arg("--name")
        .arg("experiment")
        .env("HOME", &temp_dir)
        .env("PATH", test_path)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout was: {}\nstderr was: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Environment `experiment` forked from `demo`"));
    assert!(stdout.contains("snapshot: microvm-snapshot://firecracker/demo/experiment"));

    let target_state_path = temp_dir
        .join(".agentenv")
        .join("envs")
        .join("experiment")
        .join("state.json");
    let target: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(target_state_path).unwrap()).unwrap();
    assert_eq!(target["name"], "experiment");
    let handle = target["handles"]["sandbox"].as_str().unwrap();
    assert!(handle.starts_with("microvm://firecracker/experiment?"));
    assert!(handle.contains("tap=tap-source"));
    assert!(child_workdir.join("rootfs.ext4").is_file());

    let source_requests = source_server.join().unwrap();
    let child_requests = child_server.join().unwrap();
    assert_eq!(source_requests.len(), 3);
    assert!(source_requests[0].starts_with("PATCH /vm "));
    assert!(source_requests[1].starts_with("PUT /snapshot/create "));
    assert!(source_requests[2].starts_with("PATCH /vm "));
    assert_eq!(child_requests.len(), 1);
    assert!(child_requests[0].starts_with("PUT /snapshot/load "));
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
        "search", "add", "install", "list", "info", "remove", "publish", "verify", "prune",
    ] {
        assert!(
            stdout.contains(command),
            "missing {command}; stdout was: {stdout}"
        );
    }
}

#[test]
fn skills_help_lists_propose_subcommand() {
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line.trim_start().starts_with("propose")),
        "stdout was: {stdout}"
    );
}

#[test]
fn skills_propose_help_lists_expected_flags() {
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in ["--from-traces", "--blueprint", "--min-self-test-score"] {
        assert!(
            stdout.contains(flag),
            "missing {flag}; stdout was: {stdout}"
        );
    }
}

#[test]
fn skills_propose_requires_from_traces_and_blueprint() {
    let temp_dir = make_temp_dir("skills-propose-required");
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--from-traces"), "stderr was: {stderr}");
}

#[test]
fn skills_propose_validation_runs_before_loading_skills_config() {
    let temp_dir = make_temp_dir("skills-propose-invalid-config");
    let config_dir = temp_dir.join(".config").join("agentenv");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(config_dir.join("config.toml"), "skills = [").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--from-traces"), "stderr was: {stderr}");
}

#[test]
fn skills_propose_open_pr_rejects_invalid_repo() {
    let temp_dir = make_temp_dir("skills-propose-invalid-repo");
    let blueprint = temp_dir.join("agentenv.yaml");
    fs::write(&blueprint, "version: 0.1.0\n").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--open-pr")
        .arg("--repo")
        .arg("bad repo")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("no proposals emitted"),
        "stdout was: {stdout}"
    );
    assert!(stderr.contains("owner/repo"), "stderr was: {stderr}");
}

#[test]
fn skills_propose_from_traces_emits_local_proposal_with_fake_llm() {
    let temp_dir = make_temp_dir("skills-propose-e2e");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let out = temp_dir.join("proposed");
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--out")
        .arg(&out)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["warnings"].as_array().unwrap().len(), 0);
    assert_eq!(json["proposals"][0]["name"], "fs-edit-skill");
    let expected_proposal_path = out.join("fs-edit-skill").to_string_lossy().into_owned();
    assert_eq!(
        json["proposals"][0]["path"].as_str(),
        Some(expected_proposal_path.as_str())
    );
    assert_eq!(json["proposals"][0]["novelty"].as_f64(), Some(0.9));
    assert_eq!(json["proposals"][0]["utility"].as_f64(), Some(0.6));
    assert_eq!(json["proposals"][0]["self_test_score"].as_f64(), Some(1.0));

    let proposal_dir = out.join("fs-edit-skill");
    for relative in [
        "SKILL.md",
        "skill.yaml",
        "proposal.yaml",
        "self-test.json",
        "traces/provenance.json",
    ] {
        assert!(
            proposal_dir.join(relative).is_file(),
            "proposal should emit {relative}"
        );
    }

    let skill_md = fs::read_to_string(proposal_dir.join("SKILL.md")).unwrap();
    assert!(skill_md.contains("agentenv-proposal: true"));
    assert!(skill_md.contains("Read {{target_path}}."));

    let skill_yaml: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(proposal_dir.join("skill.yaml")).unwrap())
            .unwrap();
    assert_eq!(skill_yaml["name"].as_str(), Some("fs-edit-skill"));
    assert_eq!(skill_yaml["entry"].as_str(), Some("SKILL.md"));
    assert_eq!(skill_yaml["agentenv_proposal"].as_bool(), Some(true));
    let files = skill_yaml["files"].as_sequence().unwrap();
    for expected in [
        "SKILL.md",
        "proposal.yaml",
        "self-test.json",
        "traces/provenance.json",
    ] {
        assert!(
            files.iter().any(|file| file.as_str() == Some(expected)),
            "skill.yaml should declare {expected}: {skill_yaml:?}"
        );
    }

    let proposal_yaml: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(proposal_dir.join("proposal.yaml")).unwrap())
            .unwrap();
    assert_eq!(proposal_yaml["status"].as_str(), Some("proposed"));
    let expected_blueprint_id = blueprint_digest(&blueprint);
    assert_eq!(
        proposal_yaml["blueprint_id"].as_str(),
        Some(expected_blueprint_id.as_str())
    );
    assert_eq!(proposal_yaml["occurrences"].as_u64(), Some(3));

    let self_test: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(proposal_dir.join("self-test.json")).unwrap())
            .unwrap();
    assert_eq!(self_test["passed"].as_bool(), Some(true));
    assert_eq!(self_test["matched_steps"].as_u64(), Some(1));
    assert_eq!(self_test["total_steps"].as_u64(), Some(1));

    let provenance: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(proposal_dir.join("traces/provenance.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        provenance["fingerprint"].as_str(),
        Some(fs_read_candidate_fingerprint())
    );
    assert_eq!(provenance["source_trace_ids"].as_array().unwrap().len(), 3);
    assert_eq!(provenance["sequence"][0]["tool"].as_str(), Some("fs_read"));
}

#[test]
fn skills_propose_filters_duplicate_existing_proposal_by_min_novelty() {
    let temp_dir = make_temp_dir("skills-propose-existing-proposal");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let out = temp_dir.join("proposed");
    let existing = out.join("existing-fs-edit-skill");
    fs::create_dir_all(&existing).unwrap();
    fs::write(
        existing.join("SKILL.md"),
        "---\nname: existing-fs-edit-skill\ndescription: Edit a repeated filesystem target.\n---\n\nRead {{target_path}}.\n",
    )
    .unwrap();
    fs::write(
        existing.join("skill.yaml"),
        "name: existing-fs-edit-skill\nversion: 0.1.0\ndescription: Edit a repeated filesystem target.\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--out")
        .arg(&out)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--min-novelty")
        .arg("0.85")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json_named("fs-edit-skill-v2"),
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["proposals"].as_array().unwrap().len(), 0);
    let warnings = json["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .unwrap()
            .contains("novelty 0.3 is below 0.85")),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !out.join("fs-edit-skill-v2/SKILL.md").exists(),
        "duplicate-ish proposal should be skipped before emission"
    );
}

#[test]
fn skills_propose_filters_duplicate_installed_skill_by_provenance_fingerprint() {
    let temp_dir = make_temp_dir("skills-propose-existing-installed");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let bundle = temp_dir.join("installed-skill-bundle");
    fs::create_dir_all(bundle.join("traces")).unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: existing-installed-skill\nversion: 0.1.0\ndescription: unrelated installed skill\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - traces/provenance.json\nself_test:\n  command: test -f traces/provenance.json\n",
    )
    .unwrap();
    fs::write(
        bundle.join("SKILL.md"),
        "This text intentionally does not overlap the generated procedure.\n",
    )
    .unwrap();
    fs::write(
        bundle.join("traces/provenance.json"),
        serde_json::json!({
            "name_seed": "fs-read",
            "blueprint_id": blueprint_digest(&blueprint),
            "fingerprint": fs_read_candidate_fingerprint(),
            "occurrences": 3,
            "sequence": [{"tool": "fs_read", "args_shape": {"path": "string:path"}}],
            "source_trace_ids": ["trace-1", "trace-2", "trace-3"],
            "redaction_count": 0
        })
        .to_string(),
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
    let install_json: serde_json::Value = serde_json::from_slice(&install.stdout).unwrap();
    assert_eq!(
        install_json["name"].as_str(),
        Some("existing-installed-skill")
    );
    assert!(
        temp_dir
            .join(".agentenv/skills/existing-installed-skill/0.1.0/content/traces/provenance.json")
            .is_file(),
        "install command should copy proposal provenance into installed content"
    );

    let out = temp_dir.join("proposed");
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--out")
        .arg(&out)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--min-novelty")
        .arg("0.1")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json_named("fs-edit-skill-v3"),
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["proposals"].as_array().unwrap().len(), 0);
    let warnings = json["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("novelty 0 is below 0.1")),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !out.join("fs-edit-skill-v3/SKILL.md").exists(),
        "exact installed duplicate should be skipped before emission"
    );
}

#[test]
fn skills_propose_warns_and_continues_past_malformed_existing_proposal_provenance() {
    let temp_dir = make_temp_dir("skills-propose-malformed-proposed-provenance");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let out = temp_dir.join("proposed");
    let existing = out.join("broken-cache");
    fs::create_dir_all(existing.join("traces")).unwrap();
    fs::write(
        existing.join("skill.yaml"),
        "name: broken-cache\nversion: 0.1.0\ndescription: unrelated cached proposal\nentry: SKILL.md\nfiles:\n  - SKILL.md\n  - traces/provenance.json\n",
    )
    .unwrap();
    fs::write(
        existing.join("SKILL.md"),
        "This cached proposal is unrelated to filesystem reads.\n",
    )
    .unwrap();
    fs::write(existing.join("traces/provenance.json"), "{not json").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--out")
        .arg(&out)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["proposals"][0]["name"], "fs-edit-skill");
    let warnings = json["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|warning| {
            let warning = warning.as_str().unwrap();
            warning.contains("broken-cache") && warning.contains("provenance")
        }),
        "stdout was: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn skills_propose_rejects_unsupported_semantic_backend() {
    let temp_dir = make_temp_dir("skills-propose-semantic-backend");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(&blueprint, "version: 0.1.0\n").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--semantic-backend")
        .arg("remote")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--semantic-backend") && stderr.contains("local"),
        "stderr was: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn skills_propose_open_pr_publishes_first_proposal_with_fake_git_and_gh() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = make_temp_dir("skills-propose-open-pr");
    let repo_root = temp_dir.join("repo");
    let home = temp_dir.join("home");
    fs::create_dir_all(&repo_root).unwrap();
    fs::create_dir_all(&home).unwrap();
    let blueprint = repo_root.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    let store = SqliteEventStore::open(&db_path).unwrap();
    let blueprint_id = blueprint_digest(&blueprint);
    store
        .append_many(&[
            propose_event("trace-1", &blueprint_id, "fs_read", "/repo/a.rs"),
            propose_event("trace-2", &blueprint_id, "fs_read", "/repo/b.rs"),
            propose_event("trace-3", &blueprint_id, "fs_read", "/repo/c.rs"),
        ])
        .unwrap();

    let log_path = temp_dir.join("commands.log");
    let fake_bin = temp_dir.join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    for program in ["git", "gh"] {
        let script = fake_bin.join(program);
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> '{}'\nif [ \"$(basename \"$0\")\" = git ] && [ \"$1\" = rev-parse ]; then\n  printf '%s\\n' '{}'\nfi\nif [ \"$(basename \"$0\")\" = gh ]; then\n  printf '%s\\n' 'https://github.com/owner/repo/pull/123'\nfi\n",
                log_path.display(),
                repo_root.display()
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
    }

    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![fake_bin];
    paths.extend(std::env::split_paths(&path));
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--open-pr")
        .arg("--repo")
        .arg("owner/repo")
        .env("HOME", &home)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&repo_root)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let out = repo_root.join(".agentenv/skills/proposed");
    assert!(out.join("fs-edit-skill/SKILL.md").is_file());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("https://github.com/owner/repo/pull/123"),
        "stdout was: {stdout}"
    );

    let log = fs::read_to_string(&log_path).unwrap();
    let canonical_repo_root = fs::canonicalize(&repo_root).unwrap();
    let expected_commands = [
        "git rev-parse --show-toplevel".to_owned(),
        format!(
            "git -C {} diff --cached --quiet --exit-code",
            canonical_repo_root.display()
        ),
        format!(
            "git -C {} checkout -B agentenv/proposed-skill/fs-edit-skill",
            canonical_repo_root.display()
        ),
        format!(
            "git -C {} add -- .agentenv/skills/proposed/fs-edit-skill",
            canonical_repo_root.display()
        ),
        format!(
            "git -C {} commit -m feat: propose trace-derived skill fs-edit-skill",
            canonical_repo_root.display()
        ),
        format!(
            "git -C {} push -u origin agentenv/proposed-skill/fs-edit-skill",
            canonical_repo_root.display()
        ),
        "gh pr create --repo owner/repo --draft --title feat: propose trace-derived skill fs-edit-skill --body Trace-derived skill proposal.".to_owned(),
    ];
    let mut cursor = 0;
    for expected in expected_commands {
        let relative = log[cursor..]
            .find(&expected)
            .unwrap_or_else(|| panic!("missing ordered command `{expected}`; log was: {log}"));
        cursor += relative + expected.len();
    }
}

#[cfg(unix)]
#[test]
fn skills_propose_open_pr_rejects_staged_changes_before_emitting() {
    let temp_dir = make_temp_dir("skills-propose-open-pr-staged");
    let repo_root = temp_dir.join("repo");
    let home = temp_dir.join("home");
    fs::create_dir_all(&repo_root).unwrap();
    fs::create_dir_all(&home).unwrap();
    run_git(&repo_root, &["init"]);

    let blueprint = repo_root.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    fs::write(repo_root.join("unrelated.txt"), "user staged change\n").unwrap();
    run_git(&repo_root, &["add", "unrelated.txt"]);

    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--open-pr")
        .arg("--repo")
        .arg("owner/repo")
        .env("HOME", &home)
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&repo_root)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("commit or unstage") && stderr.contains("staged"),
        "stderr was: {stderr}"
    );
    assert!(
        !repo_root
            .join(".agentenv/skills/proposed/fs-edit-skill/SKILL.md")
            .exists(),
        "proposal should not be emitted when the index has unrelated staged changes"
    );
}

#[cfg(unix)]
#[test]
fn skills_propose_open_pr_rejects_explicit_outside_repo_before_emitting() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = make_temp_dir("skills-propose-open-pr-outside");
    let repo_root = temp_dir.join("repo");
    let outside = temp_dir.join("outside");
    fs::create_dir_all(&repo_root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let blueprint = repo_root.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    let store = SqliteEventStore::open(&db_path).unwrap();
    let blueprint_id = blueprint_digest(&blueprint);
    store
        .append_many(&[
            propose_event("trace-1", &blueprint_id, "fs_read", "/repo/a.rs"),
            propose_event("trace-2", &blueprint_id, "fs_read", "/repo/b.rs"),
            propose_event("trace-3", &blueprint_id, "fs_read", "/repo/c.rs"),
        ])
        .unwrap();

    let log_path = temp_dir.join("commands.log");
    let fake_bin = temp_dir.join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let git = fake_bin.join("git");
    fs::write(
        &git,
        format!(
            "#!/bin/sh\nprintf 'git %s\\n' \"$*\" >> '{}'\nif [ \"$1\" = rev-parse ]; then\n  printf '%s\\n' '{}'\nfi\n",
            log_path.display(),
            repo_root.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&git).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&git, permissions).unwrap();

    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![fake_bin];
    paths.extend(std::env::split_paths(&path));
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--out")
        .arg(&outside)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--open-pr")
        .arg("--repo")
        .arg("owner/repo")
        .env("HOME", temp_dir.join("home"))
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&repo_root)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--out must be inside the git worktree when --open-pr is set"),
        "stderr was: {stderr}"
    );
    assert!(
        !outside.join("fs-edit-skill/SKILL.md").exists(),
        "proposal should not be emitted outside the repo"
    );
    let log = fs::read_to_string(&log_path).unwrap();
    assert_eq!(log.trim(), "git rev-parse --show-toplevel");
}

#[cfg(unix)]
#[test]
fn skills_propose_open_pr_rejects_default_output_through_symlinked_agentenv() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp_dir = make_temp_dir("skills-propose-open-pr-symlink-default");
    let repo_root = temp_dir.join("repo");
    let outside = temp_dir.join("outside-agentenv");
    fs::create_dir_all(&repo_root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    run_git(&repo_root, &["init"]);
    symlink(&outside, repo_root.join(".agentenv")).unwrap();

    let blueprint = repo_root.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join("events.db");
    let store = SqliteEventStore::open(&db_path).unwrap();
    let blueprint_id = blueprint_digest(&blueprint);
    store
        .append_many(&[
            propose_event("trace-1", &blueprint_id, "fs_read", "/repo/a.rs"),
            propose_event("trace-2", &blueprint_id, "fs_read", "/repo/b.rs"),
            propose_event("trace-3", &blueprint_id, "fs_read", "/repo/c.rs"),
        ])
        .unwrap();

    let gh_log = temp_dir.join("gh.log");
    let fake_bin = temp_dir.join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let gh = fake_bin.join("gh");
    fs::write(
        &gh,
        format!(
            "#!/bin/sh\nprintf 'gh %s\\n' \"$*\" >> '{}'\nprintf '%s\\n' 'https://github.com/owner/repo/pull/789'\n",
            gh_log.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&gh).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&gh, permissions).unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![fake_bin];
    paths.extend(std::env::split_paths(&path));

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--open-pr")
        .arg("--repo")
        .arg("owner/repo")
        .env("HOME", temp_dir.join("home"))
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&repo_root)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("inside the git worktree"),
        "stderr was: {stderr}"
    );
    assert!(
        !outside
            .join("skills/proposed/fs-edit-skill/SKILL.md")
            .exists(),
        "proposal should not be emitted through the .agentenv symlink"
    );
    assert!(
        !gh_log.exists(),
        "gh should not be reached when output preflight fails"
    );
    let head = git_stdout(&repo_root, &["symbolic-ref", "--short", "HEAD"]);
    assert_ne!(head, "agentenv/proposed-skill/fs-edit-skill");
}

#[cfg(unix)]
#[test]
fn skills_propose_open_pr_sanitizes_git_branch_slug_for_lock_like_names() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = make_temp_dir("skills-propose-open-pr-slug");
    let repo_root = temp_dir.join("repo");
    fs::create_dir_all(&repo_root).unwrap();
    let blueprint = repo_root.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    let store = SqliteEventStore::open(&db_path).unwrap();
    let blueprint_id = blueprint_digest(&blueprint);
    store
        .append_many(&[
            propose_event("trace-1", &blueprint_id, "fs_read", "/repo/a.rs"),
            propose_event("trace-2", &blueprint_id, "fs_read", "/repo/b.rs"),
            propose_event("trace-3", &blueprint_id, "fs_read", "/repo/c.rs"),
        ])
        .unwrap();

    let log_path = temp_dir.join("commands.log");
    let fake_bin = temp_dir.join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    for program in ["git", "gh"] {
        let script = fake_bin.join(program);
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> '{}'\nif [ \"$(basename \"$0\")\" = git ] && [ \"$1\" = rev-parse ]; then\n  printf '%s\\n' '{}'\nfi\nif [ \"$(basename \"$0\")\" = gh ]; then\n  printf '%s\\n' 'https://github.com/owner/repo/pull/456'\nfi\n",
                log_path.display(),
                repo_root.display()
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
    }

    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![fake_bin];
    paths.extend(std::env::split_paths(&path));
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--open-pr")
        .arg("--repo")
        .arg("owner/repo")
        .env("HOME", temp_dir.join("home"))
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json_named("bad..name.lock"),
        )
        .current_dir(&repo_root)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let log = fs::read_to_string(&log_path).unwrap();
    let checkout_line = log
        .lines()
        .find(|line| line.contains(" checkout -B "))
        .unwrap();
    assert!(
        checkout_line.contains("agentenv/proposed-skill/bad-name-lock-"),
        "log was: {log}"
    );
    assert!(!checkout_line.contains(".."), "log was: {log}");
    assert!(!checkout_line.contains(".lock"), "log was: {log}");
}

#[cfg(unix)]
#[test]
fn skills_propose_open_pr_fails_when_no_proposals_are_emitted() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = make_temp_dir("skills-propose-open-pr-empty");
    let repo_root = temp_dir.join("repo");
    fs::create_dir_all(&repo_root).unwrap();
    let blueprint = repo_root.join("myapp.yaml");
    fs::write(&blueprint, "version: 0.1.0\n").unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    SqliteEventStore::open(&db_path).unwrap();

    let fake_bin = temp_dir.join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let git = fake_bin.join("git");
    fs::write(
        &git,
        format!(
            "#!/bin/sh\nif [ \"$1\" = rev-parse ]; then\n  printf '%s\\n' '{}'\nfi\n",
            repo_root.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&git).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&git, permissions).unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![fake_bin];
    paths.extend(std::env::split_paths(&path));

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--open-pr")
        .arg("--repo")
        .arg("owner/repo")
        .env("HOME", &temp_dir)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .current_dir(&repo_root)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--open-pr requested but no proposals were emitted"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_propose_without_configured_llm_fails_clearly() {
    let temp_dir = make_temp_dir("skills-propose-missing-llm");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(&blueprint, "version: 0.1.0\n").unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    let store = SqliteEventStore::open(&db_path).unwrap();
    let blueprint_id = blueprint_digest(&blueprint);
    store
        .append_many(&[
            propose_event("trace-1", &blueprint_id, "fs_read", "/repo/a.rs"),
            propose_event("trace-2", &blueprint_id, "fs_read", "/repo/b.rs"),
            propose_event("trace-3", &blueprint_id, "fs_read", "/repo/c.rs"),
        ])
        .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skill proposal LLM provider is not configured"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_propose_uses_configured_openai_compatible_provider_and_env_credential() {
    let temp_dir = make_temp_dir("skills-propose-http-provider");
    let project_dir = temp_dir.join("project");
    fs::create_dir_all(&project_dir).unwrap();
    let (endpoint, captured_request, server) =
        spawn_openai_compatible_skill_proposer(fixture_generalization_json());
    let blueprint = project_dir.join("agentenv.yaml");
    fs::write(
        &blueprint,
        format!(
            r#"
version: 0.1.0
sandbox: {{ driver: openshell }}
agent: {{ driver: codex }}
context: {{ driver: filesystem, mount: . }}
skills:
  proposal:
    llm:
      provider: openai-compatible
      endpoint: {endpoint}
      model: test-model
      credential: AGENTENV_TEST_SKILL_PROPOSER_TOKEN
"#
        ),
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    let store = SqliteEventStore::open(&db_path).unwrap();
    let blueprint_id = blueprint_digest(&blueprint);
    store
        .append_many(&[
            propose_event("trace-1", &blueprint_id, "fs_read", "/repo/a.rs"),
            propose_event("trace-2", &blueprint_id, "fs_read", "/repo/b.rs"),
            propose_event("trace-3", &blueprint_id, "fs_read", "/repo/c.rs"),
        ])
        .unwrap();

    let out = temp_dir.join("proposed");
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--out")
        .arg(&out)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_SKILL_PROPOSER_ALLOW_LOCAL_ENDPOINTS", "1")
        .env("AGENTENV_TEST_SKILL_PROPOSER_TOKEN", "test-token")
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    server.join().unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    assert!(out.join("fs-edit-skill/SKILL.md").is_file());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["proposals"][0]["name"], "fs-edit-skill");
    let request = captured_request.lock().unwrap().clone().unwrap();
    assert!(
        request.contains("authorization: Bearer test-token")
            || request.contains("Authorization: Bearer test-token"),
        "request was: {request}"
    );
    assert!(
        request.contains(r#""model":"test-model""#),
        "request was: {request}"
    );
}

#[test]
fn skills_propose_http_provider_times_out_when_server_never_responds() {
    let temp_dir = make_temp_dir("skills-propose-http-timeout");
    let (endpoint, server) = spawn_never_responding_skill_proposer();
    let blueprint = temp_dir.join("agentenv.yaml");
    write_skill_proposer_blueprint(
        &blueprint,
        &endpoint,
        "test-model",
        "AGENTENV_TEST_SKILL_PROPOSER_TIMEOUT_TOKEN",
    );
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let started_at = Instant::now();
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_SKILL_PROPOSER_ALLOW_LOCAL_ENDPOINTS", "1")
        .env("AGENTENV_SKILL_PROPOSER_HTTP_TIMEOUT_MS", "100")
        .env(
            "AGENTENV_TEST_SKILL_PROPOSER_TIMEOUT_TOKEN",
            "timeout-token",
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    let elapsed = started_at.elapsed();
    server.join().unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timed out"),
        "stderr was: {stderr}; elapsed: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "request should not wait for the production default timeout, elapsed: {elapsed:?}"
    );
    assert!(
        stderr.contains("skill proposal LLM request failed"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_propose_blocks_metadata_endpoint_before_http_request() {
    let temp_dir = make_temp_dir("skills-propose-metadata-endpoint");
    let blueprint = temp_dir.join("agentenv.yaml");
    write_skill_proposer_blueprint(
        &blueprint,
        "http://169.254.169.254/latest/meta-data",
        "test-model",
        "AGENTENV_TEST_SKILL_PROPOSER_METADATA_TOKEN",
    );
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_SKILL_PROPOSER_HTTP_TIMEOUT_MS", "100")
        .env(
            "AGENTENV_TEST_SKILL_PROPOSER_METADATA_TOKEN",
            "metadata-token",
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skill proposal LLM endpoint was blocked"),
        "stderr was: {stderr}"
    );
    assert!(stderr.contains("169.254.169.254"), "stderr was: {stderr}");
}

#[test]
fn skills_propose_does_not_follow_provider_redirect_to_metadata_endpoint() {
    let temp_dir = make_temp_dir("skills-propose-redirect-ssrf");
    let (endpoint, request_count, server) =
        spawn_redirecting_skill_proposer("http://169.254.169.254/latest/meta-data");
    let blueprint = temp_dir.join("agentenv.yaml");
    write_skill_proposer_blueprint(
        &blueprint,
        &endpoint,
        "test-model",
        "AGENTENV_TEST_SKILL_PROPOSER_REDIRECT_TOKEN",
    );
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_SKILL_PROPOSER_ALLOW_LOCAL_ENDPOINTS", "1")
        .env("AGENTENV_SKILL_PROPOSER_HTTP_TIMEOUT_MS", "500")
        .env(
            "AGENTENV_TEST_SKILL_PROPOSER_REDIRECT_TOKEN",
            "redirect-token",
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    server.join().unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("307 Temporary Redirect"),
        "stderr was: {stderr}"
    );
    assert!(
        stderr.contains("redirecting to metadata"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_propose_blocks_private_endpoint_with_only_local_opt_in() {
    let temp_dir = make_temp_dir("skills-propose-private-local-only");
    let blueprint = temp_dir.join("agentenv.yaml");
    write_skill_proposer_blueprint(
        &blueprint,
        "http://10.0.0.1/v1/chat/completions",
        "test-model",
        "AGENTENV_TEST_SKILL_PROPOSER_PRIVATE_LOCAL_TOKEN",
    );
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_SKILL_PROPOSER_ALLOW_LOCAL_ENDPOINTS", "1")
        .env("AGENTENV_SKILL_PROPOSER_HTTP_TIMEOUT_MS", "100")
        .env(
            "AGENTENV_TEST_SKILL_PROPOSER_PRIVATE_LOCAL_TOKEN",
            "private-local-token",
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skill proposal LLM endpoint was blocked"),
        "stderr was: {stderr}"
    );
    assert!(stderr.contains("10.0.0.1"), "stderr was: {stderr}");
}

#[test]
fn skills_propose_private_endpoint_opt_in_reaches_request_layer() {
    let temp_dir = make_temp_dir("skills-propose-private-opt-in");
    let blueprint = temp_dir.join("agentenv.yaml");
    write_skill_proposer_blueprint(
        &blueprint,
        "http://10.0.0.1/v1/chat/completions",
        "test-model",
        "AGENTENV_TEST_SKILL_PROPOSER_PRIVATE_TOKEN",
    );
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_SKILL_PROPOSER_ALLOW_PRIVATE_ENDPOINTS", "1")
        .env("AGENTENV_SKILL_PROPOSER_HTTP_TIMEOUT_MS", "100")
        .env(
            "AGENTENV_TEST_SKILL_PROPOSER_PRIVATE_TOKEN",
            "private-token",
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("skill proposal LLM endpoint was blocked"),
        "stderr was: {stderr}"
    );
    assert!(
        stderr.contains("skill proposal LLM request failed"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_propose_redacts_and_bounds_non_success_provider_body() {
    let temp_dir = make_temp_dir("skills-propose-http-error-redaction");
    let (endpoint, server) = spawn_erroring_skill_proposer("test-token", "x".repeat(10_000));
    let blueprint = temp_dir.join("agentenv.yaml");
    write_skill_proposer_blueprint(
        &blueprint,
        &endpoint,
        "test-model",
        "AGENTENV_TEST_SKILL_PROPOSER_ERROR_TOKEN",
    );
    let db_path = temp_dir.join(".agentenv/events.db");
    seed_propose_events(&db_path, &blueprint);

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("AGENTENV_SKILL_PROPOSER_ALLOW_LOCAL_ENDPOINTS", "1")
        .env("AGENTENV_TEST_SKILL_PROPOSER_ERROR_TOKEN", "test-token")
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    server.join().unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("test-token"), "stderr was: {stderr}");
    assert!(stderr.contains("[REDACTED]"), "stderr was: {stderr}");
    assert!(
        stderr.len() < 6_000,
        "stderr should include a bounded provider body, got {} bytes",
        stderr.len()
    );
}

#[test]
fn skills_propose_missing_explicit_events_db_fails_clearly() {
    let temp_dir = make_temp_dir("skills-propose-missing-events-db");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/missing-events.db");

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.trim().is_empty(), "stdout was: {stdout}");
    assert!(stderr.contains("events DB"), "stderr was: {stderr}");
    assert!(
        stderr.contains(&db_path.display().to_string()),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_propose_empty_events_db_json_warns_without_stderr_warning() {
    let temp_dir = make_temp_dir("skills-propose-empty-events-db");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(
        &blueprint,
        "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n",
    )
    .unwrap();
    let db_path = temp_dir.join(".agentenv/events.db");
    SqliteEventStore::open(&db_path).unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("propose")
        .arg("--from-traces")
        .arg("--blueprint")
        .arg(&blueprint)
        .arg("--events-db")
        .arg(&db_path)
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env(
            "AGENTENV_SKILL_PROPOSER_FIXTURE_JSON",
            fixture_generalization_json(),
        )
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["proposals"].as_array().unwrap().len(), 0);
    assert!(!json["warnings"].as_array().unwrap().is_empty());
    let warning = json["warnings"][0].as_str().unwrap();
    assert!(warning.contains("No traces"), "warning was: {warning}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(warning), "stderr was: {stderr}");
}

#[test]
fn skills_verify_all_succeeds_for_valid_local_cache() {
    let temp_dir = make_temp_dir("skills-verify-valid");
    write_cli_cache_skill(
        &temp_dir,
        "code-review",
        "1.2.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        true,
    );

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("--all")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("verified"), "stdout was: {stdout}");
}

#[test]
fn skills_verify_all_prints_warnings_for_passed_skills() {
    let temp_dir = make_temp_dir("skills-verify-passed-warning");
    write_cli_cache_skill(
        &temp_dir,
        "missing-archive",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        true,
    );

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("--all")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("warning:"), "stderr was: {stderr}");
    assert!(
        stderr.contains("extracted tree digest"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_verify_all_fails_for_broken_local_cache() {
    let temp_dir = make_temp_dir("skills-verify-broken");
    write_cli_cache_skill(
        &temp_dir,
        "code-review",
        "1.2.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        false,
    );

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("--all")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", output_summary(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed"), "stderr was: {stderr}");
}

#[test]
fn skills_prune_dry_run_does_not_delete_archive() {
    let temp_dir = make_temp_dir("skills-prune-dry-run");
    let root = temp_dir.join(".agentenv");
    let cache_dir = root.join("cache/skills");
    fs::create_dir_all(&cache_dir).unwrap();
    let archive =
        cache_dir.join("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tar.zst");
    fs::write(&archive, b"unreferenced").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("prune")
        .arg("--dry-run")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    assert!(archive.exists(), "dry-run should not delete archive");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("would remove"), "stdout was: {stdout}");
}

#[test]
fn skills_prune_deletes_unreferenced_archive() {
    let temp_dir = make_temp_dir("skills-prune-delete");
    let root = temp_dir.join(".agentenv");
    let cache_dir = root.join("cache/skills");
    fs::create_dir_all(&cache_dir).unwrap();
    let archive =
        cache_dir.join("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tar.zst");
    fs::write(&archive, b"unreferenced").unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("prune")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    assert!(
        !archive.exists(),
        "prune should delete unreferenced archive"
    );
}

#[test]
fn skills_ci_json_passes_valid_bundle() {
    let temp_dir = make_temp_dir("skills-ci-json-pass");
    let bundle = temp_dir.join("bundle");
    write_signed_ci_skill_bundle(&bundle, "ci-cli-pass", "0.1.0", "CI pass fixture");

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("JSON parse failed: {err}\n{}", output_summary(&output)));
    assert_eq!(report["status"], "passed");
    assert_eq!(report["candidate"]["name"], "ci-cli-pass");
    assert_eq!(report["candidate"]["version"], "0.1.0");
    assert_ci_tier_status(&report, "static_lint", "passed");
    assert_ci_tier_status(&report, "functional_regression", "passed");
}

#[test]
fn skills_ci_json_exits_one_for_invalid_bundle() {
    let temp_dir = make_temp_dir("skills-ci-json-invalid");
    let bundle = temp_dir.join("bundle");
    write_signed_ci_skill_bundle(&bundle, "ci-cli-invalid", "0.1.0", "CI invalid fixture");
    fs::write(
        bundle.join("SKILL.md"),
        "# Invalid\n\n```rust\nfn main() {}\n",
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", output_summary(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("JSON parse failed: {err}\n{}", output_summary(&output)));
    assert_eq!(report["status"], "failed");
    assert_ci_tier_status(&report, "static_lint", "failed");
    assert_ci_findings_include(
        &report,
        "static_lint",
        "agentenv.skill.markdown.unclosed-fence",
    );
}

#[test]
fn skills_ci_writes_sarif_file() {
    let temp_dir = make_temp_dir("skills-ci-sarif");
    let bundle = temp_dir.join("bundle");
    let sarif_path = temp_dir.join("skill-ci.sarif");
    write_signed_ci_skill_bundle(&bundle, "ci-cli-sarif", "0.1.0", "CI SARIF fixture");
    fs::write(
        bundle.join("SKILL.md"),
        "# SARIF\n\nUse token sk-test-1234567890abcdefghijklmnop carefully.\n",
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--sarif")
        .arg(&sarif_path)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", output_summary(&output));
    assert!(sarif_path.is_file(), "SARIF file was not written");
    let sarif: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(results
        .iter()
        .any(|result| { result["ruleId"].as_str() == Some("agentenv.skill.secret.detected") }));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status"), "stdout was: {stdout}");
}

#[test]
fn skills_ci_registry_snapshot_drives_dedup_failure() {
    let temp_dir = make_temp_dir("skills-ci-dedup");
    let bundle = temp_dir.join("bundle");
    write_signed_ci_skill_bundle(&bundle, "ci-cli-dedup", "0.1.0", "CI dedup fixture");
    let manifest = load_skill_manifest(&bundle).unwrap();
    let digest = compute_bundle_digest(&bundle, &manifest).unwrap();
    let snapshot = temp_dir.join("registry-snapshot.json");
    fs::write(
        &snapshot,
        serde_json::to_string_pretty(&json!({
            "skills": [
                {
                    "name": "existing-dedup",
                    "version": "1.0.0",
                    "description": "CI dedup fixture",
                    "procedure_text": "# CI dedup fixture\n\nUse this skill safely. Ask before destructive actions.\n",
                    "fingerprint": digest,
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("ci")
        .arg(&bundle)
        .arg("--registry-snapshot")
        .arg(&snapshot)
        .arg("--no-fail-fast")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", output_summary(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("JSON parse failed: {err}\n{}", output_summary(&output)));
    assert_eq!(report["status"], "failed");
    assert_ci_tier_status(&report, "semantic_dedup", "failed");
    assert_ci_tier_status(&report, "functional_regression", "passed");
    assert_ci_findings_include(
        &report,
        "semantic_dedup",
        "agentenv.skill.dedup.probable-duplicate",
    );
}

#[test]
fn skill_ci_workflow_references_cli_command() {
    let workflow_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/skill-ci.yaml");
    let workflow = fs::read_to_string(&workflow_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow_path.display()));

    assert!(workflow.contains("workflow_call"));
    assert!(workflow.contains("agentenv skills ci"));
    assert!(workflow.contains("upload-sarif"));
}

#[test]
fn skills_install_list_info_verify_and_remove_local_bundle() {
    let temp_dir = make_temp_dir("skills-cli-local");
    let bundle = temp_dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), "# CLI Skill\n").unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: cli-skill\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n",
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
        "name: registry-skill\nversion: 0.1.0\ndescription: Registry demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n",
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
        "name: override-skill\nversion: 0.1.0\ndescription: Override demo\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n",
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
fn skills_cli_publish_rejects_missing_or_unattested_self_tests_e2e() {
    let temp_dir = make_temp_dir("skills-cli-self-test-gate-errors");
    let registry = temp_dir.join("registry");
    let missing_bundle = temp_dir.join("missing-self-test");
    write_local_skill_bundle(
        &missing_bundle,
        "missing-cli-self-test",
        "0.1.0",
        "Missing CLI self-test",
        None,
    );

    let missing_publish = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&missing_bundle)
        .arg("--registry")
        .arg(&registry)
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(!missing_publish.status.success());
    assert!(
        String::from_utf8_lossy(&missing_publish.stderr).contains("skill self-test is missing"),
        "{}",
        output_summary(&missing_publish)
    );
    assert!(
        !registry.join("index.yaml").exists(),
        "missing self-test publish should not create registry index"
    );

    let bundle = temp_dir.join("attestation-required");
    write_local_skill_bundle(
        &bundle,
        "attestation-required-cli",
        "0.1.0",
        "Attestation required CLI",
        Some("test -f SKILL.md"),
    );
    let no_run_publish = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&bundle)
        .arg("--registry")
        .arg(&registry)
        .arg("--allow-unsigned")
        .arg("--no-self-test-run")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(!no_run_publish.status.success());
    assert!(
        String::from_utf8_lossy(&no_run_publish.stderr)
            .contains("missing signed self-test attestation"),
        "{}",
        output_summary(&no_run_publish)
    );
    assert!(
        !registry.join("index.yaml").exists(),
        "unattested no-rerun publish should not create registry index"
    );
}

#[test]
fn skills_cli_skill_test_file_publish_add_verify_e2e() {
    let temp_dir = make_temp_dir("skills-cli-skill-test-file-e2e");
    let registry = temp_dir.join("registry");
    let bundle = temp_dir.join("bundle");
    write_local_skill_bundle_with_skill_test_file(
        &bundle,
        "file-self-test-cli",
        "0.1.0",
        "File self-test CLI",
    );

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
    assert_eq!(publish_json["name"], "file-self-test-cli");
    assert_eq!(publish_json["self_test_score"], 1.0);
    assert!(publish_json["self_test_attestation_digest"].is_string());
    assert!(registry
        .join("bundles/file-self-test-cli/0.1.0/skill-test.yaml")
        .is_file());
    assert!(registry
        .join("bundles/file-self-test-cli/0.1.0/self-test-attestation.json")
        .is_file());

    let search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("file-self")
        .arg("--registry")
        .arg(&registry)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(search.status.success(), "{}", output_summary(&search));
    let search_json: serde_json::Value = serde_json::from_slice(&search.stdout).unwrap();
    assert_eq!(search_json["skills"][0]["name"], "file-self-test-cli");
    assert_eq!(search_json["skills"][0]["self_test_score"], 1.0);
    assert!(search_json["skills"][0]["self_test_attestation_digest"].is_string());

    let add = Command::new(agentenv_bin())
        .arg("skills")
        .arg("add")
        .arg("file-self-test-cli@0.1.0")
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
    assert_eq!(add_json["name"], "file-self-test-cli");
    assert_eq!(add_json["self_test_score"], 1.0);
    let installed_path = PathBuf::from(add_json["path"].as_str().unwrap());
    assert!(installed_path.join("content/skill-test.yaml").is_file());

    let verify = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("file-self-test-cli")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", output_summary(&verify));
    let verify_json: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify_json["name"], "file-self-test-cli");
    assert_eq!(verify_json["self_test_score"], 1.0);
    assert!(verify_json["self_test_attestation"].is_string());
}

#[test]
fn skills_publish_can_use_supplied_self_test_attestation_without_rerun() {
    let temp_dir = make_temp_dir("skills-cli-publish-supplied-self-test-attestation");
    let registry = temp_dir.join("registry");
    let bundle = temp_dir.join("bundle");
    let sentinel = temp_dir.join("self-test-reran");
    write_local_skill_bundle(
        &bundle,
        "supplied-attestation-skill",
        "0.1.0",
        "Supplied attestation",
        Some(&format!("touch {}", sentinel.display())),
    );

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
    let installed: serde_json::Value = serde_json::from_slice(&install.stdout).unwrap();
    let attestation_path = installed["self_test_attestation"].as_str().unwrap();
    assert!(sentinel.is_file());
    fs::remove_file(&sentinel).unwrap();

    let publish = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&bundle)
        .arg("--registry")
        .arg(&registry)
        .arg("--allow-unsigned")
        .arg("--self-test-attestation")
        .arg(attestation_path)
        .arg("--no-self-test-run")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(publish.status.success(), "{}", output_summary(&publish));
    let published: serde_json::Value = serde_json::from_slice(&publish.stdout).unwrap();
    assert_eq!(published["self_test_score"], 1.0);
    assert!(registry
        .join("bundles/supplied-attestation-skill/0.1.0/self-test-attestation.json")
        .is_file());
    assert!(
        !sentinel.exists(),
        "publish with supplied attestation reran the self-test"
    );

    let remove = Command::new(agentenv_bin())
        .arg("skills")
        .arg("remove")
        .arg("supplied-attestation-skill")
        .arg("--yes")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(remove.status.success(), "{}", output_summary(&remove));

    let add = Command::new(agentenv_bin())
        .arg("skills")
        .arg("add")
        .arg("supplied-attestation-skill@0.1.0")
        .arg("--registry")
        .arg(&registry)
        .arg("--allow-unsigned")
        .arg("--self-test-attestation")
        .arg(attestation_path)
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(add.status.success(), "{}", output_summary(&add));
    let add_json: serde_json::Value = serde_json::from_slice(&add.stdout).unwrap();
    assert_eq!(add_json["self_test_score"], 1.0);
    assert!(
        !sentinel.exists(),
        "add with supplied attestation reran the self-test"
    );
}

#[test]
fn skills_cli_filesystem_registry_scans_indexless_subdirectories_e2e() {
    let temp_dir = make_temp_dir("skills-cli-indexless-filesystem-registry");
    let registry = temp_dir.join("registry");
    write_indexless_filesystem_registry_skill(
        &registry,
        "indexless-cli-skill",
        "0.2.0",
        "Indexless CLI demo",
    );
    fs::write(
        temp_dir.join("agentenv.yaml"),
        format!(
            "skills:\n  registries:\n    - name: local-dev\n      type: filesystem\n      path: {}\n",
            registry.display()
        ),
    )
    .unwrap();

    let search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("indexless")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(search.status.success(), "{}", output_summary(&search));
    assert_skill_search_names(&search.stdout, &["indexless-cli-skill"]);

    let add = Command::new(agentenv_bin())
        .arg("skills")
        .arg("add")
        .arg("indexless-cli-skill")
        .arg("--allow-unsigned")
        .arg("--json")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(add.status.success(), "{}", output_summary(&add));
    let add_json: serde_json::Value = serde_json::from_slice(&add.stdout).unwrap();
    assert_eq!(add_json["name"], "indexless-cli-skill");
    assert_eq!(add_json["version"], "0.2.0");
    assert_eq!(add_json["source_type"], "filesystem");
    assert_eq!(
        add_json["source_label"],
        "filesystem:local-dev:indexless-cli-skill@0.2.0"
    );
}

#[test]
fn skills_search_reports_http_registry_override_ssrf_block() {
    let temp_dir = make_temp_dir("skills-cli-http-registry-override-ssrf");

    let search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("registry")
        .arg("--registry")
        .arg("http://127.0.0.1:9/skills")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!search.status.success());
    let stderr = String::from_utf8_lossy(&search.stderr);
    assert!(
        !stderr.contains("unsupported registry URL scheme"),
        "stderr was: {stderr}"
    );
    assert!(
        stderr.contains("blocked by SSRF policy"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_search_accepts_git_registry_override_syntax() {
    let temp_dir = make_temp_dir("skills-cli-git-registry-override");

    let search = Command::new(agentenv_bin())
        .arg("skills")
        .arg("search")
        .arg("registry")
        .arg("--registry")
        .arg("git+https://127.0.0.1/acme/skills")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!search.status.success());
    let stderr = String::from_utf8_lossy(&search.stderr);
    assert!(
        !stderr.contains("unsupported registry URL scheme"),
        "stderr was: {stderr}"
    );
    assert!(
        stderr.contains("blocked by SSRF policy"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_add_accepts_git_registry_override_syntax_until_ssrf_block() {
    let temp_dir = make_temp_dir("skills-cli-git-add-registry-override");

    let add = Command::new(agentenv_bin())
        .arg("skills")
        .arg("add")
        .arg("registry-skill@0.1.0")
        .arg("--registry")
        .arg("git+https://127.0.0.1/acme/skills")
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!add.status.success());
    let stderr = String::from_utf8_lossy(&add.stderr);
    assert!(
        !stderr.contains("unsupported registry URL scheme"),
        "stderr was: {stderr}"
    );
    assert!(
        stderr.contains("blocked by SSRF policy"),
        "stderr was: {stderr}"
    );
}

#[test]
fn skills_publish_reports_git_registry_override_as_read_only() {
    let temp_dir = make_temp_dir("skills-cli-git-publish-registry-override");
    let bundle = temp_dir.join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), "# Git Publish\n").unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        "name: git-publish-cli\nversion: 0.1.0\ndescription: Git publish CLI\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n",
    )
    .unwrap();

    let publish = Command::new(agentenv_bin())
        .arg("skills")
        .arg("publish")
        .arg(&bundle)
        .arg("--registry")
        .arg("git+https://127.0.0.1/acme/skills")
        .arg("--allow-unsigned")
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!publish.status.success());
    let stderr = String::from_utf8_lossy(&publish.stderr);
    assert!(
        stderr.contains("registry `cli` of type `git` does not support publishing"),
        "stderr was: {stderr}"
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
fn skills_cli_enforces_trust_self_tests_version_selectors_and_remove_confirmation() {
    let temp_dir = make_temp_dir("skills-cli-lifecycle-matrix");
    let old_bundle = temp_dir.join("matrix-0.1.0");
    let new_bundle = temp_dir.join("matrix-0.2.0");
    write_local_skill_bundle(
        &old_bundle,
        "matrix-skill",
        "0.1.0",
        "Old matrix skill",
        Some("test -f SKILL.md"),
    );
    write_local_skill_bundle(
        &new_bundle,
        "matrix-skill",
        "0.2.0",
        "New matrix skill",
        Some("test -f SKILL.md"),
    );

    let unsigned_default = Command::new(agentenv_bin())
        .arg("skills")
        .arg("install")
        .arg("--from")
        .arg(&old_bundle)
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();
    assert!(!unsigned_default.status.success());
    assert!(
        String::from_utf8_lossy(&unsigned_default.stderr).contains("missing Ed25519 signature"),
        "{}",
        output_summary(&unsigned_default)
    );

    for bundle in [&old_bundle, &new_bundle] {
        let install = Command::new(agentenv_bin())
            .arg("skills")
            .arg("install")
            .arg("--from")
            .arg(bundle)
            .arg("--allow-unsigned")
            .arg("--json")
            .env("HOME", &temp_dir)
            .current_dir(&temp_dir)
            .output()
            .unwrap();
        assert!(install.status.success(), "{}", output_summary(&install));
        let installed: serde_json::Value = serde_json::from_slice(&install.stdout).unwrap();
        assert_eq!(installed["name"], "matrix-skill");
        assert_eq!(installed["signature_status"], "unsigned");
    }

    let ambiguous_info = Command::new(agentenv_bin())
        .arg("skills")
        .arg("info")
        .arg("matrix-skill")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(!ambiguous_info.status.success());
    assert!(
        String::from_utf8_lossy(&ambiguous_info.stderr).contains("multiple installed versions"),
        "{}",
        output_summary(&ambiguous_info)
    );

    let info_old = Command::new(agentenv_bin())
        .arg("skills")
        .arg("info")
        .arg("matrix-skill")
        .arg("--version")
        .arg("0.1.0")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(info_old.status.success(), "{}", output_summary(&info_old));
    let info_old_json: serde_json::Value = serde_json::from_slice(&info_old.stdout).unwrap();
    assert_eq!(info_old_json["version"], "0.1.0");

    let verify_new = Command::new(agentenv_bin())
        .arg("skills")
        .arg("verify")
        .arg("matrix-skill")
        .arg("--version")
        .arg("0.2.0")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(
        verify_new.status.success(),
        "{}",
        output_summary(&verify_new)
    );
    let verify_new_json: serde_json::Value = serde_json::from_slice(&verify_new.stdout).unwrap();
    assert_eq!(verify_new_json["version"], "0.2.0");
    assert_eq!(verify_new_json["self_test_score"], 1.0);
    assert!(verify_new_json["self_test_attestation"]
        .as_str()
        .unwrap()
        .ends_with(".json"));

    let remove_without_yes = Command::new(agentenv_bin())
        .arg("skills")
        .arg("remove")
        .arg("matrix-skill")
        .arg("--version")
        .arg("0.1.0")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(!remove_without_yes.status.success());
    assert!(
        String::from_utf8_lossy(&remove_without_yes.stderr).contains("without --yes"),
        "{}",
        output_summary(&remove_without_yes)
    );

    let remove_old = Command::new(agentenv_bin())
        .arg("skills")
        .arg("remove")
        .arg("matrix-skill")
        .arg("--version")
        .arg("0.1.0")
        .arg("--yes")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(
        remove_old.status.success(),
        "{}",
        output_summary(&remove_old)
    );
    let remove_old_json: serde_json::Value = serde_json::from_slice(&remove_old.stdout).unwrap();
    assert_eq!(remove_old_json["version"], "0.1.0");

    let list_after_remove = Command::new(agentenv_bin())
        .arg("skills")
        .arg("list")
        .arg("--json")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();
    assert!(
        list_after_remove.status.success(),
        "{}",
        output_summary(&list_after_remove)
    );
    let list_after_remove_json: serde_json::Value =
        serde_json::from_slice(&list_after_remove.stdout).unwrap();
    assert_eq!(
        list_after_remove_json["skills"]
            .as_array()
            .unwrap()
            .iter()
            .map(|skill| skill["version"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["0.2.0"]
    );
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

    let deadline = Instant::now() + PTY_QUIT_TIMEOUT;
    let mut next_quit = Instant::now() + Duration::from_millis(500);
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
                "term did not exit within {:?} after `q`; pid: {process_id:?}; kill: {kill_result:?}; reap: {reap_result:?}; pty output:\n{}",
                PTY_QUIT_TIMEOUT,
                String::from_utf8_lossy(&pty_output)
            );
        }
        if Instant::now() >= next_quit {
            writer.write_all(b"q").unwrap();
            writer.flush().unwrap();
            next_quit = Instant::now() + Duration::from_millis(250);
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
    let mut server = spawn_approvals_server(temp.path(), port);

    server.wait_for_http_ok(port, "/healthz");
}

#[test]
fn approvals_serve_unsigned_decision_callback_returns_401_without_deciding() {
    let temp = tempfile::tempdir().unwrap();
    let port = reserve_tcp_port();
    write_approval_callback_config(temp.path(), "callback-test-secret");
    write_minimal_env_state(temp.path(), "demo");
    seed_pending_approval(temp.path(), "demo", "req-unsigned");
    let mut server = spawn_approvals_server(temp.path(), port);
    server.wait_for_http_ok(port, "/healthz");
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
    let mut server = spawn_approvals_server(temp.path(), port);
    server.wait_for_http_ok(port, "/healthz");
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
    let mut server = spawn_approvals_server(temp.path(), port);
    server.wait_for_http_ok(port, "/healthz");
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
    let mut server = spawn_approvals_server(temp.path(), port);
    server.wait_for_http_ok(port, "/healthz");
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
        "missing environment variable",
        "missing credential",
        "missing_credential",
    ]
    .iter()
    .any(|needle| stderr.contains(needle))
}

#[test]
fn reference_blueprint_skip_reason_accepts_missing_env_vars() {
    assert!(reference_blueprint_skip_reason(
        "create failed: missing environment variable `MCP_URL`"
    ));
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

fn write_cli_cache_skill(
    home: &Path,
    name: &str,
    version: &str,
    digest: &str,
    matching_skill_md: bool,
) {
    let skill_dir = home
        .join(".agentenv")
        .join("skills")
        .join(name)
        .join(version);
    fs::create_dir_all(skill_dir.join(".agentenv")).unwrap();
    let skill_md_name = if matching_skill_md {
        name
    } else {
        "different-name"
    };
    fs::write(
        skill_dir.join("SKILL.md"),
        format!("---\nname: {skill_md_name}\nversion: {version}\n---\n# {name}\n"),
    )
    .unwrap();
    let hex = digest.strip_prefix("sha256:").unwrap();
    fs::write(
        skill_dir.join(".agentenv/manifest.json"),
        format!(
            r#"{{
  "schema_version": "0.1",
  "name": "{name}",
  "version": "{version}",
  "source": "file:///skills/{name}",
  "digest": "{digest}",
  "signatures": [],
  "archive": {{
    "digest": "{digest}",
    "cache_key": "{hex}.tar.zst"
  }}
}}"#
        ),
    )
    .unwrap();
    fs::write(
        skill_dir.join(".agentenv/provenance.json"),
        format!(
            r#"{{
  "schema_version": "0.1",
  "subject": {{
    "name": "{name}",
    "version": "{version}",
    "digest": "{digest}"
  }},
  "attestations": []
}}"#
        ),
    )
    .unwrap();
}

fn write_local_skill_bundle(
    bundle: &Path,
    name: &str,
    version: &str,
    description: &str,
    self_test: Option<&str>,
) {
    fs::create_dir_all(bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), format!("# {description}\n")).unwrap();
    let self_test_yaml = self_test
        .map(|command| format!("self_test:\n  command: {command}\n"))
        .unwrap_or_default();
    fs::write(
        bundle.join("skill.yaml"),
        format!(
            "name: {name}\nversion: {version}\ndescription: {description}\nentry: SKILL.md\nfiles:\n  - SKILL.md\n{self_test_yaml}"
        ),
    )
    .unwrap();
}

fn write_signed_ci_skill_bundle(bundle: &Path, name: &str, version: &str, description: &str) {
    fs::create_dir_all(bundle).unwrap();
    fs::write(
        bundle.join("SKILL.md"),
        format!("# {description}\n\nUse this skill safely. Ask before destructive actions.\n"),
    )
    .unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        format!(
            "name: {name}\nversion: {version}\ndescription: {description}\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n"
        ),
    )
    .unwrap();
    sign_local_skill_bundle(bundle);
}

fn sign_local_skill_bundle(bundle: &Path) {
    let manifest = load_skill_manifest(bundle).unwrap();
    let digest = compute_bundle_digest(bundle, &manifest).unwrap();
    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let payload = signature_payload(&manifest, &digest).unwrap();
    let signature = hex::encode(signing_key.sign(&payload).to_bytes());
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let mut manifest_text = fs::read_to_string(bundle.join("skill.yaml")).unwrap();
    manifest_text.push_str(&format!(
        "signatures:\n  ed25519: {signature}\n  public_key_ed25519: {public_key}\n"
    ));
    fs::write(bundle.join("skill.yaml"), manifest_text).unwrap();
}

fn write_local_skill_bundle_with_skill_test_file(
    bundle: &Path,
    name: &str,
    version: &str,
    description: &str,
) {
    fs::create_dir_all(bundle).unwrap();
    fs::write(bundle.join("SKILL.md"), format!("# {description}\n")).unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        format!(
            "name: {name}\nversion: {version}\ndescription: {description}\nentry: SKILL.md\nfiles:\n  - SKILL.md\n"
        ),
    )
    .unwrap();
    fs::write(
        bundle.join("skill-test.yaml"),
        "self_test:\n  runner: agentenv\n  assertions:\n    - type: file_exists\n      path: SKILL.md\n  timeout_seconds: 5\n",
    )
    .unwrap();
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
            "name: {name}\nversion: {version}\ndescription: {description}\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n"
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

fn write_indexless_filesystem_registry_skill(
    registry: &Path,
    name: &str,
    version: &str,
    description: &str,
) {
    let bundle = registry.join(name);
    fs::create_dir_all(&bundle).unwrap();
    fs::write(
        bundle.join("SKILL.md"),
        format!("# {description}\n\n{name}\n"),
    )
    .unwrap();
    fs::write(
        bundle.join("skill.yaml"),
        format!(
            "name: {name}\nversion: {version}\ndescription: {description}\nentry: SKILL.md\nfiles:\n  - SKILL.md\nself_test:\n  command: test -f SKILL.md\n"
        ),
    )
    .unwrap();
}

fn assert_ci_tier_status(report: &serde_json::Value, tier_name: &str, expected_status: &str) {
    let tier = ci_tier(report, tier_name);
    assert_eq!(
        tier["status"].as_str(),
        Some(expected_status),
        "report was: {report}"
    );
}

fn assert_ci_findings_include(report: &serde_json::Value, tier_name: &str, rule_id: &str) {
    let tier = ci_tier(report, tier_name);
    let findings = tier["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding["rule_id"].as_str() == Some(rule_id)),
        "missing {rule_id}; tier was: {tier}"
    );
}

fn ci_tier<'a>(report: &'a serde_json::Value, tier_name: &str) -> &'a serde_json::Value {
    report["tiers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tier| tier["tier"].as_str() == Some(tier_name))
        .unwrap_or_else(|| panic!("missing {tier_name}; report was: {report}"))
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

fn run_git(current_dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(current_dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(current_dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(current_dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn write_minimal_env_state(home: &Path, name: &str) -> PathBuf {
    write_minimal_env_state_with_credentials(home, name, &[])
}

#[cfg(unix)]
fn spawn_fake_firecracker_api(
    path: &Path,
    expected_requests: usize,
) -> thread::JoinHandle<Vec<String>> {
    use std::os::unix::net::UnixListener;

    if path.exists() {
        fs::remove_file(path).unwrap();
    }
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while requests.len() < expected_requests && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_fake_firecracker_request(&mut stream);
                    requests.push(request);
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("fake Firecracker API accept failed: {err}"),
            }
        }
        requests
    })
}

#[cfg(unix)]
fn read_fake_firecracker_request(stream: &mut std::os::unix::net::UnixStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if fake_http_request_complete(&buffer) {
            break;
        }
    }
    String::from_utf8(buffer).unwrap()
}

#[cfg(unix)]
fn fake_http_request_complete(buffer: &[u8]) -> bool {
    let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    buffer.len() >= header_end + 4 + content_length
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

fn propose_event(trace_id: &str, blueprint_id: &str, tool: &str, path: &str) -> ActivityEvent {
    ActivityEvent::new(
        "2026-05-11T00:00:00Z",
        ActivityKind::McpToolCall,
        ActivityResult::Ok,
        trace_id,
    )
    .with_env("demo")
    .with_subject_value("tool", serde_json::json!(tool))
    .with_subject_value("arguments", serde_json::json!({"path": path}))
    .with_extra("blueprint_id", serde_json::json!(blueprint_id))
}

fn blueprint_digest(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn fixture_generalization_json() -> String {
    fixture_generalization_json_named("fs-edit-skill")
}

fn fixture_generalization_json_named(name: &str) -> String {
    serde_json::json!({
        "name": name,
        "description": "Edit a repeated filesystem target.",
        "template_variables": [{"name": "target_path", "description": "Target path", "example": "src/lib.rs"}],
        "procedure_steps": [{"tool": "fs_read", "instruction": "Read {{target_path}}."}],
        "self_test": {"command": "test -f SKILL.md"},
        "skill_md_body": "Read {{target_path}}."
    })
    .to_string()
}

fn fs_read_candidate_fingerprint() -> &'static str {
    r#"[{"tool":"fs_read","args_shape":{"path":"string:path"}}]"#
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

fn spawn_openai_compatible_skill_proposer(
    content: String,
) -> (String, Arc<Mutex<Option<String>>>, thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let captured_request = Arc::new(Mutex::new(None));
    let captured_for_thread = Arc::clone(&captured_request);
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + LOCAL_HTTP_TEST_TIMEOUT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for OpenAI-compatible test request"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept OpenAI-compatible test request: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(LOCAL_HTTP_TEST_TIMEOUT))
            .unwrap();
        let request = read_http_request(&mut stream);
        *captured_for_thread.lock().unwrap() = Some(request);
        let body = serde_json::json!({
            "choices": [{"message": {"content": content}}],
        })
        .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });

    (endpoint, captured_request, handle)
}

fn spawn_never_responding_skill_proposer() -> (String, thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + LOCAL_HTTP_TEST_TIMEOUT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for never-responding test request"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept never-responding test request: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(LOCAL_HTTP_TEST_TIMEOUT))
            .unwrap();
        let _request = read_http_request(&mut stream);
        thread::sleep(Duration::from_secs(2));
    });

    (endpoint, handle)
}

fn spawn_erroring_skill_proposer(secret: &str, suffix: String) -> (String, thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let body = format!("provider failed with token {secret}: {suffix}");
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + LOCAL_HTTP_TEST_TIMEOUT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for erroring test request"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept erroring test request: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(LOCAL_HTTP_TEST_TIMEOUT))
            .unwrap();
        let _request = read_http_request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 500 Internal Server Error\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });

    (endpoint, handle)
}

fn spawn_redirecting_skill_proposer(
    location: &str,
) -> (String, Arc<AtomicUsize>, thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_thread = Arc::clone(&request_count);
    let location = location.to_owned();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + LOCAL_HTTP_TEST_TIMEOUT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for redirecting test request"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept redirecting test request: {error}"),
            }
        };
        request_count_for_thread.fetch_add(1, Ordering::SeqCst);
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(LOCAL_HTTP_TEST_TIMEOUT))
            .unwrap();
        let _request = read_http_request(&mut stream);
        let body = format!("redirecting to metadata: {location}");
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nlocation: {location}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        match stream.write_all(response.as_bytes()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => panic!("write redirecting test response: {error}"),
        }
    });

    (endpoint, request_count, handle)
}

fn write_skill_proposer_blueprint(blueprint: &Path, endpoint: &str, model: &str, credential: &str) {
    fs::write(
        blueprint,
        format!(
            r#"
version: 0.1.0
sandbox: {{ driver: openshell }}
agent: {{ driver: codex }}
context: {{ driver: filesystem, mount: . }}
skills:
  proposal:
    llm:
      provider: openai-compatible
      endpoint: {endpoint}
      model: {model}
      credential: {credential}
"#
        ),
    )
    .unwrap();
}

fn seed_propose_events(db_path: &Path, blueprint: &Path) {
    let store = SqliteEventStore::open(db_path).unwrap();
    let blueprint_id = blueprint_digest(blueprint);
    store
        .append_many(&[
            propose_event("trace-1", &blueprint_id, "fs_read", "/repo/a.rs"),
            propose_event("trace-2", &blueprint_id, "fs_read", "/repo/b.rs"),
            propose_event("trace-3", &blueprint_id, "fs_read", "/repo/c.rs"),
        ])
        .unwrap();
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count != 0, "connection closed before request headers");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(header_end) = find_header_end(&bytes) {
            let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let target_len = header_end + 4 + content_length;
            while bytes.len() < target_len {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count != 0, "connection closed before request body");
                bytes.extend_from_slice(&buffer[..count]);
            }
            return String::from_utf8_lossy(&bytes).to_string();
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
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

impl ApprovalsServerChild {
    fn wait_for_http_ok(&mut self, port: u16, path: &str) {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let url = format!("http://127.0.0.1:{port}{path}");
        let deadline = std::time::Instant::now() + LOCAL_HTTP_TEST_TIMEOUT;
        let mut last_error = None;

        while std::time::Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                let stderr = child_stderr(&mut self.child);
                panic!(
                    "approvals server exited before {url} responded: {status}; stderr was: {stderr}"
                );
            }

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
}

fn spawn_approvals_server(home: &Path, port: u16) -> ApprovalsServerChild {
    let guard = APPROVALS_SERVER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let child = Command::new(agentenv_bin())
        .env("HOME", home)
        .args(["approvals", "serve", "--addr", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ApprovalsServerChild {
        child,
        _guard: guard,
    }
}

fn child_stderr(child: &mut process::Child) -> String {
    let mut stderr = String::new();
    if let Some(pipe) = child.stderr.as_mut() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
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
        .timeout(LOCAL_HTTP_TEST_TIMEOUT)
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
