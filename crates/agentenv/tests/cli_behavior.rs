use std::{
    fs,
    path::{Path, PathBuf},
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
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

fn fixture_blueprint() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../blueprints/claude+filesystem+openshell.yaml")
}

fn make_temp_dir(prefix: &str) -> PathBuf {
    let unique = format!(
        "{prefix}-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    fs::create_dir_all(&path).unwrap();
    path
}
