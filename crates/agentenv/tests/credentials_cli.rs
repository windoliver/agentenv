use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn cli() -> Command {
    Command::cargo_bin("agentenv").expect("binary available")
}

#[test]
fn credentials_set_list_where_reset_round_trip() {
    let temp_home = TempDir::new().expect("temp home");

    cli()
        .env("HOME", temp_home.path())
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("SOURCE_KEY", "sk-ant-from-env")
        .args([
            "credentials",
            "set",
            "ANTHROPIC_API_KEY",
            "--from-env",
            "SOURCE_KEY",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ANTHROPIC_API_KEY"));

    cli()
        .env("HOME", temp_home.path())
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .args(["credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ANTHROPIC_API_KEY"))
        .stdout(predicate::str::contains("sk-ant-from-env").not());

    cli()
        .env("HOME", temp_home.path())
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .args(["credentials", "where", "ANTHROPIC_API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("file"));

    cli()
        .env("HOME", temp_home.path())
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .args(["credentials", "reset", "ANTHROPIC_API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ANTHROPIC_API_KEY"));

    cli()
        .env("HOME", temp_home.path())
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .args(["credentials", "where", "ANTHROPIC_API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn credentials_set_supports_default_env_name() {
    let temp_home = TempDir::new().expect("temp home");

    cli()
        .env("HOME", temp_home.path())
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .env("OPENAI_API_KEY", "sk-openai-from-env")
        .args(["credentials", "set", "OPENAI_API_KEY", "--from-env"])
        .assert()
        .success();

    cli()
        .env("HOME", temp_home.path())
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .args(["credentials", "where", "OPENAI_API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("file"));
}
