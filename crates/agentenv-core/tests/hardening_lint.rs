use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use agentenv_core::hardening::{lint_blueprint_hardening, HardeningLintSeverity};

fn unique_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn blueprint(dockerfile: &str, hardening: Option<&str>) -> String {
    let hardening = hardening
        .map(|profile| format!("  hardening: {profile}\n"))
        .unwrap_or_default();
    format!(
        r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
{hardening}  image:
    source: byo
    dockerfile: {dockerfile}
agent:
  driver: codex
context:
  driver: filesystem
policy:
  tier: restricted
  presets: []
"#
    )
}

fn diagnostic_severities(
    report: &agentenv_core::hardening::HardeningLintReport,
) -> BTreeMap<&str, HardeningLintSeverity> {
    report
        .diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.severity))
        .collect()
}

#[test]
fn strict_dockerfile_reports_hardening_conflicts() {
    let root = unique_root("agentenv-hardening-lint-strict");
    let sandbox_dir = root.join("sandbox");
    fs::create_dir_all(&sandbox_dir).unwrap();
    let dockerfile = sandbox_dir.join("Dockerfile");
    fs::write(
        &dockerfile,
        r#"
FROM alpine:3.20
RUN apk add --no-cache gcc git
RUN docker run --privileged alpine true
RUN echo cap_add: NET_ADMIN
USER root
"#,
    )
    .unwrap();

    let yaml = blueprint("sandbox/Dockerfile", Some("strict"));
    let report = lint_blueprint_hardening(&yaml, Path::new(&root)).unwrap();

    assert_eq!(report.profile, "strict");
    assert_eq!(report.dockerfile.as_deref(), Some(dockerfile.as_path()));

    let severities = diagnostic_severities(&report);
    assert_eq!(
        severities.get("dockerfile_user_root"),
        Some(&HardeningLintSeverity::Error)
    );
    assert_eq!(
        severities.get("dockerfile_reintroduces_stripped_package"),
        Some(&HardeningLintSeverity::Error)
    );
    assert!(severities.contains_key("dockerfile_privileged"));
    assert!(severities.contains_key("dockerfile_cap_add"));
    assert!(severities.contains_key("dockerfile_missing_hardening_marker"));
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == HardeningLintSeverity::Error));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn baseline_is_default_and_package_reintroduction_is_warning() {
    let root = unique_root("agentenv-hardening-lint-baseline");
    let sandbox_dir = root.join("sandbox");
    fs::create_dir_all(&sandbox_dir).unwrap();
    fs::write(
        sandbox_dir.join("Dockerfile"),
        r#"
FROM ubuntu:24.04
ENV AGENTENV_HARDENING_PROFILE=baseline
RUN apt-get update && apt-get install -y gcc
USER agent
"#,
    )
    .unwrap();

    let yaml = blueprint("sandbox/Dockerfile", None);
    let report = lint_blueprint_hardening(&yaml, Path::new(&root)).unwrap();

    assert_eq!(report.profile, "baseline");
    let severities = diagnostic_severities(&report);
    assert_eq!(
        severities.get("dockerfile_reintroduces_stripped_package"),
        Some(&HardeningLintSeverity::Warning)
    );
    assert!(!severities.contains_key("dockerfile_missing_hardening_marker"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn strict_detects_package_reintroduction_from_multiline_apt_install() {
    let root = unique_root("agentenv-hardening-lint-multiline-apt");
    let sandbox_dir = root.join("sandbox");
    fs::create_dir_all(&sandbox_dir).unwrap();
    fs::write(
        sandbox_dir.join("Dockerfile"),
        r#"
FROM ubuntu:24.04
ENV AGENTENV_HARDENING_PROFILE=strict
RUN apt-get update && apt-get install -y \
    gcc \
    git
USER agent
"#,
    )
    .unwrap();

    let yaml = blueprint("sandbox/Dockerfile", Some("strict"));
    let report = lint_blueprint_hardening(&yaml, Path::new(&root)).unwrap();

    let package_diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "dockerfile_reintroduces_stripped_package")
        .expect("expected package reintroduction diagnostic");
    assert_eq!(package_diagnostic.severity, HardeningLintSeverity::Error);
    assert!(
        package_diagnostic.message.contains("gcc") && package_diagnostic.message.contains("git"),
        "unexpected diagnostic message: {}",
        package_diagnostic.message
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn builder_stage_user_root_does_not_apply_to_final_stage() {
    let root = unique_root("agentenv-hardening-lint-multistage-user");
    let sandbox_dir = root.join("sandbox");
    fs::create_dir_all(&sandbox_dir).unwrap();
    fs::write(
        sandbox_dir.join("Dockerfile"),
        r#"
FROM alpine:3.20 AS builder
USER root
RUN echo building

FROM alpine:3.20
ENV AGENTENV_HARDENING_PROFILE=strict
RUN echo final
"#,
    )
    .unwrap();

    let yaml = blueprint("sandbox/Dockerfile", Some("strict"));
    let report = lint_blueprint_hardening(&yaml, Path::new(&root)).unwrap();

    assert!(
        !report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "dockerfile_user_root"),
        "builder-stage USER root should not be reported for final stage: {:?}",
        report.diagnostics
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lint_severity_serializes_lowercase() {
    assert_eq!(
        serde_json::to_value(HardeningLintSeverity::Warning).unwrap(),
        serde_json::json!("warning")
    );
}
