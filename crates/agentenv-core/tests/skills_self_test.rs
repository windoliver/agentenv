use std::{fs, path::Path};

use agentenv_core::skills::{
    load_skill_self_test_spec, SkillError, SkillSelfTestAssertion, SkillSelfTestRunner,
};

#[test]
fn self_test_spec_loads_from_skill_test_yaml() {
    let root = temp_dir("self-test-yaml");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: demo\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
  timeout_seconds: 120
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("self-test should load");

    assert_eq!(spec.runner, SkillSelfTestRunner::Agentenv);
    assert_eq!(spec.timeout_seconds, 120);
    assert_eq!(
        spec.assertions,
        vec![SkillSelfTestAssertion::FileExists {
            path: "SKILL.md".into()
        }]
    );
}

#[test]
fn self_test_spec_loads_from_skill_md_frontmatter() {
    let root = temp_dir("self-test-frontmatter");
    write_file(
        &root.join("SKILL.md"),
        r#"---
self_test:
  runner: agentenv
  assertions:
    - type: command_exits_zero
      cmd: "test -f SKILL.md"
---
# Demo
"#,
    );
    write_file(
        &root.join("skill.yaml"),
        "name: demo-frontmatter\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let spec = load_skill_self_test_spec(&root).expect("frontmatter self-test should load");

    assert_eq!(spec.assertions.len(), 1);
    assert!(matches!(
        &spec.assertions[0],
        SkillSelfTestAssertion::CommandExitsZero { cmd } if cmd == "test -f SKILL.md"
    ));
}

#[test]
fn self_test_spec_translates_legacy_skill_yaml_command() {
    let root = temp_dir("self-test-legacy-command");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        r#"name: legacy-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  command: "test -f SKILL.md"
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("legacy command should translate");

    assert_eq!(spec.timeout_seconds, 30);
    assert_eq!(
        spec.assertions,
        vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: "test -f SKILL.md".to_owned()
        }]
    );
}

#[test]
fn self_test_spec_rejects_conflicting_locations() {
    let root = temp_dir("self-test-conflict");
    write_file(
        &root.join("SKILL.md"),
        r#"---
self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
---
# Demo
"#,
    );
    write_file(
        &root.join("skill.yaml"),
        r#"name: conflict-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  runner: agentenv
  assertions:
    - type: command_exits_zero
      cmd: "test -f SKILL.md"
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("conflict must fail");

    assert!(matches!(
        error,
        SkillError::ConflictingSelfTestDeclarations { .. }
    ));
}

#[test]
fn self_test_spec_rejects_invalid_agent_assertion_ratio() {
    let root = temp_dir("self-test-bad-ratio");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: bad-ratio\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  blueprint: test/minimal.yaml
  assertions:
    - type: agent_produces
      prompt: "summarize"
      expect_tokens_matching: ["Cargo.toml"]
      min_match_ratio: 1.2
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("ratio must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_spec_normalizes_file_exists_paths_before_conflict_check() {
    let root = temp_dir("self-test-normalized-path-conflict");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: ./SKILL.md
"#,
    );
    write_file(
        &root.join("skill.yaml"),
        r#"name: normalized-path-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("normalized paths should not conflict");

    assert_eq!(
        spec.assertions,
        vec![SkillSelfTestAssertion::FileExists {
            path: "SKILL.md".into()
        }]
    );
}

#[test]
fn self_test_spec_rejects_blank_agent_expected_tokens() {
    let root = temp_dir("self-test-blank-agent-token");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: blank-token\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  blueprint: test/minimal.yaml
  assertions:
    - type: agent_produces
      prompt: "summarize"
      expect_tokens_matching: ["   "]
      min_match_ratio: 1.0
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("blank token must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_spec_legacy_command_ignores_explicit_timeout() {
    let root = temp_dir("self-test-legacy-command-timeout");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        r#"name: legacy-timeout-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  command: "test -f SKILL.md"
  timeout_seconds: 999
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("legacy command should translate");

    assert_eq!(spec.timeout_seconds, 30);
}

#[test]
fn self_test_spec_rejects_legacy_command_with_blueprint() {
    let root = temp_dir("self-test-legacy-command-blueprint");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        r#"name: legacy-blueprint-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  command: "test -f SKILL.md"
  blueprint: test/minimal.yaml
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("legacy blueprint must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_spec_ignores_skill_md_frontmatter_without_self_test() {
    let root = temp_dir("self-test-unrelated-frontmatter");
    write_file(
        &root.join("SKILL.md"),
        r#"---
name: demo
---
# Demo
"#,
    );
    write_file(
        &root.join("skill.yaml"),
        r#"name: unrelated-frontmatter-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  command: "test -f SKILL.md"
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("skill.yaml self-test should load");

    assert_eq!(
        spec.assertions,
        vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: "test -f SKILL.md".to_owned()
        }]
    );
}

#[test]
fn self_test_spec_ignores_malformed_skill_md_frontmatter_without_self_test() {
    let root = temp_dir("self-test-malformed-unrelated-frontmatter");
    write_file(
        &root.join("SKILL.md"),
        r#"---
name: [
---
# Demo
"#,
    );
    write_file(
        &root.join("skill.yaml"),
        r#"name: malformed-unrelated-frontmatter-demo
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  command: "test -f SKILL.md"
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("skill.yaml self-test should load");

    assert_eq!(
        spec.assertions,
        vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: "test -f SKILL.md".to_owned()
        }]
    );
}

#[test]
fn self_test_spec_rejects_unknown_self_test_fields() {
    let root = temp_dir("self-test-unknown-field");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: unknown-field\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
  timeout_second: 5
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("unknown field must fail");

    assert!(matches!(
        error,
        SkillError::Yaml { .. } | SkillError::InvalidSelfTest { .. }
    ));
}

#[test]
fn self_test_spec_rejects_unknown_skill_test_yaml_top_level_fields() {
    let root = temp_dir("self-test-unknown-top-level-field");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: unknown-top-level-field\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
unexpected: true
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("unknown field must fail");

    assert!(matches!(error, SkillError::Yaml { .. }));
}

#[test]
fn self_test_spec_rejects_unsupported_runner() {
    let root = temp_dir("self-test-unsupported-runner");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: unsupported-runner\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: other
  assertions:
    - type: file_exists
      path: SKILL.md
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("unsupported runner must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_spec_rejects_empty_assertions() {
    let root = temp_dir("self-test-empty-assertions");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: empty-assertions\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions: []
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("empty assertions must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_spec_rejects_unsafe_blueprint() {
    let root = temp_dir("self-test-unsafe-blueprint");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: unsafe-blueprint\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  blueprint: ../agentenv.yaml
  assertions:
    - type: file_exists
      path: SKILL.md
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("unsafe blueprint must fail");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn self_test_spec_rejects_unsafe_file_exists_path() {
    let root = temp_dir("self-test-unsafe-file-path");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: unsafe-file-path\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: ../SKILL.md
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("unsafe file path must fail");

    assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
}

#[test]
fn self_test_spec_rejects_empty_command() {
    let root = temp_dir("self-test-empty-command");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: empty-command\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: command_exits_zero
      cmd: "   "
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("empty command must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_spec_rejects_empty_agent_prompt() {
    let root = temp_dir("self-test-empty-agent-prompt");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: empty-agent-prompt\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );
    write_file(
        &root.join("skill-test.yaml"),
        r#"self_test:
  runner: agentenv
  assertions:
    - type: agent_produces
      prompt: "  "
      expect_tokens_matching: ["Cargo.toml"]
      min_match_ratio: 1.0
"#,
    );

    let error = load_skill_self_test_spec(&root).expect_err("empty prompt must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_spec_defaults_structured_timeout() {
    let root = temp_dir("self-test-structured-default-timeout");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        r#"name: structured-default-timeout
version: 0.1.0
entry: SKILL.md
files:
  - SKILL.md
self_test:
  runner: agentenv
  assertions:
    - type: file_exists
      path: SKILL.md
"#,
    );

    let spec = load_skill_self_test_spec(&root).expect("structured self-test should load");

    assert_eq!(spec.timeout_seconds, 120);
}

#[test]
fn self_test_spec_rejects_missing_self_test() {
    let root = temp_dir("self-test-missing");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(
        &root.join("skill.yaml"),
        "name: missing-self-test\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
    );

    let error = load_skill_self_test_spec(&root).expect_err("missing self-test must fail");

    assert!(matches!(error, SkillError::MissingSelfTest));
}

fn temp_dir(prefix: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
