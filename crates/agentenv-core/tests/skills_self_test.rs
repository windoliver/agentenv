use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use agentenv_core::skills::{
    load_skill_self_test_spec, run_skill_self_test, AgentProduceRequest, AgentProduceRunner,
    SkillAssertionStatus, SkillError, SkillSelfTestAssertion, SkillSelfTestOptions,
    SkillSelfTestRunner, SkillSelfTestSpec,
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

#[test]
fn self_test_runner_scores_file_and_command_assertions() {
    let root = temp_dir("self-test-runner-score-file-command");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: None,
        assertions: vec![
            SkillSelfTestAssertion::FileExists {
                path: "missing.txt".into(),
            },
            SkillSelfTestAssertion::CommandExitsZero {
                cmd: "exit 0".to_owned(),
            },
        ],
        timeout_seconds: 5,
    };

    let report = run_skill_self_test(
        &root,
        "demo",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        Arc::new(UnsupportedTestAgentRunner),
    )
    .expect("runner should produce report");

    assert_eq!(report.name, "demo");
    assert_eq!(report.version, "0.1.0");
    assert_eq!(report.digest, "sha256:bundle");
    assert_eq!(report.passed, 1);
    assert_eq!(report.total, 2);
    assert_eq!(report.score, 0.5);
    assert!(!report.publishable);
    assert_eq!(report.assertions.len(), 2);
    assert_eq!(report.assertions[0].assertion_type, "file_exists");
    assert_eq!(report.assertions[0].status, SkillAssertionStatus::Failed);
    assert_eq!(report.assertions[1].status, SkillAssertionStatus::Passed);
    assert!(report.started_at <= report.completed_at);
}

#[test]
fn self_test_runner_marks_publishable_at_default_threshold() {
    let root = temp_dir("self-test-runner-threshold");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("README.md"), "# Readme\n");
    write_file(&root.join("examples/demo.txt"), "demo\n");
    write_file(&root.join("fixtures/input.txt"), "input\n");
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: None,
        assertions: vec![
            SkillSelfTestAssertion::FileExists {
                path: "SKILL.md".into(),
            },
            SkillSelfTestAssertion::FileExists {
                path: "README.md".into(),
            },
            SkillSelfTestAssertion::FileExists {
                path: "examples/demo.txt".into(),
            },
            SkillSelfTestAssertion::FileExists {
                path: "fixtures/input.txt".into(),
            },
            SkillSelfTestAssertion::FileExists {
                path: "missing.txt".into(),
            },
        ],
        timeout_seconds: 5,
    };

    let report = run_skill_self_test(
        &root,
        "demo-threshold",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        Arc::new(UnsupportedTestAgentRunner),
    )
    .expect("runner should produce report");

    assert_eq!(report.passed, 4);
    assert_eq!(report.total, 5);
    assert_eq!(report.score, 0.8);
    assert!(report.publishable);
}

#[test]
fn self_test_runner_scores_agent_produces_token_matches() {
    let root = temp_dir("self-test-runner-agent-produces");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("agentenv.yaml"), "version: 1\n");
    let runner = Arc::new(FakeAgentRunner::new(
        "The answer mentions Cargo.toml and SKILL.md.",
    ));
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: Some(PathBuf::from("agentenv.yaml")),
        assertions: vec![SkillSelfTestAssertion::AgentProduces {
            prompt: "summarize".to_owned(),
            expect_tokens_matching: vec![
                "Cargo.toml".to_owned(),
                "SKILL.md".to_owned(),
                "missing-token".to_owned(),
            ],
            min_match_ratio: 0.66,
        }],
        timeout_seconds: 5,
    };

    let report = run_skill_self_test(
        &root,
        "demo-agent",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        runner.clone(),
    )
    .expect("runner should produce report");

    assert_eq!(report.passed, 1);
    assert_eq!(report.total, 1);
    assert_eq!(report.score, 1.0);
    assert!(report.publishable);
    assert_eq!(report.assertions[0].assertion_type, "agent_produces");
    assert_eq!(report.assertions[0].status, SkillAssertionStatus::Passed);

    let request = runner.take_request().expect("request should be captured");
    assert_eq!(request.skill_root, root);
    assert_eq!(request.blueprint, root.join("agentenv.yaml"));
    assert_eq!(request.prompt, "summarize");
    assert!(request.timeout > Duration::ZERO);
    assert!(request.timeout <= Duration::from_secs(5));
}

#[test]
fn self_test_runner_passes_remaining_timeout_to_agent_produces() {
    let root = temp_dir("self-test-runner-agent-produces-timeout");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("agentenv.yaml"), "version: 1\n");
    let runner = Arc::new(FakeAgentRunner::new("ready"));
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: Some(PathBuf::from("agentenv.yaml")),
        assertions: vec![
            SkillSelfTestAssertion::CommandExitsZero {
                cmd: "exit 0".to_owned(),
            },
            SkillSelfTestAssertion::AgentProduces {
                prompt: "summarize".to_owned(),
                expect_tokens_matching: vec!["ready".to_owned()],
                min_match_ratio: 1.0,
            },
        ],
        timeout_seconds: 5,
    };

    let report = run_skill_self_test(
        &root,
        "demo-agent-timeout",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        runner.clone(),
    )
    .expect("runner should produce report");

    assert!(report.publishable);

    let request = runner.take_request().expect("request should be captured");
    assert!(request.timeout > Duration::ZERO);
    assert!(
        request.timeout < Duration::from_secs(5),
        "agent_produces should receive remaining budget, got {:?}",
        request.timeout
    );
}

#[test]
fn self_test_runner_bounds_slow_agent_produces_runner() {
    let root = temp_dir("self-test-runner-slow-agent-produces");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    write_file(&root.join("agentenv.yaml"), "version: 1\n");
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: Some(PathBuf::from("agentenv.yaml")),
        assertions: vec![SkillSelfTestAssertion::AgentProduces {
            prompt: "summarize".to_owned(),
            expect_tokens_matching: vec!["ready".to_owned()],
            min_match_ratio: 1.0,
        }],
        timeout_seconds: 1,
    };

    let started = Instant::now();
    let report = run_skill_self_test(
        &root,
        "demo-slow-agent",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        Arc::new(SlowAgentRunner),
    )
    .expect("runner should produce report");

    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(report.passed, 0);
    assert_eq!(report.assertions[0].status, SkillAssertionStatus::Failed);
    assert!(report.assertions[0].message.contains("timed out"));
}

#[test]
fn self_test_runner_rejects_invalid_threshold_option() {
    let root = temp_dir("self-test-runner-invalid-threshold");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: None,
        assertions: vec![SkillSelfTestAssertion::FileExists {
            path: "SKILL.md".into(),
        }],
        timeout_seconds: 5,
    };

    let error = run_skill_self_test(
        &root,
        "demo-invalid-threshold",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions {
            threshold: f64::NAN,
        },
        Arc::new(UnsupportedTestAgentRunner),
    )
    .expect_err("invalid threshold must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[test]
fn self_test_runner_rejects_unrepresentable_deadline() {
    let root = temp_dir("self-test-runner-unrepresentable-deadline");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: None,
        assertions: vec![SkillSelfTestAssertion::FileExists {
            path: "SKILL.md".into(),
        }],
        timeout_seconds: u64::MAX,
    };

    let error = run_skill_self_test(
        &root,
        "demo-huge-timeout",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        Arc::new(UnsupportedTestAgentRunner),
    )
    .expect_err("huge timeout must fail");

    assert!(matches!(error, SkillError::InvalidSelfTest { .. }));
}

#[cfg(unix)]
#[test]
fn self_test_runner_clears_command_environment() {
    let root = temp_dir("self-test-runner-command-env-clear");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: None,
        assertions: vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: r#"test -z "$HOME""#.to_owned(),
        }],
        timeout_seconds: 5,
    };

    let report = run_skill_self_test(
        &root,
        "demo-env-clear",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        Arc::new(UnsupportedTestAgentRunner),
    )
    .expect("runner should produce report");

    assert_eq!(report.assertions[0].status, SkillAssertionStatus::Passed);
}

#[cfg(unix)]
#[test]
fn self_test_runner_kills_command_descendants_on_timeout() {
    let root = temp_dir("self-test-runner-command-descendants");
    write_file(&root.join("SKILL.md"), "# Demo\n");
    let late_file = root.join("late.txt");
    let spec = SkillSelfTestSpec {
        runner: SkillSelfTestRunner::Agentenv,
        blueprint: None,
        assertions: vec![SkillSelfTestAssertion::CommandExitsZero {
            cmd: "(/bin/sleep 2; /usr/bin/touch late.txt) & /bin/sleep 5".to_owned(),
        }],
        timeout_seconds: 1,
    };

    let report = run_skill_self_test(
        &root,
        "demo-descendants",
        "0.1.0",
        "sha256:bundle",
        &spec,
        SkillSelfTestOptions::default(),
        Arc::new(UnsupportedTestAgentRunner),
    )
    .expect("runner should produce report");

    assert_eq!(report.assertions[0].status, SkillAssertionStatus::Failed);
    thread::sleep(Duration::from_secs(3));
    assert!(!late_file.exists());
}

struct UnsupportedTestAgentRunner;

impl AgentProduceRunner for UnsupportedTestAgentRunner {
    fn run_agent_prompt(&self, _request: AgentProduceRequest<'_>) -> Result<String, SkillError> {
        Err(SkillError::UnsupportedAgentProduces)
    }
}

struct SlowAgentRunner;

impl AgentProduceRunner for SlowAgentRunner {
    fn run_agent_prompt(&self, request: AgentProduceRequest<'_>) -> Result<String, SkillError> {
        while !request.cancelled.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(10));
        }
        Ok("ready".to_owned())
    }
}

#[derive(Debug)]
struct CapturedAgentRequest {
    skill_root: PathBuf,
    blueprint: PathBuf,
    prompt: String,
    timeout: Duration,
}

struct FakeAgentRunner {
    output: String,
    request: Mutex<Option<CapturedAgentRequest>>,
}

impl FakeAgentRunner {
    fn new(output: &str) -> Self {
        Self {
            output: output.to_owned(),
            request: Mutex::new(None),
        }
    }

    fn take_request(&self) -> Option<CapturedAgentRequest> {
        self.request.lock().unwrap().take()
    }
}

impl AgentProduceRunner for FakeAgentRunner {
    fn run_agent_prompt(&self, request: AgentProduceRequest<'_>) -> Result<String, SkillError> {
        *self.request.lock().unwrap() = Some(CapturedAgentRequest {
            skill_root: request.skill_root.to_path_buf(),
            blueprint: request.blueprint.to_path_buf(),
            prompt: request.prompt.to_owned(),
            timeout: request.timeout,
        });
        Ok(self.output.clone())
    }
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
