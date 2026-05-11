use async_trait::async_trait;

use agentenv_core::skills::load_skill_manifest;
use agentenv_core::skills::propose::{
    emit_proposal, evaluate_self_test, CandidateToolCall, ProposalEmitInput, ProposalScore,
    ProposalSelfTestInput,
};
use agentenv_core::skills::propose::{
    extract_candidates, normalize_args_shape, CandidateExtractionOptions, ProposalCandidate,
};
use agentenv_core::skills::propose::{
    score_proposal, ExistingSkillSummary, NoveltyBackend, ProposalScoreInput,
};
use agentenv_core::skills::propose::{
    validate_generalization, ProcedureStep, ProposeRunInput, ProposedSelfTest,
    ProposedSkillService, SkillGeneralization, SkillGeneralizationRequest, SkillGeneralizer,
    TemplateVariable,
};
use agentenv_events::{ActivityResult, TraceRun, TraceToolCall};

#[test]
fn extraction_finds_repeated_tool_sequences_for_distinct_traces() {
    let traces = vec![
        trace(
            "trace-1",
            vec![
                call("fs_read", "/repo/a.rs"),
                call("fs_write", "/repo/a.rs"),
            ],
        ),
        trace(
            "trace-2",
            vec![
                call("fs_read", "/repo/b.rs"),
                call("fs_write", "/repo/b.rs"),
            ],
        ),
        trace(
            "trace-3",
            vec![
                call("fs_read", "/repo/c.rs"),
                call("fs_write", "/repo/c.rs"),
            ],
        ),
        trace("trace-4", vec![call("fs_read", "/repo/solo.rs")]),
    ];

    let candidates: Vec<ProposalCandidate> = extract_candidates(
        &traces,
        CandidateExtractionOptions {
            blueprint_id: "sha256:blueprint-a".to_owned(),
            min_occurrences: 3,
        },
    )
    .unwrap();

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].occurrences, 3);
    assert_eq!(
        candidates[0]
            .sequence
            .iter()
            .map(|call| call.tool.as_str())
            .collect::<Vec<_>>(),
        vec!["fs_read", "fs_write"]
    );
    assert_eq!(
        candidates[0].source_trace_ids,
        vec!["trace-1", "trace-2", "trace-3"]
    );
}

#[test]
fn argument_shape_redacts_secret_like_values() {
    let shape = normalize_args_shape(&serde_json::json!({
        "path": "/repo/src/lib.rs",
        "token": "sk-secret",
        "nested": {"authorization": "Bearer secret", "count": 1}
    }));

    let rendered = serde_json::to_string(&shape).unwrap();
    assert!(!rendered.contains("sk-secret"));
    assert!(!rendered.contains("Bearer secret"));
    assert!(rendered.contains("[redacted]"));
    assert!(rendered.contains("string:path"));
}

#[test]
fn generalization_validation_accepts_schema_clean_output() {
    let generalization = clean_generalization();

    validate_generalization(&generalization, &["fs_read".to_owned()]).unwrap();
}

#[test]
fn generalization_validation_rejects_invalid_names_and_secret_leaks() {
    let invalid_name = SkillGeneralization {
        name: "../bad".to_owned(),
        description: "Bad".to_owned(),
        template_variables: Vec::new(),
        procedure_steps: Vec::new(),
        self_test: ProposedSelfTest {
            command: "test -f SKILL.md".to_owned(),
        },
        skill_md_body: "Body".to_owned(),
    };
    assert!(validate_generalization(&invalid_name, &[]).is_err());

    let secret_body = SkillGeneralization {
        name: "secret-skill".to_owned(),
        description: "Bad".to_owned(),
        template_variables: Vec::new(),
        procedure_steps: vec![ProcedureStep {
            tool: Some("fs_read".to_owned()),
            instruction: "Use token sk-secret".to_owned(),
        }],
        self_test: ProposedSelfTest {
            command: "test -f SKILL.md".to_owned(),
        },
        skill_md_body: "token sk-secret".to_owned(),
    };
    assert!(validate_generalization(&secret_body, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_secrets_in_llm_text_fields() {
    let mut secret_description = clean_generalization();
    secret_description.description = "Use api_key from the trace".to_owned();
    assert!(validate_generalization(&secret_description, &["fs_read".to_owned()]).is_err());

    let mut secret_variable_description = clean_generalization();
    secret_variable_description.template_variables[0].description =
        "Password captured from args".to_owned();
    assert!(
        validate_generalization(&secret_variable_description, &["fs_read".to_owned()]).is_err()
    );

    let mut secret_variable_example = clean_generalization();
    secret_variable_example.template_variables[0].example = "token: copied".to_owned();
    assert!(validate_generalization(&secret_variable_example, &["fs_read".to_owned()]).is_err());

    let mut secret_self_test = clean_generalization();
    secret_self_test.self_test.command = "echo Bearer copied".to_owned();
    assert!(validate_generalization(&secret_self_test, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_allows_non_secret_sk_words() {
    let mut generalization = clean_generalization();
    generalization.description =
        "Use task-specific steps for disk-backed filesystem edits.".to_owned();
    generalization.skill_md_body =
        "Use task-specific steps for disk-backed edits to {{target_path}}.".to_owned();

    validate_generalization(&generalization, &["fs_read".to_owned()]).unwrap();
}

#[test]
fn generalization_validation_rejects_actual_sk_secret_tokens() {
    let mut generalization = clean_generalization();
    generalization.description = "Use sk-secret from the trace".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_secret_shaped_skill_names() {
    let mut generalization = clean_generalization();
    generalization.name = "sk-secret".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_secret_shaped_template_variable_names() {
    let mut generalization = clean_generalization();
    generalization.template_variables.push(TemplateVariable {
        name: "sk-secret".to_owned(),
        description: "Secret-shaped variable name.".to_owned(),
        example: "src/main.rs".to_owned(),
    });

    let error = validate_generalization(&generalization, &["fs_read".to_owned()]).unwrap_err();
    assert!(error.to_string().contains("secret-like"));
}

#[test]
fn generalization_validation_rejects_empty_template_variable_examples() {
    let mut generalization = clean_generalization();
    generalization.template_variables[0].example = "  ".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_undeclared_placeholders() {
    let mut generalization = clean_generalization();
    generalization.template_variables = Vec::new();
    generalization.skill_md_body = "Read {{target_path}} before editing.".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_unclosed_placeholder_markers() {
    let mut generalization = clean_generalization();
    generalization.skill_md_body = "Read {{target_path before editing.".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_stray_closing_placeholder_markers() {
    let mut generalization = clean_generalization();
    generalization.skill_md_body = "Read {{target_path}} before editing }}.".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_unreferenced_declared_variables() {
    let mut generalization = clean_generalization();
    generalization.template_variables.push(TemplateVariable {
        name: "unused_path".to_owned(),
        description: "Unused path variable.".to_owned(),
        example: "src/main.rs".to_owned(),
    });

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_empty_procedure_steps() {
    let mut generalization = clean_generalization();
    generalization.procedure_steps = Vec::new();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_body_only_template_variable_references() {
    let mut generalization = clean_generalization();
    generalization.procedure_steps[0].instruction = "Read the target before editing.".to_owned();
    generalization.skill_md_body = "Read {{target_path}} before editing.".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_duplicate_template_variables() {
    let mut generalization = clean_generalization();
    generalization.template_variables.push(TemplateVariable {
        name: "target_path".to_owned(),
        description: "Duplicate path variable.".to_owned(),
        example: "src/main.rs".to_owned(),
    });

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_unknown_procedure_step_tools() {
    let mut generalization = clean_generalization();
    generalization.procedure_steps[0].tool = Some("unknown_tool".to_owned());

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn scoring_maps_duplicate_minor_variant_and_new_capability_to_ladder() {
    let duplicate = score_proposal(ProposalScoreInput {
        name: "review-skill".to_owned(),
        description: "Review code changes".to_owned(),
        procedure_text: "read diff write review".to_owned(),
        fingerprint: "same".to_owned(),
        occurrences: 3,
        existing_skills: vec![ExistingSkillSummary {
            name: "review-skill".to_owned(),
            description: "Review code changes".to_owned(),
            procedure_text: "read diff write review".to_owned(),
            fingerprint: Some("same".to_owned()),
        }],
        backend: NoveltyBackend::Local,
    })
    .unwrap();
    assert_eq!(duplicate.novelty, 0.0);

    let new_capability = score_proposal(ProposalScoreInput {
        name: "snapshot-skill".to_owned(),
        description: "Create and verify snapshots".to_owned(),
        procedure_text: "snapshot verify restore".to_owned(),
        fingerprint: "new".to_owned(),
        occurrences: 5,
        existing_skills: Vec::new(),
        backend: NoveltyBackend::Local,
    })
    .unwrap();
    assert_eq!(new_capability.novelty, 0.9);
    assert!(new_capability.utility > 0.5);
}

#[test]
fn scoring_maps_local_similarity_to_minor_and_distinct_variants() {
    let minor_variation = score_proposal(ProposalScoreInput {
        name: "review-skill-v2".to_owned(),
        description: "Review code changes carefully".to_owned(),
        procedure_text: "read diff write review".to_owned(),
        fingerprint: "minor".to_owned(),
        occurrences: 2,
        existing_skills: vec![ExistingSkillSummary {
            name: "review-skill".to_owned(),
            description: "Review code changes".to_owned(),
            procedure_text: "read diff write review".to_owned(),
            fingerprint: Some("existing".to_owned()),
        }],
        backend: NoveltyBackend::Local,
    })
    .unwrap();
    assert_eq!(minor_variation.novelty, 0.3);

    let distinct_variant = score_proposal(ProposalScoreInput {
        name: "review-tests-skill".to_owned(),
        description: "Review test changes".to_owned(),
        procedure_text: "read tests write review".to_owned(),
        fingerprint: "distinct".to_owned(),
        occurrences: 2,
        existing_skills: vec![ExistingSkillSummary {
            name: "review-skill".to_owned(),
            description: "Review code changes".to_owned(),
            procedure_text: "read diff write review".to_owned(),
            fingerprint: Some("existing".to_owned()),
        }],
        backend: NoveltyBackend::Local,
    })
    .unwrap();
    assert_eq!(distinct_variant.novelty, 0.6);
}

#[test]
fn self_test_scores_step_and_variable_coverage() {
    let report = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned(), "fs_write".to_owned()],
        procedure_steps: vec![
            ProcedureStep {
                tool: Some("fs_read".to_owned()),
                instruction: "Read {{target_path}}".to_owned(),
            },
            ProcedureStep {
                tool: Some("fs_write".to_owned()),
                instruction: "Write {{target_path}}".to_owned(),
            },
        ],
        template_variables: vec![TemplateVariable {
            name: "target_path".to_owned(),
            description: "Target path".to_owned(),
            example: "src/lib.rs".to_owned(),
        }],
        min_score: 0.8,
    })
    .unwrap();

    assert!(report.passed);
    assert!(report.score >= 0.8);
    assert_eq!(report.matched_steps, 2);
    assert_eq!(report.matched_variables, 1);
}

#[test]
fn self_test_missing_source_tool_coverage_fails() {
    let report = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec![
            "fs_read".to_owned(),
            "fs_write".to_owned(),
            "fs_read".to_owned(),
        ],
        procedure_steps: vec![ProcedureStep {
            tool: Some("fs_read".to_owned()),
            instruction: "Read {{target_path}}".to_owned(),
        }],
        template_variables: vec![TemplateVariable {
            name: "target_path".to_owned(),
            description: "Target path".to_owned(),
            example: "src/lib.rs".to_owned(),
        }],
        min_score: 0.8,
    })
    .unwrap();

    assert!(!report.passed);
    assert!(report.matched_steps < report.total_steps);
    assert_eq!(report.matched_steps, 1);
    assert_eq!(report.total_steps, 2);
}

#[test]
fn self_test_human_instruction_steps_do_not_penalize_source_tool_coverage() {
    let report = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned(), "fs_write".to_owned()],
        procedure_steps: vec![
            ProcedureStep {
                tool: Some("fs_read".to_owned()),
                instruction: "Read {{target_path}}".to_owned(),
            },
            ProcedureStep {
                tool: None,
                instruction: "Explain the intended change to {{target_path}}.".to_owned(),
            },
            ProcedureStep {
                tool: Some("fs_write".to_owned()),
                instruction: "Write {{target_path}}".to_owned(),
            },
        ],
        template_variables: vec![TemplateVariable {
            name: "target_path".to_owned(),
            description: "Target path".to_owned(),
            example: "src/lib.rs".to_owned(),
        }],
        min_score: 0.8,
    })
    .unwrap();

    assert!(report.passed);
    assert!(report.failures.is_empty());
    assert_eq!(report.matched_steps, 2);
    assert_eq!(report.total_steps, 2);
}

#[test]
fn self_test_unknown_generated_tool_fails() {
    let report = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned()],
        procedure_steps: vec![
            ProcedureStep {
                tool: Some("fs_read".to_owned()),
                instruction: "Read the target file.".to_owned(),
            },
            ProcedureStep {
                tool: Some("unknown_tool".to_owned()),
                instruction: "Use an unknown generated tool.".to_owned(),
            },
        ],
        template_variables: Vec::new(),
        min_score: 0.5,
    })
    .unwrap();

    assert!(!report.passed);
    assert!(report
        .failures
        .iter()
        .any(|failure| failure.contains("unknown_tool")));
}

#[test]
fn self_test_rejects_empty_procedure_steps() {
    let error = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned()],
        procedure_steps: Vec::new(),
        template_variables: Vec::new(),
        min_score: 0.8,
    })
    .unwrap_err();

    assert!(error.to_string().contains("procedure step"));
}

#[test]
fn self_test_rejects_out_of_range_min_score() {
    let error = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned()],
        procedure_steps: vec![ProcedureStep {
            tool: Some("fs_read".to_owned()),
            instruction: "Read the target file.".to_owned(),
        }],
        template_variables: Vec::new(),
        min_score: 1.1,
    })
    .unwrap_err();

    assert!(error.to_string().contains("between 0.0 and 1.0"));
}

#[test]
fn self_test_no_variables_scores_variable_coverage_complete() {
    let report = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned()],
        procedure_steps: vec![ProcedureStep {
            tool: Some("fs_read".to_owned()),
            instruction: "Read the target file.".to_owned(),
        }],
        template_variables: Vec::new(),
        min_score: 1.0,
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(report.matched_variables, 0);
    assert_eq!(report.total_variables, 0);
    assert_eq!(report.score, 1.0);
}

#[test]
fn proposal_writer_emits_skill_manifest_and_reports() {
    let temp = temp_dir("proposal-writer");
    let output_root = temp.join("proposed");
    let generalization = valid_generalization();
    let output = emit_proposal(proposal_writer_input(output_root.clone(), generalization)).unwrap();

    assert_eq!(output.name, "fs-edit-skill");
    assert_eq!(output.novelty, 0.9);
    assert_eq!(output.utility, 0.6);
    assert_eq!(output.final_score, 0.81);
    assert!(output.path.join("SKILL.md").is_file());
    assert!(output.path.join("skill.yaml").is_file());
    assert!(output.path.join("proposal.yaml").is_file());
    assert!(output.path.join("self-test.json").is_file());
    assert!(output.path.join("traces/provenance.json").is_file());
    let manifest = load_skill_manifest(&output.path).unwrap();
    assert_eq!(manifest.name, "fs-edit-skill");
    assert_eq!(manifest.entry, std::path::PathBuf::from("SKILL.md"));

    let proposal = read_yaml(&output.path.join("proposal.yaml"));
    assert_eq!(
        yaml_str(&proposal, "created_at"),
        Some("2026-05-11T00:00:00Z")
    );
}

#[test]
fn proposal_writer_refuses_existing_output_and_preserves_contents() {
    let temp = temp_dir("proposal-writer-existing");
    let output_root = temp.join("proposed");
    let existing = output_root.join("fs-edit-skill");
    std::fs::create_dir_all(&existing).unwrap();
    std::fs::write(existing.join("sentinel.txt"), "keep").unwrap();

    let error = emit_proposal(proposal_writer_input(
        output_root.clone(),
        valid_generalization(),
    ))
    .unwrap_err();

    assert!(error.to_string().contains("already exists"));
    assert_eq!(
        std::fs::read_to_string(existing.join("sentinel.txt")).unwrap(),
        "keep"
    );
    assert!(!existing.join("SKILL.md").exists());
    assert_no_staging_dirs(&output_root);
}

#[test]
fn proposal_writer_serializes_skill_md_frontmatter_safely() {
    let temp = temp_dir("proposal-writer-frontmatter");
    let output_root = temp.join("proposed");
    let mut generalization = valid_generalization();
    generalization.description =
        "Edit: a repeated filesystem target\nwith --- marker text".to_owned();

    let output = emit_proposal(proposal_writer_input(output_root, generalization)).unwrap();
    let skill_md = std::fs::read_to_string(output.path.join("SKILL.md")).unwrap();
    let frontmatter = skill_md
        .strip_prefix("---\n")
        .and_then(|body| body.split_once("\n---\n"))
        .map(|(frontmatter, _body)| frontmatter)
        .expect("SKILL.md should contain YAML frontmatter");
    let metadata: serde_yaml::Value = serde_yaml::from_str(frontmatter).unwrap();

    assert_eq!(
        yaml_str(&metadata, "description"),
        Some("Edit: a repeated filesystem target\nwith --- marker text")
    );
}

#[tokio::test]
async fn proposal_service_runs_full_pipeline_with_fake_generalizer() {
    let temp = temp_dir("proposal-service");
    let traces = vec![
        trace("trace-1", vec![call("fs_read", "/repo/a.rs")]),
        trace("trace-2", vec![call("fs_read", "/repo/b.rs")]),
        trace("trace-3", vec![call("fs_read", "/repo/c.rs")]),
    ];
    let service = ProposedSkillService::new(Box::new(FakeGeneralizer));

    let output = service
        .run(ProposeRunInput {
            traces,
            output_root: temp.join("proposed"),
            blueprint_id: "sha256:blueprint-a".to_owned(),
            min_occurrences: 3,
            min_novelty: 0.6,
            min_self_test_score: 0.8,
            existing_skills: Vec::new(),
            agentenv_version: "0.0.1-alpha0".to_owned(),
            created_at: "2026-05-11T00:00:00Z".to_owned(),
        })
        .await
        .unwrap();

    assert_eq!(output.proposals.len(), 1);
    assert_eq!(output.proposals[0].name, "fs-edit-skill");
    assert!(output.proposals[0].path.join("SKILL.md").is_file());
}

struct FakeGeneralizer;

#[async_trait]
impl SkillGeneralizer for FakeGeneralizer {
    async fn generalize(
        &self,
        _request: SkillGeneralizationRequest,
    ) -> Result<SkillGeneralization, agentenv_core::skills::SkillError> {
        Ok(valid_generalization())
    }
}

fn clean_generalization() -> SkillGeneralization {
    SkillGeneralization {
        name: "fs-edit-skill".to_owned(),
        description: "Edit a repeated filesystem target.".to_owned(),
        template_variables: vec![TemplateVariable {
            name: "target_path".to_owned(),
            description: "Path to the file being edited.".to_owned(),
            example: "src/lib.rs".to_owned(),
        }],
        procedure_steps: vec![ProcedureStep {
            tool: Some("fs_read".to_owned()),
            instruction: "Read {{target_path}} before editing.".to_owned(),
        }],
        self_test: ProposedSelfTest {
            command: "test -f SKILL.md".to_owned(),
        },
        skill_md_body: "Read {{target_path}} before editing.".to_owned(),
    }
}

fn valid_generalization() -> SkillGeneralization {
    SkillGeneralization {
        name: "fs-edit-skill".to_owned(),
        description: "Edit a repeated filesystem target.".to_owned(),
        template_variables: vec![TemplateVariable {
            name: "target_path".to_owned(),
            description: "Target path".to_owned(),
            example: "src/lib.rs".to_owned(),
        }],
        procedure_steps: vec![ProcedureStep {
            tool: Some("fs_read".to_owned()),
            instruction: "Read {{target_path}}.".to_owned(),
        }],
        self_test: ProposedSelfTest {
            command: "test -f SKILL.md".to_owned(),
        },
        skill_md_body: "Read {{target_path}}.".to_owned(),
    }
}

fn proposal_writer_input(
    output_root: std::path::PathBuf,
    generalization: SkillGeneralization,
) -> ProposalEmitInput {
    let report = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned()],
        procedure_steps: generalization.procedure_steps.clone(),
        template_variables: generalization.template_variables.clone(),
        min_score: 0.8,
    })
    .unwrap();

    ProposalEmitInput {
        output_root,
        candidate: ProposalCandidate {
            name_seed: "fs-read".to_owned(),
            blueprint_id: "sha256:blueprint-a".to_owned(),
            fingerprint: "fingerprint-a".to_owned(),
            occurrences: 3,
            sequence: vec![CandidateToolCall {
                tool: "fs_read".to_owned(),
                args_shape: serde_json::json!({"path": "string:path"}),
            }],
            source_trace_ids: vec![
                "trace-1".to_owned(),
                "trace-2".to_owned(),
                "trace-3".to_owned(),
            ],
            redaction_count: 0,
        },
        generalization,
        score: ProposalScore {
            novelty: 0.9,
            utility: 0.6,
            final_score: 0.81,
            nearest_matches: Vec::new(),
            reasons: vec!["no existing skill matches".to_owned()],
        },
        self_test: report,
        agentenv_version: "0.0.1-alpha0".to_owned(),
        created_at: "2026-05-11T00:00:00Z".to_owned(),
    }
}

fn temp_dir(prefix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn read_yaml(path: &std::path::Path) -> serde_yaml::Value {
    let yaml = std::fs::read_to_string(path).unwrap();
    serde_yaml::from_str(&yaml).unwrap()
}

fn yaml_str<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a str> {
    match value {
        serde_yaml::Value::Mapping(mapping) => mapping
            .get(serde_yaml::Value::String(key.to_owned()))
            .and_then(serde_yaml::Value::as_str),
        _ => None,
    }
}

fn assert_no_staging_dirs(root: &std::path::Path) {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        assert!(
            !file_name.contains(".staging"),
            "unexpected staging directory left behind: {file_name}"
        );
    }
}

fn trace(trace_id: &str, calls: Vec<TraceToolCall>) -> TraceRun {
    TraceRun {
        trace_id: trace_id.to_owned(),
        env: Some("demo".to_owned()),
        blueprint_id: "sha256:blueprint-a".to_owned(),
        started_at: "2026-05-11T00:00:00Z".to_owned(),
        calls,
        terminal_result: ActivityResult::Ok,
        event_ids: Vec::new(),
    }
}

fn call(tool: &str, path: &str) -> TraceToolCall {
    TraceToolCall {
        event_id: 0,
        ordinal: 0,
        tool: tool.to_owned(),
        args: serde_json::json!({"path": path}),
        result: ActivityResult::Ok,
        subject: serde_json::json!({"tool": tool}),
    }
}
