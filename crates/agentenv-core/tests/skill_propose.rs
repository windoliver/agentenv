use agentenv_core::skills::propose::{
    extract_candidates, normalize_args_shape, CandidateExtractionOptions, ProposalCandidate,
};
use agentenv_core::skills::propose::{
    validate_generalization, ProcedureStep, ProposedSelfTest, SkillGeneralization, TemplateVariable,
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
fn generalization_validation_rejects_undeclared_placeholders() {
    let mut generalization = clean_generalization();
    generalization.template_variables = Vec::new();
    generalization.skill_md_body = "Read {{target_path}} before editing.".to_owned();

    assert!(validate_generalization(&generalization, &["fs_read".to_owned()]).is_err());
}

#[test]
fn generalization_validation_rejects_stray_closing_placeholder_markers() {
    let mut generalization = clean_generalization();
    generalization.skill_md_body = "Read {{target_path}} before editing }}.".to_owned();

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
