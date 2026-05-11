use agentenv_core::skills::propose::{
    extract_candidates, normalize_args_shape, CandidateExtractionOptions, ProposalCandidate,
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
