use agentenv_events::{
    trace::{TraceQuery, TraceRun},
    ActivityEvent, ActivityKind, ActivityResult, SqliteEventStore,
};

#[test]
fn trace_query_groups_successful_mcp_calls_by_trace_id_and_blueprint() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "trace-a",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            event(
                "trace-a",
                2,
                "demo",
                "sha256:blueprint-a",
                "fs_write",
                ActivityResult::Ok,
            ),
            event(
                "trace-b",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            event(
                "trace-c",
                1,
                "demo",
                "sha256:blueprint-b",
                "fs_read",
                ActivityResult::Ok,
            ),
        ])
        .unwrap();

    let traces = store
        .query_trace_runs(TraceQuery {
            blueprint_id: "sha256:blueprint-a".to_owned(),
            env: Some("demo".to_owned()),
            limit: 100,
        })
        .unwrap();

    assert_eq!(traces.len(), 2);
    assert_eq!(trace(&traces, "trace-a").calls.len(), 2);
    assert_eq!(trace(&traces, "trace-a").calls[0].tool, "fs_read");
    assert_eq!(trace(&traces, "trace-a").calls[1].tool, "fs_write");
    assert_eq!(trace(&traces, "trace-b").calls.len(), 1);
}

#[test]
fn trace_query_excludes_denied_pending_and_error_traces() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "ok-trace",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            event(
                "denied-trace",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            ActivityEvent::new(
                "2026-05-11T00:00:02Z",
                ActivityKind::EgressDenied,
                ActivityResult::Denied,
                "denied-trace",
            )
            .with_env("demo")
            .with_extra("blueprint_id", serde_json::json!("sha256:blueprint-a")),
            event(
                "error-trace",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Error,
            ),
            ActivityEvent::new(
                "2026-05-11T00:00:03Z",
                ActivityKind::ApprovalRequested,
                ActivityResult::PendingApproval,
                "pending-trace",
            )
            .with_env("demo")
            .with_extra("blueprint_id", serde_json::json!("sha256:blueprint-a")),
        ])
        .unwrap();

    let traces = store
        .query_trace_runs(TraceQuery {
            blueprint_id: "sha256:blueprint-a".to_owned(),
            env: Some("demo".to_owned()),
            limit: 100,
        })
        .unwrap();

    assert_eq!(
        traces
            .iter()
            .map(|trace| trace.trace_id.as_str())
            .collect::<Vec<_>>(),
        vec!["ok-trace"]
    );
}

#[test]
fn trace_query_excludes_same_trace_disqualifying_event_without_blueprint_id() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "ok-trace",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            event(
                "blocked-trace",
                2,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            ActivityEvent::new(
                "2026-05-11T00:00:03Z",
                ActivityKind::EgressDenied,
                ActivityResult::Denied,
                "blocked-trace",
            )
            .with_env("demo"),
        ])
        .unwrap();

    let traces = store
        .query_trace_runs(TraceQuery {
            blueprint_id: "sha256:blueprint-a".to_owned(),
            env: Some("demo".to_owned()),
            limit: 100,
        })
        .unwrap();

    assert_eq!(
        traces
            .iter()
            .map(|trace| trace.trace_id.as_str())
            .collect::<Vec<_>>(),
        vec!["ok-trace"]
    );
}

#[test]
fn trace_query_limit_selects_complete_trace_runs_not_raw_events() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "older-trace",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            event(
                "latest-trace",
                2,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            event(
                "latest-trace",
                3,
                "demo",
                "sha256:blueprint-a",
                "fs_write",
                ActivityResult::Ok,
            ),
        ])
        .unwrap();

    let traces = store
        .query_trace_runs(TraceQuery {
            blueprint_id: "sha256:blueprint-a".to_owned(),
            env: Some("demo".to_owned()),
            limit: 1,
        })
        .unwrap();

    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].trace_id, "latest-trace");
    assert_eq!(traces[0].calls.len(), 2);
    assert_eq!(traces[0].calls[0].tool, "fs_read");
    assert_eq!(traces[0].calls[1].tool, "fs_write");
}

#[test]
fn trace_query_keeps_trace_with_resolved_approval_request() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
    store
        .append_many(&[
            event(
                "approved-trace",
                1,
                "demo",
                "sha256:blueprint-a",
                "fs_read",
                ActivityResult::Ok,
            ),
            ActivityEvent::new(
                "2026-05-11T00:00:02Z",
                ActivityKind::ApprovalRequested,
                ActivityResult::PendingApproval,
                "approved-trace",
            )
            .with_env("demo")
            .with_subject_value("request_id", serde_json::json!("approval-1"))
            .with_extra("blueprint_id", serde_json::json!("sha256:blueprint-a")),
            ActivityEvent::new(
                "2026-05-11T00:00:03Z",
                ActivityKind::ApprovalDecided,
                ActivityResult::Ok,
                "approved-trace",
            )
            .with_env("demo")
            .with_subject_value("request_id", serde_json::json!("approval-1"))
            .with_extra("blueprint_id", serde_json::json!("sha256:blueprint-a")),
        ])
        .unwrap();

    let traces = store
        .query_trace_runs(TraceQuery {
            blueprint_id: "sha256:blueprint-a".to_owned(),
            env: Some("demo".to_owned()),
            limit: 100,
        })
        .unwrap();

    assert_eq!(
        traces
            .iter()
            .map(|trace| trace.trace_id.as_str())
            .collect::<Vec<_>>(),
        vec!["approved-trace"]
    );
}

fn event(
    trace_id: &str,
    ordinal: u32,
    env: &str,
    blueprint_id: &str,
    tool: &str,
    result: ActivityResult,
) -> ActivityEvent {
    ActivityEvent::new(
        format!("2026-05-11T00:00:{ordinal:02}Z"),
        ActivityKind::McpToolCall,
        result,
        trace_id,
    )
    .with_env(env)
    .with_subject_value("tool", serde_json::json!(tool))
    .with_subject_value(
        "arguments",
        serde_json::json!({"path": format!("file-{ordinal}.rs")}),
    )
    .with_extra("blueprint_id", serde_json::json!(blueprint_id))
}

fn trace<'a>(traces: &'a [TraceRun], trace_id: &str) -> &'a TraceRun {
    traces
        .iter()
        .find(|trace| trace.trace_id == trace_id)
        .unwrap()
}
