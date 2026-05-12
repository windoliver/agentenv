# M7-6 Trace Skill Proposer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `agentenv skills propose --from-traces` so successful activity traces can produce scored, self-tested, PR-ready skill draft proposals.

**Architecture:** Add trace-oriented readers in `agentenv-events`, a focused proposal pipeline under `agentenv-core::skills::propose`, and a thin CLI facade under `agentenv skills propose`. Core owns deterministic extraction, validation, scoring, self-test, and proposal emission; the CLI owns config, credentials, OpenAI-compatible HTTP providers, and optional `git`/`gh` PR publishing.

**Tech Stack:** Rust 2021, `clap`, `serde`, `serde_json`, `serde_yaml`, `rusqlite`, `reqwest` with `rustls`, `time`, existing `agentenv-events`, `agentenv-core::skills`, and `agentenv-credstore`.

---

## File Structure

- Create: `crates/agentenv-events/src/trace.rs`
- Modify: `crates/agentenv-events/src/lib.rs`
- Create: `crates/agentenv-events/tests/trace_query.rs`
- Create: `crates/agentenv-core/src/skills/propose/mod.rs`
- Create: `crates/agentenv-core/src/skills/propose/model.rs`
- Create: `crates/agentenv-core/src/skills/propose/extract.rs`
- Create: `crates/agentenv-core/src/skills/propose/generalize.rs`
- Create: `crates/agentenv-core/src/skills/propose/score.rs`
- Create: `crates/agentenv-core/src/skills/propose/self_test.rs`
- Create: `crates/agentenv-core/src/skills/propose/emit.rs`
- Create: `crates/agentenv-core/src/skills/propose/service.rs`
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/src/skills/config.rs`
- Modify: `crates/agentenv-core/src/skills/error.rs`
- Create: `crates/agentenv-core/tests/skill_propose.rs`
- Create: `crates/agentenv/src/skills_propose_cli.rs`
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/src/skills_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`
- Reference: `docs/superpowers/specs/2026-05-11-m7-6-trace-skill-proposer-design.md`

## Task 1: Activity Trace Query API

**Files:**
- Create: `crates/agentenv-events/tests/trace_query.rs`
- Create: `crates/agentenv-events/src/trace.rs`
- Modify: `crates/agentenv-events/src/lib.rs`

- [ ] **Step 1: Write failing trace query tests**

Create `crates/agentenv-events/tests/trace_query.rs`:

```rust
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
            event("trace-a", 1, "demo", "sha256:blueprint-a", "fs_read", ActivityResult::Ok),
            event("trace-a", 2, "demo", "sha256:blueprint-a", "fs_write", ActivityResult::Ok),
            event("trace-b", 1, "demo", "sha256:blueprint-a", "fs_read", ActivityResult::Ok),
            event("trace-c", 1, "demo", "sha256:blueprint-b", "fs_read", ActivityResult::Ok),
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
            event("ok-trace", 1, "demo", "sha256:blueprint-a", "fs_read", ActivityResult::Ok),
            event("denied-trace", 1, "demo", "sha256:blueprint-a", "fs_read", ActivityResult::Ok),
            ActivityEvent::new(
                "2026-05-11T00:00:02Z",
                ActivityKind::EgressDenied,
                ActivityResult::Denied,
                "denied-trace",
            )
            .with_env("demo")
            .with_extra("blueprint_id", serde_json::json!("sha256:blueprint-a")),
            event("error-trace", 1, "demo", "sha256:blueprint-a", "fs_read", ActivityResult::Error),
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

    assert_eq!(traces.iter().map(|trace| trace.trace_id.as_str()).collect::<Vec<_>>(), vec!["ok-trace"]);
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
    .with_subject_value("arguments", serde_json::json!({"path": format!("file-{ordinal}.rs")}))
    .with_extra("blueprint_id", serde_json::json!(blueprint_id))
}

fn trace<'a>(traces: &'a [TraceRun], trace_id: &str) -> &'a TraceRun {
    traces
        .iter()
        .find(|trace| trace.trace_id == trace_id)
        .unwrap()
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-events --test trace_query
```

Expected: FAIL because `agentenv_events::trace` and `SqliteEventStore::query_trace_runs` do not exist.

- [ ] **Step 3: Add trace models and query implementation**

Create `crates/agentenv-events/src/trace.rs`:

```rust
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ActivityResult, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceQuery {
    pub blueprint_id: String,
    pub env: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRun {
    pub trace_id: String,
    pub env: Option<String>,
    pub blueprint_id: String,
    pub started_at: String,
    pub calls: Vec<TraceToolCall>,
    pub terminal_result: ActivityResult,
    pub event_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceToolCall {
    pub event_id: i64,
    pub ordinal: u32,
    pub tool: String,
    pub args: Value,
    pub result: ActivityResult,
    pub subject: Value,
}

pub(crate) fn event_blueprint_id(event: &crate::ActivityEvent) -> Option<&str> {
    event.extras.get("blueprint_id").and_then(Value::as_str)
}

pub(crate) fn event_tool_name(event: &crate::ActivityEvent) -> Option<&str> {
    event.subject.get("tool").and_then(Value::as_str)
}

pub(crate) fn event_arguments(event: &crate::ActivityEvent) -> Value {
    event
        .subject
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(Default::default()))
}

pub(crate) fn stored_event_id(row: &StoredEvent) -> i64 {
    row.id
}
```

Modify `crates/agentenv-events/src/lib.rs`:

```rust
pub mod trace;
pub use trace::{TraceQuery, TraceRun, TraceToolCall};
```

Add `query_trace_runs` to `impl SqliteEventStore` in `crates/agentenv-events/src/store.rs`:

```rust
pub fn query_trace_runs(&self, query: crate::trace::TraceQuery) -> StoreResult<Vec<crate::trace::TraceRun>> {
    use crate::trace::{event_arguments, event_blueprint_id, event_tool_name, TraceRun, TraceToolCall};
    use std::collections::{BTreeMap, BTreeSet};

    let rows = self.query(EventQuery {
        env: query.env.clone(),
        limit: query.limit.clamp(1, 10_000),
        ..EventQuery::default()
    })?;

    let mut excluded = BTreeSet::new();
    let mut grouped: BTreeMap<String, Vec<StoredEvent>> = BTreeMap::new();

    for row in rows {
        if event_blueprint_id(&row.event) != Some(query.blueprint_id.as_str()) {
            continue;
        }
        let trace_id = row.event.trace_id.clone();
        if row.event.kind == ActivityKind::EgressDenied
            || row.event.kind == ActivityKind::SpawnRejected
            || row.event.result == ActivityResult::Denied
            || row.event.result == ActivityResult::PendingApproval
            || row.event.result == ActivityResult::Error
        {
            excluded.insert(trace_id);
            continue;
        }
        grouped.entry(trace_id).or_default().push(row);
    }

    let mut runs = Vec::new();
    for (trace_id, mut rows) in grouped {
        if excluded.contains(&trace_id) {
            continue;
        }
        rows.sort_by_key(|row| row.id);
        let mut calls = Vec::new();
        for row in &rows {
            if row.event.kind != ActivityKind::McpToolCall {
                continue;
            }
            let Some(tool) = event_tool_name(&row.event) else {
                continue;
            };
            calls.push(TraceToolCall {
                event_id: row.id,
                ordinal: calls.len() as u32,
                tool: tool.to_owned(),
                args: event_arguments(&row.event),
                result: row.event.result,
                subject: serde_json::to_value(&row.event.subject)?,
            });
        }
        if calls.is_empty() {
            continue;
        }
        let started_at = rows
            .first()
            .map(|row| row.event.ts.clone())
            .unwrap_or_default();
        let env = rows.iter().find_map(|row| row.event.env.clone());
        let event_ids = rows.iter().map(|row| row.id).collect();
        runs.push(TraceRun {
            trace_id,
            env,
            blueprint_id: query.blueprint_id.clone(),
            started_at,
            calls,
            terminal_result: ActivityResult::Ok,
            event_ids,
        });
    }
    runs.sort_by(|left, right| left.trace_id.cmp(&right.trace_id));
    Ok(runs)
}
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-events --test trace_query
```

Expected: PASS with 2 tests passing.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-events/src/lib.rs crates/agentenv-events/src/store.rs crates/agentenv-events/src/trace.rs crates/agentenv-events/tests/trace_query.rs
git commit -m "feat: add activity trace queries"
```

## Task 2: Proposal Models And Extraction

**Files:**
- Create: `crates/agentenv-core/tests/skill_propose.rs`
- Create: `crates/agentenv-core/src/skills/propose/mod.rs`
- Create: `crates/agentenv-core/src/skills/propose/model.rs`
- Create: `crates/agentenv-core/src/skills/propose/extract.rs`
- Modify: `crates/agentenv-core/src/skills/mod.rs`

- [ ] **Step 1: Write failing extraction tests**

Append to `crates/agentenv-core/tests/skill_propose.rs`:

```rust
use agentenv_core::skills::propose::{
    extract_candidates, normalize_args_shape, CandidateExtractionOptions, ProposalCandidate,
};
use agentenv_events::{ActivityResult, TraceRun, TraceToolCall};

#[test]
fn extraction_finds_repeated_tool_sequences_for_distinct_traces() {
    let traces = vec![
        trace("trace-1", vec![call("fs_read", "/repo/a.rs"), call("fs_write", "/repo/a.rs")]),
        trace("trace-2", vec![call("fs_read", "/repo/b.rs"), call("fs_write", "/repo/b.rs")]),
        trace("trace-3", vec![call("fs_read", "/repo/c.rs"), call("fs_write", "/repo/c.rs")]),
        trace("trace-4", vec![call("fs_read", "/repo/solo.rs")]),
    ];

    let candidates = extract_candidates(
        &traces,
        CandidateExtractionOptions {
            blueprint_id: "sha256:blueprint-a".to_owned(),
            min_occurrences: 3,
        },
    )
    .unwrap();

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].occurrences, 3);
    assert_eq!(candidates[0].sequence.iter().map(|call| call.tool.as_str()).collect::<Vec<_>>(), vec!["fs_read", "fs_write"]);
    assert_eq!(candidates[0].source_trace_ids, vec!["trace-1", "trace-2", "trace-3"]);
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
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core --test skill_propose extraction_
```

Expected: FAIL because `skills::propose` and extraction functions do not exist.

- [ ] **Step 3: Add proposal model and extraction modules**

Create `crates/agentenv-core/src/skills/propose/model.rs`:

```rust
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposalCandidate {
    pub name_seed: String,
    pub blueprint_id: String,
    pub fingerprint: String,
    pub occurrences: usize,
    pub sequence: Vec<CandidateToolCall>,
    pub source_trace_ids: Vec<String>,
    pub redaction_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateToolCall {
    pub tool: String,
    pub args_shape: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateExtractionOptions {
    pub blueprint_id: String,
    pub min_occurrences: usize,
}
```

Create `crates/agentenv-core/src/skills/propose/extract.rs`:

```rust
use std::collections::{BTreeMap, BTreeSet};

use agentenv_events::TraceRun;
use serde_json::Value;

use super::model::{CandidateExtractionOptions, CandidateToolCall, ProposalCandidate};
use crate::skills::SkillError;

pub fn normalize_args_shape(value: &Value) -> Value {
    normalize_value(value).0
}

pub fn extract_candidates(
    traces: &[TraceRun],
    options: CandidateExtractionOptions,
) -> Result<Vec<ProposalCandidate>, SkillError> {
    if options.min_occurrences < 2 {
        return Err(SkillError::InvalidConfig {
            message: "min occurrences must be at least 2".to_owned(),
        });
    }

    let mut groups: BTreeMap<String, (Vec<CandidateToolCall>, BTreeSet<String>, usize)> = BTreeMap::new();
    for trace in traces {
        if trace.blueprint_id != options.blueprint_id || trace.calls.is_empty() {
            continue;
        }
        let mut redactions = 0usize;
        let sequence = trace
            .calls
            .iter()
            .map(|call| {
                let (args_shape, count) = normalize_value(&call.args);
                redactions += count;
                CandidateToolCall {
                    tool: call.tool.clone(),
                    args_shape,
                }
            })
            .collect::<Vec<_>>();
        let fingerprint = fingerprint_for(&sequence)?;
        let entry = groups
            .entry(fingerprint)
            .or_insert_with(|| (sequence, BTreeSet::new(), 0));
        entry.1.insert(trace.trace_id.clone());
        entry.2 += redactions;
    }

    let mut candidates = Vec::new();
    for (fingerprint, (sequence, trace_ids, redaction_count)) in groups {
        if trace_ids.len() < options.min_occurrences {
            continue;
        }
        let source_trace_ids = trace_ids.into_iter().collect::<Vec<_>>();
        let name_seed = sequence
            .iter()
            .map(|call| call.tool.replace('_', "-"))
            .collect::<Vec<_>>()
            .join("-");
        candidates.push(ProposalCandidate {
            name_seed,
            blueprint_id: options.blueprint_id.clone(),
            fingerprint,
            occurrences: source_trace_ids.len(),
            sequence,
            source_trace_ids,
            redaction_count,
        });
    }
    candidates.sort_by(|left, right| right.occurrences.cmp(&left.occurrences).then(left.fingerprint.cmp(&right.fingerprint)));
    Ok(candidates)
}

fn normalize_value(value: &Value) -> (Value, usize) {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            let mut redactions = 0usize;
            for (key, value) in map {
                if is_secret_key(key) {
                    out.insert(key.clone(), Value::String("[redacted]".to_owned()));
                    redactions += 1;
                } else {
                    let (normalized, count) = normalize_value(value);
                    out.insert(key.clone(), normalized);
                    redactions += count;
                }
            }
            (Value::Object(out), redactions)
        }
        Value::Array(values) => {
            let mut redactions = 0usize;
            let values = values
                .iter()
                .map(|value| {
                    let (normalized, count) = normalize_value(value);
                    redactions += count;
                    normalized
                })
                .collect();
            (Value::Array(values), redactions)
        }
        Value::String(text) if looks_like_path(text) => (Value::String("string:path".to_owned()), 0),
        Value::String(text) if looks_like_url(text) => (Value::String("string:url".to_owned()), 0),
        Value::String(_) => (Value::String("string".to_owned()), 0),
        Value::Number(_) => (Value::String("number".to_owned()), 0),
        Value::Bool(_) => (Value::String("bool".to_owned()), 0),
        Value::Null => (Value::String("null".to_owned()), 0),
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("token") || key.contains("secret") || key.contains("authorization") || key.contains("password")
}

fn looks_like_path(text: &str) -> bool {
    text.starts_with('/') || text.contains(".rs") || text.contains(".md") || text.contains(".toml")
}

fn looks_like_url(text: &str) -> bool {
    text.starts_with("http://") || text.starts_with("https://")
}

fn fingerprint_for(sequence: &[CandidateToolCall]) -> Result<String, SkillError> {
    serde_json::to_string(sequence).map_err(|source| SkillError::InvalidConfig {
        message: format!("failed to fingerprint proposal candidate: {source}"),
    })
}
```

Create `crates/agentenv-core/src/skills/propose/mod.rs`:

```rust
mod extract;
mod model;

pub use extract::{extract_candidates, normalize_args_shape};
pub use model::{CandidateExtractionOptions, CandidateToolCall, ProposalCandidate};
```

Modify `crates/agentenv-core/src/skills/mod.rs`:

```rust
pub mod propose;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-core --test skill_propose extraction_
```

Expected: PASS for the extraction tests.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/src/skills/propose crates/agentenv-core/tests/skill_propose.rs
git commit -m "feat: extract skill candidates from traces"
```

## Task 3: Generalization Schema And Validation

**Files:**
- Modify: `crates/agentenv-core/src/skills/propose/mod.rs`
- Create: `crates/agentenv-core/src/skills/propose/generalize.rs`
- Modify: `crates/agentenv-core/src/skills/propose/model.rs`
- Modify: `crates/agentenv-core/tests/skill_propose.rs`

- [ ] **Step 1: Write failing generalization validation tests**

Append to `crates/agentenv-core/tests/skill_propose.rs`:

```rust
use agentenv_core::skills::propose::{
    validate_generalization, ProcedureStep, ProposedSelfTest, SkillGeneralization,
    TemplateVariable,
};

#[test]
fn generalization_validation_accepts_schema_clean_output() {
    let generalization = SkillGeneralization {
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
    };

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
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core --test skill_propose generalization_
```

Expected: FAIL because generalization models and validation are missing.

- [ ] **Step 3: Add generalization models and validation**

Extend `crates/agentenv-core/src/skills/propose/model.rs`:

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillGeneralization {
    pub name: String,
    pub description: String,
    pub template_variables: Vec<TemplateVariable>,
    pub procedure_steps: Vec<ProcedureStep>,
    pub self_test: ProposedSelfTest,
    pub skill_md_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
    pub example: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureStep {
    pub tool: Option<String>,
    pub instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedSelfTest {
    pub command: String,
}
```

Create `crates/agentenv-core/src/skills/propose/generalize.rs`:

```rust
use std::collections::BTreeSet;

use async_trait::async_trait;

use super::model::SkillGeneralization;
use crate::skills::{validate_skill_name, SkillError};

#[async_trait]
pub trait SkillGeneralizer: Send + Sync {
    async fn generalize(&self, request: SkillGeneralizationRequest) -> Result<SkillGeneralization, SkillError>;
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SkillGeneralizationRequest {
    pub schema_version: String,
    pub candidate_json: serde_json::Value,
    pub existing_skill_summaries: Vec<String>,
}

pub fn validate_generalization(
    generalization: &SkillGeneralization,
    allowed_tools: &[String],
) -> Result<(), SkillError> {
    validate_skill_name(&generalization.name)?;
    require_non_empty("description", &generalization.description)?;
    require_non_empty("skill_md_body", &generalization.skill_md_body)?;
    reject_secret_text(&generalization.skill_md_body)?;

    let allowed_tools = allowed_tools.iter().cloned().collect::<BTreeSet<_>>();
    let variables = generalization
        .template_variables
        .iter()
        .map(|variable| variable.name.clone())
        .collect::<BTreeSet<_>>();
    for variable in &generalization.template_variables {
        validate_skill_name(&variable.name)?;
        require_non_empty("template variable description", &variable.description)?;
    }
    for step in &generalization.procedure_steps {
        require_non_empty("procedure step instruction", &step.instruction)?;
        reject_secret_text(&step.instruction)?;
        if let Some(tool) = &step.tool {
            if !allowed_tools.contains(tool) {
                return Err(SkillError::InvalidConfig {
                    message: format!("generalized step references unknown tool `{tool}`"),
                });
            }
        }
    }
    for variable in variables {
        let marker = format!("{{{{{variable}}}}}");
        let referenced = generalization.skill_md_body.contains(&marker)
            || generalization
                .procedure_steps
                .iter()
                .any(|step| step.instruction.contains(&marker));
        if !referenced {
            return Err(SkillError::InvalidConfig {
                message: format!("template variable `{variable}` is not referenced"),
            });
        }
    }
    require_non_empty("self-test command", &generalization.self_test.command)?;
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), SkillError> {
    if value.trim().is_empty() {
        return Err(SkillError::InvalidConfig {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn reject_secret_text(value: &str) -> Result<(), SkillError> {
    let lowered = value.to_ascii_lowercase();
    if lowered.contains("sk-") || lowered.contains("bearer ") || lowered.contains("token ") {
        return Err(SkillError::InvalidConfig {
            message: "generalized skill text contains secret-like content".to_owned(),
        });
    }
    Ok(())
}
```

Modify `crates/agentenv-core/src/skills/propose/mod.rs`:

```rust
mod generalize;
pub use generalize::{validate_generalization, SkillGeneralizationRequest, SkillGeneralizer};
pub use model::{ProcedureStep, ProposedSelfTest, SkillGeneralization, TemplateVariable};
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-core --test skill_propose generalization_
```

Expected: PASS for generalization tests.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/skills/propose crates/agentenv-core/tests/skill_propose.rs
git commit -m "feat: validate skill proposal generalization"
```

## Task 4: Novelty And Utility Scoring

**Files:**
- Create: `crates/agentenv-core/src/skills/propose/score.rs`
- Modify: `crates/agentenv-core/src/skills/propose/mod.rs`
- Modify: `crates/agentenv-core/src/skills/propose/model.rs`
- Modify: `crates/agentenv-core/tests/skill_propose.rs`

- [ ] **Step 1: Write failing scoring tests**

Append to `crates/agentenv-core/tests/skill_propose.rs`:

```rust
use agentenv_core::skills::propose::{
    score_proposal, ExistingSkillSummary, NoveltyBackend, ProposalScoreInput,
};

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
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core --test skill_propose scoring_
```

Expected: FAIL because score types and functions are missing.

- [ ] **Step 3: Implement local scoring**

Extend `model.rs`:

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProposalScore {
    pub novelty: f32,
    pub utility: f32,
    pub final_score: f32,
    pub nearest_matches: Vec<SkillMatch>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SkillMatch {
    pub name: String,
    pub similarity: f32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingSkillSummary {
    pub name: String,
    pub description: String,
    pub procedure_text: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoveltyBackend {
    Local,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposalScoreInput {
    pub name: String,
    pub description: String,
    pub procedure_text: String,
    pub fingerprint: String,
    pub occurrences: usize,
    pub existing_skills: Vec<ExistingSkillSummary>,
    pub backend: NoveltyBackend,
}
```

Create `score.rs`:

```rust
use std::collections::BTreeSet;

use super::model::{ProposalScore, ProposalScoreInput, SkillMatch};
use crate::skills::SkillError;

pub fn score_proposal(input: ProposalScoreInput) -> Result<ProposalScore, SkillError> {
    let mut best: Option<SkillMatch> = None;
    let mut novelty = 0.9f32;
    let mut reasons = Vec::new();

    for existing in &input.existing_skills {
        if existing.fingerprint.as_deref() == Some(input.fingerprint.as_str()) {
            novelty = 0.0;
            best = Some(SkillMatch {
                name: existing.name.clone(),
                similarity: 1.0,
                reason: "exact fingerprint match".to_owned(),
            });
            reasons.push("duplicate of existing skill".to_owned());
            break;
        }
        let similarity = jaccard(&input.procedure_text, &existing.procedure_text)
            .max(jaccard(&input.description, &existing.description));
        if best.as_ref().is_none_or(|current| similarity > current.similarity) {
            best = Some(SkillMatch {
                name: existing.name.clone(),
                similarity,
                reason: "local semantic similarity".to_owned(),
            });
        }
    }

    if novelty != 0.0 {
        if let Some(best) = &best {
            novelty = if best.similarity >= 0.85 {
                reasons.push("minor variation of existing skill".to_owned());
                0.3
            } else if best.similarity >= 0.45 {
                reasons.push("distinct variant of existing skill family".to_owned());
                0.6
            } else {
                reasons.push("new capability category".to_owned());
                0.9
            };
        } else {
            reasons.push("no existing skill matches".to_owned());
        }
    }

    let utility = ((input.occurrences as f32) / 5.0).clamp(0.0, 1.0);
    let final_score = (novelty * 0.7) + (utility * 0.3);
    Ok(ProposalScore {
        novelty,
        utility,
        final_score,
        nearest_matches: best.into_iter().collect(),
        reasons,
    })
}

fn jaccard(left: &str, right: &str) -> f32 {
    let left = tokens(left);
    let right = tokens(right);
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let intersection = left.intersection(&right).count() as f32;
    let union = left.union(&right).count() as f32;
    if union == 0.0 { 0.0 } else { intersection / union }
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}
```

Modify `mod.rs` exports:

```rust
mod score;
pub use model::{ExistingSkillSummary, NoveltyBackend, ProposalScore, ProposalScoreInput, SkillMatch};
pub use score::score_proposal;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-core --test skill_propose scoring_
```

Expected: PASS for scoring tests.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/skills/propose crates/agentenv-core/tests/skill_propose.rs
git commit -m "feat: score proposed skills"
```

## Task 5: Self-Test Gate

**Files:**
- Create: `crates/agentenv-core/src/skills/propose/self_test.rs`
- Modify: `crates/agentenv-core/src/skills/propose/mod.rs`
- Modify: `crates/agentenv-core/src/skills/propose/model.rs`
- Modify: `crates/agentenv-core/tests/skill_propose.rs`

- [ ] **Step 1: Write failing self-test tests**

Append to `crates/agentenv-core/tests/skill_propose.rs`:

```rust
use agentenv_core::skills::propose::{
    evaluate_self_test, ProposalSelfTestInput,
};

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
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core --test skill_propose self_test_
```

Expected: FAIL because self-test types and evaluator are missing.

- [ ] **Step 3: Implement self-test evaluator**

Extend `model.rs`:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct ProposalSelfTestInput {
    pub source_tools: Vec<String>,
    pub procedure_steps: Vec<ProcedureStep>,
    pub template_variables: Vec<TemplateVariable>,
    pub min_score: f32,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProposalSelfTestReport {
    pub score: f32,
    pub passed: bool,
    pub matched_steps: u32,
    pub total_steps: u32,
    pub matched_variables: u32,
    pub total_variables: u32,
    pub failures: Vec<String>,
}
```

Create `self_test.rs`:

```rust
use std::collections::BTreeSet;

use super::model::{ProposalSelfTestInput, ProposalSelfTestReport};
use crate::skills::SkillError;

pub fn evaluate_self_test(input: ProposalSelfTestInput) -> Result<ProposalSelfTestReport, SkillError> {
    if !(0.0..=1.0).contains(&input.min_score) {
        return Err(SkillError::InvalidConfig {
            message: "min self-test score must be between 0.0 and 1.0".to_owned(),
        });
    }
    let source_tools = input.source_tools.iter().cloned().collect::<BTreeSet<_>>();
    let total_steps = input.procedure_steps.len() as u32;
    let matched_steps = input
        .procedure_steps
        .iter()
        .filter(|step| step.tool.as_ref().is_some_and(|tool| source_tools.contains(tool)))
        .count() as u32;

    let all_text = input
        .procedure_steps
        .iter()
        .map(|step| step.instruction.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let total_variables = input.template_variables.len() as u32;
    let matched_variables = input
        .template_variables
        .iter()
        .filter(|variable| all_text.contains(&format!("{{{{{}}}}}", variable.name)))
        .count() as u32;

    let step_score = ratio(matched_steps, total_steps);
    let variable_score = ratio(matched_variables, total_variables);
    let score = ((step_score * 0.7) + (variable_score * 0.3)).clamp(0.0, 1.0);
    let mut failures = Vec::new();
    if matched_steps != total_steps {
        failures.push("not every procedure step maps to a source tool".to_owned());
    }
    if matched_variables != total_variables {
        failures.push("not every template variable is referenced by a step".to_owned());
    }

    Ok(ProposalSelfTestReport {
        score,
        passed: score >= input.min_score,
        matched_steps,
        total_steps,
        matched_variables,
        total_variables,
        failures,
    })
}

fn ratio(matched: u32, total: u32) -> f32 {
    if total == 0 { 1.0 } else { matched as f32 / total as f32 }
}
```

Modify `mod.rs` exports:

```rust
mod self_test;
pub use model::{ProposalSelfTestInput, ProposalSelfTestReport};
pub use self_test::evaluate_self_test;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-core --test skill_propose self_test_
```

Expected: PASS for self-test tests.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/skills/propose crates/agentenv-core/tests/skill_propose.rs
git commit -m "feat: gate proposals with trace self tests"
```

## Task 6: Proposal Emission

**Files:**
- Create: `crates/agentenv-core/src/skills/propose/emit.rs`
- Modify: `crates/agentenv-core/src/skills/propose/mod.rs`
- Modify: `crates/agentenv-core/src/skills/propose/model.rs`
- Modify: `crates/agentenv-core/tests/skill_propose.rs`

- [ ] **Step 1: Write failing proposal writer tests**

Append to `crates/agentenv-core/tests/skill_propose.rs`:

```rust
use agentenv_core::skills::{
    load_skill_manifest,
    propose::{emit_proposal, ProposalEmitInput},
};

#[test]
fn proposal_writer_emits_skill_manifest_and_reports() {
    let temp = tempfile::tempdir().unwrap();
    let output_root = temp.path().join("proposed");
    let generalization = valid_generalization();
    let report = evaluate_self_test(ProposalSelfTestInput {
        source_tools: vec!["fs_read".to_owned()],
        procedure_steps: generalization.procedure_steps.clone(),
        template_variables: generalization.template_variables.clone(),
        min_score: 0.8,
    })
    .unwrap();

    let output = emit_proposal(ProposalEmitInput {
        output_root: output_root.clone(),
        candidate: ProposalCandidate {
            name_seed: "fs-read".to_owned(),
            blueprint_id: "sha256:blueprint-a".to_owned(),
            fingerprint: "fingerprint-a".to_owned(),
            occurrences: 3,
            sequence: vec![CandidateToolCall {
                tool: "fs_read".to_owned(),
                args_shape: serde_json::json!({"path": "string:path"}),
            }],
            source_trace_ids: vec!["trace-1".to_owned(), "trace-2".to_owned(), "trace-3".to_owned()],
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
    })
    .unwrap();

    assert_eq!(output.name, "fs-edit-skill");
    assert!(output.path.join("SKILL.md").is_file());
    assert!(output.path.join("skill.yaml").is_file());
    assert!(output.path.join("proposal.yaml").is_file());
    assert!(output.path.join("self-test.json").is_file());
    assert!(output.path.join("traces/provenance.json").is_file());
    let manifest = load_skill_manifest(&output.path).unwrap();
    assert_eq!(manifest.name, "fs-edit-skill");
    assert_eq!(manifest.entry, std::path::PathBuf::from("SKILL.md"));
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
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core --test skill_propose proposal_writer_
```

Expected: FAIL because `emit_proposal` and writer types are missing.

- [ ] **Step 3: Implement proposal writer**

Extend `model.rs`:

```rust
#[derive(Debug, Clone)]
pub struct ProposalEmitInput {
    pub output_root: std::path::PathBuf,
    pub candidate: ProposalCandidate,
    pub generalization: SkillGeneralization,
    pub score: ProposalScore,
    pub self_test: ProposalSelfTestReport,
    pub agentenv_version: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProposalEmitOutput {
    pub name: String,
    pub path: std::path::PathBuf,
    pub novelty: f32,
    pub self_test_score: f32,
}
```

Create `emit.rs` with a staging directory, explicit files, and no overwrite:

```rust
use std::{fs, path::Path};

use serde::Serialize;

use super::model::{ProposalEmitInput, ProposalEmitOutput};
use crate::skills::{load_skill_manifest, validate_skill_name, SkillError};

#[derive(Serialize)]
struct ProposalYaml<'a> {
    schema_version: &'static str,
    status: &'static str,
    blueprint_id: &'a str,
    occurrences: usize,
    novelty: f32,
    utility: f32,
    self_test_score: f32,
    generated_by: GeneratedBy<'a>,
}

#[derive(Serialize)]
struct GeneratedBy<'a> {
    agentenv_version: &'a str,
}

pub fn emit_proposal(input: ProposalEmitInput) -> Result<ProposalEmitOutput, SkillError> {
    validate_skill_name(&input.generalization.name)?;
    let output = input.output_root.join(&input.generalization.name);
    if output.exists() {
        return Err(SkillError::InvalidConfig {
            message: format!("proposal output `{}` already exists", output.display()),
        });
    }
    let staging = input.output_root.join(format!(".{}.staging", input.generalization.name));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|source| SkillError::Io { path: staging.clone(), source })?;
    }
    fs::create_dir_all(staging.join("traces")).map_err(|source| SkillError::Io { path: staging.clone(), source })?;

    write_file(&staging.join("SKILL.md"), render_skill_md(&input))?;
    write_file(&staging.join("skill.yaml"), render_skill_yaml(&input)?)?;
    write_file(&staging.join("proposal.yaml"), render_proposal_yaml(&input)?)?;
    write_file(&staging.join("self-test.json"), json_pretty(&input.self_test, &staging.join("self-test.json"))?)?;
    write_file(&staging.join("traces/provenance.json"), json_pretty(&input.candidate, &staging.join("traces/provenance.json"))?)?;
    load_skill_manifest(&staging)?;
    fs::rename(&staging, &output).map_err(|source| SkillError::Io { path: output.clone(), source })?;
    Ok(ProposalEmitOutput {
        name: input.generalization.name,
        path: output,
        novelty: input.score.novelty,
        self_test_score: input.self_test.score,
    })
}

fn render_skill_md(input: &ProposalEmitInput) -> String {
    format!(
        "---\nname: {}\ndescription: {}\nversion: 0.1.0\ntags: [agentenv-proposed, trace-derived]\nagentenv-proposal: true\nagentenv-schema: \"0.1\"\n---\n\n# {}\n\n{}\n",
        input.generalization.name,
        input.generalization.description,
        input.generalization.name,
        input.generalization.skill_md_body
    )
}

fn render_skill_yaml(input: &ProposalEmitInput) -> Result<String, SkillError> {
    serde_yaml::to_string(&serde_json::json!({
        "name": input.generalization.name,
        "version": "0.1.0",
        "description": input.generalization.description,
        "entry": "SKILL.md",
        "files": ["SKILL.md", "proposal.yaml", "self-test.json", "traces/provenance.json"],
        "self_test": {"command": input.generalization.self_test.command},
        "agentenv_proposal": true,
        "agentenv_schema": "0.1"
    }))
    .map_err(|source| SkillError::Serde { path: input.output_root.join("skill.yaml"), source })
}

fn render_proposal_yaml(input: &ProposalEmitInput) -> Result<String, SkillError> {
    let value = ProposalYaml {
        schema_version: "0.1",
        status: "proposed",
        blueprint_id: &input.candidate.blueprint_id,
        occurrences: input.candidate.occurrences,
        novelty: input.score.novelty,
        utility: input.score.utility,
        self_test_score: input.self_test.score,
        generated_by: GeneratedBy {
            agentenv_version: &input.agentenv_version,
        },
    };
    serde_yaml::to_string(&value).map_err(|source| SkillError::Serde { path: input.output_root.join("proposal.yaml"), source })
}

fn write_file(path: &Path, content: String) -> Result<(), SkillError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SkillError::Io { path: parent.to_path_buf(), source })?;
    }
    fs::write(path, content).map_err(|source| SkillError::Io { path: path.to_path_buf(), source })
}

fn json_pretty<T: serde::Serialize>(value: &T, path: &Path) -> Result<String, SkillError> {
    serde_json::to_string_pretty(value).map_err(|source| SkillError::InvalidConfig {
        message: format!("failed to serialize `{}`: {source}", path.display()),
    })
}
```

Modify `mod.rs` exports:

```rust
mod emit;
pub use emit::emit_proposal;
pub use model::{ProposalEmitInput, ProposalEmitOutput};
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-core --test skill_propose proposal_writer_
```

Expected: PASS for proposal writer tests.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/skills/propose crates/agentenv-core/tests/skill_propose.rs
git commit -m "feat: emit proposed skill drafts"
```

## Task 7: Proposal Config Parsing

**Files:**
- Modify: `crates/agentenv-core/src/skills/config.rs`
- Modify: `crates/agentenv-core/src/skills/mod.rs`
- Modify: `crates/agentenv-core/tests/skills.rs`

- [ ] **Step 1: Write failing config tests**

Append to `crates/agentenv-core/tests/skills.rs`:

```rust
#[test]
fn skills_config_loads_proposal_provider_settings() {
    let yaml = r#"
skills:
  proposal:
    llm:
      provider: default
      endpoint: https://llm.example.test/v1
      model: proposal-generalizer
      credential: AGENTENV_SKILL_PROPOSER_TOKEN
    semantic:
      backend: local
    pr:
      default_repo: owner/skills
"#;

    let config = load_project_skills_config(yaml).unwrap();
    let proposal = config.proposal.unwrap();
    assert_eq!(proposal.llm.unwrap().provider, "default");
    assert_eq!(proposal.semantic.unwrap().backend, "local");
    assert_eq!(proposal.pr.unwrap().default_repo.unwrap(), "owner/skills");
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core --test skills skills_config_loads_proposal_provider_settings
```

Expected: FAIL because `SkillsConfig::proposal` does not exist.

- [ ] **Step 3: Add proposal config types**

Modify `SkillsConfig` in `config.rs`:

```rust
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SkillsConfig {
    #[serde(default)]
    pub registries: Vec<RegistryConfig>,
    #[serde(default)]
    pub registry_order: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<ProposalConfig>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProposalConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<ProposalLlmConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic: Option<ProposalSemanticConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<ProposalPrConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProposalLlmConfig {
    pub provider: String,
    pub endpoint: String,
    pub model: String,
    pub credential: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProposalSemanticConfig {
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProposalPrConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_repo: Option<String>,
}
```

Update `merge_project_over_user` so project proposal config overrides user proposal config when present and preserves the user value when absent:

```rust
let proposal = project.proposal.or(user.proposal);
```

Export the new config types from `skills/mod.rs`:

```rust
pub use config::{ProposalConfig, ProposalLlmConfig, ProposalPrConfig, ProposalSemanticConfig};
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-core --test skills skills_config_loads_proposal_provider_settings
```

Expected: PASS for proposal config parsing.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/skills/config.rs crates/agentenv-core/src/skills/mod.rs crates/agentenv-core/tests/skills.rs
git commit -m "feat: parse skill proposal config"
```

## Task 8: Proposal Service Orchestration

**Files:**
- Create: `crates/agentenv-core/src/skills/propose/service.rs`
- Modify: `crates/agentenv-core/src/skills/propose/mod.rs`
- Modify: `crates/agentenv-core/src/skills/propose/model.rs`
- Modify: `crates/agentenv-core/tests/skill_propose.rs`

- [ ] **Step 1: Write failing service test with fake generalizer**

Append to `crates/agentenv-core/tests/skill_propose.rs`:

```rust
use async_trait::async_trait;
use agentenv_core::skills::propose::{
    ProposedSkillService, ProposeRunInput, SkillGeneralizationRequest, SkillGeneralizer,
};

#[tokio::test]
async fn proposal_service_runs_full_pipeline_with_fake_generalizer() {
    let temp = tempfile::tempdir().unwrap();
    let traces = vec![
        trace("trace-1", vec![call("fs_read", "/repo/a.rs")]),
        trace("trace-2", vec![call("fs_read", "/repo/b.rs")]),
        trace("trace-3", vec![call("fs_read", "/repo/c.rs")]),
    ];
    let service = ProposedSkillService::new(Box::new(FakeGeneralizer));

    let output = service
        .run(ProposeRunInput {
            traces,
            output_root: temp.path().join("proposed"),
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
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv-core --test skill_propose proposal_service_
```

Expected: FAIL because `ProposedSkillService` and orchestration models are missing.

- [ ] **Step 3: Implement service orchestration**

Extend `model.rs`:

```rust
#[derive(Debug, Clone)]
pub struct ProposeRunInput {
    pub traces: Vec<agentenv_events::TraceRun>,
    pub output_root: std::path::PathBuf,
    pub blueprint_id: String,
    pub min_occurrences: usize,
    pub min_novelty: f32,
    pub min_self_test_score: f32,
    pub existing_skills: Vec<ExistingSkillSummary>,
    pub agentenv_version: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProposeRunOutput {
    pub proposals: Vec<ProposalEmitOutput>,
    pub warnings: Vec<String>,
}
```

Create `service.rs`:

```rust
use super::{
    emit_proposal, evaluate_self_test, extract_candidates, score_proposal, validate_generalization,
    CandidateExtractionOptions, ProposalEmitInput, ProposalScoreInput, ProposalSelfTestInput,
    ProposeRunInput, ProposeRunOutput, SkillGeneralizationRequest, SkillGeneralizer,
};
use crate::skills::SkillError;

pub struct ProposedSkillService {
    generalizer: Box<dyn SkillGeneralizer>,
}

impl ProposedSkillService {
    pub fn new(generalizer: Box<dyn SkillGeneralizer>) -> Self {
        Self { generalizer }
    }

    pub async fn run(&self, input: ProposeRunInput) -> Result<ProposeRunOutput, SkillError> {
        let candidates = extract_candidates(
            &input.traces,
            CandidateExtractionOptions {
                blueprint_id: input.blueprint_id.clone(),
                min_occurrences: input.min_occurrences,
            },
        )?;
        let mut proposals = Vec::new();
        let mut warnings = Vec::new();
        for candidate in candidates {
            let request = SkillGeneralizationRequest {
                schema_version: "0.1".to_owned(),
                candidate_json: serde_json::to_value(&candidate).map_err(|source| SkillError::InvalidConfig {
                    message: format!("failed to encode proposal candidate: {source}"),
                })?,
                existing_skill_summaries: input.existing_skills.iter().map(|skill| skill.name.clone()).collect(),
            };
            let generalization = self.generalizer.generalize(request).await?;
            let allowed_tools = candidate.sequence.iter().map(|call| call.tool.clone()).collect::<Vec<_>>();
            validate_generalization(&generalization, &allowed_tools)?;
            let score = score_proposal(ProposalScoreInput {
                name: generalization.name.clone(),
                description: generalization.description.clone(),
                procedure_text: generalization.skill_md_body.clone(),
                fingerprint: candidate.fingerprint.clone(),
                occurrences: candidate.occurrences,
                existing_skills: input.existing_skills.clone(),
                backend: super::NoveltyBackend::Local,
            })?;
            if score.novelty < input.min_novelty {
                warnings.push(format!("skipped `{}` because novelty {} is below {}", generalization.name, score.novelty, input.min_novelty));
                continue;
            }
            let self_test = evaluate_self_test(ProposalSelfTestInput {
                source_tools: allowed_tools,
                procedure_steps: generalization.procedure_steps.clone(),
                template_variables: generalization.template_variables.clone(),
                min_score: input.min_self_test_score,
            })?;
            if !self_test.passed {
                warnings.push(format!("skipped `{}` because self-test score {} is below {}", generalization.name, self_test.score, input.min_self_test_score));
                continue;
            }
            proposals.push(emit_proposal(ProposalEmitInput {
                output_root: input.output_root.clone(),
                candidate,
                generalization,
                score,
                self_test,
                agentenv_version: input.agentenv_version.clone(),
                created_at: input.created_at.clone(),
            })?);
        }
        Ok(ProposeRunOutput { proposals, warnings })
    }
}
```

Modify `mod.rs` exports:

```rust
mod service;
pub use model::{ProposeRunInput, ProposeRunOutput};
pub use service::ProposedSkillService;
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv-core --test skill_propose proposal_service_
```

Expected: PASS for service orchestration.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-core/src/skills/propose crates/agentenv-core/tests/skill_propose.rs
git commit -m "feat: orchestrate skill proposal pipeline"
```

## Task 9: CLI Subcommand And Fake Provider Path

**Files:**
- Create: `crates/agentenv/src/skills_propose_cli.rs`
- Modify: `crates/agentenv/src/main.rs`
- Modify: `crates/agentenv/src/skills_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing CLI tests**

Append to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn skills_help_lists_propose_subcommand() {
    let output = Command::new(agentenv_bin())
        .arg("skills")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("propose"), "stdout was: {stdout}");
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
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_help_lists_propose_subcommand skills_propose_requires_from_traces_and_blueprint
```

Expected: FAIL because the `propose` subcommand does not exist.

- [ ] **Step 3: Add CLI args and dispatch stub**

Create `crates/agentenv/src/skills_propose_cli.rs`:

```rust
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;

#[derive(Debug, Args, Clone)]
pub struct SkillsProposeArgs {
    #[arg(long)]
    pub from_traces: bool,
    #[arg(long, value_name = "FILE")]
    pub blueprint: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    pub events_db: Option<PathBuf>,
    #[arg(long)]
    pub env: Option<String>,
    #[arg(long, default_value_t = 3)]
    pub min_occurrences: usize,
    #[arg(long, default_value_t = 0.6)]
    pub min_novelty: f32,
    #[arg(long, default_value_t = 0.8)]
    pub min_self_test_score: f32,
    #[arg(long)]
    pub llm_provider: Option<String>,
    #[arg(long, default_value = "local")]
    pub semantic_backend: String,
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub open_pr: bool,
    #[arg(long)]
    pub repo: Option<String>,
}

pub async fn run_skills_propose(args: SkillsProposeArgs) -> Result<()> {
    validate_args(&args)?;
    println!("no proposals emitted");
    Ok(())
}

pub fn validate_args(args: &SkillsProposeArgs) -> Result<()> {
    if !args.from_traces {
        bail!("`agentenv skills propose` requires --from-traces");
    }
    if args.blueprint.is_none() {
        bail!("`agentenv skills propose` requires --blueprint <path>");
    }
    if args.min_occurrences < 2 {
        bail!("--min-occurrences must be at least 2");
    }
    if !(0.0..=1.0).contains(&args.min_novelty) {
        bail!("--min-novelty must be between 0.0 and 1.0");
    }
    if !(0.0..=1.0).contains(&args.min_self_test_score) {
        bail!("--min-self-test-score must be between 0.0 and 1.0");
    }
    if args.open_pr && args.repo.is_none() {
        bail!("--open-pr requires --repo owner/repo");
    }
    Ok(())
}
```

Modify `crates/agentenv/src/main.rs`:

```rust
mod skills_propose_cli;
```

Modify `crates/agentenv/src/skills_cli.rs`:

```rust
use crate::skills_propose_cli::{run_skills_propose, SkillsProposeArgs};

#[derive(Debug, Subcommand)]
pub enum SkillsCommand {
    Propose(SkillsProposeArgs),
    Search(SkillsSearchArgs),
    Add(SkillsAddArgs),
    Install(SkillsInstallArgs),
    List(SkillsListArgs),
    Info(SkillsInfoArgs),
    Remove(SkillsRemoveArgs),
    Publish(SkillsPublishArgs),
    Verify(SkillsVerifyArgs),
    Prune(SkillsPruneArgs),
}
```

Add dispatch branch:

```rust
SkillsCommand::Propose(args) => run_skills_propose(args).await,
```

Update `registry_override_for_command` to return `None` for `SkillsCommand::Propose(_)`.

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_help_lists_propose_subcommand skills_propose_requires_from_traces_and_blueprint
```

Expected: PASS for CLI command shape tests.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/src/main.rs crates/agentenv/src/skills_cli.rs crates/agentenv/src/skills_propose_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: add skills propose command"
```

## Task 10: CLI Full Pipeline With Fake LLM

**Files:**
- Modify: `crates/agentenv/src/skills_propose_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing end-to-end CLI proposal test**

Append to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn skills_propose_from_traces_emits_local_proposal_with_fake_llm() {
    let temp_dir = make_temp_dir("skills-propose-e2e");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(&blueprint, "version: 0.1.0\nsandbox: { driver: openshell }\nagent: { driver: codex }\ncontext: { driver: filesystem, mount: . }\n").unwrap();
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
        .arg("--llm-provider")
        .arg("fixture")
        .arg("--json")
        .env("HOME", &temp_dir)
        .env("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON", fixture_generalization_json())
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    assert!(out.join("fs-edit-skill/SKILL.md").is_file());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["proposals"][0]["name"], "fs-edit-skill");
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
    serde_json::json!({
        "name": "fs-edit-skill",
        "description": "Edit a repeated filesystem target.",
        "template_variables": [{"name": "target_path", "description": "Target path", "example": "src/lib.rs"}],
        "procedure_steps": [{"tool": "fs_read", "instruction": "Read {{target_path}}."}],
        "self_test": {"command": "test -f SKILL.md"},
        "skill_md_body": "Read {{target_path}}."
    })
    .to_string()
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_propose_from_traces_emits_local_proposal_with_fake_llm
```

Expected: FAIL because `run_skills_propose` does not read traces or run the core service.

- [ ] **Step 3: Implement fake and HTTP generalizers plus CLI orchestration**

In `skills_propose_cli.rs`, add:

```rust
use agentenv_core::skills::{
    propose::{ProposeRunInput, ProposedSkillService, SkillGeneralization, SkillGeneralizationRequest, SkillGeneralizer},
    ProposalConfig,
};
use agentenv_events::{SqliteEventStore, TraceQuery};
use async_trait::async_trait;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct SkillsProposeJson {
    proposals: Vec<agentenv_core::skills::propose::ProposalEmitOutput>,
    warnings: Vec<String>,
}

struct FixtureGeneralizer {
    value: SkillGeneralization,
}

#[async_trait]
impl SkillGeneralizer for FixtureGeneralizer {
    async fn generalize(
        &self,
        _request: SkillGeneralizationRequest,
    ) -> Result<SkillGeneralization, agentenv_core::skills::SkillError> {
        Ok(self.value.clone())
    }
}
```

Update `run_skills_propose`:

```rust
pub async fn run_skills_propose(args: SkillsProposeArgs) -> Result<()> {
    validate_args(&args)?;
    let blueprint = args.blueprint.as_ref().unwrap();
    let blueprint_id = blueprint_id_for_path(blueprint)?;
    let events_db = args.events_db.clone().unwrap_or_else(default_events_db_path);
    let store = SqliteEventStore::open(&events_db)
        .with_context(|| format!("open activity database `{}`", events_db.display()))?;
    let traces = store.query_trace_runs(TraceQuery {
        blueprint_id: blueprint_id.clone(),
        env: args.env.clone(),
        limit: 10_000,
    })?;
    let output_root = args.out.clone().unwrap_or_else(default_proposed_dir);
    let generalizer = generalizer_for_args(&args)?;
    let service = ProposedSkillService::new(generalizer);
    let output = service
        .run(ProposeRunInput {
            traces,
            output_root,
            blueprint_id,
            min_occurrences: args.min_occurrences,
            min_novelty: args.min_novelty,
            min_self_test_score: args.min_self_test_score,
            existing_skills: Vec::new(),
            agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            created_at: now_event_ts(),
        })
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&SkillsProposeJson {
            proposals: output.proposals,
            warnings: output.warnings,
        })?);
    } else {
        for proposal in output.proposals {
            println!("{} {} {}", proposal.name, proposal.novelty, proposal.path.display());
        }
        for warning in output.warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}
```

Add helpers:

```rust
fn generalizer_for_args(args: &SkillsProposeArgs) -> Result<Box<dyn SkillGeneralizer>> {
    if args.llm_provider.as_deref() == Some("fixture") {
        let raw = std::env::var("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON")
            .context("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON is required for fixture provider")?;
        let value = serde_json::from_str(&raw).context("parse fixture generalization JSON")?;
        return Ok(Box::new(FixtureGeneralizer { value }));
    }
    bail!("skill proposal LLM provider is not configured")
}

fn default_events_db_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agentenv/events.db")
}

fn default_proposed_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agentenv/skills/proposed")
}

fn blueprint_id_for_path(path: &std::path::Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read blueprint `{}`", path.display()))?;
    let digest = sha2::Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}
```

- [ ] **Step 4: Run test and verify pass**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_propose_from_traces_emits_local_proposal_with_fake_llm
```

Expected: PASS for fake-provider end-to-end proposal emission.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/src/skills_propose_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: run skills propose from traces"
```

## Task 11: OpenAI-Compatible Provider And Credential Resolution

**Files:**
- Modify: `crates/agentenv/src/skills_propose_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing missing-provider test**

Append to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn skills_propose_without_configured_llm_fails_clearly() {
    let temp_dir = make_temp_dir("skills-propose-missing-llm");
    let blueprint = temp_dir.join("myapp.yaml");
    fs::write(&blueprint, "version: 0.1.0\n").unwrap();
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
        .env("HOME", &temp_dir)
        .current_dir(&temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("skill proposal LLM provider is not configured"), "stderr was: {stderr}");
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_propose_without_configured_llm_fails_clearly
```

Expected: FAIL until error text and config path are implemented.

- [ ] **Step 3: Add HTTP provider adapter**

In `skills_propose_cli.rs`, add an OpenAI-compatible adapter:

```rust
struct HttpGeneralizer {
    endpoint: String,
    model: String,
    bearer: String,
    client: reqwest::Client,
}

#[async_trait]
impl SkillGeneralizer for HttpGeneralizer {
    async fn generalize(
        &self,
        request: SkillGeneralizationRequest,
    ) -> Result<SkillGeneralization, agentenv_core::skills::SkillError> {
        let response = self.client
            .post(&self.endpoint)
            .bearer_auth(&self.bearer)
            .json(&serde_json::json!({
                "model": self.model,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "Return only JSON for an agentenv skill proposal."},
                    {"role": "user", "content": serde_json::to_string(&request).unwrap_or_default()}
                ]
            }))
            .send()
            .await
            .map_err(|source| agentenv_core::skills::SkillError::InvalidConfig {
                message: format!("skill proposal LLM request failed: {source}"),
            })?;
        let value: serde_json::Value = response.json().await.map_err(|source| agentenv_core::skills::SkillError::InvalidConfig {
            message: format!("skill proposal LLM response was not JSON: {source}"),
        })?;
        let content = value
            .pointer("/choices/0/message/content")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| agentenv_core::skills::SkillError::InvalidConfig {
                message: "skill proposal LLM response missing choices[0].message.content".to_owned(),
            })?;
        serde_json::from_str(content).map_err(|source| agentenv_core::skills::SkillError::InvalidConfig {
            message: format!("skill proposal LLM content failed schema validation: {source}"),
        })
    }
}
```

Update `generalizer_for_args` to:

1. Use fixture when `--llm-provider fixture`.
2. Load proposal config through existing `load_effective_config`.
3. Resolve `ProposalLlmConfig.credential` through `CredentialStore`.
4. Construct `HttpGeneralizer`.
5. Return the exact missing-config error when no provider exists.

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_propose_without_configured_llm_fails_clearly
cargo test -p agentenv --test cli_behavior skills_propose_from_traces_emits_local_proposal_with_fake_llm
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/src/skills_propose_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: configure skill proposal llm provider"
```

## Task 12: Optional PR Publishing

**Files:**
- Modify: `crates/agentenv/src/skills_propose_cli.rs`
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Write failing PR validation and command construction tests**

Append to `crates/agentenv/tests/cli_behavior.rs`:

```rust
#[test]
fn skills_propose_open_pr_requires_valid_repo() {
    let temp_dir = make_temp_dir("skills-propose-bad-repo");
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--repo must be owner/repo"), "stderr was: {stderr}");
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_propose_open_pr_requires_valid_repo
```

Expected: FAIL until repo validation is implemented.

- [ ] **Step 3: Implement PR validation and publisher interface**

In `skills_propose_cli.rs`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
struct PullRequestPlan {
    repo: String,
    branch: String,
    title: String,
    body: String,
}

fn validate_repo(repo: &str) -> Result<()> {
    let Some((owner, name)) = repo.split_once('/') else {
        bail!("--repo must be owner/repo");
    };
    let valid = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    if !valid(owner) || !valid(name) {
        bail!("--repo must be owner/repo with conservative characters");
    }
    Ok(())
}

fn pr_plan_for(repo: String, proposal: &agentenv_core::skills::propose::ProposalEmitOutput) -> PullRequestPlan {
    let short_name = proposal.name.replace('_', "-");
    PullRequestPlan {
        repo,
        branch: format!("agentenv/proposed-skill/{short_name}"),
        title: format!("feat: propose trace-derived skill {}", proposal.name),
        body: format!(
            "Trace-derived skill proposal.\n\nNovelty: {}\nSelf-test score: {}\nPath: `{}`\n",
            proposal.novelty,
            proposal.self_test_score,
            proposal.path.display()
        ),
    }
}
```

Update `validate_args` to call `validate_repo` when `repo` is present.

Add a publisher function that runs non-interactive commands:

```rust
fn publish_pr(plan: &PullRequestPlan, proposal_path: &std::path::Path) -> Result<String> {
    run_command("git", &["checkout", "-B", &plan.branch])?;
    run_command("git", &["add", proposal_path.to_str().context("proposal path is not UTF-8")?])?;
    run_command("git", &["commit", "-m", &plan.title])?;
    run_command("git", &["push", "-u", "origin", &plan.branch])?;
    let output = std::process::Command::new("gh")
        .args(["pr", "create", "--repo", &plan.repo, "--draft", "--title", &plan.title, "--body", &plan.body])
        .output()
        .context("run gh pr create")?;
    if !output.status.success() {
        bail!("gh pr create failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
```

Use the publisher only after proposal emission succeeds and only when
`--open-pr` is set.

- [ ] **Step 4: Run PR tests and existing propose tests**

Run:

```bash
cargo test -p agentenv --test cli_behavior skills_propose_open_pr_requires_valid_repo
cargo test -p agentenv --test cli_behavior skills_propose_from_traces_emits_local_proposal_with_fake_llm
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/src/skills_propose_cli.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat: support skill proposal pull requests"
```

## Task 13: End-To-End Verification And Polish

**Files:**
- Review/modify: `crates/agentenv-events/src/trace.rs`
- Review/modify: `crates/agentenv-events/src/store.rs`
- Review/modify: `crates/agentenv-core/src/skills/propose/*.rs`
- Review/modify: `crates/agentenv-core/src/skills/config.rs`
- Review/modify: `crates/agentenv/src/skills_propose_cli.rs`
- Review/modify: `crates/agentenv/src/skills_cli.rs`
- Review/modify: `crates/agentenv/tests/cli_behavior.rs`
- Review: `docs/superpowers/specs/2026-05-11-m7-6-trace-skill-proposer-design.md`

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits 0.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace -- -D warnings
```

Expected: command exits 0. Fix each warning in the smallest owning module, then rerun this exact command.

- [ ] **Step 3: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: command exits 0 with all non-ignored tests passing.

- [ ] **Step 4: Confirm requirement coverage**

Check the implementation against this list and update code when any item is missing:

```text
- CLI: agentenv skills propose --from-traces --blueprint <path>
- Trace filtering by blueprint_id
- Repeated sequence extraction with min occurrences
- Redaction before prompt/proposal emission
- LLM generalization with strict JSON validation
- Novelty ladder 0.0, 0.3, 0.6, 0.9
- Self-test gate default score >= 0.8
- Emission under ~/.agentenv/skills/proposed/<name>/
- Optional --open-pr --repo owner/repo path
- No driver protocol/schema version changes
```

- [ ] **Step 5: Commit final fixes**

```bash
git status --short
git add crates/agentenv-events crates/agentenv-core crates/agentenv
git commit -m "test: verify trace skill proposer"
```

Skip this commit if `git status --short` is empty after verification.
