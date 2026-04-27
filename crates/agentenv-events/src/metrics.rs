use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::activity::{ActivityKind, ActivityResult};
use crate::store::{SqliteEventStore, StoreResult};

pub const LATENCY_BUCKET_LABELS: [&str; 12] = [
    "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "+Inf",
];

const LATENCY_BUCKET_MILLIS: [Option<u64>; 12] = [
    Some(5),
    Some(10),
    Some(25),
    Some(50),
    Some(100),
    Some(250),
    Some(500),
    Some(1_000),
    Some(2_500),
    Some(5_000),
    Some(10_000),
    None,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvMetricRow {
    pub status: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCountMetric {
    pub kind: String,
    pub env: Option<String>,
    pub result: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBlockMetric {
    pub kind: String,
    pub driver: Option<String>,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolMetric {
    pub tool: String,
    pub env: Option<String>,
    pub result: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyBucketMetric {
    pub op: String,
    pub driver: Option<String>,
    pub le: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkCounterMetric {
    pub sink: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub envs_by_status: Vec<EnvMetricRow>,
    pub events_total: Vec<EventCountMetric>,
    pub policy_blocks_total: Vec<PolicyBlockMetric>,
    pub mcp_tool_calls_total: Vec<McpToolMetric>,
    pub sandbox_latency: Vec<LatencyBucketMetric>,
    pub approvals_pending_total: u64,
    pub event_drops_total: Vec<SinkCounterMetric>,
    pub event_sink_errors_total: Vec<SinkCounterMetric>,
}

impl MetricsSnapshot {
    pub fn from_store(
        store: &SqliteEventStore,
        envs_by_status: &[EnvMetricRow],
    ) -> StoreResult<Self> {
        let events_total = store
            .counts_by_kind_result()?
            .into_iter()
            .map(|row| EventCountMetric {
                kind: activity_kind_label(row.kind),
                env: row.env,
                result: activity_result_label(row.result),
                count: row.count,
            })
            .collect();
        let policy_blocks_total = store
            .policy_blocks_by_kind_driver()?
            .into_iter()
            .map(|row| PolicyBlockMetric {
                kind: row.kind,
                driver: row.driver,
                count: row.count,
            })
            .collect();
        let mcp_tool_calls_total = store
            .mcp_tool_calls_by_tool_env_result()?
            .into_iter()
            .map(|row| McpToolMetric {
                tool: row.tool,
                env: row.env,
                result: activity_result_label(row.result),
                count: row.count,
            })
            .collect();
        let sandbox_latency = latency_buckets(store.sandbox_latency_rows()?);
        let approvals_pending_total = store.approvals_pending_count()?;

        Ok(Self {
            envs_by_status: envs_by_status.to_vec(),
            events_total,
            policy_blocks_total,
            mcp_tool_calls_total,
            sandbox_latency,
            approvals_pending_total,
            event_drops_total: Vec::new(),
            event_sink_errors_total: Vec::new(),
        })
    }
}

pub fn render_prometheus(snapshot: &MetricsSnapshot) -> String {
    let mut output = String::new();

    render_help_type(
        &mut output,
        "agentenv_envs_total",
        "Number of known agentenv environments by status.",
        "gauge",
    );
    for row in &snapshot.envs_by_status {
        render_sample(
            &mut output,
            "agentenv_envs_total",
            &[("status", Some(row.status.as_str()))],
            row.count,
        );
    }

    render_help_type(
        &mut output,
        "agentenv_events_total",
        "Total activity events by kind, environment, and result.",
        "counter",
    );
    for row in &snapshot.events_total {
        render_sample(
            &mut output,
            "agentenv_events_total",
            &[
                ("kind", Some(row.kind.as_str())),
                ("env", row.env.as_deref()),
                ("result", Some(row.result.as_str())),
            ],
            row.count,
        );
    }

    render_help_type(
        &mut output,
        "agentenv_sandbox_latency_seconds_bucket",
        "Cumulative sandbox operation latency buckets in seconds.",
        "counter",
    );
    for row in &snapshot.sandbox_latency {
        render_sample(
            &mut output,
            "agentenv_sandbox_latency_seconds_bucket",
            &[
                ("op", Some(row.op.as_str())),
                ("driver", row.driver.as_deref()),
                ("le", Some(row.le.as_str())),
            ],
            row.count,
        );
    }

    render_help_type(
        &mut output,
        "agentenv_mcp_tool_calls_total",
        "Total MCP tool calls by tool, environment, and result.",
        "counter",
    );
    for row in &snapshot.mcp_tool_calls_total {
        render_sample(
            &mut output,
            "agentenv_mcp_tool_calls_total",
            &[
                ("tool", Some(row.tool.as_str())),
                ("env", row.env.as_deref()),
                ("result", Some(row.result.as_str())),
            ],
            row.count,
        );
    }

    render_help_type(
        &mut output,
        "agentenv_policy_blocks_total",
        "Total policy blocks by kind and driver.",
        "counter",
    );
    for row in &snapshot.policy_blocks_total {
        render_sample(
            &mut output,
            "agentenv_policy_blocks_total",
            &[
                ("kind", Some(row.kind.as_str())),
                ("driver", row.driver.as_deref()),
            ],
            row.count,
        );
    }

    render_help_type(
        &mut output,
        "agentenv_approvals_pending_total",
        "Derived number of approvals pending a terminal decision.",
        "gauge",
    );
    render_scalar(
        &mut output,
        "agentenv_approvals_pending_total",
        snapshot.approvals_pending_total,
    );

    render_help_type(
        &mut output,
        "agentenv_event_drops_total",
        "Total events dropped by sink.",
        "counter",
    );
    for row in &snapshot.event_drops_total {
        render_sample(
            &mut output,
            "agentenv_event_drops_total",
            &[("sink", Some(row.sink.as_str()))],
            row.count,
        );
    }

    render_help_type(
        &mut output,
        "agentenv_event_sink_errors_total",
        "Total event sink write errors by sink.",
        "counter",
    );
    for row in &snapshot.event_sink_errors_total {
        render_sample(
            &mut output,
            "agentenv_event_sink_errors_total",
            &[("sink", Some(row.sink.as_str()))],
            row.count,
        );
    }

    output
}

fn latency_buckets(rows: Vec<crate::store::SandboxLatencyRow>) -> Vec<LatencyBucketMetric> {
    let mut grouped: BTreeMap<(String, Option<String>), Vec<u64>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.op, row.driver))
            .or_default()
            .push(row.latency_ms);
    }

    let mut buckets = Vec::new();
    for ((op, driver), latencies) in grouped {
        for (label, limit_ms) in LATENCY_BUCKET_LABELS.iter().zip(LATENCY_BUCKET_MILLIS) {
            let count = latencies
                .iter()
                .filter(|latency_ms| match limit_ms {
                    Some(limit_ms) => **latency_ms <= limit_ms,
                    None => true,
                })
                .count() as u64;
            buckets.push(LatencyBucketMetric {
                op: op.clone(),
                driver: driver.clone(),
                le: (*label).to_owned(),
                count,
            });
        }
    }
    buckets
}

fn render_help_type(output: &mut String, name: &str, help: &str, metric_type: &str) {
    output.push_str("# HELP ");
    output.push_str(name);
    output.push(' ');
    output.push_str(help);
    output.push('\n');
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push(' ');
    output.push_str(metric_type);
    output.push('\n');
}

fn render_scalar(output: &mut String, name: &str, value: u64) {
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn render_sample(output: &mut String, name: &str, labels: &[(&str, Option<&str>)], value: u64) {
    output.push_str(name);
    output.push('{');
    for (index, (key, value)) in labels.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(key);
        output.push_str("=\"");
        output.push_str(&escape_label_value(value.unwrap_or("")));
        output.push('"');
    }
    output.push_str("} ");
    output.push_str(&value.to_string());
    output.push('\n');
}

fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn activity_kind_label(kind: ActivityKind) -> String {
    enum_label(kind)
}

fn activity_result_label(result: ActivityResult) -> String {
    enum_label(result)
}

fn enum_label<T>(value: T) -> String
where
    T: Serialize,
{
    match serde_json::to_value(value) {
        Ok(Value::String(label)) => label,
        _ => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};
    use crate::metrics::{
        render_prometheus, EnvMetricRow, MetricsSnapshot, SinkCounterMetric, LATENCY_BUCKET_LABELS,
    };
    use crate::store::SqliteEventStore;

    fn event(ts: &str, kind: ActivityKind, result: ActivityResult) -> ActivityEvent {
        ActivityEvent::new(ts, kind, result, format!("trace-{ts}"))
    }

    #[test]
    fn prometheus_render_includes_required_series() {
        let snapshot = MetricsSnapshot {
            envs_by_status: vec![EnvMetricRow {
                status: "running".to_owned(),
                count: 1,
            }],
            events_total: Vec::new(),
            policy_blocks_total: Vec::new(),
            mcp_tool_calls_total: Vec::new(),
            sandbox_latency: Vec::new(),
            approvals_pending_total: 1,
            event_drops_total: vec![SinkCounterMetric {
                sink: "sqlite".to_owned(),
                count: 0,
            }],
            event_sink_errors_total: vec![SinkCounterMetric {
                sink: "webhook".to_owned(),
                count: 0,
            }],
        };

        let rendered = render_prometheus(&snapshot);

        for series in [
            "agentenv_envs_total",
            "agentenv_events_total",
            "agentenv_sandbox_latency_seconds_bucket",
            "agentenv_mcp_tool_calls_total",
            "agentenv_policy_blocks_total",
            "agentenv_approvals_pending_total",
            "agentenv_event_drops_total",
            "agentenv_event_sink_errors_total",
        ] {
            assert!(rendered.contains(&format!("# HELP {series}")));
            assert!(rendered.contains(&format!("# TYPE {series}")));
        }
        assert!(rendered.contains("agentenv_envs_total{status=\"running\"} 1"));
        assert!(rendered.contains("agentenv_approvals_pending_total 1"));
    }

    #[test]
    fn prometheus_render_escapes_label_values() {
        let snapshot = MetricsSnapshot {
            envs_by_status: vec![EnvMetricRow {
                status: "run\\ning\"\n".to_owned(),
                count: 2,
            }],
            events_total: Vec::new(),
            policy_blocks_total: Vec::new(),
            mcp_tool_calls_total: Vec::new(),
            sandbox_latency: Vec::new(),
            approvals_pending_total: 0,
            event_drops_total: Vec::new(),
            event_sink_errors_total: Vec::new(),
        };

        let rendered = render_prometheus(&snapshot);

        assert!(rendered.contains("status=\"run\\\\ning\\\"\\n\""));
    }

    #[test]
    fn snapshot_aggregates_mcp_tool_calls_by_subject_tool_env_and_result() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::McpToolCall,
                    ActivityResult::Ok,
                )
                .with_env("demo")
                .with_subject_value("tool", serde_json::json!("read_file")),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::McpToolCall,
                    ActivityResult::Ok,
                )
                .with_env("demo")
                .with_subject_value("tool", serde_json::json!("read_file")),
                event(
                    "2026-04-26T12:00:02Z",
                    ActivityKind::McpToolCall,
                    ActivityResult::Error,
                )
                .with_env("other")
                .with_subject_value("tool", serde_json::json!("read_file")),
            ])
            .unwrap();

        let snapshot = MetricsSnapshot::from_store(&store, &[]).unwrap();

        assert!(snapshot.mcp_tool_calls_total.iter().any(|row| {
            row.tool == "read_file"
                && row.env.as_deref() == Some("demo")
                && row.result == "ok"
                && row.count == 2
        }));
        assert!(snapshot.mcp_tool_calls_total.iter().any(|row| {
            row.tool == "read_file"
                && row.env.as_deref() == Some("other")
                && row.result == "error"
                && row.count == 1
        }));
    }

    #[test]
    fn approvals_pending_derived_count_never_underflows() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::ApprovalDecided,
                    ActivityResult::Ok,
                ),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::ApprovalDecided,
                    ActivityResult::Denied,
                ),
            ])
            .unwrap();

        let snapshot = MetricsSnapshot::from_store(&store, &[]).unwrap();

        assert_eq!(snapshot.approvals_pending_total, 0);
    }

    #[test]
    fn latency_buckets_are_cumulative_and_include_positive_infinity() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();
        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::SandboxCreate,
                    ActivityResult::Ok,
                )
                .with_actor_value("driver", serde_json::json!("openshell"))
                .with_latency_ms(5),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::SandboxCreate,
                    ActivityResult::Ok,
                )
                .with_actor_value("driver", serde_json::json!("openshell"))
                .with_latency_ms(250),
                event(
                    "2026-04-26T12:00:02Z",
                    ActivityKind::SandboxCreate,
                    ActivityResult::Ok,
                )
                .with_actor_value("driver", serde_json::json!("openshell"))
                .with_latency_ms(11_000),
            ])
            .unwrap();

        let snapshot = MetricsSnapshot::from_store(&store, &[]).unwrap();
        let counts = LATENCY_BUCKET_LABELS
            .iter()
            .map(|le| {
                snapshot
                    .sandbox_latency
                    .iter()
                    .find(|row| {
                        row.op == "create"
                            && row.driver.as_deref() == Some("openshell")
                            && row.le == *le
                    })
                    .map(|row| row.count)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(counts[0], 1);
        assert_eq!(counts[5], 2);
        assert_eq!(counts[10], 2);
        assert_eq!(counts[11], 3);
    }
}
