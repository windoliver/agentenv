use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ActivityResult;

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
