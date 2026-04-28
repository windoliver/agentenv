use std::{collections::HashSet, fs};

use agentenv_approvals::{ApprovalStatus, LocalApprovalStore};
use agentenv_core::env::EnvStateFile;
use agentenv_core::runtime::{self, RuntimeOptions};
use agentenv_events::{LocalEventStore, StoredEvent, StoredEventKind};
use agentenv_proto::{ApprovalDecision, ApprovalScope};
use agentenv_tui::{
    backend::OpsBackend,
    model::{ApprovalRow, DetailState, EnvRow, EventRow, OpsSnapshot},
};
use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::builtin_factory::BuiltInDriverFactory;

pub struct LocalOpsBackend {
    options: RuntimeOptions,
    events: LocalEventStore,
    approvals: LocalApprovalStore,
    emitted_import_diagnostics: HashSet<String>,
}

impl LocalOpsBackend {
    pub fn new(options: RuntimeOptions) -> Result<Self> {
        let events = LocalEventStore::open(&options.root).context("open event store")?;
        let approvals = LocalApprovalStore::open(&options.root).context("open approval store")?;
        Ok(Self {
            options,
            events,
            approvals,
            emitted_import_diagnostics: HashSet::new(),
        })
    }

    fn import_jsonl_for_envs(&mut self, envs: &[runtime::EnvListRow]) -> Vec<String> {
        let mut diagnostics = Vec::new();
        for env in envs {
            if let Ok(name) = agentenv_core::env::validate_env_name(&env.name) {
                let paths = agentenv_core::env::EnvPaths::new(self.options.root.clone(), name);
                match self
                    .events
                    .import_env_jsonl(&env.name, &paths.events_path())
                {
                    Ok(report) if report.skipped > 0 => diagnostics.push(format!(
                        "{}: legacy event import skipped {} malformed line(s)",
                        env.name, report.skipped
                    )),
                    Ok(_) => {}
                    Err(error) => diagnostics
                        .push(format!("{}: legacy event import failed: {error}", env.name)),
                }
            }
        }
        self.append_import_diagnostics(&diagnostics);
        diagnostics
    }

    fn append_import_diagnostics(&mut self, diagnostics: &[String]) {
        for diagnostic in diagnostics {
            let Some((env, _detail)) = diagnostic.split_once(':') else {
                continue;
            };
            let key = format!("{env}\0{diagnostic}");
            if !self.emitted_import_diagnostics.insert(key) {
                continue;
            }
            let event = legacy_jsonl_import_event(env, diagnostic);
            let _ = self.events.append(&event);
        }
    }
}

#[async_trait(?Send)]
impl OpsBackend for LocalOpsBackend {
    async fn load_snapshot(&mut self, selected_env: Option<&str>) -> Result<OpsSnapshot> {
        let envs = runtime::list_envs(&self.options).context("list envs")?;
        let import_diagnostics = self.import_jsonl_for_envs(&envs);
        let selected = selected_env
            .filter(|name| envs.iter().any(|env| env.name == *name))
            .or_else(|| envs.first().map(|env| env.name.as_str()));
        let detail = match selected {
            Some(name) => match runtime::describe_env(&self.options, name) {
                Ok(description) => Some(DetailState {
                    env: name.to_owned(),
                    lines: detail_lines(
                        &self.options,
                        name,
                        &description.state,
                        &import_diagnostics,
                    ),
                }),
                Err(error) => Some(DetailState {
                    env: name.to_owned(),
                    lines: vec![format!("error: {error}")],
                }),
            },
            None => None,
        };

        let events = self
            .events
            .list_recent(selected, 200)
            .context("list recent events")?
            .into_iter()
            .map(|event| EventRow {
                ts: event.ts,
                env: event.env,
                kind: event.kind.as_str().to_owned(),
                subject: event.subject,
                reason: event.reason,
            })
            .collect();
        let approvals = self
            .approvals
            .list_pending(None)
            .context("list pending approvals")?
            .into_iter()
            .map(|approval| ApprovalRow {
                request_id: approval.request_id,
                env: approval.env,
                agent: approval.agent,
                subject: approval.subject,
                reason: approval.reason,
            })
            .collect();

        Ok(OpsSnapshot {
            envs: envs
                .into_iter()
                .map(|env| EnvRow {
                    name: env.name,
                    agent: env.agent,
                    sandbox: env.sandbox,
                    context: env.context,
                    status: env.status,
                })
                .collect(),
            events,
            approvals,
            detail,
            events_per_minute: self.events.events_per_minute().context("event rate")?,
        })
    }

    async fn destroy_env(&mut self, env: &str) -> Result<()> {
        runtime::destroy_env(&self.options, &BuiltInDriverFactory, env)
            .await
            .with_context(|| format!("destroy env `{env}`"))?;
        let mut event = StoredEvent::new(
            env,
            now_rfc3339(),
            StoredEventKind::Runtime,
            "env_destroyed",
        );
        event.reason = Some("destroy command".to_owned());
        self.events.append(&event).context("append destroy event")?;
        Ok(())
    }

    async fn allow_approval(&mut self, request_id: &str) -> Result<()> {
        let record = self
            .approvals
            .decide(
                request_id,
                ApprovalDecision::Allow,
                ApprovalScope::Session,
                "term",
                &now_rfc3339(),
            )
            .context("allow approval")?;
        if record.status == ApprovalStatus::Stale {
            anyhow::bail!("approval request {request_id} is no longer pending");
        }
        Ok(())
    }

    async fn deny_approval(&mut self, request_id: &str) -> Result<()> {
        let record = self
            .approvals
            .decide(
                request_id,
                ApprovalDecision::Deny,
                ApprovalScope::Session,
                "term",
                &now_rfc3339(),
            )
            .context("deny approval")?;
        if record.status == ApprovalStatus::Stale {
            anyhow::bail!("approval request {request_id} is no longer pending");
        }
        Ok(())
    }
}

fn detail_lines(
    options: &RuntimeOptions,
    env: &str,
    state: &EnvStateFile,
    import_diagnostics: &[String],
) -> Vec<String> {
    let mut lines = vec![
        format!("status: {:?}", state.phase),
        format!("created: {}", state.created_at),
        format!("updated: {}", state.updated_at),
        format!("driver.agent: {}", state.drivers.agent.name),
        format!("driver.sandbox: {}", state.drivers.sandbox.name),
        format!("driver.context: {}", state.drivers.context.name),
        format!(
            "driver.inference: {}",
            state
                .drivers
                .inference
                .as_ref()
                .map(|driver| driver.name.as_str())
                .unwrap_or("none")
        ),
        format!(
            "handles: sandbox={} context={} inference={}",
            present_or_missing(state.handles.sandbox.as_deref()),
            present_or_missing(state.handles.context.as_deref()),
            present_or_missing(state.handles.inference.as_deref())
        ),
        format!(
            "endpoints: context_mcp={} inference={}",
            present_or_missing(
                state
                    .endpoints
                    .context_mcp
                    .as_ref()
                    .map(|endpoint| endpoint.url.as_str())
            ),
            present_or_missing(state.endpoints.inference.as_deref())
        ),
        credential_summary(&state.credential_names),
        "sessions: not loaded".to_owned(),
        "capabilities: via driver runtime".to_owned(),
    ];

    lines.extend(policy_lines(options, env, state));
    let diagnostic_prefix = format!("{env}:");
    lines.extend(
        import_diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.starts_with(&diagnostic_prefix))
            .cloned(),
    );
    lines
}

fn present_or_missing(value: Option<&str>) -> &'static str {
    match value {
        Some(value) if !value.is_empty() => "present",
        _ => "missing",
    }
}

fn credential_summary(names: &[String]) -> String {
    if names.is_empty() {
        "credentials: 0".to_owned()
    } else {
        format!("credentials: {} ({})", names.len(), names.join(", "))
    }
}

fn policy_lines(options: &RuntimeOptions, env: &str, state: &EnvStateFile) -> Vec<String> {
    if let Some(policy) = state.resolved_policy.as_ref() {
        return vec![
            format!(
                "policy.network: allow={} deny={} approval={}",
                policy.network.allow.len(),
                policy.network.deny.len(),
                policy.network.approval_required.len()
            ),
            format!(
                "policy.filesystem: read_only={} read_write={}",
                policy.filesystem.read_only.len(),
                policy.filesystem.read_write.len()
            ),
            format!(
                "policy.process: profile={} allow_syscalls={} deny_syscalls={}",
                policy.process.profile,
                policy.process.allow_syscalls.len(),
                policy.process.deny_syscalls.len()
            ),
            format!("policy.inference: routes={}", policy.inference.routes.len()),
        ];
    }

    let mut lines = vec!["policy: declared in blueprint".to_owned()];
    if let Ok(name) = agentenv_core::env::validate_env_name(env) {
        let paths = agentenv_core::env::EnvPaths::new(options.root.clone(), name);
        lines.push(format!(
            "blueprint: {}",
            file_summary(&paths.blueprint_path())
        ));
        lines.push(format!("lockfile: {}", file_summary(&paths.lock_path())));
    }
    lines
}

fn file_summary(path: &std::path::Path) -> &'static str {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => "present",
        _ => "missing",
    }
}

fn legacy_jsonl_import_event(env: &str, diagnostic: &str) -> StoredEvent {
    let mut event = StoredEvent::new(
        env,
        now_rfc3339(),
        StoredEventKind::Runtime,
        "legacy_jsonl_import",
    );
    event.reason = Some(diagnostic.to_owned());
    event
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    use agentenv_proto::LogLevel;

    use super::{legacy_jsonl_import_event, LocalOpsBackend};

    #[test]
    fn term_import_diagnostic_events_are_deduped() {
        let root = tempfile::tempdir().expect("tempdir");
        let options = agentenv_core::runtime::RuntimeOptions {
            root: root.path().to_path_buf(),
            log_level: LogLevel::Info,
            non_interactive: true,
        };
        let mut backend = LocalOpsBackend::new(options).expect("backend");

        let diagnostic = "demo: legacy event import failed: broken jsonl".to_owned();
        backend.append_import_diagnostics(&[diagnostic.clone()]);
        backend.append_import_diagnostics(&[diagnostic]);

        let events = backend
            .events
            .list_recent(Some("demo"), 10)
            .expect("list diagnostic events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, agentenv_events::StoredEventKind::Runtime);
        assert_eq!(events[0].subject, "legacy_jsonl_import");
        assert_eq!(
            events[0].reason.as_deref(),
            Some("demo: legacy event import failed: broken jsonl")
        );
    }

    #[test]
    fn term_import_diagnostic_event_uses_runtime_subject() {
        let event = legacy_jsonl_import_event(
            "demo",
            "demo: legacy event import skipped 2 malformed line(s)",
        );

        assert_eq!(event.env, "demo");
        assert_eq!(event.kind, agentenv_events::StoredEventKind::Runtime);
        assert_eq!(event.subject, "legacy_jsonl_import");
        assert_eq!(
            event.reason.as_deref(),
            Some("demo: legacy event import skipped 2 malformed line(s)")
        );
    }
}
