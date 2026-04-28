use agentenv_approvals::LocalApprovalStore;
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
}

impl LocalOpsBackend {
    pub fn new(options: RuntimeOptions) -> Result<Self> {
        let events = LocalEventStore::open(&options.root).context("open event store")?;
        let approvals = LocalApprovalStore::open(&options.root).context("open approval store")?;
        Ok(Self {
            options,
            events,
            approvals,
        })
    }

    fn import_jsonl_for_envs(&self, envs: &[runtime::EnvListRow]) {
        for env in envs {
            if let Ok(name) = agentenv_core::env::validate_env_name(&env.name) {
                let paths = agentenv_core::env::EnvPaths::new(self.options.root.clone(), name);
                let _ = self
                    .events
                    .import_env_jsonl(&env.name, &paths.events_path());
            }
        }
    }
}

#[async_trait(?Send)]
impl OpsBackend for LocalOpsBackend {
    async fn load_snapshot(&mut self, selected_env: Option<&str>) -> Result<OpsSnapshot> {
        let envs = runtime::list_envs(&self.options).context("list envs")?;
        self.import_jsonl_for_envs(&envs);
        let selected = selected_env
            .filter(|name| envs.iter().any(|env| env.name == *name))
            .or_else(|| envs.first().map(|env| env.name.as_str()));
        let detail = match selected {
            Some(name) => match runtime::describe_env(&self.options, name) {
                Ok(description) => Some(DetailState {
                    env: name.to_owned(),
                    lines: vec![
                        format!("status: {:?}", description.state.phase),
                        format!("agent: {}", description.state.drivers.agent.name),
                        format!("sandbox: {}", description.state.drivers.sandbox.name),
                        format!("context: {}", description.state.drivers.context.name),
                        format!(
                            "policy: {}",
                            description
                                .state
                                .resolved_policy
                                .as_ref()
                                .map(|_| "resolved")
                                .unwrap_or("declared")
                        ),
                    ],
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
        self.approvals
            .decide(
                request_id,
                ApprovalDecision::Allow,
                ApprovalScope::Session,
                "term",
                &now_rfc3339(),
            )
            .context("allow approval")?;
        Ok(())
    }

    async fn deny_approval(&mut self, request_id: &str) -> Result<()> {
        self.approvals
            .decide(
                request_id,
                ApprovalDecision::Deny,
                ApprovalScope::Session,
                "term",
                &now_rfc3339(),
            )
            .context("deny approval")?;
        Ok(())
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}
