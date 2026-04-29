use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use agentenv_events::EventEmitter;
#[cfg(test)]
use agentenv_events::NoopEventEmitter;
use serde_json::json;
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::events::{approval_decided_event, approval_requested_event};
use crate::model::{
    ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalKind, ApprovalRequest, ApprovalScope,
};
use crate::store::{ApprovalStore, ApprovalStoreError};

type Waiter = oneshot::Sender<ApprovalDecisionRecord>;
type WaiterMap = BTreeMap<String, Vec<Waiter>>;

#[derive(Clone)]
pub struct ApprovalCoordinator {
    store: Arc<ApprovalStore>,
    events: Arc<dyn EventEmitter>,
    waiters: Arc<Mutex<WaiterMap>>,
    session_grants: Arc<Mutex<BTreeSet<SessionGrantKey>>>,
    poll_interval: Duration,
}

pub struct ApprovalCoordinatorConfig {
    pub store: ApprovalStore,
    pub events: Arc<dyn EventEmitter>,
    pub poll_interval: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ApprovalCoordinatorError {
    #[error(transparent)]
    Store(#[from] ApprovalStoreError),
    #[error("approval waiter for request `{request_id}` closed before a decision was recorded")]
    WaiterClosed { request_id: String },
    #[error("approval coordinator mutex `{name}` was poisoned")]
    LockPoisoned { name: &'static str },
}

impl ApprovalCoordinator {
    pub fn new(config: ApprovalCoordinatorConfig) -> Self {
        Self {
            store: Arc::new(config.store),
            events: config.events,
            waiters: Arc::new(Mutex::new(BTreeMap::new())),
            session_grants: Arc::new(Mutex::new(BTreeSet::new())),
            poll_interval: config.poll_interval,
        }
    }

    pub async fn submit_request(
        &self,
        request: ApprovalRequest,
    ) -> Result<(), ApprovalCoordinatorError> {
        self.store.insert_request(&request)?;
        self.events.emit(approval_requested_event(&request));
        Ok(())
    }

    pub async fn decide(
        &self,
        decision: ApprovalDecisionRecord,
    ) -> Result<ApprovalDecisionRecord, ApprovalCoordinatorError> {
        let request = self.request_for_decision(&decision)?;
        self.store.record_decision(&decision)?;
        self.events
            .emit(approval_decided_event(&request, &decision));
        self.remember_session_grant(&request, &decision)?;
        self.wake_waiters(&decision.request_id, &decision)?;
        Ok(decision)
    }

    pub async fn wait_for_decision(
        &self,
        request_id: &str,
    ) -> Result<ApprovalDecisionRecord, ApprovalCoordinatorError> {
        if let Some(decision) = self.store.get_decision(request_id)? {
            return Ok(decision);
        }

        let request_id = request_id.to_owned();
        let (sender, mut receiver) = oneshot::channel();
        {
            let mut waiters = self.lock_waiters()?;
            waiters.entry(request_id.clone()).or_default().push(sender);
        }

        if let Some(decision) = self.store.get_decision(&request_id)? {
            self.wake_waiters(&request_id, &decision)?;
            return Ok(decision);
        }

        loop {
            tokio::select! {
                decision = &mut receiver => {
                    return decision.map_err(|_| ApprovalCoordinatorError::WaiterClosed {
                        request_id,
                    });
                }
                () = tokio::time::sleep(self.poll_interval) => {
                    if let Some(decision) = self.store.get_decision(&request_id)? {
                        self.wake_waiters(&request_id, &decision)?;
                        return Ok(decision);
                    }
                }
            }
        }
    }

    pub async fn expire_due(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalDecisionRecord>, ApprovalCoordinatorError> {
        let mut decisions = Vec::new();

        for request in self.store.due_pending_requests(now)? {
            let decision = ApprovalDecisionRecord {
                request_id: request.id.clone(),
                decision: ApprovalDecisionValue::Deny,
                scope: ApprovalScope::Once,
                decided_by: "agentenv:auto-deny".to_owned(),
                decided_at: now,
                reason: Some("auto_deny_timeout".to_owned()),
                context: json!({"source": "auto-deny"}),
                trace_id: request.created_trace_id.clone(),
            };

            match self.store.record_decision(&decision) {
                Ok(()) => {
                    self.events
                        .emit(approval_decided_event(&request, &decision));
                    self.wake_waiters(&decision.request_id, &decision)?;
                    decisions.push(decision);
                }
                Err(ApprovalStoreError::AlreadyDecided { request_id }) => {
                    if let Some(existing) = self.store.get_decision(&request_id)? {
                        self.wake_waiters(&request_id, &existing)?;
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }

        Ok(decisions)
    }

    pub fn store(&self) -> &ApprovalStore {
        self.store.as_ref()
    }

    fn request_for_decision(
        &self,
        decision: &ApprovalDecisionRecord,
    ) -> Result<ApprovalRequest, ApprovalCoordinatorError> {
        self.store
            .get_request(&decision.request_id)?
            .ok_or_else(|| ApprovalStoreError::NotFound {
                request_id: decision.request_id.clone(),
            })
            .map_err(Into::into)
    }

    fn remember_session_grant(
        &self,
        request: &ApprovalRequest,
        decision: &ApprovalDecisionRecord,
    ) -> Result<(), ApprovalCoordinatorError> {
        if decision.decision != ApprovalDecisionValue::Allow
            || decision.scope != ApprovalScope::Session
        {
            return Ok(());
        }

        let mut grants = self.lock_session_grants()?;
        grants.insert(SessionGrantKey::from_request(request));
        Ok(())
    }

    fn wake_waiters(
        &self,
        request_id: &str,
        decision: &ApprovalDecisionRecord,
    ) -> Result<(), ApprovalCoordinatorError> {
        let waiters = {
            let mut waiters = self.lock_waiters()?;
            waiters.remove(request_id).unwrap_or_default()
        };

        for waiter in waiters {
            let _send_result = waiter.send(decision.clone());
        }

        Ok(())
    }

    fn lock_waiters(&self) -> Result<MutexGuard<'_, WaiterMap>, ApprovalCoordinatorError> {
        self.waiters
            .lock()
            .map_err(|_| ApprovalCoordinatorError::LockPoisoned { name: "waiters" })
    }

    fn lock_session_grants(
        &self,
    ) -> Result<MutexGuard<'_, BTreeSet<SessionGrantKey>>, ApprovalCoordinatorError> {
        self.session_grants
            .lock()
            .map_err(|_| ApprovalCoordinatorError::LockPoisoned {
                name: "session_grants",
            })
    }
}

impl ApprovalCoordinatorConfig {
    #[cfg(test)]
    pub fn for_test(store: ApprovalStore) -> Self {
        Self {
            store,
            events: Arc::new(NoopEventEmitter),
            poll_interval: Duration::from_millis(10),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SessionGrantKey {
    env: String,
    kind: &'static str,
    subject: String,
}

impl SessionGrantKey {
    fn from_request(request: &ApprovalRequest) -> Self {
        Self {
            env: request.env.clone(),
            kind: approval_kind_key(request.kind),
            subject: request.subject.clone(),
        }
    }
}

fn approval_kind_key(kind: ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::EgressHost => "egress_host",
        ApprovalKind::McpTool => "mcp_tool",
        ApprovalKind::ZoneAccess => "zone_access",
        ApprovalKind::PackageInstall => "package_install",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use time::OffsetDateTime;

    use crate::model::{
        ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalKind, ApprovalRequest, ApprovalScope,
    };
    use crate::store::ApprovalStore;

    use super::{ApprovalCoordinator, ApprovalCoordinatorConfig};

    fn fixed_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_777_443_200).unwrap()
    }

    fn test_request(id: &str) -> ApprovalRequest {
        ApprovalRequest::new(
            id,
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "network access",
            json!({"url": "https://api.example.test/v1"}),
            fixed_time(),
            ApprovalScope::Session,
            Duration::from_secs(30),
            format!("trace-{id}"),
        )
    }

    fn test_decision(request_id: &str, decision: ApprovalDecisionValue) -> ApprovalDecisionRecord {
        ApprovalDecisionRecord {
            request_id: request_id.to_owned(),
            decision,
            scope: ApprovalScope::Session,
            decided_by: "alice".to_owned(),
            decided_at: OffsetDateTime::from_unix_timestamp(1_777_443_205).unwrap(),
            reason: Some("approved for test".to_owned()),
            context: json!({"source": "test"}),
            trace_id: "trace-decision".to_owned(),
        }
    }

    #[tokio::test]
    async fn decision_wakes_waiting_driver() {
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        let coordinator = ApprovalCoordinator::new(ApprovalCoordinatorConfig::for_test(store));
        let request = test_request("req-1");

        coordinator.submit_request(request.clone()).await.unwrap();
        let waiter = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.wait_for_decision("req-1").await.unwrap() }
        });

        coordinator
            .decide(test_decision("req-1", ApprovalDecisionValue::Allow))
            .await
            .unwrap();

        assert_eq!(waiter.await.unwrap().decision, ApprovalDecisionValue::Allow);
    }

    #[tokio::test]
    async fn auto_deny_records_deny_and_wakes_waiter() {
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        let coordinator = ApprovalCoordinator::new(ApprovalCoordinatorConfig::for_test(store));
        let mut request = test_request("req-auto");
        request.expires_at = OffsetDateTime::from_unix_timestamp(1_777_443_201).unwrap();

        coordinator.submit_request(request).await.unwrap();
        let waiter = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.wait_for_decision("req-auto").await.unwrap() }
        });
        coordinator
            .expire_due(OffsetDateTime::from_unix_timestamp(1_777_443_240).unwrap())
            .await
            .unwrap();

        let decision = waiter.await.unwrap();
        assert_eq!(decision.decision, ApprovalDecisionValue::Deny);
        assert_eq!(decision.decided_by, "agentenv:auto-deny");
    }
}
