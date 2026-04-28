#![forbid(unsafe_code)]

use agentenv_events::{LocalEventStore, StoredEvent, StoredEventKind};
use agentenv_proto::{ApprovalDecision, ApprovalKind, ApprovalScope};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Allowed,
    Denied,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequestRecord {
    pub request_id: String,
    pub env: String,
    pub agent: Option<String>,
    pub kind: ApprovalKind,
    pub subject: String,
    pub reason: String,
    pub status: ApprovalStatus,
    pub requested_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub scope: Option<ApprovalScope>,
    pub context: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum ApprovalStoreError {
    #[error("failed to create approval store directory `{path}`: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sqlite approval store error at `{path}`: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to encode approval context: {source}")]
    ContextEncode {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode approval context: {source}")]
    ContextDecode {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to append approval event: {source}")]
    Event {
        #[source]
        source: agentenv_events::EventStoreError,
    },
}

pub type ApprovalStoreResult<T> = Result<T, ApprovalStoreError>;

pub struct LocalApprovalStore {
    path: PathBuf,
    conn: Connection,
    events: LocalEventStore,
}

impl LocalApprovalStore {
    pub fn open(root: &Path) -> ApprovalStoreResult<Self> {
        fs::create_dir_all(root).map_err(|source| ApprovalStoreError::CreateDir {
            path: root.to_path_buf(),
            source,
        })?;
        let path = agentenv_events::default_store_path(root);
        let conn = Connection::open(&path).map_err(|source| ApprovalStoreError::Sqlite {
            path: path.clone(),
            source,
        })?;
        let events =
            LocalEventStore::open(root).map_err(|source| ApprovalStoreError::Event { source })?;
        let store = Self { path, conn, events };
        store.init_schema()?;
        Ok(store)
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    fn init_schema(&self) -> ApprovalStoreResult<()> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS approvals (
                    request_id TEXT PRIMARY KEY,
                    env TEXT NOT NULL,
                    agent TEXT,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'allowed', 'denied', 'stale')),
                    requested_at TEXT NOT NULL,
                    decided_at TEXT,
                    decided_by TEXT,
                    scope TEXT,
                    context_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_approvals_status_env
                    ON approvals(status, env, requested_at);
                "#,
            )
            .map_err(|source| ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })
    }

    pub fn upsert_pending(&self, request: ApprovalRequestRecord) -> ApprovalStoreResult<()> {
        let context_json = serde_json::to_string(&request.context)
            .map_err(|source| ApprovalStoreError::ContextEncode { source })?;
        self.conn
            .execute(
                "INSERT INTO approvals
                 (request_id, env, agent, kind, subject, reason, status, requested_at,
                  decided_at, decided_by, scope, context_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, NULL, NULL, NULL, ?8)
                 ON CONFLICT(request_id) DO UPDATE SET
                    env = excluded.env,
                    agent = excluded.agent,
                    kind = excluded.kind,
                    subject = excluded.subject,
                    reason = excluded.reason,
                    status = 'pending',
                    requested_at = excluded.requested_at,
                    decided_at = NULL,
                    decided_by = NULL,
                    scope = NULL,
                    context_json = excluded.context_json",
                params![
                    request.request_id,
                    request.env,
                    request.agent,
                    approval_kind_str(&request.kind),
                    request.subject,
                    request.reason,
                    request.requested_at,
                    context_json
                ],
            )
            .map_err(|source| ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    pub fn list_pending(
        &self,
        env: Option<&str>,
    ) -> ApprovalStoreResult<Vec<ApprovalRequestRecord>> {
        match env {
            Some(env) => self.list_with_filter(
                "SELECT request_id, env, agent, kind, subject, reason, status, requested_at,
                        decided_at, decided_by, scope, context_json
                 FROM approvals
                 WHERE status = 'pending' AND env = ?1
                 ORDER BY requested_at ASC, request_id ASC",
                params![env],
            ),
            None => self.list_with_filter(
                "SELECT request_id, env, agent, kind, subject, reason, status, requested_at,
                        decided_at, decided_by, scope, context_json
                 FROM approvals
                 WHERE status = 'pending'
                 ORDER BY requested_at ASC, request_id ASC",
                [],
            ),
        }
    }

    pub fn decide(
        &self,
        request_id: &str,
        decision: ApprovalDecision,
        scope: ApprovalScope,
        decided_by: &str,
        decided_at: &str,
    ) -> ApprovalStoreResult<ApprovalRequestRecord> {
        let Some(mut record) = self.get_request(request_id)? else {
            return Ok(stale_missing_request(
                request_id, scope, decided_by, decided_at,
            ));
        };

        if record.status != ApprovalStatus::Pending {
            record.status = ApprovalStatus::Stale;
            return Ok(record);
        }

        let status = match decision {
            ApprovalDecision::Allow => ApprovalStatus::Allowed,
            ApprovalDecision::Deny => ApprovalStatus::Denied,
        };
        self.conn
            .execute(
                "UPDATE approvals
                 SET status = ?1, decided_at = ?2, decided_by = ?3, scope = ?4
                 WHERE request_id = ?5 AND status = 'pending'",
                params![
                    approval_status_str(status),
                    decided_at,
                    decided_by,
                    approval_scope_str(&scope),
                    request_id
                ],
            )
            .map_err(|source| ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        record.status = status;
        record.decided_at = Some(decided_at.to_owned());
        record.decided_by = Some(decided_by.to_owned());
        record.scope = Some(scope);
        self.emit_decision_event(&record)?;
        Ok(record)
    }

    fn list_with_filter<P>(
        &self,
        sql: &str,
        params: P,
    ) -> ApprovalStoreResult<Vec<ApprovalRequestRecord>>
    where
        P: rusqlite::Params,
    {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|source| ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let rows = stmt.query_map(params, row_to_approval).map_err(|source| {
            ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            }
        })?;
        let mut out = Vec::new();
        for row in rows {
            let raw = row.map_err(|source| ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
            out.push(raw.into_record()?);
        }
        Ok(out)
    }

    fn get_request(&self, request_id: &str) -> ApprovalStoreResult<Option<ApprovalRequestRecord>> {
        let raw = self
            .conn
            .query_row(
                "SELECT request_id, env, agent, kind, subject, reason, status, requested_at,
                        decided_at, decided_by, scope, context_json
                 FROM approvals WHERE request_id = ?1",
                params![request_id],
                row_to_approval,
            )
            .optional()
            .map_err(|source| ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        raw.map(ApprovalRow::into_record).transpose()
    }

    fn emit_decision_event(&self, record: &ApprovalRequestRecord) -> ApprovalStoreResult<()> {
        let kind = match record.status {
            ApprovalStatus::Allowed => StoredEventKind::ApprovalAllowed,
            ApprovalStatus::Denied => StoredEventKind::ApprovalDenied,
            ApprovalStatus::Pending | ApprovalStatus::Stale => return Ok(()),
        };
        let ts = record
            .decided_at
            .as_deref()
            .unwrap_or(record.requested_at.as_str());
        let mut event = StoredEvent::new(&record.env, ts, kind, &record.subject);
        event.reason = Some(record.reason.clone());
        event.metadata = serde_json::json!({
            "request_id": record.request_id,
            "decided_by": record.decided_by,
            "scope": record.scope,
        });
        self.events
            .append(&event)
            .map_err(|source| ApprovalStoreError::Event { source })?;
        Ok(())
    }
}

struct ApprovalRow {
    request_id: String,
    env: String,
    agent: Option<String>,
    kind: String,
    subject: String,
    reason: String,
    status: String,
    requested_at: String,
    decided_at: Option<String>,
    decided_by: Option<String>,
    scope: Option<String>,
    context_json: String,
}

impl ApprovalRow {
    fn into_record(self) -> ApprovalStoreResult<ApprovalRequestRecord> {
        let context = serde_json::from_str(&self.context_json)
            .map_err(|source| ApprovalStoreError::ContextDecode { source })?;
        Ok(ApprovalRequestRecord {
            request_id: self.request_id,
            env: self.env,
            agent: self.agent,
            kind: approval_kind_from_str(&self.kind),
            subject: self.subject,
            reason: self.reason,
            status: approval_status_from_str(&self.status),
            requested_at: self.requested_at,
            decided_at: self.decided_at,
            decided_by: self.decided_by,
            scope: self.scope.as_deref().map(approval_scope_from_str),
            context,
        })
    }
}

fn row_to_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRow> {
    Ok(ApprovalRow {
        request_id: row.get(0)?,
        env: row.get(1)?,
        agent: row.get(2)?,
        kind: row.get(3)?,
        subject: row.get(4)?,
        reason: row.get(5)?,
        status: row.get(6)?,
        requested_at: row.get(7)?,
        decided_at: row.get(8)?,
        decided_by: row.get(9)?,
        scope: row.get(10)?,
        context_json: row.get(11)?,
    })
}

fn stale_missing_request(
    request_id: &str,
    scope: ApprovalScope,
    decided_by: &str,
    decided_at: &str,
) -> ApprovalRequestRecord {
    ApprovalRequestRecord {
        request_id: request_id.to_owned(),
        env: String::new(),
        agent: None,
        kind: ApprovalKind::EgressHost,
        subject: String::new(),
        reason: "request is missing or already pruned".to_owned(),
        status: ApprovalStatus::Stale,
        requested_at: decided_at.to_owned(),
        decided_at: Some(decided_at.to_owned()),
        decided_by: Some(decided_by.to_owned()),
        scope: Some(scope),
        context: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn approval_kind_str(kind: &ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::EgressHost => "egress_host",
        ApprovalKind::McpTool => "mcp_tool",
        ApprovalKind::ZoneAccess => "zone_access",
    }
}

fn approval_kind_from_str(value: &str) -> ApprovalKind {
    match value {
        "mcp_tool" => ApprovalKind::McpTool,
        "zone_access" => ApprovalKind::ZoneAccess,
        _ => ApprovalKind::EgressHost,
    }
}

fn approval_status_str(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Allowed => "allowed",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Stale => "stale",
    }
}

fn approval_status_from_str(value: &str) -> ApprovalStatus {
    match value {
        "allowed" => ApprovalStatus::Allowed,
        "denied" => ApprovalStatus::Denied,
        "stale" => ApprovalStatus::Stale,
        _ => ApprovalStatus::Pending,
    }
}

fn approval_scope_str(scope: &ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "once",
        ApprovalScope::Session => "session",
        ApprovalScope::PersistSandbox => "persist-sandbox",
        ApprovalScope::ProposeForBaseline => "propose-for-baseline",
    }
}

fn approval_scope_from_str(value: &str) -> ApprovalScope {
    match value {
        "session" => ApprovalScope::Session,
        "persist-sandbox" => ApprovalScope::PersistSandbox,
        "propose-for-baseline" => ApprovalScope::ProposeForBaseline,
        _ => ApprovalScope::Once,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_request(id: &str) -> ApprovalRequestRecord {
        ApprovalRequestRecord {
            request_id: id.to_owned(),
            env: "demo".to_owned(),
            agent: Some("codex".to_owned()),
            kind: ApprovalKind::EgressHost,
            subject: "api.stripe.com:443".to_owned(),
            reason: "egress requires approval".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: "2026-04-27T12:00:00Z".to_owned(),
            decided_at: None,
            decided_by: None,
            scope: None,
            context: serde_json::json!({"driver": "sandbox"}),
        }
    }

    fn pending_request_for_env(id: &str, env: &str, requested_at: &str) -> ApprovalRequestRecord {
        ApprovalRequestRecord {
            request_id: id.to_owned(),
            env: env.to_owned(),
            requested_at: requested_at.to_owned(),
            ..pending_request(id)
        }
    }

    #[test]
    fn approval_store_lists_pending_requests() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .upsert_pending(pending_request("req_1"))
            .expect("insert pending");

        let pending = store.list_pending(None).expect("list pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "req_1");
        assert_eq!(pending[0].status, ApprovalStatus::Pending);
    }

    #[test]
    fn approval_decision_updates_status_and_emits_event() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .upsert_pending(pending_request("req_2"))
            .expect("insert pending");
        let decided = store
            .decide(
                "req_2",
                ApprovalDecision::Allow,
                ApprovalScope::Session,
                "operator",
                "2026-04-27T12:01:00Z",
            )
            .expect("decide request");

        assert_eq!(decided.status, ApprovalStatus::Allowed);
        assert_eq!(decided.decided_by.as_deref(), Some("operator"));
        assert!(store.list_pending(None).expect("list pending").is_empty());

        let events = LocalEventStore::open(root.path())
            .expect("open events")
            .list_recent(Some("demo"), 10)
            .expect("list decision events");
        assert!(events.iter().any(|event| {
            event.kind == StoredEventKind::ApprovalAllowed && event.subject == "api.stripe.com:443"
        }));
    }

    #[test]
    fn deciding_missing_request_returns_stale() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        let result = store
            .decide(
                "missing",
                ApprovalDecision::Deny,
                ApprovalScope::Once,
                "operator",
                "2026-04-27T12:01:00Z",
            )
            .expect("missing decision");

        assert_eq!(result.status, ApprovalStatus::Stale);
    }

    #[test]
    fn list_pending_filters_by_env_and_orders_oldest_first() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .upsert_pending(pending_request_for_env(
                "req_new",
                "demo",
                "2026-04-27T12:02:00Z",
            ))
            .expect("insert newer demo");
        store
            .upsert_pending(pending_request_for_env(
                "req_other",
                "other",
                "2026-04-27T12:00:00Z",
            ))
            .expect("insert other");
        store
            .upsert_pending(pending_request_for_env(
                "req_old",
                "demo",
                "2026-04-27T12:01:00Z",
            ))
            .expect("insert older demo");

        let pending = store.list_pending(Some("demo")).expect("list demo");

        assert_eq!(
            pending
                .iter()
                .map(|request| request.request_id.as_str())
                .collect::<Vec<_>>(),
            vec!["req_old", "req_new"]
        );
    }

    #[test]
    fn upsert_pending_preserves_context_json() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");
        let mut request = pending_request("req_context");
        request.context = serde_json::json!({
            "driver": "sandbox",
            "nested": {
                "ports": [443, 8443],
                "temporary": true
            }
        });

        store
            .upsert_pending(request.clone())
            .expect("insert pending");

        let pending = store.list_pending(None).expect("list pending");
        assert_eq!(pending[0].context, request.context);
    }

    #[test]
    fn deny_decision_emits_denied_event() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .upsert_pending(pending_request("req_deny"))
            .expect("insert pending");
        let decided = store
            .decide(
                "req_deny",
                ApprovalDecision::Deny,
                ApprovalScope::Once,
                "operator",
                "2026-04-27T12:01:00Z",
            )
            .expect("deny request");

        assert_eq!(decided.status, ApprovalStatus::Denied);
        let events = LocalEventStore::open(root.path())
            .expect("open events")
            .list_recent(Some("demo"), 10)
            .expect("list decision events");
        assert!(events.iter().any(|event| {
            event.kind == StoredEventKind::ApprovalDenied
                && event.metadata["request_id"] == "req_deny"
        }));
    }

    #[test]
    fn deciding_non_pending_request_returns_stale_without_extra_event() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .upsert_pending(pending_request("req_once"))
            .expect("insert pending");
        store
            .decide(
                "req_once",
                ApprovalDecision::Allow,
                ApprovalScope::Session,
                "operator",
                "2026-04-27T12:01:00Z",
            )
            .expect("allow request");
        let stale = store
            .decide(
                "req_once",
                ApprovalDecision::Deny,
                ApprovalScope::Once,
                "operator",
                "2026-04-27T12:02:00Z",
            )
            .expect("second decision");

        assert_eq!(stale.status, ApprovalStatus::Stale);
        assert_eq!(
            LocalEventStore::open(root.path())
                .expect("open events")
                .list_recent(Some("demo"), 10)
                .expect("list decision events")
                .len(),
            1
        );
    }
}
