use std::path::PathBuf;

use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::model::{
    format_rfc3339, ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalRequest,
    ApprovalRequestFilter, ApprovalStatus,
};

#[derive(Debug, thiserror::Error)]
pub enum ApprovalStoreError {
    #[error("approval store sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("approval store IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("approval JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("approval timestamp parse error: {0}")]
    Time(#[from] time::error::Parse),
    #[error("approval request `{request_id}` was not found")]
    NotFound { request_id: String },
    #[error("approval request `{request_id}` already has a terminal decision")]
    AlreadyDecided { request_id: String },
    #[error("approval field `{field}` was not a string after serialization")]
    NonStringEnum { field: &'static str },
}

pub struct ApprovalStore {
    path: PathBuf,
}

impl ApprovalStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ApprovalStoreError> {
        let store = Self { path: path.into() };
        store.migrate()?;
        Ok(store)
    }

    pub fn insert_request(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        let conn = self.connection()?;
        let context_json = serde_json::to_string(&request.context)?;
        let kind = enum_to_db_string(request.kind, "kind")?;
        let default_scope = enum_to_db_string(request.default_scope, "default_scope")?;
        let status = enum_to_db_string(request.status, "status")?;
        let auto_deny_after_ms = u64_to_sql_integer(request.auto_deny_after_ms)?;

        conn.execute(
            r#"
            INSERT INTO approval_requests (
                id,
                env,
                kind,
                subject,
                reason,
                context_json,
                requested_at,
                default_scope,
                auto_deny_after_ms,
                status,
                driver_name,
                driver_request_handle,
                expires_at,
                created_trace_id
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                request.id,
                request.env,
                kind,
                request.subject,
                request.reason,
                context_json,
                format_rfc3339(request.requested_at),
                default_scope,
                auto_deny_after_ms,
                status,
                request.driver_name,
                request.driver_request_handle,
                format_rfc3339(request.expires_at),
                request.created_trace_id,
            ],
        )?;
        Ok(())
    }

    pub fn get_request(
        &self,
        request_id: &str,
    ) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        let conn = self.connection()?;
        let sql = request_select_sql("WHERE id = ?1");
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_and_then(params![request_id], request_from_row)?;

        rows.next().transpose()
    }

    pub fn list_requests(
        &self,
        filter: ApprovalRequestFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let conn = self.connection()?;
        let mut sql = request_select_sql("WHERE 1 = 1");
        let mut query_params = Vec::new();

        if let Some(env) = filter.env {
            sql.push_str(" AND env = ?");
            query_params.push(SqlValue::Text(env));
        }
        if let Some(status) = filter.status {
            sql.push_str(" AND status = ?");
            query_params.push(SqlValue::Text(enum_to_db_string(status, "status")?));
        }

        sql.push_str(" ORDER BY requested_at ASC, id ASC");

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_and_then(params_from_iter(query_params), request_from_row)?;
        collect_rows(rows)
    }

    pub fn record_decision(
        &self,
        decision: &ApprovalDecisionRecord,
    ) -> Result<(), ApprovalStoreError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let stored_status = tx
            .query_row(
                "SELECT status FROM approval_requests WHERE id = ?1",
                params![decision.request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        let Some(stored_status) = stored_status else {
            return Err(ApprovalStoreError::NotFound {
                request_id: decision.request_id.clone(),
            });
        };

        let status: ApprovalStatus = enum_from_db_string(stored_status)?;
        if status != ApprovalStatus::Pending {
            return Err(ApprovalStoreError::AlreadyDecided {
                request_id: decision.request_id.clone(),
            });
        }

        let decision_value = enum_to_db_string(decision.decision, "decision")?;
        let scope = enum_to_db_string(decision.scope, "scope")?;
        let context_json = serde_json::to_string(&decision.context)?;
        tx.execute(
            r#"
            INSERT INTO approval_decisions (
                request_id,
                decision,
                scope,
                decided_by,
                decided_at,
                reason,
                context_json,
                trace_id
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                decision.request_id,
                decision_value,
                scope,
                decision.decided_by,
                format_rfc3339(decision.decided_at),
                decision.reason,
                context_json,
                decision.trace_id,
            ],
        )?;

        let terminal_status = match decision.decision {
            ApprovalDecisionValue::Allow => ApprovalStatus::Approved,
            ApprovalDecisionValue::Deny => ApprovalStatus::Denied,
        };
        tx.execute(
            "UPDATE approval_requests SET status = ?1 WHERE id = ?2",
            params![
                enum_to_db_string(terminal_status, "status")?,
                decision.request_id
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_decision(
        &self,
        request_id: &str,
    ) -> Result<Option<ApprovalDecisionRecord>, ApprovalStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT
                request_id,
                decision,
                scope,
                decided_by,
                decided_at,
                reason,
                context_json,
                trace_id
            FROM approval_decisions
            WHERE request_id = ?1
            "#,
        )?;
        let mut rows = stmt.query_and_then(params![request_id], decision_from_row)?;

        rows.next().transpose()
    }

    pub fn due_pending_requests(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let conn = self.connection()?;
        let sql = request_select_sql(
            "WHERE status = ?1 AND expires_at <= ?2 ORDER BY expires_at ASC, id ASC",
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_and_then(
            params![
                enum_to_db_string(ApprovalStatus::Pending, "status")?,
                format_rfc3339(now)
            ],
            request_from_row,
        )?;
        collect_rows(rows)
    }

    pub fn expire_without_waiter(
        &self,
        request_id: &str,
        _now: OffsetDateTime,
    ) -> Result<(), ApprovalStoreError> {
        let conn = self.connection()?;
        let changed = conn.execute(
            "UPDATE approval_requests SET status = ?1 WHERE id = ?2 AND status = ?3",
            params![
                enum_to_db_string(ApprovalStatus::Expired, "status")?,
                request_id,
                enum_to_db_string(ApprovalStatus::Pending, "status")?
            ],
        )?;

        if changed == 0 && self.get_request(request_id)?.is_none() {
            return Err(ApprovalStoreError::NotFound {
                request_id: request_id.to_owned(),
            });
        }

        Ok(())
    }

    fn migrate(&self) -> Result<(), ApprovalStoreError> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }

        let conn = self.connection()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS approval_requests (
              id TEXT PRIMARY KEY,
              env TEXT NOT NULL,
              kind TEXT NOT NULL,
              subject TEXT NOT NULL,
              reason TEXT NOT NULL,
              context_json TEXT NOT NULL,
              requested_at TEXT NOT NULL,
              default_scope TEXT NOT NULL,
              auto_deny_after_ms INTEGER NOT NULL,
              status TEXT NOT NULL,
              driver_name TEXT,
              driver_request_handle TEXT,
              expires_at TEXT NOT NULL,
              created_trace_id TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS approval_requests_env_status_requested_at_idx
              ON approval_requests(env, status, requested_at);
            CREATE INDEX IF NOT EXISTS approval_requests_status_expires_at_idx
              ON approval_requests(status, expires_at);

            CREATE TABLE IF NOT EXISTS approval_decisions (
              request_id TEXT PRIMARY KEY,
              decision TEXT NOT NULL,
              scope TEXT NOT NULL,
              decided_by TEXT NOT NULL,
              decided_at TEXT NOT NULL,
              reason TEXT,
              context_json TEXT NOT NULL,
              trace_id TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_delivery_targets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              env TEXT,
              kind_filter_json TEXT NOT NULL,
              channel TEXT NOT NULL,
              url TEXT NOT NULL,
              secret_ref TEXT
            );

            CREATE TABLE IF NOT EXISTS approval_delivery_attempts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              request_id TEXT NOT NULL,
              target_id INTEGER NOT NULL,
              status TEXT NOT NULL,
              attempt_count INTEGER NOT NULL,
              next_attempt_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection, ApprovalStoreError> {
        Ok(Connection::open_with_flags(
            &self.path,
            database_open_flags(),
        )?)
    }
}

fn database_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

fn request_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        SELECT
            id,
            env,
            kind,
            subject,
            reason,
            context_json,
            requested_at,
            default_scope,
            auto_deny_after_ms,
            status,
            driver_name,
            driver_request_handle,
            expires_at,
            created_trace_id
        FROM approval_requests
        {where_clause}
        "#
    )
}

fn request_from_row(row: &rusqlite::Row<'_>) -> Result<ApprovalRequest, ApprovalStoreError> {
    let auto_deny_after_ms = row.get::<_, i64>(8)?;
    Ok(ApprovalRequest {
        id: row.get(0)?,
        env: row.get(1)?,
        kind: enum_from_db_string(row.get::<_, String>(2)?)?,
        subject: row.get(3)?,
        reason: row.get(4)?,
        context: serde_json::from_str(&row.get::<_, String>(5)?)?,
        requested_at: parse_rfc3339(row.get::<_, String>(6)?)?,
        default_scope: enum_from_db_string(row.get::<_, String>(7)?)?,
        auto_deny_after_ms: sql_integer_to_u64(auto_deny_after_ms, 8)?,
        status: enum_from_db_string(row.get::<_, String>(9)?)?,
        driver_name: row.get(10)?,
        driver_request_handle: row.get(11)?,
        expires_at: parse_rfc3339(row.get::<_, String>(12)?)?,
        created_trace_id: row.get(13)?,
    })
}

fn decision_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<ApprovalDecisionRecord, ApprovalStoreError> {
    Ok(ApprovalDecisionRecord {
        request_id: row.get(0)?,
        decision: enum_from_db_string(row.get::<_, String>(1)?)?,
        scope: enum_from_db_string(row.get::<_, String>(2)?)?,
        decided_by: row.get(3)?,
        decided_at: parse_rfc3339(row.get::<_, String>(4)?)?,
        reason: row.get(5)?,
        context: serde_json::from_str(&row.get::<_, String>(6)?)?,
        trace_id: row.get(7)?,
    })
}

fn collect_rows<T>(
    rows: rusqlite::AndThenRows<
        '_,
        impl FnMut(&rusqlite::Row<'_>) -> Result<T, ApprovalStoreError>,
    >,
) -> Result<Vec<T>, ApprovalStoreError> {
    rows.collect()
}

fn enum_to_db_string<T: Serialize>(
    value: T,
    field: &'static str,
) -> Result<String, ApprovalStoreError> {
    let value = serde_json::to_value(value)?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(ApprovalStoreError::NonStringEnum { field })
}

fn enum_from_db_string<T: DeserializeOwned>(value: String) -> Result<T, ApprovalStoreError> {
    Ok(serde_json::from_value(serde_json::Value::String(value))?)
}

fn parse_rfc3339(value: String) -> Result<OffsetDateTime, ApprovalStoreError> {
    Ok(OffsetDateTime::parse(&value, &Rfc3339)?)
}

fn u64_to_sql_integer(value: u64) -> Result<i64, ApprovalStoreError> {
    i64::try_from(value).map_err(|error| {
        ApprovalStoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
    })
}

fn sql_integer_to_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use time::OffsetDateTime;

    use crate::model::{
        ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalKind, ApprovalRequest,
        ApprovalRequestFilter, ApprovalScope, ApprovalStatus,
    };

    use super::*;

    fn request(id: &str, seconds: i64) -> ApprovalRequest {
        let requested_at = OffsetDateTime::from_unix_timestamp(1_777_443_200 + seconds).unwrap();
        ApprovalRequest::new(
            id,
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "network access",
            json!({"url": "https://api.example.test/v1"}),
            requested_at,
            ApprovalScope::Session,
            Duration::from_secs(30),
            format!("trace-{id}"),
        )
    }

    fn decision(request_id: &str) -> ApprovalDecisionRecord {
        ApprovalDecisionRecord {
            request_id: request_id.to_owned(),
            decision: ApprovalDecisionValue::Allow,
            scope: ApprovalScope::Session,
            decided_by: "alice".to_owned(),
            decided_at: OffsetDateTime::from_unix_timestamp(1_777_443_260).unwrap(),
            reason: Some("approved for test".to_owned()),
            context: json!({"source": "test"}),
            trace_id: "trace-decision".to_owned(),
        }
    }

    #[test]
    fn pending_requests_list_in_age_order() {
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        store.insert_request(&request("req-newer", 10)).unwrap();
        store.insert_request(&request("req-older", 0)).unwrap();

        let rows = store
            .list_requests(ApprovalRequestFilter {
                env: Some("demo".to_owned()),
                status: Some(ApprovalStatus::Pending),
            })
            .unwrap();

        assert_eq!(
            rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            vec!["req-older", "req-newer"]
        );
    }

    #[test]
    fn terminal_decision_updates_status_once() {
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        store.insert_request(&request("req-1", 0)).unwrap();

        store.record_decision(&decision("req-1")).unwrap();
        let duplicate = store.record_decision(&decision("req-1")).unwrap_err();

        assert!(
            matches!(duplicate, ApprovalStoreError::AlreadyDecided { request_id } if request_id == "req-1")
        );
        assert_eq!(
            store.get_request("req-1").unwrap().unwrap().status,
            ApprovalStatus::Approved
        );
    }

    #[test]
    fn due_requests_are_selected_for_auto_deny() {
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        store.insert_request(&request("req-due", 0)).unwrap();
        store.insert_request(&request("req-future", 60)).unwrap();

        let now = OffsetDateTime::from_unix_timestamp(1_777_443_240).unwrap();
        let due = store.due_pending_requests(now).unwrap();

        assert_eq!(
            due.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            vec!["req-due"]
        );
    }
}
