use std::path::{Path, PathBuf};

use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

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
    #[error("unsafe approval database path: {path}")]
    UnsafeDatabasePath { path: PathBuf },
    #[error("approval timestamp is outside SQLite integer nanosecond range: {0}")]
    TimestampOutOfRange(i128),
    #[error("approval delivery attempt `{delivery_id}` was not found")]
    DeliveryNotFound { delivery_id: i64 },
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
        let requested_at_unix_ns = unix_timestamp_nanos_to_sql(request.requested_at)?;
        let expires_at_unix_ns = unix_timestamp_nanos_to_sql(request.expires_at)?;

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
                created_trace_id,
                requested_at_unix_ns,
                expires_at_unix_ns
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#,
            params![
                request.id,
                request.env,
                kind,
                request.subject,
                request.reason,
                context_json,
                format_rfc3339_utc(request.requested_at),
                default_scope,
                auto_deny_after_ms,
                status,
                request.driver_name,
                request.driver_request_handle,
                format_rfc3339_utc(request.expires_at),
                request.created_trace_id,
                requested_at_unix_ns,
                expires_at_unix_ns,
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

        sql.push_str(" ORDER BY requested_at_unix_ns ASC, id ASC");

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
        let terminal_status = match decision.decision {
            ApprovalDecisionValue::Allow => ApprovalStatus::Approved,
            ApprovalDecisionValue::Deny => ApprovalStatus::Denied,
        };
        let changed = tx.execute(
            "UPDATE approval_requests SET status = ?1 WHERE id = ?2 AND status = ?3",
            params![
                enum_to_db_string(terminal_status, "status")?,
                decision.request_id,
                enum_to_db_string(ApprovalStatus::Pending, "status")?
            ],
        )?;
        if changed == 0 {
            return match request_status_in_transaction(&tx, &decision.request_id)? {
                Some(_) => Err(ApprovalStoreError::AlreadyDecided {
                    request_id: decision.request_id.clone(),
                }),
                None => Err(ApprovalStoreError::NotFound {
                    request_id: decision.request_id.clone(),
                }),
            };
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
                format_rfc3339_utc(decision.decided_at),
                decision.reason,
                context_json,
                decision.trace_id,
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

    pub fn enqueue_delivery_attempt(
        &self,
        request_id: &str,
        target_id: i64,
        next_attempt_at: OffsetDateTime,
    ) -> Result<(), ApprovalStoreError> {
        let conn = self.connection()?;
        conn.execute(
            r#"
            INSERT INTO approval_delivery_attempts (
                request_id,
                target_id,
                status,
                attempt_count,
                next_attempt_at,
                last_error,
                last_attempt_at
            )
            VALUES (?1, ?2, ?3, 0, ?4, NULL, NULL)
            "#,
            params![
                request_id,
                target_id,
                "pending",
                format_rfc3339_utc(next_attempt_at)
            ],
        )?;
        Ok(())
    }

    pub fn record_delivery_failure(
        &self,
        delivery_id: i64,
        next_attempt_at: OffsetDateTime,
        error: &str,
    ) -> Result<(), ApprovalStoreError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let Some(status) = delivery_status_in_transaction(&tx, delivery_id)? else {
            return Err(ApprovalStoreError::DeliveryNotFound { delivery_id });
        };

        if status == "delivered" {
            tx.commit()?;
            return Ok(());
        }

        tx.execute(
            r#"
            UPDATE approval_delivery_attempts
            SET
                status = ?1,
                attempt_count = attempt_count + 1,
                next_attempt_at = ?2,
                last_error = ?3,
                last_attempt_at = ?4
            WHERE id = ?5
            "#,
            params![
                "pending",
                format_rfc3339_utc(next_attempt_at),
                error,
                format_rfc3339_utc(OffsetDateTime::now_utc()),
                delivery_id
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_delivery_success(&self, delivery_id: i64) -> Result<(), ApprovalStoreError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let Some(status) = delivery_status_in_transaction(&tx, delivery_id)? else {
            return Err(ApprovalStoreError::DeliveryNotFound { delivery_id });
        };

        if status == "delivered" {
            tx.commit()?;
            return Ok(());
        }

        tx.execute(
            r#"
            UPDATE approval_delivery_attempts
            SET
                status = ?1,
                attempt_count = attempt_count + 1,
                last_error = NULL,
                last_attempt_at = ?2
            WHERE id = ?3
            "#,
            params![
                "delivered",
                format_rfc3339_utc(OffsetDateTime::now_utc()),
                delivery_id
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn due_pending_requests(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let conn = self.connection()?;
        let sql = request_select_sql(
            "WHERE status = ?1 AND expires_at_unix_ns <= ?2 ORDER BY expires_at_unix_ns ASC, id ASC",
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_and_then(
            params![
                enum_to_db_string(ApprovalStatus::Pending, "status")?,
                unix_timestamp_nanos_to_sql(now)?
            ],
            request_from_row,
        )?;
        collect_rows(rows)
    }

    pub fn expire_without_waiter(
        &self,
        request_id: &str,
        now: OffsetDateTime,
    ) -> Result<(), ApprovalStoreError> {
        let conn = self.connection()?;
        let changed = conn.execute(
            "UPDATE approval_requests SET status = ?1 WHERE id = ?2 AND status = ?3 AND expires_at_unix_ns <= ?4",
            params![
                enum_to_db_string(ApprovalStatus::Expired, "status")?,
                request_id,
                enum_to_db_string(ApprovalStatus::Pending, "status")?,
                unix_timestamp_nanos_to_sql(now)?
            ],
        )?;

        if changed == 0 {
            let Some(request) = self.get_request(request_id)? else {
                return Err(ApprovalStoreError::NotFound {
                    request_id: request_id.to_owned(),
                });
            };
            if request.status != ApprovalStatus::Pending {
                return Err(ApprovalStoreError::AlreadyDecided {
                    request_id: request_id.to_owned(),
                });
            }
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
              created_trace_id TEXT NOT NULL,
              requested_at_unix_ns INTEGER NOT NULL,
              expires_at_unix_ns INTEGER NOT NULL
            );

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
              next_attempt_at TEXT NOT NULL,
              last_error TEXT,
              last_attempt_at TEXT
            );
            "#,
        )?;
        migrate_request_timestamp_columns(&conn)?;
        recreate_request_timestamp_indexes(&conn)?;
        add_column_if_missing(&conn, "approval_delivery_attempts", "last_error", "TEXT")?;
        add_column_if_missing(
            &conn,
            "approval_delivery_attempts",
            "last_attempt_at",
            "TEXT",
        )?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection, ApprovalStoreError> {
        create_private_database_file(&self.path)?;
        let path = database_open_path(&self.path)?;
        Ok(Connection::open_with_flags(path, database_open_flags())?)
    }
}

#[cfg(unix)]
fn database_open_path(path: &Path) -> Result<PathBuf, ApprovalStoreError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| ApprovalStoreError::UnsafeDatabasePath {
            path: path.to_owned(),
        })?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    Ok(std::fs::canonicalize(parent)?.join(file_name))
}

#[cfg(not(unix))]
fn database_open_path(path: &Path) -> Result<PathBuf, ApprovalStoreError> {
    Ok(path.to_owned())
}

fn database_open_flags() -> OpenFlags {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;

    #[cfg(unix)]
    {
        flags | OpenFlags::SQLITE_OPEN_NOFOLLOW
    }

    #[cfg(not(unix))]
    {
        flags
    }
}

#[cfg(unix)]
fn create_private_database_file(path: &Path) -> Result<(), ApprovalStoreError> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::unix::fs::OpenOptionsExt;

    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            harden_existing_database_file(path)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn harden_existing_database_file(path: &Path) -> Result<(), ApprovalStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(ApprovalStoreError::UnsafeDatabasePath {
            path: path.to_owned(),
        });
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn create_private_database_file(_path: &Path) -> Result<(), ApprovalStoreError> {
    Ok(())
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

fn format_rfc3339_utc(value: OffsetDateTime) -> String {
    format_rfc3339(value.to_offset(UtcOffset::UTC))
}

fn migrate_request_timestamp_columns(conn: &Connection) -> Result<(), ApprovalStoreError> {
    add_column_if_missing(
        conn,
        "approval_requests",
        "requested_at_unix_ns",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(
        conn,
        "approval_requests",
        "expires_at_unix_ns",
        "INTEGER NOT NULL DEFAULT 0",
    )?;

    let rows = {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, requested_at, expires_at
            FROM approval_requests
            WHERE requested_at_unix_ns IS NULL
               OR requested_at_unix_ns = 0
               OR expires_at_unix_ns IS NULL
               OR expires_at_unix_ns = 0
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut collected = Vec::new();
        for row in rows {
            collected.push(row?);
        }
        collected
    };

    for (id, requested_at, expires_at) in rows {
        let requested_at_unix_ns = unix_timestamp_nanos_to_sql(parse_rfc3339(requested_at)?)?;
        let expires_at_unix_ns = unix_timestamp_nanos_to_sql(parse_rfc3339(expires_at)?)?;
        conn.execute(
            r#"
            UPDATE approval_requests
            SET requested_at_unix_ns = ?1,
                expires_at_unix_ns = ?2
            WHERE id = ?3
            "#,
            params![requested_at_unix_ns, expires_at_unix_ns, id],
        )?;
    }

    Ok(())
}

fn recreate_request_timestamp_indexes(conn: &Connection) -> Result<(), ApprovalStoreError> {
    conn.execute_batch(
        r#"
        DROP INDEX IF EXISTS approval_requests_env_status_requested_at_idx;
        DROP INDEX IF EXISTS approval_requests_status_expires_at_idx;

        CREATE INDEX approval_requests_env_status_requested_at_idx
          ON approval_requests(env, status, requested_at_unix_ns);
        CREATE INDEX approval_requests_status_expires_at_idx
          ON approval_requests(status, expires_at_unix_ns);
        "#,
    )?;
    Ok(())
}

fn request_status_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
) -> Result<Option<ApprovalStatus>, ApprovalStoreError> {
    tx.query_row(
        "SELECT status FROM approval_requests WHERE id = ?1",
        params![request_id],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(enum_from_db_string)
    .transpose()
}

fn delivery_status_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    delivery_id: i64,
) -> Result<Option<String>, ApprovalStoreError> {
    Ok(tx
        .query_row(
            "SELECT status FROM approval_delivery_attempts WHERE id = ?1",
            params![delivery_id],
            |row| row.get(0),
        )
        .optional()?)
}

fn u64_to_sql_integer(value: u64) -> Result<i64, ApprovalStoreError> {
    i64::try_from(value).map_err(|error| {
        ApprovalStoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
    })
}

fn unix_timestamp_nanos_to_sql(value: OffsetDateTime) -> Result<i64, ApprovalStoreError> {
    let nanos = value.unix_timestamp_nanos();
    i64::try_from(nanos).map_err(|_| ApprovalStoreError::TimestampOutOfRange(nanos))
}

fn sql_integer_to_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), ApprovalStoreError> {
    if column_exists(conn, table, column)? {
        return Ok(());
    }

    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
    match conn.execute(&sql, []) {
        Ok(_) => Ok(()),
        Err(error) if is_duplicate_column_error(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, ApprovalStoreError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;

    for name in rows {
        if name? == column {
            return Ok(true);
        }
    }

    Ok(false)
}

fn is_duplicate_column_error(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(_, Some(message))
            if message.contains("duplicate column name")
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rusqlite::params;
    use serde_json::json;
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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

    #[cfg(unix)]
    #[test]
    fn sqlite_store_creates_database_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.db");

        let _store = ApprovalStore::open(&path).unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn non_utc_timestamps_are_normalized_for_due_selection() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.db");
        let store = ApprovalStore::open(&path).unwrap();

        let requested_at = OffsetDateTime::parse("2026-04-29T05:00:00-07:00", &Rfc3339).unwrap();
        let mut request = ApprovalRequest::new(
            "req-offset",
            "demo",
            ApprovalKind::EgressHost,
            "api.example.test:443",
            "network access",
            json!({"url": "https://api.example.test/v1"}),
            requested_at,
            ApprovalScope::Session,
            Duration::from_secs(30),
            "trace-offset",
        );
        request.expires_at = OffsetDateTime::parse("2026-04-29T05:00:30-07:00", &Rfc3339).unwrap();
        store.insert_request(&request).unwrap();

        let conn = Connection::open(&path).unwrap();
        let stored_requested_at: String = conn
            .query_row(
                "SELECT requested_at FROM approval_requests WHERE id = ?1",
                params!["req-offset"],
                |row| row.get(0),
            )
            .unwrap();
        let stored_expires_at: String = conn
            .query_row(
                "SELECT expires_at FROM approval_requests WHERE id = ?1",
                params!["req-offset"],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(stored_requested_at, "2026-04-29T12:00:00Z");
        assert_eq!(stored_expires_at, "2026-04-29T12:00:30Z");
        let now = OffsetDateTime::parse("2026-04-29T05:00:31-07:00", &Rfc3339).unwrap();
        assert_eq!(store.due_pending_requests(now).unwrap().len(), 1);
    }

    #[test]
    fn terminal_status_without_decision_returns_already_decided() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.db");
        let store = ApprovalStore::open(&path).unwrap();
        store.insert_request(&request("req-terminal", 0)).unwrap();

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE approval_requests SET status = ?1 WHERE id = ?2",
            params!["denied", "req-terminal"],
        )
        .unwrap();

        let error = store
            .record_decision(&decision("req-terminal"))
            .unwrap_err();

        assert!(
            matches!(error, ApprovalStoreError::AlreadyDecided { request_id } if request_id == "req-terminal")
        );
    }

    #[test]
    fn expire_without_waiter_does_not_expire_before_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        store.insert_request(&request("req-future", 60)).unwrap();

        let now = OffsetDateTime::from_unix_timestamp(1_777_443_240).unwrap();
        store.expire_without_waiter("req-future", now).unwrap();

        assert_eq!(
            store.get_request("req-future").unwrap().unwrap().status,
            ApprovalStatus::Pending
        );
    }

    #[test]
    fn fractional_expiry_later_in_same_second_is_not_due() {
        let temp = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open(temp.path().join("events.db")).unwrap();
        let mut request = request("req-fractional", 0);
        request.expires_at = OffsetDateTime::parse("2026-04-29T12:00:00.5Z", &Rfc3339).unwrap();
        store.insert_request(&request).unwrap();

        let now = OffsetDateTime::parse("2026-04-29T12:00:00Z", &Rfc3339).unwrap();

        assert!(store.due_pending_requests(now).unwrap().is_empty());
        store.expire_without_waiter("req-fractional", now).unwrap();
        assert_eq!(
            store.get_request("req-fractional").unwrap().unwrap().status,
            ApprovalStatus::Pending
        );
    }

    #[test]
    fn migration_backfills_legacy_timestamp_columns_for_due_pending_and_expire_without_waiter() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE approval_requests (
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

            CREATE INDEX approval_requests_env_status_requested_at_idx
              ON approval_requests(env, status, requested_at);
            CREATE INDEX approval_requests_status_expires_at_idx
              ON approval_requests(status, expires_at);
            "#,
        )
        .unwrap();
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
                "req-legacy",
                "demo",
                "egress_host",
                "api.example.test:443",
                "network access",
                r#"{"url":"https://api.example.test/v1"}"#,
                "2026-04-29T12:00:00Z",
                "session",
                30_000_i64,
                "pending",
                Option::<String>::None,
                Option::<String>::None,
                "2026-04-29T12:00:30Z",
                "trace-legacy",
            ],
        )
        .unwrap();
        drop(conn);

        let store = ApprovalStore::open(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        assert!(column_exists(&conn, "approval_requests", "requested_at_unix_ns").unwrap());
        assert!(column_exists(&conn, "approval_requests", "expires_at_unix_ns").unwrap());
        let stored_ns: (i64, i64) = conn
            .query_row(
                "SELECT requested_at_unix_ns, expires_at_unix_ns FROM approval_requests WHERE id = ?1",
                params!["req-legacy"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            stored_ns,
            (
                unix_timestamp_nanos_to_sql(
                    OffsetDateTime::parse("2026-04-29T12:00:00Z", &Rfc3339).unwrap()
                )
                .unwrap(),
                unix_timestamp_nanos_to_sql(
                    OffsetDateTime::parse("2026-04-29T12:00:30Z", &Rfc3339).unwrap()
                )
                .unwrap()
            )
        );

        let indexed_sql: Vec<String> = conn
            .prepare(
                r#"
                SELECT sql
                FROM sqlite_master
                WHERE type = 'index'
                  AND name IN (
                    'approval_requests_env_status_requested_at_idx',
                    'approval_requests_status_expires_at_idx'
                  )
                ORDER BY name
                "#,
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(indexed_sql.len(), 2);
        assert!(indexed_sql.iter().all(|sql| sql.contains("_unix_ns")));

        let rows = store
            .list_requests(ApprovalRequestFilter {
                env: Some("demo".to_owned()),
                status: Some(ApprovalStatus::Pending),
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "req-legacy");

        let now = OffsetDateTime::parse("2026-04-29T12:00:31Z", &Rfc3339).unwrap();
        let due = store.due_pending_requests(now).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "req-legacy");

        store.expire_without_waiter("req-legacy", now).unwrap();
        assert_eq!(
            store.get_request("req-legacy").unwrap().unwrap().status,
            ApprovalStatus::Expired
        );
    }

    #[test]
    fn delivery_attempt_failure_and_success_update_retry_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.db");
        let store = ApprovalStore::open(&path).unwrap();

        let first_retry = OffsetDateTime::parse("2026-04-29T12:00:01Z", &Rfc3339).unwrap();
        store
            .enqueue_delivery_attempt("req-1", 42, first_retry)
            .unwrap();

        let conn = Connection::open(&path).unwrap();
        let delivery_id: i64 = conn
            .query_row(
                "SELECT id FROM approval_delivery_attempts WHERE request_id = ?1",
                params!["req-1"],
                |row| row.get(0),
            )
            .unwrap();

        let second_retry = OffsetDateTime::parse("2026-04-29T12:00:02Z", &Rfc3339).unwrap();
        store
            .record_delivery_failure(delivery_id, second_retry, "http 503")
            .unwrap();

        let failed: (String, i64, String, Option<String>) = conn
            .query_row(
                "SELECT status, attempt_count, next_attempt_at, last_error FROM approval_delivery_attempts WHERE id = ?1",
                params![delivery_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(failed.0, "pending");
        assert_eq!(failed.1, 1);
        assert_eq!(failed.2, "2026-04-29T12:00:02Z");
        assert_eq!(failed.3.as_deref(), Some("http 503"));

        store.record_delivery_success(delivery_id).unwrap();

        let delivered: (String, i64, Option<String>) = conn
            .query_row(
                "SELECT status, attempt_count, last_error FROM approval_delivery_attempts WHERE id = ?1",
                params![delivery_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(delivered.0, "delivered");
        assert_eq!(delivered.1, 2);
        assert_eq!(delivered.2, None);
    }

    #[test]
    fn delivery_attempt_success_ignores_late_failure_and_duplicate_success() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.db");
        let store = ApprovalStore::open(&path).unwrap();

        let first_retry = OffsetDateTime::parse("2026-04-29T12:00:01Z", &Rfc3339).unwrap();
        store
            .enqueue_delivery_attempt("req-1", 42, first_retry)
            .unwrap();

        let conn = Connection::open(&path).unwrap();
        let delivery_id: i64 = conn
            .query_row(
                "SELECT id FROM approval_delivery_attempts WHERE request_id = ?1",
                params!["req-1"],
                |row| row.get(0),
            )
            .unwrap();

        store.record_delivery_success(delivery_id).unwrap();
        store.record_delivery_success(delivery_id).unwrap();

        let late_retry = OffsetDateTime::parse("2026-04-29T12:00:02Z", &Rfc3339).unwrap();
        store
            .record_delivery_failure(delivery_id, late_retry, "late timeout")
            .unwrap();

        let delivered: (String, i64, Option<String>) = conn
            .query_row(
                "SELECT status, attempt_count, last_error FROM approval_delivery_attempts WHERE id = ?1",
                params![delivery_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(delivered.0, "delivered");
        assert_eq!(delivered.1, 1);
        assert_eq!(delivered.2, None);
    }
}
