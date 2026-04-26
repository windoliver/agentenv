use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite activity store error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("activity store IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("activity event JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("activity event field {field} did not serialize to a string")]
    NonStringEnum { field: &'static str },
    #[error("activity event latency_ms is outside SQLite integer range: {0}")]
    LatencyOutOfRange(u64),
    #[error("activity event stored negative latency_ms: {0}")]
    NegativeLatency(i64),
    #[error("activity event count is outside u64 range: {0}")]
    CountOutOfRange(i64),
    #[error("unsafe activity database path: {path}")]
    UnsafeDatabasePath { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredEvent {
    pub id: i64,
    pub event: ActivityEvent,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventQuery {
    pub env: Option<String>,
    pub kind: Option<ActivityKind>,
    pub result: Option<ActivityResult>,
    pub after_id: Option<i64>,
    pub from_ts: Option<String>,
    pub to_ts: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCount {
    pub kind: ActivityKind,
    pub env: Option<String>,
    pub result: ActivityResult,
    pub count: u64,
}

pub struct SqliteEventStore {
    path: PathBuf,
}

impl SqliteEventStore {
    pub fn open(path: impl Into<PathBuf>) -> StoreResult<Self> {
        let store = Self { path: path.into() };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn migrate(&self) -> StoreResult<()> {
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
            CREATE TABLE IF NOT EXISTS activity_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              kind TEXT NOT NULL,
              env TEXT,
              actor_json TEXT NOT NULL,
              subject_json TEXT NOT NULL,
              result TEXT NOT NULL,
              latency_ms INTEGER,
              trace_id TEXT NOT NULL,
              reason_code TEXT,
              extras_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS activity_events_ts_idx ON activity_events(ts);
            CREATE INDEX IF NOT EXISTS activity_events_env_ts_idx ON activity_events(env, ts);
            CREATE INDEX IF NOT EXISTS activity_events_kind_ts_idx ON activity_events(kind, ts);
            CREATE INDEX IF NOT EXISTS activity_events_result_ts_idx ON activity_events(result, ts);
            "#,
        )?;
        Ok(())
    }

    pub fn append_many(&self, events: &[ActivityEvent]) -> StoreResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO activity_events (
                    ts,
                    kind,
                    env,
                    actor_json,
                    subject_json,
                    result,
                    latency_ms,
                    trace_id,
                    reason_code,
                    extras_json
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
            )?;

            for event in events {
                let kind = enum_to_db_string(event.kind, "kind")?;
                let result = enum_to_db_string(event.result, "result")?;
                let actor_json = serde_json::to_string(&event.actor)?;
                let subject_json = serde_json::to_string(&event.subject)?;
                let extras_json = serde_json::to_string(&event.extras)?;
                let latency_ms = match event.latency_ms {
                    Some(value) => Some(
                        i64::try_from(value).map_err(|_| StoreError::LatencyOutOfRange(value))?,
                    ),
                    None => None,
                };

                stmt.execute(params![
                    event.ts,
                    kind,
                    event.env,
                    actor_json,
                    subject_json,
                    result,
                    latency_ms,
                    event.trace_id,
                    event.reason_code,
                    extras_json,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn query(&self, query: EventQuery) -> StoreResult<Vec<StoredEvent>> {
        let conn = self.connection()?;
        let mut sql = String::from(
            r#"
            SELECT
                id,
                ts,
                kind,
                env,
                actor_json,
                subject_json,
                result,
                latency_ms,
                trace_id,
                reason_code,
                extras_json
            FROM activity_events
            WHERE 1 = 1
            "#,
        );
        let mut query_params = Vec::new();

        if let Some(env) = query.env {
            sql.push_str(" AND env = ?");
            query_params.push(SqlValue::Text(env));
        }
        if let Some(kind) = query.kind {
            sql.push_str(" AND kind = ?");
            query_params.push(SqlValue::Text(enum_to_db_string(kind, "kind")?));
        }
        if let Some(result) = query.result {
            sql.push_str(" AND result = ?");
            query_params.push(SqlValue::Text(enum_to_db_string(result, "result")?));
        }
        if let Some(after_id) = query.after_id {
            sql.push_str(" AND id > ?");
            query_params.push(SqlValue::Integer(after_id));
        }
        if let Some(from_ts) = query.from_ts {
            sql.push_str(" AND ts >= ?");
            query_params.push(SqlValue::Text(from_ts));
        }
        if let Some(to_ts) = query.to_ts {
            sql.push_str(" AND ts <= ?");
            query_params.push(SqlValue::Text(to_ts));
        }

        sql.push_str(" ORDER BY id DESC LIMIT ?");
        query_params.push(SqlValue::Integer(query.limit.clamp(1, 10_000) as i64));

        let mut stmt = conn.prepare(&sql)?;
        let raw_rows = stmt.query_map(params_from_iter(query_params), raw_event_from_row)?;
        let mut rows = Vec::new();
        for raw in raw_rows {
            rows.push(raw?.try_into_stored_event()?);
        }
        Ok(rows)
    }

    pub fn counts_by_kind_result(&self) -> StoreResult<Vec<EventCount>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT kind, env, result, COUNT(*)
            FROM activity_events
            GROUP BY kind, env, result
            ORDER BY kind ASC, env ASC, result ASC
            "#,
        )?;
        let raw_rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;

        let mut rows = Vec::new();
        for raw in raw_rows {
            let (kind, env, result, count) = raw?;
            rows.push(EventCount {
                kind: enum_from_db_string(kind)?,
                env,
                result: enum_from_db_string(result)?,
                count: u64::try_from(count).map_err(|_| StoreError::CountOutOfRange(count))?,
            });
        }
        Ok(rows)
    }

    fn connection(&self) -> StoreResult<Connection> {
        create_private_database_file(&self.path)?;
        Ok(Connection::open(&self.path)?)
    }
}

pub fn read_legacy_jsonl(
    path: impl AsRef<Path>,
    driver_filter: Option<&str>,
    kind_filter: Option<ActivityKind>,
) -> StoreResult<Vec<ActivityEvent>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let event = match parse_jsonl_activity_event(line) {
            Ok(event) => event,
            Err(_) => continue,
        };

        if let Some(kind) = kind_filter {
            if event.kind != kind {
                continue;
            }
        }
        if let Some(driver) = driver_filter {
            if event.actor.get("driver").and_then(Value::as_str) != Some(driver) {
                continue;
            }
        }

        events.push(event);
    }

    Ok(events)
}

#[cfg(unix)]
fn create_private_database_file(path: &Path) -> StoreResult<()> {
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
fn harden_existing_database_file(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::UnsafeDatabasePath {
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
fn create_private_database_file(_path: &Path) -> StoreResult<()> {
    Ok(())
}

#[derive(Debug)]
struct RawStoredEvent {
    id: i64,
    ts: String,
    kind: String,
    env: Option<String>,
    actor_json: String,
    subject_json: String,
    result: String,
    latency_ms: Option<i64>,
    trace_id: String,
    reason_code: Option<String>,
    extras_json: String,
}

impl RawStoredEvent {
    fn try_into_stored_event(self) -> StoreResult<StoredEvent> {
        let latency_ms = match self.latency_ms {
            Some(value) if value < 0 => return Err(StoreError::NegativeLatency(value)),
            Some(value) => {
                Some(u64::try_from(value).map_err(|_| StoreError::NegativeLatency(value))?)
            }
            None => None,
        };

        Ok(StoredEvent {
            id: self.id,
            event: ActivityEvent {
                ts: self.ts,
                kind: enum_from_db_string(self.kind)?,
                env: self.env,
                actor: serde_json::from_str(&self.actor_json)?,
                subject: serde_json::from_str(&self.subject_json)?,
                result: enum_from_db_string(self.result)?,
                latency_ms,
                trace_id: self.trace_id,
                reason_code: self.reason_code,
                extras: serde_json::from_str(&self.extras_json)?,
            },
        })
    }
}

fn raw_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawStoredEvent> {
    Ok(RawStoredEvent {
        id: row.get(0)?,
        ts: row.get(1)?,
        kind: row.get(2)?,
        env: row.get(3)?,
        actor_json: row.get(4)?,
        subject_json: row.get(5)?,
        result: row.get(6)?,
        latency_ms: row.get(7)?,
        trace_id: row.get(8)?,
        reason_code: row.get(9)?,
        extras_json: row.get(10)?,
    })
}

fn enum_to_db_string<T>(value: T, field: &'static str) -> StoreResult<String>
where
    T: Serialize,
{
    match serde_json::to_value(value)? {
        Value::String(value) => Ok(value),
        _ => Err(StoreError::NonStringEnum { field }),
    }
}

fn enum_from_db_string<T>(value: String) -> StoreResult<T>
where
    T: DeserializeOwned,
{
    Ok(serde_json::from_value(Value::String(value))?)
}

#[derive(Debug, Deserialize)]
struct LegacyJsonlEvent {
    ts: String,
    driver: Option<String>,
    level: Option<String>,
    msg: Option<String>,
}

fn legacy_json_value_to_activity(value: Value) -> StoreResult<ActivityEvent> {
    let legacy: LegacyJsonlEvent = serde_json::from_value(value)?;
    let mut event = ActivityEvent::new(
        legacy.ts,
        ActivityKind::Log,
        ActivityResult::Ok,
        "legacy-jsonl",
    );

    if let Some(driver) = legacy.driver {
        event = event.with_actor_value("driver", Value::String(driver));
    }
    if let Some(level) = legacy.level {
        event = event.with_extra("level", Value::String(level));
    }
    if let Some(msg) = legacy.msg {
        event = event.with_extra("msg", Value::String(msg));
    }

    Ok(event)
}

fn parse_jsonl_activity_event(line: &str) -> StoreResult<ActivityEvent> {
    let value: Value = serde_json::from_str(line)?;
    if value.get("kind").is_some() && value.get("result").is_some() {
        Ok(serde_json::from_value(value)?)
    } else {
        legacy_json_value_to_activity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

    fn event(ts: &str, kind: ActivityKind, env: &str, result: ActivityResult) -> ActivityEvent {
        ActivityEvent::new(ts, kind, result, "trace-store").with_env(env)
    }

    fn query_all(limit: usize) -> EventQuery {
        EventQuery {
            limit,
            ..EventQuery::default()
        }
    }

    #[test]
    fn sqlite_store_appends_and_filters_by_env_kind_result() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();

        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::SandboxCreate,
                    "demo",
                    ActivityResult::Ok,
                ),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::EgressDenied,
                    "demo",
                    ActivityResult::Denied,
                ),
                event(
                    "2026-04-26T12:00:02Z",
                    ActivityKind::EgressDenied,
                    "other",
                    ActivityResult::Denied,
                ),
            ])
            .unwrap();

        let rows = store
            .query(EventQuery {
                env: Some("demo".to_owned()),
                kind: Some(ActivityKind::EgressDenied),
                result: Some(ActivityResult::Denied),
                after_id: None,
                limit: 100,
                ..EventQuery::default()
            })
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event.env.as_deref(), Some("demo"));
        assert_eq!(rows[0].event.kind, ActivityKind::EgressDenied);
    }

    #[test]
    fn sqlite_store_queries_newest_rows_first_with_limit() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();

        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::SandboxCreate,
                    "demo",
                    ActivityResult::Ok,
                ),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::EgressAllowed,
                    "demo",
                    ActivityResult::Ok,
                ),
                event(
                    "2026-04-26T12:00:02Z",
                    ActivityKind::EgressDenied,
                    "demo",
                    ActivityResult::Denied,
                ),
            ])
            .unwrap();

        let rows = store.query(query_all(2)).unwrap();

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event.ts, "2026-04-26T12:00:02Z");
        assert_eq!(rows[1].event.ts, "2026-04-26T12:00:01Z");
    }

    #[test]
    fn sqlite_store_filters_by_timestamp_range() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();

        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::SandboxCreate,
                    "demo",
                    ActivityResult::Ok,
                ),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::EgressAllowed,
                    "demo",
                    ActivityResult::Ok,
                ),
                event(
                    "2026-04-26T12:00:02Z",
                    ActivityKind::EgressDenied,
                    "demo",
                    ActivityResult::Denied,
                ),
            ])
            .unwrap();

        let rows = store
            .query(EventQuery {
                from_ts: Some("2026-04-26T12:00:01Z".to_owned()),
                to_ts: Some("2026-04-26T12:00:01Z".to_owned()),
                limit: 100,
                ..EventQuery::default()
            })
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event.ts, "2026-04-26T12:00:01Z");
    }

    #[test]
    fn sqlite_store_clamps_zero_limit_to_one() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();

        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::SandboxCreate,
                    "demo",
                    ActivityResult::Ok,
                ),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::EgressDenied,
                    "demo",
                    ActivityResult::Denied,
                ),
            ])
            .unwrap();

        let rows = store.query(query_all(0)).unwrap();

        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn sqlite_store_counts_by_kind_env_and_result() {
        let temp = tempfile::tempdir().unwrap();
        let store = SqliteEventStore::open(temp.path().join("events.db")).unwrap();

        store
            .append_many(&[
                event(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::EgressDenied,
                    "demo",
                    ActivityResult::Denied,
                ),
                event(
                    "2026-04-26T12:00:01Z",
                    ActivityKind::EgressDenied,
                    "demo",
                    ActivityResult::Denied,
                ),
                event(
                    "2026-04-26T12:00:02Z",
                    ActivityKind::SandboxCreate,
                    "other",
                    ActivityResult::Ok,
                ),
            ])
            .unwrap();

        let counts = store.counts_by_kind_result().unwrap();

        assert!(counts
            .iter()
            .any(|count| count.kind == ActivityKind::EgressDenied
                && count.env.as_deref() == Some("demo")
                && count.result == ActivityResult::Denied
                && count.count == 2));
        assert!(counts
            .iter()
            .any(|count| count.kind == ActivityKind::SandboxCreate
                && count.env.as_deref() == Some("other")
                && count.result == ActivityResult::Ok
                && count.count == 1));
    }

    #[test]
    fn legacy_jsonl_reader_accepts_old_event_shape() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        std::fs::write(
            &path,
            "{\"ts\":\"2026-04-21T00:00:00Z\",\"driver\":\"context\",\"level\":\"info\",\"msg\":\"context ready\"}\n",
        )
        .unwrap();

        let rows = read_legacy_jsonl(&path, None, None).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, ActivityKind::Log);
        assert_eq!(rows[0].actor["driver"], serde_json::json!("context"));
        assert_eq!(rows[0].extras["msg"], serde_json::json!("context ready"));
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_store_creates_database_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.db");

        let _store = SqliteEventStore::open(&path).unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_store_rejects_symlink_database_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.db");
        let link = temp.path().join("events.db");
        std::fs::write(&target, "").unwrap();
        symlink(&target, &link).unwrap();

        assert!(SqliteEventStore::open(&link).is_err());
    }

    #[test]
    fn legacy_jsonl_reader_skips_malformed_lines() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        std::fs::write(
            &path,
            concat!(
                "{\"ts\":\"2026-04-21T00:00:00Z\",\"driver\":\"context\",\"level\":\"info\",\"msg\":\"context ready\"}\n",
                "{malformed json}\n",
                "{\"ts\":\"2026-04-21T00:00:01Z\",\"driver\":\"sandbox\",\"level\":\"warn\",\"msg\":\"sandbox ready\"}\n",
            ),
        )
        .unwrap();

        let rows = read_legacy_jsonl(&path, None, None).unwrap();

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].actor["driver"], serde_json::json!("context"));
        assert_eq!(rows[1].actor["driver"], serde_json::json!("sandbox"));
    }
}
