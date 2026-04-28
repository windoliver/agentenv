use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MAX_LIST_RECENT_LIMIT: usize = 1_000;
const NANOS_PER_SECOND: i64 = 1_000_000_000;
const LEGACY_JSONL_FALLBACK_TS: &str = "1970-01-01T00:00:00Z";

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("failed to create event store directory `{path}`: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to {action} event file `{path}`: {source}")]
    FileIo {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sqlite event store error at `{path}`: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to encode event metadata: {source}")]
    MetadataEncode {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode event metadata: {source}")]
    MetadataDecode {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode event kind `{value}`")]
    KindDecode { value: String },
    #[error("failed to decode event timestamp `{ts}`: {source}")]
    TimestampDecode {
        ts: String,
        #[source]
        source: time::error::Parse,
    },
    #[error("event timestamp `{ts}` is outside the supported nanosecond range")]
    TimestampRange { ts: String },
}

pub type EventStoreResult<T> = Result<T, EventStoreError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredEventKind {
    EgressDenied,
    ApprovalRequested,
    ApprovalAllowed,
    ApprovalDenied,
    Log,
    Runtime,
}

impl StoredEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EgressDenied => "egress_denied",
            Self::ApprovalRequested => "approval_requested",
            Self::ApprovalAllowed => "approval_allowed",
            Self::ApprovalDenied => "approval_denied",
            Self::Log => "log",
            Self::Runtime => "runtime",
        }
    }

    fn from_str(value: &str) -> EventStoreResult<Self> {
        let kind = match value {
            "egress_denied" => Self::EgressDenied,
            "approval_requested" => Self::ApprovalRequested,
            "approval_allowed" => Self::ApprovalAllowed,
            "approval_denied" => Self::ApprovalDenied,
            "log" => Self::Log,
            "runtime" => Self::Runtime,
            _ => {
                return Err(EventStoreError::KindDecode {
                    value: value.to_owned(),
                });
            }
        };
        Ok(kind)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: Option<i64>,
    pub env: String,
    pub ts: String,
    pub kind: StoredEventKind,
    pub subject: String,
    pub reason: Option<String>,
    pub driver: Option<String>,
    pub handle: Option<String>,
    pub metadata: serde_json::Value,
}

impl StoredEvent {
    pub fn new(
        env: impl Into<String>,
        ts: impl Into<String>,
        kind: StoredEventKind,
        subject: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            env: env.into(),
            ts: ts.into(),
            kind,
            subject: subject.into(),
            reason: None,
            driver: None,
            handle: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventImportReport {
    pub imported: usize,
    pub skipped: usize,
}

pub fn default_store_path(root: &Path) -> PathBuf {
    root.join("ops.sqlite3")
}

pub struct LocalEventStore {
    path: PathBuf,
    conn: Connection,
}

impl LocalEventStore {
    pub fn open(root: &Path) -> EventStoreResult<Self> {
        fs::create_dir_all(root).map_err(|source| EventStoreError::CreateDir {
            path: root.to_path_buf(),
            source,
        })?;
        let path = default_store_path(root);
        let conn = Connection::open(&path).map_err(|source| EventStoreError::Sqlite {
            path: path.clone(),
            source,
        })?;
        let store = Self { path, conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    fn init_schema(&self) -> EventStoreResult<()> {
        self.conn
            .execute_batch(
                r#"
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    env TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    ts_epoch_nanos INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    reason TEXT,
                    driver TEXT,
                    handle TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_env_ts ON events(env, ts DESC);
                CREATE TABLE IF NOT EXISTS jsonl_offsets (
                    env TEXT NOT NULL,
                    path TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    PRIMARY KEY (env, path)
                );
                "#,
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        self.ensure_ts_epoch_nanos_column()?;
        self.ensure_jsonl_offsets_path_key()?;
        self.conn
            .execute_batch(
                r#"
                CREATE INDEX IF NOT EXISTS idx_events_ts_epoch_nanos_id
                    ON events(ts_epoch_nanos DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_events_env_ts_epoch_nanos_id
                    ON events(env, ts_epoch_nanos DESC, id DESC);
                "#,
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })
    }

    fn ensure_jsonl_offsets_path_key(&self) -> EventStoreResult<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, pk FROM pragma_table_info('jsonl_offsets')")
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let mut env_pk = 0;
        let mut path_pk = 0;
        for row in rows {
            let (name, pk) = row.map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
            if name == "env" {
                env_pk = pk;
            } else if name == "path" {
                path_pk = pk;
            }
        }
        drop(stmt);

        if env_pk == 1 && path_pk == 2 {
            return Ok(());
        }

        self.migrate_jsonl_offsets_path_key()
    }

    fn migrate_jsonl_offsets_path_key(&self) -> EventStoreResult<()> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let result = self
            .conn
            .execute_batch(
                r#"
                CREATE TABLE jsonl_offsets_new (
                    env TEXT NOT NULL,
                    path TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    PRIMARY KEY (env, path)
                );
                INSERT OR REPLACE INTO jsonl_offsets_new (env, path, offset)
                    SELECT env, path, offset FROM jsonl_offsets;
                DROP TABLE jsonl_offsets;
                ALTER TABLE jsonl_offsets_new RENAME TO jsonl_offsets;
                "#,
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            });

        match result {
            Ok(()) => self
                .conn
                .execute_batch("COMMIT")
                .map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }),
            Err(err) => {
                let rollback = self.conn.execute_batch("ROLLBACK");
                if let Err(source) = rollback {
                    return Err(EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    });
                }
                Err(err)
            }
        }
    }

    fn ensure_ts_epoch_nanos_column(&self) -> EventStoreResult<()> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('events') WHERE name = 'ts_epoch_nanos'
                )",
                [],
                |row| row.get(0),
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        if exists {
            return Ok(());
        }

        self.migrate_ts_epoch_nanos_column()
    }

    fn migrate_ts_epoch_nanos_column(&self) -> EventStoreResult<()> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let result = self
            .conn
            .execute(
                "ALTER TABLE events ADD COLUMN ts_epoch_nanos INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })
            .and_then(|_| self.backfill_ts_epoch_nanos());

        match result {
            Ok(()) => self
                .conn
                .execute_batch("COMMIT")
                .map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }),
            Err(err) => {
                let rollback = self.conn.execute_batch("ROLLBACK");
                if let Err(source) = rollback {
                    return Err(EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    });
                }
                Err(err)
            }
        }
    }

    fn backfill_ts_epoch_nanos(&self) -> EventStoreResult<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, ts FROM events")
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let mut updates = Vec::new();
        for row in rows {
            let (id, ts) = row.map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
            updates.push((id, parse_ts_epoch_nanos(&ts)?));
        }
        drop(stmt);

        for (id, ts_epoch_nanos) in updates {
            self.conn
                .execute(
                    "UPDATE events SET ts_epoch_nanos = ?1 WHERE id = ?2",
                    params![ts_epoch_nanos, id],
                )
                .map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
        }

        Ok(())
    }

    pub fn append(&self, event: &StoredEvent) -> EventStoreResult<i64> {
        insert_event(&self.conn, &self.path, event)
    }

    pub fn list_recent(
        &self,
        env: Option<&str>,
        limit: usize,
    ) -> EventStoreResult<Vec<StoredEvent>> {
        let sql_all = "SELECT id, env, ts, kind, subject, reason, driver, handle, metadata_json
             FROM events ORDER BY ts_epoch_nanos DESC, id DESC LIMIT ?1";
        let sql_env = "SELECT id, env, ts, kind, subject, reason, driver, handle, metadata_json
             FROM events WHERE env = ?1 ORDER BY ts_epoch_nanos DESC, id DESC LIMIT ?2";
        let limit = bounded_list_recent_limit(limit);

        if let Some(env) = env {
            let mut stmt =
                self.conn
                    .prepare(sql_env)
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows =
                stmt.query(params![env, limit])
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            collect_events(rows, &self.path)
        } else {
            let mut stmt =
                self.conn
                    .prepare(sql_all)
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows = stmt
                .query(params![limit])
                .map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            collect_events(rows, &self.path)
        }
    }

    pub fn import_env_jsonl(
        &self,
        env: &str,
        events_path: &Path,
    ) -> EventStoreResult<EventImportReport> {
        let mut file = match fs::File::open(events_path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(EventImportReport {
                    imported: 0,
                    skipped: 0,
                });
            }
            Err(source) => {
                return Err(EventStoreError::FileIo {
                    action: "open",
                    path: events_path.to_path_buf(),
                    source,
                });
            }
        };

        let len = file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| EventStoreError::FileIo {
                action: "read metadata for",
                path: events_path.to_path_buf(),
                source,
            })?;
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let result = (|| {
            let stored_offset = self.jsonl_offset(env, events_path)?;
            let start = if stored_offset <= len {
                stored_offset
            } else {
                0
            };
            file.seek(SeekFrom::Start(start))
                .map_err(|source| EventStoreError::FileIo {
                    action: "seek",
                    path: events_path.to_path_buf(),
                    source,
                })?;

            let mut content = String::new();
            file.read_to_string(&mut content)
                .map_err(|source| EventStoreError::FileIo {
                    action: "read",
                    path: events_path.to_path_buf(),
                    source,
                })?;

            let complete_len = content
                .rfind('\n')
                .map(|last_newline| last_newline + 1)
                .unwrap_or(0);
            let complete_content = &content[..complete_len];
            let offset = start + complete_len as u64;
            let mut imported = 0;
            let mut skipped = 0;
            let mut events = Vec::new();
            for line in complete_content
                .lines()
                .filter(|line| !line.trim().is_empty())
            {
                match event_from_jsonl_line(env, line) {
                    Some(event) => {
                        events.push(event);
                        imported += 1;
                    }
                    None => skipped += 1,
                }
            }

            for event in events {
                insert_event(&self.conn, &self.path, &event)?;
            }
            self.set_jsonl_offset(env, events_path, offset)?;
            Ok(EventImportReport { imported, skipped })
        })();

        match result {
            Ok(report) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
                Ok(report)
            }
            Err(err) => {
                let rollback = self.conn.execute_batch("ROLLBACK");
                if let Err(source) = rollback {
                    return Err(EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    });
                }
                Err(err)
            }
        }
    }

    fn jsonl_offset(&self, env: &str, events_path: &Path) -> EventStoreResult<u64> {
        match self.conn.query_row(
            "SELECT offset FROM jsonl_offsets WHERE env = ?1 AND path = ?2",
            params![env, jsonl_path_key(events_path)],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(offset) => Ok(offset.max(0) as u64),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(source) => Err(EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            }),
        }
    }

    fn set_jsonl_offset(&self, env: &str, events_path: &Path, offset: u64) -> EventStoreResult<()> {
        self.conn
            .execute(
                "INSERT INTO jsonl_offsets (env, path, offset) VALUES (?1, ?2, ?3)
                 ON CONFLICT(env, path) DO UPDATE SET offset = excluded.offset",
                params![env, jsonl_path_key(events_path), offset as i64],
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    pub fn events_per_minute(&self) -> EventStoreResult<u64> {
        let upper = current_epoch_nanos()?;
        let lower = upper.saturating_sub(60 * NANOS_PER_SECOND);
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE ts_epoch_nanos BETWEEN ?1 AND ?2",
                params![lower, upper],
                |row| row.get(0),
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(count.max(0) as u64)
    }
}

fn insert_event(conn: &Connection, path: &Path, event: &StoredEvent) -> EventStoreResult<i64> {
    let metadata_json = serde_json::to_string(&event.metadata)
        .map_err(|source| EventStoreError::MetadataEncode { source })?;
    let ts_epoch_nanos = parse_ts_epoch_nanos(&event.ts)?;
    conn.execute(
        "INSERT INTO events (
            env, ts, ts_epoch_nanos, kind, subject, reason, driver, handle, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            event.env,
            event.ts,
            ts_epoch_nanos,
            event.kind.as_str(),
            event.subject,
            event.reason,
            event.driver,
            event.handle,
            metadata_json
        ],
    )
    .map_err(|source| EventStoreError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(conn.last_insert_rowid())
}

fn jsonl_path_key(events_path: &Path) -> String {
    events_path.display().to_string()
}

fn collect_events(mut rows: rusqlite::Rows<'_>, path: &Path) -> EventStoreResult<Vec<StoredEvent>> {
    let mut events = Vec::new();
    while let Some(row) = rows.next().map_err(|source| EventStoreError::Sqlite {
        path: path.to_path_buf(),
        source,
    })? {
        events.push(row_to_event(row, path)?);
    }
    Ok(events)
}

fn event_from_jsonl_line(env: &str, line: &str) -> Option<StoredEvent> {
    let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
    let ts = value
        .get("ts")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(LEGACY_JSONL_FALLBACK_TS);
    parse_ts_epoch_nanos(ts).ok()?;
    let kind = value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .map(StoredEventKind::from_str)
        .map(|kind| kind.unwrap_or(StoredEventKind::Runtime))
        .unwrap_or(StoredEventKind::Log);
    let subject = value
        .get("subject")
        .or_else(|| value.get("msg"))
        .or_else(|| value.get("message"))
        .or_else(|| value.get("kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("event");
    let mut event = StoredEvent::new(env, ts, kind, subject);
    event.reason = value
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    event.driver = value
        .get("driver")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    event.handle = value
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    event.metadata = value;
    Some(event)
}

fn bounded_list_recent_limit(limit: usize) -> i64 {
    limit.min(MAX_LIST_RECENT_LIMIT) as i64
}

fn current_epoch_nanos() -> EventStoreResult<i64> {
    epoch_nanos_to_i64("now", OffsetDateTime::now_utc().unix_timestamp_nanos())
}

fn parse_ts_epoch_nanos(ts: &str) -> EventStoreResult<i64> {
    let parsed =
        OffsetDateTime::parse(ts, &Rfc3339).map_err(|source| EventStoreError::TimestampDecode {
            ts: ts.to_owned(),
            source,
        })?;
    epoch_nanos_to_i64(ts, parsed.unix_timestamp_nanos())
}

fn epoch_nanos_to_i64(ts: &str, nanos: i128) -> EventStoreResult<i64> {
    i64::try_from(nanos).map_err(|_| EventStoreError::TimestampRange { ts: ts.to_owned() })
}

fn row_to_event(row: &rusqlite::Row<'_>, path: &Path) -> EventStoreResult<StoredEvent> {
    let metadata_json: String = row.get(8).map_err(|source| EventStoreError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = serde_json::from_str(&metadata_json)
        .map_err(|source| EventStoreError::MetadataDecode { source })?;
    let kind_value: String = row.get(3).map_err(|source| EventStoreError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
    let kind = StoredEventKind::from_str(&kind_value)?;
    Ok(StoredEvent {
        id: row.get(0).map_err(|source| EventStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?,
        env: row.get(1).map_err(|source| EventStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?,
        ts: row.get(2).map_err(|source| EventStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?,
        kind,
        subject: row.get(4).map_err(|source| EventStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?,
        reason: row.get(5).map_err(|source| EventStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?,
        driver: row.get(6).map_err(|source| EventStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?,
        handle: row.get(7).map_err(|source| EventStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

    use super::{EventStoreError, LocalEventStore, StoredEvent, StoredEventKind};

    #[test]
    fn events_per_minute_excludes_old_rfc3339_same_day_event() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");
        let now = OffsetDateTime::now_utc();
        let old_ts = (now - Duration::minutes(2))
            .format(&Rfc3339)
            .expect("format old timestamp");
        let current_ts = now.format(&Rfc3339).expect("format current timestamp");

        store
            .append(&StoredEvent::new(
                "dev",
                old_ts,
                StoredEventKind::Log,
                "old event",
            ))
            .expect("append old event");
        store
            .append(&StoredEvent::new(
                "dev",
                current_ts,
                StoredEventKind::Log,
                "current event",
            ))
            .expect("append current event");

        assert_eq!(store.events_per_minute().expect("count events"), 1);
    }

    #[test]
    fn events_per_minute_excludes_future_rfc3339_event() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");
        let now = OffsetDateTime::now_utc();
        let current_ts = now.format(&Rfc3339).expect("format current timestamp");
        let future_ts = (now + Duration::minutes(2))
            .format(&Rfc3339)
            .expect("format future timestamp");

        store
            .append(&StoredEvent::new(
                "dev",
                current_ts,
                StoredEventKind::Log,
                "current event",
            ))
            .expect("append current event");
        store
            .append(&StoredEvent::new(
                "dev",
                future_ts,
                StoredEventKind::Log,
                "future event",
            ))
            .expect("append future event");

        assert_eq!(store.events_per_minute().expect("count events"), 1);
    }

    #[test]
    fn list_recent_orders_rfc3339_offsets_by_instant() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T08:30:00-04:00",
                StoredEventKind::Log,
                "later by instant",
            ))
            .expect("append later event");
        store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T12:00:00Z",
                StoredEventKind::Log,
                "earlier by instant",
            ))
            .expect("append earlier event");

        let events = store.list_recent(None, 10).expect("list recent events");

        assert_eq!(events[0].subject, "later by instant");
        assert_eq!(events[1].subject, "earlier by instant");
    }

    #[test]
    fn list_recent_orders_fractional_rfc3339_timestamps_by_instant() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T12:00:00.900Z",
                StoredEventKind::Log,
                "later by fraction",
            ))
            .expect("append later event");
        store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T12:00:00.100Z",
                StoredEventKind::Log,
                "earlier by fraction",
            ))
            .expect("append earlier event");

        let events = store.list_recent(None, 10).expect("list recent events");

        assert_eq!(events[0].subject, "later by fraction");
        assert_eq!(events[1].subject, "earlier by fraction");
    }

    #[test]
    fn list_recent_orders_submillisecond_rfc3339_timestamps_by_instant() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T12:00:00.000002Z",
                StoredEventKind::Log,
                "later by nanos",
            ))
            .expect("append later event");
        store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T12:00:00.000001Z",
                StoredEventKind::Log,
                "earlier by nanos",
            ))
            .expect("append earlier event");

        let events = store.list_recent(None, 10).expect("list recent events");

        assert_eq!(events[0].subject, "later by nanos");
        assert_eq!(events[1].subject, "earlier by nanos");
    }

    #[test]
    fn local_store_creates_parsed_time_indexes() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        for name in [
            "idx_events_ts_epoch_nanos_id",
            "idx_events_env_ts_epoch_nanos_id",
        ] {
            let sql: String = store
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?1",
                    [name],
                    |row| row.get(0),
                )
                .expect("index exists");

            assert!(
                sql.contains("ts_epoch_nanos"),
                "index `{name}` did not include normalized timestamp column: {sql}"
            );
        }
    }

    #[test]
    fn open_backfills_epoch_nanos_for_old_schema_events() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = super::default_store_path(root.path());
        let conn = rusqlite::Connection::open(&path).expect("open old database");
        conn.execute_batch(
            r#"
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                env TEXT NOT NULL,
                ts TEXT NOT NULL,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                reason TEXT,
                driver TEXT,
                handle TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            INSERT INTO events (env, ts, kind, subject, metadata_json)
            VALUES
                ('dev', '2026-04-27T12:00:00.000002Z', 'log', 'later old row', '{}'),
                ('dev', '2026-04-27T12:00:00.000001Z', 'log', 'earlier old row', '{}');
            "#,
        )
        .expect("seed old schema");
        drop(conn);

        let store = LocalEventStore::open(root.path()).expect("migrate old database");
        let events = store.list_recent(None, 10).expect("list recent events");

        assert_eq!(events[0].subject, "later old row");
        assert_eq!(events[1].subject, "earlier old row");
    }

    #[test]
    fn failed_old_schema_backfill_retries_on_next_open() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = super::default_store_path(root.path());
        let conn = rusqlite::Connection::open(&path).expect("open old database");
        conn.execute_batch(
            r#"
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                env TEXT NOT NULL,
                ts TEXT NOT NULL,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                reason TEXT,
                driver TEXT,
                handle TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            INSERT INTO events (env, ts, kind, subject, metadata_json)
            VALUES ('dev', 'not-a-timestamp', 'log', 'bad old row', '{}');
            "#,
        )
        .expect("seed invalid old schema");
        drop(conn);

        let first = LocalEventStore::open(root.path());
        assert!(matches!(
            first,
            Err(EventStoreError::TimestampDecode { .. })
        ));

        let second = LocalEventStore::open(root.path());
        assert!(matches!(
            second,
            Err(EventStoreError::TimestampDecode { .. })
        ));
    }

    #[test]
    fn append_rejects_invalid_rfc3339_timestamp() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        let result = store.append(&StoredEvent::new(
            "dev",
            "not-a-timestamp",
            StoredEventKind::Log,
            "event",
        ));

        assert!(matches!(
            result,
            Err(EventStoreError::TimestampDecode { .. })
        ));
    }

    #[test]
    fn list_recent_errors_on_corrupt_metadata_json() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");
        let id = store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T12:00:00Z",
                StoredEventKind::Log,
                "event",
            ))
            .expect("append event");

        store
            .conn
            .execute(
                "UPDATE events SET metadata_json = ?1 WHERE id = ?2",
                rusqlite::params!["{", id],
            )
            .expect("corrupt metadata");

        let result = store.list_recent(None, 10);

        assert!(matches!(
            result,
            Err(EventStoreError::MetadataDecode { .. })
        ));
    }

    #[test]
    fn list_recent_huge_limit_is_bounded() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        for index in 0..1_001 {
            store
                .append(&StoredEvent::new(
                    "dev",
                    format!("2026-04-27T12:{:02}:00Z", index % 60),
                    StoredEventKind::Log,
                    format!("event-{index}"),
                ))
                .expect("append event");
        }

        let events = store
            .list_recent(None, usize::MAX)
            .expect("list recent events");

        assert_eq!(events.len(), 1_000);
    }

    #[test]
    fn list_recent_errors_on_unknown_event_kind() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");
        let id = store
            .append(&StoredEvent::new(
                "dev",
                "2026-04-27T12:00:00Z",
                StoredEventKind::Log,
                "event",
            ))
            .expect("append event");

        store
            .conn
            .execute(
                "UPDATE events SET kind = ?1 WHERE id = ?2",
                rusqlite::params!["surprise", id],
            )
            .expect("corrupt kind");

        let result = store.list_recent(None, 10);

        assert!(matches!(result, Err(EventStoreError::KindDecode { .. })));
    }
}
