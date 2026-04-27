use std::{
    fs,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("failed to create event store directory `{path}`: {source}")]
    CreateDir {
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

    fn from_str(value: &str) -> Self {
        match value {
            "egress_denied" => Self::EgressDenied,
            "approval_requested" => Self::ApprovalRequested,
            "approval_allowed" => Self::ApprovalAllowed,
            "approval_denied" => Self::ApprovalDenied,
            "log" => Self::Log,
            _ => Self::Runtime,
        }
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
                    env TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    offset INTEGER NOT NULL
                );
                "#,
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })
    }

    pub fn append(&self, event: &StoredEvent) -> EventStoreResult<i64> {
        let metadata_json = serde_json::to_string(&event.metadata)
            .map_err(|source| EventStoreError::MetadataEncode { source })?;
        self.conn
            .execute(
                "INSERT INTO events (env, ts, kind, subject, reason, driver, handle, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.env,
                    event.ts,
                    event.kind.as_str(),
                    event.subject,
                    event.reason,
                    event.driver,
                    event.handle,
                    metadata_json
                ],
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_recent(
        &self,
        env: Option<&str>,
        limit: usize,
    ) -> EventStoreResult<Vec<StoredEvent>> {
        let sql_all = "SELECT id, env, ts, kind, subject, reason, driver, handle, metadata_json
             FROM events ORDER BY ts DESC, id DESC LIMIT ?1";
        let sql_env = "SELECT id, env, ts, kind, subject, reason, driver, handle, metadata_json
             FROM events WHERE env = ?1 ORDER BY ts DESC, id DESC LIMIT ?2";

        if let Some(env) = env {
            let mut stmt =
                self.conn
                    .prepare(sql_env)
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows = stmt.query(params![env, limit as i64]).map_err(|source| {
                EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }
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
            let rows =
                stmt.query(params![limit as i64])
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            collect_events(rows, &self.path)
        }
    }

    pub fn events_per_minute(&self) -> EventStoreResult<u64> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE unixepoch(ts) >= unixepoch('now') - 60",
                [],
                |row| row.get(0),
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(count.max(0) as u64)
    }
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

fn row_to_event(row: &rusqlite::Row<'_>, path: &Path) -> EventStoreResult<StoredEvent> {
    let metadata_json: String = row.get(8).map_err(|source| EventStoreError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = serde_json::from_str(&metadata_json)
        .map_err(|source| EventStoreError::MetadataDecode { source })?;
    let kind: String = row.get(3).map_err(|source| EventStoreError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
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
        kind: StoredEventKind::from_str(&kind),
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
}
