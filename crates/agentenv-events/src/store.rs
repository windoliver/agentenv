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
        let mut events = Vec::new();

        if let Some(env) = env {
            let mut stmt =
                self.conn
                    .prepare(sql_env)
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows = stmt
                .query_map(params![env, limit as i64], row_to_event)
                .map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            for row in rows {
                events.push(row.map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?);
            }
        } else {
            let mut stmt =
                self.conn
                    .prepare(sql_all)
                    .map_err(|source| EventStoreError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows = stmt
                .query_map(params![limit as i64], row_to_event)
                .map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            for row in rows {
                events.push(row.map_err(|source| EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?);
            }
        }

        Ok(events)
    }

    pub fn events_per_minute(&self) -> EventStoreResult<u64> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE ts >= datetime('now', '-60 seconds')",
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

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvent> {
    let metadata_json: String = row.get(8)?;
    let metadata = serde_json::from_str(&metadata_json)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
    let kind: String = row.get(3)?;
    Ok(StoredEvent {
        id: row.get(0)?,
        env: row.get(1)?,
        ts: row.get(2)?,
        kind: StoredEventKind::from_str(&kind),
        subject: row.get(4)?,
        reason: row.get(5)?,
        driver: row.get(6)?,
        handle: row.get(7)?,
        metadata,
    })
}
