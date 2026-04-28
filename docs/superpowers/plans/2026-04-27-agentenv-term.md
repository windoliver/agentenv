# agentenv term Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the full local `agentenv term` operator TUI from issue #24, including durable local events, approvals, command mode destroy, and monochrome rendering.

**Architecture:** `agentenv-events` owns `~/.agentenv/ops.sqlite3` activity events and legacy JSONL import. `agentenv-approvals` owns approval request and decision tables in the same database and emits decision events. `crates/tui` owns app state, rendering, key handling, and a backend trait; `crates/agentenv` wires the CLI to a local backend that calls existing runtime functions.

**Tech Stack:** Rust 2021, `ratatui`, `crossterm`, `tokio`, `rusqlite` with bundled SQLite, `serde_json`, existing `agentenv-core` runtime APIs, and `portable-pty` for CLI terminal smoke tests.

---

## File Structure

- Modify `Cargo.toml`: add workspace `rusqlite` dependency.
- Modify `crates/agentenv-events/Cargo.toml`: add `rusqlite`, `serde`, `serde_json`, `thiserror`, `time`, and `tempfile` dev dependency.
- Replace `crates/agentenv-events/src/lib.rs`: public event model, local store, JSONL import tests.
- Create `crates/agentenv-events/src/store.rs`: SQLite schema, append/query/import logic.
- Modify `crates/agentenv-approvals/Cargo.toml`: add `agentenv-events`, `agentenv-proto`, `rusqlite`, `serde`, `serde_json`, `thiserror`, `time`, and `tempfile` dev dependency.
- Replace `crates/agentenv-approvals/src/lib.rs`: approval model, local approval store, tests.
- Modify `crates/tui/Cargo.toml`: add `agentenv-core`, `agentenv-events`, `agentenv-approvals`, `agentenv-proto`, `anyhow`, `async-trait`, `crossterm`, `ratatui`, `serde`, `tokio`, and `time`.
- Replace `crates/tui/src/lib.rs`: public module exports and `run_terminal`.
- Create `crates/tui/src/model.rs`: UI snapshot, row, detail, pane, mode, command, and theme-independent app state types.
- Create `crates/tui/src/backend.rs`: `OpsBackend` trait and backend command result types.
- Create `crates/tui/src/command.rs`: command mode parser.
- Create `crates/tui/src/app.rs`: reducer-style key handling and dirty-state management.
- Create `crates/tui/src/render.rs`: ratatui rendering for normal, logs, policy, and help views.
- Create `crates/tui/src/theme.rs`: color and monochrome style selection.
- Create `crates/tui/src/terminal.rs`: crossterm setup, async input bridge, refresh loop, and terminal teardown.
- Modify `crates/agentenv/Cargo.toml`: add local `agentenv-tui`, `agentenv-events`, `agentenv-approvals`, `async-trait`, `crossterm`, `time`, and `portable-pty` dev dependency.
- Modify `crates/agentenv/src/main.rs`: add `term` subcommand and delegate to `run_term`.
- Create `crates/agentenv/src/term_backend.rs`: local `OpsBackend` implementation using `agentenv_core::runtime`, event store, and approval store.
- Modify `crates/agentenv/tests/cli_behavior.rs`: add help, remote unsupported, PTY smoke, and local destroy/event coverage where integration-accessible.

## Task 1: Event Store Schema And Basic Query

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agentenv-events/Cargo.toml`
- Replace: `crates/agentenv-events/src/lib.rs`
- Create: `crates/agentenv-events/src/store.rs`

- [ ] **Step 1: Write the failing event store schema test**

Replace `crates/agentenv-events/src/lib.rs` with this public surface and first test:

```rust
#![forbid(unsafe_code)]

mod store;

pub use store::{
    default_store_path, EventImportReport, LocalEventStore, StoredEvent, StoredEventKind,
};

#[cfg(test)]
mod tests {
    use super::{default_store_path, LocalEventStore};

    #[test]
    fn local_store_initializes_ops_database() {
        let root = tempfile::tempdir().expect("tempdir");

        let store = LocalEventStore::open(root.path()).expect("open event store");

        assert_eq!(store.path(), default_store_path(root.path()));
        assert!(store
            .list_recent(None, 10)
            .expect("list recent events")
            .is_empty());
    }
}
```

- [ ] **Step 2: Run the test and verify it fails for missing implementation**

Run:

```bash
cargo test -p agentenv-events local_store_initializes_ops_database
```

Expected: FAIL with unresolved imports for `store`, `LocalEventStore`, or `default_store_path`.

- [ ] **Step 3: Add dependencies and minimal event store implementation**

In workspace `Cargo.toml`, add this dependency under `[workspace.dependencies]`:

```toml
rusqlite = { version = "0.32", features = ["bundled"] }
```

Update `crates/agentenv-events/Cargo.toml`:

```toml
[dependencies]
agentenv-core = { path = "../agentenv-core" }
agentenv-proto = { path = "../agentenv-proto" }
rusqlite.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
time.workspace = true

[dev-dependencies]
tempfile = "=3.16.0"
```

Create `crates/agentenv-events/src/store.rs`:

```rust
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
        let metadata_json =
            serde_json::to_string(&event.metadata).map_err(|source| EventStoreError::MetadataEncode {
                source,
            })?;
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
        let sql_all =
            "SELECT id, env, ts, kind, subject, reason, driver, handle, metadata_json
             FROM events ORDER BY ts DESC, id DESC LIMIT ?1";
        let sql_env =
            "SELECT id, env, ts, kind, subject, reason, driver, handle, metadata_json
             FROM events WHERE env = ?1 ORDER BY ts DESC, id DESC LIMIT ?2";
        let mut events = Vec::new();

        if let Some(env) = env {
            let mut stmt = self.conn.prepare(sql_env).map_err(|source| {
                EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }
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
            let mut stmt = self.conn.prepare(sql_all).map_err(|source| {
                EventStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }
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
    let metadata = serde_json::from_str(&metadata_json).unwrap_or_else(|_| {
        serde_json::Value::Object(serde_json::Map::new())
    });
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
```

- [ ] **Step 4: Run the test and verify it passes**

Run:

```bash
cargo test -p agentenv-events local_store_initializes_ops_database
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/agentenv-events/Cargo.toml crates/agentenv-events/src/lib.rs crates/agentenv-events/src/store.rs
git commit -m "feat(events): add local ops event store"
```

## Task 2: Event Append, Filtering, Metrics, And JSONL Import

**Files:**
- Modify: `crates/agentenv-events/src/lib.rs`
- Modify: `crates/agentenv-events/src/store.rs`

- [ ] **Step 1: Add failing event behavior tests**

Append these tests to `crates/agentenv-events/src/lib.rs`:

```rust
    use super::{StoredEvent, StoredEventKind};
    use std::{fs, io::Write};

    #[test]
    fn local_store_appends_and_filters_recent_events() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        store
            .append(&StoredEvent::new(
                "alpha",
                "2026-04-27T12:00:00Z",
                StoredEventKind::Log,
                "alpha ready",
            ))
            .expect("append alpha");
        store
            .append(&StoredEvent::new(
                "beta",
                "2026-04-27T12:00:01Z",
                StoredEventKind::EgressDenied,
                "169.254.169.254",
            ))
            .expect("append beta");

        let alpha = store
            .list_recent(Some("alpha"), 10)
            .expect("list alpha events");
        assert_eq!(alpha.len(), 1);
        assert_eq!(alpha[0].subject, "alpha ready");

        let all = store.list_recent(None, 10).expect("list all events");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].env, "beta");
    }

    #[test]
    fn jsonl_import_skips_bad_lines_and_tracks_offset() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");
        let env_dir = root.path().join("envs").join("demo");
        fs::create_dir_all(&env_dir).expect("create env dir");
        let events_path = env_dir.join("events.jsonl");
        fs::write(
            &events_path,
            concat!(
                "{\"ts\":\"2026-04-27T12:00:00Z\",\"driver\":\"context\",\"level\":\"info\",\"msg\":\"context ready\"}\n",
                "not json\n",
                "{\"ts\":\"2026-04-27T12:00:01Z\",\"kind\":\"egress_denied\",\"subject\":\"metadata\"}\n",
            ),
        )
        .expect("write jsonl");

        let first = store
            .import_env_jsonl("demo", &events_path)
            .expect("first import");
        assert_eq!(first.imported, 2);
        assert_eq!(first.skipped, 1);

        let second = store
            .import_env_jsonl("demo", &events_path)
            .expect("second import");
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped, 0);

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&events_path)
            .expect("open append");
        file.write_all(
            b"{\"ts\":\"2026-04-27T12:00:02Z\",\"driver\":\"agent\",\"msg\":\"agent ready\"}\n",
        )
        .expect("append jsonl");

        let third = store
            .import_env_jsonl("demo", &events_path)
            .expect("third import");
        assert_eq!(third.imported, 1);
        assert_eq!(third.skipped, 0);
        assert_eq!(
            store
                .list_recent(Some("demo"), 10)
                .expect("list imported")
                .len(),
            3
        );
    }
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```bash
cargo test -p agentenv-events --lib
```

Expected: the append/filter test may pass after Task 1; the JSONL test FAILS with missing `import_env_jsonl`.

- [ ] **Step 3: Add JSONL import and robust metadata decoding**

Add imports to `crates/agentenv-events/src/store.rs`:

```rust
use std::io::{Read, Seek, SeekFrom};
```

Add this method inside `impl LocalEventStore`:

```rust
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
                return Err(EventStoreError::CreateDir {
                    path: events_path.to_path_buf(),
                    source,
                });
            }
        };

        let len = file.metadata().map(|metadata| metadata.len()).map_err(|source| {
            EventStoreError::CreateDir {
                path: events_path.to_path_buf(),
                source,
            }
        })?;
        let stored_offset = self.jsonl_offset(env)?;
        let start = if stored_offset <= len { stored_offset } else { 0 };
        file.seek(SeekFrom::Start(start)).map_err(|source| EventStoreError::CreateDir {
            path: events_path.to_path_buf(),
            source,
        })?;

        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|source| EventStoreError::CreateDir {
                path: events_path.to_path_buf(),
                source,
            })?;

        let mut imported = 0;
        let mut skipped = 0;
        for line in content.lines().filter(|line| !line.trim().is_empty()) {
            match event_from_jsonl_line(env, line) {
                Some(event) => {
                    self.append(&event)?;
                    imported += 1;
                }
                None => skipped += 1,
            }
        }

        self.set_jsonl_offset(env, events_path, len)?;
        Ok(EventImportReport { imported, skipped })
    }

    fn jsonl_offset(&self, env: &str) -> EventStoreResult<u64> {
        match self.conn.query_row(
            "SELECT offset FROM jsonl_offsets WHERE env = ?1",
            params![env],
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

    fn set_jsonl_offset(
        &self,
        env: &str,
        events_path: &Path,
        offset: u64,
    ) -> EventStoreResult<()> {
        self.conn
            .execute(
                "INSERT INTO jsonl_offsets (env, path, offset) VALUES (?1, ?2, ?3)
                 ON CONFLICT(env) DO UPDATE SET path = excluded.path, offset = excluded.offset",
                params![env, events_path.display().to_string(), offset as i64],
            )
            .map_err(|source| EventStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }
```

Add this helper at module scope:

```rust
fn event_from_jsonl_line(env: &str, line: &str) -> Option<StoredEvent> {
    let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
    let ts = value
        .get("ts")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("1970-01-01T00:00:00Z");
    let kind = value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .map(StoredEventKind::from_str)
        .unwrap_or(StoredEventKind::Log);
    let subject = value
        .get("subject")
        .or_else(|| value.get("msg"))
        .or_else(|| value.get("message"))
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
```

- [ ] **Step 4: Run all event tests**

Run:

```bash
cargo test -p agentenv-events
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-events/src/lib.rs crates/agentenv-events/src/store.rs
git commit -m "feat(events): import legacy jsonl activity"
```

## Task 3: Approval Store And Decision Events

**Files:**
- Modify: `crates/agentenv-approvals/Cargo.toml`
- Replace: `crates/agentenv-approvals/src/lib.rs`

- [ ] **Step 1: Write failing approval store tests**

Replace `crates/agentenv-approvals/src/lib.rs` with:

```rust
#![forbid(unsafe_code)]

use agentenv_events::{LocalEventStore, StoredEvent, StoredEventKind};
use agentenv_proto::{ApprovalDecision, ApprovalKind, ApprovalScope};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};
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
    #[error("approval store is not implemented")]
    NotImplemented,
}

pub type ApprovalStoreResult<T> = Result<T, ApprovalStoreError>;

pub struct LocalApprovalStore;

impl LocalApprovalStore {
    pub fn open(_root: &Path) -> ApprovalStoreResult<Self> {
        Err(ApprovalStoreError::NotImplemented)
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
        assert!(events
            .iter()
            .any(|event| event.kind == StoredEventKind::ApprovalAllowed
                && event.subject == "api.stripe.com:443"));
    }

    #[test]
    fn deciding_missing_request_returns_none() {
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
}
```

- [ ] **Step 2: Run approval tests and verify they fail**

Run:

```bash
cargo test -p agentenv-approvals
```

Expected: FAIL with missing methods `upsert_pending`, `list_pending`, and `decide`, plus dependency errors until Cargo is updated.

- [ ] **Step 3: Add dependencies and approval persistence**

Update `crates/agentenv-approvals/Cargo.toml`:

```toml
[dependencies]
agentenv-events = { path = "../agentenv-events" }
agentenv-proto = { path = "../agentenv-proto" }
rusqlite.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
time.workspace = true

[dev-dependencies]
tempfile = "=3.16.0"
```

Replace `ApprovalStoreError` and `LocalApprovalStore` implementation in `crates/agentenv-approvals/src/lib.rs` with:

```rust
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
        let events = LocalEventStore::open(root).map_err(|source| ApprovalStoreError::Event {
            source,
        })?;
        let store = Self { path, conn, events };
        store.init_schema()?;
        Ok(store)
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
                    status TEXT NOT NULL,
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
        let context_json =
            serde_json::to_string(&request.context).map_err(|source| {
                ApprovalStoreError::ContextEncode { source }
            })?;
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
                    requested_at = excluded.requested_at,
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
        let sql_all =
            "SELECT request_id, env, agent, kind, subject, reason, status, requested_at,
                    decided_at, decided_by, scope, context_json
             FROM approvals WHERE status = 'pending' ORDER BY requested_at ASC";
        let sql_env =
            "SELECT request_id, env, agent, kind, subject, reason, status, requested_at,
                    decided_at, decided_by, scope, context_json
             FROM approvals WHERE status = 'pending' AND env = ?1 ORDER BY requested_at ASC";

        let mut out = Vec::new();
        if let Some(env) = env {
            let mut stmt = self.conn.prepare(sql_env).map_err(|source| {
                ApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let rows = stmt
                .query_map(params![env], row_to_approval)
                .map_err(|source| ApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            for row in rows {
                out.push(row.map_err(|source| ApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?);
            }
        } else {
            let mut stmt = self.conn.prepare(sql_all).map_err(|source| {
                ApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let rows = stmt.query_map([], row_to_approval).map_err(|source| {
                ApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                }
            })?;
            for row in rows {
                out.push(row.map_err(|source| ApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?);
            }
        }
        Ok(out)
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
            return Ok(ApprovalRequestRecord {
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
            });
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
                 WHERE request_id = ?5",
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

    fn get_request(
        &self,
        request_id: &str,
    ) -> ApprovalStoreResult<Option<ApprovalRequestRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT request_id, env, agent, kind, subject, reason, status, requested_at,
                        decided_at, decided_by, scope, context_json
                 FROM approvals WHERE request_id = ?1",
            )
            .map_err(|source| ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        match stmt.query_row(params![request_id], row_to_approval) {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(source) => Err(ApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            }),
        }
    }

    fn emit_decision_event(&self, record: &ApprovalRequestRecord) -> ApprovalStoreResult<()> {
        let kind = match record.status {
            ApprovalStatus::Allowed => StoredEventKind::ApprovalAllowed,
            ApprovalStatus::Denied => StoredEventKind::ApprovalDenied,
            ApprovalStatus::Pending | ApprovalStatus::Stale => StoredEventKind::Runtime,
        };
        let mut event = StoredEvent::new(&record.env, record.decided_at.clone().unwrap_or_else(|| record.requested_at.clone()), kind, &record.subject);
        event.reason = Some(record.reason.clone());
        event.metadata = serde_json::json!({
            "request_id": record.request_id,
            "decided_by": record.decided_by,
            "scope": record.scope,
        });
        self.events.append(&event).map_err(|source| ApprovalStoreError::Event {
            source,
        })?;
        Ok(())
    }
}
```

Add helper functions at module scope:

```rust
fn row_to_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRequestRecord> {
    let kind: String = row.get(3)?;
    let status: String = row.get(6)?;
    let scope: Option<String> = row.get(10)?;
    let context_json: String = row.get(11)?;
    Ok(ApprovalRequestRecord {
        request_id: row.get(0)?,
        env: row.get(1)?,
        agent: row.get(2)?,
        kind: approval_kind_from_str(&kind),
        subject: row.get(4)?,
        reason: row.get(5)?,
        status: approval_status_from_str(&status),
        requested_at: row.get(7)?,
        decided_at: row.get(8)?,
        decided_by: row.get(9)?,
        scope: scope.as_deref().map(approval_scope_from_str),
        context: serde_json::from_str(&context_json)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new())),
    })
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
```

- [ ] **Step 4: Run approval tests**

Run:

```bash
cargo test -p agentenv-approvals
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv-approvals/Cargo.toml crates/agentenv-approvals/src/lib.rs
git commit -m "feat(approvals): persist approval decisions"
```

## Task 4: TUI Model, Backend Trait, And Command Parser

**Files:**
- Modify: `crates/tui/Cargo.toml`
- Replace: `crates/tui/src/lib.rs`
- Create: `crates/tui/src/model.rs`
- Create: `crates/tui/src/backend.rs`
- Create: `crates/tui/src/command.rs`

- [ ] **Step 1: Write failing command and model tests**

Create `crates/tui/src/command.rs`:

```rust
use crate::model::CommandAction;

pub fn parse_command(input: &str) -> Result<CommandAction, String> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix("destroy ") {
        let env = rest.trim();
        if !env.is_empty() {
            return Ok(CommandAction::DestroyEnv(env.to_owned()));
        }
    }
    Err(format!("unknown command `{trimmed}`"))
}

#[cfg(test)]
mod tests {
    use super::parse_command;
    use crate::model::CommandAction;

    #[test]
    fn parses_destroy_command() {
        assert_eq!(
            parse_command("destroy myapp").expect("parse destroy"),
            CommandAction::DestroyEnv("myapp".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_command() {
        let error = parse_command("policy-add github_read myapp").expect_err("unknown command");
        assert!(error.contains("unknown command"));
    }
}
```

Create `crates/tui/src/model.rs` with the enum referenced by the test and one snapshot constructor test:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAction {
    DestroyEnv(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Envs,
    Events,
    Approvals,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Normal,
    Logs,
    Policy,
    Help,
    Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvRow {
    pub name: String,
    pub agent: String,
    pub sandbox: String,
    pub context: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub ts: String,
    pub env: String,
    pub kind: String,
    pub subject: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    pub request_id: String,
    pub env: String,
    pub agent: Option<String>,
    pub subject: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailState {
    pub env: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpsSnapshot {
    pub envs: Vec<EnvRow>,
    pub events: Vec<EventRow>,
    pub approvals: Vec<ApprovalRow>,
    pub detail: Option<DetailState>,
    pub events_per_minute: u64,
}

impl OpsSnapshot {
    pub fn empty() -> Self {
        Self {
            envs: Vec::new(),
            events: Vec::new(),
            approvals: Vec::new(),
            detail: None,
            events_per_minute: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OpsSnapshot;

    #[test]
    fn empty_snapshot_has_no_rows() {
        let snapshot = OpsSnapshot::empty();
        assert!(snapshot.envs.is_empty());
        assert!(snapshot.events.is_empty());
        assert!(snapshot.approvals.is_empty());
        assert_eq!(snapshot.events_per_minute, 0);
    }
}
```

- [ ] **Step 2: Run command/model tests and verify they fail for missing exports**

Run:

```bash
cargo test -p tui --lib
```

Expected: FAIL until `lib.rs` exports the new modules and crate dependencies are added.

- [ ] **Step 3: Add dependencies, exports, and backend trait**

Update `crates/tui/Cargo.toml`:

```toml
[dependencies]
agentenv-approvals = { path = "../agentenv-approvals" }
agentenv-core = { path = "../agentenv-core" }
agentenv-events = { path = "../agentenv-events" }
agentenv-proto = { path = "../agentenv-proto" }
anyhow.workspace = true
async-trait.workspace = true
crossterm.workspace = true
ratatui.workspace = true
serde.workspace = true
tokio.workspace = true
time.workspace = true
```

Replace `crates/tui/src/lib.rs`:

```rust
#![forbid(unsafe_code)]

pub mod app;
pub mod backend;
pub mod command;
pub mod model;
pub mod render;
pub mod terminal;
pub mod theme;

pub use backend::OpsBackend;
pub use model::{CommandAction, OpsSnapshot, Pane, ViewMode};
pub use terminal::{run_terminal, TermOptions};
```

Create `crates/tui/src/backend.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;

use crate::model::OpsSnapshot;

#[async_trait(?Send)]
pub trait OpsBackend {
    async fn load_snapshot(&mut self, selected_env: Option<&str>) -> Result<OpsSnapshot>;
    async fn destroy_env(&mut self, env: &str) -> Result<()>;
    async fn allow_approval(&mut self, request_id: &str) -> Result<()>;
    async fn deny_approval(&mut self, request_id: &str) -> Result<()>;
}
```

Create empty modules so compilation reaches the command/model tests:

```rust
// crates/tui/src/app.rs
#![allow(dead_code)]
```

```rust
// crates/tui/src/render.rs
#![allow(dead_code)]
```

```rust
// crates/tui/src/terminal.rs
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TermOptions {
    pub no_color: bool,
    pub refresh_interval: Duration,
}

pub async fn run_terminal<B>(
    _backend: B,
    _options: TermOptions,
) -> anyhow::Result<()>
where
    B: crate::backend::OpsBackend,
{
    Ok(())
}
```

```rust
// crates/tui/src/theme.rs
#![allow(dead_code)]
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p tui --lib
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/tui/Cargo.toml crates/tui/src/lib.rs crates/tui/src/model.rs crates/tui/src/backend.rs crates/tui/src/command.rs crates/tui/src/app.rs crates/tui/src/render.rs crates/tui/src/terminal.rs crates/tui/src/theme.rs
git commit -m "feat(tui): add term app model"
```

## Task 5: TUI Reducer, Navigation, Approval Keys, And Dirty State

**Files:**
- Modify: `crates/tui/src/app.rs`
- Modify: `crates/tui/src/model.rs`

- [ ] **Step 1: Write failing reducer tests**

Replace `crates/tui/src/app.rs` with:

```rust
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::model::{CommandAction, OpsSnapshot, Pane, ViewMode};

#[derive(Debug, Clone)]
pub enum AppIntent {
    None,
    Quit,
    Refresh,
    Execute(CommandAction),
    AllowApproval(String),
    DenyApproval(String),
}

#[derive(Debug, Clone)]
pub struct App {
    snapshot: OpsSnapshot,
    active_pane: Pane,
    mode: ViewMode,
    selected_env: usize,
    selected_approval: usize,
    command_buffer: String,
    status: Option<String>,
    dirty: bool,
}

impl App {
    pub fn new(snapshot: OpsSnapshot) -> Self {
        Self {
            snapshot,
            active_pane: Pane::Envs,
            mode: ViewMode::Normal,
            selected_env: 0,
            selected_approval: 0,
            command_buffer: String::new(),
            status: None,
            dirty: true,
        }
    }

    pub fn active_pane(&self) -> Pane {
        self.active_pane
    }

    pub fn mode(&self) -> ViewMode {
        self.mode
    }

    pub fn selected_env_name(&self) -> Option<&str> {
        self.snapshot
            .envs
            .get(self.selected_env)
            .map(|row| row.name.as_str())
    }

    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    pub fn command_buffer(&self) -> &str {
        &self.command_buffer
    }

    pub fn snapshot(&self) -> &OpsSnapshot {
        &self.snapshot
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn take_dirty(&mut self) -> bool {
        let dirty = self.dirty;
        self.dirty = false;
        dirty
    }
}

#[cfg(test)]
mod tests {
    use super::{App, AppIntent};
    use crate::model::{ApprovalRow, CommandAction, EnvRow, OpsSnapshot, Pane, ViewMode};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn app_with_rows() -> App {
        App::new(OpsSnapshot {
            envs: vec![
                EnvRow {
                    name: "alpha".to_owned(),
                    agent: "codex".to_owned(),
                    sandbox: "openshell".to_owned(),
                    context: "filesystem".to_owned(),
                    status: "running".to_owned(),
                },
                EnvRow {
                    name: "beta".to_owned(),
                    agent: "claude".to_owned(),
                    sandbox: "openshell".to_owned(),
                    context: "mcp".to_owned(),
                    status: "running".to_owned(),
                },
            ],
            approvals: vec![ApprovalRow {
                request_id: "req_1".to_owned(),
                env: "alpha".to_owned(),
                agent: Some("codex".to_owned()),
                subject: "api.stripe.com:443".to_owned(),
                reason: "egress".to_owned(),
            }],
            ..OpsSnapshot::empty()
        })
    }

    #[test]
    fn tab_cycles_panes() {
        let mut app = app_with_rows();

        assert_eq!(app.handle_key(key(KeyCode::Tab)), AppIntent::None);

        assert_eq!(app.active_pane(), Pane::Events);
        assert!(app.is_dirty());
    }

    #[test]
    fn jump_letter_selects_env_by_index() {
        let mut app = app_with_rows();

        assert_eq!(app.handle_key(key(KeyCode::Char('b'))), AppIntent::Refresh);

        assert_eq!(app.selected_env_name(), Some("beta"));
    }

    #[test]
    fn approval_keys_emit_intents_in_approval_pane() {
        let mut app = app_with_rows();
        app.handle_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));

        assert_eq!(
            app.handle_key(key(KeyCode::Char('y'))),
            AppIntent::AllowApproval("req_1".to_owned())
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Char('n'))),
            AppIntent::DenyApproval("req_1".to_owned())
        );
    }

    #[test]
    fn command_mode_parses_destroy() {
        let mut app = app_with_rows();
        app.handle_key(key(KeyCode::Char(':')));
        for ch in "destroy alpha".chars() {
            app.handle_key(key(KeyCode::Char(ch)));
        }

        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            AppIntent::Execute(CommandAction::DestroyEnv("alpha".to_owned()))
        );
    }

    #[test]
    fn help_overlay_toggles() {
        let mut app = app_with_rows();

        app.handle_key(key(KeyCode::Char('?')));
        assert_eq!(app.mode(), ViewMode::Help);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.mode(), ViewMode::Normal);
    }

    #[test]
    fn dirty_flag_can_be_cleared_and_set_again() {
        let mut app = app_with_rows();
        assert!(app.take_dirty());
        assert!(!app.take_dirty());

        app.handle_key(key(KeyCode::Tab));

        assert!(app.take_dirty());
    }
}
```

- [ ] **Step 2: Run reducer tests and verify they fail**

Run:

```bash
cargo test -p tui --lib app::
```

Expected: FAIL with missing `handle_key` and missing `PartialEq` for `AppIntent`.

- [ ] **Step 3: Implement reducer behavior**

Add derives to `AppIntent`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppIntent {
```

Add methods inside `impl App`:

```rust
    pub fn apply_snapshot(&mut self, snapshot: OpsSnapshot) {
        if self.snapshot != snapshot {
            self.snapshot = snapshot;
            if self.selected_env >= self.snapshot.envs.len() {
                self.selected_env = self.snapshot.envs.len().saturating_sub(1);
            }
            if self.selected_approval >= self.snapshot.approvals.len() {
                self.selected_approval = self.snapshot.approvals.len().saturating_sub(1);
            }
            self.dirty = true;
        }
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = Some(status.into());
        self.dirty = true;
    }

    pub fn clear_status(&mut self) {
        self.status = None;
        self.dirty = true;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> AppIntent {
        if self.mode == ViewMode::Command {
            return self.handle_command_key(key);
        }

        match key.code {
            KeyCode::Char('q') => AppIntent::Quit,
            KeyCode::Tab => {
                self.active_pane = match self.active_pane {
                    Pane::Envs => Pane::Events,
                    Pane::Events => Pane::Approvals,
                    Pane::Approvals => Pane::Detail,
                    Pane::Detail => Pane::Envs,
                };
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::BackTab => {
                self.active_pane = match self.active_pane {
                    Pane::Envs => Pane::Detail,
                    Pane::Events => Pane::Envs,
                    Pane::Approvals => Pane::Events,
                    Pane::Detail => Pane::Approvals,
                };
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('A') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.active_pane = Pane::Approvals;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('L') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.mode = ViewMode::Logs;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('P') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.mode = ViewMode::Policy;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('?') => {
                self.mode = ViewMode::Help;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Esc => {
                self.mode = ViewMode::Normal;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char(':') => {
                self.mode = ViewMode::Command;
                self.command_buffer.clear();
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char(ch) if self.active_pane == Pane::Envs && ch.is_ascii_lowercase() => {
                let index = (ch as u8 - b'a') as usize;
                if index < self.snapshot.envs.len() {
                    self.selected_env = index;
                    self.dirty = true;
                    AppIntent::Refresh
                } else {
                    AppIntent::None
                }
            }
            KeyCode::Char('y') | KeyCode::Char('a') if self.active_pane == Pane::Approvals => {
                self.selected_approval_id()
                    .map(AppIntent::AllowApproval)
                    .unwrap_or(AppIntent::None)
            }
            KeyCode::Char('n') | KeyCode::Char('d') if self.active_pane == Pane::Approvals => {
                self.selected_approval_id()
                    .map(AppIntent::DenyApproval)
                    .unwrap_or(AppIntent::None)
            }
            _ => AppIntent::None,
        }
    }

    fn move_selection(&mut self, delta: isize) -> AppIntent {
        match self.active_pane {
            Pane::Envs => {
                self.selected_env = move_index(self.selected_env, self.snapshot.envs.len(), delta);
                self.dirty = true;
                AppIntent::Refresh
            }
            Pane::Approvals => {
                self.selected_approval =
                    move_index(self.selected_approval, self.snapshot.approvals.len(), delta);
                self.dirty = true;
                AppIntent::None
            }
            Pane::Events | Pane::Detail => AppIntent::None,
        }
    }

    fn handle_command_key(&mut self, key: KeyEvent) -> AppIntent {
        match key.code {
            KeyCode::Esc => {
                self.mode = ViewMode::Normal;
                self.command_buffer.clear();
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Enter => {
                let command = self.command_buffer.clone();
                self.mode = ViewMode::Normal;
                self.command_buffer.clear();
                self.dirty = true;
                match crate::command::parse_command(&command) {
                    Ok(action) => AppIntent::Execute(action),
                    Err(error) => {
                        self.status = Some(error);
                        AppIntent::None
                    }
                }
            }
            KeyCode::Backspace => {
                self.command_buffer.pop();
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char(ch) => {
                self.command_buffer.push(ch);
                self.dirty = true;
                AppIntent::None
            }
            _ => AppIntent::None,
        }
    }

    fn selected_approval_id(&self) -> Option<String> {
        self.snapshot
            .approvals
            .get(self.selected_approval)
            .map(|row| row.request_id.clone())
    }
```

Add helper:

```rust
fn move_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs()).min(len - 1)
    } else {
        current.saturating_add(delta as usize).min(len - 1)
    }
}
```

- [ ] **Step 4: Run reducer tests**

Run:

```bash
cargo test -p tui --lib app::
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/tui/src/app.rs crates/tui/src/model.rs
git commit -m "feat(tui): handle term navigation"
```

## Task 6: TUI Theme And Rendering

**Files:**
- Modify: `crates/tui/src/theme.rs`
- Modify: `crates/tui/src/render.rs`
- Modify: `crates/tui/src/app.rs`

- [ ] **Step 1: Write failing render tests**

Replace `crates/tui/src/theme.rs`:

```rust
use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub color_enabled: bool,
}

impl Theme {
    pub fn color() -> Self {
        Self { color_enabled: true }
    }

    pub fn mono() -> Self {
        Self { color_enabled: false }
    }

    pub fn active_border(self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }
}
```

Replace `crates/tui/src/render.rs` with the test harness and function signature:

```rust
use ratatui::{prelude::*, widgets::*};

use crate::{app::App, theme::Theme};

pub fn render_app(frame: &mut Frame<'_>, app: &App, theme: Theme) {
    let _ = (frame, app, theme);
}

#[cfg(test)]
mod tests {
    use super::render_app;
    use crate::{
        app::App,
        model::{ApprovalRow, DetailState, EnvRow, EventRow, OpsSnapshot},
        theme::Theme,
    };
    use ratatui::{backend::TestBackend, Terminal};

    fn text_from_terminal(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<Vec<_>>()
            .join("")
    }

    fn sample_app() -> App {
        App::new(OpsSnapshot {
            envs: vec![EnvRow {
                name: "alpha".to_owned(),
                agent: "codex".to_owned(),
                sandbox: "openshell".to_owned(),
                context: "filesystem".to_owned(),
                status: "running".to_owned(),
            }],
            events: vec![EventRow {
                ts: "12:00:00".to_owned(),
                env: "alpha".to_owned(),
                kind: "egress_denied".to_owned(),
                subject: "metadata".to_owned(),
                reason: Some("denied_cloud_metadata".to_owned()),
            }],
            approvals: vec![ApprovalRow {
                request_id: "req_1".to_owned(),
                env: "alpha".to_owned(),
                agent: Some("codex".to_owned()),
                subject: "api.stripe.com:443".to_owned(),
                reason: "egress".to_owned(),
            }],
            detail: Some(DetailState {
                env: "alpha".to_owned(),
                lines: vec!["policy: balanced".to_owned()],
            }),
            events_per_minute: 12,
        })
    }

    #[test]
    fn renders_all_four_panes() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let app = sample_app();

        terminal
            .draw(|frame| render_app(frame, &app, Theme::color()))
            .expect("draw");

        let rendered = text_from_terminal(&terminal);
        for expected in ["agentenv", "Envs", "Events", "Approvals", "Detail", "alpha", "req_1"] {
            assert!(rendered.contains(expected), "missing {expected} in {rendered}");
        }
    }

    #[test]
    fn monochrome_render_uses_textual_selection_marker() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let app = sample_app();

        terminal
            .draw(|frame| render_app(frame, &app, Theme::mono()))
            .expect("draw");

        let rendered = text_from_terminal(&terminal);
        assert!(rendered.contains("> [a] alpha"), "rendered was {rendered}");
    }
}
```

- [ ] **Step 2: Run render tests and verify they fail**

Run:

```bash
cargo test -p tui --lib render::
```

Expected: FAIL because `render_app` draws nothing.

- [ ] **Step 3: Add app accessors needed by rendering**

Add these methods to `impl App` in `crates/tui/src/app.rs`:

```rust
    pub fn selected_env_index(&self) -> usize {
        self.selected_env
    }

    pub fn selected_approval_index(&self) -> usize {
        self.selected_approval
    }
```

- [ ] **Step 4: Implement four-pane rendering**

Replace `render_app` in `crates/tui/src/render.rs`:

```rust
pub fn render_app(frame: &mut Frame<'_>, app: &App, theme: Theme) {
    let area = frame.size();
    let root = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(2),
    ])
    .split(area);

    let snapshot = app.snapshot();
    let header = format!(
        " agentenv · {} envs · {} events/min ",
        snapshot.envs.len(),
        snapshot.events_per_minute
    );
    frame.render_widget(Paragraph::new(header).style(theme.active_border()), root[0]);

    let body = Layout::vertical([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .split(root[1]);
    let upper = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body[0]);
    let lower = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body[1]);

    render_envs(frame, upper[0], app, theme);
    render_events(frame, upper[1], app, theme);
    render_approvals(frame, lower[0], app, theme);
    render_detail(frame, lower[1], app, theme);

    let footer = match app.command_buffer().is_empty() {
        true => "[Tab] switch pane  [a-z] jump env  [A] approvals  [L] logs  [P] policy  [?] help  [q] quit".to_owned(),
        false => format!(":{}", app.command_buffer()),
    };
    let status = app.status().unwrap_or("");
    frame.render_widget(
        Paragraph::new(format!("{footer}\n{status}")),
        root[2],
    );
}

fn render_envs(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let rows = app
        .snapshot()
        .envs
        .iter()
        .enumerate()
        .map(|(index, env)| {
            let letter = (b'a' + index as u8) as char;
            let marker = if index == app.selected_env_index() { ">" } else { " " };
            Line::from(format!(
                "{marker} [{letter}] {:<16} {:<8} {:<10} {:<10} {}",
                env.name, env.agent, env.sandbox, env.context, env.status
            ))
        })
        .collect::<Vec<_>>();
    let block = Block::bordered().title("Envs").border_style(theme.active_border());
    frame.render_widget(Paragraph::new(rows).block(block), area);
}

fn render_events(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let rows = app
        .snapshot()
        .events
        .iter()
        .map(|event| {
            let reason = event.reason.as_deref().unwrap_or("");
            Line::from(format!(
                "{} [{}] {} {} {}",
                event.ts, event.env, event.kind, event.subject, reason
            ))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(rows).block(Block::bordered().title("Events").border_style(theme.active_border())),
        area,
    );
}

fn render_approvals(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let rows = app
        .snapshot()
        .approvals
        .iter()
        .enumerate()
        .map(|(index, approval)| {
            let marker = if index == app.selected_approval_index() { ">" } else { " " };
            Line::from(format!(
                "{marker} {} [{}] {} {}",
                approval.request_id, approval.env, approval.subject, approval.reason
            ))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(rows).block(Block::bordered().title("Approvals").border_style(theme.active_border())),
        area,
    );
}

fn render_detail(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let lines = app
        .snapshot()
        .detail
        .as_ref()
        .map(|detail| detail.lines.iter().map(|line| Line::from(line.clone())).collect())
        .unwrap_or_else(|| vec![Line::from("No env selected")]);
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title("Detail").border_style(theme.active_border())),
        area,
    );
}
```

- [ ] **Step 5: Run render tests**

Run:

```bash
cargo test -p tui --lib render::
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/tui/src/theme.rs crates/tui/src/render.rs crates/tui/src/app.rs
git commit -m "feat(tui): render term panes"
```

## Task 7: TUI Async Terminal Loop

**Files:**
- Modify: `crates/tui/src/terminal.rs`
- Modify: `crates/tui/src/app.rs`

- [ ] **Step 1: Write failing loop tests around intent execution**

Append this test module to `crates/tui/src/terminal.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::execute_intent;
    use crate::{
        app::AppIntent,
        backend::OpsBackend,
        model::{CommandAction, OpsSnapshot},
    };
    use anyhow::Result;
    use async_trait::async_trait;

    #[derive(Default)]
    struct RecordingBackend {
        destroyed: Vec<String>,
        allowed: Vec<String>,
        denied: Vec<String>,
    }

    #[async_trait(?Send)]
    impl OpsBackend for RecordingBackend {
        async fn load_snapshot(&mut self, _selected_env: Option<&str>) -> Result<OpsSnapshot> {
            Ok(OpsSnapshot::empty())
        }

        async fn destroy_env(&mut self, env: &str) -> Result<()> {
            self.destroyed.push(env.to_owned());
            Ok(())
        }

        async fn allow_approval(&mut self, request_id: &str) -> Result<()> {
            self.allowed.push(request_id.to_owned());
            Ok(())
        }

        async fn deny_approval(&mut self, request_id: &str) -> Result<()> {
            self.denied.push(request_id.to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn execute_intent_calls_backend() {
        let mut backend = RecordingBackend::default();

        execute_intent(
            &mut backend,
            AppIntent::Execute(CommandAction::DestroyEnv("demo".to_owned())),
        )
        .await
        .expect("destroy intent");
        execute_intent(&mut backend, AppIntent::AllowApproval("req_1".to_owned()))
            .await
            .expect("allow intent");
        execute_intent(&mut backend, AppIntent::DenyApproval("req_2".to_owned()))
            .await
            .expect("deny intent");

        assert_eq!(backend.destroyed, ["demo"]);
        assert_eq!(backend.allowed, ["req_1"]);
        assert_eq!(backend.denied, ["req_2"]);
    }
}
```

- [ ] **Step 2: Run the loop test and verify it fails**

Run:

```bash
cargo test -p tui execute_intent_calls_backend
```

Expected: FAIL with missing `execute_intent`.

- [ ] **Step 3: Implement terminal loop and intent execution**

Replace `crates/tui/src/terminal.rs` with:

```rust
use std::{io, thread, time::Duration};

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event as CrosstermEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::{sync::mpsc, time};

use crate::{
    app::{App, AppIntent},
    backend::OpsBackend,
    model::{CommandAction, OpsSnapshot},
    render::render_app,
    theme::Theme,
};

#[derive(Debug, Clone)]
pub struct TermOptions {
    pub no_color: bool,
    pub refresh_interval: Duration,
}

pub async fn execute_intent<B>(backend: &mut B, intent: AppIntent) -> Result<bool>
where
    B: OpsBackend,
{
    match intent {
        AppIntent::None => Ok(false),
        AppIntent::Quit => Ok(true),
        AppIntent::Refresh => Ok(false),
        AppIntent::Execute(CommandAction::DestroyEnv(env)) => {
            backend.destroy_env(&env).await?;
            Ok(false)
        }
        AppIntent::AllowApproval(request_id) => {
            backend.allow_approval(&request_id).await?;
            Ok(false)
        }
        AppIntent::DenyApproval(request_id) => {
            backend.deny_approval(&request_id).await?;
            Ok(false)
        }
    }
}

pub async fn run_terminal<B>(mut backend: B, options: TermOptions) -> Result<()>
where
    B: OpsBackend,
{
    let initial = backend.load_snapshot(None).await?;
    let mut app = App::new(initial);
    let theme = if options.no_color || std::env::var_os("NO_COLOR").is_some() {
        Theme::mono()
    } else {
        Theme::color()
    };

    enable_raw_mode().context("enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alternate screen")?;
    let backend_terminal = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend_terminal).context("create terminal")?;
    let result = run_loop(&mut terminal, &mut app, &mut backend, theme, options.refresh_interval).await;
    disable_raw_mode().context("disable terminal raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).context("leave alternate screen")?;
    terminal.show_cursor().context("show cursor")?;
    result
}

async fn run_loop<B>(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    backend: &mut B,
    theme: Theme,
    refresh_interval: Duration,
) -> Result<()>
where
    B: OpsBackend,
{
    let (tx, mut rx) = mpsc::unbounded_channel();
    thread::spawn(move || loop {
        match event::read() {
            Ok(event) => {
                if tx.send(event).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    });

    let mut interval = time::interval(refresh_interval);
    loop {
        if app.take_dirty() {
            terminal
                .draw(|frame| render_app(frame, app, theme))
                .context("draw term ui")?;
        }

        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    break;
                };
                if let CrosstermEvent::Key(key) = event {
                    let intent = app.handle_key(key);
                    match execute_intent(backend, intent).await {
                        Ok(true) => break,
                        Ok(false) => {
                            let snapshot = backend.load_snapshot(app.selected_env_name()).await?;
                            app.apply_snapshot(snapshot);
                        }
                        Err(error) => app.set_status(error.to_string()),
                    }
                }
            }
            _ = interval.tick() => {
                let snapshot = backend.load_snapshot(app.selected_env_name()).await?;
                app.apply_snapshot(snapshot);
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 4: Run terminal tests**

Run:

```bash
cargo test -p tui execute_intent_calls_backend
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/tui/src/terminal.rs
git commit -m "feat(tui): run async terminal loop"
```

## Task 8: CLI `agentenv term` And Local Backend

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agentenv/Cargo.toml`
- Modify: `crates/agentenv/src/main.rs`
- Create: `crates/agentenv/src/term_backend.rs`

- [ ] **Step 1: Write failing CLI help and remote tests**

Add these tests to `crates/agentenv/tests/cli_behavior.rs` near the other CLI behavior tests:

```rust
#[test]
fn term_help_lists_flags_and_key_bindings() {
    let output = Command::new(agentenv_bin())
        .arg("term")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", output_summary(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--no-color"), "stdout was: {stdout}");
    assert!(stdout.contains("--remote"), "stdout was: {stdout}");
    assert!(stdout.contains("[Tab] switch pane"), "stdout was: {stdout}");
    assert!(stdout.contains(":destroy <env>"), "stdout was: {stdout}");
}

#[test]
fn term_remote_reports_unsupported_until_daemon_exists() {
    let temp_dir = make_temp_dir("term-remote-unsupported");
    let output = Command::new(agentenv_bin())
        .arg("term")
        .arg("--remote")
        .arg("http://127.0.0.1:9898")
        .env("HOME", &temp_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("remote term requires"), "stderr was: {stderr}");
}
```

- [ ] **Step 2: Run CLI tests and verify they fail**

Run:

```bash
cargo test -p agentenv term_
```

Expected: FAIL because `term` is not a known subcommand.

- [ ] **Step 3: Add CLI dependencies**

Update workspace `Cargo.toml` so `time` includes formatting support:

```toml
time = { version = "0.3", features = ["serde", "macros", "formatting"] }
```

Update `crates/agentenv/Cargo.toml` dependencies:

```toml
agentenv-approvals = { path = "../agentenv-approvals" }
agentenv-events = { path = "../agentenv-events" }
agentenv-tui = { package = "tui", path = "../tui" }
async-trait.workspace = true
crossterm.workspace = true
time.workspace = true
```

Add dev dependency:

```toml
portable-pty = "0.8"
```

- [ ] **Step 4: Add `term_backend` module**

Create `crates/agentenv/src/term_backend.rs`:

```rust
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
                let _ = self.events.import_env_jsonl(&env.name, &paths.events_path());
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
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
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
```

- [ ] **Step 5: Wire CLI command**

In `crates/agentenv/src/main.rs`, add:

```rust
mod term_backend;
```

Add `Term(TermArgs),` to `enum Commands`.

Add this args type near other args:

```rust
#[derive(Debug, Args)]
#[command(after_long_help = "\
Key bindings:
  [Tab] switch pane
  [Shift+Tab] switch pane backward
  [a-z] jump env
  [A] approvals
  [L] logs
  [P] policy
  [?] help
  [:] command mode
  :destroy <env>
  [q] quit")]
struct TermArgs {
    #[arg(long)]
    no_color: bool,
    #[arg(long, value_name = "ENDPOINT")]
    remote: Option<String>,
}
```

Add match arm:

```rust
        Some(Commands::Term(args)) => run_term(args).await,
```

Add function:

```rust
async fn run_term(args: TermArgs) -> Result<()> {
    if let Some(endpoint) = args.remote {
        bail!("remote term requires a future agentenv daemon; unsupported endpoint `{endpoint}`");
    }
    let options = runtime_options(true)?;
    let backend = term_backend::LocalOpsBackend::new(options)?;
    agentenv_tui::run_terminal(
        backend,
        agentenv_tui::terminal::TermOptions {
            no_color: args.no_color,
            refresh_interval: Duration::from_millis(250),
        },
    )
    .await
}
```

- [ ] **Step 6: Run CLI help and remote tests**

Run:

```bash
cargo test -p agentenv term_
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/agentenv/Cargo.toml crates/agentenv/src/main.rs crates/agentenv/src/term_backend.rs crates/agentenv/tests/cli_behavior.rs
git commit -m "feat(cli): add agentenv term command"
```

## Task 9: Local Backend Destroy And Approval Unit Coverage

**Files:**
- Modify: `crates/agentenv/src/term_backend.rs`

- [ ] **Step 1: Add failing backend unit tests**

Append to `crates/agentenv/src/term_backend.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::LocalOpsBackend;
    use agentenv_approvals::{ApprovalRequestRecord, ApprovalStatus, LocalApprovalStore};
    use agentenv_core::runtime::RuntimeOptions;
    use agentenv_proto::{ApprovalKind, LogLevel};
    use agentenv_tui::backend::OpsBackend;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_root(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("agentenv-term-{label}-{}-{suffix}", std::process::id()));
        fs::create_dir_all(&root).expect("create root");
        root
    }

    fn runtime_options(root: PathBuf) -> RuntimeOptions {
        RuntimeOptions {
            root,
            log_level: LogLevel::Info,
            non_interactive: true,
        }
    }

    fn write_minimal_env(root: &Path, name: &str) {
        let env_dir = root.join("envs").join(name);
        fs::create_dir_all(&env_dir).expect("create env dir");
        let version = env!("CARGO_PKG_VERSION");
        fs::write(
            env_dir.join("state.json"),
            serde_json::json!({
                "version": "0.1.0",
                "name": name,
                "phase": "running",
                "created_at": "2026-04-27T00:00:00Z",
                "updated_at": "2026-04-27T00:00:00Z",
                "drivers": {
                    "sandbox": {"name": "openshell", "version": version},
                    "agent": {"name": "codex", "version": version},
                    "context": {"name": "filesystem", "version": version},
                    "inference": {"name": "passthrough", "version": version}
                },
                "handles": {},
                "endpoints": {},
                "first_enter_hint_shown": false
            })
            .to_string(),
        )
        .expect("write state");
        fs::write(env_dir.join("blueprint.yaml"), "version: 0.1.0\n").expect("write blueprint");
        fs::write(
            env_dir.join("lock.yaml"),
            "version: 0.1.0\nprotocol_version: \"0.1\"\nblueprint_hash: e0f55f3c3b82fc73132f1e776095311825afb01a7803c31228985cf0701d0736\ndrivers:\n  sandbox:\n    name: openshell\n    version: 0.0.1-alpha0\n  agent:\n    name: codex\n    version: 0.0.1-alpha0\n  context:\n    name: filesystem\n    version: 0.0.1-alpha0\n",
        )
        .expect("write lock");
    }

    fn approval_request(id: &str) -> ApprovalRequestRecord {
        ApprovalRequestRecord {
            request_id: id.to_owned(),
            env: "demo".to_owned(),
            agent: Some("codex".to_owned()),
            kind: ApprovalKind::EgressHost,
            subject: "api.stripe.com:443".to_owned(),
            reason: "egress".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: "2026-04-27T12:00:00Z".to_owned(),
            decided_at: None,
            decided_by: None,
            scope: None,
            context: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn local_backend_destroy_env_removes_state_and_records_event() {
        let root = unique_root("destroy");
        write_minimal_env(&root, "demo");
        let mut backend = LocalOpsBackend::new(runtime_options(root.clone())).expect("backend");

        backend.destroy_env("demo").await.expect("destroy env");

        assert!(!root.join("envs").join("demo").exists());
        let snapshot = backend.load_snapshot(None).await.expect("snapshot");
        assert!(snapshot
            .events
            .iter()
            .any(|event| event.subject == "env_destroyed"));
    }

    #[tokio::test]
    async fn local_backend_approval_actions_update_queue() {
        let root = unique_root("approval");
        let approvals = LocalApprovalStore::open(&root).expect("approvals");
        approvals
            .upsert_pending(approval_request("req_1"))
            .expect("insert approval");
        let mut backend = LocalOpsBackend::new(runtime_options(root)).expect("backend");

        backend.allow_approval("req_1").await.expect("allow");

        let snapshot = backend.load_snapshot(None).await.expect("snapshot");
        assert!(snapshot.approvals.is_empty());
        assert!(snapshot
            .events
            .iter()
            .any(|event| event.kind == "approval_allowed"));
    }
}
```

- [ ] **Step 2: Run backend tests and verify failures**

Run:

```bash
cargo test -p agentenv local_backend_
```

Expected: FAIL if lockfile fixture is too small for `destroy_env` or if local backend does not append the expected event.

- [ ] **Step 3: Adjust backend fixture parsing and event visibility**

If the destroy test fails because `describe_env` requires a valid lockfile, replace the test lock fixture with the same `lock.yaml` content from `write_minimal_env_state_with_credentials` in `crates/agentenv/tests/cli_behavior.rs`.

If the destroy test fails because recent events are filtered by selected env after the env was removed, change `destroy_env` to append the event before calling runtime destroy:

```rust
    async fn destroy_env(&mut self, env: &str) -> Result<()> {
        let mut event = StoredEvent::new(env, now_rfc3339(), StoredEventKind::Runtime, "env_destroyed");
        event.reason = Some("destroy command".to_owned());
        runtime::destroy_env(&self.options, &BuiltInDriverFactory, env)
            .await
            .with_context(|| format!("destroy env `{env}`"))?;
        self.events.append(&event).context("append destroy event")?;
        Ok(())
    }
```

- [ ] **Step 4: Run backend tests**

Run:

```bash
cargo test -p agentenv local_backend_
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/src/term_backend.rs
git commit -m "test(term): cover local backend actions"
```

## Task 10: PTY Smoke Test For Launch And Quit

**Files:**
- Modify: `crates/agentenv/tests/cli_behavior.rs`

- [ ] **Step 1: Add failing PTY smoke test**

Add imports at the top of `crates/agentenv/tests/cli_behavior.rs`:

```rust
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
```

Add this test near the other CLI tests:

```rust
#[test]
fn term_launches_and_quits_from_pty() {
    let temp_dir = make_temp_dir("term-pty-quit");
    write_minimal_env_state(&temp_dir, "demo");

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(agentenv_bin());
    cmd.arg("term");
    cmd.env("HOME", temp_dir.display().to_string());
    cmd.env("NO_COLOR", "1");
    let mut child = pair.slave.spawn_command(cmd).unwrap();
    let mut writer = pair.master.take_writer().unwrap();

    thread::sleep(Duration::from_millis(500));
    writer.write_all(b"q").unwrap();
    thread::sleep(Duration::from_millis(500));

    let status = child.wait().unwrap();
    assert!(status.success(), "term exited with {status:?}");
}
```

- [ ] **Step 2: Run PTY smoke test and verify it fails if terminal loop hangs**

Run:

```bash
cargo test -p agentenv term_launches_and_quits_from_pty -- --nocapture
```

Expected: FAIL if the TUI does not receive `q` or if raw terminal setup fails in a PTY.

- [ ] **Step 3: Make quit reliable**

If the test hangs, update `run_loop` in `crates/tui/src/terminal.rs` so `AppIntent::Quit` breaks the loop before refreshing the backend:

```rust
                    match execute_intent(backend, intent).await {
                        Ok(true) => break,
                        Ok(false) => {
                            let snapshot = backend.load_snapshot(app.selected_env_name()).await?;
                            app.apply_snapshot(snapshot);
                        }
                        Err(error) => app.set_status(error.to_string()),
                    }
```

If raw mode teardown hides the exit status, keep teardown in a best-effort block but return the original loop result:

```rust
    let result = run_loop(&mut terminal, &mut app, &mut backend, theme, options.refresh_interval).await;
    let raw_result = disable_raw_mode().context("disable terminal raw mode");
    let screen_result = execute!(terminal.backend_mut(), LeaveAlternateScreen).context("leave alternate screen");
    let cursor_result = terminal.show_cursor().context("show cursor");
    result.and(raw_result).and(screen_result).and(cursor_result)
```

- [ ] **Step 4: Run PTY smoke test**

Run:

```bash
cargo test -p agentenv term_launches_and_quits_from_pty -- --nocapture
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/agentenv/tests/cli_behavior.rs crates/tui/src/terminal.rs crates/agentenv/Cargo.toml
git commit -m "test(term): smoke test terminal launch"
```

## Task 11: Help, Logs, Policy, And No-Color Completion

**Files:**
- Modify: `crates/tui/src/render.rs`
- Modify: `crates/tui/src/theme.rs`
- Modify: `crates/tui/src/app.rs`

- [ ] **Step 1: Add failing view mode render tests**

Append to `crates/tui/src/render.rs` tests:

```rust
    #[test]
    fn help_logs_and_policy_modes_render_expected_titles() {
        for (key, expected) in [
            (crossterm::event::KeyCode::Char('?'), "Help"),
            (crossterm::event::KeyCode::Char('L'), "Logs"),
            (crossterm::event::KeyCode::Char('P'), "Policy"),
        ] {
            let backend = TestBackend::new(80, 24);
            let mut terminal = Terminal::new(backend).expect("terminal");
            let mut app = sample_app();
            app.handle_key(crossterm::event::KeyEvent::new(
                key,
                crossterm::event::KeyModifiers::SHIFT,
            ));

            terminal
                .draw(|frame| render_app(frame, &app, Theme::mono()))
                .expect("draw");

            let rendered = text_from_terminal(&terminal);
            assert!(rendered.contains(expected), "missing {expected} in {rendered}");
        }
    }
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
cargo test -p tui help_logs_and_policy_modes_render_expected_titles
```

Expected: FAIL because `render_app` does not branch on view mode.

- [ ] **Step 3: Render alternate modes**

At the top of `render_app`, before normal layout, add:

```rust
    match app.mode() {
        crate::model::ViewMode::Help => {
            render_fullscreen(frame, area, "Help", vec![
                Line::from("[Tab] switch pane"),
                Line::from("[Shift+Tab] switch pane backward"),
                Line::from("[a-z] jump env"),
                Line::from("[A] approvals"),
                Line::from("[L] logs"),
                Line::from("[P] policy"),
                Line::from(":destroy <env>"),
                Line::from("[q] quit"),
            ], theme);
            return;
        }
        crate::model::ViewMode::Logs => {
            let lines = app.snapshot().events.iter().map(|event| {
                Line::from(format!("{} [{}] {} {}", event.ts, event.env, event.kind, event.subject))
            }).collect();
            render_fullscreen(frame, area, "Logs", lines, theme);
            return;
        }
        crate::model::ViewMode::Policy => {
            let lines = app.snapshot().detail.as_ref()
                .map(|detail| detail.lines.iter().filter(|line| line.contains("policy")).map(|line| Line::from(line.clone())).collect())
                .unwrap_or_else(|| vec![Line::from("No policy detail")]);
            render_fullscreen(frame, area, "Policy", lines, theme);
            return;
        }
        crate::model::ViewMode::Normal | crate::model::ViewMode::Command => {}
    }
```

Add helper:

```rust
fn render_fullscreen(frame: &mut Frame<'_>, area: Rect, title: &'static str, lines: Vec<Line<'_>>, theme: Theme) {
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(title).border_style(theme.active_border())),
        area,
    );
}
```

- [ ] **Step 4: Run view render tests**

Run:

```bash
cargo test -p tui help_logs_and_policy_modes_render_expected_titles
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/tui/src/render.rs crates/tui/src/theme.rs crates/tui/src/app.rs
git commit -m "feat(tui): render term alternate views"
```

## Task 12: Final Verification And Documentation Touches

**Files:**
- Modify: `crates/tui/README.md`
- Modify: `crates/agentenv-events/README.md`
- Modify: `crates/agentenv-approvals/README.md`

- [ ] **Step 1: Update crate READMEs**

Set `crates/tui/README.md`:

```markdown
# tui

`tui` implements the local `agentenv term` operator interface. It owns ratatui rendering, app state, key handling, command mode, and the backend trait used by the `agentenv` binary.
```

Set `crates/agentenv-events/README.md`:

```markdown
# agentenv-events

`agentenv-events` stores local day-2 activity records in `~/.agentenv/ops.sqlite3` and imports legacy per-env `events.jsonl` activity.
```

Set `crates/agentenv-approvals/README.md`:

```markdown
# agentenv-approvals

`agentenv-approvals` stores pending approval requests and operator decisions in `~/.agentenv/ops.sqlite3`.
```

- [ ] **Step 2: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits 0.

- [ ] **Step 3: Run focused crate tests**

Run:

```bash
cargo test -p agentenv-events
cargo test -p agentenv-approvals
cargo test -p tui
cargo test -p agentenv term_
```

Expected: all focused commands exit 0.

- [ ] **Step 4: Run clippy**

Run:

```bash
cargo clippy --workspace -- -D warnings
```

Expected: exits 0 with no warnings.

- [ ] **Step 5: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: exits 0. If environment-dependent OpenShell tests skip or report accepted preflight limitations per existing test behavior, preserve the existing skip logic and do not weaken assertions for the term feature.

- [ ] **Step 6: Commit final docs**

```bash
git add crates/tui/README.md crates/agentenv-events/README.md crates/agentenv-approvals/README.md Cargo.lock
git commit -m "docs(term): document local ops tui crates"
```

## Self-Review Checklist

- Spec coverage:
  - Four panes: Tasks 6 and 11.
  - Navigation: Task 5.
  - `:destroy <env>`: Tasks 5, 7, 8, and 9.
  - Approval allow/deny: Tasks 3, 5, 7, and 9.
  - `--no-color` and `NO_COLOR`: Tasks 6, 8, and 10.
  - Low idle CPU design: Task 7 uses a blocking input thread plus bounded refresh tick and dirty redraw.
  - Embedded SQLite local sink: Tasks 1, 2, and 3.
  - Remote future mode: Task 8.
- Type consistency:
  - `OpsSnapshot`, `EnvRow`, `EventRow`, `ApprovalRow`, and `DetailState` are defined in Task 4 and reused by later tasks.
  - `OpsBackend` is async with `?Send`, matching local rusqlite-backed adapters.
  - `StoredEventKind` is local to `agentenv-events` and does not modify `agentenv-proto`.
- Risk notes:
  - `portable-pty` may reveal platform-specific terminal behavior; keep the test scoped to launch and `q`.
  - `rusqlite` uses bundled SQLite to avoid a runtime system SQLite dependency.
  - `time::format_description::well_known::Rfc3339` is covered by Task 8's workspace `time` feature update.
