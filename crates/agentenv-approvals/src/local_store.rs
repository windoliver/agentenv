use agentenv_events::{LocalEventStore, StoredEventKind};
use agentenv_proto::{ApprovalDecision, ApprovalKind, ApprovalScope};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

const NANOS_PER_SECOND: i64 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalApprovalStatus {
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
    pub status: LocalApprovalStatus,
    pub requested_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub scope: Option<ApprovalScope>,
    pub context: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum LocalApprovalStoreError {
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
    #[error("failed to encode approval event metadata: {source}")]
    EventMetadataEncode {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode approval {field} `{value}`")]
    Decode { field: &'static str, value: String },
    #[error("failed to decode approval timestamp `{ts}` as RFC3339")]
    TimestampDecode { ts: String },
    #[error("approval timestamp `{ts}` is outside the supported nanosecond range")]
    TimestampRange { ts: String },
    #[error("failed to append approval event: {source}")]
    Event {
        #[source]
        source: agentenv_events::EventStoreError,
    },
}

pub type LocalApprovalStoreResult<T> = Result<T, LocalApprovalStoreError>;

pub struct LocalApprovalStore {
    path: PathBuf,
    conn: Connection,
}

impl LocalApprovalStore {
    pub fn open(root: &Path) -> LocalApprovalStoreResult<Self> {
        fs::create_dir_all(root).map_err(|source| LocalApprovalStoreError::CreateDir {
            path: root.to_path_buf(),
            source,
        })?;
        let path = agentenv_events::default_store_path(root);
        let conn = Connection::open(&path).map_err(|source| LocalApprovalStoreError::Sqlite {
            path: path.clone(),
            source,
        })?;
        let _events = LocalEventStore::open(root)
            .map_err(|source| LocalApprovalStoreError::Event { source })?;
        let store = Self { path, conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    fn init_schema(&self) -> LocalApprovalStoreResult<()> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS approvals (
                    request_id TEXT PRIMARY KEY,
                    env TEXT NOT NULL,
                    agent TEXT,
                    kind TEXT NOT NULL CHECK (kind IN ('egress_host', 'mcp_tool', 'zone_access', 'package_install')),
                    subject TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'allowed', 'denied', 'stale')),
                    requested_at TEXT NOT NULL,
                    decided_at TEXT,
                    decided_by TEXT,
                    scope TEXT CHECK (scope IS NULL OR scope IN (
                        'once',
                        'session',
                        'persist-sandbox',
                        'propose-for-baseline'
                    )),
                    context_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_approvals_status_env
                    ON approvals(status, env, requested_at);
                "#,
            )
            .map_err(|source| LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })
    }

    pub fn upsert_pending(&self, request: ApprovalRequestRecord) -> LocalApprovalStoreResult<()> {
        let context_json = serde_json::to_string(&request.context)
            .map_err(|source| LocalApprovalStoreError::ContextEncode { source })?;
        self.conn
            .execute(
                "INSERT INTO approvals
                 (request_id, env, agent, kind, subject, reason, status, requested_at,
                  decided_at, decided_by, scope, context_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, NULL, NULL, NULL, ?8)
                 ON CONFLICT(request_id) DO NOTHING",
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
            .map_err(|source| LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    pub fn list_pending(
        &self,
        env: Option<&str>,
    ) -> LocalApprovalStoreResult<Vec<ApprovalRequestRecord>> {
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
    ) -> LocalApprovalStoreResult<ApprovalRequestRecord> {
        let Some(mut record) = self.get_request(request_id)? else {
            return Ok(stale_missing_request(
                request_id, scope, decided_by, decided_at,
            ));
        };

        if record.status != LocalApprovalStatus::Pending {
            record.status = LocalApprovalStatus::Stale;
            return Ok(record);
        }

        let status = match decision {
            ApprovalDecision::Allow => LocalApprovalStatus::Allowed,
            ApprovalDecision::Deny => LocalApprovalStatus::Denied,
        };
        let scope_value = approval_scope_str(&scope);
        parse_ts_epoch_nanos(decided_at)?;

        record.status = status;
        record.decided_at = Some(decided_at.to_owned());
        record.decided_by = Some(decided_by.to_owned());
        record.scope = Some(scope.clone());
        let tx = self.conn.unchecked_transaction().map_err(|source| {
            LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            }
        })?;
        let updated = tx
            .execute(
                "UPDATE approvals
                 SET status = ?1, decided_at = ?2, decided_by = ?3, scope = ?4
                 WHERE request_id = ?5 AND status = 'pending'",
                params![
                    approval_status_str(status),
                    decided_at,
                    decided_by,
                    scope_value,
                    request_id
                ],
            )
            .map_err(|source| LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        if updated == 0 {
            tx.rollback()
                .map_err(|source| LocalApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            return self.stale_request_after_race(request_id, scope, decided_by, decided_at);
        }
        insert_decision_event(&tx, &self.path, &record)?;
        tx.commit()
            .map_err(|source| LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(record)
    }

    fn list_with_filter<P>(
        &self,
        sql: &str,
        params: P,
    ) -> LocalApprovalStoreResult<Vec<ApprovalRequestRecord>>
    where
        P: rusqlite::Params,
    {
        let mut stmt =
            self.conn
                .prepare(sql)
                .map_err(|source| LocalApprovalStoreError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
        let rows = stmt.query_map(params, row_to_approval).map_err(|source| {
            LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            }
        })?;
        let mut out = Vec::new();
        for row in rows {
            let raw = row.map_err(|source| LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
            out.push(raw.into_record()?);
        }
        Ok(out)
    }

    fn get_request(
        &self,
        request_id: &str,
    ) -> LocalApprovalStoreResult<Option<ApprovalRequestRecord>> {
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
            .map_err(|source| LocalApprovalStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        raw.map(ApprovalRow::into_record).transpose()
    }

    fn stale_request_after_race(
        &self,
        request_id: &str,
        scope: ApprovalScope,
        decided_by: &str,
        decided_at: &str,
    ) -> LocalApprovalStoreResult<ApprovalRequestRecord> {
        let Some(mut record) = self.get_request(request_id)? else {
            return Ok(stale_missing_request(
                request_id, scope, decided_by, decided_at,
            ));
        };
        record.status = LocalApprovalStatus::Stale;
        Ok(record)
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
    fn into_record(self) -> LocalApprovalStoreResult<ApprovalRequestRecord> {
        let context = serde_json::from_str(&self.context_json)
            .map_err(|source| LocalApprovalStoreError::ContextDecode { source })?;
        Ok(ApprovalRequestRecord {
            request_id: self.request_id,
            env: self.env,
            agent: self.agent,
            kind: approval_kind_from_str(&self.kind)?,
            subject: self.subject,
            reason: self.reason,
            status: approval_status_from_str(&self.status)?,
            requested_at: self.requested_at,
            decided_at: self.decided_at,
            decided_by: self.decided_by,
            scope: self
                .scope
                .as_deref()
                .map(approval_scope_from_str)
                .transpose()?,
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
        status: LocalApprovalStatus::Stale,
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
        ApprovalKind::PackageInstall => "package_install",
    }
}

fn approval_kind_from_str(value: &str) -> LocalApprovalStoreResult<ApprovalKind> {
    let kind = match value {
        "egress_host" => ApprovalKind::EgressHost,
        "mcp_tool" => ApprovalKind::McpTool,
        "zone_access" => ApprovalKind::ZoneAccess,
        "package_install" => ApprovalKind::PackageInstall,
        _ => {
            return Err(LocalApprovalStoreError::Decode {
                field: "kind",
                value: value.to_owned(),
            });
        }
    };
    Ok(kind)
}

fn approval_status_str(status: LocalApprovalStatus) -> &'static str {
    match status {
        LocalApprovalStatus::Pending => "pending",
        LocalApprovalStatus::Allowed => "allowed",
        LocalApprovalStatus::Denied => "denied",
        LocalApprovalStatus::Stale => "stale",
    }
}

fn approval_status_from_str(value: &str) -> LocalApprovalStoreResult<LocalApprovalStatus> {
    let status = match value {
        "pending" => LocalApprovalStatus::Pending,
        "allowed" => LocalApprovalStatus::Allowed,
        "denied" => LocalApprovalStatus::Denied,
        "stale" => LocalApprovalStatus::Stale,
        _ => {
            return Err(LocalApprovalStoreError::Decode {
                field: "status",
                value: value.to_owned(),
            });
        }
    };
    Ok(status)
}

fn approval_scope_str(scope: &ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "once",
        ApprovalScope::Session => "session",
        ApprovalScope::PersistSandbox => "persist-sandbox",
        ApprovalScope::ProposeForBaseline => "propose-for-baseline",
    }
}

fn approval_scope_from_str(value: &str) -> LocalApprovalStoreResult<ApprovalScope> {
    let scope = match value {
        "once" => ApprovalScope::Once,
        "session" => ApprovalScope::Session,
        "persist-sandbox" => ApprovalScope::PersistSandbox,
        "propose-for-baseline" => ApprovalScope::ProposeForBaseline,
        _ => {
            return Err(LocalApprovalStoreError::Decode {
                field: "scope",
                value: value.to_owned(),
            });
        }
    };
    Ok(scope)
}

fn insert_decision_event(
    conn: &Connection,
    path: &Path,
    record: &ApprovalRequestRecord,
) -> LocalApprovalStoreResult<i64> {
    let kind = match record.status {
        LocalApprovalStatus::Allowed => StoredEventKind::ApprovalAllowed,
        LocalApprovalStatus::Denied => StoredEventKind::ApprovalDenied,
        LocalApprovalStatus::Pending | LocalApprovalStatus::Stale => return Ok(0),
    };
    let ts = record
        .decided_at
        .as_deref()
        .unwrap_or(record.requested_at.as_str());
    let metadata = serde_json::json!({
        "request_id": record.request_id,
        "decided_by": record.decided_by,
        "scope": record.scope,
    });
    let metadata_json = serde_json::to_string(&metadata)
        .map_err(|source| LocalApprovalStoreError::EventMetadataEncode { source })?;
    let ts_epoch_nanos = parse_ts_epoch_nanos(ts)?;

    conn.execute(
        "INSERT INTO events (
            env, ts, ts_epoch_nanos, kind, subject, reason, driver, handle, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7)",
        params![
            record.env,
            ts,
            ts_epoch_nanos,
            kind.as_str(),
            record.subject,
            record.reason,
            metadata_json
        ],
    )
    .map_err(|source| LocalApprovalStoreError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(conn.last_insert_rowid())
}

fn parse_ts_epoch_nanos(ts: &str) -> LocalApprovalStoreResult<i64> {
    let parsed = parse_rfc3339(ts)
        .ok_or_else(|| LocalApprovalStoreError::TimestampDecode { ts: ts.to_owned() })?;
    epoch_nanos_to_i64(ts, parsed)
}

fn epoch_nanos_to_i64(ts: &str, nanos: i128) -> LocalApprovalStoreResult<i64> {
    i64::try_from(nanos).map_err(|_| LocalApprovalStoreError::TimestampRange { ts: ts.to_owned() })
}

fn parse_rfc3339(ts: &str) -> Option<i128> {
    let bytes = ts.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }

    let year = parse_digits_i32(bytes, 0, 4)?;
    let month = parse_digits_u32(bytes, 5, 2)?;
    let day = parse_digits_u32(bytes, 8, 2)?;
    let hour = parse_digits_u32(bytes, 11, 2)?;
    let minute = parse_digits_u32(bytes, 14, 2)?;
    let second = parse_digits_u32(bytes, 17, 2)?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let mut index = 19;
    let mut nanos = 0_i128;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        let mut digits = 0;
        while let Some(byte) = bytes.get(index) {
            if !byte.is_ascii_digit() {
                break;
            }
            if digits < 9 {
                nanos = nanos * 10 + i128::from(byte - b'0');
            }
            digits += 1;
            index += 1;
        }
        if index == start {
            return None;
        }
        for _ in digits..9 {
            nanos *= 10;
        }
    }

    let offset_seconds = match bytes.get(index) {
        Some(b'Z') => {
            if index + 1 != bytes.len() {
                return None;
            }
            0_i128
        }
        Some(sign @ (b'+' | b'-')) => {
            if index + 6 != bytes.len() || bytes.get(index + 3) != Some(&b':') {
                return None;
            }
            let offset_hour = parse_digits_u32(bytes, index + 1, 2)?;
            let offset_minute = parse_digits_u32(bytes, index + 4, 2)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let seconds = i128::from(offset_hour * 3600 + offset_minute * 60);
            if *sign == b'+' {
                seconds
            } else {
                -seconds
            }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    let local_seconds = i128::from(days) * 86_400 + i128::from(hour * 3_600 + minute * 60 + second);
    Some((local_seconds - offset_seconds) * i128::from(NANOS_PER_SECOND) + nanos)
}

fn parse_digits_i32(bytes: &[u8], start: usize, len: usize) -> Option<i32> {
    let value = parse_digits_u32(bytes, start, len)?;
    i32::try_from(value).ok()
}

fn parse_digits_u32(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let mut value = 0_u32;
    for index in start..start + len {
        let byte = *bytes.get(index)?;
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Some(value)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i32::try_from(month).unwrap_or(0);
    let day = i32::try_from(day).unwrap_or(0);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era * 146_097 + day_of_era - 719_468)
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
            status: LocalApprovalStatus::Pending,
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
        assert_eq!(pending[0].status, LocalApprovalStatus::Pending);
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

        assert_eq!(decided.status, LocalApprovalStatus::Allowed);
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

        assert_eq!(result.status, LocalApprovalStatus::Stale);
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
    fn upserting_pending_request_preserves_original_payload() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");
        let original = pending_request("req_pending_replay");
        let mut replayed = pending_request("req_pending_replay");
        replayed.env = "other".to_owned();
        replayed.agent = Some("claude".to_owned());
        replayed.kind = ApprovalKind::McpTool;
        replayed.subject = "dangerous_tool".to_owned();
        replayed.reason = "different replay reason".to_owned();
        replayed.requested_at = "2026-04-27T12:10:00Z".to_owned();
        replayed.context = serde_json::json!({"driver": "replayed"});

        store
            .upsert_pending(original.clone())
            .expect("insert pending");
        store.upsert_pending(replayed).expect("replay pending");

        let pending = store.list_pending(None).expect("list pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], original);
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

        assert_eq!(decided.status, LocalApprovalStatus::Denied);
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

        assert_eq!(stale.status, LocalApprovalStatus::Stale);
        assert_eq!(
            LocalEventStore::open(root.path())
                .expect("open events")
                .list_recent(Some("demo"), 10)
                .expect("list decision events")
                .len(),
            1
        );
    }

    #[test]
    fn upserting_decided_request_does_not_reopen_or_emit_second_event() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .upsert_pending(pending_request("req_replay"))
            .expect("insert pending");
        store
            .decide(
                "req_replay",
                ApprovalDecision::Allow,
                ApprovalScope::Session,
                "operator",
                "2026-04-27T12:01:00Z",
            )
            .expect("allow request");
        let mut replayed = pending_request("req_replay");
        replayed.subject = "replayed.example.com:443".to_owned();
        store.upsert_pending(replayed).expect("replay pending");

        assert!(store.list_pending(None).expect("list pending").is_empty());
        let stale = store
            .decide(
                "req_replay",
                ApprovalDecision::Deny,
                ApprovalScope::Once,
                "operator",
                "2026-04-27T12:02:00Z",
            )
            .expect("second decision");
        assert_eq!(stale.status, LocalApprovalStatus::Stale);
        assert_eq!(
            LocalEventStore::open(root.path())
                .expect("open events")
                .list_recent(Some("demo"), 10)
                .expect("list decision events")
                .len(),
            1
        );
    }

    #[test]
    fn invalid_decided_at_leaves_request_pending_and_emits_no_event() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .upsert_pending(pending_request("req_bad_ts"))
            .expect("insert pending");
        let err = store
            .decide(
                "req_bad_ts",
                ApprovalDecision::Allow,
                ApprovalScope::Session,
                "operator",
                "not-rfc3339",
            )
            .expect_err("invalid timestamp should fail");

        assert!(matches!(
            err,
            LocalApprovalStoreError::TimestampDecode { .. }
        ));
        assert_eq!(
            store
                .list_pending(None)
                .expect("list pending")
                .first()
                .expect("pending request")
                .request_id,
            "req_bad_ts"
        );
        assert!(LocalEventStore::open(root.path())
            .expect("open events")
            .list_recent(Some("demo"), 10)
            .expect("list decision events")
            .is_empty());
    }

    #[test]
    fn unknown_persisted_values_fail_closed() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalApprovalStore::open(root.path()).expect("open approval store");

        store
            .conn
            .execute(
                "INSERT INTO approvals
                 (request_id, env, agent, kind, subject, reason, status, requested_at,
                  decided_at, decided_by, scope, context_json)
                 VALUES (?1, 'demo', NULL, ?2, 'subject', 'reason', 'pending',
                         '2026-04-27T12:00:00Z', NULL, NULL, NULL, '{}')",
                params!["req_bad_kind", "future_kind"],
            )
            .expect_err("unknown kind should be rejected by constraint");
        store
            .conn
            .execute(
                "INSERT INTO approvals
                 (request_id, env, agent, kind, subject, reason, status, requested_at,
                  decided_at, decided_by, scope, context_json)
                 VALUES (?1, 'demo', NULL, 'egress_host', 'subject', 'reason', ?2,
                         '2026-04-27T12:00:00Z', NULL, NULL, NULL, '{}')",
                params!["req_bad_status", "future_status"],
            )
            .expect_err("unknown status should be rejected by constraint");
        store
            .conn
            .execute(
                "INSERT INTO approvals
                 (request_id, env, agent, kind, subject, reason, status, requested_at,
                  decided_at, decided_by, scope, context_json)
                 VALUES (?1, 'demo', NULL, 'egress_host', 'subject', 'reason', 'allowed',
                         '2026-04-27T12:00:00Z', '2026-04-27T12:01:00Z',
                         'operator', ?2, '{}')",
                params!["req_bad_scope", "future_scope"],
            )
            .expect_err("unknown scope should be rejected by constraint");

        assert!(store.list_pending(None).expect("list pending").is_empty());
    }
}
