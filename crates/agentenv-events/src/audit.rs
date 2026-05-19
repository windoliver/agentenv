use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PUBLIC_KEY_METADATA_KEY: &str = "ed25519_public_key";

pub type AuditResult<T> = Result<T, AuditError>;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("sqlite audit store error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("audit IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("audit signing error")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("audit signing key must contain exactly 32 raw bytes")]
    InvalidSigningKeyLength,
    #[error("audit signing key path or permissions are unsafe: {path}")]
    UnsafeSigningKey { path: PathBuf },
    #[error("audit signing key does not match store public key metadata")]
    PublicKeyMismatch,
    #[error("audit database path is unsafe: {path}")]
    UnsafeDatabasePath { path: PathBuf },
}

pub struct AuditPolicy;

pub struct AuditStore {
    path: PathBuf,
}

pub struct AuditSigningKey {
    signing_key: SigningKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyReport {
    pub valid: bool,
    pub checked_entries: usize,
    pub first_invalid_sequence: Option<i64>,
}

impl AuditPolicy {
    pub fn includes(event: &ActivityEvent) -> bool {
        match event.kind {
            ActivityKind::Auth
            | ActivityKind::CredentialInjected
            | ActivityKind::CredentialSet
            | ActivityKind::CredentialReset
            | ActivityKind::PolicyApplied
            | ActivityKind::ApprovalRequested
            | ActivityKind::ApprovalDecided
            | ActivityKind::EgressDenied
            | ActivityKind::SpawnRejected => true,
            ActivityKind::SandboxCreate | ActivityKind::Exec => {
                event.result == ActivityResult::Error
            }
            ActivityKind::SandboxDestroy
            | ActivityKind::EgressAllowed
            | ActivityKind::McpToolCall
            | ActivityKind::AgentTurn
            | ActivityKind::GenAiModelCall
            | ActivityKind::SpawnRequested
            | ActivityKind::SpawnQueued
            | ActivityKind::SpawnAdmitted
            | ActivityKind::SpawnStarted
            | ActivityKind::SpawnReady
            | ActivityKind::BuildOneflightHit
            | ActivityKind::BuildOneflightMiss
            | ActivityKind::BuildQueueDepth
            | ActivityKind::Log => false,
        }
    }
}

impl AuditSigningKey {
    pub fn load_or_create(path: impl AsRef<Path>) -> AuditResult<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }

        let bytes = match std::fs::symlink_metadata(path) {
            Ok(_) => {
                harden_existing_key_file(path)?;
                std::fs::read(path)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                create_private_key_file(path, &bytes)?;
                bytes.to_vec()
            }
            Err(error) => return Err(error.into()),
        };

        let secret_key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AuditError::InvalidSigningKeyLength)?;

        Ok(Self {
            signing_key: SigningKey::from_bytes(&secret_key),
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn sign_hash(&self, entry_hash: &[u8; 32]) -> Signature {
        self.signing_key.sign(entry_hash)
    }
}

impl AuditStore {
    pub fn open(path: impl Into<PathBuf>) -> AuditResult<Self> {
        let store = Self { path: path.into() };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, key: &AuditSigningKey, event: &ActivityEvent) -> AuditResult<i64> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let prev_hash = latest_entry_hash(&tx)?.unwrap_or_else(|| ZERO_HASH.to_owned());
        let event_json = serde_json::to_string(event)?;
        let public_key = key.public_key_hex();
        match metadata_public_key_hex(&tx)? {
            Some(stored_public_key) if stored_public_key != public_key => {
                return Err(AuditError::PublicKeyMismatch);
            }
            Some(_) => {}
            None => {
                tx.execute(
                    r#"
                    INSERT OR REPLACE INTO audit_metadata(key, value)
                    VALUES (?1, ?2), ('signature_algorithm', 'ed25519'), ('hash_algorithm', 'sha256')
                    "#,
                    params![PUBLIC_KEY_METADATA_KEY, &public_key],
                )?;
            }
        }

        tx.execute(
            r#"
            INSERT INTO audit_entries (
                ts,
                env,
                event_json,
                prev_hash,
                entry_hash,
                signature,
                public_key
            )
            VALUES (?1, ?2, ?3, ?4, '', '', ?5)
            "#,
            params![event.ts, event.env, event_json, prev_hash, public_key],
        )?;

        let sequence = tx.last_insert_rowid();
        let event_value = serde_json::to_value(event)?;
        let canonical_json = canonical_entry_json(sequence, &event.ts, &prev_hash, event_value)?;
        let entry_hash = sha256_bytes(&canonical_json);
        let signature = key.sign_hash(&entry_hash);

        tx.execute(
            r#"
            UPDATE audit_entries
            SET entry_hash = ?1, signature = ?2
            WHERE sequence = ?3
            "#,
            params![
                hex::encode(entry_hash),
                hex::encode(signature.to_bytes()),
                sequence
            ],
        )?;

        tx.commit()?;
        Ok(sequence)
    }

    pub fn verify(&self) -> AuditResult<AuditVerifyReport> {
        let conn = self.connection()?;
        let rows = load_audit_rows(&conn)?;
        if rows.is_empty() {
            return Ok(valid_report(0));
        }

        let Some(public_key_hex) = metadata_public_key_hex(&conn)? else {
            return Ok(invalid_report(1, rows[0].sequence));
        };
        self.verify_rows_with_public_key_hex(rows, &public_key_hex)
    }

    pub fn verify_with_public_key_hex(
        &self,
        public_key_hex: &str,
    ) -> AuditResult<AuditVerifyReport> {
        let conn = self.connection()?;
        let rows = load_audit_rows(&conn)?;
        self.verify_rows_with_public_key_hex(rows, public_key_hex)
    }

    pub fn public_key_hex(&self) -> AuditResult<Option<String>> {
        let conn = self.connection()?;
        metadata_public_key_hex(&conn)
    }

    pub fn has_entries_for_env(&self, env: &str) -> AuditResult<bool> {
        let conn = self.connection()?;
        for row in load_audit_rows(&conn)? {
            if audit_row_event_env(&row)?.as_deref() == Some(env) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn count_entries_for_env(&self, env: &str) -> AuditResult<usize> {
        let conn = self.connection()?;
        let mut count = 0usize;
        for row in load_audit_rows(&conn)? {
            if audit_row_event_env(&row)?.as_deref() == Some(env) {
                count += 1;
            }
        }
        Ok(count)
    }

    fn verify_rows_with_public_key_hex(
        &self,
        rows: Vec<RawAuditRow>,
        public_key_hex: &str,
    ) -> AuditResult<AuditVerifyReport> {
        let trusted_public_key = match verifying_key_from_hex(public_key_hex) {
            Ok(public_key) => public_key,
            Err(_) => {
                return Ok(rows
                    .first()
                    .map(|row| invalid_report(1, row.sequence))
                    .unwrap_or_else(|| valid_report(0)));
            }
        };
        let trusted_public_key_hex = hex::encode(trusted_public_key.to_bytes());
        let mut checked_entries = 0usize;
        let mut expected_prev_hash = ZERO_HASH.to_owned();

        for (expected_sequence, row) in (1i64..).zip(rows) {
            checked_entries += 1;
            if row.sequence != expected_sequence || row.prev_hash != expected_prev_hash {
                return Ok(invalid_report(checked_entries, row.sequence));
            }
            if row.public_key != trusted_public_key_hex {
                return Ok(invalid_report(checked_entries, row.sequence));
            }

            let event_value: Value = match serde_json::from_str(&row.event_json) {
                Ok(value) => value,
                Err(_) => return Ok(invalid_report(checked_entries, row.sequence)),
            };
            let canonical_json =
                canonical_entry_json(row.sequence, &row.ts, &row.prev_hash, event_value)?;
            let entry_hash = sha256_bytes(&canonical_json);
            let entry_hash_hex = hex::encode(entry_hash);
            if row.entry_hash != entry_hash_hex {
                return Ok(invalid_report(checked_entries, row.sequence));
            }

            let signature = match signature_from_hex(&row.signature) {
                Ok(signature) => signature,
                Err(_) => return Ok(invalid_report(checked_entries, row.sequence)),
            };
            if trusted_public_key.verify(&entry_hash, &signature).is_err() {
                return Ok(invalid_report(checked_entries, row.sequence));
            }

            expected_prev_hash = row.entry_hash;
        }

        Ok(valid_report(checked_entries))
    }

    pub fn export_jsonl(&self, mut writer: impl Write) -> AuditResult<()> {
        self.export_jsonl_range(&mut writer, None, None)
    }

    pub fn export_jsonl_range(
        &self,
        mut writer: impl Write,
        from: Option<&str>,
        to: Option<&str>,
    ) -> AuditResult<()> {
        self.export_jsonl_range_for_env(&mut writer, from, to, None)
    }

    pub fn export_jsonl_range_for_env(
        &self,
        mut writer: impl Write,
        from: Option<&str>,
        to: Option<&str>,
        env: Option<&str>,
    ) -> AuditResult<()> {
        let conn = self.connection()?;
        for row in load_audit_rows(&conn)? {
            let event: Value = serde_json::from_str(&row.event_json)?;
            let event_env = event_env_from_value(&event);
            if !audit_row_matches(&row, event_env, from, to, env) {
                continue;
            }
            let entry = JsonlAuditEntry {
                sequence: row.sequence,
                ts: row.ts,
                env: event_env.map(ToOwned::to_owned),
                event,
                prev_hash: row.prev_hash,
                entry_hash: row.entry_hash,
                signature: row.signature,
                public_key: row.public_key,
            };
            serde_json::to_writer(&mut writer, &entry)?;
            writer.write_all(b"\n")?;
        }
        Ok(())
    }

    pub fn export_csv(&self, mut writer: impl Write) -> AuditResult<()> {
        self.export_csv_range(&mut writer, None, None)
    }

    pub fn export_csv_range(
        &self,
        mut writer: impl Write,
        from: Option<&str>,
        to: Option<&str>,
    ) -> AuditResult<()> {
        self.export_csv_range_for_env(&mut writer, from, to, None)
    }

    pub fn export_csv_range_for_env(
        &self,
        mut writer: impl Write,
        from: Option<&str>,
        to: Option<&str>,
        env: Option<&str>,
    ) -> AuditResult<()> {
        writer.write_all(
            b"sequence,ts,env,kind,result,trace_id,prev_hash,entry_hash,signature,public_key,event_json\n",
        )?;

        let conn = self.connection()?;
        for row in load_audit_rows(&conn)? {
            let event: ActivityEvent = serde_json::from_str(&row.event_json)?;
            if !audit_row_matches(&row, event.env.as_deref(), from, to, env) {
                continue;
            }
            write_csv_row(
                &mut writer,
                &[
                    row.sequence.to_string(),
                    row.ts,
                    event.env.unwrap_or_default(),
                    enum_as_string(event.kind)?,
                    enum_as_string(event.result)?,
                    event.trace_id,
                    row.prev_hash,
                    row.entry_hash,
                    row.signature,
                    row.public_key,
                    row.event_json,
                ],
            )?;
        }
        Ok(())
    }

    fn migrate(&self) -> AuditResult<()> {
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
            CREATE TABLE IF NOT EXISTS audit_entries (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              env TEXT,
              event_json TEXT NOT NULL,
              prev_hash TEXT NOT NULL,
              entry_hash TEXT NOT NULL,
              signature TEXT NOT NULL,
              public_key TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_metadata (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    fn connection(&self) -> AuditResult<Connection> {
        create_private_database_file(&self.path)?;
        let path = database_open_path(&self.path)?;
        Ok(Connection::open_with_flags(path, database_open_flags())?)
    }
}

fn audit_row_matches(
    row: &RawAuditRow,
    event_env: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    env: Option<&str>,
) -> bool {
    if env.is_some_and(|env| event_env != Some(env)) {
        return false;
    }
    if let Some(from) = from {
        let from = normalized_audit_from_bound(from);
        if row.ts.as_str() < from.as_str() {
            return false;
        }
    }
    if let Some(to) = to {
        let to = normalized_audit_to_bound(to);
        if row.ts.as_str() > to.as_str() {
            return false;
        }
    }
    true
}

fn audit_row_event_env(row: &RawAuditRow) -> AuditResult<Option<String>> {
    let event: ActivityEvent = serde_json::from_str(&row.event_json)?;
    Ok(event.env)
}

fn event_env_from_value(value: &Value) -> Option<&str> {
    value.get("env").and_then(Value::as_str)
}

fn normalized_audit_from_bound(bound: &str) -> String {
    if is_date_only_bound(bound) {
        format!("{bound}T00:00:00Z")
    } else {
        bound.to_owned()
    }
}

fn normalized_audit_to_bound(bound: &str) -> String {
    if is_date_only_bound(bound) {
        format!("{bound}T23:59:59.999999999Z")
    } else {
        bound.to_owned()
    }
}

fn is_date_only_bound(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

#[derive(Debug)]
struct RawAuditRow {
    sequence: i64,
    ts: String,
    event_json: String,
    prev_hash: String,
    entry_hash: String,
    signature: String,
    public_key: String,
}

#[derive(Serialize)]
struct JsonlAuditEntry {
    sequence: i64,
    ts: String,
    env: Option<String>,
    event: Value,
    prev_hash: String,
    entry_hash: String,
    signature: String,
    public_key: String,
}

fn latest_entry_hash(conn: &Connection) -> AuditResult<Option<String>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT entry_hash
        FROM audit_entries
        ORDER BY sequence DESC
        LIMIT 1
        "#,
    )?;
    let mut rows = stmt.query([])?;
    Ok(match rows.next()? {
        Some(row) => Some(row.get(0)?),
        None => None,
    })
}

fn metadata_public_key_hex(conn: &Connection) -> AuditResult<Option<String>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT value
        FROM audit_metadata
        WHERE key = ?1
        "#,
    )?;
    let mut rows = stmt.query(params![PUBLIC_KEY_METADATA_KEY])?;
    Ok(match rows.next()? {
        Some(row) => Some(row.get(0)?),
        None => None,
    })
}

fn load_audit_rows(conn: &Connection) -> AuditResult<Vec<RawAuditRow>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT sequence, ts, event_json, prev_hash, entry_hash, signature, public_key
        FROM audit_entries
        ORDER BY sequence ASC
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(RawAuditRow {
            sequence: row.get(0)?,
            ts: row.get(1)?,
            event_json: row.get(2)?,
            prev_hash: row.get(3)?,
            entry_hash: row.get(4)?,
            signature: row.get(5)?,
            public_key: row.get(6)?,
        })
    })?;

    let mut audit_rows = Vec::new();
    for row in rows {
        audit_rows.push(row?);
    }
    Ok(audit_rows)
}

fn canonical_entry_json(
    sequence: i64,
    ts: &str,
    prev_hash: &str,
    event: Value,
) -> AuditResult<Vec<u8>> {
    let mut canonical = BTreeMap::new();
    canonical.insert("sequence", Value::from(sequence));
    canonical.insert("ts", Value::String(ts.to_owned()));
    canonical.insert("prev_hash", Value::String(prev_hash.to_owned()));
    canonical.insert("event", event);
    Ok(serde_json::to_vec(&canonical)?)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn invalid_report(checked_entries: usize, sequence: i64) -> AuditVerifyReport {
    AuditVerifyReport {
        valid: false,
        checked_entries,
        first_invalid_sequence: Some(sequence),
    }
}

fn valid_report(checked_entries: usize) -> AuditVerifyReport {
    AuditVerifyReport {
        valid: true,
        checked_entries,
        first_invalid_sequence: None,
    }
}

fn verifying_key_from_hex(value: &str) -> AuditResult<VerifyingKey> {
    let bytes = hex::decode(value)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AuditError::InvalidSigningKeyLength)?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

fn signature_from_hex(value: &str) -> AuditResult<Signature> {
    Ok(Signature::try_from(hex::decode(value)?.as_slice())?)
}

fn enum_as_string<T: Serialize>(value: T) -> AuditResult<String> {
    match serde_json::to_value(value)? {
        Value::String(value) => Ok(value),
        _ => Ok(String::new()),
    }
}

fn write_csv_row(writer: &mut impl Write, fields: &[String]) -> AuditResult<()> {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(csv_escape(field).as_bytes())?;
    }
    writer.write_all(b"\n")?;
    Ok(())
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[cfg(unix)]
fn create_private_key_file(path: &Path, bytes: &[u8]) -> AuditResult<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_key_file(path: &Path, bytes: &[u8]) -> AuditResult<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[cfg(unix)]
fn harden_existing_key_file(path: &Path) -> AuditResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(AuditError::UnsafeSigningKey {
            path: path.to_owned(),
        });
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(AuditError::UnsafeSigningKey {
            path: path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_existing_key_file(_path: &Path) -> AuditResult<()> {
    Ok(())
}

#[cfg(unix)]
fn database_open_path(path: &Path) -> AuditResult<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| AuditError::UnsafeDatabasePath {
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
fn database_open_path(path: &Path) -> AuditResult<PathBuf> {
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
fn create_private_database_file(path: &Path) -> AuditResult<()> {
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
fn harden_existing_database_file(path: &Path) -> AuditResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(AuditError::UnsafeDatabasePath {
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
fn create_private_database_file(_path: &Path) -> AuditResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rusqlite::{params, Connection};

    use super::{
        canonical_entry_json, sha256_bytes, AuditError, AuditPolicy, AuditSigningKey, AuditStore,
    };
    use crate::{ActivityEvent, ActivityKind, ActivityResult};

    fn event(kind: ActivityKind, result: ActivityResult) -> ActivityEvent {
        ActivityEvent::new("2026-04-26T12:00:00Z", kind, result, "trace-audit").with_env("demo")
    }

    #[test]
    fn audit_policy_selects_security_sensitive_events() {
        assert!(AuditPolicy::includes(&event(
            ActivityKind::Auth,
            ActivityResult::Ok
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::CredentialInjected,
            ActivityResult::Ok
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::CredentialSet,
            ActivityResult::Ok
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::CredentialReset,
            ActivityResult::Ok
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::PolicyApplied,
            ActivityResult::Ok
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::ApprovalRequested,
            ActivityResult::PendingApproval
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::ApprovalDecided,
            ActivityResult::Ok
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::EgressDenied,
            ActivityResult::Denied
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::SpawnRejected,
            ActivityResult::Denied
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::SandboxCreate,
            ActivityResult::Error
        )));
        assert!(AuditPolicy::includes(&event(
            ActivityKind::Exec,
            ActivityResult::Error
        )));

        assert!(!AuditPolicy::includes(&event(
            ActivityKind::SandboxCreate,
            ActivityResult::Ok
        )));
        assert!(!AuditPolicy::includes(&event(
            ActivityKind::Exec,
            ActivityResult::Ok
        )));
        assert!(!AuditPolicy::includes(&event(
            ActivityKind::Log,
            ActivityResult::Ok
        )));
    }

    #[test]
    fn audit_store_appends_and_verifies_hash_chain() {
        let temp = tempfile::tempdir().unwrap();
        let store = AuditStore::open(temp.path().join("events.db")).unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();

        let first = event(ActivityKind::EgressDenied, ActivityResult::Denied);
        let second = event(ActivityKind::ApprovalDecided, ActivityResult::Ok);
        assert_eq!(store.append(&key, &first).unwrap(), 1);
        assert_eq!(store.append(&key, &second).unwrap(), 2);

        let report = store.verify().unwrap();
        assert!(report.valid);
        assert_eq!(report.checked_entries, 2);
        assert_eq!(report.first_invalid_sequence, None);

        let conn = Connection::open(temp.path().join("events.db")).unwrap();
        let rows = conn
            .prepare("SELECT sequence, prev_hash, entry_hash FROM audit_entries ORDER BY sequence")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(rows[0].0, 1);
        assert_eq!(rows[0].1, "0".repeat(64));
        assert_eq!(rows[1].1, rows[0].2);
    }

    #[test]
    fn audit_verify_detects_modified_entry() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("events.db");
        let store = AuditStore::open(&db_path).unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        store
            .append(
                &key,
                &event(
                    ActivityKind::ApprovalRequested,
                    ActivityResult::PendingApproval,
                ),
            )
            .unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE audit_entries SET event_json = ?1 WHERE sequence = 1",
            params![serde_json::to_string(&event(ActivityKind::Auth, ActivityResult::Ok)).unwrap()],
        )
        .unwrap();

        let report = store.verify().unwrap();
        assert!(!report.valid);
        assert_eq!(report.checked_entries, 1);
        assert_eq!(report.first_invalid_sequence, Some(1));
    }

    #[test]
    fn audit_env_scope_uses_signed_event_env_not_row_env() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("events.db");
        let store = AuditStore::open(&db_path).unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        store
            .append(
                &key,
                &event(ActivityKind::CredentialInjected, ActivityResult::Ok),
            )
            .unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE audit_entries SET env = ?1 WHERE sequence = 1",
            params!["other"],
        )
        .unwrap();

        assert!(store.verify().unwrap().valid);
        assert!(store.has_entries_for_env("demo").unwrap());

        let mut demo_export = Vec::new();
        store
            .export_jsonl_range_for_env(&mut demo_export, None, None, Some("demo"))
            .unwrap();
        let demo_export = String::from_utf8(demo_export).unwrap();
        assert!(demo_export.contains("trace-audit"), "{demo_export}");
        assert!(demo_export.contains("\"env\":\"demo\""), "{demo_export}");

        let mut other_export = Vec::new();
        store
            .export_jsonl_range_for_env(&mut other_export, None, None, Some("other"))
            .unwrap();
        assert!(
            String::from_utf8(other_export).unwrap().is_empty(),
            "tampered row env must not move a signed event to another env"
        );
    }

    #[test]
    fn audit_verify_detects_signature_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("events.db");
        let store = AuditStore::open(&db_path).unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        store
            .append(
                &key,
                &event(ActivityKind::CredentialReset, ActivityResult::Ok),
            )
            .unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE audit_entries SET signature = ?1 WHERE sequence = 1",
            params!["00".repeat(64)],
        )
        .unwrap();

        let report = store.verify().unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_sequence, Some(1));
    }

    #[test]
    fn audit_verify_with_trusted_key_rejects_row_key_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("events.db");
        let store = AuditStore::open(&db_path).unwrap();
        let original_key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        store
            .append(
                &original_key,
                &event(ActivityKind::EgressDenied, ActivityResult::Denied),
            )
            .unwrap();

        let attacker_key =
            AuditSigningKey::load_or_create(temp.path().join("attacker.key")).unwrap();
        let attacker_event = event(ActivityKind::Auth, ActivityResult::Ok);
        let attacker_event_json = serde_json::to_string(&attacker_event).unwrap();
        let canonical = canonical_entry_json(
            1,
            &attacker_event.ts,
            &"0".repeat(64),
            serde_json::to_value(&attacker_event).unwrap(),
        )
        .unwrap();
        let entry_hash = sha256_bytes(&canonical);
        let signature = attacker_key.sign_hash(&entry_hash);

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            r#"
            UPDATE audit_entries
            SET event_json = ?1, entry_hash = ?2, signature = ?3, public_key = ?4
            WHERE sequence = 1
            "#,
            params![
                attacker_event_json,
                hex::encode(entry_hash),
                hex::encode(signature.to_bytes()),
                attacker_key.public_key_hex(),
            ],
        )
        .unwrap();

        let report = store
            .verify_with_public_key_hex(&original_key.public_key_hex())
            .unwrap();
        assert!(!report.valid);
        assert_eq!(report.checked_entries, 1);
        assert_eq!(report.first_invalid_sequence, Some(1));
    }

    #[test]
    fn audit_verify_rejects_row_public_key_mismatch_with_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("events.db");
        let store = AuditStore::open(&db_path).unwrap();
        let original_key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        let attacker_key =
            AuditSigningKey::load_or_create(temp.path().join("attacker.key")).unwrap();
        store
            .append(
                &original_key,
                &event(ActivityKind::EgressDenied, ActivityResult::Denied),
            )
            .unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE audit_entries SET public_key = ?1 WHERE sequence = 1",
            params![attacker_key.public_key_hex()],
        )
        .unwrap();

        let report = store.verify().unwrap();
        assert!(!report.valid);
        assert_eq!(report.checked_entries, 1);
        assert_eq!(report.first_invalid_sequence, Some(1));
    }

    #[test]
    fn audit_verify_reports_malformed_signature_as_invalid_entry() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("events.db");
        let store = AuditStore::open(&db_path).unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        store
            .append(
                &key,
                &event(ActivityKind::CredentialReset, ActivityResult::Ok),
            )
            .unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE audit_entries SET signature = ?1 WHERE sequence = 1",
            params!["not-hex"],
        )
        .unwrap();

        let report = store.verify().unwrap();
        assert!(!report.valid);
        assert_eq!(report.checked_entries, 1);
        assert_eq!(report.first_invalid_sequence, Some(1));
    }

    #[test]
    fn audit_exports_include_hashes_and_event_json() {
        let temp = tempfile::tempdir().unwrap();
        let store = AuditStore::open(temp.path().join("events.db")).unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        store
            .append(
                &key,
                &event(ActivityKind::EgressDenied, ActivityResult::Denied),
            )
            .unwrap();

        let mut jsonl = Vec::new();
        store.export_jsonl(&mut jsonl).unwrap();
        let jsonl = String::from_utf8(jsonl).unwrap();
        assert!(jsonl.contains("\"sequence\":1"));
        assert!(jsonl.contains("\"prev_hash\""));
        assert!(jsonl.contains("\"entry_hash\""));
        assert!(jsonl.contains("\"event\""));

        let mut csv = Cursor::new(Vec::new());
        store.export_csv(&mut csv).unwrap();
        let csv = String::from_utf8(csv.into_inner()).unwrap();
        assert!(csv
            .starts_with("sequence,ts,env,kind,result,trace_id,prev_hash,entry_hash,signature,public_key,event_json\n"));
        assert!(csv.contains("egress_denied"));
        assert!(csv.contains("event_json"));
    }

    #[test]
    fn audit_export_to_date_includes_that_full_day() {
        let temp = tempfile::tempdir().unwrap();
        let store = AuditStore::open(temp.path().join("events.db")).unwrap();
        let key = AuditSigningKey::load_or_create(temp.path().join("audit.key")).unwrap();
        store
            .append(
                &key,
                &ActivityEvent::new(
                    "2026-04-26T12:00:00Z",
                    ActivityKind::CredentialSet,
                    ActivityResult::Ok,
                    "trace-april-26",
                )
                .with_env("demo"),
            )
            .unwrap();
        store
            .append(
                &key,
                &ActivityEvent::new(
                    "2026-04-27T00:00:00Z",
                    ActivityKind::CredentialSet,
                    ActivityResult::Ok,
                    "trace-april-27",
                )
                .with_env("demo"),
            )
            .unwrap();

        let mut exported = Vec::new();
        store
            .export_jsonl_range(&mut exported, None, Some("2026-04-26"))
            .unwrap();
        let exported = String::from_utf8(exported).unwrap();

        assert!(exported.contains("trace-april-26"), "{exported}");
        assert!(!exported.contains("trace-april-27"), "{exported}");
    }

    #[cfg(unix)]
    #[test]
    fn audit_signing_key_file_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("audit.key");
        let _key = AuditSigningKey::load_or_create(&key_path).unwrap();

        let mode = std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn audit_signing_key_rejects_existing_permissive_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("audit.key");
        std::fs::write(&key_path, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        match AuditSigningKey::load_or_create(&key_path) {
            Err(AuditError::UnsafeSigningKey { path }) => assert_eq!(path, key_path),
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("permissive signing key file was accepted"),
        }

        let mode = std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }
}
