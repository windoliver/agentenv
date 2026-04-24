use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use agentenv_proto::SessionStatus;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SESSION_STATE_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("session `{session_id}` not found")]
    NotFound { session_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStateFile {
    pub version: String,
    pub env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_session_id: Option<String>,
    #[serde(default)]
    pub sessions: Vec<PersistedSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSession {
    pub id: String,
    pub driver_session_id: String,
    pub name: String,
    pub status: SessionStatus,
    pub command: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

pub fn empty_session_file(env: &str) -> SessionStateFile {
    SessionStateFile {
        version: SESSION_STATE_VERSION.to_owned(),
        env: env.to_owned(),
        default_session_id: None,
        sessions: Vec::new(),
    }
}

pub fn sessions_path(paths: &crate::env::EnvPaths) -> PathBuf {
    paths.env_dir().join("sessions.json")
}

pub fn read_sessions(
    paths: &crate::env::EnvPaths,
    env: &str,
) -> Result<SessionStateFile, crate::env::EnvError> {
    let path = sessions_path(paths);
    match crate::env::read_regular_file(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|source| crate::env::EnvError::Json { path, source }),
        Err(crate::env::EnvError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(empty_session_file(env))
        }
        Err(error) => Err(error),
    }
}

pub fn write_sessions(
    paths: &crate::env::EnvPaths,
    sessions: &SessionStateFile,
) -> Result<(), crate::env::EnvError> {
    let path = sessions_path(paths);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| crate::env::EnvError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let rendered =
        serde_json::to_string_pretty(sessions).map_err(|source| crate::env::EnvError::Json {
            path: path.clone(),
            source,
        })?;
    let temp_path = path.with_file_name(format!(".sessions.json.{}.tmp", std::process::id()));
    std::fs::write(&temp_path, rendered).map_err(|source| crate::env::EnvError::Io {
        path: temp_path.clone(),
        source,
    })?;
    std::fs::rename(&temp_path, &path).map_err(|source| {
        let _ = std::fs::remove_file(&temp_path);
        crate::env::EnvError::Io { path, source }
    })
}

pub fn upsert_session(file: &mut SessionStateFile, session: PersistedSession, make_default: bool) {
    if let Some(existing) = file.sessions.iter_mut().find(|item| item.id == session.id) {
        *existing = session;
    } else {
        file.sessions.push(session);
    }
    if make_default || file.default_session_id.is_none() {
        file.default_session_id = file.sessions.last().map(|item| item.id.clone());
    }
}

pub fn find_session<'a>(
    file: &'a SessionStateFile,
    session_id: &str,
) -> Result<&'a PersistedSession, SessionStoreError> {
    file.sessions
        .iter()
        .find(|session| session.id == session_id || session.driver_session_id == session_id)
        .ok_or_else(|| SessionStoreError::NotFound {
            session_id: session_id.to_owned(),
        })
}

pub fn is_live_status(status: &SessionStatus) -> bool {
    matches!(
        status,
        SessionStatus::Starting | SessionStatus::Attached | SessionStatus::Detached
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_session_file_uses_env_name() {
        let file = empty_session_file("demo");
        assert_eq!(file.env, "demo");
        assert!(file.sessions.is_empty());
    }

    #[test]
    fn session_file_round_trips() {
        let root = std::env::temp_dir().join(format!("agentenv-sessions-{}", std::process::id()));
        let paths = crate::env::EnvPaths::new(root, crate::env::validate_env_name("demo").unwrap());
        std::fs::create_dir_all(paths.env_dir()).unwrap();
        let mut file = empty_session_file("demo");
        file.default_session_id = Some("s1".to_owned());
        file.sessions.push(PersistedSession {
            id: "s1".to_owned(),
            driver_session_id: "tmux-s1".to_owned(),
            name: "demo".to_owned(),
            status: SessionStatus::Detached,
            command: "agentenv-agent".to_owned(),
            created_at: "2026-04-24T17:00:00Z".to_owned(),
            updated_at: "2026-04-24T17:00:00Z".to_owned(),
            working_dir: Some("/sandbox".to_owned()),
            metadata: BTreeMap::new(),
        });

        write_sessions(&paths, &file).unwrap();
        assert_eq!(read_sessions(&paths, "demo").unwrap(), file);
    }

    #[test]
    fn upsert_replaces_existing_session_and_sets_default() {
        let mut file = empty_session_file("demo");
        upsert_session(&mut file, session("s1", "tmux-s1"), false);
        assert_eq!(file.default_session_id.as_deref(), Some("s1"));

        let mut replacement = session("s1", "tmux-s1b");
        replacement.status = SessionStatus::Attached;
        upsert_session(&mut file, replacement.clone(), true);

        assert_eq!(file.sessions, vec![replacement]);
        assert_eq!(file.default_session_id.as_deref(), Some("s1"));
    }

    #[test]
    fn find_session_matches_core_or_driver_id() {
        let mut file = empty_session_file("demo");
        upsert_session(&mut file, session("s1", "tmux-s1"), true);

        assert_eq!(find_session(&file, "s1").unwrap().id, "s1");
        assert_eq!(find_session(&file, "tmux-s1").unwrap().id, "s1");

        let err = find_session(&file, "missing").unwrap_err();
        assert!(err.to_string().contains("session `missing` not found"));
    }

    #[test]
    fn live_statuses_are_starting_attached_and_detached() {
        assert!(is_live_status(&SessionStatus::Starting));
        assert!(is_live_status(&SessionStatus::Attached));
        assert!(is_live_status(&SessionStatus::Detached));
        assert!(!is_live_status(&SessionStatus::Exited));
        assert!(!is_live_status(&SessionStatus::Killed));
        assert!(!is_live_status(&SessionStatus::Unknown));
    }

    fn session(id: &str, driver_session_id: &str) -> PersistedSession {
        PersistedSession {
            id: id.to_owned(),
            driver_session_id: driver_session_id.to_owned(),
            name: "demo".to_owned(),
            status: SessionStatus::Detached,
            command: "agentenv-agent".to_owned(),
            created_at: "2026-04-24T17:00:00Z".to_owned(),
            updated_at: "2026-04-24T17:00:00Z".to_owned(),
            working_dir: Some("/sandbox".to_owned()),
            metadata: BTreeMap::new(),
        }
    }
}
