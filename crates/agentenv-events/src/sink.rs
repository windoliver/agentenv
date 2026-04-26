use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;
use url::Url;

use crate::activity::ActivityEvent;
use crate::store::{SqliteEventStore, StoreError};

#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    fn name(&self) -> &'static str;
    async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkConfig {
    DefaultSqlite,
    Sqlite { path: PathBuf },
    Jsonl { path: PathBuf },
    OtelGrpc { endpoint: String },
    Webhook { url: Url },
}

impl SinkConfig {
    pub fn parse(uri: &str) -> Result<Self, SinkError> {
        if uri == "sqlite" {
            return Ok(Self::DefaultSqlite);
        }

        if let Some(path) = uri.strip_prefix("sqlite:") {
            return parse_sink_path(uri, path).map(|path| Self::Sqlite { path });
        }

        if let Some(path) = uri.strip_prefix("file:") {
            return parse_sink_path(uri, path).map(|path| Self::Jsonl { path });
        }

        if let Some(endpoint) = uri.strip_prefix("otel:") {
            if endpoint.starts_with("grpc://") && endpoint.len() > "grpc://".len() {
                return Ok(Self::OtelGrpc {
                    endpoint: endpoint.to_owned(),
                });
            }
            return Err(SinkError::InvalidSinkUri {
                uri: uri.to_owned(),
            });
        }

        if let Some(raw_url) = uri.strip_prefix("webhook:") {
            let url = Url::parse(raw_url).map_err(|source| SinkError::InvalidWebhookUrl {
                uri: uri.to_owned(),
                source,
            })?;
            match url.scheme() {
                "http" | "https" => return Ok(Self::Webhook { url }),
                _ => {
                    return Err(SinkError::InvalidSinkUri {
                        uri: uri.to_owned(),
                    })
                }
            }
        }

        Err(SinkError::UnsupportedSink {
            uri: uri.to_owned(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("unsupported events sink: {uri}")]
    UnsupportedSink { uri: String },
    #[error("invalid events sink URI: {uri}")]
    InvalidSinkUri { uri: String },
    #[error("invalid events webhook sink URL in {uri}: {source}")]
    InvalidWebhookUrl {
        uri: String,
        source: url::ParseError,
    },
    #[error("events sink IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("events sink JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("events sqlite sink error: {0}")]
    Store(#[from] StoreError),
    #[error("events sink worker failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("unsafe events JSONL sink path: {path}")]
    UnsafeJsonlPath { path: PathBuf },
    #[error("events dispatcher worker is closed")]
    DispatcherClosed,
}

pub struct SqliteSink {
    path: PathBuf,
}

impl SqliteSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait::async_trait]
impl EventSink for SqliteSink {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError> {
        if events.is_empty() {
            return Ok(());
        }

        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let store = SqliteEventStore::open(path)?;
            store.append_many(&events)
        })
        .await??;
        Ok(())
    }
}

pub struct JsonlSink {
    path: PathBuf,
}

impl JsonlSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait::async_trait]
impl EventSink for JsonlSink {
    fn name(&self) -> &'static str {
        "jsonl"
    }

    async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError> {
        if events.is_empty() {
            return Ok(());
        }

        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await?;
        }

        prepare_jsonl_file(&self.path)?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        let mut buffer = Vec::new();
        for event in events {
            serde_json::to_writer(&mut buffer, &event)?;
            buffer.push(b'\n');
        }
        file.write_all(&buffer).await?;
        file.flush().await?;
        Ok(())
    }
}

fn parse_sink_path(uri: &str, path: &str) -> Result<PathBuf, SinkError> {
    if path.is_empty() {
        return Err(SinkError::InvalidSinkUri {
            uri: uri.to_owned(),
        });
    }
    Ok(PathBuf::from(path))
}

#[cfg(unix)]
fn prepare_jsonl_file(path: &Path) -> Result<(), SinkError> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::unix::fs::OpenOptionsExt;

    match OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => harden_existing_jsonl_file(path),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn harden_existing_jsonl_file(path: &Path) -> Result<(), SinkError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(SinkError::UnsafeJsonlPath {
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
fn prepare_jsonl_file(_path: &Path) -> Result<(), SinkError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sink_uris() {
        assert!(matches!(
            SinkConfig::parse("sqlite").unwrap(),
            SinkConfig::DefaultSqlite
        ));
        assert!(matches!(
            SinkConfig::parse("sqlite:/tmp/events.db").unwrap(),
            SinkConfig::Sqlite { .. }
        ));
        assert!(matches!(
            SinkConfig::parse("file:/tmp/events.jsonl").unwrap(),
            SinkConfig::Jsonl { .. }
        ));
        assert!(matches!(
            SinkConfig::parse("otel:grpc://collector:4317").unwrap(),
            SinkConfig::OtelGrpc { .. }
        ));
        assert!(matches!(
            SinkConfig::parse("webhook:https://example.test/events?kinds=egress_denied").unwrap(),
            SinkConfig::Webhook { .. }
        ));
    }

    #[test]
    fn rejects_unknown_sink_uri() {
        let err = SinkConfig::parse("syslog:/dev/log").unwrap_err();
        assert!(err.to_string().contains("unsupported events sink"));
    }

    #[tokio::test]
    async fn jsonl_sink_writes_one_full_event_per_line() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        let sink = JsonlSink::new(&path);
        let event = crate::ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            crate::ActivityKind::SandboxCreate,
            crate::ActivityResult::Ok,
            "trace-jsonl",
        )
        .with_env("demo");

        sink.write_batch(vec![event.clone()]).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let rendered: crate::ActivityEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rendered, event);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn jsonl_sink_creates_file_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        let sink = JsonlSink::new(&path);
        let event = crate::ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            crate::ActivityKind::SandboxCreate,
            crate::ActivityResult::Ok,
            "trace-jsonl",
        );

        sink.write_batch(vec![event]).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
