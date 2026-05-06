use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use agentenv_core::{
    digest::{parse_sha256_digest, sha256_hex},
    driver::{DriverError, DriverResult},
};
use agentenv_events::{ActivityEvent, ActivityKind, ActivityResult, EventEmitter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    command_string, now_timestamp_string, sanitize_build_name, CommandRequest, CommandRunner,
};

#[derive(Debug, Clone)]
pub(super) struct BuildQueueConfig {
    pub max_inflight: usize,
    pub queue_limit: usize,
    pub lock_timeout: Duration,
}

impl BuildQueueConfig {
    pub(super) fn from_env() -> Self {
        Self {
            max_inflight: env_usize("AGENTENV_BUILD_MAX_INFLIGHT", 4).max(1),
            queue_limit: env_usize("AGENTENV_BUILD_QUEUE_LIMIT", 128),
            lock_timeout: Duration::from_secs(
                env_usize("AGENTENV_BUILD_LOCK_TIMEOUT_SECS", 900) as u64
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct BuildInput {
    pub env_name: String,
    pub dockerfile: PathBuf,
    pub staged_context: PathBuf,
    pub context_digest: String,
    pub expected_digest: Option<String>,
    pub agentenv_version: String,
    pub agent: String,
    pub mcp_port: String,
    pub workspace_mount: String,
    pub seed: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct BuildMaterialization {
    pub image_ref: String,
    pub image_digest: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildMetadata {
    version: u8,
    build_key: String,
    driver: String,
    driver_version: String,
    image_ref: String,
    image_digest: String,
    created_at: String,
    source: BuildSourceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildSourceMetadata {
    dockerfile: String,
    context_digest: String,
}

pub(super) struct BuildCache<'a> {
    root: PathBuf,
    config: BuildQueueConfig,
    events: &'a dyn EventEmitter,
}

impl<'a> BuildCache<'a> {
    pub(super) fn new(root: PathBuf, events: &'a dyn EventEmitter) -> Self {
        Self {
            root,
            config: BuildQueueConfig::from_env(),
            events,
        }
    }

    pub(super) fn digest_staged_context(path: &Path) -> DriverResult<String> {
        let mut entries = Vec::new();
        collect_context_entries(path, path, &mut entries)?;
        entries.sort_by(|left, right| left.path.cmp(&right.path).then(left.kind.cmp(right.kind)));

        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend_from_slice(entry.kind.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(entry.path.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(entry.mode.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&entry.payload);
            bytes.push(0);
        }

        Ok(format!("sha256:{}", sha256_hex(&bytes)))
    }

    pub(super) fn build_key(&self, input: &BuildInput) -> DriverResult<String> {
        parse_sha256_digest(&input.context_digest).map_err(|source| DriverError::InvalidInput {
            message: format!(
                "staged BYO context digest `{}` is invalid: {source}",
                input.context_digest
            ),
        })?;
        if !input.staged_context.is_dir() {
            return Err(DriverError::InvalidInput {
                message: format!(
                    "staged BYO context `{}` is not a directory",
                    input.staged_context.display()
                ),
            });
        }
        if let Some(seed) = input.seed.as_deref() {
            parse_sha256_digest(seed).map_err(|source| DriverError::InvalidInput {
                message: format!("BYO build seed `{seed}` is invalid: {source}"),
            })?;
        }

        let dockerfile =
            fs::canonicalize(&input.dockerfile).map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to resolve BYO Dockerfile `{}`: {source}",
                    input.dockerfile.display()
                ),
            })?;
        let material = BuildKeyMaterial {
            version: 1,
            seed: input.seed.as_deref(),
            dockerfile: dockerfile.display().to_string(),
            context_digest: &input.context_digest,
            build_args: build_args(input),
            driver_version: env!("CARGO_PKG_VERSION"),
        };
        let bytes = serde_json::to_vec(&material).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to serialize BYO build cache key material: {source}"),
        })?;

        Ok(format!("sha256:{}", sha256_hex(&bytes)))
    }

    pub(super) fn cache_dir(&self, key: &str) -> PathBuf {
        self.root.join("build-cache").join(cache_dir_name(key))
    }

    pub(super) fn write_env_digest(&self, env_name: &str, digest: &str) -> DriverResult<()> {
        parse_sha256_digest(digest).map_err(|source| DriverError::InvalidInput {
            message: format!("cached BYO image digest `{digest}` is invalid: {source}"),
        })?;
        let digest_dir = self.root.join("build").join(sanitize_build_name(env_name));
        fs::create_dir_all(&digest_dir).map_err(|source| DriverError::InvalidInput {
            message: format!(
                "failed to create BYO digest sidecar directory `{}`: {source}",
                digest_dir.display()
            ),
        })?;
        fs::write(digest_dir.join("image-digest"), format!("{digest}\n")).map_err(|source| {
            DriverError::InvalidInput {
                message: format!("failed to write BYO digest sidecar for `{env_name}`: {source}"),
            }
        })?;
        Ok(())
    }

    pub(super) fn materialize_cached(
        &self,
        input: &BuildInput,
        runner: &dyn CommandRunner,
    ) -> DriverResult<Option<BuildMaterialization>> {
        let key = self.build_key(input)?;
        let cache_dir = self.cache_dir(&key);
        let Some(metadata) = self.read_valid_metadata(input, &key, &cache_dir, runner)? else {
            return Ok(None);
        };

        self.write_env_digest(&input.env_name, &metadata.image_digest)?;
        self.emit_hit(&input.env_name, &key, &metadata.image_digest);

        Ok(Some(BuildMaterialization {
            image_ref: metadata.image_ref,
            image_digest: metadata.image_digest,
            tag: tag_for_key(&key),
        }))
    }

    fn read_valid_metadata(
        &self,
        input: &BuildInput,
        key: &str,
        cache_dir: &Path,
        runner: &dyn CommandRunner,
    ) -> DriverResult<Option<BuildMetadata>> {
        let metadata_path = cache_dir.join("metadata.json");
        if !metadata_path.is_file() {
            return Ok(None);
        }

        let metadata_bytes =
            fs::read(&metadata_path).map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to read build cache metadata `{}`: {source}",
                    metadata_path.display()
                ),
            })?;
        let metadata: BuildMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|source| {
                DriverError::InvalidInput {
                    message: format!(
                        "failed to parse build cache metadata `{}`: {source}",
                        metadata_path.display()
                    ),
                }
            })?;

        if !self.metadata_matches(input, key, cache_dir, &metadata)? {
            return Ok(None);
        }
        if !self.docker_image_matches(key, &metadata.image_digest, runner)? {
            return Ok(None);
        }

        Ok(Some(metadata))
    }

    fn metadata_matches(
        &self,
        input: &BuildInput,
        key: &str,
        cache_dir: &Path,
        metadata: &BuildMetadata,
    ) -> DriverResult<bool> {
        if metadata.version != 1
            || metadata.build_key != key
            || metadata.driver != "openshell"
            || metadata.driver_version != env!("CARGO_PKG_VERSION")
            || metadata.source.context_digest != input.context_digest
        {
            return Ok(false);
        }

        parse_sha256_digest(&metadata.image_digest).map_err(|source| {
            DriverError::InvalidInput {
                message: format!(
                    "cached BYO image digest `{}` is invalid: {source}",
                    metadata.image_digest
                ),
            }
        })?;
        if let Some(expected) = input.expected_digest.as_deref() {
            parse_sha256_digest(expected).map_err(|source| DriverError::InvalidInput {
                message: format!("expected BYO image digest `{expected}` is invalid: {source}"),
            })?;
            if expected != metadata.image_digest {
                return Ok(false);
            }
        }

        let digest_path = cache_dir.join("image-digest");
        let digest_file =
            fs::read_to_string(&digest_path).map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to read build cache digest `{}`: {source}",
                    digest_path.display()
                ),
            })?;
        if digest_file.trim() != metadata.image_digest {
            return Ok(false);
        }

        let expected_context = cache_dir.join("context");
        if metadata.image_ref != expected_context.display().to_string()
            || !expected_context.is_dir()
        {
            return Ok(false);
        }

        let source_dockerfile =
            fs::canonicalize(&metadata.source.dockerfile).map_err(|source| {
                DriverError::InvalidInput {
                    message: format!(
                        "failed to resolve cached BYO Dockerfile `{}`: {source}",
                        metadata.source.dockerfile
                    ),
                }
            })?;
        let input_dockerfile =
            fs::canonicalize(&input.dockerfile).map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to resolve BYO Dockerfile `{}`: {source}",
                    input.dockerfile.display()
                ),
            })?;
        if source_dockerfile != input_dockerfile {
            return Ok(false);
        }

        Ok(true)
    }

    fn docker_image_matches(
        &self,
        key: &str,
        expected_digest: &str,
        runner: &dyn CommandRunner,
    ) -> DriverResult<bool> {
        let request = CommandRequest {
            args: vec![
                "image".to_owned(),
                "inspect".to_owned(),
                "--format".to_owned(),
                "{{.Id}}".to_owned(),
                tag_for_key(key),
            ],
            env: BTreeMap::new(),
        };
        let command = command_string("docker", &request.args);
        let output =
            runner
                .run("docker", &request)
                .map_err(|source| DriverError::CommandSpawn {
                    command: command.clone(),
                    source,
                })?;
        if output.status.is_none_or(|status| status != 0) {
            return Ok(false);
        }

        Ok(output.stdout.trim() == expected_digest)
    }

    fn emit_hit(&self, env_name: &str, key: &str, digest: &str) {
        let event = ActivityEvent::new(
            now_timestamp_string(),
            ActivityKind::BuildOneflightHit,
            ActivityResult::Ok,
            format!("openshell-build-cache-{}", Uuid::new_v4()),
        )
        .with_env(env_name)
        .with_actor_value("driver", serde_json::json!("openshell"))
        .with_subject_value("build_key", serde_json::json!(key))
        .with_extra("image_digest", serde_json::json!(digest))
        .with_extra("max_inflight", serde_json::json!(self.config.max_inflight))
        .with_extra("queue_limit", serde_json::json!(self.config.queue_limit))
        .with_extra(
            "lock_timeout_secs",
            serde_json::json!(self.config.lock_timeout.as_secs()),
        );
        self.events.emit(event);
    }
}

#[derive(Debug, Serialize)]
struct BuildKeyMaterial<'a> {
    version: u8,
    seed: Option<&'a str>,
    dockerfile: String,
    context_digest: &'a str,
    build_args: Vec<String>,
    driver_version: &'a str,
}

#[derive(Debug)]
struct ContextEntry {
    kind: &'static str,
    path: String,
    mode: String,
    payload: Vec<u8>,
}

pub(super) fn tag_for_key(key: &str) -> String {
    let suffix = key
        .strip_prefix("sha256:")
        .unwrap_or(key)
        .chars()
        .take(12)
        .collect::<String>();
    format!("agentenv-byo-{suffix}:latest")
}

fn cache_dir_name(key: &str) -> String {
    key.replace(':', "-")
}

fn build_args(input: &BuildInput) -> Vec<String> {
    vec![
        format!("AGENTENV_VERSION={}", input.agentenv_version),
        format!("AGENTENV_AGENT={}", input.agent),
        format!("AGENTENV_MCP_PORT={}", input.mcp_port),
        format!("AGENTENV_WORKSPACE_MOUNT={}", input.workspace_mount),
    ]
}

fn collect_context_entries(
    root: &Path,
    path: &Path,
    entries: &mut Vec<ContextEntry>,
) -> DriverResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DriverError::InvalidInput {
        message: format!(
            "failed to stat staged context `{}`: {source}",
            path.display()
        ),
    })?;

    if metadata.is_dir() {
        let read_dir = fs::read_dir(path).map_err(|source| DriverError::InvalidInput {
            message: format!(
                "failed to read staged context directory `{}`: {source}",
                path.display()
            ),
        })?;
        for entry in read_dir {
            let entry = entry.map_err(|source| DriverError::InvalidInput {
                message: format!(
                    "failed to read staged context directory entry `{}`: {source}",
                    path.display()
                ),
            })?;
            collect_context_entries(root, &entry.path(), entries)?;
        }
        return Ok(());
    }

    let relative = path
        .strip_prefix(root)
        .map_err(|source| DriverError::InvalidInput {
            message: format!(
                "failed to relativize staged context path `{}`: {source}",
                path.display()
            ),
        })?
        .to_string_lossy()
        .replace('\\', "/");
    let mode = file_mode(&metadata);

    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|source| DriverError::InvalidInput {
            message: format!(
                "failed to read staged symlink `{}`: {source}",
                path.display()
            ),
        })?;
        entries.push(ContextEntry {
            kind: "symlink",
            path: relative,
            mode,
            payload: target.to_string_lossy().into_owned().into_bytes(),
        });
    } else if metadata.is_file() {
        let payload = fs::read(path).map_err(|source| DriverError::InvalidInput {
            message: format!("failed to read staged file `{}`: {source}", path.display()),
        })?;
        entries.push(ContextEntry {
            kind: "file",
            path: relative,
            mode,
            payload,
        });
    }

    Ok(())
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;

    format!("{:o}", metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> String {
    "portable".to_owned()
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}
