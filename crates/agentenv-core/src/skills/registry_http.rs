use std::{
    cmp::Ordering,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use reqwest::{redirect::Policy, Client, Method};
use semver::Version;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::security::ssrf::{validate_outbound, SsrfOptions};

use super::signature::verify_skill_package_signature;
use super::{
    compute_bundle_digest,
    manifest::{load_remote_skill_manifest, normalize_bundle_path, validated_bundle_file},
    validate_skill_name, verify_ed25519_signature, FetchedSkill, RegistryAdapter, SkillError,
    SkillManifest, SkillSearchHit, SkillSelfTestAttestation,
};

const BUNDLES_DIR: &str = "bundles";
const CONTENT_DIR: &str = "content";
const INDEX_JSON_FILE: &str = "index.json";
const INDEX_YAML_FILE: &str = "index.yaml";
const MANIFEST_FILE: &str = "skill.yaml";
const SKILL_TEST_FILE: &str = "skill-test.yaml";
const SOURCE_TYPE: &str = "http";

#[derive(Debug, Clone)]
pub(crate) struct HttpRegistryAdapter {
    name: String,
    base_url: Url,
    bearer_token: Option<String>,
    client: Client,
    ssrf_options: SsrfOptions,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct HttpRegistryIndex {
    #[serde(default, alias = "entries")]
    skills: Vec<SkillSearchHit>,
}

#[derive(Debug, Clone, Copy)]
enum HttpRegistryIndexFormat {
    Json,
    Yaml,
}

impl HttpRegistryAdapter {
    pub(crate) fn new(
        name: impl Into<String>,
        base_url: impl AsRef<str>,
        bearer_token: Option<String>,
        ssrf_options: SsrfOptions,
    ) -> Result<Self, SkillError> {
        let base_url =
            Url::parse(base_url.as_ref()).map_err(|source| SkillError::InvalidConfig {
                message: format!("invalid HTTP registry URL: {source}"),
            })?;
        validate_registry_url(&base_url, &ssrf_options)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|source| SkillError::HttpRegistry {
                url: base_url.to_string(),
                source: Box::new(source),
            })?;
        Ok(Self {
            name: name.into(),
            base_url,
            bearer_token,
            client,
            ssrf_options,
        })
    }

    fn index_json_url(&self) -> Result<Url, SkillError> {
        self.url_for(&[INDEX_JSON_FILE])
    }

    fn index_yaml_url(&self) -> Result<Url, SkillError> {
        self.url_for(&[INDEX_YAML_FILE])
    }

    fn manifest_url(&self, name: &str, version: &str) -> Result<Url, SkillError> {
        self.url_for(&[BUNDLES_DIR, name, version, MANIFEST_FILE])
    }

    fn skill_test_url(&self, name: &str, version: &str) -> Result<Url, SkillError> {
        self.url_for(&[BUNDLES_DIR, name, version, SKILL_TEST_FILE])
    }

    fn attestation_url(&self, name: &str, version: &str) -> Result<Url, SkillError> {
        self.url_for(&[BUNDLES_DIR, name, version, "self-test-attestation.json"])
    }

    fn tarball_url(&self, name: &str, version: &str) -> Result<Url, SkillError> {
        self.url_for(&["skills", name, &format!("{version}.tar.zst")])
    }

    fn tarball_signature_url(&self, name: &str, version: &str) -> Result<Url, SkillError> {
        self.url_for(&["skills", name, &format!("{version}.tar.zst.sig")])
    }

    fn content_url(
        &self,
        name: &str,
        version: &str,
        relative_path: &Path,
    ) -> Result<Url, SkillError> {
        let mut segments = vec![BUNDLES_DIR, name, version, CONTENT_DIR];
        let path_segments = relative_path
            .components()
            .map(|component| match component {
                Component::Normal(part) => {
                    part.to_str().ok_or_else(|| SkillError::UnsafeBundlePath {
                        path: relative_path.to_path_buf(),
                    })
                }
                _ => Err(SkillError::UnsafeBundlePath {
                    path: relative_path.to_path_buf(),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        segments.extend(path_segments);
        self.url_for(&segments)
    }

    fn url_for(&self, segments: &[&str]) -> Result<Url, SkillError> {
        let mut url = self.base_url.clone();
        {
            let mut path_segments =
                url.path_segments_mut()
                    .map_err(|_| SkillError::InvalidConfig {
                        message: format!(
                            "HTTP registry `{}` cannot be used as a base URL",
                            self.base_url
                        ),
                    })?;
            path_segments.pop_if_empty();
            for segment in segments {
                path_segments.push(segment);
            }
        }
        validate_registry_url(&url, &self.ssrf_options)?;
        Ok(url)
    }

    async fn read_index(&self) -> Result<HttpRegistryIndex, SkillError> {
        self.read_index_with_format()
            .await
            .map(|(index, _format)| index)
    }

    async fn read_index_with_format(
        &self,
    ) -> Result<(HttpRegistryIndex, HttpRegistryIndexFormat), SkillError> {
        if let Some(content) = self.get_optional_text(self.index_json_url()?).await? {
            let mut index: HttpRegistryIndex =
                serde_json::from_str(&content).map_err(|source| SkillError::InvalidConfig {
                    message: format!("failed to parse HTTP registry index JSON: {source}"),
                })?;
            self.validate_index(&mut index)?;
            return Ok((index, HttpRegistryIndexFormat::Json));
        }

        let Some(content) = self.get_optional_text(self.index_yaml_url()?).await? else {
            return Ok((HttpRegistryIndex::default(), HttpRegistryIndexFormat::Json));
        };
        let mut index: HttpRegistryIndex =
            serde_yaml::from_str(&content).map_err(|source| SkillError::Yaml {
                path: PathBuf::from(INDEX_YAML_FILE),
                source,
            })?;
        self.validate_index(&mut index)?;
        Ok((index, HttpRegistryIndexFormat::Yaml))
    }

    fn validate_index(&self, index: &mut HttpRegistryIndex) -> Result<(), SkillError> {
        for hit in &mut index.skills {
            self.validate_hit(hit)?;
        }
        Ok(())
    }

    async fn write_index(
        &self,
        mut index: HttpRegistryIndex,
        format: HttpRegistryIndexFormat,
    ) -> Result<(), SkillError> {
        sort_hits(&mut index.skills);
        match format {
            HttpRegistryIndexFormat::Json => {
                let content = serde_json::to_vec_pretty(&index).map_err(|source| {
                    SkillError::InvalidConfig {
                        message: format!("failed to serialize HTTP registry index JSON: {source}"),
                    }
                })?;
                self.put_bytes(self.index_json_url()?, content).await
            }
            HttpRegistryIndexFormat::Yaml => {
                let content =
                    serde_yaml::to_string(&index).map_err(|source| SkillError::Serde {
                        path: PathBuf::from(INDEX_YAML_FILE),
                        source,
                    })?;
                self.put_bytes(self.index_yaml_url()?, content.into_bytes())
                    .await
            }
        }
    }

    fn validate_hit(&self, hit: &mut SkillSearchHit) -> Result<(), SkillError> {
        validate_skill_name(&hit.name)?;
        hit.version
            .parse::<Version>()
            .map_err(|source| SkillError::InvalidVersion {
                version: hit.version.clone(),
                source,
            })?;
        hit.registry = self.name.clone();
        Ok(())
    }

    fn hit_for_manifest(&self, manifest: &SkillManifest, digest: String) -> SkillSearchHit {
        SkillSearchHit {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            description: manifest.description.clone(),
            registry: self.name.clone(),
            digest: Some(digest),
            signature_ed25519: manifest.signature_ed25519.clone(),
            public_key_ed25519: manifest.signature_public_key_ed25519.clone(),
            self_test_score: None,
            self_test_attestation_digest: None,
        }
    }

    async fn resolved_hit(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SkillSearchHit, SkillError> {
        validate_skill_name(name)?;
        if let Some(version) = version {
            version
                .parse::<Version>()
                .map_err(|source| SkillError::InvalidVersion {
                    version: version.to_owned(),
                    source,
                })?;
        }

        let index = self.read_index().await?;
        let matches = index
            .skills
            .into_iter()
            .filter(|hit| hit.name == name)
            .collect::<Vec<_>>();

        if let Some(version) = version {
            return matches
                .into_iter()
                .find(|hit| hit.version == version)
                .ok_or_else(|| SkillError::SkillNotInstalled {
                    name: name.to_owned(),
                });
        }

        matches
            .into_iter()
            .max_by(|left, right| compare_versions(&left.version, &right.version))
            .ok_or_else(|| SkillError::SkillNotInstalled {
                name: name.to_owned(),
            })
    }

    async fn get_optional_text(&self, url: Url) -> Result<Option<String>, SkillError> {
        let url_text = url.to_string();
        let response = self
            .request(Method::GET, url.clone(), None)
            .await
            .map_err(|source| map_request_error(url_text.clone(), source))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure_success(&url, response.status())?;
        response
            .text()
            .await
            .map(Some)
            .map_err(|source| SkillError::HttpRegistry {
                url: url.to_string(),
                source: Box::new(source),
            })
    }

    async fn get_text(&self, url: Url) -> Result<String, SkillError> {
        self.get_optional_text(url.clone())
            .await?
            .ok_or_else(|| SkillError::HttpStatus {
                url: url.to_string(),
                status: reqwest::StatusCode::NOT_FOUND,
            })
    }

    async fn get_optional_bytes(&self, url: Url) -> Result<Option<Vec<u8>>, SkillError> {
        let url_text = url.to_string();
        let response = self
            .request(Method::GET, url.clone(), None)
            .await
            .map_err(|source| map_request_error(url_text.clone(), source))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure_success(&url, response.status())?;
        response
            .bytes()
            .await
            .map(|bytes| Some(bytes.to_vec()))
            .map_err(|source| SkillError::HttpRegistry {
                url: url.to_string(),
                source: Box::new(source),
            })
    }

    async fn get_bytes(&self, url: Url) -> Result<Vec<u8>, SkillError> {
        let response = self.request(Method::GET, url.clone(), None).await?;
        ensure_success(&url, response.status())?;
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|source| SkillError::HttpRegistry {
                url: url.to_string(),
                source: Box::new(source),
            })
    }

    async fn fetch_expanded_bundle(
        &self,
        hit: &SkillSearchHit,
        staging_path: &Path,
    ) -> Result<(), SkillError> {
        let manifest_url = self.manifest_url(&hit.name, &hit.version)?;
        let manifest_content = self.get_text(manifest_url).await?;
        let remote_manifest =
            load_remote_skill_manifest(&manifest_content, Path::new(MANIFEST_FILE))?;
        if remote_manifest.name != hit.name || remote_manifest.version.to_string() != hit.version {
            return Err(SkillError::InvalidConfig {
                message: format!(
                    "HTTP registry index selected `{}` version `{}`, but manifest is `{}` version `{}`",
                    hit.name, hit.version, remote_manifest.name, remote_manifest.version
                ),
            });
        }
        write_file(
            &staging_path.join(MANIFEST_FILE),
            manifest_content.as_bytes(),
        )?;

        for declared_file in &remote_manifest.declared_files {
            let content = self
                .get_bytes(self.content_url(&hit.name, &hit.version, declared_file)?)
                .await?;
            write_file(&staging_path.join(declared_file), &content)?;
        }
        if let Some(content) = self
            .get_optional_bytes(self.skill_test_url(&hit.name, &hit.version)?)
            .await?
        {
            write_file(&staging_path.join(SKILL_TEST_FILE), &content)?;
        }

        Ok(())
    }

    async fn verify_tarball_signature_sidecar(
        &self,
        hit: &SkillSearchHit,
        manifest: &SkillManifest,
        digest: &str,
    ) -> Result<(), SkillError> {
        if hit.signature_ed25519.is_none() && hit.public_key_ed25519.is_none() {
            return Ok(());
        }

        let public_key =
            hit.public_key_ed25519
                .as_deref()
                .ok_or_else(|| SkillError::MissingSignature {
                    name: hit.name.clone(),
                    version: hit.version.clone(),
                })?;
        let signature_bytes = self
            .get_bytes(self.tarball_signature_url(&hit.name, &hit.version)?)
            .await?;
        let signature = std::str::from_utf8(&signature_bytes)
            .map_err(|source| SkillError::InvalidSignature {
                name: hit.name.clone(),
                version: hit.version.clone(),
                message: format!("signature sidecar is not valid UTF-8: {source}"),
            })?
            .trim();
        if signature.is_empty() {
            return Err(SkillError::InvalidSignature {
                name: hit.name.clone(),
                version: hit.version.clone(),
                message: "signature sidecar is empty".to_owned(),
            });
        }
        if let Some(index_signature) = hit.signature_ed25519.as_deref() {
            if index_signature != signature {
                return Err(SkillError::InvalidSignature {
                    name: hit.name.clone(),
                    version: hit.version.clone(),
                    message: "signature sidecar does not match index signature".to_owned(),
                });
            }
        }

        verify_ed25519_signature(manifest, digest, signature, public_key)
    }

    async fn put_bytes(&self, url: Url, body: Vec<u8>) -> Result<(), SkillError> {
        let response = self.request(Method::PUT, url.clone(), Some(body)).await?;
        ensure_success(&url, response.status())
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, SkillError> {
        let mut request = self.client.request(method, url.clone());
        if let Some(token) = self.bearer_token.as_deref() {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|source| SkillError::HttpRegistry {
                url: url.to_string(),
                source: Box::new(source),
            })
    }
}

#[async_trait::async_trait]
impl RegistryAdapter for HttpRegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        let query = query.to_ascii_lowercase();
        let index = self.read_index().await?;
        let mut hits = index
            .skills
            .into_iter()
            .filter(|hit| {
                let searchable_description = hit.description.as_deref().unwrap_or_default();
                query.is_empty()
                    || hit.name.to_ascii_lowercase().contains(&query)
                    || searchable_description.to_ascii_lowercase().contains(&query)
            })
            .collect::<Vec<_>>();
        sort_hits(&mut hits);
        Ok(hits)
    }

    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError> {
        let hit = self.resolved_hit(name, version).await?;
        let staging_path = staging_fetch_path(&hit.name, &hit.version);
        remove_directory_if_exists(&staging_path)?;
        fs::create_dir_all(&staging_path).map_err(|source| SkillError::Io {
            path: staging_path.clone(),
            source,
        })?;

        let used_tarball = if let Some(bytes) = self
            .get_optional_bytes(self.tarball_url(&hit.name, &hit.version)?)
            .await?
        {
            unpack_tar_zst(&bytes, &staging_path)?;
            true
        } else {
            self.fetch_expanded_bundle(&hit, &staging_path).await?;
            false
        };

        let manifest = super::load_skill_manifest(&staging_path)?;
        if manifest.name != hit.name || manifest.version.to_string() != hit.version {
            return Err(SkillError::InvalidConfig {
                message: format!(
                    "HTTP registry index selected `{}` version `{}`, but manifest is `{}` version `{}`",
                    hit.name, hit.version, manifest.name, manifest.version
                ),
            });
        }
        let digest = compute_bundle_digest(&staging_path, &manifest)?;
        if let Some(expected) = hit.digest.as_deref() {
            if expected != digest {
                return Err(SkillError::DigestMismatch {
                    expected: expected.to_owned(),
                    actual: digest,
                });
            }
        }
        if used_tarball {
            self.verify_tarball_signature_sidecar(&hit, &manifest, &digest)
                .await?;
        }

        Ok(FetchedSkill {
            staging_path,
            registry: self.name.clone(),
            source_type: SOURCE_TYPE.to_owned(),
            name: manifest.name,
            version: manifest.version.to_string(),
        })
    }

    async fn publish(
        &self,
        bundle_path: &Path,
        allow_unsigned: bool,
        attestation: Option<&SkillSelfTestAttestation>,
    ) -> Result<SkillSearchHit, SkillError> {
        let manifest = super::load_skill_manifest(bundle_path)?;
        let digest = compute_bundle_digest(bundle_path, &manifest)?;
        verify_publish_signature(&manifest, &digest, allow_unsigned)?;
        let attestation = attestation.ok_or(SkillError::MissingSelfTestAttestation)?;
        let version = manifest.version.to_string();
        let mut hit = self.hit_for_manifest(&manifest, digest.clone());
        hit.apply_self_test_attestation(Some(attestation));
        let (mut index, index_format) = self.read_index_with_format().await?;

        if let Some(existing) = index
            .skills
            .iter()
            .find(|hit| hit.name == manifest.name && hit.version == version)
        {
            if existing.digest.as_deref() != Some(digest.as_str()) {
                return Err(SkillError::AlreadyInstalledDifferentDigest {
                    name: manifest.name,
                    version,
                    existing: existing
                        .digest
                        .clone()
                        .unwrap_or_else(|| "unknown".to_owned()),
                });
            }
        }

        let manifest_bytes = read_regular_file(&bundle_path.join(MANIFEST_FILE))?;
        self.put_bytes(self.manifest_url(&manifest.name, &version)?, manifest_bytes)
            .await?;
        if let Some(bytes) = read_optional_regular_file(&bundle_path.join(SKILL_TEST_FILE))? {
            self.put_bytes(self.skill_test_url(&manifest.name, &version)?, bytes)
                .await?;
        }
        for declared_file in &manifest.declared_files {
            let source = validated_bundle_file(bundle_path, declared_file)?;
            let bytes = read_regular_file(&source)?;
            self.put_bytes(
                self.content_url(&manifest.name, &version, declared_file)?,
                bytes,
            )
            .await?;
        }
        let bytes = serde_json::to_vec_pretty(attestation).map_err(|source| {
            SkillError::InvalidSelfTestAttestation {
                message: format!("failed to serialize self-test attestation: {source}"),
            }
        })?;
        self.put_bytes(self.attestation_url(&manifest.name, &version)?, bytes)
            .await?;

        index
            .skills
            .retain(|existing| existing.name != hit.name || existing.version != hit.version);
        index.skills.push(hit.clone());
        self.write_index(index, index_format).await?;
        Ok(hit)
    }
}

fn unpack_tar_zst(bytes: &[u8], destination: &Path) -> Result<(), SkillError> {
    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|source| SkillError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|source| SkillError::Io {
        path: destination.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let mut entry = entry.map_err(|source| SkillError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
        let entry_path = entry
            .path()
            .map_err(|source| SkillError::Io {
                path: destination.to_path_buf(),
                source,
            })?
            .into_owned();
        let normalized = normalize_bundle_path(&entry_path)?;
        let target = destination.join(normalized);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&target).map_err(|source| SkillError::Io {
                path: target,
                source,
            })?;
        } else if entry_type.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|source| SkillError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            entry.unpack(&target).map_err(|source| SkillError::Io {
                path: target,
                source,
            })?;
        } else {
            return Err(SkillError::UnsafeBundlePath { path: entry_path });
        }
    }

    Ok(())
}

fn validate_registry_url(url: &Url, options: &SsrfOptions) -> Result<(), SkillError> {
    validate_outbound(url, options.clone())
        .map(|_| ())
        .map_err(|source| SkillError::RegistryUrlBlocked {
            url: url.to_string(),
            source: Box::new(source),
        })
}

fn ensure_success(url: &Url, status: reqwest::StatusCode) -> Result<(), SkillError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(SkillError::HttpStatus {
            url: url.to_string(),
            status,
        })
    }
}

fn map_request_error(url: String, source: SkillError) -> SkillError {
    match source {
        SkillError::HttpRegistry { source, .. } => SkillError::HttpRegistry { url, source },
        other => other,
    }
}

fn verify_publish_signature(
    manifest: &SkillManifest,
    digest: &str,
    allow_unsigned: bool,
) -> Result<(), SkillError> {
    verify_skill_package_signature(manifest, digest, allow_unsigned).map(|_| ())
}

fn remove_directory_if_exists(path: &Path) -> Result<(), SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir_all(path).map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_file(path: &Path, content: &[u8]) -> Result<(), SkillError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SkillError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, content).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_optional_regular_file(path: &Path) -> Result<Option<Vec<u8>>, SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => read_regular_file(path).map(Some),
        Ok(_) => Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn read_regular_file(path: &Path) -> Result<Vec<u8>, SkillError> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    ensure_opened_regular_file(path, &file)?;
    read_opened_file(path, &mut file)
}

#[cfg(not(unix))]
fn read_regular_file(path: &Path) -> Result<Vec<u8>, SkillError> {
    let mut file = fs::File::open(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    ensure_opened_regular_file(path, &file)?;
    read_opened_file(path, &mut file)
}

fn ensure_opened_regular_file(path: &Path, file: &fs::File) -> Result<(), SkillError> {
    let metadata = file.metadata().map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        })
    }
}

fn read_opened_file(path: &Path, file: &mut fs::File) -> Result<Vec<u8>, SkillError> {
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(content)
}

fn staging_fetch_path(name: &str, version: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "agentenv-skill-http-fetch-{name}-{version}-{}-{}",
        std::process::id(),
        temporary_suffix()
    ))
}

fn temporary_suffix() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    }
}

fn sort_hits(hits: &mut [SkillSearchHit]) {
    hits.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| compare_versions(&left.version, &right.version))
    });
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    match (left.parse::<Version>(), right.parse::<Version>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}
