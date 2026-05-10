use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use reqwest::{header, redirect::Policy, Client, Method, StatusCode};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::security::ssrf::{validate_outbound, SsrfOptions};

use super::{
    compute_bundle_digest,
    manifest::{normalize_bundle_path, validated_bundle_file},
    validate_skill_name, verify_ed25519_signature, FetchedSkill, RegistryAdapter, SkillError,
    SkillManifest, SkillSearchHit,
};

const OCI_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const AGENTENV_SKILL_CONFIG: &str = "application/vnd.agentenv.skill.config.v1+json";
const AGENTENV_SKILL_MANIFEST: &str = "application/vnd.agentenv.skill.manifest.v1+yaml";
const AGENTENV_SKILL_FILE: &str = "application/vnd.agentenv.skill.file.v1";
const AGENTENV_SKILLS_INDEX: &str = "application/vnd.agentenv.skills.index.v1+yaml";
const SKILL_PATH_ANNOTATION: &str = "io.agentenv.skill.path";
const INDEX_TAG: &str = "skills-index";
const MANIFEST_FILE: &str = "skill.yaml";
const SOURCE_TYPE: &str = "oci";

#[derive(Debug, Clone)]
pub(crate) struct OciRegistryAdapter {
    name: String,
    reference: OciReference,
    base_url: Url,
    bearer_token: Option<String>,
    client: Client,
    ssrf_options: SsrfOptions,
}

#[derive(Debug, Clone)]
struct OciReference {
    registry: String,
    repository: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OciSkillIndex {
    #[serde(default, alias = "entries")]
    skills: Vec<SkillSearchHit>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciImageManifest {
    schema_version: u32,
    media_type: String,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciDescriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

impl OciRegistryAdapter {
    pub(crate) fn new(
        name: impl Into<String>,
        reference: impl AsRef<str>,
        bearer_token: Option<String>,
        ssrf_options: SsrfOptions,
    ) -> Result<Self, SkillError> {
        let reference = OciReference::parse(reference.as_ref())?;
        let base_url = registry_base_url(&reference, &ssrf_options)?;
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
            reference,
            base_url,
            bearer_token,
            client,
            ssrf_options,
        })
    }

    fn manifest_url(&self, tag: &str) -> Result<Url, SkillError> {
        self.url_for(&["manifests", tag])
    }

    fn blob_url(&self, digest: &str) -> Result<Url, SkillError> {
        self.url_for(&["blobs", digest])
    }

    fn upload_url(&self) -> Result<Url, SkillError> {
        self.url_for(&["blobs", "uploads"])
    }

    fn url_for(&self, tail_segments: &[&str]) -> Result<Url, SkillError> {
        let mut url = self.base_url.clone();
        {
            let mut segments =
                url.path_segments_mut()
                    .map_err(|_| SkillError::InvalidOciReference {
                        reference: self.reference.as_string(),
                    })?;
            segments.pop_if_empty();
            segments.push("v2");
            for component in self.reference.repository.split('/') {
                segments.push(component);
            }
            for segment in tail_segments {
                segments.push(segment);
            }
            if matches!(tail_segments, ["blobs", "uploads"]) {
                segments.push("");
            }
        }
        validate_registry_url(&url, &self.ssrf_options)?;
        Ok(url)
    }

    async fn read_index(&self) -> Result<OciSkillIndex, SkillError> {
        let Some(manifest) = self.get_optional_manifest(INDEX_TAG).await? else {
            return Ok(OciSkillIndex::default());
        };
        let Some(index_layer) = manifest
            .layers
            .iter()
            .find(|layer| layer.media_type == AGENTENV_SKILLS_INDEX)
        else {
            return Ok(OciSkillIndex::default());
        };
        let content = self.get_blob_text(&index_layer.digest).await?;
        let mut index: OciSkillIndex =
            serde_yaml::from_str(&content).map_err(|source| SkillError::Yaml {
                path: PathBuf::from(INDEX_TAG),
                source,
            })?;
        for hit in &mut index.skills {
            self.validate_hit(hit)?;
        }
        Ok(index)
    }

    async fn write_index(&self, mut index: OciSkillIndex) -> Result<(), SkillError> {
        sort_hits(&mut index.skills);
        let content = serde_yaml::to_string(&index).map_err(|source| SkillError::Serde {
            path: PathBuf::from(INDEX_TAG),
            source,
        })?;
        let config = self
            .upload_blob(AGENTENV_SKILL_CONFIG, b"{}".to_vec())
            .await?;
        let layer = self
            .upload_blob(AGENTENV_SKILLS_INDEX, content.into_bytes())
            .await?;
        self.put_manifest(
            INDEX_TAG,
            OciImageManifest {
                schema_version: 2,
                media_type: OCI_IMAGE_MANIFEST.to_owned(),
                config,
                layers: vec![layer],
            },
        )
        .await
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

    async fn get_optional_manifest(
        &self,
        tag: &str,
    ) -> Result<Option<OciImageManifest>, SkillError> {
        let url = self.manifest_url(tag)?;
        let response = self
            .request(Method::GET, url.clone(), None, Some(OCI_IMAGE_MANIFEST))
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure_success(&url, response.status())?;
        let text = response
            .text()
            .await
            .map_err(|source| SkillError::HttpRegistry {
                url: url.to_string(),
                source: Box::new(source),
            })?;
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|source| SkillError::InvalidConfig {
                message: format!("invalid OCI manifest for `{tag}`: {source}"),
            })
    }

    async fn get_blob(&self, digest: &str) -> Result<Vec<u8>, SkillError> {
        let url = self.blob_url(digest)?;
        let response = self.request(Method::GET, url.clone(), None, None).await?;
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

    async fn get_blob_text(&self, digest: &str) -> Result<String, SkillError> {
        let bytes = self.get_blob(digest).await?;
        String::from_utf8(bytes).map_err(|source| SkillError::InvalidConfig {
            message: format!("OCI blob `{digest}` is not UTF-8: {source}"),
        })
    }

    async fn upload_blob(
        &self,
        media_type: &str,
        content: Vec<u8>,
    ) -> Result<OciDescriptor, SkillError> {
        let digest = sha256_digest(&content);
        let upload_start = self.upload_url()?;
        let response = self
            .request(Method::POST, upload_start.clone(), None, None)
            .await?;
        ensure_success(&upload_start, response.status())?;
        let location = self.upload_location(&upload_start, &response)?;

        let response = self
            .request(Method::PATCH, location.clone(), Some(content.clone()), None)
            .await?;
        ensure_success(&location, response.status())?;
        let mut location = self.upload_location(&location, &response)?;
        location.query_pairs_mut().append_pair("digest", &digest);
        validate_registry_url(&location, &self.ssrf_options)?;

        let response = self
            .request(Method::PUT, location.clone(), None, None)
            .await?;
        ensure_success(&location, response.status())?;
        Ok(OciDescriptor {
            media_type: media_type.to_owned(),
            digest,
            size: content.len() as u64,
            annotations: BTreeMap::new(),
        })
    }

    async fn put_manifest(&self, tag: &str, manifest: OciImageManifest) -> Result<(), SkillError> {
        let url = self.manifest_url(tag)?;
        let content =
            serde_json::to_vec(&manifest).map_err(|source| SkillError::InvalidConfig {
                message: format!("failed to serialize OCI manifest `{tag}`: {source}"),
            })?;
        let response = self
            .request(
                Method::PUT,
                url.clone(),
                Some(content),
                Some(OCI_IMAGE_MANIFEST),
            )
            .await?;
        ensure_success(&url, response.status())
    }

    fn upload_location(
        &self,
        base_url: &Url,
        response: &reqwest::Response,
    ) -> Result<Url, SkillError> {
        let value = response
            .headers()
            .get(header::LOCATION)
            .ok_or_else(|| SkillError::InvalidConfig {
                message: "OCI upload response missing Location header".to_owned(),
            })?
            .to_str()
            .map_err(|source| SkillError::InvalidConfig {
                message: format!("OCI upload Location header is not valid UTF-8: {source}"),
            })?;
        let location = base_url
            .join(value)
            .map_err(|source| SkillError::InvalidConfig {
                message: format!("OCI upload Location header is invalid: {source}"),
            })?;
        validate_registry_url(&location, &self.ssrf_options)?;
        Ok(location)
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> Result<reqwest::Response, SkillError> {
        let mut request = self.client.request(method, url.clone());
        if let Some(token) = self.bearer_token.as_deref() {
            request = request.bearer_auth(token);
        }
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
            request = request.header(header::ACCEPT, content_type);
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
impl RegistryAdapter for OciRegistryAdapter {
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
        let tag = skill_tag(&hit.name, &hit.version);
        let manifest = self.get_optional_manifest(&tag).await?.ok_or_else(|| {
            SkillError::SkillNotInstalled {
                name: hit.name.clone(),
            }
        })?;
        let staging_path = staging_fetch_path(&hit.name, &hit.version);
        remove_directory_if_exists(&staging_path)?;
        fs::create_dir_all(&staging_path).map_err(|source| SkillError::Io {
            path: staging_path.clone(),
            source,
        })?;

        let manifest_layer = manifest
            .layers
            .iter()
            .find(|layer| layer.media_type == AGENTENV_SKILL_MANIFEST)
            .ok_or_else(|| SkillError::InvalidConfig {
                message: format!("OCI skill `{}` missing skill manifest layer", hit.name),
            })?;
        let manifest_content = self.get_blob(&manifest_layer.digest).await?;
        write_file(&staging_path.join(MANIFEST_FILE), &manifest_content)?;

        for layer in manifest
            .layers
            .iter()
            .filter(|layer| layer.media_type == AGENTENV_SKILL_FILE)
        {
            let relative_path = layer
                .annotations
                .get(SKILL_PATH_ANNOTATION)
                .ok_or_else(|| SkillError::InvalidConfig {
                    message: format!(
                        "OCI skill `{}` file layer missing path annotation",
                        hit.name
                    ),
                })?;
            let relative_path = normalize_bundle_path(Path::new(relative_path))?;
            let content = self.get_blob(&layer.digest).await?;
            write_file(&staging_path.join(relative_path), &content)?;
        }

        let manifest = super::load_skill_manifest(&staging_path)?;
        if manifest.name != hit.name || manifest.version.to_string() != hit.version {
            return Err(SkillError::InvalidConfig {
                message: format!(
                    "OCI index selected `{}` version `{}`, but manifest is `{}` version `{}`",
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
    ) -> Result<SkillSearchHit, SkillError> {
        let manifest = super::load_skill_manifest(bundle_path)?;
        let digest = compute_bundle_digest(bundle_path, &manifest)?;
        verify_publish_signature(&manifest, &digest, allow_unsigned)?;
        let version = manifest.version.to_string();
        let hit = self.hit_for_manifest(&manifest, digest.clone());
        let mut index = self.read_index().await?;

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

        let config = self
            .upload_blob(
                AGENTENV_SKILL_CONFIG,
                serde_json::to_vec(&hit).map_err(|source| SkillError::InvalidConfig {
                    message: format!("failed to serialize skill config: {source}"),
                })?,
            )
            .await?;
        let manifest_bytes = read_regular_file(&bundle_path.join(MANIFEST_FILE))?;
        let manifest_layer = self
            .upload_blob(AGENTENV_SKILL_MANIFEST, manifest_bytes)
            .await?;
        let mut layers = vec![manifest_layer];
        for declared_file in &manifest.declared_files {
            let source = validated_bundle_file(bundle_path, declared_file)?;
            let bytes = read_regular_file(&source)?;
            let mut descriptor = self.upload_blob(AGENTENV_SKILL_FILE, bytes).await?;
            descriptor.annotations.insert(
                SKILL_PATH_ANNOTATION.to_owned(),
                path_to_annotation(declared_file)?,
            );
            layers.push(descriptor);
        }
        self.put_manifest(
            &skill_tag(&manifest.name, &version),
            OciImageManifest {
                schema_version: 2,
                media_type: OCI_IMAGE_MANIFEST.to_owned(),
                config,
                layers,
            },
        )
        .await?;

        index
            .skills
            .retain(|existing| existing.name != hit.name || existing.version != hit.version);
        index.skills.push(hit.clone());
        self.write_index(index).await?;
        Ok(hit)
    }
}

impl OciReference {
    fn parse(reference: &str) -> Result<Self, SkillError> {
        let reference = reference.trim();
        let Some((registry, repository)) = reference.split_once('/') else {
            return Err(SkillError::InvalidOciReference {
                reference: reference.to_owned(),
            });
        };
        if registry.is_empty()
            || repository.is_empty()
            || reference.contains("://")
            || reference.contains(char::is_whitespace)
        {
            return Err(SkillError::InvalidOciReference {
                reference: reference.to_owned(),
            });
        }
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
        })
    }

    fn as_string(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }
}

fn registry_base_url(reference: &OciReference, options: &SsrfOptions) -> Result<Url, SkillError> {
    let scheme = if options.allow_loopback && is_loopback_registry(&reference.registry) {
        "http"
    } else {
        "https"
    };
    Url::parse(&format!("{scheme}://{}", reference.registry)).map_err(|_| {
        SkillError::InvalidOciReference {
            reference: reference.as_string(),
        }
    })
}

fn is_loopback_registry(registry: &str) -> bool {
    let host = registry
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or(registry);
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

fn validate_registry_url(url: &Url, options: &SsrfOptions) -> Result<(), SkillError> {
    validate_outbound(url, options.clone())
        .map(|_| ())
        .map_err(|source| SkillError::RegistryUrlBlocked {
            url: url.to_string(),
            source: Box::new(source),
        })
}

fn ensure_success(url: &Url, status: StatusCode) -> Result<(), SkillError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(SkillError::HttpStatus {
            url: url.to_string(),
            status,
        })
    }
}

fn verify_publish_signature(
    manifest: &SkillManifest,
    digest: &str,
    allow_unsigned: bool,
) -> Result<(), SkillError> {
    if allow_unsigned {
        return Ok(());
    }

    let signature =
        manifest
            .signature_ed25519
            .as_deref()
            .ok_or_else(|| SkillError::MissingSignature {
                name: manifest.name.clone(),
                version: manifest.version.to_string(),
            })?;
    let public_key = manifest
        .signature_public_key_ed25519
        .as_deref()
        .ok_or_else(|| SkillError::MissingSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
        })?;

    verify_ed25519_signature(manifest, digest, signature, public_key)
}

fn sha256_digest(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("sha256:{:x}", hasher.finalize())
}

fn skill_tag(name: &str, version: &str) -> String {
    format!("{name}:{version}")
}

fn path_to_annotation(path: &Path) -> Result<String, SkillError> {
    path.components()
        .map(|component| match component {
            Component::Normal(part) => {
                part.to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| SkillError::UnsafeBundlePath {
                        path: path.to_path_buf(),
                    })
            }
            _ => Err(SkillError::UnsafeBundlePath {
                path: path.to_path_buf(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
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
        "agentenv-skill-oci-fetch-{name}-{version}-{}-{}",
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
