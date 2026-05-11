use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use semver::Version;
use sha2::{Digest, Sha256};

use crate::security::ssrf::SsrfOptions;

use super::{
    info_installed_skill, install_local_skill, list_installed_skills, registry_filesystem,
    registry_git, registry_http, registry_oci, remove_installed_skill, validate_skill_name,
    verify_installed_skill, FetchedSkill, InstalledSkill, InstalledSkillSelector, RegistryAdapter,
    RegistryConfig, RegistryKind, SkillError, SkillInstallOptions, SkillSearchHit, SkillsConfig,
};

pub type SkillCredentialResolver =
    Arc<dyn Fn(&str) -> Result<Option<String>, SkillError> + Send + Sync>;

#[derive(Clone)]
pub struct SkillService {
    root: PathBuf,
    config: SkillsConfig,
    credential_resolver: SkillCredentialResolver,
    ssrf_options: SsrfOptions,
}

#[derive(Debug, Clone)]
pub struct SkillAddRequest {
    pub handle: String,
    pub registry: Option<String>,
    pub allow_unsigned: bool,
}

#[derive(Debug, Clone)]
pub struct SkillPublishRequest {
    pub bundle_path: PathBuf,
    pub registry: Option<String>,
    pub allow_unsigned: bool,
}

impl SkillService {
    pub fn new(root: impl Into<PathBuf>, config: SkillsConfig) -> Self {
        Self {
            root: root.into(),
            config,
            credential_resolver: Arc::new(|_| Ok(None)),
            ssrf_options: SsrfOptions::default(),
        }
    }

    pub fn with_credential_resolver(mut self, resolver: SkillCredentialResolver) -> Self {
        self.credential_resolver = resolver;
        self
    }

    pub fn with_ssrf_options(mut self, options: SsrfOptions) -> Self {
        self.ssrf_options = options;
        self
    }

    pub async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        let mut hits = Vec::new();
        for registry in self.ordered_registries()? {
            let adapter = self.adapter_for(registry)?;
            hits.extend(adapter.search(query).await?);
        }
        sort_hits(&mut hits);
        Ok(hits)
    }

    pub async fn add(&self, request: SkillAddRequest) -> Result<InstalledSkill, SkillError> {
        let parsed = ParsedSkillHandle::parse(&request.handle)?;
        let registries = match request.registry.as_deref() {
            Some(registry) => vec![self.registry_by_name(registry)?],
            None => self.ordered_registries()?,
        };

        for registry in registries {
            let adapter = self.adapter_for(registry)?;
            match adapter.fetch(&parsed.name, parsed.version.as_deref()).await {
                Ok(fetched) => {
                    return self.install_fetched_skill(fetched, request.allow_unsigned);
                }
                Err(SkillError::SkillNotInstalled { .. }) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(SkillError::SkillNotInstalled { name: parsed.name })
    }

    pub async fn publish(
        &self,
        request: SkillPublishRequest,
    ) -> Result<SkillSearchHit, SkillError> {
        let registry = match request.registry.as_deref() {
            Some(registry) => self.registry_by_name(registry)?,
            None => self
                .ordered_registries()?
                .into_iter()
                .next()
                .ok_or_else(|| SkillError::InvalidConfig {
                    message: "no skill registries configured".to_owned(),
                })?,
        };
        let adapter = self.adapter_for(registry)?;
        adapter
            .publish(&request.bundle_path, request.allow_unsigned)
            .await
    }

    pub fn install_from_path(
        &self,
        bundle_path: impl AsRef<Path>,
        allow_unsigned: bool,
        source_label: impl Into<String>,
    ) -> Result<InstalledSkill, SkillError> {
        install_local_skill(
            &self.root,
            bundle_path,
            SkillInstallOptions {
                allow_unsigned,
                source_type: "local".to_owned(),
                source_label: source_label.into(),
            },
        )
    }

    pub fn list(&self) -> Result<Vec<InstalledSkill>, SkillError> {
        list_installed_skills(&self.root)
    }

    pub fn info(&self, selector: InstalledSkillSelector) -> Result<InstalledSkill, SkillError> {
        info_installed_skill(&self.root, selector)
    }

    pub fn remove(&self, selector: InstalledSkillSelector) -> Result<InstalledSkill, SkillError> {
        remove_installed_skill(&self.root, selector)
    }

    pub fn verify(&self, selector: InstalledSkillSelector) -> Result<InstalledSkill, SkillError> {
        verify_installed_skill(&self.root, selector)
    }

    fn ordered_registries(&self) -> Result<Vec<&RegistryConfig>, SkillError> {
        if self.config.registry_order.is_empty() {
            return Ok(self.config.registries.iter().collect());
        }

        self.config
            .registry_order
            .iter()
            .map(|name| self.registry_by_name(name))
            .collect()
    }

    fn registry_by_name(&self, name: &str) -> Result<&RegistryConfig, SkillError> {
        self.config
            .registries
            .iter()
            .find(|registry| registry.name == name)
            .ok_or_else(|| SkillError::RegistryNotFound {
                name: name.to_owned(),
            })
    }

    fn adapter_for(
        &self,
        registry: &RegistryConfig,
    ) -> Result<Box<dyn RegistryAdapter + Send + Sync>, SkillError> {
        match registry.kind {
            RegistryKind::Filesystem => {
                let path = registry
                    .path
                    .clone()
                    .ok_or_else(|| SkillError::InvalidConfig {
                        message: format!("filesystem registry `{}` requires path", registry.name),
                    })?;
                Ok(Box::new(
                    registry_filesystem::FilesystemRegistryAdapter::new(
                        registry.name.clone(),
                        path,
                    ),
                ))
            }
            RegistryKind::Http => {
                let url = registry
                    .url
                    .clone()
                    .ok_or_else(|| SkillError::InvalidConfig {
                        message: format!("http registry `{}` requires url", registry.name),
                    })?;
                Ok(Box::new(registry_http::HttpRegistryAdapter::new(
                    registry.name.clone(),
                    url,
                    self.bearer_token_for(registry)?,
                    self.ssrf_options.clone(),
                )?))
            }
            RegistryKind::Oci => {
                let reference = registry
                    .url
                    .clone()
                    .ok_or_else(|| SkillError::InvalidConfig {
                        message: format!("oci registry `{}` requires url", registry.name),
                    })?;
                Ok(Box::new(registry_oci::OciRegistryAdapter::new(
                    registry.name.clone(),
                    reference,
                    self.bearer_token_for(registry)?,
                    self.ssrf_options.clone(),
                )?))
            }
            RegistryKind::Git => {
                validate_skill_name(&registry.name)?;
                let url = registry
                    .url
                    .clone()
                    .ok_or_else(|| SkillError::InvalidConfig {
                        message: format!("git registry `{}` requires url", registry.name),
                    })?;
                Ok(Box::new(registry_git::GitRegistryAdapter::new(
                    registry.name.clone(),
                    url.clone(),
                    git_cache_root(&self.root, &registry.name, &url)?,
                    self.ssrf_options.clone(),
                )))
            }
        }
    }

    fn bearer_token_for(&self, registry: &RegistryConfig) -> Result<Option<String>, SkillError> {
        let Some(auth) = registry.auth.as_deref() else {
            return Ok(None);
        };

        let credential_name = if auth == "bearer-from-credstore" {
            default_bearer_credential_name(&registry.name)
        } else if let Some(name) = auth.strip_prefix("bearer-from-credstore:") {
            if name.is_empty() {
                return Err(SkillError::InvalidConfig {
                    message: format!(
                        "http registry `{}` has an empty bearer credential reference",
                        registry.name
                    ),
                });
            }
            name.to_owned()
        } else {
            return Err(SkillError::UnsupportedRegistryAuth {
                scheme: auth
                    .split_once(':')
                    .map(|(scheme, _)| scheme)
                    .unwrap_or(auth)
                    .to_owned(),
            });
        };

        (self.credential_resolver)(&credential_name)?
            .ok_or_else(|| SkillError::CredentialReferenceUnavailable {
                name: credential_name,
            })
            .map(Some)
    }

    fn install_fetched_skill(
        &self,
        fetched: FetchedSkill,
        allow_unsigned: bool,
    ) -> Result<InstalledSkill, SkillError> {
        let source_label = source_label_for_fetched(&fetched);
        let installed = install_local_skill(
            &self.root,
            &fetched.staging_path,
            SkillInstallOptions {
                allow_unsigned,
                source_type: fetched.source_type.clone(),
                source_label,
            },
        );
        cleanup_staging_path(&fetched.staging_path);
        installed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSkillHandle {
    name: String,
    version: Option<String>,
}

impl ParsedSkillHandle {
    fn parse(handle: &str) -> Result<Self, SkillError> {
        let handle = handle.trim();
        let (name, version) = match handle.rsplit_once('@') {
            Some((name, version)) => {
                if version.is_empty() {
                    return Err(SkillError::InvalidConfig {
                        message: "skill handle version must not be empty".to_owned(),
                    });
                }
                (name, Some(version.to_owned()))
            }
            None => (handle, None),
        };

        validate_skill_name(name)?;
        if let Some(version) = version.as_deref() {
            version
                .parse::<Version>()
                .map_err(|source| SkillError::InvalidVersion {
                    version: version.to_owned(),
                    source,
                })?;
        }

        Ok(Self {
            name: name.to_owned(),
            version,
        })
    }
}

fn cleanup_staging_path(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_dir() {
        let _ = fs::remove_dir_all(path);
    }
}

fn source_label_for_fetched(fetched: &FetchedSkill) -> String {
    format!(
        "{}:{}:{}@{}",
        fetched.source_type, fetched.registry, fetched.name, fetched.version
    )
}

fn git_cache_root(root: &Path, registry_name: &str, url: &str) -> Result<PathBuf, SkillError> {
    let url_digest = git_cache_url_digest(url);
    ensure_owned_directory_path(root, &["cache", "skill-git", registry_name, &url_digest])
}

fn git_cache_url_digest(url: &str) -> String {
    let digest = Sha256::digest(url.as_bytes());
    hex::encode(&digest[..8])
}

fn ensure_owned_directory_path(root: &Path, components: &[&str]) -> Result<PathBuf, SkillError> {
    ensure_owned_directory(root)?;
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
        ensure_owned_directory(&path)?;
    }
    Ok(path)
}

fn ensure_owned_directory(path: &Path) -> Result<(), SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            if metadata.file_type().is_dir() {
                Ok(())
            } else {
                Err(SkillError::UnsafeBundlePath {
                    path: path.to_path_buf(),
                })
            }
        }
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn sort_hits(hits: &mut [SkillSearchHit]) {
    hits.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| compare_versions(&left.version, &right.version))
            .then_with(|| left.registry.cmp(&right.registry))
    });
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<Version>(), right.parse::<Version>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn default_bearer_credential_name(registry_name: &str) -> String {
    let normalized = registry_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("AGENTENV_SKILLS_{normalized}_TOKEN")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_fetched_skill_source_label_records_registry_name_and_version() {
        let fetched = FetchedSkill {
            staging_path: PathBuf::from("/tmp/staged-git-skill"),
            registry: "git-dev".to_owned(),
            source_type: "git".to_owned(),
            name: "provenance-git".to_owned(),
            version: "0.4.0".to_owned(),
        };

        assert_eq!(
            source_label_for_fetched(&fetched),
            "git:git-dev:provenance-git@0.4.0"
        );
    }

    #[test]
    fn service_installs_git_fetched_skill_with_provenance_label() {
        let root = temp_dir("skill-service-git-provenance-home").join(".agentenv");
        let bundle = temp_dir("skill-service-git-provenance-bundle");
        write_file(&bundle.join("SKILL.md"), "# Git provenance\n");
        write_file(
            &bundle.join("skill.yaml"),
            "name: provenance-git\nversion: 0.4.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        let service = SkillService::new(&root, SkillsConfig::default());
        let fetched = FetchedSkill {
            staging_path: bundle.clone(),
            registry: "git-dev".to_owned(),
            source_type: "git".to_owned(),
            name: "provenance-git".to_owned(),
            version: "0.4.0".to_owned(),
        };

        let installed = service
            .install_fetched_skill(fetched, true)
            .expect("fetched git skill should install");

        assert_eq!(installed.name, "provenance-git");
        assert_eq!(installed.source_type, "git");
        assert_eq!(installed.source_label, "git:git-dev:provenance-git@0.4.0");
        assert!(!bundle.exists());
    }

    #[test]
    fn git_cache_root_changes_when_registry_url_changes() {
        let root = temp_dir("skill-service-git-cache-url").join(".agentenv");

        let first =
            git_cache_root(&root, "git-dev", "git+https://github.com/acme/skills-one").unwrap();
        let second =
            git_cache_root(&root, "git-dev", "git+https://github.com/acme/skills-two").unwrap();

        assert_ne!(first, second);
        assert_eq!(
            first.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("git-dev"))
        );
        assert_eq!(
            second.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("git-dev"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn git_cache_root_rejects_symlinked_cache_parent() {
        let home = temp_dir("skill-service-git-cache-symlink-home");
        let root = home.join(".agentenv");
        let outside = temp_dir("skill-service-git-cache-symlink-outside");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("cache")).unwrap();

        let error = git_cache_root(&root, "git-dev", "git+https://github.com/acme/skills")
            .expect_err("git cache parent symlink must be rejected");

        assert!(matches!(error, SkillError::UnsafeBundlePath { .. }));
        assert!(!outside.join("skill-git").exists());
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }
}
