use std::{
    fs,
    path::{Path, PathBuf},
};

use semver::Version;

use super::{
    info_installed_skill, install_local_skill, list_installed_skills, registry_filesystem,
    remove_installed_skill, validate_skill_name, verify_installed_skill, InstalledSkill,
    InstalledSkillSelector, RegistryAdapter, RegistryConfig, RegistryKind, SkillError,
    SkillInstallOptions, SkillSearchHit, SkillsConfig,
};

#[derive(Debug, Clone)]
pub struct SkillService {
    root: PathBuf,
    config: SkillsConfig,
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
        }
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
                    let source_label = format!(
                        "{}:{}:{}@{}",
                        fetched.source_type, fetched.registry, fetched.name, fetched.version
                    );
                    let installed = install_local_skill(
                        &self.root,
                        &fetched.staging_path,
                        SkillInstallOptions {
                            allow_unsigned: request.allow_unsigned,
                            source_type: fetched.source_type.clone(),
                            source_label,
                        },
                    );
                    cleanup_staging_path(&fetched.staging_path);
                    return installed;
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
    ) -> Result<registry_filesystem::FilesystemRegistryAdapter, SkillError> {
        match registry.kind {
            RegistryKind::Filesystem => {
                let path = registry
                    .path
                    .clone()
                    .ok_or_else(|| SkillError::InvalidConfig {
                        message: format!("filesystem registry `{}` requires path", registry.name),
                    })?;
                Ok(registry_filesystem::FilesystemRegistryAdapter::new(
                    registry.name.clone(),
                    path,
                ))
            }
            RegistryKind::Http | RegistryKind::Oci => Err(SkillError::InvalidConfig {
                message: format!(
                    "registry `{}` uses unsupported adapter kind `{:?}`",
                    registry.name, registry.kind
                ),
            }),
        }
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
