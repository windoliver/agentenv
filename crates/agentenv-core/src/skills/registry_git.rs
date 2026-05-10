use std::{
    cmp::Ordering,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use semver::Version;

use super::{
    compute_bundle_digest, manifest::validated_bundle_file, validate_skill_name, FetchedSkill,
    RegistryAdapter, SkillError, SkillManifest, SkillSearchHit,
};

const MANIFEST_FILE: &str = "skill.yaml";
const SOURCE_TYPE: &str = "git";

pub(crate) trait GitCheckout: Send + Sync + std::fmt::Debug {
    fn checkout(&self, url: &str, cache_root: &Path) -> Result<PathBuf, SkillError>;
}

#[derive(Debug)]
struct CommandGitCheckout;

#[derive(Debug, Clone)]
struct ScannedGitSkill {
    path: PathBuf,
    manifest: SkillManifest,
    digest: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GitRegistryAdapter {
    name: String,
    url: String,
    cache_root: PathBuf,
    checkout: Arc<dyn GitCheckout>,
}

impl GitCheckout for CommandGitCheckout {
    fn checkout(&self, url: &str, cache_root: &Path) -> Result<PathBuf, SkillError> {
        ensure_directory(cache_root)?;
        let checkout = cache_root.join("checkout");
        if checkout.join(".git").is_dir() {
            run_git(
                &[
                    "-C".to_owned(),
                    path_arg(&checkout),
                    "fetch".to_owned(),
                    "--all".to_owned(),
                    "--tags".to_owned(),
                    "--prune".to_owned(),
                ],
                url,
            )?;
            run_git(
                &[
                    "-C".to_owned(),
                    path_arg(&checkout),
                    "reset".to_owned(),
                    "--hard".to_owned(),
                    "origin/HEAD".to_owned(),
                ],
                url,
            )?;
            return Ok(checkout);
        }

        let clone_url = clone_url(url)?;
        run_git(
            &[
                "clone".to_owned(),
                "--filter=blob:none".to_owned(),
                "--depth=1".to_owned(),
                clone_url,
                path_arg(&checkout),
            ],
            url,
        )?;
        Ok(checkout)
    }
}

impl GitRegistryAdapter {
    pub(crate) fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        cache_root: impl Into<PathBuf>,
    ) -> Self {
        Self::with_checkout(name, url, cache_root, Arc::new(CommandGitCheckout))
    }

    pub(crate) fn with_checkout(
        name: impl Into<String>,
        url: impl Into<String>,
        cache_root: impl Into<PathBuf>,
        checkout: Arc<dyn GitCheckout>,
    ) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            cache_root: cache_root.into(),
            checkout,
        }
    }

    fn checkout_path(&self) -> Result<PathBuf, SkillError> {
        self.checkout.checkout(&self.url, &self.cache_root)
    }

    fn scan(&self) -> Result<Vec<ScannedGitSkill>, SkillError> {
        let checkout_path = self.checkout_path()?;
        let mut skills = Vec::new();
        scan_directory(&checkout_path, &mut skills)?;
        Ok(skills)
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
}

#[async_trait::async_trait]
impl RegistryAdapter for GitRegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        let query = query.to_ascii_lowercase();
        let mut hits = self
            .scan()?
            .into_iter()
            .filter_map(|skill| {
                let description = skill.manifest.description.as_deref().unwrap_or_default();
                let matches = query.is_empty()
                    || skill.manifest.name.to_ascii_lowercase().contains(&query)
                    || description.to_ascii_lowercase().contains(&query);
                matches.then(|| self.hit_for_manifest(&skill.manifest, skill.digest))
            })
            .collect::<Vec<_>>();
        sort_hits(&mut hits);
        Ok(hits)
    }

    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError> {
        validate_skill_name(name)?;
        if let Some(version) = version {
            version
                .parse::<Version>()
                .map_err(|source| SkillError::InvalidVersion {
                    version: version.to_owned(),
                    source,
                })?;
        }

        let mut matches = self
            .scan()?
            .into_iter()
            .filter(|skill| {
                skill.manifest.name == name
                    && version
                        .map(|version| skill.manifest.version.to_string() == version)
                        .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            compare_versions(
                &left.manifest.version.to_string(),
                &right.manifest.version.to_string(),
            )
        });
        let skill =
            matches
                .into_iter()
                .next_back()
                .ok_or_else(|| SkillError::SkillNotInstalled {
                    name: name.to_owned(),
                })?;

        let version = skill.manifest.version.to_string();
        let staging_path = staging_fetch_path(&skill.manifest.name, &version);
        remove_directory_if_exists(&staging_path)?;
        copy_bundle_contents(&skill.path, &staging_path, &skill.manifest)?;

        Ok(FetchedSkill {
            staging_path,
            registry: self.name.clone(),
            source_type: SOURCE_TYPE.to_owned(),
            name: skill.manifest.name,
            version,
        })
    }

    async fn publish(
        &self,
        _bundle_path: &Path,
        _allow_unsigned: bool,
    ) -> Result<SkillSearchHit, SkillError> {
        Err(SkillError::UnsupportedRegistryPublish {
            registry: self.name.clone(),
            kind: SOURCE_TYPE.to_owned(),
        })
    }
}

fn scan_directory(root: &Path, skills: &mut Vec<ScannedGitSkill>) -> Result<(), SkillError> {
    for entry in fs::read_dir(root).map_err(|source| SkillError::Io {
        path: root.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| SkillError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| SkillError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_dir() {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some(".git") {
            continue;
        }

        let manifest_path = path.join(MANIFEST_FILE);
        if manifest_path_is_file(&manifest_path)? {
            let manifest = super::load_skill_manifest(&path)?;
            let digest = compute_bundle_digest(&path, &manifest)?;
            skills.push(ScannedGitSkill {
                path: path.clone(),
                manifest,
                digest,
            });
        }
        scan_directory(&path, skills)?;
    }
    Ok(())
}

fn manifest_path_is_file(path: &Path) -> Result<bool, SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_file() {
                Ok(true)
            } else {
                Err(SkillError::UnsafeBundlePath {
                    path: path.to_path_buf(),
                })
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn clone_url(url: &str) -> Result<String, SkillError> {
    let Some(stripped) = url.strip_prefix("git+") else {
        return Err(SkillError::GitRegistry {
            url: url.to_owned(),
            message: "git registry URL must use git+https".to_owned(),
        });
    };
    if !stripped.starts_with("https://") {
        return Err(SkillError::GitRegistry {
            url: url.to_owned(),
            message: "git registry URL must use git+https".to_owned(),
        });
    }
    Ok(stripped.to_owned())
}

fn run_git(args: &[String], url: &str) -> Result<(), SkillError> {
    let output = Command::new("git")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|source| SkillError::GitRegistry {
            url: url.to_owned(),
            message: format!("failed to run git: {source}"),
        })?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let message = if stderr.is_empty() {
        format!("git exited with status {}", output.status)
    } else {
        format!("git exited with status {}: {stderr}", output.status)
    };
    Err(SkillError::GitRegistry {
        url: url.to_owned(),
        message,
    })
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn staging_fetch_path(name: &str, version: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "agentenv-skill-git-fetch-{name}-{version}-{}-{}",
        std::process::id(),
        temporary_suffix()
    ))
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

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), SkillError> {
    let metadata = fs::symlink_metadata(source).map_err(|source_error| SkillError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SkillError::UnsafeBundlePath {
            path: source.to_path_buf(),
        });
    }
    if let Some(parent) = destination.parent() {
        ensure_directory(parent)?;
    }
    fs::copy(source, destination).map_err(|source| SkillError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn copy_bundle_contents(
    source_root: &Path,
    destination_root: &Path,
    manifest: &SkillManifest,
) -> Result<(), SkillError> {
    ensure_directory(destination_root)?;
    copy_regular_file(
        &source_root.join(MANIFEST_FILE),
        &destination_root.join(MANIFEST_FILE),
    )?;
    for declared_file in &manifest.declared_files {
        let source = validated_bundle_file(source_root, declared_file)?;
        copy_regular_file(&source, &destination_root.join(declared_file))?;
    }
    Ok(())
}

fn sort_hits(hits: &mut [SkillSearchHit]) {
    hits.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| compare_versions(&left.version, &right.version))
            .then_with(|| left.registry.cmp(&right.registry))
    });
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    match (left.parse::<Version>(), right.parse::<Version>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn ensure_directory(path: &Path) -> Result<(), SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)
            .map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            }),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn temporary_suffix() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, sync::Arc};

    #[derive(Debug)]
    struct StaticCheckout {
        path: PathBuf,
    }

    impl GitCheckout for StaticCheckout {
        fn checkout(&self, _url: &str, _cache_root: &Path) -> Result<PathBuf, SkillError> {
            Ok(self.path.clone())
        }
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

    #[tokio::test]
    async fn git_registry_search_scans_skill_directories() {
        let checkout = temp_dir("skill-git-search");
        write_file(
            &checkout.join("tools/review/skill.yaml"),
            "name: review-skill\nversion: 0.2.0\ndescription: Review helper\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("tools/review/SKILL.md"), "# Review\n");
        let adapter = GitRegistryAdapter::with_checkout(
            "git-dev",
            "git+https://github.com/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
        );

        let hits = adapter.search("review").await.unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "review-skill");
        assert_eq!(hits[0].version, "0.2.0");
        assert_eq!(hits[0].registry, "git-dev");
    }

    #[tokio::test]
    async fn git_registry_fetch_selects_highest_semver_and_copies_bundle() {
        let checkout = temp_dir("skill-git-fetch");
        write_file(
            &checkout.join("old/skill.yaml"),
            "name: versioned-git\nversion: 0.1.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("old/SKILL.md"), "# Old\n");
        write_file(
            &checkout.join("new/skill.yaml"),
            "name: versioned-git\nversion: 0.3.0\nentry: SKILL.md\nfiles:\n  - SKILL.md\n",
        );
        write_file(&checkout.join("new/SKILL.md"), "# New\n");
        let adapter = GitRegistryAdapter::with_checkout(
            "git-dev",
            "git+https://github.com/acme/skills",
            temp_dir("skill-git-cache"),
            Arc::new(StaticCheckout { path: checkout }),
        );

        let fetched = adapter.fetch("versioned-git", None).await.unwrap();

        assert_eq!(fetched.source_type, "git");
        assert_eq!(fetched.version, "0.3.0");
        assert!(fetched.staging_path.join("SKILL.md").is_file());
    }
}
