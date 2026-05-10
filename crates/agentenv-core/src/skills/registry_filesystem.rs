use std::{
    cmp::Ordering,
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use semver::Version;
use serde::{Deserialize, Serialize};

use super::{
    compute_bundle_digest, manifest::validated_bundle_file, validate_skill_name,
    verify_ed25519_signature, FetchedSkill, RegistryAdapter, SkillError, SkillManifest,
    SkillSearchHit,
};

const BUNDLES_DIR: &str = "bundles";
const INDEX_FILE: &str = "index.yaml";
const MANIFEST_FILE: &str = "skill.yaml";
const SOURCE_TYPE: &str = "filesystem";

#[derive(Debug, Clone)]
pub(crate) struct FilesystemRegistryAdapter {
    name: String,
    root: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FilesystemRegistryIndex {
    #[serde(default)]
    skills: Vec<SkillSearchHit>,
}

#[derive(Debug, Clone)]
struct ResolvedFilesystemHit {
    hit: SkillSearchHit,
    source: FilesystemHitSource,
}

#[derive(Debug, Clone)]
enum FilesystemHitSource {
    Indexed,
    Scanned(PathBuf),
}

impl FilesystemRegistryAdapter {
    pub(crate) fn new(name: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            root: root.into(),
        }
    }

    fn index_path(&self) -> PathBuf {
        self.root.join(INDEX_FILE)
    }

    fn read_index(&self) -> Result<FilesystemRegistryIndex, SkillError> {
        let mut index = self.read_persisted_index()?;
        let mut scanned = self.scan_index()?;
        scanned
            .skills
            .retain(|scanned| !contains_hit(&index.skills, scanned));
        index.skills.extend(scanned.skills);
        sort_hits(&mut index.skills);
        Ok(index)
    }

    fn read_persisted_index(&self) -> Result<FilesystemRegistryIndex, SkillError> {
        let path = self.index_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(SkillError::UnsafeBundlePath { path }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FilesystemRegistryIndex::default());
            }
            Err(source) => {
                return Err(SkillError::Io { path, source });
            }
        }

        let content = read_regular_string(&path)?;
        let mut index: FilesystemRegistryIndex =
            serde_yaml::from_str(&content).map_err(|source| SkillError::Yaml { path, source })?;
        for hit in &mut index.skills {
            self.validate_hit(hit)?;
        }
        Ok(index)
    }

    fn scan_index(&self) -> Result<FilesystemRegistryIndex, SkillError> {
        let mut skills = Vec::new();
        let mut seen = HashSet::new();
        for entry in fs::read_dir(&self.root).map_err(|source| SkillError::Io {
            path: self.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| SkillError::Io {
                path: self.root.clone(),
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
            if path.file_name().and_then(|name| name.to_str()) == Some(BUNDLES_DIR) {
                continue;
            }
            let manifest_path = path.join(MANIFEST_FILE);
            if !manifest_path.is_file() {
                continue;
            }
            let manifest = super::load_skill_manifest(&path)?;
            let version = manifest.version.to_string();
            if !seen.insert((manifest.name.clone(), version.clone())) {
                return Err(SkillError::InvalidConfig {
                    message: format!(
                        "filesystem registry `{}` has duplicate scanned skill `{}` version `{}`",
                        self.name, manifest.name, version
                    ),
                });
            }
            let digest = compute_bundle_digest(&path, &manifest)?;
            skills.push(self.hit_for_manifest(&manifest, digest));
        }
        sort_hits(&mut skills);
        Ok(FilesystemRegistryIndex { skills })
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

    fn write_index(&self, mut index: FilesystemRegistryIndex) -> Result<(), SkillError> {
        sort_hits(&mut index.skills);
        write_yaml_atomic(&self.index_path(), &index)
    }

    fn upsert_hit(&self, hit: SkillSearchHit) -> Result<(), SkillError> {
        let mut index = self.read_persisted_index()?;
        index
            .skills
            .retain(|existing| existing.name != hit.name || existing.version != hit.version);
        index.skills.push(hit);
        self.write_index(index)
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

    fn existing_bundle_digest(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<String>, SkillError> {
        let Some(path) = existing_child_directory(&self.root, &[BUNDLES_DIR, name, version])?
        else {
            return Ok(None);
        };

        let manifest = super::load_skill_manifest(&path)?;
        if manifest.name != name || manifest.version.to_string() != version {
            return Err(SkillError::UnsafeBundlePath {
                path: path.join(MANIFEST_FILE),
            });
        }
        compute_bundle_digest(path, &manifest).map(Some)
    }

    fn resolved_hit(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<ResolvedFilesystemHit, SkillError> {
        validate_skill_name(name)?;
        if let Some(version) = version {
            version
                .parse::<Version>()
                .map_err(|source| SkillError::InvalidVersion {
                    version: version.to_owned(),
                    source,
                })?;
        }

        let persisted = self.read_persisted_index()?;
        let scanned = self.scan_index()?;
        let persisted_hits = persisted.skills;
        let mut matches = persisted_hits
            .iter()
            .filter(|hit| hit.name == name)
            .cloned()
            .map(|hit| ResolvedFilesystemHit {
                hit,
                source: FilesystemHitSource::Indexed,
            })
            .collect::<Vec<_>>();
        for hit in scanned.skills {
            if contains_hit(&persisted_hits, &hit) || hit.name != name {
                continue;
            }
            let path = self.scanned_bundle_path_for_hit(&hit)?.ok_or_else(|| {
                SkillError::SkillNotInstalled {
                    name: hit.name.clone(),
                }
            })?;
            matches.push(ResolvedFilesystemHit {
                hit,
                source: FilesystemHitSource::Scanned(path),
            });
        }

        if let Some(version) = version {
            return matches
                .into_iter()
                .find(|resolved| resolved.hit.version == version)
                .ok_or_else(|| SkillError::SkillNotInstalled {
                    name: name.to_owned(),
                });
        }

        matches
            .into_iter()
            .max_by(|left, right| compare_versions(&left.hit.version, &right.hit.version))
            .ok_or_else(|| SkillError::SkillNotInstalled {
                name: name.to_owned(),
            })
    }

    fn bundle_path_for_hit(&self, resolved: &ResolvedFilesystemHit) -> Result<PathBuf, SkillError> {
        match &resolved.source {
            FilesystemHitSource::Indexed => existing_child_directory(
                &self.root,
                &[BUNDLES_DIR, &resolved.hit.name, &resolved.hit.version],
            )?
            .ok_or_else(|| SkillError::SkillNotInstalled {
                name: resolved.hit.name.clone(),
            }),
            FilesystemHitSource::Scanned(path) => Ok(path.clone()),
        }
    }

    fn scanned_bundle_path_for_hit(
        &self,
        hit: &SkillSearchHit,
    ) -> Result<Option<PathBuf>, SkillError> {
        for entry in fs::read_dir(&self.root).map_err(|source| SkillError::Io {
            path: self.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| SkillError::Io {
                path: self.root.clone(),
                source,
            })?;
            let path = entry.path();
            if !fs::symlink_metadata(&path)
                .map_err(|source| SkillError::Io {
                    path: path.clone(),
                    source,
                })?
                .file_type()
                .is_dir()
            {
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) == Some(BUNDLES_DIR) {
                continue;
            }
            if !path.join(MANIFEST_FILE).is_file() {
                continue;
            }
            let manifest = super::load_skill_manifest(&path)?;
            if manifest.name == hit.name && manifest.version.to_string() == hit.version {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }
}

#[async_trait::async_trait]
impl RegistryAdapter for FilesystemRegistryAdapter {
    async fn search(&self, query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        ensure_directory(&self.root)?;
        let query = query.to_ascii_lowercase();
        let index = self.read_index()?;
        let mut hits = index
            .skills
            .into_iter()
            .filter_map(|mut hit| {
                let searchable_description = hit.description.as_deref().unwrap_or_default();
                let matches = query.is_empty()
                    || hit.name.to_ascii_lowercase().contains(&query)
                    || searchable_description.to_ascii_lowercase().contains(&query);
                if matches {
                    hit.registry = self.name.clone();
                    Some(hit)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        sort_hits(&mut hits);
        Ok(hits)
    }

    async fn fetch(&self, name: &str, version: Option<&str>) -> Result<FetchedSkill, SkillError> {
        ensure_directory(&self.root)?;
        let resolved = self.resolved_hit(name, version)?;
        let hit = &resolved.hit;
        let bundle_path = self.bundle_path_for_hit(&resolved)?;
        let manifest = super::load_skill_manifest(&bundle_path)?;
        if manifest.name != hit.name || manifest.version.to_string() != hit.version {
            return Err(SkillError::UnsafeBundlePath {
                path: bundle_path.join(MANIFEST_FILE),
            });
        }
        let digest = compute_bundle_digest(&bundle_path, &manifest)?;
        if let Some(expected) = hit.digest.as_deref() {
            if expected != digest {
                return Err(SkillError::DigestMismatch {
                    expected: expected.to_owned(),
                    actual: digest,
                });
            }
        }

        let staging_path = staging_fetch_path(&hit.name, &hit.version);
        remove_directory_if_exists(&staging_path)?;
        copy_bundle_contents(&bundle_path, &staging_path, &manifest)?;

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
        ensure_directory(&self.root)?;
        ensure_directory(&self.root.join(BUNDLES_DIR))?;
        let manifest = super::load_skill_manifest(bundle_path)?;
        let digest = compute_bundle_digest(bundle_path, &manifest)?;
        verify_publish_signature(&manifest, &digest, allow_unsigned)?;
        let version = manifest.version.to_string();
        let hit = self.hit_for_manifest(&manifest, digest.clone());

        if let Some(existing_digest) = self.existing_bundle_digest(&manifest.name, &version)? {
            if existing_digest != digest {
                return Err(SkillError::AlreadyInstalledDifferentDigest {
                    name: manifest.name,
                    version,
                    existing: existing_digest,
                });
            }
            self.upsert_hit(hit.clone())?;
            return Ok(hit);
        }

        let bundle_parent = ensure_child_directory(&self.root, &[BUNDLES_DIR, &manifest.name])?;
        let destination = bundle_parent.join(&version);
        let staging = staging_publish_path(&bundle_parent, &version)?;
        remove_directory_if_exists(&staging)?;
        copy_bundle_contents(bundle_path, &staging, &manifest)?;
        rename_directory(&staging, &destination)?;
        self.upsert_hit(hit.clone())?;
        Ok(hit)
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

fn contains_hit(hits: &[SkillSearchHit], needle: &SkillSearchHit) -> bool {
    hits.iter()
        .any(|hit| hit.name == needle.name && hit.version == needle.version)
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

fn ensure_directory(path: &Path) -> Result<(), SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|source| SkillError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            ensure_existing_directory(path)
        }
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn ensure_existing_directory(path: &Path) -> Result<(), SkillError> {
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

fn existing_child_directory(
    root: &Path,
    components: &[&str],
) -> Result<Option<PathBuf>, SkillError> {
    ensure_existing_directory(root)?;
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(SkillError::UnsafeBundlePath { path }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(SkillError::Io { path, source }),
        }
    }
    Ok(Some(path))
}

fn ensure_child_directory(root: &Path, components: &[&str]) -> Result<PathBuf, SkillError> {
    ensure_existing_directory(root)?;
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(SkillError::UnsafeBundlePath { path }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&path).map_err(|source| SkillError::Io {
                    path: path.clone(),
                    source,
                })?;
                ensure_existing_directory(&path)?;
            }
            Err(source) => return Err(SkillError::Io { path, source }),
        }
    }
    Ok(path)
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

fn rename_directory(from: &Path, to: &Path) -> Result<(), SkillError> {
    if let Ok(metadata) = fs::symlink_metadata(to) {
        if !metadata.file_type().is_dir() {
            return Err(SkillError::UnsafeBundlePath {
                path: to.to_path_buf(),
            });
        }
    }
    fs::rename(from, to).map_err(|source| SkillError::Io {
        path: to.to_path_buf(),
        source,
    })
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), SkillError> {
    if let Some(parent) = destination.parent() {
        ensure_directory(parent)?;
    }
    let mut source_file = open_regular_file(source)?;
    let mut destination_file = fs::File::create(destination).map_err(|source| SkillError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    std::io::copy(&mut source_file, &mut destination_file).map_err(|source| SkillError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(unix)]
fn open_regular_file(path: &Path) -> Result<fs::File, SkillError> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    ensure_opened_regular_file(path, &file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_file(path: &Path) -> Result<fs::File, SkillError> {
    let file = fs::File::open(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    ensure_opened_regular_file(path, &file)?;
    Ok(file)
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

fn read_regular_string(path: &Path) -> Result<String, SkillError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }

    read_regular_string_no_follow(path)
}

#[cfg(unix)]
fn read_regular_string_no_follow(path: &Path) -> Result<String, SkillError> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(content)
}

#[cfg(not(unix))]
fn read_regular_string_no_follow(path: &Path) -> Result<String, SkillError> {
    fs::read_to_string(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_yaml_atomic<T>(path: &Path, value: &T) -> Result<(), SkillError>
where
    T: Serialize,
{
    let parent = path.parent().ok_or_else(|| SkillError::UnsafeBundlePath {
        path: path.to_path_buf(),
    })?;
    ensure_directory(parent)?;

    let yaml = serde_yaml::to_string(value).map_err(|source| SkillError::Serde {
        path: path.to_path_buf(),
        source,
    })?;
    let tmp_path = temporary_path(path);
    fs::write(&tmp_path, yaml).map_err(|source| SkillError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    replace_file(&tmp_path, path).map_err(|source| {
        let _ = fs::remove_file(&tmp_path);
        SkillError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let from = from
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let replaced = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    file_name.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        temporary_suffix()
    ));
    path.with_file_name(file_name)
}

fn staging_publish_path(parent: &Path, version: &str) -> Result<PathBuf, SkillError> {
    ensure_existing_directory(parent)?;
    Ok(parent.join(format!(
        ".{version}.publish-{}-{}",
        std::process::id(),
        temporary_suffix()
    )))
}

fn staging_fetch_path(name: &str, version: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "agentenv-skill-fetch-{name}-{version}-{}-{}",
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
