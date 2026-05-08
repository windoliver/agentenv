use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use semver::Version;
use serde::Deserialize;
use serde_yaml::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    compute_bundle_digest, index,
    manifest::{normalize_bundle_path, validated_bundle_file},
    validate_skill_name, verify_ed25519_signature, SkillError, SkillManifest,
};

const MANIFEST_FILE: &str = "skill.yaml";
const CONTENT_DIR: &str = "content";
const SIGNATURE_STATUS_UNSIGNED: &str = "unsigned";
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InstalledSkill {
    pub name: String,
    pub version: String,
    pub source_type: String,
    pub source_label: String,
    pub digest: String,
    pub signature_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_public_key_ed25519: Option<String>,
    pub entry: PathBuf,
    pub installed_at: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SkillInstallOptions {
    pub allow_unsigned: bool,
    pub source_type: String,
    pub source_label: String,
}

#[derive(Debug, Clone)]
pub enum InstalledSkillSelector {
    Name(String),
    NameVersion { name: String, version: String },
}

#[derive(Debug, Deserialize)]
struct RawSkillManifest {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    entry: Option<String>,
    files: Option<Vec<String>>,
    self_test: Option<RawSelfTest>,
    signatures: Option<RawSignatures>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawSelfTest {
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSignatures {
    ed25519: Option<String>,
    public_key: Option<String>,
    public_key_ed25519: Option<String>,
}

pub fn install_local_skill(
    root: impl AsRef<Path>,
    bundle: impl AsRef<Path>,
    options: SkillInstallOptions,
) -> Result<InstalledSkill, SkillError> {
    let root = root.as_ref();
    let bundle = bundle.as_ref();
    let manifest = super::load_skill_manifest(bundle)?;
    let digest = compute_bundle_digest(bundle, &manifest)?;

    let signature_status = if options.allow_unsigned {
        SIGNATURE_STATUS_UNSIGNED.to_owned()
    } else {
        return Err(SkillError::MissingSignature {
            name: manifest.name,
            version: manifest.version.to_string(),
        });
    };

    let version = manifest.version.to_string();
    let install_dir = install_dir(root, &manifest.name, &version);
    if let Some(existing) = read_existing_install(root, &manifest.name, &version)? {
        if existing.digest != digest {
            return Err(SkillError::AlreadyInstalledDifferentDigest {
                name: manifest.name,
                version,
                existing: existing.digest,
            });
        }
        if cached_install_matches_record(&existing)? {
            return Ok(existing);
        }
    }

    let installed = InstalledSkill {
        name: manifest.name.clone(),
        version: version.clone(),
        source_type: options.source_type,
        source_label: options.source_label,
        digest,
        signature_status,
        signature_public_key_ed25519: None,
        entry: PathBuf::from(CONTENT_DIR).join(&manifest.entry),
        installed_at: installed_at_now(),
        path: install_dir.clone(),
    };

    let staging_dir = staging_install_dir(&install_dir)?;
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir).map_err(|source| SkillError::Io {
            path: staging_dir.clone(),
            source,
        })?;
    }
    fs::create_dir_all(staging_dir.join(CONTENT_DIR)).map_err(|source| SkillError::Io {
        path: staging_dir.join(CONTENT_DIR),
        source,
    })?;

    copy_regular_file(
        &bundle.join(MANIFEST_FILE),
        &staging_dir.join(MANIFEST_FILE),
    )?;
    for declared_file in &manifest.declared_files {
        let source = validated_bundle_file(bundle, declared_file)?;
        let destination = staging_dir.join(CONTENT_DIR).join(declared_file);
        copy_regular_file(&source, &destination)?;
    }
    index::write_record(&index::installed_record_path(&staging_dir), &installed)?;
    replace_install_dir(&staging_dir, &install_dir)?;
    index::rebuild(root)?;

    Ok(installed)
}

pub fn list_installed_skills(root: impl AsRef<Path>) -> Result<Vec<InstalledSkill>, SkillError> {
    index::rebuild(root.as_ref())
}

pub fn info_installed_skill(
    root: impl AsRef<Path>,
    selector: InstalledSkillSelector,
) -> Result<InstalledSkill, SkillError> {
    let resolved = resolve_installed(root.as_ref(), selector)?;
    let mut installed = index::read_record(&index::installed_record_path(&resolved.path))?;
    installed.path = resolved.path;
    Ok(installed)
}

pub fn remove_installed_skill(
    root: impl AsRef<Path>,
    selector: InstalledSkillSelector,
) -> Result<InstalledSkill, SkillError> {
    let root = root.as_ref();
    let installed = info_installed_skill(root, selector)?;
    match fs::symlink_metadata(&installed.path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir_all(&installed.path).map_err(|source| SkillError::Io {
                path: installed.path.clone(),
                source,
            })?;
        }
        Ok(_) => {
            return Err(SkillError::UnsafeBundlePath {
                path: installed.path.clone(),
            });
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SkillError::Io {
                path: installed.path.clone(),
                source,
            });
        }
    }
    remove_empty_parent(&installed.path)?;
    index::rebuild(root)?;
    Ok(installed)
}

pub fn verify_installed_skill(
    root: impl AsRef<Path>,
    selector: InstalledSkillSelector,
) -> Result<InstalledSkill, SkillError> {
    let installed = info_installed_skill(root, selector)?;
    ensure_content_directory(&installed.path)?;
    let manifest = load_cached_manifest(&installed.path)?;
    validate_installed_record(&installed, &manifest)?;
    let content_root = installed.path.join(CONTENT_DIR);
    let actual_digest = compute_bundle_digest(&content_root, &manifest)?;
    if actual_digest != installed.digest {
        return Err(SkillError::DigestMismatch {
            expected: installed.digest,
            actual: actual_digest,
        });
    }

    verify_signature_if_required(&installed, &manifest)?;
    if let Some(command) = manifest.self_test_command.as_deref() {
        run_self_test(&installed, command)?;
    }

    Ok(installed)
}

fn verify_signature_if_required(
    installed: &InstalledSkill,
    manifest: &SkillManifest,
) -> Result<(), SkillError> {
    if installed.signature_status == SIGNATURE_STATUS_UNSIGNED
        && manifest.signature_ed25519.is_none()
        && installed.signature_public_key_ed25519.is_none()
    {
        return Ok(());
    }

    let Some(signature) = manifest.signature_ed25519.as_deref() else {
        return Err(SkillError::MissingSignature {
            name: installed.name.clone(),
            version: installed.version.clone(),
        });
    };

    let public_key = installed
        .signature_public_key_ed25519
        .as_deref()
        .ok_or_else(|| SkillError::MissingSignature {
            name: installed.name.clone(),
            version: installed.version.clone(),
        })?;
    verify_ed25519_signature(manifest, &installed.digest, signature, public_key)?;

    Ok(())
}

fn run_self_test(installed: &InstalledSkill, command: &str) -> Result<(), SkillError> {
    let content_root = installed.path.join(CONTENT_DIR);
    let mut command = shell_command(command);
    command.current_dir(&content_root).env_clear();
    let mut child = command.spawn().map_err(|source| SkillError::Io {
        path: content_root.clone(),
        source,
    })?;
    let deadline = Instant::now() + SELF_TEST_TIMEOUT;

    loop {
        if let Some(status) = child.try_wait().map_err(|source| SkillError::Io {
            path: content_root.clone(),
            source,
        })? {
            if status.success() {
                return Ok(());
            }
            return Err(SkillError::SelfTestFailed {
                name: installed.name.clone(),
                version: installed.version.clone(),
                status: status.code().map_or(-1, |code| code),
            });
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SkillError::SelfTestFailed {
                name: installed.name.clone(),
                version: installed.version.clone(),
                status: -1,
            });
        }

        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("cmd.exe");
    shell.args(["/C", command]);
    shell
}

#[cfg(not(windows))]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("/bin/sh");
    shell.args(["-c", command]);
    shell
}

fn resolve_installed(
    root: &Path,
    selector: InstalledSkillSelector,
) -> Result<InstalledSkill, SkillError> {
    let installed = index::rebuild(root)?;
    match selector {
        InstalledSkillSelector::Name(name) => resolve_by_name(installed, name),
        InstalledSkillSelector::NameVersion { name, version } => installed
            .into_iter()
            .find(|skill| skill.name == name && skill.version == version)
            .ok_or(SkillError::SkillNotInstalled { name }),
    }
}

fn resolve_by_name(
    installed: Vec<InstalledSkill>,
    name: String,
) -> Result<InstalledSkill, SkillError> {
    let matches = installed
        .into_iter()
        .filter(|skill| skill.name == name)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Err(SkillError::SkillNotInstalled { name }),
        [installed] => Ok(installed.clone()),
        _ => {
            let versions = matches
                .iter()
                .map(|skill| skill.version.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(SkillError::AmbiguousInstalledVersion { name, versions })
        }
    }
}

fn install_dir(root: &Path, name: &str, version: &str) -> PathBuf {
    index::skills_root(root).join(name).join(version)
}

fn read_existing_install(
    root: &Path,
    name: &str,
    version: &str,
) -> Result<Option<InstalledSkill>, SkillError> {
    let Some(install_dir) = existing_install_dir(root, name, version)? else {
        return Ok(None);
    };
    let record_path = index::installed_record_path(&install_dir);
    let mut installed = index::read_record(&record_path)?;
    if installed.name != name || installed.version != version {
        return Err(SkillError::UnsafeBundlePath { path: record_path });
    }
    installed.path = install_dir.to_path_buf();
    Ok(Some(installed))
}

fn existing_install_dir(
    root: &Path,
    name: &str,
    version: &str,
) -> Result<Option<PathBuf>, SkillError> {
    let skills_root = index::skills_root(root);
    let Some(()) = existing_directory(&skills_root)? else {
        return Ok(None);
    };
    let name_dir = skills_root.join(name);
    let Some(()) = existing_directory(&name_dir)? else {
        return Ok(None);
    };
    let install_dir = name_dir.join(version);
    let Some(()) = existing_directory(&install_dir)? else {
        return Ok(None);
    };
    Ok(Some(install_dir))
}

fn existing_directory(path: &Path) -> Result<Option<()>, SkillError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(SkillError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_dir() {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }
    Ok(Some(()))
}

fn cached_install_matches_record(installed: &InstalledSkill) -> Result<bool, SkillError> {
    ensure_content_directory(&installed.path)?;
    let manifest = match load_cached_manifest(&installed.path) {
        Ok(manifest) => manifest,
        Err(error) if cache_can_be_repaired(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    validate_installed_record(installed, &manifest)?;
    let content_root = installed.path.join(CONTENT_DIR);
    match compute_bundle_digest(&content_root, &manifest) {
        Ok(actual) => Ok(actual == installed.digest),
        Err(error) if cache_can_be_repaired(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_installed_record(
    installed: &InstalledSkill,
    manifest: &SkillManifest,
) -> Result<(), SkillError> {
    if installed.name != manifest.name || installed.version != manifest.version.to_string() {
        return Err(SkillError::UnsafeBundlePath {
            path: index::installed_record_path(&installed.path),
        });
    }

    let expected_entry = PathBuf::from(CONTENT_DIR).join(&manifest.entry);
    if installed.entry != expected_entry {
        return Err(SkillError::UnsafeBundlePath {
            path: installed.entry.clone(),
        });
    }

    Ok(())
}

fn ensure_content_directory(install_dir: &Path) -> Result<(), SkillError> {
    let path = install_dir.join(CONTENT_DIR);
    let metadata = fs::symlink_metadata(&path).map_err(|source| SkillError::Io {
        path: path.clone(),
        source,
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_dir() {
        return Err(SkillError::UnsafeBundlePath { path });
    }
    Ok(())
}

fn cache_can_be_repaired(error: &SkillError) -> bool {
    match error {
        SkillError::Io { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
        SkillError::Yaml { .. }
        | SkillError::InvalidSkillName { .. }
        | SkillError::InvalidVersion { .. }
        | SkillError::MissingDeclaredFile { .. }
        | SkillError::EmptyFilePattern { .. }
        | SkillError::MissingManifestField { .. } => true,
        SkillError::UnsafeBundlePath { .. }
        | SkillError::DigestMismatch { .. }
        | SkillError::MissingSignature { .. }
        | SkillError::InvalidSignature { .. }
        | SkillError::SkillNotInstalled { .. }
        | SkillError::AmbiguousInstalledVersion { .. }
        | SkillError::AlreadyInstalledDifferentDigest { .. }
        | SkillError::Serde { .. }
        | SkillError::Toml { .. }
        | SkillError::RegistryNotFound { .. }
        | SkillError::InvalidConfig { .. }
        | SkillError::SelfTestFailed { .. } => false,
    }
}

fn staging_install_dir(install_dir: &Path) -> Result<PathBuf, SkillError> {
    let parent = install_dir
        .parent()
        .ok_or_else(|| SkillError::UnsafeBundlePath {
            path: install_dir.to_path_buf(),
        })?;
    fs::create_dir_all(parent).map_err(|source| SkillError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let version = install_dir
        .file_name()
        .ok_or_else(|| SkillError::UnsafeBundlePath {
            path: install_dir.to_path_buf(),
        })?
        .to_string_lossy();
    Ok(parent.join(format!(
        ".{version}.tmp-{}-{}",
        std::process::id(),
        temporary_suffix()
    )))
}

fn replace_install_dir(staging_dir: &Path, install_dir: &Path) -> Result<(), SkillError> {
    if !install_dir.exists() {
        return fs::rename(staging_dir, install_dir).map_err(|source| SkillError::Io {
            path: install_dir.to_path_buf(),
            source,
        });
    }

    let backup_dir = backup_install_dir(install_dir)?;
    if backup_dir.exists() {
        fs::remove_dir_all(&backup_dir).map_err(|source| SkillError::Io {
            path: backup_dir.clone(),
            source,
        })?;
    }

    fs::rename(install_dir, &backup_dir).map_err(|source| SkillError::Io {
        path: install_dir.to_path_buf(),
        source,
    })?;
    match fs::rename(staging_dir, install_dir) {
        Ok(()) => {
            fs::remove_dir_all(&backup_dir).map_err(|source| SkillError::Io {
                path: backup_dir,
                source,
            })?;
            Ok(())
        }
        Err(source) => {
            let _ = fs::rename(&backup_dir, install_dir);
            Err(SkillError::Io {
                path: install_dir.to_path_buf(),
                source,
            })
        }
    }
}

fn backup_install_dir(install_dir: &Path) -> Result<PathBuf, SkillError> {
    let parent = install_dir
        .parent()
        .ok_or_else(|| SkillError::UnsafeBundlePath {
            path: install_dir.to_path_buf(),
        })?;
    let version = install_dir
        .file_name()
        .ok_or_else(|| SkillError::UnsafeBundlePath {
            path: install_dir.to_path_buf(),
        })?
        .to_string_lossy();
    Ok(parent.join(format!(
        ".{version}.backup-{}-{}",
        std::process::id(),
        temporary_suffix()
    )))
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), SkillError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|source| SkillError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
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
    let metadata = fs::symlink_metadata(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SkillError::UnsafeBundlePath {
            path: path.to_path_buf(),
        });
    }
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

fn remove_empty_parent(install_dir: &Path) -> Result<(), SkillError> {
    let Some(parent) = install_dir.parent() else {
        return Ok(());
    };
    if parent
        .read_dir()
        .map_err(|source| SkillError::Io {
            path: parent.to_path_buf(),
            source,
        })?
        .next()
        .is_none()
    {
        fs::remove_dir(parent).map_err(|source| SkillError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn load_cached_manifest(install_dir: &Path) -> Result<SkillManifest, SkillError> {
    let manifest_path = install_dir.join(MANIFEST_FILE);
    let content_root = install_dir.join(CONTENT_DIR);
    let content = read_regular_string(&manifest_path)?;
    let raw: RawSkillManifest =
        serde_yaml::from_str(&content).map_err(|source| SkillError::Yaml {
            path: manifest_path.clone(),
            source,
        })?;

    let name = required(raw.name, &manifest_path, "name")?;
    validate_skill_name(&name)?;

    let version = required(raw.version, &manifest_path, "version")?;
    let version = version
        .parse::<Version>()
        .map_err(|source| SkillError::InvalidVersion {
            version: version.clone(),
            source,
        })?;

    let entry = normalize_bundle_path(Path::new(&required(raw.entry, &manifest_path, "entry")?))?;
    let files = raw.files.ok_or_else(|| SkillError::MissingManifestField {
        path: manifest_path.clone(),
        field: "files",
    })?;
    let declared_files = expand_declared_files(&content_root, files)?;
    if !declared_files.contains(&entry) {
        return Err(SkillError::MissingDeclaredFile { path: entry });
    }

    let extra = raw.extra;
    let (signature_ed25519, signature_public_key_ed25519) = raw
        .signatures
        .map(|signatures| {
            (
                signatures.ed25519,
                signatures.public_key_ed25519.or(signatures.public_key),
            )
        })
        .unwrap_or((None, None));

    Ok(SkillManifest {
        name,
        version,
        description: raw.description,
        entry,
        declared_files,
        self_test_command: raw.self_test.and_then(|self_test| self_test.command),
        signature_ed25519,
        signature_public_key_ed25519,
        extra,
    })
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

    fs::read_to_string(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn required(
    value: Option<String>,
    manifest_path: &Path,
    field: &'static str,
) -> Result<String, SkillError> {
    value.ok_or_else(|| SkillError::MissingManifestField {
        path: manifest_path.to_path_buf(),
        field,
    })
}

fn expand_declared_files(root: &Path, patterns: Vec<String>) -> Result<Vec<PathBuf>, SkillError> {
    let mut files = BTreeSet::new();

    for pattern in patterns {
        if let Some(directory) = pattern.strip_suffix("/**") {
            let directory = normalize_bundle_path(Path::new(directory))?;
            let matched = collect_declared_files(root, &directory, &mut files)?;
            if matched == 0 {
                return Err(SkillError::EmptyFilePattern { pattern });
            }
        } else {
            let file = normalize_bundle_path(Path::new(&pattern))?;
            validated_bundle_file(root, &file)?;
            files.insert(file);
        }
    }

    Ok(files.into_iter().collect())
}

fn collect_declared_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<usize, SkillError> {
    validated_bundle_directory(root, directory)?;
    collect_declared_files_inner(root, directory, files)
}

fn collect_declared_files_inner(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<usize, SkillError> {
    let absolute_directory = root.join(directory);
    let entries = fs::read_dir(&absolute_directory).map_err(|source| SkillError::Io {
        path: absolute_directory.clone(),
        source,
    })?;
    let mut matched = 0;

    for entry in entries {
        let entry = entry.map_err(|source| SkillError::Io {
            path: absolute_directory.clone(),
            source,
        })?;
        let relative_path = normalize_bundle_path(&directory.join(entry.file_name()))?;
        let absolute_path = root.join(&relative_path);
        let metadata = fs::symlink_metadata(&absolute_path)
            .map_err(|source| missing_or_io_error(source, &absolute_path, &relative_path))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            matched += collect_declared_files_inner(root, &relative_path, files)?;
        } else if file_type.is_file() {
            files.insert(relative_path);
            matched += 1;
        } else {
            return Err(SkillError::MissingDeclaredFile {
                path: relative_path,
            });
        }
    }

    Ok(matched)
}

fn validated_bundle_directory(root: &Path, relative_path: &Path) -> Result<PathBuf, SkillError> {
    let relative_path = normalize_bundle_path(relative_path)?;
    let mut absolute_path = root.to_path_buf();
    let mut components = relative_path.components().peekable();

    while let Some(component) = components.next() {
        let Component::Normal(part) = component else {
            return Err(SkillError::UnsafeBundlePath {
                path: relative_path.clone(),
            });
        };
        absolute_path.push(part);
        let metadata = fs::symlink_metadata(&absolute_path)
            .map_err(|source| missing_or_io_error(source, &absolute_path, &relative_path))?;
        let file_type = metadata.file_type();

        if components.peek().is_some() {
            if !file_type.is_dir() {
                return Err(SkillError::MissingDeclaredFile {
                    path: relative_path.clone(),
                });
            }
            continue;
        }

        if file_type.is_dir() {
            return Ok(absolute_path);
        }

        return Err(SkillError::MissingDeclaredFile {
            path: relative_path.clone(),
        });
    }

    Err(SkillError::UnsafeBundlePath {
        path: relative_path,
    })
}

fn missing_or_io_error(
    source: std::io::Error,
    absolute_path: &Path,
    relative_path: &Path,
) -> SkillError {
    if source.kind() == std::io::ErrorKind::NotFound {
        SkillError::MissingDeclaredFile {
            path: relative_path.to_path_buf(),
        }
    } else {
        SkillError::Io {
            path: absolute_path.to_path_buf(),
            source,
        }
    }
}

fn installed_at_now() -> String {
    let now = OffsetDateTime::now_utc();
    match now.format(&Rfc3339) {
        Ok(formatted) => formatted,
        Err(_) => now.unix_timestamp().to_string(),
    }
}

fn temporary_suffix() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    }
}
