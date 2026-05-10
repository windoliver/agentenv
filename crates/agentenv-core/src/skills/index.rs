use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{store::InstalledSkill, validate_skill_name, SkillError};

const SKILLS_DIR: &str = "skills";
const INDEX_FILE: &str = "index.yaml";
const INSTALLED_FILE: &str = "installed.yaml";

#[derive(Debug, Default, Serialize, Deserialize)]
struct InstalledSkillsIndex {
    skills: Vec<InstalledSkill>,
}

pub(crate) fn skills_root(root: &Path) -> PathBuf {
    root.join(SKILLS_DIR)
}

pub(crate) fn index_path(root: &Path) -> PathBuf {
    skills_root(root).join(INDEX_FILE)
}

pub(crate) fn installed_record_path(install_dir: &Path) -> PathBuf {
    install_dir.join(INSTALLED_FILE)
}

pub(crate) fn rebuild(root: &Path) -> Result<Vec<InstalledSkill>, SkillError> {
    let skills_root = skills_root(root);
    let root_metadata = match fs::symlink_metadata(&skills_root) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(SkillError::Io {
                path: skills_root.clone(),
                source,
            });
        }
    };
    if !root_metadata.file_type().is_dir() {
        return Err(SkillError::UnsafeBundlePath { path: skills_root });
    }

    let mut installed = Vec::new();
    for name_entry in fs::read_dir(&skills_root).map_err(|source| SkillError::Io {
        path: skills_root.clone(),
        source,
    })? {
        let name_entry = name_entry.map_err(|source| SkillError::Io {
            path: skills_root.clone(),
            source,
        })?;
        let name_path = name_entry.path();
        let Some(name) = path_component_string(&name_path) else {
            return Err(SkillError::UnsafeBundlePath { path: name_path });
        };
        if name.starts_with('.') {
            continue;
        }
        let name_file_type = symlink_file_type(&name_path)?;
        if name_file_type.is_symlink() {
            return Err(SkillError::UnsafeBundlePath { path: name_path });
        }
        if !name_file_type.is_dir() {
            continue;
        }
        validate_skill_name(&name)?;

        for version_entry in fs::read_dir(&name_path).map_err(|source| SkillError::Io {
            path: name_path.clone(),
            source,
        })? {
            let version_entry = version_entry.map_err(|source| SkillError::Io {
                path: name_path.clone(),
                source,
            })?;
            let install_dir = version_entry.path();
            let Some(version) = path_component_string(&install_dir) else {
                return Err(SkillError::UnsafeBundlePath { path: install_dir });
            };
            if version.starts_with('.') {
                continue;
            }
            let version_file_type = symlink_file_type(&install_dir)?;
            if version_file_type.is_symlink() {
                return Err(SkillError::UnsafeBundlePath { path: install_dir });
            }
            if !version_file_type.is_dir() {
                continue;
            }
            version
                .parse::<semver::Version>()
                .map_err(|source| SkillError::InvalidVersion {
                    version: version.clone(),
                    source,
                })?;

            let record_path = installed_record_path(&install_dir);
            match symlink_file_type(&record_path) {
                Ok(file_type) if file_type.is_symlink() => {
                    return Err(SkillError::UnsafeBundlePath { path: record_path });
                }
                Ok(file_type) if file_type.is_file() => {}
                Ok(_) => continue,
                Err(SkillError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }

            let mut record = read_record(&record_path)?;
            if record.name != name || record.version != version {
                return Err(SkillError::UnsafeBundlePath { path: record_path });
            }
            record.path = install_dir.clone();
            installed.push(record);
        }
    }

    sort_installed(&mut installed);
    write(root, &installed)?;
    Ok(installed)
}

pub(crate) fn write(root: &Path, installed: &[InstalledSkill]) -> Result<(), SkillError> {
    let mut installed = installed.to_vec();
    sort_installed(&mut installed);
    let index = InstalledSkillsIndex { skills: installed };
    let path = index_path(root);
    write_yaml_atomic(&path, &index)
}

pub(crate) fn read_record(path: &Path) -> Result<InstalledSkill, SkillError> {
    let content = read_regular_string(path)?;
    serde_yaml::from_str(&content).map_err(|source| SkillError::Serde {
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn write_record(path: &Path, installed: &InstalledSkill) -> Result<(), SkillError> {
    write_yaml_atomic(path, installed)
}

fn sort_installed(installed: &mut [InstalledSkill]) {
    installed.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
    });
}

fn path_component_string(path: &Path) -> Option<String> {
    path.file_name()?.to_str().map(ToOwned::to_owned)
}

fn symlink_file_type(path: &Path) -> Result<fs::FileType, SkillError> {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type())
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn read_regular_string(path: &Path) -> Result<String, SkillError> {
    let file_type = symlink_file_type(path)?;
    if !file_type.is_file() {
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
    fs::create_dir_all(parent).map_err(|source| SkillError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

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

fn temporary_suffix() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    }
}
