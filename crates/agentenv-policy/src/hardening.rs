use std::{collections::BTreeMap, env, fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{model::NetworkPolicy, PolicyError, PolicyResult};

const BUILTIN_PROFILE_NAMES: [&str; 3] = ["baseline", "strict", "open"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningProfile {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub packages: HardeningPackages,
    #[serde(default)]
    pub mounts: HardeningMounts,
    #[serde(default)]
    pub ulimits: HardeningUlimits,
    #[serde(default)]
    pub capabilities: HardeningCapabilities,
    pub dockerfile: HardeningDockerfile,
    #[serde(default)]
    pub disable_core_dumps: bool,
    #[serde(default)]
    pub disable_user_namespaces: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningPackages {
    #[serde(default)]
    pub strip: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningMounts {
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
    #[serde(default)]
    pub tmpfs: Vec<HardeningTmpfsMount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningTmpfsMount {
    pub path: String,
    pub size: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningUlimits {
    pub nproc: Option<u64>,
    pub nofile: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HardeningCapabilities {
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningDockerfile {
    pub marker: String,
    pub fragment: String,
}

impl HardeningProfile {
    pub fn from_yaml(name: &str, yaml: &str) -> PolicyResult<Self> {
        let mut profile: Self =
            serde_yaml::from_str(yaml).map_err(|err| hardening_error(name, err.to_string()))?;
        profile.normalize();
        profile.validate(name)?;
        Ok(profile)
    }

    fn normalize(&mut self) {
        sort_and_dedup(&mut self.packages.strip);
        sort_and_dedup(&mut self.mounts.read_only);
        sort_and_dedup(&mut self.mounts.read_write);
        sort_and_dedup(&mut self.capabilities.drop);
        self.mounts.tmpfs.sort_by_key(tmpfs_sort_key);
        self.mounts.tmpfs.dedup();
    }

    fn validate(&self, source_name: &str) -> PolicyResult<()> {
        if self.name.trim().is_empty() {
            return Err(hardening_error(source_name, "name must be non-empty"));
        }
        if self.description.trim().is_empty() {
            return Err(hardening_error(&self.name, "description must be non-empty"));
        }
        if self.dockerfile.marker.trim().is_empty() {
            return Err(hardening_error(
                &self.name,
                "dockerfile marker must be non-empty",
            ));
        }
        if !self.dockerfile.fragment.contains("RUN ") {
            return Err(hardening_error(
                &self.name,
                "dockerfile fragment must contain `RUN `",
            ));
        }
        if self.ulimits.nproc == Some(0) {
            return Err(hardening_error(&self.name, "nproc ulimit must be positive"));
        }
        if self.ulimits.nofile == Some(0) {
            return Err(hardening_error(
                &self.name,
                "nofile ulimit must be positive",
            ));
        }
        for package in &self.packages.strip {
            if package.trim().is_empty() || package.chars().any(char::is_whitespace) {
                return Err(hardening_error(
                    &self.name,
                    "package strip entries must be non-empty and contain no whitespace",
                ));
            }
        }
        validate_filesystem_paths(&self.name, "read_only", &self.mounts.read_only)?;
        validate_filesystem_paths(&self.name, "read_write", &self.mounts.read_write)?;
        for mount in &self.mounts.tmpfs {
            if !mount.path.starts_with('/') {
                return Err(hardening_error(
                    &self.name,
                    format!("tmpfs path `{}` must be absolute", mount.path),
                ));
            }
            if mount
                .size
                .as_deref()
                .is_some_and(|size| size.trim().is_empty())
            {
                return Err(hardening_error(
                    &self.name,
                    format!("tmpfs path `{}` size must be non-empty", mount.path),
                ));
            }
        }
        Ok(())
    }
}

fn validate_filesystem_paths(name: &str, field: &str, paths: &[String]) -> PolicyResult<()> {
    for path in paths {
        if path.trim().is_empty() {
            return Err(hardening_error(
                name,
                format!("mounts.{field} path must be non-empty and absolute"),
            ));
        }
        if !path.starts_with('/') {
            return Err(hardening_error(
                name,
                format!("mounts.{field} path `{path}` must be absolute"),
            ));
        }
    }

    Ok(())
}

pub fn builtin_hardening_profile(name: &str) -> PolicyResult<HardeningProfile> {
    let yaml = match name {
        "baseline" => include_str!("../hardening/baseline.yaml"),
        "strict" => include_str!("../hardening/strict.yaml"),
        "open" => include_str!("../hardening/open.yaml"),
        _ => return Err(unknown_hardening_profile(name)),
    };

    HardeningProfile::from_yaml(name, yaml)
}

pub fn resolve_hardening_profile(value: &str) -> PolicyResult<HardeningProfile> {
    if BUILTIN_PROFILE_NAMES.contains(&value) {
        return builtin_hardening_profile(value);
    }

    let local_path = Path::new(value);
    if local_path.is_file() {
        return load_profile_from_path(value, local_path);
    }

    if let Ok(profile_dir) = env::var("AGENTENV_HARDENING_PROFILE_DIR") {
        let path = Path::new(&profile_dir).join(format!("{value}.yaml"));
        if path.is_file() {
            return load_profile_from_path(value, &path);
        }
    }

    if let Some(home_dir) = home_dir() {
        let path = home_dir
            .join(".agentenv")
            .join("hardening")
            .join(format!("{value}.yaml"));
        if path.is_file() {
            return load_profile_from_path(value, &path);
        }
    }

    Err(unknown_hardening_profile(value))
}

pub fn apply_hardening_to_policy(
    policy: &mut NetworkPolicy,
    profile: &HardeningProfile,
    persist_home: bool,
) -> PolicyResult<()> {
    for path in &profile.mounts.read_only {
        merge_path(
            &mut policy.filesystem.read_only,
            &mut policy.filesystem.read_write,
            path,
        );
    }

    for path in &profile.mounts.read_write {
        merge_path(
            &mut policy.filesystem.read_write,
            &mut policy.filesystem.read_only,
            path,
        );
    }

    if persist_home {
        merge_path(
            &mut policy.filesystem.read_write,
            &mut policy.filesystem.read_only,
            "$HOME",
        );
    }

    sort_and_dedup(&mut policy.filesystem.read_only);
    sort_and_dedup(&mut policy.filesystem.read_write);
    Ok(())
}

pub fn hardening_metadata(
    profile: &HardeningProfile,
) -> PolicyResult<BTreeMap<String, serde_json::Value>> {
    profile.validate(&profile.name)?;

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "hardening_profile".to_owned(),
        Value::String(profile.name.clone()),
    );
    metadata.insert(
        "hardening_packages_strip".to_owned(),
        serde_json::to_value(&profile.packages.strip).map_err(json_error)?,
    );
    metadata.insert(
        "hardening_tmpfs".to_owned(),
        serde_json::to_value(&profile.mounts.tmpfs).map_err(json_error)?,
    );
    metadata.insert(
        "hardening_capabilities_drop".to_owned(),
        serde_json::to_value(&profile.capabilities.drop).map_err(json_error)?,
    );
    metadata.insert(
        "hardening_dockerfile_marker".to_owned(),
        Value::String(profile.dockerfile.marker.clone()),
    );
    metadata.insert(
        "hardening_dockerfile_fragment".to_owned(),
        Value::String(profile.dockerfile.fragment.clone()),
    );
    metadata.insert(
        "hardening_disable_core_dumps".to_owned(),
        Value::Bool(profile.disable_core_dumps),
    );
    metadata.insert(
        "hardening_disable_user_namespaces".to_owned(),
        Value::Bool(profile.disable_user_namespaces),
    );
    metadata.insert(
        "hardening_ulimit_nproc".to_owned(),
        serde_json::to_value(profile.ulimits.nproc).map_err(json_error)?,
    );
    metadata.insert(
        "hardening_ulimit_nofile".to_owned(),
        serde_json::to_value(profile.ulimits.nofile).map_err(json_error)?,
    );

    Ok(metadata)
}

fn load_profile_from_path(name: &str, path: &Path) -> PolicyResult<HardeningProfile> {
    let yaml = fs::read_to_string(path).map_err(|err| {
        hardening_error(name, format!("failed to read `{}`: {err}", path.display()))
    })?;
    HardeningProfile::from_yaml(name, &yaml)
}

fn home_dir() -> Option<std::path::PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}

fn merge_path(target: &mut Vec<String>, other: &mut Vec<String>, path: &str) {
    target.retain(|existing| existing != path);
    other.retain(|existing| existing != path);
    target.push(path.to_owned());
}

fn sort_and_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn tmpfs_sort_key(mount: &HardeningTmpfsMount) -> String {
    format!(
        "{}|{}",
        mount.path,
        mount.size.as_deref().unwrap_or_default()
    )
}

fn hardening_error(name: &str, message: impl Into<String>) -> PolicyError {
    PolicyError::HardeningProfile {
        name: name.to_owned(),
        message: message.into(),
    }
}

fn json_error(err: serde_json::Error) -> PolicyError {
    hardening_error("metadata", err.to_string())
}

fn unknown_hardening_profile(name: &str) -> PolicyError {
    PolicyError::UnknownHardeningProfile {
        name: name.to_owned(),
        available: BUILTIN_PROFILE_NAMES.join(", "),
    }
}
