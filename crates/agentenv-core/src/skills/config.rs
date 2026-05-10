use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::Deserialize;
use serde_yaml::Value;
use url::Url;

use super::{
    registry::{RegistryConfig, RegistryKind},
    validate_skill_name, SkillError,
};

const CLI_REGISTRY_NAME: &str = "cli";
const PROJECT_CONFIG_PATH: &str = "agentenv.yaml";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SkillsConfig {
    #[serde(default)]
    pub registries: Vec<RegistryConfig>,
    #[serde(default)]
    pub registry_order: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillsConfigOverride {
    pub registry: Option<String>,
}

pub fn load_project_skills_config(yaml: &str) -> Result<SkillsConfig, SkillError> {
    let value: Value = serde_yaml::from_str(yaml).map_err(|source| SkillError::Yaml {
        path: PathBuf::from(PROJECT_CONFIG_PATH),
        source,
    })?;

    let Some(skills) = value
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String("skills".to_owned())))
    else {
        return Ok(SkillsConfig::default());
    };

    if skills.is_null() {
        return Ok(SkillsConfig::default());
    }

    let config = serde_yaml::from_value(skills.clone()).map_err(|source| SkillError::Yaml {
        path: PathBuf::from(PROJECT_CONFIG_PATH),
        source,
    })?;

    normalize_config(config)
}

pub fn load_user_skills_config(toml_text: &str) -> Result<SkillsConfig, SkillError> {
    let config: UserConfig =
        toml::from_str(toml_text).map_err(|source| SkillError::Toml { source })?;

    normalize_config(config.skills)
}

pub fn merge_skills_config(
    user: SkillsConfig,
    project: Option<SkillsConfig>,
    override_config: SkillsConfigOverride,
) -> Result<SkillsConfig, SkillError> {
    let config = match project {
        Some(project) if has_skills_config(&project) => merge_project_over_user(user, project)?,
        _ => user,
    };

    if let Some(registry) = override_config.registry {
        return apply_registry_override(config, &registry);
    }

    normalize_config(config)
}

#[derive(Debug, Default, Deserialize)]
struct UserConfig {
    #[serde(default)]
    skills: SkillsConfig,
}

fn apply_registry_override(
    config: SkillsConfig,
    registry: &str,
) -> Result<SkillsConfig, SkillError> {
    let registry = registry.trim();
    if registry.is_empty() {
        return Err(invalid_config("registry override must not be empty"));
    }

    if let Some(registry) = registry_from_override_source(registry)? {
        return normalize_config(SkillsConfig {
            registries: vec![registry],
            registry_order: vec![CLI_REGISTRY_NAME.to_owned()],
        });
    }

    if is_bare_oci_reference(registry) {
        return normalize_config(SkillsConfig {
            registries: vec![RegistryConfig::oci(CLI_REGISTRY_NAME, registry, None)],
            registry_order: vec![CLI_REGISTRY_NAME.to_owned()],
        });
    }
    if registry.contains('/') {
        return Err(invalid_config(format!(
            "invalid registry override `{registry}`"
        )));
    }

    validate_skill_name(registry)?;
    let config = normalize_config(config)?;
    let selected = config
        .registries
        .into_iter()
        .find(|candidate| candidate.name == registry)
        .ok_or_else(|| SkillError::RegistryNotFound {
            name: registry.to_owned(),
        })?;

    Ok(SkillsConfig {
        registries: vec![selected],
        registry_order: vec![registry.to_owned()],
    })
}

fn registry_from_override_source(source: &str) -> Result<Option<RegistryConfig>, SkillError> {
    if Path::new(source).is_absolute() {
        return Ok(Some(RegistryConfig::filesystem(
            CLI_REGISTRY_NAME,
            PathBuf::from(source),
        )));
    }
    if !source.contains("://") && source.contains('/') {
        return Ok(None);
    }

    let Ok(url) = Url::parse(source) else {
        return Ok(None);
    };

    match url.scheme() {
        "file" => Ok(Some(RegistryConfig::filesystem(
            CLI_REGISTRY_NAME,
            url.to_file_path()
                .map_err(|()| invalid_config(format!("invalid file registry URL `{source}`")))?,
        ))),
        "http" | "https" => Ok(Some(RegistryConfig::http(
            CLI_REGISTRY_NAME,
            url.as_str(),
            None,
        ))),
        "oci" => Ok(Some(RegistryConfig::oci(
            CLI_REGISTRY_NAME,
            normalize_oci_reference(&oci_reference_from_url(&url)?)?,
            None,
        ))),
        scheme => Err(invalid_config(format!(
            "unsupported registry URL scheme `{scheme}`"
        ))),
    }
}

fn oci_reference_from_url(url: &Url) -> Result<String, SkillError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid_config(
            "oci registry URL must not include user info",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_config(
            "oci registry URL must not include query or fragment",
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| invalid_config("oci registry URL must include a host"))?;

    let mut reference = host.to_owned();
    if let Some(port) = url.port() {
        reference.push(':');
        reference.push_str(&port.to_string());
    }
    if url.path() != "/" {
        reference.push_str(url.path());
    }

    if reference.is_empty() {
        return Err(invalid_config("oci registry reference must not be empty"));
    }

    Ok(reference)
}

fn normalize_config(mut config: SkillsConfig) -> Result<SkillsConfig, SkillError> {
    normalize_registry_values(&mut config)?;
    validate_registries(&config.registries)?;

    if config.registry_order.is_empty() {
        config.registry_order = config
            .registries
            .iter()
            .map(|registry| registry.name.clone())
            .collect();
    }

    validate_registry_order(&config)?;

    Ok(config)
}

fn normalize_registry_values(config: &mut SkillsConfig) -> Result<(), SkillError> {
    for registry in &mut config.registries {
        match registry.kind {
            RegistryKind::Filesystem => {}
            RegistryKind::Http => {
                if let Some(url) = registry.url.as_mut() {
                    *url = url.trim().to_owned();
                }
            }
            RegistryKind::Oci => {
                if let Some(reference) = registry.url.as_mut() {
                    *reference = normalize_oci_reference(reference)?;
                }
            }
        }
    }

    Ok(())
}

fn merge_project_over_user(
    user: SkillsConfig,
    project: SkillsConfig,
) -> Result<SkillsConfig, SkillError> {
    let user = normalize_config(user)?;
    let project = normalize_config(project)?;
    let mut by_name = BTreeMap::new();
    let mut order = Vec::new();

    for registry in user.registries {
        order.push(registry.name.clone());
        by_name.insert(registry.name.clone(), registry);
    }

    for registry in project.registries {
        if !by_name.contains_key(&registry.name) {
            order.push(registry.name.clone());
        }
        by_name.insert(registry.name.clone(), registry);
    }

    if !project.registry_order.is_empty() {
        let project_order = project.registry_order.iter().collect::<BTreeSet<_>>();
        order.retain(|name| !project_order.contains(name));
        let mut merged_order = project.registry_order;
        merged_order.extend(order);
        order = merged_order;
    }

    normalize_config(SkillsConfig {
        registries: by_name.into_values().collect(),
        registry_order: order,
    })
}

fn validate_registries(registries: &[RegistryConfig]) -> Result<(), SkillError> {
    let mut names = BTreeSet::new();
    for registry in registries {
        validate_skill_name(&registry.name)?;
        if !names.insert(registry.name.as_str()) {
            return Err(invalid_config(format!(
                "duplicate registry name `{}`",
                registry.name
            )));
        }
        validate_registry_required_fields(registry)?;
    }

    Ok(())
}

fn validate_registry_required_fields(registry: &RegistryConfig) -> Result<(), SkillError> {
    match registry.kind {
        RegistryKind::Filesystem => {
            if registry
                .path
                .as_ref()
                .is_none_or(|path| path.as_os_str().is_empty())
            {
                return Err(invalid_config(format!(
                    "filesystem registry `{}` requires path",
                    registry.name
                )));
            }
        }
        RegistryKind::Http => {
            let Some(url) = registry
                .url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty())
            else {
                return Err(invalid_config(format!(
                    "http registry `{}` requires url",
                    registry.name
                )));
            };
            validate_http_url(&registry.name, url)?;
        }
        RegistryKind::Oci => {
            let Some(reference) = registry
                .url
                .as_deref()
                .map(str::trim)
                .filter(|reference| !reference.is_empty())
            else {
                return Err(invalid_config(format!(
                    "oci registry `{}` requires url",
                    registry.name
                )));
            };
            normalize_oci_reference(reference)?;
        }
    }

    Ok(())
}

fn validate_http_url(name: &str, value: &str) -> Result<(), SkillError> {
    let url = Url::parse(value).map_err(|source| {
        invalid_config(format!(
            "http registry `{name}` has invalid url `{value}`: {source}"
        ))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid_config(format!(
            "http registry `{name}` uses unsupported url scheme `{}`",
            url.scheme()
        )));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid_config(format!(
            "http registry `{name}` url must include a host"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid_config(format!(
            "http registry `{name}` url must not include user info"
        )));
    }
    Ok(())
}

fn normalize_oci_reference(reference: &str) -> Result<String, SkillError> {
    let reference = reference.trim();
    if let Ok(url) = Url::parse(reference) {
        if url.scheme() == "oci" {
            return normalize_oci_reference(&oci_reference_from_url(&url)?);
        }
    }

    if !is_bare_oci_reference(reference) {
        return Err(invalid_config(format!(
            "invalid oci registry reference `{reference}`"
        )));
    }
    Ok(reference.to_owned())
}

fn is_bare_oci_reference(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.contains(char::is_whitespace)
        || value.contains("://")
        || value.contains('@')
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
    {
        return false;
    }

    let mut parts = value.split('/');
    let Some(host) = parts.next() else {
        return false;
    };
    let Some(first_path) = parts.next() else {
        return false;
    };
    if first_path.is_empty() || parts.clone().any(str::is_empty) {
        return false;
    }

    is_valid_oci_host(host)
        && is_valid_oci_path_component(first_path)
        && parts.all(is_valid_oci_path_component)
}

fn is_valid_oci_host(host: &str) -> bool {
    let Some((domain, port)) = split_host_port(host) else {
        return false;
    };
    if !(domain == "localhost" || domain.contains('.')) {
        return false;
    }
    if !domain.split('.').all(|label| {
        is_valid_oci_host_label(label) && !label.starts_with('-') && !label.ends_with('-')
    }) {
        return false;
    }

    port.is_none_or(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn split_host_port(host: &str) -> Option<(&str, Option<&str>)> {
    let (domain, port) = match host.split_once(':') {
        Some((domain, port)) => {
            if port.contains(':') {
                return None;
            }
            (domain, Some(port))
        }
        None => (host, None),
    };

    if domain.is_empty() {
        None
    } else {
        Some((domain, port))
    }
}

fn is_valid_oci_host_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_valid_oci_path_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_lowercase()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
    {
        return false;
    }

    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    })
}

fn validate_registry_order(config: &SkillsConfig) -> Result<(), SkillError> {
    let registry_names = config
        .registries
        .iter()
        .map(|registry| registry.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut order_names = BTreeSet::new();

    for name in &config.registry_order {
        validate_skill_name(name)?;
        if !order_names.insert(name.as_str()) {
            return Err(invalid_config(format!(
                "duplicate registry order entry `{name}`"
            )));
        }
        if !registry_names.contains(name.as_str()) {
            return Err(invalid_config(format!(
                "registry_order references unknown registry `{name}`"
            )));
        }
    }

    Ok(())
}

fn has_skills_config(config: &SkillsConfig) -> bool {
    !config.registries.is_empty() || !config.registry_order.is_empty()
}

fn invalid_config(message: impl Into<String>) -> SkillError {
    SkillError::InvalidConfig {
        message: message.into(),
    }
}
