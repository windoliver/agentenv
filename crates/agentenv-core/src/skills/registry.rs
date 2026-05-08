use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RegistryConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: RegistryKind,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub auth: Option<String>,
}

impl RegistryConfig {
    pub fn filesystem(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Filesystem,
            url: None,
            path: Some(path.into()),
            auth: None,
        }
    }

    pub fn http(name: impl Into<String>, url: impl Into<String>, auth: Option<String>) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Http,
            url: Some(url.into()),
            path: None,
            auth,
        }
    }

    pub fn oci(
        name: impl Into<String>,
        reference: impl Into<String>,
        auth: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: RegistryKind::Oci,
            url: Some(reference.into()),
            path: None,
            auth,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryKind {
    Filesystem,
    Http,
    Oci,
}
