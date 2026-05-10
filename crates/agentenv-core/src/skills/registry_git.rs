use std::path::Path;

use super::{FetchedSkill, RegistryAdapter, SkillError, SkillSearchHit};

const SOURCE_TYPE: &str = "git";

#[derive(Debug, Clone)]
pub(crate) struct GitRegistryAdapter {
    name: String,
    _url: String,
}

impl GitRegistryAdapter {
    pub(crate) fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            _url: url.into(),
        }
    }
}

#[async_trait::async_trait]
impl RegistryAdapter for GitRegistryAdapter {
    async fn search(&self, _query: &str) -> Result<Vec<SkillSearchHit>, SkillError> {
        Err(SkillError::InvalidConfig {
            message: format!("git registry `{}` is not implemented yet", self.name),
        })
    }

    async fn fetch(&self, name: &str, _version: Option<&str>) -> Result<FetchedSkill, SkillError> {
        Err(SkillError::SkillNotInstalled {
            name: name.to_owned(),
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
