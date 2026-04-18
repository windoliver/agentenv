pub use agentenv_proto::{
    FilesystemPolicy, InferencePolicy, InferenceRoute, NetworkAccessPolicy, NetworkPolicy,
    NetworkRule, NetworkTarget, PolicyReloadability, ProcessPolicy,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetAccess {
    Read,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetSelection {
    pub name: String,
    pub access: PresetAccess,
}

impl PresetSelection {
    pub fn from_slug(slug: &str) -> Result<Self, crate::PolicyError> {
        if let Some(name) = slug.strip_suffix("_readwrite") {
            return Ok(Self {
                name: name.to_owned(),
                access: PresetAccess::ReadWrite,
            });
        }

        if let Some(name) = slug.strip_suffix("_read") {
            return Ok(Self {
                name: name.to_owned(),
                access: PresetAccess::Read,
            });
        }

        Err(crate::PolicyError::UnsupportedPresetAccess {
            name: slug.to_owned(),
            access: "missing _read or _readwrite suffix".to_owned(),
        })
    }
}
