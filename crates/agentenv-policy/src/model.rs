pub use agentenv_proto::{
    FilesystemPolicy, HttpAccessLevel, InferencePolicy, InferenceRoute, NetworkAccessPolicy,
    NetworkPolicy, NetworkRule, NetworkTarget, PolicyReloadability, ProcessPolicy,
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
            if name.is_empty() {
                return Err(crate::PolicyError::UnsupportedPresetAccess {
                    name: slug.to_owned(),
                    access: "missing preset name before _readwrite suffix".to_owned(),
                });
            }

            return Ok(Self {
                name: name.to_owned(),
                access: PresetAccess::ReadWrite,
            });
        }

        if let Some(name) = slug.strip_suffix("_read") {
            if name.is_empty() {
                return Err(crate::PolicyError::UnsupportedPresetAccess {
                    name: slug.to_owned(),
                    access: "missing preset name before _read suffix".to_owned(),
                });
            }

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
