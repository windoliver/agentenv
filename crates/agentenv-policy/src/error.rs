use thiserror::Error;

pub type PolicyResult<T> = Result<T, PolicyError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unknown preset `{name}`. available presets: {available}")]
    UnknownPreset { name: String, available: String },
    #[error("unsupported access mode `{access}` for preset `{name}`")]
    UnsupportedPresetAccess { name: String, access: String },
    #[error("policy update requires recreate for domains: {domains}")]
    RequiresRecreate { domains: String },
    #[error("failed to load preset registry: {message}")]
    PresetRegistry { message: String },
    #[error("translator `{translator}` does not support this policy: {message}")]
    TranslationUnsupported {
        translator: &'static str,
        message: String,
    },
}

impl PolicyError {
    pub fn requires_recreate<const N: usize>(domains: [&str; N]) -> Self {
        Self::RequiresRecreate {
            domains: domains.join(", "),
        }
    }
}
