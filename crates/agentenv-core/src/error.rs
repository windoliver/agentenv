use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlueprintError {
    #[error("failed to parse blueprint YAML: {0}")]
    ParseYaml(#[from] serde_yaml::Error),
    #[error("failed to deserialize blueprint data: {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("missing environment variable `{name}`")]
    UnresolvedEnvVar { name: String },
    #[error("credential reference `{name}` could not be resolved")]
    UnresolvedCredential { name: String },
    #[error("invalid interpolation expression `{expression}`")]
    InvalidInterpolation { expression: String },
    #[error("failed to interpolate blueprint at `{path}`: {source}")]
    Interpolation {
        path: String,
        #[source]
        source: Box<BlueprintError>,
    },
}

impl BlueprintError {
    pub(crate) fn at_path(self, path: impl Into<String>) -> Self {
        Self::Interpolation {
            path: path.into(),
            source: Box::new(self),
        }
    }
}
