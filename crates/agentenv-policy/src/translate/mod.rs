use crate::PolicyResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceUpdate {
    pub provider: String,
    pub model: String,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedPolicy {
    pub format: &'static str,
    pub policy_yaml: String,
    pub inference_update: Option<InferenceUpdate>,
}

pub trait PolicyTranslator {
    fn translate(&self, policy: &agentenv_proto::NetworkPolicy) -> PolicyResult<TranslatedPolicy>;
}

pub mod docker;
pub mod openshell;

pub use docker::DockerTranslator;
pub use openshell::OpenShellTranslator;
