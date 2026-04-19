#[derive(Debug, Default)]
pub struct DockerTranslator;

impl super::PolicyTranslator for DockerTranslator {
    fn translate(
        &self,
        _policy: &agentenv_proto::NetworkPolicy,
    ) -> crate::PolicyResult<super::TranslatedPolicy> {
        Err(crate::PolicyError::TranslationUnsupported {
            translator: "docker",
            message: "docker translation is post-MVP".to_owned(),
        })
    }
}
