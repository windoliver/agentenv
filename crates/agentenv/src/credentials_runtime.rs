use agentenv_core::{
    driver::DriverError,
    runtime::{CredentialProvider, RuntimeError, RuntimeResult, RuntimeSecret},
};
use agentenv_credstore::{CredentialStore, CredentialStoreError, SecretString};
use agentenv_proto::CredentialRequirement;

pub(crate) struct CliCredentialProvider {
    pub(crate) store: CredentialStore,
    pub(crate) non_interactive: bool,
    pub(crate) prompter: Box<dyn CredentialPrompter>,
}

pub(crate) trait CredentialPrompter {
    fn prompt(&mut self, requirement: &CredentialRequirement) -> RuntimeResult<SecretString>;
}

pub(crate) struct TerminalCredentialPrompter;

impl CredentialPrompter for TerminalCredentialPrompter {
    fn prompt(&mut self, requirement: &CredentialRequirement) -> RuntimeResult<SecretString> {
        let mut prompt = format!("Enter value for `{}`", requirement.name);
        if !requirement.description.trim().is_empty() {
            prompt.push_str(&format!(" ({})", requirement.description));
        }
        prompt.push_str(": ");
        let value = rpassword::prompt_password(prompt).map_err(|source| {
            RuntimeError::Driver(DriverError::InvalidInput {
                message: format!(
                    "failed to prompt for credential `{}`: {source}",
                    requirement.name
                ),
            })
        })?;
        Ok(SecretString::new(value))
    }
}

impl CredentialProvider for CliCredentialProvider {
    fn resolve(
        &mut self,
        requirement: &CredentialRequirement,
    ) -> RuntimeResult<Option<RuntimeSecret>> {
        let name = &requirement.name;
        match self.store.resolve(name, requirement) {
            Ok(secret) => Ok(Some(RuntimeSecret::new(secret.expose_secret().to_owned()))),
            Err(CredentialStoreError::MissingCredential { .. }) if !requirement.required => {
                Ok(None)
            }
            Err(CredentialStoreError::MissingCredential { .. }) if self.non_interactive => {
                Err(RuntimeError::MissingCredential {
                    name: name.to_owned(),
                })
            }
            Err(CredentialStoreError::MissingCredential { .. }) => {
                let prompted = self.prompter.prompt(requirement)?;
                self.store
                    .store(name, &prompted)
                    .map_err(credential_store_runtime_error)?;
                let resolved = self
                    .store
                    .resolve(name, requirement)
                    .map_err(credential_store_runtime_error)?;
                Ok(Some(RuntimeSecret::new(
                    resolved.expose_secret().to_owned(),
                )))
            }
            Err(error) => Err(credential_store_runtime_error(error)),
        }
    }

    fn backend_name(&self, name: &str) -> RuntimeResult<Option<String>> {
        Ok(self
            .store
            .where_is(name)
            .ok()
            .flatten()
            .map(|backend| backend.to_string()))
    }
}

pub(crate) fn credential_store_runtime_error(error: CredentialStoreError) -> RuntimeError {
    RuntimeError::Driver(DriverError::InvalidInput {
        message: error.to_string(),
    })
}
