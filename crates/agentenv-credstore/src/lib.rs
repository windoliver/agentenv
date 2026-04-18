#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use agentenv_proto::{CredentialRequirement, ValidatorSpec};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

const DEFAULT_SERVICE_NAME: &str = "agentenv";
const STORE_DIR: &str = ".agentenv";
const CREDENTIALS_FILE: &str = "credentials.json";
const INDEX_FILE: &str = "credentials-index.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialBackend {
    Keyring,
    File,
    Env,
}

impl fmt::Display for CredentialBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keyring => f.write_str("keyring"),
            Self::File => f.write_str("file"),
            Self::Env => f.write_str("env"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Debug, Error)]
pub enum CredentialStoreError {
    #[error("home directory is unavailable; cannot derive credential store path")]
    HomeDirectoryUnavailable,
    #[error("credential `{name}` is missing")]
    MissingCredential { name: String },
    #[error("credential `{name}` failed validation: {reason}")]
    Validation { name: String, reason: String },
    #[error("environment variable `{env_var}` for credential `{name}` is missing")]
    MissingEnvironmentVariable { name: String, env_var: String },
    #[error("keyring operation for `{name}` failed: {message}")]
    Keyring { name: String, message: String },
    #[error("failed to read or write `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse or serialize JSON at `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("regex validator for `{name}` is invalid: {source}")]
    ValidatorRegex {
        name: String,
        #[source]
        source: regex::Error,
    },
    #[error("curl probe validator for `{name}` failed to send request: {source}")]
    ValidatorProbeRequest {
        name: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("curl probe validator for `{name}` returned status {status}")]
    ValidatorProbeStatus {
        name: String,
        status: reqwest::StatusCode,
    },
}

pub type Result<T> = std::result::Result<T, CredentialStoreError>;

#[derive(Clone, Debug)]
pub struct CredentialStoreConfig {
    pub root_dir: PathBuf,
    pub service_name: String,
}

impl CredentialStoreConfig {
    pub fn from_home_dir() -> Result<Self> {
        let home = dirs::home_dir().ok_or(CredentialStoreError::HomeDirectoryUnavailable)?;
        Ok(Self {
            root_dir: home.join(STORE_DIR),
            service_name: DEFAULT_SERVICE_NAME.to_owned(),
        })
    }

    pub fn from_root_dir(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
            service_name: DEFAULT_SERVICE_NAME.to_owned(),
        }
    }

    fn credentials_path(&self) -> PathBuf {
        self.root_dir.join(CREDENTIALS_FILE)
    }

    fn index_path(&self) -> PathBuf {
        self.root_dir.join(INDEX_FILE)
    }
}

trait KeyringClient: Send + Sync {
    fn get(&self, name: &str) -> std::result::Result<Option<SecretString>, KeyringClientError>;
    fn set(&self, name: &str, value: &SecretString) -> std::result::Result<(), KeyringClientError>;
    fn remove(&self, name: &str) -> std::result::Result<(), KeyringClientError>;
}

#[derive(Debug, Error)]
enum KeyringClientError {
    #[error("{0}")]
    Other(String),
}

struct OsKeyringClient {
    service_name: String,
}

impl OsKeyringClient {
    fn new(service_name: String) -> Self {
        Self { service_name }
    }

    fn entry(&self, name: &str) -> std::result::Result<keyring::Entry, KeyringClientError> {
        keyring::Entry::new(&self.service_name, name)
            .map_err(|error| KeyringClientError::Other(error.to_string()))
    }
}

impl KeyringClient for OsKeyringClient {
    fn get(&self, name: &str) -> std::result::Result<Option<SecretString>, KeyringClientError> {
        let entry = self.entry(name)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(SecretString::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(KeyringClientError::Other(error.to_string())),
        }
    }

    fn set(&self, name: &str, value: &SecretString) -> std::result::Result<(), KeyringClientError> {
        let entry = self.entry(name)?;
        entry
            .set_password(value.expose_secret())
            .map_err(|error| KeyringClientError::Other(error.to_string()))
    }

    fn remove(&self, name: &str) -> std::result::Result<(), KeyringClientError> {
        let entry = self.entry(name)?;
        match entry.delete_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(KeyringClientError::Other(error.to_string())),
        }
    }
}

struct DisabledKeyringClient;

impl KeyringClient for DisabledKeyringClient {
    fn get(&self, _name: &str) -> std::result::Result<Option<SecretString>, KeyringClientError> {
        Ok(None)
    }

    fn set(
        &self,
        _name: &str,
        _value: &SecretString,
    ) -> std::result::Result<(), KeyringClientError> {
        Err(KeyringClientError::Other(
            "keyring disabled via AGENTENV_DISABLE_KEYRING".to_owned(),
        ))
    }

    fn remove(&self, _name: &str) -> std::result::Result<(), KeyringClientError> {
        Ok(())
    }
}

#[derive(Default, Deserialize, Serialize)]
struct FileCredentials {
    #[serde(default)]
    values: BTreeMap<String, String>,
}

#[derive(Default, Deserialize, Serialize)]
struct CredentialIndex {
    #[serde(default)]
    locations: BTreeMap<String, CredentialBackend>,
}

pub struct CredentialStore {
    config: CredentialStoreConfig,
    keyring: Box<dyn KeyringClient>,
    startup_warnings: Vec<String>,
}

impl CredentialStore {
    pub fn from_default_paths() -> Result<Self> {
        let config = CredentialStoreConfig::from_home_dir()?;
        Self::new(config)
    }

    pub fn new(config: CredentialStoreConfig) -> Result<Self> {
        let keyring: Box<dyn KeyringClient> = if disable_keyring_from_env() {
            Box::new(DisabledKeyringClient)
        } else {
            Box::new(OsKeyringClient::new(config.service_name.clone()))
        };
        Self::new_with_keyring(config, keyring)
    }

    pub fn resolve(&self, name: &str, requirement: &CredentialRequirement) -> Result<SecretString> {
        if let Some(secret) = self.read_from_keyring_best_effort(name) {
            self.validate(name, requirement, &secret)?;
            return Ok(secret);
        }

        if let Some(secret) = self.read_from_file(name)? {
            self.validate(name, requirement, &secret)?;
            return Ok(secret);
        }

        if let Ok(secret) = std::env::var(name) {
            let secret = SecretString::new(secret);
            self.validate(name, requirement, &secret)?;
            return Ok(secret);
        }

        Err(CredentialStoreError::MissingCredential {
            name: name.to_owned(),
        })
    }

    pub fn store(&mut self, name: &str, value: &SecretString) -> Result<()> {
        let mut used_keyring = false;
        match self.keyring.set(name, value) {
            Ok(_) => {
                used_keyring = true;
                self.remove_from_file(name)?;
                self.set_index_location(name, CredentialBackend::Keyring)?;
            }
            Err(error) => {
                warn!(credential = %name, %error, "keyring unavailable, falling back to file backend");
            }
        }

        if !used_keyring {
            self.write_to_file(name, value)?;
            self.set_index_location(name, CredentialBackend::File)?;
        }

        Ok(())
    }

    pub fn store_from_env(&mut self, name: &str, env_var: &str) -> Result<()> {
        let value = std::env::var(env_var).map_err(|_| {
            CredentialStoreError::MissingEnvironmentVariable {
                name: name.to_owned(),
                env_var: env_var.to_owned(),
            }
        })?;
        self.store(name, &SecretString::new(value))
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        let indexed_backend = self.indexed_backend(name)?;
        let removed_from_file = self.remove_from_file(name)?;

        match self.keyring.remove(name) {
            Ok(_) => {
                self.remove_index_location(name)?;
                Ok(())
            }
            Err(error) => {
                let can_ignore_keyring_error = matches!(
                    indexed_backend,
                    Some(CredentialBackend::File) | Some(CredentialBackend::Env)
                ) || (indexed_backend.is_none()
                    && removed_from_file);

                if can_ignore_keyring_error {
                    warn!(
                        credential = %name,
                        %error,
                        "keyring removal failed for non-keyring credential; continuing"
                    );
                    self.remove_index_location(name)?;
                    Ok(())
                } else {
                    Err(CredentialStoreError::Keyring {
                        name: name.to_owned(),
                        message: error.to_string(),
                    })
                }
            }
        }
    }

    pub fn list(&self) -> Result<Vec<String>> {
        let mut names = BTreeSet::new();
        let index = self.read_index()?;
        names.extend(index.locations.into_keys());

        let file = self.read_file_store()?;
        names.extend(file.values.into_keys());

        Ok(names.into_iter().collect())
    }

    pub fn where_is(&self, name: &str) -> Result<Option<CredentialBackend>> {
        if self.read_from_keyring_best_effort(name).is_some() {
            return Ok(Some(CredentialBackend::Keyring));
        }

        if self.read_from_file(name)?.is_some() {
            return Ok(Some(CredentialBackend::File));
        }

        if std::env::var_os(name).is_some() {
            return Ok(Some(CredentialBackend::Env));
        }

        Ok(None)
    }

    pub fn startup_warnings(&self) -> &[String] {
        &self.startup_warnings
    }

    pub fn credentials_path(&self) -> PathBuf {
        self.config.credentials_path()
    }

    fn new_with_keyring(
        config: CredentialStoreConfig,
        keyring: Box<dyn KeyringClient>,
    ) -> Result<Self> {
        ensure_store_dir(&config.root_dir)?;
        let warnings = collect_permission_warnings(&config.credentials_path())?;
        for warning in &warnings {
            warn!("{warning}");
        }

        Ok(Self {
            config,
            keyring,
            startup_warnings: warnings,
        })
    }

    fn read_from_keyring_best_effort(&self, name: &str) -> Option<SecretString> {
        match self.keyring.get(name) {
            Ok(secret) => secret,
            Err(error) => {
                warn!(credential = %name, %error, "failed to read from keyring");
                None
            }
        }
    }

    fn validate(
        &self,
        name: &str,
        requirement: &CredentialRequirement,
        secret: &SecretString,
    ) -> Result<()> {
        if let Some(validator) = &requirement.validator {
            match validator {
                ValidatorSpec::Regex { pattern } => {
                    let regex = Regex::new(pattern).map_err(|source| {
                        CredentialStoreError::ValidatorRegex {
                            name: name.to_owned(),
                            source,
                        }
                    })?;

                    if !regex.is_match(secret.expose_secret()) {
                        return Err(CredentialStoreError::Validation {
                            name: name.to_owned(),
                            reason: format!("value does not match regex `{pattern}`"),
                        });
                    }
                }
                ValidatorSpec::CurlProbe { url } => {
                    let client = reqwest::blocking::Client::new();
                    let response = client
                        .get(url)
                        .header(
                            reqwest::header::AUTHORIZATION,
                            format!("Bearer {}", secret.expose_secret()),
                        )
                        .send()
                        .map_err(|source| CredentialStoreError::ValidatorProbeRequest {
                            name: name.to_owned(),
                            source,
                        })?;

                    if !response.status().is_success() {
                        return Err(CredentialStoreError::ValidatorProbeStatus {
                            name: name.to_owned(),
                            status: response.status(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn read_from_file(&self, name: &str) -> Result<Option<SecretString>> {
        let store = self.read_file_store()?;
        Ok(store.values.get(name).cloned().map(SecretString::new))
    }

    fn write_to_file(&mut self, name: &str, value: &SecretString) -> Result<()> {
        let mut store = self.read_file_store()?;
        store
            .values
            .insert(name.to_owned(), value.expose_secret().to_owned());
        self.write_file_store(&store)
    }

    fn remove_from_file(&mut self, name: &str) -> Result<bool> {
        let credentials_path = self.config.credentials_path();
        if !credentials_path.exists() {
            return Ok(false);
        }

        let mut store = self.read_file_store()?;
        let removed = store.values.remove(name).is_some();
        if removed {
            self.write_file_store(&store)?;
        }
        Ok(removed)
    }

    fn read_file_store(&self) -> Result<FileCredentials> {
        read_json(&self.config.credentials_path())
    }

    fn write_file_store(&self, store: &FileCredentials) -> Result<()> {
        write_json(&self.config.credentials_path(), store)
    }

    fn read_index(&self) -> Result<CredentialIndex> {
        read_json(&self.config.index_path())
    }

    fn write_index(&self, index: &CredentialIndex) -> Result<()> {
        write_json(&self.config.index_path(), index)
    }

    fn set_index_location(&mut self, name: &str, location: CredentialBackend) -> Result<()> {
        let mut index = self.read_index()?;
        index.locations.insert(name.to_owned(), location);
        self.write_index(&index)
    }

    fn remove_index_location(&mut self, name: &str) -> Result<()> {
        let mut index = self.read_index()?;
        index.locations.remove(name);
        self.write_index(&index)
    }

    fn indexed_backend(&self, name: &str) -> Result<Option<CredentialBackend>> {
        let index = self.read_index()?;
        Ok(index.locations.get(name).copied())
    }
}

fn disable_keyring_from_env() -> bool {
    match std::env::var("AGENTENV_DISABLE_KEYRING") {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => false,
    }
}

fn ensure_store_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| CredentialStoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_json<T>(path: &Path) -> Result<T>
where
    T: Default + for<'de> Deserialize<'de>,
{
    if !path.exists() {
        return Ok(T::default());
    }
    let content = fs::read_to_string(path).map_err(|source| CredentialStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&content).map_err(|source| CredentialStoreError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn write_json<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    let serialized =
        serde_json::to_string_pretty(value).map_err(|source| CredentialStoreError::Json {
            path: path.to_path_buf(),
            source,
        })?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_store_dir(parent)?;

    let tmp_path = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(&tmp_path)
        .map_err(|source| CredentialStoreError::Io {
            path: tmp_path.clone(),
            source,
        })?;
    file.write_all(serialized.as_bytes())
        .map_err(|source| CredentialStoreError::Io {
            path: tmp_path.clone(),
            source,
        })?;
    file.flush().map_err(|source| CredentialStoreError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    fs::rename(&tmp_path, path).map_err(|source| CredentialStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            CredentialStoreError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }

    Ok(())
}

fn collect_permission_warnings(path: &Path) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if path.exists() {
            let metadata = fs::metadata(path).map_err(|source| CredentialStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                warnings.push(format!(
                    "credential fallback file `{}` is too permissive (mode {:o}); expected 600",
                    path.display(),
                    mode & 0o777
                ));
            }
        }
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use agentenv_proto::{CredentialKind, CredentialRequirement};
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Default)]
    struct MockKeyringState {
        values: BTreeMap<String, String>,
        fail_reads: bool,
        fail_writes: bool,
        fail_removals: bool,
    }

    #[derive(Clone, Default)]
    struct MockKeyring {
        state: Arc<Mutex<MockKeyringState>>,
    }

    impl MockKeyring {
        fn insert(&self, name: &str, value: &str) {
            let mut state = self.state.lock().expect("lock state");
            state.values.insert(name.to_owned(), value.to_owned());
        }

        fn remove_value(&self, name: &str) {
            let mut state = self.state.lock().expect("lock state");
            state.values.remove(name);
        }
    }

    impl KeyringClient for MockKeyring {
        fn get(&self, name: &str) -> std::result::Result<Option<SecretString>, KeyringClientError> {
            let state = self.state.lock().expect("lock state");
            if state.fail_reads {
                return Err(KeyringClientError::Other("read failure".to_owned()));
            }
            Ok(state.values.get(name).cloned().map(SecretString::new))
        }

        fn set(
            &self,
            name: &str,
            value: &SecretString,
        ) -> std::result::Result<(), KeyringClientError> {
            let mut state = self.state.lock().expect("lock state");
            if state.fail_writes {
                return Err(KeyringClientError::Other("write failure".to_owned()));
            }
            state
                .values
                .insert(name.to_owned(), value.expose_secret().to_owned());
            Ok(())
        }

        fn remove(&self, name: &str) -> std::result::Result<(), KeyringClientError> {
            let mut state = self.state.lock().expect("lock state");
            if state.fail_removals {
                return Err(KeyringClientError::Other("remove failure".to_owned()));
            }
            state.values.remove(name);
            Ok(())
        }
    }

    fn requirement(name: &str) -> CredentialRequirement {
        CredentialRequirement {
            name: name.to_owned(),
            kind: CredentialKind::ApiKey,
            required: true,
            description: "required for tests".to_owned(),
            validator: None,
        }
    }

    fn test_store(mock_keyring: MockKeyring, dir: &TempDir) -> CredentialStore {
        let config = CredentialStoreConfig::from_root_dir(dir.path());
        CredentialStore::new_with_keyring(config, Box::new(mock_keyring))
            .expect("create credential store")
    }

    #[test]
    fn secret_string_redacts_debug_and_display() {
        let secret = SecretString::new("very-secret");
        let debug_repr = format!("{secret:?}");
        let display_repr = format!("{secret}");

        assert!(debug_repr.contains("REDACTED"));
        assert!(!debug_repr.contains("very-secret"));
        assert_eq!(display_repr, "[REDACTED]");
    }

    #[test]
    fn resolve_uses_keyring_then_file_then_env() {
        let env_lock = ENV_LOCK.lock().expect("env lock");
        let env_key = "AGENTENV_TEST_RESOLVE_KEY";
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        keyring.insert(env_key, "keyring-value");

        let mut store = test_store(keyring.clone(), &temp_dir);
        store
            .write_to_file(env_key, &SecretString::new("file-value"))
            .expect("write file value");
        std::env::set_var(env_key, "env-value");

        let resolved = store
            .resolve(env_key, &requirement(env_key))
            .expect("resolve value");
        assert_eq!(resolved.expose_secret(), "keyring-value");

        keyring.remove_value(env_key);
        let resolved = store
            .resolve(env_key, &requirement(env_key))
            .expect("resolve value");
        assert_eq!(resolved.expose_secret(), "file-value");

        let removed_from_file = store.remove_from_file(env_key).expect("remove file value");
        assert!(removed_from_file);
        let resolved = store
            .resolve(env_key, &requirement(env_key))
            .expect("resolve value");
        assert_eq!(resolved.expose_secret(), "env-value");

        std::env::remove_var(env_key);
        drop(env_lock);
    }

    #[test]
    fn store_falls_back_to_file_when_keyring_write_fails() {
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        keyring.state.lock().expect("lock").fail_writes = true;

        let mut store = test_store(keyring, &temp_dir);
        store
            .store("AGENTENV_TEST_KEY", &SecretString::new("from-file"))
            .expect("store credential");

        let backend = store.where_is("AGENTENV_TEST_KEY").expect("where");
        assert_eq!(backend, Some(CredentialBackend::File));
    }

    #[test]
    fn successful_keyring_store_clears_existing_file_fallback_copy() {
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        keyring.state.lock().expect("lock").fail_writes = true;
        let mut store = test_store(keyring.clone(), &temp_dir);
        let credential_name = "AGENTENV_TEST_KEY";

        store
            .store(credential_name, &SecretString::new("file-value"))
            .expect("store with keyring failure");
        assert_eq!(
            store.where_is(credential_name).expect("where"),
            Some(CredentialBackend::File)
        );

        keyring.state.lock().expect("lock").fail_writes = false;
        store
            .store(credential_name, &SecretString::new("keyring-value"))
            .expect("store with keyring success");

        let file_store = store.read_file_store().expect("read file store");
        assert!(!file_store.values.contains_key(credential_name));
        assert_eq!(
            store.where_is(credential_name).expect("where"),
            Some(CredentialBackend::Keyring)
        );
    }

    #[test]
    fn remove_returns_error_when_keyring_delete_fails() {
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        keyring.state.lock().expect("lock").fail_removals = true;
        let mut store = test_store(keyring, &temp_dir);

        let error = store
            .remove("AGENTENV_TEST_KEY")
            .expect_err("expected keyring removal failure");

        match error {
            CredentialStoreError::Keyring { name, .. } => assert_eq!(name, "AGENTENV_TEST_KEY"),
            other => panic!("expected keyring error, got {other:?}"),
        }
    }

    #[test]
    fn remove_succeeds_for_file_backend_when_keyring_delete_fails() {
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        keyring.state.lock().expect("lock").fail_writes = true;
        let mut store = test_store(keyring.clone(), &temp_dir);
        let credential_name = "AGENTENV_TEST_FILE_BACKEND";

        store
            .store(credential_name, &SecretString::new("file-value"))
            .expect("store in file backend");
        keyring.state.lock().expect("lock").fail_removals = true;

        store
            .remove(credential_name)
            .expect("remove should succeed for file backend");

        assert_eq!(store.where_is(credential_name).expect("where"), None);
        assert!(store.list().expect("list").is_empty());
    }

    #[test]
    fn remove_keeps_index_when_keyring_delete_fails_for_keyring_backend() {
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        let mut store = test_store(keyring.clone(), &temp_dir);
        let credential_name = "AGENTENV_TEST_KEYRING_BACKEND";

        store
            .store(credential_name, &SecretString::new("keyring-value"))
            .expect("store in keyring backend");
        keyring.state.lock().expect("lock").fail_removals = true;

        let error = store
            .remove(credential_name)
            .expect_err("expected keyring removal failure");
        match error {
            CredentialStoreError::Keyring { name, .. } => assert_eq!(name, credential_name),
            other => panic!("expected keyring error, got {other:?}"),
        }

        assert_eq!(
            store.where_is(credential_name).expect("where"),
            Some(CredentialBackend::Keyring)
        );
        assert!(store
            .list()
            .expect("list")
            .contains(&credential_name.to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn writes_json_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        keyring.state.lock().expect("lock").fail_writes = true;
        let mut store = test_store(keyring, &temp_dir);

        store
            .store("AGENTENV_TEST_KEY", &SecretString::new("from-file"))
            .expect("store credential");

        let metadata = fs::metadata(store.credentials_path()).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn warns_when_json_file_is_too_permissive() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().expect("tempdir");
        let credentials_path = temp_dir.path().join(CREDENTIALS_FILE);
        fs::write(&credentials_path, "{}").expect("write credentials file");
        fs::set_permissions(&credentials_path, fs::Permissions::from_mode(0o644))
            .expect("set permissions");

        let store = test_store(MockKeyring::default(), &temp_dir);
        assert_eq!(store.startup_warnings().len(), 1);
        assert!(store.startup_warnings()[0].contains("too permissive"));
    }

    #[test]
    fn regex_validator_rejects_non_matching_value() {
        let temp_dir = TempDir::new().expect("tempdir");
        let keyring = MockKeyring::default();
        let mut store = test_store(keyring, &temp_dir);
        store
            .write_to_file("ANTHROPIC_API_KEY", &SecretString::new("wrong-prefix"))
            .expect("write credential");

        let requirement = CredentialRequirement {
            name: "ANTHROPIC_API_KEY".to_owned(),
            kind: CredentialKind::ApiKey,
            required: true,
            description: "must use sk-ant- prefix".to_owned(),
            validator: Some(ValidatorSpec::Regex {
                pattern: "^sk-ant-".to_owned(),
            }),
        };

        let error = store
            .resolve("ANTHROPIC_API_KEY", &requirement)
            .expect_err("expected regex validation to fail");
        match error {
            CredentialStoreError::Validation { .. } => {}
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn env_only_values_are_not_persisted() {
        let env_lock = ENV_LOCK.lock().expect("env lock");
        let key = "AGENTENV_TEST_ENV_ONLY";
        std::env::set_var(key, "env-only-value");
        let store = test_store(MockKeyring::default(), &TempDir::new().expect("tempdir"));

        let resolved = store.resolve(key, &requirement(key)).expect("resolve");
        let listed = store.list().expect("list");

        assert_eq!(resolved.expose_secret(), "env-only-value");
        assert!(listed.is_empty());

        std::env::remove_var(key);
        drop(env_lock);
    }

    #[test]
    fn list_returns_names_only_never_values() {
        let temp_dir = TempDir::new().expect("tempdir");
        let mut store = test_store(MockKeyring::default(), &temp_dir);
        let credential_name = "AGENTENV_TEST_NAME_ONLY";
        let secret_value = "do-not-print-me";

        store
            .write_to_file(credential_name, &SecretString::new(secret_value))
            .expect("write file value");

        let names = store.list().expect("list credentials");

        assert_eq!(names, vec![credential_name.to_owned()]);
        assert!(!format!("{names:?}").contains(secret_value));
    }
}
