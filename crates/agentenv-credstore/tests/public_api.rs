use agentenv_credstore::{CredentialStore, CredentialStoreConfig, SecretString};

#[test]
fn public_api_exposes_store_and_secret_types() {
    let secret = SecretString::new("value");
    assert_eq!(secret.expose_secret(), "value");

    let config = CredentialStoreConfig::from_root_dir("/tmp/agentenv-credstore-api");
    let _store = CredentialStore::new(config).expect("create credential store");
}
