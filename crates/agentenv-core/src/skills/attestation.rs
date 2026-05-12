use std::{fs, io::Write, path::Path};

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{SkillAssertionResult, SkillError, SkillSelfTestReport, SELF_TEST_PUBLISH_THRESHOLD};

const SELF_TEST_ATTESTATION_SCHEMA_VERSION: &str = "0.1";
const SELF_TEST_ATTESTATION_PREDICATE_TYPE: &str =
    "https://agentenv.dev/attestations/skill-self-test/v1";
const SELF_TEST_ATTESTATION_PAYLOAD_HEADER: &[u8] = b"agentenv-skill-self-test-attestation-v1\n";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSelfTestAttestation {
    pub schema_version: String,
    pub predicate_type: String,
    pub subject: SkillSelfTestSubject,
    pub self_test_digest: String,
    pub runner: String,
    pub score: f64,
    pub publishable: bool,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
    pub assertions: Vec<SkillAssertionResult>,
    pub signature: SkillSelfTestAttestationSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSelfTestSubject {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSelfTestAttestationSignature {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_ed25519: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct SkillSelfTestSigningKey {
    signing_key: SigningKey,
}

#[derive(Debug, Clone)]
pub struct SkillAttestationValidationOptions {
    pub trusted_public_keys: Vec<String>,
    pub now: OffsetDateTime,
    pub max_age_seconds: u64,
    pub threshold: f64,
}

impl Default for SkillAttestationValidationOptions {
    fn default() -> Self {
        Self {
            trusted_public_keys: Vec::new(),
            now: OffsetDateTime::now_utc(),
            max_age_seconds: 86_400,
            threshold: SELF_TEST_PUBLISH_THRESHOLD,
        }
    }
}

impl SkillSelfTestSigningKey {
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn load_or_create(path: &Path) -> Result<Self, SkillError> {
        #[cfg(unix)]
        match fs::symlink_metadata(path) {
            Ok(_) => {
                ensure_unix_key_file_hygiene(path)?;
                return read_existing_key(path);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SkillError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }

        #[cfg(not(unix))]
        {
            if path.exists() {
                return read_existing_key(path);
            }
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| SkillError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let mut secret = [0_u8; 32];
        OsRng.fill_bytes(&mut secret);
        write_new_key_file(path, &secret)?;
        Ok(Self::from_secret_bytes(secret))
    }
}

fn read_existing_key(path: &Path) -> Result<SkillSelfTestSigningKey, SkillError> {
    let bytes = fs::read(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let secret = secret_bytes_from_slice(path, &bytes)?;
    Ok(SkillSelfTestSigningKey::from_secret_bytes(secret))
}

pub fn sign_skill_self_test_attestation(
    report: &SkillSelfTestReport,
    key: &SkillSelfTestSigningKey,
) -> Result<SkillSelfTestAttestation, SkillError> {
    let public_key = key.public_key_hex();
    let mut attestation = SkillSelfTestAttestation {
        schema_version: SELF_TEST_ATTESTATION_SCHEMA_VERSION.to_owned(),
        predicate_type: SELF_TEST_ATTESTATION_PREDICATE_TYPE.to_owned(),
        subject: SkillSelfTestSubject {
            name: report.name.clone(),
            version: report.version.clone(),
            digest: report.digest.clone(),
        },
        self_test_digest: report.self_test_digest.clone(),
        runner: "agentenv".to_owned(),
        score: report.score,
        publishable: report.publishable,
        started_at: report.started_at,
        completed_at: report.completed_at,
        assertions: report.assertions.clone(),
        signature: SkillSelfTestAttestationSignature {
            key_id: "local-agentenv".to_owned(),
            algorithm: "ed25519".to_owned(),
            public_key_ed25519: public_key,
            value: String::new(),
        },
    };
    let payload = attestation_payload(&attestation)?;
    let signature = key.signing_key.sign(&payload);
    attestation.signature.value = hex::encode(signature.to_bytes());
    Ok(attestation)
}

pub fn validate_skill_publish_attestation(
    name: &str,
    version: &str,
    digest: &str,
    self_test_digest: &str,
    attestation: &SkillSelfTestAttestation,
    options: SkillAttestationValidationOptions,
) -> Result<(), SkillError> {
    if attestation.schema_version != SELF_TEST_ATTESTATION_SCHEMA_VERSION {
        return Err(invalid_attestation(format!(
            "unsupported schema version `{}`",
            attestation.schema_version
        )));
    }
    if attestation.predicate_type != SELF_TEST_ATTESTATION_PREDICATE_TYPE {
        return Err(invalid_attestation(format!(
            "unsupported predicate type `{}`",
            attestation.predicate_type
        )));
    }
    if attestation.subject.name != name
        || attestation.subject.version != version
        || attestation.subject.digest != digest
    {
        return Err(SkillError::SelfTestAttestationSubjectMismatch);
    }
    if attestation.self_test_digest != self_test_digest {
        return Err(SkillError::SelfTestAttestationDigestMismatch);
    }
    validate_attestation_fields(attestation, &options)?;
    if attestation.score < options.threshold || !attestation.publishable {
        return Err(SkillError::SelfTestScoreBelowThreshold {
            score: attestation.score,
            threshold: options.threshold,
        });
    }
    validate_attestation_recency(attestation.completed_at, &options)?;
    verify_attestation_signature(attestation, &options)
}

fn attestation_payload(attestation: &SkillSelfTestAttestation) -> Result<Vec<u8>, SkillError> {
    #[derive(Serialize)]
    struct SignaturePayload<'a> {
        key_id: &'a str,
        algorithm: &'a str,
        public_key_ed25519: &'a str,
    }

    #[derive(Serialize)]
    struct CanonicalAttestationPayload<'a> {
        schema_version: &'a str,
        predicate_type: &'a str,
        subject: &'a SkillSelfTestSubject,
        self_test_digest: &'a str,
        runner: &'a str,
        score: f64,
        publishable: bool,
        started_at: OffsetDateTime,
        completed_at: OffsetDateTime,
        assertions: &'a [SkillAssertionResult],
        signature: SignaturePayload<'a>,
    }

    let normalized = CanonicalAttestationPayload {
        schema_version: &attestation.schema_version,
        predicate_type: &attestation.predicate_type,
        subject: &attestation.subject,
        self_test_digest: &attestation.self_test_digest,
        runner: &attestation.runner,
        score: attestation.score,
        publishable: attestation.publishable,
        started_at: attestation.started_at,
        completed_at: attestation.completed_at,
        assertions: &attestation.assertions,
        signature: SignaturePayload {
            key_id: &attestation.signature.key_id,
            algorithm: &attestation.signature.algorithm,
            public_key_ed25519: &attestation.signature.public_key_ed25519,
        },
    };
    let json = serde_json::to_vec(&normalized).map_err(|source| {
        invalid_attestation(format!("failed to serialize canonical payload: {source}"))
    })?;

    let mut payload = SELF_TEST_ATTESTATION_PAYLOAD_HEADER.to_vec();
    payload.extend(json);
    Ok(payload)
}

fn verify_attestation_signature(
    attestation: &SkillSelfTestAttestation,
    options: &SkillAttestationValidationOptions,
) -> Result<(), SkillError> {
    if attestation.signature.algorithm != "ed25519" {
        return Err(invalid_attestation(format!(
            "unsupported signature algorithm `{}`",
            attestation.signature.algorithm
        )));
    }
    if !options
        .trusted_public_keys
        .iter()
        .any(|trusted| trusted == &attestation.signature.public_key_ed25519)
    {
        return Err(invalid_attestation(
            "self-test attestation public key is not trusted",
        ));
    }

    let public_key_bytes = decode_hex_exact(
        "public key",
        &attestation.signature.public_key_ed25519,
        PUBLIC_KEY_LENGTH,
    )?;
    let signature_bytes =
        decode_hex_exact("signature", &attestation.signature.value, SIGNATURE_LENGTH)?;
    let public_key = public_key_from_bytes(&public_key_bytes)?;
    let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|source| {
        invalid_attestation(format!("invalid self-test attestation signature: {source}"))
    })?;
    let payload = attestation_payload(attestation)?;

    public_key
        .verify(&payload, &signature)
        .map_err(|source| invalid_attestation(format!("signature verification failed: {source}")))
}

fn validate_attestation_fields(
    attestation: &SkillSelfTestAttestation,
    options: &SkillAttestationValidationOptions,
) -> Result<(), SkillError> {
    if attestation.runner != "agentenv" {
        return Err(invalid_attestation(format!(
            "unsupported self-test runner `{}`",
            attestation.runner
        )));
    }
    if !attestation.score.is_finite() || !(0.0..=1.0).contains(&attestation.score) {
        return Err(invalid_attestation(
            "self-test score must be between 0.0 and 1.0",
        ));
    }
    if !options.threshold.is_finite() || !(0.0..=1.0).contains(&options.threshold) {
        return Err(invalid_attestation(
            "self-test attestation threshold must be between 0.0 and 1.0",
        ));
    }
    if attestation.started_at > attestation.completed_at {
        return Err(invalid_attestation(
            "self-test attestation started_at is after completed_at",
        ));
    }
    Ok(())
}

fn validate_attestation_recency(
    completed_at: OffsetDateTime,
    options: &SkillAttestationValidationOptions,
) -> Result<(), SkillError> {
    let age = options.now - completed_at;
    let max_age_seconds = i64::try_from(options.max_age_seconds).unwrap_or(i64::MAX);
    if age.is_negative() || age.whole_seconds() > max_age_seconds {
        return Err(SkillError::StaleSelfTestAttestation {
            completed_at: completed_at
                .format(&Rfc3339)
                .unwrap_or_else(|_| completed_at.to_string()),
        });
    }
    Ok(())
}

fn decode_hex_exact(label: &str, value: &str, expected_len: usize) -> Result<Vec<u8>, SkillError> {
    let bytes = hex::decode(value)
        .map_err(|source| invalid_attestation(format!("invalid {label} hex: {source}")))?;
    if bytes.len() != expected_len {
        return Err(invalid_attestation(format!(
            "{label} must be {expected_len} bytes"
        )));
    }
    Ok(bytes)
}

fn public_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, SkillError> {
    let public_key: [u8; PUBLIC_KEY_LENGTH] = bytes.try_into().map_err(|_| {
        invalid_attestation(format!("public key must be {PUBLIC_KEY_LENGTH} bytes"))
    })?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|source| invalid_attestation(format!("invalid public key: {source}")))
}

fn secret_bytes_from_slice(path: &Path, bytes: &[u8]) -> Result<[u8; 32], SkillError> {
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SkillError::InvalidSelfTestSigningKey {
            path: path.to_path_buf(),
        })?;
    Ok(secret)
}

#[cfg(unix)]
fn ensure_unix_key_file_hygiene(path: &Path) -> Result<(), SkillError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(SkillError::InvalidSelfTestSigningKey {
            path: path.to_path_buf(),
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SkillError::InvalidSelfTestSigningKey {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn write_new_key_file(path: &Path, secret: &[u8; 32]) -> Result<(), SkillError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| SkillError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(secret).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_new_key_file(path: &Path, secret: &[u8; 32]) -> Result<(), SkillError> {
    fs::write(path, secret).map_err(|source| SkillError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn invalid_attestation(message: impl Into<String>) -> SkillError {
    SkillError::InvalidSelfTestAttestation {
        message: message.into(),
    }
}
