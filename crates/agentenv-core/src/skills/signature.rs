use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use serde_yaml::Value;

use super::{SkillError, SkillManifest};

const SIGNATURE_PAYLOAD_HEADER: &[u8] = b"agentenv-skill-signature-v1\n";

#[derive(Serialize)]
struct SignedManifest<'a> {
    name: &'a str,
    version: String,
    description: &'a Option<String>,
    entry: String,
    files: Vec<String>,
    self_test_command: &'a Option<String>,
    extra: BTreeMap<&'a str, &'a Value>,
}

pub fn signature_payload(manifest: &SkillManifest, digest: &str) -> Result<Vec<u8>, SkillError> {
    let normalized = SignedManifest {
        name: &manifest.name,
        version: manifest.version.to_string(),
        description: &manifest.description,
        entry: manifest.entry.to_string_lossy().replace('\\', "/"),
        files: manifest
            .declared_files
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect(),
        self_test_command: &manifest.self_test_command,
        extra: signed_extra(&manifest.extra),
    };

    let json = serde_json::to_vec(&normalized).map_err(|source| SkillError::InvalidSignature {
        name: manifest.name.clone(),
        version: manifest.version.to_string(),
        message: source.to_string(),
    })?;

    let mut payload = SIGNATURE_PAYLOAD_HEADER.to_vec();
    payload.extend(json);
    payload.push(b'\n');
    payload.extend(digest.as_bytes());
    Ok(payload)
}

pub fn verify_ed25519_signature(
    manifest: &SkillManifest,
    digest: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), SkillError> {
    let public_key_bytes =
        hex::decode(public_key_hex).map_err(|source| invalid_signature(manifest, source))?;
    let signature_bytes =
        hex::decode(signature_hex).map_err(|source| invalid_signature(manifest, source))?;

    let public_key_array: [u8; 32] =
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SkillError::InvalidSignature {
                name: manifest.name.clone(),
                version: manifest.version.to_string(),
                message: "public key must be 32 bytes".to_owned(),
            })?;
    let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|source| {
        SkillError::InvalidSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            message: source.to_string(),
        }
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|source| {
        SkillError::InvalidSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            message: source.to_string(),
        }
    })?;
    let payload = signature_payload(manifest, digest)?;

    verifying_key
        .verify(&payload, &signature)
        .map_err(|source| SkillError::InvalidSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
            message: source.to_string(),
        })
}

pub(crate) fn verify_skill_package_signature(
    manifest: &SkillManifest,
    digest: &str,
    allow_unsigned: bool,
) -> Result<Option<String>, SkillError> {
    if allow_unsigned {
        return Ok(None);
    }

    let signature =
        manifest
            .signature_ed25519
            .as_deref()
            .ok_or_else(|| SkillError::MissingSignature {
                name: manifest.name.clone(),
                version: manifest.version.to_string(),
            })?;
    let public_key = manifest
        .signature_public_key_ed25519
        .as_deref()
        .ok_or_else(|| SkillError::MissingSignature {
            name: manifest.name.clone(),
            version: manifest.version.to_string(),
        })?;

    verify_ed25519_signature(manifest, digest, signature, public_key)?;
    Ok(Some(public_key.to_owned()))
}

fn invalid_signature(manifest: &SkillManifest, source: impl std::fmt::Display) -> SkillError {
    SkillError::InvalidSignature {
        name: manifest.name.clone(),
        version: manifest.version.to_string(),
        message: source.to_string(),
    }
}

fn signed_extra(extra: &BTreeMap<String, Value>) -> BTreeMap<&str, &Value> {
    extra
        .iter()
        .filter_map(|(key, value)| {
            if is_signature_extra_key(key) {
                None
            } else {
                Some((key.as_str(), value))
            }
        })
        .collect()
}

fn is_signature_extra_key(key: &str) -> bool {
    matches!(
        key,
        "ed25519_public_key" | "public_key_ed25519" | "signature_public_key_ed25519"
    )
}
