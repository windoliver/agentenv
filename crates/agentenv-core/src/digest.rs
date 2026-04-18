use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DigestError {
    #[error("digest must start with `sha256:`")]
    InvalidPrefix,
    #[error("sha256 digest must contain exactly 64 lowercase hexadecimal characters")]
    InvalidDigestFormat,
    #[error("sha256 hex must contain exactly 64 lowercase hexadecimal characters")]
    InvalidHexFormat,
}

pub fn parse_sha256_digest(value: &str) -> Result<[u8; 32], DigestError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(DigestError::InvalidPrefix)?;
    parse_lower_hex(hex, DigestError::InvalidDigestFormat)
}

pub fn parse_sha256_hex(value: &str) -> Result<[u8; 32], DigestError> {
    parse_lower_hex(value, DigestError::InvalidHexFormat)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn parse_lower_hex(value: &str, error: DigestError) -> Result<[u8; 32], DigestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error);
    }

    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| error)?;
    Ok(bytes)
}
