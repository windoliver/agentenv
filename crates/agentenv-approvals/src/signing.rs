use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadSignature(String);

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid HMAC signing key length")]
    InvalidKeyLength,
}

impl PayloadSignature {
    pub fn header_value(&self) -> &str {
        &self.0
    }
}

pub fn sign_payload(
    secret: &str,
    timestamp: i64,
    delivery_id: &str,
    body: &[u8],
) -> PayloadSignature {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    update_mac(&mut mac, timestamp, delivery_id, body);
    let bytes = mac.finalize().into_bytes();

    PayloadSignature(format!("sha256={}", hex::encode(bytes)))
}

pub fn verify_payload(
    secret: &str,
    timestamp: i64,
    delivery_id: &str,
    body: &[u8],
    header: &str,
) -> Result<bool, SigningError> {
    let Some(signature_hex) = header.strip_prefix("sha256=") else {
        return Ok(false);
    };
    let Ok(signature) = hex::decode(signature_hex) else {
        return Ok(false);
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| SigningError::InvalidKeyLength)?;
    update_mac(&mut mac, timestamp, delivery_id, body);

    Ok(mac.verify_slice(&signature).is_ok())
}

fn update_mac(mac: &mut HmacSha256, timestamp: i64, delivery_id: &str, body: &[u8]) {
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(delivery_id.as_bytes());
    mac.update(b".");
    mac.update(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_signature_is_stable() {
        let signature = sign_payload(
            "secret",
            1_777_443_200,
            "delivery-1",
            br#"{"request_id":"req-1"}"#,
        );
        assert_eq!(
            signature.header_value(),
            "sha256=a87d47cfe4a090cce038569efdf547891d2e124c705978e01a6209ad40130a29"
        );
    }

    #[test]
    fn verifies_matching_signature_and_rejects_wrong_signature() {
        let body = br#"{"request_id":"req-1"}"#;
        let signature = sign_payload("secret", 1_777_443_200, "delivery-1", body);

        assert!(verify_payload(
            "secret",
            1_777_443_200,
            "delivery-1",
            body,
            signature.header_value()
        )
        .unwrap());
        assert!(
            !verify_payload("secret", 1_777_443_200, "delivery-1", body, "sha256=bad").unwrap()
        );
    }
}
