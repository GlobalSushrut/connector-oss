//! Ed25519 signing helpers for IIA court-tier artifacts.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use super::SigningTierV2;

/// Canonical digest over JSON-serializable value (sorted keys via serde_json).
pub fn canonical_digest_json<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Sign canonical JSON digest with Ed25519 (court tier).
pub fn sign_json_ed25519<T: serde::Serialize>(
    signing_key: &SigningKey,
    value: &T,
) -> Result<SignedPayloadV2, serde_json::Error> {
    let digest = canonical_digest_json(value)?;
    let sig = signing_key.sign(digest.as_bytes());
    Ok(SignedPayloadV2 {
        content_digest_sha256: digest,
        signature_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.to_bytes(),
        ),
        public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        signing_tier: SigningTierV2::Ed25519Court,
    })
}

/// Verify Ed25519 signature over canonical JSON digest.
pub fn verify_json_ed25519<T: serde::Serialize>(
    verifying_key: &VerifyingKey,
    value: &T,
    signature_b64: &str,
) -> Result<bool, serde_json::Error> {
    let digest = canonical_digest_json(value)?;
    let sig_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signature_b64,
    ) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    if sig_bytes.len() != 64 {
        return Ok(false);
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    Ok(verifying_key
        .verify(digest.as_bytes(), &sig)
        .is_ok())
}

/// Verify a [`SignedPayloadV2`] against the unsigned body it claims to cover.
///
/// Checks: digest matches canonical JSON of `value`, tier is court, Ed25519 verifies.
pub fn verify_signed_payload_v2<T: serde::Serialize>(
    value: &T,
    payload: &SignedPayloadV2,
) -> bool {
    if payload.signing_tier != SigningTierV2::Ed25519Court {
        return false;
    }
    let Ok(digest) = canonical_digest_json(value) else {
        return false;
    };
    if digest != payload.content_digest_sha256 {
        return false;
    }
    let Ok(pk_bytes) = hex::decode(&payload.public_key_hex) else {
        return false;
    };
    if pk_bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_bytes);
    let Ok(vk) = VerifyingKey::from_bytes(&arr) else {
        return false;
    };
    verify_json_ed25519(&vk, value, &payload.signature_b64).unwrap_or(false)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SignedPayloadV2 {
    pub content_digest_sha256: String,
    pub signature_b64: String,
    pub public_key_hex: String,
    pub signing_tier: SigningTierV2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let doc = serde_json::json!({"a": 1, "b": "two"});
        let signed = sign_json_ed25519(&sk, &doc).unwrap();
        assert!(verify_json_ed25519(&vk, &doc, &signed.signature_b64).unwrap());
    }
}
