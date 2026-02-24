//! Signing and verification

use ed25519_dalek::{Signature, Signer, Verifier};

use vac_core::{VacError, VacResult};

use crate::keys::{verifying_key_from_did, KeyPair};

/// Sign a message
pub fn sign(keypair: &KeyPair, message: &[u8]) -> [u8; 64] {
    let signature = keypair.signing_key().sign(message);
    signature.to_bytes()
}

/// Verify a signature using strict validation.
///
/// Uses `verify_strict()` which:
/// - Rejects non-canonical S values (S >= L) to prevent signature malleability
/// - Rejects small-order public keys (torsion points) to prevent trivial forgery
/// - Uses cofactorless verification to avoid cofactor-8 equivalence attacks
pub fn verify(did: &str, message: &[u8], signature: &[u8; 64]) -> VacResult<bool> {
    let verifying_key = verifying_key_from_did(did)?;
    let sig = Signature::from_bytes(signature);
    
    Ok(verifying_key.verify_strict(message, &sig).is_ok())
}

/// Sign a block (convenience function)
pub fn sign_block(keypair: &KeyPair, block_data: &[u8]) -> vac_core::Signature {
    let sig_bytes = sign(keypair, block_data);
    vac_core::Signature {
        public_key: keypair.did_key(),
        signature: sig_bytes.to_vec(),
    }
}

/// Verify a block signature
pub fn verify_block_signature(
    signature: &vac_core::Signature,
    block_data: &[u8],
) -> VacResult<bool> {
    if signature.signature.len() != 64 {
        return Err(VacError::InvalidHash {
            expected: 64,
            actual: signature.signature.len(),
        });
    }
    
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature.signature);
    
    verify(&signature.public_key, block_data, &sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sign_and_verify() {
        let kp = KeyPair::generate();
        let message = b"hello world";
        
        let signature = sign(&kp, message);
        let valid = verify(&kp.did_key(), message, &signature).unwrap();
        
        assert!(valid);
    }
    
    #[test]
    fn test_invalid_signature() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let message = b"hello world";
        
        let signature = sign(&kp1, message);
        let valid = verify(&kp2.did_key(), message, &signature).unwrap();
        
        assert!(!valid);
    }
    
    #[test]
    fn test_tampered_message() {
        let kp = KeyPair::generate();
        let message = b"hello world";
        let tampered = b"hello worlD";
        
        let signature = sign(&kp, message);
        let valid = verify(&kp.did_key(), tampered, &signature).unwrap();
        
        assert!(!valid);
    }
    
    #[test]
    fn test_sign_block() {
        let kp = KeyPair::generate();
        let block_data = b"block content";
        
        let sig = sign_block(&kp, block_data);
        
        assert!(sig.public_key.starts_with("did:key:z"));
        assert_eq!(sig.signature.len(), 64);
        
        let valid = verify_block_signature(&sig, block_data).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_c2_verify_strict_rejects_malleable_signature() {
        // C2: verify_strict rejects signatures where S >= L (curve order).
        // ed25519-dalek's SigningKey.sign() always produces canonical S,
        // so we verify that a manually crafted non-canonical S is rejected.

        let kp = KeyPair::generate();
        let message = b"test malleability";
        let sig_bytes = sign(&kp, message);

        // The canonical signature should verify
        assert!(verify(&kp.did_key(), message, &sig_bytes).unwrap());

        // Flip the high bit of S (byte 63) to create a non-canonical S value.
        // This makes S >= L in most cases, which verify_strict should reject.
        let mut malleable = sig_bytes;
        malleable[63] ^= 0x80;

        let result = verify(&kp.did_key(), message, &malleable).unwrap();
        // verify_strict should reject this (non-canonical S)
        assert!(!result, "verify_strict must reject non-canonical S values");
    }

    #[test]
    fn test_h2_domain_separated_prolly_hash() {
        // H2: Prolly node hash uses domain prefix "vac.prolly.v1"
        // so it cannot collide with raw sha256 of the same data.
        // Domain-separated hash must differ from raw hash of the same data.
        // We test this by computing sha256_domain vs sha256 on the same input.
        use vac_core::cid::{sha256, sha256_domain};

        let data = b"test_prolly_node_data";
        let raw_hash = sha256(data);
        let domain_hash = sha256_domain(b"vac.prolly.v1", data);

        assert_ne!(domain_hash, raw_hash, "Domain-separated hash must differ from raw hash");
    }
}
