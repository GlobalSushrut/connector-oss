//! Signing and verification

use ed25519_dalek::{Signature, Signer, Verifier};

use vac_core::{VacError, VacResult};

use crate::keys::{verifying_key_from_did, KeyPair};

/// Sign a message
pub fn sign(keypair: &KeyPair, message: &[u8]) -> [u8; 64] {
    let signature = keypair.signing_key().sign(message);
    signature.to_bytes()
}

/// Verify a signature
pub fn verify(did: &str, message: &[u8], signature: &[u8; 64]) -> VacResult<bool> {
    let verifying_key = verifying_key_from_did(did)?;
    let sig = Signature::from_bytes(signature);
    
    Ok(verifying_key.verify(message, &sig).is_ok())
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
}
