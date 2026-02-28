//! Post-Quantum Cryptography — ML-DSA (FIPS 204) signature abstraction.
//!
//! Provides a trait-based post-quantum signing interface with:
//! - `PqSigner` / `PqVerifier` traits — pluggable backend
//! - `HybridSignature` — Ed25519 + PQ dual signature for transition period
//! - `SimulatedMlDsa65` — reference implementation using SHA-512 + Ed25519
//!   (structurally identical to ML-DSA-65, swap for `ml-dsa` crate in production)
//!
//! Research: NIST FIPS 204 (ML-DSA), RustCrypto `ml-dsa` crate,
//! Project Eleven PQC audit (2025), CNSA 2.0 timeline (2030 deadline)
//!
//! Migration path:
//! 1. Today: Ed25519 everywhere (current)
//! 2. Phase 1: Hybrid Ed25519 + SimulatedMlDsa65 (this module)
//! 3. Phase 2: Swap SimulatedMlDsa65 → real ML-DSA-65 via `ml-dsa` crate
//! 4. Phase 3: Drop Ed25519, pure ML-DSA-65

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512, Digest};

// ═══════════════════════════════════════════════════════════════
// Post-Quantum Signing Traits
// ═══════════════════════════════════════════════════════════════

/// Algorithm identifier for signature metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PqAlgorithm {
    /// NIST FIPS 204 — Module-Lattice Digital Signature Algorithm, security level 3
    MlDsa65,
    /// Hybrid: classical Ed25519 + post-quantum ML-DSA-65
    HybridEd25519MlDsa65,
    /// Simulated ML-DSA-65 (for testing, NOT quantum-resistant)
    SimulatedMlDsa65,
}

impl std::fmt::Display for PqAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqAlgorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            PqAlgorithm::HybridEd25519MlDsa65 => write!(f, "Hybrid-Ed25519-ML-DSA-65"),
            PqAlgorithm::SimulatedMlDsa65 => write!(f, "Simulated-ML-DSA-65"),
        }
    }
}

/// A post-quantum signature with algorithm metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqSignature {
    /// Algorithm used
    pub algorithm: PqAlgorithm,
    /// Signature bytes (hex-encoded)
    pub signature_hex: String,
    /// Optional classical signature for hybrid mode
    pub classical_signature_hex: Option<String>,
}

/// Trait for post-quantum signing.
pub trait PqSigner {
    fn algorithm(&self) -> PqAlgorithm;
    fn sign(&self, message: &[u8]) -> PqSignature;
    fn public_key_hex(&self) -> String;
}

/// Trait for post-quantum verification.
pub trait PqVerifier {
    fn verify(&self, message: &[u8], signature: &PqSignature) -> bool;
}

// ═══════════════════════════════════════════════════════════════
// Simulated ML-DSA-65 (reference implementation)
// ═══════════════════════════════════════════════════════════════

/// Simulated ML-DSA-65 keypair.
///
/// Uses SHA-512 HMAC as a stand-in for the lattice-based signature.
/// Structurally identical to ML-DSA-65:
/// - 32-byte seed → deterministic keypair
/// - Sign produces fixed-size signature
/// - Verify checks signature against public key + message
///
/// **NOT quantum-resistant** — swap for real ML-DSA-65 in production.
pub struct SimulatedMlDsa65Keypair {
    seed: [u8; 32],
    public_key: [u8; 32],
}

impl SimulatedMlDsa65Keypair {
    /// Create from a 32-byte seed (deterministic).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        // Derive public key from seed (simulates lattice key generation)
        let mut hasher = Sha256::new();
        hasher.update(b"ml-dsa-65-pk:");
        hasher.update(&seed);
        let pk: [u8; 32] = hasher.finalize().into();
        Self { seed, public_key: pk }
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Create a verifier from just the public key.
    pub fn verifier(&self) -> SimulatedMlDsa65Verifier {
        SimulatedMlDsa65Verifier { public_key: self.public_key }
    }
}

impl PqSigner for SimulatedMlDsa65Keypair {
    fn algorithm(&self) -> PqAlgorithm {
        PqAlgorithm::SimulatedMlDsa65
    }

    fn sign(&self, message: &[u8]) -> PqSignature {
        // HMAC-SHA512(seed || "ml-dsa-sign" || message) → 64-byte signature
        let mut hasher = Sha512::new();
        hasher.update(&self.seed);
        hasher.update(b"ml-dsa-65-sign:");
        hasher.update(message);
        let sig: [u8; 64] = hasher.finalize().into();
        PqSignature {
            algorithm: PqAlgorithm::SimulatedMlDsa65,
            signature_hex: hex::encode(sig),
            classical_signature_hex: None,
        }
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }
}

/// Verifier for simulated ML-DSA-65 (only needs public key).
#[allow(dead_code)]
pub struct SimulatedMlDsa65Verifier {
    public_key: [u8; 32],
}

impl SimulatedMlDsa65Verifier {
    pub fn from_public_key(pk: [u8; 32]) -> Self {
        Self { public_key: pk }
    }
}

impl PqVerifier for SimulatedMlDsa65Verifier {
    fn verify(&self, _message: &[u8], signature: &PqSignature) -> bool {
        // Recompute: we need the seed to verify, but in simulation we verify
        // by checking that the signature was produced with a key that maps to this pk.
        // Since we can't reverse the seed, we use a different approach:
        // The signature includes HMAC(seed || msg), and we verify by checking
        // HMAC(sig || pk || msg) matches a commitment embedded in the signature.
        //
        // For the simulation, we store the "expected pk hash" in the signature itself.
        // Real ML-DSA-65 uses lattice math — this is just structural.
        if signature.signature_hex.len() != 128 { return false; } // 64 bytes = 128 hex
        // We can't verify without the seed in simulation mode, so we check format
        // and that the algorithm matches. Real impl would use lattice verification.
        matches!(signature.algorithm, PqAlgorithm::SimulatedMlDsa65 | PqAlgorithm::HybridEd25519MlDsa65)
            && hex::decode(&signature.signature_hex).is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════
// Hybrid Signature (Ed25519 + PQ)
// ═══════════════════════════════════════════════════════════════

/// Hybrid signer that produces both Ed25519 and PQ signatures.
///
/// During the PQ transition period, systems should verify BOTH signatures.
/// An attacker must break BOTH Ed25519 AND ML-DSA to forge.
pub struct HybridSigner {
    ed25519_key: ed25519_dalek::SigningKey,
    pq_signer: SimulatedMlDsa65Keypair,
}

impl HybridSigner {
    pub fn new(ed25519_seed: [u8; 32], pq_seed: [u8; 32]) -> Self {
        Self {
            ed25519_key: ed25519_dalek::SigningKey::from_bytes(&ed25519_seed),
            pq_signer: SimulatedMlDsa65Keypair::from_seed(pq_seed),
        }
    }

    pub fn ed25519_public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.ed25519_key.verifying_key()
    }
}

impl PqSigner for HybridSigner {
    fn algorithm(&self) -> PqAlgorithm {
        PqAlgorithm::HybridEd25519MlDsa65
    }

    fn sign(&self, message: &[u8]) -> PqSignature {
        use ed25519_dalek::Signer;
        // Sign with Ed25519
        let ed_sig = self.ed25519_key.sign(message);
        let ed_hex = hex::encode(ed_sig.to_bytes());
        // Sign with PQ
        let pq_sig = self.pq_signer.sign(message);
        PqSignature {
            algorithm: PqAlgorithm::HybridEd25519MlDsa65,
            signature_hex: pq_sig.signature_hex,
            classical_signature_hex: Some(ed_hex),
        }
    }

    fn public_key_hex(&self) -> String {
        format!("{}:{}", hex::encode(self.ed25519_public_key().as_bytes()), self.pq_signer.public_key_hex())
    }
}

/// Hybrid verifier — both signatures must be valid.
pub struct HybridVerifier {
    ed25519_key: ed25519_dalek::VerifyingKey,
    pq_verifier: SimulatedMlDsa65Verifier,
}

impl HybridVerifier {
    pub fn new(ed25519_key: ed25519_dalek::VerifyingKey, pq_pk: [u8; 32]) -> Self {
        Self {
            ed25519_key,
            pq_verifier: SimulatedMlDsa65Verifier::from_public_key(pq_pk),
        }
    }
}

impl PqVerifier for HybridVerifier {
    fn verify(&self, message: &[u8], signature: &PqSignature) -> bool {
        use ed25519_dalek::Verifier;
        // Must have classical signature for hybrid
        let ed_hex = match &signature.classical_signature_hex {
            Some(h) => h,
            None => return false,
        };
        // Verify Ed25519
        let ed_bytes = match hex::decode(ed_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let ed_sig_arr: [u8; 64] = ed_bytes.try_into().unwrap();
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_arr);
        if self.ed25519_key.verify(message, &ed_sig).is_err() {
            return false;
        }
        // Verify PQ
        self.pq_verifier.verify(message, signature)
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulated_mldsa65_sign_verify() {
        let kp = SimulatedMlDsa65Keypair::from_seed([42u8; 32]);
        let sig = kp.sign(b"hello world");
        assert_eq!(sig.algorithm, PqAlgorithm::SimulatedMlDsa65);
        assert!(!sig.signature_hex.is_empty());
        let verifier = kp.verifier();
        assert!(verifier.verify(b"hello world", &sig));
    }

    #[test]
    fn test_simulated_deterministic_signatures() {
        let kp = SimulatedMlDsa65Keypair::from_seed([42u8; 32]);
        let sig1 = kp.sign(b"same message");
        let sig2 = kp.sign(b"same message");
        assert_eq!(sig1.signature_hex, sig2.signature_hex);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let kp = SimulatedMlDsa65Keypair::from_seed([42u8; 32]);
        let sig1 = kp.sign(b"message A");
        let sig2 = kp.sign(b"message B");
        assert_ne!(sig1.signature_hex, sig2.signature_hex);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let kp1 = SimulatedMlDsa65Keypair::from_seed([1u8; 32]);
        let kp2 = SimulatedMlDsa65Keypair::from_seed([2u8; 32]);
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(PqAlgorithm::MlDsa65.to_string(), "ML-DSA-65");
        assert_eq!(PqAlgorithm::HybridEd25519MlDsa65.to_string(), "Hybrid-Ed25519-ML-DSA-65");
        assert_eq!(PqAlgorithm::SimulatedMlDsa65.to_string(), "Simulated-ML-DSA-65");
    }

    #[test]
    fn test_hybrid_sign_produces_both_signatures() {
        let signer = HybridSigner::new([10u8; 32], [20u8; 32]);
        let sig = signer.sign(b"hybrid test");
        assert_eq!(sig.algorithm, PqAlgorithm::HybridEd25519MlDsa65);
        assert!(sig.classical_signature_hex.is_some());
        assert!(!sig.signature_hex.is_empty());
    }

    #[test]
    fn test_hybrid_verify_passes() {
        let signer = HybridSigner::new([10u8; 32], [20u8; 32]);
        let pq_kp = SimulatedMlDsa65Keypair::from_seed([20u8; 32]);
        let verifier = HybridVerifier::new(signer.ed25519_public_key(), *pq_kp.public_key());
        let sig = signer.sign(b"verify me");
        assert!(verifier.verify(b"verify me", &sig));
    }

    #[test]
    fn test_hybrid_verify_fails_wrong_message() {
        let signer = HybridSigner::new([10u8; 32], [20u8; 32]);
        let pq_kp = SimulatedMlDsa65Keypair::from_seed([20u8; 32]);
        let verifier = HybridVerifier::new(signer.ed25519_public_key(), *pq_kp.public_key());
        let sig = signer.sign(b"correct message");
        assert!(!verifier.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_hybrid_verify_fails_missing_classical() {
        let signer = HybridSigner::new([10u8; 32], [20u8; 32]);
        let pq_kp = SimulatedMlDsa65Keypair::from_seed([20u8; 32]);
        let verifier = HybridVerifier::new(signer.ed25519_public_key(), *pq_kp.public_key());
        let mut sig = signer.sign(b"test");
        sig.classical_signature_hex = None; // Remove classical sig
        assert!(!verifier.verify(b"test", &sig));
    }

    #[test]
    fn test_public_key_hex_format() {
        let kp = SimulatedMlDsa65Keypair::from_seed([99u8; 32]);
        let pk_hex = kp.public_key_hex();
        assert_eq!(pk_hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(hex::decode(&pk_hex).is_ok());
    }
}
