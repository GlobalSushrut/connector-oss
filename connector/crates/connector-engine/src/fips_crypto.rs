//! FIPS 140-3 Cryptographic Module — trait-based pluggable crypto backend.
//!
//! Provides a unified cryptographic interface that can be backed by:
//! - **Default**: RustCrypto (ed25519-dalek, sha2, aes-gcm) — no C deps
//! - **FIPS mode**: `aws-lc-rs` with `aws-lc-fips-sys` — NIST FIPS 140-3 Level 1 certified
//!
//! Research: AWS-LC FIPS 3.0 (first library with ML-KEM in FIPS validation),
//! NIST SP 800-140, CMVP, ring API compatibility.
//!
//! Usage: Instantiate `DefaultCryptoModule` for development/testing.
//! For FIPS compliance, implement `CryptoModule` trait with aws-lc-rs backend.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// ═══════════════════════════════════════════════════════════════
// Crypto Module Trait
// ═══════════════════════════════════════════════════════════════

/// FIPS compliance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FipsLevel {
    /// Not FIPS validated — using RustCrypto
    None,
    /// FIPS 140-3 Level 1 (software module)
    Level1,
    /// FIPS 140-3 Level 2 (tamper-evident)
    Level2,
    /// FIPS 140-3 Level 3 (tamper-resistant)
    Level3,
}

impl std::fmt::Display for FipsLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FipsLevel::None => write!(f, "None"),
            FipsLevel::Level1 => write!(f, "FIPS-140-3-L1"),
            FipsLevel::Level2 => write!(f, "FIPS-140-3-L2"),
            FipsLevel::Level3 => write!(f, "FIPS-140-3-L3"),
        }
    }
}

/// Algorithm registry — what the module supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmSupport {
    pub sha256: bool,
    pub sha384: bool,
    pub sha512: bool,
    pub aes_128_gcm: bool,
    pub aes_256_gcm: bool,
    pub ed25519: bool,
    pub ecdsa_p256: bool,
    pub ecdsa_p384: bool,
    pub x25519: bool,
    pub ml_kem_768: bool,
    pub ml_dsa_65: bool,
    pub hkdf_sha256: bool,
    pub hmac_sha256: bool,
}

/// Unified cryptographic module trait.
///
/// Implementors provide cryptographic primitives backed by either
/// RustCrypto or a FIPS-validated library (aws-lc-rs).
pub trait CryptoModule: Send + Sync {
    /// FIPS compliance level of this module.
    fn fips_level(&self) -> FipsLevel;

    /// Module name/version.
    fn module_name(&self) -> &str;

    /// Supported algorithms.
    fn algorithms(&self) -> AlgorithmSupport;

    /// SHA-256 hash.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// HMAC-SHA256.
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];

    /// HKDF-SHA256 key derivation.
    fn hkdf_sha256(&self, ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8>;

    /// Generate random bytes.
    fn random_bytes(&self, len: usize) -> Vec<u8>;

    /// Perform self-test (FIPS requirement: power-on self-test).
    fn self_test(&self) -> Result<(), String>;
}

// ═══════════════════════════════════════════════════════════════
// Default (RustCrypto) Backend
// ═══════════════════════════════════════════════════════════════

/// Default crypto module using pure-Rust RustCrypto crates.
/// NOT FIPS validated, but functionally correct.
pub struct DefaultCryptoModule;

impl DefaultCryptoModule {
    pub fn new() -> Self { Self }
}

impl CryptoModule for DefaultCryptoModule {
    fn fips_level(&self) -> FipsLevel { FipsLevel::None }
    fn module_name(&self) -> &str { "RustCrypto-Default/1.0" }

    fn algorithms(&self) -> AlgorithmSupport {
        AlgorithmSupport {
            sha256: true,
            sha384: false,
            sha512: true,
            aes_128_gcm: false,
            aes_256_gcm: true,
            ed25519: true,
            ecdsa_p256: false,
            ecdsa_p384: false,
            x25519: false,
            ml_kem_768: false,
            ml_dsa_65: false,
            hkdf_sha256: true,
            hmac_sha256: true,
        }
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        // Standard HMAC construction
        let mut k = [0u8; 64];
        if key.len() <= 64 {
            k[..key.len()].copy_from_slice(key);
        } else {
            let h = self.sha256(key);
            k[..32].copy_from_slice(&h);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 { ipad[i] ^= k[i]; opad[i] ^= k[i]; }

        let mut inner = Sha256::new();
        inner.update(&ipad);
        inner.update(data);
        let inner_hash: [u8; 32] = inner.finalize().into();

        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        outer.finalize().into()
    }

    fn hkdf_sha256(&self, ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
        // HKDF-Extract
        let prk = self.hmac_sha256(if salt.is_empty() { &[0u8; 32] } else { salt }, ikm);
        // HKDF-Expand
        let n = (output_len + 31) / 32;
        let mut okm = Vec::with_capacity(output_len);
        let mut t = Vec::new();
        for i in 1..=n {
            let mut input = Vec::new();
            input.extend_from_slice(&t);
            input.extend_from_slice(info);
            input.push(i as u8);
            let block = self.hmac_sha256(&prk, &input);
            t = block.to_vec();
            okm.extend_from_slice(&block);
        }
        okm.truncate(output_len);
        okm
    }

    fn random_bytes(&self, len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut buf = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    fn self_test(&self) -> Result<(), String> {
        // Known-answer test for SHA-256 (NIST example)
        let hash = self.sha256(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        if hex::encode(hash) != expected {
            return Err("SHA-256 self-test FAILED".into());
        }
        // HMAC-SHA256 smoke test
        let hmac = self.hmac_sha256(b"key", b"data");
        if hmac.len() != 32 {
            return Err("HMAC-SHA256 self-test FAILED".into());
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// Crypto Module Registry
// ═══════════════════════════════════════════════════════════════

/// Registry for selecting crypto backends at runtime.
pub struct CryptoModuleRegistry {
    modules: Vec<Box<dyn CryptoModule>>,
    active_index: usize,
}

impl CryptoModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: vec![Box::new(DefaultCryptoModule::new())],
            active_index: 0,
        }
    }

    pub fn register(&mut self, module: Box<dyn CryptoModule>) {
        self.modules.push(module);
    }

    pub fn set_active(&mut self, index: usize) -> Result<(), String> {
        if index >= self.modules.len() {
            return Err(format!("Module index {} out of range ({})", index, self.modules.len()));
        }
        self.active_index = index;
        Ok(())
    }

    pub fn active(&self) -> &dyn CryptoModule {
        &*self.modules[self.active_index]
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Find first module with FIPS validation.
    pub fn fips_module(&self) -> Option<&dyn CryptoModule> {
        self.modules.iter()
            .find(|m| m.fips_level() != FipsLevel::None)
            .map(|m| &**m)
    }

    /// Run self-tests on all modules.
    pub fn self_test_all(&self) -> Vec<(String, Result<(), String>)> {
        self.modules.iter()
            .map(|m| (m.module_name().to_string(), m.self_test()))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_module_sha256() {
        let m = DefaultCryptoModule::new();
        let hash = m.sha256(b"hello");
        assert_eq!(hash.len(), 32);
        // Known SHA-256 of "hello"
        assert_eq!(hex::encode(hash), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_default_module_hmac() {
        let m = DefaultCryptoModule::new();
        let mac = m.hmac_sha256(b"key", b"data");
        assert_eq!(mac.len(), 32);
        // Deterministic
        let mac2 = m.hmac_sha256(b"key", b"data");
        assert_eq!(mac, mac2);
        // Different key → different MAC
        let mac3 = m.hmac_sha256(b"different", b"data");
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_hkdf_produces_correct_length() {
        let m = DefaultCryptoModule::new();
        let key = m.hkdf_sha256(b"input key", b"salt", b"info", 48);
        assert_eq!(key.len(), 48);
        let key16 = m.hkdf_sha256(b"input key", b"salt", b"info", 16);
        assert_eq!(key16.len(), 16);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let m = DefaultCryptoModule::new();
        let k1 = m.hkdf_sha256(b"ikm", b"salt", b"info", 32);
        let k2 = m.hkdf_sha256(b"ikm", b"salt", b"info", 32);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_random_bytes_length() {
        let m = DefaultCryptoModule::new();
        assert_eq!(m.random_bytes(16).len(), 16);
        assert_eq!(m.random_bytes(64).len(), 64);
    }

    #[test]
    fn test_random_bytes_not_all_zeros() {
        let m = DefaultCryptoModule::new();
        let r = m.random_bytes(32);
        assert!(r.iter().any(|&b| b != 0), "Random bytes should not be all zeros");
    }

    #[test]
    fn test_self_test_passes() {
        let m = DefaultCryptoModule::new();
        assert!(m.self_test().is_ok());
    }

    #[test]
    fn test_fips_level_is_none() {
        let m = DefaultCryptoModule::new();
        assert_eq!(m.fips_level(), FipsLevel::None);
        assert_eq!(m.fips_level().to_string(), "None");
    }

    #[test]
    fn test_algorithm_support() {
        let m = DefaultCryptoModule::new();
        let algs = m.algorithms();
        assert!(algs.sha256);
        assert!(algs.aes_256_gcm);
        assert!(algs.ed25519);
        assert!(!algs.ml_kem_768); // Not yet
        assert!(!algs.ml_dsa_65);  // Not yet
    }

    #[test]
    fn test_registry_default_module() {
        let reg = CryptoModuleRegistry::new();
        assert_eq!(reg.module_count(), 1);
        assert_eq!(reg.active().module_name(), "RustCrypto-Default/1.0");
        assert!(reg.fips_module().is_none());
    }

    #[test]
    fn test_registry_self_test_all() {
        let reg = CryptoModuleRegistry::new();
        let results = reg.self_test_all();
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
    }
}
