use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use std::path::Path;

/// Ed25519 signing keypair for the platform binary.
/// Used to sign trust certificates, proof-of-work outputs, and audit exports.
///
/// CRITICAL: Keys must be generated ONCE and persisted to disk.
/// Path: $DATA_DIR/keys/platform_signing.key (mode 0600)
pub struct PlatformSigningKey {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl PlatformSigningKey {
    /// Load from disk if key exists, otherwise generate and persist.
    pub fn load_or_generate(data_dir: &str) -> Self {
        let key_dir = format!("{}/keys", data_dir);
        let key_path = format!("{}/platform_signing.key", key_dir);
        let pub_path = format!("{}/platform_verifying.pub", key_dir);

        if Path::new(&key_path).exists() {
            let raw = std::fs::read(&key_path).unwrap_or_else(|e| {
                eprintln!("[signing] FATAL: cannot read platform signing key {}: {}", key_path, e);
                std::process::exit(1);
            });
            if raw.len() != 32 {
                eprintln!(
                    "[signing] FATAL: platform signing key {} is corrupt (expected 32 bytes, got {})",
                    key_path,
                    raw.len()
                );
                std::process::exit(1);
            }
            let bytes: [u8; 32] = raw.try_into().unwrap();
            let signing_key = SigningKey::from_bytes(&bytes);
            let verifying_key = signing_key.verifying_key();
            tracing::info!("[signing] Loaded platform Ed25519 keypair from {}", key_dir);
            tracing::info!("[signing] Public key: {}", hex::encode(verifying_key.to_bytes()));
            Self { signing_key, verifying_key }
        } else {
            std::fs::create_dir_all(&key_dir)
                .unwrap_or_else(|e| panic!("Cannot create key dir {}: {}", key_dir, e));

            let signing_key = SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();

            std::fs::write(&key_path, signing_key.to_bytes())
                .unwrap_or_else(|e| panic!("Cannot write platform signing key {}: {}", key_path, e));

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap_or_else(|e| eprintln!("[signing] WARN: cannot chmod platform_signing.key: {}", e));
            }

            std::fs::write(&pub_path, verifying_key.to_bytes()).unwrap_or_else(|e| {
                eprintln!("[signing] FATAL: cannot write platform verifying key {}: {}", pub_path, e);
                std::process::exit(1);
            });

            tracing::info!("[signing] Generated NEW platform Ed25519 keypair → {}", key_dir);
            tracing::info!("[signing] Public key: {}", hex::encode(verifying_key.to_bytes()));
            tracing::warn!("[signing] IMPORTANT: Back up {}/platform_signing.key — losing it invalidates all signed certificates.", key_dir);

            Self { signing_key, verifying_key }
        }
    }

    /// Sign arbitrary bytes. Returns base64-standard-encoded signature.
    pub fn sign(&self, message: &[u8]) -> String {
        let sig = self.signing_key.sign(message);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
    }

    /// Verify a base64-encoded Ed25519 signature over a message.
    pub fn verify(&self, message: &[u8], signature_b64: &str) -> bool {
        let sig_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.verifying_key.verify(message, &sig).is_ok()
    }

    /// Stable node Ed25519 signing key — use for all court-tier IIA receipts (never ephemeral).
    pub fn ed25519(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Hex-encoded public key for embedding / API responses.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Base64-encoded public key for API responses.
    pub fn public_key_b64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, self.verifying_key.to_bytes())
    }
}
