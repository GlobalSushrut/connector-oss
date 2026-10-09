use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use std::path::Path;

/// Ed25519 signing keypair with disk persistence.
///
/// CRITICAL: Keys must be generated ONCE and persisted to disk.
/// Regenerating on restart invalidates every previously issued license signature.
///
/// Storage layout:
///   $CONNECTOR_KEY_DIR/signing.key   — 32-byte raw Ed25519 private key (0600)
///   $CONNECTOR_KEY_DIR/verifying.pub — 32-byte raw Ed25519 public key  (0644)
pub struct SigningKeys {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl SigningKeys {
    /// Load from disk if key files exist, otherwise generate and persist.
    /// Panics on I/O errors — license server cannot operate without a stable keypair.
    pub fn load_or_generate(key_dir: &str) -> Self {
        let signing_path = format!("{}/signing.key", key_dir);
        let verifying_path = format!("{}/verifying.pub", key_dir);

        if Path::new(&signing_path).exists() && Path::new(&verifying_path).exists() {
            // Load existing keypair
            let raw = std::fs::read(&signing_path)
                .unwrap_or_else(|e| panic!("Cannot read signing key {}: {}", signing_path, e));
            if raw.len() != 32 {
                panic!("Signing key file {} is corrupt (expected 32 bytes, got {})", signing_path, raw.len());
            }
            let bytes: [u8; 32] = raw.try_into().unwrap();
            let signing_key = SigningKey::from_bytes(&bytes);
            let verifying_key = signing_key.verifying_key();
            eprintln!("[keys] Loaded persistent Ed25519 keypair from {}", key_dir);
            eprintln!("[keys] Public key: {}", hex::encode(verifying_key.to_bytes()));
            Self { signing_key, verifying_key }
        } else {
            // First-time generation — write to disk atomically
            std::fs::create_dir_all(key_dir)
                .unwrap_or_else(|e| panic!("Cannot create key dir {}: {}", key_dir, e));

            let signing_key = SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();

            // Write private key (mode 0600)
            std::fs::write(&signing_path, signing_key.to_bytes())
                .unwrap_or_else(|e| panic!("Cannot write signing key {}: {}", signing_path, e));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&signing_path,
                    std::fs::Permissions::from_mode(0o600))
                    .unwrap_or_else(|e| eprintln!("[keys] WARN: cannot chmod signing.key: {}", e));
            }

            // Write public key (mode 0644)
            std::fs::write(&verifying_path, verifying_key.to_bytes())
                .unwrap_or_else(|e| panic!("Cannot write verifying key {}: {}", verifying_path, e));

            eprintln!("[keys] Generated NEW Ed25519 keypair → {}", key_dir);
            eprintln!("[keys] Public key (embed in binaries): {}", hex::encode(verifying_key.to_bytes()));
            eprintln!("[keys] IMPORTANT: Back up {}/signing.key securely — losing it invalidates all licenses.", key_dir);

            Self { signing_key, verifying_key }
        }
    }

    /// Sign a message. Returns base64url-encoded signature.
    pub fn sign(&self, message: &[u8]) -> String {
        let sig = self.signing_key.sign(message);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
    }

    /// Verify a base64-encoded Ed25519 signature.
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

    /// Verify using any raw 32-byte Ed25519 public key (for binary-embedded key verification).
    pub fn verify_with_pubkey(pubkey_bytes: &[u8; 32], message: &[u8], signature_b64: &str) -> bool {
        let vk = match VerifyingKey::from_bytes(pubkey_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(message, &sig).is_ok()
    }

    /// Hex-encoded public key — embed this in deployed binaries at build time.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Base64-encoded public key — for API responses and admin display.
    pub fn public_key_b64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, self.verifying_key.to_bytes())
    }

    /// Raw 32 bytes — for embedding in binary as const.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// Generate a cryptographically secure license key secret.
/// Format: lic_<tier>_<32 hex chars>
/// The secret is a hash of tier + customer + random UUID so it's unguessable.
pub fn generate_key_secret(tier: &str, customer: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tier.as_bytes());
    hasher.update(b":");
    hasher.update(customer.as_bytes());
    hasher.update(b":");
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    let hash = hasher.finalize();
    let prefix = match tier.to_lowercase().as_str() {
        "sovereign" => "lic_sov",
        "core"      => "lic_core",
        "enterprise"=> "lic_ent",
        "scale"     => "lic_scale",
        "business"  => "lic_biz",
        "growth"    => "lic_growth",
        "startup"   => "lic_start",
        _           => "lic_indie",
    };
    format!("{}_{}", prefix, hex::encode(&hash[..16]))
}

/// Generate a signed offline license FILE in PEM-style format.
/// The binary can validate this entirely offline using the embedded public key.
///
/// Format:
///   -----BEGIN LICENSE FILE-----
///   base64(json_payload + "." + base64_ed25519_sig)
///   -----END LICENSE FILE-----
///
/// Payload JSON contains: key_id, tier, customer_email, issued_at, expires_at,
///   max_agents, max_events, machine_id (if node-locked), features[]
pub fn generate_license_file(keys: &SigningKeys, payload: &serde_json::Value) -> String {
    let payload_str = serde_json::to_string(payload).unwrap_or_default();
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        payload_str.as_bytes(),
    );
    let sig = keys.sign(payload_b64.as_bytes());
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        sig.as_bytes(),
    );
    let combined = format!("{}.{}", payload_b64, sig_b64);
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, combined.as_bytes());

    // Wrap in 64-char PEM lines
    let lines: String = encoded.as_bytes().chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");

    format!("-----BEGIN LICENSE FILE-----\n{}\n-----END LICENSE FILE-----", lines)
}

/// Parse and verify a license FILE produced by generate_license_file.
/// Returns the decoded JSON payload if valid, or None if tampered/invalid.
pub fn verify_license_file(keys: &SigningKeys, pem: &str) -> Option<serde_json::Value> {
    let body = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let combined_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body).ok()?;
    let combined = std::str::from_utf8(&combined_bytes).ok()?;
    let dot = combined.rfind('.')?;
    let payload_b64 = &combined[..dot];
    let sig_b64_outer = &combined[dot + 1..];

    // Decode inner sig
    let sig_inner_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, sig_b64_outer).ok()?;
    let sig_inner = std::str::from_utf8(&sig_inner_bytes).ok()?;

    // Verify: signature is over the payload_b64 bytes
    if !keys.verify(payload_b64.as_bytes(), sig_inner) {
        return None;
    }

    // Decode payload
    let payload_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, payload_b64).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}
