//! CNP Transport — L2 (Noise Encryption) + L3 (Port Security).
//!
//! L2: Encrypts CnpFrame bytes using the Noise_IK channel for the target agent.
//! L3: Wraps the encrypted frame with HMAC signature, anti-replay nonce, and TTL.
//!
//! On receive, the layers are unwrapped in reverse: verify security → decrypt → frame.

use sha2::{Sha256, Digest};
use std::collections::{HashMap, VecDeque};
use crate::cnp::types::*;

// ═══════════════════════════════════════════════════════════════
// L2: Encryption Layer
// ═══════════════════════════════════════════════════════════════

/// L2 Encryption — wraps/unwraps Noise_IK encryption on CnpFrames.
///
/// In production, this delegates to `NoiseChannelManager` from noise_channel.rs.
/// Here we provide a self-contained implementation for the CNP stack that
/// can operate standalone or bridge to the existing NoiseChannelManager.
pub struct CnpEncryptor {
    /// Channel secrets: channel_id → symmetric key (derived from Noise handshake)
    channel_keys: HashMap<String, [u8; 32]>,
    /// Send counters per channel (for nonce generation)
    send_counters: HashMap<String, u64>,
    /// Recv counters per channel (for nonce verification)
    recv_counters: HashMap<String, u64>,
}

impl CnpEncryptor {
    pub fn new() -> Self {
        Self {
            channel_keys: HashMap::new(),
            send_counters: HashMap::new(),
            recv_counters: HashMap::new(),
        }
    }

    /// Register a channel with its derived transport key.
    /// Called after Noise_IK handshake completes.
    pub fn register_channel(&mut self, channel_id: &str, transport_key: [u8; 32]) {
        self.channel_keys.insert(channel_id.to_string(), transport_key);
        self.send_counters.insert(channel_id.to_string(), 0);
        self.recv_counters.insert(channel_id.to_string(), 0);
    }

    /// Remove a channel (on close).
    pub fn remove_channel(&mut self, channel_id: &str) {
        self.channel_keys.remove(channel_id);
        self.send_counters.remove(channel_id);
        self.recv_counters.remove(channel_id);
    }

    /// L2 Encrypt: CnpFrame → CnpEncryptedFrame
    ///
    /// Uses HMAC-SHA256(key, counter || data) as simulated AEAD.
    /// Production: replace with ChaCha20-Poly1305 via `snow` crate.
    pub fn encrypt(&mut self, channel_id: &str, frame: &CnpFrame) -> CnpResult<CnpEncryptedFrame> {
        let key = self.channel_keys.get(channel_id).ok_or_else(|| CnpError::TransportError {
            detail: format!("No key for channel {}", channel_id),
        })?;

        let counter = self.send_counters.get_mut(channel_id).ok_or_else(|| CnpError::TransportError {
            detail: format!("No counter for channel {}", channel_id),
        })?;

        // Simulate AEAD: HMAC(key, counter || plaintext)
        let ciphertext = simulated_encrypt(key, *counter, &frame.data);
        let current_counter = *counter;
        *counter += 1;

        Ok(CnpEncryptedFrame {
            channel_id: channel_id.to_string(),
            ciphertext,
            counter: current_counter,
        })
    }

    /// L2 Decrypt: CnpEncryptedFrame → raw bytes
    ///
    /// Verifies the counter is in expected range and decrypts.
    pub fn decrypt(&mut self, encrypted: &CnpEncryptedFrame) -> CnpResult<Vec<u8>> {
        let key = self.channel_keys.get(&encrypted.channel_id).ok_or_else(|| CnpError::TransportError {
            detail: format!("No key for channel {}", encrypted.channel_id),
        })?;

        let recv_counter = self.recv_counters.get_mut(&encrypted.channel_id).ok_or_else(|| CnpError::TransportError {
            detail: format!("No recv counter for channel {}", encrypted.channel_id),
        })?;

        // Counter must be >= expected (allow for reordering within window)
        if encrypted.counter < *recv_counter {
            return Err(CnpError::TransportError {
                detail: format!("Counter replay: got {}, expected >= {}", encrypted.counter, recv_counter),
            });
        }

        let plaintext = simulated_decrypt(key, encrypted.counter, &encrypted.ciphertext)?;
        *recv_counter = encrypted.counter + 1;

        Ok(plaintext)
    }

    /// Check if a channel is registered.
    pub fn has_channel(&self, channel_id: &str) -> bool {
        self.channel_keys.contains_key(channel_id)
    }

    /// Get the number of registered channels.
    pub fn channel_count(&self) -> usize {
        self.channel_keys.len()
    }
}

/// Simulated AEAD encrypt: XOR with key-derived stream + append MAC.
/// NOT cryptographically secure — use ChaCha20-Poly1305 in production.
fn simulated_encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let stream_key = derive_stream_key(key, counter);
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 32);

    // XOR encrypt
    for (i, &byte) in plaintext.iter().enumerate() {
        ciphertext.push(byte ^ stream_key[i % 32]);
    }

    // Append MAC
    let mac = compute_mac(key, counter, &ciphertext);
    ciphertext.extend_from_slice(&mac);

    ciphertext
}

/// Simulated AEAD decrypt: verify MAC + XOR with key-derived stream.
fn simulated_decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> CnpResult<Vec<u8>> {
    if ciphertext.len() < 32 {
        return Err(CnpError::TransportError {
            detail: "Ciphertext too short (missing MAC)".into(),
        });
    }

    let mac_start = ciphertext.len() - 32;
    let encrypted_data = &ciphertext[..mac_start];
    let received_mac = &ciphertext[mac_start..];

    // Verify MAC
    let expected_mac = compute_mac(key, counter, encrypted_data);
    if received_mac != expected_mac {
        return Err(CnpError::TransportError {
            detail: "MAC verification failed — message tampered or wrong key".into(),
        });
    }

    // XOR decrypt
    let stream_key = derive_stream_key(key, counter);
    let mut plaintext = Vec::with_capacity(encrypted_data.len());
    for (i, &byte) in encrypted_data.iter().enumerate() {
        plaintext.push(byte ^ stream_key[i % 32]);
    }

    Ok(plaintext)
}

fn derive_stream_key(key: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cnp-stream:");
    hasher.update(key);
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

fn compute_mac(key: &[u8; 32], counter: u64, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cnp-mac:");
    hasher.update(key);
    hasher.update(counter.to_le_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

// ═══════════════════════════════════════════════════════════════
// L3: Port Security Layer
// ═══════════════════════════════════════════════════════════════

/// L3 Security — HMAC authentication, anti-replay, TTL enforcement, rate limiting.
///
/// Wraps an encrypted frame with port-level security metadata.
/// On receive, validates all security properties before passing to L2.
pub struct CnpSecurityLayer {
    /// Port secrets: port_id → shared secret (for HMAC)
    port_secrets: HashMap<String, [u8; 32]>,
    /// Nonce windows: port_id → set of recently seen nonces
    nonce_windows: HashMap<String, VecDeque<(u64, i64)>>,
    /// Rate counters: (port_id, agent_pid) → (count, window_start_ms)
    rate_counters: HashMap<(String, String), (u32, i64)>,
    /// Rate limit per agent per port per second
    rate_limit_per_sec: u32,
    /// Global nonce counter for outgoing messages
    nonce_counter: u64,
}

impl CnpSecurityLayer {
    pub fn new(rate_limit_per_sec: u32) -> Self {
        Self {
            port_secrets: HashMap::new(),
            nonce_windows: HashMap::new(),
            rate_counters: HashMap::new(),
            rate_limit_per_sec,
            nonce_counter: 0,
        }
    }

    /// Register a port with its shared secret.
    pub fn register_port(&mut self, port_id: &str, secret: [u8; 32]) {
        self.port_secrets.insert(port_id.to_string(), secret);
        self.nonce_windows.insert(port_id.to_string(), VecDeque::new());
    }

    /// Remove a port.
    pub fn remove_port(&mut self, port_id: &str) {
        self.port_secrets.remove(port_id);
        self.nonce_windows.remove(port_id);
    }

    /// L3 Secure: CnpEncryptedFrame → CnpSecuredFrame
    ///
    /// Signs the encrypted frame with HMAC, adds nonce and TTL.
    pub fn secure(
        &mut self,
        port_id: &str,
        sender_pid: &str,
        encrypted: CnpEncryptedFrame,
        ttl_ms: i64,
    ) -> CnpResult<CnpSecuredFrame> {
        let secret = self.port_secrets.get(port_id).ok_or_else(|| CnpError::SecurityError {
            verdict: format!("No secret for port {}", port_id),
        })?;

        self.nonce_counter += 1;
        let nonce = self.nonce_counter;
        let timestamp_ms = now_ms();

        // Compute HMAC signature
        let signature = compute_port_signature(
            secret, port_id, sender_pid, &encrypted.ciphertext, nonce, timestamp_ms,
        );

        Ok(CnpSecuredFrame {
            encrypted,
            port_id: port_id.to_string(),
            signature,
            nonce,
            ttl_ms,
            timestamp_ms,
        })
    }

    /// L3 Verify: validate a CnpSecuredFrame.
    ///
    /// Checks: signature → TTL → anti-replay → rate-limit
    /// Returns the inner CnpEncryptedFrame on success.
    pub fn verify<'a>(
        &mut self,
        secured: &'a CnpSecuredFrame,
        sender_pid: &str,
    ) -> CnpResult<&'a CnpEncryptedFrame> {
        let now = now_ms();

        // 1. Check port secret exists
        let secret = self.port_secrets.get(&secured.port_id).ok_or_else(|| CnpError::SecurityError {
            verdict: format!("Unknown port {}", secured.port_id),
        })?;

        // 2. Verify HMAC signature
        let expected_sig = compute_port_signature(
            secret,
            &secured.port_id,
            sender_pid,
            &secured.encrypted.ciphertext,
            secured.nonce,
            secured.timestamp_ms,
        );
        if secured.signature != expected_sig {
            return Err(CnpError::SecurityError {
                verdict: "Invalid HMAC signature".into(),
            });
        }

        // 3. Check TTL
        if secured.ttl_ms > 0 && now > secured.timestamp_ms + secured.ttl_ms {
            return Err(CnpError::MessageExpired {
                message_id: format!("nonce-{}", secured.nonce),
                ttl_ms: secured.ttl_ms,
            });
        }

        // 4. Anti-replay check (nonce window)
        let window = self.nonce_windows
            .get_mut(&secured.port_id)
            .ok_or_else(|| CnpError::SecurityError {
                verdict: format!("No nonce window for port {}", secured.port_id),
            })?;

        // Evict old nonces outside the window
        let window_start = now - CNP_NONCE_WINDOW_MS;
        while window.front().map_or(false, |(_, ts)| *ts < window_start) {
            window.pop_front();
        }

        // Check if nonce was already seen
        if window.iter().any(|(n, _)| *n == secured.nonce) {
            return Err(CnpError::SecurityError {
                verdict: "Replay detected: nonce already seen".into(),
            });
        }
        window.push_back((secured.nonce, now));

        // 5. Rate limiting
        let rate_key = (secured.port_id.clone(), sender_pid.to_string());
        let (count, window_start_ms) = self.rate_counters.entry(rate_key).or_insert((0, now));
        if now - *window_start_ms > 1000 {
            // Reset window
            *count = 0;
            *window_start_ms = now;
        }
        *count += 1;
        if *count > self.rate_limit_per_sec {
            return Err(CnpError::RateLimitExceeded {
                agent: sender_pid.to_string(),
                limit: self.rate_limit_per_sec,
            });
        }

        Ok(&secured.encrypted)
    }

    /// Check if a port is registered.
    pub fn has_port(&self, port_id: &str) -> bool {
        self.port_secrets.contains_key(port_id)
    }
}

fn compute_port_signature(
    secret: &[u8; 32],
    port_id: &str,
    sender_pid: &str,
    ciphertext: &[u8],
    nonce: u64,
    timestamp_ms: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cnp-port-sig:");
    hasher.update(secret);
    hasher.update(port_id.as_bytes());
    hasher.update(sender_pid.as_bytes());
    hasher.update(ciphertext);
    hasher.update(nonce.to_le_bytes());
    hasher.update(timestamp_ms.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cnp::types::CnpPayload;
    use crate::cnp::codec::CnpCodec;

    fn test_key() -> [u8; 32] { [0xAA; 32] }
    fn test_port_secret() -> [u8; 32] { [0xBB; 32] }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut enc = CnpEncryptor::new();
        enc.register_channel("ch-1", test_key());

        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "secret".into() });
        let frame = CnpCodec::encode(&msg).unwrap();

        let encrypted = enc.encrypt("ch-1", &frame).unwrap();
        assert_ne!(encrypted.ciphertext, frame.data); // Actually encrypted

        let plaintext = enc.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext, frame.data); // Round-trips
    }

    #[test]
    fn test_encrypt_wrong_channel() {
        let mut enc = CnpEncryptor::new();
        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "x".into() });
        let frame = CnpCodec::encode(&msg).unwrap();
        assert!(enc.encrypt("nonexistent", &frame).is_err());
    }

    #[test]
    fn test_counter_replay_rejected() {
        let mut enc = CnpEncryptor::new();
        enc.register_channel("ch-1", test_key());

        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "x".into() });
        let frame = CnpCodec::encode(&msg).unwrap();

        let encrypted = enc.encrypt("ch-1", &frame).unwrap();
        enc.decrypt(&encrypted).unwrap(); // First decrypt OK

        // Replay same counter → rejected
        assert!(enc.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let mut enc = CnpEncryptor::new();
        enc.register_channel("ch-1", test_key());

        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "x".into() });
        let frame = CnpCodec::encode(&msg).unwrap();

        let mut encrypted = enc.encrypt("ch-1", &frame).unwrap();
        // Tamper
        if encrypted.ciphertext.len() > 33 {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        assert!(enc.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_security_layer_sign_verify() {
        let mut sec = CnpSecurityLayer::new(100);
        sec.register_port("port-1", test_port_secret());

        let encrypted = CnpEncryptedFrame {
            channel_id: "ch-1".into(),
            ciphertext: vec![1, 2, 3, 4],
            counter: 0,
        };

        let secured = sec.secure("port-1", "agent-a", encrypted, 30_000).unwrap();
        assert!(!secured.signature.is_empty());

        let verified = sec.verify(&secured, "agent-a");
        assert!(verified.is_ok());
    }

    #[test]
    fn test_security_wrong_signature() {
        let mut sec = CnpSecurityLayer::new(100);
        sec.register_port("port-1", test_port_secret());

        let encrypted = CnpEncryptedFrame {
            channel_id: "ch-1".into(),
            ciphertext: vec![1, 2, 3],
            counter: 0,
        };

        let mut secured = sec.secure("port-1", "agent-a", encrypted, 30_000).unwrap();
        secured.signature = "bad-sig".into();

        assert!(sec.verify(&secured, "agent-a").is_err());
    }

    #[test]
    fn test_nonce_replay_rejected() {
        let mut sec = CnpSecurityLayer::new(100);
        sec.register_port("port-1", test_port_secret());

        let encrypted = CnpEncryptedFrame {
            channel_id: "ch-1".into(),
            ciphertext: vec![1, 2, 3],
            counter: 0,
        };

        let secured = sec.secure("port-1", "agent-a", encrypted, 30_000).unwrap();
        sec.verify(&secured, "agent-a").unwrap();

        // Replay same secured frame → nonce already seen
        assert!(sec.verify(&secured, "agent-a").is_err());
    }

    #[test]
    fn test_rate_limiting() {
        let mut sec = CnpSecurityLayer::new(2); // 2 per second
        sec.register_port("port-1", test_port_secret());

        for i in 0..2 {
            let encrypted = CnpEncryptedFrame {
                channel_id: "ch-1".into(),
                ciphertext: vec![i as u8],
                counter: i,
            };
            let secured = sec.secure("port-1", "agent-a", encrypted, 30_000).unwrap();
            sec.verify(&secured, "agent-a").unwrap();
        }

        // Third message in same second → rate limited
        let encrypted = CnpEncryptedFrame {
            channel_id: "ch-1".into(),
            ciphertext: vec![99],
            counter: 99,
        };
        let secured = sec.secure("port-1", "agent-a", encrypted, 30_000).unwrap();
        let result = sec.verify(&secured, "agent-a");
        assert!(matches!(result, Err(CnpError::RateLimitExceeded { .. })));
    }
}
