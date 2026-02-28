//! Noise_IK Secure Channel — encrypted agent-to-agent communication.
//!
//! Implements the Noise Protocol Framework IK handshake pattern for
//! establishing encrypted channels between agents/cells.
//!
//! IK pattern: Initiator knows responder's static key (from Agent Card).
//!   → e, es, s, ss    (initiator sends ephemeral + static)
//!   ← e, ee, se       (responder sends ephemeral)
//!
//! Research: Noise Protocol Framework rev 34, `snow` crate (5M+ downloads),
//! `clatter` for PQ-hybrid Noise (future upgrade path),
//! Diem/Libra Noise_IK implementation, Signal Protocol double ratchet.
//!
//! This module provides a pure-Rust simulation of the Noise_IK handshake
//! using HMAC-SHA256 key derivation. For production, swap the transport
//! with `snow` crate using `Noise_IK_25519_ChaChaPoly_SHA256`.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Channel State
// ═══════════════════════════════════════════════════════════════

/// State of a Noise handshake/channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    /// Handshake not started
    Init,
    /// Initiator has sent message 1 (→ e, es, s, ss)
    HandshakeInitSent,
    /// Responder has received msg 1, sent msg 2 (← e, ee, se)
    HandshakeRespSent,
    /// Handshake complete — transport encryption active
    Transport,
    /// Channel closed
    Closed,
    /// Handshake failed
    Failed,
}

/// Cipher suite identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// X25519 DH + ChaChaPoly + SHA-256 (standard Noise)
    Noise25519ChaChaSha256,
    /// X25519 DH + AES-256-GCM + SHA-256
    Noise25519AesGcmSha256,
    /// Hybrid: X25519 + ML-KEM-768 + ChaChaPoly + SHA-256 (PQ future)
    HybridX25519MlKem768ChaChaSha256,
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherSuite::Noise25519ChaChaSha256 => write!(f, "Noise_IK_25519_ChaChaPoly_SHA256"),
            CipherSuite::Noise25519AesGcmSha256 => write!(f, "Noise_IK_25519_AESGCM_SHA256"),
            CipherSuite::HybridX25519MlKem768ChaChaSha256 => write!(f, "Noise_hybridIK_25519+MLKEM768_ChaChaPoly_SHA256"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Keypair (simulated X25519)
// ═══════════════════════════════════════════════════════════════

/// Simulated Noise keypair (32-byte keys).
/// In production, use actual X25519 via `snow` or `x25519-dalek`.
#[derive(Debug, Clone)]
pub struct NoiseKeypair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl NoiseKeypair {
    /// Generate from seed (deterministic for testing).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"noise-sk:");
        hasher.update(&seed);
        let private_key: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"noise-pk:");
        hasher.update(&private_key);
        let public_key: [u8; 32] = hasher.finalize().into();

        Self { private_key, public_key }
    }

    /// Simulated DH using public keys for commutativity.
    /// Real X25519: DH(a,B) == DH(b,A). We simulate by hashing sorted public keys.
    /// The "shared secret" depends on both parties' public keys — not private keys.
    /// This is NOT cryptographically secure — use `snow` crate for production.
    fn dh(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"noise-dh:");
        // Use sorted public keys for true commutativity
        if self.public_key <= *their_public {
            hasher.update(&self.public_key);
            hasher.update(their_public);
        } else {
            hasher.update(their_public);
            hasher.update(&self.public_key);
        }
        hasher.finalize().into()
    }
}

// ═══════════════════════════════════════════════════════════════
// Noise Channel
// ═══════════════════════════════════════════════════════════════

/// A Noise_IK secure channel between two parties.
#[derive(Debug, Clone)]
pub struct NoiseChannel {
    pub channel_id: String,
    pub state: ChannelState,
    pub cipher_suite: CipherSuite,
    pub local_static: NoiseKeypair,
    pub local_ephemeral: Option<NoiseKeypair>,
    pub remote_static_pk: Option<[u8; 32]>,
    pub remote_ephemeral_pk: Option<[u8; 32]>,
    /// Derived symmetric key for transport (after handshake)
    pub transport_key: Option<[u8; 32]>,
    /// Message counter for nonce generation
    pub send_counter: u64,
    pub recv_counter: u64,
    /// Handshake hash (chaining value)
    handshake_hash: [u8; 32],
}

impl NoiseChannel {
    /// Create initiator channel (we know responder's static public key).
    pub fn initiator(
        channel_id: impl Into<String>,
        local_static: NoiseKeypair,
        remote_static_pk: [u8; 32],
        ephemeral_seed: [u8; 32],
    ) -> Self {
        let local_ephemeral = NoiseKeypair::from_seed(ephemeral_seed);
        Self {
            channel_id: channel_id.into(),
            state: ChannelState::Init,
            cipher_suite: CipherSuite::Noise25519ChaChaSha256,
            local_static,
            local_ephemeral: Some(local_ephemeral),
            remote_static_pk: Some(remote_static_pk),
            remote_ephemeral_pk: None,
            transport_key: None,
            send_counter: 0,
            recv_counter: 0,
            handshake_hash: [0u8; 32],
        }
    }

    /// Create responder channel (we don't know initiator's static key yet).
    pub fn responder(
        channel_id: impl Into<String>,
        local_static: NoiseKeypair,
        ephemeral_seed: [u8; 32],
    ) -> Self {
        let local_ephemeral = NoiseKeypair::from_seed(ephemeral_seed);
        Self {
            channel_id: channel_id.into(),
            state: ChannelState::Init,
            cipher_suite: CipherSuite::Noise25519ChaChaSha256,
            local_static,
            local_ephemeral: Some(local_ephemeral),
            remote_static_pk: None,
            remote_ephemeral_pk: None,
            transport_key: None,
            send_counter: 0,
            recv_counter: 0,
            handshake_hash: [0u8; 32],
        }
    }

    /// Initiator: produce handshake message 1 (→ e, es, s, ss).
    pub fn write_handshake_msg1(&mut self) -> Result<HandshakeMessage, String> {
        if self.state != ChannelState::Init {
            return Err(format!("Cannot write msg1 in state {:?}", self.state));
        }
        let remote_pk = self.remote_static_pk.ok_or("No remote static pk")?;
        let ephemeral_pk = self.local_ephemeral.as_ref().ok_or("No ephemeral key")?.public_key;
        let es = self.local_ephemeral.as_ref().unwrap().dh(&remote_pk);
        let ss = self.local_static.dh(&remote_pk);

        self.mix_hash(&es);
        self.mix_hash(&ss);

        self.state = ChannelState::HandshakeInitSent;

        Ok(HandshakeMessage {
            ephemeral_pk,
            static_pk: Some(self.local_static.public_key),
            payload: Vec::new(),
        })
    }

    /// Responder: process msg1, produce msg2 (← e, ee, se).
    pub fn read_msg1_write_msg2(&mut self, msg1: &HandshakeMessage) -> Result<HandshakeMessage, String> {
        if self.state != ChannelState::Init {
            return Err(format!("Cannot read msg1 in state {:?}", self.state));
        }

        self.remote_ephemeral_pk = Some(msg1.ephemeral_pk);
        self.remote_static_pk = msg1.static_pk;

        let remote_ephem = msg1.ephemeral_pk;
        let remote_static = msg1.static_pk.ok_or("No remote static in msg1")?;

        // Copy ephemeral data before mutable borrows
        let ephemeral_pk = self.local_ephemeral.as_ref().ok_or("No ephemeral key")?.public_key;
        let es = self.local_static.dh(&remote_ephem);
        let ss = self.local_static.dh(&remote_static);
        let ee = self.local_ephemeral.as_ref().unwrap().dh(&remote_ephem);
        let se = self.local_ephemeral.as_ref().unwrap().dh(&remote_static);

        self.mix_hash(&es);
        self.mix_hash(&ss);
        self.mix_hash(&ee);
        self.mix_hash(&se);

        // Derive transport key
        self.transport_key = Some(self.handshake_hash);
        self.state = ChannelState::Transport;

        Ok(HandshakeMessage {
            ephemeral_pk,
            static_pk: None,
            payload: Vec::new(),
        })
    }

    /// Initiator: process msg2, complete handshake.
    pub fn read_msg2(&mut self, msg2: &HandshakeMessage) -> Result<(), String> {
        if self.state != ChannelState::HandshakeInitSent {
            return Err(format!("Cannot read msg2 in state {:?}", self.state));
        }

        self.remote_ephemeral_pk = Some(msg2.ephemeral_pk);
        let remote_ephem = msg2.ephemeral_pk;

        // Compute DH values before mutable borrows
        let ee = self.local_ephemeral.as_ref().ok_or("No ephemeral key")?.dh(&remote_ephem);
        let se = self.local_static.dh(&remote_ephem);

        self.mix_hash(&ee);
        self.mix_hash(&se);

        self.transport_key = Some(self.handshake_hash);
        self.state = ChannelState::Transport;

        Ok(())
    }

    /// Encrypt a message using the transport key.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.transport_key.as_ref().ok_or("No transport key")?;
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&self.send_counter.to_le_bytes());
        hasher.update(plaintext);
        let tag: [u8; 32] = hasher.finalize().into();

        let mut ciphertext = Vec::with_capacity(8 + plaintext.len() + 32);
        ciphertext.extend_from_slice(&self.send_counter.to_le_bytes());
        // Simple XOR encryption with derived keystream
        let mut keystream_hasher = Sha256::new();
        keystream_hasher.update(key);
        keystream_hasher.update(&self.send_counter.to_le_bytes());
        keystream_hasher.update(b"keystream");
        let ks: [u8; 32] = keystream_hasher.finalize().into();
        for (i, &b) in plaintext.iter().enumerate() {
            ciphertext.push(b ^ ks[i % 32]);
        }
        ciphertext.extend_from_slice(&tag);
        self.send_counter += 1;
        Ok(ciphertext)
    }

    /// Decrypt a message using the transport key.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 8 + 32 {
            return Err("Ciphertext too short".into());
        }
        let key = self.transport_key.as_ref().ok_or("No transport key")?;
        let counter = u64::from_le_bytes(ciphertext[..8].try_into().unwrap());
        let encrypted = &ciphertext[8..ciphertext.len() - 32];
        let tag = &ciphertext[ciphertext.len() - 32..];

        // Decrypt
        let mut keystream_hasher = Sha256::new();
        keystream_hasher.update(key);
        keystream_hasher.update(&counter.to_le_bytes());
        keystream_hasher.update(b"keystream");
        let ks: [u8; 32] = keystream_hasher.finalize().into();
        let plaintext: Vec<u8> = encrypted.iter().enumerate().map(|(i, &b)| b ^ ks[i % 32]).collect();

        // Verify tag
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&counter.to_le_bytes());
        hasher.update(&plaintext);
        let expected_tag: [u8; 32] = hasher.finalize().into();
        if tag != expected_tag.as_slice() {
            return Err("Authentication tag mismatch — message tampered".into());
        }
        self.recv_counter = counter + 1;
        Ok(plaintext)
    }

    /// Close the channel.
    pub fn close(&mut self) {
        self.state = ChannelState::Closed;
        self.transport_key = None;
    }

    /// Is the channel in transport (usable) state?
    pub fn is_transport(&self) -> bool {
        self.state == ChannelState::Transport
    }

    fn mix_hash(&mut self, data: &[u8; 32]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(data);
        self.handshake_hash = hasher.finalize().into();
    }
}

/// Handshake message exchanged between parties.
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    pub ephemeral_pk: [u8; 32],
    pub static_pk: Option<[u8; 32]>,
    pub payload: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════
// Channel Manager
// ═══════════════════════════════════════════════════════════════

/// Manages multiple Noise channels.
pub struct NoiseChannelManager {
    channels: HashMap<String, NoiseChannel>,
}

impl NoiseChannelManager {
    pub fn new() -> Self {
        Self { channels: HashMap::new() }
    }

    pub fn add_channel(&mut self, channel: NoiseChannel) {
        self.channels.insert(channel.channel_id.clone(), channel);
    }

    pub fn get(&self, id: &str) -> Option<&NoiseChannel> {
        self.channels.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut NoiseChannel> {
        self.channels.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<NoiseChannel> {
        self.channels.remove(id)
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    pub fn active_channels(&self) -> Vec<&str> {
        self.channels.iter()
            .filter(|(_, c)| c.is_transport())
            .map(|(id, _)| id.as_str())
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypairs() -> (NoiseKeypair, NoiseKeypair) {
        let alice = NoiseKeypair::from_seed([1u8; 32]);
        let bob = NoiseKeypair::from_seed([2u8; 32]);
        (alice, bob)
    }

    #[test]
    fn test_full_handshake_and_transport() {
        let (alice_static, bob_static) = make_keypairs();
        let bob_pk = bob_static.public_key;

        // Alice (initiator) knows Bob's static pk
        let mut alice = NoiseChannel::initiator("ch-1", alice_static, bob_pk, [10u8; 32]);
        // Bob (responder)
        let mut bob = NoiseChannel::responder("ch-1", bob_static, [20u8; 32]);

        // Handshake
        let msg1 = alice.write_handshake_msg1().unwrap();
        assert_eq!(alice.state, ChannelState::HandshakeInitSent);

        let msg2 = bob.read_msg1_write_msg2(&msg1).unwrap();
        assert_eq!(bob.state, ChannelState::Transport);

        alice.read_msg2(&msg2).unwrap();
        assert_eq!(alice.state, ChannelState::Transport);

        // Transport
        let ct = alice.encrypt(b"hello bob").unwrap();
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn test_bidirectional_transport() {
        let (alice_s, bob_s) = make_keypairs();
        let bob_pk = bob_s.public_key;
        let mut alice = NoiseChannel::initiator("ch-2", alice_s, bob_pk, [10u8; 32]);
        let mut bob = NoiseChannel::responder("ch-2", bob_s, [20u8; 32]);

        let msg1 = alice.write_handshake_msg1().unwrap();
        let msg2 = bob.read_msg1_write_msg2(&msg1).unwrap();
        alice.read_msg2(&msg2).unwrap();

        // Alice → Bob
        let ct1 = alice.encrypt(b"from alice").unwrap();
        let pt1 = bob.decrypt(&ct1).unwrap();
        assert_eq!(pt1, b"from alice");

        // Bob → Alice
        let ct2 = bob.encrypt(b"from bob").unwrap();
        let pt2 = alice.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"from bob");
    }

    #[test]
    fn test_tampered_message_detected() {
        let (alice_s, bob_s) = make_keypairs();
        let bob_pk = bob_s.public_key;
        let mut alice = NoiseChannel::initiator("ch-3", alice_s, bob_pk, [10u8; 32]);
        let mut bob = NoiseChannel::responder("ch-3", bob_s, [20u8; 32]);

        let msg1 = alice.write_handshake_msg1().unwrap();
        let msg2 = bob.read_msg1_write_msg2(&msg1).unwrap();
        alice.read_msg2(&msg2).unwrap();

        let mut ct = alice.encrypt(b"secret").unwrap();
        // Tamper with ciphertext
        if ct.len() > 10 { ct[10] ^= 0xFF; }
        assert!(bob.decrypt(&ct).is_err());
    }

    #[test]
    fn test_handshake_wrong_state_fails() {
        let (alice_s, _) = make_keypairs();
        let mut alice = NoiseChannel::initiator("ch-4", alice_s, [0u8; 32], [10u8; 32]);

        alice.write_handshake_msg1().unwrap();
        // Can't write msg1 again
        assert!(alice.write_handshake_msg1().is_err());
    }

    #[test]
    fn test_channel_close() {
        let (alice_s, bob_s) = make_keypairs();
        let bob_pk = bob_s.public_key;
        let mut alice = NoiseChannel::initiator("ch-5", alice_s, bob_pk, [10u8; 32]);
        let mut bob = NoiseChannel::responder("ch-5", bob_s, [20u8; 32]);

        let msg1 = alice.write_handshake_msg1().unwrap();
        let msg2 = bob.read_msg1_write_msg2(&msg1).unwrap();
        alice.read_msg2(&msg2).unwrap();
        assert!(alice.is_transport());

        alice.close();
        assert_eq!(alice.state, ChannelState::Closed);
        assert!(!alice.is_transport());
        assert!(alice.encrypt(b"fail").is_err());
    }

    #[test]
    fn test_cipher_suite_display() {
        assert_eq!(CipherSuite::Noise25519ChaChaSha256.to_string(), "Noise_IK_25519_ChaChaPoly_SHA256");
        assert_eq!(CipherSuite::HybridX25519MlKem768ChaChaSha256.to_string(), "Noise_hybridIK_25519+MLKEM768_ChaChaPoly_SHA256");
    }

    #[test]
    fn test_channel_manager() {
        let (alice_s, bob_s) = make_keypairs();
        let bob_pk = bob_s.public_key;
        let mut alice = NoiseChannel::initiator("ch-mgr", alice_s, bob_pk, [10u8; 32]);
        let mut bob = NoiseChannel::responder("ch-mgr-r", bob_s, [20u8; 32]);

        let msg1 = alice.write_handshake_msg1().unwrap();
        let msg2 = bob.read_msg1_write_msg2(&msg1).unwrap();
        alice.read_msg2(&msg2).unwrap();

        let mut mgr = NoiseChannelManager::new();
        mgr.add_channel(alice);
        mgr.add_channel(bob);
        assert_eq!(mgr.channel_count(), 2);
        assert_eq!(mgr.active_channels().len(), 2);
    }

    #[test]
    fn test_message_counter_increments() {
        let (alice_s, bob_s) = make_keypairs();
        let bob_pk = bob_s.public_key;
        let mut alice = NoiseChannel::initiator("ch-ctr", alice_s, bob_pk, [10u8; 32]);
        let mut bob = NoiseChannel::responder("ch-ctr", bob_s, [20u8; 32]);

        let msg1 = alice.write_handshake_msg1().unwrap();
        let msg2 = bob.read_msg1_write_msg2(&msg1).unwrap();
        alice.read_msg2(&msg2).unwrap();

        assert_eq!(alice.send_counter, 0);
        alice.encrypt(b"msg1").unwrap();
        assert_eq!(alice.send_counter, 1);
        alice.encrypt(b"msg2").unwrap();
        assert_eq!(alice.send_counter, 2);
    }
}
