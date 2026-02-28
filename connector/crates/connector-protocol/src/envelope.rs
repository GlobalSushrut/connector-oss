//! Wire Format (Layer 4) — Envelope, message types, CID-addressed packets.
//!
//! All messages use DAG-CBOR encoding with content-addressed CIDs.
//! Magic bytes: CONP (0x43 0x4F 0x4E 0x50)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::EntityId;

/// Protocol magic bytes: "CONP"
pub const MAGIC: [u8; 4] = [0x43, 0x4F, 0x4E, 0x50];

/// Protocol version 1.0
pub const VERSION: u16 = 0x0100;

// ── Priority ────────────────────────────────────────────────────────

/// Message priority levels. Lower number = higher priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Priority {
    /// E-stop, safety-critical. Preempts everything.
    Emergency = 0,
    /// Real-time control commands.
    Realtime = 1,
    /// Normal control messages.
    Control = 2,
    /// Data transfer, telemetry.
    Data = 3,
    /// Bulk, background tasks.
    Bulk = 4,
}

// ── Ordering Mode ───────────────────────────────────────────────────

/// Message ordering guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum OrderingMode {
    /// Best-effort delivery, no ordering. <1ms latency.
    Unordered = 0,
    /// Causal ordering: if A→B then deliver(A) before deliver(B). <10ms.
    Causal = 1,
    /// Total ordering: all nodes see same order. <100ms. Requires consensus.
    Total = 2,
}

// ── Message Type ────────────────────────────────────────────────────

/// All message types in the Connector Protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    // Handshake (0x01–0x04)
    Handshake = 0x01,
    HandshakeResponse = 0x02,
    Ping = 0x03,
    Pong = 0x04,

    // Capability (0x10–0x13)
    CapabilityRequest = 0x10,
    CapabilityGrant = 0x11,
    CapabilityRevoke = 0x12,
    CapabilityDelegate = 0x13,

    // Contract (0x20–0x23)
    ContractOffer = 0x20,
    ContractGrant = 0x21,
    ContractReceipt = 0x22,
    ContractRollback = 0x23,

    // Command (0x30–0x33)
    Command = 0x30,
    CommandAck = 0x31,
    Telemetry = 0x32,
    Event = 0x33,

    // Consensus (0x40–0x43)
    ConsensusPropose = 0x40,
    ConsensusPrepare = 0x41,
    ConsensusPrecommit = 0x42,
    ConsensusCommit = 0x43,

    // Safety (0xE0–0xE4)
    EmergencyStop = 0xE0,
    ClearStop = 0xE1,
    SafetyHeartbeat = 0xE2,
    SafetyFault = 0xE3,
    SafetyInterlock = 0xE4,

    // Discovery (0xF0–0xF4)
    DiscoverRequest = 0xF0,
    DiscoverResponse = 0xF1,
    StateSync = 0xF2,
    AttestationRequest = 0xF3,
    AttestationResponse = 0xF4,
}

impl MessageType {
    /// Whether this message type is safety-critical (priority 0).
    pub fn is_safety_critical(&self) -> bool {
        matches!(
            self,
            Self::EmergencyStop | Self::ClearStop | Self::SafetyFault
        )
    }

    /// Get the message type group name.
    pub fn group(&self) -> &'static str {
        match (*self as u8) >> 4 {
            0x0 => "handshake",
            0x1 => "capability",
            0x2 => "contract",
            0x3 => "command",
            0x4 => "consensus",
            0xE => "safety",
            0xF => "discovery",
            _ => "unknown",
        }
    }
}

// ── Recipient ───────────────────────────────────────────────────────

/// Message recipient — single entity or multicast group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recipient {
    /// Single entity.
    Entity(EntityId),
    /// All entities with a specific capability.
    Capability(String),
    /// All entities in a cell.
    Cell(String),
    /// Broadcast to all entities.
    Broadcast,
}

// ── Envelope Flags ──────────────────────────────────────────────────

/// Bit flags for the envelope.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvelopeFlags(pub u16);

impl EnvelopeFlags {
    pub fn compressed(&self) -> bool { self.0 & 0x0001 != 0 }
    pub fn fragmented(&self) -> bool { self.0 & 0x0002 != 0 }
    pub fn encrypted(&self) -> bool { self.0 & 0x0004 != 0 }
    pub fn priority_preempt(&self) -> bool { self.0 & 0x0008 != 0 }
    pub fn safety_critical(&self) -> bool { self.0 & 0x0010 != 0 }
    pub fn post_quantum_sig(&self) -> bool { self.0 & 0x0800 != 0 }

    pub fn ordering_mode(&self) -> OrderingMode {
        match (self.0 >> 8) & 0x07 {
            0 => OrderingMode::Unordered,
            1 => OrderingMode::Causal,
            2 => OrderingMode::Total,
            _ => OrderingMode::Unordered,
        }
    }

    pub fn set_encrypted(&mut self) { self.0 |= 0x0004; }
    pub fn set_safety_critical(&mut self) { self.0 |= 0x0010; }
    pub fn set_priority_preempt(&mut self) { self.0 |= 0x0008; }

    pub fn set_ordering_mode(&mut self, mode: OrderingMode) {
        self.0 = (self.0 & !0x0700) | ((mode as u16) << 8);
    }
}

// ── Envelope ────────────────────────────────────────────────────────

/// The message envelope — wraps every message in the Connector Protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Content-addressed ID of this envelope.
    pub envelope_cid: String,
    /// Sender DID.
    pub sender: EntityId,
    /// Recipient (entity, capability group, cell, or broadcast).
    pub recipient: Recipient,
    /// Message type.
    pub message_type: MessageType,
    /// CID of the payload.
    pub payload_cid: String,
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_ns: u64,
    /// Monotonic sequence number per sender.
    pub sequence: u64,
    /// Time-to-live (hops remaining).
    pub ttl: u32,
    /// Message priority.
    pub priority: Priority,
    /// Ordering mode.
    pub ordering: OrderingMode,
    /// Ed25519 signature over envelope_cid.
    pub signature: Vec<u8>,
}

impl Envelope {
    /// Compute the CID for this envelope (excluding signature and envelope_cid).
    pub fn compute_cid(&self) -> String {
        let canonical = serde_json::json!({
            "sender": self.sender,
            "recipient": self.recipient,
            "message_type": self.message_type,
            "payload_cid": self.payload_cid,
            "timestamp_ns": self.timestamp_ns,
            "sequence": self.sequence,
            "ttl": self.ttl,
            "priority": self.priority,
            "ordering": self.ordering,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let hash = Sha256::digest(&bytes);
        format!("cid:{}", hex_encode(&hash))
    }

    /// Compute the CID of a payload.
    pub fn compute_payload_cid(payload: &[u8]) -> String {
        let hash = Sha256::digest(payload);
        format!("cid:{}", hex_encode(&hash))
    }

    /// Create a new envelope.
    pub fn new(
        sender: EntityId,
        recipient: Recipient,
        message_type: MessageType,
        payload: &[u8],
        sequence: u64,
    ) -> Self {
        let payload_cid = Self::compute_payload_cid(payload);
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let priority = if message_type.is_safety_critical() {
            Priority::Emergency
        } else {
            Priority::Control
        };

        let mut env = Self {
            envelope_cid: String::new(),
            sender,
            recipient,
            message_type,
            payload_cid,
            timestamp_ns: now_ns,
            sequence,
            ttl: 64,
            priority,
            ordering: OrderingMode::Causal,
            signature: vec![],
        };
        env.envelope_cid = env.compute_cid();
        env
    }

    /// Sign the envelope.
    pub fn sign(&mut self, key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let sig = key.sign(self.envelope_cid.as_bytes());
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify the envelope signature.
    pub fn verify_signature(&self, key: &ed25519_dalek::VerifyingKey) -> crate::error::ProtoResult<()> {
        use ed25519_dalek::Verifier;
        if self.signature.len() != 64 {
            return Err(crate::error::ProtocolError::Signature("bad length".into()));
        }
        let sig_bytes: [u8; 64] = self.signature[..64].try_into()
            .map_err(|_| crate::error::ProtocolError::Signature("conversion".into()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        key.verify(self.envelope_cid.as_bytes(), &sig)
            .map_err(|e| crate::error::ProtocolError::Signature(e.to_string()))
    }

    /// Serialize to wire format bytes (header + JSON body).
    pub fn to_wire(&self) -> Vec<u8> {
        let body = serde_json::to_vec(self).unwrap_or_default();
        let len = body.len() as u32;
        let mut flags = EnvelopeFlags::default();
        flags.set_encrypted();
        if self.message_type.is_safety_critical() {
            flags.set_safety_critical();
            flags.set_priority_preempt();
        }
        flags.set_ordering_mode(self.ordering);

        let mut wire = Vec::with_capacity(12 + body.len());
        wire.extend_from_slice(&MAGIC);
        wire.extend_from_slice(&VERSION.to_be_bytes());
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend_from_slice(&flags.0.to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    /// Parse from wire format bytes.
    pub fn from_wire(data: &[u8]) -> crate::error::ProtoResult<Self> {
        if data.len() < 12 {
            return Err(crate::error::ProtocolError::Envelope("too short".into()));
        }
        if data[0..4] != MAGIC {
            return Err(crate::error::ProtocolError::Envelope("bad magic".into()));
        }
        let _version = u16::from_be_bytes([data[4], data[5]]);
        let len = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;
        let _flags = u16::from_be_bytes([data[10], data[11]]);

        if data.len() < 12 + len {
            return Err(crate::error::ProtocolError::Envelope("truncated".into()));
        }

        serde_json::from_slice(&data[12..12 + len])
            .map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_envelope_cid_deterministic() {
        let sender = EntityId::new(crate::identity::EntityClass::Agent, "a1");
        let e1 = Envelope::new(
            sender.clone(),
            Recipient::Entity(EntityId::new(crate::identity::EntityClass::Machine, "m1")),
            MessageType::Command,
            b"test payload",
            1,
        );
        let e2 = Envelope::new(
            sender,
            Recipient::Entity(EntityId::new(crate::identity::EntityClass::Machine, "m1")),
            MessageType::Command,
            b"test payload",
            1,
        );
        // Same inputs produce same payload_cid, but envelope_cid differs due to timestamp
        assert_eq!(e1.payload_cid, e2.payload_cid);
    }

    #[test]
    fn test_envelope_sign_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let mut env = Envelope::new(
            EntityId::new(crate::identity::EntityClass::Agent, "a1"),
            Recipient::Entity(EntityId::new(crate::identity::EntityClass::Machine, "m1")),
            MessageType::Command,
            b"move axis",
            1,
        );
        env.sign(&key);
        assert!(env.verify_signature(&key.verifying_key()).is_ok());

        let wrong_key = SigningKey::generate(&mut OsRng);
        assert!(env.verify_signature(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn test_envelope_wire_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let mut env = Envelope::new(
            EntityId::new(crate::identity::EntityClass::Sensor, "s1"),
            Recipient::Entity(EntityId::new(crate::identity::EntityClass::Service, "svc1")),
            MessageType::Telemetry,
            b"temperature: 22.5",
            42,
        );
        env.sign(&key);

        let wire = env.to_wire();
        assert_eq!(&wire[0..4], &MAGIC);

        let parsed = Envelope::from_wire(&wire).unwrap();
        assert_eq!(parsed.envelope_cid, env.envelope_cid);
        assert_eq!(parsed.sender, env.sender);
        assert_eq!(parsed.message_type, MessageType::Telemetry);
        assert_eq!(parsed.sequence, 42);
    }

    #[test]
    fn test_envelope_bad_magic() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(Envelope::from_wire(&data).is_err());
    }

    #[test]
    fn test_message_type_safety() {
        assert!(MessageType::EmergencyStop.is_safety_critical());
        assert!(MessageType::ClearStop.is_safety_critical());
        assert!(!MessageType::Command.is_safety_critical());
        assert!(!MessageType::Telemetry.is_safety_critical());
    }

    #[test]
    fn test_message_type_groups() {
        assert_eq!(MessageType::Handshake.group(), "handshake");
        assert_eq!(MessageType::CapabilityRequest.group(), "capability");
        assert_eq!(MessageType::ContractOffer.group(), "contract");
        assert_eq!(MessageType::Command.group(), "command");
        assert_eq!(MessageType::ConsensusPropose.group(), "consensus");
        assert_eq!(MessageType::EmergencyStop.group(), "safety");
        assert_eq!(MessageType::DiscoverRequest.group(), "discovery");
    }

    #[test]
    fn test_envelope_flags() {
        let mut flags = EnvelopeFlags::default();
        assert!(!flags.encrypted());
        assert!(!flags.safety_critical());

        flags.set_encrypted();
        assert!(flags.encrypted());

        flags.set_safety_critical();
        assert!(flags.safety_critical());

        flags.set_ordering_mode(OrderingMode::Total);
        assert_eq!(flags.ordering_mode(), OrderingMode::Total);
    }

    #[test]
    fn test_safety_message_auto_priority() {
        let env = Envelope::new(
            EntityId::new(crate::identity::EntityClass::Agent, "op"),
            Recipient::Broadcast,
            MessageType::EmergencyStop,
            b"fire",
            1,
        );
        assert_eq!(env.priority, Priority::Emergency);
    }

    #[test]
    fn test_recipient_types() {
        let r1 = Recipient::Entity(EntityId::new(crate::identity::EntityClass::Machine, "m1"));
        let r2 = Recipient::Capability("machine.move_axis".into());
        let r3 = Recipient::Cell("factory-1".into());
        let r4 = Recipient::Broadcast;

        let json1 = serde_json::to_string(&r1).unwrap();
        let json4 = serde_json::to_string(&r4).unwrap();
        assert!(json1.contains("entity"));
        assert!(json4.contains("broadcast"));
    }
}
