//! CNP Codec — L1 Content-Addressed Encoding/Decoding.
//!
//! Provides deterministic serialization (DAG-CBOR via serde_json fallback),
//! content-addressing (SHA-256 CID), and frame construction for all CNP messages.
//!
//! Every message that enters the CNP stack is first serialized to a CnpFrame
//! with a content identifier, then passed up to L2 for encryption.

use sha2::{Sha256, Digest};
use crate::cnp::types::{CnpMessage, CnpFrame, CnpError, CnpResult, CNP_MAX_MESSAGE_BYTES};

// ═══════════════════════════════════════════════════════════════
// CnpCodec — L1 encode/decode
// ═══════════════════════════════════════════════════════════════

/// L1 Codec: serializes CnpMessage → CnpFrame (with CID) and back.
pub struct CnpCodec;

impl CnpCodec {
    /// Encode a CnpMessage into a content-addressed CnpFrame.
    ///
    /// Pipeline: CnpMessage → JSON bytes → SHA-256 CID → CnpFrame
    /// (In production, replace JSON with DAG-CBOR for deterministic encoding.)
    pub fn encode(message: &CnpMessage) -> CnpResult<CnpFrame> {
        // Serialize to bytes (JSON as DAG-CBOR stand-in)
        let data = serde_json::to_vec(message).map_err(|e| CnpError::CodecError {
            detail: format!("Serialization failed: {}", e),
        })?;

        let size_bytes = data.len() as u64;
        if size_bytes > CNP_MAX_MESSAGE_BYTES {
            return Err(CnpError::PayloadTooLarge {
                size: size_bytes,
                max: CNP_MAX_MESSAGE_BYTES,
            });
        }

        // Compute content identifier (SHA-256)
        let cid = compute_cid(&data);

        Ok(CnpFrame { cid, data, size_bytes })
    }

    /// Decode a CnpFrame back into a CnpMessage.
    ///
    /// Verifies the CID matches the data before deserializing.
    pub fn decode(frame: &CnpFrame) -> CnpResult<CnpMessage> {
        // Verify content integrity
        let computed_cid = compute_cid(&frame.data);
        if computed_cid != frame.cid {
            return Err(CnpError::CodecError {
                detail: format!(
                    "CID mismatch: expected {}, computed {}",
                    frame.cid, computed_cid
                ),
            });
        }

        // Deserialize
        serde_json::from_slice(&frame.data).map_err(|e| CnpError::CodecError {
            detail: format!("Deserialization failed: {}", e),
        })
    }

    /// Compute the CID for a CnpMessage without creating a full frame.
    pub fn compute_message_cid(message: &CnpMessage) -> CnpResult<String> {
        let data = serde_json::to_vec(message).map_err(|e| CnpError::CodecError {
            detail: format!("Serialization failed: {}", e),
        })?;
        Ok(compute_cid(&data))
    }

    /// Verify a frame's integrity (CID matches data).
    pub fn verify(frame: &CnpFrame) -> bool {
        compute_cid(&frame.data) == frame.cid
    }
}

// ═══════════════════════════════════════════════════════════════
// CID Computation
// ═══════════════════════════════════════════════════════════════

/// Compute a content identifier from raw bytes.
/// Format: `cnp1-sha256-<hex>` (CNP v1 CID scheme).
fn compute_cid(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    format!("cnp1-sha256-{}", hex::encode(hash))
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cnp::types::{CnpPayload, SensorModality, SensorReading, ActuationCommand, CognitiveMsgType};

    #[test]
    fn test_encode_decode_text() {
        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "hello".into() });
        let frame = CnpCodec::encode(&msg).unwrap();

        assert!(frame.cid.starts_with("cnp1-sha256-"));
        assert!(frame.size_bytes > 0);
        assert!(CnpCodec::verify(&frame));

        let decoded = CnpCodec::decode(&frame).unwrap();
        assert_eq!(decoded.from_agent, "a");
        assert_eq!(decoded.to_agent, "b");
    }

    #[test]
    fn test_cid_determinism() {
        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "deterministic".into() });
        let frame1 = CnpCodec::encode(&msg).unwrap();
        let frame2 = CnpCodec::encode(&msg).unwrap();
        // Same message content → same CID (JSON keys are ordered by serde)
        assert_eq!(frame1.cid, frame2.cid);
    }

    #[test]
    fn test_cid_integrity_check() {
        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "test".into() });
        let mut frame = CnpCodec::encode(&msg).unwrap();

        // Tamper with data
        if !frame.data.is_empty() {
            frame.data[0] ^= 0xFF;
        }
        assert!(!CnpCodec::verify(&frame));
        assert!(CnpCodec::decode(&frame).is_err());
    }

    #[test]
    fn test_encode_sensor_payload() {
        let msg = CnpMessage::new(
            "sensor-hub",
            "fusion",
            CnpPayload::Sensor {
                sensor_id: "imu-001".into(),
                modality: SensorModality::Imu,
                reading: SensorReading::multi(vec![0.01, -9.81, 0.03], "m/s²"),
                timestamp_us: 1_700_000_000_000_000,
            },
        );
        let frame = CnpCodec::encode(&msg).unwrap();
        let decoded = CnpCodec::decode(&frame).unwrap();
        if let CnpPayload::Sensor { sensor_id, .. } = &decoded.payload {
            assert_eq!(sensor_id, "imu-001");
        } else {
            panic!("Expected Sensor payload");
        }
    }

    #[test]
    fn test_encode_actuation_payload() {
        let msg = CnpMessage::new(
            "planner",
            "arm",
            CnpPayload::Actuation {
                target_id: "arm-001".into(),
                command: ActuationCommand::Gripper { open: true, force_n: 5.0 },
                deadline_us: Some(10_000),
            },
        );
        let frame = CnpCodec::encode(&msg).unwrap();
        let decoded = CnpCodec::decode(&frame).unwrap();
        if let CnpPayload::Actuation { command, .. } = &decoded.payload {
            match command {
                ActuationCommand::Gripper { open, force_n } => {
                    assert!(*open);
                    assert!((force_n - 5.0).abs() < f64::EPSILON);
                }
                _ => panic!("Expected Gripper"),
            }
        } else {
            panic!("Expected Actuation payload");
        }
    }

    #[test]
    fn test_encode_cognitive_payload() {
        let msg = CnpMessage::new(
            "thinker-a",
            "thinker-b",
            CnpPayload::Cognitive {
                cognitive_type: CognitiveMsgType::ShareTension {
                    tension_id: "t-1".into(),
                    tension_type: "resource_conflict".into(),
                    magnitude: 0.9,
                    context_cids: vec!["cid-1".into()],
                    description: "Memory contention".into(),
                },
            },
        );
        let frame = CnpCodec::encode(&msg).unwrap();
        let decoded = CnpCodec::decode(&frame).unwrap();
        assert!(decoded.is_cognitive());
    }

    #[test]
    fn test_compute_message_cid() {
        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "cid test".into() });
        let cid = CnpCodec::compute_message_cid(&msg).unwrap();
        let frame = CnpCodec::encode(&msg).unwrap();
        assert_eq!(cid, frame.cid);
    }
}
