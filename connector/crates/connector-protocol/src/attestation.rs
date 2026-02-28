//! Device Attestation (SPDM/DICE) — hardware root-of-trust verification.
//!
//! Before any entity joins a Connector cell, it must prove its identity
//! and firmware integrity via DICE chain and SPDM attestation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::EntityId;

// ── Firmware Measurement ────────────────────────────────────────────

/// A single firmware layer measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareMeasurement {
    pub layer: u32,
    pub description: String,
    pub hash: String,
}

// ── Attestation Evidence ────────────────────────────────────────────

/// Evidence provided by a device during attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub entity_id: EntityId,
    pub measurements: Vec<FirmwareMeasurement>,
    pub certificate_chain: Vec<Vec<u8>>,
    pub runtime_hash: String,
    pub timestamp: i64,
    pub nonce: [u8; 16],
}

// ── Attestation Result ──────────────────────────────────────────────

/// Result of attestation verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationResult {
    /// All measurements match known-good values.
    Verified,
    /// One or more measurements don't match.
    Failed { reason: String },
    /// No known-good measurements to compare against (first-time enrollment).
    Enrolled,
}

// ── Attestation Verifier ────────────────────────────────────────────

/// Verifies device attestation evidence against known-good measurements.
pub struct AttestationVerifier {
    /// entity_id → known-good measurement hashes per layer
    known_good: HashMap<EntityId, Vec<String>>,
    /// Results log
    results: Vec<(EntityId, AttestationResult, i64)>,
    /// Re-attestation interval in milliseconds
    pub reattest_interval_ms: i64,
}

impl AttestationVerifier {
    pub fn new() -> Self {
        Self {
            known_good: HashMap::new(),
            results: Vec::new(),
            reattest_interval_ms: 300_000, // 5 minutes
        }
    }

    /// Enroll known-good measurements for an entity.
    pub fn enroll(&mut self, entity_id: EntityId, measurement_hashes: Vec<String>) {
        self.known_good.insert(entity_id, measurement_hashes);
    }

    /// Verify attestation evidence.
    pub fn verify(&mut self, evidence: &AttestationEvidence) -> AttestationResult {
        let now = chrono::Utc::now().timestamp_millis();

        let result = if let Some(known) = self.known_good.get(&evidence.entity_id) {
            let evidence_hashes: Vec<&str> = evidence.measurements.iter()
                .map(|m| m.hash.as_str())
                .collect();

            if known.len() != evidence_hashes.len() {
                AttestationResult::Failed {
                    reason: format!(
                        "Measurement count mismatch: expected {}, got {}",
                        known.len(), evidence_hashes.len()
                    ),
                }
            } else {
                let mut mismatches = Vec::new();
                for (i, (expected, actual)) in known.iter().zip(evidence_hashes.iter()).enumerate() {
                    if expected != actual {
                        mismatches.push(format!("layer {}: expected {}, got {}", i, expected, actual));
                    }
                }
                if mismatches.is_empty() {
                    AttestationResult::Verified
                } else {
                    AttestationResult::Failed {
                        reason: format!("Measurement mismatch: {}", mismatches.join("; ")),
                    }
                }
            }
        } else {
            // First time — auto-enroll
            let hashes: Vec<String> = evidence.measurements.iter()
                .map(|m| m.hash.clone())
                .collect();
            self.known_good.insert(evidence.entity_id.clone(), hashes);
            AttestationResult::Enrolled
        };

        self.results.push((evidence.entity_id.clone(), result.clone(), now));
        result
    }

    /// Check if an entity needs re-attestation.
    pub fn needs_reattestation(&self, entity_id: &EntityId) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        let last = self.results.iter()
            .rev()
            .find(|(id, result, _)| id == entity_id && *result == AttestationResult::Verified)
            .map(|(_, _, t)| *t);

        match last {
            Some(t) => now - t > self.reattest_interval_ms,
            None => true,
        }
    }

    /// Compute a DICE-derived identity hash from firmware layers.
    pub fn compute_dice_identity(layers: &[&[u8]]) -> String {
        let mut current = [0u8; 32];
        for layer in layers {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(layer);
            current = hasher.finalize().into();
        }
        current.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn result_count(&self) -> usize { self.results.len() }
}

impl Default for AttestationVerifier {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EntityClass;

    fn did(n: &str) -> EntityId { EntityId::new(EntityClass::Device, n) }

    fn make_evidence(entity: &EntityId, hashes: Vec<&str>) -> AttestationEvidence {
        AttestationEvidence {
            entity_id: entity.clone(),
            measurements: hashes.iter().enumerate().map(|(i, h)| FirmwareMeasurement {
                layer: i as u32,
                description: format!("layer_{}", i),
                hash: h.to_string(),
            }).collect(),
            certificate_chain: vec![],
            runtime_hash: "rt_hash".into(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            nonce: [0u8; 16],
        }
    }

    #[test]
    fn test_first_time_enrollment() {
        let mut verifier = AttestationVerifier::new();
        let d1 = did("dev1");
        let evidence = make_evidence(&d1, vec!["aaa", "bbb"]);
        let result = verifier.verify(&evidence);
        assert_eq!(result, AttestationResult::Enrolled);
    }

    #[test]
    fn test_verified_after_enrollment() {
        let mut verifier = AttestationVerifier::new();
        let d1 = did("dev1");

        // First time → enroll
        let ev1 = make_evidence(&d1, vec!["aaa", "bbb"]);
        verifier.verify(&ev1);

        // Same measurements → verified
        let ev2 = make_evidence(&d1, vec!["aaa", "bbb"]);
        assert_eq!(verifier.verify(&ev2), AttestationResult::Verified);
    }

    #[test]
    fn test_measurement_mismatch_fails() {
        let mut verifier = AttestationVerifier::new();
        let d1 = did("dev1");
        verifier.enroll(d1.clone(), vec!["aaa".into(), "bbb".into()]);

        let evidence = make_evidence(&d1, vec!["aaa", "TAMPERED"]);
        let result = verifier.verify(&evidence);
        assert!(matches!(result, AttestationResult::Failed { .. }));
    }

    #[test]
    fn test_measurement_count_mismatch() {
        let mut verifier = AttestationVerifier::new();
        let d1 = did("dev1");
        verifier.enroll(d1.clone(), vec!["aaa".into(), "bbb".into()]);

        let evidence = make_evidence(&d1, vec!["aaa"]); // only 1 layer
        let result = verifier.verify(&evidence);
        assert!(matches!(result, AttestationResult::Failed { .. }));
    }

    #[test]
    fn test_dice_identity_computation() {
        let id1 = AttestationVerifier::compute_dice_identity(&[b"firmware_v1", b"app_v1"]);
        let id2 = AttestationVerifier::compute_dice_identity(&[b"firmware_v1", b"app_v1"]);
        let id3 = AttestationVerifier::compute_dice_identity(&[b"firmware_v1", b"app_v2"]);

        assert_eq!(id1, id2); // deterministic
        assert_ne!(id1, id3); // different app → different identity
    }

    #[test]
    fn test_needs_reattestation() {
        let mut verifier = AttestationVerifier::new();
        verifier.reattest_interval_ms = 100; // 100ms interval

        let d1 = did("dev1");
        assert!(verifier.needs_reattestation(&d1)); // never attested

        verifier.enroll(d1.clone(), vec!["a".into()]);
        let ev = make_evidence(&d1, vec!["a"]);
        verifier.verify(&ev);

        // Just verified — should NOT need re-attestation yet
        assert!(!verifier.needs_reattestation(&d1));

        // Manually backdate the result to simulate passage of time
        if let Some(entry) = verifier.results.last_mut() {
            entry.2 -= 200; // 200ms ago
        }
        assert!(verifier.needs_reattestation(&d1));
    }
}
