//! AgentPacketDnaV1 — the DNA of every Connector network packet.
//!
//! Today's networks carry IP/TCP/HTTP metadata. Connector needs a **genome**
//! that LLMs and tools cannot invent, strip, or forge: seven fixed parameters
//! cryptographically bound to the payload digest.
//!
//! ## The seven genome parameters (agent DNA)
//!
//! | # | Field | Meaning |
//! |---|-------|---------|
//! | 1 | `principal_id` | Cryptographic who — not model text |
//! | 2 | `agent_pid` | Instance / process identity |
//! | 3 | `character_hash` | ACS / character contract — prompt cannot override |
//! | 4 | `contract_hash` | CLS / policy / knowledge contract version |
//! | 5 | `quantum_id` | DockLock / isolation quantum binding |
//! | 6 | `flow_lease_id` | Network flow admission lease |
//! | 7 | `effect_digest` | Exact action + canonical parameters digest |
//!
//! Signature covers genome + `payload_digest` + nonce/expiry. Missing or
//! mutated DNA → fail closed. Header: `x-connector-dna`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PACKET_DNA_SCHEMA: &str = "connector.agent_packet_dna.v1";
pub const PACKET_DNA_HEADER: &str = "x-connector-dna";
pub const PACKET_DNA_GENOME_LEN: usize = 7;

/// The seven genome slots — stable order for canonical signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentGenomeV1 {
    /// 1 — cryptographic principal
    pub principal_id: String,
    /// 2 — agent instance
    pub agent_pid: String,
    /// 3 — character / ACS hash
    pub character_hash: String,
    /// 4 — policy / CLS contract hash
    pub contract_hash: String,
    /// 5 — isolation quantum
    pub quantum_id: String,
    /// 6 — flow lease
    pub flow_lease_id: String,
    /// 7 — exact effect / params digest
    pub effect_digest: String,
}

impl AgentGenomeV1 {
    pub fn as_seven(&self) -> [&str; PACKET_DNA_GENOME_LEN] {
        [
            self.principal_id.as_str(),
            self.agent_pid.as_str(),
            self.character_hash.as_str(),
            self.contract_hash.as_str(),
            self.quantum_id.as_str(),
            self.flow_lease_id.as_str(),
            self.effect_digest.as_str(),
        ]
    }

    pub fn assert_complete(&self) -> Result<(), &'static str> {
        for (i, slot) in self.as_seven().iter().enumerate() {
            if slot.trim().is_empty() {
                return Err(match i {
                    0 => "dna_missing_principal_id",
                    1 => "dna_missing_agent_pid",
                    2 => "dna_missing_character_hash",
                    3 => "dna_missing_contract_hash",
                    4 => "dna_missing_quantum_id",
                    5 => "dna_missing_flow_lease_id",
                    _ => "dna_missing_effect_digest",
                });
            }
        }
        Ok(())
    }
}

/// Full packet DNA: genome + payload bind + signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPacketDnaV1 {
    pub schema: String,
    pub genome: AgentGenomeV1,
    /// SHA-256 hex of the application payload (body / CNP payload / tool args).
    pub payload_digest: String,
    pub nonce: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub hop: u32,
    pub signer_key_id: String,
    pub digest_hex: String,
    pub signature: String,
}

impl AgentPacketDnaV1 {
    pub fn unsigned_preimage(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": PACKET_DNA_SCHEMA,
            "genome": {
                "principal_id": self.genome.principal_id,
                "agent_pid": self.genome.agent_pid,
                "character_hash": self.genome.character_hash,
                "contract_hash": self.genome.contract_hash,
                "quantum_id": self.genome.quantum_id,
                "flow_lease_id": self.genome.flow_lease_id,
                "effect_digest": self.genome.effect_digest,
            },
            "payload_digest": self.payload_digest,
            "nonce": self.nonce,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "hop": self.hop,
            "signer_key_id": self.signer_key_id,
        })
    }

    pub fn compute_digest_hex(&self) -> String {
        let bytes = serde_json::to_vec(&self.unsigned_preimage()).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    pub fn digest_matches(&self) -> bool {
        self.digest_hex == self.compute_digest_hex()
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms > self.expires_at_ms
    }
}

/// Digest arbitrary payload bytes (UTF-8 JSON preferred).
pub fn payload_digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn payload_digest_json(v: &serde_json::Value) -> String {
    let canon = match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(c) = map.get(k) {
                    out.insert(k.clone(), c.clone());
                }
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    };
    let bytes = serde_json::to_vec(&canon).unwrap_or_default();
    payload_digest_bytes(&bytes)
}

/// Effect digest = hash(operation | address | parameter_digest).
pub fn effect_digest_of(operation: &str, address: &str, parameter_digest: &str) -> String {
    let material = format!("{operation}|{address}|{parameter_digest}");
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

fn sign_digest(secret: &[u8], digest_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b"|dna.v1|");
    h.update(digest_hex.as_bytes());
    hex::encode(h.finalize())
}

/// Mint signed DNA. Caller supplies the seven genome slots + payload digest.
pub fn mint_packet_dna(
    secret: &[u8],
    genome: AgentGenomeV1,
    payload_digest: impl Into<String>,
    ttl_ms: i64,
    hop: u32,
    signer_key_id: impl Into<String>,
) -> Result<AgentPacketDnaV1, &'static str> {
    genome.assert_complete()?;
    let now = chrono::Utc::now().timestamp_millis();
    let mut dna = AgentPacketDnaV1 {
        schema: PACKET_DNA_SCHEMA.into(),
        genome,
        payload_digest: payload_digest.into(),
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at_ms: now,
        expires_at_ms: now.saturating_add(ttl_ms.max(1_000)),
        hop,
        signer_key_id: signer_key_id.into(),
        digest_hex: String::new(),
        signature: String::new(),
    };
    dna.digest_hex = dna.compute_digest_hex();
    dna.signature = sign_digest(secret, &dna.digest_hex);
    Ok(dna)
}

/// Verify genome completeness, digest, signature, expiry, and payload bind.
pub fn verify_packet_dna(
    dna: &AgentPacketDnaV1,
    secret: &[u8],
    expected_payload_digest: Option<&str>,
    now_ms: i64,
) -> Result<(), &'static str> {
    if dna.schema != PACKET_DNA_SCHEMA {
        return Err("dna_invalid_schema");
    }
    dna.genome.assert_complete()?;
    if !dna.digest_matches() {
        return Err("dna_digest_mismatch");
    }
    if dna.is_expired(now_ms) {
        return Err("dna_expired");
    }
    let expect_sig = sign_digest(secret, &dna.digest_hex);
    if expect_sig != dna.signature {
        return Err("dna_signature_invalid");
    }
    if let Some(want) = expected_payload_digest {
        if want != dna.payload_digest {
            return Err("dna_payload_digest_mismatch");
        }
    }
    Ok(())
}

pub fn encode_dna_header(dna: &AgentPacketDnaV1) -> Result<String, serde_json::Error> {
    let raw = serde_json::to_vec(dna)?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

pub fn decode_dna_header(value: &str) -> Result<AgentPacketDnaV1, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "dna_header_b64".to_string())?;
    serde_json::from_slice(&raw).map_err(|e| format!("dna_header_json:{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_genome() -> AgentGenomeV1 {
        AgentGenomeV1 {
            principal_id: "prin_1".into(),
            agent_pid: "agent_1".into(),
            character_hash: "char_abc".into(),
            contract_hash: "cls_def".into(),
            quantum_id: "q_1".into(),
            flow_lease_id: "fl_1".into(),
            effect_digest: "eff_1".into(),
        }
    }

    #[test]
    fn dna_roundtrip_and_one_byte_deny() {
        let secret = b"test-dna-secret-32-bytes-minimum!!";
        let dna = mint_packet_dna(secret, sample_genome(), "deadbeef", 60_000, 0, "node-v1").unwrap();
        verify_packet_dna(&dna, secret, Some("deadbeef"), dna.issued_at_ms).unwrap();

        let mut evil = dna.clone();
        evil.genome.principal_id.push('x');
        assert!(verify_packet_dna(&evil, secret, Some("deadbeef"), dna.issued_at_ms).is_err());

        let mut evil2 = dna.clone();
        evil2.payload_digest = "cafebabe".into();
        evil2.digest_hex = evil2.compute_digest_hex();
        // resign would be needed — without resign, digest_matches fails
        assert!(!evil2.digest_matches() || verify_packet_dna(&evil2, secret, Some("cafebabe"), dna.issued_at_ms).is_err());
    }

    #[test]
    fn header_codec() {
        let secret = b"test-dna-secret-32-bytes-minimum!!";
        let dna = mint_packet_dna(secret, sample_genome(), "aa", 60_000, 0, "k").unwrap();
        let h = encode_dna_header(&dna).unwrap();
        let back = decode_dna_header(&h).unwrap();
        assert_eq!(back.genome.agent_pid, "agent_1");
        verify_packet_dna(&back, secret, Some("aa"), back.issued_at_ms).unwrap();
    }

    #[test]
    fn incomplete_genome_refused() {
        let mut g = sample_genome();
        g.character_hash.clear();
        assert!(g.assert_complete().is_err());
    }
}
