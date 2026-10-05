//! Identity Layer (Layer 1) — DICE, SPIFFE, DID-based entity identity.
//!
//! Every participant in the Connector Protocol is an Entity with a DID,
//! identity proof, capabilities, and safety level.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ProtocolError, ProtoResult};
use crate::safety::SafetyIntegrityLevel;

// ── Entity Class ────────────────────────────────────────────────────

/// Classification of protocol entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityClass {
    Agent,
    Machine,
    Device,
    Service,
    Sensor,
    Actuator,
    Composite,
}

impl EntityClass {
    /// Default SIL for each entity class.
    pub fn default_sil(&self) -> SafetyIntegrityLevel {
        match self {
            Self::Agent => SafetyIntegrityLevel::SIL0,
            Self::Machine => SafetyIntegrityLevel::SIL3,
            Self::Device => SafetyIntegrityLevel::SIL1,
            Self::Service => SafetyIntegrityLevel::SIL0,
            Self::Sensor => SafetyIntegrityLevel::SIL1,
            Self::Actuator => SafetyIntegrityLevel::SIL3,
            Self::Composite => SafetyIntegrityLevel::SIL3,
        }
    }

    /// Whether this entity class requires real-time communication.
    pub fn requires_realtime(&self) -> bool {
        matches!(self, Self::Machine | Self::Device | Self::Sensor | Self::Actuator | Self::Composite)
    }
}

impl std::fmt::Display for EntityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Agent => write!(f, "agent"),
            Self::Machine => write!(f, "machine"),
            Self::Device => write!(f, "device"),
            Self::Service => write!(f, "service"),
            Self::Sensor => write!(f, "sensor"),
            Self::Actuator => write!(f, "actuator"),
            Self::Composite => write!(f, "composite"),
        }
    }
}

// ── Identity Proof ──────────────────────────────────────────────────

/// How an entity proves its identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum IdentityProof {
    /// Hardware root-of-trust via DICE composition engine.
    Dice {
        firmware_hash: String,
        layer_hashes: Vec<String>,
        certificate_chain: Vec<Vec<u8>>,
    },
    /// Software workload identity via SPIFFE SVID.
    Spiffe {
        spiffe_id: String,
        svid: Vec<u8>,
        trust_domain: String,
    },
    /// Lightweight self-signed Ed25519 identity.
    SelfSigned {
        public_key: Vec<u8>,
        signature: Vec<u8>,
        nonce: [u8; 16],
    },
}

impl IdentityProof {
    /// Create a self-signed identity proof.
    pub fn self_signed(key: &SigningKey, nonce: [u8; 16]) -> Self {
        let pubkey = key.verifying_key().to_bytes().to_vec();
        let mut msg = Vec::new();
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(&nonce);
        let sig = key.sign(&msg);
        Self::SelfSigned {
            public_key: pubkey,
            signature: sig.to_bytes().to_vec(),
            nonce,
        }
    }

    /// Verify a self-signed identity proof.
    pub fn verify_self_signed(&self) -> ProtoResult<VerifyingKey> {
        match self {
            Self::SelfSigned { public_key, signature, nonce } => {
                if public_key.len() != 32 || signature.len() != 64 {
                    return Err(ProtocolError::Identity("invalid key/sig length".into()));
                }
                let vk_bytes: [u8; 32] = public_key[..32].try_into().unwrap();
                let vk = VerifyingKey::from_bytes(&vk_bytes)
                    .map_err(|e| ProtocolError::Identity(e.to_string()))?;
                let sig_bytes: [u8; 64] = signature[..64].try_into().unwrap();
                let sig = Signature::from_bytes(&sig_bytes);
                let mut msg = Vec::new();
                msg.extend_from_slice(public_key);
                msg.extend_from_slice(nonce);
                vk.verify(&msg, &sig)
                    .map_err(|e| ProtocolError::Identity(e.to_string()))?;
                Ok(vk)
            }
            _ => Err(ProtocolError::Identity("not a self-signed proof".into())),
        }
    }

    /// Create a mock DICE proof for testing.
    pub fn mock_dice(firmware_hash: &str) -> Self {
        Self::Dice {
            firmware_hash: firmware_hash.to_string(),
            layer_hashes: vec![firmware_hash.to_string()],
            certificate_chain: vec![],
        }
    }

    /// Create a mock SPIFFE proof for testing.
    pub fn mock_spiffe(spiffe_id: &str, trust_domain: &str) -> Self {
        Self::Spiffe {
            spiffe_id: spiffe_id.to_string(),
            svid: vec![],
            trust_domain: trust_domain.to_string(),
        }
    }
}

// ── DID ─────────────────────────────────────────────────────────────

/// A Decentralized Identifier for the Connector Protocol.
/// Format: did:connector:<entity_class>:<unique_id>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub String);

impl EntityId {
    /// Create a new DID for an entity.
    pub fn new(entity_class: EntityClass, unique_id: &str) -> Self {
        Self(format!("did:connector:{}:{}", entity_class, unique_id))
    }

    /// Generate a DID from a public key hash.
    pub fn from_key(entity_class: EntityClass, public_key: &[u8]) -> Self {
        let hash = Sha256::digest(public_key);
        let short = hex_encode(&hash[..16]);
        Self::new(entity_class, &short)
    }

    /// Parse the entity class from the DID.
    pub fn entity_class(&self) -> Option<EntityClass> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() >= 4 && parts[0] == "did" && parts[1] == "connector" {
            match parts[2] {
                "agent" => Some(EntityClass::Agent),
                "machine" => Some(EntityClass::Machine),
                "device" => Some(EntityClass::Device),
                "service" => Some(EntityClass::Service),
                "sensor" => Some(EntityClass::Sensor),
                "actuator" => Some(EntityClass::Actuator),
                "composite" => Some(EntityClass::Composite),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── DID Document ────────────────────────────────────────────────────

/// Connector extensions to the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorExtensions {
    pub entity_class: EntityClass,
    pub safety_level: SafetyIntegrityLevel,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub safety_constraints: HashMap<String, serde_json::Value>,
    pub clock_domain: Option<String>,
    pub attestation_type: Option<String>,
    pub firmware_hash: Option<String>,
}

/// A DID Document with Connector Protocol extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    pub id: EntityId,
    pub authentication: Vec<AuthenticationMethod>,
    pub service_endpoints: Vec<ServiceEndpoint>,
    pub extensions: ConnectorExtensions,
    pub created: i64,
    pub updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationMethod {
    pub id: String,
    pub method_type: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
}

impl DIDDocument {
    /// Create a new DID document.
    pub fn new(
        entity_id: EntityId,
        entity_class: EntityClass,
        public_key: &[u8],
        endpoint: &str,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            id: entity_id.clone(),
            authentication: vec![AuthenticationMethod {
                id: format!("{}#key-1", entity_id),
                method_type: "Ed25519VerificationKey2020".to_string(),
                public_key: public_key.to_vec(),
            }],
            service_endpoints: vec![ServiceEndpoint {
                id: format!("{}#cp", entity_id),
                service_type: "ConnectorProtocol".to_string(),
                endpoint: endpoint.to_string(),
            }],
            extensions: ConnectorExtensions {
                entity_class,
                safety_level: entity_class.default_sil(),
                capabilities: vec![],
                safety_constraints: HashMap::new(),
                clock_domain: None,
                attestation_type: None,
                firmware_hash: None,
            },
            created: now,
            updated: now,
        }
    }

    /// Get the primary public key.
    pub fn primary_key(&self) -> Option<&[u8]> {
        self.authentication.first().map(|a| a.public_key.as_slice())
    }

    /// Get the primary service endpoint.
    pub fn primary_endpoint(&self) -> Option<&str> {
        self.service_endpoints.first().map(|s| s.endpoint.as_str())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Entity Registry ─────────────────────────────────────────────────

/// Registry of known entities in a cell.
pub struct EntityRegistry {
    entities: HashMap<EntityId, DIDDocument>,
}

impl EntityRegistry {
    pub fn new() -> Self {
        Self { entities: HashMap::new() }
    }

    pub fn register(&mut self, doc: DIDDocument) {
        self.entities.insert(doc.id.clone(), doc);
    }

    pub fn get(&self, id: &EntityId) -> ProtoResult<&DIDDocument> {
        self.entities.get(id)
            .ok_or_else(|| ProtocolError::NotFound(format!("Entity {}", id)))
    }

    pub fn resolve(&self, did_str: &str) -> ProtoResult<&DIDDocument> {
        let id = EntityId(did_str.to_string());
        self.get(&id)
    }

    pub fn discover_by_class(&self, class: EntityClass) -> Vec<&DIDDocument> {
        self.entities.values()
            .filter(|d| d.extensions.entity_class == class)
            .collect()
    }

    pub fn discover_by_capability(&self, cap: &str) -> Vec<&DIDDocument> {
        self.entities.values()
            .filter(|d| d.extensions.capabilities.contains(&cap.to_string()))
            .collect()
    }

    pub fn remove(&mut self, id: &EntityId) -> Option<DIDDocument> {
        self.entities.remove(id)
    }

    pub fn len(&self) -> usize { self.entities.len() }
    pub fn is_empty(&self) -> bool { self.entities.is_empty() }
}

impl Default for EntityRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_entity_id_creation() {
        let id = EntityId::new(EntityClass::Machine, "cnc-mill-7");
        assert_eq!(id.as_str(), "did:connector:machine:cnc-mill-7");
        assert_eq!(id.entity_class(), Some(EntityClass::Machine));
    }

    #[test]
    fn test_entity_id_from_key() {
        let key = SigningKey::generate(&mut OsRng);
        let id = EntityId::from_key(EntityClass::Agent, key.verifying_key().as_bytes());
        assert!(id.as_str().starts_with("did:connector:agent:"));
        assert_eq!(id.entity_class(), Some(EntityClass::Agent));
    }

    #[test]
    fn test_all_entity_classes() {
        for (class, name) in [
            (EntityClass::Agent, "agent"),
            (EntityClass::Machine, "machine"),
            (EntityClass::Device, "device"),
            (EntityClass::Service, "service"),
            (EntityClass::Sensor, "sensor"),
            (EntityClass::Actuator, "actuator"),
            (EntityClass::Composite, "composite"),
        ] {
            let id = EntityId::new(class, "test");
            assert_eq!(id.entity_class(), Some(class));
            assert!(id.as_str().contains(name));
        }
    }

    #[test]
    fn test_entity_class_default_sil() {
        assert_eq!(EntityClass::Agent.default_sil(), SafetyIntegrityLevel::SIL0);
        assert_eq!(EntityClass::Machine.default_sil(), SafetyIntegrityLevel::SIL3);
        assert_eq!(EntityClass::Device.default_sil(), SafetyIntegrityLevel::SIL1);
        assert_eq!(EntityClass::Service.default_sil(), SafetyIntegrityLevel::SIL0);
        assert_eq!(EntityClass::Actuator.default_sil(), SafetyIntegrityLevel::SIL3);
    }

    #[test]
    fn test_entity_class_realtime() {
        assert!(!EntityClass::Agent.requires_realtime());
        assert!(EntityClass::Machine.requires_realtime());
        assert!(EntityClass::Sensor.requires_realtime());
        assert!(!EntityClass::Service.requires_realtime());
    }

    #[test]
    fn test_self_signed_identity_proof() {
        let key = SigningKey::generate(&mut OsRng);
        let nonce = [42u8; 16];
        let proof = IdentityProof::self_signed(&key, nonce);
        let vk = proof.verify_self_signed().unwrap();
        assert_eq!(vk, key.verifying_key());
    }

    #[test]
    fn test_self_signed_wrong_key_fails() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let proof = IdentityProof::self_signed(&key1, [0u8; 16]);

        // Tamper with the public key
        if let IdentityProof::SelfSigned { signature, nonce, .. } = &proof {
            let tampered = IdentityProof::SelfSigned {
                public_key: key2.verifying_key().to_bytes().to_vec(),
                signature: signature.clone(),
                nonce: *nonce,
            };
            assert!(tampered.verify_self_signed().is_err());
        }
    }

    #[test]
    fn test_did_document_creation() {
        let key = SigningKey::generate(&mut OsRng);
        let entity_id = EntityId::new(EntityClass::Machine, "cnc-1");
        let doc = DIDDocument::new(
            entity_id.clone(),
            EntityClass::Machine,
            key.verifying_key().as_bytes(),
            "noise://192.168.1.100:7100",
        );

        assert_eq!(doc.id, entity_id);
        assert_eq!(doc.extensions.entity_class, EntityClass::Machine);
        assert_eq!(doc.extensions.safety_level, SafetyIntegrityLevel::SIL3);
        assert!(doc.primary_key().is_some());
        assert_eq!(doc.primary_endpoint(), Some("noise://192.168.1.100:7100"));
    }

    #[test]
    fn test_did_document_serde() {
        let key = SigningKey::generate(&mut OsRng);
        let entity_id = EntityId::new(EntityClass::Sensor, "temp-1");
        let doc = DIDDocument::new(
            entity_id,
            EntityClass::Sensor,
            key.verifying_key().as_bytes(),
            "noise://10.0.0.5:7100",
        );
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: DIDDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.extensions.entity_class, EntityClass::Sensor);
    }

    #[test]
    fn test_entity_registry() {
        let key = SigningKey::generate(&mut OsRng);
        let mut reg = EntityRegistry::new();

        let doc1 = DIDDocument::new(
            EntityId::new(EntityClass::Machine, "m1"),
            EntityClass::Machine,
            key.verifying_key().as_bytes(),
            "noise://host:7100",
        );
        let doc2 = DIDDocument::new(
            EntityId::new(EntityClass::Sensor, "s1"),
            EntityClass::Sensor,
            key.verifying_key().as_bytes(),
            "noise://host:7101",
        );

        reg.register(doc1);
        reg.register(doc2);

        assert_eq!(reg.len(), 2);
        assert!(reg.get(&EntityId::new(EntityClass::Machine, "m1")).is_ok());
        assert_eq!(reg.discover_by_class(EntityClass::Machine).len(), 1);
        assert_eq!(reg.discover_by_class(EntityClass::Sensor).len(), 1);
        assert_eq!(reg.discover_by_class(EntityClass::Agent).len(), 0);
    }

    #[test]
    fn test_entity_registry_resolve() {
        let key = SigningKey::generate(&mut OsRng);
        let mut reg = EntityRegistry::new();
        reg.register(DIDDocument::new(
            EntityId::new(EntityClass::Agent, "a1"),
            EntityClass::Agent,
            key.verifying_key().as_bytes(),
            "noise://host:7100",
        ));

        assert!(reg.resolve("did:connector:agent:a1").is_ok());
        assert!(reg.resolve("did:connector:agent:missing").is_err());
    }
}
