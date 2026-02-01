//! Codec traits and implementations for VAC objects

use cid::Cid;
use serde::{de::DeserializeOwned, Serialize};

use crate::error::{VacError, VacResult};

/// Trait for objects that can be content-addressed
pub trait ContentAddressable: Serialize + DeserializeOwned {
    /// Compute the CID for this object
    fn cid(&self) -> VacResult<Cid> {
        crate::cid::compute_cid(self)
    }
    
    /// Serialize to DAG-CBOR bytes
    fn to_bytes(&self) -> VacResult<Vec<u8>> {
        crate::cid::to_dag_cbor(self)
    }
    
    /// Deserialize from DAG-CBOR bytes
    fn from_bytes(bytes: &[u8]) -> VacResult<Self> {
        ciborium::from_reader(bytes)
            .map_err(|e| VacError::CodecError(e.to_string()))
    }
}

// Implement ContentAddressable for all core types
impl ContentAddressable for crate::types::Event {}
impl ContentAddressable for crate::types::ClaimBundle {}
impl ContentAddressable for crate::types::Bracket {}
impl ContentAddressable for crate::types::Node {}
impl ContentAddressable for crate::types::Frame {}
impl ContentAddressable for crate::types::BlockHeader {}
impl ContentAddressable for crate::types::ManifestRoot {}
impl ContentAddressable for crate::types::VaultPatch {}
impl ContentAddressable for crate::types::InterferenceEdge {}
impl ContentAddressable for crate::types::ProllyNode {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Event, Source, SourceKind};
    
    #[test]
    fn test_roundtrip() {
        let source = Source {
            kind: SourceKind::User,
            principal_id: "did:key:z6Mk...".to_string(),
        };
        let event = Event::new(1706764800000, Cid::default(), source);
        
        // Serialize
        let bytes = event.to_bytes().unwrap();
        
        // Deserialize
        let event2: Event = Event::from_bytes(&bytes).unwrap();
        
        assert_eq!(event.ts, event2.ts);
        assert_eq!(event.type_, event2.type_);
    }
    
    #[test]
    fn test_cid_deterministic() {
        let source = Source {
            kind: SourceKind::User,
            principal_id: "did:key:z6Mk...".to_string(),
        };
        let event = Event::new(1706764800000, Cid::default(), source.clone());
        let event2 = Event::new(1706764800000, Cid::default(), source);
        
        // Same content should produce same CID
        assert_eq!(event.cid().unwrap(), event2.cid().unwrap());
    }
}
