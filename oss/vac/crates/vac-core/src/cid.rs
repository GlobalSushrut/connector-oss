//! CID computation for VAC objects
//!
//! Uses CIDv1 + DAG-CBOR + SHA2-256 as specified in arch.md

use cid::Cid;
use multihash::Multihash;
use serde::Serialize;
use sha2::Digest;

use crate::error::{VacError, VacResult};

/// DAG-CBOR multicodec code
const DAG_CBOR_CODE: u64 = 0x71;

/// SHA2-256 multihash code
const SHA256_CODE: u64 = 0x12;

/// Compute CIDv1 for any serializable object using DAG-CBOR + SHA2-256
pub fn compute_cid<T: Serialize>(obj: &T) -> VacResult<Cid> {
    // Serialize to DAG-CBOR
    let bytes = to_dag_cbor(obj)?;
    
    // Compute SHA2-256 hash
    let hash_bytes = sha256(&bytes);
    
    // Create multihash (SHA2-256 = 0x12, 32 bytes)
    let mh = Multihash::<64>::wrap(SHA256_CODE, &hash_bytes)
        .map_err(|e| VacError::CidError(e.to_string()))?;
    
    // Create CIDv1
    let cid = Cid::new_v1(DAG_CBOR_CODE, mh);
    
    Ok(cid)
}

/// Serialize object to DAG-CBOR bytes
pub fn to_dag_cbor<T: Serialize>(obj: &T) -> VacResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(obj, &mut bytes)
        .map_err(|e| VacError::CodecError(e.to_string()))?;
    Ok(bytes)
}

/// Compute SHA2-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a domain-separated SHA2-256 hash: H(domain || data).
/// Prevents cross-context hash collisions between block hashes,
/// manifest hashes, Prolly node hashes, etc.
pub fn sha256_domain(domain: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute hash for a Prolly node with domain separation.
/// H("vac.prolly.v1" || level || num_keys || key_0 || ... || key_n || value_0 || ... || value_n)
pub fn compute_prolly_node_hash(level: u8, keys: &[Vec<u8>], values: &[Cid]) -> [u8; 32] {
    let mut data = Vec::new();
    
    // Level
    data.push(level);
    
    // Number of keys (2 bytes, big endian)
    let num_keys = keys.len() as u16;
    data.extend_from_slice(&num_keys.to_be_bytes());
    
    // Keys (length-prefixed)
    for key in keys {
        let key_len = key.len() as u16;
        data.extend_from_slice(&key_len.to_be_bytes());
        data.extend_from_slice(key);
    }
    
    // Values (CIDs as bytes)
    for value in values {
        data.extend_from_slice(&value.to_bytes());
    }
    
    sha256_domain(b"vac.prolly.v1", &data)
}

/// Compute block hash
/// H(block_no || prev_block_hash || ts || patch_cid || manifest_cid || signatures)
pub fn compute_block_hash(
    block_no: u64,
    prev_block_hash: &[u8; 32],
    ts: i64,
    patch_cid: &Cid,
    manifest_cid: &Cid,
    signatures: &[crate::types::Signature],
) -> VacResult<[u8; 32]> {
    let block_data = BlockHashData {
        block_no,
        prev_block_hash: *prev_block_hash,
        ts,
        patch_cid: patch_cid.clone(),
        manifest_cid: manifest_cid.clone(),
        signatures: signatures.to_vec(),
    };
    
    let bytes = to_dag_cbor(&block_data)?;
    Ok(sha256_domain(b"vac.block.v1", &bytes))
}

#[derive(serde::Serialize)]
struct BlockHashData {
    block_no: u64,
    prev_block_hash: [u8; 32],
    ts: i64,
    patch_cid: Cid,
    manifest_cid: Cid,
    signatures: Vec<crate::types::Signature>,
}

/// Compute manifest hash
pub fn compute_manifest_hash(
    block_no: u64,
    chapter_index_root: &[u8; 32],
    snaptree_roots: &std::collections::BTreeMap<String, [u8; 32]>,
    pcnn_basis_root: &[u8; 32],
    pcnn_mpn_root: &[u8; 32],
    pcnn_ie_root: &[u8; 32],
    body_cas_root: &[u8; 32],
    policy_root: &[u8; 32],
    revocation_root: &[u8; 32],
) -> VacResult<[u8; 32]> {
    let manifest_data = ManifestHashData {
        block_no,
        chapter_index_root: *chapter_index_root,
        snaptree_roots: snaptree_roots.clone(),
        pcnn_basis_root: *pcnn_basis_root,
        pcnn_mpn_root: *pcnn_mpn_root,
        pcnn_ie_root: *pcnn_ie_root,
        body_cas_root: *body_cas_root,
        policy_root: *policy_root,
        revocation_root: *revocation_root,
    };
    
    let bytes = to_dag_cbor(&manifest_data)?;
    Ok(sha256_domain(b"vac.manifest.v1", &bytes))
}

/// Build a structured Prolly tree key for MemPackets.
///
/// Format: `{packet_type}/{subject_id}/{predicate}/{cid_short}`
///
/// Uses `/` as separator to avoid conflicts with `:` in subject IDs and CIDs.
///
/// This ensures:
/// - All packets for a subject are adjacent (range query by subject)
/// - All packets of a type are adjacent (type query)
/// - The tree root CID changes when ANY packet changes (tamper detection)
///
/// Examples:
/// - `extraction/patient:P-44291/allergy/bafy2bzace7f3a`
/// - `action/patient:P-44291/ehr.update_allergy/bafy2bzace9a20`
/// - `llm_raw/patient:P-44291/deepseek/bafy2bzace04bb`
pub fn build_prolly_key(
    packet_type: &str,
    subject_id: &str,
    predicate: &str,
    cid: &Cid,
) -> Vec<u8> {
    let cid_str = cid.to_string();
    let cid_short = if cid_str.len() > 36 { &cid_str[..36] } else { &cid_str };
    format!("{}/{}/{}/{}", packet_type, subject_id, predicate, cid_short)
        .into_bytes()
}

/// Parse a structured Prolly key back into components.
/// Returns (packet_type, subject_id, predicate, cid_short) or None if malformed.
pub fn parse_prolly_key(key: &[u8]) -> Option<(&str, &str, &str, &str)> {
    let s = std::str::from_utf8(key).ok()?;
    let mut parts = s.splitn(4, '/');
    let ptype = parts.next()?;
    let subject = parts.next()?;
    let predicate = parts.next()?;
    let cid_short = parts.next()?;
    Some((ptype, subject, predicate, cid_short))
}

#[derive(serde::Serialize)]
struct ManifestHashData {
    block_no: u64,
    chapter_index_root: [u8; 32],
    snaptree_roots: std::collections::BTreeMap<String, [u8; 32]>,
    pcnn_basis_root: [u8; 32],
    pcnn_mpn_root: [u8; 32],
    pcnn_ie_root: [u8; 32],
    body_cas_root: [u8; 32],
    policy_root: [u8; 32],
    revocation_root: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Event, Source, SourceKind};
    
    #[test]
    fn test_compute_cid() {
        let source = Source {
            kind: SourceKind::User,
            principal_id: "did:key:z6Mk...".to_string(),
        };
        let event = Event::new(1706764800000, Cid::default(), source);
        
        let cid = compute_cid(&event).unwrap();
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), DAG_CBOR_CODE);
    }
    
    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello world");
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_prolly_node_hash() {
        let keys = vec![b"key1".to_vec(), b"key2".to_vec()];
        let values = vec![Cid::default(), Cid::default()];
        
        let hash = compute_prolly_node_hash(0, &keys, &values);
        assert_eq!(hash.len(), 32);
        
        // Same inputs should produce same hash
        let hash2 = compute_prolly_node_hash(0, &keys, &values);
        assert_eq!(hash, hash2);
        
        // Different level should produce different hash
        let hash3 = compute_prolly_node_hash(1, &keys, &values);
        assert_ne!(hash, hash3);
    }
    
    #[test]
    fn test_build_prolly_key() {
        let cid = Cid::default();
        let key = build_prolly_key("extraction", "patient:P-44291", "allergy", &cid);
        let key_str = std::str::from_utf8(&key).unwrap();
        
        assert!(key_str.starts_with("extraction/patient:P-44291/allergy/"));
        // Key should contain the CID prefix (truncated to 20 chars)
        assert!(key_str.len() > "extraction:patient:P-44291:allergy:".len());
    }
    
    #[test]
    fn test_build_prolly_key_different_types() {
        let cid = Cid::default();
        let key1 = build_prolly_key("llm_raw", "patient:P-44291", "deepseek", &cid);
        let key2 = build_prolly_key("action", "patient:P-44291", "ehr.update", &cid);
        
        // Different types produce different keys
        assert_ne!(key1, key2);
        
        // Keys sort by type first (action < llm_raw lexicographically)
        assert!(key2 < key1);
    }
    
    #[test]
    fn test_parse_prolly_key_roundtrip() {
        let cid = Cid::default();
        let key = build_prolly_key("decision", "user:alice", "approve_action", &cid);
        
        let parsed = parse_prolly_key(&key);
        assert!(parsed.is_some());
        
        let (ptype, subject, predicate, cid_short) = parsed.unwrap();
        assert_eq!(ptype, "decision");
        assert_eq!(subject, "user:alice");
        assert_eq!(predicate, "approve_action");
        assert!(!cid_short.is_empty());
    }
    
    #[test]
    fn test_parse_prolly_key_malformed() {
        assert!(parse_prolly_key(b"no_slashes").is_none());
        assert!(parse_prolly_key(b"only/two").is_none());
        assert!(parse_prolly_key(b"only/two/three").is_none());
        // Four parts should work
        assert!(parse_prolly_key(b"a/b/c/d").is_some());
    }
    
    #[test]
    fn test_mem_packet_cid_deterministic() {
        use crate::types::{MemPacket, PacketType, Source, SourceKind};
        
        let source = Source {
            kind: SourceKind::Tool,
            principal_id: "did:key:z6MkAgent".to_string(),
        };
        let packet = MemPacket::new(
            PacketType::LlmRaw,
            serde_json::json!({"response": "test"}),
            Cid::default(),
            "patient:P-44291".to_string(),
            "pipeline:abc".to_string(),
            source.clone(),
            1706764800000,
        );
        
        let packet2 = MemPacket::new(
            PacketType::LlmRaw,
            serde_json::json!({"response": "test"}),
            Cid::default(),
            "patient:P-44291".to_string(),
            "pipeline:abc".to_string(),
            source,
            1706764800000,
        );
        
        let cid1 = compute_cid(&packet).unwrap();
        let cid2 = compute_cid(&packet2).unwrap();
        assert_eq!(cid1, cid2);
    }
}
