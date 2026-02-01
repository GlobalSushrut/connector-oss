//! CID computation for VAC objects
//!
//! Uses CIDv1 + DAG-CBOR + SHA2-256 as specified in arch.md

use cid::Cid;
use multihash::Multihash;
use serde::Serialize;
use sha2::{Sha256, Digest};

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

/// Compute hash for a Prolly node
/// H(level || num_keys || key_0 || ... || key_n || value_0 || ... || value_n)
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
    
    sha256(&data)
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
    Ok(sha256(&bytes))
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
    Ok(sha256(&bytes))
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
}
