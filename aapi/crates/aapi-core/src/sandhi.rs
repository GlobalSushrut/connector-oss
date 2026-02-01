//! Sandhi - Canonicalization and Hashing for VĀKYA
//!
//! Sandhi (संधि) means "joining" in Sanskrit. This module provides
//! deterministic canonicalization of VĀKYA objects for hashing and signing.
//!
//! Implements RFC 8785 (JSON Canonicalization Scheme) for deterministic JSON.

use sha2::{Sha256, Digest};
use serde::Serialize;
use serde_json::Value;

use crate::error::{AapiError, AapiResult};
use crate::types::ContentHash;
use crate::vakya::Vakya;

/// Sandhi output - the canonical form of a VĀKYA
#[derive(Debug, Clone)]
pub struct SandhiOutput {
    /// Canonical JSON bytes (JCS-compliant)
    pub canonical_bytes: Vec<u8>,
    /// SHA-256 hash of canonical bytes
    pub vakya_hash: ContentHash,
    /// Original VĀKYA ID for reference
    pub vakya_id: String,
}

impl SandhiOutput {
    /// Get the hash as a hex string
    pub fn hash_hex(&self) -> &str {
        &self.vakya_hash.value
    }

    /// Get the canonical JSON as a string
    pub fn canonical_json(&self) -> AapiResult<String> {
        String::from_utf8(self.canonical_bytes.clone())
            .map_err(|e| AapiError::Canonicalization(e.to_string()))
    }
}

/// Canonicalize a VĀKYA according to RFC 8785 (JCS)
pub fn canonicalize(vakya: &Vakya) -> AapiResult<SandhiOutput> {
    // First, serialize to JSON Value
    let value = serde_json::to_value(vakya)?;
    
    // Apply JCS canonicalization
    let canonical_bytes = jcs_canonicalize(&value)?;
    
    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);
    
    Ok(SandhiOutput {
        canonical_bytes,
        vakya_hash: ContentHash::sha256(hash_hex),
        vakya_id: vakya.vakya_id.0.clone(),
    })
}

/// Canonicalize any serializable value
pub fn canonicalize_value<T: Serialize>(value: &T) -> AapiResult<Vec<u8>> {
    let json_value = serde_json::to_value(value)?;
    jcs_canonicalize(&json_value)
}

/// Compute SHA-256 hash of bytes
pub fn hash_bytes(bytes: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash_bytes = hasher.finalize();
    ContentHash::sha256(hex::encode(hash_bytes))
}

/// Compute SHA-256 hash of a serializable value after canonicalization
pub fn hash_value<T: Serialize>(value: &T) -> AapiResult<ContentHash> {
    let canonical = canonicalize_value(value)?;
    Ok(hash_bytes(&canonical))
}

/// RFC 8785 JSON Canonicalization Scheme implementation
/// 
/// Rules:
/// 1. Object keys are sorted lexicographically by UTF-16 code units
/// 2. No whitespace between tokens
/// 3. Numbers use shortest representation
/// 4. Strings use minimal escaping
fn jcs_canonicalize(value: &Value) -> AapiResult<Vec<u8>> {
    let mut output = Vec::new();
    jcs_serialize(value, &mut output)?;
    Ok(output)
}

fn jcs_serialize(value: &Value, output: &mut Vec<u8>) -> AapiResult<()> {
    match value {
        Value::Null => {
            output.extend_from_slice(b"null");
        }
        Value::Bool(b) => {
            output.extend_from_slice(if *b { b"true" } else { b"false" });
        }
        Value::Number(n) => {
            // Use the default JSON representation for numbers
            let s = n.to_string();
            output.extend_from_slice(s.as_bytes());
        }
        Value::String(s) => {
            jcs_serialize_string(s, output);
        }
        Value::Array(arr) => {
            output.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                jcs_serialize(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(obj) => {
            output.push(b'{');
            
            // Sort keys lexicographically by UTF-16 code units
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by(|a, b| {
                let a_utf16: Vec<u16> = a.encode_utf16().collect();
                let b_utf16: Vec<u16> = b.encode_utf16().collect();
                a_utf16.cmp(&b_utf16)
            });
            
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                jcs_serialize_string(key, output);
                output.push(b':');
                jcs_serialize(obj.get(*key).unwrap(), output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn jcs_serialize_string(s: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\x08' => output.extend_from_slice(b"\\b"),
            '\x0c' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            c if c < '\x20' => {
                // Control characters use \uXXXX
                output.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                // All other characters are written as-is (UTF-8)
                let mut buf = [0u8; 4];
                output.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    output.push(b'"');
}

/// Verify that a hash matches the canonical form of a VĀKYA
pub fn verify_hash(vakya: &Vakya, expected_hash: &ContentHash) -> AapiResult<bool> {
    let sandhi = canonicalize(vakya)?;
    Ok(sandhi.vakya_hash.value == expected_hash.value)
}

/// Merkle tree node for building transparency logs
#[derive(Debug, Clone, Serialize)]
pub struct MerkleNode {
    pub hash: ContentHash,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
    pub leaf_data: Option<String>,
}

impl MerkleNode {
    /// Create a leaf node from data
    pub fn leaf(data: &[u8]) -> Self {
        // Leaf prefix: 0x00
        let mut hasher = Sha256::new();
        hasher.update(&[0x00]);
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());
        
        Self {
            hash: ContentHash::sha256(hash),
            left: None,
            right: None,
            leaf_data: Some(hex::encode(data)),
        }
    }

    /// Create an internal node from two children
    pub fn internal(left: MerkleNode, right: MerkleNode) -> Self {
        // Internal prefix: 0x01
        let mut hasher = Sha256::new();
        hasher.update(&[0x01]);
        hasher.update(hex::decode(&left.hash.value).unwrap_or_default());
        hasher.update(hex::decode(&right.hash.value).unwrap_or_default());
        let hash = hex::encode(hasher.finalize());
        
        Self {
            hash: ContentHash::sha256(hash),
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            leaf_data: None,
        }
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.leaf_data.is_some()
    }
}

/// Build a Merkle tree from a list of leaf hashes
pub fn build_merkle_tree(leaves: Vec<ContentHash>) -> Option<MerkleNode> {
    if leaves.is_empty() {
        return None;
    }

    let mut nodes: Vec<MerkleNode> = leaves
        .into_iter()
        .map(|h| MerkleNode {
            hash: h,
            left: None,
            right: None,
            leaf_data: None,
        })
        .collect();

    while nodes.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        
        while i < nodes.len() {
            if i + 1 < nodes.len() {
                let left = nodes[i].clone();
                let right = nodes[i + 1].clone();
                next_level.push(MerkleNode::internal(left, right));
                i += 2;
            } else {
                // Odd node: promote to next level
                next_level.push(nodes[i].clone());
                i += 1;
            }
        }
        
        nodes = next_level;
    }

    nodes.into_iter().next()
}

/// Merkle proof for inclusion verification
#[derive(Debug, Clone, Serialize)]
pub struct MerkleProof {
    pub leaf_hash: ContentHash,
    pub proof_hashes: Vec<(ContentHash, bool)>, // (hash, is_right)
    pub root_hash: ContentHash,
}

impl MerkleProof {
    /// Verify the proof
    pub fn verify(&self) -> bool {
        let mut current = hex::decode(&self.leaf_hash.value).unwrap_or_default();
        
        for (sibling, is_right) in &self.proof_hashes {
            let sibling_bytes = hex::decode(&sibling.value).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(&[0x01]); // Internal node prefix
            
            if *is_right {
                hasher.update(&current);
                hasher.update(&sibling_bytes);
            } else {
                hasher.update(&sibling_bytes);
                hasher.update(&current);
            }
            
            current = hasher.finalize().to_vec();
        }
        
        hex::encode(&current) == self.root_hash.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jcs_simple_object() {
        let value = json!({"b": 2, "a": 1});
        let canonical = jcs_canonicalize(&value).unwrap();
        let canonical_str = String::from_utf8(canonical).unwrap();
        assert_eq!(canonical_str, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_jcs_nested_object() {
        let value = json!({"z": {"b": 2, "a": 1}, "a": []});
        let canonical = jcs_canonicalize(&value).unwrap();
        let canonical_str = String::from_utf8(canonical).unwrap();
        assert_eq!(canonical_str, r#"{"a":[],"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_jcs_string_escaping() {
        let value = json!({"text": "hello\nworld"});
        let canonical = jcs_canonicalize(&value).unwrap();
        let canonical_str = String::from_utf8(canonical).unwrap();
        assert_eq!(canonical_str, r#"{"text":"hello\nworld"}"#);
    }

    #[test]
    fn test_hash_determinism() {
        let value = json!({"b": 2, "a": 1});
        let hash1 = hash_value(&value).unwrap();
        let hash2 = hash_value(&value).unwrap();
        assert_eq!(hash1.value, hash2.value);
    }

    #[test]
    fn test_merkle_leaf() {
        let leaf = MerkleNode::leaf(b"test data");
        assert!(leaf.is_leaf());
        assert!(!leaf.hash.value.is_empty());
    }

    #[test]
    fn test_merkle_tree_single() {
        let leaves = vec![ContentHash::sha256("abc123")];
        let tree = build_merkle_tree(leaves.clone());
        assert!(tree.is_some());
        assert_eq!(tree.unwrap().hash.value, "abc123");
    }

    #[test]
    fn test_merkle_tree_multiple() {
        let leaves = vec![
            ContentHash::sha256("hash1"),
            ContentHash::sha256("hash2"),
            ContentHash::sha256("hash3"),
        ];
        let tree = build_merkle_tree(leaves);
        assert!(tree.is_some());
        let root = tree.unwrap();
        assert!(!root.is_leaf());
    }
}
