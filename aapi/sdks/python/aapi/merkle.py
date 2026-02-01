import hashlib
from typing import Any, Dict, List

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class MerkleTreeVerifier:
    """Client-side Merkle Tree verification utilities"""
    
    @staticmethod
    def hash_leaf(data: bytes) -> str:
        """Hash a leaf node (0x00 prefix)"""
        hasher = hashlib.sha256()
        hasher.update(b'\x00')
        hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def hash_internal(left_hex: str, right_hex: str) -> str:
        """Hash an internal node (0x01 prefix)"""
        hasher = hashlib.sha256()
        hasher.update(b'\x01')
        hasher.update(bytes.fromhex(left_hex))
        hasher.update(bytes.fromhex(right_hex))
        return hasher.hexdigest()

    @classmethod
    def verify_proof(cls, leaf_hash: str, proof_path: List[Dict[str, Any]], expected_root: str) -> bool:
        """
        Verify a Merkle inclusion proof.
        
        Args:
            leaf_hash: The hash of the leaf being verified
            proof_path: List of dicts with 'hash' and 'position' ('left' or 'right')
            expected_root: The trusted root hash
            
        Returns:
            True if the proof is valid and matches the root
        """
        current_hash = leaf_hash
        
        for node in proof_path:
            sibling_hash = node['hash']
            position = node.get('position', 'right') # Default to sibling is on right?
            # Actually, typically proof says "hash" and implies relative position or explicit
            
            # The Rust implementation returns (String, bool) where bool is is_right
            # The API returns struct ProofNode { hash, position: String }
            
            if position == 'right' or position == True:
                # Sibling is on the right, so current is left
                current_hash = cls.hash_internal(current_hash, sibling_hash)
            else:
                # Sibling is on the left, so current is right
                current_hash = cls.hash_internal(sibling_hash, current_hash)
                
        return current_hash == expected_root
