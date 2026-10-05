use serde::{Deserialize, Serialize};

/// Detached package signature (payload and verification in Phase 4.2).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CpkgSignatureEnvelope {
    /// e.g. `ed25519`
    pub algorithm: String,
    /// Hub- or author-registered key identifier.
    pub key_id: String,
    /// Hex SHA-256 over the canonical bytes signed (typically manifest + file manifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
    /// Standard base64 (no URL encoding) signature bytes.
    pub signature_b64: String,
    /// Optional parent key in a Hub → author delegation chain (verification extension).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_key_id: Option<String>,
}
