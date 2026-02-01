//! Data models for IndexDB records

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aapi_core::types::{ContentHash, EffectBucket, PrincipalId, ResourceId};
use aapi_core::error::ReasonCode;

/// Stored VĀKYA record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VakyaRecord {
    /// Unique record ID
    pub id: Uuid,
    /// VĀKYA ID from the request
    pub vakya_id: String,
    /// Hash of the canonical VĀKYA
    pub vakya_hash: String,
    /// Actor principal ID
    pub karta_pid: String,
    /// Actor type
    pub karta_type: String,
    /// Resource ID
    pub karma_rid: String,
    /// Resource kind
    pub karma_kind: Option<String>,
    /// Action performed
    pub kriya_action: String,
    /// Expected effect bucket
    pub expected_effect: EffectBucket,
    /// Capability reference or token ID
    pub cap_ref: String,
    /// Full VĀKYA JSON
    pub vakya_json: serde_json::Value,
    /// Signature
    pub signature: Option<String>,
    /// Key ID used for signing
    pub key_id: Option<String>,
    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,
    /// Span ID
    pub span_id: Option<String>,
    /// Parent span ID
    pub parent_span_id: Option<String>,
    /// Record creation timestamp
    pub created_at: DateTime<Utc>,
    /// Merkle tree leaf index
    pub leaf_index: Option<i64>,
    /// Merkle tree root at time of insertion
    pub merkle_root: Option<String>,
}

impl VakyaRecord {
    pub fn new(
        vakya_id: String,
        vakya_hash: String,
        karta_pid: String,
        karma_rid: String,
        kriya_action: String,
        vakya_json: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            vakya_id,
            vakya_hash,
            karta_pid,
            karta_type: "human".to_string(),
            karma_rid,
            karma_kind: None,
            kriya_action,
            expected_effect: EffectBucket::None,
            cap_ref: String::new(),
            vakya_json,
            signature: None,
            key_id: None,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            created_at: Utc::now(),
            leaf_index: None,
            merkle_root: None,
        }
    }
}

/// Stored effect record (AEO - Agentic Effect Object)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectRecord {
    /// Unique record ID
    pub id: Uuid,
    /// Associated VĀKYA ID
    pub vakya_id: String,
    /// Effect bucket type
    pub effect_bucket: EffectBucket,
    /// Target resource ID
    pub target_rid: String,
    /// Target resource kind
    pub target_kind: Option<String>,
    /// State before the action (hash or value)
    pub before_hash: Option<String>,
    /// State after the action (hash or value)
    pub after_hash: Option<String>,
    /// Before state JSON (if captured)
    pub before_state: Option<serde_json::Value>,
    /// After state JSON (if captured)
    pub after_state: Option<serde_json::Value>,
    /// Delta/diff representation
    pub delta: Option<serde_json::Value>,
    /// Whether the effect is reversible
    pub reversible: bool,
    /// Reversal instructions (if reversible)
    pub reversal_instructions: Option<serde_json::Value>,
    /// Effect timestamp
    pub created_at: DateTime<Utc>,
    /// Merkle leaf index
    pub leaf_index: Option<i64>,
}

impl EffectRecord {
    pub fn new(vakya_id: String, effect_bucket: EffectBucket, target_rid: String) -> Self {
        Self {
            id: Uuid::now_v7(),
            vakya_id,
            effect_bucket,
            target_rid,
            target_kind: None,
            before_hash: None,
            after_hash: None,
            before_state: None,
            after_state: None,
            delta: None,
            reversible: false,
            reversal_instructions: None,
            created_at: Utc::now(),
            leaf_index: None,
        }
    }

    /// Check if this effect can be reversed
    pub fn can_reverse(&self) -> bool {
        self.reversible && self.reversal_instructions.is_some()
    }
}

/// Stored receipt record (PRAMĀṆA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRecord {
    /// Unique record ID
    pub id: Uuid,
    /// Associated VĀKYA ID
    pub vakya_id: String,
    /// VĀKYA hash
    pub vakya_hash: String,
    /// Reason code
    pub reason_code: ReasonCode,
    /// Human-readable message
    pub message: Option<String>,
    /// Execution duration in milliseconds
    pub duration_ms: Option<i64>,
    /// Associated effect IDs
    pub effect_ids: Vec<String>,
    /// Gateway/executor ID
    pub executor_id: String,
    /// Receipt signature
    pub signature: Option<String>,
    /// Key ID used for signing
    pub key_id: Option<String>,
    /// Receipt timestamp
    pub created_at: DateTime<Utc>,
    /// Full receipt JSON
    pub receipt_json: serde_json::Value,
    /// Merkle leaf index
    pub leaf_index: Option<i64>,
}

impl ReceiptRecord {
    pub fn new(
        vakya_id: String,
        vakya_hash: String,
        reason_code: ReasonCode,
        executor_id: String,
        receipt_json: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            vakya_id,
            vakya_hash,
            reason_code,
            message: None,
            duration_ms: None,
            effect_ids: vec![],
            executor_id,
            signature: None,
            key_id: None,
            created_at: Utc::now(),
            receipt_json,
            leaf_index: None,
        }
    }

    pub fn is_success(&self) -> bool {
        self.reason_code.is_success()
    }
}

/// Merkle tree checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleCheckpoint {
    /// Checkpoint ID
    pub id: Uuid,
    /// Tree type (vakya, effect, receipt)
    pub tree_type: TreeType,
    /// Tree size (number of leaves)
    pub tree_size: i64,
    /// Root hash
    pub root_hash: String,
    /// Checkpoint timestamp
    pub created_at: DateTime<Utc>,
    /// Previous checkpoint ID
    pub previous_id: Option<Uuid>,
    /// Signature over the checkpoint
    pub signature: Option<String>,
}

/// Type of Merkle tree
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeType {
    Vakya,
    Effect,
    Receipt,
}

impl std::fmt::Display for TreeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeType::Vakya => write!(f, "vakya"),
            TreeType::Effect => write!(f, "effect"),
            TreeType::Receipt => write!(f, "receipt"),
        }
    }
}

/// Audit log entry for system events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Entry ID
    pub id: Uuid,
    /// Event type
    pub event_type: AuditEventType,
    /// Actor who triggered the event
    pub actor: Option<String>,
    /// Target resource
    pub target: Option<String>,
    /// Event details
    pub details: serde_json::Value,
    /// Event timestamp
    pub created_at: DateTime<Utc>,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
}

/// Types of audit events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// VĀKYA submitted
    VakyaSubmitted,
    /// VĀKYA executed
    VakyaExecuted,
    /// VĀKYA denied
    VakyaDenied,
    /// Effect captured
    EffectCaptured,
    /// Receipt issued
    ReceiptIssued,
    /// Capability issued
    CapabilityIssued,
    /// Capability revoked
    CapabilityRevoked,
    /// Key generated
    KeyGenerated,
    /// Key revoked
    KeyRevoked,
    /// Merkle checkpoint created
    MerkleCheckpoint,
    /// Query executed
    QueryExecuted,
    /// System event
    System,
}

/// Inclusion proof for transparency verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Leaf hash
    pub leaf_hash: String,
    /// Leaf index
    pub leaf_index: i64,
    /// Tree size at time of proof
    pub tree_size: i64,
    /// Proof hashes (sibling path)
    pub proof_hashes: Vec<ProofNode>,
    /// Root hash
    pub root_hash: String,
}

/// Node in a Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    /// Hash value
    pub hash: String,
    /// Position (left or right)
    pub position: ProofPosition,
}

/// Position of a proof node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofPosition {
    Left,
    Right,
}

/// Consistency proof between two tree states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// First tree size
    pub first_size: i64,
    /// Second tree size
    pub second_size: i64,
    /// First root hash
    pub first_root: String,
    /// Second root hash
    pub second_root: String,
    /// Proof hashes
    pub proof_hashes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vakya_record_creation() {
        let record = VakyaRecord::new(
            "vakya-123".to_string(),
            "hash-abc".to_string(),
            "user:alice".to_string(),
            "file:/test.txt".to_string(),
            "file.read".to_string(),
            serde_json::json!({}),
        );
        
        assert_eq!(record.vakya_id, "vakya-123");
        assert!(record.id.to_string().len() > 0);
    }

    #[test]
    fn test_effect_record_reversibility() {
        let mut effect = EffectRecord::new(
            "vakya-123".to_string(),
            EffectBucket::Update,
            "file:/test.txt".to_string(),
        );
        
        assert!(!effect.can_reverse());
        
        effect.reversible = true;
        effect.reversal_instructions = Some(serde_json::json!({"action": "restore"}));
        
        assert!(effect.can_reverse());
    }

    #[test]
    fn test_receipt_success_check() {
        let success = ReceiptRecord::new(
            "vakya-123".to_string(),
            "hash-abc".to_string(),
            ReasonCode::Success,
            "gateway-1".to_string(),
            serde_json::json!({}),
        );
        assert!(success.is_success());

        let failure = ReceiptRecord::new(
            "vakya-456".to_string(),
            "hash-def".to_string(),
            ReasonCode::AuthorizationDenied,
            "gateway-1".to_string(),
            serde_json::json!({}),
        );
        assert!(!failure.is_success());
    }
}
