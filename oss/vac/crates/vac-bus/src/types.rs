//! Core types for the event bus.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A replication event transmitted between cells via the event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEvent {
    /// ID of the cell that originated this event
    pub cell_id: String,
    /// Monotonically increasing sequence number per cell
    pub seq: u64,
    /// The operation to replicate
    pub op: ReplicationOp,
    /// Timestamp in milliseconds since epoch
    pub ts: i64,
    /// Ed25519 signature of DAG-CBOR(op) by the cell's keypair
    pub signature: Vec<u8>,
}

impl ReplicationEvent {
    /// Create a new unsigned replication event.
    pub fn new(cell_id: impl Into<String>, seq: u64, op: ReplicationOp) -> Self {
        Self {
            cell_id: cell_id.into(),
            seq,
            op,
            ts: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        }
    }

    /// Create a new event with a provided timestamp (for testing).
    pub fn with_ts(cell_id: impl Into<String>, seq: u64, op: ReplicationOp, ts: i64) -> Self {
        Self {
            cell_id: cell_id.into(),
            seq,
            op,
            ts,
            signature: Vec::new(),
        }
    }

    /// Set the signature on this event.
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Returns true if this event has a non-empty signature.
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    /// Produce the canonical bytes that are signed/verified.
    ///
    /// Canonical form: JSON of `{"cell_id":...,"seq":...,"ts":...,"op":...}`
    /// The signature field is excluded.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "cell_id": self.cell_id,
            "seq": self.seq,
            "ts": self.ts,
            "op": serde_json::to_value(&self.op).unwrap_or_default(),
        });
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Sign this event with the cell's Ed25519 signing key.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let bytes = self.signable_bytes();
        let sig = signing_key.sign(&bytes);
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify this event's signature against a peer's public key.
    ///
    /// Returns `Ok(())` if valid, `Err(reason)` if invalid or missing.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        if self.signature.is_empty() {
            return Err("event is unsigned".to_string());
        }
        if self.signature.len() != 64 {
            return Err(format!("invalid signature length: {} (expected 64)", self.signature.len()));
        }
        let sig_bytes: [u8; 64] = self.signature[..64]
            .try_into()
            .map_err(|_| "signature conversion failed".to_string())?;
        let sig = Signature::from_bytes(&sig_bytes);
        let bytes = self.signable_bytes();
        verifying_key
            .verify(&bytes, &sig)
            .map_err(|e| format!("signature verification failed: {}", e))
    }
}

/// Operations that can be replicated across cells.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReplicationOp {
    // ── VAC Storage Ops ──────────────────────────────────────────────

    /// Write a MemPacket to a namespace
    PacketWrite {
        namespace: String,
        packet_cbor: Vec<u8>,
        packet_cid: String,
    },
    /// Seal packets (make immutable)
    PacketSeal { cids: Vec<String> },
    /// Evict packets from storage
    PacketEvict { cids: Vec<String> },
    /// Change a packet's memory tier
    TierChange { cid: String, new_tier: String },
    /// Register an agent on this cell
    AgentRegister {
        pid: String,
        name: String,
        namespace: String,
    },
    /// Append an audit log entry
    AuditEntry { entry_cbor: Vec<u8> },
    /// Commit a signed block (Prolly tree)
    BlockCommit { block_cbor: Vec<u8> },
    /// Periodic heartbeat from a cell
    Heartbeat {
        agent_count: u32,
        packet_count: u64,
        merkle_root: [u8; 32],
        load: u8,
    },

    // ── AAPI Distribution Ops ────────────────────────────────────────

    /// Forward a VĀKYA to another cell for execution
    VakyaForward {
        vakya_cbor: Vec<u8>,
        pipeline_id: String,
        step_id: String,
        reply_topic: String,
    },
    /// Reply with execution result from a forwarded VĀKYA
    VakyaReply {
        step_id: String,
        result_cbor: Vec<u8>,
    },
    /// Rollback an effect on a remote cell (saga pattern)
    VakyaRollback {
        effect_cbor: Vec<u8>,
        saga_id: String,
    },
    /// Replicate a policy to all cells in cluster
    PolicyUpdate { policy_cbor: Vec<u8> },
    /// Announce an adapter's availability on a cell
    AdapterAnnounce {
        domain: String,
        cell_id: String,
        actions: Vec<String>,
    },
    /// Deregister an adapter from a cell
    AdapterDeregister {
        domain: String,
        cell_id: String,
    },
    /// Request approval from human/manager/security
    ApprovalRequest {
        approval_id: String,
        vakya_cbor: Vec<u8>,
        approvers: Vec<String>,
        timeout_ms: u64,
    },
    /// Response to an approval request
    ApprovalResponse {
        approval_id: String,
        approved: bool,
        approver: String,
        comment: Option<String>,
    },

    // --- Phase L1.1: Signal Distribution ---
    /// Deliver an async signal to an agent on a remote cell (cross-cell kill(2))
    SignalDeliver {
        /// Target agent PID
        target_pid: String,
        /// CBOR-encoded AgentSignal
        signal_cbor: Vec<u8>,
        /// Originating cell ID
        origin_cell: String,
    },
}

impl ReplicationOp {
    /// Returns a short label for the operation type (for metrics/logging).
    pub fn op_type(&self) -> &'static str {
        match self {
            Self::PacketWrite { .. } => "packet_write",
            Self::PacketSeal { .. } => "packet_seal",
            Self::PacketEvict { .. } => "packet_evict",
            Self::TierChange { .. } => "tier_change",
            Self::AgentRegister { .. } => "agent_register",
            Self::AuditEntry { .. } => "audit_entry",
            Self::BlockCommit { .. } => "block_commit",
            Self::Heartbeat { .. } => "heartbeat",
            Self::VakyaForward { .. } => "vakya_forward",
            Self::VakyaReply { .. } => "vakya_reply",
            Self::VakyaRollback { .. } => "vakya_rollback",
            Self::PolicyUpdate { .. } => "policy_update",
            Self::AdapterAnnounce { .. } => "adapter_announce",
            Self::AdapterDeregister { .. } => "adapter_deregister",
            Self::ApprovalRequest { .. } => "approval_request",
            Self::ApprovalResponse { .. } => "approval_response",
            Self::SignalDeliver { .. } => "signal_deliver",
        }
    }

    /// Returns true if this is a VAC storage operation.
    pub fn is_vac_op(&self) -> bool {
        matches!(
            self,
            Self::PacketWrite { .. }
                | Self::PacketSeal { .. }
                | Self::PacketEvict { .. }
                | Self::TierChange { .. }
                | Self::AgentRegister { .. }
                | Self::AuditEntry { .. }
                | Self::BlockCommit { .. }
                | Self::Heartbeat { .. }
        )
    }

    /// Returns true if this is an AAPI distribution operation.
    pub fn is_aapi_op(&self) -> bool {
        !self.is_vac_op()
    }
}
