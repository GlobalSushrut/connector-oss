//! Surface Receipt — Proof chain for every render
//!
//! Following CLS/Books patterns: every surface render produces a signed receipt
//! that can be verified, audited, and chained.

use super::cid::SurfaceCid;
use super::document::{SurfaceType, SurfaceView};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Receipt for a surface render operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceReceipt {
    pub receipt_id: String,
    pub surface_cid: SurfaceCid,
    pub surface_type: SurfaceType,
    pub view: SurfaceView,
    pub subject_id: String,
    pub rendered_at: i64,
    pub render_duration_ms: u64,
    pub actor: String,
    pub role: String,
    pub time_context: Option<TimeContext>,
    pub parent_receipt: Option<String>,
    pub signature: Option<String>,
    pub chain_hash: String,
}

/// Time context for time-travel queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeContext {
    pub selector: String,
    pub resolved_start: i64,
    pub resolved_end: i64,
    pub is_time_travel: bool,
}

impl SurfaceReceipt {
    pub fn new(
        surface_cid: SurfaceCid,
        surface_type: SurfaceType,
        view: SurfaceView,
        subject_id: &str,
        actor: &str,
        role: &str,
        render_duration_ms: u64,
    ) -> Self {
        let rendered_at = chrono::Utc::now().timestamp_millis();
        let receipt_id = format!("rcpt_{}", &surface_cid.hash[12..28]);
        
        // Compute chain hash
        let chain_input = format!("{}:{}:{}:{}", surface_cid.hash, rendered_at, actor, subject_id);
        let mut hasher = Sha256::new();
        hasher.update(chain_input.as_bytes());
        let chain_hash = hex::encode(&hasher.finalize()[..8]);

        Self {
            receipt_id,
            surface_cid,
            surface_type,
            view,
            subject_id: subject_id.to_string(),
            rendered_at,
            render_duration_ms,
            actor: actor.to_string(),
            role: role.to_string(),
            time_context: None,
            parent_receipt: None,
            signature: None,
            chain_hash,
        }
    }

    pub fn with_time_context(mut self, ctx: TimeContext) -> Self {
        self.time_context = Some(ctx);
        self
    }

    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_receipt = Some(parent_id.to_string());
        // Recompute chain hash with parent
        let chain_input = format!("{}:{}:{}", self.chain_hash, parent_id, self.rendered_at);
        let mut hasher = Sha256::new();
        hasher.update(chain_input.as_bytes());
        self.chain_hash = hex::encode(&hasher.finalize()[..8]);
        self
    }

    pub fn sign(mut self, signature: &str) -> Self {
        self.signature = Some(signature.to_string());
        self
    }

    /// Verify receipt chain integrity
    pub fn verify_chain(&self, parent: Option<&SurfaceReceipt>) -> bool {
        if let Some(parent_id) = &self.parent_receipt {
            if let Some(p) = parent {
                p.receipt_id == *parent_id
            } else {
                false
            }
        } else {
            true // No parent required
        }
    }
}

/// Receipt chain for audit trail
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiptChain {
    receipts: Vec<SurfaceReceipt>,
    root_hash: Option<String>,
}

impl ReceiptChain {
    pub fn new() -> Self { Self::default() }

    pub fn append(&mut self, receipt: SurfaceReceipt) {
        let receipt = if let Some(last) = self.receipts.last() {
            receipt.with_parent(&last.receipt_id)
        } else {
            receipt
        };
        
        // Update root hash
        let mut hasher = Sha256::new();
        if let Some(ref root) = self.root_hash {
            hasher.update(root.as_bytes());
        }
        hasher.update(receipt.chain_hash.as_bytes());
        self.root_hash = Some(hex::encode(&hasher.finalize()[..8]));
        
        self.receipts.push(receipt);
    }

    pub fn root_hash(&self) -> Option<&str> {
        self.root_hash.as_deref()
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn last(&self) -> Option<&SurfaceReceipt> {
        self.receipts.last()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SurfaceReceipt> {
        self.receipts.iter()
    }

    /// Verify entire chain integrity
    pub fn verify(&self) -> bool {
        for i in 1..self.receipts.len() {
            if !self.receipts[i].verify_chain(Some(&self.receipts[i - 1])) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::builder::SurfaceBuilder;
    use crate::surface::cid::SurfaceCid;

    #[test]
    fn test_receipt_creation() {
        let doc = SurfaceBuilder::agent("test").judgment_ok("OK").build();
        let cid = SurfaceCid::from_document(&doc);
        let receipt = SurfaceReceipt::new(cid, SurfaceType::Agent, SurfaceView::Summary, "test", "user-1", "Developer", 50);
        assert!(receipt.receipt_id.starts_with("rcpt_"));
    }

    #[test]
    fn test_receipt_chain() {
        let mut chain = ReceiptChain::new();
        
        for i in 0..3 {
            let doc = SurfaceBuilder::agent(&format!("test-{}", i)).judgment_ok("OK").build();
            let cid = SurfaceCid::from_document(&doc);
            let receipt = SurfaceReceipt::new(cid, SurfaceType::Agent, SurfaceView::Summary, &format!("test-{}", i), "user-1", "Developer", 50);
            chain.append(receipt);
        }

        assert_eq!(chain.len(), 3);
        assert!(chain.verify());
        assert!(chain.root_hash().is_some());
    }
}
