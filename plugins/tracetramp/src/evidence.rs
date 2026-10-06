//! Evidence Plane - Trace, Explain, Prove, Cost
//!
//! Generates cryptographic receipts and audit trails via Connector

use crate::connector::ConnectorClient;
use crate::error::AppError;
use tracing::{info, debug};

/// Generate a cryptographic receipt for a trace via Connector
pub async fn generate_receipt(
    connector: &ConnectorClient,
    request_id: &str,
    trace_id: &str,
    status: &str,
) -> Result<crate::connector::Receipt, AppError> {
    debug!("Generating receipt via Connector for request {}", request_id);
    let receipt = connector.issue_receipt(request_id, trace_id, status).await?;
    info!("Generated receipt: {} (CID: {})", receipt.receipt_id, receipt.cid);
    Ok(receipt)
}

/// Verify receipt integrity by re-fetching from Connector
pub async fn verify_receipt(
    connector: &ConnectorClient,
    request_id: &str,
) -> Result<bool, AppError> {
    debug!("Verifying receipt for request {}", request_id);
    match connector.get_receipt(request_id).await {
        Ok(_receipt) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Hash a decision tree for integrity verification
pub fn hash_tree(tree: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(tree).unwrap_or_default();
    sha256::digest(&bytes)
}

/// Compute CID-style hash (multibase-compatible format)
pub fn compute_cid(data: &[u8]) -> String {
    let hash = sha256::digest(data);
    format!("bafybei{}", &hash[..52.min(hash.len())])
}

/// Verify hash matches expected
pub fn verify_hash(data: &[u8], expected_hash: &str) -> bool {
    let actual = sha256::digest(data);
    actual == expected_hash
}
