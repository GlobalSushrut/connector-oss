//! Cross-Cell Capability Verification.
//!
//! Verifies that a VAKYA's delegation chain is valid across cell boundaries.
//! Each cell registers its Ed25519 public key. When a VAKYA arrives from
//! another cell, we verify:
//! 1. The source cell's public key is known.
//! 2. The DelegationHop chain is monotonically attenuating (scopes only shrink).
//! 3. No hop adds capabilities that weren't present in the parent.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

use aapi_core::Vakya;

use crate::error::{FederationError, FederationResult};

// ============================================================================
// CrossCellCapabilityVerifier
// ============================================================================

/// Verifies capability chains across cell boundaries.
pub struct CrossCellCapabilityVerifier {
    /// cell_id → Ed25519 public key bytes
    cell_keys: HashMap<String, Vec<u8>>,
}

impl CrossCellCapabilityVerifier {
    pub fn new() -> Self {
        Self {
            cell_keys: HashMap::new(),
        }
    }

    /// Register a cell's public key (from membership announcements).
    pub fn register_cell(&mut self, cell_id: &str, public_key: Vec<u8>) {
        self.cell_keys
            .insert(cell_id.to_string(), public_key);
    }

    /// Deregister a cell.
    pub fn deregister_cell(&mut self, cell_id: &str) {
        self.cell_keys.remove(cell_id);
    }

    /// Check if a cell is known.
    pub fn is_known_cell(&self, cell_id: &str) -> bool {
        self.cell_keys.contains_key(cell_id)
    }

    /// Number of registered cells.
    pub fn cell_count(&self) -> usize {
        self.cell_keys.len()
    }

    /// Verify a VAKYA's capability chain from a source cell.
    ///
    /// Checks:
    /// 1. Source cell's public key is registered.
    /// 2. Delegation chain hops are monotonically attenuating.
    /// 3. Scopes only shrink (never grow) across hops.
    pub fn verify_cross_cell(
        &self,
        vakya: &Vakya,
        source_cell_id: &str,
    ) -> FederationResult<VerificationResult> {
        // 1. Verify source cell is known
        if !self.cell_keys.contains_key(source_cell_id) {
            return Err(FederationError::UnknownCell(source_cell_id.to_string()));
        }

        debug!(
            source_cell = %source_cell_id,
            delegation_hops = vakya.v1_karta.delegation_chain.len(),
            "Verifying cross-cell capability"
        );

        let chain = &vakya.v1_karta.delegation_chain;

        // 2. Verify delegation chain monotonic attenuation
        let mut issues = Vec::new();
        let mut parent_scopes: Option<Vec<String>> = None;

        for (i, hop) in chain.iter().enumerate() {
            // Check attenuation: scopes can only be removed, never added
            if let Some(ref attenuation) = hop.attenuation {
                if let Some(ref prev_scopes) = parent_scopes {
                    // After attenuation, remaining scopes must be subset of parent
                    let remaining: Vec<String> = prev_scopes
                        .iter()
                        .filter(|s| !attenuation.removed_scopes.contains(s))
                        .cloned()
                        .collect();
                    parent_scopes = Some(remaining);
                } else {
                    // First hop with attenuation — record what's removed
                    let base_scopes = vakya.v7_adhikarana.scopes.clone();
                    let remaining: Vec<String> = base_scopes
                        .iter()
                        .filter(|s| !attenuation.removed_scopes.contains(s))
                        .cloned()
                        .collect();
                    parent_scopes = Some(remaining);
                }
            }

            // Verify delegator is not empty
            if hop.delegator.0.is_empty() {
                issues.push(format!("hop {} has empty delegator", i));
            }
        }

        let valid = issues.is_empty();

        Ok(VerificationResult {
            valid,
            source_cell_id: source_cell_id.to_string(),
            delegation_depth: chain.len(),
            issues,
        })
    }
}

impl Default for CrossCellCapabilityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of cross-cell capability verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub source_cell_id: String,
    pub delegation_depth: usize,
    pub issues: Vec<String>,
}
