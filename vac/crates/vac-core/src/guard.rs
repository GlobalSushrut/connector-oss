//! MAC Guard — Bell-LaPadula + Biba Lattice (Layer 1 of 5-Layer Guard Pipeline)
//!
//! Deterministic mandatory access control for agentic AI memory operations.
//! Uses integer security levels — no floating-point, no weights, no ambiguity.
//!
//! Research: Bell-LaPadula (DoD 1973), Biba Integrity Model (1977),
//! NIST SP 800-53 AC-3/AC-4, Cross-Domain Solutions, Common Criteria EAL 5+
//!
//! BLP (confidentiality): "no read up, no write down"
//!   - Subject cannot read objects above their clearance
//!   - Subject cannot write to objects below their clearance (prevents data leakage)
//!
//! Biba (integrity): "no read down, no write up"
//!   - Subject cannot write to objects above their integrity level
//!   - Prevents untrusted data from contaminating trusted stores (RAG poisoning)
//!
//! Combined: For each operation, BOTH BLP and Biba must pass.

use serde::{Deserialize, Serialize};
use crate::namespace_types::SecurityLevel;

// ═══════════════════════════════════════════════════════════════
// Guard Decision
// ═══════════════════════════════════════════════════════════════

/// Deterministic decision from any guard layer. No weights, no scores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardDecision {
    /// Operation permitted
    Allow,
    /// Operation denied — final, no override possible
    Deny { reason: String },
    /// Operation requires human approval before proceeding
    Hold { reason: String },
    /// Operation allowed but specific fields must be redacted
    Redact { fields: Vec<String> },
}

impl GuardDecision {
    pub fn is_deny(&self) -> bool { matches!(self, GuardDecision::Deny { .. }) }
    pub fn is_allow(&self) -> bool { matches!(self, GuardDecision::Allow) }
    pub fn is_hold(&self) -> bool { matches!(self, GuardDecision::Hold { .. }) }
}

/// Structured verdict from a single guard layer, with evidence and timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerVerdict {
    pub layer: u8,
    pub layer_name: String,
    pub decision: GuardDecision,
    pub reason: String,
    pub evidence: Vec<String>,
    pub duration_us: u64,
}

/// Full verdict chain from all 5 layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardVerdictChain {
    pub request_id: String,
    pub agent_pid: String,
    pub operation: String,
    pub namespace: String,
    pub timestamp: i64,
    pub layer_verdicts: Vec<LayerVerdict>,
    pub final_decision: GuardDecision,
}

// ═══════════════════════════════════════════════════════════════
// MAC Guard — Layer 1
// ═══════════════════════════════════════════════════════════════

/// Mandatory Access Control guard using Bell-LaPadula + Biba lattice.
///
/// All checks are deterministic: integer comparison, no floats, no weights.
/// A DENY from this layer is FINAL and cannot be overridden by any other layer.
pub struct MacGuard;

impl MacGuard {
    /// Bell-LaPadula: subject cannot read objects above their clearance level.
    /// "No read up" — prevents unauthorized access to classified information.
    ///
    /// - `subject_clearance`: agent's security clearance level
    /// - `object_classification`: namespace's security level
    /// - `is_kernel`: true if caller is the kernel itself (trusted subject)
    pub fn check_read(
        subject_clearance: SecurityLevel,
        object_classification: SecurityLevel,
        is_kernel: bool,
    ) -> GuardDecision {
        // Trusted subjects (kernel) bypass BLP read restrictions
        if is_kernel {
            return GuardDecision::Allow;
        }

        if subject_clearance < object_classification {
            return GuardDecision::Deny {
                reason: format!(
                    "BLP violation: subject clearance {} < object classification {} (no read-up)",
                    subject_clearance, object_classification
                ),
            };
        }

        GuardDecision::Allow
    }

    /// Bell-LaPadula + Biba combined write check.
    ///
    /// BLP *-property: subject cannot write to objects BELOW their clearance.
    /// This prevents data leakage from high-clearance to low-clearance namespaces.
    ///
    /// Biba integrity: subject cannot write to objects ABOVE their integrity level
    /// without an explicit integrity grant. This prevents untrusted agents from
    /// contaminating trusted knowledge stores (RAG poisoning defense).
    ///
    /// - `subject_clearance`: agent's security clearance level
    /// - `object_classification`: target namespace's security level
    /// - `is_kernel`: true if caller is the kernel (trusted subject)
    /// - `has_integrity_grant`: true if agent has explicit grant to write up
    /// - `has_write_down_grant`: true if agent has explicit grant to write down
    pub fn check_write(
        subject_clearance: SecurityLevel,
        object_classification: SecurityLevel,
        is_kernel: bool,
        has_integrity_grant: bool,
        has_write_down_grant: bool,
    ) -> GuardDecision {
        // Trusted subjects (kernel) bypass all write restrictions
        if is_kernel {
            return GuardDecision::Allow;
        }

        // BLP *-property: no write-down (prevents data leakage)
        if subject_clearance > object_classification && !has_write_down_grant {
            return GuardDecision::Deny {
                reason: format!(
                    "BLP *-property violation: subject clearance {} > object classification {} (no write-down without grant)",
                    subject_clearance, object_classification
                ),
            };
        }

        // Biba integrity: no write-up from untrusted (prevents contamination)
        if subject_clearance < object_classification && !has_integrity_grant {
            return GuardDecision::Deny {
                reason: format!(
                    "Biba integrity violation: subject level {} < object level {} (no write-up without integrity grant)",
                    subject_clearance, object_classification
                ),
            };
        }

        GuardDecision::Allow
    }

    /// Combined read+write check for a given operation.
    /// Returns the FIRST deny encountered (short-circuit).
    pub fn check_operation(
        subject_clearance: SecurityLevel,
        object_classification: SecurityLevel,
        is_read: bool,
        is_write: bool,
        is_kernel: bool,
        has_integrity_grant: bool,
        has_write_down_grant: bool,
    ) -> GuardDecision {
        if is_read {
            let read_decision = Self::check_read(
                subject_clearance,
                object_classification,
                is_kernel,
            );
            if read_decision.is_deny() {
                return read_decision;
            }
        }

        if is_write {
            let write_decision = Self::check_write(
                subject_clearance,
                object_classification,
                is_kernel,
                has_integrity_grant,
                has_write_down_grant,
            );
            if write_decision.is_deny() {
                return write_decision;
            }
        }

        GuardDecision::Allow
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blp_no_read_up() {
        // Standard agent cannot read Kernel namespace
        let d = MacGuard::check_read(SecurityLevel::Standard, SecurityLevel::Kernel, false);
        assert!(d.is_deny());
        // Standard agent cannot read Control namespace
        let d = MacGuard::check_read(SecurityLevel::Standard, SecurityLevel::Control, false);
        assert!(d.is_deny());
        // Standard agent CAN read Standard (same level)
        let d = MacGuard::check_read(SecurityLevel::Standard, SecurityLevel::Standard, false);
        assert!(d.is_allow());
        // Standard agent CAN read Public (below)
        let d = MacGuard::check_read(SecurityLevel::Standard, SecurityLevel::Public, false);
        assert!(d.is_allow());
    }

    #[test]
    fn test_blp_no_write_down() {
        // Protected agent cannot write to Public without grant (data leakage)
        let d = MacGuard::check_write(SecurityLevel::Protected, SecurityLevel::Public, false, false, false);
        assert!(d.is_deny());
        // Protected agent CAN write to Protected (same level)
        let d = MacGuard::check_write(SecurityLevel::Protected, SecurityLevel::Protected, false, false, false);
        assert!(d.is_allow());
    }

    #[test]
    fn test_biba_no_write_up() {
        // Standard agent cannot write to Protected without integrity grant
        let d = MacGuard::check_write(SecurityLevel::Standard, SecurityLevel::Protected, false, false, false);
        assert!(d.is_deny());
        // ToolIO agent cannot write to Knowledge (prevents RAG poisoning)
        let d = MacGuard::check_write(SecurityLevel::ToolIO, SecurityLevel::Protected, false, false, false);
        assert!(d.is_deny());
        // Public agent cannot write to Standard
        let d = MacGuard::check_write(SecurityLevel::Public, SecurityLevel::Standard, false, false, false);
        assert!(d.is_deny());
    }

    #[test]
    fn test_integrity_grant_allows_write_up() {
        // Standard agent WITH integrity grant CAN write to Protected
        let d = MacGuard::check_write(SecurityLevel::Standard, SecurityLevel::Protected, false, true, false);
        assert!(d.is_allow());
    }

    #[test]
    fn test_write_down_grant_allows_write_down() {
        // Protected agent WITH write-down grant CAN write to Public
        let d = MacGuard::check_write(SecurityLevel::Protected, SecurityLevel::Public, false, false, true);
        assert!(d.is_allow());
    }

    #[test]
    fn test_kernel_bypasses_all() {
        // Kernel can read anything
        let d = MacGuard::check_read(SecurityLevel::Public, SecurityLevel::Kernel, true);
        assert!(d.is_allow());
        // Kernel can write anywhere
        let d = MacGuard::check_write(SecurityLevel::Public, SecurityLevel::Kernel, true, false, false);
        assert!(d.is_allow());
        let d = MacGuard::check_write(SecurityLevel::Kernel, SecurityLevel::Public, true, false, false);
        assert!(d.is_allow());
    }

    #[test]
    fn test_same_level_always_allowed() {
        for level in [SecurityLevel::Public, SecurityLevel::ToolIO, SecurityLevel::Standard,
                      SecurityLevel::Protected, SecurityLevel::Control, SecurityLevel::Kernel] {
            let d = MacGuard::check_read(level, level, false);
            assert!(d.is_allow(), "Read same level {:?} should be allowed", level);
            let d = MacGuard::check_write(level, level, false, false, false);
            assert!(d.is_allow(), "Write same level {:?} should be allowed", level);
        }
    }

    #[test]
    fn test_combined_operation_read_denied() {
        let d = MacGuard::check_operation(
            SecurityLevel::Standard, SecurityLevel::Kernel,
            true, false, false, false, false,
        );
        assert!(d.is_deny());
    }

    #[test]
    fn test_combined_operation_write_denied() {
        let d = MacGuard::check_operation(
            SecurityLevel::Standard, SecurityLevel::Protected,
            false, true, false, false, false,
        );
        assert!(d.is_deny());
    }

    #[test]
    fn test_guard_decision_variants() {
        assert!(GuardDecision::Allow.is_allow());
        assert!(!GuardDecision::Allow.is_deny());
        assert!(GuardDecision::Deny { reason: "test".into() }.is_deny());
        assert!(GuardDecision::Hold { reason: "test".into() }.is_hold());
        assert!(!GuardDecision::Redact { fields: vec![] }.is_deny());
    }
}
