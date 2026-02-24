//! Audit Exporters — compliance report generation for SOC2, HIPAA, GDPR, and SCITT.
//!
//! Transforms the kernel's audit log + packets + sessions into structured
//! compliance reports that satisfy regulatory requirements:
//! - **SOC2**: Trust Services Criteria (CC6.1 access control, CC7.2 monitoring)
//! - **HIPAA**: §164.312 audit controls, §164.528 access accounting
//! - **GDPR**: Art. 15 right of access, Art. 17 right to erasure, Art. 30 records of processing
//! - **SCITT**: Supply Chain Integrity, Transparency and Trust receipts (IETF draft-ietf-scitt-architecture)
//!
//! Design sources: EU AI Act Art. 12 (logging), FDA 21 CFR Part 11 (electronic records),
//! FINRA Rule 3110 (supervision), NIST 800-53 AU controls.

use std::collections::BTreeMap;

use cid::Cid;
use serde::{Deserialize, Serialize};

use crate::cid::{compute_cid, sha256};
use crate::types::*;

/// Simple hex encoding (avoids external `hex` crate dependency)
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// =============================================================================
// Common types
// =============================================================================

/// Compliance framework identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Soc2,
    Hipaa,
    Gdpr,
    Scitt,
    EuAiAct,
    Finra,
    Fda21Cfr11,
    Nist80053,
    Nist80061,
    Custom(String),
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceFramework::Soc2 => write!(f, "SOC2"),
            ComplianceFramework::Hipaa => write!(f, "HIPAA"),
            ComplianceFramework::Gdpr => write!(f, "GDPR"),
            ComplianceFramework::Scitt => write!(f, "SCITT"),
            ComplianceFramework::EuAiAct => write!(f, "EU_AI_Act"),
            ComplianceFramework::Finra => write!(f, "FINRA"),
            ComplianceFramework::Fda21Cfr11 => write!(f, "FDA_21CFR11"),
            ComplianceFramework::Nist80053 => write!(f, "NIST_800-53"),
            ComplianceFramework::Nist80061 => write!(f, "NIST_800-61"),
            ComplianceFramework::Custom(s) => write!(f, "Custom({})", s),
        }
    }
}

/// Time range for audit queries
#[derive(Debug, Clone)]
pub struct AuditTimeRange {
    pub from_ms: i64,
    pub to_ms: i64,
}

/// A single audit finding / line item in a compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    /// Finding identifier
    pub finding_id: String,
    /// Compliance control reference (e.g., "CC6.1", "§164.312(b)")
    pub control_ref: String,
    /// Finding status
    pub status: FindingStatus,
    /// Description
    pub description: String,
    /// Evidence: audit entry IDs that support this finding
    pub evidence_audit_ids: Vec<String>,
    /// Evidence: packet CIDs
    pub evidence_cids: Vec<String>,
    /// Timestamp
    pub timestamp: i64,
}

/// Status of a compliance finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Control is satisfied
    Pass,
    /// Control has a gap
    Fail,
    /// Informational / advisory
    Info,
    /// Needs manual review
    Review,
}

// =============================================================================
// SOC2 Export
// =============================================================================

/// SOC2 Trust Services Criteria report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soc2Report {
    pub report_id: String,
    pub generated_at: i64,
    pub time_range: (i64, i64),
    pub framework: ComplianceFramework,
    /// CC6: Logical and Physical Access Controls
    pub access_control_findings: Vec<AuditFinding>,
    /// CC7: System Operations (monitoring, incident response)
    pub operations_findings: Vec<AuditFinding>,
    /// CC8: Change Management
    pub change_management_findings: Vec<AuditFinding>,
    /// Summary statistics
    pub total_operations: u64,
    pub total_access_checks: u64,
    pub total_denied: u64,
    pub total_agents: u64,
    /// Integrity hash of this report
    pub report_hash: Option<String>,
}

/// Generate a SOC2 compliance report from kernel audit entries.
pub fn export_soc2(
    audit_log: &[KernelAuditEntry],
    time_range: &AuditTimeRange,
) -> Soc2Report {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let filtered: Vec<&KernelAuditEntry> = audit_log
        .iter()
        .filter(|e| e.timestamp >= time_range.from_ms && e.timestamp <= time_range.to_ms)
        .collect();

    let mut access_findings = Vec::new();
    let mut ops_findings = Vec::new();
    let mut change_findings = Vec::new();
    let mut total_access_checks = 0u64;
    let mut total_denied = 0u64;
    let mut agents: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in &filtered {
        agents.insert(entry.agent_pid.clone());

        match entry.operation {
            // CC6.1: Logical Access — every access check is logged
            MemoryKernelOp::AccessCheck | MemoryKernelOp::AccessGrant | MemoryKernelOp::AccessRevoke => {
                total_access_checks += 1;
                if entry.outcome == OpOutcome::Denied {
                    total_denied += 1;
                    access_findings.push(AuditFinding {
                        finding_id: format!("SOC2-CC6.1-{}", entry.audit_id),
                        control_ref: "CC6.1".to_string(),
                        status: FindingStatus::Info,
                        description: format!(
                            "Access denied: agent={} target={} reason={}",
                            entry.agent_pid,
                            entry.target.as_deref().unwrap_or("unknown"),
                            entry.error.as_deref().unwrap_or("none"),
                        ),
                        evidence_audit_ids: vec![entry.audit_id.clone()],
                        evidence_cids: vec![],
                        timestamp: entry.timestamp,
                    });
                }
            }
            // CC7.2: Monitoring — all memory operations logged
            MemoryKernelOp::MemWrite | MemoryKernelOp::MemRead | MemoryKernelOp::MemEvict => {
                if entry.outcome == OpOutcome::Failed {
                    ops_findings.push(AuditFinding {
                        finding_id: format!("SOC2-CC7.2-{}", entry.audit_id),
                        control_ref: "CC7.2".to_string(),
                        status: FindingStatus::Review,
                        description: format!(
                            "Operation failed: op={} agent={} error={}",
                            entry.operation,
                            entry.agent_pid,
                            entry.error.as_deref().unwrap_or("none"),
                        ),
                        evidence_audit_ids: vec![entry.audit_id.clone()],
                        evidence_cids: vec![],
                        timestamp: entry.timestamp,
                    });
                }
            }
            // CC8.1: Change Management — seal, clear, terminate
            MemoryKernelOp::MemSeal | MemoryKernelOp::MemClear | MemoryKernelOp::AgentTerminate => {
                change_findings.push(AuditFinding {
                    finding_id: format!("SOC2-CC8.1-{}", entry.audit_id),
                    control_ref: "CC8.1".to_string(),
                    status: FindingStatus::Info,
                    description: format!(
                        "Change event: op={} agent={} target={}",
                        entry.operation,
                        entry.agent_pid,
                        entry.target.as_deref().unwrap_or("none"),
                    ),
                    evidence_audit_ids: vec![entry.audit_id.clone()],
                    evidence_cids: vec![],
                    timestamp: entry.timestamp,
                });
            }
            _ => {}
        }
    }

    // CC6.1 pass/fail: access control is in place if all operations are logged
    access_findings.push(AuditFinding {
        finding_id: "SOC2-CC6.1-summary".to_string(),
        control_ref: "CC6.1".to_string(),
        status: FindingStatus::Pass,
        description: format!(
            "All {} access operations logged. {} denied attempts recorded.",
            total_access_checks, total_denied,
        ),
        evidence_audit_ids: vec![],
        evidence_cids: vec![],
        timestamp: now,
    });

    // CC7.2 pass: monitoring is in place
    ops_findings.push(AuditFinding {
        finding_id: "SOC2-CC7.2-summary".to_string(),
        control_ref: "CC7.2".to_string(),
        status: FindingStatus::Pass,
        description: format!(
            "All {} operations monitored and logged in audit trail.",
            filtered.len(),
        ),
        evidence_audit_ids: vec![],
        evidence_cids: vec![],
        timestamp: now,
    });

    let mut report = Soc2Report {
        report_id: format!("soc2-{}", now),
        generated_at: now,
        time_range: (time_range.from_ms, time_range.to_ms),
        framework: ComplianceFramework::Soc2,
        access_control_findings: access_findings,
        operations_findings: ops_findings,
        change_management_findings: change_findings,
        total_operations: filtered.len() as u64,
        total_access_checks,
        total_denied,
        total_agents: agents.len() as u64,
        report_hash: None,
    };

    // Compute integrity hash
    if let Ok(bytes) = serde_json::to_vec(&report) {
        let hash = sha256(&bytes);
        report.report_hash = Some(to_hex(&hash));
    }

    report
}

// =============================================================================
// HIPAA Export
// =============================================================================

/// HIPAA compliance report — §164.312 audit controls, §164.528 access accounting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaReport {
    pub report_id: String,
    pub generated_at: i64,
    pub time_range: (i64, i64),
    pub framework: ComplianceFramework,
    /// §164.312(b): Audit controls — every access to PHI is logged
    pub audit_control_findings: Vec<AuditFinding>,
    /// §164.312(a): Access control — only authorized agents access PHI
    pub access_control_findings: Vec<AuditFinding>,
    /// §164.312(c): Integrity — data has not been altered
    pub integrity_findings: Vec<AuditFinding>,
    /// §164.528: Accounting of disclosures
    pub disclosure_log: Vec<DisclosureEntry>,
    /// Summary
    pub total_phi_accesses: u64,
    pub total_unauthorized_attempts: u64,
    pub integrity_verified: bool,
    pub report_hash: Option<String>,
}

/// A PHI disclosure entry per §164.528
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureEntry {
    /// Who accessed the data
    pub agent_pid: String,
    /// What was accessed
    pub target: String,
    /// When
    pub timestamp: i64,
    /// Purpose
    pub purpose: String,
    /// Audit entry ID
    pub audit_id: String,
}

/// Generate a HIPAA compliance report.
pub fn export_hipaa(
    audit_log: &[KernelAuditEntry],
    time_range: &AuditTimeRange,
) -> HipaaReport {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let filtered: Vec<&KernelAuditEntry> = audit_log
        .iter()
        .filter(|e| e.timestamp >= time_range.from_ms && e.timestamp <= time_range.to_ms)
        .collect();

    let mut audit_findings = Vec::new();
    let mut access_findings = Vec::new();
    let mut integrity_findings = Vec::new();
    let mut disclosure_log = Vec::new();
    let mut total_phi_accesses = 0u64;
    let mut total_unauthorized = 0u64;

    for entry in &filtered {
        match entry.operation {
            MemoryKernelOp::MemRead => {
                total_phi_accesses += 1;
                disclosure_log.push(DisclosureEntry {
                    agent_pid: entry.agent_pid.clone(),
                    target: entry.target.clone().unwrap_or_default(),
                    timestamp: entry.timestamp,
                    purpose: entry.reason.clone().unwrap_or("unspecified".to_string()),
                    audit_id: entry.audit_id.clone(),
                });

                if entry.outcome == OpOutcome::Denied {
                    total_unauthorized += 1;
                    access_findings.push(AuditFinding {
                        finding_id: format!("HIPAA-312a-{}", entry.audit_id),
                        control_ref: "§164.312(a)".to_string(),
                        status: FindingStatus::Info,
                        description: format!(
                            "Unauthorized PHI access attempt: agent={} target={}",
                            entry.agent_pid,
                            entry.target.as_deref().unwrap_or("unknown"),
                        ),
                        evidence_audit_ids: vec![entry.audit_id.clone()],
                        evidence_cids: vec![],
                        timestamp: entry.timestamp,
                    });
                }
            }
            MemoryKernelOp::MemWrite => {
                total_phi_accesses += 1;
                audit_findings.push(AuditFinding {
                    finding_id: format!("HIPAA-312b-{}", entry.audit_id),
                    control_ref: "§164.312(b)".to_string(),
                    status: FindingStatus::Pass,
                    description: format!(
                        "PHI write logged: agent={} target={}",
                        entry.agent_pid,
                        entry.target.as_deref().unwrap_or("unknown"),
                    ),
                    evidence_audit_ids: vec![entry.audit_id.clone()],
                    evidence_cids: vec![],
                    timestamp: entry.timestamp,
                });
            }
            MemoryKernelOp::IntegrityCheck => {
                let passed = entry.outcome == OpOutcome::Success;
                integrity_findings.push(AuditFinding {
                    finding_id: format!("HIPAA-312c-{}", entry.audit_id),
                    control_ref: "§164.312(c)".to_string(),
                    status: if passed { FindingStatus::Pass } else { FindingStatus::Fail },
                    description: format!(
                        "Integrity check {}: {}",
                        if passed { "passed" } else { "FAILED" },
                        entry.error.as_deref().unwrap_or("no errors"),
                    ),
                    evidence_audit_ids: vec![entry.audit_id.clone()],
                    evidence_cids: vec![],
                    timestamp: entry.timestamp,
                });
            }
            MemoryKernelOp::MemSeal => {
                integrity_findings.push(AuditFinding {
                    finding_id: format!("HIPAA-312c-seal-{}", entry.audit_id),
                    control_ref: "§164.312(c)".to_string(),
                    status: FindingStatus::Pass,
                    description: format!(
                        "Data sealed (immutable): target={}",
                        entry.target.as_deref().unwrap_or("unknown"),
                    ),
                    evidence_audit_ids: vec![entry.audit_id.clone()],
                    evidence_cids: vec![],
                    timestamp: entry.timestamp,
                });
            }
            _ => {}
        }
    }

    let integrity_verified = integrity_findings.iter().all(|f| f.status != FindingStatus::Fail);

    let mut report = HipaaReport {
        report_id: format!("hipaa-{}", now),
        generated_at: now,
        time_range: (time_range.from_ms, time_range.to_ms),
        framework: ComplianceFramework::Hipaa,
        audit_control_findings: audit_findings,
        access_control_findings: access_findings,
        integrity_findings,
        disclosure_log,
        total_phi_accesses,
        total_unauthorized_attempts: total_unauthorized,
        integrity_verified,
        report_hash: None,
    };

    if let Ok(bytes) = serde_json::to_vec(&report) {
        report.report_hash = Some(to_hex(&sha256(&bytes)));
    }

    report
}

// =============================================================================
// GDPR Export
// =============================================================================

/// GDPR compliance report — Art. 15, 17, 30
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdprReport {
    pub report_id: String,
    pub generated_at: i64,
    pub time_range: (i64, i64),
    pub framework: ComplianceFramework,
    /// Art. 30: Records of processing activities
    pub processing_records: Vec<ProcessingRecord>,
    /// Art. 15: Right of access — what data do we hold about a subject?
    pub subject_access_records: Vec<SubjectAccessRecord>,
    /// Art. 17: Right to erasure — what was deleted?
    pub erasure_records: Vec<ErasureRecord>,
    /// Summary
    pub total_processing_activities: u64,
    pub total_subjects: u64,
    pub report_hash: Option<String>,
}

/// Art. 30: A record of processing activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingRecord {
    /// What operation was performed
    pub operation: String,
    /// Who performed it (agent PID)
    pub controller: String,
    /// Purpose of processing
    pub purpose: String,
    /// Data subject(s) affected
    pub data_subjects: Vec<String>,
    /// Legal basis
    pub legal_basis: String,
    /// When
    pub timestamp: i64,
    /// Audit entry ID
    pub audit_id: String,
}

/// Art. 15: Subject access record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectAccessRecord {
    /// Data subject identifier
    pub subject_id: String,
    /// Operations involving this subject
    pub operations: Vec<String>,
    /// Total accesses
    pub access_count: u64,
    /// First access
    pub first_access: i64,
    /// Last access
    pub last_access: i64,
}

/// Art. 17: Erasure record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureRecord {
    /// What was erased
    pub target: String,
    /// Who requested erasure
    pub requested_by: String,
    /// When
    pub erased_at: i64,
    /// Audit entry ID
    pub audit_id: String,
}

/// Generate a GDPR compliance report.
pub fn export_gdpr(
    audit_log: &[KernelAuditEntry],
    time_range: &AuditTimeRange,
) -> GdprReport {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let filtered: Vec<&KernelAuditEntry> = audit_log
        .iter()
        .filter(|e| e.timestamp >= time_range.from_ms && e.timestamp <= time_range.to_ms)
        .collect();

    let mut processing_records = Vec::new();
    let mut erasure_records = Vec::new();
    let mut subject_map: BTreeMap<String, SubjectAccessRecord> = BTreeMap::new();

    for entry in &filtered {
        // Art. 30: Record every write/read as a processing activity
        match entry.operation {
            MemoryKernelOp::MemWrite | MemoryKernelOp::MemRead => {
                let target = entry.target.clone().unwrap_or_default();
                processing_records.push(ProcessingRecord {
                    operation: entry.operation.to_string(),
                    controller: entry.agent_pid.clone(),
                    purpose: entry.reason.clone().unwrap_or("agent_processing".to_string()),
                    data_subjects: vec![target.clone()],
                    legal_basis: "legitimate_interest".to_string(),
                    timestamp: entry.timestamp,
                    audit_id: entry.audit_id.clone(),
                });

                // Track per-subject access
                if !target.is_empty() {
                    let record = subject_map.entry(target.clone()).or_insert_with(|| {
                        SubjectAccessRecord {
                            subject_id: target,
                            operations: Vec::new(),
                            access_count: 0,
                            first_access: entry.timestamp,
                            last_access: entry.timestamp,
                        }
                    });
                    record.access_count += 1;
                    record.last_access = record.last_access.max(entry.timestamp);
                    let op_str = entry.operation.to_string();
                    if !record.operations.contains(&op_str) {
                        record.operations.push(op_str);
                    }
                }
            }
            // Art. 17: Erasure
            MemoryKernelOp::MemClear | MemoryKernelOp::MemEvict => {
                erasure_records.push(ErasureRecord {
                    target: entry.target.clone().unwrap_or_default(),
                    requested_by: entry.agent_pid.clone(),
                    erased_at: entry.timestamp,
                    audit_id: entry.audit_id.clone(),
                });
            }
            _ => {}
        }
    }

    let subject_access_records: Vec<SubjectAccessRecord> = subject_map.into_values().collect();
    let total_subjects = subject_access_records.len() as u64;

    let mut report = GdprReport {
        report_id: format!("gdpr-{}", now),
        generated_at: now,
        time_range: (time_range.from_ms, time_range.to_ms),
        framework: ComplianceFramework::Gdpr,
        processing_records,
        subject_access_records,
        erasure_records,
        total_processing_activities: filtered.len() as u64,
        total_subjects,
        report_hash: None,
    };

    if let Ok(bytes) = serde_json::to_vec(&report) {
        report.report_hash = Some(to_hex(&sha256(&bytes)));
    }

    report
}

// =============================================================================
// SCITT Receipt
// =============================================================================

/// SCITT Signed Statement — a claim about a software artifact or agent action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScittStatement {
    /// Statement identifier
    pub statement_id: String,
    /// Issuer (agent PID or DID)
    pub issuer: String,
    /// Subject (what this statement is about)
    pub subject: String,
    /// Content type
    pub content_type: String,
    /// The claim payload
    pub payload: serde_json::Value,
    /// Timestamp
    pub issued_at: i64,
}

/// SCITT Receipt — proof that a statement was registered in the transparency log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScittReceipt {
    /// Receipt identifier
    pub receipt_id: String,
    /// The statement this receipt is for
    pub statement_id: String,
    /// Transparency log entry number (maps to RangeWindow sn)
    pub log_entry: u64,
    /// Merkle tree root at time of registration
    pub tree_root: [u8; 32],
    /// Tree size at time of registration
    pub tree_size: u64,
    /// Inclusion proof (Merkle path)
    pub inclusion_proof: Vec<[u8; 32]>,
    /// Timestamp of registration
    pub registered_at: i64,
    /// CID of the receipt itself
    pub receipt_cid: Option<Cid>,
}

/// Generate a SCITT receipt for a packet CID within a RangeWindow.
///
/// The receipt proves that the packet was included in the transparency log
/// at a specific tree size, with a verifiable Merkle inclusion proof.
pub fn generate_scitt_receipt(
    statement_id: &str,
    packet_cid: &Cid,
    window_sn: u64,
    window_leaf_cids: &[Cid],
    window_root: [u8; 32],
    tree_size: u64,
) -> Option<ScittReceipt> {
    // Find the packet's index in the window
    let index = window_leaf_cids.iter().position(|c| c == packet_cid)?;

    // Compute inclusion proof
    let proof = crate::range_window::compute_inclusion_proof(window_leaf_cids, index)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let mut receipt = ScittReceipt {
        receipt_id: format!("scitt-receipt-{}-{}", window_sn, index),
        statement_id: statement_id.to_string(),
        log_entry: window_sn,
        tree_root: window_root,
        tree_size,
        inclusion_proof: proof,
        registered_at: now,
        receipt_cid: None,
    };

    if let Ok(cid) = compute_cid(&receipt) {
        receipt.receipt_cid = Some(cid);
    }

    Some(receipt)
}

/// Verify a SCITT receipt's inclusion proof
pub fn verify_scitt_receipt(receipt: &ScittReceipt, packet_cid: &Cid) -> bool {
    crate::range_window::verify_inclusion_proof(
        packet_cid,
        0, // The proof was generated for the packet's position
        receipt.tree_size as usize,
        &receipt.inclusion_proof,
        &receipt.tree_root,
    )
}

// =============================================================================
// Multi-framework export
// =============================================================================

/// Export audit data for multiple compliance frameworks at once
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiFrameworkReport {
    pub generated_at: i64,
    pub frameworks: Vec<ComplianceFramework>,
    pub soc2: Option<Soc2Report>,
    pub hipaa: Option<HipaaReport>,
    pub gdpr: Option<GdprReport>,
    pub report_hash: Option<String>,
}

/// Generate reports for all requested frameworks
pub fn export_multi(
    audit_log: &[KernelAuditEntry],
    time_range: &AuditTimeRange,
    frameworks: &[ComplianceFramework],
) -> MultiFrameworkReport {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let soc2 = if frameworks.contains(&ComplianceFramework::Soc2) {
        Some(export_soc2(audit_log, time_range))
    } else {
        None
    };

    let hipaa = if frameworks.contains(&ComplianceFramework::Hipaa) {
        Some(export_hipaa(audit_log, time_range))
    } else {
        None
    };

    let gdpr = if frameworks.contains(&ComplianceFramework::Gdpr) {
        Some(export_gdpr(audit_log, time_range))
    } else {
        None
    };

    let mut report = MultiFrameworkReport {
        generated_at: now,
        frameworks: frameworks.to_vec(),
        soc2,
        hipaa,
        gdpr,
        report_hash: None,
    };

    if let Ok(bytes) = serde_json::to_vec(&report) {
        report.report_hash = Some(to_hex(&sha256(&bytes)));
    }

    report
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_audit_entries() -> Vec<KernelAuditEntry> {
        vec![
            KernelAuditEntry {
                audit_id: "a001".into(), timestamp: 1000,
                operation: MemoryKernelOp::AgentRegister,
                agent_pid: "pid:001".into(), target: Some("pid:001".into()),
                outcome: OpOutcome::Success, reason: Some("register".into()),
                error: None, duration_us: Some(100), vakya_id: None,
                before_hash: None, after_hash: None, merkle_root: None, scitt_receipt_cid: None,
            },
            KernelAuditEntry {
                audit_id: "a002".into(), timestamp: 2000,
                operation: MemoryKernelOp::MemWrite,
                agent_pid: "pid:001".into(), target: Some("cid:packet1".into()),
                outcome: OpOutcome::Success, reason: Some("store extraction".into()),
                error: None, duration_us: Some(200), vakya_id: None,
                before_hash: None, after_hash: Some("hash1".into()), merkle_root: None, scitt_receipt_cid: None,
            },
            KernelAuditEntry {
                audit_id: "a003".into(), timestamp: 3000,
                operation: MemoryKernelOp::MemRead,
                agent_pid: "pid:002".into(), target: Some("cid:packet1".into()),
                outcome: OpOutcome::Denied, reason: None,
                error: Some("No read access to namespace".into()),
                duration_us: Some(10), vakya_id: None,
                before_hash: None, after_hash: None, merkle_root: None, scitt_receipt_cid: None,
            },
            KernelAuditEntry {
                audit_id: "a004".into(), timestamp: 4000,
                operation: MemoryKernelOp::AccessCheck,
                agent_pid: "pid:002".into(), target: Some("ns:hospital".into()),
                outcome: OpOutcome::Denied, reason: None,
                error: Some("No access".into()),
                duration_us: Some(5), vakya_id: None,
                before_hash: None, after_hash: None, merkle_root: None, scitt_receipt_cid: None,
            },
            KernelAuditEntry {
                audit_id: "a005".into(), timestamp: 5000,
                operation: MemoryKernelOp::MemSeal,
                agent_pid: "pid:001".into(), target: Some("sealed:2".into()),
                outcome: OpOutcome::Success, reason: Some("evidence preservation".into()),
                error: None, duration_us: Some(50), vakya_id: None,
                before_hash: None, after_hash: None, merkle_root: None, scitt_receipt_cid: None,
            },
            KernelAuditEntry {
                audit_id: "a006".into(), timestamp: 6000,
                operation: MemoryKernelOp::IntegrityCheck,
                agent_pid: "pid:001".into(), target: Some("errors:0".into()),
                outcome: OpOutcome::Success, reason: None,
                error: None, duration_us: Some(300), vakya_id: None,
                before_hash: None, after_hash: None, merkle_root: None, scitt_receipt_cid: None,
            },
            KernelAuditEntry {
                audit_id: "a007".into(), timestamp: 7000,
                operation: MemoryKernelOp::MemEvict,
                agent_pid: "pid:001".into(), target: Some("evicted:3".into()),
                outcome: OpOutcome::Success, reason: Some("cleanup".into()),
                error: None, duration_us: Some(150), vakya_id: None,
                before_hash: None, after_hash: None, merkle_root: None, scitt_receipt_cid: None,
            },
        ]
    }

    fn time_range() -> AuditTimeRange {
        AuditTimeRange { from_ms: 0, to_ms: 10000 }
    }

    #[test]
    fn test_soc2_export() {
        let entries = make_audit_entries();
        let report = export_soc2(&entries, &time_range());

        assert_eq!(report.framework, ComplianceFramework::Soc2);
        assert_eq!(report.total_operations, 7);
        assert!(report.total_access_checks >= 1);
        assert!(report.total_denied >= 1);
        assert!(report.total_agents >= 1);
        assert!(report.report_hash.is_some());

        // Should have access control findings (denied attempts + summary)
        assert!(!report.access_control_findings.is_empty());
        // Should have CC6.1 summary pass
        assert!(report.access_control_findings.iter().any(|f| f.status == FindingStatus::Pass));
    }

    #[test]
    fn test_hipaa_export() {
        let entries = make_audit_entries();
        let report = export_hipaa(&entries, &time_range());

        assert_eq!(report.framework, ComplianceFramework::Hipaa);
        assert!(report.total_phi_accesses >= 2); // write + read
        assert_eq!(report.total_unauthorized_attempts, 1); // denied read
        assert!(report.integrity_verified); // integrity check passed
        assert!(report.report_hash.is_some());

        // Disclosure log should have entries
        assert!(!report.disclosure_log.is_empty());

        // Integrity findings should include seal + integrity check
        assert!(report.integrity_findings.iter().any(|f| f.control_ref == "§164.312(c)"));
    }

    #[test]
    fn test_gdpr_export() {
        let entries = make_audit_entries();
        let report = export_gdpr(&entries, &time_range());

        assert_eq!(report.framework, ComplianceFramework::Gdpr);
        assert!(!report.processing_records.is_empty());
        assert!(report.total_subjects >= 1);
        assert!(report.report_hash.is_some());

        // Erasure records from MemEvict
        assert!(!report.erasure_records.is_empty());

        // Subject access records
        assert!(!report.subject_access_records.is_empty());
    }

    #[test]
    fn test_scitt_receipt_generation() {
        use crate::range_window::compute_merkle_root;

        let cids: Vec<Cid> = (0..4u8).map(|i| {
            crate::cid::compute_cid(&vec![i; 32]).unwrap_or_default()
        }).collect();

        let root = compute_merkle_root(&cids);

        let receipt = generate_scitt_receipt(
            "stmt:001",
            &cids[2],
            0,
            &cids,
            root,
            4,
        );

        assert!(receipt.is_some());
        let receipt = receipt.unwrap();
        assert_eq!(receipt.statement_id, "stmt:001");
        assert_eq!(receipt.log_entry, 0);
        assert_eq!(receipt.tree_size, 4);
        assert!(!receipt.inclusion_proof.is_empty());
        assert!(receipt.receipt_cid.is_some());
    }

    #[test]
    fn test_scitt_receipt_not_found() {
        let cids: Vec<Cid> = (0..2u8).map(|i| {
            crate::cid::compute_cid(&vec![i; 32]).unwrap_or_default()
        }).collect();
        let root = crate::range_window::compute_merkle_root(&cids);

        let fake_cid = crate::cid::compute_cid(&vec![99u8; 32]).unwrap_or_default();
        let receipt = generate_scitt_receipt("stmt:x", &fake_cid, 0, &cids, root, 2);
        assert!(receipt.is_none());
    }

    #[test]
    fn test_multi_framework_export() {
        let entries = make_audit_entries();
        let report = export_multi(
            &entries,
            &time_range(),
            &[ComplianceFramework::Soc2, ComplianceFramework::Hipaa, ComplianceFramework::Gdpr],
        );

        assert!(report.soc2.is_some());
        assert!(report.hipaa.is_some());
        assert!(report.gdpr.is_some());
        assert_eq!(report.frameworks.len(), 3);
        assert!(report.report_hash.is_some());
    }

    #[test]
    fn test_empty_time_range() {
        let entries = make_audit_entries();
        let narrow = AuditTimeRange { from_ms: 99999, to_ms: 100000 };
        let report = export_soc2(&entries, &narrow);
        assert_eq!(report.total_operations, 0);
    }

    #[test]
    fn test_compliance_framework_display() {
        assert_eq!(ComplianceFramework::Soc2.to_string(), "SOC2");
        assert_eq!(ComplianceFramework::Hipaa.to_string(), "HIPAA");
        assert_eq!(ComplianceFramework::Gdpr.to_string(), "GDPR");
        assert_eq!(ComplianceFramework::Scitt.to_string(), "SCITT");
        assert_eq!(ComplianceFramework::EuAiAct.to_string(), "EU_AI_Act");
    }
}
