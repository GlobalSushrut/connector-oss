//! package.rs - The semantic decision package for all Connector surfaces.
//!
//! This module defines the `DecisionSurfacePackage`, which is the primary
//! semantic object for all user-facing outputs. It is a layer above the
//! canonical `SurfaceDocument`, designed to transform infrastructure-grade
//! data into a decision-oriented product surface.
//!
//! The core principle is that the semantic package comes first, and the
//! document/render view comes second.

use serde::{Deserialize, Serialize};

use super::document::{ResourceLink, SubjectIdentity};

// ----------------------------------------------------------------------------
// -----------------[ Top-Level Decision Surface Package ]---------------------
// ----------------------------------------------------------------------------

/// The primary semantic package for all Connector decision surfaces.
///
/// This struct is the standard, user-facing representation of a Connector
/// decision. It is designed to be easily rendered into a decision card,
/// JSON API response, or other human-readable format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionSurfacePackage {
    /// The subject of the decision (e.g., agent, service, contract).
    pub subject: SubjectIdentity,
    /// The one-line outcome of the decision.
    pub decision: DecisionLine,
    /// The human-readable explanation for the decision.
    pub why: WhyLine,
    /// The immediate safety and operational risk posture.
    pub risk: RiskLine,
    /// Applicable compliance verdicts (e.g., HIPAA, EU AI Act).
    pub compliance: Vec<ComplianceBadge>,
    /// The legal-grade verification summary.
    pub proof: ProofLine,
    /// The economic impact summary, if applicable.
    pub cost: Option<CostLine>,
    /// Guided next actions for the user.
    pub next: Vec<NextAction>,
    /// How certain the system is about its decision.
    pub confidence: Option<ConfidenceLine>,
    /// Standard metadata for the decision package.
    pub meta: DecisionMeta,
    /// Richer operational reasoning and top evidence for deep dives.
    pub deep: Option<DecisionDeepSections>,
    /// Full proof/evidence chain and internal identifiers for auditors.
    pub forensic: Option<DecisionForensicSections>,
}

// ----------------------------------------------------------------------------
// --------------------[ Core Decision Package Components ]--------------------
// ----------------------------------------------------------------------------

/// A single, clear statement of the decision's outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionLine {
    pub outcome: String,
}

/// A human-readable explanation of why the decision was made.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhyLine {
    pub explanation: String,
    /// Optional link to the specific rule or evidence that drove the reason.
    pub source_link: Option<ResourceLink>,
}

/// The assessed risk posture of the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskLine {
    pub level: RiskLevel,
    pub summary: String,
}

/// The risk level, used for visual prioritization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
    None,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::None => "NONE",
        }
    }
}

/// A badge indicating the verdict for a specific compliance standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceBadge {
    pub standard: String,
    pub status: ComplianceStatus,
}

/// The status of a compliance check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Warn,
    NotApplicable,
}

/// A human-legible summary of the decision's proof posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofLine {
    pub status: ProofStatus,
    pub summary: String,
}

/// The verification status of the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProofStatus {
    Verified,
    Unverified,
    Tampered,
    Incomplete,
}

impl ProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Unverified => "UNVERIFIED",
            Self::Tampered => "TAMPERED",
            Self::Incomplete => "INCOMPLETE",
        }
    }
}

/// The economic impact of the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostLine {
    pub amount_usd: f64,
    pub change_summary: Option<String>, // e.g., "↓18%", "+$0.41 vs last run"
}

/// A guided next action for the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextAction {
    pub label: String,
    pub command: String,
    pub primary: bool,
}

/// The system's confidence in its decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceLine {
    pub score: f64, // 0.0 to 1.0
    pub level: ConfidenceLevel,
}

/// Qualitative confidence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// Metadata associated with the decision package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionMeta {
    pub timestamp: i64,
    pub package_cid: String,
    pub source_document_cid: String,
}

// ----------------------------------------------------------------------------
// ---------------------[ Deep and Forensic Sections ]-------------------------
// ----------------------------------------------------------------------------

/// Container for sections visible in a 'deep' view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionDeepSections {
    pub sections: Vec<super::document::SurfaceSection>,
}

/// Container for sections visible in a 'forensic' view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionForensicSections {
    pub sections: Vec<super::document::SurfaceSection>,
}
