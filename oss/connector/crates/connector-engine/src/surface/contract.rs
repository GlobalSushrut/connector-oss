//! Surface Contract — Mandatory output invariants per SURFACE_CONTRACT_STANDARD.md
//!
//! Every surface MUST return these fields. No exceptions.
//! This is the governing standard for all Connector outputs.

use super::document::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The mandatory contract that every surface output must satisfy.
/// This is the core invariant that makes SOE enterprise-grade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceContract {
    pub subject: SubjectIdentity,
    pub state: StateVector,
    pub judgment: Judgment,
    pub signals: Vec<Signal>,
    pub actions: Vec<SurfaceAction>,
    pub evidence: EvidencePosture,
    pub trust: TrustScore,
}

/// One-line summary judgment with severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Judgment {
    pub text: String,
    pub severity: Severity,
}

impl Judgment {
    pub fn ok(text: impl Into<String>) -> Self { Self { text: text.into(), severity: Severity::Ok } }
    pub fn info(text: impl Into<String>) -> Self { Self { text: text.into(), severity: Severity::Info } }
    pub fn warn(text: impl Into<String>) -> Self { Self { text: text.into(), severity: Severity::Warn } }
    pub fn risk(text: impl Into<String>) -> Self { Self { text: text.into(), severity: Severity::Risk } }
    pub fn critical(text: impl Into<String>) -> Self { Self { text: text.into(), severity: Severity::Critical } }
}

/// Key signal with optional deep link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub icon: SignalIcon,
    pub text: String,
    pub link: Option<ResourceLink>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalIcon { Check, Cross, Warning, Info, Question }

impl SignalIcon {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Check => "✓", Self::Cross => "✗", Self::Warning => "⚠", Self::Info => "ℹ", Self::Question => "?" }
    }
}

impl Signal {
    pub fn check(text: impl Into<String>) -> Self { Self { icon: SignalIcon::Check, text: text.into(), link: None } }
    pub fn cross(text: impl Into<String>) -> Self { Self { icon: SignalIcon::Cross, text: text.into(), link: None } }
    pub fn warn(text: impl Into<String>) -> Self { Self { icon: SignalIcon::Warning, text: text.into(), link: None } }
    pub fn info(text: impl Into<String>) -> Self { Self { icon: SignalIcon::Info, text: text.into(), link: None } }
    pub fn with_link(mut self, link: ResourceLink) -> Self { self.link = Some(link); self }
}

/// Contract validation result
#[derive(Debug, Clone)]
pub struct ContractValidation {
    pub valid: bool,
    pub errors: Vec<ContractError>,
    pub warnings: Vec<ContractWarning>,
}

#[derive(Debug, Clone)]
pub struct ContractError {
    pub field: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ContractWarning {
    pub field: &'static str,
    pub message: String,
}

impl SurfaceContract {
    /// Validate that the contract satisfies all mandatory requirements
    pub fn validate(&self) -> ContractValidation {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Subject validation
        if self.subject.display.is_empty() {
            errors.push(ContractError { field: "subject.display", message: "Display name is required".into() });
        }
        if self.subject.inspect.is_empty() {
            errors.push(ContractError { field: "subject.inspect", message: "Inspect ID is required".into() });
        }

        // Judgment validation
        if self.judgment.text.is_empty() {
            errors.push(ContractError { field: "judgment.text", message: "Judgment text is required".into() });
        }
        if self.judgment.text.len() > 100 {
            warnings.push(ContractWarning { field: "judgment.text", message: "Judgment should be one line (<100 chars)".into() });
        }

        // Signals validation (3–7 mandatory per Surface Contract Standard)
        if self.signals.len() < 3 {
            errors.push(ContractError {
                field: "signals",
                message: "Between 3 and 7 signals are required".into(),
            });
        }
        if self.signals.len() > 7 {
            warnings.push(ContractWarning { field: "signals", message: "More than 7 signals may overwhelm users".into() });
        }

        // Evidence validation
        if self.evidence.status == EvidenceStatus::Missing && self.trust.score > 50 {
            warnings.push(ContractWarning { field: "evidence/trust", message: "High trust with missing evidence is suspicious".into() });
        }

        ContractValidation { valid: errors.is_empty(), errors, warnings }
    }

    /// Convert contract to a full surface document
    pub fn to_document(&self, surface_type: SurfaceType, view: SurfaceView) -> SurfaceDocument {
        SurfaceDocument {
            meta: SurfaceMeta { surface_type, view, generated_at: chrono::Utc::now().timestamp_millis() },
            header: SurfaceHeader {
                title: format!("{}: {}", surface_type_str(surface_type), self.subject.display),
                subject: self.subject.clone(),
                state: self.state.clone(),
                badges: vec![
                    SurfaceBadge { label: "Trust".into(), value: format!("{}/{}", self.trust.score, self.trust.grade.as_char()), severity: if self.trust.score >= 80 { Severity::Ok } else if self.trust.score >= 60 { Severity::Warn } else { Severity::Risk } },
                    SurfaceBadge { label: "Evidence".into(), value: self.evidence.status.as_str().into(), severity: match self.evidence.status { EvidenceStatus::Complete => Severity::Ok, EvidenceStatus::Partial => Severity::Warn, _ => Severity::Risk } },
                ],
                time_range: None,
            },
            summary: Some(self.judgment.text.clone()),
            sections: vec![
                SurfaceSection {
                    title: "Signals".into(),
                    kind: SectionKind::Findings,
                    content: SectionContent::Findings(self.signals.iter().map(|s| Finding {
                        severity: match s.icon { SignalIcon::Check => Severity::Ok, SignalIcon::Cross => Severity::Critical, SignalIcon::Warning => Severity::Warn, _ => Severity::Info },
                        code: "".into(),
                        message: s.text.clone(),
                        link: s.link.clone(),
                    }).collect()),
                    collapsed: false,
                },
            ],
            actions: self.actions.clone(),
            footer: Some(SurfaceFooter {
                root_hash: self.evidence.root_hash.clone(),
                verified: self.evidence.verified,
                receipt_count: self.evidence.receipt_count as u32,
                chain_valid: self.evidence.chain_intact,
                timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            }),
        }
    }
}

pub fn surface_type_str(st: SurfaceType) -> &'static str {
    match st {
        SurfaceType::Agent => "AGENT", SurfaceType::Audit => "AUDIT", SurfaceType::Memory => "MEMORY",
        SurfaceType::Knowledge => "KNOWLEDGE", SurfaceType::Policy => "POLICY", SurfaceType::Tool => "TOOL",
        SurfaceType::Contract => "CONTRACT", SurfaceType::Proof => "PROOF", SurfaceType::Compliance => "COMPLIANCE",
        SurfaceType::Health => "HEALTH", SurfaceType::Books => "BOOKS", SurfaceType::Debug => "DEBUG",
        SurfaceType::Trace => "TRACE", SurfaceType::Inspect => "INSPECT", SurfaceType::Review => "REVIEW",
        SurfaceType::Explain => "EXPLAIN", SurfaceType::Monitor => "MONITOR",
    }
}

impl EvidenceStatus {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Complete => "COMPLETE", Self::Partial => "PARTIAL", Self::Missing => "MISSING", Self::Corrupted => "CORRUPTED" }
    }
}

impl fmt::Display for ContractValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.valid {
            write!(f, "Contract valid")?;
        } else {
            write!(f, "Contract invalid: {} errors", self.errors.len())?;
        }
        if !self.warnings.is_empty() {
            write!(f, ", {} warnings", self.warnings.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_validation() {
        let contract = SurfaceContract {
            subject: SubjectIdentity::new(ResourceKind::Agent, "test-agent"),
            state: StateVector::active_verified(),
            judgment: Judgment::ok("All systems operational"),
            signals: vec![
                Signal::check("Health OK"),
                Signal::check("Policy compliant"),
                Signal::check("Evidence chain intact"),
            ],
            actions: vec![],
            evidence: EvidencePosture::complete(10, "sha256:abc"),
            trust: TrustScore::new(95),
        };
        let validation = contract.validate();
        assert!(validation.valid);
    }

    #[test]
    fn test_contract_to_document() {
        let contract = SurfaceContract {
            subject: SubjectIdentity::new(ResourceKind::Agent, "test-agent"),
            state: StateVector::active_verified(),
            judgment: Judgment::ok("All systems operational"),
            signals: vec![
                Signal::check("Health OK"),
                Signal::check("Policy aligned"),
                Signal::check("Operational baseline met"),
            ],
            actions: vec![],
            evidence: EvidencePosture::complete(10, "sha256:abc"),
            trust: TrustScore::new(95),
        };
        let doc = contract.to_document(SurfaceType::Agent, SurfaceView::Summary);
        assert!(doc.header.title.contains("AGENT"));
    }
}
