//! Surface Document — Core SOE types per spec

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceDocument {
    pub meta: SurfaceMeta,
    pub header: SurfaceHeader,
    pub summary: Option<String>,
    pub sections: Vec<SurfaceSection>,
    pub actions: Vec<SurfaceAction>,
    pub footer: Option<SurfaceFooter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceMeta {
    pub surface_type: SurfaceType,
    pub view: SurfaceView,
    pub generated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceType { Agent, Audit, Memory, Knowledge, Policy, Tool, Contract, Proof, Compliance, Health, Books, Debug, Trace, Inspect, Review, Explain, Monitor }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SurfaceView { #[default] Summary, Ops, Forensic, Exec }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceHeader {
    pub title: String,
    pub subject: SubjectIdentity,
    pub state: StateVector,
    pub badges: Vec<SurfaceBadge>,
    pub time_range: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectIdentity {
    /// Always shown, e.g. `agent/claims-review-002`
    pub display: String,
    /// CLI inspect target, e.g. `claims-review-002`
    pub inspect: String,
    /// Forensic / proof-oriented id, e.g. `agt_abc123`
    pub proof: String,
    /// Internal stable id; defaults to `inspect` when not separately assigned
    #[serde(default)]
    pub uid: String,
    pub kind: ResourceKind,
    pub namespace: Option<String>,
}

impl SubjectIdentity {
    pub fn new(kind: ResourceKind, name: &str) -> Self {
        let inspect = name.to_string();
        let proof = format!(
            "{}_{}",
            kind.short(),
            &name[..name.len().min(6)]
        );
        Self {
            display: format!("{}/{}", kind.prefix(), name),
            inspect: inspect.clone(),
            proof,
            uid: inspect,
            kind,
            namespace: None,
        }
    }

    /// Effective internal id when `uid` was omitted in deserialization.
    pub fn effective_uid(&self) -> &str {
        if self.uid.is_empty() {
            self.inspect.as_str()
        } else {
            self.uid.as_str()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceKind { Agent, Memory, MemPacket, Knowledge, Audit, Receipt, Tool, Policy, Contract, Proof, Evidence, Run, Session, Event }

impl ResourceKind {
    pub fn prefix(&self) -> &'static str {
        match self { Self::Agent => "agent", Self::Memory => "memory", Self::MemPacket => "packet", Self::Knowledge => "knowledge", Self::Audit => "audit", Self::Receipt => "receipt", Self::Tool => "tool", Self::Policy => "policy", Self::Contract => "contract", Self::Proof => "proof", Self::Evidence => "evidence", Self::Run => "run", Self::Session => "session", Self::Event => "event" }
    }
    pub fn short(&self) -> &'static str {
        match self { Self::Agent => "agt", Self::Memory => "mem", Self::MemPacket => "mpk", Self::Knowledge => "kno", Self::Audit => "aud", Self::Receipt => "rct", Self::Tool => "tol", Self::Policy => "pol", Self::Contract => "cls", Self::Proof => "prf", Self::Evidence => "evd", Self::Run => "run", Self::Session => "ses", Self::Event => "evt" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVector { pub execution: ExecutionState, pub trust: TrustState, pub health: HealthState, pub compliance: ComplianceState }

impl StateVector {
    pub fn display(&self) -> String { format!("{} | {} | {} | {}", self.execution.as_str(), self.trust.as_str(), self.health.as_str(), self.compliance.as_str()) }
    pub fn active_verified() -> Self { Self { execution: ExecutionState::Active, trust: TrustState::Verified, health: HealthState::Healthy, compliance: ComplianceState::Compliant } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionState { Idle, Active, Completed, Failed, Paused, Blocked }
impl ExecutionState { pub fn as_str(&self) -> &'static str { match self { Self::Idle => "IDLE", Self::Active => "ACTIVE", Self::Completed => "COMPLETED", Self::Failed => "FAILED", Self::Paused => "PAUSED", Self::Blocked => "BLOCKED" } } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState { Verified, Partial, Degraded, Broken, Unknown }
impl TrustState { pub fn as_str(&self) -> &'static str { match self { Self::Verified => "VERIFIED", Self::Partial => "PARTIAL", Self::Degraded => "DEGRADED", Self::Broken => "BROKEN", Self::Unknown => "UNKNOWN" } } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState { Healthy, Degraded, Unhealthy, Unknown }
impl HealthState { pub fn as_str(&self) -> &'static str { match self { Self::Healthy => "HEALTHY", Self::Degraded => "DEGRADED", Self::Unhealthy => "UNHEALTHY", Self::Unknown => "UNKNOWN" } } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceState { Compliant, NonCompliant, Partial, Unknown }
impl ComplianceState { pub fn as_str(&self) -> &'static str { match self { Self::Compliant => "COMPLIANT", Self::NonCompliant => "NON-COMPLIANT", Self::Partial => "PARTIAL", Self::Unknown => "UNKNOWN" } } }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePosture { pub status: EvidenceStatus, pub receipt_count: usize, pub verified: bool, pub chain_intact: bool, pub completeness: f64, pub root_hash: Option<String> }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStatus { Complete, Partial, Missing, Corrupted }

impl EvidencePosture {
    pub fn complete(count: usize, hash: &str) -> Self { Self { status: EvidenceStatus::Complete, receipt_count: count, verified: true, chain_intact: true, completeness: 1.0, root_hash: Some(hash.into()) } }
}

/// Letter grade for trust, per Surface Contract Standard (A–F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TrustGrade {
    A,
    B,
    C,
    D,
    F,
}

impl TrustGrade {
    pub fn from_score(score: u8) -> Self {
        match score {
            90..=100 => Self::A,
            80..=89 => Self::B,
            70..=79 => Self::C,
            60..=69 => Self::D,
            _ => Self::F,
        }
    }

    pub const fn as_char(self) -> char {
        match self {
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
            Self::F => 'F',
        }
    }
}

/// Optional breakdown for enterprise reporting (omit empty fields in JSON).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustComponents {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub score: u8,
    pub grade: TrustGrade,
    #[serde(default)]
    pub components: TrustComponents,
}

impl TrustScore {
    pub fn new(score: u8) -> Self {
        Self {
            score,
            grade: TrustGrade::from_score(score),
            components: TrustComponents::default(),
        }
    }

    pub fn with_components(score: u8, components: TrustComponents) -> Self {
        Self {
            score,
            grade: TrustGrade::from_score(score),
            components,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceBadge { pub label: String, pub value: String, pub severity: Severity }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity { Ok, Info, Warn, Risk, Critical }
impl Severity { pub fn icon(&self) -> &'static str { match self { Self::Ok => "✓", Self::Info => "ℹ", Self::Warn => "⚠", Self::Risk => "⚠⚠", Self::Critical => "✖" } } }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceSection { pub title: String, pub kind: SectionKind, pub content: SectionContent, pub collapsed: bool }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionKind { StatsGrid, KeyValueTable, Timeline, Findings, List, Evidence, Narrative, Trace, RawData, Links, Health, Lineage }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectionContent {
    Stats(Vec<StatItem>), KeyValue(Vec<KeyValueItem>), Timeline(Vec<TimelineEvent>),
    Findings(Vec<Finding>), List(Vec<ListItem>), Evidence(Vec<EvidenceItem>),
    Narrative(String), Trace(Vec<TraceSpan>), RawData(BlobContainer), Links(Vec<ResourceLink>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatItem { pub label: String, pub value: String, pub link: Option<ResourceLink> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValueItem { pub key: String, pub value: String, pub link: Option<ResourceLink> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent { pub timestamp: String, pub event_type: String, pub message: String, pub severity: Severity, pub link: Option<ResourceLink> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding { pub severity: Severity, pub code: String, pub message: String, pub link: Option<ResourceLink> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListItem { pub text: String, pub link: Option<ResourceLink> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem { pub evidence_type: String, pub cid: String, pub verified: bool, pub link: ResourceLink }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan { pub span_id: String, pub name: String, pub duration_ms: u64, pub status: String, pub depth: u32, pub link: Option<ResourceLink> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLink { pub label: String, pub resource_type: ResourceKind, pub id: String, pub command: String, pub url: Option<String>, pub action: LinkAction }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkAction { Inspect, Cat, Verify, Trace, Raw, Forensic }

impl ResourceLink {
    pub fn inspect(kind: ResourceKind, id: &str) -> Self { Self { label: "[inspect]".into(), resource_type: kind, id: id.into(), command: format!("connectorctl {} inspect {}", kind.prefix(), id), url: Some(format!("/ui/{}/{}", kind.prefix(), id)), action: LinkAction::Inspect } }
    pub fn verify(kind: ResourceKind, id: &str) -> Self { Self { label: "[verify]".into(), resource_type: kind, id: id.into(), command: format!("connectorctl verify {}", id), url: None, action: LinkAction::Verify } }
    pub fn trace(id: &str) -> Self { Self { label: "[trace]".into(), resource_type: ResourceKind::Run, id: id.into(), command: format!("connectorctl trace {}", id), url: None, action: LinkAction::Trace } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobContainer { pub id: String, pub label: String, pub content_type: ContentType, pub size: usize, pub preview: String, pub expanded: bool }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType { Json, Text, Binary, Markdown }

impl BlobContainer {
    pub fn json(id: &str, data: &serde_json::Value) -> Self {
        let full = serde_json::to_string_pretty(data).unwrap_or_default();
        Self { id: id.into(), label: id.into(), content_type: ContentType::Json, size: full.len(), preview: if full.len() > 80 { format!("{}...", &full[..80]) } else { full }, expanded: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceAction { pub label: String, pub description: String, pub command: String, pub primary: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceFooter { pub root_hash: Option<String>, pub verified: bool, pub receipt_count: u32, pub chain_valid: bool, pub timestamp: String }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_subject_identity() {
        let id = SubjectIdentity::new(ResourceKind::Agent, "claims-review-002");
        assert_eq!(id.display, "agent/claims-review-002");
    }
    #[test]
    fn test_trust_score() {
        assert_eq!(TrustScore::new(95).grade, TrustGrade::A);
        assert_eq!(TrustScore::new(75).grade, TrustGrade::C);
        assert_eq!(TrustScore::new(95).grade.as_char(), 'A');
    }

    #[test]
    fn subject_identity_uid_defaults_to_inspect() {
        let id = SubjectIdentity::new(ResourceKind::Agent, "claims-review-002");
        assert_eq!(id.uid, "claims-review-002");
        assert_eq!(id.effective_uid(), "claims-review-002");
    }
}
