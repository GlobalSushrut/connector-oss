//! Signal Layer — Intelligence extraction for operator-friendly output
//!
//! Transforms raw surface data into prioritized, decision-driven signals.
//! Implements the "1% knowledge" principle: show what matters, hide the rest.

use super::document::*;
use serde::{Deserialize, Serialize};

/// Extracted signal from a surface — the "1% that matters"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub status: StatusLine,
    pub problem: Option<ProblemBlock>,
    pub action: ActionBlock,
    pub impact: Option<ImpactBlock>,
    pub delta: Option<DeltaBlock>,
    pub pattern: Option<PatternBlock>,
    pub trust: TrustLine,
    pub drill_down: String,
}

impl Signal {
    /// Render as compact 3-line output
    pub fn compact(&self) -> String {
        let mut lines = vec![self.status.render()];
        if let Some(ref p) = self.problem { lines.push(p.render()); }
        lines.push(self.action.render());
        lines.join("\n")
    }

    /// Render as operator summary (5-7 lines)
    pub fn summary(&self) -> String {
        let mut lines = vec![self.status.render()];
        if let Some(ref p) = self.problem { lines.push(p.render()); }
        if let Some(ref i) = self.impact { lines.push(i.render()); }
        if let Some(ref d) = self.delta { lines.push(d.render()); }
        lines.push(self.action.render());
        lines.push(format!("  └─ {}", self.drill_down));
        lines.join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusLine {
    pub level: StatusLevel,
    pub subject: String,
    pub state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusLevel { Critical, Degraded, Warning, Healthy, Unknown }

impl StatusLevel {
    pub fn emoji(&self) -> &'static str {
        match self { Self::Critical => "✖", Self::Degraded => "⚠", Self::Warning => "△", Self::Healthy => "✓", Self::Unknown => "?" }
    }
    pub fn label(&self) -> &'static str {
        match self { Self::Critical => "CRITICAL", Self::Degraded => "DEGRADED", Self::Warning => "WARNING", Self::Healthy => "HEALTHY", Self::Unknown => "UNKNOWN" }
    }
    pub fn from_severity(s: Severity) -> Self {
        match s { Severity::Critical => Self::Critical, Severity::Risk => Self::Degraded, Severity::Warn => Self::Warning, _ => Self::Healthy }
    }
}

impl StatusLine {
    pub fn render(&self) -> String { format!("{} {} — {}", self.level.emoji(), self.level.label(), self.state) }
    pub fn healthy(subject: &str) -> Self { Self { level: StatusLevel::Healthy, subject: subject.into(), state: "System stable".into() } }
    pub fn critical(subject: &str, state: &str) -> Self { Self { level: StatusLevel::Critical, subject: subject.into(), state: state.into() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemBlock { pub issue: String, pub location: String, pub scope: String }

impl ProblemBlock {
    pub fn render(&self) -> String { format!("  ISSUE: {} | Location: {} | Scope: {}", self.issue, self.location, self.scope) }
    pub fn new(issue: &str, location: &str, scope: &str) -> Self { Self { issue: issue.into(), location: location.into(), scope: scope.into() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionBlock { pub recommendation: String, pub command: String, pub priority: ActionPriority }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionPriority { Immediate, Soon, Optional, None }

impl ActionBlock {
    pub fn render(&self) -> String {
        let prefix = match self.priority { ActionPriority::Immediate => "→ ACTION (now):", ActionPriority::Soon => "→ ACTION:", ActionPriority::Optional => "→ SUGGEST:", ActionPriority::None => "→ INFO:" };
        format!("{} {} | {}", prefix, self.recommendation, self.command)
    }
    pub fn immediate(rec: &str, cmd: &str) -> Self { Self { recommendation: rec.into(), command: cmd.into(), priority: ActionPriority::Immediate } }
    pub fn suggest(rec: &str, cmd: &str) -> Self { Self { recommendation: rec.into(), command: cmd.into(), priority: ActionPriority::Optional } }
    pub fn none() -> Self { Self { recommendation: "No action required".into(), command: "".into(), priority: ActionPriority::None } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactBlock { pub description: String, pub affected_count: Option<u64>, pub affected_type: String, pub downstream: Vec<String> }

impl ImpactBlock {
    pub fn render(&self) -> String {
        let count = self.affected_count.map(|c| format!("{} {}", c, self.affected_type)).unwrap_or_else(|| self.affected_type.clone());
        let ds = if self.downstream.is_empty() { String::new() } else { format!(" | Downstream: {}", self.downstream.join(", ")) };
        format!("  IMPACT: {}{}", count, ds)
    }
    pub fn records(count: u64, desc: &str) -> Self { Self { description: desc.into(), affected_count: Some(count), affected_type: "records".into(), downstream: vec![] } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaBlock { pub changes: Vec<DeltaChange> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaChange { pub metric: String, pub direction: DeltaDirection, pub from: String, pub to: String }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaDirection { Up, Down, Stable }

impl DeltaDirection { pub fn arrow(&self) -> &'static str { match self { Self::Up => "↑", Self::Down => "↓", Self::Stable => "→" } } }

impl DeltaBlock {
    pub fn render(&self) -> String {
        let changes: Vec<String> = self.changes.iter().map(|c| format!("{} {} {} → {}", c.metric, c.direction.arrow(), c.from, c.to)).collect();
        format!("  DELTA: {}", changes.join(" | "))
    }
    pub fn single(metric: &str, dir: DeltaDirection, from: &str, to: &str) -> Self {
        Self { changes: vec![DeltaChange { metric: metric.into(), direction: dir, from: from.into(), to: to.into() }] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternBlock { pub pattern_type: PatternType, pub description: String, pub confidence: f64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType { RepeatedFailure, Spike, Anomaly, Degradation, Recovery }

impl PatternType { pub fn label(&self) -> &'static str { match self { Self::RepeatedFailure => "REPEATED FAILURE", Self::Spike => "SPIKE", Self::Anomaly => "ANOMALY", Self::Degradation => "DEGRADATION", Self::Recovery => "RECOVERY" } } }

impl PatternBlock {
    pub fn render(&self) -> String { format!("  PATTERN: {} — {} ({:.0}% confidence)", self.pattern_type.label(), self.description, self.confidence * 100.0) }
    pub fn repeated_failure(desc: &str, conf: f64) -> Self { Self { pattern_type: PatternType::RepeatedFailure, description: desc.into(), confidence: conf } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLine { pub verified: bool, pub chain_intact: bool, pub tier: String }

impl TrustLine {
    pub fn render(&self) -> String {
        let v = if self.verified { "✓ VERIFIED" } else { "✗ UNVERIFIED" };
        let c = if self.chain_intact { "✓ Chain intact" } else { "✗ Chain broken" };
        format!("  TRUST: {} | {} | Tier: {}", v, c, self.tier)
    }
    pub fn verified(tier: &str) -> Self { Self { verified: true, chain_intact: true, tier: tier.into() } }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_signal_compact() {
        let signal = Signal {
            status: StatusLine::critical("agent/test", "Pipeline failed"),
            problem: Some(ProblemBlock::new("Transform stage failed", "stage-2", "1 pipeline")),
            action: ActionBlock::immediate("Retry pipeline", "connectorctl pipeline retry exec-001"),
            impact: Some(ImpactBlock::records(23, "dropped")),
            delta: None, pattern: None,
            trust: TrustLine::verified("T1"),
            drill_down: "connectorctl inspect agent/test".into(),
        };
        let out = signal.compact();
        assert!(out.contains("CRITICAL"));
        assert!(out.contains("ACTION"));
    }
}
