//! Intelligence Layer — Decision engine, pattern detection, global health
//!
//! The "thin intelligence layer" that transforms raw surfaces into operator guidance.

use super::document::*;
use super::signal::*;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// Signal Extractor — Extract intelligence from surfaces
// ═══════════════════════════════════════════════════════════════════════════

pub struct SignalExtractor;

impl SignalExtractor {
    pub fn extract(doc: &SurfaceDocument) -> Signal {
        let status = Self::extract_status(doc);
        let problem = Self::extract_problem(doc);
        let action = Self::extract_action(doc, &status, &problem);
        let impact = Self::extract_impact(doc);
        let pattern = Self::detect_pattern(doc);
        let trust = Self::extract_trust(doc);
        let drill_down = format!("connectorctl inspect {}", doc.header.subject.inspect);

        Signal { status, problem, action, impact, delta: None, pattern, trust, drill_down }
    }

    fn extract_status(doc: &SurfaceDocument) -> StatusLine {
        let worst = doc.header.badges.iter()
            .map(|b| b.severity)
            .max_by_key(|s| match s { Severity::Critical => 4, Severity::Risk => 3, Severity::Warn => 2, _ => 0 })
            .unwrap_or(Severity::Ok);
        let level = StatusLevel::from_severity(worst);
        let state = match level {
            StatusLevel::Critical => Self::find_issue(doc, Severity::Critical),
            StatusLevel::Degraded => Self::find_issue(doc, Severity::Risk),
            _ => doc.header.state.display(),
        };
        StatusLine { level, subject: doc.header.subject.display.clone(), state }
    }

    fn find_issue(doc: &SurfaceDocument, sev: Severity) -> String {
        for section in &doc.sections {
            if let SectionContent::Findings(findings) = &section.content {
                if let Some(f) = findings.iter().find(|f| f.severity == sev) {
                    return f.message.clone();
                }
            }
        }
        "Issue detected".into()
    }

    fn extract_problem(doc: &SurfaceDocument) -> Option<ProblemBlock> {
        for section in &doc.sections {
            if let SectionContent::Findings(findings) = &section.content {
                if let Some(f) = findings.iter().find(|f| f.severity == Severity::Critical || f.severity == Severity::Risk) {
                    return Some(ProblemBlock::new(&f.message, &f.code, &section.title));
                }
            }
        }
        None
    }

    fn extract_action(doc: &SurfaceDocument, status: &StatusLine, _problem: &Option<ProblemBlock>) -> ActionBlock {
        if status.level == StatusLevel::Critical {
            if let Some(a) = doc.actions.iter().find(|a| a.primary) {
                return ActionBlock::immediate(&a.description, &a.command);
            }
            return ActionBlock::immediate("Investigate immediately", &format!("connectorctl inspect {}", doc.header.subject.inspect));
        }
        if status.level == StatusLevel::Degraded {
            if let Some(a) = doc.actions.iter().find(|a| a.primary) {
                return ActionBlock { recommendation: a.description.clone(), command: a.command.clone(), priority: ActionPriority::Soon };
            }
        }
        doc.actions.first().map(|a| ActionBlock::suggest(&a.description, &a.command)).unwrap_or_else(ActionBlock::none)
    }

    fn extract_impact(doc: &SurfaceDocument) -> Option<ImpactBlock> {
        for section in &doc.sections {
            if let SectionContent::Stats(stats) = &section.content {
                for stat in stats {
                    if stat.label.to_lowercase().contains("error") || stat.label.to_lowercase().contains("failed") {
                        if let Ok(count) = stat.value.parse::<u64>() {
                            if count > 0 { return Some(ImpactBlock::records(count, &stat.label)); }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_pattern(doc: &SurfaceDocument) -> Option<PatternBlock> {
        // Look for repeated issues in timeline
        let mut failure_count = 0;
        for section in &doc.sections {
            if let SectionContent::Timeline(events) = &section.content {
                for e in events {
                    if e.message.to_lowercase().contains("fail") || e.message.to_lowercase().contains("error") {
                        failure_count += 1;
                    }
                }
            }
        }
        if failure_count >= 3 {
            return Some(PatternBlock::repeated_failure(&format!("{} failures in timeline", failure_count), 0.85));
        }
        None
    }

    fn extract_trust(doc: &SurfaceDocument) -> TrustLine {
        // Check for evidence section
        for section in &doc.sections {
            if let SectionContent::Evidence(items) = &section.content {
                let verified = items.iter().all(|e| e.verified);
                return TrustLine { verified, chain_intact: verified, tier: "T1".into() };
            }
        }
        TrustLine::verified("T2")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global Health Aggregator — Unified status across all systems
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalHealth {
    pub overall: StatusLevel,
    pub summary: String,
    pub systems: Vec<SystemHealth>,
    pub top_issues: Vec<TopIssue>,
    pub drill_down: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub name: String,
    pub status: StatusLevel,
    pub count: u32,
    pub issues: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopIssue {
    pub severity: StatusLevel,
    pub description: String,
    pub location: String,
    pub command: String,
}

impl GlobalHealth {
    pub fn render(&self) -> String {
        let mut lines = vec![
            format!("{} {} — {}", self.overall.emoji(), self.overall.label(), self.summary),
        ];
        
        for sys in &self.systems {
            let icon = sys.status.emoji();
            let issues = if sys.issues > 0 { format!(" ({} issues)", sys.issues) } else { String::new() };
            lines.push(format!("  {} {} — {} total{}", icon, sys.name, sys.count, issues));
        }
        
        if !self.top_issues.is_empty() {
            lines.push("  TOP ISSUES:".into());
            for issue in &self.top_issues {
                lines.push(format!("    {} {} | {}", issue.severity.emoji(), issue.description, issue.command));
            }
        }
        
        lines.push(format!("  └─ {}", self.drill_down));
        lines.join("\n")
    }

    pub fn from_signals(signals: &[Signal]) -> Self {
        let mut systems: Vec<SystemHealth> = vec![];
        let mut top_issues: Vec<TopIssue> = vec![];
        
        // Group by subject type
        let mut agents = SystemHealth { name: "Agents".into(), status: StatusLevel::Healthy, count: 0, issues: 0 };
        let mut pipelines = SystemHealth { name: "Pipelines".into(), status: StatusLevel::Healthy, count: 0, issues: 0 };
        let mut network = SystemHealth { name: "Network".into(), status: StatusLevel::Healthy, count: 0, issues: 0 };
        
        for signal in signals {
            let subject = &signal.status.subject.to_lowercase();
            let sys = if subject.contains("agent") { &mut agents }
                else if subject.contains("pipeline") { &mut pipelines }
                else { &mut network };
            
            sys.count += 1;
            if signal.status.level == StatusLevel::Critical || signal.status.level == StatusLevel::Degraded {
                sys.issues += 1;
                if sys.status as u8 > signal.status.level as u8 { sys.status = signal.status.level; }
                
                top_issues.push(TopIssue {
                    severity: signal.status.level,
                    description: signal.status.state.clone(),
                    location: signal.status.subject.clone(),
                    command: signal.drill_down.clone(),
                });
            }
        }
        
        if agents.count > 0 { systems.push(agents); }
        if pipelines.count > 0 { systems.push(pipelines); }
        if network.count > 0 { systems.push(network); }
        
        // Sort issues by severity
        top_issues.sort_by_key(|i| match i.severity { StatusLevel::Critical => 0, StatusLevel::Degraded => 1, _ => 2 });
        top_issues.truncate(3);
        
        let overall = systems.iter().map(|s| s.status).min_by_key(|s| match s { StatusLevel::Critical => 0, StatusLevel::Degraded => 1, _ => 2 }).unwrap_or(StatusLevel::Healthy);
        let total_issues: u32 = systems.iter().map(|s| s.issues).sum();
        let summary = if total_issues == 0 { "All systems operational".into() } else { format!("{} issues across {} systems", total_issues, systems.len()) };
        
        GlobalHealth { overall, summary, systems, top_issues, drill_down: "connectorctl status --full".into() }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Operator Narrative — Human-readable state language
// ═══════════════════════════════════════════════════════════════════════════

pub struct Narrator;

impl Narrator {
    /// Convert signal to human narrative
    pub fn narrate(signal: &Signal) -> String {
        let status_text = match signal.status.level {
            StatusLevel::Critical => format!("System is experiencing a critical failure: {}", signal.status.state),
            StatusLevel::Degraded => format!("System is degraded: {}", signal.status.state),
            StatusLevel::Warning => format!("System has warnings: {}", signal.status.state),
            StatusLevel::Healthy => "System is stable and operating normally.".into(),
            StatusLevel::Unknown => "System state is unknown.".into(),
        };
        
        let problem_text = signal.problem.as_ref().map(|p| format!("The issue is in {} ({}).", p.location, p.scope)).unwrap_or_default();
        let impact_text = signal.impact.as_ref().map(|i| format!("{} {} affected.", i.affected_count.unwrap_or(0), i.affected_type)).unwrap_or_default();
        let action_text = if signal.action.priority != ActionPriority::None {
            format!("Recommended action: {}", signal.action.recommendation)
        } else { String::new() };
        
        [status_text, problem_text, impact_text, action_text].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_global_health() {
        let signals = vec![
            Signal {
                status: StatusLine::critical("agent/test", "Pipeline failed"),
                problem: Some(ProblemBlock::new("Stage failed", "stage-2", "pipeline")),
                action: ActionBlock::immediate("Retry", "connectorctl retry"),
                impact: None, delta: None, pattern: None,
                trust: TrustLine::verified("T1"),
                drill_down: "connectorctl inspect agent/test".into(),
            },
        ];
        let health = GlobalHealth::from_signals(&signals);
        assert_eq!(health.overall, StatusLevel::Critical);
        assert!(!health.top_issues.is_empty());
    }
    
    #[test]
    fn test_narrator() {
        let signal = Signal {
            status: StatusLine::critical("agent/test", "Pipeline failed"),
            problem: Some(ProblemBlock::new("Stage failed", "stage-2", "pipeline")),
            action: ActionBlock::immediate("Retry", "connectorctl retry"),
            impact: Some(ImpactBlock::records(23, "dropped")),
            delta: None, pattern: None,
            trust: TrustLine::verified("T1"),
            drill_down: "connectorctl inspect".into(),
        };
        let narrative = Narrator::narrate(&signal);
        assert!(narrative.contains("critical failure"));
        assert!(narrative.contains("23 records"));
    }
}
