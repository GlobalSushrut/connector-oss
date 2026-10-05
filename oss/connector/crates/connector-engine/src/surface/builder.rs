//! Surface Builder — Fluent API for constructing surfaces
//!
//! Makes developer life 100x easier with chainable, type-safe surface construction.
//!
//! ```rust,ignore
//! let surface = SurfaceBuilder::new(SurfaceType::Agent, "claims-agent-001")
//!     .view(SurfaceView::Ops)
//!     .state(StateVector::active_verified())
//!     .judgment(Judgment::ok("Agent running normally"))
//!     .signal(Signal::check("Health OK"))
//!     .signal(Signal::check("Policy compliant"))
//!     .stats("Health", vec![("CPU", "12%"), ("Memory", "847MB")])
//!     .timeline("Activity", vec![...])
//!     .action("Trace", "Show execution trace", "connectorctl trace agent claims-agent-001")
//!     .build();
//! ```

use super::document::*;
use super::contract::{SurfaceContract, Judgment, Signal};

fn surface_type_str(st: SurfaceType) -> &'static str {
    match st {
        SurfaceType::Agent => "AGENT", SurfaceType::Audit => "AUDIT", SurfaceType::Memory => "MEMORY",
        SurfaceType::Knowledge => "KNOWLEDGE", SurfaceType::Policy => "POLICY", SurfaceType::Tool => "TOOL",
        SurfaceType::Contract => "CONTRACT", SurfaceType::Proof => "PROOF", SurfaceType::Compliance => "COMPLIANCE",
        SurfaceType::Health => "HEALTH", SurfaceType::Books => "BOOKS", SurfaceType::Debug => "DEBUG",
        SurfaceType::Trace => "TRACE", SurfaceType::Inspect => "INSPECT", SurfaceType::Review => "REVIEW",
        SurfaceType::Explain => "EXPLAIN", SurfaceType::Monitor => "MONITOR",
    }
}

/// Fluent builder for constructing SurfaceDocument instances
#[derive(Debug, Clone)]
pub struct SurfaceBuilder {
    surface_type: SurfaceType,
    view: SurfaceView,
    subject: SubjectIdentity,
    state: StateVector,
    judgment: Option<Judgment>,
    signals: Vec<Signal>,
    badges: Vec<SurfaceBadge>,
    sections: Vec<SurfaceSection>,
    actions: Vec<SurfaceAction>,
    evidence: EvidencePosture,
    trust: TrustScore,
    time_range: Option<String>,
}

impl SurfaceBuilder {
    /// Apply mandatory contract defaults (judgment + 3–7 signals) per Surface Contract Standard.
    fn apply_contract_defaults(&mut self) {
        if self.judgment.is_none() {
            self.judgment = Some(Judgment::info(format!(
                "{} — {}",
                self.state.display(),
                self.subject.display
            )));
        }
        let filler = [
            format!("Execution: {}", self.state.execution.as_str()),
            format!("Trust posture: {}", self.state.trust.as_str()),
            format!("Health: {}", self.state.health.as_str()),
            format!("Compliance: {}", self.state.compliance.as_str()),
        ];
        for line in filler {
            if self.signals.len() >= 3 {
                break;
            }
            if self.signals.iter().any(|s| s.text == line) {
                continue;
            }
            self.signals.push(Signal::info(line));
        }
        while self.signals.len() < 3 {
            self.signals
                .push(Signal::info("Review surface sections for supporting detail"));
        }
    }

    /// Create a new surface builder
    pub fn new(surface_type: SurfaceType, subject_id: &str) -> Self {
        let kind = Self::infer_resource_kind(surface_type);
        Self {
            surface_type,
            view: SurfaceView::Summary,
            subject: SubjectIdentity::new(kind, subject_id),
            state: StateVector::active_verified(),
            judgment: None,
            signals: Vec::new(),
            badges: Vec::new(),
            sections: Vec::new(),
            actions: Vec::new(),
            evidence: EvidencePosture { status: EvidenceStatus::Partial, receipt_count: 0, verified: false, chain_intact: true, completeness: 0.0, root_hash: None },
            trust: TrustScore::new(80),
            time_range: None,
        }
    }

    fn infer_resource_kind(st: SurfaceType) -> ResourceKind {
        match st {
            SurfaceType::Agent | SurfaceType::Debug | SurfaceType::Health => ResourceKind::Agent,
            SurfaceType::Memory => ResourceKind::Memory,
            SurfaceType::Knowledge => ResourceKind::Knowledge,
            SurfaceType::Audit | SurfaceType::Books => ResourceKind::Audit,
            SurfaceType::Policy | SurfaceType::Compliance => ResourceKind::Policy,
            SurfaceType::Tool => ResourceKind::Tool,
            SurfaceType::Contract => ResourceKind::Contract,
            SurfaceType::Proof => ResourceKind::Proof,
            _ => ResourceKind::Agent,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Core Configuration
    // ═══════════════════════════════════════════════════════════════════════

    pub fn view(mut self, view: SurfaceView) -> Self { self.view = view; self }
    pub fn state(mut self, state: StateVector) -> Self { self.state = state; self }
    pub fn subject(mut self, subject: SubjectIdentity) -> Self { self.subject = subject; self }
    pub fn time_range(mut self, range: impl Into<String>) -> Self { self.time_range = Some(range.into()); self }

    // ═══════════════════════════════════════════════════════════════════════
    // Judgment & Signals (Contract Fields)
    // ═══════════════════════════════════════════════════════════════════════

    pub fn judgment(mut self, judgment: Judgment) -> Self { self.judgment = Some(judgment); self }
    pub fn judgment_ok(self, text: impl Into<String>) -> Self { self.judgment(Judgment::ok(text)) }
    pub fn judgment_warn(self, text: impl Into<String>) -> Self { self.judgment(Judgment::warn(text)) }
    pub fn judgment_critical(self, text: impl Into<String>) -> Self { self.judgment(Judgment::critical(text)) }

    pub fn signal(mut self, signal: Signal) -> Self { self.signals.push(signal); self }
    pub fn signal_check(self, text: impl Into<String>) -> Self { self.signal(Signal::check(text)) }
    pub fn signal_warn(self, text: impl Into<String>) -> Self { self.signal(Signal::warn(text)) }
    pub fn signal_cross(self, text: impl Into<String>) -> Self { self.signal(Signal::cross(text)) }

    // ═══════════════════════════════════════════════════════════════════════
    // Trust & Evidence
    // ═══════════════════════════════════════════════════════════════════════

    pub fn trust(mut self, score: u8) -> Self { self.trust = TrustScore::new(score); self }
    pub fn evidence(mut self, evidence: EvidencePosture) -> Self { self.evidence = evidence; self }
    pub fn evidence_complete(mut self, receipt_count: usize, root_hash: &str) -> Self {
        self.evidence = EvidencePosture::complete(receipt_count, root_hash); self
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Badges
    // ═══════════════════════════════════════════════════════════════════════

    pub fn badge(mut self, label: impl Into<String>, value: impl Into<String>, severity: Severity) -> Self {
        self.badges.push(SurfaceBadge { label: label.into(), value: value.into(), severity }); self
    }
    pub fn badge_ok(self, label: impl Into<String>, value: impl Into<String>) -> Self { self.badge(label, value, Severity::Ok) }
    pub fn badge_warn(self, label: impl Into<String>, value: impl Into<String>) -> Self { self.badge(label, value, Severity::Warn) }
    pub fn badge_info(self, label: impl Into<String>, value: impl Into<String>) -> Self { self.badge(label, value, Severity::Info) }

    // ═══════════════════════════════════════════════════════════════════════
    // Sections — The heart of surface content
    // ═══════════════════════════════════════════════════════════════════════

    pub fn section(mut self, section: SurfaceSection) -> Self { self.sections.push(section); self }

    /// Add a stats grid section
    pub fn stats(self, title: impl Into<String>, items: Vec<(&str, &str)>) -> Self {
        self.section(SurfaceSection {
            title: title.into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(items.into_iter().map(|(k, v)| StatItem { label: k.into(), value: v.into(), link: None }).collect()),
            collapsed: false,
        })
    }

    /// Add a stats grid with links
    pub fn stats_linked(self, title: impl Into<String>, items: Vec<(&str, &str, Option<ResourceLink>)>) -> Self {
        self.section(SurfaceSection {
            title: title.into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(items.into_iter().map(|(k, v, l)| StatItem { label: k.into(), value: v.into(), link: l }).collect()),
            collapsed: false,
        })
    }

    /// Add a key-value table section
    pub fn kv_table(self, title: impl Into<String>, items: Vec<(&str, &str)>) -> Self {
        self.section(SurfaceSection {
            title: title.into(),
            kind: SectionKind::KeyValueTable,
            content: SectionContent::KeyValue(items.into_iter().map(|(k, v)| KeyValueItem { key: k.into(), value: v.into(), link: None }).collect()),
            collapsed: false,
        })
    }

    /// Add a timeline section
    pub fn timeline(self, title: impl Into<String>, events: Vec<TimelineEvent>) -> Self {
        self.section(SurfaceSection { title: title.into(), kind: SectionKind::Timeline, content: SectionContent::Timeline(events), collapsed: false })
    }

    /// Add a findings section
    pub fn findings(self, title: impl Into<String>, findings: Vec<Finding>) -> Self {
        self.section(SurfaceSection { title: title.into(), kind: SectionKind::Findings, content: SectionContent::Findings(findings), collapsed: false })
    }

    /// Add an evidence section
    pub fn evidence_section(self, title: impl Into<String>, items: Vec<EvidenceItem>) -> Self {
        self.section(SurfaceSection { title: title.into(), kind: SectionKind::Evidence, content: SectionContent::Evidence(items), collapsed: false })
    }

    /// Add a trace section
    pub fn trace(self, title: impl Into<String>, spans: Vec<TraceSpan>) -> Self {
        self.section(SurfaceSection { title: title.into(), kind: SectionKind::Trace, content: SectionContent::Trace(spans), collapsed: false })
    }

    /// Add a narrative section
    pub fn narrative(self, title: impl Into<String>, text: impl Into<String>) -> Self {
        self.section(SurfaceSection { title: title.into(), kind: SectionKind::Narrative, content: SectionContent::Narrative(text.into()), collapsed: false })
    }

    /// Add a raw data blob section (collapsed by default)
    pub fn raw_data(self, title: impl Into<String>, blob: BlobContainer) -> Self {
        self.section(SurfaceSection { title: title.into(), kind: SectionKind::RawData, content: SectionContent::RawData(blob), collapsed: true })
    }

    /// Add a links section
    pub fn links(self, title: impl Into<String>, links: Vec<ResourceLink>) -> Self {
        self.section(SurfaceSection { title: title.into(), kind: SectionKind::Links, content: SectionContent::Links(links), collapsed: false })
    }

    /// Add a list section
    pub fn list(self, title: impl Into<String>, items: Vec<&str>) -> Self {
        self.section(SurfaceSection {
            title: title.into(),
            kind: SectionKind::List,
            content: SectionContent::List(items.into_iter().map(|t| ListItem { text: t.into(), link: None }).collect()),
            collapsed: false,
        })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Actions
    // ═══════════════════════════════════════════════════════════════════════

    pub fn action(mut self, label: impl Into<String>, description: impl Into<String>, command: impl Into<String>) -> Self {
        self.actions.push(SurfaceAction { label: label.into(), description: description.into(), command: command.into(), primary: self.actions.is_empty() });
        self
    }

    pub fn action_primary(mut self, label: impl Into<String>, description: impl Into<String>, command: impl Into<String>) -> Self {
        self.actions.push(SurfaceAction { label: label.into(), description: description.into(), command: command.into(), primary: true });
        self
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Build
    // ═══════════════════════════════════════════════════════════════════════

    /// Build the surface document
    pub fn build(mut self) -> SurfaceDocument {
        self.apply_contract_defaults();
        let mut badges = self.badges;
        if badges.is_empty() {
            badges.push(SurfaceBadge { label: "Trust".into(), value: format!("{}/{}", self.trust.score, self.trust.grade.as_char()), severity: if self.trust.score >= 80 { Severity::Ok } else { Severity::Warn } });
            badges.push(SurfaceBadge { label: "State".into(), value: self.state.execution.as_str().into(), severity: Severity::Info });
        }

        SurfaceDocument {
            meta: SurfaceMeta { surface_type: self.surface_type, view: self.view, generated_at: chrono::Utc::now().timestamp_millis() },
            header: SurfaceHeader { title: format!("{}: {}", surface_type_str(self.surface_type), self.subject.display), subject: self.subject, state: self.state, badges, time_range: self.time_range },
            summary: self.judgment.map(|j| j.text),
            sections: self.sections,
            actions: self.actions,
            footer: Some(SurfaceFooter { root_hash: self.evidence.root_hash, verified: self.evidence.verified, receipt_count: self.evidence.receipt_count as u32, chain_valid: self.evidence.chain_intact, timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string() }),
        }
    }

    /// Build and validate against contract
    pub fn build_validated(mut self) -> Result<SurfaceDocument, Vec<String>> {
        self.apply_contract_defaults();
        let contract = SurfaceContract {
            subject: self.subject.clone(),
            state: self.state.clone(),
            judgment: self.judgment.clone().unwrap_or_else(|| Judgment::info("No judgment provided")),
            signals: self.signals.clone(),
            actions: self.actions.clone(),
            evidence: self.evidence.clone(),
            trust: self.trust.clone(),
        };
        let validation = contract.validate();
        if validation.valid {
            Ok(self.build())
        } else {
            Err(validation.errors.iter().map(|e| format!("{}: {}", e.field, e.message)).collect())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper constructors for common patterns
// ═══════════════════════════════════════════════════════════════════════════

impl SurfaceBuilder {
    /// Quick agent surface
    pub fn agent(id: &str) -> Self { Self::new(SurfaceType::Agent, id) }
    /// Quick audit surface
    pub fn audit(id: &str) -> Self { Self::new(SurfaceType::Audit, id) }
    /// Quick debug surface
    pub fn debug(id: &str) -> Self { Self::new(SurfaceType::Debug, id) }
    /// Quick compliance surface
    pub fn compliance(id: &str) -> Self { Self::new(SurfaceType::Compliance, id) }
    /// Quick books surface
    pub fn books(id: &str) -> Self { Self::new(SurfaceType::Books, id) }
    /// Quick memory surface
    pub fn memory(id: &str) -> Self { Self::new(SurfaceType::Memory, id) }
    /// Quick health surface
    pub fn health(id: &str) -> Self { Self::new(SurfaceType::Health, id) }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fluent_builder() {
        let surface = SurfaceBuilder::agent("claims-agent-001")
            .view(SurfaceView::Ops)
            .judgment_ok("Agent running normally")
            .signal_check("Health OK")
            .signal_check("Policy compliant")
            .stats("Health", vec![("CPU", "12%"), ("Memory", "847MB")])
            .action("Trace", "Show trace", "connectorctl trace agent claims-agent-001")
            .build();

        assert_eq!(surface.header.title, "AGENT: agent/claims-agent-001");
        assert_eq!(surface.sections.len(), 1);
        assert_eq!(surface.actions.len(), 1);
    }

    #[test]
    fn test_quick_constructors() {
        let _ = SurfaceBuilder::agent("test").build();
        let _ = SurfaceBuilder::audit("test").build();
        let _ = SurfaceBuilder::debug("test").build();
        let _ = SurfaceBuilder::compliance("test").build();
    }
}
