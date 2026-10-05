//! Surface Renderer — Terminal and JSON output

use super::document::*;
use super::package::{ComplianceStatus, DecisionSurfacePackage, RiskLevel};

/// Renderer trait for surface documents
pub trait Renderer {
    fn render(&self, doc: &SurfaceDocument) -> String;
}

/// Terminal renderer with ANSI colors and clickable links
pub struct TerminalRenderer {
    pub width: usize,
    pub use_color: bool,
    pub use_hyperlinks: bool,
}

impl Default for TerminalRenderer {
    fn default() -> Self { Self { width: 100, use_color: true, use_hyperlinks: true } }
}

impl TerminalRenderer {
    pub fn render_decision_card(&self, pkg: &DecisionSurfacePackage) -> String {
        let mut out = String::new();

        // 1. Subject
        out.push_str(&format!("{}\n\n", self.bold(&pkg.subject.display)));

        // 2. Decision
        out.push_str(&format!("Decision: {}\n", pkg.decision.outcome));

        // 3. Problem
        let problem = if !pkg.risk.summary.is_empty() {
            pkg.risk.summary.clone()
        } else {
            pkg.why.explanation.clone()
        };
        out.push_str(&format!("Problem: {}\n", problem));

        // 4. Next actions (primary first, then secondary)
        let primary = pkg.next.iter().find(|a| a.primary);
        let secondaries: Vec<_> = pkg.next.iter().filter(|a| !a.primary).collect();
        if let Some(action) = primary {
            out.push_str(&format!("Action: {}\n", self.hyperlink(&action.command, &action.command)));
        }
        for action in &secondaries {
            out.push_str(&format!("  {} {}\n", self.dim("○"), self.hyperlink(&action.command, &action.label)));
        }

        // 5. Trust
        out.push_str(&format!("Trust: {}\n", pkg.proof.summary));

        // 6. Why
        out.push_str(&format!("Why: {}\n", pkg.why.explanation));

        // 7. Risk
        let risk_color = match pkg.risk.level {
            RiskLevel::High => "91",   // light red
            RiskLevel::Medium => "33", // yellow
            RiskLevel::Low => "32",    // green
            RiskLevel::None => "37",   // white
        };
        out.push_str(&format!(
            "Risk: {} {}\n",
            self.color(risk_color, pkg.risk.level.as_str()),
            self.dim(&pkg.risk.summary)
        ));

        // 8. Cost
        if let Some(cost) = &pkg.cost {
            let change = cost.change_summary.as_deref().unwrap_or("");
            out.push_str(&format!(
                "Cost: ${:.2} {}\n",
                cost.amount_usd,
                self.dim(change)
            ));
        }

        // 9. Compliance
        if !pkg.compliance.is_empty() {
            let compliance_display = pkg
                .compliance
                .iter()
                .map(|c| {
                    let icon = match c.status {
                        ComplianceStatus::Pass => self.color("32", "✓"),
                        ComplianceStatus::Fail => self.color("31", "✗"),
                        ComplianceStatus::Warn => self.color("33", "⚠"),
                        ComplianceStatus::NotApplicable => self.dim("-"),
                    };
                    format!("{} {}", icon, c.standard)
                })
                .collect::<Vec<_>>()
                .join("  ");
            out.push_str(&format!("Compliance: {}\n", compliance_display));
        }

        out
    }

    pub fn new() -> Self { Self::default() }
    pub fn no_color(mut self) -> Self { self.use_color = false; self }
    pub fn no_hyperlinks(mut self) -> Self { self.use_hyperlinks = false; self }

    fn color(&self, code: &str, text: &str) -> String {
        if self.use_color { format!("\x1b[{}m{}\x1b[0m", code, text) } else { text.to_string() }
    }
    fn bold(&self, text: &str) -> String { self.color("1", text) }
    fn dim(&self, text: &str) -> String { self.color("2", text) }

    fn hyperlink(&self, cmd: &str, label: &str) -> String {
        if self.use_hyperlinks { format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", cmd, self.color("34", label)) }
        else { self.color("34", label) }
    }

    fn render_header(&self, header: &SurfaceHeader) -> String {
        let line = "─".repeat(self.width.min(60));
        let state_display = header.state.display();
        format!("╭{}╮\n│ {} │\n│ {} │\n│ {} │\n╰{}╯\n",
            line, self.bold(&header.title), header.subject.display, self.dim(&state_display), line)
    }

    fn render_badges(&self, badges: &[SurfaceBadge]) -> String {
        if badges.is_empty() { return String::new(); }
        badges.iter().map(|b| {
            let c = match b.severity { Severity::Ok => "32", Severity::Info => "34", Severity::Warn => "33", Severity::Risk => "31", Severity::Critical => "91" };
            format!("[{}: {}]", b.label, self.color(c, &b.value))
        }).collect::<Vec<_>>().join(" ") + "\n"
    }

    fn render_section(&self, section: &SurfaceSection) -> String {
        let icon = if section.collapsed { "▶" } else { "▼" };
        let mut out = format!("\n{} {}\n", icon, self.bold(&section.title));
        if section.collapsed { return out; }
        out.push_str(&self.render_content(&section.content));
        out
    }

    fn render_content(&self, content: &SectionContent) -> String {
        match content {
            SectionContent::Stats(items) => items.iter().map(|i| format!("  {}: {}{}\n", self.dim(&i.label), i.value, self.render_link_opt(&i.link))).collect(),
            SectionContent::KeyValue(items) => items.iter().map(|i| format!("  {}: {}{}\n", self.dim(&i.key), i.value, self.render_link_opt(&i.link))).collect(),
            SectionContent::Timeline(events) => events.iter().map(|e| format!("  {} {} {} {}{}\n", self.dim(&e.timestamp), e.severity.icon(), self.color("36", &e.event_type), e.message, self.render_link_opt(&e.link))).collect(),
            SectionContent::Findings(items) => items.iter().map(|f| {
                let (icon, c) = match f.severity { Severity::Ok => ("✓", "32"), Severity::Warn => ("⚠", "33"), Severity::Critical => ("✖", "91"), _ => ("•", "37") };
                format!("  {} {} {}{}\n", self.color(c, icon), self.dim(&f.code), f.message, self.render_link_opt(&f.link))
            }).collect(),
            SectionContent::Evidence(items) => items.iter().map(|e| {
                let icon = if e.verified { self.color("32", "✓") } else { self.color("33", "?") };
                format!("  {} {} {} {}\n", icon, e.evidence_type, self.dim(&e.cid), self.render_link(&e.link))
            }).collect(),
            SectionContent::Trace(spans) => spans.iter().map(|s| {
                let indent = "  ".repeat(s.depth as usize + 1);
                let icon = if s.status == "ok" { self.color("32", "✓") } else { self.color("31", "✗") };
                format!("{}{} {} {}ms{}\n", indent, icon, s.name, s.duration_ms, self.render_link_opt(&s.link))
            }).collect(),
            SectionContent::Narrative(text) => format!("  {}\n", text.replace('\n', "\n  ")),
            SectionContent::RawData(blob) => {
                let hint = if blob.expanded { "" } else { " [expand]" };
                format!("  {} ({} bytes){}\n  {}\n", self.dim(&blob.id), blob.size, hint, self.dim(&blob.preview))
            },
            SectionContent::Links(links) => links.iter().map(|l| format!("  {}\n", self.render_link(l))).collect(),
            SectionContent::List(items) => items.iter().map(|i| format!("  • {}{}\n", i.text, self.render_link_opt(&i.link))).collect(),
        }
    }

    fn render_link(&self, link: &ResourceLink) -> String { self.hyperlink(&link.command, &link.label) }
    fn render_link_opt(&self, link: &Option<ResourceLink>) -> String { link.as_ref().map(|l| format!(" {}", self.render_link(l))).unwrap_or_default() }

    fn render_actions(&self, actions: &[SurfaceAction]) -> String {
        if actions.is_empty() { return String::new(); }
        let mut out = format!("\n{}\n", self.bold("Actions"));
        for a in actions {
            let m = if a.primary { "▸" } else { "○" };
            out.push_str(&format!("  {} {} — {}\n    {}\n", m, self.bold(&a.label), a.description, self.hyperlink(&a.command, &format!("[{}]", a.command))));
        }
        out
    }

    fn render_footer(&self, footer: &SurfaceFooter) -> String {
        let chain = if footer.chain_valid { self.color("32", "chain valid") } else { self.color("31", "chain invalid") };
        let hash = footer.root_hash.as_ref().map(|h| format!(" root={}", self.dim(h))).unwrap_or_default();
        format!("\n{}\n{} receipts={} {} {}\n", "─".repeat(self.width.min(60)), self.dim(&footer.timestamp), footer.receipt_count, chain, hash)
    }
}

impl Renderer for TerminalRenderer {
    fn render(&self, doc: &SurfaceDocument) -> String {
        let mut out = self.render_header(&doc.header);
        out.push_str(&self.render_badges(&doc.header.badges));
        if let Some(ref s) = doc.summary { out.push_str(&format!("\n{}\n", s)); }
        for section in &doc.sections { out.push_str(&self.render_section(section)); }
        out.push_str(&self.render_actions(&doc.actions));
        if let Some(ref f) = doc.footer { out.push_str(&self.render_footer(f)); }
        out
    }
}

/// JSON renderer for machine consumption
pub struct JsonRenderer;

impl JsonRenderer {
    pub fn render_package(&self, pkg: &DecisionSurfacePackage) -> String {
        serde_json::to_string_pretty(pkg).unwrap_or_else(|_| "{}".into())
    }
}

impl Renderer for JsonRenderer {
    fn render(&self, doc: &SurfaceDocument) -> String {
        serde_json::to_string_pretty(doc).unwrap_or_else(|_| "{}".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_terminal_render() {
        let doc = SurfaceDocument {
            meta: SurfaceMeta { surface_type: SurfaceType::Debug, view: SurfaceView::Summary, generated_at: 0 },
            header: SurfaceHeader { title: "DEBUG: test".into(), subject: SubjectIdentity::new(ResourceKind::Agent, "test"), state: StateVector::active_verified(), badges: vec![], time_range: None },
            summary: Some("Test summary".into()), sections: vec![], actions: vec![], footer: None,
        };
        let out = TerminalRenderer::new().no_color().render(&doc);
        assert!(out.contains("DEBUG: test"));
    }
}
