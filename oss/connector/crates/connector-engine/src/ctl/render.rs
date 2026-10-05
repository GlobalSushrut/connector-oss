//! Terminal Renderer — Clickable links, expandable raw data, rich output

use super::executor::*;
use super::output::OutputMode;

pub struct TerminalRenderer {
    mode: OutputMode,
    width: usize,
    use_color: bool,
    use_hyperlinks: bool,
}

impl Default for TerminalRenderer {
    fn default() -> Self { Self::new() }
}

impl TerminalRenderer {
    pub fn new() -> Self {
        Self { mode: OutputMode::Default, width: 120, use_color: true, use_hyperlinks: true }
    }

    pub fn with_mode(mut self, mode: OutputMode) -> Self { self.mode = mode; self }
    pub fn with_width(mut self, w: usize) -> Self { self.width = w; self }
    pub fn no_color(mut self) -> Self { self.use_color = false; self }
    pub fn no_hyperlinks(mut self) -> Self { self.use_hyperlinks = false; self }

    pub fn render(&self, result: &ExecutionResult) -> String {
        match self.mode {
            OutputMode::Json => self.render_json(result),
            OutputMode::Book => self.render_markdown(&result.surface),
            OutputMode::Compact => self.render_compact(&result.surface),
            _ => self.render_table(&result.surface),
        }
    }

    fn render_compact(&self, doc: &SurfaceDocument) -> String {
        format!("{} [{}] {}", doc.title, doc.header.state.as_str(), doc.summary.as_deref().unwrap_or(""))
    }

    fn render_json(&self, result: &ExecutionResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
    }

    #[allow(dead_code)]
    fn render_yaml(&self, _result: &ExecutionResult) -> String {
        "---".into() // YAML rendering placeholder
    }

    fn render_table(&self, doc: &SurfaceDocument) -> String {
        let mut out = String::new();
        out.push_str(&self.render_header(doc));
        out.push_str(&self.render_badges(&doc.header.badges));
        if let Some(ref s) = doc.summary { out.push_str(&format!("\n{}\n", s)); }
        for section in &doc.sections { out.push_str(&self.render_section(section)); }
        out.push_str(&self.render_actions(&doc.actions));
        if let Some(ref f) = doc.footer { out.push_str(&self.render_footer(f)); }
        out
    }

    fn render_plain(&self, doc: &SurfaceDocument) -> String { self.render_table(doc) }
    fn render_markdown(&self, doc: &SurfaceDocument) -> String {
        let mut out = format!("# {}\n\n", doc.title);
        if let Some(ref s) = doc.summary { out.push_str(&format!("{}\n\n", s)); }
        for section in &doc.sections {
            out.push_str(&format!("## {}\n\n", section.title));
            out.push_str(&self.render_section_content_md(&section.content));
        }
        out
    }

    fn render_header(&self, doc: &SurfaceDocument) -> String {
        let state_icon = match doc.header.state {
            SurfaceState::Active => "●", SurfaceState::Verified => "✓",
            SurfaceState::Degraded => "◐", SurfaceState::Failed => "✗",
            _ => "○",
        };
        let time_info = doc.header.time_range.as_ref().map(|t| format!(" @ {}", t)).unwrap_or_default();
        format!("\n{} {} {}{}\n{}\n", self.color("36", state_icon), self.bold(&doc.title), self.dim(&doc.header.identity.canonical()), time_info, "─".repeat(self.width.min(80)))
    }

    fn render_badges(&self, badges: &[SurfaceBadge]) -> String {
        if badges.is_empty() { return String::new(); }
        let parts: Vec<String> = badges.iter().map(|b| {
            let color = match b.severity { Severity::Ok => "32", Severity::Info => "34", Severity::Warn => "33", Severity::Risk => "31", Severity::Critical => "91" };
            format!("[{}: {}]", b.label, self.color(color, &b.value))
        }).collect();
        format!("{}\n", parts.join(" "))
    }

    fn render_section(&self, section: &SurfaceSection) -> String {
        let collapse_icon = if section.collapsed { "▶" } else { "▼" };
        let mut out = format!("\n{} {}\n", collapse_icon, self.bold(&section.title));
        if section.collapsed { return out; }
        out.push_str(&self.render_section_content(&section.content));
        out
    }

    fn render_section_content(&self, content: &SectionContent) -> String {
        match content {
            SectionContent::Stats(items) => self.render_stats(items),
            SectionContent::KeyValue(items) => self.render_kv(items),
            SectionContent::Timeline(events) => self.render_timeline(events),
            SectionContent::Findings(items) => self.render_findings(items),
            SectionContent::Evidence(items) => self.render_evidence(items),
            SectionContent::Trace(spans) => self.render_trace(spans),
            SectionContent::Narrative(text) => format!("  {}\n", text.replace('\n', "\n  ")),
            SectionContent::RawData(blob) => self.render_raw_blob(blob),
            SectionContent::Links(links) => self.render_links(links),
            SectionContent::List(items) => items.iter().map(|i| format!("  • {}{}\n", i.text, self.render_link_opt(&i.link))).collect(),
        }
    }

    fn render_section_content_md(&self, content: &SectionContent) -> String {
        match content {
            SectionContent::Stats(items) => items.iter().map(|i| format!("- **{}**: {}\n", i.label, i.value)).collect(),
            SectionContent::Timeline(events) => events.iter().map(|e| format!("- `{}` **{}** — {}\n", e.timestamp, e.event_type, e.message)).collect(),
            SectionContent::Narrative(text) => format!("{}\n\n", text),
            SectionContent::RawData(blob) => format!("```json\n{}\n```\n\n", blob.preview),
            _ => String::new(),
        }
    }

    fn render_stats(&self, items: &[StatItem]) -> String {
        items.iter().map(|i| format!("  {}: {}{}\n", self.dim(&i.label), i.value, self.render_link_opt(&i.link))).collect()
    }

    fn render_kv(&self, items: &[KeyValueItem]) -> String {
        items.iter().map(|i| format!("  {}: {}{}\n", self.dim(&i.key), i.value, self.render_link_opt(&i.link))).collect()
    }

    fn render_timeline(&self, events: &[TimelineEvent]) -> String {
        events.iter().map(|e| {
            let icon = match e.severity { Severity::Ok => "✓", Severity::Warn => "⚠", Severity::Critical => "✗", _ => "•" };
            format!("  {} {} {} {}{}\n", self.dim(&e.timestamp), icon, self.color("36", &e.event_type), e.message, self.render_link_opt(&e.link))
        }).collect()
    }

    fn render_findings(&self, items: &[Finding]) -> String {
        items.iter().map(|f| {
            let (icon, color) = match f.severity { Severity::Ok => ("✓", "32"), Severity::Warn => ("⚠", "33"), Severity::Critical => ("✗", "91"), _ => ("•", "37") };
            format!("  {} {} {}{}\n", self.color(color, icon), self.dim(&f.code), f.message, self.render_link_opt(&f.link))
        }).collect()
    }

    fn render_evidence(&self, items: &[EvidenceItem]) -> String {
        items.iter().map(|e| {
            let icon = if e.verified { self.color("32", "✓") } else { self.color("33", "?") };
            format!("  {} {} {} {}\n", icon, e.evidence_type, self.dim(&e.cid), self.render_deep_link(&e.link))
        }).collect()
    }

    fn render_trace(&self, spans: &[TraceSpan]) -> String {
        spans.iter().map(|s| {
            let indent = "  ".repeat(s.depth as usize + 1);
            let status_icon = if s.status == "ok" { self.color("32", "✓") } else { self.color("31", "✗") };
            format!("{}{} {} {}ms{}\n", indent, status_icon, s.name, s.duration_ms, self.render_link_opt(&s.link))
        }).collect()
    }

    fn render_raw_blob(&self, blob: &RawDataBlob) -> String {
        let expand_hint = if blob.expanded { "" } else { &format!(" {} to expand", self.hyperlink(&blob.fetch_command, "[↓]")) };
        format!("  {} ({} bytes){}\n  {}\n", self.dim(&blob.id), blob.size, expand_hint, self.dim(&blob.preview))
    }

    fn render_links(&self, links: &[DeepLink]) -> String {
        links.iter().map(|l| format!("  {}\n", self.render_deep_link(l))).collect()
    }

    fn render_link_opt(&self, link: &Option<DeepLink>) -> String {
        link.as_ref().map(|l| format!(" {}", self.render_deep_link(l))).unwrap_or_default()
    }

    fn render_deep_link(&self, link: &DeepLink) -> String {
        self.hyperlink(&link.command, &link.label)
    }

    fn render_actions(&self, actions: &[SurfaceAction]) -> String {
        if actions.is_empty() { return String::new(); }
        let mut out = format!("\n{}\n", self.bold("Actions"));
        for a in actions {
            let marker = if a.primary { "▸" } else { "○" };
            out.push_str(&format!("  {} {} — {}\n    {}\n", marker, self.bold(&a.label), a.description, self.hyperlink(&a.command, &format!("[{}]", a.command))));
        }
        out
    }

    fn render_footer(&self, footer: &SurfaceFooter) -> String {
        let chain = if footer.chain_valid { self.color("32", "chain valid") } else { self.color("31", "chain invalid") };
        let hash = footer.root_hash.as_ref().map(|h| format!(" root={}", self.dim(h))).unwrap_or_default();
        format!("\n{}\n{} receipts={} {} {}\n", "─".repeat(self.width.min(80)), self.dim(&footer.timestamp), footer.receipt_count, chain, hash)
    }

    fn hyperlink(&self, cmd: &str, label: &str) -> String {
        if self.use_hyperlinks {
            format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", cmd, self.color("34", label))
        } else {
            self.color("34", label)
        }
    }

    fn color(&self, code: &str, text: &str) -> String {
        if self.use_color { format!("\x1b[{}m{}\x1b[0m", code, text) } else { text.to_string() }
    }

    fn bold(&self, text: &str) -> String {
        if self.use_color { format!("\x1b[1m{}\x1b[0m", text) } else { text.to_string() }
    }

    fn dim(&self, text: &str) -> String {
        if self.use_color { format!("\x1b[2m{}\x1b[0m", text) } else { text.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::time::TimeSelector;

    #[test]
    fn test_render_debug() {
        let executor = super::super::executor::CommandExecutor::new();
        let result = executor.execute_debug("agent/test-001", &TimeSelector::Now);
        let renderer = TerminalRenderer::new().no_color().no_hyperlinks();
        let output = renderer.render(&result);
        assert!(output.contains("DEBUG: agent/test-001"));
        assert!(output.contains("Runtime"));
    }

    #[test]
    fn test_render_json() {
        let executor = super::super::executor::CommandExecutor::new();
        let result = executor.execute_audit("agent/test-001", &TimeSelector::Now);
        let renderer = TerminalRenderer::new().with_mode(OutputMode::Json);
        let output = renderer.render(&result);
        assert!(output.contains("\"doc_type\": \"Audit\""));
    }

    #[test]
    fn test_render_all_7_commands() {
        let executor = super::super::executor::CommandExecutor::new();
        let renderer = TerminalRenderer::new().no_color();
        let time = TimeSelector::Now;
        
        let debug = renderer.render(&executor.execute_debug("agent/x", &time));
        assert!(debug.contains("DEBUG:"));
        
        let audit = renderer.render(&executor.execute_audit("agent/x", &time));
        assert!(audit.contains("AUDIT:"));
        
        let compliance = renderer.render(&executor.execute_compliance("agent/x", &time));
        assert!(compliance.contains("COMPLIANCE:"));
        
        let explain = renderer.render(&executor.execute_explain("agent/x", &time));
        assert!(explain.contains("EXPLAIN:"));
        
        let trace = renderer.render(&executor.execute_trace("agent/x", &time));
        assert!(trace.contains("TRACE:"));
        
        let inspect = renderer.render(&executor.execute_inspect("agent/x", &time));
        assert!(inspect.contains("INSPECT:"));
        
        let review = renderer.render(&executor.execute_review("agent/x", &time));
        assert!(review.contains("REVIEW:"));
    }
}
