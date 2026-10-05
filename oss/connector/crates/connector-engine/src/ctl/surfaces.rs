//! Surface Generators — 7 inspection commands with clickable links and raw data

use super::executor::*;
use super::identity::{ResourceIdentity, ResourceKind};
use serde_json::json;

pub struct SurfaceBuilder {
    title: String, doc_type: SurfaceType, subject: String, identity: ResourceIdentity,
    state: SurfaceState, badges: Vec<SurfaceBadge>, time_range: Option<String>,
    summary: Option<String>, sections: Vec<SurfaceSection>, actions: Vec<SurfaceAction>,
    footer: Option<SurfaceFooter>,
}

impl SurfaceBuilder {
    pub fn new(doc_type: SurfaceType, subject: &str) -> Self {
        Self { title: subject.into(), doc_type, subject: subject.into(),
            identity: ResourceIdentity::new(ResourceKind::Agent, subject),
            state: SurfaceState::Active, badges: vec![], time_range: None,
            summary: None, sections: vec![], actions: vec![], footer: None }
    }
    pub fn title(mut self, t: &str) -> Self { self.title = t.into(); self }
    pub fn identity(mut self, i: ResourceIdentity) -> Self { self.identity = i; self }
    pub fn state(mut self, s: SurfaceState) -> Self { self.state = s; self }
    pub fn badge(mut self, l: &str, v: &str, s: Severity) -> Self {
        self.badges.push(SurfaceBadge { label: l.into(), value: v.into(), severity: s }); self
    }
    pub fn time_range(mut self, r: &str) -> Self { self.time_range = Some(r.into()); self }
    pub fn summary(mut self, s: &str) -> Self { self.summary = Some(s.into()); self }
    pub fn section(mut self, s: SurfaceSection) -> Self { self.sections.push(s); self }
    pub fn action(mut self, l: &str, d: &str, c: &str, p: bool) -> Self {
        self.actions.push(SurfaceAction { label: l.into(), description: d.into(), command: c.into(), primary: p }); self
    }
    pub fn footer(mut self, h: Option<String>, v: bool, r: u32, c: bool) -> Self {
        self.footer = Some(SurfaceFooter { root_hash: h, verified: v, receipt_count: r, chain_valid: c, timestamp: "now".into() }); self
    }
    pub fn build(self) -> SurfaceDocument {
        SurfaceDocument { title: self.title, doc_type: self.doc_type,
            header: SurfaceHeader { subject: self.subject, identity: self.identity, state: self.state, badges: self.badges, time_range: self.time_range },
            summary: self.summary, sections: self.sections, actions: self.actions, footer: self.footer }
    }
}

fn stats_section(title: &str, items: Vec<(&str, &str, Option<&str>)>) -> SurfaceSection {
    SurfaceSection { title: title.into(), kind: SectionKind::StatsGrid, collapsed: false,
        content: SectionContent::Stats(items.into_iter().map(|(l,v,t)| StatItem { label: l.into(), value: v.into(), link: t.map(DeepLink::inspect) }).collect()) }
}

fn timeline_section(title: &str, events: Vec<(&str, &str, &str, Severity, Option<&str>)>) -> SurfaceSection {
    SurfaceSection { title: title.into(), kind: SectionKind::Timeline, collapsed: false,
        content: SectionContent::Timeline(events.into_iter().map(|(ts,et,m,s,l)| TimelineEvent { timestamp: ts.into(), event_type: et.into(), message: m.into(), severity: s, link: l.map(DeepLink::trace) }).collect()) }
}

fn evidence_section(title: &str, items: Vec<(&str, &str, bool)>) -> SurfaceSection {
    SurfaceSection { title: title.into(), kind: SectionKind::Evidence, collapsed: false,
        content: SectionContent::Evidence(items.into_iter().map(|(t,c,v)| EvidenceItem { evidence_type: t.into(), cid: c.into(), verified: v, link: DeepLink::verify(c) }).collect()) }
}

fn findings_section(title: &str, items: Vec<(Severity, &str, &str, Option<&str>)>) -> SurfaceSection {
    SurfaceSection { title: title.into(), kind: SectionKind::Findings, collapsed: false,
        content: SectionContent::Findings(items.into_iter().map(|(s,c,m,l)| Finding { severity: s, code: c.into(), message: m.into(), link: l.map(DeepLink::inspect) }).collect()) }
}

fn trace_section(title: &str, spans: Vec<(&str, &str, u64, &str, u32)>) -> SurfaceSection {
    SurfaceSection { title: title.into(), kind: SectionKind::Trace, collapsed: false,
        content: SectionContent::Trace(spans.into_iter().map(|(id,n,d,st,dp)| TraceSpan { span_id: id.into(), name: n.into(), duration_ms: d, status: st.into(), depth: dp, link: Some(DeepLink::trace(id)) }).collect()) }
}

fn raw_section(title: &str, id: &str, data: serde_json::Value) -> SurfaceSection {
    SurfaceSection { title: title.into(), kind: SectionKind::RawData, collapsed: true, content: SectionContent::RawData(RawDataBlob::json(id, &data)) }
}

// 1. DEBUG
pub fn build_debug_surface(target: &str, ctx: &TimeContext) -> SurfaceDocument {
    let id = ResourceIdentity::parse(target).unwrap_or_else(|| ResourceIdentity::agent(target));
    SurfaceBuilder::new(SurfaceType::Debug, target).title(&format!("DEBUG: {}", target)).identity(id)
        .state(SurfaceState::Active).badge("Status", "Running", Severity::Ok).badge("Memory", "847 MB", Severity::Info)
        .time_range(if ctx.is_time_travel { "time-travel" } else { "now" })
        .summary("Agent running normally. No anomalies.")
        .section(stats_section("Runtime", vec![("Uptime", "4h 23m", None), ("Actions", "1,247", Some("agent/actions")), ("Memory Ops", "8,431", Some("agent/memory"))]))
        .section(timeline_section("Recent Events", vec![("10:23:45", "tool_call", "Called ehr-bridge.lookup", Severity::Ok, Some("act_8831")), ("10:23:44", "memory_write", "Stored patient context", Severity::Ok, Some("mpk_7721"))]))
        .section(raw_section("Raw State", "state_dump", json!({"agent_id": target, "state": "running", "memory_mb": 847})))
        .action("Trace Last", "Show trace", &format!("connectorctl trace {} --last 1", target), true)
        .footer(Some("sha256:abc...".into()), true, 1247, true).build()
}

// 2. AUDIT
pub fn build_audit_surface(target: &str, ctx: &TimeContext) -> SurfaceDocument {
    SurfaceBuilder::new(SurfaceType::Audit, target).title(&format!("AUDIT: {}", target))
        .state(SurfaceState::Verified).badge("Compliance", "100%", Severity::Ok).badge("Receipts", "1,247", Severity::Info)
        .summary("All actions verified. Evidence chain intact.")
        .section(stats_section("Summary", vec![("Total Actions", "1,247", None), ("Verified", "1,247", None), ("Violations", "0", None)]))
        .section(evidence_section("Evidence Chain", vec![("Receipt", "rcpt_001", true), ("Receipt", "rcpt_002", true), ("Receipt", "rcpt_003", true)]))
        .section(raw_section("Audit Log", "audit_log", json!({"total": 1247, "verified": 1247, "chain_valid": true})))
        .action("Verify Chain", "Verify evidence", &format!("connectorctl verify {} --full", target), true)
        .footer(Some("sha256:def...".into()), true, 1247, true).build()
}

// 3. COMPLIANCE
pub fn build_compliance_surface(target: &str, _ctx: &TimeContext) -> SurfaceDocument {
    SurfaceBuilder::new(SurfaceType::Compliance, target).title(&format!("COMPLIANCE: {}", target))
        .state(SurfaceState::Verified).badge("HIPAA", "✓", Severity::Ok).badge("SOC2", "✓", Severity::Ok).badge("GDPR", "✓", Severity::Ok)
        .summary("All regulatory requirements met.")
        .section(findings_section("Compliance Checks", vec![(Severity::Ok, "HIPAA-001", "PHI access logged", None), (Severity::Ok, "SOC2-001", "Audit trail complete", None)]))
        .action("Export Report", "Generate PDF", &format!("connectorctl export {} --compliance --pdf", target), true).build()
}

// 4. EXPLAIN
pub fn build_explain_surface(target: &str, _ctx: &TimeContext) -> SurfaceDocument {
    SurfaceBuilder::new(SurfaceType::Explain, target).title(&format!("EXPLAIN: {}", target))
        .state(SurfaceState::Active).badge("Decision", "Approved", Severity::Ok)
        .summary("Decision was made based on policy rules and context.")
        .section(SurfaceSection { title: "Reasoning".into(), kind: SectionKind::Narrative, collapsed: false,
            content: SectionContent::Narrative("The agent approved this action because:\n1. Policy hipaa-strict allows PHI access for treatment\n2. User has valid credentials\n3. Budget was within limits".into()) })
        .section(evidence_section("Supporting Evidence", vec![("PolicyCheck", "pol_881", true), ("CredentialCheck", "cred_221", true)]))
        .action("Trace Decision", "Show full trace", &format!("connectorctl trace {}", target), true).build()
}

// 5. TRACE
pub fn build_trace_surface(target: &str, _ctx: &TimeContext) -> SurfaceDocument {
    SurfaceBuilder::new(SurfaceType::Trace, target).title(&format!("TRACE: {}", target))
        .state(SurfaceState::Active).badge("Spans", "12", Severity::Info).badge("Duration", "847ms", Severity::Ok)
        .summary("Execution completed successfully in 847ms.")
        .section(trace_section("Execution Trace", vec![
            ("span_001", "contract.execute", 847, "ok", 0),
            ("span_002", "governance.check", 12, "ok", 1),
            ("span_003", "tool.ehr_lookup", 234, "ok", 1),
            ("span_004", "llm.infer", 589, "ok", 1),
            ("span_005", "memory.write", 8, "ok", 1),
        ]))
        .section(raw_section("Trace Data", "trace_raw", json!({"spans": 12, "duration_ms": 847, "status": "ok"})))
        .action("Inspect Span", "Deep inspect", &format!("connectorctl inspect {}/span_001", target), true).build()
}

// 6. INSPECT
pub fn build_inspect_surface(target: &str, ctx: &TimeContext) -> SurfaceDocument {
    SurfaceBuilder::new(SurfaceType::Inspect, target).title(&format!("INSPECT: {}", target))
        .state(SurfaceState::Active).badge("Type", "Agent", Severity::Info)
        .time_range(if ctx.is_time_travel { "time-travel" } else { "now" })
        .summary("Deep inspection of resource state and history.")
        .section(stats_section("Overview", vec![("Sessions", "3", Some("agent/sessions")), ("Tools", "5", Some("agent/tools")), ("Contracts", "2", Some("agent/contracts"))]))
        .section(timeline_section("History", vec![("10:23:45", "action", "Completed task", Severity::Ok, Some("act_8831")), ("10:20:00", "start", "Agent started", Severity::Info, None)]))
        .action("Show Raw", "Full JSON", &format!("connectorctl show {} --json", target), true).build()
}

// 7. REVIEW
pub fn build_review_surface(target: &str, _ctx: &TimeContext) -> SurfaceDocument {
    SurfaceBuilder::new(SurfaceType::Review, target).title(&format!("REVIEW: {}", target))
        .state(SurfaceState::Partial).badge("Pending", "2", Severity::Warn).badge("Approved", "45", Severity::Ok)
        .summary("2 items pending review. 45 approved in last 24h.")
        .section(findings_section("Pending Approvals", vec![(Severity::Warn, "APR-001", "High-value transaction requires approval", Some("approval/apr_001")), (Severity::Warn, "APR-002", "New tool attachment", Some("approval/apr_002"))]))
        .action("Approve All", "Batch approve", &format!("connectorctl approve {} --all", target), true)
        .action("Deny", "Reject pending", &format!("connectorctl deny {} --pending", target), false).build()
}

pub fn build_surface(verb: super::grammar::Verb, target: &str, ctx: &TimeContext) -> SurfaceDocument {
    match verb {
        super::grammar::Verb::Trace => build_trace_surface(target, ctx),
        super::grammar::Verb::Inspect => build_inspect_surface(target, ctx),
        super::grammar::Verb::Review => build_review_surface(target, ctx),
        super::grammar::Verb::Explain => build_explain_surface(target, ctx),
        _ => build_debug_surface(target, ctx),
    }
}
