//! Agent Surface — Health, activity, policy status

use crate::surface::document::*;

pub fn build_agent_surface(agent_id: &str, view: SurfaceView) -> SurfaceDocument {
    let subject = SubjectIdentity::new(ResourceKind::Agent, agent_id);
    let state = StateVector::active_verified();
    
    let sections = match view {
        SurfaceView::Summary => vec![
            SurfaceSection { title: "Health".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "CPU".into(), value: "12%".into(), link: None },
                    StatItem { label: "Memory".into(), value: "847 MB".into(), link: None },
                    StatItem { label: "Uptime".into(), value: "4h 23m".into(), link: None },
                ]) },
        ],
        SurfaceView::Ops => vec![
            SurfaceSection { title: "Health Metrics".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "CPU".into(), value: "12%".into(), link: None },
                    StatItem { label: "Memory".into(), value: "847 MB".into(), link: None },
                    StatItem { label: "Response Time".into(), value: "234ms".into(), link: None },
                    StatItem { label: "Error Rate".into(), value: "0.1%".into(), link: None },
                ]) },
            SurfaceSection { title: "Recent Activity".into(), kind: SectionKind::Timeline, collapsed: false,
                content: SectionContent::Timeline(vec![
                    TimelineEvent { timestamp: "14:08:23".into(), event_type: "tool_call".into(), message: "icd10_lookup".into(), severity: Severity::Ok, link: Some(ResourceLink::trace("act_8831")) },
                    TimelineEvent { timestamp: "14:08:22".into(), event_type: "memory_read".into(), message: "patient-intake/record-42".into(), severity: Severity::Ok, link: None },
                ]) },
            SurfaceSection { title: "Policy Status".into(), kind: SectionKind::Findings, collapsed: false,
                content: SectionContent::Findings(vec![
                    Finding { severity: Severity::Ok, code: "HIPAA".into(), message: "Compliant".into(), link: None },
                    Finding { severity: Severity::Ok, code: "SOC2".into(), message: "Compliant".into(), link: None },
                ]) },
        ],
        SurfaceView::Forensic => vec![
            SurfaceSection { title: "Full Execution Trace".into(), kind: SectionKind::Trace, collapsed: false,
                content: SectionContent::Trace(vec![
                    TraceSpan { span_id: "span_001".into(), name: "agent.start".into(), duration_ms: 12, status: "ok".into(), depth: 0, link: Some(ResourceLink::trace("span_001")) },
                    TraceSpan { span_id: "span_002".into(), name: "memory.read".into(), duration_ms: 45, status: "ok".into(), depth: 1, link: Some(ResourceLink::trace("span_002")) },
                    TraceSpan { span_id: "span_003".into(), name: "tool.call".into(), duration_ms: 234, status: "ok".into(), depth: 1, link: Some(ResourceLink::trace("span_003")) },
                ]) },
            SurfaceSection { title: "Evidence Chain".into(), kind: SectionKind::Evidence, collapsed: false,
                content: SectionContent::Evidence(vec![
                    EvidenceItem { evidence_type: "Receipt".into(), cid: "rcpt_001".into(), verified: true, link: ResourceLink::verify(ResourceKind::Receipt, "rcpt_001") },
                ]) },
        ],
        SurfaceView::Exec => vec![
            SurfaceSection { title: "Executive Summary".into(), kind: SectionKind::Narrative, collapsed: false,
                content: SectionContent::Narrative("Agent is operating normally with high trust score. No compliance violations detected. System resources are within normal parameters.".into()) },
        ],
    };

    SurfaceDocument {
        meta: SurfaceMeta { surface_type: SurfaceType::Agent, view, generated_at: now_ms() },
        header: SurfaceHeader { title: format!("AGENT: {}", agent_id), subject, state, badges: vec![
            SurfaceBadge { label: "Trust".into(), value: "94/A".into(), severity: Severity::Ok },
            SurfaceBadge { label: "Status".into(), value: "Running".into(), severity: Severity::Ok },
        ], time_range: None },
        summary: Some("Agent running normally. No anomalies detected.".into()),
        sections,
        actions: vec![
            SurfaceAction { label: "Trace".into(), description: "Show execution trace".into(), command: format!("connectorctl trace agent {}", agent_id), primary: true },
            SurfaceAction { label: "Audit".into(), description: "Review audit trail".into(), command: format!("connectorctl audit agent {}", agent_id), primary: false },
        ],
        footer: Some(SurfaceFooter { root_hash: Some("sha256:abc...".into()), verified: true, receipt_count: 148, chain_valid: true, timestamp: "now".into() }),
    }
}

fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }
