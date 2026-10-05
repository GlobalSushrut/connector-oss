//! Compliance Surface — HIPAA, SOC2, GDPR, EU AI Act

use crate::surface::document::*;

pub fn build_compliance_surface(target: &str, framework: &str, view: SurfaceView) -> SurfaceDocument {
    let subject = SubjectIdentity::new(ResourceKind::Policy, target);
    let state = StateVector { execution: ExecutionState::Completed, trust: TrustState::Verified, health: HealthState::Healthy, compliance: ComplianceState::Compliant };
    
    let sections = match view {
        SurfaceView::Summary => vec![
            SurfaceSection { title: "Key Points".into(), kind: SectionKind::Findings, collapsed: false,
                content: SectionContent::Findings(vec![
                    Finding { severity: Severity::Ok, code: "PHI".into(), message: "PHI protection active".into(), link: None },
                    Finding { severity: Severity::Ok, code: "AUDIT".into(), message: "Audit trail verified".into(), link: None },
                    Finding { severity: Severity::Warn, code: "RETENTION".into(), message: "2 retention warnings".into(), link: Some(ResourceLink::inspect(ResourceKind::Policy, "W-201")) },
                ]) },
        ],
        SurfaceView::Ops => vec![
            SurfaceSection { title: "Safeguards".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Administrative".into(), value: "PASS".into(), link: None },
                    StatItem { label: "Technical".into(), value: "PASS".into(), link: None },
                    StatItem { label: "Retention".into(), value: "WARNING".into(), link: None },
                ]) },
            SurfaceSection { title: "Warnings".into(), kind: SectionKind::Findings, collapsed: false,
                content: SectionContent::Findings(vec![
                    Finding { severity: Severity::Warn, code: "W-201".into(), message: "Export missing retention tag".into(), link: Some(ResourceLink::inspect(ResourceKind::Policy, "W-201")) },
                    Finding { severity: Severity::Warn, code: "W-118".into(), message: "Elevated scope read".into(), link: Some(ResourceLink::inspect(ResourceKind::Policy, "W-118")) },
                ]) },
            SurfaceSection { title: "Evidence".into(), kind: SectionKind::Evidence, collapsed: false,
                content: SectionContent::Evidence(vec![
                    EvidenceItem { evidence_type: "Receipts".into(), cid: "24 receipts".into(), verified: true, link: ResourceLink::verify(ResourceKind::Receipt, "all") },
                ]) },
        ],
        SurfaceView::Forensic => vec![
            SurfaceSection { title: "Access Trace".into(), kind: SectionKind::Timeline, collapsed: false,
                content: SectionContent::Timeline(vec![
                    TimelineEvent { timestamp: "12:04:11".into(), event_type: "READ".into(), message: "user/compliance-admin-01 → mem://case/884".into(), severity: Severity::Info, link: Some(ResourceLink::inspect(ResourceKind::Memory, "case/884")) },
                    TimelineEvent { timestamp: "12:05:22".into(), event_type: "PROCESS".into(), message: "agent/care-agent-002 → mem://case/884".into(), severity: Severity::Ok, link: Some(ResourceLink::trace("act_884")) },
                    TimelineEvent { timestamp: "12:06:03".into(), event_type: "BUNDLE".into(), message: "system/export → blob://export/224".into(), severity: Severity::Warn, link: None },
                ]) },
            SurfaceSection { title: "Chain Verification".into(), kind: SectionKind::Evidence, collapsed: false,
                content: SectionContent::Evidence(vec![
                    EvidenceItem { evidence_type: "packet 884-1".into(), cid: "pkt_884_1".into(), verified: true, link: ResourceLink::verify(ResourceKind::MemPacket, "pkt_884_1") },
                    EvidenceItem { evidence_type: "packet 884-2".into(), cid: "pkt_884_2".into(), verified: true, link: ResourceLink::verify(ResourceKind::MemPacket, "pkt_884_2") },
                    EvidenceItem { evidence_type: "export bundle".into(), cid: "exp_224".into(), verified: false, link: ResourceLink::inspect(ResourceKind::Evidence, "exp_224") },
                ]) },
            SurfaceSection { title: "Anomaly Breakdown".into(), kind: SectionKind::Findings, collapsed: false,
                content: SectionContent::Findings(vec![
                    Finding { severity: Severity::Warn, code: "W-201".into(), message: "artifact: blob://export/224".into(), link: None },
                    Finding { severity: Severity::Warn, code: "W-118".into(), message: "actor: user/compliance-admin-01".into(), link: Some(ResourceLink::inspect(ResourceKind::Agent, "compliance-admin-01")) },
                ]) },
        ],
        SurfaceView::Exec => vec![
            SurfaceSection { title: "Overview".into(), kind: SectionKind::Narrative, collapsed: false,
                content: SectionContent::Narrative(format!("The system is compliant with {} safeguards. Minor operational risks exist but do not indicate breach.", framework)) },
            SurfaceSection { title: "Business Risk".into(), kind: SectionKind::Findings, collapsed: false,
                content: SectionContent::Findings(vec![
                    Finding { severity: Severity::Ok, code: "BREACH".into(), message: "No breach detected".into(), link: None },
                    Finding { severity: Severity::Warn, code: "GAPS".into(), message: "Minor audit gaps in retention tagging".into(), link: None },
                ]) },
            SurfaceSection { title: "Recommendation".into(), kind: SectionKind::List, collapsed: false,
                content: SectionContent::List(vec![
                    ListItem { text: "Resolve retention metadata gaps".into(), link: None },
                    ListItem { text: "Enforce elevated access justification logging".into(), link: None },
                ]) },
        ],
    };

    SurfaceDocument {
        meta: SurfaceMeta { surface_type: SurfaceType::Compliance, view, generated_at: now_ms() },
        header: SurfaceHeader { title: format!("{} STATUS: {}", framework.to_uppercase(), target), subject, state, badges: vec![
            SurfaceBadge { label: "State".into(), value: "PASS WITH WARNINGS".into(), severity: Severity::Warn },
            SurfaceBadge { label: "Risk".into(), value: "MODERATE".into(), severity: Severity::Warn },
            SurfaceBadge { label: "Trust".into(), value: "91/100".into(), severity: Severity::Ok },
        ], time_range: None },
        summary: Some("PHI handling compliant with minor warnings.".into()),
        sections,
        actions: vec![
            SurfaceAction { label: "Forensic".into(), description: "Open forensic view".into(), command: format!("connectorctl compliance {} {} --view forensic", framework, target), primary: true },
            SurfaceAction { label: "Export".into(), description: "Export compliance report".into(), command: format!("connectorctl export compliance {} {} --format pdf", framework, target), primary: false },
        ],
        footer: Some(SurfaceFooter { root_hash: Some("sha256:comp...".into()), verified: true, receipt_count: 24, chain_valid: true, timestamp: "now".into() }),
    }
}

fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }
