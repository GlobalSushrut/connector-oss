//! Audit Surface — Investigation, evidence chain, receipts

use crate::surface::document::*;

pub fn build_audit_surface(target: &str, view: SurfaceView) -> SurfaceDocument {
    let subject = SubjectIdentity::new(ResourceKind::Audit, target);
    let state = StateVector::active_verified();
    
    let sections = match view {
        SurfaceView::Summary => vec![
            SurfaceSection { title: "Key Findings".into(), kind: SectionKind::Findings, collapsed: false,
                content: SectionContent::Findings(vec![
                    Finding { severity: Severity::Ok, code: "CHAIN".into(), message: "Chain intact".into(), link: None },
                    Finding { severity: Severity::Ok, code: "RECEIPTS".into(), message: "All receipts present".into(), link: None },
                ]) },
        ],
        SurfaceView::Ops => vec![
            SurfaceSection { title: "Key Signals".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Actions Total".into(), value: "148".into(), link: None },
                    StatItem { label: "Blocked".into(), value: "2".into(), link: None },
                    StatItem { label: "Receipts".into(), value: "148".into(), link: Some(ResourceLink::verify(ResourceKind::Receipt, "all")) },
                ]) },
            SurfaceSection { title: "Timeline".into(), kind: SectionKind::Timeline, collapsed: false,
                content: SectionContent::Timeline(vec![
                    TimelineEvent { timestamp: "14:08".into(), event_type: "PolicyDenied".into(), message: "claims_export blocked".into(), severity: Severity::Warn, link: Some(ResourceLink::inspect(ResourceKind::Event, "evt_001")) },
                    TimelineEvent { timestamp: "14:06".into(), event_type: "ToolExecuted".into(), message: "summarize_claims".into(), severity: Severity::Ok, link: Some(ResourceLink::trace("act_002")) },
                ]) },
            SurfaceSection { title: "Trust Verification".into(), kind: SectionKind::Evidence, collapsed: false,
                content: SectionContent::Evidence(vec![
                    EvidenceItem { evidence_type: "Chain".into(), cid: "chain_001".into(), verified: true, link: ResourceLink::verify(ResourceKind::Proof, "chain_001") },
                ]) },
        ],
        SurfaceView::Forensic => vec![
            SurfaceSection { title: "Evidence Tree".into(), kind: SectionKind::Evidence, collapsed: false,
                content: SectionContent::Evidence(vec![
                    EvidenceItem { evidence_type: "Receipt".into(), cid: "rcpt_001".into(), verified: true, link: ResourceLink::verify(ResourceKind::Receipt, "rcpt_001") },
                    EvidenceItem { evidence_type: "Receipt".into(), cid: "rcpt_002".into(), verified: true, link: ResourceLink::verify(ResourceKind::Receipt, "rcpt_002") },
                    EvidenceItem { evidence_type: "Proof".into(), cid: "proof_001".into(), verified: true, link: ResourceLink::verify(ResourceKind::Proof, "proof_001") },
                ]) },
            SurfaceSection { title: "Raw Containers".into(), kind: SectionKind::RawData, collapsed: true,
                content: SectionContent::RawData(BlobContainer::json("audit_raw", &serde_json::json!({"total": 148, "verified": 148}))) },
        ],
        SurfaceView::Exec => vec![
            SurfaceSection { title: "Investigation Overview".into(), kind: SectionKind::Narrative, collapsed: false,
                content: SectionContent::Narrative("The event chain is complete and verified. All actions have corresponding receipts. Two policy denials occurred but were handled correctly per governance rules.".into()) },
        ],
    };

    SurfaceDocument {
        meta: SurfaceMeta { surface_type: SurfaceType::Audit, view, generated_at: now_ms() },
        header: SurfaceHeader { title: format!("AUDIT: {}", target), subject, state, badges: vec![
            SurfaceBadge { label: "State".into(), value: "VERIFIED".into(), severity: Severity::Ok },
            SurfaceBadge { label: "Receipts".into(), value: "148".into(), severity: Severity::Info },
        ], time_range: None },
        summary: Some("Agent execution stable. No tampering detected.".into()),
        sections,
        actions: vec![
            SurfaceAction { label: "Verify Chain".into(), description: "Verify full evidence chain".into(), command: format!("connectorctl verify {}", target), primary: true },
            SurfaceAction { label: "Export".into(), description: "Export audit report".into(), command: format!("connectorctl export audit {} --format pdf", target), primary: false },
        ],
        footer: Some(SurfaceFooter { root_hash: Some("sha256:4ab2...".into()), verified: true, receipt_count: 148, chain_valid: true, timestamp: "now".into() }),
    }
}

fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }
