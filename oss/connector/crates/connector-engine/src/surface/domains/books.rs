//! Books Surface — Operational ledger, transactions, reconciliation

use crate::surface::document::*;

pub fn build_books_surface(target: &str, view: SurfaceView) -> SurfaceDocument {
    let subject = SubjectIdentity::new(ResourceKind::Audit, target);
    let state = StateVector { execution: ExecutionState::Completed, trust: TrustState::Verified, health: HealthState::Healthy, compliance: ComplianceState::Compliant };
    
    let sections = match view {
        SurfaceView::Summary => vec![
            SurfaceSection { title: "Key Points".into(), kind: SectionKind::Findings, collapsed: false,
                content: SectionContent::Findings(vec![
                    Finding { severity: Severity::Ok, code: "LEDGER".into(), message: "Ledger balanced".into(), link: None },
                    Finding { severity: Severity::Ok, code: "PROOF".into(), message: "Proof postings verified".into(), link: None },
                    Finding { severity: Severity::Warn, code: "REVIEW".into(), message: "2 warning entries require review".into(), link: None },
                ]) },
        ],
        SurfaceView::Ops => vec![
            SurfaceSection { title: "Recent Entries".into(), kind: SectionKind::Timeline, collapsed: false,
                content: SectionContent::Timeline(vec![
                    TimelineEvent { timestamp: "14:08".into(), event_type: "DR".into(), message: "memory/read 1 packet".into(), severity: Severity::Info, link: Some(ResourceLink::inspect(ResourceKind::MemPacket, "mpk_001")) },
                    TimelineEvent { timestamp: "14:08".into(), event_type: "DR".into(), message: "tool/compute 1 call".into(), severity: Severity::Info, link: Some(ResourceLink::inspect(ResourceKind::Tool, "icd10")) },
                    TimelineEvent { timestamp: "14:08".into(), event_type: "CR".into(), message: "decision/approve 1 outcome".into(), severity: Severity::Ok, link: Some(ResourceLink::inspect(ResourceKind::Event, "dec_001")) },
                    TimelineEvent { timestamp: "14:08".into(), event_type: "CR".into(), message: "proof/receipt 1 receipt".into(), severity: Severity::Ok, link: Some(ResourceLink::verify(ResourceKind::Receipt, "rcpt_001")) },
                ]) },
            SurfaceSection { title: "Balance View".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Memory Ops".into(), value: "342".into(), link: None },
                    StatItem { label: "Tool Ops".into(), value: "18".into(), link: None },
                    StatItem { label: "Policy Checks".into(), value: "24".into(), link: None },
                    StatItem { label: "Proof Entries".into(), value: "148".into(), link: None },
                ]) },
        ],
        SurfaceView::Forensic => vec![
            SurfaceSection { title: "Ledger Chain".into(), kind: SectionKind::Evidence, collapsed: false,
                content: SectionContent::Evidence(vec![
                    EvidenceItem { evidence_type: "entry/001".into(), cid: "ent_001".into(), verified: true, link: ResourceLink::verify(ResourceKind::Receipt, "rcpt_001") },
                    EvidenceItem { evidence_type: "entry/002".into(), cid: "ent_002".into(), verified: true, link: ResourceLink::verify(ResourceKind::Receipt, "rcpt_002") },
                    EvidenceItem { evidence_type: "entry/003".into(), cid: "ent_003".into(), verified: true, link: ResourceLink::verify(ResourceKind::Proof, "proof_003") },
                ]) },
            SurfaceSection { title: "Posting Detail".into(), kind: SectionKind::RawData, collapsed: true,
                content: SectionContent::RawData(BlobContainer::json("entry_003", &serde_json::json!({
                    "debit": "tool/icd10_lookup",
                    "credit": "decision/approve_claim",
                    "evidence": "rcpt_002",
                    "hash": "4ab2..."
                }))) },
        ],
        SurfaceView::Exec => vec![
            SurfaceSection { title: "Books Executive View".into(), kind: SectionKind::Narrative, collapsed: false,
                content: SectionContent::Narrative("Operational ledger is balanced and trustworthy. No unreconciled critical entries exist.".into()) },
            SurfaceSection { title: "Business Impact".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Auditability".into(), value: "Strong".into(), link: None },
                    StatItem { label: "Cost Visibility".into(), value: "Good".into(), link: None },
                    StatItem { label: "Operational Risk".into(), value: "Low".into(), link: None },
                ]) },
        ],
    };

    SurfaceDocument {
        meta: SurfaceMeta { surface_type: SurfaceType::Books, view, generated_at: now_ms() },
        header: SurfaceHeader { title: format!("BOOKS: {}", target), subject, state, badges: vec![
            SurfaceBadge { label: "State".into(), value: "BALANCED".into(), severity: Severity::Ok },
            SurfaceBadge { label: "Entries".into(), value: "148".into(), severity: Severity::Info },
        ], time_range: None },
        summary: Some("Ledger balanced. All proof postings verified.".into()),
        sections,
        actions: vec![
            SurfaceAction { label: "Reconcile".into(), description: "Run reconciliation".into(), command: format!("connectorctl books reconcile {}", target), primary: true },
            SurfaceAction { label: "Export".into(), description: "Export ledger".into(), command: format!("connectorctl books export {} --format csv", target), primary: false },
        ],
        footer: Some(SurfaceFooter { root_hash: Some("sha256:bks...".into()), verified: true, receipt_count: 148, chain_valid: true, timestamp: "now".into() }),
    }
}

fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }
