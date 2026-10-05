//! Debug Surface — Execution trace, tool calls, decisions

use crate::surface::document::*;

pub fn build_debug_surface(target: &str, view: SurfaceView) -> SurfaceDocument {
    let subject = SubjectIdentity::new(ResourceKind::Agent, target);
    let state = StateVector { execution: ExecutionState::Completed, trust: TrustState::Verified, health: HealthState::Healthy, compliance: ComplianceState::Compliant };
    
    let sections = match view {
        SurfaceView::Summary => vec![
            SurfaceSection { title: "Execution".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Steps".into(), value: "8".into(), link: None },
                    StatItem { label: "Tools".into(), value: "3 calls".into(), link: None },
                    StatItem { label: "Memory".into(), value: "5 reads, 2 writes".into(), link: None },
                ]) },
        ],
        SurfaceView::Ops => vec![
            SurfaceSection { title: "Execution Trace".into(), kind: SectionKind::Timeline, collapsed: false,
                content: SectionContent::Timeline(vec![
                    TimelineEvent { timestamp: "14:08:23.001".into(), event_type: "START".into(), message: "claims_review".into(), severity: Severity::Info, link: Some(ResourceLink::trace("span_001")) },
                    TimelineEvent { timestamp: "14:08:23.045".into(), event_type: "MEMORY_READ".into(), message: "patient-intake/record-42".into(), severity: Severity::Ok, link: None },
                    TimelineEvent { timestamp: "14:08:23.123".into(), event_type: "TOOL_CALL".into(), message: "icd10_lookup(code=\"E11\")".into(), severity: Severity::Ok, link: Some(ResourceLink::inspect(ResourceKind::Tool, "icd10_lookup")) },
                    TimelineEvent { timestamp: "14:08:24.401".into(), event_type: "DECISION".into(), message: "approve_claim".into(), severity: Severity::Ok, link: Some(ResourceLink::inspect(ResourceKind::Event, "dec_001")) },
                    TimelineEvent { timestamp: "14:08:24.456".into(), event_type: "MEMORY_WRITE".into(), message: "claims-analysis/summary-001".into(), severity: Severity::Ok, link: None },
                    TimelineEvent { timestamp: "14:08:24.512".into(), event_type: "POLICY_CHECK".into(), message: "hipaa_compliant".into(), severity: Severity::Ok, link: Some(ResourceLink::verify(ResourceKind::Policy, "hipaa")) },
                ]) },
            SurfaceSection { title: "Tool Calls".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "icd10_lookup".into(), value: "1.2s SUCCESS".into(), link: Some(ResourceLink::inspect(ResourceKind::Tool, "icd10_lookup")) },
                ]) },
            SurfaceSection { title: "Decisions".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "approve_claim".into(), value: "confidence=0.94".into(), link: Some(ResourceLink::inspect(ResourceKind::Event, "dec_001")) },
                ]) },
        ],
        SurfaceView::Forensic => vec![
            SurfaceSection { title: "Complete Execution Trace".into(), kind: SectionKind::Trace, collapsed: false,
                content: SectionContent::Trace(vec![
                    TraceSpan { span_id: "span_001".into(), name: "START claims_review".into(), duration_ms: 0, status: "ok".into(), depth: 0, link: None },
                    TraceSpan { span_id: "span_002".into(), name: "MEMORY_READ mpk_01KX4A2B".into(), duration_ms: 44, status: "ok".into(), depth: 1, link: None },
                    TraceSpan { span_id: "span_003".into(), name: "TOOL_CALL icd10_lookup".into(), duration_ms: 1278, status: "ok".into(), depth: 1, link: None },
                    TraceSpan { span_id: "span_004".into(), name: "TOOL_RESULT success".into(), duration_ms: 0, status: "ok".into(), depth: 2, link: None },
                    TraceSpan { span_id: "span_005".into(), name: "DECISION approve_claim".into(), duration_ms: 55, status: "ok".into(), depth: 1, link: None },
                    TraceSpan { span_id: "span_006".into(), name: "MEMORY_WRITE mpk_02LY5B3C".into(), duration_ms: 11, status: "ok".into(), depth: 1, link: None },
                ]) },
            SurfaceSection { title: "Decision Reasoning".into(), kind: SectionKind::RawData, collapsed: true,
                content: SectionContent::RawData(BlobContainer::json("reasoning", &serde_json::json!({
                    "input_context": "patient record with ICD-10 E11",
                    "policy_checks": ["hipaa_compliant", "budget_ok"],
                    "confidence": 0.94,
                    "evidence_refs": ["rcpt_001", "rcpt_002"]
                }))) },
            SurfaceSection { title: "Memory Lineage".into(), kind: SectionKind::List, collapsed: false,
                content: SectionContent::List(vec![
                    ListItem { text: "mpk_01KX4A2B → mpk_02LY5B3C".into(), link: Some(ResourceLink::inspect(ResourceKind::MemPacket, "mpk_01KX4A2B")) },
                ]) },
        ],
        SurfaceView::Exec => vec![
            SurfaceSection { title: "Execution Overview".into(), kind: SectionKind::Narrative, collapsed: false,
                content: SectionContent::Narrative("The agent successfully completed the claims review flow. No critical errors occurred.".into()) },
            SurfaceSection { title: "Outcome".into(), kind: SectionKind::StatsGrid, collapsed: false,
                content: SectionContent::Stats(vec![
                    StatItem { label: "Decision".into(), value: "Approved".into(), link: None },
                    StatItem { label: "Confidence".into(), value: "High".into(), link: None },
                    StatItem { label: "Policy".into(), value: "Compliant".into(), link: None },
                ]) },
        ],
    };

    SurfaceDocument {
        meta: SurfaceMeta { surface_type: SurfaceType::Debug, view, generated_at: now_ms() },
        header: SurfaceHeader { title: format!("DEBUG: {}", target), subject, state, badges: vec![
            SurfaceBadge { label: "Last Run".into(), value: "2026-03-21 14:08:23".into(), severity: Severity::Info },
            SurfaceBadge { label: "Status".into(), value: "COMPLETED".into(), severity: Severity::Ok },
            SurfaceBadge { label: "Duration".into(), value: "2.4s".into(), severity: Severity::Info },
        ], time_range: None },
        summary: Some("Execution completed successfully with no errors.".into()),
        sections,
        actions: vec![
            SurfaceAction { label: "Trace".into(), description: "Show full trace".into(), command: format!("connectorctl trace {}", target), primary: true },
            SurfaceAction { label: "Forensic".into(), description: "Open forensic view".into(), command: format!("connectorctl debug {} --view forensic", target), primary: false },
        ],
        footer: Some(SurfaceFooter { root_hash: Some("sha256:dbg...".into()), verified: true, receipt_count: 8, chain_valid: true, timestamp: "now".into() }),
    }
}

fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }
