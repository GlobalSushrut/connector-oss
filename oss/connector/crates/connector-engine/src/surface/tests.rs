//! Integration Tests — End-to-end SOE usage examples
//!
//! These tests demonstrate the full SOE workflow and serve as documentation.

#[cfg(test)]
mod integration_tests {
    use crate::surface::*;

    // ═══════════════════════════════════════════════════════════════════════
    // Example 1: Building an Agent Health Surface
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_agent_health_surface_workflow() {
        // Step 1: Build surface using fluent API
        let surface = SurfaceBuilder::agent("claims-agent-001")
            .view(SurfaceView::Ops)
            .judgment_ok("Agent running normally with high performance")
            .signal_check("Health metrics within normal range")
            .signal_check("Policy compliance verified")
            .signal_check("Evidence chain intact")
            .trust(95)
            .evidence_complete(148, "sha256:abc123def456")
            .stats("Health Metrics", vec![
                ("CPU", "12%"),
                ("Memory", "847 MB"),
                ("Response Time", "234ms"),
                ("Error Rate", "0.1%"),
            ])
            .timeline("Recent Activity", vec![
                TimelineEvent {
                    timestamp: "14:08:23".into(),
                    event_type: "tool_call".into(),
                    message: "icd10_lookup completed".into(),
                    severity: Severity::Ok,
                    link: Some(ResourceLink::trace("act_8831")),
                },
                TimelineEvent {
                    timestamp: "14:08:22".into(),
                    event_type: "memory_read".into(),
                    message: "patient-intake/record-42".into(),
                    severity: Severity::Ok,
                    link: None,
                },
            ])
            .action("Trace", "Show execution trace", "connectorctl trace agent claims-agent-001")
            .action("Audit", "Review audit trail", "connectorctl audit agent claims-agent-001")
            .build();

        // Step 2: Render to terminal
        let terminal_output = TerminalRenderer::new().render(&surface);
        assert!(terminal_output.contains("AGENT: agent/claims-agent-001"));
        assert!(terminal_output.contains("CPU"));

        // Step 3: Export to multiple formats
        let json = Exporter::export(&surface, ExportFormat::Json);
        assert!(json.contains("claims-agent-001"));

        let markdown = Exporter::export(&surface, ExportFormat::Markdown);
        assert!(markdown.contains("# AGENT:"));

        let html = Exporter::export(&surface, ExportFormat::Html);
        assert!(html.contains("<!DOCTYPE html>"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 2: Compliance Surface with Warnings
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compliance_surface_with_warnings() {
        let surface = SurfaceBuilder::compliance("care-agent-002")
            .view(SurfaceView::Ops)
            .judgment_warn("HIPAA compliant with minor warnings")
            .signal_check("PHI protection active")
            .signal_check("Audit trail verified")
            .signal_warn("2 retention warnings")
            .signal_warn("1 elevated access path")
            .badge_warn("State", "PASS WITH WARNINGS")
            .badge_warn("Risk", "MODERATE")
            .badge_ok("Trust", "91/100")
            .findings("Safeguards", vec![
                Finding { severity: Severity::Ok, code: "ADMIN".into(), message: "Administrative: PASS".into(), link: None },
                Finding { severity: Severity::Ok, code: "TECH".into(), message: "Technical: PASS".into(), link: None },
                Finding { severity: Severity::Warn, code: "RETENTION".into(), message: "Retention: WARNING".into(), link: None },
            ])
            .findings("Warnings", vec![
                Finding { severity: Severity::Warn, code: "W-201".into(), message: "Export missing retention tag".into(), link: Some(ResourceLink::inspect(ResourceKind::Policy, "W-201")) },
                Finding { severity: Severity::Warn, code: "W-118".into(), message: "Elevated scope read".into(), link: Some(ResourceLink::inspect(ResourceKind::Policy, "W-118")) },
            ])
            .action("Forensic", "Open forensic view", "connectorctl compliance hipaa care-agent-002 --view forensic")
            .build();

        let output = TerminalRenderer::new().render(&surface);
        assert!(output.contains("W-201"));
        assert!(output.contains("retention"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 3: Error Surface for Not Found
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_surface_not_found() {
        let error_surface = ErrorSurfaceBuilder::not_found("Agent", "claims-review");
        
        let output = TerminalRenderer::new().render(&error_surface);
        assert!(output.contains("not found"));
        assert!(output.contains("connectorctl agent list"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 4: Verification Failed with Required Actions
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verification_failed_surface() {
        let error_surface = ErrorSurfaceBuilder::verification_failed(
            "agent-001",
            47,
            "Hash mismatch at block 47",
        );

        let output = TerminalRenderer::new().render(&error_surface);
        assert!(output.contains("block 47"));
        assert!(output.contains("Isolate"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 5: Role-Based View Access
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_role_based_access() {
        // Developer can access Forensic
        assert!(Role::Developer.can_access(SurfaceView::Forensic));
        
        // Operator cannot access Forensic
        assert!(!Role::Operator.can_access(SurfaceView::Forensic));
        
        // Executive defaults to Exec view
        assert_eq!(Role::Executive.default_view(), SurfaceView::Exec);
        
        // Auditor can access all views
        assert!(Role::Auditor.can_access(SurfaceView::Summary));
        assert!(Role::Auditor.can_access(SurfaceView::Ops));
        assert!(Role::Auditor.can_access(SurfaceView::Forensic));
        assert!(Role::Auditor.can_access(SurfaceView::Exec));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 6: Redaction for Different Roles
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_redaction_by_role() {
        let operator_redactor = Redactor::for_role(Role::Operator);
        let developer_redactor = Redactor::for_role(Role::Developer);

        // Operator sees redacted SSN
        let ssn = "123-45-6789";
        assert_eq!(operator_redactor.redact(ssn, ValueType::Ssn), "███-██-████");
        
        // Developer sees full SSN
        assert_eq!(developer_redactor.redact(ssn, ValueType::Ssn), ssn);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 7: Compound Surface (Multi-Domain)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compound_surface() {
        let agent_surface = SurfaceBuilder::agent("test-001")
            .judgment_ok("Agent healthy")
            .stats("Health", vec![("CPU", "10%")])
            .build();

        let audit_surface = SurfaceBuilder::audit("test-001")
            .judgment_ok("Audit verified")
            .stats("Evidence", vec![("Receipts", "148")])
            .build();

        let compound = CompoundBuilder::new()
            .add(agent_surface)
            .add(audit_surface)
            .title("Agent + Audit Overview")
            .composition(CompositionStrategy::Sequential)
            .build()
            .unwrap();

        assert_eq!(compound.all_surfaces().len(), 2);
        
        // Flatten for rendering
        let flat = compound.flatten();
        assert!(flat.header.title.contains("Agent + Audit"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 8: Pagination and Filtering
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pagination_and_filtering() {
        // Create a query with filters
        let query = Query::new()
            .filter(Filter::eq("severity", "critical"))
            .filter(Filter::gt("size", 1000.0))
            .sort_by(Sort::desc("timestamp"))
            .paginate(2, 50);

        assert_eq!(query.filters.len(), 2);
        assert_eq!(query.page.page, 2);
        assert_eq!(query.page.page_size, 50);

        // Page info display
        let page_info = PageInfo::new(2, 50, 1247);
        assert_eq!(page_info.total_pages, 25);
        assert!(page_info.display().contains("51-100"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 9: Command Routing
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_command_routing() {
        let router = SurfaceRouter::new();

        // Debug command routes to Debug surface
        assert_eq!(router.surface_for("debug", "agent"), SurfaceType::Debug);
        assert_eq!(router.default_view_for("debug", "agent"), SurfaceView::Ops);

        // Compliance command routes to Compliance surface
        assert_eq!(router.surface_for("compliance", "hipaa"), SurfaceType::Compliance);

        // Routing context
        let ctx = RoutingContext::resolve("audit", "agent", "claims-001", None);
        assert_eq!(ctx.surface_type, SurfaceType::Audit);
        assert_eq!(ctx.view, SurfaceView::Summary);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 10: Contract Validation
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_contract_validation() {
        let valid_contract = SurfaceContract {
            subject: SubjectIdentity::new(ResourceKind::Agent, "test-agent"),
            state: StateVector::active_verified(),
            judgment: Judgment::ok("All systems operational"),
            signals: vec![
                Signal::check("Health OK"),
                Signal::check("Policy compliant"),
                Signal::check("Evidence chain intact"),
            ],
            actions: vec![],
            evidence: EvidencePosture::complete(10, "sha256:abc"),
            trust: TrustScore::new(95),
        };

        let validation = valid_contract.validate();
        assert!(validation.valid);
        assert!(validation.errors.is_empty());

        // Convert to document
        let doc = valid_contract.to_document(SurfaceType::Agent, SurfaceView::Summary);
        assert!(doc.header.title.contains("AGENT"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 11: Domain Surface Generators
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_domain_surface_generators() {
        // Agent surface
        let agent = build_agent_surface("claims-001", SurfaceView::Ops);
        assert!(agent.header.title.contains("AGENT"));
        assert!(!agent.sections.is_empty());

        // Audit surface
        let audit = build_audit_surface("claims-001", SurfaceView::Summary);
        assert!(audit.header.title.contains("AUDIT"));

        // Compliance surface
        let compliance = build_compliance_surface("care-agent", "HIPAA", SurfaceView::Ops);
        assert!(compliance.header.title.contains("HIPAA"));

        // Debug surface
        let debug = build_debug_surface("agent-001", SurfaceView::Forensic);
        assert!(debug.header.title.contains("DEBUG"));

        // Books surface
        let books = build_books_surface("operations", SurfaceView::Exec);
        assert!(books.header.title.contains("BOOKS"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 12: Full Workflow - Command to Rendered Output
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_full_workflow() {
        // Simulate: connectorctl debug agent claims-001 --view ops

        // 1. Route command
        let ctx = RoutingContext::resolve("debug", "agent", "claims-001", Some(SurfaceView::Ops));
        assert_eq!(ctx.surface_type, SurfaceType::Debug);

        // 2. Generate surface using domain generator
        let surface = build_debug_surface(&ctx.subject_id, ctx.view);

        // 3. Check role access
        let role = Role::Developer;
        assert!(role.can_access(ctx.view));

        // 4. Render to terminal
        let output = TerminalRenderer::new().render(&surface);
        assert!(output.contains("DEBUG"));
        assert!(output.contains("claims-001"));

        // 5. Export if needed
        let json = Exporter::export(&surface, ExportFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["meta"]["surface_type"], "Debug");
    }
}
