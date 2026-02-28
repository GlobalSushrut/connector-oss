//! Display — multi-audience rendering of Trace output.
//!
//! Provides four views of the same trace data:
//! - **Human**: Box-drawing timeline with emoji, narrative labels
//! - **LLM**: Structured natural language JSON
//! - **Tool**: OTel GenAI-compatible span array
//! - **Raw**: Full PipelineOutput (unchanged kernel data)
//!
//! ```rust,no_run
//! use connector_api::{Connector, PipelineOutputExt, TraceExt};
//!
//! let c = Connector::new().llm("openai", "gpt-4o", "sk-...").build();
//! let output = c.agent("bot").instructions("Help").run("Hi", "user:alice").unwrap();
//!
//! // Human-readable display
//! let trace = output.trace();
//! println!("{}", trace);
//!
//! // LLM-friendly JSON
//! let llm_view = trace.to_llm();
//!
//! // OTel-compatible spans
//! let otel_spans = trace.to_otel_spans();
//! ```

use connector_engine::output::PipelineOutput;
use connector_engine::trace::Trace;

// ─── TraceExt — extension trait for PipelineOutput ───────────────

/// Extension trait that adds `.get_trace()` to PipelineOutput.
///
/// Now that PipelineOutput embeds a Trace directly (auto-built from kernel),
/// this trait provides backward-compatible access plus convenience methods.
pub trait TraceExt {
    /// Get the embedded structured Trace.
    fn trace(&self) -> &Trace;
}

impl TraceExt for PipelineOutput {
    fn trace(&self) -> &Trace {
        &self.trace
    }
}

// Display impls for Trace, Span, TraceSummary are in connector-engine/src/trace.rs
// (Rust orphan rule requires Display to be in the same crate as the type)

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::output::*;
    use connector_engine::trust::{TrustScore, TrustDimensions};
    use connector_engine::trace::{Trace, TraceSummary, SpanStatus as TraceSpanStatus};
    use connector_engine::ConnectorMemory;

    fn make_test_output() -> PipelineOutput {
        let now = chrono::Utc::now().to_rfc3339();
        PipelineOutput {
            text: "Patient classified as ESI-2".to_string(),
            status: PipelineStatus {
                ok: true,
                trust: 91,
                trust_grade: "A".to_string(),
                actors: 2,
                steps: 5,
                duration_ms: 245,
                total_tokens: 1500,
                total_cost_usd: 0.003,
                summary: "2 actors, 5 steps, trust 91/100".to_string(),
            },
            aapi: AapiSummary {
                authorized: 4,
                denied: 0,
                pending_approval: 1,
                vakya_count: 5,
                compliance: vec!["hipaa".to_string(), "soc2".to_string()],
                action_records: 3,
                interaction_count: 1,
                policy_count: 1,
                capability_count: 0,
                budget_count: 0,
            },
            memory: MemorySummary {
                created: 2,
                recalled: 1,
                shared: 1,
                total_packets: 3,
                memories: vec![
                    ConnectorMemory {
                        id: "bafy2bzaceabcdef1234567890".to_string(),
                        content: "Patient has chest pain".to_string(),
                        user: "patient:P-123".to_string(),
                        kind: "input".to_string(),
                        tags: vec!["clinical".to_string()],
                        score: 0.9,
                        created: "2025-02-22T10:30:00Z".to_string(),
                        source: "user".to_string(),
                        verified: true,
                        session: "sess:001".to_string(),
                    },
                    ConnectorMemory {
                        id: "bafy2bzacexyz9876543210abc".to_string(),
                        content: "ESI-2 classification".to_string(),
                        user: "patient:P-123".to_string(),
                        kind: "decision".to_string(),
                        tags: vec!["triage".to_string()],
                        score: 0.95,
                        created: "2025-02-22T10:30:01Z".to_string(),
                        source: "llm".to_string(),
                        verified: true,
                        session: "sess:001".to_string(),
                    },
                ],
            },
            connector: ConnectorSummary {
                control_plane: "active".to_string(),
                pipeline_id: "pipe:hospital-er".to_string(),
                audit_entries: 5,
                trust_details: TrustScore {
                    score: 91,
                    grade: "A".to_string(),
                    dimensions: TrustDimensions {
                        memory_integrity: 19,
                        audit_completeness: 20,
                        authorization_coverage: 18,
                        decision_provenance: 18,
                        operational_health: 16,
                        claim_validity: None,
                    },
                    operations_analyzed: 5,
                    verifiable: true,
                },
            },
            trace: Trace {
                trace_id: "trace_hospital-er".to_string(),
                session_id: None,
                pipeline_name: "hospital-er".to_string(),
                started_at: now.clone(),
                ended_at: now,
                duration_ms: 245,
                status: TraceSpanStatus::Ok,
                summary: TraceSummary {
                    narrative: "triage → doctor ran in 245ms. Trust: 91/100 (A). 4 authorized, 0 denied, 1 pending".to_string(),
                    steps: vec![
                        connector_engine::trace::StepSummary { step: 1, agent: "triage".into(), action: "Classified patient".into(), tools_used: vec![], authorization: "all allowed".into(), memories_used: 0, duration_ms: 122 },
                        connector_engine::trace::StepSummary { step: 2, agent: "doctor".into(), action: "Diagnosed patient".into(), tools_used: vec![], authorization: "all allowed".into(), memories_used: 1, duration_ms: 123 },
                    ],
                    actors: 2,
                    total_spans: 3,
                    llm_calls: 0,
                    tool_calls: 0,
                    memory_ops: 3,
                    total_tokens: 1500,
                    total_cost_usd: 0.003,
                    trust_score: 91,
                    trust_grade: "A".to_string(),
                    trust_explanation: "19/20 memory integrity, 20/20 audit completeness, 18/20 authorization coverage, 18/20 decision provenance, 16/20 operational health".to_string(),
                    authorization_summary: "4 authorized, 0 denied, 1 pending".to_string(),
                    compliance: vec!["hipaa".to_string(), "soc2".to_string()],
                },
                spans: vec![],
            },
            events: vec![
                ObservationEvent { event_type: "memory_stored".into(), severity: EventSeverity::Info, message: "Stored memory by triage".into(), agent: Some("triage".into()), cid: Some("bafy2bzaceabcdef1234567890".into()), source: Provenance::Kernel, timestamp_ms: 0 },
                ObservationEvent { event_type: "memory_stored".into(), severity: EventSeverity::Info, message: "Stored memory by doctor".into(), agent: Some("doctor".into()), cid: Some("bafy2bzacexyz9876543210abc".into()), source: Provenance::Kernel, timestamp_ms: 0 },
            ],
            warnings: vec![],
            errors: vec![],
            run_trace: None,
        }
    }

    #[test]
    fn test_trace_from_output() {
        let output = make_test_output();
        let trace = output.trace();

        assert!(trace.trace_id.starts_with("trace_"));
        assert_eq!(trace.pipeline_name, "hospital-er");
        assert_eq!(trace.duration_ms, 245);
        assert_eq!(trace.status, TraceSpanStatus::Ok);
        assert_eq!(trace.summary.actors, 2);
        assert_eq!(trace.summary.trust_score, 91);
        assert_eq!(trace.summary.trust_grade, "A");
        assert!(trace.summary.trust_explanation.contains("19/20 memory integrity"));
        assert!(trace.summary.narrative.contains("triage"));
        assert!(trace.summary.compliance.contains(&"hipaa".to_string()));
    }

    #[test]
    fn test_trace_display_human() {
        let output = make_test_output();
        let trace = output.trace();
        let display = format!("{}", trace);

        // Should contain box-drawing characters
        assert!(display.contains("╔"));
        assert!(display.contains("╚"));
        // Should contain pipeline name
        assert!(display.contains("hospital-er"));
        // Should contain trust score
        assert!(display.contains("91/100"));
        assert!(display.contains("(A)"));
        // Should contain actor steps
        assert!(display.contains("Agent") || display.contains("triage"));
        // Should contain compliance
        assert!(display.contains("hipaa"));
        assert!(display.contains("soc2"));
        // Should contain authorization summary
        assert!(display.contains("authorized"));
    }

    #[test]
    fn test_trace_llm_view() {
        let output = make_test_output();
        let trace = output.trace();
        let llm = trace.to_llm();

        assert!(llm["summary"].as_str().unwrap().contains("triage"));
        assert_eq!(llm["trust"]["score"], 91);
        assert_eq!(llm["trust"]["grade"], "A");
        assert!(llm["trust"]["explanation"].as_str().unwrap().contains("19/20"));
        assert_eq!(llm["counts"]["actors"], 2);
        assert!(llm["compliance"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn test_trace_otel_spans() {
        let output = make_test_output();
        let trace = output.trace();
        let otel = trace.to_otel_spans();

        // Trace spans may be empty in test fixture (no real kernel)
        // but the method should work without panic
        for span in &otel {
            assert!(span["trace_id"].as_str().unwrap().starts_with("trace_"));
            assert!(span["attributes"]["gen_ai.operation.name"].is_string());
            assert_eq!(span["kind"], "INTERNAL");
        }
    }

    #[test]
    fn test_trace_summary_display() {
        let output = make_test_output();
        let trace = output.trace();
        let display = format!("{}", trace.summary);

        assert!(display.contains("triage"));
        assert!(display.contains("91/100"));
        assert!(display.contains("hipaa"));
    }

    // ── New observability tests ──────────────────────────────────

    #[test]
    fn test_pipeline_output_display() {
        let output = make_test_output();
        let display = format!("{}", output);

        // Should show clean status badge
        assert!(display.contains("✅"), "missing status icon: {}", display);
        assert!(display.contains("Agent complete"), "missing status: {}", display);
        // Should show trust
        assert!(display.contains("91/100"), "missing trust: {}", display);
        // Should show response
        assert!(display.contains("Patient classified"), "missing response: {}", display);
        // Should show stats
        assert!(display.contains("agent"), "missing agent count: {}", display);
        assert!(display.contains("245ms"), "missing duration: {}", display);
        // Should show compliance
        assert!(display.contains("HIPAA ✓"), "missing hipaa: {}", display);
        // Should show provenance
        assert!(display.contains("zero-fake"), "missing provenance: {}", display);
        assert!(display.contains("verified"), "missing verified: {}", display);
        // Should show progressive disclosure hint
        assert!(display.contains(".dashboard()"), "missing hint: {}", display);
    }

    #[test]
    fn test_pipeline_output_to_json() {
        let output = make_test_output();
        let json = output.to_json();

        // Every field should have provenance source
        assert_eq!(json["text"]["source"], "llm");
        assert_eq!(json["status"]["trust"]["source"], "kernel");
        assert_eq!(json["status"]["trust_grade"]["source"], "derived");
        assert_eq!(json["aapi"]["compliance"]["source"], "user");
        assert_eq!(json["memory"]["created"]["source"], "kernel");
        // Values should be correct
        assert_eq!(json["status"]["trust"]["value"], 91);
        assert_eq!(json["status"]["actors"]["value"], 2);
        assert_eq!(json["memory"]["created"]["value"], 2);
    }

    #[test]
    fn test_pipeline_output_to_otel() {
        let output = make_test_output();
        let otel = output.to_otel();

        assert!(otel["resource_spans"].is_array());
        let resource = &otel["resource_spans"][0];
        assert!(resource["resource"]["attributes"].is_array());
        assert!(resource["scope_spans"].is_array());
    }

    #[test]
    fn test_observation_events() {
        let output = make_test_output();

        assert_eq!(output.events.len(), 2);
        assert_eq!(output.events[0].event_type, "memory_stored");
        assert_eq!(output.events[0].source, Provenance::Kernel);
        assert!(output.all_observations_verified());

        let info_events = output.events_by_severity(EventSeverity::Info);
        assert_eq!(info_events.len(), 2);
    }

    #[test]
    fn test_provenance_summary() {
        let output = make_test_output();
        let prov = output.provenance_summary();

        assert_eq!(prov["kernel_verified"], 2);
        assert_eq!(prov["llm_unverified"], 0);
        assert_eq!(prov["total"], 2);
        assert_eq!(prov["trust_percentage"], 100.0);
    }

    #[test]
    fn test_warnings_and_errors() {
        let mut output = make_test_output();
        output.warnings = vec!["Tool requires approval".to_string()];
        output.errors = vec!["Access denied".to_string()];

        let display = format!("{}", output);
        assert!(display.contains("⚠ Tool requires approval"), "missing warning: {}", display);
        assert!(display.contains("✗ Access denied"), "missing error: {}", display);
    }

    #[test]
    fn test_verified_type() {
        let v = Verified::kernel(42u32);
        assert!(v.is_trusted());
        assert_eq!(v.value, 42);
        assert_eq!(v.source, Provenance::Kernel);

        let v2 = Verified::llm("hello".to_string());
        assert!(!v2.is_trusted());
        assert_eq!(v2.source, Provenance::Llm);

        let v3 = Verified::kernel_with_cid(true, "bafy2bzace...");
        assert!(v3.is_trusted());
        assert_eq!(v3.evidence_cid.as_deref(), Some("bafy2bzace..."));
    }
}
