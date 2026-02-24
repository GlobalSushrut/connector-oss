//! Integration module — wires Kernel + RangeWindow + Interference + Knot + Audit together.
//!
//! Provides `AgentRuntime`, a high-level facade that orchestrates the full pipeline:
//! Register → Ingest → Window → Compact → Query → Audit Export
//!
//! This is the single entry point that downstream consumers (Python SDK, MCP tools,
//! AAPI gateway) will use.

use cid::Cid;

use crate::audit_export::*;
use crate::interference::{StateVector, compact_window};
use crate::interference::InterferenceEdge as IEdge;
use crate::kernel::*;
use crate::knot::*;
use crate::range_window::*;
use crate::types::*;

// =============================================================================
// AgentRuntime — the unified facade
// =============================================================================

/// High-level runtime that orchestrates all modules.
///
/// Usage:
/// ```ignore
/// let mut rt = AgentRuntime::new();
/// let pid = rt.register_agent("bot", "ns:hospital", None, None, None);
/// rt.start_agent(&pid);
/// let sid = rt.create_session(&pid, "sess:001", None);
/// let cid = rt.ingest_packet(&pid, packet);
/// // ... more packets ...
/// let results = rt.query(&pid, &KnotQuery { ... });
/// let report = rt.export_soc2(&pid, 0, i64::MAX);
/// ```
pub struct AgentRuntime {
    /// The memory kernel
    pub kernel: MemoryKernel,
    /// Per-agent RangeWindow managers (agent_pid → manager)
    window_managers: std::collections::HashMap<String, RangeWindowManager>,
    /// Per-agent StateVector chains (agent_pid → Vec<StateVector>)
    state_vectors: std::collections::HashMap<String, Vec<StateVector>>,
    /// Per-agent InterferenceEdge chains (agent_pid → Vec<IEdge>)
    interference_edges: std::collections::HashMap<String, Vec<IEdge>>,
    /// Global knot topology engine (shared across agents)
    pub knot_engine: KnotEngine,
    /// RangeWindow config
    window_config: RangeWindowConfig,
}

impl AgentRuntime {
    /// Create a new runtime with default configuration
    pub fn new() -> Self {
        Self {
            kernel: MemoryKernel::new(),
            window_managers: std::collections::HashMap::new(),
            state_vectors: std::collections::HashMap::new(),
            interference_edges: std::collections::HashMap::new(),
            knot_engine: KnotEngine::new(),
            window_config: RangeWindowConfig::default(),
        }
    }

    /// Create with custom window config
    pub fn with_window_config(config: RangeWindowConfig) -> Self {
        Self {
            window_config: config,
            ..Self::new()
        }
    }

    // =========================================================================
    // Agent lifecycle (delegates to kernel)
    // =========================================================================

    /// Register a new agent. Returns the assigned PID.
    pub fn register_agent(
        &mut self,
        name: &str,
        namespace: &str,
        role: Option<&str>,
        model: Option<&str>,
        framework: Option<&str>,
    ) -> String {
        let result = self.kernel.dispatch(SyscallRequest {
            agent_pid: String::new(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: name.to_string(),
                namespace: namespace.to_string(),
                role: role.map(|s| s.to_string()),
                model: model.map(|s| s.to_string()),
                framework: framework.map(|s| s.to_string()),
            },
            reason: None,
            vakya_id: None,
        });

        let pid = match result.value {
            SyscallValue::AgentPid(pid) => pid,
            _ => panic!("AgentRegister should return AgentPid"),
        };

        // Create per-agent managers
        self.window_managers.insert(
            pid.clone(),
            RangeWindowManager::new(namespace.to_string(), pid.clone(), self.window_config.clone()),
        );
        self.state_vectors.insert(pid.clone(), Vec::new());
        self.interference_edges.insert(pid.clone(), Vec::new());

        pid
    }

    /// Start an agent
    pub fn start_agent(&mut self, pid: &str) -> OpOutcome {
        self.kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None,
        }).outcome
    }

    /// Terminate an agent
    pub fn terminate_agent(&mut self, pid: &str, reason: &str) -> OpOutcome {
        self.kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::AgentTerminate,
            payload: SyscallPayload::AgentTerminate {
                target_pid: None,
                reason: reason.to_string(),
            },
            reason: None,
            vakya_id: None,
        }).outcome
    }

    // =========================================================================
    // Session lifecycle
    // =========================================================================

    /// Create a session. Returns the session ID.
    pub fn create_session(
        &mut self,
        pid: &str,
        session_id: &str,
        label: Option<&str>,
    ) -> String {
        let result = self.kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: session_id.to_string(),
                label: label.map(|s| s.to_string()),
                parent_session_id: None,
            },
            reason: None,
            vakya_id: None,
        });

        // Notify window manager of session boundary
        if let Some(mgr) = self.window_managers.get_mut(pid) {
            if let Some(window) = mgr.notify_session_boundary() {
                self.process_committed_window(pid, &window);
            }
        }

        match result.value {
            SyscallValue::SessionId(sid) => sid,
            _ => session_id.to_string(),
        }
    }

    /// Close a session
    pub fn close_session(&mut self, pid: &str, session_id: &str) -> OpOutcome {
        let outcome = self.kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::SessionClose,
            payload: SyscallPayload::SessionClose {
                session_id: session_id.to_string(),
            },
            reason: None,
            vakya_id: None,
        }).outcome;

        // Notify window manager of session boundary
        if let Some(mgr) = self.window_managers.get_mut(pid) {
            if let Some(window) = mgr.notify_session_boundary() {
                self.process_committed_window(pid, &window);
            }
        }

        outcome
    }

    // =========================================================================
    // Packet ingestion — the core pipeline
    // =========================================================================

    /// Ingest a MemPacket through the full pipeline:
    /// 1. Write to kernel (access control, CID computation, audit)
    /// 2. Feed to RangeWindowManager (boundary detection)
    /// 3. If window committed → extract StateVector + InterferenceEdge
    /// 4. Feed entities to KnotEngine (graph building)
    ///
    /// Returns the packet CID on success, or None on failure.
    pub fn ingest_packet(&mut self, pid: &str, packet: MemPacket) -> Option<Cid> {
        // Extract metadata before kernel takes ownership
        let session_id = packet.session_id.clone();
        let entities = packet.content.entities.clone();
        let token_count = packet.tool_interaction.as_ref()
            .and_then(|ti| ti.token_usage.as_ref())
            .map(|tu| tu.total_tokens)
            .unwrap_or(0);
        let ts = packet.index.ts;

        // 1. Write to kernel
        let result = self.kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: None,
            vakya_id: None,
        });

        let packet_cid = match result.value {
            SyscallValue::Cid(cid) => cid,
            _ => return None,
        };

        // 2. Feed to RangeWindowManager
        if let Some(mgr) = self.window_managers.get_mut(pid) {
            let committed = mgr.ingest(
                packet_cid.clone(),
                ts,
                token_count,
                session_id.as_deref(),
                &entities,
            );

            // 3. If window committed, process it
            if let Some(window) = committed {
                self.process_committed_window(pid, &window);
            }
        }

        // 4. Feed entities to KnotEngine (even before window commit)
        if let Some(mgr) = self.window_managers.get(pid) {
            let sn = if mgr.window_count() > 0 {
                mgr.latest_window().map(|w| w.sn).unwrap_or(0)
            } else {
                0
            };

            for entity in &entities {
                self.knot_engine.upsert_node(
                    entity,
                    None,
                    std::collections::BTreeMap::new(),
                    &[],
                    ts,
                    sn,
                    Some(packet_cid.clone()),
                );
            }

            // Co-occurrence edges
            for i in 0..entities.len() {
                for j in (i + 1)..entities.len() {
                    self.knot_engine.upsert_edge(
                        &entities[i],
                        &entities[j],
                        "co_occurs",
                        1.0,
                        ts,
                        sn,
                        Some(packet_cid.clone()),
                    );
                }
            }
        }

        Some(packet_cid)
    }

    /// Process a committed RangeWindow: extract SV, compute IE, update knot
    fn process_committed_window(&mut self, pid: &str, window: &RangeWindow) {
        // Collect packets for this window from the kernel
        let packets: Vec<MemPacket> = window.leaf_cids.iter()
            .filter_map(|cid| self.kernel.get_packet(cid).cloned())
            .collect();

        if packets.is_empty() {
            return;
        }

        // Get previous SV for IE computation
        let prev_sv = self.state_vectors.get(pid)
            .and_then(|svs| svs.last());

        // Compact: extract SV + IE
        let result = compact_window(
            window.sn,
            pid,
            &window.namespace,
            &packets,
            window.rw_root,
            prev_sv,
        );

        // Store SV
        if let Some(svs) = self.state_vectors.get_mut(pid) {
            svs.push(result.state_vector);
        }

        // Store IE
        if let Some(ie) = result.interference_edge {
            if let Some(ies) = self.interference_edges.get_mut(pid) {
                ies.push(ie);
            }
        }

        // Feed window entities to knot engine
        self.knot_engine.ingest_packets(&packets, window.sn);
    }

    // =========================================================================
    // Flush — force-commit any pending packets
    // =========================================================================

    /// Force-commit any pending packets in the window accumulator
    pub fn flush(&mut self, pid: &str) {
        if let Some(mgr) = self.window_managers.get_mut(pid) {
            if let Some(window) = mgr.force_commit(BoundaryReason::Manual) {
                self.process_committed_window(pid, &window);
            }
        }
    }

    // =========================================================================
    // Query
    // =========================================================================

    /// Query the knot topology engine with RRF fusion
    pub fn query(&self, q: &KnotQuery) -> Vec<FusedResult> {
        self.knot_engine.query(q)
    }

    /// Get the latest StateVector for an agent
    pub fn latest_state_vector(&self, pid: &str) -> Option<&StateVector> {
        self.state_vectors.get(pid)?.last()
    }

    /// Get all StateVectors for an agent
    pub fn state_vectors(&self, pid: &str) -> &[StateVector] {
        self.state_vectors.get(pid).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get all InterferenceEdges for an agent
    pub fn interference_edges(&self, pid: &str) -> &[IEdge] {
        self.interference_edges.get(pid).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get the RangeWindowManager for an agent
    pub fn window_manager(&self, pid: &str) -> Option<&RangeWindowManager> {
        self.window_managers.get(pid)
    }

    // =========================================================================
    // Seal + SCITT receipts
    // =========================================================================

    /// Seal specific packet CIDs (makes them immutable)
    pub fn seal_packets(&mut self, pid: &str, cids: Vec<Cid>) -> OpOutcome {
        // Force-commit pending window first
        self.flush(pid);

        self.kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::MemSeal,
            payload: SyscallPayload::MemSeal { cids },
            reason: Some("evidence preservation".to_string()),
            vakya_id: None,
        }).outcome
    }

    /// Generate a SCITT receipt for a packet
    pub fn scitt_receipt(&self, pid: &str, packet_cid: &Cid) -> Option<ScittReceipt> {
        let mgr = self.window_managers.get(pid)?;

        // Find which window contains this CID
        for window in mgr.all_windows() {
            if window.leaf_cids.contains(packet_cid) {
                return generate_scitt_receipt(
                    &format!("stmt:{}", packet_cid),
                    packet_cid,
                    window.sn,
                    &window.leaf_cids,
                    window.rw_root,
                    window.tree_size,
                );
            }
        }

        None
    }

    // =========================================================================
    // Audit exports
    // =========================================================================

    /// Export SOC2 compliance report
    pub fn export_soc2(&self, from_ms: i64, to_ms: i64) -> Soc2Report {
        export_soc2(self.kernel.audit_log(), &AuditTimeRange { from_ms, to_ms })
    }

    /// Export HIPAA compliance report
    pub fn export_hipaa(&self, from_ms: i64, to_ms: i64) -> HipaaReport {
        export_hipaa(self.kernel.audit_log(), &AuditTimeRange { from_ms, to_ms })
    }

    /// Export GDPR compliance report
    pub fn export_gdpr(&self, from_ms: i64, to_ms: i64) -> GdprReport {
        export_gdpr(self.kernel.audit_log(), &AuditTimeRange { from_ms, to_ms })
    }

    /// Export all compliance frameworks
    pub fn export_all(&self, from_ms: i64, to_ms: i64) -> MultiFrameworkReport {
        export_multi(
            self.kernel.audit_log(),
            &AuditTimeRange { from_ms, to_ms },
            &[ComplianceFramework::Soc2, ComplianceFramework::Hipaa, ComplianceFramework::Gdpr],
        )
    }

    // =========================================================================
    // Verification
    // =========================================================================

    /// Verify the RangeWindow chain integrity for an agent
    pub fn verify_chain(&self, pid: &str) -> Result<bool, String> {
        self.window_managers.get(pid)
            .ok_or_else(|| format!("Agent {} not found", pid))?
            .verify_chain()
    }

    /// Run kernel integrity check
    pub fn integrity_check(&mut self, pid: &str) -> OpOutcome {
        self.kernel.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::IntegrityCheck,
            payload: SyscallPayload::IntegrityCheck,
            reason: None,
            vakya_id: None,
        }).outcome
    }
}

impl Default for AgentRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests — Full end-to-end integration
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source() -> Source {
        Source {
            kind: SourceKind::Tool,
            principal_id: "did:key:z6MkTest".to_string(),
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn make_extraction(subject: &str, entities: &[&str], payload: serde_json::Value) -> MemPacket {
        MemPacket::new(
            PacketType::Extraction,
            payload,
            Cid::default(),
            subject.to_string(),
            "pipeline:test".to_string(),
            make_source(),
            now_ms(),
        )
        .with_entities(entities.iter().map(|s| s.to_string()).collect())
    }

    fn make_decision(desc: &str) -> MemPacket {
        MemPacket::new(
            PacketType::Decision,
            serde_json::json!({"action": desc}),
            Cid::default(),
            "subject:test".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            now_ms(),
        )
        .with_reasoning("automated".to_string())
        .with_confidence(0.95)
    }

    #[test]
    fn test_full_pipeline_register_to_audit() {
        // Small windows for testing (3 packets per window)
        let mut rt = AgentRuntime::with_window_config(RangeWindowConfig {
            max_tokens: 100000,
            max_packets: 3,
            commit_on_session_boundary: true,
        });

        // 1. Register + start agent
        let pid = rt.register_agent("healthcare-bot", "ns:hospital", Some("triage"), Some("gpt-4o"), None);
        assert_eq!(rt.start_agent(&pid), OpOutcome::Success);

        // 2. Create session
        let sid = rt.create_session(&pid, "sess:intake", Some("Patient intake"));
        assert_eq!(sid, "sess:intake");

        // 3. Ingest packets (3 extractions → triggers window commit)
        let cid1 = rt.ingest_packet(&pid, make_extraction(
            "patient:P-001",
            &["patient:P-001", "penicillin"],
            serde_json::json!({"allergy": "penicillin", "severity": "severe"}),
        ).with_session("sess:intake".to_string())).unwrap();

        let _cid2 = rt.ingest_packet(&pid, make_extraction(
            "patient:P-001",
            &["patient:P-001"],
            serde_json::json!({"blood_type": "O+", "weight_kg": 72}),
        ).with_session("sess:intake".to_string())).unwrap();

        // 3rd packet triggers window commit (max_packets=3)
        let _cid3 = rt.ingest_packet(&pid, make_decision("update_allergy_record")
            .with_session("sess:intake".to_string())
        ).unwrap();

        // 4. Verify window was committed
        let mgr = rt.window_manager(&pid).unwrap();
        assert_eq!(mgr.window_count(), 1);
        let window = mgr.load_page(0).unwrap();
        assert_eq!(window.packet_count, 3);
        assert!(window.sealed);

        // 5. Verify StateVector was extracted
        let sv = rt.latest_state_vector(&pid).unwrap();
        assert_eq!(sv.sn, 0);
        assert!(sv.entities.contains_key("patient:P-001"));
        assert!(sv.entities.contains_key("penicillin"));
        assert_eq!(sv.decisions.len(), 1);
        assert_eq!(sv.source_packet_count, 3);

        // 6. Verify KnotEngine has entities
        assert!(rt.knot_engine.get_node("patient:P-001").is_some());
        assert!(rt.knot_engine.get_node("penicillin").is_some());
        assert!(rt.knot_engine.edge_count() >= 1); // co-occurrence edge

        // 7. Query the knot engine
        let results = rt.query(&KnotQuery {
            entities: vec!["patient:P-001".to_string()],
            keywords: vec!["penicillin".to_string()],
            limit: 10,
            ..Default::default()
        });
        assert!(!results.is_empty());

        // 8. Verify chain integrity
        assert!(rt.verify_chain(&pid).is_ok());

        // 9. Integrity check
        assert_eq!(rt.integrity_check(&pid), OpOutcome::Success);

        // 10. Seal evidence
        assert_eq!(rt.seal_packets(&pid, vec![cid1.clone()]), OpOutcome::Success);
        assert!(rt.kernel.is_sealed(&cid1));

        // 11. Generate SCITT receipt
        let receipt = rt.scitt_receipt(&pid, &cid1);
        assert!(receipt.is_some());
        let receipt = receipt.unwrap();
        assert_eq!(receipt.log_entry, 0);
        assert!(!receipt.inclusion_proof.is_empty());

        // 12. Export compliance reports
        let soc2 = rt.export_soc2(0, i64::MAX);
        assert!(soc2.total_operations > 0);
        assert!(soc2.report_hash.is_some());

        let hipaa = rt.export_hipaa(0, i64::MAX);
        assert!(hipaa.total_phi_accesses > 0);
        assert!(hipaa.integrity_verified);

        let gdpr = rt.export_gdpr(0, i64::MAX);
        assert!(!gdpr.processing_records.is_empty());

        // 13. Close session + terminate
        rt.close_session(&pid, "sess:intake");
        assert_eq!(rt.terminate_agent(&pid, "workflow complete"), OpOutcome::Success);

        // 14. Final audit count
        assert!(rt.kernel.audit_count() >= 10);
    }

    #[test]
    fn test_multi_agent_isolation() {
        let mut rt = AgentRuntime::with_window_config(RangeWindowConfig {
            max_tokens: 100000,
            max_packets: 2,
            commit_on_session_boundary: false,
        });

        // Register two agents in different namespaces
        let pid_a = rt.register_agent("agent-a", "ns:alpha", None, None, None);
        let pid_b = rt.register_agent("agent-b", "ns:beta", None, None, None);
        rt.start_agent(&pid_a);
        rt.start_agent(&pid_b);

        // Agent A writes packets
        let cid_a = rt.ingest_packet(&pid_a, make_extraction(
            "data:secret", &["alice"], serde_json::json!({"secret": true}),
        )).unwrap();

        // Agent B tries to read Agent A's packet — should be denied
        let result = rt.kernel.dispatch(SyscallRequest {
            agent_pid: pid_b.clone(),
            operation: MemoryKernelOp::MemRead,
            payload: SyscallPayload::MemRead { packet_cid: cid_a.clone() },
            reason: None,
            vakya_id: None,
        });
        assert_eq!(result.outcome, OpOutcome::Denied);

        // Both agents have separate window managers
        assert!(rt.window_manager(&pid_a).is_some());
        assert!(rt.window_manager(&pid_b).is_some());
    }

    #[test]
    fn test_multi_window_interference_chain() {
        let mut rt = AgentRuntime::with_window_config(RangeWindowConfig {
            max_tokens: 100000,
            max_packets: 2,
            commit_on_session_boundary: false,
        });

        let pid = rt.register_agent("bot", "ns:test", None, None, None);
        rt.start_agent(&pid);

        // Window 0: alice appears
        rt.ingest_packet(&pid, make_extraction("s", &["alice"], serde_json::json!({"role": "user"})));
        rt.ingest_packet(&pid, make_extraction("s", &["alice"], serde_json::json!({"email": "a@b.com"})));
        // Window 0 committed (2 packets)

        // Window 1: bob appears, alice changes
        rt.ingest_packet(&pid, make_extraction("s", &["alice", "bob"], serde_json::json!({"role": "admin"})));
        rt.ingest_packet(&pid, make_extraction("s", &["bob"], serde_json::json!({"dept": "eng"})));
        // Window 1 committed

        // Should have 2 StateVectors
        let svs = rt.state_vectors(&pid);
        assert_eq!(svs.len(), 2);

        // SV0: alice only
        assert!(svs[0].entities.contains_key("alice"));

        // SV1: alice + bob
        assert!(svs[1].entities.contains_key("alice"));
        assert!(svs[1].entities.contains_key("bob"));

        // Should have 1 InterferenceEdge (SV0 → SV1)
        let ies = rt.interference_edges(&pid);
        assert_eq!(ies.len(), 1);
        assert_eq!(ies[0].from_sn, 0);
        assert_eq!(ies[0].to_sn, 1);

        // bob was added in the delta
        assert!(ies[0].delta.entities_added.iter().any(|e| e.entity_id == "bob"));

        // Chain verification
        assert!(rt.verify_chain(&pid).is_ok());
    }

    #[test]
    fn test_flush_pending_packets() {
        let mut rt = AgentRuntime::with_window_config(RangeWindowConfig {
            max_tokens: 100000,
            max_packets: 100, // High limit so auto-commit doesn't trigger
            commit_on_session_boundary: false,
        });

        let pid = rt.register_agent("bot", "ns:test", None, None, None);
        rt.start_agent(&pid);

        // Ingest 3 packets (won't auto-commit because max_packets=100)
        for i in 0..3 {
            rt.ingest_packet(&pid, make_extraction(
                "s", &[&format!("entity:{}", i)], serde_json::json!({"i": i}),
            ));
        }

        // No windows committed yet
        assert_eq!(rt.window_manager(&pid).unwrap().window_count(), 0);
        assert_eq!(rt.window_manager(&pid).unwrap().pending_packet_count(), 3);

        // Flush
        rt.flush(&pid);

        // Now window is committed
        assert_eq!(rt.window_manager(&pid).unwrap().window_count(), 1);
        assert_eq!(rt.window_manager(&pid).unwrap().pending_packet_count(), 0);

        // SV was extracted
        assert_eq!(rt.state_vectors(&pid).len(), 1);
    }

    #[test]
    fn test_session_boundary_triggers_window() {
        let mut rt = AgentRuntime::with_window_config(RangeWindowConfig {
            max_tokens: 100000,
            max_packets: 100,
            commit_on_session_boundary: true,
        });

        let pid = rt.register_agent("bot", "ns:test", None, None, None);
        rt.start_agent(&pid);
        rt.create_session(&pid, "sess:1", None);

        // Ingest packets
        rt.ingest_packet(&pid, make_extraction("s", &["alice"], serde_json::json!({"x": 1}))
            .with_session("sess:1".to_string()));
        rt.ingest_packet(&pid, make_extraction("s", &["bob"], serde_json::json!({"x": 2}))
            .with_session("sess:1".to_string()));

        // Close session → triggers window commit
        rt.close_session(&pid, "sess:1");

        // Window committed
        assert_eq!(rt.window_manager(&pid).unwrap().window_count(), 1);
        assert_eq!(rt.state_vectors(&pid).len(), 1);
    }

    #[test]
    fn test_compliance_reports_from_runtime() {
        let mut rt = AgentRuntime::with_window_config(RangeWindowConfig {
            max_tokens: 100000,
            max_packets: 5,
            commit_on_session_boundary: false,
        });

        let pid = rt.register_agent("bot", "ns:hospital", Some("triage"), None, None);
        rt.start_agent(&pid);

        // Ingest some packets
        for i in 0..5 {
            rt.ingest_packet(&pid, make_extraction(
                &format!("patient:P-{:03}", i),
                &[&format!("patient:P-{:03}", i)],
                serde_json::json!({"visit": i}),
            ));
        }

        // Export all frameworks
        let report = rt.export_all(0, i64::MAX);
        assert!(report.soc2.is_some());
        assert!(report.hipaa.is_some());
        assert!(report.gdpr.is_some());

        let soc2 = report.soc2.unwrap();
        assert!(soc2.total_operations > 0);

        let hipaa = report.hipaa.unwrap();
        assert!(hipaa.total_phi_accesses > 0);
    }

    #[test]
    fn test_knot_query_after_ingestion() {
        let mut rt = AgentRuntime::with_window_config(RangeWindowConfig {
            max_tokens: 100000,
            max_packets: 2,
            commit_on_session_boundary: false,
        });

        let pid = rt.register_agent("bot", "ns:test", None, None, None);
        rt.start_agent(&pid);

        // Ingest packets with entities
        rt.ingest_packet(&pid, make_extraction("s", &["alice", "project:x"], serde_json::json!({"role": "lead"})));
        rt.ingest_packet(&pid, make_extraction("s", &["bob", "project:x"], serde_json::json!({"role": "dev"})));
        // Window committed

        rt.ingest_packet(&pid, make_extraction("s", &["alice", "project:y"], serde_json::json!({"role": "advisor"})));
        rt.ingest_packet(&pid, make_extraction("s", &["charlie"], serde_json::json!({"role": "intern"})));
        // Window committed

        // Query for alice — should find alice + connected entities
        let results = rt.query(&KnotQuery {
            entities: vec!["alice".to_string()],
            keywords: vec!["project".to_string()],
            limit: 10,
            ..Default::default()
        });

        assert!(!results.is_empty());
        // alice should be top result (appears in both graph and keyword channels)
        assert!(results.iter().any(|r| r.id == "alice"));
    }
}
