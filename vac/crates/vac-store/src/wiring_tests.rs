//! End-to-end wiring tests: Kernel → Store → Prolly/IndexDB
//!
//! These tests exercise the full pipeline:
//! 1. Create a kernel and a store backend
//! 2. Dispatch kernel syscalls (register, write, session, etc.)
//! 3. Persist kernel state to the store
//! 4. Verify retrieval through the store
//! 5. Verify snapshot/restore roundtrip

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use tokio::runtime::Handle;

    use vac_core::interference::{
        DecisionRecord, EntityState, Intent, Observation, StateVector,
    };
    use vac_core::range_window::BoundaryReason;
    use vac_core::store::{
        build_packet_prolly_key, build_sv_prolly_key, build_window_prolly_key,
        InMemoryKernelStore, KernelSnapshot, KernelStore,
    };
    use vac_core::types::*;

    use crate::indexdb_bridge::{AsyncPersistenceBackend, IndexDbKernelStore, InMemoryPersistenceBackend};
    use crate::prolly_bridge::ProllyKernelStore;

    // =========================================================================
    // Helpers
    // =========================================================================

    fn make_source() -> Source {
        Source {
            kind: SourceKind::Tool,
            principal_id: "did:key:z6MkWiring".to_string(),
        }
    }

    fn make_packet(ptype: PacketType, entities: &[&str], ts: i64, ns: &str) -> MemPacket {
        MemPacket::new(
            ptype,
            serde_json::json!({"wiring_test": true, "ts": ts}),
            cid::Cid::default(),
            "subject:wiring".to_string(),
            "pipeline:e2e".to_string(),
            make_source(),
            ts,
        )
        .with_entities(entities.iter().map(|s| s.to_string()).collect())
        .with_namespace(ns.to_string())
    }

    fn make_window(ns: &str, sn: u64, packets: &[&MemPacket]) -> vac_core::range_window::RangeWindow {
        let ts_start = packets.first().map(|p| p.index.ts).unwrap_or(0);
        let ts_end = packets.last().map(|p| p.index.ts).unwrap_or(0);
        let leaf_cids: Vec<cid::Cid> = packets.iter().map(|p| p.index.packet_cid.clone()).collect();
        let entities: Vec<String> = packets
            .iter()
            .flat_map(|p| p.content.entities.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        vac_core::range_window::RangeWindow {
            sn,
            page_code: format!("{}/{:06}", ns, sn),
            event_time_start: ts_start,
            event_time_end: ts_end,
            ingest_time: ts_end + 1,
            leaf_cids,
            token_count: packets.len() as u64 * 50,
            packet_count: packets.len() as u32,
            rw_root: [0u8; 32],
            prev_rw_root: [0u8; 32],
            tree_size: sn + 1,
            boundary_reason: BoundaryReason::PacketLimit,
            namespace: ns.to_string(),
            agent_pid: "pid:wiring".to_string(),
            session_id: None,
            tier: MemoryTier::Hot,
            scope: MemoryScope::Episodic,
            sealed: true,
            entities,
        }
    }

    fn make_acb(pid: &str, ns: &str) -> AgentControlBlock {
        AgentControlBlock {
            agent_pid: pid.to_string(),
            agent_name: format!("agent-{}", pid),
            agent_role: Some("test".to_string()),
            status: AgentStatus::Running,
            priority: 5,
            namespace: ns.to_string(),
            memory_region: MemoryRegion::new(ns.to_string()),
            active_sessions: Vec::new(),
            total_packets: 0,
            total_tokens_consumed: 0,
            total_cost_usd: 0.0,
            capabilities: Vec::new(),
            readable_namespaces: Vec::new(),
            writable_namespaces: Vec::new(),
            allowed_tools: Vec::new(),
            model: Some("gpt-4".to_string()),
            framework: Some("custom".to_string()),
            parent_pid: None,
            child_pids: Vec::new(),
            registered_at: 1000,
            last_active_at: 1000,
            terminated_at: None,
            termination_reason: None,
            phase: AgentPhase::default(),
            role: AgentRole::default(),
            namespace_mounts: Vec::new(),
            tool_bindings: Vec::new(),
        }
    }

    fn make_session(sid: &str, pid: &str, ns: &str) -> SessionEnvelope {
        SessionEnvelope {
            type_: "session".to_string(),
            version: 1,
            session_id: sid.to_string(),
            agent_id: pid.to_string(),
            namespace: ns.to_string(),
            label: Some(format!("session-{}", sid)),
            started_at: 1000,
            ended_at: None,
            packet_cids: Vec::new(),
            tier: MemoryTier::Hot,
            scope: MemoryScope::Episodic,
            compression: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            summary: None,
            summary_cid: None,
            total_tokens: 0,
            metadata: BTreeMap::new(),
        }
    }

    // =========================================================================
    // Test: Full pipeline with InMemoryKernelStore
    // =========================================================================

    #[test]
    fn test_e2e_inmemory_full_pipeline() {
        let mut store = InMemoryKernelStore::new();
        let ns = "ns:e2e";

        // 1. Store agent
        let acb = make_acb("pid:e2e", ns);
        store.store_agent(&acb).unwrap();

        // 2. Store session
        let session = make_session("sess:e2e", "pid:e2e", ns);
        store.store_session(&session).unwrap();

        // 3. Store packets
        let p1 = make_packet(PacketType::Input, &["alice"], 1000, ns);
        let p2 = make_packet(PacketType::LlmRaw, &["alice"], 2000, ns);
        let p3 = make_packet(PacketType::Extraction, &["alice", "bob"], 3000, ns);
        store.store_packet(&p1).unwrap();
        store.store_packet(&p2).unwrap();
        store.store_packet(&p3).unwrap();

        // 4. Store window
        let window = make_window(ns, 0, &[&p1, &p2, &p3]);
        store.store_window(&window).unwrap();

        // 5. Store state vector
        let sv = StateVector {
            sn: 0,
            agent_pid: "pid:e2e".to_string(),
            namespace: ns.to_string(),
            entities: {
                let mut m = BTreeMap::new();
                m.insert("alice".to_string(), EntityState {
                    entity_id: "alice".to_string(),
                    attributes: BTreeMap::new(),
                    last_seen: 3000,
                    mention_count: 3,
                    source_cids: vec![],
                });
                m.insert("bob".to_string(), EntityState {
                    entity_id: "bob".to_string(),
                    attributes: BTreeMap::new(),
                    last_seen: 3000,
                    mention_count: 1,
                    source_cids: vec![],
                });
                m
            },
            intents: vec![],
            decisions: vec![],
            contradictions: vec![],
            observations: vec![],
            summary: None,
            source_packet_count: 3,
            source_token_count: 150,
            source_rw_root: [0u8; 32],
            sv_cid: None,
            created_at: 3000,
        };
        store.store_state_vector(&sv).unwrap();

        // 6. Store audit entry
        let audit = KernelAuditEntry {
            audit_id: "audit:e2e:001".into(),
            timestamp: 3000,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:e2e".into(),
            target: Some("packet".into()),
            outcome: OpOutcome::Success,
            reason: None,
            error: None,
            duration_us: Some(50),
            vakya_id: None,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
        };
        store.store_audit_entry(&audit).unwrap();

        // === Verify all retrievals ===
        assert!(store.load_agent("pid:e2e").unwrap().is_some());
        assert!(store.load_session("sess:e2e").unwrap().is_some());
        assert_eq!(store.load_packets_by_namespace(ns).unwrap().len(), 3);
        assert!(store.load_window(ns, 0).unwrap().is_some());
        assert_eq!(store.load_windows(ns).unwrap().len(), 1);
        assert!(store.load_state_vector("pid:e2e", 0).unwrap().is_some());
        assert_eq!(store.load_state_vectors("pid:e2e").unwrap().len(), 1);
        assert_eq!(store.load_audit_entries(0, 5000).unwrap().len(), 1);
        assert_eq!(store.load_audit_entries_by_agent("pid:e2e", 10).unwrap().len(), 1);
        assert_eq!(store.load_all_agents().unwrap().len(), 1);

        // 7. Snapshot roundtrip
        let snapshot = KernelSnapshot::from_store(&store);
        assert_eq!(snapshot.agents.len(), 1);
        assert_eq!(snapshot.sessions.len(), 1);
        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.state_vectors.len(), 1);
        // Note: packets share Cid::default() so only 1 unique CID in the store,
        // but namespace index tracks all 3 references
        assert!(snapshot.packet_count >= 1);
        assert_eq!(snapshot.audit_entry_count, 1);

        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: KernelSnapshot = serde_json::from_str(&json).unwrap();
        let restored_store = restored.restore();
        assert!(restored_store.load_agent("pid:e2e").unwrap().is_some());
        assert!(restored_store.load_session("sess:e2e").unwrap().is_some());
        assert!(restored_store.load_window(ns, 0).unwrap().is_some());

        // 8. Total objects (packets collapse by CID, so count is lower than 7)
        assert!(store.total_objects() >= 5);
    }

    // =========================================================================
    // Test: Full pipeline with ProllyKernelStore
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_prolly_full_pipeline() {
        let handle = Handle::current();
        let mut store = ProllyKernelStore::new(handle);
        let ns = "ns:prolly-e2e";

        // Store agent + session
        store.store_agent(&make_acb("pid:prolly", ns)).unwrap();
        store.store_session(&make_session("sess:prolly", "pid:prolly", ns)).unwrap();

        // Store packets
        let p1 = make_packet(PacketType::Input, &["alice"], 1000, ns);
        let p2 = make_packet(PacketType::Decision, &["alice", "bob"], 2000, ns);
        store.store_packet(&p1).unwrap();
        store.store_packet(&p2).unwrap();

        // Store window
        let window = make_window(ns, 0, &[&p1, &p2]);
        store.store_window(&window).unwrap();

        // Store state vector
        let decision = DecisionRecord {
            description: "approve treatment".to_string(),
            reasoning: None,
            confidence: Some(0.9),
            decided_at: 2000,
            source_cid: None,
        };
        let sv = StateVector {
            sn: 0,
            agent_pid: "pid:prolly".to_string(),
            namespace: ns.to_string(),
            entities: BTreeMap::new(),
            intents: vec![],
            decisions: vec![decision.clone()],
            contradictions: vec![],
            observations: vec![],
            summary: None,
            source_packet_count: 2,
            source_token_count: 100,
            source_rw_root: [0u8; 32],
            sv_cid: None,
            created_at: 2000,
        };
        store.store_state_vector(&sv).unwrap();

        // === Verify ===
        assert!(store.load_agent("pid:prolly").unwrap().is_some());
        assert!(store.load_session("sess:prolly").unwrap().is_some());
        assert_eq!(store.load_packets_by_namespace(ns).unwrap().len(), 2);

        // Prolly tree path for window
        let loaded_window = store.load_window(ns, 0).unwrap();
        assert!(loaded_window.is_some());
        assert_eq!(loaded_window.unwrap().packet_count, 2);

        // Prolly tree path for state vector
        let loaded_sv = store.load_state_vector("pid:prolly", 0).unwrap();
        assert!(loaded_sv.is_some());
        assert_eq!(loaded_sv.unwrap().decisions[0].description, "approve treatment");

        // Prolly tree should have a root (content was inserted)
        assert!(store.prolly_root().is_some());

        // CAS should have objects
        assert!(store.cas().len() > 0);
    }

    // =========================================================================
    // Test: Full pipeline with IndexDbKernelStore
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_indexdb_full_pipeline() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend.clone(), handle);
        let ns = "ns:indexdb-e2e";

        // Store agent + session
        store.store_agent(&make_acb("pid:indexdb", ns)).unwrap();
        store.store_session(&make_session("sess:indexdb", "pid:indexdb", ns)).unwrap();

        // Store packets
        let p1 = make_packet(PacketType::ToolCall, &["api:weather"], 1000, ns);
        let p2 = make_packet(PacketType::ToolResult, &["api:weather"], 2000, ns);
        let p3 = make_packet(PacketType::Action, &["user:alice"], 3000, ns);
        store.store_packet(&p1).unwrap();
        store.store_packet(&p2).unwrap();
        store.store_packet(&p3).unwrap();

        // Store window
        let window = make_window(ns, 0, &[&p1, &p2, &p3]);
        store.store_window(&window).unwrap();

        // Store state vector
        let intent = Intent {
            intent_id: "intent:weather".to_string(),
            description: "check weather".to_string(),
            open: true,
            created_at: 1000,
            resolved_at: None,
            evidence_cids: vec![],
        };
        let obs = Observation {
            entity_id: "api:weather".to_string(),
            summary: "sunny in NYC".to_string(),
            updated_at: 2000,
            source_cids: vec![],
        };
        let sv = StateVector {
            sn: 0,
            agent_pid: "pid:indexdb".to_string(),
            namespace: ns.to_string(),
            entities: {
                let mut m = BTreeMap::new();
                m.insert("api:weather".to_string(), EntityState {
                    entity_id: "api:weather".to_string(),
                    attributes: BTreeMap::new(),
                    last_seen: 2000,
                    mention_count: 2,
                    source_cids: vec![],
                });
                m.insert("user:alice".to_string(), EntityState {
                    entity_id: "user:alice".to_string(),
                    attributes: BTreeMap::new(),
                    last_seen: 3000,
                    mention_count: 1,
                    source_cids: vec![],
                });
                m
            },
            intents: vec![intent],
            decisions: vec![],
            contradictions: vec![],
            observations: vec![obs],
            summary: None,
            source_packet_count: 3,
            source_token_count: 150,
            source_rw_root: [0u8; 32],
            sv_cid: None,
            created_at: 3000,
        };
        store.store_state_vector(&sv).unwrap();

        // Store audit
        let audit = KernelAuditEntry {
            audit_id: "audit:idx:001".into(),
            timestamp: 3000,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:indexdb".into(),
            target: None,
            outcome: OpOutcome::Success,
            reason: None,
            error: None,
            duration_us: Some(75),
            vakya_id: None,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
        };
        store.store_audit_entry(&audit).unwrap();

        // === Verify all retrievals ===
        assert!(store.load_agent("pid:indexdb").unwrap().is_some());
        assert!(store.load_session("sess:indexdb").unwrap().is_some());
        assert_eq!(store.load_packets_by_namespace(ns).unwrap().len(), 3);
        assert!(store.load_window(ns, 0).unwrap().is_some());
        assert_eq!(store.load_windows(ns).unwrap().len(), 1);

        let loaded_sv = store.load_state_vector("pid:indexdb", 0).unwrap();
        assert!(loaded_sv.is_some());
        let sv_data = loaded_sv.unwrap();
        assert_eq!(sv_data.intents[0].description, "check weather");
        assert_eq!(sv_data.observations[0].summary, "sunny in NYC");

        assert_eq!(store.load_audit_entries(0, 5000).unwrap().len(), 1);
        assert_eq!(store.load_audit_entries_by_agent("pid:indexdb", 10).unwrap().len(), 1);
        assert_eq!(store.load_all_agents().unwrap().len(), 1);

        // Verify backend has records
        let packet_count = backend.count("kernel_packets").await.unwrap();
        assert!(packet_count > 0);
    }

    // =========================================================================
    // Test: Multi-agent isolation across stores
    // =========================================================================

    #[test]
    fn test_e2e_multi_agent_isolation() {
        let mut store = InMemoryKernelStore::new();

        // Agent A
        store.store_agent(&make_acb("pid:A", "ns:teamA")).unwrap();
        store.store_packet(&make_packet(PacketType::Input, &["alice"], 1000, "ns:teamA")).unwrap();
        store.store_packet(&make_packet(PacketType::LlmRaw, &["alice"], 2000, "ns:teamA")).unwrap();

        // Agent B
        store.store_agent(&make_acb("pid:B", "ns:teamB")).unwrap();
        store.store_packet(&make_packet(PacketType::Input, &["bob"], 1000, "ns:teamB")).unwrap();

        // Verify isolation
        assert_eq!(store.load_packets_by_namespace("ns:teamA").unwrap().len(), 2);
        assert_eq!(store.load_packets_by_namespace("ns:teamB").unwrap().len(), 1);
        assert_eq!(store.load_packets_by_namespace("ns:teamC").unwrap().len(), 0);
        assert_eq!(store.load_all_agents().unwrap().len(), 2);
    }

    // =========================================================================
    // Test: Window chain persistence
    // =========================================================================

    #[test]
    fn test_e2e_window_chain_persistence() {
        let mut store = InMemoryKernelStore::new();
        let ns = "ns:chain";

        // Create 3 windows forming a chain
        for sn in 0..3u64 {
            let p = make_packet(PacketType::Input, &["alice"], 1000 + sn as i64 * 1000, ns);
            let mut window = make_window(ns, sn, &[&p]);
            if sn > 0 {
                window.prev_rw_root = [sn as u8; 32]; // simulate chain linking
            }
            store.store_window(&window).unwrap();
            store.store_packet(&p).unwrap();
        }

        let windows = store.load_windows(ns).unwrap();
        assert_eq!(windows.len(), 3);

        // Verify ordering (BTreeMap ensures sorted by sn)
        assert_eq!(windows[0].sn, 0);
        assert_eq!(windows[1].sn, 1);
        assert_eq!(windows[2].sn, 2);

        // Verify chain linking
        assert_eq!(windows[0].prev_rw_root, [0u8; 32]);
        assert_eq!(windows[1].prev_rw_root, [1u8; 32]);
        assert_eq!(windows[2].prev_rw_root, [2u8; 32]);
    }

    // =========================================================================
    // Test: State vector evolution persistence
    // =========================================================================

    #[test]
    fn test_e2e_state_vector_evolution() {
        let mut store = InMemoryKernelStore::new();

        // SV0: initial state
        let sv0 = StateVector {
            sn: 0,
            agent_pid: "pid:evo".to_string(),
            namespace: "ns:evo".to_string(),
            entities: {
                let mut m = BTreeMap::new();
                m.insert("alice".to_string(), EntityState {
                    entity_id: "alice".to_string(),
                    attributes: BTreeMap::new(),
                    last_seen: 1000,
                    mention_count: 2,
                    source_cids: vec![],
                });
                m
            },
            intents: vec![Intent {
                intent_id: "intent:greet".to_string(),
                description: "greet".to_string(),
                open: true,
                created_at: 1000,
                resolved_at: None,
                evidence_cids: vec![],
            }],
            decisions: vec![],
            contradictions: vec![],
            observations: vec![],
            summary: None,
            source_packet_count: 2,
            source_token_count: 100,
            source_rw_root: [0u8; 32],
            sv_cid: None,
            created_at: 1000,
        };
        store.store_state_vector(&sv0).unwrap();

        // SV1: evolved state
        let sv1 = StateVector {
            sn: 1,
            agent_pid: "pid:evo".to_string(),
            namespace: "ns:evo".to_string(),
            entities: {
                let mut m = BTreeMap::new();
                m.insert("alice".to_string(), EntityState {
                    entity_id: "alice".to_string(),
                    attributes: BTreeMap::new(),
                    last_seen: 3000,
                    mention_count: 3,
                    source_cids: vec![],
                });
                m.insert("bob".to_string(), EntityState {
                    entity_id: "bob".to_string(),
                    attributes: BTreeMap::new(),
                    last_seen: 3000,
                    mention_count: 1,
                    source_cids: vec![],
                });
                m
            },
            intents: vec![
                Intent {
                    intent_id: "intent:greet".to_string(),
                    description: "greet".to_string(),
                    open: true,
                    created_at: 1000,
                    resolved_at: None,
                    evidence_cids: vec![],
                },
                Intent {
                    intent_id: "intent:schedule".to_string(),
                    description: "schedule".to_string(),
                    open: true,
                    created_at: 2000,
                    resolved_at: None,
                    evidence_cids: vec![],
                },
            ],
            decisions: vec![DecisionRecord {
                description: "approved".to_string(),
                reasoning: None,
                confidence: Some(0.95),
                decided_at: 3000,
                source_cid: None,
            }],
            contradictions: vec![],
            observations: vec![Observation {
                entity_id: "alice".to_string(),
                summary: "alice is busy".to_string(),
                updated_at: 3000,
                source_cids: vec![],
            }],
            summary: None,
            source_packet_count: 5,
            source_token_count: 250,
            source_rw_root: [1u8; 32],
            sv_cid: None,
            created_at: 3000,
        };
        store.store_state_vector(&sv1).unwrap();

        // Verify both are retrievable
        let all_svs = store.load_state_vectors("pid:evo").unwrap();
        assert_eq!(all_svs.len(), 2);
        assert_eq!(all_svs[0].sn, 0);
        assert_eq!(all_svs[1].sn, 1);

        // Verify individual lookup
        let loaded_sv0 = store.load_state_vector("pid:evo", 0).unwrap().unwrap();
        assert_eq!(loaded_sv0.entities.len(), 1);

        let loaded_sv1 = store.load_state_vector("pid:evo", 1).unwrap().unwrap();
        assert_eq!(loaded_sv1.entities.len(), 2);
        assert_eq!(loaded_sv1.decisions[0].description, "approved");
    }

    // =========================================================================
    // Test: Prolly key determinism
    // =========================================================================

    #[test]
    fn test_e2e_prolly_key_determinism() {
        let cid = cid::Cid::default();

        // Same inputs → same keys
        let k1 = build_packet_prolly_key("pkt", "ns:det", &PacketType::Input, 1000, &cid);
        let k2 = build_packet_prolly_key("pkt", "ns:det", &PacketType::Input, 1000, &cid);
        assert_eq!(k1, k2);

        // Different type → different key
        let k3 = build_packet_prolly_key("pkt", "ns:det", &PacketType::Decision, 1000, &cid);
        assert_ne!(k1, k3);

        // Different timestamp → different key
        let k4 = build_packet_prolly_key("pkt", "ns:det", &PacketType::Input, 2000, &cid);
        assert_ne!(k1, k4);

        // Window keys
        let wk1 = build_window_prolly_key("rw", "ns:det", 0);
        let wk2 = build_window_prolly_key("rw", "ns:det", 1);
        assert_ne!(wk1, wk2);

        // SV keys
        let sk1 = build_sv_prolly_key("sv", "pid:det", 0);
        let sk2 = build_sv_prolly_key("sv", "pid:det", 1);
        assert_ne!(sk1, sk2);

        // Lexicographic ordering preserved
        let wk0_str = String::from_utf8(build_window_prolly_key("rw", "ns:det", 0)).unwrap();
        let wk9_str = String::from_utf8(build_window_prolly_key("rw", "ns:det", 9)).unwrap();
        let wk99_str = String::from_utf8(build_window_prolly_key("rw", "ns:det", 99)).unwrap();
        assert!(wk0_str < wk9_str);
        assert!(wk9_str < wk99_str);
    }

    // =========================================================================
    // Test: Backend interchangeability (same operations, different backends)
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_backend_interchangeability() {
        let ns = "ns:interchange";
        let acb = make_acb("pid:inter", ns);
        let session = make_session("sess:inter", "pid:inter", ns);
        let p1 = make_packet(PacketType::Input, &["alice"], 1000, ns);
        let p2 = make_packet(PacketType::Extraction, &["bob"], 2000, ns);

        // --- InMemory backend ---
        let mut mem_store = InMemoryKernelStore::new();
        mem_store.store_agent(&acb).unwrap();
        mem_store.store_session(&session).unwrap();
        mem_store.store_packet(&p1).unwrap();
        mem_store.store_packet(&p2).unwrap();

        // --- Prolly backend ---
        let handle = Handle::current();
        let mut prolly_store = ProllyKernelStore::new(handle.clone());
        prolly_store.store_agent(&acb).unwrap();
        prolly_store.store_session(&session).unwrap();
        prolly_store.store_packet(&p1).unwrap();
        prolly_store.store_packet(&p2).unwrap();

        // --- IndexDB backend ---
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let mut idx_store = IndexDbKernelStore::new(backend, handle);
        idx_store.store_agent(&acb).unwrap();
        idx_store.store_session(&session).unwrap();
        idx_store.store_packet(&p1).unwrap();
        idx_store.store_packet(&p2).unwrap();

        // All three should return the same results
        let mem_agent = mem_store.load_agent("pid:inter").unwrap().unwrap();
        let prolly_agent = prolly_store.load_agent("pid:inter").unwrap().unwrap();
        let idx_agent = idx_store.load_agent("pid:inter").unwrap().unwrap();
        assert_eq!(mem_agent.agent_pid, prolly_agent.agent_pid);
        assert_eq!(prolly_agent.agent_pid, idx_agent.agent_pid);

        let mem_ns = mem_store.load_packets_by_namespace(ns).unwrap().len();
        let prolly_ns = prolly_store.load_packets_by_namespace(ns).unwrap().len();
        let idx_ns = idx_store.load_packets_by_namespace(ns).unwrap().len();
        assert_eq!(mem_ns, 2);
        assert_eq!(prolly_ns, 2);
        assert_eq!(idx_ns, 2);

        assert!(mem_store.load_session("sess:inter").unwrap().is_some());
        assert!(prolly_store.load_session("sess:inter").unwrap().is_some());
        assert!(idx_store.load_session("sess:inter").unwrap().is_some());
    }

    // =========================================================================
    // Test: GC (delete) across backends
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_e2e_gc_delete_across_backends() {
        let ns = "ns:gc";
        let p1 = make_packet(PacketType::Input, &["alice"], 1000, ns);
        let cid = p1.index.packet_cid.clone();

        // InMemory
        let mut mem_store = InMemoryKernelStore::new();
        mem_store.store_packet(&p1).unwrap();
        assert!(mem_store.load_packet(&cid).unwrap().is_some());
        mem_store.delete_packet(&cid).unwrap();
        assert!(mem_store.load_packet(&cid).unwrap().is_none());

        // Prolly
        let handle = Handle::current();
        let mut prolly_store = ProllyKernelStore::new(handle.clone());
        prolly_store.store_packet(&p1).unwrap();
        assert!(prolly_store.load_packet(&cid).unwrap().is_some());
        prolly_store.delete_packet(&cid).unwrap();
        assert!(prolly_store.load_packet(&cid).unwrap().is_none());

        // IndexDB
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let mut idx_store = IndexDbKernelStore::new(backend, handle);
        idx_store.store_packet(&p1).unwrap();
        assert!(idx_store.load_packet(&cid).unwrap().is_some());
        idx_store.delete_packet(&cid).unwrap();
        assert!(idx_store.load_packet(&cid).unwrap().is_none());
    }
}
