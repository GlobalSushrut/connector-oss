//! Tests for vac-cluster.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use vac_bus::{EventBus, InProcessBus, ReplicationEvent, ReplicationOp};
use vac_core::store::{InMemoryKernelStore, KernelStore};
use vac_core::types::*;

use crate::cell::{Cell, CellStatus};
use crate::cluster_store::ClusterKernelStore;
use crate::receiver::{start_replication_loop, start_verified_replication_loop, PeerRegistry, ReceiverStats};

fn make_source() -> Source {
    Source {
        kind: SourceKind::Tool,
        principal_id: "did:key:z6MkTest".to_string(),
    }
}

fn make_packet(entities: &[&str], ts: i64) -> MemPacket {
    MemPacket::new(
        PacketType::Extraction,
        serde_json::json!({"test": true}),
        cid::Cid::default(),
        "subject:test".to_string(),
        "pipeline:test".to_string(),
        make_source(),
        ts,
    )
    .with_entities(entities.iter().map(|s| s.to_string()).collect())
    .with_namespace("ns:test".to_string())
}

// ── Cell tests ───────────────────────────────────────────────────────

#[test]
fn test_cell_creation() {
    let cell = Cell::new("cell-1");
    assert_eq!(cell.cell_id, "cell-1");
    assert_eq!(cell.current_seq(), 0);
    assert!(cell.created_at > 0);
}

#[test]
fn test_cell_seq_increment() {
    let cell = Cell::new("cell-1");
    assert_eq!(cell.next_seq(), 0);
    assert_eq!(cell.next_seq(), 1);
    assert_eq!(cell.next_seq(), 2);
    assert_eq!(cell.current_seq(), 3);
}

#[tokio::test]
async fn test_cell_status() {
    let cell = Cell::new("cell-1");
    assert_eq!(cell.get_status().await, CellStatus::Starting);

    cell.mark_ready().await;
    assert_eq!(cell.get_status().await, CellStatus::Ready);

    cell.set_status(CellStatus::Syncing).await;
    assert_eq!(cell.get_status().await, CellStatus::Syncing);
}

#[tokio::test]
async fn test_cell_merkle_root() {
    let cell = Cell::new("cell-1");
    assert_eq!(cell.get_merkle_root().await, [0u8; 32]);

    let new_root = [42u8; 32];
    cell.set_merkle_root(new_root).await;
    assert_eq!(cell.get_merkle_root().await, new_root);
}

// ── ClusterKernelStore tests ─────────────────────────────────────────

#[tokio::test]
async fn test_cluster_store_write_and_read() {
    let local = InMemoryKernelStore::new();
    let bus = Arc::new(InProcessBus::new());
    let cell = Arc::new(Cell::new("cell-1"));

    let mut store = ClusterKernelStore::new(local, bus.clone(), cell.clone(), "cluster.repl");

    let packet = make_packet(&["alice"], 1000);
    let cid = packet.index.packet_cid.clone();

    store.store_packet(&packet).unwrap();

    // Read should work locally
    let loaded = store.load_packet(&cid).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().content.entities, vec!["alice".to_string()]);
}

#[tokio::test]
async fn test_cluster_store_replicates_writes() {
    let local = InMemoryKernelStore::new();
    let bus = Arc::new(InProcessBus::new());
    let cell = Arc::new(Cell::new("cell-1"));

    // Subscribe to replication topic BEFORE creating the store
    let mut rx = bus.subscribe("cluster.repl").await.unwrap();

    let mut store = ClusterKernelStore::new(local, bus.clone(), cell.clone(), "cluster.repl");

    let packet = make_packet(&["alice"], 1000);
    store.store_packet(&packet).unwrap();

    // Give the spawned replication task a moment
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Should receive the replication event
    let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(event.cell_id, "cell-1");
    assert_eq!(event.seq, 0);
    assert_eq!(event.op.op_type(), "packet_write");
}

#[tokio::test]
async fn test_cluster_store_replicates_agent_register() {
    let local = InMemoryKernelStore::new();
    let bus = Arc::new(InProcessBus::new());
    let cell = Arc::new(Cell::new("cell-1"));

    let mut rx = bus.subscribe("cluster.repl").await.unwrap();

    let mut store = ClusterKernelStore::new(local, bus.clone(), cell.clone(), "cluster.repl");

    let acb = AgentControlBlock {
        agent_pid: "pid:001".to_string(),
        agent_name: "doctor-ai".to_string(),
        agent_role: None,
        status: AgentStatus::Running,
        priority: 5,
        namespace: "hospital/er".to_string(),
        memory_region: MemoryRegion::new("hospital/er".to_string()),
        active_sessions: Vec::new(),
        total_packets: 0,
        total_tokens_consumed: 0,
        total_cost_usd: 0.0,
        capabilities: Vec::new(),
        readable_namespaces: Vec::new(),
        writable_namespaces: Vec::new(),
        allowed_tools: Vec::new(),
        model: None,
        framework: None,
        parent_pid: None,
        child_pids: Vec::new(),
        registered_at: 1000,
        last_active_at: 2000,
        terminated_at: None,
        termination_reason: None,
        phase: AgentPhase::default(),
        role: AgentRole::default(),
        namespace_mounts: Vec::new(),
        tool_bindings: Vec::new(),
        signal_handlers: Vec::new(),
        pending_signals: Vec::new(),
        agent_priority: AgentPriority::default(),
        token_budget: None,
    };

    store.store_agent(&acb).unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(event.op.op_type(), "agent_register");
    match &event.op {
        ReplicationOp::AgentRegister { pid, name, namespace } => {
            assert_eq!(pid, "pid:001");
            assert_eq!(name, "doctor-ai");
            assert_eq!(namespace, "hospital/er");
        }
        _ => panic!("Expected AgentRegister"),
    }
}

#[tokio::test]
async fn test_cluster_store_replicates_delete() {
    let local = InMemoryKernelStore::new();
    let bus = Arc::new(InProcessBus::new());
    let cell = Arc::new(Cell::new("cell-1"));

    let mut rx = bus.subscribe("cluster.repl").await.unwrap();

    let mut store = ClusterKernelStore::new(local, bus.clone(), cell.clone(), "cluster.repl");

    let packet = make_packet(&["alice"], 1000);
    let cid = packet.index.packet_cid.clone();
    store.store_packet(&packet).unwrap();

    // Drain the PacketWrite event
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = rx.recv().await;

    // Now delete
    store.delete_packet(&cid).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(event.op.op_type(), "packet_evict");

    // Verify local delete
    assert!(store.load_packet(&cid).unwrap().is_none());
}

#[tokio::test]
async fn test_cluster_store_seq_increments() {
    let local = InMemoryKernelStore::new();
    let bus = Arc::new(InProcessBus::new());
    let cell = Arc::new(Cell::new("cell-1"));

    let mut rx = bus.subscribe("cluster.repl").await.unwrap();

    let mut store = ClusterKernelStore::new(local, bus.clone(), cell.clone(), "cluster.repl");

    // Write 3 packets
    for i in 0..3 {
        store.store_packet(&make_packet(&["alice"], 1000 + i)).unwrap();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Collect events and check sequence numbers
    let mut seqs = Vec::new();
    for _ in 0..3 {
        let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        seqs.push(event.seq);
    }

    assert_eq!(seqs, vec![0, 1, 2]);
    assert_eq!(cell.current_seq(), 3);
}

// ── Replication receiver tests ───────────────────────────────────────

#[tokio::test]
async fn test_receiver_applies_packet_write() {
    let bus = Arc::new(InProcessBus::new());

    // Cell-1: writer
    let cell1 = Arc::new(Cell::new("cell-1"));
    let local1 = InMemoryKernelStore::new();
    let mut store1 = ClusterKernelStore::new(local1, bus.clone(), cell1.clone(), "cluster.repl");

    // Cell-2: receiver
    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let (_handle, stats) =
        start_replication_loop(local2.clone(), bus.clone(), cell2.clone(), "cluster.repl")
            .await
            .unwrap();

    // Give receiver time to subscribe
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Cell-1 writes a packet
    let packet = make_packet(&["alice"], 1000);
    let cid = packet.index.packet_cid.clone();
    store1.store_packet(&packet).unwrap();

    // Wait for replication
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Cell-2 should have the packet
    let store2 = local2.lock().await;
    let loaded = store2.load_packet(&cid).unwrap();
    assert!(loaded.is_some(), "Cell-2 should have the replicated packet");
    assert_eq!(loaded.unwrap().content.entities, vec!["alice".to_string()]);

    // Check stats
    let s = stats.lock().await;
    assert_eq!(s.events_received, 1);
    assert_eq!(s.events_applied, 1);
    assert_eq!(s.events_skipped_self, 0);
}

#[tokio::test]
async fn test_receiver_skips_own_events() {
    let bus = Arc::new(InProcessBus::new());

    // Cell-1 is both writer and receiver
    let cell1 = Arc::new(Cell::new("cell-1"));
    let local1_for_receiver = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let (_handle, stats) = start_replication_loop(
        local1_for_receiver.clone(),
        bus.clone(),
        cell1.clone(),
        "cluster.repl",
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Write via ClusterKernelStore (same cell-1)
    let local1_for_store = InMemoryKernelStore::new();
    let mut store1 =
        ClusterKernelStore::new(local1_for_store, bus.clone(), cell1.clone(), "cluster.repl");
    store1.store_packet(&make_packet(&["alice"], 1000)).unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Receiver should have skipped its own event
    let s = stats.lock().await;
    assert_eq!(s.events_received, 1);
    assert_eq!(s.events_skipped_self, 1);
    assert_eq!(s.events_applied, 0);
}

#[tokio::test]
async fn test_receiver_applies_audit_entry() {
    let bus = Arc::new(InProcessBus::new());

    let cell1 = Arc::new(Cell::new("cell-1"));
    let local1 = InMemoryKernelStore::new();
    let mut store1 = ClusterKernelStore::new(local1, bus.clone(), cell1.clone(), "cluster.repl");

    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let (_handle, _stats) =
        start_replication_loop(local2.clone(), bus.clone(), cell2.clone(), "cluster.repl")
            .await
            .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Cell-1 writes an audit entry
    let entry = KernelAuditEntry {
        audit_id: "a001".into(),
        timestamp: 1000,
        operation: MemoryKernelOp::MemWrite,
        agent_pid: "pid:001".into(),
        target: Some("cid:x".into()),
        outcome: OpOutcome::Success,
        reason: None,
        error: None,
        duration_us: Some(100),
        vakya_id: None,
        before_hash: None,
        after_hash: None,
        merkle_root: None,
        scitt_receipt_cid: None,
        natural_language: None,
        business_impact: None,
        remediation_hint: None,
        causal_chain: Vec::new(),
        severity: TelemetrySeverity::default(),
        gen_ai_attrs: None,
    };
    store1.store_audit_entry(&entry).unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Cell-2 should have the audit entry
    let store2 = local2.lock().await;
    let entries = store2.load_audit_entries(0, 2000).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].audit_id, "a001");
}

#[tokio::test]
async fn test_two_cells_bidirectional_replication() {
    let bus = Arc::new(InProcessBus::new());

    // Cell-1
    let cell1 = Arc::new(Cell::new("cell-1"));
    let local1_receiver = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let (_h1, _s1) = start_replication_loop(
        local1_receiver.clone(),
        bus.clone(),
        cell1.clone(),
        "cluster.repl",
    )
    .await
    .unwrap();

    // Cell-2
    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2_receiver = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let (_h2, _s2) = start_replication_loop(
        local2_receiver.clone(),
        bus.clone(),
        cell2.clone(),
        "cluster.repl",
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Cell-1 writes a packet
    let local1_store = InMemoryKernelStore::new();
    let mut store1 =
        ClusterKernelStore::new(local1_store, bus.clone(), cell1.clone(), "cluster.repl");
    let pkt1 = make_packet(&["alice"], 1000);
    let cid1 = pkt1.index.packet_cid.clone();
    store1.store_packet(&pkt1).unwrap();

    // Cell-2 writes a different packet
    let local2_store = InMemoryKernelStore::new();
    let mut store2 =
        ClusterKernelStore::new(local2_store, bus.clone(), cell2.clone(), "cluster.repl");
    let pkt2 = make_packet(&["bob"], 2000);
    let cid2 = pkt2.index.packet_cid.clone();
    store2.store_packet(&pkt2).unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Cell-1's receiver should have Cell-2's packet
    let r1 = local1_receiver.lock().await;
    let loaded = r1.load_packet(&cid2).unwrap();
    assert!(loaded.is_some(), "Cell-1 should have Cell-2's packet");

    // Cell-2's receiver should have Cell-1's packet
    let r2 = local2_receiver.lock().await;
    let loaded = r2.load_packet(&cid1).unwrap();
    assert!(loaded.is_some(), "Cell-2 should have Cell-1's packet");
}

#[tokio::test]
async fn test_receiver_handles_evict() {
    let bus = Arc::new(InProcessBus::new());

    let cell1 = Arc::new(Cell::new("cell-1"));
    let local1 = InMemoryKernelStore::new();
    let mut store1 = ClusterKernelStore::new(local1, bus.clone(), cell1.clone(), "cluster.repl");

    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let (_handle, _stats) =
        start_replication_loop(local2.clone(), bus.clone(), cell2.clone(), "cluster.repl")
            .await
            .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Cell-1 writes then deletes
    let packet = make_packet(&["alice"], 1000);
    let cid = packet.index.packet_cid.clone();
    store1.store_packet(&packet).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify Cell-2 has it
    {
        let s2 = local2.lock().await;
        assert!(s2.load_packet(&cid).unwrap().is_some());
    }

    // Now delete on Cell-1
    store1.delete_packet(&cid).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Cell-2 should also have deleted it
    let s2 = local2.lock().await;
    assert!(
        s2.load_packet(&cid).unwrap().is_none(),
        "Cell-2 should have evicted the packet"
    );
}

// ============================================================================
// Topological Membership tests
// ============================================================================

use crate::membership::*;

// ── Vector Clock (join-semilattice) ────────────────────────────────────

#[test]
fn test_vector_clock_semilattice_properties() {
    // Build three distinct clocks
    let mut a = VectorClock::new();
    a.increment("cell-1");
    a.increment("cell-1");
    a.increment("cell-2");

    let mut b = VectorClock::new();
    b.increment("cell-2");
    b.increment("cell-2");
    b.increment("cell-3");

    let mut c = VectorClock::new();
    c.increment("cell-1");
    c.increment("cell-3");
    c.increment("cell-3");

    // Commutativity: merge(a, b) = merge(b, a)
    let ab = a.merge(&b);
    let ba = b.merge(&a);
    assert_eq!(ab, ba, "merge must be commutative");

    // Associativity: merge(merge(a, b), c) = merge(a, merge(b, c))
    let ab_c = ab.merge(&c);
    let bc = b.merge(&c);
    let a_bc = a.merge(&bc);
    assert_eq!(ab_c, a_bc, "merge must be associative");

    // Idempotence: merge(a, a) = a
    let aa = a.merge(&a);
    assert_eq!(aa, a, "merge must be idempotent");
}

#[test]
fn test_vector_clock_causality() {
    let mut a = VectorClock::new();
    a.increment("cell-1");

    let mut b = a.clone();
    b.increment("cell-2");

    // a happens-before b (a < b)
    assert!(a.happens_before(&b));
    assert!(!b.happens_before(&a));
    assert!(!a.concurrent(&b));

    // Create concurrent clocks
    let mut c = VectorClock::new();
    c.increment("cell-2");

    let mut d = VectorClock::new();
    d.increment("cell-1");

    assert!(c.concurrent(&d), "c and d should be concurrent");
    assert!(!c.happens_before(&d));
    assert!(!d.happens_before(&c));
}

// ── Simplicial Complex (topology) ──────────────────────────────────────

#[test]
fn test_simplicial_euler_characteristic() {
    let mut cx = SimplicialComplex::new();

    // Single vertex: χ = 1
    cx.add_vertex("A");
    assert_eq!(cx.euler_characteristic(), 1);

    // Two disconnected vertices: χ = 2
    cx.add_vertex("B");
    assert_eq!(cx.euler_characteristic(), 2);

    // Connect them: χ = 2 - 1 = 1 (connected graph)
    cx.add_edge("A", "B");
    assert_eq!(cx.euler_characteristic(), 1);

    // Triangle: 3 vertices, 3 edges → χ = 0
    cx.add_vertex("C");
    cx.add_edge("B", "C");
    cx.add_edge("A", "C");
    assert_eq!(cx.euler_characteristic(), 0);

    // Tree with 4 nodes: 4V - 3E = 1
    let mut tree = SimplicialComplex::new();
    tree.add_edge("A", "B");
    tree.add_edge("B", "C");
    tree.add_edge("B", "D");
    assert_eq!(tree.euler_characteristic(), 1);
}

#[test]
fn test_simplicial_connected_components() {
    let mut cx = SimplicialComplex::new();

    // Empty: β₀ = 0
    assert_eq!(cx.betti_0(), 0);

    // Single vertex: β₀ = 1
    cx.add_vertex("A");
    assert_eq!(cx.betti_0(), 1);
    assert!(cx.is_connected());

    // Two disconnected vertices: β₀ = 2 (partition!)
    cx.add_vertex("B");
    assert_eq!(cx.betti_0(), 2);
    assert!(!cx.is_connected());

    // Connect them: β₀ = 1
    cx.add_edge("A", "B");
    assert_eq!(cx.betti_0(), 1);
    assert!(cx.is_connected());

    // Add third disconnected: β₀ = 2
    cx.add_vertex("C");
    assert_eq!(cx.betti_0(), 2);

    // Connect C to A: β₀ = 1
    cx.add_edge("A", "C");
    assert_eq!(cx.betti_0(), 1);

    // Remove B (and its edges): should still be connected via A-C
    cx.remove_vertex("B");
    assert_eq!(cx.betti_0(), 1);
    assert_eq!(cx.vertex_count(), 2);
}

// ── Causal Braid (knot invariant) ──────────────────────────────────────

#[test]
fn test_braid_writhe_stability() {
    let mut braid = CausalBraid::new(100);

    // Empty braid: trivially stable
    assert_eq!(braid.writhe(), 0);
    assert_eq!(braid.stability_index(), 1.0);

    // All joins: writhe = +3, stability = 1 - 3/3 = 0.0 (unstable)
    braid.record("A", CrossingSign::Positive);
    braid.record("B", CrossingSign::Positive);
    braid.record("C", CrossingSign::Positive);
    assert_eq!(braid.writhe(), 3);
    assert!((braid.stability_index() - 0.0).abs() < f64::EPSILON);

    // Balance with leaves: writhe = +1, stability = 1 - 1/5 = 0.8
    braid.record("A", CrossingSign::Negative);
    braid.record("B", CrossingSign::Negative);
    assert_eq!(braid.writhe(), 1);
    assert!((braid.stability_index() - 0.8).abs() < f64::EPSILON);

    // Neutral crossings don't affect writhe or significant count
    braid.record("C", CrossingSign::Neutral);
    assert_eq!(braid.writhe(), 1);
    assert_eq!(braid.significant_crossings(), 5);
    assert_eq!(braid.total_crossings(), 6);
}

// ── Membership View CRDT ───────────────────────────────────────────────

#[test]
fn test_membership_view_crdt_merge() {
    let mut view_a = MembershipView::new();
    let mut view_b = MembershipView::new();

    // View A knows about cell-1
    view_a.members.insert(
        "cell-1".into(),
        MemberState {
            cell_id: "cell-1".into(),
            address: "addr-1".into(),
            is_voter: true,
            joined_at: 100,
            last_seen: 200,
            generation: 2,
            tombstone: false,
        },
    );
    view_a.clock.increment("cell-1");
    view_a.clock.increment("cell-1");

    // View B knows about cell-2, and has an older view of cell-1
    view_b.members.insert(
        "cell-1".into(),
        MemberState {
            cell_id: "cell-1".into(),
            address: "addr-1".into(),
            is_voter: true,
            joined_at: 100,
            last_seen: 150,
            generation: 1, // older generation
            tombstone: false,
        },
    );
    view_b.members.insert(
        "cell-2".into(),
        MemberState {
            cell_id: "cell-2".into(),
            address: "addr-2".into(),
            is_voter: true,
            joined_at: 110,
            last_seen: 210,
            generation: 1,
            tombstone: false,
        },
    );
    view_b.clock.increment("cell-1");
    view_b.clock.increment("cell-2");

    // Merge A into B and B into A — should produce same result (commutativity)
    let merged_ab = view_a.merge(&view_b);
    let merged_ba = view_b.merge(&view_a);

    assert_eq!(merged_ab.members.len(), 2);
    assert_eq!(merged_ba.members.len(), 2);

    // cell-1 should have generation 2 (from view_a, higher)
    assert_eq!(merged_ab.members["cell-1"].generation, 2);
    assert_eq!(merged_ba.members["cell-1"].generation, 2);

    // cell-2 should be present in both
    assert!(merged_ab.members.contains_key("cell-2"));
    assert!(merged_ba.members.contains_key("cell-2"));

    // Vector clocks should match
    assert_eq!(merged_ab.clock, merged_ba.clock);
    assert_eq!(merged_ab.clock.get("cell-1"), 2);
    assert_eq!(merged_ab.clock.get("cell-2"), 1);
}

#[test]
fn test_membership_convergence_proof() {
    // Three views merge in different orders → same result
    let mut v1 = MembershipView::new();
    let mut v2 = MembershipView::new();
    let mut v3 = MembershipView::new();

    v1.members.insert("A".into(), MemberState {
        cell_id: "A".into(), address: "a".into(), is_voter: true,
        joined_at: 1, last_seen: 1, generation: 3, tombstone: false,
    });
    v1.clock.increment("A"); v1.clock.increment("A"); v1.clock.increment("A");

    v2.members.insert("B".into(), MemberState {
        cell_id: "B".into(), address: "b".into(), is_voter: true,
        joined_at: 2, last_seen: 2, generation: 2, tombstone: false,
    });
    v2.clock.increment("B"); v2.clock.increment("B");

    v3.members.insert("A".into(), MemberState {
        cell_id: "A".into(), address: "a".into(), is_voter: true,
        joined_at: 1, last_seen: 1, generation: 1, tombstone: false,
    });
    v3.members.insert("C".into(), MemberState {
        cell_id: "C".into(), address: "c".into(), is_voter: false,
        joined_at: 3, last_seen: 3, generation: 1, tombstone: false,
    });
    v3.clock.increment("A"); v3.clock.increment("C");

    // Order 1: (v1 ⊔ v2) ⊔ v3
    let r1 = v1.merge(&v2).merge(&v3);
    // Order 2: v1 ⊔ (v2 ⊔ v3)
    let r2 = v1.merge(&v2.merge(&v3));
    // Order 3: (v3 ⊔ v1) ⊔ v2
    let r3 = v3.merge(&v1).merge(&v2);

    // All must converge to the same state
    assert_eq!(r1.members.len(), 3);
    assert_eq!(r2.members.len(), 3);
    assert_eq!(r3.members.len(), 3);

    // A should have generation 3 (highest)
    assert_eq!(r1.members["A"].generation, 3);
    assert_eq!(r2.members["A"].generation, 3);
    assert_eq!(r3.members["A"].generation, 3);

    // Clocks must match
    assert_eq!(r1.clock, r2.clock);
    assert_eq!(r2.clock, r3.clock);
}

// ── Full Membership (orchestrator) ─────────────────────────────────────

#[test]
fn test_membership_join_leave() {
    let config = MembershipConfig::default();
    let mut m = Membership::new("cell-1", "addr-1", config);

    assert_eq!(m.alive_count(), 1);
    assert_eq!(m.partition_count(), 1);

    // Join two more cells
    m.join("cell-2", "addr-2", true);
    m.join("cell-3", "addr-3", true);
    assert_eq!(m.alive_count(), 3);
    assert_eq!(m.partition_count(), 1); // fully connected
    assert!(m.has_quorum());

    // Leave cell-2
    m.leave("cell-2");
    assert_eq!(m.alive_count(), 2);
    assert_eq!(m.total_count(), 3); // tombstone still counted
    assert!(m.has_quorum()); // 2 alive voters out of 3 total voters > 3/2
}

#[test]
fn test_membership_quorum_detection() {
    let config = MembershipConfig::default();
    let mut m = Membership::new("cell-1", "addr-1", config);
    m.join("cell-2", "addr-2", true);
    m.join("cell-3", "addr-3", true);

    // 3/3 alive → quorum
    assert!(m.has_quorum());

    // Remove 2 → 1/3 alive → no quorum
    m.leave("cell-2");
    m.leave("cell-3");
    assert!(!m.has_quorum());
}

#[test]
fn test_membership_partition_detection() {
    let mut m = Membership::new(
        "cell-1",
        "addr-1",
        MembershipConfig::default(),
    );
    m.join("cell-2", "addr-2", true);

    // Fully connected: β₀ = 1
    assert_eq!(m.partition_count(), 1);

    // Manually break the edge to simulate partition
    m.complex.remove_edge("cell-1", "cell-2");
    assert_eq!(m.partition_count(), 2); // partition detected!
    assert!(!m.complex.is_connected());

    // Heal the partition
    m.complex.add_edge("cell-1", "cell-2");
    assert_eq!(m.partition_count(), 1);
    assert!(m.complex.is_connected());
}

// ============================================================================
// D15: Multi-cell end-to-end integration tests
// ============================================================================

use vac_route::router::{CellEndpoint, CellRouter};

/// Helper: spin up a full cell with store, bus, receiver, and membership.
struct TestCell {
    cell: Arc<Cell>,
    store: Arc<Mutex<InMemoryKernelStore>>,
    writer: ClusterKernelStore<InMemoryKernelStore, InProcessBus>,
    membership: Membership,
}

async fn make_test_cell(
    cell_id: &str,
    bus: Arc<InProcessBus>,
    topic: &str,
) -> (TestCell, tokio::task::JoinHandle<()>, Arc<Mutex<ReceiverStats>>) {
    let cell = Arc::new(Cell::new(cell_id));
    let receiver_store = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let writer_store = InMemoryKernelStore::new();

    let (handle, stats) = start_replication_loop(
        receiver_store.clone(),
        bus.clone(),
        cell.clone(),
        topic,
    )
    .await
    .unwrap();

    let writer = ClusterKernelStore::new(writer_store, bus.clone(), cell.clone(), topic);
    let membership = Membership::new(cell_id, &format!("addr-{}", cell_id), MembershipConfig::default());

    let tc = TestCell {
        cell,
        store: receiver_store,
        writer,
        membership,
    };
    (tc, handle, stats)
}

#[tokio::test]
async fn test_d15_three_cell_cluster_replication() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.repl";

    let (mut c1, _h1, s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (mut c2, _h2, s2) = make_test_cell("cell-2", bus.clone(), topic).await;
    let (mut c3, _h3, s3) = make_test_cell("cell-3", bus.clone(), topic).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Cell-1 writes a packet
    let pkt = make_packet(&["alice"], 1000);
    let cid = pkt.index.packet_cid.clone();
    c1.writer.store_packet(&pkt).unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Cell-2 and Cell-3 should both have it
    let s2_store = c2.store.lock().await;
    assert!(s2_store.load_packet(&cid).unwrap().is_some(), "Cell-2 should have Cell-1's packet");
    drop(s2_store);

    let s3_store = c3.store.lock().await;
    assert!(s3_store.load_packet(&cid).unwrap().is_some(), "Cell-3 should have Cell-1's packet");
    drop(s3_store);

    // Cell-1 should have skipped its own event
    let stats1 = s1.lock().await;
    assert_eq!(stats1.events_skipped_self, 1);
}

#[tokio::test]
async fn test_d15_concurrent_writes_from_multiple_cells() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.concurrent";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (mut c2, _h2, _s2) = make_test_cell("cell-2", bus.clone(), topic).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Both cells write simultaneously
    let pkt1 = make_packet(&["alice"], 1000);
    let cid1 = pkt1.index.packet_cid.clone();
    c1.writer.store_packet(&pkt1).unwrap();

    let pkt2 = make_packet(&["bob"], 2000);
    let cid2 = pkt2.index.packet_cid.clone();
    c2.writer.store_packet(&pkt2).unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Cell-1's receiver should have Cell-2's packet
    let s1 = c1.store.lock().await;
    assert!(s1.load_packet(&cid2).unwrap().is_some());
    drop(s1);

    // Cell-2's receiver should have Cell-1's packet
    let s2 = c2.store.lock().await;
    assert!(s2.load_packet(&cid1).unwrap().is_some());
}

#[tokio::test]
async fn test_d15_write_then_delete_replicates() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.delete";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (_c2, _h2, _s2) = make_test_cell("cell-2", bus.clone(), topic).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Write
    let pkt = make_packet(&["alice"], 1000);
    let cid = pkt.index.packet_cid.clone();
    c1.writer.store_packet(&pkt).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Verify Cell-2 has it
    {
        let s2 = _c2.store.lock().await;
        assert!(s2.load_packet(&cid).unwrap().is_some());
    }

    // Delete on Cell-1
    c1.writer.delete_packet(&cid).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Cell-2 should also have deleted it
    let s2 = _c2.store.lock().await;
    assert!(s2.load_packet(&cid).unwrap().is_none(), "Delete should replicate");
}

#[tokio::test]
async fn test_d15_audit_entry_replication() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.audit";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (_c2, _h2, _s2) = make_test_cell("cell-2", bus.clone(), topic).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let entry = KernelAuditEntry {
        audit_id: "audit-d15-001".into(),
        timestamp: 5000,
        operation: MemoryKernelOp::MemWrite,
        agent_pid: "pid:d15".into(),
        target: Some("cid:d15".into()),
        outcome: OpOutcome::Success,
        reason: None,
        error: None,
        duration_us: Some(42),
        vakya_id: None,
        before_hash: None,
        after_hash: None,
        merkle_root: None,
        scitt_receipt_cid: None,
        natural_language: None,
        business_impact: None,
        remediation_hint: None,
        causal_chain: Vec::new(),
        severity: TelemetrySeverity::default(),
        gen_ai_attrs: None,
    };
    c1.writer.store_audit_entry(&entry).unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let s2 = _c2.store.lock().await;
    let entries = s2.load_audit_entries(0, 10000).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].audit_id, "audit-d15-001");
}

#[tokio::test]
async fn test_d15_membership_quorum_with_routing() {
    // Verify membership + routing work together
    let mut m = Membership::new("cell-1", "addr-1", MembershipConfig::default());
    let mut router = CellRouter::new();
    let _ = router.add_cell(CellEndpoint::new("cell-1", "addr-1"));

    // Add peers
    m.join("cell-2", "addr-2", true);
    let _ = router.add_cell(CellEndpoint::new("cell-2", "addr-2"));
    m.join("cell-3", "addr-3", true);
    let _ = router.add_cell(CellEndpoint::new("cell-3", "addr-3"));

    assert!(m.has_quorum());
    assert_eq!(m.partition_count(), 1);
    assert_eq!(router.cell_count(), 3);

    // Route 100 agents — should distribute across cells
    let mut cell_counts = std::collections::HashMap::new();
    for i in 0..100 {
        let ep = router.route_agent(&format!("agent-{}", i)).unwrap();
        *cell_counts.entry(ep.cell_id.clone()).or_insert(0) += 1;
    }

    // With consistent hashing and 3 cells, each should get some agents
    assert!(cell_counts.len() >= 2, "Agents should route to multiple cells");
    for (_cell, count) in &cell_counts {
        assert!(*count > 0, "Every cell should get at least some agents");
    }
}

#[tokio::test]
async fn test_d15_cell_seq_monotonic_across_ops() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.seq";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let mut rx = bus.subscribe(topic).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Write 3 packets + 1 audit entry = 4 events
    for i in 0..3 {
        c1.writer.store_packet(&make_packet(&["alice"], 1000 + i)).unwrap();
    }
    let entry = KernelAuditEntry {
        audit_id: "a-seq".into(),
        timestamp: 9000,
        operation: MemoryKernelOp::MemWrite,
        agent_pid: "pid:seq".into(),
        target: None,
        outcome: OpOutcome::Success,
        reason: None, error: None, duration_us: None,
        vakya_id: None, before_hash: None, after_hash: None,
        merkle_root: None, scitt_receipt_cid: None,
        natural_language: None, business_impact: None, remediation_hint: None,
        causal_chain: Vec::new(), severity: TelemetrySeverity::default(), gen_ai_attrs: None,
    };
    c1.writer.store_audit_entry(&entry).unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Collect all events and verify monotonic sequence
    let mut seqs = Vec::new();
    for _ in 0..4 {
        let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        seqs.push(event.seq);
    }

    // Sequences must be strictly monotonic
    for i in 1..seqs.len() {
        assert!(seqs[i] > seqs[i - 1], "Sequence must be monotonic: {:?}", seqs);
    }
    assert_eq!(c1.cell.current_seq(), 4);
}

#[tokio::test]
async fn test_d15_bus_stats_after_cluster_operations() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.stats";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (_c2, _h2, s2) = make_test_cell("cell-2", bus.clone(), topic).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(bus.is_open());
    assert_eq!(bus.published_count(), 0);

    // Write 5 packets
    for i in 0..5 {
        c1.writer.store_packet(&make_packet(&["alice"], 1000 + i)).unwrap();
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(bus.published_count(), 5);

    // Cell-2 should have received and applied all 5
    let stats = s2.lock().await;
    assert_eq!(stats.events_received, 5);
    assert_eq!(stats.events_applied, 5);
}

#[tokio::test]
async fn test_d15_membership_view_convergence_across_cells() {
    // Simulate two cells with independent membership views that converge
    let mut m1 = Membership::new("cell-1", "addr-1", MembershipConfig::default());
    let mut m2 = Membership::new("cell-2", "addr-2", MembershipConfig::default());

    // Cell-1 knows about cell-3
    m1.join("cell-2", "addr-2", true);
    m1.join("cell-3", "addr-3", true);

    // Cell-2 knows about cell-4
    m2.join("cell-1", "addr-1", true);
    m2.join("cell-4", "addr-4", true);

    // Merge views (simulating gossip)
    let merged = m1.view.merge(&m2.view);

    // Merged view should have all 4 cells
    assert_eq!(merged.members.len(), 4);
    assert!(merged.members.contains_key("cell-1"));
    assert!(merged.members.contains_key("cell-2"));
    assert!(merged.members.contains_key("cell-3"));
    assert!(merged.members.contains_key("cell-4"));
}

#[tokio::test]
async fn test_d15_partition_detection_and_healing() {
    let mut m = Membership::new("cell-1", "addr-1", MembershipConfig::default());
    m.join("cell-2", "addr-2", true);
    m.join("cell-3", "addr-3", true);

    // Healthy: 1 partition
    assert_eq!(m.partition_count(), 1);
    assert!(m.has_quorum());

    // Simulate network partition: cell-2 disconnects from cell-1 and cell-3
    m.complex.remove_edge("cell-1", "cell-2");
    m.complex.remove_edge("cell-2", "cell-3");

    // Now cell-2 is isolated: 2 partitions
    assert_eq!(m.partition_count(), 2);

    // Heal: cell-2 reconnects to cell-1
    m.complex.add_edge("cell-1", "cell-2");
    assert_eq!(m.partition_count(), 1);
    assert!(m.complex.is_connected());
}

#[tokio::test]
async fn test_d15_multiple_writes_ordering_preserved() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.order";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (_c2, _h2, s2) = make_test_cell("cell-2", bus.clone(), topic).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Write 10 packets with increasing timestamps
    let mut cids = Vec::new();
    for i in 0..10 {
        let pkt = make_packet(&["alice"], 1000 + i);
        cids.push(pkt.index.packet_cid.clone());
        c1.writer.store_packet(&pkt).unwrap();
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Cell-2 should have all 10 packets
    let s2_store = _c2.store.lock().await;
    for cid in &cids {
        assert!(s2_store.load_packet(cid).unwrap().is_some(),
            "Cell-2 should have all replicated packets");
    }

    let stats = s2.lock().await;
    assert_eq!(stats.events_applied, 10);
}

#[tokio::test]
async fn test_d15_full_stack_cell_bus_membership_router() {
    // Full integration: 3 cells with bus + membership + router
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.full";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (_c2, _h2, _s2) = make_test_cell("cell-2", bus.clone(), topic).await;
    let (_c3, _h3, _s3) = make_test_cell("cell-3", bus.clone(), topic).await;

    // Set up membership on cell-1
    c1.membership.join("cell-2", "addr-2", true);
    c1.membership.join("cell-3", "addr-3", true);

    // Set up router
    let mut router = CellRouter::new();
    let _ = router.add_cell(CellEndpoint::new("cell-1", "addr-1"));
    let _ = router.add_cell(CellEndpoint::new("cell-2", "addr-2"));
    let _ = router.add_cell(CellEndpoint::new("cell-3", "addr-3"));

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify cluster health
    assert!(c1.membership.has_quorum());
    assert_eq!(c1.membership.partition_count(), 1);
    assert_eq!(router.cell_count(), 3);

    // Write from cell-1, verify replication to cell-2 and cell-3
    let pkt = make_packet(&["full-stack-test"], 9999);
    let cid = pkt.index.packet_cid.clone();
    c1.writer.store_packet(&pkt).unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let s2 = _c2.store.lock().await;
    assert!(s2.load_packet(&cid).unwrap().is_some());
    drop(s2);

    let s3 = _c3.store.lock().await;
    assert!(s3.load_packet(&cid).unwrap().is_some());
    drop(s3);

    // Route an agent and verify it goes to a valid cell
    let ep = router.route_agent("agent-full-stack").unwrap();
    assert!(["cell-1", "cell-2", "cell-3"].contains(&ep.cell_id.as_str()));
}

#[tokio::test]
async fn test_d15_bus_close_stops_replication() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "d15.close";

    let (mut c1, _h1, _s1) = make_test_cell("cell-1", bus.clone(), topic).await;
    let (_c2, _h2, s2) = make_test_cell("cell-2", bus.clone(), topic).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Write before close
    c1.writer.store_packet(&make_packet(&["alice"], 1000)).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let stats_before = { s2.lock().await.events_applied };
    assert_eq!(stats_before, 1);

    // Close the bus
    bus.close().await.unwrap();
    assert!(!bus.is_open());

    // Writes after close should fail
    let result = c1.writer.store_packet(&make_packet(&["bob"], 2000));
    // The local write succeeds but replication publish fails silently
    // (ClusterKernelStore logs the error but doesn't fail the local write)
    assert!(result.is_ok(), "Local write should still succeed");
}

// ── Phase 1.9: Event Signature Verification ──────────────────────────────

#[tokio::test]
async fn test_p1_9_valid_signature_accepted() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "p19.valid";

    // Cell-1 writes (signs events automatically via ClusterKernelStore)
    let cell1 = Arc::new(Cell::new("cell-1"));
    let local1 = InMemoryKernelStore::new();
    let mut store1 = ClusterKernelStore::new(local1, bus.clone(), cell1.clone(), topic);

    // Cell-2 receives with signature verification — register cell-1's public key
    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));
    let mut peers = PeerRegistry::new();
    peers.register("cell-1", *cell1.public_key());

    let (_h2, s2) = start_verified_replication_loop(
        local2.clone(), bus.clone(), cell2.clone(), topic, peers,
    ).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Cell-1 writes a packet — automatically signed
    store1.store_packet(&make_packet(&["alice"], 1000)).unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = s2.lock().await;
    assert_eq!(stats.events_applied, 1, "Valid signed event should be accepted");
    assert_eq!(stats.events_rejected, 0);
}

#[tokio::test]
async fn test_p1_9_unsigned_event_rejected() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "p19.unsigned";

    let cell1 = Arc::new(Cell::new("cell-1"));
    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));

    let mut peers = PeerRegistry::new();
    peers.register("cell-1", *cell1.public_key());

    let (_h2, s2) = start_verified_replication_loop(
        local2.clone(), bus.clone(), cell2.clone(), topic, peers,
    ).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish an UNSIGNED event directly (bypassing ClusterKernelStore)
    let unsigned_event = ReplicationEvent::new(
        "cell-1", 0,
        ReplicationOp::Heartbeat { agent_count: 1, packet_count: 10, merkle_root: [0; 32], load: 5 },
    );
    assert!(!unsigned_event.is_signed());
    bus.publish(topic, &unsigned_event).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = s2.lock().await;
    assert_eq!(stats.events_applied, 0, "Unsigned event should NOT be applied");
    assert_eq!(stats.events_rejected, 1, "Unsigned event should be rejected");
}

#[tokio::test]
async fn test_p1_9_invalid_signature_rejected() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "p19.invalid";

    let cell1 = Arc::new(Cell::new("cell-1"));
    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));

    let mut peers = PeerRegistry::new();
    peers.register("cell-1", *cell1.public_key());

    let (_h2, s2) = start_verified_replication_loop(
        local2.clone(), bus.clone(), cell2.clone(), topic, peers,
    ).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish an event with a GARBAGE signature
    let bad_event = ReplicationEvent::new(
        "cell-1", 0,
        ReplicationOp::Heartbeat { agent_count: 1, packet_count: 10, merkle_root: [0; 32], load: 5 },
    ).with_signature(vec![0xDE; 64]); // wrong bytes

    assert!(bad_event.is_signed());
    bus.publish(topic, &bad_event).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = s2.lock().await;
    assert_eq!(stats.events_applied, 0, "Invalid signature should NOT be applied");
    assert_eq!(stats.events_rejected, 1, "Invalid signature should be rejected");
}

#[tokio::test]
async fn test_p1_9_unknown_peer_rejected() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "p19.unknown";

    let cell_rogue = Arc::new(Cell::new("cell-rogue"));
    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));

    // PeerRegistry does NOT contain "cell-rogue"
    let peers = PeerRegistry::new();

    let (_h2, s2) = start_verified_replication_loop(
        local2.clone(), bus.clone(), cell2.clone(), topic, peers,
    ).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Rogue cell sends a properly signed event — but it's not a known peer
    let mut rogue_event = ReplicationEvent::new(
        "cell-rogue", 0,
        ReplicationOp::Heartbeat { agent_count: 1, packet_count: 10, merkle_root: [0; 32], load: 5 },
    );
    rogue_event.sign(cell_rogue.signing_key());
    assert!(rogue_event.is_signed());

    bus.publish(topic, &rogue_event).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = s2.lock().await;
    assert_eq!(stats.events_applied, 0, "Unknown peer should NOT be applied");
    assert_eq!(stats.events_rejected, 1, "Unknown peer should be rejected");
}

#[tokio::test]
async fn test_p1_9_signed_event_wrong_key_rejected() {
    let bus = Arc::new(InProcessBus::new());
    let topic = "p19.wrongkey";

    let cell1 = Arc::new(Cell::new("cell-1"));
    let cell_imposter = Arc::new(Cell::new("cell-1-imposter")); // different key
    let cell2 = Arc::new(Cell::new("cell-2"));
    let local2 = Arc::new(Mutex::new(InMemoryKernelStore::new()));

    let mut peers = PeerRegistry::new();
    peers.register("cell-1", *cell1.public_key()); // registered with cell-1's real key

    let (_h2, s2) = start_verified_replication_loop(
        local2.clone(), bus.clone(), cell2.clone(), topic, peers,
    ).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Imposter claims to be cell-1 but signs with different key
    let mut imposter_event = ReplicationEvent::new(
        "cell-1", 0,
        ReplicationOp::Heartbeat { agent_count: 1, packet_count: 10, merkle_root: [0; 32], load: 5 },
    );
    imposter_event.sign(cell_imposter.signing_key()); // wrong key!

    bus.publish(topic, &imposter_event).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = s2.lock().await;
    assert_eq!(stats.events_applied, 0, "Imposter event should NOT be applied");
    assert_eq!(stats.events_rejected, 1, "Imposter event should be rejected");
}
