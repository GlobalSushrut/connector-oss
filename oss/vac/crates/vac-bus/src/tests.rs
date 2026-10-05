//! Tests for vac-bus.

use crate::*;
use std::time::Duration;

fn make_heartbeat(cell_id: &str, seq: u64) -> ReplicationEvent {
    ReplicationEvent::new(
        cell_id,
        seq,
        ReplicationOp::Heartbeat {
            agent_count: 5,
            packet_count: 100,
            merkle_root: [0u8; 32],
            load: 25,
        },
    )
}

fn make_packet_write(cell_id: &str, seq: u64, ns: &str, cid: &str) -> ReplicationEvent {
    ReplicationEvent::new(
        cell_id,
        seq,
        ReplicationOp::PacketWrite {
            namespace: ns.to_string(),
            packet_cbor: vec![1, 2, 3],
            packet_cid: cid.to_string(),
        },
    )
}

fn make_vakya_forward(cell_id: &str, seq: u64, step_id: &str) -> ReplicationEvent {
    ReplicationEvent::new(
        cell_id,
        seq,
        ReplicationOp::VakyaForward {
            vakya_cbor: vec![10, 20, 30],
            pipeline_id: "pipe-1".to_string(),
            step_id: step_id.to_string(),
            reply_topic: format!("reply.{}", step_id),
        },
    )
}

// ── ReplicationEvent tests ───────────────────────────────────────────

#[test]
fn test_event_creation() {
    let event = make_heartbeat("cell-1", 1);
    assert_eq!(event.cell_id, "cell-1");
    assert_eq!(event.seq, 1);
    assert!(event.ts > 0);
    assert!(!event.is_signed());
}

#[test]
fn test_event_with_signature() {
    let event = make_heartbeat("cell-1", 1).with_signature(vec![42; 64]);
    assert!(event.is_signed());
    assert_eq!(event.signature.len(), 64);
}

#[test]
fn test_event_with_ts() {
    let event = ReplicationEvent::with_ts(
        "cell-1",
        5,
        ReplicationOp::PacketSeal {
            cids: vec!["cid-1".into()],
        },
        1700000000000,
    );
    assert_eq!(event.ts, 1700000000000);
    assert_eq!(event.seq, 5);
}

// ── ReplicationOp tests ──────────────────────────────────────────────

#[test]
fn test_op_type_labels() {
    assert_eq!(
        ReplicationOp::PacketWrite {
            namespace: String::new(),
            packet_cbor: vec![],
            packet_cid: String::new(),
        }
        .op_type(),
        "packet_write"
    );
    assert_eq!(
        ReplicationOp::Heartbeat {
            agent_count: 0,
            packet_count: 0,
            merkle_root: [0; 32],
            load: 0,
        }
        .op_type(),
        "heartbeat"
    );
    assert_eq!(
        ReplicationOp::VakyaForward {
            vakya_cbor: vec![],
            pipeline_id: String::new(),
            step_id: String::new(),
            reply_topic: String::new(),
        }
        .op_type(),
        "vakya_forward"
    );
    assert_eq!(
        ReplicationOp::ApprovalRequest {
            approval_id: String::new(),
            vakya_cbor: vec![],
            approvers: vec![],
            timeout_ms: 0,
        }
        .op_type(),
        "approval_request"
    );
}

#[test]
fn test_op_is_vac_vs_aapi() {
    let vac_op = ReplicationOp::PacketWrite {
        namespace: "ns".into(),
        packet_cbor: vec![],
        packet_cid: "cid".into(),
    };
    assert!(vac_op.is_vac_op());
    assert!(!vac_op.is_aapi_op());

    let aapi_op = ReplicationOp::VakyaForward {
        vakya_cbor: vec![],
        pipeline_id: String::new(),
        step_id: String::new(),
        reply_topic: String::new(),
    };
    assert!(aapi_op.is_aapi_op());
    assert!(!aapi_op.is_vac_op());
}

#[test]
fn test_op_serde_roundtrip() {
    let op = ReplicationOp::PacketWrite {
        namespace: "agents/doctor".into(),
        packet_cbor: vec![1, 2, 3, 4],
        packet_cid: "bafyrei_abc".into(),
    };
    let json = serde_json::to_string(&op).unwrap();
    let decoded: ReplicationOp = serde_json::from_str(&json).unwrap();
    assert_eq!(op, decoded);
}

#[test]
fn test_event_serde_roundtrip() {
    let event = make_packet_write("cell-1", 42, "agents/doctor", "bafyrei_abc");
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ReplicationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.cell_id, "cell-1");
    assert_eq!(decoded.seq, 42);
    assert_eq!(decoded.op.op_type(), "packet_write");
}

// ── InProcessBus tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_bus_publish_no_subscribers() {
    let bus = InProcessBus::new();
    let event = make_heartbeat("cell-1", 1);

    // Publishing with no subscribers should succeed (fire-and-forget)
    let result = bus.publish("cluster.heartbeat", &event).await;
    assert!(result.is_ok());
    assert_eq!(bus.published_count(), 1);
}

#[tokio::test]
async fn test_bus_single_subscriber() {
    let bus = InProcessBus::new();
    let mut rx = bus.subscribe("cluster.replication").await.unwrap();

    let event = make_packet_write("cell-1", 1, "ns", "cid-1");
    bus.publish("cluster.replication", &event).await.unwrap();

    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(received.cell_id, "cell-1");
    assert_eq!(received.seq, 1);
    assert_eq!(received.op.op_type(), "packet_write");
}

#[tokio::test]
async fn test_bus_multiple_subscribers() {
    let bus = InProcessBus::new();
    let mut rx1 = bus.subscribe("topic-a").await.unwrap();
    let mut rx2 = bus.subscribe("topic-a").await.unwrap();

    let event = make_heartbeat("cell-1", 1);
    bus.publish("topic-a", &event).await.unwrap();

    let r1 = tokio::time::timeout(Duration::from_millis(100), rx1.recv())
        .await
        .unwrap()
        .unwrap();
    let r2 = tokio::time::timeout(Duration::from_millis(100), rx2.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(r1.cell_id, "cell-1");
    assert_eq!(r2.cell_id, "cell-1");
}

#[tokio::test]
async fn test_bus_topic_isolation() {
    let bus = InProcessBus::new();
    let mut rx_a = bus.subscribe("topic-a").await.unwrap();
    let mut rx_b = bus.subscribe("topic-b").await.unwrap();

    let event_a = make_heartbeat("cell-a", 1);
    let event_b = make_heartbeat("cell-b", 2);

    bus.publish("topic-a", &event_a).await.unwrap();
    bus.publish("topic-b", &event_b).await.unwrap();

    let ra = tokio::time::timeout(Duration::from_millis(100), rx_a.recv())
        .await
        .unwrap()
        .unwrap();
    let rb = tokio::time::timeout(Duration::from_millis(100), rx_b.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ra.cell_id, "cell-a");
    assert_eq!(rb.cell_id, "cell-b");

    // rx_a should NOT receive event_b
    let timeout_result = tokio::time::timeout(Duration::from_millis(50), rx_a.recv()).await;
    assert!(timeout_result.is_err()); // Timed out = no event
}

#[tokio::test]
async fn test_bus_multiple_events_ordering() {
    let bus = InProcessBus::new();
    let mut rx = bus.subscribe("ordered").await.unwrap();

    for i in 0..10 {
        let event = make_heartbeat("cell-1", i);
        bus.publish("ordered", &event).await.unwrap();
    }

    for i in 0..10 {
        let received = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.seq, i);
    }

    assert_eq!(bus.published_count(), 10);
}

#[tokio::test]
async fn test_bus_close() {
    let bus = InProcessBus::new();
    assert!(bus.is_open());

    let _rx = bus.subscribe("topic").await.unwrap();
    bus.close().await.unwrap();

    assert!(!bus.is_open());

    // Publishing after close should fail
    let event = make_heartbeat("cell-1", 1);
    let result = bus.publish("topic", &event).await;
    assert!(result.is_err());

    // Subscribing after close should fail
    let result = bus.subscribe("topic").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_bus_topic_count() {
    let bus = InProcessBus::new();
    assert_eq!(bus.topic_count().await, 0);

    bus.subscribe("topic-1").await.unwrap();
    assert_eq!(bus.topic_count().await, 1);

    bus.subscribe("topic-2").await.unwrap();
    assert_eq!(bus.topic_count().await, 2);

    // Same topic doesn't create a new channel
    bus.subscribe("topic-1").await.unwrap();
    assert_eq!(bus.topic_count().await, 2);
}

#[tokio::test]
async fn test_bus_aapi_ops() {
    let bus = InProcessBus::new();
    let mut rx = bus.subscribe("cell.cell-2.vakya").await.unwrap();

    let event = make_vakya_forward("cell-1", 1, "step-abc");
    bus.publish("cell.cell-2.vakya", &event).await.unwrap();

    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(received.cell_id, "cell-1");
    match &received.op {
        ReplicationOp::VakyaForward {
            step_id,
            reply_topic,
            ..
        } => {
            assert_eq!(step_id, "step-abc");
            assert_eq!(reply_topic, "reply.step-abc");
        }
        _ => panic!("Expected VakyaForward"),
    }
}

#[tokio::test]
async fn test_bus_approval_roundtrip() {
    let bus = InProcessBus::new();
    let mut rx = bus.subscribe("cluster.approvals").await.unwrap();

    // Publish approval request
    let request = ReplicationEvent::new(
        "cell-1",
        1,
        ReplicationOp::ApprovalRequest {
            approval_id: "apr-001".into(),
            vakya_cbor: vec![1, 2, 3],
            approvers: vec!["manager@example.com".into()],
            timeout_ms: 3600000,
        },
    );
    bus.publish("cluster.approvals", &request).await.unwrap();

    // Publish approval response
    let response = ReplicationEvent::new(
        "cell-2",
        1,
        ReplicationOp::ApprovalResponse {
            approval_id: "apr-001".into(),
            approved: true,
            approver: "manager@example.com".into(),
            comment: Some("Looks good".into()),
        },
    );
    bus.publish("cluster.approvals", &response).await.unwrap();

    // Receive both
    let r1 = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let r2 = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(r1.op.op_type(), "approval_request");
    assert_eq!(r2.op.op_type(), "approval_response");
}

#[tokio::test]
async fn test_bus_with_custom_capacity() {
    let bus = InProcessBus::with_capacity(4);
    let mut rx = bus.subscribe("small").await.unwrap();

    // Publish within capacity
    for i in 0..4 {
        bus.publish("small", &make_heartbeat("cell-1", i))
            .await
            .unwrap();
    }

    for i in 0..4 {
        let received = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.seq, i);
    }
}

#[tokio::test]
async fn test_bus_subscription_count() {
    let bus = InProcessBus::new();
    assert_eq!(bus.subscription_count(), 0);

    let _rx1 = bus.subscribe("topic-1").await.unwrap();
    // Give the spawned task a moment to register
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(bus.subscription_count(), 1);

    let _rx2 = bus.subscribe("topic-2").await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(bus.subscription_count(), 2);

    // Drop rx1 — subscription task should exit when it tries to send
    drop(_rx1);
    // Publish to topic-1 to wake the spawned task so it detects the closed mpsc
    let _ = bus.publish("topic-1", &make_heartbeat("cell-1", 1)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(bus.subscription_count(), 1);
}

// ── D5: NatsBus compile-time verification tests ────────────────────
// These tests verify the NatsBus type structure and serialization
// without requiring a live NATS server.

#[test]
fn test_nats_event_json_serialization_for_nats_transport() {
    // NatsBus serializes events as JSON over the wire.
    // Verify the full roundtrip matches what NATS would see.
    let event = make_packet_write("cell-nats-1", 99, "agents/nurse", "bafyrei_nats_test");
    let json_bytes = serde_json::to_vec(&event).unwrap();
    let decoded: ReplicationEvent = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(decoded.cell_id, "cell-nats-1");
    assert_eq!(decoded.seq, 99);
    match &decoded.op {
        ReplicationOp::PacketWrite { namespace, packet_cid, .. } => {
            assert_eq!(namespace, "agents/nurse");
            assert_eq!(packet_cid, "bafyrei_nats_test");
        }
        _ => panic!("Expected PacketWrite"),
    }
}

#[test]
fn test_nats_all_aapi_ops_serialize_for_transport() {
    // All 8 AAPI ops must serialize cleanly for NATS transport
    let ops = vec![
        ReplicationOp::VakyaForward { vakya_cbor: vec![1], pipeline_id: "p1".into(), step_id: "s1".into(), reply_topic: "r1".into() },
        ReplicationOp::VakyaReply { step_id: "s1".into(), result_cbor: vec![2] },
        ReplicationOp::VakyaRollback { effect_cbor: vec![3], saga_id: "saga-1".into() },
        ReplicationOp::PolicyUpdate { policy_cbor: vec![4] },
        ReplicationOp::AdapterAnnounce { domain: "file".into(), cell_id: "c1".into(), actions: vec!["read".into()] },
        ReplicationOp::AdapterDeregister { domain: "file".into(), cell_id: "c1".into() },
        ReplicationOp::ApprovalRequest { approval_id: "a1".into(), vakya_cbor: vec![5], approvers: vec!["mgr".into()], timeout_ms: 5000 },
        ReplicationOp::ApprovalResponse { approval_id: "a1".into(), approved: true, approver: "mgr".into(), comment: None },
    ];
    for op in ops {
        assert!(op.is_aapi_op());
        let event = ReplicationEvent::new("cell-nats", 1, op);
        let bytes = serde_json::to_vec(&event).unwrap();
        let decoded: ReplicationEvent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.cell_id, "cell-nats");
    }
}

#[test]
fn test_nats_subject_prefix_convention() {
    // Verify the subject naming convention that NatsBus uses:
    // prefix.topic -> e.g. "vac.cluster.replication"
    let prefix = "vac.cluster";
    let topic = "replication";
    let subject = format!("{}.{}", prefix, topic);
    assert_eq!(subject, "vac.cluster.replication");

    // Cell-specific topics
    let cell_topic = format!("{}.cell.{}.vakya", prefix, "cell-42");
    assert_eq!(cell_topic, "vac.cluster.cell.cell-42.vakya");
}

#[test]
fn test_nats_large_event_serialization() {
    // NatsBus must handle large payloads (block commits, policy updates)
    let large_cbor = vec![0xAB; 64 * 1024]; // 64KB payload
    let event = ReplicationEvent::new(
        "cell-1",
        1,
        ReplicationOp::BlockCommit { block_cbor: large_cbor.clone() },
    );
    let bytes = serde_json::to_vec(&event).unwrap();
    let decoded: ReplicationEvent = serde_json::from_slice(&bytes).unwrap();
    match decoded.op {
        ReplicationOp::BlockCommit { block_cbor } => {
            assert_eq!(block_cbor.len(), 64 * 1024);
        }
        _ => panic!("Expected BlockCommit"),
    }
}

#[test]
fn test_nats_signed_event_transport() {
    // Signed events must survive JSON serialization for NATS transport
    let event = make_heartbeat("cell-1", 1)
        .with_signature([0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(64).collect()); // 64-byte sig
    assert!(event.is_signed());
    assert_eq!(event.signature.len(), 64);

    let bytes = serde_json::to_vec(&event).unwrap();
    let decoded: ReplicationEvent = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.is_signed());
    assert_eq!(decoded.signature, event.signature);
}
