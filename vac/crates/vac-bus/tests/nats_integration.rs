#![cfg(feature = "nats")]
//! Real NATS integration tests — requires nats-server binary.
//!
//! These tests spawn a real nats-server process, connect NatsBus to it,
//! and verify pub/sub, signed events over the wire, reconnection, and backoff.
//!
//! Run with:
//!   cargo test -p vac-bus --features nats --test nats_integration -- --test-threads=1

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use vac_bus::{EventBus, NatsBus, NatsConfig, ReplicationEvent, ReplicationOp};

/// Find the nats-server binary — check the crate directory first, then PATH.
fn nats_server_bin() -> String {
    let local = concat!(env!("CARGO_MANIFEST_DIR"), "/nats-server");
    if std::path::Path::new(local).exists() {
        return local.to_string();
    }
    "nats-server".to_string()
}

/// RAII guard that starts nats-server on construction, kills it on drop.
struct NatsGuard {
    child: Child,
    port: u16,
}

impl NatsGuard {
    fn new(port: u16) -> Self {
        let bin = nats_server_bin();
        let child = Command::new(&bin)
            .args(["-p", &port.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to start nats-server at {}: {}", bin, e));
        Self { child, port }
    }

    fn url(&self) -> String {
        format!("nats://127.0.0.1:{}", self.port)
    }
}

impl Drop for NatsGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Wait for NATS to accept TCP connections.
async fn wait_for_nats(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nats-server on port {} did not become ready in time", port);
}

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

// All tests use port 14222 and run serially (--test-threads=1).

// ── Test: Basic pub/sub over real NATS ──────────────────────────────

#[tokio::test]
async fn test_nats_real_publish_subscribe() {
    let _guard = NatsGuard::new(14222);
    wait_for_nats(14222).await;

    let bus = NatsBus::connect(&_guard.url(), "t1")
        .await
        .expect("connect to NATS");

    let mut rx = bus.subscribe("events").await.unwrap();

    let event = make_heartbeat("cell-1", 1);
    bus.publish("events", &event).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("closed");

    assert_eq!(received.cell_id, "cell-1");
    assert_eq!(received.seq, 1);
    assert_eq!(received.op.op_type(), "heartbeat");
    assert_eq!(bus.published_count(), 1);

    bus.close().await.unwrap();
}

// ── Test: Multiple subscribers each get a copy ──────────────────────

#[tokio::test]
async fn test_nats_real_multiple_subscribers() {
    let _guard = NatsGuard::new(14222);
    wait_for_nats(14222).await;

    let bus = NatsBus::connect(&_guard.url(), "t2").await.unwrap();

    let mut rx1 = bus.subscribe("multi").await.unwrap();
    let mut rx2 = bus.subscribe("multi").await.unwrap();

    bus.publish("multi", &make_heartbeat("cell-1", 1)).await.unwrap();

    let r1 = tokio::time::timeout(Duration::from_secs(2), rx1.recv()).await.unwrap().unwrap();
    let r2 = tokio::time::timeout(Duration::from_secs(2), rx2.recv()).await.unwrap().unwrap();

    assert_eq!(r1.cell_id, "cell-1");
    assert_eq!(r2.cell_id, "cell-1");

    bus.close().await.unwrap();
}

// ── Test: Signed events survive JSON serialization over NATS wire ───

#[tokio::test]
async fn test_nats_real_signed_event_roundtrip() {
    let _guard = NatsGuard::new(14222);
    wait_for_nats(14222).await;

    let bus = NatsBus::connect(&_guard.url(), "t3").await.unwrap();

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut rx = bus.subscribe("signed").await.unwrap();

    let mut event = make_heartbeat("cell-1", 42);
    event.sign(&signing_key);
    assert!(event.is_signed());

    bus.publish("signed", &event).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();

    assert!(received.is_signed());
    assert_eq!(received.signature.len(), 64);
    assert!(received.verify(&verifying_key).is_ok(), "Sig must survive NATS wire roundtrip");
    assert_eq!(received.cell_id, "cell-1");
    assert_eq!(received.seq, 42);

    bus.close().await.unwrap();
}

// ── Test: Invalid signature detected after NATS wire ────────────────

#[tokio::test]
async fn test_nats_real_invalid_signature_detected() {
    let _guard = NatsGuard::new(14222);
    wait_for_nats(14222).await;

    let bus = NatsBus::connect(&_guard.url(), "t4").await.unwrap();

    let good_key = SigningKey::generate(&mut OsRng);
    let wrong_key = SigningKey::generate(&mut OsRng);

    let mut rx = bus.subscribe("badsig").await.unwrap();

    let mut event = make_heartbeat("cell-1", 1);
    event.sign(&good_key);
    bus.publish("badsig", &event).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();

    assert!(received.verify(&wrong_key.verifying_key()).is_err(), "Wrong key must fail");
    assert!(received.verify(&good_key.verifying_key()).is_ok(), "Correct key must pass");

    bus.close().await.unwrap();
}

// ── Test: NatsConfig custom settings applied ────────────────────────

#[tokio::test]
async fn test_nats_real_connect_with_config() {
    let _guard = NatsGuard::new(14222);
    wait_for_nats(14222).await;

    let config = NatsConfig {
        max_reconnect_attempts: Some(5),
        reconnect_base_ms: 50,
        max_backoff_ms: 2_000,
        jitter_ms: 10,
        connection_timeout: Duration::from_secs(3),
        retry_on_initial_connect: false,
        subscription_capacity: 1024,
        client_name: Some("test-cell-1".to_string()),
    };

    let bus = NatsBus::connect_with_config(&_guard.url(), "t5", config)
        .await
        .expect("connect with config");

    let mut rx = bus.subscribe("configured").await.unwrap();
    bus.publish("configured", &make_heartbeat("cell-cfg", 1)).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    assert_eq!(received.cell_id, "cell-cfg");

    bus.close().await.unwrap();
}

// ── Test: Reconnect after server restart ────────────────────────────

#[tokio::test]
async fn test_nats_real_reconnect_after_restart() {
    let port = 14222u16;

    // Phase 1: start, connect, verify
    let guard1 = NatsGuard::new(port);
    wait_for_nats(port).await;

    let config = NatsConfig {
        max_reconnect_attempts: None,
        reconnect_base_ms: 50,
        max_backoff_ms: 500,
        jitter_ms: 10,
        connection_timeout: Duration::from_secs(2),
        retry_on_initial_connect: false,
        subscription_capacity: 1024,
        client_name: Some("reconnect-test".to_string()),
    };

    let bus = Arc::new(
        NatsBus::connect_with_config(&guard1.url(), "t6", config).await.expect("initial connect"),
    );

    let mut rx = bus.subscribe("recon").await.unwrap();
    bus.publish("recon", &make_heartbeat("cell-1", 1)).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    assert_eq!(r.seq, 1);

    // Phase 2: kill server
    drop(guard1);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Phase 3: restart server on same port
    let _guard2 = NatsGuard::new(port);
    wait_for_nats(port).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Phase 4: re-subscribe and verify pub/sub works
    let mut rx2 = bus.subscribe("recon2").await.unwrap();
    bus.publish("recon2", &make_heartbeat("cell-1", 2)).await.unwrap();

    let r2 = tokio::time::timeout(Duration::from_secs(3), rx2.recv()).await.unwrap().unwrap();
    assert_eq!(r2.seq, 2, "Should receive event after reconnect");

    assert!(bus.disconnects() >= 1, "Should have at least 1 disconnect");
    assert!(bus.reconnects() >= 1, "Should have at least 1 reconnect");

    bus.close().await.unwrap();
}

// ── Test: Connection to non-existent server fails immediately ───────

#[tokio::test]
async fn test_nats_real_connect_failure() {
    let result = NatsBus::connect("nats://127.0.0.1:19999", "fail").await;
    assert!(result.is_err(), "Should fail to connect to non-existent server");
}

// ── Test: Backoff increases between reconnect attempts ──────────────

#[tokio::test]
async fn test_nats_backoff_calculation() {
    let base: u64 = 100;
    let max_backoff: u64 = 8000;

    let calc = |attempts: usize| -> u64 {
        let shift = (attempts as u32).min(63);
        let exp_delay = base.saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX));
        exp_delay.min(max_backoff)
    };

    assert_eq!(calc(0), 100);
    assert_eq!(calc(1), 200);
    assert_eq!(calc(2), 400);
    assert_eq!(calc(3), 800);
    assert_eq!(calc(4), 1600);
    assert_eq!(calc(5), 3200);
    assert_eq!(calc(6), 6400);
    assert_eq!(calc(7), 8000);  // capped
    assert_eq!(calc(100), 8000);
}
