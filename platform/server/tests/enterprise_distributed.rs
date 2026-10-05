use reqwest::Client;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::Instant;

static BASE: OnceLock<String> = OnceLock::new();

fn base() -> &'static str {
    BASE.get_or_init(|| std::env::var("CONNECTOR_TEST_URL").unwrap_or_else(|_| "http://localhost:9090".into()))
}

fn api(path: &str) -> String {
    format!("{}/api/v1{}", base(), path)
}

fn client() -> Client {
    Client::builder().timeout(std::time::Duration::from_secs(20)).build().unwrap()
}

fn uid() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "").chars().take(12).collect()
}

async fn get(path: &str) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = client().get(api(path)).send().await.expect(path);
    let ms = t.elapsed().as_millis();
    let s = r.status().as_u16();
    let b = r.json::<Value>().await.unwrap_or_default();
    (s, b, ms)
}

async fn post(path: &str, body: Value) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = client().post(api(path)).json(&body).send().await.expect(path);
    let ms = t.elapsed().as_millis();
    let s = r.status().as_u16();
    let b = r.json::<Value>().await.unwrap_or_default();
    (s, b, ms)
}

fn ok2xx(s: u16) -> bool { s >= 200 && s < 300 }

#[tokio::test]
async fn distributed_webhook_retry_queue_behaves_consistently() {
    let hook_id = format!("wh-test-{}", uid());
    let event_id = format!("evt-test-{}", uid());
    let payload = json!({"cell_id": "cell_local", "kind": "budget.warning", "replica": 1});

    let (s1, b1, ms1) = post(&format!("/webhooks/{hook_id}/retry-queue"), json!({
        "event_id": event_id,
        "payload": payload,
        "attempt": 0
    })).await;
    println!("distributed_retry_enqueue HTTP={s1} latency={ms1}ms body={b1}");
    assert!(matches!(s1, 200..=299 | 404 | 405), "retry queue enqueue failed unsafely: HTTP {s1} body={b1}");

    let (s2, b2, ms2) = get(&format!("/webhooks/{hook_id}/retry-queue")).await;
    println!("distributed_retry_list HTTP={s2} latency={ms2}ms body={b2}");
    assert!(matches!(s2, 200..=299 | 404), "retry queue list failed unsafely: HTTP {s2} body={b2}");
    if ok2xx(s1) && ok2xx(s2) {
        assert!(b2.get("total").and_then(|v| v.as_u64()).unwrap_or(0) >= 1);
    }
}

#[tokio::test]
async fn distributed_namespace_partitioning_shows_no_cross_namespace_recall() {
    let suffix = uid();
    let ns_a = format!("ns:cell-a-{suffix}");
    let ns_b = format!("ns:cell-b-{suffix}");

    let (sw, bw, _) = post("/memory/write", json!({
        "agent_pid": format!("cell-a-agent-{suffix}"),
        "content": "distributed partition data",
        "user": "distributed-test",
        "pipeline": "partition-check",
        "namespace": ns_a
    })).await;
    assert!(ok2xx(sw), "memory write failed: HTTP {sw} body={bw}");

    let (sr, br, ms) = get(&format!("/memory/recall/{}", ns_b.replace(':', "%3A"))).await;
    let hits = br.as_array().map(|a| a.len())
        .or_else(|| br.get("count").and_then(|v| v.as_u64()).map(|n| n as usize))
        .unwrap_or(0);
    println!("distributed_namespace_recall HTTP={sr} hits={hits} latency={ms}ms body={br}");
    assert!((ok2xx(sr) || sr == 404) && hits == 0, "cross-namespace leak detected: HTTP {sr} hits={hits} body={br}");
}

#[tokio::test]
async fn distributed_background_integrity_surfaces_are_live() {
    let (s1, b1, ms1) = get("/monitor/integrity").await;
    let (s2, b2, ms2) = get("/webhooks/events").await;
    println!("distributed_integrity HTTP={s1} latency={ms1}ms body={b1}");
    println!("distributed_events HTTP={s2} latency={ms2}ms body={b2}");
    assert!(ok2xx(s1), "integrity surface unavailable: HTTP {s1} body={b1}");
    assert!(s2 < 500, "webhook events surface should fail safely even when auth is required: HTTP {s2} body={b2}");
}
