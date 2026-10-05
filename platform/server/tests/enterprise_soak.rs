use reqwest::Client;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static BASE: OnceLock<String> = OnceLock::new();

fn base() -> &'static str {
    BASE.get_or_init(|| std::env::var("CONNECTOR_TEST_URL").unwrap_or_else(|_| "http://localhost:9090".into()))
}

fn api(path: &str) -> String {
    format!("{}/api/v1{}", base(), path)
}

fn client() -> Client {
    Client::builder().timeout(Duration::from_secs(20)).build().unwrap()
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
async fn soak_laptop_controlled_stability_window() {
    let iterations: usize = std::env::var("CONNECTOR_SOAK_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(12);
    let sleep_ms: u64 = std::env::var("CONNECTOR_SOAK_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(250);
    let ns = format!("ns:soak-{}", uid());
    let agent = format!("soak-agent-{}", uid());

    let mut failures = 0usize;
    let mut max_latency = 0u128;

    for i in 0..iterations {
        let (sw, bw, mw) = post("/memory/write", json!({
            "agent_pid": agent,
            "content": format!("soak packet {i}"),
            "user": "soak",
            "pipeline": "stability",
            "namespace": ns
        })).await;
        max_latency = max_latency.max(mw);
        if !ok2xx(sw) { failures += 1; }

        let (sh, bh, mh) = get("/monitor/health").await;
        max_latency = max_latency.max(mh);
        if !ok2xx(sh) { failures += 1; }

        let (si, bi, mi) = get("/monitor/integrity").await;
        max_latency = max_latency.max(mi);
        if !ok2xx(si) { failures += 1; }

        let (sf, bf, mf) = post("/firewall/inspect", json!({
            "content": format!("soak benign content iteration {i}"),
            "agent_pid": agent,
            "namespace": "enterprise"
        })).await;
        max_latency = max_latency.max(mf);
        if !ok2xx(sf) { failures += 1; }

        println!("soak_iter={i} write={sw}/{mw}ms health={sh}/{mh}ms integrity={si}/{mi}ms firewall={sf}/{mf}ms");
        let _ = (bw, bh, bi, bf);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    let error_rate = failures as f64 / (iterations as f64 * 4.0);
    println!("soak_summary iterations={iterations} failures={failures} error_rate={error_rate:.3} max_latency_ms={max_latency}");
    assert!(error_rate <= 0.10, "soak instability too high: failures={failures} error_rate={error_rate:.3}");
}
