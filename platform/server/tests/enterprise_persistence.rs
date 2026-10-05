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

fn client_with_token(token: &str) -> Client {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap()
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

async fn get_token(path: &str, token: &str) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = client_with_token(token)
        .get(api(path))
        .send()
        .await
        .expect(path);
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

async fn post_token(path: &str, body: Value, token: &str) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = client_with_token(token)
        .post(api(path))
        .json(&body)
        .send()
        .await
        .expect(path);
    let ms = t.elapsed().as_millis();
    let s = r.status().as_u16();
    let b = r.json::<Value>().await.unwrap_or_default();
    (s, b, ms)
}

async fn auth_token_for_persistence() -> String {
    let email = format!("persist-{}@example.com", uid());
    let password = "Persist$Pass2026";
    let _ = post("/auth/signup", json!({
        "name": "Persistence Test User",
        "email": email,
        "password": password,
    })).await;
    let (_, body, _) = post("/auth/login", json!({
        "email": email,
        "password": password,
    })).await;
    body.get("access_token")
        .or_else(|| body.get("jwt"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn ok2xx(s: u16) -> bool { s >= 200 && s < 300 }

#[tokio::test]
async fn persistence_prereq_sqlite_mode_visible() {
    let storage = std::env::var("CONNECTOR_ENGINE_STORAGE").unwrap_or_default();
    println!("persistence_storage={storage}");
    if storage.is_empty() {
        println!("persistence note: set CONNECTOR_ENGINE_STORAGE=sqlite:/path/to/db for restart-survival evidence");
    }
    let (s, b, ms) = get("/monitor/health").await;
    println!("persistence_health HTTP={s} latency={ms}ms body={b}");
    assert!(ok2xx(s), "health unavailable before persistence checks: HTTP {s} body={b}");
}

#[tokio::test]
async fn persistence_write_then_verify_current_state() {
    let suffix = uid();
    let ns = format!("ns:persist-{suffix}");
    let token = auth_token_for_persistence().await;
    assert!(!token.is_empty(), "failed to obtain auth token for persistence test");

    let (sa, ba, _) = post_token("/agents", json!({
        "name": format!("Persist Agent {suffix}"),
        "namespace": ns,
        "role": "writer",
        "model": "gpt-4o-mini",
        "token_budget": 10000,
        "instructions": "Persistence control test"
    }), &token).await;
    assert!(ok2xx(sa), "agent registration failed: HTTP {sa} body={ba}");
    let agent = ba.get("pid").or_else(|| ba.get("agent_pid"))
        .and_then(|v| v.as_str()).unwrap_or("");
    assert!(!agent.is_empty(), "agent registration missing pid: body={ba}");

    let (sw, bw, _) = post("/memory/write", json!({
        "agent_pid": agent,
        "content": "persistence control packet",
        "user": "persistence",
        "pipeline": "control",
        "namespace": ns
    })).await;
    assert!(ok2xx(sw), "memory write failed: HTTP {sw} body={bw}");

    let (si, bi, _) = get("/monitor/integrity").await;
    assert!(ok2xx(si), "integrity failed before restart phase: HTTP {si} body={bi}");
}

#[tokio::test]
async fn persistence_controlled_restart_mode() {
    if std::env::var("CONNECTOR_CONTROLLED_RESTART").ok().as_deref() != Some("1") {
        println!("persistence controlled restart skipped: set CONNECTOR_CONTROLLED_RESTART=1 and point CONNECTOR_TEST_URL at a managed SQLite-backed server");
        return;
    }

    let ns = std::env::var("CONNECTOR_PERSIST_NS")
        .unwrap_or_else(|_| "ns:persist-restart-fixed".into());
    let agent = std::env::var("CONNECTOR_PERSIST_AGENT")
        .unwrap_or_else(|_| "persist-restart-agent-fixed".into());
    let expected_content = std::env::var("CONNECTOR_PERSIST_CONTENT")
        .unwrap_or_else(|_| "restart-survival packet".into());
    let phase = std::env::var("CONNECTOR_RESTART_PHASE").unwrap_or_else(|_| "pre".into());
    println!("persistence_controlled_phase={phase} namespace={ns} agent={agent}");

    if phase == "pre" {
        let token = auth_token_for_persistence().await;
        assert!(!token.is_empty(), "failed to obtain auth token for persistence controlled restart test");

        let (sa, ba, _) = post_token("/agents", json!({
            "name": format!("Persist Restart Agent {}", agent),
            "namespace": ns,
            "role": "writer",
            "model": "gpt-4o-mini",
            "token_budget": 10000,
            "instructions": "Persistence controlled restart test"
        }), &token).await;
        assert!(ok2xx(sa), "pre-restart agent registration failed: HTTP {sa} body={ba}");
        let registered_pid = ba.get("pid").or_else(|| ba.get("agent_pid"))
            .and_then(|v| v.as_str()).unwrap_or("");
        assert!(!registered_pid.is_empty(), "pre-restart registration missing pid: body={ba}");
        println!("persistence_registered_pid={registered_pid}");

        let pid_encoded = registered_pid.replace(':', "%3A");
        let (sg, bg, _) = get_token(&format!("/agents/{pid_encoded}"), &token).await;
        assert!(ok2xx(sg),
            "pre-restart registry inconsistency: register returned pid '{registered_pid}' but GET /agents/{{pid}} failed: HTTP {sg} body={bg}");

        let (sw, bw, _) = post("/memory/write", json!({
            "agent_pid": registered_pid,
            "content": expected_content,
            "user": "persistence",
            "pipeline": "restart",
            "namespace": ns
        })).await;
        assert!(ok2xx(sw), "pre-restart write failed: HTTP {sw} body={bw}");
        assert!(bw.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
            "pre-restart write returned non-success body: HTTP {sw} body={bw}");

        let (sr, br, ms) = get(&format!("/memory/recall/{}", ns.replace(':', "%3A"))).await;
        println!("persistence_pre_restart_recall HTTP={sr} latency={ms}ms body={br}");
        assert!(ok2xx(sr), "pre-restart recall failed: HTTP {sr} body={br}");
        let hits = br.as_array().map(|a| a.len())
            .or_else(|| br.get("count").and_then(|v| v.as_u64()).map(|n| n as usize))
            .or_else(|| br.get("results").and_then(|v| v.as_array()).map(|a| a.len()))
            .or_else(|| br.get("packets").and_then(|v| v.as_array()).map(|a| a.len()))
            .unwrap_or(0);
        let body_text = br.to_string();
        assert!(hits > 0, "pre-restart recall returned no hits: HTTP {sr} body={br}");
        assert!(body_text.contains(&expected_content),
            "pre-restart recall missing expected content '{expected_content}': body={br}");
    }

    if phase == "post" {
        let (sr, br, ms) = get(&format!("/memory/recall/{}", ns.replace(':', "%3A"))).await;
        println!("persistence_post_restart HTTP={sr} latency={ms}ms body={br}");
        assert!(ok2xx(sr), "post-restart recall failed: HTTP {sr} body={br}");
        let hits = br.as_array().map(|a| a.len())
            .or_else(|| br.get("count").and_then(|v| v.as_u64()).map(|n| n as usize))
            .or_else(|| br.get("results").and_then(|v| v.as_array()).map(|a| a.len()))
            .or_else(|| br.get("packets").and_then(|v| v.as_array()).map(|a| a.len()))
            .unwrap_or(0);
        let body_text = br.to_string();
        assert!(hits > 0, "post-restart recall returned no hits: HTTP {sr} body={br}");
        assert!(body_text.contains(&expected_content),
            "post-restart recall missing expected content '{expected_content}': body={br}");
        let (si, bi, _) = get("/monitor/integrity").await;
        assert!(ok2xx(si), "post-restart integrity failed: HTTP {si} body={bi}");
    }
}
