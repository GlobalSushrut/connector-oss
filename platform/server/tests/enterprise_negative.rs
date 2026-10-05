use reqwest::Client;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::Instant;

static BASE: OnceLock<String> = OnceLock::new();

fn base() -> &'static str {
    BASE.get_or_init(|| {
        std::env::var("CONNECTOR_TEST_URL")
            .unwrap_or_else(|_| "http://localhost:9090".into())
    })
}

fn api(path: &str) -> String {
    format!("{}/api/v1{}", base(), path)
}

fn client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(15))
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

async fn post(path: &str, body: Value) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = client().post(api(path)).json(&body).send().await.expect(path);
    let ms = t.elapsed().as_millis();
    let s = r.status().as_u16();
    let b = r.json::<Value>().await.unwrap_or_default();
    (s, b, ms)
}

fn safe_failure(status: u16, body: &Value) -> bool {
    status < 500 && !body.to_string().to_lowercase().contains("panic")
}

#[tokio::test]
async fn negative_auth_payloads_fail_safely() {
    let cases = vec![
        json!({"name": "", "email": "not-an-email", "password": "short"}),
        json!({"name": "x", "email": "x@example.com", "password": "alllowercase1"}),
        json!({"email": "missing-name@example.com", "password": "Valid$Pass123"}),
        json!({"name": 42, "email": ["bad"], "password": {"oops": true}}),
    ];

    for (i, body) in cases.into_iter().enumerate() {
        let (s, b, ms) = post("/auth/signup", body).await;
        println!("negative_auth_signup[{i}] HTTP={s} latency={ms}ms body={b}");
        assert!(safe_failure(s, &b), "signup malformed payload caused unsafe failure: HTTP {s} body={b}");
    }

    let login_cases = vec![
        json!({"email": "", "password": ""}),
        json!({"email": ["bad"], "password": 7}),
        json!({"user": "legacy-only-without-password"}),
    ];

    for (i, body) in login_cases.into_iter().enumerate() {
        let (s, b, ms) = post("/auth/login", body).await;
        println!("negative_auth_login[{i}] HTTP={s} latency={ms}ms body={b}");
        assert!(safe_failure(s, &b), "login malformed payload caused unsafe failure: HTTP {s} body={b}");
    }
}

#[tokio::test]
async fn negative_memory_and_secret_inputs_fail_safely() {
    let bad_ns = format!("bad ns with spaces/{}", uid());
    let cases = vec![
        ("/memory/write", json!({"agent_pid": "", "content": "", "namespace": bad_ns})),
        ("/memory/write", json!({"agent_pid": 7, "content": [1,2,3], "namespace": false})),
        ("/secrets/store", json!({"secret_id": "", "agent_pid": "", "value": "x"})),
        ("/secrets/handle", json!({"secret_id": 999, "agent_pid": ["bad"]})),
        ("/secrets/resolve", json!({"handle_id": "does-not-exist", "requesting_pid": "ghost"})),
    ];

    for (i, (path, body)) in cases.into_iter().enumerate() {
        let (s, b, ms) = post(path, body).await;
        println!("negative_stateful[{i}] path={path} HTTP={s} latency={ms}ms body={b}");
        assert!(safe_failure(s, &b), "{path} malformed payload caused unsafe failure: HTTP {s} body={b}");
    }
}

#[tokio::test]
async fn negative_webhook_and_verify_inputs_fail_safely() {
    let cases = vec![
        ("/webhooks/nonexistent/retry-queue", json!({"event_id": 7, "payload": "bad", "attempt": -1})),
        ("/webhooks/nonexistent/test", json!({"event_type": 123})),
    ];

    for (i, (path, body)) in cases.into_iter().enumerate() {
        let (s, b, ms) = post(path, body).await;
        println!("negative_webhook[{i}] path={path} HTTP={s} latency={ms}ms body={b}");
        assert!(safe_failure(s, &b), "{path} malformed payload caused unsafe failure: HTTP {s} body={b}");
    }

    let (s, b, ms) = get("/verify/invariants/does-not-exist").await;
    println!("negative_verify HTTP={s} latency={ms}ms body={b}");
    assert!(safe_failure(s, &b), "verify invalid invariant caused unsafe failure: HTTP {s} body={b}");
}
