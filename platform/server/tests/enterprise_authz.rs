use reqwest::{Client, header::{AUTHORIZATION, HeaderMap, HeaderValue}};
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

fn client_with_token(token: Option<&str>) -> Client {
    let mut headers = HeaderMap::new();
    if let Some(t) = token {
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {t}")).unwrap());
    }
    Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap()
}

fn uid() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "").chars().take(12).collect()
}

async fn post_anon(path: &str, body: Value) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = Client::new().post(api(path)).json(&body).send().await.expect(path);
    let ms = t.elapsed().as_millis();
    let s = r.status().as_u16();
    let b = r.json::<Value>().await.unwrap_or_default();
    (s, b, ms)
}

async fn get_token(path: &str, token: Option<&str>) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = client_with_token(token).get(api(path)).send().await.expect(path);
    let ms = t.elapsed().as_millis();
    let s = r.status().as_u16();
    let b = r.json::<Value>().await.unwrap_or_default();
    (s, b, ms)
}

async fn post_token(path: &str, body: Value, token: Option<&str>) -> (u16, Value, u128) {
    let t = Instant::now();
    let r = client_with_token(token).post(api(path)).json(&body).send().await.expect(path);
    let ms = t.elapsed().as_millis();
    let s = r.status().as_u16();
    let b = r.json::<Value>().await.unwrap_or_default();
    (s, b, ms)
}

async fn signup_and_login(name: &str, email: &str, password: &str) -> (String, String) {
    let _ = post_anon("/auth/signup", json!({
        "name": name,
        "email": email,
        "password": password
    })).await;
    let (_, b, _) = post_anon("/auth/login", json!({
        "email": email,
        "password": password
    })).await;
    let token = b.get("access_token").or_else(|| b.get("jwt")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let role = b.get("user").and_then(|u| u.get("role")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    (token, role)
}

#[tokio::test]
async fn authz_missing_and_invalid_tokens_are_denied() {
    let (s1, b1, _) = get_token("/auth/me", None).await;
    let (s2, b2, _) = get_token("/auth/me", Some("not-a-real-token")).await;
    println!("authz_no_token HTTP={s1} body={b1}");
    println!("authz_bad_token HTTP={s2} body={b2}");
    let denied1 = matches!(s1, 401 | 403)
        || b1.get("status").and_then(|v| v.as_u64()).map(|v| v == 401 || v == 403).unwrap_or(false)
        || b1.to_string().to_lowercase().contains("unauthorized");
    let denied2 = matches!(s2, 401 | 403)
        || b2.get("status").and_then(|v| v.as_u64()).map(|v| v == 401 || v == 403).unwrap_or(false)
        || b2.to_string().to_lowercase().contains("unauthorized");
    assert!(denied1, "missing token should be denied: HTTP {s1} body={b1}");
    assert!(denied2, "invalid token should be denied: HTTP {s2} body={b2}");
}

#[tokio::test]
async fn authz_real_token_can_reach_me_endpoint() {
    let email = format!("authz-{}@example.com", uid());
    let (token, role) = signup_and_login("Authz User", &email, "Authz$Pass2026").await;
    let (s, b, ms) = get_token("/auth/me", Some(&token)).await;
    println!("authz_me HTTP={s} role={role} latency={ms}ms body={b}");
    assert!(s >= 200 && s < 300, "valid token should access /auth/me: HTTP {s} body={b}");
}

#[tokio::test]
async fn authz_developer_cannot_use_operator_webhook_routes() {
    let email = format!("authz-dev-{}@example.com", uid());
    let (token, role) = signup_and_login("Developer User", &email, "DevOnly$Pass2026").await;
    let (s, b, ms) = post_token("/webhooks", json!({
        "name": "Denied Hook",
        "url": "https://example.invalid/hook",
        "events": ["test.ping"]
    }), Some(&token)).await;
    println!("authz_webhook_create HTTP={s} role={role} latency={ms}ms body={b}");
    assert!(matches!(s, 401 | 403) || b.get("status").and_then(|v| v.as_u64()) == Some(403));
}

#[tokio::test]
async fn authz_invalid_refresh_token_is_rejected() {
    let (s, b, ms) = post_anon("/auth/refresh", json!({"refresh_token": "definitely-invalid"})).await;
    println!("authz_refresh HTTP={s} latency={ms}ms body={b}");
    assert!(s < 500, "invalid refresh token should not 500: HTTP {s} body={b}");
    assert!(b.to_string().to_lowercase().contains("invalid") || b.to_string().to_lowercase().contains("error"));
}
