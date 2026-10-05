//! Ultimate Free open-auth smoke. Requires a running node started with:
//!   CONNECTOR_ENV=production CONNECTOR_ULTIMATE_FREE=1 CONNECTOR_DEV_MODE unset

use reqwest::Client;
use serde_json::Value;

fn base() -> String {
    std::env::var("CONNECTOR_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:9091".into())
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

#[tokio::test]
async fn open_auth_me_without_bearer() {
    if std::env::var("CONNECTOR_ULTIMATE_FREE").is_err() {
        eprintln!("[skip] Set CONNECTOR_ULTIMATE_FREE=1 on the server under test");
        return;
    }
    let r = client().get(api("/auth/me")).send().await.unwrap();
    assert!(
        r.status().is_success(),
        "GET /auth/me without token expected 2xx, got {}",
        r.status()
    );
    let body: Value = r.json().await.unwrap_or_default();
    assert!(body.get("user_id").is_some());
    assert_eq!(
        body.get("role").and_then(|v| v.as_str()),
        Some("super_admin")
    );
}

#[tokio::test]
async fn open_auth_agents_without_bearer() {
    if std::env::var("CONNECTOR_ULTIMATE_FREE").is_err() {
        eprintln!("[skip] Set CONNECTOR_ULTIMATE_FREE=1 on the server under test");
        return;
    }
    let r = client().get(api("/agents")).send().await.unwrap();
    assert!(
        r.status().is_success(),
        "GET /agents without token expected 2xx, got {}",
        r.status()
    );
}
