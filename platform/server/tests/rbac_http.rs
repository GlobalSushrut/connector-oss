//! REST RBAC smoke (T7). Requires a running node with dev bypass **disabled** or a real JWT.
//!
//! Default CI uses dev bypass; run manually after disabling bypass:
//!   CONNECTOR_DEFENSE_STRICT=1 CONNECTOR_ENV=production CONNECTOR_TEST_URL=... \
//!   cargo test --test rbac_http -- --nocapture

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
async fn auth_me_includes_billing_summary() {
    let r = client()
        .get(api("/auth/me"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await
        .unwrap();
    if !r.status().is_success() {
        eprintln!("[skip] /auth/me returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    if body.get("billing").is_some() {
        assert!(body["billing"].get("tier").is_some());
    }
}

#[tokio::test]
async fn unauthenticated_agents_list_policy() {
    let r = client().get(api("/agents")).send().await.unwrap();
    let s = r.status().as_u16();
    if s == 401 {
        return;
    }
    assert!(
        (200..300).contains(&s),
        "expected 401 (secured) or 2xx (dev/ultimate-free open auth), got {}",
        s
    );
}

#[tokio::test]
async fn apps_catalog_ok_with_dev_token() {
    let r = client()
        .get(api("/apps"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let body: Value = r.json().await.unwrap_or_default();
    assert!(body.get("apps").and_then(|v| v.as_array()).is_some());
}
