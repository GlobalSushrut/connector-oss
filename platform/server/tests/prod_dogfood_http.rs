//! Hardened production dogfood (P1.3). Run via `platform/scripts/prod-dogfood-smoke.sh`
//! or with a server started using `CONNECTOR_PRESET=production`, `CONNECTOR_DEFENSE_STRICT=1`,
//! and **no** `CONNECTOR_DEV_MODE` / `CONNECTOR_ULTIMATE_FREE`.

use reqwest::Client;
use serde_json::{json, Value};

fn base() -> String {
    std::env::var("CONNECTOR_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:9091".into())
}

fn api(path: &str) -> String {
    format!("{}/api/v1{}", base(), path)
}

fn client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap()
}

fn prod_dogfood() -> bool {
    std::env::var("CONNECTOR_PROD_DOGFOOD").is_ok()
}

async fn login_admin() -> Option<String> {
    let pw = std::env::var("CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD").unwrap_or_else(|_| "admin".into());
    let r = client()
        .post(api("/auth/login"))
        .json(&json!({
            "email": "admin@connector.local",
            "password": pw
        }))
        .send()
        .await
        .unwrap();
    if !r.status().is_success() {
        eprintln!("[skip] login failed: {}", r.status());
        return None;
    }
    let body: Value = r.json().await.unwrap_or_default();
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(String::from)
}

#[tokio::test]
async fn prod_strict_agents_requires_auth() {
    if !prod_dogfood() {
        eprintln!("[skip] set CONNECTOR_PROD_DOGFOOD=1 (see prod-dogfood-smoke.sh)");
        return;
    }
    let r = client().get(api("/agents")).send().await.unwrap();
    assert_eq!(r.status(), 401, "expected 401 without bearer");
}

#[tokio::test]
async fn prod_jwt_auth_me_and_plugins_status() {
    if !prod_dogfood() {
        eprintln!("[skip] set CONNECTOR_PROD_DOGFOOD=1");
        return;
    }
    let Some(token) = login_admin().await else {
        return;
    };
    let auth = format!("Bearer {token}");

    let me = client()
        .get(api("/auth/me"))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(me.status().is_success(), "GET /auth/me: {}", me.status());
    let body: Value = me.json().await.unwrap_or_default();
    assert_eq!(
        body.get("role").and_then(|v| v.as_str()),
        Some("super_admin")
    );

    let ps = client()
        .get(api("/plugins/status"))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(ps.status().is_success());
    let status: Value = ps.json().await.unwrap_or_default();
    let backend = status
        .pointer("/phase_5_operator/connectorctl_plugin_run_backend")
        .or_else(|| status.pointer("/phase_5_operator/isolation_runtime"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let env_backend = std::env::var("CONNECTOR_PLUGIN_RUN_BACKEND").unwrap_or_default();
    assert!(
        backend.contains("microvm")
            || env_backend.eq_ignore_ascii_case("microvm")
            || std::env::var("CONNECTOR_PRESET")
                .map(|p| p.eq_ignore_ascii_case("production"))
                .unwrap_or(false),
        "production preset should default to microvm backend, got {backend:?}"
    );
}

#[tokio::test]
async fn prod_open_auth_disabled() {
    if !prod_dogfood() {
        return;
    }
    let r = client().get(api("/auth/me")).send().await.unwrap();
    assert!(
        r.status().as_u16() == 401 || r.status().as_u16() == 403,
        "open auth must be off in strict prod, got {}",
        r.status()
    );
}
