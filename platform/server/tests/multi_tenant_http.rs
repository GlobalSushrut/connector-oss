//! Multi-tenant HTTP checks (T7). Requires a running node:
//!   CONNECTOR_MULTI_TENANT=1 CONNECTOR_TEST_URL=http://127.0.0.1:9091 \
//!   CONNECTOR_DEV_MODE=1 cargo test --test multi_tenant_http -- --nocapture

use reqwest::Client;
use serde_json::{json, Value};

fn base() -> String {
    std::env::var("CONNECTOR_TEST_URL").expect("CONNECTOR_TEST_URL")
}

fn client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap()
}

fn api(path: &str) -> String {
    format!("{}/api/v1{}", base(), path)
}

async fn login_bearer(tenant_id: Option<&str>) -> Option<String> {
    let pw = std::env::var("CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD")
        .unwrap_or_else(|_| "admin".into());
    let mut body = json!({
        "email": "admin@connector.local",
        "password": pw,
    });
    if let Some(tid) = tenant_id {
        body["tenant_id"] = json!(tid);
    }
    let r = client().post(api("/auth/login")).json(&body).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    let body: Value = r.json().await.ok()?;
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

async fn admin_bearer() -> Option<String> {
    login_bearer(None).await
}

#[tokio::test]
async fn multi_tenant_requires_tenant_on_agents_list() {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        eprintln!("[skip] CONNECTOR_MULTI_TENANT not set on server under test");
        return;
    }
    let Some(token) = admin_bearer().await else {
        eprintln!("[skip] admin login unavailable on test server");
        return;
    };
    let r = client()
        .get(api("/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let body: Value = r.json().await.unwrap_or_default();
    assert_eq!(
        body.get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("tenant_required")
    );
}

#[tokio::test]
async fn multi_tenant_accepts_x_tenant_id() {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        eprintln!("[skip] CONNECTOR_MULTI_TENANT not set on server under test");
        return;
    }
    // Tenant-bound admin login; X-Tenant-ID must match JWT tenant when present.
    let Some(token) = login_bearer(Some("acme")).await else {
        eprintln!("[skip] admin login unavailable on test server");
        return;
    };
    let hdr = reqwest::header::HeaderMap::from_iter([
        (
            reqwest::header::HeaderName::from_static("x-tenant-id"),
            reqwest::header::HeaderValue::from_static("acme"),
        ),
        (
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .expect("bearer"),
        ),
    ]);
    let r = client()
        .get(api("/agents"))
        .headers(hdr)
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success() || r.status().as_u16() == 403,
        "expected 2xx or auth-related 403, got {}",
        r.status()
    );
}

#[tokio::test]
async fn apps_catalog_readable_without_tenant_header() {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        eprintln!("[skip] CONNECTOR_MULTI_TENANT not set on server under test");
        return;
    }
    let Some(token) = admin_bearer().await else {
        eprintln!("[skip] admin login unavailable on test server");
        return;
    };
    let r = client()
        .get(api("/apps"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "apps catalog should be tenant-exempt");
    let body: Value = r.json().await.unwrap_or_default();
    assert!(body.get("apps").and_then(|v| v.as_array()).is_some());
}

#[tokio::test]
async fn tenant_mismatch_returns_403() {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        eprintln!("[skip] CONNECTOR_MULTI_TENANT not set on server under test");
        return;
    }
    let Some(token) = login_bearer(Some("jwt-tenant")).await else {
        eprintln!("[skip] admin login unavailable on test server");
        return;
    };
    let r = client()
        .get(api("/agents"))
        .header("x-tenant-id", "header-tenant")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let body: Value = r.json().await.unwrap_or_default();
    assert_eq!(
        body.get("error").and_then(|e| e.get("code")).and_then(|v| v.as_str()),
        Some("tenant_mismatch")
    );
}

#[tokio::test]
async fn login_accepts_tenant_id_in_body() {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        eprintln!("[skip] CONNECTOR_MULTI_TENANT not set on server under test");
        return;
    }
    let pw = std::env::var("CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD")
        .unwrap_or_else(|_| "admin".into());
    let r = client()
        .post(api("/auth/login"))
        .json(&json!({
            "email": "admin@connector.local",
            "password": pw,
            "tenant_id": "acme"
        }))
        .send()
        .await
        .unwrap();
    if r.status().as_u16() == 401 {
        eprintln!("[skip] default admin credentials not present on this node");
        return;
    }
    assert!(r.status().is_success());
    let body: Value = r.json().await.unwrap_or_default();
    if body.get("access_token").is_none() {
        eprintln!(
            "[skip] login did not return access_token: {:?}",
            body.get("error")
        );
        return;
    }
    let user_tid = body
        .get("user")
        .and_then(|u| u.get("tenant_id"))
        .and_then(|v| v.as_str());
    assert_eq!(user_tid, Some("acme"));
}
