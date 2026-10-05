//! Unified apps catalog smoke (T2). Requires running node at CONNECTOR_TEST_URL.

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

fn bearer() -> String {
    if let Ok(k) = std::env::var("CONNECTOR_TEST_API_KEY") {
        if !k.is_empty() {
            return k;
        }
    }
    std::env::var("CONNECTOR_DEV_TOKEN").unwrap_or_else(|_| "dev-token".into())
}

#[tokio::test]
async fn apps_catalog_lists_plugins_and_workflows_shape() {
    let r = client()
        .get(api("/apps"))
        .header("Authorization", format!("Bearer {}", bearer()))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "GET /apps expected 2xx, got {}",
        r.status()
    );
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/json"),
        "expected JSON not SPA HTML, got content-type {ct:?}"
    );
    let body: Value = r.json().await.unwrap_or_default();
    let apps = body
        .get("apps")
        .and_then(|v| v.as_array())
        .expect("apps array");
    assert!(body.get("counts").is_some() || body.get("ok").is_some());
    for row in apps.iter().take(3) {
        assert!(row.get("id").is_some());
        assert!(row.get("kind").is_some());
    }
}

#[tokio::test]
async fn apps_catalog_kind_plugin_filter() {
    let r = client()
        .get(api("/apps?kind=plugin"))
        .header("Authorization", format!("Bearer {}", bearer()))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let body: Value = r.json().await.unwrap_or_default();
    let apps = body
        .get("apps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for row in &apps {
        if let Some(k) = row.get("kind").and_then(|v| v.as_str()) {
            assert_eq!(k, "plugin");
        }
    }
}

#[tokio::test]
async fn apps_show_tracetramp_when_present() {
    let list = client()
        .get(api("/apps?kind=plugin"))
        .header("Authorization", format!("Bearer {}", bearer()))
        .send()
        .await
        .unwrap();
    if !list.status().is_success() {
        return;
    }
    let body: Value = list.json().await.unwrap_or_default();
    let has_tt = body
        .get("apps")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter().any(|r| {
                r.get("id")
                    .and_then(|v| v.as_str())
                    .map(|id| id == "tracetramp")
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    if !has_tt {
        eprintln!("[skip] tracetramp not in apps catalog on this node");
        return;
    }
    let r = client()
        .get(api("/apps/tracetramp"))
        .header("Authorization", format!("Bearer {}", bearer()))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let detail: Value = r.json().await.unwrap_or_default();
    assert_eq!(
        detail.get("app").and_then(|a| a.get("id")).and_then(|v| v.as_str()),
        Some("tracetramp")
    );
}
