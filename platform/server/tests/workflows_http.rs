//! Workflow API smoke (Phase 3). Requires running node at CONNECTOR_TEST_URL.

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
async fn workflows_list_returns_json_catalog() {
    let r = client()
        .get(api("/workflows"))
        .header("Authorization", format!("Bearer {}", bearer()))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "GET /workflows expected 2xx, got {}",
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
    assert!(body.get("workflows").is_some() || body.get("ok").is_some());
}

#[tokio::test]
async fn workflows_reference_templates_public() {
    let r = client()
        .get(api("/workflows/reference-templates"))
        .header("Authorization", format!("Bearer {}", bearer()))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let body: Value = r.json().await.unwrap_or_default();
    assert!(body.get("templates").and_then(|v| v.as_array()).is_some());
}

#[tokio::test]
async fn workflows_catalog_status() {
    let r = client()
        .get(api("/workflows/catalog"))
        .header("Authorization", format!("Bearer {}", bearer()))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let body: Value = r.json().await.unwrap_or_default();
    assert!(body.get("catalog_dir").is_some());
}

#[tokio::test]
async fn workflows_register_reference_template_and_dry_run() {
    let auth = format!("Bearer {}", bearer());
    let templates = client()
        .get(api("/workflows/reference-templates"))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(templates.status().is_success());
    let tpl_body: Value = templates.json().await.unwrap_or_default();
    let cls_source = tpl_body
        .get("templates")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|t| t.get("cls_source"))
        .and_then(|v| v.as_str())
        .expect("reference template cls_source");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let workflow_id = format!("http-test-{suffix}");
    let reg = client()
        .post(api("/workflows"))
        .header("Authorization", &auth)
        .json(&json!({
            "workflow_id": workflow_id,
            "package_id": "hitl_approve_audit",
            "version": "v1",
            "cls_source": cls_source,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        reg.status().is_success(),
        "POST /workflows expected 2xx, got {}",
        reg.status()
    );
    let reg_body: Value = reg.json().await.unwrap_or_default();
    assert_eq!(reg_body.get("ok"), Some(&json!(true)));

    let dry = client()
        .post(api(&format!("/workflows/{workflow_id}/dry-run")))
        .header("Authorization", &auth)
        .json(&json!({ "replay_minutes": 5 }))
        .send()
        .await
        .unwrap();
    assert!(
        dry.status().is_success(),
        "POST dry-run expected 2xx, got {}",
        dry.status()
    );
    let dry_body: Value = dry.json().await.unwrap_or_default();
    assert!(dry_body.get("dry_run").is_some() || dry_body.get("ok") == Some(&json!(true)));

    let listed = client()
        .get(api("/workflows"))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let list_body: Value = listed.json().await.unwrap_or_default();
    let ids: Vec<&str> = list_body
        .get("workflows")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r.get("workflow_id").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        ids.iter().any(|id| *id == workflow_id.as_str()),
        "registered workflow missing from GET /workflows"
    );
}

#[tokio::test]
async fn workflow_enable_registers_cnp_topics() {
    let auth = format!("Bearer {}", bearer());
    let templates = client()
        .get(api("/workflows/reference-templates"))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let tpl_body: Value = templates.json().await.unwrap_or_default();
    let cls_source = tpl_body
        .get("templates")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|t| t.get("cls_source"))
        .and_then(|v| v.as_str())
        .expect("reference template cls_source");
    let workflow_id = format!("cnp-enable-{}", uuid::Uuid::new_v4().simple());
    let reg = client()
        .post(api("/workflows"))
        .header("Authorization", &auth)
        .json(&json!({
            "workflow_id": workflow_id,
            "package_id": "hitl_approve_audit",
            "version": "v1",
            "cls_source": cls_source,
        }))
        .send()
        .await
        .unwrap();
    assert!(reg.status().is_success());

    let mut body = json!({});
    for state in ["COMPILED", "STAGED", "ENABLED"] {
        let tr = client()
            .post(api(&format!("/workflows/{workflow_id}/lifecycle")))
            .header("Authorization", &auth)
            .json(&json!({ "state": state }))
            .send()
            .await
            .unwrap();
        assert!(
            tr.status().is_success(),
            "transition to {state}: {}",
            tr.status()
        );
        body = tr.json().await.unwrap_or_default();
    }
    let cnp = body.get("cnp_dispatch").expect("cnp_dispatch on ENABLE");
    assert_eq!(cnp.get("transport").and_then(|v| v.as_str()), Some("cnp"));
    assert!(cnp.get("workflow.actions").is_some());
    assert!(cnp.get("workflow.events").is_some());
    let dt = cnp
        .get("dispatch_token")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(dt.starts_with("cpk_wf_"), "expected workflow dispatch token, got {dt}");

    let dry = client()
        .post(api(&format!("/workflows/{workflow_id}/dry-run")))
        .header("Authorization", &auth)
        .json(&json!({ "replay_minutes": 60 }))
        .send()
        .await
        .unwrap();
    assert!(dry.status().is_success());
    let dry_body: Value = dry.json().await.unwrap_or_default();
    let replay = dry_body
        .pointer("/dry_run/cnp_replay")
        .or_else(|| dry_body.get("cnp_replay"));
    if let Some(r) = replay {
        assert!(r.get("cnp_topic_filter").is_some());
        assert!(r.get("cnp_bus_registration").is_some());
    }

    let en_body: Value = body;
    let cls = en_body.get("cls_execution").expect("cls_execution on ENABLE");
    assert_eq!(
        cls.get("execution_path").and_then(|v| v.as_str()),
        Some("cls_engine_only")
    );
    assert_eq!(
        cls.get("parallel_runners_allowed").and_then(|v| v.as_bool()),
        Some(false)
    );
}
