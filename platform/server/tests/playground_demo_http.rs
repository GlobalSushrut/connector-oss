//! Playground demo HTTP paths. Requires a running playground node:
//!   CONNECTOR_PLAYGROUND=1 CONNECTOR_TEST_URL=http://127.0.0.1:9091 \
//!   cargo test -p connector-platform --test playground_demo_http -- --nocapture
//!
//! Covers: session → demo verb, PLAYGROUND_AGENT_CAP, grant tenant deny,
//! public status omits operator emails.

use reqwest::Client;
use serde_json::{json, Value};

fn base() -> String {
    std::env::var("CONNECTOR_TEST_URL").unwrap_or_default()
}

fn skip() -> bool {
    if base().is_empty() {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        true
    } else {
        false
    }
}

fn client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap()
}

fn api(path: &str) -> String {
    format!("{}/api/v1{}", base(), path)
}

async fn playground_status() -> Option<Value> {
    let r = client().get(api("/playground/status")).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json().await.ok()
}

#[tokio::test]
async fn public_status_omits_unlimited_emails() {
    if skip() {
        return;
    }
    let Some(v) = playground_status().await else {
        eprintln!("[skip] playground status unavailable");
        return;
    };
    if v.get("playground").and_then(|x| x.as_bool()) != Some(true) {
        eprintln!("[skip] node is not in playground mode");
        return;
    }
    assert!(
        v.get("privileged_unlimited_emails").is_none(),
        "public status must not list operator emails: {v}"
    );
    assert!(v.get("privileged_unlimited_configured").is_some());
    assert_eq!(v.get("agents_default").and_then(|x| x.as_str()), Some("one_demo"));
}

#[tokio::test]
async fn gateway_list_without_agent_pid_refused() {
    if skip() {
        return;
    }
    let Some(status) = playground_status().await else {
        eprintln!("[skip] playground status unavailable");
        return;
    };
    if status.get("playground").and_then(|x| x.as_bool()) != Some(true) {
        eprintln!("[skip] node is not in playground mode");
        return;
    }
    let token = match std::env::var("CONNECTOR_TEST_BEARER") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => {
            eprintln!("[skip] CONNECTOR_TEST_BEARER not set (session JWT)");
            return;
        }
    };
    let r = client()
        .get(api("/intelligence/gateway/grants"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap_or_default();
    assert_eq!(
        body.get("error").and_then(|x| x.as_str()),
        Some("agent_pid_required"),
        "unscoped grant list must be refused: {body}"
    );
}

#[tokio::test]
async fn gateway_put_grant_rejects_foreign_agent() {
    if skip() {
        return;
    }
    let Some(status) = playground_status().await else {
        eprintln!("[skip] playground status unavailable");
        return;
    };
    if status.get("playground").and_then(|x| x.as_bool()) != Some(true) {
        eprintln!("[skip] node is not in playground mode");
        return;
    }
    let token = match std::env::var("CONNECTOR_TEST_BEARER") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => {
            eprintln!("[skip] CONNECTOR_TEST_BEARER not set");
            return;
        }
    };
    let r = client()
        .post(api("/intelligence/gateway/grant"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "agent_pid": "agent_not_this_tenant",
            "address": "https://evil.example",
            "effect": "ask",
            "layer": "cone",
        }))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap_or_default();
    let err = body.get("error").and_then(|x| x.as_str()).unwrap_or("");
    assert!(
        err == "agent_not_found" || err == "agent_not_in_session_tenant" || err == "tenant_required",
        "foreign grant must be denied, got {body}"
    );
}

#[tokio::test]
async fn intelligence_apply_returns_cap_not_silent_ok() {
    if skip() {
        return;
    }
    let Some(status) = playground_status().await else {
        eprintln!("[skip] playground status unavailable");
        return;
    };
    if status.get("playground").and_then(|x| x.as_bool()) != Some(true) {
        eprintln!("[skip] node is not in playground mode");
        return;
    }
    let token = match std::env::var("CONNECTOR_TEST_BEARER") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => {
            eprintln!("[skip] CONNECTOR_TEST_BEARER not set");
            return;
        }
    };
    let r = client()
        .post(api("/intelligence/apply"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "apiVersion": "connector.ai/v1",
            "kind": "Intelligence",
            "metadata": { "name": "second-agent" },
            "spec": {
                "purpose": "should hit PLAYGROUND_AGENT_CAP",
                "class": "app",
                "activate": true
            }
        }))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap_or_default();
    if body.get("ok").and_then(|x| x.as_bool()) == Some(true) {
        eprintln!("[skip] session had spare agent cap (MAX_AGENTS>1 or empty session)");
        return;
    }
    assert_eq!(
        body.get("code").and_then(|x| x.as_str()),
        Some("PLAYGROUND_AGENT_CAP"),
        "cap must be explicit: {body}"
    );
    assert_eq!(body.get("ok").and_then(|x| x.as_bool()), Some(false));
}
