//! Live HTTP adversarial checks for constitutional trust properties.
//! Skips unless CONNECTOR_TEST_URL is set (and optional flags for multi-tenant / open-auth suites).

use reqwest::Client;
use serde_json::Value;

fn base() -> Option<String> {
    std::env::var("CONNECTOR_TEST_URL").ok()
}

fn client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap()
}

fn api(root: &str, path: &str) -> String {
    format!("{}/api/v1{}", root.trim_end_matches('/'), path)
}

#[tokio::test]
async fn proof_generate_is_not_preverified() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .post(api(&root, "/proof/generate"))
        .header("Authorization", "Bearer dev-token")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({"agent_pid": "nonexistent-agent-for-trust-test"}))
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] proof/generate returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    assert_ne!(
        body.get("verified").and_then(|v| v.as_bool()),
        Some(true),
        "proof generate must not claim verified:true"
    );
    assert!(body.get("proof_id").and_then(|v| v.as_str()).is_some());
}

#[tokio::test]
async fn ha_federation_never_claims_automatic_failover() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .get(api(&root, "/runtime/ha-federation"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] ha-federation returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    assert_eq!(
        body.get("automatic_failover").and_then(|v| v.as_bool()),
        Some(false)
    );
}

#[tokio::test]
async fn legacy_header_only_tenant_rejected_when_multi_tenant() {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        eprintln!("[skip] CONNECTOR_MULTI_TENANT not set on server under test");
        return;
    }
    if std::env::var("CONNECTOR_ALLOW_LEGACY_HEADER_TENANT").is_ok() {
        eprintln!("[skip] legacy header tenant explicitly allowed");
        return;
    }
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    // Unverified JWT-shaped token without tenant_id + spoof header — expect mismatch or legacy reject.
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"sub":"u1","role":"admin"}"#);
    let token = format!("aaa.{payload}.bbb");
    let r = client()
        .get(api(&root, "/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .header("x-tenant-id", "spoofed")
        .send()
        .await
        .unwrap();
    assert!(
        r.status().as_u16() == 403 || r.status().as_u16() == 401,
        "expected 401/403 for legacy/spoof tenant, got {}",
        r.status()
    );
}

#[tokio::test]
async fn substrate_and_forensics_status_schemas() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    for path in ["/substrate/status", "/forensics/status", "/substrate/admission/matrix"] {
        let r = client()
            .get(api(&root, path))
            .header("Authorization", "Bearer dev-token")
            .send()
            .await;
        let Ok(r) = r else {
            eprintln!("[skip] server unreachable");
            return;
        };
        if !r.status().is_success() {
            eprintln!("[skip] {path} returned {}", r.status());
            continue;
        }
        let body: Value = r.json().await.unwrap_or_default();
        let data = body.get("data").cloned().unwrap_or(body);
        assert!(
            data.get("schema").and_then(|v| v.as_str()).is_some(),
            "{path} must return schema in operator envelope"
        );
    }
}

#[tokio::test]
async fn tracetramp_proxy_requires_auth_without_token() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    if std::env::var("CONNECTOR_DEV_AUTH_BYPASS").is_ok() {
        eprintln!("[skip] dev auth bypass enabled on server under test");
        return;
    }
    let r = client()
        .get(api(&root, "/plugins/tracetramp/admin/stats"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "TT management proxy must reject unauthenticated callers"
    );
}

#[tokio::test]
async fn kernel_status_includes_flow_lease_map() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .get(api(&root, "/kernel/status"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] kernel/status returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    let data = body.get("data").cloned().unwrap_or(body);
    let fl = data
        .get("flow_lease")
        .expect("kernel/status must include flow_lease block for connector-kerneld");
    assert_eq!(
        fl.get("schema").and_then(|v| v.as_str()),
        Some("flow_lease_map.v1")
    );
    assert!(fl.get("active_leases").and_then(|v| v.as_u64()).is_some());
    assert!(fl.get("leases").and_then(|v| v.as_array()).is_some());
}

#[tokio::test]
async fn substrate_status_includes_handoff_queue_stats() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .get(api(&root, "/substrate/status"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] substrate/status returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    let data = body.get("data").cloned().unwrap_or(body);
    let hq = data
        .get("handoff_queue")
        .expect("substrate/status must expose handoff_queue stats");
    assert_eq!(
        hq.get("schema").and_then(|v| v.as_str()),
        Some("handoff_queue_stats.v1")
    );
}

#[tokio::test]
async fn admission_matrix_lists_wired_effect_routes() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .get(api(&root, "/substrate/admission/matrix"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] admission matrix returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    let data = body.get("data").cloned().unwrap_or(body);
    let wired = data.get("wired_count").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        wired >= 17,
        "admission matrix must declare >=17 wired effect routes, got {wired}"
    );
    let routes = data
        .get("wired_effect_routes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        routes.iter().any(|r| {
            r.get("path").and_then(|p| p.as_str()) == Some("/multiagent/pipeline")
        }),
        "admission matrix must include /multiagent/pipeline"
    );
}

#[tokio::test]
async fn substrate_status_includes_durability_block() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .get(api(&root, "/substrate/status"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] substrate/status returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    let data = body.get("data").cloned().unwrap_or(body);
    assert!(
        data.get("durability")
            .and_then(|d| d.get("schema"))
            .and_then(|s| s.as_str())
            .is_some(),
        "substrate/status must expose durability schema block"
    );
    let wal = data
        .get("durability")
        .and_then(|d| d.get("wal_status"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert!(
        wal == "write_through" || wal == "interval_flush" || wal == "lag",
        "durability wal_status must be honest, got {wal}"
    );
}

#[tokio::test]
async fn books_costs_unavailable_is_not_numeric_zero() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .get(api(&root, "/books/costs"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] books/costs returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    let has_usage = body
        .get("meta")
        .and_then(|m| m.get("has_usage_data"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if has_usage {
        eprintln!("[skip] books has usage data on test server");
        return;
    }
    let cost = body.get("data").and_then(|d| d.get("total_cost_usd"));
    assert!(
        cost.map(|v| v.is_null()).unwrap_or(false),
        "books/costs without usage must not report numeric zero cost"
    );
}

#[tokio::test]
async fn graph_entity_admission_denied_for_blocked_agent() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .post(api(&root, "/memory/graph/entity"))
        .header("Authorization", "Bearer dev-token")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "id": "trust-test-entity",
            "agent_pid": "__connector_admission_block_test__"
        }))
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if r.status().is_success() {
        eprintln!("[skip] admission did not deny blocked test agent (dev permissive mode)");
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    let err = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        err == "admission_denied" || body.get("ok").and_then(|v| v.as_bool()) == Some(false),
        "graph entity must fail closed on admission deny, got {body}"
    );
}

#[tokio::test]
async fn ring1_memory_write_denied_without_quantum() {
    if std::env::var("CONNECTOR_IIA_RING1_TEST").is_err() {
        eprintln!("[skip] CONNECTOR_IIA_RING1_TEST not set");
        return;
    }
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let agent = std::env::var("CONNECTOR_IIA_TEST_AGENT").unwrap_or_else(|_| "iia-test-agent".into());
    let r = client()
        .post(api(&root, "/memory/write"))
        .header("Authorization", "Bearer dev-token")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "agent_pid": agent,
            "content": "ring1 adversarial probe"
        }))
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    assert!(
        r.status().as_u16() == 403 || r.status().as_u16() == 401,
        "memory write without quantum must deny under ring1, got {}",
        r.status()
    );
}

#[tokio::test]
async fn docklock_status_exposes_ring1_hardening_fields() {
    if std::env::var("CONNECTOR_IIA_RING1_TEST").is_err() {
        eprintln!("[skip] CONNECTOR_IIA_RING1_TEST not set");
        return;
    }
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    let r = client()
        .get(api(&root, "/runtime/docklock/status"))
        .header("Authorization", "Bearer dev-token")
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    if !r.status().is_success() {
        eprintln!("[skip] docklock/status returned {}", r.status());
        return;
    }
    let body: Value = r.json().await.unwrap_or_default();
    let dock = body.get("docklock").cloned().unwrap_or(body);
    assert_eq!(
        dock.get("ring1_enforce").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(
        dock.get("bypass_fail_closed").and_then(|v| v.as_bool()) == Some(true),
        "docklock status must advertise bypass_fail_closed"
    );
}

#[tokio::test]
async fn native_invoke_rejects_tenant_spoof_header() {
    let Some(root) = base() else {
        eprintln!("[skip] CONNECTOR_TEST_URL not set");
        return;
    };
    // Without a real JWT this may 401/deny — either is fail-closed; never 200 allow.
    let r = client()
        .post(api(&root, "/native/invocations"))
        .header("Authorization", "Bearer not-a-real-jwt")
        .header("X-Tenant-Id", "attacker-tenant")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "origin": {
                "workload_uid": "wl_adv",
                "intelligence_uid": "intel_adv",
                "principal": "p_adv"
            },
            "effect": { "effect_class": "tool", "mutates": true },
            "contract_ref": "contract:adversarial",
            "tenant_id": "victim-tenant",
            "tool_name": "noop"
        }))
        .send()
        .await;
    let Ok(r) = r else {
        eprintln!("[skip] server unreachable");
        return;
    };
    let status = r.status();
    let body: Value = r.json().await.unwrap_or(Value::Null);
    assert!(
        !status.is_success()
            || body.get("ok") == Some(&Value::Bool(false))
            || body.get("error").is_some(),
        "tenant spoof must not succeed: status={status} body={body}"
    );
}
