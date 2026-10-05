//! Enterprise Capabilities Test Suite 2
//!
//! Tests every newly-exposed capability from EXPOSURE_GAP.md:
//! - Service 18: Memory2 (sessions, seal, revoke, get_packet, recall2, RAG+grounding, real interference, graph)
//! - Service 19: AAPI (UCAN caps, budgets, policies, HIPAA, financial, tool auth, interactions)
//! - Service 20: Cognitive Pipeline (observe, context, plan, reasoning, judgment, cycle, report)
//!
//! Requires: server running at http://localhost:9090 with CONNECTOR_DEV_MODE=1

use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
 use tokio::sync::OnceCell;

static BASE_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
fn base() -> &'static str {
    BASE_URL.get_or_init(|| {
        std::env::var("CONNECTOR_TEST_URL").unwrap_or_else(|_| "http://localhost:9090".into())
    })
}
fn api(path: &str) -> String { format!("{}/api/v1{}", base(), path) }
fn uid() -> String { uuid::Uuid::new_v4().to_string().replace('-', "") }

fn client() -> Client {
    Client::builder().timeout(Duration::from_secs(15)).build().unwrap()
}

 static TEST_TOKEN: OnceCell<String> = OnceCell::const_new();

fn authed(token: &str) -> Client {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
    );
    Client::builder().timeout(Duration::from_secs(15)).default_headers(h).build().unwrap()
}

async fn signup_login() -> String {
    let email = format!("cap2-{}@example.com", uid());
    let pw = "Cap2$Pass2026";
    let _ = client().post(api("/auth/signup"))
        .json(&json!({"name":"U","email":email,"password":pw})).send().await;
    let r = client().post(api("/auth/login"))
        .json(&json!({"email":email,"password":pw})).send().await.unwrap();
    let b: Value = r.json().await.unwrap_or_default();
    b.get("access_token").or_else(|| b.get("jwt"))
        .and_then(|v| v.as_str()).unwrap_or("").to_string()
}

 async fn auth_token() -> &'static str {
     TEST_TOKEN.get_or_init(|| async { signup_login().await }).await.as_str()
 }

// Convenience wrappers using authed client
async fn post_a(tok: &str, path: &str, body: Value) -> Value {
    authed(tok).post(api(path)).json(&body)
        .send().await.expect(path).json().await.expect(path)
}
async fn get_a(tok: &str, path: &str) -> Value {
    authed(tok).get(api(path))
        .send().await.expect(path).json().await.expect(path)
}
async fn delete_a(tok: &str, path: &str) -> Value {
    authed(tok).delete(api(path))
        .send().await.expect(path).json().await.expect(path)
}

async fn post(_c: &Client, path: &str, body: Value) -> Value {
    let tok = auth_token().await;
    post_a(tok, path, body).await
}

async fn get(_c: &Client, path: &str) -> Value {
    let tok = auth_token().await;
    get_a(tok, path).await
}

async fn delete(_c: &Client, path: &str) -> Value {
    let tok = auth_token().await;
    delete_a(tok, path).await
}

/// Register an agent, return kernel pid
async fn register_agent(_c: &Client, name: &str) -> String {
    let tok = auth_token().await;
    let ns = format!("ns:cap2-{}", uid());
    let r = authed(tok).post(api("/agents"))
        .json(&json!({"name":name,"namespace":ns,"role":"writer","model":"gpt-4o-mini","token_budget":50000}))
        .send().await.unwrap();
    let b: Value = r.json().await.unwrap_or_default();
    b.get("kernel_pid").or_else(|| b.get("pid")).or_else(|| b.get("agent_pid"))
        .and_then(|v| v.as_str()).unwrap_or("test_agent").to_string()
}

// ═══════════════════════════════════════════
// SERVICE 18: MEMORY2 — P0 Gap Tests
// ═══════════════════════════════════════════

#[tokio::test]
async fn test_m2_01_session_create() {
    let c = client();
    let pid = register_agent(&c, "m2-session-create").await;
    let r = post(&c, "/memory/sessions", json!({
        "agent_pid": pid, "label": "test conversation"
    })).await;
    assert_eq!(r["ok"], true, "create_session failed: {}", r);
    assert!(r["session_id"].as_str().unwrap_or("").starts_with("session:"),
        "session_id must start with 'session:': {}", r);
}

#[tokio::test]
async fn test_m2_02_session_list() {
    let c = client();
    let pid = register_agent(&c, "m2-session-list").await;
    post(&c, "/memory/sessions", json!({ "agent_pid": pid, "label": "s1" })).await;
    post(&c, "/memory/sessions", json!({ "agent_pid": pid, "label": "s2" })).await;
    let r = get(&c, "/memory/sessions/list").await;
    assert!(r["sessions"].is_array(), "sessions must be array: {}", r);
    assert!(r["count"].as_u64().unwrap_or(0) >= 2, "expect >= 2: {}", r);
}

#[tokio::test]
async fn test_m2_03_session_close() {
    let c = client();
    let pid = register_agent(&c, "m2-session-close").await;
    let sess = post(&c, "/memory/sessions", json!({ "agent_pid": pid })).await;
    let sid = sess["session_id"].as_str().unwrap().to_string();
    let r = post(&c, &format!("/memory/sessions/{}/close", sid), json!({ "agent_pid": pid })).await;
    assert_eq!(r["ok"], true, "close_session failed: {}", r);
}

#[tokio::test]
async fn test_m2_04_session_packets() {
    let c = client();
    let pid = register_agent(&c, "m2-session-packets").await;
    let sess = post(&c, "/memory/sessions", json!({ "agent_pid": pid })).await;
    let sid = sess["session_id"].as_str().unwrap().to_string();
    post(&c, "/memory/write", json!({
        "agent_pid": pid, "content": "session-scoped content", "user": "u", "session_id": sid
    })).await;
    let r = get(&c, &format!("/memory/sessions/{}/packets", sid)).await;
    assert!(r["packets"].is_array(), "packets must be array: {}", r);
    assert_eq!(r["session_id"].as_str().unwrap_or(""), sid);
}

#[tokio::test]
async fn test_m2_05_seal_packet() {
    let c = client();
    let pid = register_agent(&c, "m2-seal").await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "immutable fact", "user": "auditor" })).await;
    let ns = format!("ns:{}", pid.trim_start_matches("agent_"));
    let recall = get(&c, &format!("/memory/recall2/{}", ns)).await;
    if let Some(first) = recall["packets"].as_array().and_then(|a| a.first()) {
        let cid = first["cid"].as_str().unwrap_or("").to_string();
        if !cid.is_empty() {
            let r = post(&c, &format!("/memory/packets/{}/seal", cid), json!({ "agent_pid": pid })).await;
            assert_eq!(r["ok"], true, "seal failed: {}", r);
            assert_eq!(r["immutable"], true);
        }
    }
}

#[tokio::test]
async fn test_m2_06_access_revoke() {
    let c = client();
    let owner = register_agent(&c, "m2-revoke-owner").await;
    let grantee = register_agent(&c, "m2-revoke-grantee").await;
    let ns = format!("ns:{}", owner.trim_start_matches("agent_"));
    let r = post(&c, "/memory/access/revoke", json!({
        "owner_pid": owner, "namespace": ns, "grantee_pid": grantee
    })).await;
    assert!(r.get("ok").is_some(), "revoke must return ok field: {}", r);
}

#[tokio::test]
async fn test_m2_07_recall_full_nine_fields() {
    let c = client();
    let pid = register_agent(&c, "m2-recall2").await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "full fields test", "user": "u" })).await;
    let ns = format!("ns:{}", pid.trim_start_matches("agent_"));
    let r = get(&c, &format!("/memory/recall2/{}", ns)).await;
    assert!(r["packets"].is_array());
    if let Some(p) = r["packets"].as_array().and_then(|a| a.first()) {
        for field in &["cid","type","text","entities","tags","namespace","tier","timestamp","sealed"] {
            assert!(p.get(field).is_some(), "recall2 packet missing field {}: {}", field, p);
        }
    }
    assert!(r["filters_applied"].is_object(), "missing filters_applied: {}", r);
}

#[tokio::test]
async fn test_m2_08_recall_temporal_filter() {
    let c = client();
    let pid = register_agent(&c, "m2-temporal").await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "event", "user": "u" })).await;
    let ns = format!("ns:{}", pid.trim_start_matches("agent_"));
    let future_ms = chrono::Utc::now().timestamp_millis() + 999_999_999;
    let r = get(&c, &format!("/memory/recall2/{}?ts_from={}", ns, future_ms)).await;
    assert_eq!(r["count"].as_u64().unwrap_or(0), 0, "Future ts_from yields 0: {}", r);
}

#[tokio::test]
async fn test_m2_09_rag_query2_grounding_wired() {
    let c = client();
    let pid = register_agent(&c, "m2-rag2").await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "diabetes treatment plan", "user": "doc" })).await;
    let ns = format!("ns:{}", pid.trim_start_matches("agent_"));
    post(&c, "/memory/knowledge/ingest", json!({ "namespace": ns })).await;
    let r = post(&c, "/memory/knowledge/query2", json!({
        "entities": ["diabetes"], "keywords": ["treatment"],
        "token_budget": 2048, "max_facts": 10
    })).await;
    assert!(r["facts"].is_array(), "facts must be array: {}", r);
    assert!(r.get("grounding_active").is_some(), "missing grounding_active");
    assert!(r.get("time_range_applied").is_some(), "missing time_range_applied");
    assert!(r.get("warnings").is_some(), "missing warnings");
    // Verify all 11 fact fields if facts returned
    if let Some(f) = r["facts"].as_array().and_then(|a| a.first()) {
        for field in &["text","source_cid","entity_id","relevance_score","tier","timestamp",
                       "namespace","channels","grounded_code","grounded_desc","token_estimate"] {
            assert!(f.get(field).is_some(), "fact missing field {}: {}", field, f);
        }
    }
}

#[tokio::test]
async fn test_m2_10_rag_query2_time_range() {
    let c = client();
    let now = chrono::Utc::now().timestamp_millis();
    let pid = register_agent(&c, "m2-rag-time").await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "alpha data", "user": "u" })).await;
    let ns = format!("ns:{}", pid.trim_start_matches("agent_"));
    post(&c, "/memory/knowledge/ingest", json!({ "namespace": ns })).await;
    let r = post(&c, "/memory/knowledge/query2", json!({
        "entities": ["alpha"], "keywords": ["data"],
        "ts_from": now - 60000, "ts_to": now + 60000
    })).await;
    assert_eq!(r["time_range_applied"], true, "time_range must be applied: {}", r);
}

#[tokio::test]
async fn test_m2_11_real_interference_engine() {
    let c = client();
    let pid = register_agent(&c, "m2-interference").await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "alpha is positive", "user": "u" })).await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "beta correlates with alpha", "user": "u" })).await;
    let r = get(&c, &format!("/memory/interference2/{}", pid)).await;
    assert!(r.get("error").is_none(), "error: {}", r);
    assert!(r.get("entities_upserted").is_some(), "missing entities_upserted");
    assert!(r.get("contradiction_detected").is_some(), "missing contradiction_detected");
    assert!(r.get("interference_score").is_some(), "missing interference_score");
    assert!(r["growth_events"].is_array(), "growth_events must be array");
    assert!(r["engine"].as_str().unwrap_or("").contains("StateVector"),
        "Should use real StateVector engine: {}", r);
}

#[tokio::test]
async fn test_m2_12_graph_entities() {
    let c = client();
    let r = get(&c, "/memory/graph/entities").await;
    assert!(r["entities"].is_array(), "entities must be array: {}", r);
    assert!(r.get("count").is_some(), "missing count: {}", r);
}

#[tokio::test]
async fn test_m2_13_add_entity_and_edge() {
    let c = client();
    let er = post(&c, "/memory/graph/entity", json!({
        "id": "concept:test-entity",
        "entity_type": "test",
        "tags": ["automated"],
        "attributes": { "source": "caps2_test" }
    })).await;
    assert_eq!(er["ok"], true, "add_entity failed: {}", er);
    let edge_r = post(&c, "/memory/graph/edge", json!({
        "from": "concept:test-entity",
        "to": "concept:test-target",
        "relation": "connects_to",
        "weight": 0.8
    })).await;
    assert_eq!(edge_r["ok"], true, "add_edge failed: {}", edge_r);
}

#[tokio::test]
async fn test_m2_14_graph_neighbors() {
    let c = client();
    post(&c, "/memory/graph/entity", json!({ "id": "nbr:source", "entity_type": "t", "tags": [] })).await;
    post(&c, "/memory/graph/entity", json!({ "id": "nbr:dest", "entity_type": "t", "tags": [] })).await;
    post(&c, "/memory/graph/edge", json!({ "from": "nbr:source", "to": "nbr:dest", "relation": "linked", "weight": 1.0 })).await;
    let r = get(&c, "/memory/graph/neighbors/nbr:source").await;
    assert_eq!(r["entity_id"].as_str().unwrap_or(""), "nbr:source");
    assert!(r["neighbors"].is_array());
}

#[tokio::test]
async fn test_m2_15_knowledge_seed() {
    let c = client();
    let r = post(&c, "/memory/graph/seed", json!({
        "entities": [
            { "id": "med:aspirin", "entity_type": "medication", "tags": ["analgesic"], "attributes": {} },
            { "id": "cond:headache", "entity_type": "symptom", "tags": [], "attributes": {} }
        ],
        "edges": [
            { "from": "med:aspirin", "to": "cond:headache", "relation": "treats", "weight": 0.8 }
        ]
    })).await;
    assert_eq!(r["ok"], true, "seed failed: {}", r);
    assert_eq!(r["entities_seeded"].as_u64().unwrap_or(0), 2);
    assert_eq!(r["edges_seeded"].as_u64().unwrap_or(0), 1);
}

#[tokio::test]
async fn test_m2_16_knowledge_compile() {
    let c = client();
    let pid = register_agent(&c, "m2-compile").await;
    let r = post(&c, "/memory/knowledge/compile", json!({
        "agent_pid": pid,
        "insight": "Confirmed: aspirin reduces platelet aggregation",
        "source_cids": ["cid:a1", "cid:a2"],
        "entities": ["aspirin", "platelet"],
        "confidence": 0.96,
        "reasoning_steps": 3
    })).await;
    assert_eq!(r["ok"], true, "compile failed: {}", r);
    assert_eq!(r["confidence"].as_f64().unwrap_or(0.0), 0.96);
    assert!(r["note"].as_str().unwrap_or("").contains("compiled_knowledge"));
}

#[tokio::test]
async fn test_m2_17_growth_events() {
    let c = client();
    let pid = register_agent(&c, "m2-growth").await;
    post(&c, "/memory/write", json!({ "agent_pid": pid, "content": "entity A appeared", "user": "u" })).await;
    let r = get(&c, &format!("/memory/graph/growth-events/{}", pid)).await;
    assert!(r.get("error").is_none(), "error: {}", r);
    assert!(r.get("growth_event_count").is_some(), "missing growth_event_count");
    assert!(r["growth_events"].is_array());
    assert!(r["note"].as_str().unwrap_or("").contains("audit trail"));
}

// ═══════════════════════════════════════════
// SERVICE 19: AAPI
// ═══════════════════════════════════════════

#[tokio::test]
async fn test_aapi_01_issue_and_verify_capability() {
    let c = client();
    let r = post(&c, "/aapi/capabilities/issue", json!({
        "issuer": "platform:admin",
        "subject": "agent:test-cap",
        "actions": ["ehr.read_*"],
        "resources": ["ehr:*"],
        "ttl_hours": 8
    })).await;
    assert_eq!(r["ok"], true, "issue_capability failed: {}", r);
    assert_eq!(r["valid"], true);
    let token_id = r["token_id"].as_str().unwrap().to_string();

    let v = get(&c, &format!("/aapi/capabilities/{}/verify", token_id)).await;
    assert_eq!(v["valid"], true, "should be valid: {}", v);
    assert_eq!(v["exists"], true);
}

#[tokio::test]
async fn test_aapi_02_delegate_attenuated() {
    let c = client();
    let parent = post(&c, "/aapi/capabilities/issue", json!({
        "issuer": "platform:admin", "subject": "agent:parent",
        "actions": ["ehr.read_*","ehr.write_*","ehr.delete_*"],
        "resources": ["ehr:*"], "ttl_hours": 24
    })).await;
    let pid = parent["token_id"].as_str().unwrap().to_string();
    let r = post(&c, "/aapi/capabilities/delegate", json!({
        "parent_token_id": pid, "new_subject": "agent:child",
        "remove_actions": ["ehr.delete_*"]
    })).await;
    assert_eq!(r["ok"], true, "delegate failed: {}", r);
    assert!(r["note"].as_str().unwrap_or("").contains("Attenuated"));
    let child_actions = r["actions"].as_array().unwrap();
    assert!(!child_actions.iter().any(|a| a.as_str().unwrap_or("").contains("delete")),
        "Child must not have delete: {}", r);
}

#[tokio::test]
async fn test_aapi_03_revoke_invalidates() {
    let c = client();
    let issued = post(&c, "/aapi/capabilities/issue", json!({
        "issuer": "platform:admin", "subject": "agent:revoke-me",
        "actions": ["tool.*"], "resources": ["*"], "ttl_hours": 1
    })).await;
    let tid = issued["token_id"].as_str().unwrap().to_string();
    assert_eq!(get(&c, &format!("/aapi/capabilities/{}/verify", tid)).await["valid"], true);
    let r = delete(&c, &format!("/aapi/capabilities/{}", tid)).await;
    assert_eq!(r["revoked"], true);
    assert_eq!(get(&c, &format!("/aapi/capabilities/{}/verify", tid)).await["valid"], false,
        "After revoke must be invalid");
}

#[tokio::test]
async fn test_aapi_04_budget_full_lifecycle() {
    let c = client();
    let pid = register_agent(&c, "aapi-budget").await;
    // Create
    let cr = post(&c, "/aapi/budgets", json!({ "agent_pid": pid, "resource": "api_calls", "limit": 10.0 })).await;
    assert_eq!(cr["ok"], true);
    // Check
    let check = get(&c, &format!("/aapi/budgets/{}/api_calls", pid)).await;
    assert_eq!(check["has_budget"], true);
    assert_eq!(check["exhausted"], false);
    // Consume 9
    let cons = post(&c, "/aapi/budgets/consume", json!({ "agent_pid": pid, "resource": "api_calls", "amount": 9.0 })).await;
    assert_eq!(cons["ok"], true);
    assert!((cons["remaining"].as_f64().unwrap_or(-1.0) - 1.0).abs() < 0.01);
    // Over-consume should be denied and leave remaining budget unchanged
    let denied = post(&c, "/aapi/budgets/consume", json!({ "agent_pid": pid, "resource": "api_calls", "amount": 5.0 })).await;
    assert_eq!(denied["ok"], false, "over-consume should be denied: {}", denied);
    let check_after_denied = get(&c, &format!("/aapi/budgets/{}/api_calls", pid)).await;
    assert_eq!(check_after_denied["exhausted"], false, "budget should not be exhausted after denied over-consume: {}", check_after_denied);
    assert!((check_after_denied["remaining"].as_f64().unwrap_or(-1.0) - 1.0).abs() < 0.01);
    // Consume the exact remaining amount → exhausted
    let exact = post(&c, "/aapi/budgets/consume", json!({ "agent_pid": pid, "resource": "api_calls", "amount": 1.0 })).await;
    assert_eq!(exact["ok"], true, "exact final consume should succeed: {}", exact);
    assert_eq!(get(&c, &format!("/aapi/budgets/{}/api_calls", pid)).await["exhausted"], true);
}

#[tokio::test]
async fn test_aapi_05_dynamic_policy_crud() {
    let c = client();
    let add = post(&c, "/aapi/policies", json!({
        "id": "test-deny-all-delete",
        "name": "Deny Delete Test",
        "rules": [{"effect":"deny","action_pattern":"*.delete","resource_pattern":"protected:*","roles":[],"priority":90}]
    })).await;
    assert_eq!(add["ok"], true, "add_policy: {}", add);

    // Eval — should be denied
    let eval = post(&c, "/aapi/policies/evaluate", json!({ "action": "record.delete", "resource": "protected:x" })).await;
    assert_eq!(eval["allowed"], false, "Should be denied: {}", eval);

    // Remove
    let del = delete(&c, "/aapi/policies/test-deny-all-delete").await;
    assert_eq!(del["removed"], true, "remove_policy: {}", del);
}

#[tokio::test]
async fn test_aapi_06_hipaa_template() {
    let c = client();
    let r = post(&c, "/aapi/policies/hipaa", json!({})).await;
    assert_eq!(r["ok"], true, "hipaa: {}", r);
    assert!(r["rules_applied"].is_array());

    // EHR delete must be denied
    let e1 = post(&c, "/aapi/policies/evaluate", json!({ "action": "record.delete", "resource": "ehr:patient:123" })).await;
    assert_eq!(e1["allowed"], false, "HIPAA must deny ehr delete: {}", e1);

    // Doctor ehr read must be allowed
    let e2 = post(&c, "/aapi/policies/evaluate", json!({ "action": "ehr.read_chart", "resource": "ehr:patient:123", "role": "doctor" })).await;
    assert_eq!(e2["allowed"], true, "HIPAA must allow doctor ehr read: {}", e2);
}

#[tokio::test]
async fn test_aapi_06b_hipaa_template_idempotent() {
    let c = client();

    let first = post(&c, "/aapi/policies/hipaa", json!({})).await;
    assert_eq!(first["ok"], true, "first hipaa apply failed: {}", first);
    assert_eq!(first["already_applied"], false, "first apply should not report already_applied: {}", first);

    let deny_before = post(&c, "/aapi/policies/evaluate", json!({
        "action": "record.delete",
        "resource": "ehr:patient:123"
    })).await;
    let allow_before = post(&c, "/aapi/policies/evaluate", json!({
        "action": "ehr.read_chart",
        "resource": "ehr:patient:123",
        "role": "doctor"
    })).await;

    let first_total = first["total_policies"].as_u64().unwrap_or(0);

    let second = post(&c, "/aapi/policies/hipaa", json!({})).await;
    assert_eq!(second["ok"], true, "second hipaa apply failed: {}", second);
    assert_eq!(second["already_applied"], true, "second apply should be idempotent: {}", second);
    assert_eq!(second["total_policies"].as_u64().unwrap_or(0), first_total,
        "second apply must not increase policy count: first={}, second={}", first, second);

    let deny_after = post(&c, "/aapi/policies/evaluate", json!({
        "action": "record.delete",
        "resource": "ehr:patient:123"
    })).await;
    let allow_after = post(&c, "/aapi/policies/evaluate", json!({
        "action": "ehr.read_chart",
        "resource": "ehr:patient:123",
        "role": "doctor"
    })).await;

    assert_eq!(deny_before["allowed"], false, "baseline HIPAA deny missing: {}", deny_before);
    assert_eq!(deny_after["allowed"], deny_before["allowed"],
        "deny decision changed after duplicate apply: before={}, after={}", deny_before, deny_after);
    assert_eq!(deny_after["requires_approval"], deny_before["requires_approval"],
        "deny approval semantics changed after duplicate apply: before={}, after={}", deny_before, deny_after);

    assert_eq!(allow_before["allowed"], true, "baseline HIPAA allow missing: {}", allow_before);
    assert_eq!(allow_after["allowed"], allow_before["allowed"],
        "allow decision changed after duplicate apply: before={}, after={}", allow_before, allow_after);
    assert_eq!(allow_after["requires_approval"], allow_before["requires_approval"],
        "allow approval semantics changed after duplicate apply: before={}, after={}", allow_before, allow_after);
}

#[tokio::test]
async fn test_aapi_07_financial_template() {
    let c = client();
    let r = post(&c, "/aapi/policies/financial", json!({})).await;
    assert_eq!(r["ok"], true, "financial: {}", r);

    // Trade must require approval
    let e1 = post(&c, "/aapi/policies/evaluate", json!({ "action": "trade.execute", "resource": "portfolio:u1" })).await;
    assert_eq!(e1["requires_approval"], true, "Trade needs approval: {}", e1);

    // Ledger delete must be denied
    let e2 = post(&c, "/aapi/policies/evaluate", json!({ "action": "audit.delete", "resource": "ledger:tx" })).await;
    assert_eq!(e2["allowed"], false, "Ledger delete must be denied: {}", e2);
}

#[tokio::test]
async fn test_aapi_08_authorize_tool() {
    let c = client();
    let pid = register_agent(&c, "aapi-tool-auth").await;
    post(&c, "/aapi/capabilities/issue", json!({
        "issuer": "platform:admin", "subject": pid,
        "actions": ["tool.search"], "resources": ["tool://search"], "ttl_hours": 1
    })).await;
    let r = post(&c, "/aapi/tools/authorize", json!({
        "agent_pid": pid, "action": "tool.search", "resource": "tool://search"
    })).await;
    assert!(r.get("allowed").is_some(), "authorize_tool missing allowed: {}", r);
    assert!(r.get("effect").is_some());
    assert!(r.get("reason").is_some());
}

#[tokio::test]
async fn test_aapi_09_register_tool_aapi() {
    let c = client();
    let r = post(&c, "/aapi/tools/register", json!({ "name": "web_search", "description": "Search web" })).await;
    assert_eq!(r["ok"], true, "register_tool_aapi: {}", r);
    assert!(r["capability_issued"].as_str().unwrap_or("").contains("web_search"));
    assert_eq!(r["audit_logged"], true);
}

#[tokio::test]
async fn test_aapi_10_interaction_log_and_list() {
    let c = client();
    let pid = register_agent(&c, "aapi-interactions").await;
    let r = post(&c, "/aapi/interactions", json!({
        "agent_pid": pid, "itype": "llm_call", "target": "gpt-4o",
        "operation": "chat_completion", "status": "success",
        "duration_ms": 1234, "tokens": 456, "cost_usd": 0.0023
    })).await;
    assert_eq!(r["ok"], true, "log_interaction: {}", r);

    let list = get(&c, &format!("/aapi/interactions?agent_pid={}", pid)).await;
    assert!(list["count"].as_u64().unwrap_or(0) >= 1, "list_interactions: {}", list);
    let found = list["interactions"].as_array().unwrap()
        .iter().any(|i| i["agent_pid"].as_str().unwrap_or("") == pid);
    assert!(found, "should find our interaction: {}", list);
}

#[tokio::test]
async fn test_aapi_11_compliance_config() {
    let c = client();
    let r = post(&c, "/aapi/compliance", json!({
        "regulations": ["HIPAA","SOC2","GDPR"],
        "data_classification": "PHI",
        "retention_days": 2555,
        "requires_human_review": true
    })).await;
    assert_eq!(r["ok"], true, "compliance: {}", r);
    assert_eq!(r["retention_days"].as_u64().unwrap_or(0), 2555);
    assert_eq!(r["regulations"].as_array().unwrap().len(), 3);
}

// ═══════════════════════════════════════════
// SERVICE 20: COGNITIVE PIPELINE
// ═══════════════════════════════════════════

#[tokio::test]
async fn test_cog_01_observe_basic() {
    let c = client();
    let pid = register_agent(&c, "cog-observe").await;
    let r = post(&c, "/cognitive/observe", json!({
        "agent_pid": pid, "input": "Patient presents with acute chest pain",
        "user": "user:doctor", "pipeline": "pipe:er", "judgment_profile": "medical"
    })).await;
    assert_eq!(r["ok"], true, "observe: {}", r);
    assert!(r["cid"].as_str().unwrap_or("").len() > 0, "missing cid");
    for field in &["entities","quality_score","quality_grade","warnings","timestamp"] {
        assert!(r.get(*field).is_some(), "observe missing {}: {}", field, r);
    }
    assert!(r["quality_score"].as_u64().unwrap_or(0) > 0, "quality_score > 0");
}

#[tokio::test]
async fn test_cog_02_observe_with_session() {
    let c = client();
    let pid = register_agent(&c, "cog-observe-sess").await;
    let sess = post(&c, "/memory/sessions", json!({ "agent_pid": pid })).await;
    let sid = sess["session_id"].as_str().unwrap().to_string();
    let r = post(&c, "/cognitive/observe", json!({
        "agent_pid": pid, "input": "BP 180/110 tachycardic",
        "user": "user:nurse", "pipeline": "pipe:vitals", "session_id": sid
    })).await;
    assert_eq!(r["ok"], true, "observe_with_session: {}", r);
    assert!(r["cid"].as_str().unwrap_or("").len() > 0);
}

#[tokio::test]
async fn test_cog_03_perceived_context_all_dimensions() {
    let c = client();
    let pid = register_agent(&c, "cog-context").await;
    post(&c, "/cognitive/observe", json!({
        "agent_pid": pid, "input": "Patient allergic to penicillin",
        "user": "user:doc", "pipeline": "pipe:intake"
    })).await;
    let r = get(&c, &format!("/cognitive/context/{}?judgment_profile=medical&limit=10", pid)).await;
    assert_eq!(r["ok"], true, "perceived_context: {}", r);
    assert!(r["memories"].is_array());
    let dims = &r["judgment"]["dimensions"];
    for dim in &["cid_integrity","audit_coverage","access_control","evidence_quality",
                  "claim_coverage","temporal_freshness","contradiction_score","source_credibility"] {
        assert!(dims.get(*dim).is_some(), "judgment missing dim {}: {}", dim, r);
    }
}

#[tokio::test]
async fn test_cog_04_create_plan() {
    let c = client();
    let pid = register_agent(&c, "cog-plan").await;
    let r = post(&c, "/cognitive/plan", json!({
        "agent_pid": pid,
        "goal": "Diagnose acute STEMI",
        "steps": ["Assess symptoms","Order ECG","Draw troponin","Activate cath lab","Administer aspirin"],
        "dependencies": [[3,2],[4,1]]
    })).await;
    assert_eq!(r["ok"], true, "create_plan: {}", r);
    assert_eq!(r["step_count"].as_u64().unwrap_or(0), 5);
    assert!(r["steps"].is_array());
    assert!(r.get("progress").is_some());
}

#[tokio::test]
async fn test_cog_05_reasoning_step_is_kernel_persisted() {
    let c = client();
    let pid = register_agent(&c, "cog-reasoning").await;
    let r = post(&c, "/cognitive/reasoning/step", json!({
        "agent_pid": pid,
        "thought": "ECG shows ST elevation inferior leads — STEMI pattern",
        "action": "interpret_ecg", "result": "STEMI confirmed", "evidence_cids": []
    })).await;
    assert_eq!(r["ok"], true, "reasoning_step: {}", r);
    assert!(r.get("step_number").is_some(), "missing step_number");
    assert!(r.get("cid").is_some(), "kernel-persisted step missing cid");
}

#[tokio::test]
async fn test_cog_06_conclusion_is_decision_packet() {
    let c = client();
    let pid = register_agent(&c, "cog-conclude").await;
    let r = post(&c, "/cognitive/reasoning/conclude", json!({
        "agent_pid": pid,
        "conclusion": "Inferior STEMI confirmed — emergency PCI required",
        "confidence": 0.94, "evidence_cids": []
    })).await;
    assert_eq!(r["ok"], true, "conclude: {}", r);
    assert!(r["cid"].as_str().unwrap_or("").len() > 0, "conclusion must have CID");
    assert_eq!(r["confidence"].as_f64().unwrap_or(0.0), 0.94);
    assert_eq!(r["packet_type"].as_str().unwrap_or(""), "Decision",
        "Conclusion must be Decision packet");
}

#[tokio::test]
async fn test_cog_07_judgment_all_profiles() {
    let c = client();
    for profile in &["default","medical","financial"] {
        let r = post(&c, "/cognitive/judgment", json!({ "agent_pid": "system", "profile": profile })).await;
        assert!(r.get("score").is_some(), "{} judgment missing score", profile);
        let dims = &r["dimensions"];
        for dim in &["cid_integrity","audit_coverage","access_control","evidence_quality",
                      "claim_coverage","temporal_freshness","contradiction_score","source_credibility"] {
            assert!(dims.get(*dim).is_some(), "{} judgment missing dim {}", profile, dim);
        }
    }
}

#[tokio::test]
async fn test_cog_08_cognitive_cycle_full_response() {
    let c = client();
    let pid = register_agent(&c, "cog-cycle").await;
    let r = post(&c, "/cognitive/cycle", json!({
        "agent_pid": pid,
        "input": "Patient diaphoretic, BP 90/60, chest pain 9/10",
        "user": "user:paramedic", "pipeline": "pipe:emergency",
        "goal": "Stabilise critical patient",
        "steps": ["Assess airway","IV access","Monitor vitals"],
        "judgment_profile": "medical"
    })).await;
    assert_eq!(r["ok"], true, "cognitive_cycle: {}", r);
    for field in &["cycle_number","observation_cid","facts_retrieved",
                    "reasoning_steps","quality_score","contradiction_detected","warnings"] {
        assert!(r.get(*field).is_some(), "cycle missing {}: {}", field, r);
    }
    assert!(r["cycle_number"].as_u64().unwrap_or(0) >= 1);
    assert!(r["reasoning_steps"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn test_cog_09_cycle_increments() {
    let c = client();
    let pid = register_agent(&c, "cog-increment").await;
    let mut last_cycle = 0u64;
    for i in 1u64..=3 {
        let r = post(&c, "/cognitive/cycle", json!({
            "agent_pid": pid, "input": format!("observation {}", i),
            "user": "u", "pipeline": "p", "goal": "process", "steps": []
        })).await;
        let cycle = r["cycle_number"].as_u64().unwrap_or(0);
        assert!(cycle > last_cycle, "cycle number should monotonically increase across process-global binding engine: {}", r);
        last_cycle = cycle;
    }
}

#[tokio::test]
async fn test_cog_10_cognitive_report() {
    let c = client();
    let pid = register_agent(&c, "cog-report").await;
    for _ in 0..2 {
        post(&c, "/cognitive/cycle", json!({
            "agent_pid": pid, "input": "test input",
            "user": "u", "pipeline": "p", "goal": "g", "steps": []
        })).await;
    }
    let r = get(&c, &format!("/cognitive/report/{}", pid)).await;
    assert_eq!(r["agent_pid"].as_str().unwrap_or(""), pid);
    assert!(r["total_cycles"].as_u64().unwrap_or(0) >= 2, "shared BindingEngine keeps process-global cycle count: {}", r);
    assert!(r["cycles"].is_array());
    assert!(r["cycles"].as_array().unwrap().len() >= 2, "report should contain at least the cycles we just created: {}", r);
    for field in &["total_reasoning_steps","contradictions_detected","final_quality_score"] {
        assert!(r.get(*field).is_some(), "report missing {}: {}", field, r);
    }
}

// ═══════════════════════════════════════════
// CROSS-SYSTEM INTEGRATION TESTS
// ═══════════════════════════════════════════

#[tokio::test]
async fn test_int_01_ucan_then_cognitive_cycle() {
    let c = client();
    let pid = register_agent(&c, "int-ucan-cycle").await;
    // Issue UCAN
    let cap = post(&c, "/aapi/capabilities/issue", json!({
        "issuer": "platform:admin", "subject": pid,
        "actions": ["cognitive.*"], "resources": ["pipeline:*"], "ttl_hours": 1
    })).await;
    assert_eq!(cap["ok"], true);
    // Budget
    post(&c, "/aapi/budgets", json!({ "agent_pid": pid, "resource": "cycles", "limit": 50.0 })).await;
    // Cycle
    let cycle = post(&c, "/cognitive/cycle", json!({
        "agent_pid": pid, "input": "Analyse market anomaly",
        "user": "user:analyst", "pipeline": "pipe:market",
        "goal": "Detect anomaly", "steps": ["Collect","Analyse","Report"]
    })).await;
    assert_eq!(cycle["ok"], true, "integrated cycle: {}", cycle);
    // Consume budget
    let cons = post(&c, "/aapi/budgets/consume", json!({ "agent_pid": pid, "resource": "cycles", "amount": 1.0 })).await;
    assert_eq!(cons["ok"], true);
    assert!((cons["remaining"].as_f64().unwrap_or(-1.0) - 49.0).abs() < 0.01);
}

#[tokio::test]
async fn test_int_02_seed_then_rag_then_cycle() {
    let c = client();
    // Seed oncology ontology
    post(&c, "/memory/graph/seed", json!({
        "entities": [
            { "id": "drug:pembrolizumab", "entity_type": "immunotherapy", "tags": ["cancer"], "attributes": {} },
            { "id": "cancer:nsclc", "entity_type": "diagnosis", "tags": ["lung"], "attributes": {} }
        ],
        "edges": [{ "from": "drug:pembrolizumab", "to": "cancer:nsclc", "relation": "first_line", "weight": 0.92 }]
    })).await;
    // Write + observe
    let pid = register_agent(&c, "int-seed-cycle").await;
    post(&c, "/cognitive/observe", json!({
        "agent_pid": pid, "input": "Patient with NSCLC PD-L1 positive, candidate for pembrolizumab",
        "user": "user:oncologist", "pipeline": "pipe:oncology"
    })).await;
    // RAG query — should pick up seeded knowledge
    let ns = format!("ns:{}", pid.trim_start_matches("agent_"));
    post(&c, "/memory/knowledge/ingest", json!({ "namespace": ns })).await;
    let r = post(&c, "/memory/knowledge/query2", json!({
        "entities": ["nsclc","pembrolizumab"], "keywords": ["immunotherapy"]
    })).await;
    assert!(r["facts"].is_array(), "facts: {}", r);
    assert_eq!(r["grounding_active"], true);
}

#[tokio::test]
async fn test_int_03_session_lifecycle_with_seal() {
    let c = client();
    let pid = register_agent(&c, "int-session-seal").await;
    // Create session
    let sess = post(&c, "/memory/sessions", json!({ "agent_pid": pid, "label": "er-visit" })).await;
    let sid = sess["session_id"].as_str().unwrap().to_string();
    // Observe in session
    post(&c, "/cognitive/observe", json!({
        "agent_pid": pid, "input": "Patient arrived at 14:32 with chest pain",
        "user": "user:nurse", "pipeline": "pipe:er", "session_id": sid
    })).await;
    // Get session packets
    let pkts = get(&c, &format!("/memory/sessions/{}/packets", sid)).await;
    assert!(pkts["packets"].is_array());
    // Seal first packet
    if let Some(first) = pkts["packets"].as_array().and_then(|a| a.first()) {
        let cid = first["cid"].as_str().unwrap_or("");
        if !cid.is_empty() {
            let seal_r = post(&c, &format!("/memory/packets/{}/seal", cid), json!({ "agent_pid": pid })).await;
            assert_eq!(seal_r["ok"], true, "session seal: {}", seal_r);
            assert_eq!(seal_r["immutable"], true);
        }
    }
    // Close session
    let close_r = post(&c, &format!("/memory/sessions/{}/close", sid), json!({ "agent_pid": pid })).await;
    assert_eq!(close_r["ok"], true, "close session: {}", close_r);
}

#[tokio::test]
async fn test_int_04_hipaa_blocks_cycle_delete_attempt() {
    let c = client();
    // Apply HIPAA
    post(&c, "/aapi/policies/hipaa", json!({})).await;
    // Attempt to authorize ehr delete — must fail
    let pid = register_agent(&c, "int-hipaa-guard").await;
    let r = post(&c, "/aapi/tools/authorize", json!({
        "agent_pid": pid, "action": "record.delete", "resource": "ehr:patient:999"
    })).await;
    assert_eq!(r["allowed"], false, "HIPAA must block ehr delete: {}", r);
}

#[tokio::test]
async fn test_int_05_cognitive_cycle_then_growth_events() {
    let c = client();
    let pid = register_agent(&c, "int-growth-cycle").await;
    // Multiple cycles to build graph
    for i in 0..3 {
        post(&c, "/cognitive/cycle", json!({
            "agent_pid": pid,
            "input": format!("Entity {} observation with related concept {}", i, i+1),
            "user": "u", "pipeline": "p", "goal": "analyse", "steps": []
        })).await;
    }
    // Check growth events
    let r = get(&c, &format!("/memory/graph/growth-events/{}", pid)).await;
    assert!(r.get("error").is_none(), "growth events error: {}", r);
    assert!(r["growth_events"].is_array());
    // Check interference
    let ir = get(&c, &format!("/memory/interference2/{}", pid)).await;
    assert!(ir.get("interference_score").is_some(), "interference: {}", ir);
    // Check report
    let rep = get(&c, &format!("/cognitive/report/{}", pid)).await;
    assert!(rep["total_cycles"].as_u64().unwrap_or(0) >= 3);
}
