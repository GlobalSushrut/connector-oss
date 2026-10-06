use reqwest::Client;

fn enabled() -> bool {
    std::env::var("RUN_LIVE_CONNECTOR_TESTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn base_url() -> String {
    std::env::var("LIVE_CONNECTOR_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:9735".to_string())
}

fn auth_token() -> String {
    std::env::var("LIVE_CONNECTOR_API_KEY").unwrap_or_else(|_| "dev-token".to_string())
}

#[tokio::test]
async fn tt02_live_connector_endpoint_resolution() {
    if !enabled() {
        eprintln!("Skipping live connector endpoint test (set RUN_LIVE_CONNECTOR_TESTS=1)");
        return;
    }

    let client = Client::new();
    let base = base_url();
    let bearer = format!("Bearer {}", auth_token());

    let endpoints = vec![
        (
            "policy_evaluate",
            "POST",
            format!("{}/api/v1/aapi/policies/evaluate", base),
            Some(serde_json::json!({
                "request_id": "live-test-1",
                "trace_id": "live-test-trace-1",
                "tenant_id": "default",
                "actor_id": "live-test-actor",
                "environment": "dev",
                "policy_bundle": "default",
                "input_payload": { "prompt": "hello" },
                "tools_requested": [],
                "output_mode": "text",
                "execution_profile": "default"
            })),
        ),
        (
            "capabilities_verify",
            "GET",
            format!("{}/api/v1/aapi/capabilities/live-test-token/verify", base),
            None,
        ),
        (
            "budgets_consume",
            "POST",
            format!("{}/api/v1/aapi/budgets/consume", base),
            Some(serde_json::json!({
                "agent_pid": "agent_test",
                "resource": "tokens",
                "amount": 1
            })),
        ),
        (
            "budget_tokens_lookup",
            "GET",
            format!("{}/api/v1/aapi/budgets/agent_test/tokens", base),
            None,
        ),
        (
            "capabilities_issue",
            "POST",
            format!("{}/api/v1/aapi/capabilities/issue", base),
            Some(serde_json::json!({
                "request_id": "live-test-3",
                "trace_id": "live-test-trace-3",
                "tenant_id": "default",
                "actor_id": "live-test-actor",
                "scope": "tracetramp.request",
                "ttl_seconds": 60
            })),
        ),
        (
            "interactions_log",
            "POST",
            format!("{}/api/v1/aapi/interactions", base),
            Some(serde_json::json!({
                "request_id": "live-test-4",
                "trace_id": "live-test-trace-4",
                "tenant_id": "default",
                "action": "test",
                "outcome": "allow"
            })),
        ),
        (
            "monitor_trust",
            "GET",
            format!("{}/api/v1/monitor/trust", base),
            None,
        ),
    ];

    for (name, method, url, body) in endpoints {
        let mut req = match method {
            "POST" => client.post(&url),
            "GET" => client.get(&url),
            _ => unreachable!("unsupported method"),
        }
        .header("Authorization", bearer.clone());

        if let Some(payload) = body {
            req = req.json(&payload);
        }

        let resp = req.send().await.expect("request should complete");
        let status = resp.status();
        assert!(
            status.as_u16() != 404 && status.as_u16() != 405,
            "endpoint {} unresolved: {} -> {}",
            name,
            url,
            status
        );
    }
}
