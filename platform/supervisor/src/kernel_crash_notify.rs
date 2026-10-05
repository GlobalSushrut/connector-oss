//! Best-effort `POST /api/v1/kernel/plugin-crash-recovery/record` when a supervised child exits non-success
//! (Phase 5.10.2 — `ProcessSpec::plugin_crash_plugin_id`).

use std::time::Duration;

async fn post_once(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
) -> bool {
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(body);
    if let Some(tok) = bearer {
        req = req.header("Authorization", format!("Bearer {}", tok));
    }
    let Ok(resp) = req.send().await else {
        return false;
    };
    resp.status().is_success()
}

/// Fire-and-forget kernel notification; never panics; ignores transport / HTTP errors.
pub async fn notify_plugin_crash_on_exit(plugin_id: &str) {
    let pid = plugin_id.trim();
    if pid.is_empty() {
        return;
    }
    let base = std::env::var("CONNECTOR_API_URL").unwrap_or_else(|_| "http://localhost:9091".to_string());
    let url = format!(
        "{}/api/v1/kernel/plugin-crash-recovery/record",
        base.trim_end_matches('/')
    );

    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return;
    };

    let body = serde_json::json!({ "plugin_id": pid });
    let api_key = std::env::var("CONNECTOR_API_KEY").ok();

    if let Some(ref k) = api_key {
        if post_once(&client, &url, &body, Some(k.as_str())).await {
            return;
        }
    }
    if api_key.as_deref() != Some("dev-token")
        && post_once(&client, &url, &body, Some("dev-token")).await
    {
        return;
    }
    let _ = post_once(&client, &url, &body, None).await;
}
