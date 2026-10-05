//! Short HTTP probes for optional plugin management URLs (`GET /plugins/status`).

use std::time::Duration;

pub fn witnessctl_management_url() -> Option<String> {
    let u = std::env::var("CONNECTOR_WITNESSCTL_MANAGEMENT_URL")
        .or_else(|_| std::env::var("WITNESSCTL_MANAGEMENT_URL"))
        .ok()
        .or_else(|| {
            crate::services::plugin_configure::overlay_string("witnessctl", "management_url")
        })
        .unwrap_or_default();
    let u = u.trim().to_string();
    if u.is_empty() {
        None
    } else {
        Some(u.trim_end_matches('/').to_string())
    }
}

pub fn devguard_management_url() -> Option<String> {
    let u = std::env::var("CONNECTOR_DEVGUARD_MANAGEMENT_URL")
        .or_else(|_| std::env::var("DEVGUARD_MANAGEMENT_URL"))
        .ok()
        .or_else(|| crate::services::plugin_configure::overlay_string("devguard", "management_url"))
        .unwrap_or_default();
    let u = u.trim().to_string();
    if u.is_empty() {
        None
    } else {
        Some(u.trim_end_matches('/').to_string())
    }
}

/// Host (and optional port) for operator UI — no path, no credentials.
pub fn management_display_host(raw: &str) -> String {
    let t = raw.trim();
    let rest = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let host = rest.split('/').next().unwrap_or(rest);
    if host.len() > 72 {
        format!("{}…", &host[..69])
    } else {
        host.to_string()
    }
}

async fn probe_get_2xx(url: &str) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .connect_timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// `GET {base}/health` (WitnessCtl exposes this without API auth).
pub async fn witnessctl_upstream_reachable() -> Option<bool> {
    let base = witnessctl_management_url()?;
    let url = format!("{}/health", base);
    Some(probe_get_2xx(&url).await)
}

/// Try DevGuard extension `GET {base}/devguard/status`, then generic `GET {base}/health`.
pub async fn devguard_upstream_reachable() -> Option<bool> {
    let base = devguard_management_url()?;
    let url = format!("{}/devguard/status", base);
    if probe_get_2xx(&url).await {
        return Some(true);
    }
    let url2 = format!("{}/health", base);
    Some(probe_get_2xx(&url2).await)
}
