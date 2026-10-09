use anyhow::Result;
use chrono::Utc;
use std::path::PathBuf;
use std::time::Duration;

use crate::connector_client::ConnectorClient;

pub async fn run(client: &ConnectorClient, session_id: &str, interval_seconds: u64) -> Result<()> {
    let state_dir = std::env::current_dir()?.join(".devguard");
    std::fs::create_dir_all(&state_dir)?;
    let heartbeat_path = state_dir.join("live.heartbeat");
    let state_path = state_dir.join("live_state.json");

    loop {
        let now = Utc::now();
        let status = build_live_state(client, session_id).await;
        let state = serde_json::json!({
            "session_id": session_id,
            "timestamp": now.to_rfc3339(),
            "working": status.working,
            "last_action": status.last_action,
            "blocked_count": status.blocked_count,
            "approvals_pending": status.approvals_pending,
            "stats": status.stats,
        });
        let _ = std::fs::write(&heartbeat_path, now.timestamp().to_string());
        let _ = std::fs::write(&state_path, serde_json::to_string_pretty(&state)?);
        tokio::time::sleep(Duration::from_secs(interval_seconds.max(1))).await;
    }
}

pub fn read_live_state(workspace: PathBuf) -> Option<serde_json::Value> {
    let state_path = workspace.join(".devguard/live_state.json");
    let raw = std::fs::read_to_string(state_path).ok()?;
    serde_json::from_str(&raw).ok()
}

struct LiveSnapshot {
    working: bool,
    last_action: String,
    blocked_count: u64,
    approvals_pending: u64,
    stats: serde_json::Value,
}

async fn build_live_state(client: &ConnectorClient, session_id: &str) -> LiveSnapshot {
    let session = client.session_status(session_id).await.ok();
    let trail = client.audit_trail(session_id).await.ok();
    let mut last_action = "none".to_string();
    let mut blocked_count = 0u64;
    let mut approvals_pending = 0u64;
    if let Some(trail) = trail {
        if let Some(entries) = trail.get("entries").and_then(|v| v.as_array()) {
            for e in entries.iter().rev() {
                if last_action == "none" {
                    if let Some(a) = e.get("action").and_then(|v| v.as_str()) {
                        if !a.is_empty() {
                            last_action = a.to_string();
                        }
                    }
                }
                let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("");
                if action.contains("deny") || action.contains("blocked") {
                    blocked_count += 1;
                }
                let details = e.get("details").cloned().unwrap_or_default();
                let typ = details.get("type").or_else(|| e.get("type")).and_then(|v| v.as_str()).unwrap_or("");
                if typ == "approval.created" {
                    approvals_pending += 1;
                }
                if typ == "approval.approved" || typ == "approval.rejected" || typ == "approval.expired" {
                    approvals_pending = approvals_pending.saturating_sub(1);
                }
            }
        }
    }
    let stats = session
        .as_ref()
        .and_then(|s| s.get("session").or_else(|| Some(s)))
        .and_then(|s| s.get("stats"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let working = session
        .as_ref()
        .and_then(|s| s.get("session").or_else(|| Some(s)))
        .and_then(|s| s.get("active"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    LiveSnapshot {
        working,
        last_action,
        blocked_count,
        approvals_pending,
        stats,
    }
}
