//! `devguard approvals` — manage pending approvals via kernel HITL HTTP (DG-09).

use anyhow::{bail, Result};
use crate::connector_client::ConnectorClient;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};

pub async fn list(client: &ConnectorClient, session: Option<&str>) -> Result<()> {
    let sessions = client.session_list().await?;
    let empty = vec![];
    let sess_arr = sessions.get("sessions").and_then(|v| v.as_array()).unwrap_or(&empty);

    if sess_arr.is_empty() {
        println!("No active sessions. Run `devguard connect <tool>` first.");
        return Ok(());
    }

    let mut found_any = false;
    println!(
        "{:<14} {:<10} {:<34} {:<8} {:<12} {:<16}",
        "APPROVAL", "STATUS", "ACTION", "RISK", "TIME_LEFT", "SESSION"
    );
    println!("{}", "─".repeat(106));

    for sess in sess_arr {
        let sid = sess.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
        let agent_pid = sess
            .get("agent_pid")
            .or_else(|| sess.get("pid"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(filter) = session {
            if sid != filter {
                continue;
            }
        }

        // Prefer live kernel HITL queue when agent_pid is known.
        if !agent_pid.is_empty() {
            if let Ok(pending) = client.hitl_pending(agent_pid).await {
                let rows = pending
                    .get("requests")
                    .or_else(|| pending.get("pending"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                for r in rows {
                    found_any = true;
                    let id = r
                        .get("request_id")
                        .or_else(|| r.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let action = r
                        .get("summary")
                        .or_else(|| r.get("action"))
                        .or_else(|| r.get("operation"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("hitl");
                    let risk = r.get("risk").and_then(|v| v.as_str()).unwrap_or("MEDIUM");
                    let expires = r
                        .get("expires_at")
                        .and_then(|v| v.as_str())
                        .and_then(parse_ts)
                        .map(format_time_left)
                        .unwrap_or_else(|| "-".into());
                    println!(
                        "{:<14} {:<10} {:<34} {:<8} {:<12} {:<16}",
                        truncate(id, 14),
                        "PENDING",
                        truncate(action, 34),
                        risk,
                        expires,
                        truncate(sid, 16),
                    );
                }
            }
        }

        // Also show session audit trail (historical).
        if let Ok(trail) = client.audit_trail(sid).await {
            let entries = trail
                .get("entries")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for r in resolved_approvals(&entries).into_iter().take(8) {
                found_any = true;
                println!(
                    "{:<14} {:<10} {:<34} {:<8} {:<12} {:<16}",
                    truncate(&r.id, 14),
                    r.status,
                    truncate(&r.action, 34),
                    r.risk,
                    "-",
                    truncate(sid, 16),
                );
            }
            let _ = pending_approvals(&entries);
        }
    }

    if !found_any {
        println!("  No pending approvals or denials found.");
        println!("  Tip: approve/deny use POST /api/v1/agents/:pid/hitl/:id/{{approve,deny}}");
    }

    Ok(())
}

#[derive(Clone)]
struct PendingRow {
    id: String,
    action: String,
    risk: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct ResolvedRow {
    id: String,
    action: String,
    risk: String,
    status: String,
}

fn pending_approvals(entries: &[serde_json::Value]) -> Vec<PendingRow> {
    let mut created: HashMap<String, PendingRow> = HashMap::new();
    let mut resolved: HashSet<String> = HashSet::new();
    for entry in entries {
        let details = entry.get("details").cloned().unwrap_or_default();
        let typ = details
            .get("type")
            .or_else(|| entry.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let id = details
            .get("approval_id")
            .or_else(|| entry.get("approval_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if id.is_empty() {
            continue;
        }
        if typ == "approval.created" {
            let action = details
                .get("summary")
                .or_else(|| details.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("approval required")
                .to_string();
            let risk = details
                .get("risk")
                .and_then(|v| v.as_str())
                .unwrap_or("MEDIUM")
                .to_string();
            let created_at = entry
                .get("timestamp")
                .or_else(|| details.get("timestamp"))
                .and_then(|v| v.as_str())
                .and_then(parse_ts)
                .unwrap_or_else(Utc::now);
            created.insert(
                id.to_string(),
                PendingRow {
                    id: id.to_string(),
                    action,
                    risk,
                    expires_at: created_at + Duration::minutes(30),
                },
            );
        }
        if typ == "approval.approved" || typ == "approval.rejected" || typ == "approval.expired" {
            resolved.insert(id.to_string());
        }
    }
    created
        .into_values()
        .filter(|p| !resolved.contains(&p.id))
        .collect()
}

fn resolved_approvals(entries: &[serde_json::Value]) -> Vec<ResolvedRow> {
    let mut out = Vec::new();
    for entry in entries {
        let details = entry.get("details").cloned().unwrap_or_default();
        let typ = details
            .get("type")
            .or_else(|| entry.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let status = match typ {
            "approval.approved" => Some("APPROVED"),
            "approval.rejected" => Some("REJECTED"),
            "approval.expired" => Some("EXPIRED"),
            _ => None,
        };
        if let Some(status) = status {
            let id = details
                .get("approval_id")
                .or_else(|| entry.get("approval_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let action = details
                .get("summary")
                .or_else(|| details.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("approval")
                .to_string();
            let risk = details
                .get("risk")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string();
            out.push(ResolvedRow {
                id,
                action,
                risk,
                status: status.to_string(),
            });
        }
    }
    out
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn format_time_left(expires_at: DateTime<Utc>) -> String {
    let now = Utc::now();
    if expires_at <= now {
        "expired".to_string()
    } else {
        let d = expires_at - now;
        let mins = d.num_minutes();
        let secs = d.num_seconds() - mins * 60;
        format!("{}m {}s", mins, secs.max(0))
    }
}

fn truncate(s: &str, width: usize) -> String {
    if s.len() <= width {
        s.to_string()
    } else {
        format!("{}...", &s[..width.saturating_sub(3)])
    }
}

async fn resolve_agent_pid(client: &ConnectorClient, hint: Option<&str>) -> Result<String> {
    if let Some(pid) = hint.filter(|s| !s.is_empty()) {
        return Ok(pid.to_string());
    }
    let sessions = client.session_list().await?;
    let empty = vec![];
    let sess_arr = sessions.get("sessions").and_then(|v| v.as_array()).unwrap_or(&empty);
    for sess in sess_arr {
        if let Some(pid) = sess
            .get("agent_pid")
            .or_else(|| sess.get("pid"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            return Ok(pid.to_string());
        }
    }
    bail!("No agent_pid found — pass --session or run `devguard connect` first")
}

pub async fn approve(client: &ConnectorClient, id: &str) -> Result<()> {
    println!("Approving via kernel HITL: {}", id);
    let agent_pid = resolve_agent_pid(client, None).await?;
    let resp = client.hitl_approve(&agent_pid, id).await?;
    if resp.get("error").is_some() || resp.get("ok") == Some(&serde_json::json!(false)) {
        bail!("HITL approve failed: {}", resp);
    }
    println!("✓ Approved (HITL): {} on agent {}", id, agent_pid);
    Ok(())
}

pub async fn reject(client: &ConnectorClient, id: &str, reason: Option<&str>) -> Result<()> {
    let reason_str = reason.unwrap_or("Rejected by operator");
    println!("Denying via kernel HITL: {} ({})", id, reason_str);
    let agent_pid = resolve_agent_pid(client, None).await?;
    let resp = client.hitl_deny(&agent_pid, id, Some(reason_str)).await?;
    if resp.get("error").is_some() || resp.get("ok") == Some(&serde_json::json!(false)) {
        bail!("HITL deny failed: {}", resp);
    }
    println!("✗ Denied (HITL): {} on agent {}", id, agent_pid);
    Ok(())
}
