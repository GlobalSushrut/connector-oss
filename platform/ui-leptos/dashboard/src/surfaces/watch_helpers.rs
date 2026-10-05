//! Shared WATCH event parsing for RUN strip + WATCH canvas.

use serde_json::Value;

#[derive(Clone, Debug)]
pub struct WatchEventVm {
    pub id: String,
    pub time: String,
    pub decision: &'static str,
    pub agent: String,
    pub action: String,
    pub resource: String,
    pub workflow_id: Option<String>,
    pub summary: String,
    pub kind: String,
    /// Deny reason / error code when present (SGKE, admission, …).
    pub reason: String,
    pub error_code: String,
}

pub fn parse_watch_events(v: &Value) -> Vec<WatchEventVm> {
    v.get("events")
        .or_else(|| v.get("items"))
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(parse_one).collect())
        .unwrap_or_default()
}

pub fn next_cursor(v: &Value) -> Option<String> {
    v.get("next_cursor")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parse_one(e: &Value) -> Option<WatchEventVm> {
    let decision = match e
        .get("decision")
        .or_else(|| e.get("outcome"))
        .and_then(|x| x.as_str())
        .unwrap_or("info")
        .to_ascii_lowercase()
        .as_str()
    {
        "allow" | "allowed" | "ok" | "success" | "completed" | "approved" => "allow",
        "deny" | "denied" | "error" | "fail" | "failed" | "blocked" | "reject" | "rejected" => {
            "deny"
        }
        _ => "info",
    };
    let workflow_id = e
        .get("workflow_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let time = e
        .get("time")
        .or_else(|| e.get("ts"))
        .or_else(|| e.get("timestamp"))
        .map(format_ts)
        .unwrap_or_else(|| "—".into());
    let reason = e
        .get("reason")
        .or_else(|| e.get("message"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let error_code = e
        .get("error")
        .or_else(|| e.get("error_code"))
        .or_else(|| e.get("code"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    Some(WatchEventVm {
        id: e
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        time,
        decision,
        agent: e
            .get("agent_pid")
            .or_else(|| e.get("agent"))
            .and_then(|x| x.as_str())
            .unwrap_or("—")
            .to_string(),
        action: e
            .get("action")
            .or_else(|| e.get("kind"))
            .and_then(|x| x.as_str())
            .unwrap_or("—")
            .to_string(),
        resource: e
            .get("resource")
            .or_else(|| e.get("target"))
            .and_then(|x| x.as_str())
            .unwrap_or("—")
            .to_string(),
        workflow_id,
        summary: e
            .get("summary")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        kind: e
            .get("kind")
            .and_then(|x| x.as_str())
            .unwrap_or("action")
            .to_string(),
        reason,
        error_code,
    })
}

/// True when reason/error looks like an SGKE deny (P6.6).
pub fn is_sgke_deny(reason: &str, error_code: &str) -> bool {
    let blob = format!("{reason} {error_code}").to_ascii_lowercase();
    blob.contains("sgke")
        || blob.contains("denied-by-sgke")
        || blob.contains("sgke_high_i_missing_h")
}

fn format_ts(v: &Value) -> String {
    if let Some(s) = v.as_str() {
        return short_time(s);
    }
    if let Some(n) = v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)) {
        // ms epoch from AAPI
        let secs = if n > 10_000_000_000 { n / 1000 } else { n };
        return format!("t+{secs}");
    }
    "—".into()
}

fn short_time(s: &str) -> String {
    if let Some(t) = s.split('T').nth(1) {
        return t.chars().take(8).collect();
    }
    if s.len() > 12 {
        s.chars()
            .rev()
            .take(8)
            .collect::<String>()
            .chars()
            .rev()
            .collect()
    } else {
        s.to_string()
    }
}

pub fn filter_events(
    events: &[WatchEventVm],
    decision_filter: &str,
    search: &str,
) -> Vec<WatchEventVm> {
    let q = search.trim().to_ascii_lowercase();
    events
        .iter()
        .filter(|e| {
            let dec_ok = match decision_filter {
                "allow" => e.decision == "allow",
                "deny" => e.decision == "deny",
                "info" => e.decision == "info",
                _ => true,
            };
            if !dec_ok {
                return false;
            }
            if q.is_empty() {
                return true;
            }
            e.agent.to_ascii_lowercase().contains(&q)
                || e.action.to_ascii_lowercase().contains(&q)
                || e.resource.to_ascii_lowercase().contains(&q)
                || e.summary.to_ascii_lowercase().contains(&q)
                || e.reason.to_ascii_lowercase().contains(&q)
                || e.error_code.to_ascii_lowercase().contains(&q)
                || e.workflow_id
                    .as_ref()
                    .map(|w| w.to_ascii_lowercase().contains(&q))
                    .unwrap_or(false)
        })
        .cloned()
        .collect()
}
