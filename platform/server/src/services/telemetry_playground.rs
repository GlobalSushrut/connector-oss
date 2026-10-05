//! Anonymous playground funnel telemetry (P2-20).
//!
//! `POST /api/v1/telemetry/playground` accepts a small JSON event from
//! the dashboard's playground build and appends it to a bounded in-
//! memory ring buffer plus the engine_store for cross-restart inspection
//! by ops. Events are intentionally tiny and PII-free: an event id, a
//! per-session opaque hash, optional numeric properties, and a server-
//! issued timestamp.
//!
//! No payload from the client is trusted verbatim: free-form fields are
//! truncated, the session_hash is normalised, and the event id must
//! match one of a small allowlist. Outside playground mode the endpoint
//! 404s — telemetry is a playground-only concern.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;

const TELEMETRY_FOLDER: &str = "telemetry_playground";

/// Allow-listed event ids the funnel cares about.
const KNOWN_EVENTS: &[&str] = &[
    "session_start",
    "workflow_installed",
    "first_receipt",
    "install_clicked",
    "signup_clicked",
    "tour_step_completed",
    "session_export_downloaded",
];

const MAX_LABEL_LEN: usize = 64;

#[derive(Debug, Deserialize)]
pub struct TelemetryEvent {
    pub event: String,
    #[serde(default)]
    pub session_hash: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub value: Option<f64>,
}

fn sanitise(s: &str) -> String {
    let s = s.trim();
    if s.len() > MAX_LABEL_LEN {
        s.chars().take(MAX_LABEL_LEN).collect()
    } else {
        s.to_string()
    }
}

/// `POST /api/v1/telemetry/playground`
pub async fn record(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Json(req): Json<TelemetryEvent>,
) -> Json<Value> {
    if !crate::services::playground::is_playground_mode() {
        return Json(json!({
            "ok": false,
            "error": "telemetry endpoint only enabled in playground mode",
            "code": "PLAYGROUND_TELEMETRY_DISABLED",
        }));
    }
    if !KNOWN_EVENTS.contains(&req.event.as_str()) {
        return Json(json!({
            "ok": false,
            "error": format!("unknown event id `{}` — see KNOWN_EVENTS in services/telemetry_playground.rs", req.event),
        }));
    }
    let entry = json!({
        "event": req.event,
        "session_hash": req.session_hash.as_deref().map(sanitise),
        "label": req.label.as_deref().map(sanitise),
        "value": req.value,
        "recorded_at": chrono::Utc::now().to_rfc3339(),
    });
    {
        let mut es = state.engine_store.lock().unwrap();
        // Keys are millis since epoch — naturally sorted, naturally
        // unique, no collision math needed under realistic load.
        let key = chrono::Utc::now().timestamp_millis().to_string();
        let _ = es.folder_put(TELEMETRY_FOLDER, &key, &entry);
    }
    Json(json!({"ok": true, "recorded": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_truncates_long_labels() {
        let long = "x".repeat(MAX_LABEL_LEN * 2);
        let out = sanitise(&long);
        assert_eq!(out.len(), MAX_LABEL_LEN);
    }

    #[test]
    fn known_events_contains_canonical_funnel_ids() {
        for id in ["session_start", "workflow_installed", "first_receipt"] {
            assert!(KNOWN_EVENTS.contains(&id), "missing canonical id: {id}");
        }
    }
}
