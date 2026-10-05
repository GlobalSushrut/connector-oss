//! BIZ-7: Activation funnel telemetry — structured JSON events per lifecycle milestone.
//!
//! Fires one structured JSON event per lifecycle milestone:
//!   - `agent.registered`   — new agent created
//!   - `agent.first_run`    — first cognitive cycle for an agent
//!   - `agent.suspended`    — agent suspended (triggers consolidation)
//!   - `agent.terminated`   — agent terminated
//!   - `tool.invoked`       — tool call dispatched successfully
//!   - `memory.written`     — memory packet stored
//!   - `user.signup`        — new account created
//!   - `billing.upgraded`   — tier upgrade event
//!   - `reflection.written` — reflection packet generated
//!
//! Events are written to the engine_store under `analytics_events/<event_id>`
//! and optionally forwarded to a webhook via `CONNECTOR_ANALYTICS_WEBHOOK_URL`.
//!
//! Routes:
//!   GET  /api/v1/analytics/events          — recent events (last 100)
//!   GET  /api/v1/analytics/funnel          — activation funnel counts
//!   POST /api/v1/analytics/events (internal) — emit event

use crate::auth::extract_claims;
use crate::state::SharedState;
use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

// ── Event model ───────────────────────────────────────────────────────────────

/// Structured lifecycle event. One per milestone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    /// Unique event ID (ms-epoch + random suffix)
    pub event_id: String,
    /// Event type slug (e.g. "agent.registered")
    pub event_type: String,
    /// Account or agent ID affected
    pub principal_id: String,
    /// Optional agent PID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    /// Optional session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Arbitrary event metadata (tier, model, namespace, etc.)
    pub properties: serde_json::Value,
    /// ISO-8601 timestamp
    pub ts: String,
    /// Epoch ms
    pub ts_ms: i64,
}

impl AnalyticsEvent {
    pub fn new(
        event_type: impl Into<String>,
        principal_id: impl Into<String>,
        properties: serde_json::Value,
    ) -> Self {
        let ts_ms = chrono::Utc::now().timestamp_millis();
        Self {
            event_id: format!("evt_{}_{}", ts_ms, uuid::Uuid::new_v4().simple()),
            event_type: event_type.into(),
            principal_id: principal_id.into(),
            agent_pid: None,
            session_id: None,
            properties,
            ts: chrono::Utc::now().to_rfc3339(),
            ts_ms,
        }
    }

    pub fn with_agent(mut self, pid: impl Into<String>) -> Self {
        self.agent_pid = Some(pid.into());
        self
    }
}

// ── Emit helper (called from other services) ─────────────────────────────────

/// Fire a structured analytics event. Non-blocking — writes to engine_store.
///
/// Call this after every lifecycle milestone:
/// ```rust
/// analytics::emit(&state, AnalyticsEvent::new("agent.registered", &user_id, json!({
///     "agent_pid": pid, "namespace": ns
/// })));
/// ```
pub fn emit(state: &crate::state::PlatformState, event: AnalyticsEvent) {
    // Persist to engine_store for GET /analytics/events
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "analytics_events",
            &event.event_id,
            &serde_json::to_value(&event).unwrap_or_default(),
        );
    }

    // Respect CONNECTOR_ANALYTICS_DISABLED — skip webhook, local store still written
    let disabled = std::env::var("CONNECTOR_ANALYTICS_DISABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if disabled {
        return;
    }

    // Optional webhook forward
    let webhook_url = std::env::var("CONNECTOR_ANALYTICS_WEBHOOK_URL").ok();
    if let Some(url) = webhook_url {
        let event_json = serde_json::to_string(&event).unwrap_or_default();
        tracing::debug!(event_type = %event.event_type, url = %url, payload = %event_json, "analytics: forwarding event to webhook");
        // Fire-and-forget via a spawned task (non-blocking, best-effort)
        let _ = std::thread::Builder::new()
            .name("analytics-webhook".into())
            .spawn(move || {
                // Best-effort HTTP POST — errors are logged, never propagated
                if let Ok(client) = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(3))
                    .build()
                {
                    let _ = client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .body(event_json)
                        .send();
                }
            });
    }

    tracing::info!(
        event_type = %event.event_type,
        principal = %event.principal_id,
        "analytics: event emitted"
    );
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// GET /api/v1/analytics/events — return last 100 events for the authenticated user
pub async fn list_events(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    let events: Vec<serde_json::Value> = {
        let es = state.engine_store.lock().unwrap();
        let mut all: Vec<(String, serde_json::Value)> = es
            .folder_keys("analytics_events", None)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|k| {
                es.folder_get("analytics_events", &k)
                    .ok()
                    .flatten()
                    .map(|v| (k, v))
            })
            .filter(|(_, v)| {
                v.get("principal_id")
                    .and_then(|p| p.as_str())
                    .map(|p| {
                        p == claims.sub
                            || v.get("agent_pid")
                                .and_then(|a| a.as_str())
                                .map(|a| a.starts_with(&claims.sub))
                                .unwrap_or(false)
                    })
                    .unwrap_or(true) // include unattributed events for admin
            })
            .collect();

        // Sort by ts_ms descending, take last 100
        all.sort_by(|a, b| {
            let ta = a.1.get("ts_ms").and_then(|v| v.as_i64()).unwrap_or(0);
            let tb = b.1.get("ts_ms").and_then(|v| v.as_i64()).unwrap_or(0);
            tb.cmp(&ta)
        });
        all.into_iter().take(100).map(|(_, v)| v).collect()
    };

    Json(serde_json::json!({
        "ok": true,
        "events": events,
        "count": events.len(),
    }))
}

/// GET /api/v1/analytics/funnel — activation funnel counts
///
/// Returns counts for each funnel stage:
///   signup → first_run → first_deploy → first_paid_call
pub async fn funnel(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let _claims = match extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    let es = state.engine_store.lock().unwrap();
    let all_events: Vec<serde_json::Value> = es
        .folder_keys("analytics_events", None)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|k| es.folder_get("analytics_events", &k).ok().flatten())
        .collect();
    drop(es);

    let count_type = |t: &str| -> u64 {
        all_events
            .iter()
            .filter(|e| e.get("event_type").and_then(|v| v.as_str()) == Some(t))
            .count() as u64
    };

    Json(serde_json::json!({
        "ok": true,
        "funnel": {
            "signup":          count_type("user.signup"),
            "first_run":       count_type("agent.first_run"),
            "first_deploy":    count_type("agent.registered"),
            "tool_invoked":    count_type("tool.invoked"),
            "reflection":      count_type("reflection.written"),
            "billing_upgrade": count_type("billing.upgraded"),
        },
        "total_events": all_events.len(),
    }))
}

/// POST /api/v1/analytics/events — internal event emission endpoint
pub async fn emit_event(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let _claims = match extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    let event_type = body
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("custom");
    let principal_id = body
        .get("principal_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let properties = body
        .get("properties")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let mut event = AnalyticsEvent::new(event_type, principal_id, properties);
    if let Some(pid) = body.get("agent_pid").and_then(|v| v.as_str()) {
        event = event.with_agent(pid);
    }

    let event_id = event.event_id.clone();
    let subject = event
        .agent_pid
        .clone()
        .filter(|pid| !pid.is_empty())
        .unwrap_or_else(|| "analytics".into());
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &subject,
        "analytics",
        "emit_analytics_event",
        &serde_json::json!({"event_type": event_type, "event_id": event_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    emit(&state, event);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "event_id": event_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}
