//! Setup wizard hub + recommendations engine.
//!
//! Implements the small server surface the Leptos `/setup` hub and
//! Overview "Recommended next steps" panel read from:
//!
//! - `GET  /api/v1/setup/state`           — which wizards are done /
//!   in-progress / not started. The dashboard already mirrors wizard
//!   state in `localStorage["wizard:<id>"]`; this endpoint is the
//!   server-authoritative view useful for cross-device sync and CLI.
//! - `POST /api/v1/setup/dismiss`         — mark a wizard skipped.
//!   Optional per plan §4.3 (localStorage is the primary store); the
//!   endpoint exists so a `connectorctl` invocation or a teammate's
//!   parallel session can also dismiss.
//! - `GET  /api/v1/setup/recommendations` — up to three "what to do
//!   next" cards computed from the current node state.
//!
//! State is persisted in the engine_store under the `setup` folder, so
//! it survives restarts and is per-tenant when the engine is in
//! multi-tenant mode.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth, state::SharedState};

const SETUP_FOLDER: &str = "setup_state";

/// Canonical wizard ids the dashboard ships. The list is kept in sync
/// with `pages/setup.rs::WIZARDS` in the Leptos crate. New wizards
/// added there should be appended here; the server uses this list to
/// fan out a "not started" entry when nothing is persisted.
const KNOWN_WIZARDS: &[&str] = &[
    "first_run",
    "connect_tool",
    "install_workflow",
    "devguard_setup",
    "tracetramp_setup",
    "witnessctl_setup",
    "first_agent",
    "first_budget",
    "invite_teammate",
];

#[derive(Debug, Deserialize)]
pub struct DismissRequest {
    pub wizard_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

fn read_state_entry(state: &SharedState, wizard_id: &str) -> Value {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(SETUP_FOLDER, wizard_id)
        .ok()
        .flatten()
        .unwrap_or(Value::Null)
}

fn write_state_entry(state: &SharedState, wizard_id: &str, value: &Value) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(SETUP_FOLDER, wizard_id, value);
}

/// `GET /api/v1/setup/state` — wizard-by-wizard completion summary.
pub async fn get_state(State(state): State<SharedState>) -> Json<Value> {
    let mut wizards = Vec::with_capacity(KNOWN_WIZARDS.len());
    for id in KNOWN_WIZARDS {
        let entry = read_state_entry(&state, id);
        let status = entry
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("not_started")
            .to_string();
        let updated_at = entry
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        wizards.push(json!({
            "id": id,
            "status": status,
            "updated_at": updated_at,
        }));
    }
    let next = wizards
        .iter()
        .find(|w| {
            w.get("status")
                .and_then(|v| v.as_str())
                .map(|s| s != "completed" && s != "dismissed")
                .unwrap_or(true)
        })
        .and_then(|w| w.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()));
    Json(json!({
        "ok": true,
        "wizards": wizards,
        "next_wizard_id": next,
        "hint": "Persisted server-side under engine_store/setup_state — dashboard mirrors in localStorage for offline UX.",
    }))
}

/// `POST /api/v1/setup/dismiss`
pub async fn dismiss(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<DismissRequest>,
) -> Json<Value> {
    // Anyone authenticated can dismiss their own wizard step. Viewers
    // included — dismissing is a no-op on the data plane.
    if !crate::services::runtime_control::dev_auth_bypass_allowed()
        && auth::extract_claims(&headers).is_none()
    {
        return Json(json!({"ok": false, "error": "Unauthorized"}));
    }
    if req.wizard_id.trim().is_empty() {
        return Json(json!({"ok": false, "error": "wizard_id required"}));
    }
    let entry = json!({
        "status": "dismissed",
        "reason": req.reason.unwrap_or_default(),
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    write_state_entry(&state, &req.wizard_id, &entry);
    Json(json!({"ok": true, "wizard_id": req.wizard_id, "status": "dismissed"}))
}

#[derive(Debug, Deserialize)]
pub struct CompleteRequest {
    pub wizard_id: String,
}

/// `POST /api/v1/setup/complete` — mark a wizard finished (server-side mirror of
/// `localStorage[wizard:<id>:completed]`).
pub async fn complete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> Json<Value> {
    if !crate::services::runtime_control::dev_auth_bypass_allowed()
        && auth::extract_claims(&headers).is_none()
    {
        return Json(json!({"ok": false, "error": "Unauthorized"}));
    }
    let id = req.wizard_id.trim();
    if id.is_empty() {
        return Json(json!({"ok": false, "error": "wizard_id required"}));
    }
    // Accept both kebab (dashboard) and snake (KNOWN_WIZARDS) forms.
    let canonical = id.replace('-', "_");
    let entry = json!({
        "status": "completed",
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    write_state_entry(&state, &canonical, &entry);
    Json(json!({
        "ok": true,
        "wizard_id": canonical,
        "status": "completed",
    }))
}

/// `GET /api/v1/setup/recommendations`
///
/// Up to three suggestions derived from the current node state:
/// installed workflows, registered agents, budgets, license tier.
/// Dashboard renders each as a card on Overview; tapping the CTA
/// deep-links to the relevant page.
pub async fn recommendations(State(state): State<SharedState>) -> Json<Value> {
    let mut recs: Vec<Value> = Vec::new();

    // Snapshot a few state hints with a single engine_store lock.
    let (workflow_count, agent_count) = {
        let es = state.engine_store.lock().unwrap();
        let wf = es
            .folder_keys("workflow_runtime", None)
            .map(|k| k.len())
            .unwrap_or(0);
        let ag = es.folder_keys("agents", None).map(|k| k.len()).unwrap_or(0);
        (wf, ag)
    };

    if workflow_count == 0 {
        recs.push(json!({
            "id": "install_workflow",
            "title": "Install a pre-built workflow",
            "summary": "Three reference templates ship with Connector — one click, no Builder hop.",
            "cta_label": "Open Apps",
            "cta_path": "/apps#pre-built",
        }));
    }
    if agent_count == 0 {
        recs.push(json!({
            "id": "create_agent",
            "title": "Create your first agent",
            "summary": "Agents are the unit of work. Spin up one with a 30-second wizard.",
            "cta_label": "Open Agents",
            "cta_path": "/agents?new=1",
        }));
    }

    // Budget reminder regardless of state — billing pages are gated
    // off in playground, but on self-deploy a fresh node has no
    // budget set and operators are reminded once.
    let budgets = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("budgets", None)
            .map(|k| k.len())
            .unwrap_or(0)
    };
    if budgets == 0 && recs.len() < 3 {
        recs.push(json!({
            "id": "set_budget",
            "title": "Set a budget",
            "summary": "Caps protect spend even before LLM keys are wired in.",
            "cta_label": "Open Billing",
            "cta_path": "/billing/setup-budget",
        }));
    }

    if recs.len() < 3 {
        recs.push(json!({
            "id": "invite_teammate",
            "title": "Invite a teammate",
            "summary": "Add a teammate so a second pair of eyes is on every approval gate.",
            "cta_label": "Open Setup Hub",
            "cta_path": "/setup/invite",
        }));
    }

    // Cap to 3 — the Overview slot is intentionally tight.
    recs.truncate(3);

    Json(json!({
        "ok": true,
        "recommendations": recs,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    }))
}
