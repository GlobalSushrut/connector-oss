//! Playground session export + self-deploy import.
//!
//! Two endpoints that close the trial-to-production loop (plan §6.3):
//!
//! - `GET  /api/v1/playground/session/export` (P1-22) — emits a
//!   tar.gz snapshot of the current playground session. The dashboard
//!   downloads it from the "Save this session" banner and the
//!   `/install` page.
//!
//! - `POST /api/v1/import/playground-session` (P1-23) — accepts the
//!   same archive on a fresh self-deploy node so the first-run wizard
//!   can pre-populate plugins, workflows and agents.
//!
//! The format is deliberately minimal: a tar.gz containing one
//! `session.json` envelope. Workflow CCL sources and agent metadata
//! are inline; secrets / API keys are scrubbed because playground
//! issues them per-session.

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Write;

use crate::{auth, state::SharedState};

const IMPORT_FOLDER: &str = "import_sessions";

fn snapshot_session(state: &SharedState, session_id: &str) -> Value {
    let Some(session) = ({
        let sessions = state.playground_sessions.lock().ok();
        sessions.and_then(|s| s.get(session_id).cloned())
    }) else {
        return json!({
            "schema_version": "playground-session.v1",
            "error": "playground session not found",
            "session_id": session_id,
        });
    };
    let workflows: Vec<Value> = {
        let mut es = state.engine_store.lock().unwrap();
        session
            .workflow_ids
            .iter()
            .filter_map(|k| es.folder_get("workflow_runtime", k).ok().flatten())
            .collect()
    };
    let agents: Vec<Value> = {
        let mut es = state.engine_store.lock().unwrap();
        session
            .agent_pids
            .iter()
            .filter_map(|k| es.folder_get("agents", k).ok().flatten())
            .collect()
    };
    json!({
        "schema_version": "playground-session.v1",
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "session_id": session.session_id,
        "tenant_id": session.tenant_id,
        "deployment": crate::services::deployment::deployment_info_value(state.as_ref()),
        "workflows": workflows,
        "agents": agents,
        "note": "Secrets / api_keys are deliberately omitted — self-deploy issues its own.",
    })
}

/// Build a tar.gz containing a single `session.json` entry.
fn build_tarball(snapshot: &Value) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec_pretty(snapshot).map_err(|e| e.to_string())?;
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = tar::Builder::new(&mut gz);
        let mut header = tar::Header::new_gnu();
        header.set_path("session.json").map_err(|e| e.to_string())?;
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(chrono::Utc::now().timestamp() as u64);
        header.set_cksum();
        tar.append(&header, payload.as_slice())
            .map_err(|e| e.to_string())?;
        tar.finish().map_err(|e| e.to_string())?;
    }
    gz.finish().map_err(|e| e.to_string())
}

/// `GET /api/v1/playground/session/export`
pub async fn export(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    // Playground sessions authenticate via bearer cpk_* keys; the
    // standard claims extractor is enough — we just need someone
    // authenticated. Dev bypass mirrors every other handler.
    if !crate::services::runtime_control::dev_auth_bypass_allowed()
        && auth::extract_claims(&headers).is_none()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "Unauthorized"})),
        )
            .into_response();
    }

    let Some(claims) = auth::extract_claims(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "Unauthorized"})),
        )
            .into_response();
    };
    let snapshot = snapshot_session(&state, &claims.sub);
    match build_tarball(&snapshot) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/gzip"),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static(
                        "attachment; filename=\"connector-trial-session.tar.gz\"",
                    ),
                ),
            ],
            Body::from(bytes),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": format!("tar.gz build failed: {e}")})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    /// Either an inline session.json envelope or `null` to import from
    /// the on-disk staging directory (`/var/lib/connector/import/`).
    #[serde(default)]
    pub session: Option<Value>,
    /// Set true to clobber existing workflows / agents on conflict.
    /// Defaults to false (skip-conflict).
    #[serde(default)]
    pub overwrite: bool,
}

/// `POST /api/v1/import/playground-session`
pub async fn import(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Option<Json<ImportRequest>>,
) -> Json<Value> {
    if !crate::services::runtime_control::dev_auth_bypass_allowed()
        && auth::extract_claims(&headers).is_none()
    {
        return Json(json!({"ok": false, "error": "Unauthorized"}));
    }
    let Some(Json(req)) = body else {
        return Json(json!({"ok": false, "error": "session payload required"}));
    };

    let envelope = match req.session {
        Some(v) => v,
        None => {
            return Json(json!({
                "ok": false,
                "error": "On-disk staging import (/var/lib/connector/import/) not yet implemented — pass `session` inline.",
                "code": "IMPORT_STAGING_NOT_AVAILABLE",
            }));
        }
    };

    if envelope.get("schema_version").and_then(|v| v.as_str()) != Some("playground-session.v1") {
        return Json(json!({
            "ok": false,
            "error": "Unrecognised schema_version. Export was generated by an incompatible version.",
        }));
    }

    let workflows = envelope
        .get("workflows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let agents = envelope
        .get("agents")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut workflow_imported = 0_usize;
    let mut workflow_skipped = 0_usize;
    {
        let mut es = state.engine_store.lock().unwrap();
        for wf in &workflows {
            let Some(id) = wf.get("workflow_id").and_then(|v| v.as_str()) else {
                continue;
            };
            let exists = es
                .folder_get("workflow_runtime", id)
                .ok()
                .flatten()
                .is_some();
            if exists && !req.overwrite {
                workflow_skipped += 1;
                continue;
            }
            if es.folder_put("workflow_runtime", id, wf).is_ok() {
                workflow_imported += 1;
            }
        }
    }

    // Stash the raw envelope for forensic / debug audit so the
    // first-run wizard can re-render it later if needed.
    {
        let mut es = state.engine_store.lock().unwrap();
        let key = chrono::Utc::now().timestamp_millis().to_string();
        let _ = es.folder_put(IMPORT_FOLDER, &key, &envelope);
    }

    Json(json!({
        "ok": true,
        "schema_version": "playground-session.v1",
        "imported": {
            "workflows": workflow_imported,
            "workflows_skipped": workflow_skipped,
            "agents_seen": agents.len(),
        },
        "hint": "Open /workflows to verify the imported records, then run /setup to finish first-run.",
    }))
}
