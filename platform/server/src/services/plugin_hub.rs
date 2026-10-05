use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{auth, state::SharedState};

const CAP_GRANTS_FOLDER: &str = "plugin_capability_grants";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilityGrant {
    pub plugin_id: String,
    pub requested: Vec<String>,
    pub granted: Vec<String>,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCapabilityGrantRequest {
    pub granted: Vec<String>,
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), serde_json::Value> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

fn requested_caps_for(plugin_id: &str) -> Vec<String> {
    match plugin_id {
        "tracetramp" => vec![
            "aapi.evaluate".to_string(),
            "audit.write".to_string(),
            "trace.read".to_string(),
            "events.subscribe:approvals".to_string(),
            "network.outbound:api.openai.com:443".to_string(),
            "secret.read".to_string(),
        ],
        "witnessctl" => vec![
            "audit.write".to_string(),
            "trace.read".to_string(),
            "events.subscribe:evidence".to_string(),
            "secret.read".to_string(),
        ],
        _ => vec![
            "audit.write".to_string(),
            "filesystem.read".to_string(),
            "secret.read".to_string(),
        ],
    }
}

pub fn load_grant(state: &SharedState, plugin_id: &str) -> PluginCapabilityGrant {
    let requested = requested_caps_for(plugin_id);
    let es = state.engine_store.lock().unwrap();
    es.folder_get(CAP_GRANTS_FOLDER, plugin_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<PluginCapabilityGrant>(v).ok())
        .unwrap_or(PluginCapabilityGrant {
            plugin_id: plugin_id.to_string(),
            requested: requested.clone(),
            granted: requested,
            updated_at: chrono::Utc::now().to_rfc3339(),
        })
}

fn persist_grant(state: &SharedState, row: &PluginCapabilityGrant) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        CAP_GRANTS_FOLDER,
        &row.plugin_id,
        &serde_json::to_value(row).unwrap_or_default(),
    );
}

pub async fn plugin_install_preflight(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
) -> Json<serde_json::Value> {
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let grant = load_grant(&state, &plugin_id);
    Json(json!({
        "ok": true,
        "plugin_id": plugin_id,
        "requested_capabilities": grant.requested,
        "granted_capabilities": grant.granted,
        "all_requested_granted": grant.requested.iter().all(|c| grant.granted.iter().any(|g| g == c)),
        "install_cta": "Review and grant capabilities before install",
    }))
}

pub async fn update_plugin_capability_grants(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateCapabilityGrantRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let requested = requested_caps_for(&plugin_id);
    if req
        .granted
        .iter()
        .any(|g| !requested.iter().any(|r| r == g))
    {
        return Json(
            json!({"ok": false, "error": "granted capabilities must be a subset of requested"}),
        );
    }
    let row = PluginCapabilityGrant {
        plugin_id: plugin_id.clone(),
        requested,
        granted: req.granted,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    persist_grant(&state, &row);
    Json(json!({"ok": true, "plugin_id": plugin_id, "grant": row}))
}

pub async fn plugin_service_map(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mut nodes = Vec::new();
    for plugin_id in crate::services::plugin_matrix::KNOWN_PLUGINS {
        let lifecycle =
            crate::services::plugin_lifecycle::load_plugin_lifecycle_state(&state, plugin_id);
        nodes.push(json!({
            "id": plugin_id,
            "cage_host": crate::internal_dns::plugin_cage_hostname(plugin_id),
            "public_path": format!("/plugin/{plugin_id}"),
            "installed": lifecycle.installed,
            "enabled": lifecycle.enabled,
            "runtime_backend": "microvm",
            "health_probe": format!("/api/v1/plugins/{plugin_id}/status"),
        }));
    }
    let edges = vec![
        json!({"from":"tracetramp","to":"witnessctl","kind":"evidence_handoff"}),
        json!({"from":"devguard","to":"tracetramp","kind":"policy_trace_pipeline"}),
    ];
    Json(json!({"ok": true, "nodes": nodes, "edges": edges}))
}

pub async fn plugin_header_health(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mut healthy = 0usize;
    let mut degraded = 0usize;
    let mut disabled = 0usize;
    for plugin_id in crate::services::plugin_matrix::KNOWN_PLUGINS {
        let row = crate::services::plugin_lifecycle::load_plugin_lifecycle_state(&state, plugin_id);
        if !row.installed || !row.enabled {
            disabled += 1;
        } else {
            healthy += 1;
        }
    }
    let overall = if degraded > 0 {
        "degraded"
    } else if healthy > 0 {
        "ok"
    } else {
        "disabled"
    };
    Json(json!({
        "ok": true,
        "overall": overall,
        "counts": {"healthy": healthy, "degraded": degraded, "disabled": disabled},
        "pill_text": format!("Plugins: {} ok · {} disabled", healthy, disabled),
    }))
}

pub async fn plugin_installer_plan(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
) -> Json<serde_json::Value> {
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let lifecycle =
        crate::services::plugin_lifecycle::load_plugin_lifecycle_state(&state, &plugin_id);
    let grant = load_grant(&state, &plugin_id);
    Json(json!({
        "ok": true,
        "plugin_id": plugin_id,
        "current": lifecycle,
        "plan": [
            {"step":"preflight","done": true, "detail":"manifest + compatibility check"},
            {"step":"capability_grants","done": grant.requested.iter().all(|c| grant.granted.iter().any(|g| g == c)), "detail":"operator grants requested capabilities"},
            {"step":"configure","done": true, "detail":"configure defaults/schema"},
            {"step":"activate","done": lifecycle.installed && lifecycle.enabled, "detail":"enable runtime + health probe"},
        ],
        "cta": "POST /api/v1/plugins/:id/lifecycle {\"action\":\"install\"}",
    }))
}
