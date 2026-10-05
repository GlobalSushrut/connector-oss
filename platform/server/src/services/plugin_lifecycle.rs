use std::collections::BTreeSet;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{auth, state::SharedState};

const LIFECYCLE_FOLDER: &str = "plugin_lifecycle";
const LIFECYCLE_EVENTS_FOLDER: &str = "plugin_lifecycle_events";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginLifecycleState {
    pub plugin_id: String,
    pub installed: bool,
    pub enabled: bool,
    pub version: String,
    pub revision: u64,
    pub last_action: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginLifecycleEvent {
    pub event_id: String,
    pub plugin_id: String,
    pub action: String,
    pub from_installed: bool,
    pub from_enabled: bool,
    pub to_installed: bool,
    pub to_enabled: bool,
    pub from_version: String,
    pub to_version: String,
    pub at: String,
}

impl PluginLifecycleState {
    fn default_for(plugin_id: &str) -> Self {
        let enabled_in_deployment = crate::services::plugin_matrix::is_plugin_enabled(plugin_id);
        Self {
            plugin_id: plugin_id.to_string(),
            installed: enabled_in_deployment,
            enabled: enabled_in_deployment,
            version: "builtin".to_string(),
            revision: 1,
            last_action: if enabled_in_deployment {
                "bootstrap".to_string()
            } else {
                "uninstalled".to_string()
            },
            updated_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LifecycleActionRequest {
    pub action: String,
    #[serde(default)]
    pub target_version: Option<String>,
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

pub fn load_plugin_lifecycle_state(state: &SharedState, plugin_id: &str) -> PluginLifecycleState {
    let es = state.engine_store.lock().unwrap();
    if let Ok(Some(v)) = es.folder_get(LIFECYCLE_FOLDER, plugin_id) {
        if let Ok(row) = serde_json::from_value::<PluginLifecycleState>(v) {
            return row;
        }
    }
    drop(es);
    PluginLifecycleState::default_for(plugin_id)
}

fn plugin_is_known_or_installed(state: &SharedState, plugin_id: &str) -> bool {
    crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id)
        || crate::services::plugin_cpkg::cpkg_store_exists(state, plugin_id)
        || {
            let es = state.engine_store.lock().unwrap();
            es.folder_get(LIFECYCLE_FOLDER, plugin_id)
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_value::<PluginLifecycleState>(v).ok())
                .map(|row| row.installed || row.revision > 1)
                .unwrap_or(false)
        }
}

fn actions_for_state(row: &PluginLifecycleState) -> Vec<&'static str> {
    if !row.installed {
        return vec!["install", "install_only", "bind"];
    }
    let mut out = vec!["update", "uninstall"];
    if row.enabled {
        out.push("disable");
        out.push("deactivate");
    } else {
        out.push("enable");
        out.push("activate");
    }
    out
}

fn status_badge(row: &PluginLifecycleState) -> &'static str {
    if !row.installed {
        "not_installed"
    } else if !row.enabled {
        "disabled"
    } else {
        "enabled"
    }
}

pub(crate) fn persist_plugin_lifecycle_state(state: &SharedState, row: &PluginLifecycleState) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        LIFECYCLE_FOLDER,
        &row.plugin_id,
        &serde_json::to_value(row).unwrap_or_default(),
    );
}

pub(crate) fn persist_lifecycle_event(state: &SharedState, event: &PluginLifecycleEvent) {
    let mut es = state.engine_store.lock().unwrap();
    let key = format!("{}:{}", event.plugin_id, event.event_id);
    let _ = es.folder_put(
        LIFECYCLE_EVENTS_FOLDER,
        &key,
        &serde_json::to_value(event).unwrap_or_default(),
    );
}

fn recent_plugin_events(
    state: &SharedState,
    plugin_id: &str,
    limit: usize,
) -> Vec<PluginLifecycleEvent> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys(LIFECYCLE_EVENTS_FOLDER, None)
        .unwrap_or_default();
    let mut out: Vec<PluginLifecycleEvent> = keys
        .iter()
        .filter(|k| k.starts_with(&format!("{plugin_id}:")))
        .filter_map(|k| es.folder_get(LIFECYCLE_EVENTS_FOLDER, k).ok().flatten())
        .filter_map(|v| serde_json::from_value::<PluginLifecycleEvent>(v).ok())
        .collect();
    out.sort_by(|a, b| a.at.cmp(&b.at));
    out.reverse();
    out.into_iter().take(limit.max(1)).collect()
}

fn apply_action(
    mut row: PluginLifecycleState,
    req: &LifecycleActionRequest,
) -> Result<PluginLifecycleState, String> {
    let action = req.action.trim().to_ascii_lowercase();
    match action.as_str() {
        "install" => {
            // Legacy: install still auto-enables (compatibility).
            row.installed = true;
            row.enabled = true;
            if let Some(v) = req.target_version.as_ref().filter(|v| !v.trim().is_empty()) {
                row.version = v.trim().to_string();
            }
        }
        // ExtensionHost: install without activate (install ≠ enable).
        "install_only" | "bind" => {
            row.installed = true;
            row.enabled = false;
            if let Some(v) = req.target_version.as_ref().filter(|v| !v.trim().is_empty()) {
                row.version = v.trim().to_string();
            }
        }
        "activate" | "enable" => {
            if !row.installed {
                return Err("Cannot activate/enable before install".to_string());
            }
            row.enabled = true;
        }
        "deactivate" | "disable" => {
            if !row.installed {
                return Err("Cannot deactivate/disable an uninstalled plugin".to_string());
            }
            row.enabled = false;
        }
        "update" => {
            if !row.installed {
                return Err("Cannot update before install".to_string());
            }
            if let Some(v) = req.target_version.as_ref().filter(|v| !v.trim().is_empty()) {
                row.version = v.trim().to_string();
            }
        }
        "uninstall" | "revoke" => {
            row.installed = false;
            row.enabled = false;
        }
        _ => {
            return Err(
                "Invalid action. Use install|install_only|bind|activate|enable|deactivate|disable|update|uninstall|revoke"
                    .to_string(),
            );
        }
    }
    row.revision = row.revision.saturating_add(1);
    row.last_action = action;
    row.updated_at = chrono::Utc::now().to_rfc3339();
    Ok(row)
}

/// Apply a lifecycle transition and persist (used by ExtensionHost facade).
pub fn transition_lifecycle(
    state: &SharedState,
    plugin_id: &str,
    action: &str,
    target_version: Option<String>,
) -> Result<PluginLifecycleState, String> {
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !plugin_is_known_or_installed(state, &plugin_id) {
        return Err("Unknown plugin id".into());
    }
    let row = load_plugin_lifecycle_state(state, &plugin_id);
    let before = row.clone();
    let req = LifecycleActionRequest {
        action: action.to_string(),
        target_version,
    };
    let updated = apply_action(row, &req)?;
    persist_plugin_lifecycle_state(state, &updated);
    if updated.last_action == "uninstall" || updated.last_action == "revoke" {
        let _ = crate::services::plugin_cpkg::purge_cpkg_store(state, &plugin_id);
    }
    persist_lifecycle_event(
        state,
        &PluginLifecycleEvent {
            event_id: format!("evt_{}", uuid::Uuid::new_v4().simple()),
            plugin_id: plugin_id.clone(),
            action: action.to_ascii_lowercase(),
            from_installed: before.installed,
            from_enabled: before.enabled,
            to_installed: updated.installed,
            to_enabled: updated.enabled,
            from_version: before.version,
            to_version: updated.version.clone(),
            at: chrono::Utc::now().to_rfc3339(),
        },
    );
    Ok(updated)
}

pub async fn get_plugin_lifecycle(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
) -> Json<serde_json::Value> {
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !plugin_is_known_or_installed(&state, &plugin_id) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let row = load_plugin_lifecycle_state(&state, &plugin_id);
    Json(json!({
        "ok": true,
        "plugin": row,
        "status_badge": status_badge(&row),
        "available_actions": actions_for_state(&row),
        "recent_events": recent_plugin_events(&state, &plugin_id, 10),
    }))
}

pub async fn list_plugin_lifecycle(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mut ids: BTreeSet<String> = crate::services::plugin_matrix::KNOWN_PLUGINS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    {
        let es = state.engine_store.lock().unwrap();
        if let Ok(keys) = es.folder_keys(LIFECYCLE_FOLDER, None) {
            ids.extend(keys);
        }
    }
    ids.extend(crate::services::plugin_cpkg::list_cpkg_store_plugin_ids(&state));
    let plugins: Vec<_> = ids
        .iter()
        .map(|id| {
            let row = load_plugin_lifecycle_state(&state, id);
            json!({
                "plugin": row.clone(),
                "status_badge": status_badge(&row),
                "available_actions": actions_for_state(&row),
            })
        })
        .collect();
    Json(json!({"ok": true, "count": plugins.len(), "plugins": plugins}))
}

pub async fn get_plugin_lifecycle_history(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
) -> Json<serde_json::Value> {
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !plugin_is_known_or_installed(&state, &plugin_id) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let events = recent_plugin_events(&state, &plugin_id, 100);
    Json(json!({"ok": true, "plugin_id": plugin_id, "count": events.len(), "events": events}))
}

pub async fn apply_plugin_lifecycle(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<LifecycleActionRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !plugin_is_known_or_installed(&state, &plugin_id) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let row = load_plugin_lifecycle_state(&state, &plugin_id);
    let before = row.clone();
    let updated = match apply_action(row, &req) {
        Ok(u) => u,
        Err(e) => return Json(json!({"ok": false, "error": e})),
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "plugin-lifecycle",
        "plugins",
        "plugin_lifecycle",
        &json!({"plugin_id": plugin_id.as_str(), "action": req.action.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    persist_plugin_lifecycle_state(&state, &updated);
    let mut purged_store = false;
    if updated.last_action == "uninstall" {
        match crate::services::plugin_cpkg::purge_cpkg_store(&state, &plugin_id) {
            Ok(p) => purged_store = p,
            Err(e) => {
                open_proceed.finish_observed(false);
                return Json(json!({
                    "ok": false,
                    "error": e,
                    "plugin": updated,
                    "task_id": admitted.task_id,
                    "executed": false,
                    "admits": false,
                }));
            }
        }
    }
    persist_lifecycle_event(
        &state,
        &PluginLifecycleEvent {
            event_id: format!("evt_{}", uuid::Uuid::new_v4().simple()),
            plugin_id: plugin_id.clone(),
            action: req.action.to_ascii_lowercase(),
            from_installed: before.installed,
            from_enabled: before.enabled,
            to_installed: updated.installed,
            to_enabled: updated.enabled,
            from_version: before.version,
            to_version: updated.version.clone(),
            at: chrono::Utc::now().to_rfc3339(),
        },
    );
    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "plugin": updated,
        "status_badge": status_badge(&updated),
        "available_actions": actions_for_state(&updated),
        "purged_cpkg_store": purged_store,
        "note": "Deployment-level plugin matrix still follows CONNECTOR_PLUGINS_ENABLED; lifecycle is control-plane state for hub UX and automation."
    }))
}
