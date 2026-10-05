use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::{auth, state::SharedState};

const SETTINGS_SCHEMA_FOLDER: &str = "plugin_settings_schema";
const SETTINGS_VALUES_FOLDER: &str = "plugin_settings_values";

/// In-process overlay so POST /plugins/:id/configure takes effect for proxies
/// without requiring a platform restart / env rewrite. Env vars still win when set.
fn runtime_overlay() -> &'static Mutex<HashMap<String, Map<String, Value>>> {
    static OVERLAY: OnceLock<Mutex<HashMap<String, Map<String, Value>>>> = OnceLock::new();
    OVERLAY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn overlay_put(plugin_id: &str, values: &Map<String, Value>) {
    if let Ok(mut g) = runtime_overlay().lock() {
        g.insert(plugin_id.to_string(), values.clone());
    }
}

/// String setting from configure overlay (UI-saved), if present and non-empty.
pub fn overlay_string(plugin_id: &str, key: &str) -> Option<String> {
    let g = runtime_overlay().lock().ok()?;
    let v = g.get(plugin_id)?.get(key)?;
    let s = v.as_str()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Hydrate overlay from engine store (e.g. after restart) so saved configure values still apply.
pub fn hydrate_overlay_from_store(state: &SharedState, plugin_id: &str) {
    let es = state.engine_store.lock().unwrap();
    if let Ok(Some(Value::Object(m))) = es.folder_get(SETTINGS_VALUES_FOLDER, plugin_id) {
        drop(es);
        overlay_put(plugin_id, &m);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFieldDef {
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub help: String,
    #[serde(default)]
    pub default: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSettingsSchema {
    pub plugin_id: String,
    pub schema_id: String,
    pub title: String,
    pub fields: Vec<PluginFieldDef>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub values: Map<String, Value>,
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

fn default_schema_for(plugin_id: &str) -> PluginSettingsSchema {
    match plugin_id {
        "tracetramp" => PluginSettingsSchema {
            plugin_id: plugin_id.to_string(),
            schema_id: "tracetramp.settings.v1".to_string(),
            title: "TraceTramp Settings".to_string(),
            fields: vec![
                PluginFieldDef {
                    key: "management_url".to_string(),
                    label: "Management URL".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    help: "TraceTramp admin base URL (for /admin/* proxy).".to_string(),
                    default: Some(json!("http://127.0.0.1:19742")),
                },
                PluginFieldDef {
                    key: "admin_token".to_string(),
                    label: "Admin Token".to_string(),
                    field_type: "secret".to_string(),
                    required: true,
                    help: "Bearer used by connector platform to call TraceTramp.".to_string(),
                    default: None,
                },
            ],
        },
        "witnessctl" => PluginSettingsSchema {
            plugin_id: plugin_id.to_string(),
            schema_id: "witnessctl.settings.v1".to_string(),
            title: "WitnessCtl Settings".to_string(),
            fields: vec![
                PluginFieldDef {
                    key: "management_url".to_string(),
                    label: "Management URL".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    help: "WitnessCtl control-plane URL.".to_string(),
                    default: Some(json!("http://127.0.0.1:19100")),
                },
                PluginFieldDef {
                    key: "admin_token".to_string(),
                    label: "Admin Token".to_string(),
                    field_type: "secret".to_string(),
                    required: true,
                    help: "Bearer used by connector platform for WitnessCtl APIs.".to_string(),
                    default: None,
                },
            ],
        },
        _ => PluginSettingsSchema {
            plugin_id: plugin_id.to_string(),
            schema_id: "devguard.settings.v1".to_string(),
            title: "DevGuard Settings".to_string(),
            fields: vec![
                PluginFieldDef {
                    key: "management_url".to_string(),
                    label: "Management URL".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    help: "DevGuard workstation management endpoint.".to_string(),
                    default: Some(json!("http://127.0.0.1:19555")),
                },
                PluginFieldDef {
                    key: "enforce_mode".to_string(),
                    label: "Enforce Mode".to_string(),
                    field_type: "boolean".to_string(),
                    required: false,
                    help: "Enable strict policy enforcement in extension workflow.".to_string(),
                    default: Some(json!(true)),
                },
            ],
        },
    }
}

fn load_schema(state: &SharedState, plugin_id: &str) -> PluginSettingsSchema {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(SETTINGS_SCHEMA_FOLDER, plugin_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<PluginSettingsSchema>(v).ok())
        .unwrap_or_else(|| default_schema_for(plugin_id))
}

fn load_values(
    state: &SharedState,
    plugin_id: &str,
    schema: &PluginSettingsSchema,
) -> Map<String, Value> {
    let es = state.engine_store.lock().unwrap();
    let mut values = es
        .folder_get(SETTINGS_VALUES_FOLDER, plugin_id)
        .ok()
        .flatten()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    for f in &schema.fields {
        if !values.contains_key(&f.key) {
            if let Some(d) = f.default.clone() {
                values.insert(f.key.clone(), d);
            }
        }
    }
    values
}

fn field_type_matches(field_type: &str, value: &Value) -> bool {
    match field_type {
        "string" | "secret" => value.is_string(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        "json" => true,
        _ => true,
    }
}

fn validate_values(
    schema: &PluginSettingsSchema,
    values: &Map<String, Value>,
) -> Result<(), String> {
    for field in &schema.fields {
        if field.required && !values.contains_key(&field.key) {
            return Err(format!("Missing required field '{}'", field.key));
        }
        if let Some(v) = values.get(&field.key) {
            if !field_type_matches(&field.field_type, v) {
                return Err(format!(
                    "Field '{}' has invalid type '{}'",
                    field.key, field.field_type
                ));
            }
        }
    }
    Ok(())
}

/// GET /api/v1/plugins/:id/configure/schema — manifest-derived settings schema.
pub async fn get_plugin_settings_schema(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
) -> Json<Value> {
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let schema = load_schema(&state, &plugin_id);
    Json(
        json!({"ok": true, "plugin_id": plugin_id, "schema": schema, "source": "manifest.settings"}),
    )
}

/// GET /api/v1/plugins/:id/configure — current validated settings values.
pub async fn get_plugin_settings_values(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
) -> Json<Value> {
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let schema = load_schema(&state, &plugin_id);
    let values = load_values(&state, &plugin_id, &schema);
    overlay_put(&plugin_id, &values);
    Json(
        json!({"ok": true, "plugin_id": plugin_id, "values": values, "schema_id": schema.schema_id}),
    )
}

/// POST /api/v1/plugins/:id/configure — apply settings values validated by schema.
pub async fn set_plugin_settings_values(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateSettingsRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let schema = load_schema(&state, &plugin_id);
    let mut values = load_values(&state, &plugin_id, &schema);
    for (k, v) in req.values {
        values.insert(k, v);
    }
    let Err(err) = validate_values(&schema, &values) else {
        let admitted = match crate::substrate::pate::require_proceed(
            &state,
            "plugin-lifecycle",
            "plugins",
            "plugin_settings",
            &json!({"plugin_id": plugin_id.as_str()}),
        ) {
            Ok(atu) => atu,
            Err(body) => return Json(body),
        };
        let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            SETTINGS_VALUES_FOLDER,
            &plugin_id,
            &Value::Object(values.clone()),
        );
        drop(es);
        overlay_put(&plugin_id, &values);
        open_proceed.finish_observed(true);
        return Json(json!({
            "ok": true,
            "task_id": admitted.task_id,
            "executed": true,
            "admits": false,
            "plugin_id": plugin_id,
            "schema_id": schema.schema_id,
            "values": values,
            "message": "Plugin settings updated (in-process overlay active; env vars still override when set)",
            "runtime_note": "Proxies prefer CONNECTOR_* env when present; otherwise use these saved values."
        }));
    };
    Json(json!({"ok": false, "error": err}))
}
