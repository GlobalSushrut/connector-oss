use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    operator::{
        capability_seed::seed_capabilities,
        honesty::operator_envelope,
        surface::merged_surface_for_workflow,
    },
    services::plugin_matrix,
    state::SharedState,
};

#[derive(Debug, Deserialize)]
pub struct CapabilitiesQuery {
    pub institution: Option<String>,
}

fn institution_installed(state: &SharedState, institution_id: &str) -> bool {
    match institution_id {
        "kernel" => true,
        id if plugin_matrix::KNOWN_PLUGINS.contains(&id) => {
            plugin_matrix::is_plugin_enabled(id)
                && crate::services::plugin_lifecycle::load_plugin_lifecycle_state(state, id).installed
        }
        _ => false,
    }
}

fn annotate_availability(state: &SharedState, record: &Value) -> Value {
    let institution_id = record
        .get("institution_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let installed = institution_installed(state, institution_id);
    let mut out = record.clone();
    if let Some(caps) = out.get_mut("capabilities").and_then(|v| v.as_array_mut()) {
        for cap in caps.iter_mut() {
            if let Some(obj) = cap.as_object_mut() {
                obj.insert("available".into(), json!(installed));
            }
        }
    }
    if let Some(obj) = out.as_object_mut() {
        obj.insert("installed".into(), json!(installed));
    }
    out
}

/// `GET /api/v1/operator/capabilities`
pub async fn get_operator_capabilities(
    State(state): State<SharedState>,
    Query(q): Query<CapabilitiesQuery>,
) -> Json<Value> {
    let mut institutions: Vec<Value> = seed_capabilities()
        .into_iter()
        .map(|r| annotate_availability(&state, &r))
        .collect();

    if let Some(filter) = q.institution.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
        if !filter.is_empty() {
            institutions.retain(|r| {
                r.get("institution_id")
                    .and_then(|v| v.as_str())
                    .map(|id| id == filter)
                    .unwrap_or(false)
            });
        }
    }

    Json(operator_envelope(json!({
        "schema": "operator_capabilities.v1",
        "count": institutions.len(),
        "institutions": institutions,
    })))
}

/// `GET /api/v1/workflows/:id/capabilities`
pub async fn get_workflow_capabilities(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
) -> Json<Value> {
    let Some(surface) = merged_surface_for_workflow(&state, &workflow_id) else {
        return Json(json!({"ok": false, "error": "Workflow not found"}));
    };

    let institution_ids: Vec<String> = surface
        .get("institutions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let all = seed_capabilities();
    let mut resolved: Vec<Value> = Vec::new();
    for id in &institution_ids {
        if let Some(rec) = all
            .iter()
            .find(|r| r.get("institution_id").and_then(|v| v.as_str()) == Some(id.as_str()))
        {
            resolved.push(annotate_availability(&state, rec));
        }
    }

    // Kernel capabilities always available for export/audit drawer topics.
    if let Some(kernel) = all
        .iter()
        .find(|r| r.get("institution_id").and_then(|v| v.as_str()) == Some("kernel"))
    {
        if !resolved.iter().any(|r| {
            r.get("institution_id").and_then(|v| v.as_str()) == Some("kernel")
        }) {
            resolved.push(annotate_availability(&state, kernel));
        }
    }

    Json(operator_envelope(json!({
        "workflow_id": workflow_id,
        "institution_ids": institution_ids,
        "institutions": resolved,
        "hint": "Capabilities intersect manifest institutions with installed plugins. DevGuard has no evidence.export.",
    })))
}
