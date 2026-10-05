use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    operator::{
        honesty::operator_envelope,
        surface_merge::{
            load_plugin_contracts_for_institutions, resolve_merged_surface, OPERATOR_SURFACE_FOLDER,
            panel_type_registry,
        },
    },
    services::workflow_runtime::{
        get_workflow, require_admin_or_dev, workflow_list_row_json, WORKFLOW_FOLDER,
    },
    state::SharedState,
};

#[derive(Debug, Deserialize)]
pub struct ListSurfacesQuery {
    #[serde(default)]
    pub ids: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PutSurfaceRequest {
    #[serde(flatten)]
    pub manifest: Value,
}

pub fn get_stored_surface(state: &SharedState, workflow_id: &str) -> Option<Value> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(OPERATOR_SURFACE_FOLDER, workflow_id)
        .ok()
        .flatten()
}

pub fn put_stored_surface(state: &SharedState, workflow_id: &str, manifest: &Value) -> Result<(), String> {
    if manifest
        .get("schema")
        .and_then(|v| v.as_str())
        .filter(|s| *s == "operator_surface.v1")
        .is_none()
    {
        return Err("manifest.schema must be operator_surface.v1".into());
    }
    let mut es = state.engine_store.lock().unwrap();
    es.folder_put(OPERATOR_SURFACE_FOLDER, workflow_id, manifest)
        .map_err(|e| format!("store failed: {e}"))
}

pub fn merged_surface_for_workflow(state: &SharedState, workflow_id: &str) -> Option<Value> {
    let rec = get_workflow(state, workflow_id)?;
    let stored = get_stored_surface(state, workflow_id);
    let (workflow_row, contracts) = {
        let mut es = state.engine_store.lock().unwrap();
        let row = workflow_list_row_json(&mut **es, &rec);
        let institutions: Vec<String> = stored
            .as_ref()
            .and_then(|s| s.get("institutions"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(|| {
                crate::operator::surface_merge::infer_institutions_from_cls(&rec.cls_source)
            });
        let contracts = load_plugin_contracts_for_institutions(&mut **es, &institutions);
        (row, contracts)
    };
    Some(resolve_merged_surface(
        &rec,
        &workflow_row,
        stored,
        &contracts,
    ))
}

/// `GET /api/v1/workflows/:id/surface`
pub async fn get_workflow_surface(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
) -> impl IntoResponse {
    let Some(surface) = merged_surface_for_workflow(&state, &workflow_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "Workflow not found"})),
        )
            .into_response();
    };
    Json(operator_envelope(json!({
        "workflow_id": workflow_id,
        "surface": surface,
    })))
    .into_response()
}

/// `GET /api/v1/workflows/surfaces?ids=a,b,c`
pub async fn list_workflow_surfaces(
    State(state): State<SharedState>,
    Query(q): Query<ListSurfacesQuery>,
) -> Json<Value> {
    let ids: Vec<String> = if let Some(raw) = q.ids {
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(WORKFLOW_FOLDER, None)
            .unwrap_or_default()
    };

    let mut surfaces = Vec::new();
    for id in ids {
        if let Some(surface) = merged_surface_for_workflow(&state, &id) {
            surfaces.push(json!({
                "workflow_id": id,
                "surface": surface,
            }));
        }
    }
    Json(operator_envelope(json!({
        "count": surfaces.len(),
        "surfaces": surfaces,
    })))
}

/// `PUT /api/v1/workflows/:id/surface`
pub async fn put_workflow_surface(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<PutSurfaceRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    if get_workflow(&state, &workflow_id).is_none() {
        return Json(json!({"ok": false, "error": "Workflow not found"}));
    }
    let mut manifest = req.manifest;
    if let Some(obj) = manifest.as_object_mut() {
        obj.insert("workflow_id".into(), json!(workflow_id));
        obj.insert("schema".into(), json!("operator_surface.v1"));
    }
    // Universal two-way accounting — required on every stored surface.
    if let Some(rec) = get_workflow(&state, &workflow_id) {
        crate::operator::surface_merge::ensure_accounting(&mut manifest, &rec.cls_source);
    }
    if let Err(errs) = crate::operator::lint_surface::lint_operator_surface(&manifest) {
        return Json(json!({
            "ok": false,
            "error": "operator_surface lint failed",
            "lint_errors": errs,
        }));
    }
    if let Err(err) = put_stored_surface(&state, &workflow_id, &manifest) {
        return Json(json!({"ok": false, "error": err}));
    }
    let surface = merged_surface_for_workflow(&state, &workflow_id).unwrap_or(manifest);
    Json(operator_envelope(json!({
        "workflow_id": workflow_id,
        "surface": surface,
        "stored": true,
    })))
}

/// `GET /api/v1/operator/panel-types`
pub async fn get_operator_panel_types() -> Json<Value> {
    Json(operator_envelope(panel_type_registry()))
}

/// Persist operator manifest from catalog sync (no auth — internal).
pub fn persist_catalog_operator_manifest(state: &SharedState, workflow_id: &str, manifest: &Value) {
    let mut m = manifest.clone();
    if let Some(obj) = m.as_object_mut() {
        obj.insert("workflow_id".into(), json!(workflow_id));
        obj.entry("schema".to_string())
            .or_insert(json!("operator_surface.v1"));
    }
    let cls = get_workflow(state, workflow_id)
        .map(|r| r.cls_source)
        .unwrap_or_default();
    crate::operator::surface_merge::ensure_accounting(&mut m, &cls);
    let _ = put_stored_surface(state, workflow_id, &m);
}
