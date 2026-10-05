//! Watch **`CONNECTOR_WORKFLOW_CATALOG_DIR`** for `*.ccl` workflow sources and upsert into the kernel store.
//!
//! Operators drop CLS into a directory; workflows appear in **`GET /api/v1/apps`** without
//! per-file **`connectorctl workflow apply`**.

use std::path::{Path, PathBuf};

use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    operator::surface::persist_catalog_operator_manifest,
    services::cls::compile_ccl_contract,
    services::workflow_runtime::{get_workflow, upsert_workflow_from_catalog, WorkflowState},
    state::SharedState,
};

const SYNC_META_FOLDER: &str = "workflow_catalog_sync";
const SYNC_META_KEY: &str = "last";

#[derive(Debug, Deserialize)]
struct WorkflowSidecar {
    workflow_id: Option<String>,
    package_id: Option<String>,
    version: Option<String>,
    operator: Option<Value>,
    operator_surface: Option<Value>,
}

fn read_operator_manifest_from_catalog(ccl_path: &Path) -> Option<Value> {
    let operator_path = ccl_path.with_extension("operator.json");
    if operator_path.is_file() {
        let raw = std::fs::read_to_string(&operator_path).ok()?;
        return serde_json::from_str(&raw).ok();
    }
    let sidecar = read_sidecar(ccl_path)?;
    sidecar.operator_surface.or(sidecar.operator)
}

/// Resolve catalog directory: `CONNECTOR_WORKFLOW_CATALOG_DIR` or `{data_dir}/workflows/catalog`.
pub fn resolve_workflow_catalog_dir(data_dir: &str) -> PathBuf {
    std::env::var("CONNECTOR_WORKFLOW_CATALOG_DIR")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(data_dir).join("workflows").join("catalog"))
}

fn read_sidecar(path: &Path) -> Option<WorkflowSidecar> {
    let sidecar = path.with_extension("workflow.json");
    if !sidecar.is_file() {
        return None;
    }
    let raw = std::fs::read_to_string(&sidecar).ok()?;
    serde_json::from_str(&raw).ok()
}

fn catalog_auto_enable() -> bool {
    std::env::var("CONNECTOR_WORKFLOW_CATALOG_AUTO_ENABLE")
        .ok()
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes"
        })
        .unwrap_or(false)
}

fn persist_sync_report(state: &SharedState, report: &Value) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(SYNC_META_FOLDER, SYNC_META_KEY, report);
}

pub fn last_sync_report(state: &SharedState) -> Option<Value> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(SYNC_META_FOLDER, SYNC_META_KEY)
        .ok()
        .flatten()
}

/// Scan catalog dir and upsert workflows. Returns a report object (also persisted).
pub fn sync_workflow_catalog(state: &SharedState, data_dir: &str) -> Value {
    let dir = resolve_workflow_catalog_dir(data_dir);
    let started = chrono::Utc::now().to_rfc3339();

    if !dir.is_dir() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            let report = json!({
                "ok": false,
                "catalog_dir": dir.to_string_lossy(),
                "error": format!("could not create catalog dir: {e}"),
                "started_at": started,
            });
            persist_sync_report(state, &report);
            return report;
        }
    }

    let mut created = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;
    let mut errors: Vec<Value> = Vec::new();
    let mut items: Vec<Value> = Vec::new();

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            let report = json!({
                "ok": false,
                "catalog_dir": dir.to_string_lossy(),
                "error": format!("read_dir failed: {e}"),
                "started_at": started,
            });
            persist_sync_report(state, &report);
            return report;
        }
    };

    let initial_state = if catalog_auto_enable() {
        WorkflowState::Enabled
    } else {
        WorkflowState::Draft
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("ccl") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let sidecar = read_sidecar(&path);
        let workflow_id = sidecar
            .as_ref()
            .and_then(|s| s.workflow_id.clone())
            .unwrap_or_else(|| stem.clone());
        let package_id = sidecar
            .as_ref()
            .and_then(|s| s.package_id.clone())
            .unwrap_or_else(|| stem.clone());
        let version = sidecar
            .as_ref()
            .and_then(|s| s.version.clone())
            .unwrap_or_else(|| "v1".to_string());

        let cls_source = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                errors.push(json!({
                    "file": path.to_string_lossy(),
                    "error": format!("read failed: {e}"),
                }));
                continue;
            }
        };

        if cls_source.trim().is_empty() {
            errors.push(json!({
                "file": path.to_string_lossy(),
                "error": "empty cls source",
            }));
            continue;
        }

        if compile_ccl_contract(&cls_source).is_err() {
            errors.push(json!({
                "workflow_id": workflow_id,
                "file": path.to_string_lossy(),
                "error": "CCL parse failed",
            }));
            continue;
        }

        let action = upsert_workflow_from_catalog(
            state,
            &workflow_id,
            &package_id,
            &version,
            &cls_source,
            initial_state,
        );
        if let Some(manifest) = read_operator_manifest_from_catalog(&path) {
            persist_catalog_operator_manifest(state, &workflow_id, &manifest);
        }
        match action {
            "created" => created += 1,
            "updated" => updated += 1,
            "unchanged" => unchanged += 1,
            _ => {}
        }
        let state_label = get_workflow(state, &workflow_id)
            .and_then(|r| serde_json::to_value(r.state).ok())
            .unwrap_or(json!(null));
        items.push(json!({
            "action": action,
            "workflow_id": workflow_id,
            "package_id": package_id,
            "state": state_label,
        }));
    }

    let finished = chrono::Utc::now().to_rfc3339();
    let report = json!({
        "ok": true,
        "catalog_dir": dir.to_string_lossy(),
        "started_at": started,
        "finished_at": finished,
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "errors": errors,
        "items": items,
        "auto_enable": catalog_auto_enable(),
        "hint": "Drop *.ccl files here (optional sidecar: same stem + .workflow.json with workflow_id, package_id, version). Listed in GET /api/v1/apps.",
    });
    persist_sync_report(state, &report);
    report
}

fn require_admin_or_dev(headers: &axum::http::HeaderMap) -> Result<(), Value> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = crate::auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = crate::auth::PlatformRole::from_str(&claims.role);
    if role.rank() < crate::auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

/// `GET /api/v1/workflows/catalog` — catalog directory + last sync report.
pub async fn get_workflow_catalog_status(State(state): State<SharedState>) -> Json<Value> {
    let data_dir = state.config.data_dir.clone();
    let dir = resolve_workflow_catalog_dir(&data_dir);
    Json(json!({
        "ok": true,
        "catalog_dir": dir.to_string_lossy(),
        "watch_interval_ms": std::env::var("CONNECTOR_WORKFLOW_CATALOG_WATCH_MS").ok(),
        "auto_enable": catalog_auto_enable(),
        "last_sync": last_sync_report(&state),
    }))
}

/// `POST /api/v1/workflows/catalog/sync` — scan directory now (admin or dev).
pub async fn post_workflow_catalog_sync(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let data_dir = state.config.data_dir.clone();
    Json(sync_workflow_catalog(&state, &data_dir))
}

pub fn spawn_workflow_catalog_watch_loop(state: SharedState, data_dir: String) {
    let interval_ms = std::env::var("CONNECTOR_WORKFLOW_CATALOG_WATCH_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30_000);

    if interval_ms == 0 {
        return;
    }

    tokio::spawn(async move {
        let dir = resolve_workflow_catalog_dir(&data_dir);
        tracing::info!(
            catalog_dir = %dir.display(),
            interval_ms,
            "workflow catalog watch: initial sync + periodic scan"
        );
        let st0 = state.clone();
        let dd0 = data_dir.clone();
        let _ = tokio::task::spawn_blocking(move || sync_workflow_catalog(&st0, &dd0)).await;

        let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
        loop {
            interval.tick().await;
            let st = state.clone();
            let dd = data_dir.clone();
            match tokio::task::spawn_blocking(move || sync_workflow_catalog(&st, &dd)).await {
                Ok(report) => {
                    if report.get("created").and_then(|v| v.as_u64()).unwrap_or(0) > 0
                        || report.get("updated").and_then(|v| v.as_u64()).unwrap_or(0) > 0
                    {
                        tracing::info!(
                            created = report.get("created").and_then(|v| v.as_u64()).unwrap_or(0),
                            updated = report.get("updated").and_then(|v| v.as_u64()).unwrap_or(0),
                            "workflow catalog sync applied changes"
                        );
                    }
                }
                Err(e) => tracing::warn!(error = %e, "workflow catalog sync task failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_catalog_dir_default_under_data_dir() {
        let p = resolve_workflow_catalog_dir("/tmp/connector-data");
        assert!(p.ends_with("workflows/catalog"));
    }

    #[test]
    fn catalog_auto_enable_false_by_default() {
        std::env::remove_var("CONNECTOR_WORKFLOW_CATALOG_AUTO_ENABLE");
        assert!(!catalog_auto_enable());
    }
}
