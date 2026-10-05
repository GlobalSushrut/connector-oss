//! One-shot workflow bootstrap: register → COMPILED → STAGED → ENABLED → dry-run → enqueue.
//!
//! `POST /api/v1/workflows/bootstrap` is idempotent when `idempotency_key` is set.
//! Failures after a *new* register archive that draft so callers do not see a half-enabled workflow.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    services::workflow_runtime::{
        apply_workflow_transition, dry_run_workflow, get_workflow, put_workflow,
        register_workflow_inner, DryRunWorkflowRequest, RegisterWorkflowRequest, WorkflowRecord,
        WorkflowState,
    },
    state::SharedState,
};

const IDEMPOTENCY_FOLDER: &str = "workflow_bootstrap_idempotency";

#[derive(Debug, Deserialize)]
pub struct BootstrapWorkflowRequest {
    /// `reference:<template_id>` or omit when `cls_source` is set.
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub cls_source: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub package_id: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub reference_id: Option<String>,
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub run: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub accounting_mode: Option<String>,
    /// AppPackageV2 pin — required when enable=true outside lab.
    #[serde(default)]
    pub package: Option<connector_native_contract::PackagePin>,
}

fn idempotency_get(state: &SharedState, key: &str) -> Option<Value> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(IDEMPOTENCY_FOLDER, key).ok().flatten()
}

fn idempotency_put(state: &SharedState, key: &str, value: &Value) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(IDEMPOTENCY_FOLDER, key, value);
}

async fn resolve_reference(id: &str) -> Result<(String, String, String, Vec<String>), Value> {
    let Json(catalog) = crate::services::workflow_runtime::list_reference_templates().await;
    let templates = catalog
        .get("templates")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for t in templates {
        if t.get("id").and_then(|v| v.as_str()) == Some(id) {
            let name = t
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(id)
                .to_string();
            let src = t
                .get("cls_source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if src.trim().is_empty() {
                return Err(json!({
                    "ok": false,
                    "error": "Reference template has empty cls_source",
                    "code": "REFERENCE_TEMPLATE_EMPTY",
                }));
            }
            let plugins = t
                .get("plugins")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            return Ok((name, src, id.to_string(), plugins));
        }
    }
    Err(json!({
        "ok": false,
        "error": format!("Unknown reference template `{id}`"),
        "code": "REFERENCE_TEMPLATE_NOT_FOUND",
    }))
}

fn archive_if_created(state: &SharedState, created: bool, workflow_id: &str) {
    if !created {
        return;
    }
    if let Some(mut rec) = get_workflow(state, workflow_id) {
        rec.state = WorkflowState::Archived;
        rec.updated_at = chrono::Utc::now().to_rfc3339();
        put_workflow(state, &rec);
    }
}

pub(crate) struct BootstrapWorkflowParams {
    pub workflow_id: String,
    pub package_id: String,
    pub cls_source: String,
    pub version: Option<String>,
    pub accounting_mode: Option<String>,
    pub enable: bool,
    pub dry_run: bool,
    pub run: bool,
    pub idempotency_key: Option<String>,
    pub package: Option<connector_native_contract::PackagePin>,
}

pub(crate) async fn bootstrap_workflow_inner(
    state: &SharedState,
    params: BootstrapWorkflowParams,
) -> Value {
    if let Some(ref key) = params
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(cached) = idempotency_get(state, key) {
            return json!({
                "ok": true,
                "idempotent_replay": true,
                "result": cached,
            });
        }
    }

    let workflow_id = params.workflow_id.trim().to_string();
    let package_id = params.package_id.trim().to_string();
    if workflow_id.is_empty() || package_id.is_empty() || params.cls_source.trim().is_empty() {
        return json!({
            "ok": false,
            "error": "workflow_id, package_id, and cls_source required",
        });
    }

    let existed = get_workflow(state, &workflow_id).is_some();
    let mut created = false;
    if !existed {
        match register_workflow_inner(
            state,
            RegisterWorkflowRequest {
                workflow_id: workflow_id.clone(),
                package_id: package_id.clone(),
                version: params.version.clone().or_else(|| Some("v1".into())),
                cls_source: params.cls_source.clone(),
                accounting_mode: params.accounting_mode.clone(),
            },
        ) {
            Ok(_) => created = true,
            Err(e) => return e,
        }
    }

    let Some(rec) = get_workflow(state, &workflow_id) else {
        return json!({"ok": false, "error": "Workflow not found after register"});
    };

    let mut lifecycle = Vec::new();
    if params.enable {
        match walk_to_enabled(state, &rec, params.run, params.package.as_ref()) {
            Ok(steps) => lifecycle = steps,
            Err(e) => {
                archive_if_created(state, created, &workflow_id);
                return e;
            }
        }
        if params.run {
            if let Some(current) = get_workflow(state, &workflow_id) {
                if current.state == WorkflowState::Enabled
                    && !lifecycle.iter().any(|s| s.get("durable_run").is_some())
                {
                    let queued =
                        crate::services::workflow_runner::enqueue_enabled_run(state, &current);
                    lifecycle.push(json!({"durable_run": queued, "note": "enqueued on already-ENABLED workflow"}));
                }
            }
        }
    }

    let final_rec = get_workflow(state, &workflow_id);
    let executing = {
        let mut es = state.engine_store.lock().unwrap();
        crate::services::workflow_runner::is_executing(&mut **es, &workflow_id)
    };
    let result = json!({
        "ok": true,
        "workflow_id": workflow_id,
        "package_id": package_id,
        "created": created,
        "workflow": final_rec,
        "lifecycle": lifecycle,
        "dry_run": Value::Null,
        "executing": executing,
        "execution_honesty": if executing {
            "Lease runner claimed this workflow"
        } else if params.enable && params.run {
            "Run queued for the durable CLS lease runner; executing becomes true after claim"
        } else {
            "Bootstrap did not enqueue a durable run"
        },
    });
    if let Some(ref key) = params.idempotency_key {
        idempotency_put(state, key, &result);
    }
    result
}

fn walk_to_enabled(
    state: &SharedState,
    rec: &WorkflowRecord,
    enqueue_run: bool,
    package: Option<&connector_native_contract::PackagePin>,
) -> Result<Vec<Value>, Value> {
    let path: &[WorkflowState] = match rec.state {
        WorkflowState::Draft => &[
            WorkflowState::Compiled,
            WorkflowState::Staged,
            WorkflowState::Enabled,
        ],
        WorkflowState::Compiled => &[WorkflowState::Staged, WorkflowState::Enabled],
        WorkflowState::Staged => &[WorkflowState::Enabled],
        WorkflowState::Paused => &[WorkflowState::Enabled],
        WorkflowState::Enabled => &[],
        WorkflowState::Archived => {
            return Err(json!({
                "ok": false,
                "error": "Cannot bootstrap an archived workflow",
            }));
        }
    };
    let mut steps = Vec::new();
    for (i, to) in path.iter().enumerate() {
        let enqueue = enqueue_run && *to == WorkflowState::Enabled;
        let last = i + 1 == path.len();
        let out = apply_workflow_transition(
            state,
            &rec.workflow_id,
            *to,
            enqueue && last,
            package,
        )?;
        steps.push(out);
    }
    Ok(steps)
}

/// `POST /api/v1/workflows/bootstrap`
pub async fn bootstrap_workflow(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<BootstrapWorkflowRequest>,
) -> Json<Value> {
    if let Err(e) = crate::services::workflow_runtime::require_admin_or_dev(&headers) {
        return Json(e);
    }

    let idem = req
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let playground_sid = crate::services::playground::playground_session_id_from_headers(&headers);
    if let Some(ref key) = idem {
        if let Some(cached) = idempotency_get(&state, key) {
            return Json(json!({
                "ok": true,
                "idempotent_replay": true,
                "result": cached,
            }));
        }
    }

    let enable = req.enable.unwrap_or(true);
    let do_dry_run = req.dry_run.unwrap_or(true);
    let do_run = req.run.unwrap_or(true);

    let mut reference_meta: Option<Value> = None;
    let (workflow_id, package_id, cls_source, accounting_mode) = {
        let ref_id = req.reference_id.clone().or_else(|| {
            req.source.as_deref().and_then(|s| {
                s.strip_prefix("reference:")
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
            })
        });
        if let Some(id) = ref_id {
            match resolve_reference(&id).await {
                Ok((name, src, rid, plugins)) => {
                    reference_meta = Some(json!({
                        "id": rid,
                        "name": name,
                        "plugins": plugins,
                    }));
                    let wf = req
                        .workflow_id
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| format!("ref-{}", id.replace('_', "-")));
                    let pkg = req
                        .package_id
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| format!("pkg-reference-{}", id.replace('_', "-")));
                    let acct = req.accounting_mode.clone().or_else(|| {
                        crate::operator::surface_merge::bundled_reference_surface(&id).and_then(
                            |s| {
                                s.pointer("/accounting/mode")
                                    .and_then(|m| m.as_str())
                                    .map(|m| m.to_string())
                            },
                        )
                    });
                    (wf, pkg, src, acct)
                }
                Err(e) => return Json(e),
            }
        } else {
            let Some(src) = req.cls_source.clone().filter(|s| !s.trim().is_empty()) else {
                return Json(json!({
                    "ok": false,
                    "error": "provide cls_source or source=reference:<id> (or reference_id)",
                }));
            };
            let Some(wf) = req
                .workflow_id
                .clone()
                .filter(|s| !s.trim().is_empty())
            else {
                return Json(json!({
                    "ok": false,
                    "error": "workflow_id required when bootstrapping from cls_source",
                }));
            };
            let pkg = req
                .package_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| format!("pkg-{wf}"));
            (wf, pkg, src, req.accounting_mode.clone())
        }
    };

    let mut result = bootstrap_workflow_inner(
        &state,
        BootstrapWorkflowParams {
            workflow_id,
            package_id,
            cls_source,
            version: req.version.clone(),
            accounting_mode,
            enable,
            dry_run: do_dry_run,
            run: do_run,
            idempotency_key: idem.clone(),
            package: req.package.clone(),
        },
    )
    .await;

    if do_dry_run && result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let wf_id = result
            .get("workflow_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let Json(d) = dry_run_workflow(
            State(state.clone()),
            axum::extract::Path(wf_id.clone()),
            headers,
            Json(DryRunWorkflowRequest {
                replay_minutes: Some(15),
                events: None,
            }),
        )
        .await;
        if d.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            if result.get("created").and_then(|v| v.as_bool()) == Some(true) {
                archive_if_created(&state, true, &wf_id);
            }
            return Json(d);
        }
        if let Some(obj) = result.as_object_mut() {
            obj.insert("dry_run".into(), d);
            obj.insert(
                "isolation_attestation".into(),
                crate::services::plugin_runtime_inventory::current_isolation_attestation(&state),
            );
            if let Some(meta) = reference_meta {
                obj.insert("reference".into(), meta);
            }
        }
        if let (Some(sid), Some(workflow_id)) = (
            playground_sid.as_deref(),
            result.get("workflow_id").and_then(|v| v.as_str()),
        ) {
            crate::services::playground::record_workflow_created(
                &state.playground_sessions,
                sid,
                workflow_id,
            );
        }
        if let Some(ref key) = idem {
            idempotency_put(&state, key, &result);
        }
    } else if result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        if let Some(obj) = result.as_object_mut() {
            obj.insert(
                "isolation_attestation".into(),
                crate::services::plugin_runtime_inventory::current_isolation_attestation(&state),
            );
            if let Some(meta) = reference_meta {
                obj.insert("reference".into(), meta);
            }
        }
        if let (Some(sid), Some(workflow_id)) = (
            playground_sid.as_deref(),
            result.get("workflow_id").and_then(|v| v.as_str()),
        ) {
            crate::services::playground::record_workflow_created(
                &state.playground_sessions,
                sid,
                workflow_id,
            );
        }
    }

    Json(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_prefix_is_reference() {
        let s = "reference:hitl_approve_audit";
        assert_eq!(s.strip_prefix("reference:").unwrap(), "hitl_approve_audit");
    }
}
