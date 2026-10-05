//! Burn verified Gloo `.cpkg` manifests into the Connector workflow registry.
//!
//! After a package passes Connector cpkg checks, workflows declared in `gloo.json`
//! are registered and enabled with system-tier metadata — same operational class as
//! first-party governance apps (DevGuard, TraceTramp, WitnessCtl).

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::services::workflow_bootstrap::{bootstrap_workflow_inner, BootstrapWorkflowParams};
use crate::services::workflow_runtime::{get_workflow, WorkflowRecord};
use crate::state::SharedState;

pub(crate) const CPKG_GLOO_REGISTRY_FOLDER: &str = "cpkg_gloo_registry";
pub(crate) const WORKFLOW_SYSTEM_META_FOLDER: &str = "workflow_system_meta";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpkgGlooRegistryEntry {
    pub plugin_id: String,
    pub version: String,
    pub app_id: String,
    pub system_tier: String,
    pub importance: String,
    pub receipt_head: String,
    pub workflow_ids: Vec<String>,
    pub burned_in_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSystemMeta {
    pub workflow_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub system_tier: String,
    pub importance: String,
    pub origin: String,
    pub receipt_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GlooManifest {
    #[serde(default)]
    app_id: String,
    #[serde(default)]
    system_tier: String,
    #[serde(default)]
    workflows: Vec<GlooWorkflowSpec>,
}

#[derive(Debug, Deserialize)]
struct GlooWorkflowSpec {
    id: String,
    package_id: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    cls_source: String,
    #[serde(default)]
    accounting_mode: Option<String>,
}

pub fn is_system_tier_plugin(state: &SharedState, plugin_id: &str) -> bool {
    crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id)
        || get_cpkg_registry_entry(state, plugin_id).is_some()
}

pub fn get_cpkg_registry_entry(state: &SharedState, plugin_id: &str) -> Option<CpkgGlooRegistryEntry> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(CPKG_GLOO_REGISTRY_FOLDER, plugin_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

pub fn get_workflow_system_meta(state: &SharedState, workflow_id: &str) -> Option<WorkflowSystemMeta> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(WORKFLOW_SYSTEM_META_FOLDER, workflow_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

fn persist_cpkg_registry_entry(state: &SharedState, entry: &CpkgGlooRegistryEntry) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        CPKG_GLOO_REGISTRY_FOLDER,
        &entry.plugin_id,
        &serde_json::to_value(entry).unwrap_or_default(),
    );
}

fn persist_workflow_system_meta(state: &SharedState, meta: &WorkflowSystemMeta) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        WORKFLOW_SYSTEM_META_FOLDER,
        &meta.workflow_id,
        &serde_json::to_value(meta).unwrap_or_default(),
    );
}

pub fn verify_staged_gloo_package(files_dir: &Path) -> Result<(), String> {
    let gloo_path = files_dir.join("gloo.json");
    if !gloo_path.exists() {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&gloo_path).map_err(|e| e.to_string())?;
    let manifest: GlooManifest =
        serde_json::from_str(&raw).map_err(|e| format!("parse gloo.json: {e}"))?;
    if manifest.workflows.is_empty() {
        return Err("gloo.json declares no workflows; installer packages must declare at least one workflow".into());
    }
    for wf in &manifest.workflows {
        if wf.id.trim().is_empty() || wf.cls_source.trim().is_empty() {
            return Err(format!(
                "gloo workflow `{}` missing id or cls_source",
                wf.id
            ));
        }
    }
    verify_gloo_receipts(files_dir, &manifest).map(|_| ())?;
    Ok(())
}

pub fn verify_gloo_receipts(files_dir: &Path, manifest: &GlooManifest) -> Result<String, String> {
    let receipt_path = files_dir.join("META/gloo-receipts.json");
    if !receipt_path.exists() {
        return Err(
            "gloo package missing META/gloo-receipts.json — rebuild with `gloo build`".into(),
        );
    }
    let raw = std::fs::read_to_string(&receipt_path).map_err(|e| e.to_string())?;
    let ledger: Value = serde_json::from_str(&raw).map_err(|e| format!("invalid gloo receipts: {e}"))?;
    if ledger.get("app_id").and_then(|v| v.as_str()) != Some(manifest.app_id.as_str()) {
        return Err("gloo receipt ledger app_id mismatch".into());
    }
    ledger
        .get("receipt_head")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "gloo receipt ledger missing receipt_head".into())
}

pub async fn burn_in_installed_cpkg(
    state: &SharedState,
    plugin_id: &str,
    version: &str,
    files_dir: &Path,
) -> Value {
    let gloo_path = files_dir.join("gloo.json");
    if !gloo_path.exists() {
        return json!({
            "ok": true,
            "skipped": true,
            "reason": "no gloo.json manifest in package",
        });
    }

    let raw = match std::fs::read_to_string(&gloo_path) {
        Ok(v) => v,
        Err(e) => {
            return json!({
                "ok": false,
                "error": format!("read gloo.json: {e}"),
            });
        }
    };
    let manifest: GlooManifest = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return json!({
                "ok": false,
                "error": format!("parse gloo.json: {e}"),
            });
        }
    };

    let receipt_head = match verify_gloo_receipts(files_dir, &manifest) {
        Ok(head) => head,
        Err(e) => {
            return json!({
                "ok": false,
                "error": e,
                "code": "GLOO_RECEIPT_VERIFY_FAILED",
            });
        }
    };

    let system_tier = if manifest.system_tier.trim().is_empty() {
        "installed".to_string()
    } else {
        manifest.system_tier.clone()
    };
    let importance = "system_default";

    let mut workflow_results = Vec::new();
    let mut workflow_ids = Vec::new();

    for wf in &manifest.workflows {
        if wf.id.trim().is_empty() || wf.cls_source.trim().is_empty() {
            workflow_results.push(json!({
                "workflow_id": wf.id,
                "ok": false,
                "error": "workflow id and cls_source required for burn-in",
            }));
            continue;
        }

        let idempotency_key = format!("cpkg:{plugin_id}:{version}:{}", wf.id);
        let bootstrap = bootstrap_workflow_inner(
            state,
            BootstrapWorkflowParams {
                workflow_id: wf.id.clone(),
                package_id: wf.package_id.clone(),
                cls_source: wf.cls_source.clone(),
                version: if wf.version.trim().is_empty() {
                    Some("v1".into())
                } else {
                    Some(wf.version.clone())
                },
                accounting_mode: wf.accounting_mode.clone(),
                enable: true,
                dry_run: false,
                run: true,
                idempotency_key: Some(idempotency_key),
                package: None,
            },
        )
        .await;

        let ok = bootstrap.get("ok").and_then(|v| v.as_bool()) == Some(true);
        if ok {
            workflow_ids.push(wf.id.clone());
            let meta = WorkflowSystemMeta {
                workflow_id: wf.id.clone(),
                plugin_id: plugin_id.to_string(),
                package_id: wf.package_id.clone(),
                system_tier: system_tier.clone(),
                importance: importance.into(),
                origin: "cpkg_burn_in".into(),
                receipt_hash: None,
            };
            persist_workflow_system_meta(state, &meta);

            if let Some(rec) = get_workflow(state, &wf.id) {
                tag_workflow_operator_surface(state, &rec, plugin_id, &system_tier, importance);
            }
        }
        workflow_results.push(json!({
            "workflow_id": wf.id,
            "bootstrap": bootstrap,
        }));
    }

    let entry = CpkgGlooRegistryEntry {
        plugin_id: plugin_id.to_string(),
        version: version.to_string(),
        app_id: if manifest.app_id.trim().is_empty() {
            plugin_id.to_string()
        } else {
            manifest.app_id.clone()
        },
        system_tier: system_tier.clone(),
        importance: importance.into(),
        receipt_head: receipt_head.clone(),
        workflow_ids: workflow_ids.clone(),
        burned_in_at: chrono::Utc::now().to_rfc3339(),
    };
    persist_cpkg_registry_entry(state, &entry);

    json!({
        "ok": workflow_results.iter().all(|r| r.pointer("/bootstrap/ok").and_then(|v| v.as_bool()) != Some(false)),
        "skipped": false,
        "plugin_id": plugin_id,
        "version": version,
        "system_tier": system_tier,
        "importance": importance,
        "receipt_head": receipt_head,
        "workflows": workflow_results,
        "registry": entry,
        "honesty": "Verified cpkg burned into workflow registry with system_default importance (same class as DevGuard/TraceTramp/WitnessCtl governance apps).",
    })
}

fn tag_workflow_operator_surface(
    state: &SharedState,
    rec: &WorkflowRecord,
    plugin_id: &str,
    system_tier: &str,
    importance: &str,
) {
    let mut es = state.engine_store.lock().unwrap();
    let folder = crate::operator::surface_merge::OPERATOR_SURFACE_FOLDER;
    let mut surface = es
        .folder_get(folder, &rec.workflow_id)
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            json!({
                "schema": "operator_surface.v1",
                "workflow_id": rec.workflow_id,
                "display": {
                    "title": rec.workflow_id,
                    "subtitle": rec.package_id,
                    "category": "workflow"
                },
            })
        });
    if let Some(obj) = surface.as_object_mut() {
        obj.insert(
            "governance".into(),
            json!({
                "system_tier": system_tier,
                "importance": importance,
                "plugin_id": plugin_id,
                "origin": "cpkg_burn_in",
                "protected": true,
            }),
        );
    }
    let _ = es.folder_put(folder, &rec.workflow_id, &surface);
}
