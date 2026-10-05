//! Reference workflow install + sample-run endpoints.
//!
//! Two POST routes mounted under `/api/v1/workflows/reference/{id}/...`:
//!
//! - `install`     — P0-8 in `LEPTOS_UI_IMPLEMENTATION_PLAN.md`. One-click
//!   install of a shipped CCL template into the operator's workflow set.
//!   Wraps [`crate::services::workflow_runtime::register_workflow`] with the
//!   pre-canned CLS source so the dashboard never has to round-trip via the
//!   Builder.
//!
//! - `sample-run` — P2-14. Same install path, but additionally records a
//!   synthetic dry-run execution so the operator can immediately open a
//!   results page with fake-but-plausible data. Useful for trial sessions
//!   and reviewer demos. Returns a `run_id` the dashboard navigates to.
//!
//! Both endpoints accept admin / operator / developer roles (anything that
//! could already POST `/api/v1/workflows`). Playground sessions inherit
//! their callers' bearer auth via the same middleware chain.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};

use crate::state::SharedState;

use super::workflow_runtime::{
    list_reference_templates, register_workflow, RegisterWorkflowRequest,
};

/// Look up a reference template by id from the bundled catalog.
///
/// Returns `(name, cls_source)` on hit. The catalog itself is the
/// canonical source — keeping the lookup here (instead of duplicating
/// the template list) means new templates added to
/// `list_reference_templates()` are immediately installable without
/// touching this file.
async fn find_template(id: &str) -> Option<(String, String, Vec<String>)> {
    let Json(catalog) = list_reference_templates().await;
    let templates = catalog.get("templates")?.as_array()?.clone();
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
                .unwrap_or_default()
                .to_string();
            let plugins = t
                .get("plugins")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            return Some((name, src, plugins));
        }
    }
    None
}

fn workflow_id_for(id: &str) -> String {
    // Stable, slugified id so repeat installs land on the same record
    // rather than piling up `pkg-reference-X-1`, `-2`, etc. Operators can
    // still rename via the Builder; we just need a deterministic default.
    format!("ref-{}", id.replace('_', "-"))
}

fn package_id_for(id: &str) -> String {
    format!("pkg-reference-{}", id.replace('_', "-"))
}

/// `POST /api/v1/workflows/reference/{id}/install`
pub async fn install(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    let Some((name, src, plugins)) = find_template(&id).await else {
        return Json(json!({
            "ok": false,
            "error": format!("Unknown reference template `{id}`. See GET /api/v1/workflows/reference-templates."),
            "code": "REFERENCE_TEMPLATE_NOT_FOUND",
        }));
    };
    if src.trim().is_empty() {
        return Json(json!({
            "ok": false,
            "error": "Reference template has empty cls_source — server bundled the template metadata without its CCL body.",
            "code": "REFERENCE_TEMPLATE_EMPTY",
        }));
    }

    let accounting_mode =
        crate::operator::surface_merge::bundled_reference_surface(&id).and_then(|s| {
            s.pointer("/accounting/mode")
                .and_then(|m| m.as_str())
                .map(|m| m.to_string())
        });
    let req = RegisterWorkflowRequest {
        workflow_id: workflow_id_for(&id),
        package_id: package_id_for(&id),
        version: Some("v1".to_string()),
        cls_source: src,
        accounting_mode,
    };
    let inner = register_workflow(State(state), headers, Json(req)).await;
    let mut envelope = inner.0;
    if envelope
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        envelope["reference_template"] = json!({
            "id": id,
            "name": name,
            "plugins": plugins,
        });
        let wf_id = envelope
            .get("workflow_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                envelope
                    .pointer("/workflow/workflow_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| workflow_id_for(&id));
        envelope["workflow_id"] = json!(wf_id);
        envelope["hint"] = json!(format!(
            "Reference template registered. Open /workflows/{wf_id} to review and activate."
        ));
    }
    Json(envelope)
}

/// `POST /api/v1/workflows/reference/{id}/sample-run`
///
/// Installs (if needed) then records a synthetic dry-run so the
/// dashboard can navigate straight to `/cls-execution/{run_id}` with
/// pre-seeded inputs. The dry-run record is stored under the regular
/// workflow dry-run index so it shows up everywhere a real run would.
pub async fn sample_run(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    let Some((name, _src, plugins)) = find_template(&id).await else {
        return Json(json!({
            "ok": false,
            "error": format!("Unknown reference template `{id}`."),
            "code": "REFERENCE_TEMPLATE_NOT_FOUND",
        }));
    };

    // First make sure the workflow record exists. We don't care about
    // the install response shape beyond "ok" — if registration failed
    // for any reason (e.g. CCL parser tightened post-bundle), we
    // surface the error instead of silently writing a dangling run.
    let install_resp = install(State(state.clone()), headers.clone(), Path(id.clone())).await;
    if !install_resp
        .0
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Json(json!({
            "ok": false,
            "error": "Failed to install reference template before sample run.",
            "install": install_resp.0,
        }));
    }

    let workflow_id = workflow_id_for(&id);
    let run_id = format!("sample-{}-{}", id, chrono::Utc::now().timestamp_millis());
    let recorded_at = chrono::Utc::now().to_rfc3339();

    // Plausible synthetic dry-run payload — same shape that
    // `workflow_dry_run_summary_text` in the dashboard knows how to
    // parse, so the Workflows page renders it without special-casing.
    let dry_run = json!({
        "run_id": run_id,
        "recorded_at": recorded_at,
        "sample": true,
        "events_replayed": 6,
        "dispatched_actions": [
            {"action": "memory.read", "ok": true},
            {"action": "policy.evaluate", "ok": true},
            {"action": "tool.invoke", "ok": true},
            {"action": "audit.emit", "ok": true},
        ],
        "cnp_replay": {
            "mode": "sample",
            "category_counts": {
                "policy": 2,
                "tool": 1,
                "audit": 1,
            }
        },
        "cls_compile": {"ok": true, "contract_name": name, "block_count": 4},
        "plugins": plugins,
    });

    // Best-effort: persist under the workflow's dry-run index. If the
    // engine_store lock is poisoned we still return the run id so the
    // dashboard's navigation works.
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            crate::services::workflow_runtime::WORKFLOW_RUN_FOLDER,
            &run_id,
            &dry_run,
        );
        crate::services::workflow_runtime::append_workflow_dry_run_index(
            &mut **es,
            &workflow_id,
            &run_id,
            &recorded_at,
        );
    }

    Json(json!({
        "ok": true,
        "run_id": run_id,
        "workflow_id": workflow_id,
        "dry_run": dry_run,
        "hint": "Sample run is synthetic — use POST /api/v1/workflows/{workflow_id}/dry-run with your own inputs for a real execution.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn find_template_resolves_known_id() {
        let got = find_template("hitl_approve_audit").await;
        assert!(got.is_some());
        let (name, src, plugins) = got.unwrap();
        assert!(!name.is_empty());
        assert!(!src.trim().is_empty(), "cls_source must be bundled");
        assert!(plugins.contains(&"tracetramp".to_string()));
    }

    #[tokio::test]
    async fn find_template_returns_none_for_unknown_id() {
        assert!(find_template("does_not_exist").await.is_none());
    }

    #[test]
    fn ids_are_slugified() {
        assert_eq!(
            workflow_id_for("hitl_approve_audit"),
            "ref-hitl-approve-audit"
        );
        assert_eq!(
            package_id_for("hitl_approve_audit"),
            "pkg-reference-hitl-approve-audit"
        );
    }

    #[tokio::test]
    async fn all_bundled_templates_compile() {
        use crate::services::cls::compile_ccl_contract;

        let Json(catalog) = list_reference_templates().await;
        let templates = catalog
            .get("templates")
            .and_then(|v| v.as_array())
            .expect("reference catalog must expose templates[]");
        assert!(
            !templates.is_empty(),
            "expected at least one bundled reference template"
        );
        for t in templates {
            let id = t
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing-id>");
            let src = t
                .get("cls_source")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            assert!(
                !src.trim().is_empty(),
                "template `{id}` missing cls_source body"
            );
            compile_ccl_contract(src).unwrap_or_else(|err| {
                panic!("bundled template `{id}` failed CCL compile: {err:?}");
            });
        }
    }
}
