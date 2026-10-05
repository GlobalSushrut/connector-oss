//! Hub workflow `.cpkg` publish — honesty stub (P4.2).
//!
//! Full registry / verify-on-install is future. See `docs/HUB_WORKFLOW_PUBLISH.md`.

use axum::{http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize, Default)]
pub struct HubWorkflowPublishRequest {
    pub workflow_id: Option<String>,
    pub package_id: Option<String>,
    pub version: Option<String>,
    pub requires: Option<Vec<String>>,
    pub cls_source: Option<String>,
}

/// `POST /api/v1/hub/workflows/publish` — accepts the future request shape; does not publish.
pub async fn post_hub_workflow_publish(
    Json(req): Json<HubWorkflowPublishRequest>,
) -> (StatusCode, Json<Value>) {
    let workflow_id = req
        .workflow_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let accepted = json!({
        "workflow_id": workflow_id,
        "package_id": req.package_id.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        "version": req.version.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        "requires": req.requires.unwrap_or_default(),
        "cls_source_present": req
            .cls_source
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false),
    });

    // Schema-valid call without a workflow_id is still honesty-ok (documents the contract).
    let status = if workflow_id.is_some() {
        "partial"
    } else {
        "implemented_false"
    };

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "schema": "hub.workflow.publish.v1",
            "implemented": false,
            "status": status,
            "honesty": "Hub workflow .cpkg publish is not a shipping install path; CLI preview only until Hub registry lands.",
            "docs": "docs/HUB_WORKFLOW_PUBLISH.md",
            "cli_preview": "connectorctl workflow publish <workflow_id>",
            "future": {
                "manifest_schema": "workflow.cpkg.v1",
                "verify_on_install": true,
                "yank": "DELETE /api/v1/hub/workflows/:package_id/:version",
                "install": "POST /api/v1/hub/workflows/install"
            },
            "accepted_request_shape": accepted,
        })),
    )
}
