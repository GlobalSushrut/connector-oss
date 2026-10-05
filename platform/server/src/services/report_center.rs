use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::state::SharedState;

const SEEDED_REPORT_RECEIPTS: &[&str] = &[
    "proof-export-receipt",
    "compliance-export-receipt",
    "agent-export-receipt",
    "memory-export-receipt",
    "cls-export-receipt",
    "executive-export-receipt",
];

fn load_report_receipts(state: &SharedState) -> Vec<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys("report_receipts", None)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|key| es.folder_get("report_receipts", &key).ok().flatten())
        .filter(|receipt| match receipt.get("receipt_id").and_then(|value| value.as_str()) {
            Some(id) => !SEEDED_REPORT_RECEIPTS.contains(&id),
            None => true,
        })
        .collect()
}

pub async fn get_report_center(State(state): State<SharedState>) -> impl IntoResponse {
    let evidence_packages = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("evidence_packages", None)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|key| es.folder_get("evidence_packages", &key).ok().flatten())
            .collect::<Vec<_>>()
    };

    let reports = vec![
        json!({
            "report_id": "proof-package",
            "title": "Proof Package Export",
            "kind": "proof",
            "endpoint": "/proof/list",
            "status": "catalog",
            "receipt_ref": null
        }),
        json!({
            "report_id": "compliance-report",
            "title": "Compliance Report Export",
            "kind": "compliance",
            "endpoint": "/compliance/report",
            "status": "catalog",
            "receipt_ref": null
        }),
        json!({
            "report_id": "agent-analysis",
            "title": "Agent Analysis Export",
            "kind": "agent",
            "endpoint": "/actionlog/regulation-report/soc2",
            "status": "catalog",
            "receipt_ref": null
        }),
        json!({
            "report_id": "memory-trace",
            "title": "Memory Trace Export",
            "kind": "memory",
            "endpoint": "/debug/export",
            "status": "catalog",
            "receipt_ref": null
        }),
        json!({
            "report_id": "cls-export",
            "title": "CLS App / Workflow Export",
            "kind": "cls",
            "endpoint": "/cls/packages/pkg-basic-tool-agent/execution/export",
            "status": "catalog",
            "receipt_ref": null
        }),
        json!({
            "report_id": "executive-summary",
            "title": "Executive Summary Export",
            "kind": "executive",
            "endpoint": "/monitor/usage-export",
            "status": "catalog",
            "receipt_ref": null
        }),
    ];

    let receipts = load_report_receipts(&state);

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "data": {
                "reports": reports,
                "stored_receipts": receipts,
                "evidence_packages": evidence_packages,
                "honesty": "Catalog rows are export routes, not effect receipts. Seeded placeholder receipts are not returned.",
            }
        })),
    )
}

pub async fn get_report_receipt(
    State(state): State<SharedState>,
    Path(receipt_id): Path<String>,
) -> impl IntoResponse {
    let receipts = load_report_receipts(&state);
    match receipts
        .into_iter()
        .find(|receipt| receipt["receipt_id"].as_str() == Some(receipt_id.as_str()))
    {
        Some(receipt) => (StatusCode::OK, Json(json!({ "ok": true, "data": receipt }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": { "code": "receipt_not_found", "message": format!("Receipt '{}' not found", receipt_id) }
            })),
        ),
    }
}
