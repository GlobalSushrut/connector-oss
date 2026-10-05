//! AiPassport + SpendCease HTTP surfaces (private forensic; federated verify).

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;

/// GET /api/v1/aipsprt/:passport_id — public passport record (no private map).
pub async fn get_passport(
    State(state): State<SharedState>,
    Path(passport_id): Path<String>,
) -> Json<Value> {
    match crate::substrate::aipsprt::get_passport(state.as_ref(), &passport_id) {
        Some(p) => Json(json!({ "ok": true, "passport": p })),
        None => Json(json!({ "ok": false, "error": "not_found", "status": 404 })),
    }
}

/// GET /api/v1/aipsprt/private/:passport_id — tenant forensic map (operator).
pub async fn get_private(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(passport_id): Path<String>,
) -> Json<Value> {
    if let Err(v) =
        crate::services::intelligence_authority::require_lifecycle_actor(&headers, 4)
    {
        return Json(v);
    }
    match crate::substrate::aipsprt::get_private(state.as_ref(), &passport_id) {
        Some(p) => Json(json!({ "ok": true, "private": p })),
        None => Json(json!({ "ok": false, "error": "not_found", "status": 404 })),
    }
}

/// GET /api/v1/aipsprt/index/digest/:digest — private postings list (auth; not a public oracle).
pub async fn index_by_digest(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(digest): Path<String>,
) -> Json<Value> {
    if let Err(v) =
        crate::services::intelligence_authority::require_lifecycle_actor(&headers, 4)
    {
        return Json(v);
    }
    let digest = digest.trim().to_lowercase();
    if digest.is_empty() || digest.len() > 128 {
        return Json(json!({ "ok": false, "error": "bad_digest", "status": 400 }));
    }
    let key = format!("digest:{digest}");
    let ids = crate::substrate::aipsprt::index_ids(state.as_ref(), &key);
    Json(json!({
        "ok": true,
        "index_key": key,
        "passport_ids": ids,
        "count": ids.len(),
        "honesty": "auth_private_postings_not_public_existence_oracle",
    }))
}

/// GET /api/v1/aipsprt/:passport_id/c2pa-map — thin Content Credentials export sketch.
pub async fn c2pa_map(
    State(state): State<SharedState>,
    Path(passport_id): Path<String>,
) -> Json<Value> {
    match crate::substrate::aipsprt::get_passport(state.as_ref(), &passport_id) {
        Some(p) => Json(json!({
            "ok": true,
            "c2pa_export_map": connector_trust::c2pa_export_mapping(&p),
        })),
        None => Json(json!({ "ok": false, "error": "not_found", "status": 404 })),
    }
}

#[derive(Debug, Deserialize)]
pub struct VerifyBody {
    pub passport: Value,
    pub payload_digest: Option<String>,
}

/// POST /api/v1/aipsprt/verify — federated verify against this node's pubkey.
pub async fn verify_passport(
    State(state): State<SharedState>,
    Json(body): Json<VerifyBody>,
) -> Json<Value> {
    let passport: connector_trust::AiPassportSigV1 = match serde_json::from_value(body.passport) {
        Ok(p) => p,
        Err(e) => {
            return Json(json!({ "ok": false, "error": format!("parse: {e}"), "status": 400 }));
        }
    };
    match crate::substrate::aipsprt::verify_local(
        state.as_ref(),
        &passport,
        body.payload_digest.as_deref(),
    ) {
        Ok(()) => Json(json!({
            "ok": true,
            "verified": true,
            "passport_id": passport.passport_id,
            "honesty": "issuer_attestation_not_env_truth",
        })),
        Err(e) => Json(json!({ "ok": false, "verified": false, "error": e, "status": 400 })),
    }
}

#[derive(Debug, Deserialize)]
pub struct OutboxQuery {
    pub egress_operation_id: String,
}

/// GET /api/v1/aipsprt/outbox?egress_operation_id=
pub async fn get_outbox(
    State(state): State<SharedState>,
    Query(q): Query<OutboxQuery>,
) -> Json<Value> {
    match crate::substrate::aipsprt::outbox_status(state.as_ref(), &q.egress_operation_id) {
        Some(r) => Json(json!({ "ok": true, "outbox": r })),
        None => Json(json!({ "ok": false, "error": "not_found", "status": 404 })),
    }
}

/// GET /api/v1/aipsprt/schema
pub async fn schema() -> Json<Value> {
    Json(json!({
        "aipsprt": crate::substrate::aipsprt::schema_info(),
        "spend_cease": crate::substrate::spend_cease::schema_info(),
        "c2pa_export": {
            "helper": "connector_trust::c2pa_export_mapping",
            "route": "/api/v1/aipsprt/:passport_id/c2pa-map",
            "honesty": "export_map_only_not_embedded_manifest",
        },
    }))
}

/// GET /api/v1/spend/ceiling/:pid — current generation ceiling snapshot.
pub async fn spend_ceiling(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<Value> {
    let gen = crate::substrate::llm_context_broker::current_generation(&state, &pid).to_string();
    match crate::substrate::spend_cease::get_ceiling(state.as_ref(), &pid, &gen) {
        Some(c) => Json(json!({ "ok": true, "ceiling": c })),
        None => Json(json!({
            "ok": true,
            "ceiling": null,
            "generation_id": gen,
            "hint": "no ceiling until first admit/ensure",
        })),
    }
}

/// GET /api/v1/spend/burn/:pid — live burn meter (ceiling + inflight LLM).
pub async fn spend_burn(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<Value> {
    Json(crate::substrate::spend_cease::burn_meter(&state, &pid))
}

/// GET /api/v1/spend/cease/latest/:pid
pub async fn spend_cease_latest(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<Value> {
    match crate::substrate::spend_cease::latest_cease(state.as_ref(), &pid) {
        Some(v) => Json(json!({ "ok": true, "latest": v })),
        None => Json(json!({ "ok": true, "latest": null })),
    }
}
