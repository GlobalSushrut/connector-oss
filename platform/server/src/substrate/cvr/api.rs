//! HTTP surfaces for CVR isolation posture.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::operator::honesty::operator_envelope;
use crate::state::SharedState;

/// GET /api/v1/agents/:pid/isolation
pub async fn get_agent_isolation(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<Value> {
    Json(operator_envelope(crate::substrate::cvr::posture_for_agent(
        state.as_ref(),
        &pid,
    )))
}

/// GET /api/v1/runtime/backends — the seven industry tools Connector operates.
pub async fn get_backends() -> Json<Value> {
    Json(operator_envelope(crate::substrate::cvr::backends::live()))
}

#[derive(Debug, Deserialize)]
pub struct DeployVerifyQuery {
    profile: Option<String>,
}

/// GET /api/v1/runtime/deploy-verify — fail closed on operational evidence.
pub async fn get_deploy_verify(
    State(state): State<SharedState>,
    Query(query): Query<DeployVerifyQuery>,
) -> Json<Value> {
    let requested = query.profile.as_deref().unwrap_or("linux-kvm");
    let Some(profile) =
        crate::substrate::cvr::deployment_verify::DeployProfile::parse(requested)
    else {
        return Json(operator_envelope(json!({
            "schema": crate::substrate::cvr::deployment_verify::SCHEMA,
            "ok": false,
            "operational_ready": false,
            "production_eligible": false,
            "error": "invalid_profile",
            "allowed": ["linux-kvm", "kubernetes"],
        })));
    };
    Json(operator_envelope(
        crate::substrate::cvr::deployment_verify::live(state.as_ref(), profile),
    ))
}

/// GET /api/v1/runtime/ecosystem — honest HAVE / PARTIAL / TARGET report.
pub async fn get_ecosystem() -> Json<Value> {
    Json(operator_envelope(crate::substrate::cvr::ecosystem::report()))
}

/// GET /api/v1/runtime/cease-proof/:agent_pid — ten steps scored from stored records.
pub async fn get_cease_proof(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    Json(operator_envelope(
        crate::substrate::cvr::ecosystem::cease_proof(state.as_ref(), &agent_pid),
    ))
}

/// GET /api/v1/runtime/explain/:receipt_id — reconstruct one stored receipt.
pub async fn get_explain(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(receipt_id): Path<String>,
) -> Json<Value> {
    let claims = crate::auth::extract_claims(&headers);
    let operator = claims.as_ref().map(|c| crate::substrate::cvr::ecosystem::VerifiedOperator {
        sub: c.sub.as_str(),
        jti: c.jti.as_str(),
        role: c.role.as_str(),
    });
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok());
    Json(operator_envelope(
        crate::substrate::cvr::ecosystem::explain(state.as_ref(), &receipt_id, operator, traceparent),
    ))
}

/// GET /api/v1/cvr/status — node-level CVR / HostProbe / RuntimeBundle
pub async fn get_cvr_status(State(state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(crate::substrate::cvr::cvr_posture(
        state.as_ref(),
    )))
}

/// GET /api/v1/cvr/microd — privileged supervisor live status
pub async fn get_microd_status() -> Json<Value> {
    Json(operator_envelope(json!({
        "ok": true,
        "microd": crate::substrate::cvr::microd_client::posture_json(),
        "status": crate::substrate::cvr::microd_client::status(),
    })))
}

/// POST /api/v1/cvr/microd/warm — ensure warm pool marker (D4 stub)
pub async fn post_microd_warm(Json(body): Json<Value>) -> Json<Value> {
    let n = body.get("n").and_then(|v| v.as_u64()).map(|n| n as usize);
    match crate::substrate::cvr::microd_client::warm_ensure(n) {
        Ok(v) => Json(operator_envelope(v)),
        Err(e) => Json(json!({
            "ok": false,
            "error": e,
            "status": 503,
            "hint": "Start connector-microd.service",
        })),
    }
}

/// PATCH /api/v1/agents/:pid/isolation — set engineer intent on agent_meta
pub async fn patch_agent_isolation(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let intent = body
        .get("isolation")
        .or_else(|| body.get("intent"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(parsed) = crate::substrate::cvr::IsolationIntent::parse(intent) else {
        return Json(json!({
            "ok": false,
            "error": "invalid_isolation_intent",
            "allowed": ["auto", "linux-cell", "hardened-linux-cell", "shared-microvm", "dedicated-microvm"],
            "status": 400,
        }));
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let mut meta = es
            .folder_get("agent_meta", &pid)
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({"pid": pid}));
        if let Some(obj) = meta.as_object_mut() {
            obj.insert("isolation".into(), json!(parsed.as_str()));
            if let Some(risk) = body.get("risk").and_then(|v| v.as_str()) {
                obj.insert("isolation_risk".into(), json!(risk));
            }
            if let Some(res) = body.get("resources").and_then(|v| v.as_str()) {
                if crate::substrate::cvr::ResourceProfile::parse(res).is_some() {
                    obj.insert("resources".into(), json!(res));
                }
            }
        }
        let _ = es.folder_put("agent_meta", &pid, &meta);
    }
    Json(operator_envelope(json!({
        "ok": true,
        "pid": pid,
        "isolation": parsed.as_str(),
        "resources": body.get("resources"),
        "resolution": crate::substrate::cvr::resolve_for_agent(state.as_ref(), &pid).to_json(),
    })))
}

/// POST /api/v1/agents/:pid/isolation/promote — AgentCell → MicroCell, same agent_pid (F1)
pub async fn post_promote_isolation(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let target_s = body
        .get("target")
        .or_else(|| body.get("to"))
        .and_then(|v| v.as_str())
        .unwrap_or("dedicated");
    let Some(target) = crate::substrate::cvr::PromoteTarget::parse(target_s) else {
        return Json(json!({
            "ok": false,
            "error": "invalid_promote_target",
            "allowed": ["shared", "dedicated", "shared-microvm", "dedicated-microvm", "v3", "v4"],
            "status": 400,
        }));
    };
    match crate::substrate::cvr::promote_to_microcell(state.as_ref(), &pid, target) {
        Ok(v) => Json(operator_envelope(v)),
        Err(e) => Json(e),
    }
}
