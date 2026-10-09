//! AgentPassport HTTP route handlers — all endpoints.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;
use validator::Validate;

use crate::agents;
use crate::attestation;
use crate::credentials;
use crate::error::AppError;
use crate::federation;
use crate::incidents;
use crate::reputation;
use crate::state::AppState;
use crate::types::*;
use crate::verify;

// ── Health ─────────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let db_ok        = state.pool.acquire().await.is_ok();
    let connector_ok = state.connector.health().await.is_ok();
    Json(json!({
        "status":       if db_ok && connector_ok { "ok" } else { "degraded" },
        "db":           if db_ok { "ok" } else { "error" },
        "connector":    if connector_ok { "ok" } else { "unreachable" },
        "instance_did": state.instance_did,
        "version":      env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = state.pool.acquire().await.is_ok();
    if db_ok {
        (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "not_ready" }))).into_response()
    }
}

// ── Agent registration ─────────────────────────────────────────────────────────

pub async fn register_agent(
    State(state): State<AppState>,
    Json(req):    Json<RegisterAgentRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let key_hex = std::env::var("AGENTPASSPORT_SIGNING_KEY")
        .unwrap_or_default();
    let result = agents::register_agent(&state.pool, state.default_org, &req, &key_hex).await
        .map_err(AppError::Internal)?;

    Ok((StatusCode::CREATED, Json(json!({
        "agent":          result.agent,
        "approval_token": result.approval_token,
        "next_step":      "Sponsor approval email sent. Sponsor must click the approval link (2FA required) to activate this agent.",
    }))))
}

pub async fn approve_sponsorship(
    State(state): State<AppState>,
    Path(token):  Path<String>,
) -> Result<Json<Value>, AppError> {
    agents::approve_sponsorship(&state.pool, &token).await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    Ok(Json(json!({
        "activated": true,
        "message": "Agent is now active and externally verifiable.",
    })))
}

// ── Agent directory ────────────────────────────────────────────────────────────

pub async fn list_agents(
    State(state): State<AppState>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let agents = agents::list_agents(&state.pool, state.default_org, &pg).await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({ "agents": agents, "count": agents.len() })))
}

pub async fn get_agent(
    State(state): State<AppState>,
    Path(did):    Path<String>,
) -> Result<Json<Value>, AppError> {
    let agent = agents::get_agent_by_did(&state.pool, &did).await
        .map_err(|e| AppError::NotFound(e.to_string()))?;
    Ok(Json(json!({ "agent": agent })))
}

// ── Revocation ─────────────────────────────────────────────────────────────────

pub async fn revoke_agent(
    State(state): State<AppState>,
    Path(did):    Path<String>,
    Json(req):    Json<RevokeRequest>,
) -> Result<Json<Value>, AppError> {
    req.validate().map_err(AppError::from)?;
    let actor = get_actor_did();
    agents::revoke_agent(&state.pool, state.default_org, &did, &req.reason, &actor).await
        .map_err(|e| AppError::NotFound(e.to_string()))?;
    Ok(Json(json!({ "revoked": true, "did": did })))
}

// ── Passport ───────────────────────────────────────────────────────────────────

pub async fn get_passport(
    State(state): State<AppState>,
    Path(did):    Path<String>,
) -> Result<Json<Value>, AppError> {
    let passport = attestation::build_passport(&state.pool, &did).await
        .map_err(|e| AppError::NotFound(e.to_string()))?;
    Ok(Json(json!({ "passport": passport })))
}

// ── Public verification ────────────────────────────────────────────────────────

pub async fn public_verify(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req):    Json<VerifyRequest>,
) -> Result<Json<Value>, AppError> {
    let ip = addr.ip().to_string();
    let result = verify::verify(&state, &req, None, Some(&ip)).await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    Ok(Json(serde_json::to_value(result).unwrap_or(json!({}))))
}

pub async fn get_crl(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let crl = verify::get_crl(&state.pool).await.map_err(AppError::Internal)?;
    Ok(Json(crl))
}

// ── Credentials ────────────────────────────────────────────────────────────────

pub async fn issue_credential(
    State(state): State<AppState>,
    Json(req):    Json<IssueCredentialRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let issuer_did = format!("did:connector:user:{}", state.default_org);
    let key_hex    = std::env::var("AGENTPASSPORT_SIGNING_KEY").unwrap_or_default();
    let cred = credentials::issue_credential(
        &state.pool, state.default_org, &issuer_did, &key_hex, &req
    ).await.map_err(AppError::Internal)?;
    Ok((StatusCode::CREATED, Json(json!({ "credential": cred }))))
}

pub async fn list_credentials(
    State(state): State<AppState>,
    Path(did):    Path<String>,
) -> Result<Json<Value>, AppError> {
    let creds = credentials::list_credentials(&state.pool, &did).await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({ "credentials": creds, "count": creds.len() })))
}

pub async fn revoke_credential(
    State(state): State<AppState>,
    Path(cred_id): Path<Uuid>,
    Json(req):    Json<RevokeRequest>,
) -> Result<Json<Value>, AppError> {
    req.validate().map_err(AppError::from)?;
    let actor = get_actor_did();
    credentials::revoke_credential(&state.pool, state.default_org, cred_id, &req.reason, &actor).await
        .map_err(|e| AppError::NotFound(e.to_string()))?;
    Ok(Json(json!({ "revoked": true, "credential_id": cred_id })))
}

// ── Reputation ─────────────────────────────────────────────────────────────────

pub async fn get_reputation(
    State(state): State<AppState>,
    Path(did):    Path<String>,
) -> Result<Json<Value>, AppError> {
    let rep = reputation::get_reputation(&state.pool, &did).await
        .map_err(|e| AppError::NotFound(e.to_string()))?;
    Ok(Json(rep))
}

// ── Attestation export ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ExportParams {
    pub format: Option<String>,
}

pub async fn export_attestation(
    State(state): State<AppState>,
    Path(did):    Path<String>,
    Query(p):     Query<ExportParams>,
) -> impl IntoResponse {
    let fmt = p.format.as_deref().unwrap_or("json");

    match fmt {
        "text" | "pdf" => {
            match attestation::export_text(&state, &did).await {
                Ok(text) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                        (header::CONTENT_DISPOSITION,
                         "attachment; filename=\"attestation.txt\""),
                    ],
                    text,
                ).into_response(),
                Err(e) => (StatusCode::NOT_FOUND,
                    [(header::CONTENT_TYPE, "application/json")],
                    format!("{{\"error\":\"{}\"}}", e)).into_response(),
            }
        }
        _ => {
            match attestation::export_json(&state, &did).await {
                Ok(v) => (StatusCode::OK, Json(v)).into_response(),
                Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))).into_response(),
            }
        }
    }
}

// ── Incidents ──────────────────────────────────────────────────────────────────

pub async fn create_incident(
    State(state): State<AppState>,
    Json(req):    Json<CreateIncidentRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let actor = get_actor_did();
    let incident = incidents::create_incident(
        &state.pool, &state.connector, state.default_org, &req, &actor
    ).await.map_err(AppError::Internal)?;
    Ok((StatusCode::CREATED, Json(json!({ "incident": incident }))))
}

pub async fn list_incidents(
    State(state): State<AppState>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let list = incidents::list_incidents(&state.pool, state.default_org, &pg).await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({ "incidents": list, "count": list.len() })))
}

pub async fn resolve_incident(
    State(state):   State<AppState>,
    Path(incident_id): Path<Uuid>,
    Json(req):      Json<ResolveIncidentRequest>,
) -> Result<Json<Value>, AppError> {
    req.validate().map_err(AppError::from)?;
    let actor = get_actor_did();
    let incident = incidents::resolve_incident(
        &state.pool, state.default_org, incident_id, &req, &actor
    ).await.map_err(|e| AppError::NotFound(e.to_string()))?;
    Ok(Json(json!({ "incident": incident })))
}

// ── Federation ─────────────────────────────────────────────────────────────────

pub async fn register_peer(
    State(state): State<AppState>,
    Json(req):    Json<RegisterFederationPeerRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let actor = get_actor_did();
    let peer = federation::register_peer(&state.pool, state.default_org, &req, &actor).await
        .map_err(AppError::Internal)?;
    Ok((StatusCode::CREATED, Json(json!({ "peer": peer }))))
}

pub async fn list_peers(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let peers = federation::list_peers(&state.pool, state.default_org).await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({ "peers": peers, "count": peers.len() })))
}

pub async fn sync_peer(
    State(state): State<AppState>,
    Path(peer_id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let actor = get_actor_did();
    let count = federation::sync_peer(&state.pool, state.default_org, peer_id, &state.http, &actor).await
        .map_err(|e| AppError::Connector(e.to_string()))?;
    Ok(Json(json!({ "imported": count })))
}

// ── Audit log ──────────────────────────────────────────────────────────────────

pub async fn get_audit(
    State(state): State<AppState>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let rows = sqlx::query(
        "SELECT entity_type, entity_id, action, actor_did, payload, this_cid, occurred_at
         FROM ap_audit_log WHERE org_id=$1
         ORDER BY occurred_at DESC LIMIT $2 OFFSET $3"
    )
    .bind(state.default_org)
    .bind(pg.limit()).bind(pg.offset())
    .fetch_all(&state.pool).await.map_err(AppError::from)?;

    use sqlx::Row;
    let entries: Vec<Value> = rows.iter().map(|r| json!({
        "entity_type": r.try_get::<String, _>("entity_type").unwrap_or_default(),
        "entity_id":   r.try_get::<String, _>("entity_id").unwrap_or_default(),
        "action":      r.try_get::<String, _>("action").unwrap_or_default(),
        "actor_did":   r.try_get::<Option<String>, _>("actor_did").unwrap_or_default(),
        "payload":     r.try_get::<Value, _>("payload").unwrap_or(json!({})),
        "this_cid":    r.try_get::<Option<String>, _>("this_cid").unwrap_or_default(),
        "occurred_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("occurred_at")
                           .unwrap_or_else(|_| chrono::Utc::now()),
    })).collect();

    Ok(Json(json!({ "audit": entries, "count": entries.len() })))
}

// ── Public agent export (for federation peers to call) ─────────────────────────

pub async fn export_agents(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let agents = agents::list_agents(
        &state.pool, state.default_org,
        &Pagination { limit: Some(200), offset: Some(0), status: Some("active".into()) }
    ).await.map_err(AppError::Internal)?;
    Ok(Json(json!({ "agents": agents })))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn get_actor_did() -> String {
    std::env::var("AGENTPASSPORT_ACTOR_DID")
        .unwrap_or_else(|_| "did:connector:system".into())
}
