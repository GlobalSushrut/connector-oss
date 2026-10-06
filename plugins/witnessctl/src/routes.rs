use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    capture::CaptureEngine,
    compliance::ComplianceEngine,
    config::Config,
    connector::ConnectorClient,
    custody,
    error::AppError,
    export::ExportEngine,
    proxy::ProxyEngine,
    receipt::verify_chain,
    session::SessionManager,
    types::*,
    webhook::WebhookEngine,
};

const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000000";

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub connector: ConnectorClient,
    pub sessions: SessionManager,
    pub capture: CaptureEngine,
    pub compliance: ComplianceEngine,
    pub proxy_engine: ProxyEngine,
    pub export_engine: ExportEngine,
    pub webhook: WebhookEngine,
    pub export_rate_limit: Mutex<HashMap<String, Vec<i64>>>,
    pub proxy_rate_limit: Mutex<HashMap<String, Vec<i64>>>,
    pub unlock_summary: serde_json::Value,
    pub connector_unlock_cache: Mutex<Option<(i64, bool, String)>>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    let api_state = state.clone();
    let proxy_state = state.clone();
    let integrations_router = Router::new()
        .route(
            "/api/v1/integrations/tracetramp/handoff",
            post(tracetramp_handoff),
        )
        .route(
            "/api/v1/integrations/tracetramp/by-trace/:trace_id",
            get(tracetramp_by_trace),
        );
    let api_router = Router::new()
        // Sessions
        .route("/api/v1/sessions", post(open_session))
        .route("/api/v1/sessions", get(list_sessions))
        .route("/api/v1/sessions/:id", get(get_session))
        .route("/api/v1/sessions/:id/seal", post(seal_session))
        .route("/api/v1/sessions/:id/lock", post(lock_session))
        .route("/api/v1/sessions/:id/unlock", post(unlock_session))
        .route("/api/v1/sessions/:id/quarantine", post(quarantine_session))
        .route("/api/v1/sessions/:id/unquarantine", post(unquarantine_session))
        .route("/api/v1/sessions/:id/upstream", post(update_session_upstream))
        // Ingest (SDK shim mode)
        .route("/api/v1/ingest", post(ingest_call))
        // Captures + FNI verify (P6.4)
        .route("/api/v1/captures/:id", get(get_capture))
        .route("/api/v1/captures/:id/fni-verify", get(fni_verify_capture))
        // Compliance
        .route("/api/v1/compliance/:session_id", get(get_compliance))
        .route("/api/v1/compliance/:session_id/evaluate", post(evaluate_compliance))
        .route("/api/v1/compliance/:session_id/readiness", get(get_compliance_readiness))
        .route("/api/v1/compliance/:session_id/manual-attest", post(manual_attest_compliance))
        .route("/api/v1/compliance/:session_id/hitl", get(list_hitl_queue))
        .route("/api/v1/compliance/:session_id/hitl", post(create_hitl_item))
        .route("/api/v1/compliance/:session_id/hitl/:item_id/resolve", post(resolve_hitl_item))
        // Proof & verification
        .route("/api/v1/proof/:session_id", get(get_proof))
        .route("/api/v1/verify/:session_id", get(verify_session))
        // Schema history
        .route("/api/v1/schemas/:session_id", get(get_schemas))
        // PII report
        .route("/api/v1/pii/:session_id", get(get_pii_report))
        // Export
        .route("/api/v1/export/:session_id", get(export_session))
        .route("/api/v1/report/:session_id", get(report_session))
        .route("/api/v1/report/:session_id/batch", get(report_batch_session))
        .route("/api/v1/custody/:session_id/status", get(get_custody_status))
        .route("/api/v1/popeye", get(get_popeye_scan))
        // Decision Pentest
        .route("/api/v1/pentest/:session_id/decisions", get(list_decision_pentests))
        .route("/api/v1/pentest/:session_id/decisions/:trace_id", get(get_decision_pentest))
        .route_layer(middleware::from_fn_with_state(api_state, api_auth_middleware));

    Router::new()
        // Health + minimal operator dashboard (production; replaces removed TUI)
        .route("/health", get(health_check))
        .route("/admin/dashboard", get(admin_dashboard))
        .route("/api/v1/custody/replicate", post(custody_replicate))
        .merge(integrations_router)
        .merge(api_router)
        // Proxy (reverse proxy mode)
        .route("/witness/*path", any(proxy_forward))
        .route_layer(middleware::from_fn_with_state(
            proxy_state,
            witness_proxy_rate_limit_middleware,
        ))
        .with_state(state)
}

async fn witness_proxy_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !req.uri().path().starts_with("/witness/") {
        return next.run(req).await;
    }
    let token = req
        .headers()
        .get("x-witness-session")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "anonymous".to_string());
    let now = chrono::Utc::now().timestamp();
    let mut limiter = state.proxy_rate_limit.lock().await;
    let window = limiter.entry(token).or_default();
    window.retain(|ts| now - *ts <= 60);
    if window.len() >= 1000 {
        let mut response = Json(serde_json::json!({
            "error": "Too many requests",
            "message": "Rate limit exceeded: 1000 requests per minute per witness session token"
        }))
        .into_response();
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        response
            .headers_mut()
            .insert("Retry-After", axum::http::HeaderValue::from_static("60"));
        return response;
    }
    window.push(now);
    drop(limiter);
    next.run(req).await
}

// ── Health ────────────────────────────────────────────────────────────────────

async fn admin_dashboard() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../admin-ui/dashboard.html"),
    )
}

async fn health_check(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, AppError> {
    sqlx::query("SELECT 1").fetch_one(&state.db).await.map_err(|e| AppError::DatabaseError(e))?;
    let connector_available = state.connector.health_check().await;
    let connector_authenticated = state.config.connector_api_key_present && connector_available;
    let watchdog = sqlx::query(
        "SELECT route_profile, healthy, active_session_count, heartbeat_at \
         FROM witness_proxy_watchdog WHERE service_name = 'witnessctl-proxy' ORDER BY heartbeat_at DESC LIMIT 1"
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|r| serde_json::json!({
        "route_profile": r.get::<String, _>("route_profile"),
        "healthy": r.get::<bool, _>("healthy"),
        "active_session_count": r.get::<i64, _>("active_session_count"),
        "heartbeat_at": r.get::<chrono::DateTime<chrono::Utc>, _>("heartbeat_at").to_rfc3339(),
    }));
    Ok(Json(serde_json::json!({
        "status": "ok",
        "service": "witnessctl",
        "database": true,
        "connector": connector_available,
        "connector_available": connector_available,
        "connector_authenticated": connector_authenticated,
        "unlock": state.unlock_summary,
        "cage_mode": state.config.cage_mode,
        "watchdog": watchdog,
    })))
}

const TRACETRAMP_HANDOFF_SECRET_HEADER: &str = "X-WitnessCtl-Tracetramp-Handoff-Secret";

fn secrets_equal_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn verify_tracetramp_handoff_secret(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let expected = state
        .config
        .tracetramp_handoff_secret
        .as_deref()
        .ok_or_else(|| {
            AppError::Internal(
                "TraceTramp handoff is not configured (set WITNESSCTL_TRACETRAMP_HANDOFF_SECRET)"
                    .to_string(),
            )
        })?;
    let provided = headers
        .get(TRACETRAMP_HANDOFF_SECRET_HEADER)
        .or_else(|| headers.get("x-witnessctl-tracetramp-handoff-secret"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if provided.is_empty() {
        return Err(AppError::Unauthorized(
            "Missing X-WitnessCtl-Tracetramp-Handoff-Secret".to_string(),
        ));
    }
    if !secrets_equal_ct(expected.as_bytes(), provided.as_bytes()) {
        return Err(AppError::Unauthorized(
            "Invalid TraceTramp handoff secret".to_string(),
        ));
    }
    Ok(())
}

fn json_nonempty_string(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| {
        if let Some(s) = x.as_str() {
            let t = s.trim();
            (!t.is_empty()).then_some(t.to_string())
        } else if x.is_null() {
            None
        } else {
            let s = x.to_string();
            let t = s.trim();
            (!t.is_empty()).then_some(t.to_string())
        }
    })
}

/// Aligns with TraceTramp `ledger_contract` on decision envelopes (cage strategy: dual proof).
const WITNESS_TRACETRAMP_HANDOFF_LEDGER: &str = "witnessctl_tracetramp_handoff_v1";

async fn tracetramp_handoff(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_tracetramp_handoff_secret(&state, &headers)?;
    let trace_id = json_nonempty_string(&body, "trace_id")
        .ok_or_else(|| AppError::BadRequest("missing trace_id".to_string()))?;
    let request_id = json_nonempty_string(&body, "request_id")
        .ok_or_else(|| AppError::BadRequest("missing request_id".to_string()))?;
    let tenant_id = json_nonempty_string(&body, "tenant_id")
        .ok_or_else(|| AppError::BadRequest("missing tenant_id".to_string()))?;
    if trace_id.len() > 512 || request_id.len() > 512 || tenant_id.len() > 512 {
        return Err(AppError::BadRequest(
            "trace_id, request_id, or tenant_id exceeds max length".to_string(),
        ));
    }
    if let Some(obj) = body.as_object_mut() {
        obj.entry("witness_ledger_contract".to_string())
            .or_insert(serde_json::json!(WITNESS_TRACETRAMP_HANDOFF_LEDGER));
        obj.entry("ingress_ledger_contract".to_string())
            .or_insert(serde_json::json!("tracetramp_append_only_ledger_v1"));
    }
    let recorded = record_tracetramp_witness(&state, &trace_id, &request_id, &tenant_id, &body).await?;
    Ok(Json(recorded))
}

fn witness_tenant_uuid(raw: &str) -> Uuid {
    Uuid::parse_str(raw).unwrap_or_else(|_| Uuid::nil())
}

/// TraceTramp hands off a decision. WitnessCtl records it as its own components:
/// one session, one capture, one receipt. It does not store the chat, and it does
/// not write a MemPacket. A database restart drops these rows; migrations rebuild
/// the empty tables.
async fn record_tracetramp_witness(
    state: &AppState,
    trace_id: &str,
    request_id: &str,
    tenant_label: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    let tenant_id = witness_tenant_uuid(tenant_label);
    let actor = json_nonempty_string(body, "actor_id").unwrap_or_else(|| "tracetramp".to_string());
    let decision = json_nonempty_string(body, "decision").unwrap_or_else(|| "allow".to_string());
    let verdict = match decision.to_ascii_lowercase().as_str() {
        "block" | "deny" => "deny",
        "hold" | "require_approval" => "hold",
        _ => "allow",
    };
    let pii = body.get("pii_in_request").and_then(|v| v.as_bool()).unwrap_or(false);
    let cost: f64 = body.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let operation = serde_json::json!({
        "trace_id": trace_id,
        "request_id": request_id,
        "tenant": tenant_label,
        "actor_id": actor,
        "decision": decision,
        "model": body.get("model").cloned().unwrap_or(serde_json::Value::Null),
        "pii_in_request": pii,
        "cost_usd": cost,
    });
    let operation_bytes = serde_json::to_vec(&operation).unwrap_or_default();
    let request_hash = hex::encode(Sha256::digest(&operation_bytes));

    let mut tx = state.db.begin().await?;
    let existing = sqlx::query(
        "SELECT id, chain_head_hmac, receipt_seq FROM witness_sessions \
         WHERE tenant_id = $1 AND role = 'tracetramp' AND status = 'active' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (session_id, prev_hmac, receipt_seq) = if let Some(row) = existing {
        let id: Uuid = row.get("id");
        let head: Option<String> = row.get("chain_head_hmac");
        let seq: i64 = row.get("receipt_seq");
        (id, head, seq)
    } else {
        let session_id = Uuid::new_v4();
        let token = format!("wst_tt_{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO witness_sessions \
             (id, tenant_id, upstream, role, agent_pid, mode, status, frameworks, policy, session_token) \
             VALUES ($1, $2, $3, 'tracetramp', $4, 'webhook', 'active', ARRAY['soc2']::text[], $5, $6)",
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(tenant_label)
        .bind(&actor)
        .bind(serde_json::json!({"source": "tracetramp_handoff"}))
        .bind(&token)
        .execute(&mut *tx)
        .await?;
        let open = crate::receipt::generate_receipt(
            session_id,
            None,
            "session.open",
            0,
            serde_json::json!({"role": "tracetramp", "tenant": tenant_label}),
            None,
            &state.config.hmac_secret,
        );
        sqlx::query(
            "INSERT INTO witness_receipts \
             (id, tenant_id, session_id, event_type, seq, payload, hmac, prev_hmac) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(open.id)
        .bind(tenant_id)
        .bind(session_id)
        .bind(&open.event_type)
        .bind(open.seq)
        .bind(&open.payload)
        .bind(&open.hmac)
        .bind(&open.prev_hmac)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE witness_sessions SET chain_head_hmac = $1, receipt_seq = 1 WHERE id = $2",
        )
        .bind(&open.hmac)
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
        (session_id, Some(open.hmac), 1)
    };

    let seq = receipt_seq + 1;
    let capture_id = Uuid::new_v4();
    let path = format!("/ledger/{trace_id}");
    sqlx::query(
        "INSERT INTO witness_captures \
         (id, tenant_id, session_id, seq, method, url, host, path, request_hash, \
          admission_verdict, firewall_blocked, firewall_checked, pii_in_request, pii_in_response, \
          schema_drift, tracetramp_trace_id, tracetramp_request_id, cost_usd) \
         VALUES ($1, $2, $3, $4, 'POST', $5, 'tracetramp', $6, $7, $8, $9, TRUE, $10, FALSE, FALSE, $11, $12, $13)",
    )
    .bind(capture_id)
    .bind(tenant_id)
    .bind(session_id)
    .bind(seq)
    .bind(format!("tracetramp://ledger/{trace_id}"))
    .bind(&path)
    .bind(&request_hash)
    .bind(verdict)
    .bind(verdict == "deny")
    .bind(pii)
    .bind(trace_id)
    .bind(request_id)
    .bind(cost)
    .execute(&mut *tx)
    .await?;

    let receipt = crate::receipt::generate_receipt(
        session_id,
        Some(capture_id),
        "api.call",
        seq,
        operation.clone(),
        prev_hmac.as_deref(),
        &state.config.hmac_secret,
    );
    sqlx::query(
        "INSERT INTO witness_receipts \
         (id, tenant_id, session_id, capture_id, event_type, seq, payload, hmac, prev_hmac) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(receipt.id)
    .bind(tenant_id)
    .bind(session_id)
    .bind(capture_id)
    .bind(&receipt.event_type)
    .bind(receipt.seq)
    .bind(&receipt.payload)
    .bind(&receipt.hmac)
    .bind(&receipt.prev_hmac)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE witness_sessions \
         SET chain_head_hmac = $1, receipt_seq = $2, total_calls = total_calls + 1, \
             total_blocked = total_blocked + CASE WHEN $3 THEN 1 ELSE 0 END, \
             total_pii_hits = total_pii_hits + CASE WHEN $4 THEN 1 ELSE 0 END, \
             cost_usd = cost_usd + $5, updated_at = NOW() \
         WHERE id = $6",
    )
    .bind(&receipt.hmac)
    .bind(seq)
    .bind(verdict == "deny")
    .bind(pii)
    .bind(cost)
    .bind(session_id)
    .execute(&mut *tx)
    .await?;

    let handoff_id: Uuid = sqlx::query_scalar(
        "INSERT INTO witness_tracetramp_handoffs (trace_id, request_id, tenant_id, payload) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(trace_id)
    .bind(request_id)
    .bind(tenant_label)
    .bind(body)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(serde_json::json!({
        "ok": true,
        "id": handoff_id,
        "store": "witnessctl",
        "session_id": session_id,
        "capture_id": capture_id,
        "receipt_id": receipt.id,
        "components": ["session", "capture", "receipt"],
        "honesty": "WitnessCtl recorded a session, a capture, and a receipt. This is not a MemPacket and not the TraceTramp chat log. A database restart drops these rows.",
    }))
}

async fn tracetramp_by_trace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_tracetramp_handoff_secret(&state, &headers)?;
    if trace_id.is_empty() || trace_id.len() > 512 {
        return Err(AppError::BadRequest("invalid trace_id".to_string()));
    }
    let handoff_rows = sqlx::query(
        "SELECT id, trace_id, request_id, tenant_id, payload, created_at \
         FROM witness_tracetramp_handoffs WHERE trace_id = $1 ORDER BY created_at DESC LIMIT 500",
    )
    .bind(&trace_id)
    .fetch_all(&state.db)
    .await?;
    let mut handoffs = Vec::with_capacity(handoff_rows.len());
    for r in handoff_rows {
        let payload: serde_json::Value = r.get("payload");
        handoffs.push(serde_json::json!({
            "id": r.get::<Uuid, _>("id"),
            "trace_id": r.get::<String, _>("trace_id"),
            "request_id": r.get::<String, _>("request_id"),
            "tenant_id": r.get::<String, _>("tenant_id"),
            "payload": payload,
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        }));
    }
    let capture_rows = sqlx::query(
        "SELECT id, session_id, seq, method, url, host, path, fni_flow_id, fni_verify_status, \
         tracetramp_trace_id, tracetramp_request_id, created_at \
         FROM witness_captures WHERE tracetramp_trace_id = $1 ORDER BY created_at DESC LIMIT 500",
    )
    .bind(&trace_id)
    .fetch_all(&state.db)
    .await?;
    let mut captures = Vec::with_capacity(capture_rows.len());
    for r in capture_rows {
        captures.push(serde_json::json!({
            "id": r.get::<Uuid, _>("id"),
            "session_id": r.get::<Uuid, _>("session_id"),
            "seq": r.get::<i64, _>("seq"),
            "method": r.get::<String, _>("method"),
            "url": r.get::<String, _>("url"),
            "host": r.get::<String, _>("host"),
            "path": r.get::<String, _>("path"),
            "fni_flow_id": r.get::<Option<String>, _>("fni_flow_id"),
            "fni_verify_status": r.get::<Option<String>, _>("fni_verify_status"),
            "tracetramp_trace_id": r.get::<Option<String>, _>("tracetramp_trace_id"),
            "tracetramp_request_id": r.get::<Option<String>, _>("tracetramp_request_id"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        }));
    }
    Ok(Json(serde_json::json!({
        "trace_id": trace_id,
        "handoffs": handoffs,
        "captures": captures,
    })))
}

async fn api_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if enforce_connector_unlock(&state).await.is_err() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let token = bearer_token(req.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let tenant_id = effective_tenant_id_from_headers(&state, req.headers(), token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let admin_token = std::env::var("WITNESSCTL_ADMIN_TOKEN").ok();
    let is_admin = admin_token
        .as_deref()
        .map(|t| !t.trim().is_empty() && t == token)
        .unwrap_or(false);
    if is_admin {
        let principal = connector_trust::PrincipalContextV2 {
            subject: "admin-token".into(),
            email: String::new(),
            role: "admin".into(),
            permissions: vec!["*".into()],
            tenant_id: Some(tenant_id.to_string()),
            jti: None,
            token_type: "api_key".into(),
            instance_id: None,
            auth_source: connector_trust::principal::AuthSourceV2::ApiKey,
            contract_version: 2,
        };
        req.extensions_mut().insert(principal);
        return Ok(next.run(req).await);
    }

    let has_session = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(1) FROM witness_sessions WHERE session_token = $1 AND tenant_id = $2"
    )
    .bind(token)
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .map(|count| count > 0)
    .unwrap_or(false);

    if !has_session {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let principal = connector_trust::PrincipalContextV2 {
        subject: format!("session:{}", &token[..token.len().min(12)]),
        email: String::new(),
        role: "operator".into(),
        permissions: vec!["witness:session".into()],
        tenant_id: Some(tenant_id.to_string()),
        jti: None,
        token_type: "access".into(),
        instance_id: None,
        auth_source: connector_trust::principal::AuthSourceV2::Jwt,
        contract_version: 2,
    };
    req.extensions_mut().insert(principal);

    Ok(next.run(req).await)
}

async fn enforce_connector_unlock(state: &Arc<AppState>) -> Result<(), AppError> {
    if !state.config.connector_api_key_present && state.config.requested_agents <= 3 {
        return Ok(());
    }
    let now = chrono::Utc::now().timestamp();
    {
        let cache = state.connector_unlock_cache.lock().await;
        if let Some((ts, ok, _)) = &*cache {
            if now - *ts < 30 {
                if *ok {
                    return Ok(());
                }
                return Err(AppError::Unauthorized(
                    "Connector unlock validation cached as failed".to_string(),
                ));
            }
        }
    }
    let validated = state.connector.validate_access_key().await;
    let mut cache = state.connector_unlock_cache.lock().await;
    match validated {
        Ok(()) => {
            *cache = Some((now, true, "ok".to_string()));
            Ok(())
        }
        Err(e) => {
            *cache = Some((now, false, e.to_string()));
            Err(AppError::Unauthorized(format!(
                "Connector unlock validation failed: {}",
                e
            )))
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn derive_tenant_id_from_token(token: &str) -> Uuid {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

fn effective_tenant_id(state: &Arc<AppState>, token: &str) -> Result<Uuid, AppError> {
    // Prefer explicit platform tenant binding when forwarded (UUID form).
    // Session ownership still enforced via enforce_session_access (token + tenant).
    if let Ok(raw) = std::env::var("WITNESSCTL_TENANT_ID") {
        if let Ok(tid) = Uuid::parse_str(raw.trim()) {
            return Ok(tid);
        }
    }
    if state.config.is_enterprise_tier() {
        return Ok(derive_tenant_id_from_token(token));
    }
    Uuid::parse_str(DEFAULT_TENANT_ID)
        .map_err(|e| AppError::Internal(format!("invalid default tenant id: {}", e)))
}

fn effective_tenant_id_from_headers(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    token: &str,
) -> Result<Uuid, AppError> {
    if let Some(hdr) = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok(tid) = Uuid::parse_str(hdr) {
            return Ok(tid);
        }
        // Non-UUID tenant ids: stable hash into UUID space (matches enterprise token derivation style).
        let digest = Sha256::digest(hdr.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        return Ok(Uuid::from_bytes(bytes));
    }
    effective_tenant_id(state, token)
}

fn enterprise_required(feature: &str) -> AppError {
    AppError::AdmissionDenied(format!(
        "This feature requires Enterprise tier. Contact sales. ({})",
        feature
    ))
}

// ── Sessions ──────────────────────────────────────────────────────────────────

async fn open_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<OpenSessionRequest>,
) -> Result<Json<OpenSessionResponse>, AppError> {
    let token = bearer_token(&headers)
        .ok_or_else(|| AppError::Unauthorized("Missing bearer token".to_string()))?;
    let tenant_id = effective_tenant_id_from_headers(&state, &headers, token)?;
    let resp = state.sessions.open_session(req, tenant_id).await?;
    Ok(Json(resp))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Session>, AppError> {
    enforce_session_access(&state, &headers, id).await?;
    let session = state.sessions.get_session(id).await?;
    Ok(Json(session))
}

/// `GET /api/v1/captures/:id` — capture row including `fni_verify_status` (P6.4).
async fn get_capture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query(
        "SELECT id, session_id, seq, method, url, host, path, fni_flow_id, fni_verify_status, \
         tracetramp_trace_id, tracetramp_request_id, created_at \
         FROM witness_captures WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("capture {id}")))?;
    let session_id: Uuid = row.get("session_id");
    enforce_session_access(&state, &headers, session_id).await?;
    Ok(Json(serde_json::json!({
        "id": row.get::<Uuid, _>("id"),
        "session_id": session_id,
        "seq": row.get::<i64, _>("seq"),
        "method": row.get::<String, _>("method"),
        "url": row.get::<String, _>("url"),
        "host": row.get::<String, _>("host"),
        "path": row.get::<String, _>("path"),
        "fni_flow_id": row.get::<Option<String>, _>("fni_flow_id"),
        "fni_verify_status": row.get::<Option<String>, _>("fni_verify_status"),
        "tracetramp_trace_id": row.get::<Option<String>, _>("tracetramp_trace_id"),
        "tracetramp_request_id": row.get::<Option<String>, _>("tracetramp_request_id"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        "honesty": "fni_verify_status is unverified until GET …/fni-verify; never decorative verified",
    })))
}

/// `GET /api/v1/captures/:id/fni-verify` — CFNI verify when secret + wire available (P6.4).
async fn fni_verify_capture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query(
        "SELECT session_id, fni_flow_id, fni_verify_status, fni_cfni_wire \
         FROM witness_captures WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("capture {id}")))?;
    let session_id: Uuid = row.get("session_id");
    enforce_session_access(&state, &headers, session_id).await?;

    let fni_flow_id: Option<String> = row.get("fni_flow_id");
    let stored_status: Option<String> = row.get("fni_verify_status");
    let wire: Option<String> = row.get("fni_cfni_wire");

    if fni_flow_id.is_none() {
        return Ok(Json(serde_json::json!({
            "capture_id": id,
            "fni_flow_id": null,
            "fni_verify_status": "unverified",
            "reason": "no_fni_flow_id",
            "honesty": "No FNI on capture — verify cannot upgrade status",
        })));
    }

    let (status, reason) = match wire.as_deref() {
        Some(w) if !w.is_empty() => crate::capture::verify_cfni_wire(w),
        _ => ("unverified", Some("no_cfni_wire")),
    };

    sqlx::query("UPDATE witness_captures SET fni_verify_status = $1 WHERE id = $2")
        .bind(status)
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "capture_id": id,
        "fni_flow_id": fni_flow_id,
        "fni_verify_status": status,
        "previous_status": stored_status,
        "reason": reason,
        "honesty": "verified only after independent CFNI recompute with CONNECTOR_CFNI_SECRET",
    })))
}

#[derive(Serialize)]
struct ListSessionsResponse {
    sessions: Vec<SessionStats>,
    total: usize,
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ListSessionsResponse>, AppError> {
    let token = bearer_token(&headers)
        .ok_or_else(|| AppError::Unauthorized("Missing bearer token".to_string()))?;
    let tenant_id = effective_tenant_id_from_headers(&state, &headers, token)?;
    let sessions = state.sessions.list_sessions(100, tenant_id).await?;
    let total = sessions.len();
    Ok(Json(ListSessionsResponse { sessions, total }))
}

async fn seal_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<SealQuery>,
) -> Result<Json<SealResponse>, AppError> {
    enforce_session_access(&state, &headers, id).await?;
    let resp = state.sessions.seal_session(id, query.force_seal.unwrap_or(false)).await?;
    enqueue_webhook_event(
        &state,
        id,
        "session.sealed",
        &serde_json::json!({"session_id": id, "proof_id": resp.proof_id, "cost_usd": resp.cost_usd}),
    )
    .await;
    Ok(Json(resp))
}

async fn lock_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, id).await?;
    enforce_legal_hold_mutation_guard(&state, id, "lock").await?;
    let session = state.sessions.set_session_lock(id, true).await?;
    enqueue_webhook_event(
        &state,
        id,
        "session.locked",
        &serde_json::json!({"session_id": id, "status": session.status.to_string()}),
    )
    .await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "session_id": id,
        "status": session.status.to_string(),
    })))
}

async fn unlock_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, id).await?;
    enforce_legal_hold_mutation_guard(&state, id, "unlock").await?;
    let session = state.sessions.set_session_lock(id, false).await?;
    enqueue_webhook_event(
        &state,
        id,
        "session.unlocked",
        &serde_json::json!({"session_id": id, "status": session.status.to_string()}),
    )
    .await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "session_id": id,
        "status": session.status.to_string(),
    })))
}

#[derive(Deserialize)]
struct QuarantineRequest {
    actor: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct UpdateUpstreamRequest {
    upstream: String,
    actor: Option<String>,
}

async fn quarantine_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<QuarantineRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, id).await?;
    enforce_legal_hold_mutation_guard(&state, id, "quarantine").await?;
    let actor = req.actor.unwrap_or_else(|| "witnessctl-api".to_string());
    let session = state
        .sessions
        .set_session_quarantine(id, true, &actor, req.reason.as_deref())
        .await?;
    let payload = serde_json::json!({
        "session_id": id,
        "status": "quarantined",
        "actor": actor,
        "reason": req.reason,
        "action": "session_quarantine",
    });
    record_reviewer_action(&state, id, None, &actor, "session_quarantine", &payload).await?;
    enqueue_webhook_event(&state, id, "session.quarantined", &payload).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "session_id": id,
        "status": session.status.to_string(),
    })))
}

async fn unquarantine_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<QuarantineRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, id).await?;
    enforce_legal_hold_mutation_guard(&state, id, "unquarantine").await?;
    let actor = req.actor.unwrap_or_else(|| "witnessctl-api".to_string());
    let session = state
        .sessions
        .set_session_quarantine(id, false, &actor, req.reason.as_deref())
        .await?;
    let payload = serde_json::json!({
        "session_id": id,
        "status": "active",
        "actor": actor,
        "reason": req.reason,
        "action": "session_unquarantine",
    });
    record_reviewer_action(&state, id, None, &actor, "session_unquarantine", &payload).await?;
    enqueue_webhook_event(&state, id, "session.unquarantined", &payload).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "session_id": id,
        "status": session.status.to_string(),
    })))
}

async fn update_session_upstream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUpstreamRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, id).await?;
    enforce_legal_hold_mutation_guard(&state, id, "update_upstream").await?;
    let actor = req.actor.unwrap_or_else(|| "witnessctl-api".to_string());
    let session = state.sessions.update_session_upstream(id, &req.upstream).await?;
    let payload = serde_json::json!({
        "session_id": id,
        "upstream": req.upstream,
        "actor": actor,
        "action": "session_update_upstream",
    });
    record_reviewer_action(&state, id, None, &actor, "session_update_upstream", &payload).await?;
    enqueue_webhook_event(&state, id, "session.upstream_updated", &payload).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "session_id": id,
        "upstream": session.upstream,
        "status": session.status.to_string(),
    })))
}

#[derive(Deserialize)]
struct SealQuery {
    force_seal: Option<bool>,
}

// ── Ingest ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IngestRequestWrapper {
    session_id: Uuid,
    request: RawRequest,
    response: Option<RawResponse>,
}

async fn ingest_call(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<IngestRequestWrapper>,
) -> Result<Json<CaptureResponse>, AppError> {
    enforce_session_access(&state, &headers, req.session_id).await?;
    let resp = state.capture.ingest(req.session_id, req.request, req.response).await?;
    Ok(Json(resp))
}

// ── Compliance ─────────────────────────────────────────────────────────────────

async fn get_compliance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    let verdicts = state.compliance.get_verdicts(session_id).await?;
    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "verdicts": verdicts,
        "verdict_count": verdicts.len(),
    })))
}

async fn evaluate_compliance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<crate::compliance::ComplianceReport>, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    let report = state.compliance.evaluate_session(session_id).await?;
    Ok(Json(report))
}

async fn get_compliance_readiness(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    let report = state.compliance.readiness_gate(session_id).await?;
    Ok(Json(report))
}

async fn manual_attest_compliance(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
    Json(req): Json<ManualAttestRequest>,
) -> Result<Json<ManualAttestation>, AppError> {
    if !state.config.is_enterprise_tier() {
        return Err(enterprise_required("manual compliance attestation"));
    }
    let attestation = state.compliance.manual_attest(session_id, req).await?;
    let payload = serde_json::json!({
        "session_id": session_id,
        "control_name": attestation.control_name,
        "attestor": attestation.attestor,
        "attestor_subject": attestation.attestor_subject,
        "action": "manual_attest",
    });
    record_reviewer_action(&state, session_id, None, &attestation.attestor, "manual_attest", &payload).await?;
    Ok(Json(attestation))
}

#[derive(Deserialize)]
struct CreateHitlRequest {
    control_name: String,
    severity: Option<String>,
    primary_reviewer: String,
    secondary_reviewer: Option<String>,
    timeout_minutes: Option<i64>,
    note: Option<String>,
}

#[derive(Deserialize)]
struct ResolveHitlRequest {
    actor: String,
    status: String, // approved | rejected | escalated
    note: Option<String>,
}

async fn list_hitl_queue(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !state.config.is_enterprise_tier() {
        return Err(enterprise_required("HITL approvals"));
    }
    // auto-escalate expired pending items
    let _ = sqlx::query(
        "UPDATE witness_hitl_queue \
         SET status = 'escalated', resolved_at = NOW(), resolution_note = COALESCE(resolution_note,'') || ' [auto-escalated timeout]' \
         WHERE session_id = $1 AND status = 'pending' AND due_at < NOW()"
    )
    .bind(session_id)
    .execute(&state.db)
    .await;

    let rows = sqlx::query(
        "SELECT id, control_name, severity, status, primary_reviewer, secondary_reviewer, due_at, created_at, resolved_at, resolution_note \
         FROM witness_hitl_queue WHERE session_id = $1 ORDER BY created_at DESC"
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "items": rows.iter().map(|r| serde_json::json!({
            "id": r.get::<Uuid, _>("id"),
            "control_name": r.get::<String, _>("control_name"),
            "severity": r.get::<String, _>("severity"),
            "status": r.get::<String, _>("status"),
            "primary_reviewer": r.get::<String, _>("primary_reviewer"),
            "secondary_reviewer": r.get::<Option<String>, _>("secondary_reviewer"),
            "due_at": r.get::<chrono::DateTime<chrono::Utc>, _>("due_at").to_rfc3339(),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            "resolved_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("resolved_at").map(|t| t.to_rfc3339()),
            "resolution_note": r.get::<Option<String>, _>("resolution_note"),
        })).collect::<Vec<_>>(),
    })))
}

async fn create_hitl_item(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
    Json(req): Json<CreateHitlRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !state.config.is_enterprise_tier() {
        return Err(enterprise_required("HITL approvals"));
    }
    let due_at = chrono::Utc::now() + chrono::Duration::minutes(req.timeout_minutes.unwrap_or(30));
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO witness_hitl_queue (session_id, control_name, severity, status, primary_reviewer, secondary_reviewer, due_at, resolution_note) \
         VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7) RETURNING id"
    )
    .bind(session_id)
    .bind(&req.control_name)
    .bind(req.severity.unwrap_or_else(|| "medium".to_string()))
    .bind(&req.primary_reviewer)
    .bind(&req.secondary_reviewer)
    .bind(due_at)
    .bind(req.note.unwrap_or_default())
    .fetch_one(&state.db)
    .await?;

    let payload = serde_json::json!({
        "queue_id": id,
        "control_name": req.control_name,
        "primary_reviewer": req.primary_reviewer,
        "secondary_reviewer": req.secondary_reviewer,
        "due_at": due_at.to_rfc3339(),
        "action": "hitl_create",
    });
    record_reviewer_action(&state, session_id, Some(id), "system", "hitl_create", &payload).await?;
    enqueue_webhook_event(&state, session_id, "hitl.created", &payload).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "id": id,
        "due_at": due_at.to_rfc3339(),
    })))
}

async fn resolve_hitl_item(
    State(state): State<Arc<AppState>>,
    Path((session_id, item_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<ResolveHitlRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !state.config.is_enterprise_tier() {
        return Err(enterprise_required("HITL approvals"));
    }
    if !matches!(req.status.as_str(), "approved" | "rejected" | "escalated") {
        return Err(AppError::BadRequest("status must be approved|rejected|escalated".to_string()));
    }
    let updated = sqlx::query(
        "UPDATE witness_hitl_queue SET status = $1, resolved_at = NOW(), resolution_note = $2 \
         WHERE id = $3 AND session_id = $4"
    )
    .bind(&req.status)
    .bind(req.note.clone().unwrap_or_default())
    .bind(item_id)
    .bind(session_id)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("HITL item {}", item_id)));
    }

    let payload = serde_json::json!({
        "queue_id": item_id,
        "status": req.status,
        "note": req.note,
        "action": "hitl_resolve",
    });
    record_reviewer_action(&state, session_id, Some(item_id), &req.actor, "hitl_resolve", &payload).await?;
    enqueue_webhook_event(&state, session_id, "hitl.resolved", &payload).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn record_reviewer_action(
    state: &Arc<AppState>,
    session_id: Uuid,
    queue_id: Option<Uuid>,
    actor: &str,
    action: &str,
    payload: &serde_json::Value,
) -> Result<(), AppError> {
    let payload_str = serde_json::to_string(payload).unwrap_or_default();
    let payload_hash = sha256::digest(&payload_str);
    let mut mac = Hmac::<Sha256>::new_from_slice(state.config.hmac_secret.as_bytes())
        .map_err(|e| AppError::Internal(format!("hmac init failed: {}", e)))?;
    mac.update(payload_hash.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    sqlx::query(
        "INSERT INTO witness_reviewer_actions (session_id, queue_id, actor, action, payload_hash, signature) \
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(session_id)
    .bind(queue_id)
    .bind(actor)
    .bind(action)
    .bind(payload_hash)
    .bind(signature)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn enqueue_webhook_event(
    state: &Arc<AppState>,
    session_id: Uuid,
    event_type: &str,
    payload: &serde_json::Value,
) {
    let tenant_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT tenant_id FROM witness_sessions WHERE id = $1"
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| Uuid::parse_str(DEFAULT_TENANT_ID).unwrap_or(Uuid::nil()));
    let _ = state
        .webhook
        .enqueue_event(tenant_id, Some(session_id), event_type, payload)
        .await;
}

// ── Proof & Verification ──────────────────────────────────────────────────────

async fn get_proof(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    let session = state.sessions.get_session(session_id).await?;
    let pid = session.agent_pid.ok_or_else(|| AppError::Internal("No agent_pid".to_string()))?;

    // Get Connector proof bundle
    let connector_proof = state.connector.generate_proof(&pid, "witnessctl_session").await.ok();

    // Get local receipt chain
    let receipts = sqlx::query(
        "SELECT event_type, seq, payload, hmac, prev_hmac, created_at \
         FROM witness_receipts WHERE session_id = $1 ORDER BY seq"
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await?;

    let receipt_count = receipts.len();
    let chain_head = session.chain_head_hmac;

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "proof_id": session.proof_id,
        "chain_head_hmac": chain_head,
        "receipt_count": receipt_count,
        "total_calls": session.total_calls,
        "total_blocked": session.total_blocked,
        "total_pii_hits": session.total_pii_hits,
        "sealed_at": session.sealed_at.map(|t| t.to_rfc3339()),
        "connector_proof": connector_proof,
        "receipt_chain": receipts.iter().map(|r| serde_json::json!({
            "seq": r.get::<i64, _>("seq"),
            "event_type": r.get::<String, _>("event_type"),
            "hmac": r.get::<String, _>("hmac"),
            "prev_hmac": r.get::<Option<String>, _>("prev_hmac"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })).collect::<Vec<_>>(),
    })))
}

async fn verify_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    let session = state.sessions.get_session(session_id).await?;

    // Fetch all receipts for this session
    let rows = sqlx::query(
        "SELECT id, session_id, capture_id, event_type, seq, payload, hmac, prev_hmac, created_at \
         FROM witness_receipts WHERE session_id = $1 ORDER BY seq"
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await?;

    let receipts: Vec<Receipt> = rows.iter().map(|r| Receipt {
        id: r.get("id"),
        session_id: r.get("session_id"),
        capture_id: r.get("capture_id"),
        event_type: r.get("event_type"),
        seq: r.get("seq"),
        payload: r.get("payload"),
        hmac: r.get("hmac"),
        prev_hmac: r.get("prev_hmac"),
        created_at: r.get("created_at"),
    }).collect();

    let chain_valid = verify_chain(&receipts, &state.config.hmac_secret);

    // Also verify the chain head matches
    let expected_head = receipts.last().map(|r| r.hmac.clone());
    let head_matches = expected_head.as_ref() == session.chain_head_hmac.as_ref();

    let token = bearer_token(&headers).unwrap_or("");
    let tenant_id = effective_tenant_id_from_headers(&state, &headers, token)
        .ok()
        .map(|t| t.to_string());
    let verification_status = if chain_valid && head_matches {
        connector_trust::custody::CustodyVerificationStatus::Verified
    } else if receipts.is_empty() {
        connector_trust::custody::CustodyVerificationStatus::Incomplete
    } else {
        connector_trust::custody::CustodyVerificationStatus::Failed
    };
    let custody = connector_trust::CustodyReceiptV2 {
        receipt_id: format!("wcust_{session_id}"),
        proof_id: session.proof_id.clone().map(|p| p.to_string()),
        principal_id: token
            .get(..token.len().min(16))
            .unwrap_or("session")
            .to_string(),
        tenant_id,
        event_range_start: receipts.first().map(|r| r.seq.to_string()),
        event_range_end: receipts.last().map(|r| r.seq.to_string()),
        policy_revision: None,
        chain_head: session.chain_head_hmac.clone(),
        signer_key_id: Some("witnessctl-hmac".into()),
        artifact_digests: receipts.iter().take(32).map(|r| r.hmac.clone()).collect(),
        signature_hex: None,
        verification_status,
        contract_version: 2,
    };

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "chain_valid": chain_valid,
        "head_matches": head_matches,
        "receipt_count": receipts.len(),
        "status": session.status.to_string(),
        "sealed": session.status == SessionStatus::Sealed,
        "tamper_detected": !chain_valid || !head_matches,
        "verified_at": chrono::Utc::now().to_rfc3339(),
        "custody_receipt_v2": custody,
    })))
}

// ── Schema History ────────────────────────────────────────────────────────────

async fn get_schemas(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = sqlx::query(
        "SELECT host, path, method, schema_version, request_schema, response_schema, \
         status_codes, drift_log, created_at, updated_at \
         FROM witness_schemas WHERE session_id = $1 ORDER BY host, path"
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "schemas": rows.iter().map(|r| serde_json::json!({
            "host": r.get::<String, _>("host"),
            "path": r.get::<String, _>("path"),
            "method": r.get::<String, _>("method"),
            "schema_version": r.get::<i32, _>("schema_version"),
            "request_schema": r.get::<serde_json::Value, _>("request_schema"),
            "response_schema": r.get::<serde_json::Value, _>("response_schema"),
            "status_codes": r.get::<Vec<i32>, _>("status_codes"),
            "drift_log": r.get::<serde_json::Value, _>("drift_log"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            "updated_at": r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
        })).collect::<Vec<_>>(),
        "schema_count": rows.len(),
    })))
}

// ── PII Report ────────────────────────────────────────────────────────────────

async fn get_pii_report(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Get PII hits from captures
    let captures = sqlx::query(
        "SELECT seq, method, url, host, path, pii_in_request, pii_in_response, \
         admission_verdict, firewall_blocked, created_at \
         FROM witness_captures \
         WHERE session_id = $1 AND (pii_in_request = true OR pii_in_response = true) \
         ORDER BY seq"
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await?;

    // Get PII hits table
    let pii_hits = sqlx::query(
        "SELECT location, field_path, pii_type, action, created_at \
         FROM witness_pii_hits WHERE session_id = $1 ORDER BY created_at"
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await?;

    let total_pii_captures = captures.len();
    let req_pii = captures.iter().filter(|r| r.get::<bool, _>("pii_in_request")).count();
    let resp_pii = captures.iter().filter(|r| r.get::<bool, _>("pii_in_response")).count();
    let blocked = captures.iter().filter(|r| r.get::<bool, _>("firewall_blocked")).count();

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "summary": {
            "total_captures_with_pii": total_pii_captures,
            "pii_in_requests": req_pii,
            "pii_in_responses": resp_pii,
            "blocked_by_firewall": blocked,
            "pii_hit_details": pii_hits.len(),
        },
        "captures_with_pii": captures.iter().map(|r| serde_json::json!({
            "seq": r.get::<i64, _>("seq"),
            "method": r.get::<String, _>("method"),
            "host": r.get::<String, _>("host"),
            "path": r.get::<String, _>("path"),
            "pii_in_request": r.get::<bool, _>("pii_in_request"),
            "pii_in_response": r.get::<bool, _>("pii_in_response"),
            "admission_verdict": r.get::<String, _>("admission_verdict"),
            "firewall_blocked": r.get::<bool, _>("firewall_blocked"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })).collect::<Vec<_>>(),
        "pii_hit_details": pii_hits.iter().map(|r| serde_json::json!({
            "location": r.get::<String, _>("location"),
            "field_path": r.get::<String, _>("field_path"),
            "pii_type": r.get::<String, _>("pii_type"),
            "action": r.get::<String, _>("action"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })).collect::<Vec<_>>(),
    })))
}

// ── Export ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
    include_raw: Option<bool>,
    framework: Option<String>,
    force: Option<bool>,
}

const SUPPORTED_REPORT_FRAMEWORKS: &[&str] = &[
    "soc2",
    "hipaa",
    "gdpr",
    "eu_ai_act",
    "iso_27001",
    "pci_dss",
    "nist_800_53",
];

const SUPPORTED_REPORT_FORMATS: &[&str] = &["pdf", "json", "csv", "markdown", "md"];

fn normalize_report_framework(input: &str) -> String {
    match input.trim().to_ascii_lowercase().as_str() {
        "iso27001" | "iso-27001" => "iso_27001".to_string(),
        other => other.to_string(),
    }
}

fn normalize_report_format(input: &str) -> String {
    match input.trim().to_ascii_lowercase().as_str() {
        "markdown" => "md".to_string(),
        other => other.to_string(),
    }
}

fn ensure_supported_report_framework(framework: &str) -> Result<(), AppError> {
    if SUPPORTED_REPORT_FRAMEWORKS
        .iter()
        .any(|f| f.eq_ignore_ascii_case(framework))
    {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "Unsupported report framework '{}'. Supported: {}",
            framework,
            SUPPORTED_REPORT_FRAMEWORKS.join(", ")
        )))
    }
}

fn ensure_supported_report_format(format: &str) -> Result<(), AppError> {
    if SUPPORTED_REPORT_FORMATS
        .iter()
        .any(|f| f.eq_ignore_ascii_case(format))
    {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "Unsupported report format '{}'. Supported: {}",
            format,
            SUPPORTED_REPORT_FORMATS.join(", ")
        )))
    }
}

async fn export_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Query(query): Query<ExportQuery>,
) -> Result<impl IntoResponse, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    enforce_export_rate_limit(&state, &headers).await?;

    let format = query.format.unwrap_or_else(|| "json".to_string());
    let include_raw = query.include_raw.unwrap_or(false);
    if query.framework.is_some() {
        let _ = state.compliance.evaluate_session(session_id).await?;
    }

    let result = state.export_engine.export_session(session_id, &format, include_raw).await?;

    Ok((
        [
            ("content-type", result.content_type),
            ("content-disposition", format!("attachment; filename=\"{}\"", result.filename)),
        ],
        axum::body::Bytes::from(result.body),
    ))
}

async fn report_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Query(query): Query<ExportQuery>,
) -> Result<impl IntoResponse, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    enforce_custody_export_guard(&state, session_id, query.force.unwrap_or(false)).await?;
    let framework = normalize_report_framework(query.framework.as_deref().unwrap_or("soc2"));
    ensure_supported_report_framework(&framework)?;
    if framework.eq_ignore_ascii_case("gdpr") && !state.config.is_enterprise_tier() {
        return Err(enterprise_required("GDPR export"));
    }
    let _ = state.compliance.evaluate_session(session_id).await?;
    let format = normalize_report_format(query.format.as_deref().unwrap_or("pdf"));
    ensure_supported_report_format(&format)?;
    let result = state.export_engine.export_session(session_id, &format, false).await?;
    let framework_filename = format!("{}-{}", framework, result.filename);
    Ok((
        [
            ("content-type", result.content_type),
            ("content-disposition", format!("attachment; filename=\"{}\"", framework_filename)),
        ],
        axum::body::Bytes::from(result.body),
    ))
}

#[derive(Deserialize)]
struct BatchReportQuery {
    frameworks: Option<String>,
    format: Option<String>,
    force: Option<bool>,
}

async fn report_batch_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Query(query): Query<BatchReportQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    enforce_export_rate_limit(&state, &headers).await?;
    enforce_custody_export_guard(&state, session_id, query.force.unwrap_or(false)).await?;
    let mut frameworks = query
        .frameworks
        .unwrap_or_else(|| "soc2,hipaa,gdpr,eu_ai_act,iso_27001,pci_dss,nist_800_53".to_string())
        .split(',')
        .map(normalize_report_framework)
        .filter(|f| !f.is_empty())
        .collect::<Vec<_>>();
    if frameworks.is_empty() {
        return Err(AppError::BadRequest(
            "At least one framework is required".to_string(),
        ));
    }
    frameworks.sort();
    frameworks.dedup();
    for fw in &frameworks {
        ensure_supported_report_framework(fw)?;
    }
    if !state.config.is_enterprise_tier()
        && frameworks.iter().any(|f| f.eq_ignore_ascii_case("gdpr"))
    {
        return Err(enterprise_required("GDPR export"));
    }
    let format = normalize_report_format(query.format.as_deref().unwrap_or("pdf"));
    ensure_supported_report_format(&format)?;
    let _ = state.compliance.evaluate_session(session_id).await?;
    let shared_export = state.export_engine.export_session(session_id, &format, false).await?;
    let shared_hash = sha256::digest(&shared_export.body);

    let mut reports = Vec::new();
    for fw in frameworks {
        reports.push(serde_json::json!({
            "framework": fw,
            "filename": shared_export.filename.clone(),
            "format": format,
            "sha256": shared_hash,
            "shared_artifact": true,
        }));
    }

    let manifest = serde_json::json!({
        "session_id": session_id,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "framework_count": reports.len(),
        "shared_artifact": true,
        "shared_artifact_filename": shared_export.filename,
        "shared_artifact_sha256": shared_hash,
        "reports": reports,
        "custody_manifest_hash": sha256::digest(serde_json::to_vec(&reports).unwrap_or_default()),
    });
    Ok(Json(manifest))
}

async fn custody_replicate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<crate::custody_node::ReplicateRequest>,
) -> Result<Json<crate::custody_node::ReplicateResponse>, AppError> {
    let expected = std::env::var("WITNESSCTL_CUSTODY_NODE_SECRET")
        .or_else(|_| std::env::var("WITNESSCTL_HMAC_SECRET"))
        .map_err(|_| AppError::Internal("custody secret not configured".to_string()))?;
    let provided = headers
        .get("x-witnessctl-custody-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != expected {
        return Err(AppError::Unauthorized("invalid custody secret".to_string()));
    }
    let node_id =
        std::env::var("WITNESSCTL_CUSTODY_NODE_ID").unwrap_or_else(|_| "witnessctl-primary".to_string());
    let resp = custody::handle_replicate_request(&expected, &node_id, &body)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if let Ok(session_id) = Uuid::parse_str(&body.session_id) {
        let _ = custody::store_custody_proof(&state.db, session_id, &resp.proof).await;
    }
    Ok(Json(resp))
}

async fn get_custody_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    enforce_session_access(&state, &headers, session_id).await?;
    let status = custody::custody_status(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(status))
}

async fn get_popeye_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = bearer_token(&headers)
        .ok_or_else(|| AppError::Unauthorized("Missing bearer token".to_string()))?;
    let tenant_id = effective_tenant_id(&state, token)?;

    let unsealed_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(1) FROM witness_sessions WHERE tenant_id = $1 AND status::text != 'sealed'"
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let stale_hitl_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(1) FROM witness_hitl_queue q \
         JOIN witness_sessions s ON s.id = q.session_id \
         WHERE s.tenant_id = $1 AND q.status = 'pending' AND q.due_at < NOW()"
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let pii_leak_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(1) FROM witness_captures c \
         JOIN witness_sessions s ON s.id = c.session_id \
         WHERE s.tenant_id = $1 AND c.pii_in_response = true"
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let custody_failed_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(1) FROM witness_sessions s \
         WHERE s.tenant_id = $1 \
         AND EXISTS ( \
            SELECT 1 FROM witness_custody_checkpoints c \
            WHERE c.session_id = s.id \
            ORDER BY c.created_at DESC \
            LIMIT 1 \
         ) \
         AND COALESCE(( \
            SELECT c2.failed_count FROM witness_custody_checkpoints c2 \
            WHERE c2.session_id = s.id ORDER BY c2.created_at DESC LIMIT 1 \
         ), 0) > 0"
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let chain_suspect_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(1) FROM witness_sessions s \
         WHERE s.tenant_id = $1 \
         AND COALESCE(s.chain_head_hmac, '') <> COALESCE(( \
             SELECT r.hmac FROM witness_receipts r \
             WHERE r.session_id = s.id ORDER BY r.seq DESC LIMIT 1 \
         ), '')"
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let risk_score = (chain_suspect_count * 25
        + unsealed_count * 15
        + stale_hitl_count * 20
        + pii_leak_count * 25
        + custody_failed_count * 15)
        .min(1000);
    let severity = if risk_score >= 300 {
        "critical"
    } else if risk_score >= 150 {
        "high"
    } else if risk_score > 0 {
        "elevated"
    } else {
        "clean"
    };

    Ok(Json(serde_json::json!({
        "tenant_id": tenant_id,
        "risk_score": risk_score,
        "severity": severity,
        "findings": {
            "broken_chain_sessions": chain_suspect_count,
            "unsealed_sessions": unsealed_count,
            "stale_hitl_items": stale_hitl_count,
            "pii_response_leaks": pii_leak_count,
            "custody_failure_sessions": custody_failed_count
        },
        "generated_at": chrono::Utc::now().to_rfc3339()
    })))
}

async fn enforce_export_rate_limit(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let now = chrono::Utc::now().timestamp();
    let cutoff = now - 3600;
    let mut limiter = state.export_rate_limit.lock().await;
    let timestamps = limiter.entry(ip).or_default();
    timestamps.retain(|ts| *ts >= cutoff);
    if timestamps.len() >= 10 {
        return Err(AppError::TooManyRequests(
            "Rate limit exceeded for export endpoint (10 requests/hour per IP)".to_string(),
        ));
    }
    timestamps.push(now);
    Ok(())
}

async fn enforce_custody_export_guard(
    state: &Arc<AppState>,
    session_id: Uuid,
    force: bool,
) -> Result<(), AppError> {
    let status = custody::custody_status(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let failed = status
        .get("failed_count")
        .and_then(|v| v.as_i64())
        .or_else(|| status.get("failed").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    if failed > 0 && !force {
        return Err(AppError::BadRequest(
            "CUSTODY_DEGRADED_EXPORT_BLOCK|Custody is degraded for this session; retry with force=true to export anyway"
                .to_string(),
        ));
    }
    Ok(())
}

async fn enforce_legal_hold_mutation_guard(
    state: &Arc<AppState>,
    session_id: Uuid,
    action: &str,
) -> Result<(), AppError> {
    if !state.config.legal_hold_enforced {
        return Ok(());
    }
    let held = custody::is_legal_hold(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if held {
        return Err(AppError::BadRequest(format!(
            "LEGAL_HOLD_ACTIVE|Session is under legal hold; action '{}' is blocked",
            action
        )));
    }
    Ok(())
}

async fn enforce_session_access(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    session_id: Uuid,
) -> Result<(), AppError> {
    let token = bearer_token(headers)
        .ok_or_else(|| AppError::Unauthorized("Missing bearer token".to_string()))?;
    let admin_token = std::env::var("WITNESSCTL_ADMIN_TOKEN").ok();
    let is_admin = admin_token
        .as_deref()
        .map(|t| !t.trim().is_empty() && t == token)
        .unwrap_or(false);
    if is_admin {
        return Ok(());
    }
    let tenant_id = effective_tenant_id_from_headers(state, headers, token)?;

    let matches_session = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(1) FROM witness_sessions WHERE id = $1 AND session_token = $2 AND tenant_id = $3"
    )
    .bind(session_id)
    .bind(token)
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .map(|count| count > 0)
    .unwrap_or(false);

    if !matches_session {
        return Err(AppError::Unauthorized(
            "Bearer token does not match requested session".to_string(),
        ));
    }

    Ok(())
}

// ── Proxy (reverse proxy mode) ────────────────────────────────────────────────

async fn proxy_forward(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: String,
) -> Result<Json<CaptureResponse>, AppError> {
    enforce_connector_unlock(&state).await?;
    let token = headers.get("x-witness-session")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("X-Witness-Session header required".to_string()))?;

    let session = state
        .sessions
        .get_session_by_token(token, effective_tenant_id(&state, token)?)
        .await?;

    if session.status == SessionStatus::Sealed {
        return Err(AppError::SessionSealed);
    }
    if session.status == SessionStatus::Locked {
        return Err(AppError::AdmissionDenied(
            "Session is locked; unlock before proxying requests".to_string(),
        ));
    }
    if session.status == SessionStatus::Quarantined {
        return Err(AppError::AdmissionDenied(
            "Session is quarantined; release quarantine before proxying requests".to_string(),
        ));
    }

    if headers.contains_key("x-original-method") || headers.contains_key("x-original-path") {
        return Err(AppError::BadRequest(
            "x-original-* headers are not accepted on /witness proxy requests".to_string(),
        ));
    }
    let method = method.as_str();

    if state.config.cage_mode || state.config.strict_mode {
        let method_upper = method.to_uppercase();
        if !state.config.method_allowlist.iter().any(|m| m == &method_upper) {
            return Err(AppError::FirewallBlocked(format!(
                "cage strict mode: method {} not allowed",
                method_upper
            )));
        }
        let req_path = format!("/{}", path);
        if req_path.starts_with("//") || req_path.contains('\\') {
            return Err(AppError::FirewallBlocked(format!(
                "cage strict mode: malformed path {}",
                req_path
            )));
        }
        if !state
            .config
            .path_prefix_allowlist
            .iter()
            .any(|prefix| req_path.starts_with(prefix))
        {
            return Err(AppError::FirewallBlocked(format!(
                "cage strict mode: path {} not allowed (allowlist={:?}; typical fix: /,/v1 or WITNESSCTL_CAGE_MODE=0)",
                req_path,
                state.config.path_prefix_allowlist
            )));
        }
        if let Ok(upstream) = reqwest::Url::parse(&session.upstream) {
            let host = upstream.host_str().unwrap_or_default().to_lowercase();
            if !state.config.route_allowlist.is_empty()
                && !state.config.route_allowlist.iter().any(|h| h == &host)
            {
                return Err(AppError::FirewallBlocked(format!(
                    "cage strict mode: upstream host {} not in route allowlist",
                    host
                )));
            }
            if state.config.route_profile == "vps-prod" && upstream.scheme() != "https" {
                return Err(AppError::FirewallBlocked(
                    "cage strict mode: vps-prod route profile requires https upstream".to_string(),
                ));
            }
        }
    }

    // Collect forwarded headers
    let mut fwd_headers = std::collections::HashMap::new();
    for (key, value) in headers.iter() {
        let k = key.as_str().to_string();
        if !k.starts_with("x-witness") && !k.starts_with("x-original") {
            if let Ok(v) = value.to_str() {
                fwd_headers.insert(k, v.to_string());
            }
        }
    }

    let body_opt = if body.is_empty() { None } else { Some(body.as_str()) };

    let result = state.proxy_engine.proxy_and_capture(
        &session,
        &state.capture,
        method,
        &format!("/{}", path),
        &fwd_headers,
        body_opt,
    ).await?;

    Ok(Json(result))
}

// ── Decision Pentest ──────────────────────────────────────────────────────────

/// Assemble a DecisionPentestReport for a single trace_id.
/// Tries to pull data from the cache first; regenerates from Connector OS on a miss.
async fn assemble_pentest_report(
    state: &Arc<AppState>,
    session_id: Uuid,
    trace_id: &str,
) -> Result<DecisionPentestReport, AppError> {
    // Check cache first
    let cached = sqlx::query(
        "SELECT report_json FROM witness_decision_pentest_cache \
         WHERE session_id = $1 AND trace_id = $2",
    )
    .bind(session_id)
    .bind(trace_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::DatabaseError)?;

    if let Some(row) = cached {
        let report_json: serde_json::Value = row.get("report_json");
        if let Ok(report) = serde_json::from_value::<DecisionPentestReport>(report_json) {
            return Ok(report);
        }
    }

    // Resolve capture_id and agent_pid from session context
    let capture_row = sqlx::query(
        "SELECT id, seq, host, path FROM witness_captures \
         WHERE session_id = $1 \
         AND (request_hash LIKE $2 OR id::text = $2) \
         LIMIT 1",
    )
    .bind(session_id)
    .bind(format!("%{}%", &trace_id[..trace_id.len().min(8)]))
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::DatabaseError)?;
    let capture_id: Option<Uuid> = capture_row.as_ref().map(|r| r.get("id"));

    let session_row = sqlx::query(
        "SELECT agent_pid FROM witness_sessions WHERE id = $1",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::DatabaseError)?;
    let agent_pid: Option<String> = session_row.and_then(|r| r.try_get("agent_pid").ok()).flatten();

    // Fetch from Connector OS (all three calls in parallel)
    let (pentest_val, token_val, stability_val) = tokio::join!(
        state.connector.get_decision_pentest(trace_id, agent_pid.as_deref()),
        state.connector.get_tokenization_trace(trace_id),
        state.connector.get_decision_stability(trace_id),
    );

    let pentest_val = pentest_val.unwrap_or_else(|_| serde_json::json!({}));
    let token_val = token_val.unwrap_or_else(|_| serde_json::json!({}));
    let stability_val = stability_val.unwrap_or_else(|_| serde_json::json!({}));

    let connector_available = pentest_val
        .get("connector_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Parse dehallucination chain
    let dehallucination_chain: Vec<DehallucinationChainStep> = pentest_val
        .get("dehallucination_chain")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let dehallucination_heatmap: Vec<HeatmapBin> = dehallucination_chain
        .iter()
        .map(|s| HeatmapBin {
            label: s.phase.clone(),
            value: s.risk_score,
            flagged: s.flagged,
        })
        .collect();

    // Parse knot diversion
    let knot_score = pentest_val
        .get("knot_score")
        .or_else(|| pentest_val.get("knot_diversion").and_then(|v| v.get("score")))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let knot_diverted = pentest_val
        .get("knot_diverted")
        .or_else(|| pentest_val.get("knot_diversion").and_then(|v| v.get("diverted")))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let knot_factors: Vec<String> = pentest_val
        .get("knot_diversion")
        .and_then(|v| v.get("factors"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let knot_heatmap: Vec<HeatmapBin> = pentest_val
        .get("knot_diversion")
        .and_then(|v| v.get("heatmap"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| {
            // Synthesize a single-bin heatmap from the score
            vec![HeatmapBin {
                label: "overall".to_string(),
                value: knot_score,
                flagged: knot_diverted,
            }]
        });

    let knot_diversion = KnotDiversionReport {
        score: knot_score,
        confidence: pentest_val
            .get("knot_diversion")
            .and_then(|v| v.get("confidence"))
            .and_then(|v| v.as_f64()),
        diverted: knot_diverted,
        factors: knot_factors,
        heatmap: knot_heatmap,
    };

    // Parse PII components
    let pii_components: Vec<PiiDecisionComponent> = pentest_val
        .get("pii_components")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Parse tokenization trace
    let tokenization_trace: Vec<TokenizationTraceStep> = token_val
        .get("steps")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Parse pentest graph
    let pentest_graph: DecisionPentestMiniGraph = pentest_val
        .get("pentest_graph")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| DecisionPentestMiniGraph {
            nodes: vec![],
            edges: vec![],
        });

    // Stability verdict
    let stability_verdict = stability_val
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Compute payload hash over combined connector payloads for audit integrity
    let combined = serde_json::json!({
        "pentest": &pentest_val,
        "tokenization": &token_val,
        "stability": &stability_val,
    });
    let combined_bytes = serde_json::to_vec(&combined).unwrap_or_default();
    let payload_hash = format!("{:x}", Sha256::digest(&combined_bytes));

    let report = DecisionPentestReport {
        session_id,
        trace_id: trace_id.to_string(),
        request_id: pentest_val
            .get("request_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        capture_id,
        dehallucination_chain: dehallucination_chain.clone(),
        dehallucination_heatmap,
        knot_diversion,
        pii_components: pii_components.clone(),
        tokenization_trace: tokenization_trace.clone(),
        pentest_graph,
        stability_verdict: stability_verdict.clone(),
        payload_hash: payload_hash.clone(),
        connector_available,
        generated_at: chrono::Utc::now(),
    };

    // Upsert into cache
    let report_json = serde_json::to_value(&report).unwrap_or(serde_json::json!({}));
    let _ = sqlx::query(
        "INSERT INTO witness_decision_pentest_cache \
            (session_id, trace_id, request_id, capture_id, \
             dehallucination_step_count, dehallucination_flagged, \
             knot_score, knot_diverted, pii_component_count, tokenization_count, \
             stability_verdict, payload_hash, connector_available, report_json) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) \
         ON CONFLICT (session_id, trace_id) DO UPDATE SET \
             report_json = EXCLUDED.report_json, \
             dehallucination_step_count = EXCLUDED.dehallucination_step_count, \
             dehallucination_flagged = EXCLUDED.dehallucination_flagged, \
             knot_score = EXCLUDED.knot_score, \
             knot_diverted = EXCLUDED.knot_diverted, \
             pii_component_count = EXCLUDED.pii_component_count, \
             tokenization_count = EXCLUDED.tokenization_count, \
             stability_verdict = EXCLUDED.stability_verdict, \
             payload_hash = EXCLUDED.payload_hash, \
             connector_available = EXCLUDED.connector_available, \
             generated_at = NOW()",
    )
    .bind(session_id)
    .bind(trace_id)
    .bind(&report.request_id)
    .bind(capture_id)
    .bind(dehallucination_chain.len() as i32)
    .bind(dehallucination_chain.iter().any(|s| s.flagged))
    .bind(report.knot_diversion.score)
    .bind(report.knot_diversion.diverted)
    .bind(pii_components.len() as i32)
    .bind(tokenization_trace.len() as i32)
    .bind(&stability_verdict)
    .bind(&payload_hash)
    .bind(connector_available)
    .bind(&report_json)
    .execute(&state.db)
    .await;

    Ok(report)
}

/// GET /api/v1/pentest/:session_id/decisions
/// Returns a list of DecisionPentestSummary for all cached pentest reports in the session.
async fn list_decision_pentests(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = sqlx::query(
        "SELECT trace_id, capture_id, \
                dehallucination_step_count, dehallucination_flagged, \
                knot_score, knot_diverted, pii_component_count, tokenization_count, \
                stability_verdict, connector_available, generated_at \
         FROM witness_decision_pentest_cache \
         WHERE session_id = $1 \
         ORDER BY generated_at DESC",
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::DatabaseError)?;

    // Also pull captures that have a linked trace_id from tracetramp integration
    let trace_rows = sqlx::query(
        "SELECT c.id AS capture_id, c.seq, c.host, c.path, ti.trace_id \
         FROM witness_captures c \
         JOIN witness_tracetramp_integration ti ON ti.capture_id = c.id \
         WHERE c.session_id = $1 \
         AND NOT EXISTS ( \
             SELECT 1 FROM witness_decision_pentest_cache p \
             WHERE p.session_id = $1 AND p.trace_id = ti.trace_id \
         ) \
         ORDER BY c.seq DESC \
         LIMIT 50",
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut summaries: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "trace_id": r.get::<String, _>("trace_id"),
                "capture_id": r.get::<Option<Uuid>, _>("capture_id"),
                "dehallucination_step_count": r.get::<i32, _>("dehallucination_step_count"),
                "dehallucination_chain_flagged": r.get::<bool, _>("dehallucination_flagged"),
                "knot_score": r.get::<f64, _>("knot_score"),
                "knot_diverted": r.get::<bool, _>("knot_diverted"),
                "pii_component_count": r.get::<i32, _>("pii_component_count"),
                "tokenization_count": r.get::<i32, _>("tokenization_count"),
                "stability_verdict": r.get::<String, _>("stability_verdict"),
                "connector_available": r.get::<bool, _>("connector_available"),
                "generated_at": r.get::<chrono::DateTime<chrono::Utc>, _>("generated_at"),
                "cached": true,
            })
        })
        .collect();

    // Append uncached decisions as stubs (will be fetched on click)
    for r in &trace_rows {
        summaries.push(serde_json::json!({
            "trace_id": r.get::<String, _>("trace_id"),
            "capture_id": r.get::<Option<Uuid>, _>("capture_id"),
            "dehallucination_step_count": 0,
            "dehallucination_chain_flagged": false,
            "knot_score": 0.0,
            "knot_diverted": false,
            "pii_component_count": 0,
            "tokenization_count": 0,
            "stability_verdict": "pending",
            "connector_available": null,
            "generated_at": null,
            "cached": false,
        }));
    }

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "count": summaries.len(),
        "decisions": summaries,
    })))
}

/// GET /api/v1/pentest/:session_id/decisions/:trace_id
/// Returns a full DecisionPentestReport (fetched from Connector OS if not cached).
async fn get_decision_pentest(
    State(state): State<Arc<AppState>>,
    Path((session_id, trace_id)): Path<(Uuid, String)>,
) -> Result<Json<DecisionPentestReport>, AppError> {
    let report = assemble_pentest_report(&state, session_id, &trace_id).await?;
    Ok(Json(report))
}
