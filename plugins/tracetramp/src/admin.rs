//! Management Plane
//!
//! Admin API for tenants, providers, RBAC, budgets, policies, logging, compliance

use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    middleware::from_fn,
    response::IntoResponse,
    routing::{get, post, put, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::{info, debug, warn};

use crate::{
    AppState,
    error::AppError,
    auth::{require_admin, AuthContext},
};

/// Create the Management Plane router.
/// `/health` stays public; all `/admin/*` routes require [`require_admin`].
pub fn create_router(state: AppState) -> Router {
    let admin = Router::new()
        .route("/admin/dashboard", get(admin_dashboard))
        .route("/admin/stats", get(admin_stats))
        // Tenant management
        .route("/admin/tenants", get(list_tenants).post(create_tenant))
        .route("/admin/tenants/:id", get(get_tenant).put(update_tenant).delete(delete_tenant))
        .route(
            "/admin/tenants/:tenant_id/api-keys",
            post(create_tenant_api_key),
        )
        // Provider configuration
        .route("/admin/providers", get(list_providers).post(create_provider))
        .route("/admin/providers/:id", get(get_provider).put(update_provider))
        // RBAC
        .route("/admin/rbac/roles", get(list_roles).post(create_role))
        .route("/admin/rbac/users", get(list_users).post(create_user))
        .route("/admin/rbac/users/:id/roles", put(assign_role))
        // Budgets
        .route("/admin/budgets", get(list_budgets).post(create_budget))
        .route("/admin/budgets/:id", get(get_budget).put(update_budget))
        // Traces
        .route("/admin/traces", get(list_traces))
        .route("/admin/traces/:trace_id/fni-verify", get(fni_verify_trace))
        .route("/admin/moments/:agent_vid", get(list_moments_forensics))
        .route("/admin/moments/proof/:moment_id", get(get_moment_proof_view))
        .route(
            "/admin/rollup/:agent_vid/explain/:evidence_id",
            get(rollup_explain_view),
        )
        // Policies
        .route("/admin/policies", get(list_policies).post(create_policy))
        .route("/admin/policies/:id", get(get_policy).put(update_policy))
        // Approvals
        .route("/admin/approvals", get(list_approvals))
        .route("/admin/approvals/:id/approve", post(approve_request))
        .route("/admin/approvals/:id/reject", post(reject_request))
        .route("/admin/approvals/:id/quarantine", post(quarantine_request))
        .route("/admin/approvals/:id/execute", post(execute_approved_request))
        .route("/admin/approvals/:id/result", get(get_approval_result))
        // Quarantine and operation-scoped blocks (data-plane enforced)
        .route("/admin/quarantine", get(list_quarantines).post(create_quarantine))
        .route("/admin/quarantine/release", post(release_quarantine))
        .route("/admin/quarantine/all", get(list_all_quarantines))
        .route("/admin/operation-blocks", get(list_operation_blocks).post(create_operation_block))
        .route("/admin/operation-blocks/release", post(release_operation_block))
        // Logging destinations
        .route("/admin/logging/destinations", get(list_log_destinations).post(create_log_destination))
        // Compliance
        .route("/admin/compliance/exports", get(list_compliance_exports).post(create_compliance_export))
        .route_layer(from_fn(require_admin));

    Router::new()
        .route("/health", get(health_check))
        .merge(admin)
        .with_state(Arc::new(state))
}

/// Minimal operator dashboard (replaces removed TUI for production deployments).
async fn admin_dashboard() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../admin-ui/dashboard.html"),
    )
}

/// Health check for management plane
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "tracetramp-management-plane",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn admin_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "active_calls": state.active_calls.load(Ordering::Relaxed),
        "service": "tracetramp-management-plane",
    }))
}

// Traces

#[derive(Deserialize)]
struct TraceQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    tenant_id: Option<String>,
    result: Option<String>,
}

async fn list_traces(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TraceQuery>,
) -> Result<impl IntoResponse, AppError> {
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);

    // Filter by tenant_id if provided (multi-tenant isolation)
    let rows = if let Some(ref tid) = q.tenant_id {
        sqlx::query(
            "SELECT trace_id, request_id, event_type, step, result, metadata, created_at \
             FROM trace_events \
             WHERE metadata->>'tenant_id' = $1 \
             ORDER BY created_at DESC \
             LIMIT $2 OFFSET $3",
        )
        .bind(tid)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    } else {
        sqlx::query(
            "SELECT trace_id, request_id, event_type, step, result, metadata, created_at \
             FROM trace_events \
             ORDER BY created_at DESC \
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    };

    let total: i64 = if let Some(ref tid) = q.tenant_id {
        sqlx::query_scalar("SELECT COUNT(*) FROM trace_events WHERE metadata->>'tenant_id' = $1")
            .bind(tid)
            .fetch_one(&state.db_pool)
            .await
            .unwrap_or(0)
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM trace_events")
            .fetch_one(&state.db_pool)
            .await
            .unwrap_or(0)
    };

    let traces: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let metadata: serde_json::Value = r
                .try_get::<serde_json::Value, _>("metadata")
                .unwrap_or(serde_json::Value::Null);
            let decision = metadata
                .get("decision")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let pii_detected = metadata
                .get("pii_in_request")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            serde_json::json!({
                "trace_id":   r.get::<String, _>("trace_id"),
                "request_id": r.get::<String, _>("request_id"),
                "event_type": r.get::<String, _>("event_type"),
                "step":       r.get::<String, _>("step"),
                "result":     r.get::<String, _>("result"),
                "decision":   decision,
                "pii_detected": pii_detected,
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "traces": traces,
        "count": traces.len(),
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// `GET /admin/moments/:agent_vid` — Connector MomentProof index with P0–P3 symbols.
async fn list_moments_forensics(
    State(state): State<Arc<AppState>>,
    Path(agent_vid): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let v = state.connector_client.list_agent_moments(&agent_vid).await?;
    let moments = v
        .pointer("/data/moments")
        .or_else(|| v.get("moments"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let legend = v
        .pointer("/data/legend")
        .or_else(|| v.get("legend"))
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "P0_full": "●",
                "P1_distilled": "◉",
                "P2_contextual": "○",
                "P3_commitment": "·",
            })
        });
    Ok(Json(serde_json::json!({
        "schema": "tracetramp.moments.index.v1",
        "agent_vid": agent_vid,
        "moments": moments,
        "legend": legend,
        "honesty": "Proof symbols reflect current fade state — not original capture fidelity",
    })))
}

/// `GET /admin/moments/proof/:moment_id` — full MomentProof + TraceTramp display.
async fn get_moment_proof_view(
    State(state): State<Arc<AppState>>,
    Path(moment_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let v = state.connector_client.get_moment_proof(&moment_id).await?;
    let tracetramp = v
        .pointer("/data/tracetramp")
        .or_else(|| v.get("tracetramp"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let moment = v
        .pointer("/data/moment")
        .or_else(|| v.get("moment"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(Json(serde_json::json!({
        "schema": "tracetramp.moment.proof.v1",
        "moment_id": moment_id,
        "moment": moment,
        "tracetramp": tracetramp,
        "display": {
            "title": format!(
                "TRACE MOMENT {}",
                moment
                    .get("moment_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&moment_id)
            ),
            "evidence_resolution": tracetramp.get("proof_level"),
            "proof_symbol": tracetramp.get("proof_symbol"),
            "original_raw": tracetramp.get("original_raw"),
            "decision_reconstruction": tracetramp.get("decision_reconstruction"),
            "exact_original_pages": tracetramp.get("exact_original_pages"),
            "causal_skeleton": tracetramp.get("causal_skeleton"),
            "rollup_honesty": tracetramp.get("rollup_honesty"),
            "svf_honesty": tracetramp.get("svf_honesty"),
        },
        "honesty": [
            "Proof symbols reflect current fade state — not original capture fidelity",
            "SVF: disclosure (EXPAND) ≠ materialize (CDP) — S5 never on model plane",
        ],
    })))
}

/// `GET /admin/rollup/:agent_vid/explain/:evidence_id` — why evidence faded / locked.
async fn rollup_explain_view(
    State(state): State<Arc<AppState>>,
    Path((agent_vid, evidence_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let v = state
        .connector_client
        .get_rollup_explain(&agent_vid, &evidence_id)
        .await?;
    let explain = v
        .pointer("/data/explain")
        .or_else(|| v.get("explain"))
        .cloned()
        .unwrap_or(v.clone());
    Ok(Json(serde_json::json!({
        "schema": "tracetramp.rollup.explain.v1",
        "agent_vid": agent_vid,
        "evidence_id": evidence_id,
        "explain": explain,
    })))
}

/// `GET /admin/traces/:trace_id/fni-verify` — CFNI verify from RequestReceived metadata (P6.4).
async fn fni_verify_trace(
    State(state): State<Arc<AppState>>,
    Path(trace_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // step is Debug-formatted (`RequestReceived`) at insert time in control::record_event.
    let row = sqlx::query(
        "SELECT metadata FROM trace_events \
         WHERE trace_id = $1 AND step = 'RequestReceived' \
         ORDER BY created_at ASC LIMIT 1",
    )
    .bind(&trace_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(row) = row else {
        return Ok(Json(serde_json::json!({
            "trace_id": trace_id,
            "fni_flow_id": null,
            "fni_verify_status": "unverified",
            "reason": "no_request_received_event",
            "honesty": "No FNI metadata on trace — verify cannot upgrade status",
        })));
    };

    let metadata: serde_json::Value = row
        .try_get::<serde_json::Value, _>("metadata")
        .unwrap_or(serde_json::json!({}));
    let fni_flow_id = metadata
        .get("fni_flow_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let previous = metadata
        .get("fni_verify_status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let wire = metadata
        .get("fni_cfni_wire")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if fni_flow_id.is_none() {
        return Ok(Json(serde_json::json!({
            "trace_id": trace_id,
            "fni_flow_id": null,
            "fni_verify_status": "unverified",
            "reason": "no_fni_flow_id",
            "honesty": "No FNI on trace — verify cannot upgrade status",
        })));
    }

    let (status, reason) = match wire.as_deref() {
        Some(w) if !w.is_empty() => crate::control::verify_cfni_wire(w),
        _ => ("unverified", Some("no_cfni_wire")),
    };

    let _ = sqlx::query(
        "UPDATE trace_events SET metadata = metadata || $1::jsonb \
         WHERE trace_id = $2 AND step = 'RequestReceived'",
    )
    .bind(serde_json::json!({ "fni_verify_status": status }))
    .bind(&trace_id)
    .execute(&state.db_pool)
    .await;

    Ok(Json(serde_json::json!({
        "trace_id": trace_id,
        "fni_flow_id": fni_flow_id,
        "fni_verify_status": status,
        "previous_status": previous,
        "reason": reason,
        "honesty": "verified only after independent CFNI recompute with CONNECTOR_CFNI_SECRET",
    })))
}

// Tenant management handlers

async fn list_tenants(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let tenants = sqlx::query_as::<_, TenantRow>(
        "SELECT id, name, environment, default_mode, created_at FROM tenants ORDER BY created_at DESC"
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "tenants": tenants,
        "count": tenants.len(),
    })))
}

#[derive(Deserialize)]
struct CreateTenantRequest {
    name: String,
    environment: String,
    default_mode: String,
}

async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, environment, default_mode, policy_bundle, budget_tier, providers, created_at)
        VALUES ($1, $2, $3, $4, 'default', 'standard', ARRAY['openai'], NOW())
        "#
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.environment)
    .bind(&req.default_mode)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Created tenant: {} ({})", id, req.name);
    
    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "name": req.name,
        "message": "Tenant created successfully",
    }))))
}

async fn get_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let tenant = sqlx::query_as::<_, TenantRow>(
        "SELECT id, name, environment, default_mode, created_at FROM tenants WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    match tenant {
        Some(t) => Ok(Json(t)),
        None => Err(AppError::NotFound(format!("Tenant {} not found", id))),
    }
}

#[derive(Deserialize)]
struct UpdateTenantRequest {
    name: Option<String>,
    default_mode: Option<String>,
    policy_bundle: Option<String>,
}

async fn update_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Build dynamic query based on provided fields
    let mut updates = vec![];
    
    if let Some(name) = req.name {
        updates.push(format!("name = '{}'", name));
    }
    if let Some(mode) = req.default_mode {
        updates.push(format!("default_mode = '{}'", mode));
    }
    if let Some(bundle) = req.policy_bundle {
        updates.push(format!("policy_bundle = '{}'", bundle));
    }
    
    if updates.is_empty() {
        return Err(AppError::Validation("No fields to update".to_string()));
    }
    
    let query = format!(
        "UPDATE tenants SET {} WHERE id = $1",
        updates.join(", ")
    );
    
    sqlx::query(&query)
        .bind(&id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "message": "Tenant updated successfully",
    })))
}

async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Deleted tenant: {}", id);
    
    Ok(Json(serde_json::json!({
        "message": "Tenant deleted successfully",
    })))
}

// Provider configuration handlers

async fn list_providers(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let providers = sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, api_base, provider_type, is_active FROM providers"
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "providers": providers,
    })))
}

#[derive(Deserialize)]
struct CreateProviderRequest {
    name: String,
    api_base: String,
    provider_type: String, // openai, anthropic, azure, ollama
    /// When set on PUT, stored in `api_key_encrypted` for audit / future DB-backed routing.
    /// Lab upstream still prefers `TRACETRAMP_UPSTREAM_OPENAI_API_KEY` in `connector::proxy_chat_completion`.
    #[serde(default)]
    api_key: Option<String>,
}

async fn create_provider(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateProviderRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    
    sqlx::query(
        "INSERT INTO providers (id, name, api_base, provider_type, is_active, created_at) VALUES ($1, $2, $3, $4, true, NOW())"
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.api_base)
    .bind(&req.provider_type)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "message": "Provider created successfully",
    }))))
}

async fn get_provider(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let provider = sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, api_base, provider_type, is_active FROM providers WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    match provider {
        Some(p) => Ok(Json(p)),
        None => Err(AppError::NotFound(format!("Provider {} not found", id))),
    }
}

async fn update_provider(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<CreateProviderRequest>,
) -> Result<impl IntoResponse, AppError> {
    let key_store = req
        .api_key
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    sqlx::query(
        r#"
        UPDATE providers
        SET name = $2, api_base = $3, provider_type = $4,
            api_key_encrypted = COALESCE($5, api_key_encrypted)
        WHERE id = $1
        "#,
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.api_base)
    .bind(&req.provider_type)
    .bind(key_store.as_deref())
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "message": "Provider updated successfully",
    })))
}

#[derive(Deserialize)]
struct CreateTenantApiKeyRequest {
    actor_id: String,
    #[serde(default = "default_actor_role")]
    actor_role: String,
}

fn default_actor_role() -> String {
    "user".to_string()
}

/// Mint a data-plane bearer for lab / CI. Identity is still resolved via Connector in `resolver.rs`.
async fn create_tenant_api_key(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
    Json(req): Json<CreateTenantApiKeyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)",
    )
    .bind(&tenant_id)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if !exists {
        return Err(AppError::NotFound(format!("tenant {} not found", tenant_id)));
    }

    let actor_uuid: String = match sqlx::query_scalar::<_, String>(
        "SELECT id FROM actors WHERE tenant_id = $1 AND external_id = $2",
    )
    .bind(&tenant_id)
    .bind(&req.actor_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    {
        Some(id) => id,
        None => {
            let nid = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO actors (id, tenant_id, external_id, role, clearance_level, metadata, created_at)
                VALUES ($1, $2, $3, $4, 1, '{}', NOW())
                "#,
            )
            .bind(&nid)
            .bind(&tenant_id)
            .bind(&req.actor_id)
            .bind(&req.actor_role)
            .execute(&state.db_pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            nid
        }
    };

    let plain_key = format!("cpk_live_{}", uuid::Uuid::new_v4().simple());
    let key_hash = sha256::digest(&plain_key);
    let key_prefix = plain_key.chars().take(32).collect::<String>();

    let key_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO api_keys (id, tenant_id, key_prefix, key_hash, actor_id, actor_role, environment, revoked, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'production', false, NOW())
        "#,
    )
    .bind(&key_id)
    .bind(&tenant_id)
    .bind(&key_prefix)
    .bind(&key_hash)
    .bind(&actor_uuid)
    .bind(&req.actor_role)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    info!(
        "Minted api key id={} tenant={} actor_external={}",
        key_id, tenant_id, req.actor_id
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": key_id,
            "tenant_id": tenant_id,
            "api_key": plain_key,
            "actor_id": req.actor_id,
            "actor_role": req.actor_role,
        })),
    ))
}

// ========== RBAC: Roles ==========

#[derive(Deserialize)]
struct CreateRoleRequest {
    tenant_id: String,
    name: String,
    permissions: Vec<String>,
    description: Option<String>,
}

async fn list_roles(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TenantFilter>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, RoleRow>(
        "SELECT id, tenant_id, name, permissions, description, created_at FROM rbac_roles WHERE tenant_id = $1 OR $1 IS NULL ORDER BY created_at DESC"
    )
    .bind(&params.tenant_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({ "roles": rows, "count": rows.len() })))
}

async fn create_role(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO rbac_roles (id, tenant_id, name, permissions, description, created_at) VALUES ($1, $2, $3, $4, $5, NOW())"
    )
    .bind(&id)
    .bind(&req.tenant_id)
    .bind(&req.name)
    .bind(&req.permissions)
    .bind(&req.description)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Created role: {} for tenant {}", req.name, req.tenant_id);
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id, "name": req.name }))))
}

// ========== RBAC: Users ==========

#[derive(Deserialize)]
struct CreateUserRequest {
    tenant_id: String,
    email: String,
    name: String,
    roles: Vec<String>,
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TenantFilter>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, UserRow>(
        "SELECT id, tenant_id, email, name, roles, created_at FROM rbac_users WHERE tenant_id = $1 OR $1 IS NULL ORDER BY created_at DESC"
    )
    .bind(&params.tenant_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({ "users": rows, "count": rows.len() })))
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO rbac_users (id, tenant_id, email, name, roles, created_at) VALUES ($1, $2, $3, $4, $5, NOW())"
    )
    .bind(&id)
    .bind(&req.tenant_id)
    .bind(&req.email)
    .bind(&req.name)
    .bind(&req.roles)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Created user: {} for tenant {}", req.email, req.tenant_id);
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id, "email": req.email }))))
}

#[derive(Deserialize)]
struct AssignRoleRequest {
    roles: Vec<String>,
}

async fn assign_role(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Json(req): Json<AssignRoleRequest>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query("UPDATE rbac_users SET roles = $2, updated_at = NOW() WHERE id = $1")
        .bind(&user_id)
        .bind(&req.roles)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Assigned {} roles to user {}", req.roles.len(), user_id);
    Ok(Json(serde_json::json!({ "message": "Roles assigned", "user_id": user_id })))
}

// ========== Budgets ==========

#[derive(Deserialize)]
struct CreateBudgetRequest {
    tenant_id: String,
    name: String,
    period: String,      // monthly, daily, hourly
    limit_usd: f64,
    alert_threshold: f64, // percentage (e.g., 0.8 = 80%)
    scope: String,       // tenant, app, actor
    scope_id: Option<String>,
}

async fn list_budgets(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TenantFilter>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, BudgetRow>(
        "SELECT id, tenant_id, name, period, limit_usd, alert_threshold, scope, scope_id, current_spend_usd, is_active FROM budgets WHERE tenant_id = $1 OR $1 IS NULL"
    )
    .bind(&params.tenant_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({ "budgets": rows, "count": rows.len() })))
}

async fn create_budget(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBudgetRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO budgets (id, tenant_id, name, period, limit_usd, alert_threshold, scope, scope_id, current_spend_usd, is_active, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, true, NOW())"
    )
    .bind(&id)
    .bind(&req.tenant_id)
    .bind(&req.name)
    .bind(&req.period)
    .bind(req.limit_usd)
    .bind(req.alert_threshold)
    .bind(&req.scope)
    .bind(&req.scope_id)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Created budget: {} ({} USD/{}) for tenant {}", req.name, req.limit_usd, req.period, req.tenant_id);
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id, "name": req.name }))))
}

async fn get_budget(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query_as::<_, BudgetRow>(
        "SELECT id, tenant_id, name, period, limit_usd, alert_threshold, scope, scope_id, current_spend_usd, is_active FROM budgets WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    match row {
        Some(b) => Ok(Json(serde_json::json!(b))),
        None => Err(AppError::NotFound(format!("Budget {} not found", id))),
    }
}

#[derive(Deserialize)]
struct UpdateBudgetRequest {
    limit_usd: Option<f64>,
    alert_threshold: Option<f64>,
    is_active: Option<bool>,
}

async fn update_budget(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateBudgetRequest>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(limit) = req.limit_usd {
        sqlx::query("UPDATE budgets SET limit_usd = $2, updated_at = NOW() WHERE id = $1")
            .bind(&id).bind(limit)
            .execute(&state.db_pool).await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }
    if let Some(threshold) = req.alert_threshold {
        sqlx::query("UPDATE budgets SET alert_threshold = $2, updated_at = NOW() WHERE id = $1")
            .bind(&id).bind(threshold)
            .execute(&state.db_pool).await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }
    if let Some(active) = req.is_active {
        sqlx::query("UPDATE budgets SET is_active = $2, updated_at = NOW() WHERE id = $1")
            .bind(&id).bind(active)
            .execute(&state.db_pool).await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }
    Ok(Json(serde_json::json!({ "message": "Budget updated", "id": id })))
}

// ========== Policies ==========

#[derive(Deserialize)]
struct CreatePolicyRequest {
    tenant_id: String,
    name: String,
    policy_type: String, // content_filter, tool_permission, rate_limit, pii_redact
    rules: serde_json::Value,
    enforcement_mode: String, // monitor, block, alert
    priority: i32,
    /// B18: optional intelligence agent binding.
    #[serde(default)]
    agent_pid: Option<String>,
}

async fn list_policies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TenantFilter>,
) -> Result<impl IntoResponse, AppError> {
    // Prefer agent_pid column; also match rules.agent_pid for pre-migration rows.
    let rows = sqlx::query_as::<_, PolicyRow>(
        r#"SELECT id, tenant_id, name, policy_type, rules, enforcement_mode, priority, is_active, created_at,
                  agent_pid
           FROM policies
           WHERE (tenant_id = $1 OR $1 IS NULL)
             AND ($2::text IS NULL
                  OR agent_pid = $2
                  OR rules->>'agent_pid' = $2)
           ORDER BY priority DESC"#
    )
    .bind(&params.tenant_id)
    .bind(&params.agent_pid)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({ "policies": rows, "count": rows.len() })))
}

async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    // Embed agent_pid in rules for older readers; column is first-class (B18).
    let mut rules = req.rules.clone();
    if let Some(pid) = req.agent_pid.as_ref() {
        if let Some(obj) = rules.as_object_mut() {
            obj.insert("agent_pid".into(), serde_json::json!(pid));
        }
    }
    sqlx::query(
        "INSERT INTO policies (id, tenant_id, name, policy_type, rules, enforcement_mode, priority, is_active, created_at, agent_pid) VALUES ($1, $2, $3, $4, $5, $6, $7, true, NOW(), $8)"
    )
    .bind(&id)
    .bind(&req.tenant_id)
    .bind(&req.name)
    .bind(&req.policy_type)
    .bind(&rules)
    .bind(&req.enforcement_mode)
    .bind(req.priority)
    .bind(&req.agent_pid)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Created policy: {} ({}) for tenant {} agent {:?}", req.name, req.policy_type, req.tenant_id, req.agent_pid);
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id, "name": req.name, "agent_pid": req.agent_pid }))))
}

async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query_as::<_, PolicyRow>(
        "SELECT id, tenant_id, name, policy_type, rules, enforcement_mode, priority, is_active, created_at, agent_pid FROM policies WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    match row {
        Some(p) => Ok(Json(serde_json::json!(p))),
        None => Err(AppError::NotFound(format!("Policy {} not found", id))),
    }
}

#[derive(Deserialize)]
struct UpdatePolicyRequest {
    rules: Option<serde_json::Value>,
    enforcement_mode: Option<String>,
    is_active: Option<bool>,
}

async fn update_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(rules) = req.rules {
        sqlx::query("UPDATE policies SET rules = $2, updated_at = NOW() WHERE id = $1")
            .bind(&id).bind(&rules)
            .execute(&state.db_pool).await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }
    if let Some(mode) = req.enforcement_mode {
        sqlx::query("UPDATE policies SET enforcement_mode = $2, updated_at = NOW() WHERE id = $1")
            .bind(&id).bind(&mode)
            .execute(&state.db_pool).await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }
    if let Some(active) = req.is_active {
        sqlx::query("UPDATE policies SET is_active = $2, updated_at = NOW() WHERE id = $1")
            .bind(&id).bind(active)
            .execute(&state.db_pool).await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }
    Ok(Json(serde_json::json!({ "message": "Policy updated", "id": id })))
}

// ========== Approvals ==========

/// Mark pending approvals past their TTL as expired. Returns rows affected.
/// Rows inserted without `expires_at` used to sit pending forever; those expire
/// from `created_at` plus the same TTL.
pub async fn expire_pending_approvals(pool: &sqlx::PgPool) -> Result<u64, AppError> {
    let ttl_mins: i64 = std::env::var("CONNECTOR_TT_APPROVAL_TTL_MINS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30);
    let result = sqlx::query(
        "UPDATE approval_queue
         SET status = 'expired', resolved_at = NOW(),
             comment = COALESCE(comment, 'expired_by_ttl')
         WHERE status = 'pending'
           AND (
             (expires_at IS NOT NULL AND expires_at < NOW())
             OR (
               expires_at IS NULL
               AND created_at < NOW() - ($1::text || ' minutes')::interval
             )
           )"
    )
    .bind(ttl_mins.to_string())
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(result.rows_affected())
}

async fn list_approvals(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ApprovalFilter>,
) -> Result<impl IntoResponse, AppError> {
    let expired = expire_pending_approvals(&state.db_pool).await.unwrap_or(0);
    let status = params.status.as_deref().unwrap_or("pending");
    let rows = sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, tenant_id, request_id, trace_id, actor_id, reason, status, approvers, created_at FROM approval_queue WHERE status = $1 ORDER BY created_at DESC LIMIT 100"
    )
    .bind(status)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    // `count` is the window. `total` is the table. A full window of 100 is not the pile.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM approval_queue WHERE status = $1")
        .bind(status)
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or(rows.len() as i64);

    Ok(Json(serde_json::json!({
        "approvals": rows,
        "count": rows.len(),
        "total": total,
        "limit": 100,
        "expired_swept": expired,
    })))
}

#[derive(Deserialize, Default)]
struct ApprovalActionRequest {
    #[serde(default)]
    approver_id: String,
    comment: Option<String>,
}

fn resolve_approver(ctx: &AuthContext, body: &ApprovalActionRequest) -> Result<String, AppError> {
    let subject = ctx.subject.trim();
    if !subject.is_empty() && subject != "admin-token" && subject != "dev-bypass" {
        return Ok(subject.to_string());
    }
    let from_body = body.approver_id.trim();
    if from_body.is_empty() {
        return Err(AppError::Validation(
            "approver_id required — must be the authenticated operator, not an empty client label".into(),
        ));
    }
    Ok(from_body.to_string())
}

/// Pending-only consume-once transition. Expired / already-decided holds cannot be revived.
async fn transition_pending_approval(
    pool: &sqlx::PgPool,
    id: &str,
    new_status: &str,
    resolved_by: &str,
    comment: Option<&str>,
) -> Result<(String, String, String, String), AppError> {
    let _ = expire_pending_approvals(pool).await;
    let row = sqlx::query(
        "UPDATE approval_queue
         SET status = $2, resolved_by = $3, resolved_at = NOW(), comment = $4
         WHERE id = $1
           AND status = 'pending'
           AND (expires_at IS NULL OR expires_at > NOW())
         RETURNING id, tenant_id, actor_id, status",
    )
    .bind(id)
    .bind(new_status)
    .bind(resolved_by)
    .bind(comment)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(row) = row else {
        let existing = sqlx::query("SELECT status FROM approval_queue WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        return match existing {
            None => Err(AppError::NotFound(format!("Approval '{id}' not found"))),
            Some(r) => {
                let st: String = r.try_get("status").unwrap_or_default();
                Err(AppError::Validation(format!(
                    "Cannot set '{id}' to {new_status}: current status is '{st}' (only a live pending hold can be decided; expired holds stay expired)"
                )))
            }
        };
    };

    Ok((
        row.try_get("id").unwrap_or_default(),
        row.try_get("tenant_id").unwrap_or_default(),
        row.try_get("actor_id").unwrap_or_default(),
        row.try_get("status").unwrap_or_default(),
    ))
}

fn decision_json(
    action: &str,
    id: String,
    tenant_id: String,
    actor_id: String,
    status: String,
    resolved_by: &str,
) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "id": id,
        "action": action,
        "status": status,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "resolved_by": resolved_by,
        "message": match action {
            "approve" => "Request approved",
            "reject" => "Request rejected",
            "quarantine" => "Request quarantined — that actor is blocked on this tenant until release",
            _ => "Decision recorded",
        },
        "honesty": "Pending-only consume-once. Client cannot pick a fake approver when the platform stamps verified claims. Expired or already-decided holds cannot be revived.",
    })
}

async fn approve_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<ApprovalActionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resolved_by = resolve_approver(&ctx, &req)?;
    let (id, tenant_id, actor_id, status) = transition_pending_approval(
        &state.db_pool,
        &id,
        "approved",
        &resolved_by,
        req.comment.as_deref(),
    )
    .await?;
    info!("Approval {id} approved by {resolved_by}");
    Ok(Json(decision_json(
        "approve",
        id,
        tenant_id,
        actor_id,
        status,
        &resolved_by,
    )))
}

async fn reject_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<ApprovalActionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resolved_by = resolve_approver(&ctx, &req)?;
    let (id, tenant_id, actor_id, status) = transition_pending_approval(
        &state.db_pool,
        &id,
        "rejected",
        &resolved_by,
        req.comment.as_deref(),
    )
    .await?;
    info!("Approval {id} rejected by {resolved_by}");
    Ok(Json(decision_json(
        "reject",
        id,
        tenant_id,
        actor_id,
        status,
        &resolved_by,
    )))
}

async fn quarantine_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<ApprovalActionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resolved_by = resolve_approver(&ctx, &req)?;
    let (id, tenant_id, actor_id, status) = transition_pending_approval(
        &state.db_pool,
        &id,
        "quarantined",
        &resolved_by,
        req.comment.as_deref(),
    )
    .await?;
    info!("Approval {id} quarantined by {resolved_by} (actor {actor_id})");
    Ok(Json(decision_json(
        "quarantine",
        id,
        tenant_id,
        actor_id,
        status,
        &resolved_by,
    )))
}

#[derive(Deserialize)]
struct CreateQuarantineRequest {
    tenant_id: Option<String>,
    actor_id: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct ReleaseQuarantineRequest {
    tenant_id: Option<String>,
    actor_id: Option<String>,
}

async fn list_quarantines(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ApprovalFilter>,
) -> Result<impl IntoResponse, AppError> {
    let status = params.status.as_deref().unwrap_or("quarantined");
    let rows = sqlx::query(
        "SELECT id, tenant_id, request_id, trace_id, actor_id, reason, status,
                resolved_by, resolved_at, comment, created_at, hold_metadata
         FROM approval_queue
         WHERE status = $1
         ORDER BY created_at DESC
         LIMIT 200"
    )
    .bind(status)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let quarantines: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| serde_json::json!({
            "id": row.try_get::<String, _>("id").unwrap_or_default(),
            "tenant_id": row.try_get::<String, _>("tenant_id").unwrap_or_default(),
            "request_id": row.try_get::<String, _>("request_id").unwrap_or_default(),
            "trace_id": row.try_get::<String, _>("trace_id").unwrap_or_default(),
            "actor_id": row.try_get::<String, _>("actor_id").unwrap_or_default(),
            "reason": row.try_get::<String, _>("reason").unwrap_or_default(),
            "status": row.try_get::<String, _>("status").unwrap_or_default(),
            "resolved_by": row.try_get::<Option<String>, _>("resolved_by").unwrap_or(None),
            "resolved_at": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("resolved_at").unwrap_or(None).map(|v| v.to_rfc3339()),
            "comment": row.try_get::<Option<String>, _>("comment").unwrap_or(None),
            "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|v| v.to_rfc3339()),
            "hold_metadata": row.try_get::<serde_json::Value, _>("hold_metadata").unwrap_or_else(|_| serde_json::json!({})),
        }))
        .collect();

    Ok(Json(serde_json::json!({ "quarantines": quarantines, "count": quarantines.len() })))
}

async fn create_quarantine(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateQuarantineRequest>,
) -> Result<impl IntoResponse, AppError> {
    let actor_id = req.actor_id.trim();
    if actor_id.is_empty() {
        return Err(AppError::Validation("actor_id is required".to_string()));
    }
    let reason = req.reason.unwrap_or_else(|| "operator quarantine".to_string());
    let requested_tenant = req.tenant_id.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let tenant_ids: Vec<String> = if let Some(tenant_id) = requested_tenant.filter(|v| *v != "*") {
        vec![tenant_id.to_string()]
    } else {
        sqlx::query("SELECT id FROM tenants ORDER BY created_at DESC")
            .fetch_all(&state.db_pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .into_iter()
            .filter_map(|row| row.try_get::<String, _>("id").ok())
            .collect()
    };

    if tenant_ids.is_empty() {
        return Err(AppError::Validation("No tenants available for quarantine".to_string()));
    }

    for tenant_id in &tenant_ids {
        sqlx::query(
            "INSERT INTO approval_queue
             (id, tenant_id, request_id, trace_id, actor_id, reason, status, approvers, comment, hold_metadata)
             VALUES ($1, $2, $3, $4, $5, $6, 'quarantined', ARRAY[]::text[], $7, $8)"
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(tenant_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(actor_id)
        .bind(&reason)
        .bind("operator-created quarantine")
        .bind(&serde_json::json!({ "source": "admin_api", "quarantine_type": "agent" }))
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    Ok(Json(serde_json::json!({
        "message": "Quarantine created",
        "actor_id": actor_id,
        "tenant_count": tenant_ids.len(),
        "status": "quarantined",
    })))
}

async fn release_quarantine(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReleaseQuarantineRequest>,
) -> Result<impl IntoResponse, AppError> {
    let tenant = req.tenant_id.as_deref().map(str::trim).filter(|v| !v.is_empty() && *v != "*");
    let actor = req.actor_id.as_deref().map(str::trim).filter(|v| !v.is_empty() && *v != "*");

    if tenant.is_none() && actor.is_none() {
        return Err(AppError::Validation("tenant_id or actor_id is required".to_string()));
    }

    let result = sqlx::query(
        "UPDATE approval_queue
         SET status = 'released', resolved_at = NOW(), resolved_by = 'admin-api'
         WHERE status = 'quarantined'
           AND ($1::text IS NULL OR tenant_id = $1)
           AND ($2::text IS NULL OR actor_id = $2)"
    )
    .bind(tenant)
    .bind(actor)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({ "message": "Quarantine released", "released": result.rows_affected() })))
}

#[derive(Deserialize)]
struct OperationBlockRequest {
    tenant_id: String,
    actor_id: String,
    operation_key: String,
    reason: String,
    created_by: Option<String>,
}

#[derive(Deserialize)]
struct ReleaseOperationBlockRequest {
    tenant_id: String,
    actor_id: String,
    operation_key: String,
}

async fn list_operation_blocks(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query(
        "SELECT id::text AS id, tenant_id, actor_id, operation_key, reason, active, created_by, created_at, updated_at
         FROM operation_blocks
         ORDER BY created_at DESC
         LIMIT 200"
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let operation_blocks: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| serde_json::json!({
            "id": row.try_get::<String, _>("id").unwrap_or_default(),
            "tenant_id": row.try_get::<String, _>("tenant_id").unwrap_or_default(),
            "actor_id": row.try_get::<String, _>("actor_id").unwrap_or_default(),
            "operation_key": row.try_get::<String, _>("operation_key").unwrap_or_default(),
            "reason": row.try_get::<String, _>("reason").unwrap_or_default(),
            "active": row.try_get::<bool, _>("active").unwrap_or(false),
            "created_by": row.try_get::<Option<String>, _>("created_by").unwrap_or(None),
            "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|v| v.to_rfc3339()),
            "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok().map(|v| v.to_rfc3339()),
        }))
        .collect();

    Ok(Json(serde_json::json!({ "operation_blocks": operation_blocks, "count": operation_blocks.len() })))
}

async fn create_operation_block(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OperationBlockRequest>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query(
        "INSERT INTO operation_blocks (tenant_id, actor_id, operation_key, reason, active, created_by)
         VALUES ($1, $2, $3, $4, true, $5)
         ON CONFLICT (tenant_id, actor_id, operation_key)
         DO UPDATE SET reason = EXCLUDED.reason, active = true, created_by = EXCLUDED.created_by, updated_at = NOW()"
    )
    .bind(req.tenant_id.trim())
    .bind(req.actor_id.trim())
    .bind(req.operation_key.trim())
    .bind(req.reason.trim())
    .bind(req.created_by.as_deref().unwrap_or("admin-api"))
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "message": "Operation block active",
        "tenant_id": req.tenant_id,
        "actor_id": req.actor_id,
        "operation_key": req.operation_key,
    })))
}

async fn release_operation_block(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReleaseOperationBlockRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = sqlx::query(
        "UPDATE operation_blocks
         SET active = false, updated_at = NOW()
         WHERE tenant_id = $1 AND actor_id = $2 AND operation_key = $3 AND active = true"
    )
    .bind(req.tenant_id.trim())
    .bind(req.actor_id.trim())
    .bind(req.operation_key.trim())
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({ "message": "Operation block released", "released": result.rows_affected() })))
}

// ========== Logging Destinations ==========

#[derive(Deserialize)]
struct CreateLogDestRequest {
    tenant_id: String,
    name: String,
    destination_type: String, // splunk, s3, datadog, cloudwatch, elasticsearch
    config: serde_json::Value,
}

async fn list_log_destinations(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TenantFilter>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, LogDestRow>(
        "SELECT id, tenant_id, name, destination_type, config, is_active FROM log_destinations WHERE tenant_id = $1 OR $1 IS NULL"
    )
    .bind(&params.tenant_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({ "destinations": rows, "count": rows.len() })))
}

async fn create_log_destination(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateLogDestRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO log_destinations (id, tenant_id, name, destination_type, config, is_active, created_at) VALUES ($1, $2, $3, $4, $5, true, NOW())"
    )
    .bind(&id)
    .bind(&req.tenant_id)
    .bind(&req.name)
    .bind(&req.destination_type)
    .bind(&req.config)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Created log destination: {} ({}) for tenant {}", req.name, req.destination_type, req.tenant_id);
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id, "name": req.name }))))
}

// ========== Compliance Exports ==========

#[derive(Deserialize)]
struct CreateComplianceExportRequest {
    tenant_id: String,
    name: String,
    start_date: String,
    end_date: String,
    format: String,
    delivery: String, // download, s3, email
}

async fn list_compliance_exports(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TenantFilter>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, ComplianceExportRow>(
        "SELECT id, tenant_id, name, start_date, end_date, format, delivery, status, download_url, created_at FROM compliance_exports WHERE tenant_id = $1 OR $1 IS NULL ORDER BY created_at DESC LIMIT 50"
    )
    .bind(&params.tenant_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    Ok(Json(serde_json::json!({ "exports": rows, "count": rows.len() })))
}

async fn create_compliance_export(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateComplianceExportRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    let download_url = format!("/compliance/export?tenant_id={}&start_date={}&end_date={}&format={}", 
        req.tenant_id, req.start_date, req.end_date, req.format);
    
    sqlx::query(
        "INSERT INTO compliance_exports (id, tenant_id, name, start_date, end_date, format, delivery, status, download_url, created_at) VALUES ($1, $2, $3, $4::timestamptz, $5::timestamptz, $6, $7, 'ready', $8, NOW())"
    )
    .bind(&id)
    .bind(&req.tenant_id)
    .bind(&req.name)
    .bind(&req.start_date)
    .bind(&req.end_date)
    .bind(&req.format)
    .bind(&req.delivery)
    .bind(&download_url)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    
    info!("Created compliance export: {} for tenant {}", req.name, req.tenant_id);
    Ok((StatusCode::CREATED, Json(serde_json::json!({ 
        "id": id, 
        "name": req.name,
        "download_url": download_url,
        "status": "ready"
    }))))
}

// Query filter types
#[derive(Deserialize)]
struct TenantFilter {
    tenant_id: Option<String>,
    /// B18: filter policies bound to an intelligence agent.
    #[serde(default)]
    agent_pid: Option<String>,
}

#[derive(Deserialize)]
struct ApprovalFilter {
    status: Option<String>,
}

// Database row types

#[derive(sqlx::FromRow, Serialize)]
struct TenantRow {
    id: String,
    name: String,
    environment: String,
    default_mode: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Serialize)]
struct ProviderRow {
    id: String,
    name: String,
    api_base: String,
    provider_type: String,
    is_active: bool,
}

#[derive(sqlx::FromRow, Serialize)]
struct RoleRow {
    id: String,
    tenant_id: String,
    name: String,
    permissions: Vec<String>,
    description: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Serialize)]
struct UserRow {
    id: String,
    tenant_id: String,
    email: String,
    name: String,
    roles: Vec<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Serialize)]
struct BudgetRow {
    id: String,
    tenant_id: String,
    name: String,
    period: String,
    limit_usd: f64,
    alert_threshold: f64,
    scope: String,
    scope_id: Option<String>,
    current_spend_usd: f64,
    is_active: bool,
}

#[derive(sqlx::FromRow, Serialize)]
struct PolicyRow {
    id: String,
    tenant_id: String,
    name: String,
    policy_type: String,
    rules: serde_json::Value,
    enforcement_mode: String,
    priority: i32,
    is_active: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_pid: Option<String>,
}

#[derive(sqlx::FromRow, Serialize)]
struct ApprovalRow {
    id: String,
    tenant_id: String,
    request_id: String,
    trace_id: String,
    actor_id: String,
    reason: String,
    status: String,
    approvers: Vec<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Serialize)]
struct LogDestRow {
    id: String,
    tenant_id: String,
    name: String,
    destination_type: String,
    config: serde_json::Value,
    is_active: bool,
}

#[derive(sqlx::FromRow, Serialize)]
struct ComplianceExportRow {
    id: String,
    tenant_id: String,
    name: String,
    start_date: chrono::DateTime<chrono::Utc>,
    end_date: chrono::DateTime<chrono::Utc>,
    format: String,
    delivery: String,
    status: String,
    download_url: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Execute an approved request (resume latch — consume once).
async fn execute_approved_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<axum::response::Response, AppError> {
    use axum::response::IntoResponse;

    let _ = expire_pending_approvals(&state.db_pool).await;

    let new_trace_id = uuid::Uuid::new_v4().to_string();

    // Atomic one-shot latch: only the first execute wins.
    let row = sqlx::query(
        "UPDATE approval_queue
         SET result_ready = TRUE, result_trace_id = $1
         WHERE id = $2
           AND status = 'approved'
           AND COALESCE(result_ready, FALSE) = FALSE
         RETURNING id, tenant_id, request_id, trace_id, actor_id, status,
                   request_payload, result_ready, result_trace_id, result_payload"
    )
    .bind(&new_trace_id)
    .bind(&id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(row) = row else {
        // Already consumed or not approved — return cached / error.
        let existing = sqlx::query(
            "SELECT id, status, result_ready, result_trace_id, result_payload
             FROM approval_queue WHERE id = $1"
        )
        .bind(&id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let Some(existing) = existing else {
            return Err(AppError::NotFound(format!("Approval '{}' not found", id)));
        };
        let status: String = existing.try_get("status").unwrap_or_default();
        let result_ready: bool = existing.try_get("result_ready").unwrap_or(false);
        if status == "approved" && result_ready {
            return Ok(Json(serde_json::json!({
                "message": "Approval already executed (consume-once)",
                "id": id,
                "status": "completed",
                "result_trace_id": existing.try_get::<Option<String>, _>("result_trace_id").ok().flatten(),
                "result_payload": existing.try_get::<Option<serde_json::Value>, _>("result_payload").ok().flatten(),
                "honesty": "result_ready latch — second execute does not re-run",
            }))
            .into_response());
        }
        return Err(AppError::Validation(format!(
            "Cannot execute approval '{}': status is '{}' (must be approved and unconsumed)",
            id, status
        )));
    };

    let _ = sqlx::query(
        "INSERT INTO trace_events (trace_id, request_id, event_type, step, result, metadata)
         VALUES ($1, $2, 'checkpoint', 'ApprovalExecute', 'Success', $3)"
    )
    .bind(&new_trace_id)
    .bind(row.try_get::<String, _>("request_id").unwrap_or_default())
    .bind(&serde_json::json!({
        "approval_id": id,
        "executed_by": "admin-api",
        "tenant_id": row.try_get::<String, _>("tenant_id").ok(),
        "actor_id": row.try_get::<String, _>("actor_id").ok(),
        "consume_once": true
    }))
    .execute(&state.db_pool)
    .await;

    Ok(Json(serde_json::json!({
        "message": "Approval ready for execution",
        "instruction": "Retry the original request with headers X-Approval-Resume: approved and X-Approval-Id: <id>",
        "id": id,
        "result_trace_id": new_trace_id,
        "approval_status": "approved",
        "result_ready": true,
        "consume_once": true
    }))
    .into_response())
}

/// Get the result of an executed approved request
async fn get_approval_result(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        "SELECT id, status, result_ready, result_trace_id, result_payload, resolved_at
         FROM approval_queue
         WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let row = match row {
        Some(r) => r,
        None => return Err(AppError::NotFound(format!("Approval '{}' not found", id))),
    };

    let result_ready: bool = row.try_get("result_ready").unwrap_or(false);
    let result_trace_id: Option<String> = row.try_get("result_trace_id").ok();
    let result_payload: Option<serde_json::Value> = row.try_get("result_payload").ok();
    let completed_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("resolved_at").ok();

    Ok(Json(serde_json::json!({
        "id": id,
        "status": row.try_get::<String, _>("status").unwrap_or_default(),
        "result_ready": result_ready,
        "result_trace_id": result_trace_id,
        "result_payload": result_payload,
        "completed_at": completed_at,
        "instruction": if result_ready {
            "Request executed successfully"
        } else {
            "Execute the request first via POST /admin/approvals/:id/execute"
        }
    })))
}

/// List all quarantined items (comprehensive quarantine hold)
async fn list_all_quarantines(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, request_id, trace_id, actor_id, reason, status,
                request_payload, created_at, resolved_at, resolved_by, comment
         FROM approval_queue
         WHERE status = 'quarantined'
         ORDER BY created_at DESC"
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let quarantines: Vec<serde_json::Value> = rows
        .into_iter()
        .filter_map(|row| {
            let request_payload: Option<serde_json::Value> = row.try_get("request_payload").ok();
            let preview = request_payload.as_ref().map(|p| {
                p.get("operation")
                    .map(|op| op.to_string())
                    .unwrap_or_else(|| "No operation context".to_string())
            });

            Some(serde_json::json!({
                "id": row.try_get::<String, _>("id").ok()?,
                "tenant_id": row.try_get::<String, _>("tenant_id").ok()?,
                "request_id": row.try_get::<String, _>("request_id").ok()?,
                "trace_id": row.try_get::<String, _>("trace_id").ok()?,
                "actor_id": row.try_get::<String, _>("actor_id").ok()?,
                "reason": row.try_get::<String, _>("reason").ok()?,
                "status": row.try_get::<String, _>("status").ok()?,
                "request_preview": preview,
                "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok()?,
                "resolved_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("resolved_at").ok(),
                "resolved_by": row.try_get::<String, _>("resolved_by").ok(),
                "comment": row.try_get::<String, _>("comment").ok(),
            }))
        })
        .collect();

    let total_count = quarantines.len();

    Ok(Json(serde_json::json!({
        "quarantines": quarantines,
        "total_count": total_count,
        "summary": {
            "actionable": total_count,
            "message": "These requests are blocked pending quarantine review. Use POST /admin/quarantine/release with tenant_id and/or actor_id to release."
        },
        "release_instruction": "POST /admin/quarantine/release with { tenant_id, actor_id? } to release agent"
    })))
}
