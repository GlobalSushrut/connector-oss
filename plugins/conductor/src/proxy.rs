//! Cage Proxy — intercepts every action API call made by agents during a run.
//!
//! Flow for each incoming action request:
//!   1. Parse the `X-Conductor-Run-ID`, `X-Conductor-Step`, `X-Conductor-Agent`
//!      headers to identify which run/step/agent is making the call.
//!   2. Load the cage policy for that run's pipeline.
//!   3. Evaluate the cage: check action type, host, port, path rules.
//!   4. If DENY: return 403 with the deny reason. Record the intercept.
//!   5. If ALLOW/AUDIT: forward the request to the upstream target.
//!   6. Capture request + response hashes, latency, response status.
//!   7. Write an HMAC-SHA256 chained intercept record to the DB.
//!   8. Return the upstream response to the caller.
//!
//! The proxy endpoint is:
//!   POST /api/v1/proxy/action
//!
//! Expected request body:
//!   {
//!     "action_type": "http",          // http | sql | file | subprocess | tool
//!     "method": "POST",
//!     "url": "https://api.example.com/data",
//!     "headers": { "Authorization": "Bearer ..." },
//!     "body": "...",                  // raw body string or base64
//!     "run_id": "<uuid>",
//!     "step_index": 2,
//!     "agent_id": "summariser-v1"
//!   }
//!
//! The proxy returns:
//!   {
//!     "verdict": "allow" | "deny" | "audit",
//!     "intercept_id": "<uuid>",
//!     "status": 200,
//!     "headers": { ... },
//!     "body": "...",
//!     "latency_ms": 142,
//!     "receipt_hmac": "..."
//!   }

use std::time::Instant;

use anyhow::{Context, Result};
use axum::{extract::State, Json};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::cage::{self, ActionRequest, CageVerdict};
use crate::error::{ApiResult, AppError};
use crate::AppState;

// ── Request / Response ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProxyActionRequest {
    pub action_type: String,
    pub method:      Option<String>,
    pub url:         Option<String>,
    pub headers:     Option<Value>,
    pub body:        Option<String>,
    pub run_id:      Uuid,
    pub step_index:  i32,
    pub agent_id:    String,
}

#[derive(Debug, Serialize)]
pub struct ProxyActionResponse {
    pub verdict:      String,
    pub intercept_id: Uuid,
    pub status:       Option<u16>,
    pub headers:      Option<Value>,
    pub body:         Option<String>,
    pub latency_ms:   u64,
    pub receipt_hmac: String,
    pub deny_reason:  Option<String>,
}

// ── Main handler ──────────────────────────────────────────────────────────────

/// POST /api/v1/proxy/action
///
/// The single entry-point for all agent action calls under cage control.
pub async fn proxy_action(
    State(state): State<AppState>,
    Json(req): Json<ProxyActionRequest>,
) -> ApiResult<ProxyActionResponse> {
    // ── 1. Validate inputs ────────────────────────────────────────────────────
    if req.agent_id.trim().is_empty() {
        return Err(AppError::Validation("agent_id is required".into()));
    }
    if req.action_type.trim().is_empty() {
        return Err(AppError::Validation("action_type is required".into()));
    }

    // ── 2. Resolve run → pipeline ─────────────────────────────────────────────
    let pipeline_id: Uuid = sqlx::query("SELECT pipeline_id FROM conductor_runs WHERE id = $1")
        .bind(req.run_id)
        .fetch_optional(&state.pool).await
        .context("fetch run pipeline_id")
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("Run {} not found", req.run_id)))?
        .try_get("pipeline_id")
        .map_err(|e| AppError::Internal(e.into()))?;

    // ── 3. Parse action context ───────────────────────────────────────────────
    let (host, port, path) = parse_url(req.url.as_deref());

    let action = ActionRequest {
        action_type: req.action_type.clone(),
        method:      req.method.clone(),
        host:        host.clone(),
        port,
        path:        path.clone(),
        body_size:   req.body.as_ref().map(|b| b.len() as u64).unwrap_or(0),
    };

    // ── 4. Cage evaluation ────────────────────────────────────────────────────
    let cage_result = cage::evaluate(&state.pool, pipeline_id, &action).await;

    let request_body_hash = req.body.as_ref().map(|b| {
        format!("{:x}", Sha256::digest(b.as_bytes()))
    });

    let request_id = Uuid::new_v4().to_string();

    // ── 5. If DENY — record and return 403 ───────────────────────────────────
    if cage_result.verdict == CageVerdict::Deny {
        let _intercept_id = write_intercept(
            &state.pool,
            &req,
            pipeline_id,
            host.as_deref(),
            port,
            path.as_deref(),
            request_body_hash.as_deref(),
            "deny",
            cage_result.deny_reason.as_deref(),
            cage_result.policy_matched.as_deref(),
            None, None, None, 0,
            &request_id,
        ).await.unwrap_or_else(|_| Uuid::new_v4());

        return Err(AppError::Forbidden(
            cage_result.deny_reason.clone()
                .unwrap_or_else(|| "Action denied by cage policy".into())
        ));
    }

    // ── 6. Forward the request ────────────────────────────────────────────────
    let start = Instant::now();
    let forward_result = forward_action(&req).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let (resp_status, resp_headers, resp_body, resp_body_hash) = match forward_result {
        Ok((status, headers, body)) => {
            let hash = format!("{:x}", Sha256::digest(body.as_bytes()));
            (Some(status), Some(headers), Some(body), Some(hash))
        }
        Err(ref e) => {
            tracing::warn!(
                run_id = %req.run_id,
                agent = %req.agent_id,
                action_type = %req.action_type,
                err = %e,
                "Proxy forward error"
            );
            (None, None, None, None)
        }
    };

    let verdict_str = cage_result.verdict.to_string();

    // ── 7. Write intercept record ─────────────────────────────────────────────
    let intercept_id = write_intercept(
        &state.pool,
        &req,
        pipeline_id,
        host.as_deref(),
        port,
        path.as_deref(),
        request_body_hash.as_deref(),
        &verdict_str,
        cage_result.deny_reason.as_deref(),
        cage_result.policy_matched.as_deref(),
        resp_status,
        resp_body_hash.as_deref(),
        None,
        latency_ms as i32,
        &request_id,
    ).await.unwrap_or_else(|_| Uuid::new_v4());

    // ── 8. Compute HMAC receipt ───────────────────────────────────────────────
    let receipt_hmac = compute_receipt(&state.pool, intercept_id, &req).await;

    // ── 9. Update the intercept with its own HMAC ─────────────────────────────
    let _ = sqlx::query(
        "UPDATE conductor_proxy_intercepts SET receipt_hmac = $1 WHERE id = $2"
    )
    .bind(&receipt_hmac)
    .bind(intercept_id)
    .execute(&state.pool).await;

    tracing::info!(
        run_id       = %req.run_id,
        step         = req.step_index,
        agent        = %req.agent_id,
        action_type  = %req.action_type,
        verdict      = %verdict_str,
        latency_ms,
        intercept_id = %intercept_id,
        "Proxy intercept recorded"
    );

    Ok(Json(ProxyActionResponse {
        verdict:      verdict_str,
        intercept_id,
        status:       resp_status,
        headers:      resp_headers,
        body:         resp_body,
        latency_ms,
        receipt_hmac,
        deny_reason:  cage_result.deny_reason,
    }))
}

// ── Intercept log ─────────────────────────────────────────────────────────────

/// GET /api/v1/proxy/intercepts/:run_id — list all intercepts for a run
pub async fn list_intercepts(
    State(state): State<AppState>,
    axum::extract::Path(run_id): axum::extract::Path<Uuid>,
) -> ApiResult<Value> {
    let rows = sqlx::query(
        "SELECT id, run_id, step_index, agent_id, action_type, method, target_host,
         target_port, target_path, cage_verdict, deny_reason, policy_matched,
         response_status, latency_ms, receipt_hmac, intercepted_at,
         request_size_bytes, response_size_bytes
         FROM conductor_proxy_intercepts
         WHERE run_id = $1 ORDER BY intercepted_at ASC"
    )
    .bind(run_id)
    .fetch_all(&state.pool).await
    .map_err(|e| AppError::Internal(e.into()))?;

    let intercepts: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":              r.try_get::<Uuid, _>("id").unwrap_or_default().to_string(),
        "run_id":          r.try_get::<Uuid, _>("run_id").unwrap_or_default().to_string(),
        "step_index":      r.try_get::<i32, _>("step_index").unwrap_or(0),
        "agent_id":        r.try_get::<String, _>("agent_id").unwrap_or_default(),
        "action_type":     r.try_get::<String, _>("action_type").unwrap_or_default(),
        "method":          r.try_get::<Option<String>, _>("method").unwrap_or_default(),
        "target_host":     r.try_get::<Option<String>, _>("target_host").unwrap_or_default(),
        "target_port":     r.try_get::<Option<i32>, _>("target_port").unwrap_or_default(),
        "target_path":     r.try_get::<Option<String>, _>("target_path").unwrap_or_default(),
        "verdict":         r.try_get::<String, _>("cage_verdict").unwrap_or_default(),
        "deny_reason":     r.try_get::<Option<String>, _>("deny_reason").unwrap_or_default(),
        "policy_matched":  r.try_get::<Option<String>, _>("policy_matched").unwrap_or_default(),
        "response_status": r.try_get::<Option<i32>, _>("response_status").unwrap_or_default(),
        "latency_ms":      r.try_get::<i32, _>("latency_ms").unwrap_or(0),
        "receipt_hmac":    r.try_get::<Option<String>, _>("receipt_hmac").unwrap_or_default(),
        "intercepted_at":  r.try_get::<chrono::DateTime<Utc>, _>("intercepted_at")
                            .map(|t| t.to_rfc3339()).unwrap_or_default(),
    })).collect();

    let count = intercepts.len();
    Ok(Json(json!({ "intercepts": intercepts, "count": count, "run_id": run_id })))
}

/// GET /api/v1/proxy/intercepts/:run_id/verify — verify the HMAC chain integrity
pub async fn verify_chain(
    State(state): State<AppState>,
    axum::extract::Path(run_id): axum::extract::Path<Uuid>,
) -> ApiResult<Value> {
    let rows = sqlx::query(
        "SELECT id, agent_id, action_type, intercepted_at, receipt_hmac
         FROM conductor_proxy_intercepts
         WHERE run_id = $1 ORDER BY intercepted_at ASC"
    )
    .bind(run_id)
    .fetch_all(&state.pool).await
    .map_err(|e| AppError::Internal(e.into()))?;

    let total = rows.len();
    let mut broken_at: Option<usize> = None;
    let hmac_key = hmac_key();

    for (i, row) in rows.iter().enumerate() {
        let id: Uuid   = row.try_get("id").unwrap_or_default();
        let agent_id: String  = row.try_get("agent_id").unwrap_or_default();
        let action_type: String = row.try_get("action_type").unwrap_or_default();
        let ts: String = row.try_get::<chrono::DateTime<Utc>, _>("intercepted_at")
            .map(|t| t.to_rfc3339()).unwrap_or_default();
        let stored_hmac: Option<String> = row.try_get("receipt_hmac").unwrap_or_default();

        let expected = compute_hmac(
            &hmac_key,
            &format!("{}:{}:{}:{}", id, agent_id, action_type, ts),
        );

        if stored_hmac.as_deref() != Some(&expected) {
            broken_at = Some(i);
            break;
        }
    }

    let valid = broken_at.is_none();
    Ok(Json(json!({
        "run_id": run_id,
        "total_intercepts": total,
        "chain_valid": valid,
        "broken_at_index": broken_at,
        "verification": if valid { "PASS" } else { "FAIL — chain tampered" },
    })))
}

// ── Forward engine ────────────────────────────────────────────────────────────

/// Forward an HTTP action to the actual upstream.
/// Returns (status_code, headers_json, response_body_string).
async fn forward_action(
    req: &ProxyActionRequest,
) -> Result<(u16, Value, String)> {
    let url = req.url.as_deref()
        .ok_or_else(|| anyhow::anyhow!("url is required for http actions"))?;
    let method = req.method.as_deref().unwrap_or("GET").to_uppercase();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut builder = match method.as_str() {
        "GET"    => client.get(url),
        "POST"   => client.post(url),
        "PUT"    => client.put(url),
        "PATCH"  => client.patch(url),
        "DELETE" => client.delete(url),
        "HEAD"   => client.head(url),
        m        => return Err(anyhow::anyhow!("Unsupported method: {}", m)),
    };

    // Forward allowed headers (strip hop-by-hop and Conductor internal headers)
    if let Some(Value::Object(hdrs)) = &req.headers {
        for (k, v) in hdrs {
            let k_lower = k.to_lowercase();
            if k_lower.starts_with("x-conductor-") { continue; }
            if matches!(k_lower.as_str(), "connection" | "transfer-encoding" | "te" | "keep-alive") { continue; }
            if let Some(vs) = v.as_str() {
                if let (Ok(hk), Ok(hv)) = (
                    reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                    reqwest::header::HeaderValue::from_str(vs),
                ) {
                    builder = builder.header(hk, hv);
                }
            }
        }
    }

    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }

    let resp = builder.send().await.context("forward_action HTTP send")?;
    let status = resp.status().as_u16();

    let resp_headers: Value = {
        let mut hmap = serde_json::Map::new();
        for (k, v) in resp.headers().iter() {
            if let Ok(vs) = v.to_str() {
                hmap.insert(k.to_string(), Value::String(vs.to_string()));
            }
        }
        Value::Object(hmap)
    };

    let body_bytes = resp.bytes().await.context("read response body")?;
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    Ok((status, resp_headers, body_str))
}

// ── Receipt chain ─────────────────────────────────────────────────────────────

async fn compute_receipt(pool: &PgPool, intercept_id: Uuid, req: &ProxyActionRequest) -> String {
    let prev_hmac = sqlx::query(
        "SELECT receipt_hmac FROM conductor_proxy_intercepts
         WHERE run_id = $1 AND id != $2 ORDER BY intercepted_at DESC LIMIT 1"
    )
    .bind(req.run_id)
    .bind(intercept_id)
    .fetch_optional(pool).await
    .ok().flatten()
    .and_then(|r| r.try_get::<Option<String>, _>("receipt_hmac").ok().flatten())
    .unwrap_or_else(|| "genesis".to_string());

    let key = hmac_key();
    let payload = format!("{}:{}:{}:{}:{}", intercept_id, req.agent_id, req.action_type, req.run_id, prev_hmac);
    compute_hmac(&key, &payload)
}

fn hmac_key() -> String {
    std::env::var("CONDUCTOR_HMAC_KEY")
        .unwrap_or_else(|_| "conductor-cage-proxy-hmac-secret-change-in-production".into())
}

fn compute_hmac(key: &str, payload: &str) -> String {
    use sha2::Sha256;
    // Manual HMAC-SHA256: H(key XOR opad || H(key XOR ipad || payload))
    // Use 64-byte block size for SHA-256
    let mut k = key.as_bytes().to_vec();
    if k.len() > 64 { k = Sha256::digest(&k).to_vec(); }
    k.resize(64, 0);

    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = ipad;
    inner.extend_from_slice(payload.as_bytes());
    let inner_hash = Sha256::digest(&inner);

    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    format!("{:x}", Sha256::digest(&outer))
}

// ── DB write ──────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn write_intercept(
    pool:               &PgPool,
    req:                &ProxyActionRequest,
    pipeline_id:        Uuid,
    host:               Option<&str>,
    port:               Option<u16>,
    path:               Option<&str>,
    request_body_hash:  Option<&str>,
    verdict:            &str,
    deny_reason:        Option<&str>,
    policy_matched:     Option<&str>,
    response_status:    Option<u16>,
    response_body_hash: Option<&str>,
    prev_intercept_id:  Option<Uuid>,
    latency_ms:         i32,
    request_id:         &str,
) -> Result<Uuid> {
    let id = Uuid::new_v4();

    // Fetch cage id for this pipeline (may be null if no cage configured)
    let cage_id: Option<Uuid> = sqlx::query(
        "SELECT id FROM conductor_cages WHERE pipeline_id = $1"
    )
    .bind(pipeline_id)
    .fetch_optional(pool).await.ok().flatten()
    .and_then(|r| r.try_get("id").ok());

    let resp_status_i32: Option<i32> = response_status.map(|s| s as i32);
    let port_i32: Option<i32> = port.map(|p| p as i32);

    sqlx::query(
        "INSERT INTO conductor_proxy_intercepts
         (id, run_id, step_index, agent_id, cage_id,
          action_type, method, target_host, target_port, target_path,
          request_body_hash, request_size_bytes,
          cage_verdict, deny_reason, policy_matched,
          response_status, response_body_hash, response_size_bytes,
          latency_ms, request_id, prev_receipt_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)"
    )
    .bind(id)
    .bind(req.run_id)
    .bind(req.step_index)
    .bind(&req.agent_id)
    .bind(cage_id)
    .bind(&req.action_type)
    .bind(req.method.as_deref())
    .bind(host)
    .bind(port_i32)
    .bind(path)
    .bind(request_body_hash)
    .bind(req.body.as_ref().map(|b| b.len() as i64).unwrap_or(0))
    .bind(verdict)
    .bind(deny_reason)
    .bind(policy_matched)
    .bind(resp_status_i32)
    .bind(response_body_hash)
    .bind(0_i64)
    .bind(latency_ms)
    .bind(request_id)
    .bind(prev_intercept_id)
    .execute(pool).await
    .context("write proxy intercept")?;

    Ok(id)
}

// ── URL parsing ───────────────────────────────────────────────────────────────

fn parse_url(url: Option<&str>) -> (Option<String>, Option<u16>, Option<String>) {
    let url = match url { Some(u) => u, None => return (None, None, None) };
    if let Ok(parsed) = url::Url::parse(url) {
        let host = parsed.host_str().map(|s| s.to_string());
        let port = parsed.port_or_known_default();
        let path = Some(parsed.path().to_string());
        return (host, port, path);
    }
    (None, None, None)
}
