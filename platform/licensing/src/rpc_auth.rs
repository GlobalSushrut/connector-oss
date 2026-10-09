/// RPC Authentication handlers — binary phone-home auth flow.
///
/// Flow:
///   1. POST /rpc/v1/auth     — exchange (role_id, secret_id) for RPC token
///   2. POST /rpc/v1/renew    — renew expiring RPC token (within 5-min window)
///   3. POST /rpc/v1/revoke   — revoke own token on clean shutdown
///   4. GET  /rpc/v1/verify   — lightweight token validity check
///
/// All other /rpc/v1/* routes require:
///   Authorization: RpcToken <token_string>
///
/// Payment gate: secret_id is only present in the BinaryIssuance record
/// if the associated key's payment_status is Active. Attempting auth with
/// an unpaid key returns 402 Payment Required.

use axum::{extract::State, http::{HeaderMap, StatusCode}, Json};
use serde::{Deserialize, Serialize};
use crate::SharedState;
use crate::rpc_token::{TokenError, RpcTokenManager};

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub role_id:    String,
    pub secret_id:  String,
    pub machine_id: String,
    pub binary_id:  String,
    pub binary_hash: String,
    pub version:    String,
    pub os:         Option<String>,
    pub arch:       Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RenewRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token:    String,
    pub reason:   Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token:        String,
    pub token_id:     String,
    pub expires_in:   i64,
    pub tier:         String,
    pub permissions:  Vec<String>,
    pub instance_id:  String,
    pub binary_id:    String,
    pub renewal_url:  String,
}

// ── Axum response helper ──────────────────────────────────────────────────────

type ApiResult = (StatusCode, Json<serde_json::Value>);

fn ok(v: serde_json::Value) -> ApiResult {
    (StatusCode::OK, Json(v))
}

fn err(status: StatusCode, code: &str, msg: &str) -> ApiResult {
    (status, Json(serde_json::json!({
        "error":   msg,
        "code":    code,
        "ts":      chrono::Utc::now().to_rfc3339(),
    })))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /rpc/v1/auth
/// Exchange (role_id, secret_id) for a short-lived RPC token.
/// secret_id is consumed on first use — cannot be reused.
pub async fn rpc_auth(
    State(state): State<SharedState>,
    Json(req): Json<AuthRequest>,
) -> ApiResult {
    let now = chrono::Utc::now();

    // 1-9: all sync work inside a block so MutexGuard is dropped before any .await
    let (issuance_snap, token, instance_id, permissions) = {
        let mut issuances = state.issuances.lock().unwrap();
        let issuance = match issuances.iter_mut().find(|i| {
            i.role_id == req.role_id && i.secret_id == req.secret_id
        }) {
            Some(i) => i,
            None => return err(
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Invalid role_id or secret_id. Obtain credentials from the license portal.",
            ),
        };

        if issuance.secret_id_used {
            return err(
                StatusCode::UNAUTHORIZED,
                "SECRET_ID_CONSUMED",
                "secret_id already consumed. Each binary download has a unique one-time secret_id.",
            );
        }
        if issuance.is_expired() {
            return err(
                StatusCode::UNAUTHORIZED,
                "ISSUANCE_EXPIRED",
                "Binary issuance has expired. Contact support to renew.",
            );
        }
        if let Some(ref locked_mid) = issuance.locked_machine_id.clone() {
            if locked_mid != &req.machine_id {
                return err(
                    StatusCode::FORBIDDEN,
                    "MACHINE_MISMATCH",
                    "This binary issuance is locked to a different machine.",
                );
            }
        }

        let payment_ok = {
            let store = state.store.lock().unwrap();
            store.get_key_by_id(&issuance.key_id).map_or(false, |k| !k.revoked)
        };
        let tier_paid = {
            let sdb = state.surveillance_db.lock().unwrap();
            sdb.is_payment_active(&issuance.key_id)
        };
        if !payment_ok {
            return err(StatusCode::UNAUTHORIZED, "LICENSE_REVOKED", "License key has been revoked.");
        }
        let tier_lower = issuance.tier.to_lowercase();
        let requires_payment = !matches!(tier_lower.as_str(), "community" | "indie" | "dev");
        if requires_payment && !tier_paid {
            return err(StatusCode::PAYMENT_REQUIRED, "PAYMENT_REQUIRED",
                "Active subscription required to activate this tier. Visit the billing portal.");
        }

        let permissions = tier_permissions(&issuance.tier);
        let instance_id = format!("inst_{}", uuid::Uuid::new_v4().simple());
        let token = {
            let tm = state.token_manager.lock().unwrap();
            tm.issue(&instance_id, &req.binary_id, &req.machine_id, &issuance.tier, permissions.clone())
        };

        issuance.secret_id_used = true;
        issuance.auth_count += 1;
        issuance.active_token_ids.push(token.payload.tid.clone());
        let snap = issuance.clone();
        (snap, token, instance_id, permissions)
    }; // issuances guard dropped here

    // 4. Blocklist check (async — guard already dropped)
    if state.db.is_binary_blocked(&req.binary_hash).await {
        return err(StatusCode::FORBIDDEN, "BINARY_BLOCKED",
            "This binary has been flagged and blocked. Contact support.");
    }

    state.db.upsert_issuance(&issuance_snap).await;
    state.db.record_token_issued(&token.payload.tid, &instance_id, &req.binary_id, token.payload.exp).await;

    // 11. Register instance in surveillance
    {
        let mut sdb = state.surveillance_db.lock().unwrap();
        sdb.upsert_instance(crate::database::InstanceRecord {
            instance_id:           instance_id.clone(),
            key_id:                issuance_snap.key_id.clone(),
            customer_id:           derive_customer_id(&issuance_snap.key_id),
            machine_id:            req.machine_id.clone(),
            hostname:              String::new(),
            binary_hash:           req.binary_hash.clone(),
            binary_id:             req.binary_id.clone(),
            license_address:       String::new(),
            tier:                  issuance_snap.tier.clone(),
            permissions:           permissions.clone(),
            activated_at:          now.to_rfc3339(),
            last_heartbeat:        Some(now.to_rfc3339()),
            last_usage_report:     None,
            status:                crate::database::InstanceStatus::Active,
            agents_last:           0,
            packets_last:          0,
            trust_score_last:      0,
            total_tokens_lifetime: 0,
            total_cost_lifetime:   0.0,
            warnings_issued:       0,
            grace_period_ends:     None,
            kill_issued:           false,
        });
        if let Some(inst) = sdb.get_instance(&instance_id) {
            let inst_clone = inst.clone();
            let db2 = state.db.clone();
            tokio::spawn(async move { db2.upsert_instance(&inst_clone).await; });
        }
    }

    let ttl = crate::rpc_token::RpcTokenManager::ttl_remaining(&token.payload);

    ok(serde_json::json!({
        "token":        token.raw,
        "token_id":     token.payload.tid,
        "expires_in":   ttl,
        "expires_at":   token.payload.exp,
        "tier":         issuance_snap.tier,
        "permissions":  permissions,
        "instance_id":  instance_id,
        "binary_id":    req.binary_id,
        "renewal_url":  "/rpc/v1/renew",
        "issued_at":    now.to_rfc3339(),
    }))
}

/// POST /rpc/v1/renew
/// Renew an expiring RPC token (within 5-minute renewal window).
pub async fn rpc_renew(
    State(state): State<SharedState>,
    Json(req): Json<RenewRequest>,
) -> ApiResult {
    let new_token = {
        let tm = state.token_manager.lock().unwrap();
        match tm.renew(&req.token) {
            Ok(t) => t,
            Err(TokenError::NotYetRenewable) => return err(
                StatusCode::BAD_REQUEST,
                "NOT_YET_RENEWABLE",
                "Token still has more than 5 minutes remaining. Renew within the last 5 minutes.",
            ),
            Err(TokenError::Expired) => return err(
                StatusCode::UNAUTHORIZED,
                "TOKEN_EXPIRED",
                "Token has expired. Re-authenticate via /rpc/v1/auth.",
            ),
            Err(e) => return err(
                StatusCode::UNAUTHORIZED,
                "TOKEN_INVALID",
                &e.to_string(),
            ),
        }
    };

    let ttl = crate::rpc_token::RpcTokenManager::ttl_remaining(&new_token.payload);

    state.db.record_token_issued(
        &new_token.payload.tid,
        &new_token.payload.iid,
        &new_token.payload.bid,
        new_token.payload.exp,
    ).await;

    ok(serde_json::json!({
        "token":      new_token.raw,
        "token_id":   new_token.payload.tid,
        "expires_in": ttl,
        "expires_at": new_token.payload.exp,
    }))
}

/// POST /rpc/v1/revoke
/// Binary revokes its own token on clean shutdown.
pub async fn rpc_revoke(
    State(state): State<SharedState>,
    Json(req): Json<RevokeRequest>,
) -> ApiResult {
    // Parse token to get token_id (even if expired, we still allow revocation)
    let token_id = {
        let tm = state.token_manager.lock().unwrap();
        // Validate loosely (allow expired, only check signature)
        match tm.validate_for_revoke(&req.token) {
            Ok(payload) => payload.tid,
            Err(_) => return err(
                StatusCode::UNAUTHORIZED,
                "TOKEN_INVALID",
                "Cannot parse token for revocation.",
            ),
        }
    };

    {
        let mut tm = state.token_manager.lock().unwrap();
        tm.revoke(&token_id);
    }

    state.db.record_token_revoked(&token_id, req.reason.as_deref()).await;

    ok(serde_json::json!({
        "revoked":   true,
        "token_id":  token_id,
        "ts":        chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /rpc/v1/verify
/// Lightweight token validity probe — used by binary on each API call.
/// Returns 200 OK with remaining TTL, or 401/403.
pub async fn rpc_verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult {
    let token_str = match extract_rpc_token(&headers) {
        Some(t) => t,
        None => return err(
            StatusCode::UNAUTHORIZED,
            "NO_TOKEN",
            "Authorization: RpcToken <token> header required.",
        ),
    };

    let tm = state.token_manager.lock().unwrap();
    match tm.validate(&token_str) {
        Ok(payload) => {
            let ttl = crate::rpc_token::RpcTokenManager::ttl_remaining(&payload);
            ok(serde_json::json!({
                "valid":       true,
                "token_id":    payload.tid,
                "instance_id": payload.iid,
                "binary_id":   payload.bid,
                "tier":        payload.tier,
                "permissions": payload.perm,
                "expires_in":  ttl,
                "renewable":   ttl < 300,
            }))
        }
        Err(e) => err(
            StatusCode::UNAUTHORIZED,
            "TOKEN_INVALID",
            &e.to_string(),
        ),
    }
}

// ── Admin: issue binary issuance (called after payment confirmed) ─────────────

#[derive(Debug, Deserialize)]
pub struct IssueIssuanceRequest {
    pub key_id:            String,
    pub locked_machine_id: Option<String>,
    pub expires_at:        Option<String>,
}

/// POST /api/v1/issuances
/// Admin: generate a per-download binary issuance (role_id + one-time secret_id).
/// Called by billing webhook after payment confirmed.
pub async fn create_issuance(
    State(state): State<SharedState>,
    Json(req): Json<IssueIssuanceRequest>,
) -> ApiResult {
    let key = {
        let store = state.store.lock().unwrap();
        match store.get_key_by_id(&req.key_id) {
            Some(k) => k.clone(),
            None => return err(StatusCode::NOT_FOUND, "KEY_NOT_FOUND", "License key not found."),
        }
    }; // guard dropped
    if key.revoked {
        return err(StatusCode::FORBIDDEN, "KEY_REVOKED", "License key is revoked.");
    }

    let tier = format!("{:?}", key.tier);
    let issuance = crate::rpc_token::BinaryIssuance::generate(
        &req.key_id,
        &tier,
        req.locked_machine_id,
        req.expires_at,
    );

    state.db.upsert_issuance(&issuance).await;
    state.issuances.lock().unwrap().push(issuance.clone());

    ok(serde_json::json!({
        "binary_id":  issuance.binary_id,
        "role_id":    issuance.role_id,
        "secret_id":  issuance.secret_id,
        "tier":       issuance.tier,
        "issued_at":  issuance.issued_at,
        "expires_at": issuance.expires_at,
        "instructions": {
            "step1": "Embed role_id and secret_id in the installer for this specific download.",
            "step2": "Binary calls POST /rpc/v1/auth with (role_id, secret_id, machine_id, binary_hash).",
            "step3": "secret_id is consumed on first use — generate a new issuance for each download.",
            "warning": "NEVER share secret_id between binaries. Each download must have a unique one.",
        },
    }))
}

/// GET /api/v1/issuances/:binary_id
/// Admin: get issuance status for a specific binary.
pub async fn get_issuance(
    State(state): State<SharedState>,
    axum::extract::Path(binary_id): axum::extract::Path<String>,
) -> ApiResult {
    let issuances = state.issuances.lock().unwrap();
    match issuances.iter().find(|i| i.binary_id == binary_id) {
        Some(i) => ok(serde_json::json!({
            "binary_id":       i.binary_id,
            "role_id":         i.role_id,
            "key_id":          i.key_id,
            "tier":            i.tier,
            "secret_id_used":  i.secret_id_used,
            "auth_count":      i.auth_count,
            "issued_at":       i.issued_at,
            "expires_at":      i.expires_at,
            "locked_machine":  i.locked_machine_id.is_some(),
            "active_tokens":   i.active_token_ids.len(),
        })),
        None => err(StatusCode::NOT_FOUND, "NOT_FOUND", "Issuance not found."),
    }
}

// ── Middleware helper: extract RPC token from Authorization header ─────────────

pub fn extract_rpc_token(headers: &HeaderMap) -> Option<String> {
    headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("RpcToken ").or_else(|| v.strip_prefix("Bearer ")))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Middleware: validate RPC token and return 401/403 if invalid.
/// Used as a layer in the RPC route group.
pub fn require_rpc_token(
    headers: &HeaderMap,
    tm: &crate::rpc_token::RpcTokenManager,
) -> Result<crate::rpc_token::RpcTokenPayload, ApiResult> {
    let token_str = extract_rpc_token(headers).ok_or_else(|| err(
        StatusCode::UNAUTHORIZED,
        "NO_TOKEN",
        "RPC token required. Authenticate via POST /rpc/v1/auth first.",
    ))?;

    tm.validate(&token_str).map_err(|e| match e {
        TokenError::Expired => err(
            StatusCode::UNAUTHORIZED,
            "TOKEN_EXPIRED",
            "RPC token expired. Renew via POST /rpc/v1/renew.",
        ),
        TokenError::Revoked => err(
            StatusCode::FORBIDDEN,
            "TOKEN_REVOKED",
            "RPC token has been revoked.",
        ),
        e => err(
            StatusCode::UNAUTHORIZED,
            "TOKEN_INVALID",
            &e.to_string(),
        ),
    })
}

// ── Tier permission mapping ───────────────────────────────────────────────────

pub fn tier_permissions(tier: &str) -> Vec<String> {
    let base = vec!["heartbeat".into(), "usage_report".into(), "checkin".into()];
    match tier.to_lowercase().as_str() {
        "community" | "dev" => base,
        "indie" => {
            let mut p = base;
            p.extend(["agents:3".into(), "memory".into(), "actionlog".into()]);
            p
        }
        "startup" => {
            let mut p = base;
            p.extend(["agents:10".into(), "memory".into(), "actionlog".into(),
                       "compliance".into(), "experiments".into()]);
            p
        }
        "growth" => {
            let mut p = base;
            p.extend(["agents:50".into(), "memory".into(), "actionlog".into(),
                       "compliance".into(), "experiments".into(), "rag".into(),
                       "multi_agent".into()]);
            p
        }
        "business" => {
            let mut p = base;
            p.extend(["agents:200".into(), "full".into(), "sso".into(),
                       "multi_agent".into(), "knowledge_graph".into(), "pdf_export".into()]);
            p
        }
        "scale" => {
            let mut p = base;
            p.extend(["agents:500".into(), "full".into(), "sso".into(),
                       "multi_agent".into(), "knowledge_graph".into(), "pdf_export".into(),
                       "alerting".into(), "multi_cell".into()]);
            p
        }
        "enterprise" | "core" | "sovereign" => {
            vec!["full".into(), "unlimited".into(), "sso".into(), "on_premise".into(),
                 "air_gapped".into(), "dedicated_csm".into(), "custom_compliance".into()]
        }
        _ => base,
    }
}

fn derive_customer_id(key_id: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(b"customer:");
    h.update(key_id.as_bytes());
    format!("cust_{}", hex::encode(&h.finalize()[..8]))
}
