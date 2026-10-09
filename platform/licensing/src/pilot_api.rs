use axum::{extract::{Path, State}, Json};
use serde::{Deserialize, Serialize};
use crate::pilots::{PilotGrant, EffectiveEntitlement};
use crate::SharedState;

// ═══════════════════════════════════════════════════════════════
// Admin Pilot Grant APIs
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct CreatePilotRequest {
    pub customer_id: String,
    pub granted_by: String,
    pub expires_at: String,
    pub tier_override: Option<String>,
    pub agent_limit_override: Option<u32>,
    pub packet_limit_override: Option<u64>,
    pub features_override: Vec<String>,
    pub reason: String,
}

/// POST /api/v1/admin/pilots
/// Admin: Create a new pilot grant
pub async fn create_pilot(
    State(state): State<SharedState>,
    Json(req): Json<CreatePilotRequest>,
) -> Json<serde_json::Value> {
    let pilot = PilotGrant::new(
        req.customer_id,
        req.granted_by,
        req.expires_at,
        req.tier_override,
        req.agent_limit_override,
        req.packet_limit_override,
        req.features_override,
        req.reason,
    );

    state.db.upsert_pilot_grant(&pilot).await;

    Json(serde_json::json!({
        "success": true,
        "grant_id": pilot.grant_id,
        "pilot": pilot,
    }))
}

/// GET /api/v1/admin/pilots
/// Admin: List all pilot grants
pub async fn list_pilots(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let pilots = state.db.load_all_pilot_grants().await;
    let count = pilots.len();
    Json(serde_json::json!({
        "pilots": pilots,
        "count": count,
    }))
}

/// GET /api/v1/admin/pilots/:grant_id
/// Admin: Get specific pilot grant
pub async fn get_pilot(
    State(state): State<SharedState>,
    Path(grant_id): Path<String>,
) -> Json<serde_json::Value> {
    let pilots = state.db.load_all_pilot_grants().await;
    let pilot = pilots.iter().find(|p| p.grant_id == grant_id).cloned();

    match pilot {
        Some(ref p) => Json(serde_json::json!({ "pilot": p })),
        None => Json(serde_json::json!({ "error": "Pilot grant not found" })),
    }
}

/// DELETE /api/v1/admin/pilots/:grant_id
/// Admin: Expire a pilot grant
pub async fn expire_pilot(
    State(state): State<SharedState>,
    Path(grant_id): Path<String>,
) -> Json<serde_json::Value> {
    state.db.expire_pilot_grant(&grant_id).await;

    Json(serde_json::json!({
        "success": true,
        "grant_id": grant_id,
        "status": "Expired",
    }))
}

#[derive(Debug, Deserialize)]
pub struct RevokePilotRequest {
    pub reason: String,
}

/// POST /api/v1/admin/pilots/:grant_id/revoke
/// Admin: Revoke a pilot grant with reason
pub async fn revoke_pilot(
    State(state): State<SharedState>,
    Path(grant_id): Path<String>,
    Json(req): Json<RevokePilotRequest>,
) -> Json<serde_json::Value> {
    state.db.revoke_pilot_grant(&grant_id, &req.reason).await;

    Json(serde_json::json!({
        "success": true,
        "grant_id": grant_id,
        "status": "Revoked",
        "reason": req.reason,
    }))
}

/// GET /api/v1/admin/customers/:customer_id/pilots
/// Admin: Get all pilots for a specific customer
pub async fn get_customer_pilots(
    State(state): State<SharedState>,
    Path(customer_id): Path<String>,
) -> Json<serde_json::Value> {
    let all_pilots = state.db.load_all_pilot_grants().await;
    let customer_pilots: Vec<_> = all_pilots
        .into_iter()
        .filter(|p| p.customer_id == customer_id)
        .collect();

    Json(serde_json::json!({
        "customer_id": customer_id,
        "pilots": customer_pilots,
        "count": customer_pilots.len(),
    }))
}

// ═══════════════════════════════════════════════════════════════
// Customer Portal Pilot APIs
// ═══════════════════════════════════════════════════════════════

/// GET /api/v1/portal/pilot
/// Customer: Get my active pilot status
pub async fn my_pilot_status(
    State(state): State<SharedState>,
    // TODO: Extract customer_id from JWT auth
) -> Json<serde_json::Value> {
    // For now, return a placeholder - in production, extract from JWT
    let customer_id = "demo_customer";
    
    let active_pilot = state.db.get_active_pilot_for_customer(customer_id).await;

    match active_pilot {
        Some(pilot) => {
            let is_active = pilot.is_active();
            Json(serde_json::json!({
                "has_active_pilot": is_active,
                "pilot": pilot,
            }))
        }
        None => Json(serde_json::json!({
            "has_active_pilot": false,
            "pilot": null,
        })),
    }
}

/// GET /api/v1/portal/entitlement
/// Customer: Get effective entitlement (base tier + active pilot)
pub async fn my_entitlement(
    State(state): State<SharedState>,
    // TODO: Extract customer_id and base_tier from JWT auth
) -> Json<serde_json::Value> {
    // For now, use placeholders - in production, extract from JWT
    let customer_id = "demo_customer";
    let base_tier = "Indie";

    let mut entitlement = EffectiveEntitlement::from_base_tier(base_tier);
    
    if let Some(pilot) = state.db.get_active_pilot_for_customer(customer_id).await {
        if pilot.is_active() {
            entitlement.apply_pilot(pilot);
        }
    }

    Json(serde_json::json!({
        "entitlement": entitlement,
    }))
}
