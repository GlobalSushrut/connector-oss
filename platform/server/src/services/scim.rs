//! Thin SCIM 2.0 over the existing user_store (I1). Not an IdP. OIDC remains SSO.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{hash_password, PlatformRole, User};
use crate::services::agents::caller;
use crate::state::SharedState;

const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCHEMA_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCHEMA_ERR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

fn admin(headers: &HeaderMap) -> Result<(), Value> {
    let Some((_, role)) = caller(headers) else {
        return Err(json!({
            "schemas": [SCHEMA_ERR],
            "status": "401",
            "detail": "auth_required"
        }));
    };
    if role.rank() < 5 {
        return Err(json!({
            "schemas": [SCHEMA_ERR],
            "status": "403",
            "detail": "admin_required"
        }));
    }
    Ok(())
}

fn to_scim(u: &User) -> Value {
    json!({
        "schemas": [SCHEMA_USER],
        "id": u.user_id,
        "userName": u.email,
        "displayName": u.name,
        "active": !u.locked,
        "emails": [{ "value": u.email, "primary": true }],
        "meta": {
            "resourceType": "User",
            "created": u.created_at,
        },
        "roles": [{ "value": u.role.to_str() }],
        "honesty": "Connector user_store. Not Okta. SSO is /auth/sso."
    })
}

/// GET /scim/v2/ServiceProviderConfig
pub async fn service_provider_config() -> Json<Value> {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "AIOS_CLAIM_PLAN.md I1 — fold onto user_store",
        "patch": { "supported": true },
        "bulk": { "supported": false },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Same Bearer as GET /auth/users (admin)"
        }],
        "honesty": "Thin SCIM. OIDC is still SSO. Default install may still use API keys."
    }))
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub filter: Option<String>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<usize>,
    pub count: Option<usize>,
}

/// GET /scim/v2/Users
pub async fn list_users(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Json<Value> {
    if let Err(e) = admin(&headers) {
        return Json(e);
    }
    let store = state.user_store.lock().unwrap();
    let mut resources: Vec<Value> = store.users.values().map(to_scim).collect();
    if let Some(f) = q.filter.as_deref() {
        let f = f.to_ascii_lowercase();
        resources.retain(|u| {
            u["userName"]
                .as_str()
                .map(|s| {
                    s.to_ascii_lowercase()
                        .contains(&f.replace("username eq ", "").replace('"', ""))
                })
                .unwrap_or(false)
                || format!("{u}").to_ascii_lowercase().contains(&f)
        });
    }
    let total = resources.len();
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(200).min(200);
    let skip = start.saturating_sub(1);
    let page: Vec<Value> = resources.into_iter().skip(skip).take(count).collect();
    Json(json!({
        "schemas": [SCHEMA_LIST],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": page.len(),
        "Resources": page,
    }))
}

/// GET /scim/v2/Users/:id
pub async fn get_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if let Err(e) = admin(&headers) {
        return Json(e);
    }
    let store = state.user_store.lock().unwrap();
    match store.users.get(&id) {
        Some(u) => Json(to_scim(u)),
        None => Json(json!({
            "schemas": [SCHEMA_ERR],
            "status": "404",
            "detail": "not_found"
        })),
    }
}

/// POST /scim/v2/Users — provision into user_store (same as signup, admin-only).
pub async fn create_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    if let Err(e) = admin(&headers) {
        return Json(e);
    }
    let email = body
        .get("userName")
        .and_then(|v| v.as_str())
        .or_else(|| body.pointer("/emails/0/value").and_then(|v| v.as_str()))
        .unwrap_or("")
        .trim()
        .to_string();
    let name = body
        .get("displayName")
        .and_then(|v| v.as_str())
        .unwrap_or(email.as_str())
        .to_string();
    if email.is_empty() || !email.contains('@') {
        return Json(json!({
            "schemas": [SCHEMA_ERR],
            "status": "400",
            "detail": "userName_email_required"
        }));
    }
    let pw = body
        .get("password")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("Scim.{}_", uuid::Uuid::new_v4().simple()));
    let password_hash = match hash_password(&pw) {
        Ok(h) => h,
        Err(e) => {
            return Json(json!({
                "schemas": [SCHEMA_ERR],
                "status": "500",
                "detail": e
            }))
        }
    };
    let user_id = format!("usr_{}", uuid::Uuid::new_v4());
    let user = User {
        user_id: user_id.clone(),
        email: email.clone(),
        name,
        password_hash,
        role: PlatformRole::Developer,
        created_at: chrono::Utc::now().to_rfc3339(),
        last_login: None,
        totp_secret: None,
        totp_enabled: false,
        api_keys: Vec::new(),
        locked: false,
        failed_attempts: 0,
        instance_id: None,
        tier: "community".into(),
        billing_state: "active".into(),
        stripe_customer_id: None,
        tokens_used_today: 0,
        tokens_used_month: 0,
        agents_count: 0,
        tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
    };
    let mut store = state.user_store.lock().unwrap();
    if let Err(e) = store.create_user(user) {
        return Json(json!({
            "schemas": [SCHEMA_ERR],
            "status": "409",
            "detail": e
        }));
    }
    {
        let mut es = state.engine_store.lock().unwrap();
        store.persist_user(&user_id, &mut **es);
    }
    let scim = store
        .users
        .get(&user_id)
        .map(to_scim)
        .unwrap_or(json!({ "id": user_id }));
    Json(scim)
}

/// PATCH /scim/v2/Users/:id — active false locks; true unlocks.
pub async fn patch_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    if let Err(e) = admin(&headers) {
        return Json(e);
    }
    let mut active: Option<bool> = body.get("active").and_then(|v| v.as_bool());
    if active.is_none() {
        if let Some(ops) = body.get("Operations").and_then(|v| v.as_array()) {
            for op in ops {
                let path = op.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path.eq_ignore_ascii_case("active") {
                    active = op.get("value").and_then(|v| v.as_bool());
                }
            }
        }
    }
    let mut store = state.user_store.lock().unwrap();
    let Some(user) = store.users.get_mut(&id) else {
        return Json(json!({
            "schemas": [SCHEMA_ERR],
            "status": "404",
            "detail": "not_found"
        }));
    };
    if let Some(a) = active {
        user.locked = !a;
    }
    let out = to_scim(user);
    {
        let mut es = state.engine_store.lock().unwrap();
        store.persist_user(&id, &mut **es);
    }
    Json(out)
}

/// DELETE /scim/v2/Users/:id — lock + revoke API keys (compensating deprovision).
pub async fn delete_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if let Err(e) = admin(&headers) {
        return Json(e);
    }
    let mut store = state.user_store.lock().unwrap();
    let Some(user) = store.users.get_mut(&id) else {
        return Json(json!({
            "schemas": [SCHEMA_ERR],
            "status": "404",
            "detail": "not_found"
        }));
    };
    user.locked = true;
    for k in &mut user.api_keys {
        k.revoked = true;
    }
    {
        let mut es = state.engine_store.lock().unwrap();
        store.persist_user(&id, &mut **es);
    }
    Json(json!({
        "ok": true,
        "id": id,
        "active": false,
        "honesty": "Locked + keys revoked. Not world rewind."
    }))
}
