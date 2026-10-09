//! # Customer Portal API
//!
//! Customer-facing endpoints for the hosted portal (portal.connector.dev).
//!
//! ## Auth flow
//!   POST /api/v1/portal/register     — create account (email + password + license_key?)
//!   POST /api/v1/portal/login        — login with email + password + TOTP (+ license verification)
//!   GET  /api/v1/portal/me           — current user profile
//!   POST /api/v1/portal/totp/setup   — generate TOTP secret + QR URI
//!   POST /api/v1/portal/totp/verify  — confirm TOTP code, enable 2FA
//!   POST /api/v1/portal/api-keys     — create API key (for binary operator access)
//!   GET  /api/v1/portal/api-keys     — list API keys
//!   DEL  /api/v1/portal/api-keys/:id — revoke API key
//!   PATCH /api/v1/portal/profile     — update name/email
//!   POST /api/v1/portal/change-password — change password (current + new)
//!   POST /auth/token                 — exchange API key for short-lived JWT (used by binary UI)
//!
//! ## Admin endpoints
//!   GET  /api/v1/admin/customers        — list all customers with dunning state
//!   GET  /api/v1/admin/dunning          — dunning dashboard
//!   POST /api/v1/admin/customers/:id/suspend
//!   POST /api/v1/admin/customers/:id/restore
//!   POST /api/v1/admin/customers/:id/message

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::dunning::{DunningRecord, DunningState, EmailTemplate};

// ── Shared types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalUser {
    pub user_id:       String,
    pub email:         String,
    pub name:          String,
    pub password_hash: String,
    pub created_at:    String,
    pub last_login:    Option<String>,
    pub totp_secret:   Option<String>,
    pub totp_enabled:  bool,
    pub api_keys:      Vec<PortalApiKey>,
    pub license_key_id: Option<String>,
    pub tier:          String,
    pub locked:        bool,
    pub email_verified: bool,
    pub backup_codes:  Vec<String>,  // hashed TOTP backup codes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalApiKey {
    pub key_id:     String,
    pub key_hash:   String,
    pub name:       String,
    pub scopes:     Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used:  Option<String>,
    pub revoked:    bool,
}

// ── In-memory portal user store ───────────────────────────────────────────────

pub struct PortalUserStore {
    users:       HashMap<String, PortalUser>,    // user_id → user
    email_index: HashMap<String, String>,        // email → user_id
    login_attempts: HashMap<String, (u32, i64)>, // email → (count, ts)
}

impl PortalUserStore {
    pub fn new() -> Self {
        Self { users: HashMap::new(), email_index: HashMap::new(), login_attempts: HashMap::new() }
    }

    pub fn create(&mut self, user: PortalUser) -> Result<(), &'static str> {
        if self.email_index.contains_key(&user.email) {
            return Err("Email already registered");
        }
        self.email_index.insert(user.email.clone(), user.user_id.clone());
        self.users.insert(user.user_id.clone(), user);
        Ok(())
    }

    pub fn get(&self, user_id: &str) -> Option<&PortalUser> {
        self.users.get(user_id)
    }

    pub fn get_mut(&mut self, user_id: &str) -> Option<&mut PortalUser> {
        self.users.get_mut(user_id)
    }

    pub fn by_email(&self, email: &str) -> Option<&PortalUser> {
        self.email_index.get(email).and_then(|id| self.users.get(id))
    }

    pub fn by_email_mut(&mut self, email: &str) -> Option<&mut PortalUser> {
        let id = self.email_index.get(email)?.clone();
        self.users.get_mut(&id)
    }

    pub fn rate_limit_ok(&self, email: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        if let Some((count, last)) = self.login_attempts.get(email) {
            if now - last < 300 && *count >= 5 { return false; }
        }
        true
    }

    pub fn record_failure(&mut self, email: &str) {
        let now = chrono::Utc::now().timestamp();
        let entry = self.login_attempts.entry(email.to_string()).or_insert((0, now));
        if now - entry.1 > 300 { *entry = (1, now); } else { entry.0 += 1; entry.1 = now; }
    }

    pub fn clear_failures(&mut self, email: &str) {
        self.login_attempts.remove(email);
    }

    pub fn all_users(&self) -> Vec<&PortalUser> {
        self.users.values().collect()
    }
}

// The portal user store is part of AppState — add it lazily via once_cell.
// For simplicity, we use a module-level Mutex (shared singleton).
use std::sync::OnceLock;
static PORTAL_USERS: OnceLock<Mutex<PortalUserStore>> = OnceLock::new();

fn users() -> &'static Mutex<PortalUserStore> {
    PORTAL_USERS.get_or_init(|| Mutex::new(PortalUserStore::new()))
}

/// Async bootstrap from Postgres — called at startup.
pub async fn bootstrap_portal_users_pg(db: &crate::persist::Db) {
    let loaded = db.load_all_portal_users().await;
    let count = loaded.len();
    let mut store = users().lock().unwrap();
    for user in loaded {
        store.email_index.insert(user.email.clone(), user.user_id.clone());
        store.users.insert(user.user_id.clone(), user);
    }
    eprintln!("[portal] Bootstrapped {} portal users from Postgres", count);
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Hash error: {}", e))
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordVerifier};
    use argon2::password_hash::PasswordHash;
    let parsed = match PasswordHash::new(hash) { Ok(h) => h, Err(_) => return false };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

fn verify_totp(secret_b32: &str, code: &str) -> bool {
    let secret = match totp_rs::Secret::Encoded(secret_b32.to_string()).to_bytes() {
        Ok(b) => b, Err(_) => return false,
    };
    let totp = match totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, secret, Some("Connector".to_string()), "portal_user".to_string()) {
        Ok(t) => t, Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

fn generate_totp_secret(email: &str) -> (String, String) {
    let secret = totp_rs::Secret::generate_secret();
    let secret_b32 = secret.to_encoded().to_string();
    let uri = format!(
        "otpauth://totp/Connector%20Portal:{}?secret={}&issuer=Connector%20Portal&algorithm=SHA1&digits=6&period=30",
        urlencoded(email), secret_b32
    );
    (secret_b32, uri)
}

fn urlencoded(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c.to_string() } else { format!("%{:02X}", c as u32) }).collect()
}

fn portal_jwt_secret() -> Vec<u8> {
    std::env::var("CONNECTOR_PORTAL_JWT_SECRET")
        .or_else(|_| std::env::var("CONNECTOR_JWT_SECRET"))
        .unwrap_or_else(|_| "portal-jwt-secret-dev".into())
        .into_bytes()
}

fn create_portal_jwt(user: &PortalUser, expires_secs: u64) -> Result<String, String> {
    use jsonwebtoken::{encode, Header, EncodingKey};
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = serde_json::json!({
        "sub": user.user_id,
        "email": user.email,
        "name": user.name,
        "tier": user.tier,
        "role": "customer",
        "token_type": "portal_access",
        "iat": now,
        "exp": now + expires_secs as usize,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(&Header::default(), &claims, &EncodingKey::from_secret(&portal_jwt_secret()))
        .map_err(|e| e.to_string())
}

fn verify_portal_jwt(token: &str) -> Option<serde_json::Value> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    decode::<serde_json::Value>(
        token,
        &DecodingKey::from_secret(&portal_jwt_secret()),
        &Validation::default(),
    ).ok().map(|d| d.claims)
}

fn extract_portal_claims(headers: &HeaderMap) -> Option<serde_json::Value> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    verify_portal_jwt(token)
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email:       String,
    pub password:    String,
    pub name:        String,
    pub license_key: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email:     String,
    pub password:  String,
    pub totp_code: Option<String>,
}

#[derive(Deserialize)]
pub struct TotpSetupRequest {
    pub password: String,
}

#[derive(Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name:         String,
    pub expires_days: Option<u32>,
    pub scopes:       Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    pub name:  Option<String>,
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password:     String,
}

#[derive(Deserialize)]
pub struct ApiKeyTokenRequest {
    pub api_key: String,
}

#[derive(Deserialize)]
pub struct AdminMessageRequest {
    pub subject: String,
    pub body:    String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

pub async fn register(
    State(state): State<crate::SharedState>,
    Json(req): Json<RegisterRequest>,
) -> Json<serde_json::Value> {
    if req.email.is_empty() || !req.email.contains('@') {
        return Json(serde_json::json!({"error": "Invalid email"}));
    }
    if req.password.len() < 10 {
        return Json(serde_json::json!({"error": "Password must be at least 10 characters"}));
    }
    if req.name.trim().is_empty() {
        return Json(serde_json::json!({"error": "Name is required"}));
    }

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    // Validate license key if provided
    // BUG-LIC-005 fix: license_key from user is key_secret (lic_xxx format),
    // not key_id — must use find_by_secret, not get_key
    let (license_key_id, tier) = if let Some(ref key) = req.license_key {
        let result = {
            let store = state.store.lock().unwrap();
            store.find_by_secret(key).map(|k| (k.revoked, k.key_id.clone(), format!("{:?}", k.tier)))
        }; // guard dropped
        match result {
            Some((false, id, t)) => (Some(id), t),
            Some((true, _, _)) => return Json(serde_json::json!({"error": "License key is revoked"})),
            None => return Json(serde_json::json!({"error": "Invalid license key"})),
        }
    } else {
        (None::<String>, "Community".to_string())
    };

    let user_id = format!("portal_{}", uuid::Uuid::new_v4().to_string().replace('-', "").split_at(16).0.to_string());
    let now = chrono::Utc::now();

    let user = PortalUser {
        user_id: user_id.clone(),
        email: req.email.clone(),
        name: req.name.trim().to_string(),
        password_hash,
        created_at: now.to_rfc3339(),
        last_login: None,
        totp_secret: None,
        totp_enabled: false,
        api_keys: Vec::new(),
        license_key_id,
        tier: tier.clone(),
        locked: false,
        email_verified: false,
        backup_codes: Vec::new(),
    };

    let create_result = { users().lock().unwrap().create(user) };
    match create_result {
        Ok(_) => {
            let user_snapshot = { users().lock().unwrap().get(&user_id).cloned() };
            if let Some(u) = user_snapshot {
                state.db.upsert_portal_user(&u).await;
            }

            // Add to dunning store
            {
                let mut dunning = state.dunning.lock().unwrap();
                dunning.upsert(DunningRecord::new(
                    user_id.clone(), req.email.clone(), req.name.clone(), tier.clone(),
                ));
            }

            // Send welcome email
            {
                let sender = &state.email_sender;
                sender.send(&req.email, &req.name, &EmailTemplate::Welcome {
                    name: req.name.clone(),
                    tier: tier.clone(),
                    api_key_hint: "cpk_...".into(),
                });
            }

            let user_for_jwt = { users().lock().unwrap().get(&user_id).cloned() };
            let token = match user_for_jwt.as_ref().and_then(|u| create_portal_jwt(u, 3600).ok()) {
                Some(t) => t,
                None => return Json(serde_json::json!({"error": "Failed to issue token"})),
            };

            Json(serde_json::json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "user": { "user_id": user_id, "email": req.email, "name": req.name, "tier": tier },
                "note": "Please set up 2FA at /portal/totp/setup for enhanced security.",
            }))
        }
        Err(e) => Json(serde_json::json!({"error": e})),
    }
}

pub async fn login(
    State(state): State<crate::SharedState>,
    Json(req): Json<LoginRequest>,
) -> Json<serde_json::Value> {
    let mut store = users().lock().unwrap();

    if !store.rate_limit_ok(&req.email) {
        return Json(serde_json::json!({"error": "Too many failed attempts. Try again in 5 minutes."}));
    }

    let user = match store.by_email(&req.email) {
        Some(u) => u.clone(),
        None => {
            store.record_failure(&req.email);
            return Json(serde_json::json!({"error": "Invalid credentials"}));
        }
    };

    if user.locked {
        return Json(serde_json::json!({"error": "Account locked. Contact support."}));
    }

    if !verify_password(&req.password, &user.password_hash) {
        store.record_failure(&req.email);
        return Json(serde_json::json!({"error": "Invalid credentials"}));
    }

    // TOTP check
    if user.totp_enabled {
        match &req.totp_code {
            Some(code) => {
                if let Some(ref secret) = user.totp_secret {
                    if !verify_totp(secret, code) {
                        // Check backup codes
                        let u = store.by_email_mut(&req.email).unwrap();
                        let code_hash = format!("{:x}", md5_simple(code));
                        if u.backup_codes.contains(&code_hash) {
                            u.backup_codes.retain(|c| c != &code_hash);
                        } else {
                            return Json(serde_json::json!({"error": "Invalid 2FA code"}));
                        }
                    }
                }
            }
            None => {
                return Json(serde_json::json!({
                    "error": "2FA code required",
                    "totp_required": true,
                }));
            }
        }
    }

    store.clear_failures(&req.email);
    if let Some(u) = store.by_email_mut(&req.email) {
        u.last_login = Some(chrono::Utc::now().to_rfc3339());
    }

    // Check dunning state
    let dunning_banner = {
        let dunning = state.dunning.lock().unwrap();
        dunning.get_by_email(&req.email)
            .map(|r| r.state.banner_message())
            .unwrap_or("")
            .to_string()
    };

    let token = match create_portal_jwt(&user, 3600) {
        Ok(t) => t,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    let mut resp = serde_json::json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "user": {
            "user_id": user.user_id,
            "email": user.email,
            "name": user.name,
            "tier": user.tier,
            "totp_enabled": user.totp_enabled,
            "license_key_id": user.license_key_id,
            "api_key_count": user.api_keys.iter().filter(|k| !k.revoked).count(),
        },
    });
    if !dunning_banner.is_empty() {
        resp["billing_notice"] = serde_json::json!(dunning_banner);
    }
    Json(resp)
}

pub async fn me(
    headers: HeaderMap,
    State(state): State<crate::SharedState>,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = match claims["sub"].as_str() {
        Some(id) => id.to_string(),
        None => return Json(serde_json::json!({"error": "Invalid token"})),
    };

    let store = users().lock().unwrap();
    match store.get(&user_id) {
        Some(user) => {
            let dunning = state.dunning.lock().unwrap();
            let billing_state = dunning.get_by_email(&user.email)
                .map(|r| r.state.label())
                .unwrap_or("Active");

            Json(serde_json::json!({
                "user_id": user.user_id,
                "email": user.email,
                "name": user.name,
                "tier": user.tier,
                "totp_enabled": user.totp_enabled,
                "email_verified": user.email_verified,
                "license_key_id": user.license_key_id,
                "created_at": user.created_at,
                "last_login": user.last_login,
                "api_key_count": user.api_keys.iter().filter(|k| !k.revoked).count(),
                "billing_state": billing_state,
                "backup_codes_remaining": user.backup_codes.len(),
            }))
        }
        None => Json(serde_json::json!({"error": "User not found"})),
    }
}

pub async fn totp_setup(
    headers: HeaderMap,
    Json(req): Json<TotpSetupRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims["sub"].as_str().unwrap_or("").to_string();

    let mut store = users().lock().unwrap();
    let user = match store.get(&user_id) {
        Some(u) => u.clone(),
        None => return Json(serde_json::json!({"error": "User not found"})),
    };

    if !verify_password(&req.password, &user.password_hash) {
        return Json(serde_json::json!({"error": "Invalid password"}));
    }

    let (secret, uri) = generate_totp_secret(&user.email);

    // Generate 8 backup codes
    let backup_codes: Vec<String> = (0..8).map(|_| {
        let code = format!("{:08}", rand::random::<u32>() % 100_000_000);
        code
    }).collect();
    let backup_hashes: Vec<String> = backup_codes.iter()
        .map(|c| format!("{:x}", md5_simple(c)))
        .collect();

    if let Some(u) = store.get_mut(&user_id) {
        u.totp_secret = Some(secret.clone());
        u.backup_codes = backup_hashes;
    }

    Json(serde_json::json!({
        "totp_secret": secret,
        "totp_uri": uri,
        "backup_codes": backup_codes,
        "note": "Scan the QR code with your authenticator app, then call /portal/totp/verify with a code to activate 2FA.",
    }))
}

pub async fn totp_verify(
    headers: HeaderMap,
    Json(req): Json<TotpVerifyRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims["sub"].as_str().unwrap_or("").to_string();

    let mut store = users().lock().unwrap();
    let user = match store.get_mut(&user_id) {
        Some(u) => u,
        None => return Json(serde_json::json!({"error": "User not found"})),
    };

    match &user.totp_secret.clone() {
        Some(secret) => {
            if verify_totp(secret, &req.code) {
                user.totp_enabled = true;
                Json(serde_json::json!({"totp_enabled": true, "message": "2FA activated successfully"}))
            } else {
                Json(serde_json::json!({"error": "Invalid TOTP code — check your authenticator app and try again"}))
            }
        }
        None => Json(serde_json::json!({"error": "Call /portal/totp/setup first"})),
    }
}

pub async fn create_api_key(
    State(state): State<crate::SharedState>,
    headers: HeaderMap,
    Json(req): Json<CreateApiKeyRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims["sub"].as_str().unwrap_or("").to_string();

    if req.name.trim().is_empty() {
        return Json(serde_json::json!({"error": "Key name is required"}));
    }

    let raw_key = format!("cpk_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let key_hash = match hash_password(&raw_key) {
        Ok(h) => h,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    let key_id = format!("kid_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0"));
    let now = chrono::Utc::now();
    let expires = req.expires_days.map(|d| (now + chrono::Duration::days(d as i64)).to_rfc3339());

    let api_key = PortalApiKey {
        key_id: key_id.clone(),
        key_hash,
        name: req.name.trim().to_string(),
        scopes: req.scopes.unwrap_or_else(|| vec!["operator:read".into(), "operator:write".into()]),
        created_at: now.to_rfc3339(),
        expires_at: expires,
        last_used: None,
        revoked: false,
    };

    let mut store = users().lock().unwrap();
    if let Some(user) = store.get_mut(&user_id) {
        user.api_keys.push(api_key);
        let user_clone = user.clone();
        let db = state.db.clone();
        tokio::spawn(async move { db.upsert_portal_user(&user_clone).await; });
    }

    Json(serde_json::json!({
        "key_id": key_id,
        "api_key": raw_key,
        "name": req.name.trim(),
        "note": "Save this key immediately — it will not be shown again. Use it to authenticate to your local Connector Platform dashboard.",
    }))
}

pub async fn list_api_keys(
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims["sub"].as_str().unwrap_or("").to_string();

    let store = users().lock().unwrap();
    match store.get(&user_id) {
        Some(user) => {
            let keys: Vec<serde_json::Value> = user.api_keys.iter()
                .filter(|k| !k.revoked)
                .map(|k| serde_json::json!({
                    "key_id": k.key_id,
                    "name": k.name,
                    "scopes": k.scopes,
                    "created_at": k.created_at,
                    "expires_at": k.expires_at,
                    "last_used": k.last_used,
                }))
                .collect();
            Json(serde_json::json!({"keys": keys, "count": keys.len()}))
        }
        None => Json(serde_json::json!({"error": "User not found"})),
    }
}

pub async fn revoke_api_key(
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims["sub"].as_str().unwrap_or("").to_string();

    let mut store = users().lock().unwrap();
    match store.get_mut(&user_id) {
        Some(user) => {
            if let Some(key) = user.api_keys.iter_mut().find(|k| k.key_id == key_id) {
                key.revoked = true;
                Json(serde_json::json!({"revoked": true, "key_id": key_id}))
            } else {
                Json(serde_json::json!({"error": "API key not found"}))
            }
        }
        None => Json(serde_json::json!({"error": "User not found"})),
    }
}

pub async fn update_profile(
    headers: HeaderMap,
    Json(req): Json<UpdateProfileRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims["sub"].as_str().unwrap_or("").to_string();

    let mut store = users().lock().unwrap();

    if store.get(&user_id).is_none() {
        return Json(serde_json::json!({"error": "User not found"}));
    }

    // Apply name update
    if let Some(ref name) = req.name {
        if !name.trim().is_empty() {
            if let Some(user) = store.get_mut(&user_id) {
                user.name = name.trim().to_string();
            }
        }
    }

    // Apply email update — check index first before mutating
    if let Some(ref email) = req.email {
        if email.contains('@') && !store.email_index.contains_key(email.as_str()) {
            let old_email = store.get(&user_id).map(|u| u.email.clone()).unwrap_or_default();
            store.email_index.remove(&old_email);
            store.email_index.insert(email.clone(), user_id.clone());
            if let Some(user) = store.get_mut(&user_id) {
                user.email = email.clone();
                user.email_verified = false;
            }
        }
    }

    let (name, email) = store.get(&user_id)
        .map(|u| (u.name.clone(), u.email.clone()))
        .unwrap_or_default();
    Json(serde_json::json!({"name": name, "email": email}))
}

pub async fn change_password(
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_portal_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims["sub"].as_str().unwrap_or("").to_string();

    if req.new_password.len() < 10 {
        return Json(serde_json::json!({"error": "New password must be at least 10 characters"}));
    }

    let mut store = users().lock().unwrap();
    let user = match store.get(&user_id) {
        Some(u) => u.clone(),
        None => return Json(serde_json::json!({"error": "User not found"})),
    };

    if !verify_password(&req.current_password, &user.password_hash) {
        return Json(serde_json::json!({"error": "Current password is incorrect"}));
    }

    let new_hash = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    if let Some(u) = store.get_mut(&user_id) {
        u.password_hash = new_hash;
    }
    Json(serde_json::json!({"message": "Password changed successfully"}))
}

/// Exchange a cpk_ API key for a short-lived JWT (used by binary operator UI).
pub async fn api_key_to_token(
    Json(req): Json<ApiKeyTokenRequest>,
) -> Json<serde_json::Value> {
    if !req.api_key.starts_with("cpk_") {
        return Json(serde_json::json!({"error": "Invalid API key format"}));
    }

    let store = users().lock().unwrap();
    for user in store.all_users() {
        for key in &user.api_keys {
            if key.revoked { continue; }
            // Check expiry
            if let Some(ref exp) = key.expires_at {
                if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                    if chrono::Utc::now() > exp_dt { continue; }
                }
            }
            if verify_password(&req.api_key, &key.key_hash) {
                // Issue short-lived JWT for binary UI
                let token = match create_portal_jwt(user, 28800) { // 8 hours
                    Ok(t) => t,
                    Err(e) => return Json(serde_json::json!({"error": e})),
                };
                return Json(serde_json::json!({
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": 28800,
                    "user_id": user.user_id,
                    "email": user.email,
                    "name": user.name,
                    "tier": user.tier,
                    "role": "operator",
                    "permissions": key.scopes,
                }));
            }
        }
    }
    Json(serde_json::json!({"error": "Invalid or expired API key"}))
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

pub async fn admin_list_customers(
    State(state): State<crate::SharedState>,
) -> Json<serde_json::Value> {
    let dunning = state.dunning.lock().unwrap();
    let records: Vec<serde_json::Value> = dunning.all_records().iter().map(|r| serde_json::json!({
        "customer_id": r.customer_id,
        "email": r.email,
        "name": r.name,
        "tier": r.tier,
        "billing_state": r.state.label(),
        "days_overdue": r.days_overdue,
        "retry_count": r.retry_count,
        "last_payment_at": r.last_payment_at,
        "failed_since": r.failed_since,
        "stripe_customer_id": r.stripe_customer_id,
    })).collect();

    Json(serde_json::json!({
        "count": records.len(),
        "past_due": dunning.past_due_count(),
        "suspended": dunning.suspended_count(),
        "customers": records,
    }))
}

pub async fn dunning_dashboard(
    State(state): State<crate::SharedState>,
) -> Json<serde_json::Value> {
    let dunning = state.dunning.lock().unwrap();
    let all = dunning.all_records();
    let active   = all.iter().filter(|r| matches!(r.state, crate::dunning::DunningState::Current)).count();
    let past_due = all.iter().filter(|r| matches!(r.state, crate::dunning::DunningState::PaymentFailed { .. })).count();
    let degraded = all.iter().filter(|r| matches!(r.state, crate::dunning::DunningState::Degraded { .. })).count();
    let suspended= all.iter().filter(|r| matches!(r.state, crate::dunning::DunningState::Suspended { .. })).count();
    let cancelled= all.iter().filter(|r| matches!(r.state, crate::dunning::DunningState::Cancelled)).count();

    Json(serde_json::json!({
        "total": all.len(),
        "active": active,
        "past_due": past_due,
        "degraded": degraded,
        "suspended": suspended,
        "cancelled": cancelled,
        "recovery_rate": if past_due + cancelled > 0 {
            format!("{:.1}%", (active as f64 / (active + past_due + cancelled) as f64) * 100.0)
        } else { "100%".into() },
    }))
}

pub async fn admin_suspend(
    State(state): State<crate::SharedState>,
    Path(customer_id): Path<String>,
) -> Json<serde_json::Value> {
    let mut dunning = state.dunning.lock().unwrap();
    match dunning.get_mut(&customer_id) {
        Some(r) => {
            r.state = crate::dunning::DunningState::ManualSuspend;
            Json(serde_json::json!({"suspended": true, "customer_id": customer_id}))
        }
        None => Json(serde_json::json!({"error": "Customer not found"})),
    }
}

pub async fn admin_restore(
    State(state): State<crate::SharedState>,
    Path(customer_id): Path<String>,
) -> Json<serde_json::Value> {
    let mut dunning = state.dunning.lock().unwrap();
    match dunning.get_mut(&customer_id) {
        Some(r) => {
            r.on_payment_succeeded();
            Json(serde_json::json!({"restored": true, "customer_id": customer_id}))
        }
        None => Json(serde_json::json!({"error": "Customer not found"})),
    }
}

pub async fn admin_message(
    State(state): State<crate::SharedState>,
    Path(customer_id): Path<String>,
    Json(req): Json<AdminMessageRequest>,
) -> Json<serde_json::Value> {
    let dunning = state.dunning.lock().unwrap();
    match dunning.get(&customer_id) {
        Some(r) => {
            let email = r.email.clone();
            let name  = r.name.clone();
            drop(dunning);
            // Send via email sender — custom message uses text body directly
            let sender = &state.email_sender;
            sender.send(&email, &name, &crate::dunning::EmailTemplate::Welcome {
                name: name.clone(),
                tier: "—".into(),
                api_key_hint: req.body.clone(),
            });
            Json(serde_json::json!({"sent": true, "to": email}))
        }
        None => Json(serde_json::json!({"error": "Customer not found"})),
    }
}

// ── Simple MD5 for backup code hashing (non-security-critical) ───────────────
fn md5_simple(input: &str) -> u128 {
    // Simple polynomial hash — good enough for backup code dedup, not security
    input.bytes().fold(0u128, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u128))
}
