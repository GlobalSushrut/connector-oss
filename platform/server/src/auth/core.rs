use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Algorithm, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::services::runtime_control;

// ═══════════════════════════════════════════════════════════════
// JWT Claims + Token Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,         // user_id
    pub email: String,
    pub role: String,        // PlatformRole
    pub permissions: Vec<String>,
    pub instance_id: Option<String>,
    /// Set when `CONNECTOR_MULTI_TENANT` or per-user tenant binding is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub token_type: String,  // "access" | "refresh" | "api_key"
    pub jti: String,         // unique token id (for revocation)
    pub iat: usize,
    pub exp: usize,
}

impl From<&Claims> for connector_trust::PrincipalContextV2 {
    fn from(c: &Claims) -> Self {
        connector_trust::PrincipalContextV2::from_verified_claims(
            c.sub.clone(),
            c.email.clone(),
            c.role.clone(),
            c.permissions.clone(),
            c.tenant_id.clone(),
            Some(c.jti.clone()),
            c.token_type.clone(),
            c.instance_id.clone(),
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// RBAC — 6 platform roles with granular permissions
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformRole {
    SuperAdmin,  // full access + user management + license management
    Admin,       // full access to all services
    Operator,    // read/write to services, no user management
    Developer,   // read/write to most services, no admin
    Viewer,      // read-only access
    Service,     // machine-to-machine API key (specific scopes)
}

impl PlatformRole {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "super_admin" | "superadmin" => PlatformRole::SuperAdmin,
            "admin" => PlatformRole::Admin,
            "operator" => PlatformRole::Operator,
            "developer" | "dev" => PlatformRole::Developer,
            "viewer" | "readonly" => PlatformRole::Viewer,
            "service" | "api" => PlatformRole::Service,
            _ => PlatformRole::Viewer,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            PlatformRole::SuperAdmin => "super_admin",
            PlatformRole::Admin => "admin",
            PlatformRole::Operator => "operator",
            PlatformRole::Developer => "developer",
            PlatformRole::Viewer => "viewer",
            PlatformRole::Service => "service",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            PlatformRole::SuperAdmin => 6,
            PlatformRole::Admin => 5,
            PlatformRole::Operator => 4,
            PlatformRole::Developer => 3,
            PlatformRole::Viewer => 2,
            PlatformRole::Service => 1,
        }
    }

    pub fn permissions(&self) -> Vec<String> {
        let mut perms = vec!["health:read".into(), "metrics:read".into()];
        if self.rank() >= 2 {
            perms.extend(["monitor:read", "history:read", "proof:read", "debug:read",
                           "memory:read", "experiments:read", "actionlog:read",
                           "disputes:read", "pipeline:read", "insights:read",
                           "license:read", "tools:read", "agents:read", "plugins:read",
                           "workflows:read"]
                .iter()
                .map(|s| s.to_string()));
        }
        if self.rank() >= 3 {
            perms.extend(["memory:write", "experiments:write", "tools:write",
                           "multiagent:write", "pipeline:write"].iter().map(|s| s.to_string()));
        }
        if self.rank() >= 4 {
            perms.extend(["actionlog:write", "disputes:write", "debug:write",
                           "proof:write", "history:write", "agents:write", "plugins:write",
                           "workflows:write"]
                .iter()
                .map(|s| s.to_string()));
        }
        if self.rank() >= 5 {
            perms.extend(["users:read", "users:write", "license:write",
                           "monitor:write", "insights:write"].iter().map(|s| s.to_string()));
        }
        if self.rank() >= 6 {
            perms.extend(["users:delete", "license:admin", "system:admin",
                           "rbac:admin", "keys:admin"].iter().map(|s| s.to_string()));
        }
        perms
    }
}

// ═══════════════════════════════════════════════════════════════
// User model — Argon2 hashed passwords, TOTP, API keys
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,  // Argon2id
    pub role: PlatformRole,
    pub created_at: String,
    pub last_login: Option<String>,
    pub totp_secret: Option<String>,   // TOTP 2FA secret (base32)
    pub totp_enabled: bool,
    pub api_keys: Vec<ApiKey>,
    pub locked: bool,
    pub failed_attempts: u32,
    pub instance_id: Option<String>,   // bound license instance
    // D6 / BIZ-6: billing fields
    #[serde(default = "default_tier")]
    pub tier: String,                          // community | pro | team | enterprise
    #[serde(default = "default_billing_state")]
    pub billing_state: String,                 // active | degraded | suspended | cancelled
    #[serde(default)]
    pub stripe_customer_id: Option<String>,
    #[serde(default)]
    pub tokens_used_today: u64,
    #[serde(default)]
    pub tokens_used_month: u64,
    #[serde(default)]
    pub agents_count: u32,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

fn default_tier() -> String { "community".to_string() }
fn default_billing_state() -> String { "active".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub key_id: String,
    pub key_hash: String,       // Argon2 hash of the actual key
    /// HMAC-SHA256 hex of raw key (server pepper) for O(1) restart-safe lookup.
    /// Empty on keys minted before this field existed — those must be re-issued.
    #[serde(default)]
    pub lookup_hmac: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token_id: String,
    pub user_id: String,
    pub token_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
    pub device_fingerprint: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// User Store — in-memory (production: SQLite/Postgres)
// ═══════════════════════════════════════════════════════════════

pub struct UserStore {
    pub users: HashMap<String, User>,           // user_id → User
    pub email_index: HashMap<String, String>,   // email → user_id
    pub refresh_tokens: HashMap<String, RefreshToken>,
    // FIX BUG-035: Changed from Vec to HashSet for O(1) lookups
    pub revoked_jtis: std::collections::HashSet<String>,  // revoked token IDs
    pub login_attempts: HashMap<String, (u32, i64)>,  // email → (count, last_attempt_ts)
}

impl UserStore {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            email_index: HashMap::new(),
            refresh_tokens: HashMap::new(),
            revoked_jtis: std::collections::HashSet::new(),
            login_attempts: HashMap::new(),
        }
    }

    /// X.13: Rebuild UserStore from engine_store on startup (survives restarts).
    pub fn load_from_store(es: &(dyn connector_engine::engine_store::EngineStore + Send)) -> Self {
        let mut store = Self::new();
        let keys = es.folder_keys("_auth_users", None).unwrap_or_default();
        for key in &keys {
            if let Some(val) = es.folder_get("_auth_users", key).ok().flatten() {
                if let Ok(user) = serde_json::from_value::<User>(val) {
                    store.email_index.insert(user.email.clone(), user.user_id.clone());
                    store.users.insert(user.user_id.clone(), user);
                }
            }
        }
        // Rebuild revoked JTI list
        let jti_keys = es.folder_keys("_auth_revoked_jtis", None).unwrap_or_default();
        for key in &jti_keys {
            if let Some(val) = es.folder_get("_auth_revoked_jtis", key).ok().flatten() {
                if let Some(jti) = val.as_str() {
                    // FIX BUG-035: Use insert for HashSet
                    store.revoked_jtis.insert(jti.to_string());
                }
            }
        }
        if !store.users.is_empty() {
            tracing::info!("[auth] Loaded {} user(s) from engine_store", store.users.len());
        }
        store
    }

    /// X.13: Write-through — persist a user to engine_store.
    pub fn persist_user(
        &self,
        user_id: &str,
        es: &mut (dyn connector_engine::engine_store::EngineStore + Send),
    ) {
        if let Some(user) = self.users.get(user_id) {
            if let Ok(val) = serde_json::to_value(user) {
                let _ = es.folder_put("_auth_users", user_id, &val);
            }
        }
    }

    pub fn create_user(&mut self, user: User) -> Result<(), String> {
        if self.email_index.contains_key(&user.email) {
            return Err("Email already registered".into());
        }
        self.email_index.insert(user.email.clone(), user.user_id.clone());
        self.users.insert(user.user_id.clone(), user);
        Ok(())
    }

    pub fn get_by_email(&self, email: &str) -> Option<&User> {
        self.email_index.get(email).and_then(|id| self.users.get(id))
    }

    pub fn get_by_email_mut(&mut self, email: &str) -> Option<&mut User> {
        let id = self.email_index.get(email)?.clone();
        self.users.get_mut(&id)
    }

    /// D6: find mutable user by email (alias matching payment.rs usage)
    pub fn find_by_email_mut(&mut self, email: &str) -> Option<&mut User> {
        self.get_by_email_mut(email)
    }

    /// D6: find mutable user by Stripe customer_id
    pub fn find_by_stripe_customer_id_mut(&mut self, customer_id: &str) -> Option<&mut User> {
        let user_id = self.users.values()
            .find(|u| u.stripe_customer_id.as_deref() == Some(customer_id))
            .map(|u| u.user_id.clone())?;
        self.users.get_mut(&user_id)
    }

    pub fn get_user(&self, user_id: &str) -> Option<&User> {
        self.users.get(user_id)
    }

    // FIX BUG-035: HashSet provides O(1) lookup instead of O(n) Vec scan
    pub fn is_jti_revoked(&self, jti: &str) -> bool {
        self.revoked_jtis.contains(jti)
    }

    // FIX BUG-035: Use insert for HashSet (also prevents duplicates)
    pub fn revoke_jti(&mut self, jti: String) {
        revoke_access_jti(&jti);
        self.revoked_jtis.insert(jti);
    }

    pub fn check_rate_limit(&mut self, email: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        if let Some((count, last)) = self.login_attempts.get(email) {
            if now - last < 300 && *count >= 5 {
                return false; // locked for 5 min after 5 fails
            }
        }
        true
    }

    pub fn record_failed_login(&mut self, email: &str) {
        let now = chrono::Utc::now().timestamp();
        let entry = self.login_attempts.entry(email.to_string()).or_insert((0, now));
        if now - entry.1 > 300 {
            *entry = (1, now); // reset after 5 min
        } else {
            entry.0 += 1;
            entry.1 = now;
        }
    }

    pub fn clear_failed_login(&mut self, email: &str) {
        self.login_attempts.remove(email);
    }
}

// ═══════════════════════════════════════════════════════════════
// Crypto helpers — Argon2 + JWT (HMAC-SHA256 with rotating secret)
// ═══════════════════════════════════════════════════════════════

/// FIX BUG-024: Secure JWT secret handling
/// - Production: MUST set CONNECTOR_JWT_SECRET env var (panics if missing)
/// - Dev mode: generates a random secret per process (not predictable)
pub(crate) fn jwt_secret() -> Vec<u8> {
    // Check if running in dev mode
    let dev_mode = std::env::var("CONNECTOR_DEV_MODE").is_ok()
        || std::env::var("CONNECTOR_ENV").map(|v| v == "development" || v == "dev").unwrap_or(false);
    let playground = crate::services::playground::is_playground_mode();

    match std::env::var("CONNECTOR_JWT_SECRET") {
        Ok(secret) if !secret.is_empty() => secret.into_bytes(),
        _ if dev_mode || playground => {
            // Dev / hosted trial: per-process random secret if operator did not set one.
            // Playground sessions are 90 min; restart invalidates JWTs (re-login with cpk_pg_).
            use std::sync::OnceLock;
            static FALLBACK_SECRET: OnceLock<Vec<u8>> = OnceLock::new();
            FALLBACK_SECRET.get_or_init(|| {
                use rand::Rng;
                let secret: Vec<u8> = rand::thread_rng()
                    .sample_iter(&rand::distributions::Standard)
                    .take(64)
                    .collect();
                tracing::warn!("[auth] Using random JWT secret (dev/playground). Set CONNECTOR_JWT_SECRET for persistence.");
                secret
            }).clone()
        }
        _ => {
            // Production without secret: panic with clear error
            panic!(
                "CONNECTOR_JWT_SECRET environment variable is required in production mode. \
                 Generate a secure secret with: openssl rand -base64 64"
            );
        }
    }
}

#[cfg(test)]
mod jti_revocation_tests {
    use super::*;

    #[test]
    fn revoked_jti_fails_verify_token() {
        let prev_env = std::env::var("CONNECTOR_ENV").ok();
        let prev_secret = std::env::var("CONNECTOR_JWT_SECRET").ok();
        std::env::set_var("CONNECTOR_ENV", "development");
        std::env::set_var("CONNECTOR_JWT_SECRET", "jti-test-secret-must-be-long-enough-32b");
        let claims = Claims {
            sub: "u1".into(),
            email: "u1@example.com".into(),
            role: "viewer".into(),
            permissions: vec![],
            instance_id: None,
            tenant_id: None,
            token_type: "access".into(),
            jti: format!("jti-revoke-{}", uuid::Uuid::new_v4().simple()),
            iat: chrono::Utc::now().timestamp() as usize,
            exp: (chrono::Utc::now().timestamp() + 3600) as usize,
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&jwt_secret()),
        )
        .unwrap();
        assert!(verify_token(&token).is_ok());
        revoke_access_jti(&claims.jti);
        assert!(verify_token(&token).is_err());
        match prev_env {
            Some(v) => std::env::set_var("CONNECTOR_ENV", v),
            None => std::env::remove_var("CONNECTOR_ENV"),
        }
        match prev_secret {
            Some(v) => std::env::set_var("CONNECTOR_JWT_SECRET", v),
            None => std::env::remove_var("CONNECTOR_JWT_SECRET"),
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;

    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Hash error: {}", e))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordVerifier};
    use argon2::password_hash::PasswordHash;

    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Resolve tenant id embedded in access tokens (login body, user row, or env default).
pub fn resolve_token_tenant_id(user: Option<&User>, login_tenant: Option<&str>) -> Option<String> {
    login_tenant
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| user.and_then(|u| u.tenant_id.clone()))
        .or_else(|| std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok())
        .filter(|s| !s.trim().is_empty())
}

pub fn create_token(
    user_id: &str,
    email: &str,
    role: &str,
    permissions: &[String],
    instance_id: Option<&str>,
    tenant_id: Option<&str>,
    token_type: &str,
    expires_secs: u64,
) -> Result<(String, String), String> {
    let now = chrono::Utc::now().timestamp() as usize;
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        permissions: permissions.to_vec(),
        instance_id: instance_id.map(|s| s.to_string()),
        tenant_id: tenant_id.map(|s| s.to_string()).filter(|s| !s.is_empty()),
        token_type: token_type.to_string(),
        jti: jti.clone(),
        iat: now,
        exp: now + expires_secs as usize,
    };
    let secret = jwt_secret();
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(&secret))
        .map_err(|e| e.to_string())?;
    Ok((token, jti))
}

/// BIZ-1: Generate a scoped API key in `cpk_live_{base58}` format.
/// The raw key is returned once — caller must store it; only the hash is persisted.
pub fn generate_api_key(prefix: &str) -> String {
    use rand::Rng;
    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(&rand::distributions::Standard)
        .take(24)
        .collect();
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &random_bytes,
    );
    format!("{}_{}", prefix, encoded)
}

// ─── D7: DashMap JWT auth cache — 60s TTL ─────────────────────────────────────

use std::sync::OnceLock;
use dashmap::DashMap;

type CacheEntry = (Claims, i64); // (claims, cached_at_unix_secs)

static JWT_CACHE: OnceLock<DashMap<String, CacheEntry>> = OnceLock::new();

fn jwt_cache() -> &'static DashMap<String, CacheEntry> {
    JWT_CACHE.get_or_init(DashMap::new)
}

const JWT_CACHE_TTL_SECS: i64 = 60;

static REVOKED_JTIS: OnceLock<DashMap<String, ()>> = OnceLock::new();

fn revoked_jtis() -> &'static DashMap<String, ()> {
    REVOKED_JTIS.get_or_init(DashMap::new)
}

/// Mark an access-token JTI revoked for every subsequent verify (not only refresh).
pub fn revoke_access_jti(jti: &str) {
    if jti.is_empty() {
        return;
    }
    revoked_jtis().insert(jti.to_string(), ());
    let cache = jwt_cache();
    cache.retain(|_, (claims, _)| claims.jti != jti);
}

pub fn is_access_jti_revoked(jti: &str) -> bool {
    !jti.is_empty() && revoked_jtis().contains_key(jti)
}

pub fn verify_token(token: &str) -> Result<Claims, String> {
    let now = chrono::Utc::now().timestamp();
    let cache = jwt_cache();

    // Cache hit path (< 1us on warm cache)
    if let Some(entry) = cache.get(token) {
        let (ref claims, cached_at) = *entry;
        if now - cached_at < JWT_CACHE_TTL_SECS {
            if is_access_jti_revoked(&claims.jti) {
                drop(entry);
                cache.remove(token);
                return Err("token revoked".into());
            }
            return Ok(claims.clone());
        }
        // TTL expired — fall through to re-decode and refresh
        drop(entry);
        cache.remove(token);
    }

    // Cache miss: full HMAC decode
    let secret = jwt_secret();
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&secret),
        &Validation::default(),
    )
    .map(|d| d.claims)
    .map_err(|e| e.to_string())?;

    if is_access_jti_revoked(&claims.jti) {
        return Err("token revoked".into());
    }

    // Store in cache (TTL-checked on next read)
    cache.insert(token.to_string(), (claims.clone(), now));

    // Lazy eviction: remove up to 32 stale entries to bound memory
    if cache.len() > 4096 {
        let stale: Vec<String> = cache.iter()
            .filter(|e| now - e.value().1 >= JWT_CACHE_TTL_SECS)
            .take(32)
            .map(|e| e.key().clone())
            .collect();
        for k in stale { cache.remove(&k); }
    }

    Ok(claims)
}

/// Explicitly evict a token from the cache (call on logout / JTI revocation).
pub fn invalidate_token_cache(token: &str) {
    jwt_cache().remove(token);
}

// ═══════════════════════════════════════════════════════════════
// FIX BUG-045: API Key Validation
// ═══════════════════════════════════════════════════════════════

/// Fast-lookup entry for API keys.
/// Primary key is HMAC(pepper, raw_key) — never the plaintext key.
#[derive(Clone)]
struct ApiKeyEntry {
    user_id: String,
    role: String,
    scopes: Vec<String>,
    expires_at: Option<String>,
    key_hash: String,
}

/// Maps lookup_hmac → entry. Populated on key create and rebuilt from UserStore on boot.
static API_KEY_STORE: std::sync::OnceLock<
    std::sync::RwLock<std::collections::HashMap<String, ApiKeyEntry>>,
> = std::sync::OnceLock::new();

fn api_key_store() -> &'static std::sync::RwLock<std::collections::HashMap<String, ApiKeyEntry>> {
    API_KEY_STORE.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

fn api_key_pepper() -> Vec<u8> {
    std::env::var("CONNECTOR_API_KEY_PEPPER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("CONNECTOR_JWT_SECRET").ok().filter(|s| !s.trim().is_empty()))
        .map(|s| s.into_bytes())
        .unwrap_or_else(|| b"connector-api-key-pepper-dev-only".to_vec())
}

/// Deterministic lookup token for an API key (HMAC-SHA256 hex).
pub fn api_key_lookup_hmac(raw_key: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&api_key_pepper())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").expect("hmac"));
    mac.update(raw_key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Register an API key in the fast-lookup store (called when key is created or on boot).
pub fn register_api_key(
    raw_key: &str,
    user_id: &str,
    scopes: Vec<String>,
    expires_at: Option<String>,
) {
    register_api_key_with_role(raw_key, user_id, "service", scopes, expires_at, None);
}

/// Register with role + optional Argon2 hash (hash computed if omitted).
pub fn register_api_key_with_role(
    raw_key: &str,
    user_id: &str,
    role: &str,
    scopes: Vec<String>,
    expires_at: Option<String>,
    key_hash: Option<String>,
) {
    let lookup = api_key_lookup_hmac(raw_key);
    let hash = key_hash.unwrap_or_else(|| hash_password(raw_key).unwrap_or_default());
    if let Ok(mut store) = api_key_store().write() {
        store.insert(
            lookup,
            ApiKeyEntry {
                user_id: user_id.to_string(),
                role: role.to_string(),
                scopes,
                expires_at,
                key_hash: hash,
            },
        );
    }
}

/// Rebuild fast-lookup from persisted UserStore (lookup_hmac + Argon2 verify on use).
pub fn rehydrate_api_keys_from_user_store(users: &UserStore) {
    let mut n = 0usize;
    if let Ok(mut store) = api_key_store().write() {
        store.clear();
        for user in users.users.values() {
            for key in &user.api_keys {
                if key.revoked || key.lookup_hmac.is_empty() {
                    continue;
                }
                store.insert(
                    key.lookup_hmac.clone(),
                    ApiKeyEntry {
                        user_id: user.user_id.clone(),
                        role: user.role.to_str().to_string(),
                        scopes: key.scopes.clone(),
                        expires_at: key.expires_at.clone(),
                        key_hash: key.key_hash.clone(),
                    },
                );
                n += 1;
            }
        }
    }
    if n > 0 {
        tracing::info!("[auth] Rehydrated {n} API key lookup entr(y/ies) from UserStore");
    }
}

pub fn revoke_api_key(raw_key: &str) {
    let lookup = api_key_lookup_hmac(raw_key);
    if let Ok(mut store) = api_key_store().write() {
        store.remove(&lookup);
    }
}

pub fn api_key_scopes(api_key: &str) -> Result<Vec<String>, String> {
    let entry = lookup_api_key_entry(api_key)?;
    Ok(entry.scopes)
}

fn lookup_api_key_entry(api_key: &str) -> Result<ApiKeyEntry, String> {
    let lookup = api_key_lookup_hmac(api_key);
    let entry = {
        let store = api_key_store()
            .read()
            .map_err(|_| "API key store lock poisoned".to_string())?;
        store.get(&lookup).cloned()
    };
    let Some(entry) = entry else {
        return Err("API key not found or invalid".to_string());
    };
    if let Some(exp) = &entry.expires_at {
        if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(exp) {
            if exp_time < chrono::Utc::now() {
                return Err("API key expired".to_string());
            }
        }
    }
    if !entry.key_hash.is_empty() && !verify_password(api_key, &entry.key_hash) {
        return Err("API key not found or invalid".to_string());
    }
    Ok(entry)
}

/// Validate an API key. Returns Ok(user_id) if valid, Err if invalid/expired/revoked.
pub fn validate_api_key(api_key: &str) -> Result<String, String> {
    Ok(lookup_api_key_entry(api_key)?.user_id)
}

/// Build JWT-shaped Claims for an API key (for RBAC enforcement).
pub fn claims_for_api_key(api_key: &str) -> Result<Claims, String> {
    let entry = lookup_api_key_entry(api_key)?;
    let role = PlatformRole::from_str(&entry.role);
    let perms = if entry.scopes.is_empty() {
        role.permissions()
    } else {
        entry.scopes.clone()
    };
    Ok(Claims {
        sub: entry.user_id,
        email: String::new(),
        role: role.to_str().to_string(),
        permissions: perms,
        instance_id: None,
        tenant_id: None,
        token_type: "api_key".into(),
        jti: format!("apikey:{}", &api_key[..api_key.len().min(16)]),
        iat: 0,
        exp: usize::MAX,
    })
}

// ═══════════════════════════════════════════════════════════════
// TOTP 2FA
// ═══════════════════════════════════════════════════════════════

pub fn generate_totp_secret(email: &str) -> (String, String) {
    let secret = totp_rs::Secret::generate_secret();
    let secret_b32 = secret.to_encoded().to_string();
    // Build otpauth URI manually (no otpauth feature needed)
    let uri = format!(
        "otpauth://totp/Connector%20Platform:{}?secret={}&issuer=Connector%20Platform&algorithm=SHA1&digits=6&period=30",
        email, secret_b32
    );
    (secret_b32, uri)
}

pub fn verify_totp(secret_b32: &str, code: &str) -> bool {
    let secret = match totp_rs::Secret::Encoded(secret_b32.to_string()).to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1, 6, 1, 30,
        secret,
    ) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════
// Request types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    pub instance_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
    pub device_fingerprint: Option<String>,
    /// Optional tenant for `CONNECTOR_MULTI_TENANT` (also accepts `X-Tenant-ID` on the request).
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpSetupRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_days: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct AdminSetRoleRequest {
    pub user_id: String,
    pub role: String,
}

// ═══════════════════════════════════════════════════════════════
// Auth middleware — RBAC-aware with JTI revocation check
// ═══════════════════════════════════════════════════════════════

pub async fn auth_middleware(
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();

    // Public endpoints — no auth required
    if path == "/health" || path == "/metrics"
        || path == "/api/v1/health" || path == "/api/v1/health/"
        || path == "/api/v1/auth/signup"
        || path == "/api/v1/auth/login"
        || path == "/api/v1/auth/sso/login"
        || path == "/api/v1/auth/sso/callback"
        || path == "/api/v1/auth/refresh"
        || path == "/api/v1/auth/token"  // legacy compat
        || path == "/api/v1/playground/status"
        || path == "/api/v1/playground/session"
        || path.starts_with("/api/v1/playground/session/")
    {
        return Ok(next.run(request).await);
    }

    // Dev mode bypass — any token accepted, skip JWT verification entirely (see `dev_auth_bypass_allowed`)
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        let synthetic = connector_trust::PrincipalContextV2 {
            subject: "dev_bypass".into(),
            email: String::new(),
            role: "operator".into(),
            permissions: PlatformRole::Operator.permissions(),
            tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
            jti: None,
            token_type: "synthetic".into(),
            instance_id: None,
            auth_source: connector_trust::principal::AuthSourceV2::Synthetic,
            contract_version: 2,
        };
        request.extensions_mut().insert(synthetic);
        return Ok(next.run(request).await);
    }

    // Check Bearer token
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                match verify_token(token) {
                    Ok(claims) => {
                        // Check required permission for this path
                        let path_bare = path.strip_prefix("/api/v1").unwrap_or(path).trim_start_matches('/');
                        if super::rbac::enforce_rest_access(&claims, path_bare, request.method().as_str())
                            .is_some()
                        {
                            return Err(StatusCode::FORBIDDEN);
                        }
                        let mut principal = connector_trust::PrincipalContextV2::from(&claims);
                        if token.starts_with("cpk_") {
                            principal.auth_source = connector_trust::principal::AuthSourceV2::ApiKey;
                        }
                        request.extensions_mut().insert(claims);
                        request.extensions_mut().insert(principal);
                        return Ok(next.run(request).await);
                    }
                    Err(_) => return Err(StatusCode::UNAUTHORIZED),
                }
            }
        }
    }

    // Check X-API-Key header (for service accounts)
    if let Some(api_key) = headers.get("x-api-key") {
        if let Ok(key_str) = api_key.to_str() {
            if !key_str.is_empty() && key_str.starts_with("cpk_") {
                let tenant_id = crate::middleware::tenant::extract_tenant_from_api_key_public(key_str);
                let principal = connector_trust::PrincipalContextV2 {
                    subject: format!("apikey:{}", &key_str[..key_str.len().min(16)]),
                    email: String::new(),
                    role: "service".into(),
                    permissions: vec![],
                    tenant_id,
                    jti: None,
                    token_type: "api_key".into(),
                    instance_id: None,
                    auth_source: connector_trust::principal::AuthSourceV2::ApiKey,
                    contract_version: 2,
                };
                request.extensions_mut().insert(principal);
                // API key validation happens at the handler level
                return Ok(next.run(request).await);
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

// ═══════════════════════════════════════════════════════════════
// Route handlers
// ═══════════════════════════════════════════════════════════════

pub async fn signup(
    State(state): State<crate::state::SharedState>,
    Json(req): Json<SignupRequest>,
) -> Json<serde_json::Value> {
    let dev_relax = runtime_control::dev_signup_relaxed(&state);
    // Validate
    if req.email.is_empty() || !req.email.contains('@') {
        return Json(serde_json::json!({"error": "Invalid email"}));
    }
    let min_pw = if dev_relax { 8 } else { 10 };
    if req.password.len() < min_pw {
        return Json(serde_json::json!({"error": format!("Password must be at least {} characters", min_pw)}));
    }
    if req.name.is_empty() {
        return Json(serde_json::json!({"error": "Name is required"}));
    }
    if !dev_relax {
        // Production-style strength (dev uses relaxed rules below)
        let has_upper = req.password.chars().any(|c| c.is_uppercase());
        let has_lower = req.password.chars().any(|c| c.is_lowercase());
        let has_digit = req.password.chars().any(|c| c.is_ascii_digit());
        let has_special = req.password.chars().any(|c| !c.is_alphanumeric());
        if !has_upper || !has_lower || !has_digit || !has_special {
            return Json(serde_json::json!({"error": "Password must contain uppercase, lowercase, digit, and special character"}));
        }
    }

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    let user_id = format!("usr_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();

    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    let role = if user_store.users.is_empty() {
        PlatformRole::SuperAdmin
    } else {
        PlatformRole::Developer
    };

    let user = User {
        user_id: user_id.clone(),
        email: req.email.clone(),
        name: req.name.clone(),
        password_hash,
        role,
        created_at: now.to_rfc3339(),
        last_login: None,
        totp_secret: None,
        totp_enabled: false,
        api_keys: Vec::new(),
        locked: false,
        failed_attempts: 0,
        instance_id: req.instance_id,
        tier: "community".to_string(),
        billing_state: "active".to_string(),
        stripe_customer_id: None,
        tokens_used_today: 0,
        tokens_used_month: 0,
        agents_count: 0,
        tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
    };

    match user_store.create_user(user) {
        Ok(_) => {
            // X.13: Write-through — persist new user to engine_store
            let mut es = state.engine_store.lock().unwrap();
            user_store.persist_user(&user_id, &mut **es);
            Json(serde_json::json!({
                "user_id": user_id,
                "email": req.email,
                "name": req.name,
                "role": role.to_str(),
                "created_at": now.to_rfc3339(),
                "note": if role == PlatformRole::SuperAdmin { "First user — granted SuperAdmin role" } else { "Account created" },
                "dev_runtime": dev_relax,
                "dev_agent_cap": dev_relax.then(|| runtime_control::DEV_RUNTIME_FREE_AGENT_MAX),
            }))
        }
        Err(e) => Json(serde_json::json!({"error": e})),
    }
}

pub async fn login(
    State(state): State<crate::state::SharedState>,
    Json(req): Json<LoginRequest>,
) -> Json<serde_json::Value> {
    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };

    // Rate limiting
    if !user_store.check_rate_limit(&req.email) {
        return Json(serde_json::json!({"error": "Too many failed attempts. Try again in 5 minutes."}));
    }

    let user = match user_store.get_by_email(&req.email) {
        Some(u) => u.clone(),
        None => {
            user_store.record_failed_login(&req.email);
            return Json(serde_json::json!({"error": "Invalid credentials"}));
        }
    };

    if user.locked {
        return Json(serde_json::json!({"error": "Account locked. Contact administrator."}));
    }

    if !verify_password(&req.password, &user.password_hash) {
        user_store.record_failed_login(&req.email);
        if let Some(u) = user_store.get_by_email_mut(&req.email) {
            u.failed_attempts += 1;
            if u.failed_attempts >= 10 {
                u.locked = true;
            }
        }
        return Json(serde_json::json!({"error": "Invalid credentials"}));
    }

    // TOTP check
    if user.totp_enabled {
        match &req.totp_code {
            Some(code) => {
                if let Some(ref secret) = user.totp_secret {
                    if !verify_totp(secret, code) {
                        return Json(serde_json::json!({"error": "Invalid 2FA code"}));
                    }
                }
            }
            None => return Json(serde_json::json!({"error": "2FA code required", "totp_required": true})),
        }
    }

    // Success — clear rate limiter, create tokens
    user_store.clear_failed_login(&req.email);
    if let Some(u) = user_store.get_by_email_mut(&req.email) {
        u.last_login = Some(chrono::Utc::now().to_rfc3339());
        u.failed_attempts = 0;
    }

    let permissions = user.role.permissions();
    let token_tenant = resolve_token_tenant_id(Some(&user), req.tenant_id.as_deref());
    let token_tenant_ref = token_tenant.as_deref();
    let (access_token, access_jti) = match create_token(
        &user.user_id,
        &user.email,
        user.role.to_str(),
        &permissions,
        user.instance_id.as_deref(),
        token_tenant_ref,
        "access",
        3600,
    ) {
        Ok(t) => t,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    let (refresh_token, refresh_jti) = match create_token(
        &user.user_id,
        &user.email,
        user.role.to_str(),
        &[],
        user.instance_id.as_deref(),
        token_tenant_ref,
        "refresh",
        604800,
    ) {
        Ok(t) => t,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    // Store refresh token
    user_store.refresh_tokens.insert(refresh_jti.clone(), RefreshToken {
        token_id: refresh_jti,
        user_id: user.user_id.clone(),
        token_hash: refresh_token.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        expires_at: (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
        revoked: false,
        device_fingerprint: req.device_fingerprint,
    });

    Json(serde_json::json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "user": {
            "user_id": user.user_id,
            "email": user.email,
            "name": user.name,
            "role": user.role.to_str(),
            "tenant_id": token_tenant,
        },
        "permissions": permissions,
    }))
}

pub async fn refresh(
    State(state): State<crate::state::SharedState>,
    Json(req): Json<RefreshRequest>,
) -> Json<serde_json::Value> {
    let claims = match verify_token(&req.refresh_token) {
        Ok(c) => c,
        Err(_) => return Json(serde_json::json!({"error": "Invalid refresh token"})),
    };

    if claims.token_type != "refresh" {
        return Json(serde_json::json!({"error": "Not a refresh token"}));
    }

    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };

    // Check if revoked
    if user_store.is_jti_revoked(&claims.jti) {
        return Json(serde_json::json!({"error": "Refresh token revoked"}));
    }

    let user = match user_store.get_user(&claims.sub) {
        Some(u) => u.clone(),
        None => return Json(serde_json::json!({"error": "User not found"})),
    };

    // Revoke old refresh token
    user_store.revoke_jti(claims.jti);

    // Issue new tokens
    let permissions = user.role.permissions();
    let token_tenant = claims
        .tenant_id
        .as_deref()
        .or(user.tenant_id.as_deref());
    let (access_token, _) = match create_token(
        &user.user_id,
        &user.email,
        user.role.to_str(),
        &permissions,
        user.instance_id.as_deref(),
        token_tenant,
        "access",
        3600,
    ) {
        Ok(t) => t,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    let (new_refresh, new_jti) = match create_token(
        &user.user_id,
        &user.email,
        user.role.to_str(),
        &[],
        user.instance_id.as_deref(),
        token_tenant,
        "refresh",
        604800,
    ) {
        Ok(t) => t,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    user_store.refresh_tokens.insert(new_jti.clone(), RefreshToken {
        token_id: new_jti,
        user_id: user.user_id.clone(),
        token_hash: new_refresh.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        expires_at: (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
        revoked: false,
        device_fingerprint: None,
    });

    Json(serde_json::json!({
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
}

pub async fn totp_setup(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
    Json(req): Json<TotpSetupRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    let user = match user_store.users.get_mut(&claims.sub) {
        Some(u) => u,
        None => return Json(serde_json::json!({"error": "User not found"})),
    };

    if !verify_password(&req.password, &user.password_hash) {
        return Json(serde_json::json!({"error": "Invalid password"}));
    }

    let (secret, uri) = generate_totp_secret(&user.email);
    user.totp_secret = Some(secret.clone());

    Json(serde_json::json!({
        "totp_secret": secret,
        "totp_uri": uri,
        "note": "Scan QR code in authenticator app, then verify with /auth/totp/verify",
    }))
}

pub async fn totp_verify(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
    Json(req): Json<TotpVerifyRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    let user = match user_store.users.get_mut(&claims.sub) {
        Some(u) => u,
        None => return Json(serde_json::json!({"error": "User not found"})),
    };

    match &user.totp_secret {
        Some(secret) => {
            if verify_totp(secret, &req.code) {
                user.totp_enabled = true;
                Json(serde_json::json!({"totp_enabled": true, "message": "2FA activated successfully"}))
            } else {
                Json(serde_json::json!({"error": "Invalid TOTP code"}))
            }
        }
        None => Json(serde_json::json!({"error": "Run /auth/totp/setup first"})),
    }
}

pub async fn list_keys(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };

    let user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    match user_store.get_user(&claims.sub) {
        Some(user) => {
            let keys: Vec<serde_json::Value> = user.api_keys.iter()
                .filter(|k| !k.revoked)
                .map(|k| serde_json::json!({
                    "key_id": k.key_id,
                    "name": k.name,
                    "scopes": k.scopes,
                    "created_at": k.created_at,
                    "expires_at": k.expires_at,
                    "last_used_at": k.last_used,
                    "revoked": k.revoked,
                }))
                .collect();
            Json(serde_json::json!({ "ok": true, "keys": keys, "count": keys.len() }))
        }
        None => Json(serde_json::json!({ "ok": false, "error": "User not found" })),
    }
}

pub async fn create_api_key(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
    Json(req): Json<CreateApiKeyRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };

    let raw_key = format!("cpk_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let key_hash = match hash_password(&raw_key) {
        Ok(h) => h,
        Err(e) => return Json(serde_json::json!({"error": e})),
    };

    let key_id = format!("key_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let expires = req.expires_days.map(|d| (now + chrono::Duration::days(d as i64)).to_rfc3339());

    let lookup_hmac = api_key_lookup_hmac(&raw_key);
    let scopes = req.scopes.unwrap_or_else(|| claims.permissions.clone());
    let api_key = ApiKey {
        key_id: key_id.clone(),
        key_hash: key_hash.clone(),
        lookup_hmac,
        name: req.name.clone(),
        scopes: scopes.clone(),
        created_at: now.to_rfc3339(),
        expires_at: expires.clone(),
        last_used: None,
        revoked: false,
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "auth-keys",
        "auth",
        "create_api_key",
        &serde_json::json!({"key_id": key_id.as_str(), "name": req.name.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    register_api_key_with_role(
        &raw_key,
        &claims.sub,
        &claims.role,
        scopes,
        expires,
        Some(key_hash),
    );

    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "error": e,
                "status": 503,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }));
        }
    };
    if let Some(user) = user_store.users.get_mut(&claims.sub) {
        user.api_keys.push(api_key);
    }
    if let Ok(mut es) = state.engine_store.lock() {
        user_store.persist_user(&claims.sub, &mut **es);
    }
    drop(user_store);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "key_id": key_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "api_key": raw_key,
        "name": req.name,
        "note": "Save this key — it cannot be shown again",
    }))
}

pub async fn me(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let Some(claims) = extract_claims(&headers) else {
        return Json(serde_json::json!({"error": "Unauthorized"}));
    };

    // Node-level context (same logic as devguard::node_gateway_base)
    let node_public_url = std::env::var("CONNECTOR_PUBLIC_URL").ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let host = std::env::var("CONNECTOR_HOST").unwrap_or_else(|_| "127.0.0.1".into());
            let port = std::env::var("CONNECTOR_PORT").unwrap_or_else(|_| "9091".into());
            format!("http://{host}:{port}")
        });
    let node_version = env!("CARGO_PKG_VERSION");
    let node_preset = std::env::var("CONNECTOR_PRESET").unwrap_or_else(|_| "local".into());
    let node_id = std::env::var("CONNECTOR_INSTANCE_ID")
        .or_else(|_| std::env::var("CONNECTOR_NODE_ID"))
        .unwrap_or_else(|_| "local".into());
    let node_info = serde_json::json!({
        "version": node_version,
        "preset": node_preset,
        "node_id": node_id,
        "public_url": node_public_url,
        "dashboard_url": node_public_url.clone(),
        "api_url": format!("{node_public_url}/api/v1"),
        "gateway_url": format!("{node_public_url}/v1"),
    });

    let user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    match user_store.get_user(&claims.sub) {
        Some(user) => Json(serde_json::json!({
            "user_id": &user.user_id,
            "email": &user.email,
            "name": &user.name,
            "role": user.role.to_str(),
            "tenant_id": user.tenant_id.as_ref().or(claims.tenant_id.as_ref()),
            "permissions": user.role.permissions(),
            "totp_enabled": user.totp_enabled,
            "api_keys": user.api_keys.iter().filter(|k| !k.revoked).count(),
            "created_at": &user.created_at,
            "last_login": &user.last_login,
            "instance_id": &user.instance_id,
            "node": node_info,
            "billing": {
                "tier": &user.tier,
                "billing_state": &user.billing_state,
                "stripe_customer_configured": user.stripe_customer_id.is_some(),
                "tokens_used_today": user.tokens_used_today,
                "tokens_used_month": user.tokens_used_month,
                "agents_count": user.agents_count,
                "portal_hint": "/api/v1/billing/portal",
                "usage_hint": "/api/v1/billing/usage",
            },
        })),
        None if claims.sub.starts_with("pg_")
            || claims
                .tenant_id
                .as_deref()
                .is_some_and(|t| t.starts_with("pg-"))
            || claims.token_type == "playground_key" =>
        {
            Json(serde_json::json!({
                "user_id": claims.sub,
                "email": claims.email,
                "name": "Trial",
                "role": claims.role,
                "tenant_id": claims.tenant_id,
                "permissions": claims.permissions,
                "totp_enabled": false,
                "api_keys": 1,
                "created_at": chrono::Utc::now().to_rfc3339(),
                "last_login": chrono::Utc::now().to_rfc3339(),
                "instance_id": claims.instance_id,
                "auth_via": "playground_key",
                "node": node_info,
            }))
        }
        None if crate::services::runtime_control::dev_auth_bypass_allowed() => {
            let name = if crate::services::runtime_control::free_tier_open_auth_enabled() {
                "Ultimate Free"
            } else {
                "Dev"
            };
            Json(serde_json::json!({
                "user_id": claims.sub,
                "email": claims.email,
                "name": name,
                "role": claims.role,
                "permissions": claims.permissions,
                "totp_enabled": false,
                "api_keys": 0,
                "created_at": chrono::Utc::now().to_rfc3339(),
                "last_login": chrono::Utc::now().to_rfc3339(),
                "instance_id": claims.instance_id,
                "open_auth": crate::services::runtime_control::free_tier_open_auth_enabled(),
                "node": node_info,
            }))
        }
        None => Json(serde_json::json!({"error": "User not found"})),
    }
}

pub async fn list_users(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    if PlatformRole::from_str(&claims.role).rank() < 5 {
        return Json(serde_json::json!({"error": "Admin role required"}));
    }

    let user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    let users: Vec<serde_json::Value> = user_store.users.values().map(|u| {
        serde_json::json!({
            "user_id": &u.user_id,
            "email": &u.email,
            "name": &u.name,
            "role": u.role.to_str(),
            "totp_enabled": u.totp_enabled,
            "locked": u.locked,
            "created_at": &u.created_at,
            "last_login": &u.last_login,
        })
    }).collect();

    Json(serde_json::json!({"count": users.len(), "users": users}))
}

pub async fn admin_set_role(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
    Json(req): Json<AdminSetRoleRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };
    if PlatformRole::from_str(&claims.role) != PlatformRole::SuperAdmin {
        return Json(serde_json::json!({"error": "SuperAdmin required"}));
    }

    let new_role = PlatformRole::from_str(&req.role);
    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    match user_store.users.get_mut(&req.user_id) {
        Some(user) => {
            user.role = new_role;
            Json(serde_json::json!({
                "user_id": req.user_id,
                "new_role": new_role.to_str(),
                "permissions": new_role.permissions(),
            }))
        }
        None => Json(serde_json::json!({"error": "User not found"})),
    }
}

pub async fn logout(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    user_store.revoke_jti(claims.jti);

    Json(serde_json::json!({"logged_out": true}))
}

pub async fn change_password(
    State(state): State<crate::state::SharedState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Unauthorized"})),
    };

    if req.new_password.len() < 10 {
        return Json(serde_json::json!({"error": "Password must be at least 10 characters"}));
    }

    let mut user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
    let user = match user_store.users.get_mut(&claims.sub) {
        Some(u) => u,
        None => return Json(serde_json::json!({"error": "User not found"})),
    };

    if !verify_password(&req.current_password, &user.password_hash) {
        return Json(serde_json::json!({"error": "Current password incorrect"}));
    }

    match hash_password(&req.new_password) {
        Ok(h) => {
            user.password_hash = h;
            Json(serde_json::json!({"password_changed": true}))
        }
        Err(e) => Json(serde_json::json!({"error": e})),
    }
}

fn synthetic_bypass_claims(sub: &str, email: &str, jti_suffix: &str) -> Claims {
    let now = chrono::Utc::now().timestamp() as usize;
    Claims {
        sub: sub.to_string(),
        email: email.to_string(),
        role: PlatformRole::SuperAdmin.to_str().to_string(),
        permissions: PlatformRole::SuperAdmin.permissions(),
        instance_id: None,
        tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
        token_type: "access".to_string(),
        jti: format!("open-{jti_suffix}"),
        iat: now,
        exp: now + 86_400 * 365,
    }
}

pub fn extract_claims(headers: &HeaderMap) -> Option<Claims> {
    let playground = std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| v == "1")
        .unwrap_or(false);
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());

    if let Some(token) = bearer {
        match verify_token(token) {
            Ok(claims) => return Some(claims),
            Err(_) => {
                // Playground session keys and invalid playground-shaped tokens never
                // become open-operator. Exchange cpk_pg_* at /auth/token first.
                if playground || token.starts_with("cpk_pg_") || token.starts_with("pg_") {
                    return None;
                }
            }
        }
    } else if playground {
        return None;
    }

    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        if let Some(token) = bearer {
            return Some(synthetic_bypass_claims(
                "open-operator",
                "operator@connector.local",
                token,
            ));
        }
        let label = if crate::services::runtime_control::free_tier_open_auth_enabled() {
            ("ultimate-free", "free@connector.local", "session")
        } else {
            ("dev", "dev@connector.local", "dev")
        };
        return Some(synthetic_bypass_claims(label.0, label.1, label.2));
    }
    None
}

// ═══════════════════════════════════════════════════════════════
// Axum middleware: require authenticated user with minimum role
// ═══════════════════════════════════════════════════════════════

/// Axum layer middleware that enforces a minimum role rank.
///
/// Usage in router:
/// ```
/// Router::new()
///     .route("/sensitive", post(handler))
///     .layer(axum::middleware::from_fn(auth::require_developer))
/// ```
///
/// Returns 401 if no valid token present, 403 if role rank insufficient.
pub async fn require_developer(req: Request, next: Next) -> Result<Response, StatusCode> {
    require_role_rank(req, next, 3).await  // developer+
}

pub async fn require_operator(req: Request, next: Next) -> Result<Response, StatusCode> {
    require_role_rank(req, next, 4).await  // operator+
}

pub async fn require_admin(req: Request, next: Next) -> Result<Response, StatusCode> {
    require_role_rank(req, next, 5).await  // admin+
}

async fn require_role_rank(req: Request, next: Next, min_rank: u8) -> Result<Response, StatusCode> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(next.run(req).await);
    }

    let token = req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| {
            req.headers()
                .get("x-api-key")
                .and_then(|h| h.to_str().ok())
        });

    let token = match token {
        Some(t) => t.to_string(),
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims = match verify_token(&token) {
        Ok(c) => c,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    let role = PlatformRole::from_str(&claims.role);
    if role.rank() < min_rank {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}

// ═══════════════════════════════════════════════════════════════
// ENT-4: SSO via OIDC (Okta, Google, Azure AD, GitHub, any OIDC provider)
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// SSO / OIDC (AUTH-04)
// ═══════════════════════════════════════════════════════════════

#[derive(Clone)]
struct SsoPending {
    provider: String,
    nonce: String,
    code_verifier: String,
    created_at: i64,
    /// Set when the operator UI started the login and wants the session handed back to /login.
    return_ui: bool,
}

fn sso_pending_store() -> &'static DashMap<String, SsoPending> {
    static STORE: OnceLock<DashMap<String, SsoPending>> = OnceLock::new();
    STORE.get_or_init(DashMap::new)
}

fn sso_pkce_pair() -> (String, String) {
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let verifier = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        raw,
    );
    let challenge = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        Sha256::digest(verifier.as_bytes()),
    );
    (verifier, challenge)
}

fn sso_client_secret(provider: &str) -> String {
    match provider {
        "google" => std::env::var("CONNECTOR_SSO_GOOGLE_CLIENT_SECRET").unwrap_or_default(),
        "okta" => std::env::var("CONNECTOR_SSO_OKTA_CLIENT_SECRET").unwrap_or_default(),
        "azure" => std::env::var("CONNECTOR_SSO_AZURE_CLIENT_SECRET").unwrap_or_default(),
        "github" => std::env::var("CONNECTOR_SSO_GITHUB_CLIENT_SECRET").unwrap_or_default(),
        _ => std::env::var("CONNECTOR_SSO_CLIENT_SECRET").unwrap_or_default(),
    }
}

fn sso_token_and_userinfo_urls(provider: &str) -> (String, String) {
    match provider {
        "google" => (
            "https://oauth2.googleapis.com/token".into(),
            "https://openidconnect.googleapis.com/v1/userinfo".into(),
        ),
        "okta" => {
            let domain = std::env::var("CONNECTOR_SSO_OKTA_DOMAIN").unwrap_or_default();
            (
                format!("https://{domain}/oauth2/v1/token"),
                format!("https://{domain}/oauth2/v1/userinfo"),
            )
        }
        "azure" => {
            let tenant = std::env::var("CONNECTOR_SSO_AZURE_TENANT_ID").unwrap_or_else(|_| "common".into());
            (
                format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
                "https://graph.microsoft.com/oidc/userinfo".into(),
            )
        }
        "github" => (
            "https://github.com/login/oauth/access_token".into(),
            "https://api.github.com/user".into(),
        ),
        _ => {
            let discovery = std::env::var("CONNECTOR_SSO_DISCOVERY_URL").unwrap_or_default();
            let base = discovery.trim_end_matches("/.well-known/openid-configuration");
            (
                std::env::var("CONNECTOR_SSO_TOKEN_URL")
                    .unwrap_or_else(|_| format!("{base}/token")),
                std::env::var("CONNECTOR_SSO_USERINFO_URL")
                    .unwrap_or_else(|_| format!("{base}/userinfo")),
            )
        }
    }
}

fn sso_jwks_url(provider: &str) -> Option<String> {
    match provider {
        "google" => Some("https://www.googleapis.com/oauth2/v3/certs".into()),
        "okta" => {
            let domain = std::env::var("CONNECTOR_SSO_OKTA_DOMAIN").ok()?;
            if domain.trim().is_empty() {
                return None;
            }
            Some(format!("https://{domain}/oauth2/v1/keys"))
        }
        "azure" => {
            let tenant = std::env::var("CONNECTOR_SSO_AZURE_TENANT_ID").unwrap_or_else(|_| "common".into());
            Some(format!(
                "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
            ))
        }
        "github" => None, // OAuth2 user API, not OIDC id_token
        _ => {
            if let Ok(url) = std::env::var("CONNECTOR_SSO_JWKS_URL") {
                if !url.trim().is_empty() {
                    return Some(url);
                }
            }
            let discovery = std::env::var("CONNECTOR_SSO_DISCOVERY_URL").unwrap_or_default();
            let base = discovery.trim_end_matches("/.well-known/openid-configuration");
            if base.is_empty() {
                None
            } else {
                Some(format!("{base}/jwks"))
            }
        }
    }
}

fn sso_expected_issuer(provider: &str) -> Option<String> {
    match provider {
        "google" => Some("https://accounts.google.com".into()),
        "okta" => {
            let domain = std::env::var("CONNECTOR_SSO_OKTA_DOMAIN").ok()?;
            Some(format!("https://{domain}"))
        }
        "azure" => {
            let tenant = std::env::var("CONNECTOR_SSO_AZURE_TENANT_ID").unwrap_or_else(|_| "common".into());
            Some(format!("https://login.microsoftonline.com/{tenant}/v2.0"))
        }
        _ => std::env::var("CONNECTOR_SSO_ISSUER").ok().filter(|s| !s.is_empty()),
    }
}

#[derive(Debug, Deserialize, Clone)]
struct JwksDocument {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize, Clone)]
struct JwkKey {
    kty: String,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
}

fn jwk_to_decoding_key(jwk: &JwkKey) -> Result<DecodingKey, String> {
    if jwk.kty != "RSA" {
        return Err("jwk_not_rsa".into());
    }
    let n = jwk.n.as_deref().ok_or("jwk_missing_n")?;
    let e = jwk.e.as_deref().ok_or("jwk_missing_e")?;
    DecodingKey::from_rsa_components(n, e).map_err(|err| format!("jwk_rsa_decode:{err}"))
}

fn id_token_header_kid(id_token: &str) -> Option<String> {
    let header_b64 = id_token.split('.').next()?;
    let mut s = header_b64.replace('-', "+").replace('_', "/");
    match s.len() % 4 {
        2 => s.push_str("=="),
        3 => s.push('='),
        _ => {}
    }
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    header.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Verify an OIDC id_token against a JWKS document (AUTH-04).
pub fn verify_id_token_with_jwks(
    id_token: &str,
    jwks: &JwksDocument,
    client_id: &str,
    expected_nonce: &str,
    expected_issuer: Option<&str>,
) -> Result<serde_json::Value, String> {
    let kid = id_token_header_kid(id_token);
    let jwk = jwks
        .keys
        .iter()
        .find(|k| {
            kid.as_ref().map(|want| k.kid.as_deref() == Some(want.as_str())).unwrap_or(false)
                || (kid.is_none() && jwks.keys.len() == 1)
        })
        .or_else(|| {
            jwks.keys.iter().find(|k| {
                k.kty == "RSA"
                    && k.key_use.as_deref() != Some("enc")
                    && (k.alg.as_deref().unwrap_or("RS256") == "RS256")
            })
        })
        .ok_or_else(|| "jwks_key_not_found".to_string())?;

    let key = jwk_to_decoding_key(jwk)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    if let Some(iss) = expected_issuer {
        validation.set_issuer(&[iss]);
    }
    validation.validate_exp = true;
    validation.validate_nbf = true;

    #[derive(Debug, Deserialize)]
    struct OidcClaims {
        sub: Option<String>,
        email: Option<String>,
        name: Option<String>,
        nonce: Option<String>,
        iss: Option<String>,
        aud: serde_json::Value,
        exp: Option<i64>,
        iat: Option<i64>,
        #[serde(flatten)]
        extra: serde_json::Map<String, serde_json::Value>,
    }

    let data = decode::<OidcClaims>(id_token, &key, &validation)
        .map_err(|e| format!("id_token_invalid:{e}"))?;
    if !expected_nonce.is_empty() {
        match data.claims.nonce.as_deref() {
            Some(n) if n == expected_nonce => {}
            Some(_) => return Err("sso_nonce_mismatch".into()),
            None => return Err("sso_nonce_missing".into()),
        }
    }
    let mut out = serde_json::Map::new();
    if let Some(email) = data.claims.email {
        out.insert("email".into(), serde_json::Value::String(email));
    }
    if let Some(name) = data.claims.name {
        out.insert("name".into(), serde_json::Value::String(name));
    }
    if let Some(sub) = data.claims.sub {
        out.insert("sub".into(), serde_json::Value::String(sub));
    }
    for (k, v) in data.claims.extra {
        out.entry(k).or_insert(v);
    }
    out.insert("aud".into(), data.claims.aud);
    if let Some(iss) = data.claims.iss {
        out.insert("iss".into(), serde_json::Value::String(iss));
    }
    if let Some(exp) = data.claims.exp {
        out.insert("exp".into(), serde_json::json!(exp));
    }
    if let Some(iat) = data.claims.iat {
        out.insert("iat".into(), serde_json::json!(iat));
    }
    Ok(serde_json::Value::Object(out))
}

/// Verify a Keycloak access token for `audience` against `CONNECTOR_SSO_JWKS_URL` and `CONNECTOR_SSO_ISSUER`.
/// JWKS is cached for five minutes and refetched once when the token's key is not in the cache.
pub async fn verify_idp_access_token(token: &str, audience: &str) -> Result<serde_json::Value, String> {
    static CACHE: OnceLock<std::sync::Mutex<Option<(i64, JwksDocument)>>> = OnceLock::new();
    let jwks_url = std::env::var("CONNECTOR_SSO_JWKS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or("idp_jwks_url_missing")?;
    let issuer = std::env::var("CONNECTOR_SSO_ISSUER").ok().filter(|s| !s.trim().is_empty());
    let insecure_tls = !crate::connector_profile::is_productionish_env()
        && std::env::var("CONNECTOR_SSO_INSECURE_TLS")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(None));
    let now = chrono::Utc::now().timestamp();
    let kid = id_token_header_kid(token);
    let cached = cache.lock().unwrap().as_ref().and_then(|(at, doc)| {
        let fresh = now - at < 300;
        let has_kid = kid
            .as_ref()
            .map(|k| doc.keys.iter().any(|key| key.kid.as_deref() == Some(k.as_str())))
            .unwrap_or(true);
        (fresh && has_kid).then(|| doc.clone())
    });
    let jwks = match cached {
        Some(doc) => doc,
        None => {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .danger_accept_invalid_certs(insecure_tls)
                .build()
                .map_err(|e| format!("idp_http_client:{e}"))?;
            let doc = fetch_jwks(&client, &jwks_url).await?;
            *cache.lock().unwrap() = Some((now, doc.clone()));
            doc
        }
    };
    verify_id_token_with_jwks(token, &jwks, audience, "", issuer.as_deref())
}

async fn fetch_jwks(client: &reqwest::Client, jwks_url: &str) -> Result<JwksDocument, String> {
    if let Err(code) = crate::substrate::egress_policy::assert_safe_outbound_url(jwks_url) {
        if crate::connector_profile::is_productionish_env() {
            return Err(code.to_string());
        }
    }
    let resp = client
        .get(jwks_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("jwks_fetch:{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("jwks_http_{}", resp.status().as_u16()));
    }
    resp.json::<JwksDocument>()
        .await
        .map_err(|e| format!("jwks_parse:{e}"))
}

/// Server-owned role mapping. Query params never grant roles.
fn sso_role_from_claims(idp_claims: &serde_json::Value) -> PlatformRole {
    let claim_name = std::env::var("CONNECTOR_SSO_ROLE_CLAIM").unwrap_or_else(|_| "connector_role".into());
    let raw = idp_claims
        .get(&claim_name)
        .and_then(|v| v.as_str())
        .or_else(|| idp_claims.get("role").and_then(|v| v.as_str()))
        .unwrap_or("");
    let map = std::env::var("CONNECTOR_SSO_ROLE_MAP").unwrap_or_default();
    // map format: idpRole=platformRole,admin=admin,viewer=viewer
    for pair in map.split(',') {
        if let Some((from, to)) = pair.split_once('=') {
            if from.trim().eq_ignore_ascii_case(raw) {
                return match to.trim().to_ascii_lowercase().as_str() {
                    "super_admin" | "superadmin" => PlatformRole::SuperAdmin,
                    "admin" => PlatformRole::Admin,
                    "operator" => PlatformRole::Operator,
                    "developer" => PlatformRole::Developer,
                    _ => PlatformRole::Viewer,
                };
            }
        }
    }
    // Default fail-closed: Viewer unless explicit allowlist maps a higher role.
    let _ = raw;
    PlatformRole::Viewer
}

fn issue_sso_session(
    state: &crate::state::SharedState,
    provider: &str,
    email: &str,
    name: &str,
    role: PlatformRole,
) -> serde_json::Value {
    let sso_user_id = {
        let mut us = state.user_store.lock().unwrap();
        if let Some(uid) = us.email_index.get(email).cloned() {
            if let Some(user) = us.users.get_mut(&uid) {
                user.last_login = Some(chrono::Utc::now().to_rfc3339());
                // Never elevate from IdP without map; keep existing role unless viewer bootstrap.
            }
            uid
        } else {
            let uid = format!("sso_{}_{}", provider, uuid::Uuid::new_v4().simple());
            let now_str = chrono::Utc::now().to_rfc3339();
            let user = User {
                user_id: uid.clone(),
                email: email.to_string(),
                name: name.to_string(),
                password_hash: String::new(),
                role: role.clone(),
                created_at: now_str.clone(),
                last_login: Some(now_str),
                totp_secret: None,
                totp_enabled: false,
                api_keys: vec![],
                locked: false,
                failed_attempts: 0,
                instance_id: None,
                tier: "community".to_string(),
                billing_state: "active".to_string(),
                stripe_customer_id: None,
                tokens_used_today: 0,
                tokens_used_month: 0,
                agents_count: 0,
                tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
            };
            us.email_index.insert(email.to_string(), uid.clone());
            us.users.insert(uid.clone(), user);
            tracing::info!(provider = %provider, email = %email, user_id = %uid, "SSO JIT provisioning");
            uid
        }
    };

    let effective_role = {
        let us = state.user_store.lock().unwrap();
        us.users
            .get(&sso_user_id)
            .map(|u| u.role.clone())
            .unwrap_or(role)
    };

    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: sso_user_id.clone(),
        email: email.to_string(),
        role: effective_role.to_str().to_string(),
        permissions: effective_role.permissions(),
        instance_id: None,
        tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
        token_type: "access".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        exp: now + 3600 * 8,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&jwt_secret()),
    )
    .unwrap_or_default();

    serde_json::json!({
        "ok": true,
        "provider": provider,
        "token": token,
        "user_id": sso_user_id,
        "email": email,
        "role": effective_role.to_str(),
        "jit_provisioned": true,
    })
}

/// GET /auth/sso/login?provider=google|okta|azure|github
/// Redirects user to IdP authorization endpoint with state + PKCE + nonce.
pub async fn sso_login(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let provider = params.get("provider").map(|s| s.as_str()).unwrap_or("google");
    let redirect_uri = std::env::var("CONNECTOR_SSO_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:8080/api/v1/auth/sso/callback".to_string());

    let (client_id, auth_endpoint) = match provider {
        "google" => (
            std::env::var("CONNECTOR_SSO_GOOGLE_CLIENT_ID").unwrap_or_default(),
            "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
        ),
        "okta" => {
            let domain = std::env::var("CONNECTOR_SSO_OKTA_DOMAIN").unwrap_or_default();
            (
                std::env::var("CONNECTOR_SSO_OKTA_CLIENT_ID").unwrap_or_default(),
                format!("https://{}/oauth2/v1/authorize", domain),
            )
        }
        "azure" => (
            std::env::var("CONNECTOR_SSO_AZURE_CLIENT_ID").unwrap_or_default(),
            format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                std::env::var("CONNECTOR_SSO_AZURE_TENANT_ID").unwrap_or_else(|_| "common".to_string())
            ),
        ),
        "github" => (
            std::env::var("CONNECTOR_SSO_GITHUB_CLIENT_ID").unwrap_or_default(),
            "https://github.com/login/oauth/authorize".to_string(),
        ),
        _ => {
            let discovery = std::env::var("CONNECTOR_SSO_DISCOVERY_URL").unwrap_or_default();
            (
                std::env::var("CONNECTOR_SSO_CLIENT_ID").unwrap_or_default(),
                std::env::var("CONNECTOR_SSO_AUTHORIZATION_URL").unwrap_or_else(|_| {
                    format!(
                        "{}/authorize",
                        discovery.trim_end_matches("/.well-known/openid-configuration")
                    )
                }),
            )
        }
    };

    if client_id.is_empty() {
        return axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::json!({
                "error": "sso_not_configured",
                "message": format!("SSO provider '{}' not configured. Set CONNECTOR_SSO_{}_CLIENT_ID env var.", provider, provider.to_uppercase()),
                "docs": "https://connector.ai/docs/sso",
            }).to_string()))
            .unwrap();
    }

    let state_token = format!("sso_{}", uuid::Uuid::new_v4().simple());
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let (code_verifier, code_challenge) = sso_pkce_pair();
    sso_pending_store().insert(
        state_token.clone(),
        SsoPending {
            provider: provider.to_string(),
            nonce: nonce.clone(),
            code_verifier,
            created_at: chrono::Utc::now().timestamp(),
            return_ui: params.get("return").map(|v| v == "ui").unwrap_or(false),
        },
    );

    let scope = if provider == "github" { "read:user user:email" } else { "openid email profile" };
    let mut authorize_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        auth_endpoint,
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(scope),
        urlencoding::encode(&state_token),
    );
    if provider != "github" {
        authorize_url.push_str(&format!(
            "&nonce={}&code_challenge={}&code_challenge_method=S256",
            urlencoding::encode(&nonce),
            urlencoding::encode(&code_challenge),
        ));
    }

    axum::http::Response::builder()
        .status(302)
        .header("location", &authorize_url)
        .body(axum::body::Body::empty())
        .unwrap()
}

/// GET /auth/sso — which SSO providers this node can start. Public: no secret is returned.
pub async fn sso_status() -> Json<serde_json::Value> {
    let set = |name: &str| std::env::var(name).map(|v| !v.trim().is_empty()).unwrap_or(false);
    let generic = set("CONNECTOR_SSO_CLIENT_ID")
        && set("CONNECTOR_SSO_AUTHORIZATION_URL")
        && set("CONNECTOR_SSO_TOKEN_URL")
        && set("CONNECTOR_SSO_JWKS_URL");
    Json(serde_json::json!({
        "providers": [{
            "id": "keycloak",
            "configured": generic,
            "issuer": std::env::var("CONNECTOR_SSO_ISSUER").ok().filter(|s| !s.is_empty()),
            "login_path": "/api/v1/auth/sso/login?provider=keycloak&return=ui",
        }],
    }))
}

/// GET /auth/sso/callback?code=...&state=...
/// Verifies state, exchanges code (PKCE), loads userinfo, JIT-provisions Viewer-by-default.
/// A login started by the operator UI is handed back to `/login#sso_token=…` (or `#sso_error=…`).
pub async fn sso_callback(
    state: State<crate::state::SharedState>,
    params: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let return_ui = params
        .get("state")
        .and_then(|s| sso_pending_store().get(s).map(|p| p.return_ui))
        .unwrap_or(false);
    let Json(body) = sso_callback_json(state, params).await;
    if !return_ui {
        return Json(body).into_response();
    }
    let fragment = match body.get("token").and_then(|v| v.as_str()).filter(|t| !t.is_empty()) {
        Some(token) => format!("sso_token={}", urlencoding::encode(token)),
        None => format!(
            "sso_error={}",
            urlencoding::encode(body.get("error").and_then(|v| v.as_str()).unwrap_or("sso_failed"))
        ),
    };
    axum::http::Response::builder()
        .status(302)
        .header("location", format!("/login#{fragment}"))
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn sso_callback_json(
    State(state): State<crate::state::SharedState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    // AUTH-04: query parameters never grant roles.
    let _ = params.get("connector_role");

    let code = match params.get("code") {
        Some(c) => c.clone(),
        None => return Json(serde_json::json!({"error": "missing_code", "message": "Authorization code not present in callback"})),
    };
    let state_param = match params.get("state") {
        Some(s) => s.clone(),
        None => return Json(serde_json::json!({"error": "missing_state"})),
    };

    let pending = match sso_pending_store().remove(&state_param) {
        Some((_, p)) => p,
        None => return Json(serde_json::json!({"error": "invalid_or_expired_state"})),
    };
    if chrono::Utc::now().timestamp() - pending.created_at > 600 {
        return Json(serde_json::json!({"error": "sso_state_expired"}));
    }
    let provider = pending.provider.as_str();
    // Prefer provider from pending state over query (attacker-controlled).
    let _ = params.get("provider");

    let client_id = match provider {
        "google"  => std::env::var("CONNECTOR_SSO_GOOGLE_CLIENT_ID").unwrap_or_default(),
        "okta"    => std::env::var("CONNECTOR_SSO_OKTA_CLIENT_ID").unwrap_or_default(),
        "azure"   => std::env::var("CONNECTOR_SSO_AZURE_CLIENT_ID").unwrap_or_default(),
        "github"  => std::env::var("CONNECTOR_SSO_GITHUB_CLIENT_ID").unwrap_or_default(),
        _         => std::env::var("CONNECTOR_SSO_CLIENT_ID").unwrap_or_default(),
    };
    if client_id.is_empty() {
        return Json(serde_json::json!({"error": "sso_not_configured"}));
    }

    let allow_unverified = std::env::var("CONNECTOR_SSO_ALLOW_UNVERIFIED_JIT")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    let redirect_uri = std::env::var("CONNECTOR_SSO_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:8080/api/v1/auth/sso/callback".to_string());
    let client_secret = sso_client_secret(provider);
    let (token_url, userinfo_url) = sso_token_and_userinfo_urls(provider);

    // Production / default: require live token exchange. Lab unverified JIT is opt-in only.
    if crate::connector_profile::is_productionish_env() || !allow_unverified {
        if client_secret.is_empty() && provider != "github" {
            // GitHub can work with client_id alone for some apps, but we still require secret in prod.
            if crate::connector_profile::is_productionish_env() && client_secret.is_empty() {
                return Json(serde_json::json!({
                    "error": "sso_client_secret_required",
                    "message": "Set CONNECTOR_SSO_*_CLIENT_SECRET for token exchange."
                }));
            }
        }

        let insecure_tls = !crate::connector_profile::is_productionish_env()
            && std::env::var("CONNECTOR_SSO_INSECURE_TLS")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false);
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(insecure_tls)
            .build()
        {
            Ok(c) => c,
            Err(e) => return Json(serde_json::json!({"error": "sso_http_client", "message": e.to_string()})),
        };

        if let Err(code) = crate::substrate::egress_policy::assert_safe_outbound_url(&token_url) {
            // Allow well-known IdP hosts even if private-IP DNS fails in lab.
            if crate::connector_profile::is_productionish_env() {
                return Json(serde_json::json!({"error": code, "message": "SSO token endpoint blocked by egress policy"}));
            }
        }

        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.clone()),
            ("redirect_uri", redirect_uri.clone()),
            ("client_id", client_id.clone()),
            ("code_verifier", pending.code_verifier.clone()),
        ];
        if !client_secret.is_empty() {
            form.push(("client_secret", client_secret.clone()));
        }

        let token_resp = if provider == "github" {
            client
                .post(&token_url)
                .header("Accept", "application/json")
                .form(&form)
                .send()
                .await
        } else {
            client.post(&token_url).form(&form).send().await
        };

        let token_json: serde_json::Value = match token_resp {
            Ok(resp) if resp.status().is_success() => resp.json().await.unwrap_or_default(),
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Json(serde_json::json!({
                    "error": "sso_token_exchange_failed",
                    "status": status,
                    "message": body.chars().take(300).collect::<String>(),
                }));
            }
            Err(e) => return Json(serde_json::json!({"error": "sso_token_exchange_failed", "message": e.to_string()})),
        };

        let access_token = token_json
            .get("access_token")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if access_token.is_empty() {
            return Json(serde_json::json!({"error": "sso_missing_access_token"}));
        }

        // OIDC providers (not GitHub): require JWKS-verified id_token.
        let mut id_claims: Option<serde_json::Value> = None;
        if provider != "github" {
            let id_token = token_json.get("id_token").and_then(|v| v.as_str()).unwrap_or("");
            let require_id = crate::connector_profile::is_productionish_env()
                || std::env::var("CONNECTOR_SSO_REQUIRE_ID_TOKEN")
                    .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(true);
            if id_token.is_empty() {
                if require_id {
                    return Json(serde_json::json!({"error": "sso_id_token_required"}));
                }
            } else {
                let Some(jwks_url) = sso_jwks_url(provider) else {
                    return Json(serde_json::json!({"error": "sso_jwks_url_missing"}));
                };
                let jwks = match fetch_jwks(&client, &jwks_url).await {
                    Ok(j) => j,
                    Err(e) => return Json(serde_json::json!({"error": "sso_jwks_fetch_failed", "message": e})),
                };
                let issuer = sso_expected_issuer(provider);
                match verify_id_token_with_jwks(
                    id_token,
                    &jwks,
                    &client_id,
                    &pending.nonce,
                    issuer.as_deref(),
                ) {
                    Ok(claims) if claims.get("connector_agent_pid").is_some() => {
                        return Json(serde_json::json!({
                            "error": "agent_account_cannot_open_operator_session",
                            "message": "This Keycloak account belongs to an agent. Agents sign in with their own token, not the operator dashboard.",
                        }));
                    }
                    Ok(claims) => {
                        crate::substrate::cvr::deployment_verify::record_operation_success(
                            state.as_ref(),
                            "iam",
                            "oidc_jwks_token_verified",
                            serde_json::json!({
                                "provider": provider,
                                "issuer": claims.get("iss"),
                                "subject_present": claims.get("sub").and_then(|v| v.as_str()).is_some(),
                                "token_stored": false,
                            }),
                        );
                        id_claims = Some(claims);
                    }
                    Err(e) => {
                        return Json(serde_json::json!({
                            "error": "sso_id_token_invalid",
                            "message": e,
                        }));
                    }
                }
            }
        }

        let userinfo = match client
            .get(&userinfo_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Accept", "application/json")
            .header("User-Agent", "connector-platform-sso")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => resp.json::<serde_json::Value>().await.unwrap_or_default(),
            Ok(resp) => {
                // Fall back to verified id_token claims when userinfo fails but id_token passed.
                if let Some(ref claims) = id_claims {
                    claims.clone()
                } else {
                    return Json(serde_json::json!({
                        "error": "sso_userinfo_failed",
                        "status": resp.status().as_u16(),
                    }));
                }
            }
            Err(e) => {
                if let Some(ref claims) = id_claims {
                    claims.clone()
                } else {
                    return Json(serde_json::json!({"error": "sso_userinfo_failed", "message": e.to_string()}));
                }
            }
        };

        // Prefer verified id_token email when present.
        let email = id_claims
            .as_ref()
            .and_then(|c| c.get("email").and_then(|v| v.as_str()))
            .or_else(|| userinfo.get("email").and_then(|v| v.as_str()))
            .or_else(|| userinfo.get("preferred_username").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        if email.is_empty() {
            return Json(serde_json::json!({"error": "sso_email_required"}));
        }
        let name = id_claims
            .as_ref()
            .and_then(|c| c.get("name").and_then(|v| v.as_str()))
            .or_else(|| userinfo.get("name").and_then(|v| v.as_str()))
            .or_else(|| userinfo.get("login").and_then(|v| v.as_str()))
            .unwrap_or(email.as_str())
            .to_string();
        let role_source = id_claims.as_ref().unwrap_or(&userinfo);
        let role = sso_role_from_claims(role_source);
        return Json(issue_sso_session(&state, provider, &email, &name, role));
    }

    // Lab-only unverified JIT: Viewer only.
    let sso_email = format!("sso+{}+{}@connector.sso", provider, &code[..8.min(code.len())]);
    Json(issue_sso_session(
        &state,
        provider,
        &sso_email,
        &format!("SSO:{provider}"),
        PlatformRole::Viewer,
    ))
}

// Legacy compatibility endpoint
pub async fn auth_token_legacy(
    State(state): State<crate::state::SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    if let Some(api_key) = req.get("api_key").and_then(|v| v.as_str()) {
        // ── Playground session keys (cpk_pg_*) ──────────────────────────────
        // These are ephemeral keys issued by the playground trial page. They
        // live in playground_sessions (in-memory), not the user API-key store.
        if api_key.starts_with("cpk_pg_") {
            let (session_id, tenant_id, session_email) =
                match crate::services::playground::lookup_playground_session(
                    &state.playground_sessions,
                    api_key,
                ) {
                    Some(t) => t,
                    None => {
                        return Json(serde_json::json!({
                            "error": "Playground session key not found, expired, or ended"
                        }))
                    }
                };
            let user_id = session_id.clone();
            let scopes = vec![
                "read".to_string(),
                "write".to_string(),
                "settings:read".to_string(),
                "settings:write".to_string(),
            ];
            let email = session_email.unwrap_or_else(|| {
                format!("trial_{}@playground.local", &session_id[..8.min(session_id.len())])
            });

            let (access_token, _) = match create_token(
                &user_id,
                &email,
                "developer",
                &scopes,
                None,
                Some(&tenant_id),
                "playground_key",
                5400,
            ) {
                Ok(token) => token,
                Err(err) => return Json(serde_json::json!({"error": err})),
            };

            return Json(serde_json::json!({
                "access_token": access_token,
                "refresh_token": "",
                "token_type": "Bearer",
                "expires_in": 5400,
                "user_id": user_id,
                "email": email,
                "name": "Trial User",
                "role": "developer",
                "permissions": scopes,
                "auth_via": "playground_key",
                "tenant_id": tenant_id,
            }));
        }

        if api_key.starts_with("cpk_") {
            let user_id = match validate_api_key(api_key) {
                Ok(user_id) => user_id,
                Err(err) => return Json(serde_json::json!({"error": err})),
            };
            let scopes = match api_key_scopes(api_key) {
                Ok(scopes) => scopes,
                Err(err) => return Json(serde_json::json!({"error": err})),
            };

            let user_store = match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
        Ok(g) => g,
        Err(e) => return Json(serde_json::json!({"error": e, "status": 503})),
    };
            let maybe_user = user_store.get_user(&user_id).cloned();
            drop(user_store);

            let email = maybe_user.as_ref().map(|u| u.email.clone()).unwrap_or_else(|| format!("{}@connector.local", user_id));
            let name = maybe_user.as_ref().map(|u| u.name.clone()).unwrap_or_else(|| "Operator".to_string());
            let role = maybe_user.as_ref().map(|u| u.role.to_str().to_string()).unwrap_or_else(|| PlatformRole::Service.to_str().to_string());
            let instance_id = maybe_user.as_ref().and_then(|u| u.instance_id.clone());

            let token_tenant = resolve_token_tenant_id(maybe_user.as_ref(), None);
            let (access_token, _) = match create_token(
                &user_id,
                &email,
                &role,
                &scopes,
                instance_id.as_deref(),
                token_tenant.as_deref(),
                "api_key",
                28800,
            ) {
                Ok(token) => token,
                Err(err) => return Json(serde_json::json!({"error": err})),
            };

            return Json(serde_json::json!({
                "access_token": access_token,
                "refresh_token": "",
                "token_type": "Bearer",
                "expires_in": 28800,
                "user_id": user_id,
                "email": email,
                "name": name,
                "role": role,
                "permissions": scopes,
                "auth_via": "api_key",
            }));
        }
        return Json(serde_json::json!({"error": "Unsupported API key format"}));
    }

    let email = req.get("email").or(req.get("user")).and_then(|v| v.as_str()).unwrap_or("");
    let password = req.get("password").and_then(|v| v.as_str()).unwrap_or("");

    if email.is_empty() || password.is_empty() {
        return Json(serde_json::json!({"error": "email and password required"}));
    }

    login(State(state), Json(LoginRequest {
        email: email.to_string(),
        password: password.to_string(),
        totp_code: req.get("totp_code").and_then(|v| v.as_str()).map(|s| s.to_string()),
        device_fingerprint: None,
        tenant_id: req.get("tenant_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
    })).await
}

#[cfg(test)]
mod jwt_secret_env_tests {
    use super::jwt_secret;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_cleared_env<F: FnOnce()>(f: F) {
        let _lock = ENV_MUTEX.lock().unwrap();
        let keys = [
            "CONNECTOR_JWT_SECRET",
            "CONNECTOR_DEV_MODE",
            "CONNECTOR_ENV",
        ];
        let saved: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|k| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for k in &keys {
            std::env::remove_var(k);
        }
        f();
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(&k, val),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn connect_env_dev_uses_ephemeral_secret() {
        with_cleared_env(|| {
            std::env::set_var("CONNECTOR_ENV", "dev");
            let a = jwt_secret();
            let b = jwt_secret();
            assert_eq!(a.len(), 64);
            assert_eq!(b.len(), 64);
        });
    }

    #[test]
    fn connect_env_development_uses_ephemeral_secret() {
        with_cleared_env(|| {
            std::env::set_var("CONNECTOR_ENV", "development");
            assert_eq!(jwt_secret().len(), 64);
        });
    }

    #[test]
    fn production_without_secret_panics() {
        with_cleared_env(|| {
            std::env::set_var("CONNECTOR_ENV", "production");
            let r = std::panic::catch_unwind(|| {
                let _ = jwt_secret();
            });
            assert!(r.is_err());
        });
    }
}

#[cfg(test)]
mod extract_claims_playground_tests {
    use super::extract_claims;
    use axum::http::{HeaderMap, HeaderValue};
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(pairs: &[(&str, Option<&str>)], f: F) {
        let _lock = ENV_MUTEX.lock().unwrap();
        let keys = [
            "CONNECTOR_PLAYGROUND",
            "CONNECTOR_DEV_MODE",
            "CONNECTOR_ENV",
            "CONNECTOR_ULTIMATE_FREE",
            "CONNECTOR_OPEN_AUTH",
            "CONNECTOR_FREE_TIER_OPEN_AUTH",
        ];
        let saved: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|k| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for k in &keys {
            std::env::remove_var(k);
        }
        for (k, v) in pairs {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(&k, val),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn playground_invalid_bearer_is_not_open_operator() {
        with_env(
            &[
                ("CONNECTOR_PLAYGROUND", Some("1")),
                ("CONNECTOR_DEV_MODE", Some("1")),
                ("CONNECTOR_ENV", Some("dev")),
            ],
            || {
                let mut h = HeaderMap::new();
                h.insert(
                    "authorization",
                    HeaderValue::from_static("Bearer cpk_pg_not_a_jwt"),
                );
                let claims = extract_claims(&h);
                assert!(claims.is_none(), "playground must not mint open-operator");
            },
        );
    }

    #[test]
    fn playground_missing_bearer_is_not_open_operator() {
        with_env(
            &[
                ("CONNECTOR_PLAYGROUND", Some("1")),
                ("CONNECTOR_DEV_MODE", Some("1")),
                ("CONNECTOR_ENV", Some("dev")),
            ],
            || {
                let h = HeaderMap::new();
                assert!(extract_claims(&h).is_none());
            },
        );
    }

    #[test]
    fn sso_role_map_defaults_to_viewer_without_explicit_map() {
        let prev = std::env::var("CONNECTOR_SSO_ROLE_MAP").ok();
        std::env::remove_var("CONNECTOR_SSO_ROLE_MAP");
        let claims = serde_json::json!({"connector_role": "super_admin", "role": "admin"});
        assert_eq!(super::sso_role_from_claims(&claims), super::PlatformRole::Viewer);
        std::env::set_var("CONNECTOR_SSO_ROLE_MAP", "admin=admin");
        let claims2 = serde_json::json!({"role": "admin"});
        assert_eq!(super::sso_role_from_claims(&claims2), super::PlatformRole::Admin);
        match prev {
            Some(v) => std::env::set_var("CONNECTOR_SSO_ROLE_MAP", v),
            None => std::env::remove_var("CONNECTOR_SSO_ROLE_MAP"),
        }
    }

    #[test]
    fn sso_pending_state_is_single_use() {
        let (verifier, challenge) = super::sso_pkce_pair();
        assert!(!verifier.is_empty());
        assert!(!challenge.is_empty());
        assert_ne!(verifier, challenge);
        let state = format!("sso_{}", uuid::Uuid::new_v4().simple());
        super::sso_pending_store().insert(
            state.clone(),
            super::SsoPending {
                provider: "google".into(),
                nonce: "n".into(),
            code_verifier: verifier,
            created_at: chrono::Utc::now().timestamp(),
            return_ui: false,
            },
        );
        assert!(super::sso_pending_store().remove(&state).is_some());
        assert!(super::sso_pending_store().remove(&state).is_none());
    }
}

#[cfg(test)]
mod sso_jwks_tests {
    use super::{verify_id_token_with_jwks, JwkKey, JwksDocument};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::Serialize;

    // Ephemeral RSA-2048 test key (AUTH-04 unit vector only; not a production secret).
    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCeqCAEkqB6eWTJ
YFUVhjA1Zlkryg6oN7jqE7BdaXaNq07GrxRuArIZigJ6kb5le5YsqiGvJoxwMTSV
/tkbJZObY/hjRO3T4lVz2css33hAX3YQ7EJkq3KItMqz/Sx3B5n/UXX6PsUIwP9G
kczUPlTOQvPhNxTcpbvkXxEiCqhBjOZcWQIUx3dzPLfCgx6Ks1lV/uOcl+rHgFOJ
XPXVoNOJU1ucQRi2vpHhEBC97Rq9IKGSuA5Wil/Vo1/QG4nG+6g/jSsSHU2bgn0+
1KGUfD3WhMlpGgE2EKdZ4keHdVgU2UR+hvKv6YomdHgErrvQ6du5gP+UbTz9pR8x
xKRJZiG3AgMBAAECggEABv0YkqBTgaxDlHFHXjAv2HJT3uTCz4XLge1wbopHkXGo
gdeoJTkTgkzSKMxZtYZY9PULkHe4u5/B6rzemwkFNFTrgJKX4qZM0FJu1jZZHtt1
oRo0dH3EM6G5xMLpXgGPjC/DlsyECQuDUyb3Uv6/OpS4FxrCMv6j76krtohUpV/P
OFyjPX8rNumpTlRD1RHYTSDtzad7CYrGldtO0OH022ZGsewAEKb8eCyPFuFGPhhF
gD3yS9J+BpYyaD9hWaz4ZGFyKlfhvcn/K3O+/mf7sYTfkAsKz2zCjgTzEsCyXJkt
S+HzRHRYNht/ouWVMCTShbFgkFnno32bgu2cig7NCQKBgQDWj7RvHOPRTKZUKsGp
GPFcVrkS4xIjiRsIIZhvv6r4wb03wXAfjYROe0ks7MDVLXUM0Ijl46rm/dT0Ve+r
IrBSoF0HYejBAGiw7RztwcYI5R3mvJTmUQ36DFDZdW9lhwbN7KfKrBQ1Rwovy28T
I9tSyfjoj+ocquP12w0MA5Fq3wKBgQC9TGWWqoZ9Au9X/dVHY/trRW0x0fzIWaa+
JMBAfF/oWG5UbtkDvp3h/B0uJlxW4UDRiBq+aOaM3M/LfcvlZ+uOQZouFRZvdbdp
umFkvOnlxIZQkZjCpcqPYPk4TGxzHJOGipuVtDR0PVYsweH9+rkyWsSAZEmp26rF
HTaKe6h8KQKBgHQ8hdNsIz9P9wvB3ghtqtQLZ1gEC9+Ud0CAcsSXYVhCHPAHq2Zs
lDCwOYRM/mp+pdq7Xm6sV/mrqaJ0q9JaiIs6tSs6r41fW1f+HJ3xTAell/1YTJI5
dwjvgx1LsX2fGOCWRJBXiNsUEUCzRQlpc3f2UxIqZPoC2lxmvzqy9CShAoGBAKYo
xwtHR6G3z8tW3b06f9gbKswOXGqodvp0W+S+x5i09rNaUVc+HGve1uZJecgxFKpX
Y9I7VhPTRvqBw1XssBFAeEt26yiPFZ3SoebBBDZRGOzjwEkrKfBM2LWYL6GjNcNl
K0hu05QsutWyoeJEEAepMM7aOObGENHQ4K0R+kRxAoGBAJ4zuYv0d29HioCDT7xp
XYXtkLm/JQgD88mG0FHBzpilVwb4v4fYuNuHT/7qb0A221oaD+PzPB9Av2bwnfJh
oJ/m6Dbg86rLC3a/kLEovfq2W1HlLv9r9IYA8CwuMPz/ttDuZCBToWmUUThA3wOr
zjDL77Ci6gZOUkN66qBjyPYb
-----END PRIVATE KEY-----";

    const TEST_RSA_N: &str = "nqggBJKgenlkyWBVFYYwNWZZK8oOqDe46hOwXWl2jatOxq8UbgKyGYoCepG-ZXuWLKohryaMcDE0lf7ZGyWTm2P4Y0Tt0-JVc9nLLN94QF92EOxCZKtyiLTKs_0sdweZ_1F1-j7FCMD_RpHM1D5UzkLz4TcU3KW75F8RIgqoQYzmXFkCFMd3czy3woMeirNZVf7jnJfqx4BTiVz11aDTiVNbnEEYtr6R4RAQve0avSChkrgOVopf1aNf0BuJxvuoP40rEh1Nm4J9PtShlHw91oTJaRoBNhCnWeJHh3VYFNlEfobyr-mKJnR4BK670OnbuYD_lG08_aUfMcSkSWYhtw";
    const TEST_RSA_E: &str = "AQAB";

    #[derive(Serialize)]
    struct OidcTestClaims {
        sub: String,
        email: String,
        aud: String,
        iss: String,
        nonce: String,
        exp: i64,
        iat: i64,
    }

    fn test_jwks() -> JwksDocument {
        JwksDocument {
            keys: vec![JwkKey {
                kty: "RSA".into(),
                kid: Some("test-kid".into()),
                n: Some(TEST_RSA_N.into()),
                e: Some(TEST_RSA_E.into()),
                alg: Some("RS256".into()),
                key_use: Some("sig".into()),
            }],
        }
    }

    fn mint_id_token(nonce: &str, aud: &str, iss: &str, exp_offset: i64) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".into());
        let claims = OidcTestClaims {
            sub: "sub-1".into(),
            email: "user@example.com".into(),
            aud: aud.into(),
            iss: iss.into(),
            nonce: nonce.into(),
            exp: now + exp_offset,
            iat: now,
        };
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).expect("test rsa pem"),
        )
        .expect("mint id_token")
    }

    #[test]
    fn jwks_verifies_valid_rs256_id_token() {
        let token = mint_id_token("nonce-abc", "client-xyz", "https://issuer.example", 3600);
        let claims = verify_id_token_with_jwks(
            &token,
            &test_jwks(),
            "client-xyz",
            "nonce-abc",
            Some("https://issuer.example"),
        )
        .expect("valid id_token");
        assert_eq!(claims.get("email").and_then(|v| v.as_str()), Some("user@example.com"));
        assert_eq!(claims.get("sub").and_then(|v| v.as_str()), Some("sub-1"));
    }

    #[test]
    fn jwks_rejects_nonce_mismatch_and_wrong_audience() {
        let token = mint_id_token("nonce-abc", "client-xyz", "https://issuer.example", 3600);
        let err = verify_id_token_with_jwks(
            &token,
            &test_jwks(),
            "client-xyz",
            "wrong-nonce",
            Some("https://issuer.example"),
        )
        .unwrap_err();
        assert!(err.contains("sso_nonce_mismatch"), "{err}");

        let err_aud = verify_id_token_with_jwks(
            &token,
            &test_jwks(),
            "other-client",
            "nonce-abc",
            Some("https://issuer.example"),
        )
        .unwrap_err();
        assert!(err_aud.contains("id_token_invalid"), "{err_aud}");
    }

    #[test]
    fn jwks_rejects_expired_and_tampered_tokens() {
        let expired = mint_id_token("n", "client-xyz", "https://issuer.example", -120);
        let err = verify_id_token_with_jwks(
            &expired,
            &test_jwks(),
            "client-xyz",
            "n",
            Some("https://issuer.example"),
        )
        .unwrap_err();
        assert!(err.contains("id_token_invalid"), "{err}");

        let mut good = mint_id_token("n", "client-xyz", "https://issuer.example", 3600);
        // Flip a character in the signature segment.
        if let Some(last) = good.pop() {
            good.push(if last == 'A' { 'B' } else { 'A' });
        }
        let err_tamper = verify_id_token_with_jwks(
            &good,
            &test_jwks(),
            "client-xyz",
            "n",
            Some("https://issuer.example"),
        )
        .unwrap_err();
        assert!(err_tamper.contains("id_token_invalid"), "{err_tamper}");
    }

    #[test]
    #[ignore = "requires a live Keycloak id_token in CONNECTOR_IAM_ID_TOKEN"]
    fn live_keycloak_id_token_verifies() {
        let token = std::env::var("CONNECTOR_IAM_ID_TOKEN").expect("CONNECTOR_IAM_ID_TOKEN");
        let jwks_path = std::env::var("CONNECTOR_IAM_JWKS").expect("CONNECTOR_IAM_JWKS");
        let raw = std::fs::read_to_string(jwks_path).expect("read jwks");
        let jwks: JwksDocument = serde_json::from_str(&raw).expect("jwks json");
        let client_id = std::env::var("CONNECTOR_IAM_CLIENT_ID").expect("client id");
        let issuer = std::env::var("CONNECTOR_IAM_ISSUER").expect("issuer");
        let claims = verify_id_token_with_jwks(&token, &jwks, &client_id, "", Some(issuer.as_str()))
            .expect("live keycloak id_token");
        assert!(claims.get("sub").and_then(|v| v.as_str()).is_some());
    }
}
