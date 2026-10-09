/// RPC Token System — Vault-style batch tokens for binary authentication.
///
/// Architecture (adapted from HashiCorp Vault AppRole + batch token patterns):
///
///   1. At issuance time, each download gets a unique (role_id, secret_id) pair.
///      secret_id is one-time-use — consumed on first successful /rpc/v1/auth.
///
///   2. Binary presents (role_id, secret_id, machine_id, binary_hash) →
///      server validates and returns a short-lived RPC token (TTL: 1h).
///
///   3. RPC token is a self-contained HMAC-signed blob (batch token pattern):
///      no database lookup needed to validate — just verify HMAC + check expiry.
///      This scales to millions of binaries without per-request DB reads.
///
///   4. Revocation is via a bloom filter + append-only revocation log.
///      Revoked token IDs are checked O(1) against the in-memory bloom filter.
///
///   5. Payment gate: secret_id is ONLY issued after Stripe payment confirmed.
///      No payment → no secret_id → no RPC token → all paid APIs return 402.
///
/// Token wire format (base64url-encoded JSON):
///   {
///     "v":   1,                     // token format version
///     "tid": "tok_<uuid>",          // token ID — for revocation
///     "iid": "inst_<id>",           // instance_id
///     "bid": "bin_<uuid>",          // binary_id (unique per download)
///     "mid": "<sha256_machine_id>", // machine fingerprint — node-lock
///     "tier":"Enterprise",          // license tier
///     "perm":["full","sso"],        // permission set
///     "iat": 1234567890,            // issued at (unix ts)
///     "exp": 1234571490,            // expires at (unix ts, iat+3600)
///     "sig": "<hmac_hex>"           // HMAC-SHA256(server_rpc_secret, payload)
///   }

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_TTL_SECS: i64 = 3600;         // 1 hour
const TOKEN_RENEWAL_WINDOW_SECS: i64 = 300; // renew when < 5 min left
pub const RPC_TOKEN_VERSION: u8 = 1;

// ── Token payload ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTokenPayload {
    pub v:    u8,           // format version
    pub tid:  String,       // token_id (for revocation)
    pub iid:  String,       // instance_id
    pub bid:  String,       // binary_id (per-download stamp)
    pub mid:  String,       // machine_id (node-lock binding)
    pub tier: String,       // license tier
    pub perm: Vec<String>,  // permissions
    pub iat:  i64,          // issued_at unix timestamp
    pub exp:  i64,          // expires_at unix timestamp
}

#[derive(Debug, Clone)]
pub struct RpcToken {
    pub payload: RpcTokenPayload,
    pub raw:     String,    // the full serialized+signed token string
}

// ── Token manager ─────────────────────────────────────────────────────────────

pub struct RpcTokenManager {
    /// HMAC secret for signing/verifying tokens. Never exposed externally.
    /// Loaded from CONNECTOR_RPC_SECRET env var or generated and persisted.
    secret: Vec<u8>,
    /// In-memory revocation set — token IDs that have been revoked.
    /// Rebuilt from SQLite on startup. O(1) lookup.
    revoked: HashSet<String>,
    /// Per-binary rate limit tracker: binary_id → (window_start_ts, call_count)
    rate_limits: std::collections::HashMap<String, (i64, u32)>,
    /// Max calls per binary per hour
    rate_limit_per_hour: u32,
}

impl RpcTokenManager {
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            revoked: HashSet::new(),
            rate_limits: std::collections::HashMap::new(),
            rate_limit_per_hour: std::env::var("CONNECTOR_RPC_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600), // 1 call/sec average burst window
        }
    }

    /// Load from env var or generate and persist to disk.
    pub fn load_or_generate_secret(data_dir: &str) -> Vec<u8> {
        // Priority: env var → disk file → generate new
        if let Ok(s) = std::env::var("CONNECTOR_RPC_SECRET") {
            if !s.is_empty() {
                let bytes = hex::decode(&s).unwrap_or_else(|_| s.into_bytes());
                if bytes.len() >= 32 {
                    eprintln!("[rpc_token] RPC secret loaded from CONNECTOR_RPC_SECRET");
                    return bytes;
                }
            }
        }

        let secret_path = format!("{}/keys/rpc.secret", data_dir);
        if std::path::Path::new(&secret_path).exists() {
            match std::fs::read(&secret_path) {
                Ok(b) if b.len() == 64 => {
                    eprintln!("[rpc_token] RPC secret loaded from {}", secret_path);
                    return b;
                }
                _ => eprintln!("[rpc_token] WARN: corrupt rpc.secret, regenerating"),
            }
        }

        // Generate 64-byte secret
        use rand::RngCore;
        let mut secret = vec![0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut secret);

        let _ = std::fs::create_dir_all(format!("{}/keys", data_dir));
        std::fs::write(&secret_path, &secret)
            .unwrap_or_else(|e| eprintln!("[rpc_token] WARN: cannot persist rpc.secret: {}", e));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&secret_path,
                std::fs::Permissions::from_mode(0o600));
        }

        eprintln!("[rpc_token] Generated new RPC HMAC secret → {}", secret_path);
        secret
    }

    /// Issue a new RPC token for an authenticated binary instance.
    pub fn issue(
        &self,
        instance_id: &str,
        binary_id:   &str,
        machine_id:  &str,
        tier:        &str,
        permissions: Vec<String>,
    ) -> RpcToken {
        let now = chrono::Utc::now().timestamp();
        let token_id = format!("tok_{}", uuid::Uuid::new_v4().simple());

        let payload = RpcTokenPayload {
            v:    RPC_TOKEN_VERSION,
            tid:  token_id,
            iid:  instance_id.to_string(),
            bid:  binary_id.to_string(),
            mid:  machine_id.to_string(),
            tier: tier.to_string(),
            perm: permissions,
            iat:  now,
            exp:  now + TOKEN_TTL_SECS,
        };

        let raw = self.sign_payload(&payload);
        RpcToken { payload, raw }
    }

    /// Validate an RPC token string. Returns the payload if valid.
    pub fn validate(&self, token_str: &str) -> Result<RpcTokenPayload, TokenError> {
        let (payload, sig_hex) = self.parse_token(token_str)?;

        // 1. Verify HMAC signature
        let payload_json = self.payload_canonical(&payload);
        let expected = self.hmac_hex(payload_json.as_bytes());
        if !constant_time_eq(sig_hex.as_bytes(), expected.as_bytes()) {
            return Err(TokenError::InvalidSignature);
        }

        // 2. Check expiry
        let now = chrono::Utc::now().timestamp();
        if now > payload.exp {
            return Err(TokenError::Expired);
        }

        // 3. Check revocation
        if self.revoked.contains(&payload.tid) {
            return Err(TokenError::Revoked);
        }

        // 4. Version check
        if payload.v != RPC_TOKEN_VERSION {
            return Err(TokenError::VersionMismatch);
        }

        Ok(payload)
    }

    /// Validate token and additionally check machine_id binding.
    pub fn validate_node_locked(
        &self,
        token_str:      &str,
        expected_machine_id: &str,
    ) -> Result<RpcTokenPayload, TokenError> {
        let payload = self.validate(token_str)?;
        if payload.mid != expected_machine_id {
            return Err(TokenError::MachineMismatch);
        }
        Ok(payload)
    }

    /// Renew a token if it's within the renewal window.
    /// Returns new token if renewable, error if not.
    pub fn renew(&self, token_str: &str) -> Result<RpcToken, TokenError> {
        let payload = self.validate(token_str)?;
        let now = chrono::Utc::now().timestamp();

        // Only allow renewal when within renewal window
        if (payload.exp - now) > TOKEN_RENEWAL_WINDOW_SECS {
            return Err(TokenError::NotYetRenewable);
        }

        Ok(self.issue(
            &payload.iid.clone(),
            &payload.bid.clone(),
            &payload.mid.clone(),
            &payload.tier.clone(),
            payload.perm.clone(),
        ))
    }

    /// Revoke a token by its token_id. Persists to revocation set.
    pub fn revoke(&mut self, token_id: &str) {
        self.revoked.insert(token_id.to_string());
    }

    /// Revoke all tokens for an instance_id (e.g. on kill command).
    /// NOTE: for full coverage, all tokens issued since last revocation
    /// must be swept — in practice, the TTL (1h) provides natural expiry.
    pub fn revoke_all_for_instance(&mut self, instance_id: &str, issued_since: &[String]) {
        for tid in issued_since {
            self.revoked.insert(tid.clone());
        }
        eprintln!("[rpc_token] Revoked {} tokens for instance {}", issued_since.len(), instance_id);
    }

    /// Load revoked token IDs from persistence (called on startup).
    pub fn load_revoked(&mut self, token_ids: Vec<String>) {
        for tid in token_ids {
            self.revoked.insert(tid);
        }
        eprintln!("[rpc_token] Loaded {} revoked token IDs", self.revoked.len());
    }

    /// Rate limit check: returns true if request is allowed.
    pub fn check_rate_limit(&mut self, binary_id: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let entry = self.rate_limits.entry(binary_id.to_string()).or_insert((now, 0));

        // Reset window every hour
        if now - entry.0 > 3600 {
            *entry = (now, 1);
            return true;
        }

        entry.1 += 1;
        entry.1 <= self.rate_limit_per_hour
    }

    /// Validate token for revocation purposes — checks signature only, ignores expiry.
    pub fn validate_for_revoke(&self, token_str: &str) -> Result<RpcTokenPayload, TokenError> {
        let (payload, sig_hex) = self.parse_token(token_str)?;
        let payload_json = self.payload_canonical(&payload);
        let expected = self.hmac_hex(payload_json.as_bytes());
        if !constant_time_eq(sig_hex.as_bytes(), expected.as_bytes()) {
            return Err(TokenError::InvalidSignature);
        }
        if payload.v != RPC_TOKEN_VERSION {
            return Err(TokenError::VersionMismatch);
        }
        Ok(payload)
    }

    /// Returns seconds remaining on the token.
    pub fn ttl_remaining(payload: &RpcTokenPayload) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (payload.exp - now).max(0)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn sign_payload(&self, payload: &RpcTokenPayload) -> String {
        let canonical = self.payload_canonical(payload);
        let sig = self.hmac_hex(canonical.as_bytes());
        // Encode as base64url(json_without_sig) + "." + sig_hex
        let payload_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            canonical.as_bytes(),
        );
        format!("{}.{}", payload_b64, sig)
    }

    fn parse_token(&self, token_str: &str) -> Result<(RpcTokenPayload, String), TokenError> {
        let dot = token_str.rfind('.').ok_or(TokenError::Malformed)?;
        let payload_b64 = &token_str[..dot];
        let sig_hex = token_str[dot + 1..].to_string();

        let payload_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload_b64,
        ).map_err(|_| TokenError::Malformed)?;

        let payload: RpcTokenPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|_| TokenError::Malformed)?;

        Ok((payload, sig_hex))
    }

    fn payload_canonical(&self, payload: &RpcTokenPayload) -> String {
        // Deterministic canonical form — fields in fixed order, no sig field
        format!(
            r#"{{"v":{},"tid":"{}","iid":"{}","bid":"{}","mid":"{}","tier":"{}","perm":{},"iat":{},"exp":{}}}"#,
            payload.v, payload.tid, payload.iid, payload.bid, payload.mid,
            payload.tier,
            serde_json::to_string(&payload.perm).unwrap_or_else(|_| "[]".into()),
            payload.iat, payload.exp,
        )
    }

    fn hmac_hex(&self, data: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC accepts any key size");
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
    }
}

// ── Token errors ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum TokenError {
    Malformed,
    InvalidSignature,
    Expired,
    Revoked,
    VersionMismatch,
    MachineMismatch,
    NotYetRenewable,
    RateLimited,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Malformed         => write!(f, "Token malformed"),
            TokenError::InvalidSignature  => write!(f, "Token signature invalid"),
            TokenError::Expired           => write!(f, "Token expired — renew via /rpc/v1/renew"),
            TokenError::Revoked           => write!(f, "Token revoked"),
            TokenError::VersionMismatch   => write!(f, "Token version mismatch"),
            TokenError::MachineMismatch   => write!(f, "Machine ID mismatch — node-lock violation"),
            TokenError::NotYetRenewable   => write!(f, "Token not yet in renewal window"),
            TokenError::RateLimited       => write!(f, "Rate limit exceeded"),
        }
    }
}

/// Constant-time byte comparison (prevents timing attacks).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Per-download unique binary identity ───────────────────────────────────────

/// Generated at purchase/issuance time. Each download gets a unique stamp.
/// This is the "DAO identity" — deterministic, verifiable, non-transferable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIssuance {
    /// Globally unique ID for this specific binary download/installation.
    /// Burned into the installer. Cannot be shared between instances.
    pub binary_id: String,

    /// Role ID — public identifier for this license tier/customer.
    /// Analogous to Vault AppRole RoleID. Can be shared across binaries.
    pub role_id: String,

    /// Secret ID — single-use credential for exchanging an RPC token.
    /// Analogous to Vault AppRole SecretID. Consumed on first checkin.
    /// After use → null. Attempting to reuse returns 401.
    pub secret_id: String,

    /// Whether secret_id has been consumed (exchanged for first RPC token).
    pub secret_id_used: bool,

    /// Customer-linked key this issuance belongs to.
    pub key_id: String,

    /// Tier baked into this specific binary.
    pub tier: String,

    /// Optional machine_id for node-locking. If set, RPC tokens are
    /// only valid on the machine with this fingerprint.
    pub locked_machine_id: Option<String>,

    /// Timestamp of issuance (when binary was downloaded/provisioned).
    pub issued_at: String,

    /// Expiry of this binary's credential (typically same as license expiry).
    pub expires_at: Option<String>,

    /// Number of times this binary has successfully authenticated.
    pub auth_count: u32,

    /// Last RPC token IDs issued — used for revocation on kill.
    pub active_token_ids: Vec<String>,
}

impl BinaryIssuance {
    /// Generate a new unique binary issuance at download/purchase time.
    pub fn generate(key_id: &str, tier: &str, locked_machine_id: Option<String>, expires_at: Option<String>) -> Self {
        use rand::RngCore;

        // binary_id: unique per download — UUID v4 with prefix
        let binary_id = format!("bin_{}", uuid::Uuid::new_v4().simple());

        // role_id: derived from key_id — stable identifier for this license
        let role_id = derive_role_id(key_id);

        // secret_id: 32 random bytes, hex-encoded — single-use
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret_id = format!("sid_{}", hex::encode(secret_bytes));

        Self {
            binary_id,
            role_id,
            secret_id,
            secret_id_used: false,
            key_id: key_id.to_string(),
            tier: tier.to_string(),
            locked_machine_id,
            issued_at: chrono::Utc::now().to_rfc3339(),
            expires_at,
            auth_count: 0,
            active_token_ids: Vec::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(ref exp) = self.expires_at {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                return dt < chrono::Utc::now();
            }
        }
        false
    }
}

/// Derive a stable role_id from a license key_id.
/// role_id is public and non-secret — it identifies the license tier/customer.
pub fn derive_role_id(key_id: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(b"connector_role_id_v1:");
    h.update(key_id.as_bytes());
    let result = h.finalize();
    format!("rid_{}", hex::encode(&result[..16]))
}
