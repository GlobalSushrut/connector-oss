use serde::{Deserialize, Serialize};

/// Embedded binary identity — compiled into every connector-platform binary.
///
/// In production builds, CONNECTOR_KEY_ID, CONNECTOR_BINARY_ID_BAKED, CONNECTOR_TIER_BAKED
/// are injected at build time via build.rs reading a .license-seed file or env vars.
/// The machine_id is computed at runtime from hardware fingerprints for node-locking.
///
/// RPC Authentication flow (Vault AppRole pattern):
///   1. Binary reads baked-in role_id + secret_id (injected at build / first run)
///   2. On startup: POST /rpc/v1/auth → exchange for short-lived RPC token (1h TTL)
///   3. All paid-tier feature checks include the RPC token in Authorization header
///   4. Every hour: POST /rpc/v1/renew to refresh token
///   5. On clean shutdown: POST /rpc/v1/revoke to clean up token server-side

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIdentity {
    pub license_server_url: String,
    pub license_key_id:     String,
    pub instance_id:        String,
    pub binary_id:          String,
    pub binary_hash:        String,
    pub tier:               String,
    pub permission_banner:  String,
    pub build_timestamp:    String,
    pub version:            String,
    pub machine_id:         String,
    pub hostname:           String,

    /// Seconds of offline operation allowed before hard-blocking (default 72h).
    pub offline_grace_secs: u64,

    /// UTC epoch secs of last successful license server contact.
    /// Persisted to $CONNECTOR_DATA_DIR/license/last_checkin
    pub last_checkin_ts: Option<i64>,

    /// Active RPC token (in-memory only — never persisted to disk).
    /// Issued by /rpc/v1/auth, renewed hourly, revoked on shutdown.
    #[serde(skip)]
    pub rpc_token: Option<String>,

    /// RPC token ID — used for revocation on shutdown.
    #[serde(skip)]
    pub rpc_token_id: Option<String>,

    /// RPC token expiry (unix timestamp).
    #[serde(skip)]
    pub rpc_token_exp: Option<i64>,

    /// role_id baked at build time (Vault AppRole analogue — public identifier).
    pub role_id: String,

    /// secret_id — one-time credential used to exchange for first RPC token.
    /// After first successful auth, this is consumed server-side.
    /// Stored in $CONNECTOR_DATA_DIR/license/secret_id (0600) after first issuance.
    /// If blank, binary operates in Community/unlicensed mode.
    #[serde(skip_serializing)]
    pub secret_id: String,
}

impl BinaryIdentity {
    pub fn from_env() -> Self {
        let hostname = hostname();
        let machine_id = compute_machine_id();

        let offline_grace_secs = std::env::var("CONNECTOR_OFFLINE_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(72 * 3600);

        // role_id: baked at build time from .license-seed, overridable at runtime
        let role_id = std::env::var("CONNECTOR_ROLE_ID")
            .unwrap_or_else(|_| {
                option_env!("CONNECTOR_ROLE_ID_BAKED")
                    .unwrap_or("")
                    .to_string()
            });

        // secret_id: baked at build time (first-boot only), overridable
        // After first auth, the server consumes it — binary should NOT retry with old secret_id
        let secret_id = std::env::var("CONNECTOR_SECRET_ID")
            .unwrap_or_else(|_| {
                option_env!("CONNECTOR_SECRET_ID_BAKED")
                    .unwrap_or("")
                    .to_string()
            });

        Self {
            license_server_url: std::env::var("CONNECTOR_LICENSE_SERVER")
                .unwrap_or_else(|_| {
                    option_env!("CONNECTOR_LICENSE_SERVER")
                        .unwrap_or("https://license.connector.dev")
                        .to_string()
                }),
            license_key_id: std::env::var("CONNECTOR_KEY_ID")
                .unwrap_or_else(|_| {
                    option_env!("CONNECTOR_KEY_ID").unwrap_or("").to_string()
                }),
            instance_id: std::env::var("CONNECTOR_INSTANCE_ID")
                .unwrap_or_else(|_| "".into()),
            binary_id: std::env::var("CONNECTOR_BINARY_ID")
                .unwrap_or_else(|_| {
                    option_env!("CONNECTOR_BINARY_ID_BAKED")
                        .map(String::from)
                        .unwrap_or_else(|| format!("bin_dev_{}", &machine_id[4..12.min(machine_id.len())]))
                }),
            binary_hash: compute_self_hash(),
            tier: std::env::var("CONNECTOR_TIER")
                .unwrap_or_else(|_| {
                    option_env!("CONNECTOR_TIER_BAKED").unwrap_or("Community").to_string()
                }),
            permission_banner: std::env::var("CONNECTOR_BANNER")
                .unwrap_or_else(|_| "Connector Platform — Unlicensed".into()),
            build_timestamp: option_env!("CONNECTOR_BUILD_TS").unwrap_or("dev").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            machine_id,
            hostname,
            offline_grace_secs,
            last_checkin_ts: None,
            rpc_token:     None,
            rpc_token_id:  None,
            rpc_token_exp: None,
            role_id,
            secret_id,
        }
    }

    pub fn is_licensed(&self) -> bool {
        !self.license_key_id.is_empty() && !self.instance_id.is_empty()
    }

    /// True if this binary has credentials to attempt RPC auth.
    pub fn can_rpc_auth(&self) -> bool {
        !self.role_id.is_empty() && !self.secret_id.is_empty()
    }

    /// True if binary has a live RPC token (authenticated).
    pub fn is_rpc_authenticated(&self) -> bool {
        if self.rpc_token.is_none() { return false; }
        if let Some(exp) = self.rpc_token_exp {
            let now = chrono::Utc::now().timestamp();
            return now < exp;
        }
        false
    }

    /// True if the RPC token is expiring soon (within 5-minute renewal window).
    pub fn token_needs_renewal(&self) -> bool {
        if let Some(exp) = self.rpc_token_exp {
            let now = chrono::Utc::now().timestamp();
            return (exp - now) < 300 && now < exp;
        }
        false
    }

    /// Returns the Authorization header value for RPC calls.
    pub fn rpc_auth_header(&self) -> Option<String> {
        self.rpc_token.as_ref().map(|t| format!("RpcToken {}", t))
    }

    pub fn needs_phone_home(&self) -> bool {
        (self.is_licensed() || self.can_rpc_auth()) && !self.license_server_url.is_empty()
    }

    /// Perform the Vault AppRole-style RPC authentication on binary startup.
    ///
    /// Sends: POST /rpc/v1/auth with (role_id, secret_id, machine_id, binary_hash)
    /// Receives: RPC token (1h TTL), instance_id, tier, permissions
    ///
    /// On success:
    ///   - Stores RPC token in memory (never on disk)
    ///   - Updates instance_id
    ///   - Records checkin timestamp to disk
    ///
    /// On failure:
    ///   - Returns Err with reason string
    ///   - Binary falls back to offline grace period if previously checked in
    pub fn rpc_authenticate(&mut self, data_dir: &str) -> Result<(), String> {
        if !self.can_rpc_auth() {
            // Community mode: no credentials, skip auth
            return Ok(());
        }

        let url = format!("{}/rpc/v1/auth", self.license_server_url.trim_end_matches('/'));

        let payload = serde_json::json!({
            "role_id":    self.role_id,
            "secret_id":  self.secret_id,
            "machine_id": self.machine_id,
            "binary_id":  self.binary_id,
            "binary_hash": self.binary_hash,
            "version":    self.version,
            "os":         std::env::consts::OS,
            "arch":       std::env::consts::ARCH,
        });

        let body = serde_json::to_string(&payload)
            .map_err(|e| format!("Payload serialization: {}", e))?;

        let response = blocking_post(&url, &body)
            .map_err(|e| format!("Network error on {}: {}", url, e))?;

        if response.status == 402 {
            return Err("PAYMENT_REQUIRED: Active subscription required for this tier. Visit the billing portal.".into());
        }
        if response.status == 401 {
            let msg = response.body_json()
                .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "Unauthorized".into());
            return Err(format!("AUTH_FAILED: {}", msg));
        }
        if response.status == 403 {
            let msg = response.body_json()
                .and_then(|v| v["code"].as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "Forbidden".into());
            return Err(format!("BLOCKED: {}", msg));
        }
        if response.status != 200 {
            return Err(format!("License server returned HTTP {}", response.status));
        }

        let json = response.body_json()
            .ok_or("Invalid JSON response from license server")?;

        let token = json["token"].as_str()
            .ok_or("No token in response")?
            .to_string();
        let token_id = json["token_id"].as_str()
            .unwrap_or("").to_string();
        let expires_at = json["expires_at"].as_i64()
            .unwrap_or(chrono::Utc::now().timestamp() + 3600);
        let instance_id = json["instance_id"].as_str()
            .unwrap_or("").to_string();
        let tier = json["tier"].as_str()
            .unwrap_or(&self.tier).to_string();

        self.rpc_token     = Some(token);
        self.rpc_token_id  = Some(token_id);
        self.rpc_token_exp = Some(expires_at);

        if !instance_id.is_empty() {
            self.instance_id = instance_id;
        }
        if !tier.is_empty() {
            self.tier = tier;
        }

        self.record_checkin(data_dir);

        eprintln!("[license] RPC authenticated. Instance: {} Tier: {} Token expires: {}",
            self.instance_id, self.tier,
            chrono::DateTime::from_timestamp(expires_at, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| expires_at.to_string())
        );
        Ok(())
    }

    /// Renew the RPC token before it expires (call when token_needs_renewal() is true).
    pub fn rpc_renew_token(&mut self, data_dir: &str) -> Result<(), String> {
        let token = match &self.rpc_token {
            Some(t) => t.clone(),
            None => return self.rpc_authenticate(data_dir),
        };

        let url = format!("{}/rpc/v1/renew", self.license_server_url.trim_end_matches('/'));
        let body = serde_json::json!({"token": token}).to_string();

        let response = blocking_post(&url, &body)
            .map_err(|e| format!("Renewal network error: {}", e))?;

        if response.status == 401 {
            // Token expired — re-authenticate from scratch
            eprintln!("[license] Token expired — re-authenticating");
            self.rpc_token     = None;
            self.rpc_token_id  = None;
            self.rpc_token_exp = None;
            return self.rpc_authenticate(data_dir);
        }

        if response.status != 200 {
            return Err(format!("Renewal failed: HTTP {}", response.status));
        }

        let json = response.body_json()
            .ok_or("Invalid renewal response")?;

        if let Some(new_token) = json["token"].as_str() {
            self.rpc_token    = Some(new_token.to_string());
            self.rpc_token_id = json["token_id"].as_str().map(|s| s.to_string());
            self.rpc_token_exp = json["expires_at"].as_i64();
            self.record_checkin(data_dir);
            eprintln!("[license] RPC token renewed.");
        }

        Ok(())
    }

    /// Revoke the RPC token on clean shutdown (prevents server-side orphaned tokens).
    pub fn rpc_revoke_token(&self) {
        let token = match &self.rpc_token {
            Some(t) => t.clone(),
            None    => return,
        };

        let url = format!("{}/rpc/v1/revoke", self.license_server_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "token": token,
            "reason": "clean_shutdown",
        }).to_string();

        // Best-effort: fire and forget, ignore errors
        let _ = blocking_post(&url, &body);
        eprintln!("[license] RPC token revoked on shutdown.");
    }

    /// Perform the full startup license check:
    ///   1. Load persisted checkin timestamp
    ///   2. Attempt RPC auth if credentials present
    ///   3. If auth fails but within offline grace: allow (with warning)
    ///   4. If auth fails and grace expired: return Err (binary should restrict paid features)
    pub fn startup_license_check(&mut self, data_dir: &str) -> StartupLicenseResult {
        self.load_checkin_ts(data_dir);

        // Community mode: no credentials, always allowed
        if !self.can_rpc_auth() && self.license_key_id.is_empty() {
            return StartupLicenseResult::Community;
        }

        // Attempt RPC auth
        match self.rpc_authenticate(data_dir) {
            Ok(()) => {
                eprintln!("[license] Startup auth OK — tier: {}", self.tier);
                StartupLicenseResult::Authenticated
            }
            Err(e) => {
                eprintln!("[license] Startup auth failed: {}", e);

                // Payment / revocation / machine mismatch — hard errors regardless of grace
                if e.contains("PAYMENT_REQUIRED") {
                    return StartupLicenseResult::PaymentRequired(e);
                }
                if e.contains("BLOCKED") {
                    return StartupLicenseResult::Blocked(e);
                }

                // Network error — check offline grace
                if self.within_offline_grace() {
                    let remaining = self.last_checkin_ts.map(|ts| {
                        let secs_used = chrono::Utc::now().timestamp() - ts;
                        let remaining = self.offline_grace_secs as i64 - secs_used;
                        remaining / 3600
                    }).unwrap_or(0);
                    eprintln!("[license] Offline grace active — {}h remaining", remaining);
                    StartupLicenseResult::OfflineGrace { hours_remaining: remaining }
                } else {
                    StartupLicenseResult::GraceExpired(e)
                }
            }
        }
    }

    /// Check if offline grace period has expired.
    /// Returns true = still within grace (operation allowed).
    /// Returns false = grace expired, must block until license server reachable.
    pub fn within_offline_grace(&self) -> bool {
        match self.last_checkin_ts {
            None => false, // Never successfully checked in — must check in first
            Some(ts) => {
                let now = chrono::Utc::now().timestamp();
                (now - ts) < self.offline_grace_secs as i64
            }
        }
    }

    /// Persist last successful checkin timestamp to disk.
    pub fn record_checkin(&mut self, data_dir: &str) {
        let now = chrono::Utc::now().timestamp();
        self.last_checkin_ts = Some(now);
        let path = format!("{}/license/last_checkin", data_dir);
        let _ = std::fs::create_dir_all(format!("{}/license", data_dir));
        let _ = std::fs::write(&path, now.to_string());
    }

    /// Load persisted last_checkin_ts from disk.
    pub fn load_checkin_ts(&mut self, data_dir: &str) {
        let path = format!("{}/license/last_checkin", data_dir);
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(ts) = s.trim().parse::<i64>() {
                self.last_checkin_ts = Some(ts);
            }
        }
    }

    pub fn to_checkin_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "instance_id":  &self.instance_id,
            "key_id":       &self.license_key_id,
            "machine_id":   &self.machine_id,
            "hostname":     &self.hostname,
            "binary_hash":  &self.binary_hash,
            "binary_id":    &self.binary_id,
            "version":      &self.version,
            "tier":         &self.tier,
            "os":           std::env::consts::OS,
            "arch":         std::env::consts::ARCH,
        })
    }

    pub fn to_heartbeat_payload(&self, agents: usize, packets: usize,
                                 trust_score: u32, total_tokens: u64,
                                 total_cost: f64) -> serde_json::Value {
        serde_json::json!({
            "instance_id":    &self.instance_id,
            "key_id":         &self.license_key_id,
            "machine_id":     &self.machine_id,
            "agents":         agents,
            "packets":        packets,
            "trust_score":    trust_score,
            "total_tokens":   total_tokens,
            "total_cost_usd": total_cost,
            "binary_hash":    &self.binary_hash,
        })
    }
}

// ── Startup license result ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum StartupLicenseResult {
    /// Community tier — no credentials, all community features available.
    Community,
    /// Successfully authenticated via /rpc/v1/auth.
    Authenticated,
    /// License server unreachable, still within offline grace window.
    OfflineGrace { hours_remaining: i64 },
    /// Offline grace period expired — restrict paid-tier features.
    GraceExpired(String),
    /// Payment required — subscription not active or trial expired.
    PaymentRequired(String),
    /// Binary blocked by server (tampered hash or explicit kill).
    Blocked(String),
}

impl StartupLicenseResult {
    /// True if the binary should allow paid-tier feature access.
    pub fn allows_paid_features(&self) -> bool {
        matches!(self,
            StartupLicenseResult::Authenticated |
            StartupLicenseResult::OfflineGrace { .. }
        )
    }

    /// True if binary should run normally (community or authenticated).
    pub fn is_operational(&self) -> bool {
        !matches!(self, StartupLicenseResult::Blocked(_))
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Community              => "Community mode".into(),
            Self::Authenticated          => "Licensed and authenticated".into(),
            Self::OfflineGrace { hours_remaining } =>
                format!("Offline grace active — {}h remaining", hours_remaining),
            Self::GraceExpired(e)        => format!("Grace expired: {}", e),
            Self::PaymentRequired(e)     => format!("Payment required: {}", e),
            Self::Blocked(e)             => format!("BLOCKED: {}", e),
        }
    }
}

// ── Minimal blocking HTTP client ──────────────────────────────────────────────
// Uses std::net directly to avoid adding reqwest as a dependency.
// For production the server already has tokio — these calls happen at startup
// before the async runtime is fully active, so we use sync std::net.

struct HttpResponse {
    pub status: u16,
    body: String,
}

impl HttpResponse {
    fn body_json(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.body).ok()
    }
}

fn blocking_post(url: &str, body: &str) -> Result<HttpResponse, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    // Parse URL
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")
        .ok_or_else(|| format!("Invalid URL: {}", url))?;

    let (host_port, path) = if let Some(idx) = rest.find('/') {
        (&rest[..idx], &rest[idx..])
    } else {
        (rest, "/")
    };

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if let Some(idx) = host_port.rfind(':') {
        let port_str = &host_port[idx+1..];
        if let Ok(p) = port_str.parse::<u16>() {
            (&host_port[..idx], p)
        } else {
            (host_port, default_port)
        }
    } else {
        (host_port, default_port)
    };

    // For https we'd need TLS — use a simple HTTP-only path for localhost/internal
    // In production with real Vault/license server, use the reqwest-based client
    // in services/licensing.rs which has proper TLS support.
    if scheme == "https" && !host.contains("localhost") && !host.contains("127.0.0.1") {
        // Delegate to the system's curl if available (best-effort)
        return blocking_post_curl(url, body);
    }

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("TCP connect to {}: {}", addr, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, body.len(), body
    );

    stream.write_all(request.as_bytes())
        .map_err(|e| format!("Write error: {}", e))?;

    let mut response_buf = Vec::new();
    stream.read_to_end(&mut response_buf)
        .map_err(|e| format!("Read error: {}", e))?;

    let response_str = String::from_utf8_lossy(&response_buf);

    // Parse status line
    let status_line = response_str.lines().next()
        .ok_or("Empty HTTP response")?;
    let status: u16 = status_line.split_whitespace().nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    // Extract body (after \r\n\r\n)
    let body_start = response_str.find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(response_str.len());
    let resp_body = response_str[body_start..].to_string();

    Ok(HttpResponse { status, body: resp_body })
}

/// Fallback for HTTPS: invoke system curl (available in most production environments).
fn blocking_post_curl(url: &str, body: &str) -> Result<HttpResponse, String> {
    use std::process::Command;
    use std::io::Write;

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("connector_rpc_{}.json", std::process::id()));
    std::fs::write(&tmp, body)
        .map_err(|e| format!("tmp write: {}", e))?;

    let output = Command::new("curl")
        .args([
            "-s", "-w", "\n%{http_code}",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "--data", &format!("@{}", tmp.display()),
            "--max-time", "10",
            "--connect-timeout", "5",
            url,
        ])
        .output()
        .map_err(|e| format!("curl exec: {}", e))?;

    let _ = std::fs::remove_file(&tmp);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.trim_end().rsplitn(2, '\n').collect();
    let (status_str, resp_body) = if lines.len() == 2 {
        (lines[0], lines[1])
    } else {
        ("500", stdout.as_ref())
    };

    let status: u16 = status_str.trim().parse().unwrap_or(500);
    Ok(HttpResponse { status, body: resp_body.to_string() })
}

/// Compute a strong machine fingerprint for node-locking.
/// Sources (in priority order):
///   1. /etc/machine-id (Linux systemd — globally unique per install)
///   2. /var/lib/dbus/machine-id (fallback Linux)
///   3. hostname + OS + arch + CPU model (weakest, cross-platform)
///
/// Result is a SHA-256 digest prefixed with "mfp_" for readability.
fn compute_machine_id() -> String {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();

    // Source 1: systemd machine-id (most stable on Linux)
    let machine_id_file = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_default();
    let machine_id_trimmed = machine_id_file.trim();
    if !machine_id_trimmed.is_empty() {
        hasher.update(b"machine-id:");
        hasher.update(machine_id_trimmed.as_bytes());
    }

    // Source 2: hostname
    hasher.update(b":hostname:");
    hasher.update(hostname().as_bytes());

    // Source 3: OS + arch
    hasher.update(b":os:");
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(b":arch:");
    hasher.update(std::env::consts::ARCH.as_bytes());

    // Source 4: CPU model from /proc/cpuinfo (Linux)
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(line) = cpuinfo.lines().find(|l| l.starts_with("model name")) {
                hasher.update(b":cpu:");
                hasher.update(line.as_bytes());
            }
        }
    }

    let result = hasher.finalize();
    format!("mfp_{}", &result.iter().map(|b| format!("{:02x}", b)).collect::<String>()[..32])
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".into())
                .trim()
                .to_string()
        })
}

/// Compute SHA-256 of the running binary for tamper detection.
/// Skipped in dev mode (debug binaries are large — reading takes seconds).
fn compute_self_hash() -> String {
    let is_dev = std::env::var("CONNECTOR_DEV_MODE").is_ok()
        || std::env::var("CONNECTOR_ENV").map(|v| v == "development" || v == "dev").unwrap_or(false);
    if is_dev {
        return "sha256:dev".into();
    }
    use sha2::{Sha256, Digest};
    match std::env::current_exe() {
        Ok(path) => match std::fs::read(&path) {
            Ok(bytes) => {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let result = hasher.finalize();
                format!("sha256:{}", result.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            }
            Err(_) => "sha256:unreadable".into(),
        },
        Err(_) => "sha256:unknown".into(),
    }
}
