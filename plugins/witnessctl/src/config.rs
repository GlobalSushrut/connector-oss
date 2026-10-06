use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub connector_base_url: String,
    pub connector_api_key: String,
    pub hmac_secret: String,
    pub log_level: String,
    pub connector_base_url_explicit: bool,
    pub connector_api_key_present: bool,
    pub requested_agents: usize,
    pub firewall_timeout_ms: u64,
    pub strict_mode: bool,
    pub tsa_url: Option<String>,
    pub tsa_strict_verify: bool,
    pub tsa_ca_file: Option<String>,
    pub tsa_required_frameworks: Vec<String>,
    pub attestor_jwt_secret: Option<String>,
    pub attestor_jwt_issuer: Option<String>,
    pub attestor_jwt_audience: Option<String>,
    pub worm_http_url: Option<String>,
    pub worm_http_bearer: Option<String>,
    pub worm_dir: Option<String>,
    pub worm_profile: String,
    pub legal_hold_enforced: bool,
    pub webhook_urls: Vec<String>,
    pub webhook_bearer: Option<String>,
    pub cage_mode: bool,
    pub route_profile: String,
    pub route_allowlist: Vec<String>,
    pub method_allowlist: Vec<String>,
    pub path_prefix_allowlist: Vec<String>,
    pub watchdog_interval_secs: u64,
    pub connector_license_tier: String,
    /// Shared secret for TraceTramp `POST /api/v1/integrations/tracetramp/handoff` (must match TraceTramp `TRACETRAMP_WITNESS_HANDOFF_SECRET`).
    pub tracetramp_handoff_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let connector_base_url_env = std::env::var("CONNECTOR_BASE_URL").ok();
        let connector_api_key_env = std::env::var("CONNECTOR_API_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                std::env::var("CONNECTOR_KEY")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            })
            .unwrap_or_else(|| "replace_with_connector_api_key".to_string());
        let hmac_secret = std::env::var("WITNESSCTL_HMAC_SECRET")
            .unwrap_or_else(|_| "change-me-in-production".to_string());

        Ok(Config {
            port: std::env::var("WITNESSCTL_PORT")
                .unwrap_or_else(|_| "7443".to_string())
                .parse()?,
            database_url: std::env::var("WITNESSCTL_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .map_err(|_| anyhow::anyhow!("WITNESSCTL_DATABASE_URL not set"))?,
            redis_url: std::env::var("WITNESSCTL_REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            connector_base_url: connector_base_url_env
                .clone()
                .unwrap_or_else(|| "http://localhost:9735".to_string()),
            connector_api_key: connector_api_key_env.clone(),
            hmac_secret,
            log_level: std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info".to_string()),
            connector_base_url_explicit: connector_base_url_env.is_some(),
            connector_api_key_present: {
                let key = connector_api_key_env.trim();
                !key.is_empty() && !key.eq_ignore_ascii_case("replace_with_connector_api_key")
            },
            requested_agents: std::env::var("WITNESSCTL_REQUESTED_AGENTS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1),
            firewall_timeout_ms: std::env::var("WITNESSCTL_FIREWALL_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(200),
            strict_mode: std::env::var("WITNESSCTL_STRICT_MODE")
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false),
            tsa_url: std::env::var("WITNESSCTL_TSA_URL").ok(),
            tsa_strict_verify: std::env::var("WITNESSCTL_TSA_STRICT_VERIFY")
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false),
            tsa_ca_file: std::env::var("WITNESSCTL_TSA_CA_FILE").ok(),
            tsa_required_frameworks: std::env::var("WITNESSCTL_TSA_REQUIRED_FRAMEWORKS")
                .unwrap_or_else(|_| "hipaa,soc2,pci_dss".to_string())
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            attestor_jwt_secret: std::env::var("WITNESSCTL_ATTESTOR_JWT_SECRET").ok(),
            attestor_jwt_issuer: std::env::var("WITNESSCTL_ATTESTOR_JWT_ISSUER").ok(),
            attestor_jwt_audience: std::env::var("WITNESSCTL_ATTESTOR_JWT_AUDIENCE").ok(),
            worm_http_url: std::env::var("WITNESSCTL_WORM_HTTP_URL").ok(),
            worm_http_bearer: std::env::var("WITNESSCTL_WORM_HTTP_BEARER").ok(),
            worm_dir: std::env::var("WITNESSCTL_WORM_DIR").ok(),
            worm_profile: std::env::var("WITNESSCTL_WORM_PROFILE")
                .unwrap_or_else(|_| "basic".to_string())
                .to_ascii_lowercase(),
            legal_hold_enforced: std::env::var("WITNESSCTL_LEGAL_HOLD_ENFORCED")
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(true),
            webhook_urls: std::env::var("WITNESSCTL_WEBHOOK_URLS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            webhook_bearer: std::env::var("WITNESSCTL_WEBHOOK_BEARER").ok(),
            cage_mode: std::env::var("WITNESSCTL_CAGE_MODE")
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false),
            route_profile: std::env::var("WITNESSCTL_ROUTE_PROFILE")
                .unwrap_or_else(|_| "standard".to_string()),
            route_allowlist: std::env::var("WITNESSCTL_ROUTE_ALLOWLIST")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            method_allowlist: std::env::var("WITNESSCTL_METHOD_ALLOWLIST")
                .unwrap_or_else(|_| "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS".to_string())
                .split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect(),
            path_prefix_allowlist: std::env::var("WITNESSCTL_PATH_PREFIX_ALLOWLIST")
                .unwrap_or_else(|_| "/".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            watchdog_interval_secs: std::env::var("WITNESSCTL_WATCHDOG_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(15),
            connector_license_tier: std::env::var("CONNECTOR_LICENSE_TIER")
                .unwrap_or_else(|_| "free".to_string())
                .to_ascii_lowercase(),
            tracetramp_handoff_secret: std::env::var("WITNESSCTL_TRACETRAMP_HANDOFF_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        })
    }

    pub fn validate_license_tier(&self) -> anyhow::Result<()> {
        if matches!(
            self.connector_license_tier.as_str(),
            "free" | "pro" | "enterprise"
        ) {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Invalid CONNECTOR_LICENSE_TIER '{}'. Expected one of: free, pro, enterprise.",
                self.connector_license_tier
            ))
        }
    }

    pub fn is_enterprise_tier(&self) -> bool {
        self.connector_license_tier == "enterprise"
    }

    pub fn hmac_secret_secure(&self) -> bool {
        let s = self.hmac_secret.trim();
        !s.is_empty()
            && !s.eq_ignore_ascii_case("change-me-in-production")
            && s.len() >= 32
    }

}
