use serde::{Deserialize, Serialize};

/// 8 pricing tiers — $150 to $5,000/month
/// Each tier unlocks more agents, events, features, and support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// $150/mo — 3 agents, 50K events, basic trust + compliance
    Indie,
    /// $250/mo — 10 agents, 200K events, experiments + knowledge graph
    Startup,
    /// $500/mo — 50 agents, 1M events, multi-agent + RAG + EU AI Act
    Growth,
    /// $1,000/mo — 200 agents, 5M events, SSO + judgment + 365-day retention
    Business,
    /// $2,000/mo — 500 agents, 20M events, dedicated CSM + multi-cell
    Scale,
    /// $3,000/mo — unlimited, HIPAA BAA + SOC2 Type II + EU AI Act
    Enterprise,
    /// $4,000/mo — unlimited, 24/7 support + on-prem + custom SLA
    Core,
    /// $5,000/mo — air-gapped, government/defense, full sovereignty
    Sovereign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    PdfExport,
    Alerting,
    Sso,
    CustomBranding,
    MultiCell,
    KnowledgeGraph,
    Rag,
    MultiAgent,
    Experiments,
    JudgmentEngine,
    DisputeReports,
    CustomCompliance,
    OnPremise,
    AirGapped,
    DedicatedCsm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub tier: Tier,
    pub instance_id: String,
    pub max_agents: Option<usize>,
    pub max_events: Option<usize>,
    pub max_packets: Option<usize>,
    pub retention_days: u32,
    pub valid_until: Option<i64>,
    pub price_cents: u32,
}

impl LicenseInfo {
    /// Unix timestamp (**seconds**) must be `<= valid_until` when set. `None` = no time limit.
    pub fn is_time_valid(&self, now_unix_secs: i64) -> bool {
        match self.valid_until {
            None => true,
            Some(exp) => now_unix_secs <= exp,
        }
    }

    /// Stable-ish revision for host tooling (`connector-kerneld`) to detect license / clock changes.
    pub fn host_materialization_revision(&self, now_unix_secs: i64) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        format!("{:?}", self.tier).hash(&mut h);
        self.instance_id.hash(&mut h);
        self.valid_until.hash(&mut h);
        self.is_time_valid(now_unix_secs).hash(&mut h);
        h.finish()
    }

    pub fn community() -> Self {
        Self {
            tier: Tier::Indie,
            instance_id: uuid::Uuid::new_v4().to_string(),
            max_agents: Some(3),
            max_events: Some(50_000),
            max_packets: Some(10_000),
            retention_days: 30,
            valid_until: None,
            price_cents: 15_000,
        }
    }

    pub fn for_tier(tier: Tier) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        match tier {
            Tier::Indie => Self {
                tier, instance_id: id,
                max_agents: Some(3), max_events: Some(50_000), max_packets: Some(10_000),
                retention_days: 30, valid_until: None, price_cents: 15_000,
            },
            Tier::Startup => Self {
                tier, instance_id: id,
                max_agents: Some(10), max_events: Some(200_000), max_packets: Some(50_000),
                retention_days: 90, valid_until: None, price_cents: 25_000,
            },
            Tier::Growth => Self {
                tier, instance_id: id,
                max_agents: Some(50), max_events: Some(1_000_000), max_packets: Some(200_000),
                retention_days: 180, valid_until: None, price_cents: 50_000,
            },
            Tier::Business => Self {
                tier, instance_id: id,
                max_agents: Some(200), max_events: Some(5_000_000), max_packets: Some(1_000_000),
                retention_days: 365, valid_until: None, price_cents: 100_000,
            },
            Tier::Scale => Self {
                tier, instance_id: id,
                max_agents: Some(500), max_events: Some(20_000_000), max_packets: Some(5_000_000),
                retention_days: 730, valid_until: None, price_cents: 200_000,
            },
            Tier::Enterprise => Self {
                tier, instance_id: id,
                max_agents: None, max_events: None, max_packets: None,
                retention_days: 2555, valid_until: None, price_cents: 300_000,
            },
            Tier::Core => Self {
                tier, instance_id: id,
                max_agents: None, max_events: None, max_packets: None,
                retention_days: 2555, valid_until: None, price_cents: 400_000,
            },
            Tier::Sovereign => Self {
                tier, instance_id: id,
                max_agents: None, max_events: None, max_packets: None,
                retention_days: 2555, valid_until: None, price_cents: 500_000,
            },
        }
    }

    pub fn has_feature(&self, feature: Feature) -> bool {
        let t = self.tier_rank();
        match feature {
            Feature::PdfExport      => t >= 2,  // Startup+
            Feature::Experiments    => t >= 2,  // Startup+
            Feature::KnowledgeGraph => t >= 2,  // Startup+
            Feature::Alerting       => t >= 2,  // Startup+
            Feature::Rag            => t >= 3,  // Growth+
            Feature::MultiAgent     => t >= 3,  // Growth+
            Feature::DisputeReports => t >= 3,  // Growth+
            Feature::Sso            => t >= 4,  // Business+
            Feature::JudgmentEngine => t >= 4,  // Business+
            Feature::CustomCompliance => t >= 4, // Business+
            Feature::MultiCell      => t >= 5,  // Scale+
            Feature::DedicatedCsm   => t >= 5,  // Scale+
            Feature::CustomBranding => t >= 6,  // Enterprise+
            Feature::OnPremise      => t >= 7,  // Core+
            Feature::AirGapped      => t >= 8,  // Sovereign only
        }
    }

    fn tier_rank(&self) -> u8 {
        match self.tier {
            Tier::Indie      => 1,
            Tier::Startup    => 2,
            Tier::Growth     => 3,
            Tier::Business   => 4,
            Tier::Scale      => 5,
            Tier::Enterprise => 6,
            Tier::Core       => 7,
            Tier::Sovereign  => 8,
        }
    }

    pub fn agent_limit(&self) -> usize {
        self.max_agents.unwrap_or(usize::MAX)
    }

    pub fn packet_limit(&self) -> usize {
        self.max_packets.unwrap_or(usize::MAX)
    }

    pub fn event_limit(&self) -> usize {
        self.max_events.unwrap_or(usize::MAX)
    }

    /// HMAC secret used to mint and verify `lic_<tier>_<nonce>.<hmac>` keys.
    pub fn license_hmac_secret() -> Option<Vec<u8>> {
        std::env::var("CONNECTOR_LICENSE_HMAC_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| s.into_bytes())
    }

    fn parse_tier_token(token: &str) -> Option<Tier> {
        match token {
            "sov" => Some(Tier::Sovereign),
            "core" => Some(Tier::Core),
            "ent" => Some(Tier::Enterprise),
            "scale" => Some(Tier::Scale),
            "biz" => Some(Tier::Business),
            "growth" => Some(Tier::Growth),
            "start" => Some(Tier::Startup),
            "indie" => Some(Tier::Indie),
            _ => None,
        }
    }

    fn hmac_hex(secret: &[u8], payload: &str) -> Result<String, &'static str> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| "license_hmac_key_invalid")?;
        mac.update(payload.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Mint a signed license key. Format: `lic_<tier>_<nonce>.<hmac_hex>`.
    pub fn mint_signed_key(tier: Tier, nonce: &str) -> Result<String, &'static str> {
        let secret = Self::license_hmac_secret().ok_or("CONNECTOR_LICENSE_HMAC_KEY unset")?;
        let token = match tier {
            Tier::Sovereign => "sov",
            Tier::Core => "core",
            Tier::Enterprise => "ent",
            Tier::Scale => "scale",
            Tier::Business => "biz",
            Tier::Growth => "growth",
            Tier::Startup => "start",
            Tier::Indie => "indie",
        };
        let nonce = nonce.trim();
        if nonce.len() < 8
            || nonce.len() > 64
            || !nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("license_nonce_invalid");
        }
        let payload = format!("lic_{token}_{nonce}");
        let sig = Self::hmac_hex(&secret, &payload)?;
        Ok(format!("{payload}.{sig}"))
    }

    /// Verify a signed license key. Prefix-only keys are never accepted.
    pub fn try_validate_key(key: &str) -> Result<Self, &'static str> {
        let key = key.trim();
        let (payload, sig) = key.split_once('.').ok_or("license_key_unsigned")?;
        if !payload.starts_with("lic_") {
            return Err("license_key_malformed");
        }
        let rest = &payload["lic_".len()..];
        let (tier_token, nonce) = rest.split_once('_').ok_or("license_key_malformed")?;
        let tier = Self::parse_tier_token(tier_token).ok_or("license_tier_unknown")?;
        if nonce.len() < 8
            || nonce.len() > 64
            || !nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("license_nonce_invalid");
        }
        if !sig.chars().all(|c| c.is_ascii_hexdigit()) || sig.len() != 64 {
            return Err("license_sig_malformed");
        }
        let secret = Self::license_hmac_secret().ok_or("CONNECTOR_LICENSE_HMAC_KEY unset")?;
        let expected = Self::hmac_hex(&secret, payload)?;
        let sig_bytes = hex::decode(sig).map_err(|_| "license_sig_malformed")?;
        let expected_bytes = hex::decode(&expected).map_err(|_| "license_sig_malformed")?;
        if sig_bytes.len() != expected_bytes.len()
            || !constant_time_eq(&sig_bytes, &expected_bytes)
        {
            return Err("license_sig_invalid");
        }
        Ok(Self::for_tier(tier))
    }

    /// Boot-path helper: unsigned or invalid keys collapse to community. Never grant
    /// a paid/sovereign tier from a prefix match.
    pub fn validate_key(key: &str) -> Self {
        match Self::try_validate_key(key) {
            Ok(info) => info,
            Err(reason) => {
                tracing::warn!(reason, "unsigned or invalid license key — community tier");
                Self::community()
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn prefix_only_license_never_grants_sovereign() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let prev = std::env::var("CONNECTOR_LICENSE_HMAC_KEY").ok();
        std::env::remove_var("CONNECTOR_LICENSE_HMAC_KEY");
        let info = LicenseInfo::validate_key("lic_sov_anything");
        assert_eq!(info.tier, Tier::Indie);
        assert!(LicenseInfo::try_validate_key("lic_sov_anything").is_err());
        match prev {
            Some(v) => std::env::set_var("CONNECTOR_LICENSE_HMAC_KEY", v),
            None => std::env::remove_var("CONNECTOR_LICENSE_HMAC_KEY"),
        }
    }

    #[test]
    fn signed_license_key_round_trip() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let prev = std::env::var("CONNECTOR_LICENSE_HMAC_KEY").ok();
        std::env::set_var("CONNECTOR_LICENSE_HMAC_KEY", "test-license-hmac-secret-32bytes!!");
        let key = LicenseInfo::mint_signed_key(Tier::Sovereign, "nonceabcd").unwrap();
        let info = LicenseInfo::try_validate_key(&key).unwrap();
        assert_eq!(info.tier, Tier::Sovereign);
        assert!(LicenseInfo::try_validate_key(&format!("{key}x")).is_err());
        match prev {
            Some(v) => std::env::set_var("CONNECTOR_LICENSE_HMAC_KEY", v),
            None => std::env::remove_var("CONNECTOR_LICENSE_HMAC_KEY"),
        }
    }
}

impl Default for LicenseInfo {
    fn default() -> Self { Self::community() }
}

/// When set, expired (time-wise) licenses block admission and host egress materialization reads `false`.
pub fn license_enforce_enabled() -> bool {
    matches!(
        std::env::var("CONNECTOR_LICENSE_ENFORCE")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}
