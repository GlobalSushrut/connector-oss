use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    Community,
    Indie,
    Startup,
    Growth,
    Business,
    Scale,
    Enterprise,
    Core,
    Sovereign,
}

impl Tier {
    pub fn rank(&self) -> u8 {
        match self {
            Tier::Community => 0,
            Tier::Indie => 1,
            Tier::Startup => 2,
            Tier::Growth => 3,
            Tier::Business => 4,
            Tier::Scale => 5,
            Tier::Enterprise => 6,
            Tier::Core => 7,
            Tier::Sovereign => 8,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "community" | "free" => Tier::Community,
            "indie" => Tier::Indie,
            "startup" => Tier::Startup,
            "growth" => Tier::Growth,
            "business" => Tier::Business,
            "scale" => Tier::Scale,
            "enterprise" => Tier::Enterprise,
            "core" => Tier::Core,
            "sovereign" => Tier::Sovereign,
            _ => Tier::Community,
        }
    }

    pub fn max_agents(&self) -> Option<usize> {
        match self {
            Tier::Community => Some(2),
            Tier::Indie => Some(3),
            Tier::Startup => Some(10),
            Tier::Growth => Some(50),
            Tier::Business => Some(200),
            Tier::Scale => Some(500),
            _ => None,
        }
    }

    pub fn max_events(&self) -> Option<usize> {
        match self {
            Tier::Community => Some(10_000),
            Tier::Indie => Some(50_000),
            Tier::Startup => Some(200_000),
            Tier::Growth => Some(1_000_000),
            Tier::Business => Some(5_000_000),
            Tier::Scale => Some(20_000_000),
            _ => None,
        }
    }

    pub fn price_cents(&self) -> u32 {
        match self {
            Tier::Community => 0,
            Tier::Indie => 15_000,
            Tier::Startup => 25_000,
            Tier::Growth => 50_000,
            Tier::Business => 100_000,
            Tier::Scale => 200_000,
            Tier::Enterprise => 300_000,
            Tier::Core => 400_000,
            Tier::Sovereign => 500_000,
        }
    }

    pub fn retention_days(&self) -> u32 {
        match self {
            Tier::Community => 14,
            Tier::Indie => 30,
            Tier::Startup => 90,
            Tier::Growth => 180,
            Tier::Business => 365,
            Tier::Scale => 730,
            _ => 2555,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseKey {
    pub key_id: String,
    pub key_secret: String,
    pub tier: Tier,
    pub customer_email: String,
    pub customer_name: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub max_activations: u32,
    pub active_instances: Vec<String>,
    pub revoked: bool,
    pub stripe_subscription_id: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activation {
    pub instance_id: String,
    pub key_id: String,
    pub machine_id: String,
    pub hostname: String,
    pub activated_at: String,
    pub last_heartbeat: Option<String>,
    pub deactivated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub instance_id: String,
    pub timestamp: String,
    pub agents_active: usize,
    pub packets_stored: usize,
    pub audit_entries: usize,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub instance_id: String,
    pub key_id: String,
    pub machine_id: String,
    pub agents: usize,
    pub packets: usize,
    pub trust_score: u32,
}

#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    pub tier: String,
    pub customer_email: String,
    pub customer_name: String,
    pub max_activations: Option<u32>,
    pub expires_days: Option<u32>,
    pub stripe_subscription_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActivateRequest {
    pub key_secret: String,
    pub machine_id: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct DeactivateRequest {
    pub instance_id: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub key_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub key_id: String,
    pub reason: Option<String>,
}
