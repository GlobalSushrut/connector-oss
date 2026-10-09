use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Pilot Grant — time-bounded entitlement overlay managed by admins.
/// Pilots allow temporary access to higher tiers or additional capacity
/// for evaluation, onboarding, or special programs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotGrant {
    pub grant_id: String,           // pilot_<uuid>
    pub customer_id: String,        // Links to CustomerRecord
    pub granted_by: String,         // Admin user ID
    pub granted_at: String,         // ISO 8601 timestamp
    pub expires_at: String,         // ISO 8601 timestamp
    pub status: PilotStatus,
    pub tier_override: Option<String>, // e.g., "Enterprise" for trial
    pub agent_limit_override: Option<u32>,
    pub packet_limit_override: Option<u64>,
    pub features_override: Vec<String>, // Additional features enabled
    pub reason: String,             // Why this pilot was granted
    pub notes: String,              // Admin notes
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PilotStatus {
    Active,
    Expired,
    Revoked,
}

impl PilotGrant {
    pub fn new(
        customer_id: String,
        granted_by: String,
        expires_at: String,
        tier_override: Option<String>,
        agent_limit_override: Option<u32>,
        packet_limit_override: Option<u64>,
        features_override: Vec<String>,
        reason: String,
    ) -> Self {
        let grant_id = format!("pilot_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let now = Utc::now();
        
        Self {
            grant_id,
            customer_id,
            granted_by,
            granted_at: now.to_rfc3339(),
            expires_at,
            status: PilotStatus::Active,
            tier_override,
            agent_limit_override,
            packet_limit_override,
            features_override,
            reason,
            notes: String::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        if self.status != PilotStatus::Active {
            return false;
        }
        
        // Check expiration
        if let Ok(expires) = DateTime::parse_from_rfc3339(&self.expires_at) {
            Utc::now() < expires
        } else {
            false
        }
    }

    pub fn expire(&mut self) {
        self.status = PilotStatus::Expired;
    }

    pub fn revoke(&mut self, reason: &str) {
        self.status = PilotStatus::Revoked;
        self.notes = format!("{}\nRevoked: {}", self.notes, reason);
    }
}

/// Effective entitlement after applying pilot grants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveEntitlement {
    pub base_tier: String,
    pub effective_tier: String,
    pub agent_limit: u32,
    pub packet_limit: u64,
    pub features: Vec<String>,
    pub active_pilot: Option<PilotGrant>,
    pub pilot_expires_at: Option<String>,
}

impl EffectiveEntitlement {
    pub fn from_base_tier(tier: &str) -> Self {
        let (agent_limit, packet_limit) = match tier {
            "Community" => (2, 10_000),
            "Indie" => (5, 50_000),
            "Startup" => (10, 100_000),
            "Growth" => (25, 500_000),
            "Business" => (50, 1_000_000),
            "Scale" => (100, 5_000_000),
            "Enterprise" => (500, 50_000_000),
            "Core" => (1000, 100_000_000),
            "Sovereign" => (u32::MAX, u64::MAX),
            _ => (2, 10_000), // Default to Community
        };

        Self {
            base_tier: tier.to_string(),
            effective_tier: tier.to_string(),
            agent_limit,
            packet_limit,
            features: vec![],
            active_pilot: None,
            pilot_expires_at: None,
        }
    }

    pub fn apply_pilot(&mut self, pilot: PilotGrant) {
        if !pilot.is_active() {
            return;
        }

        if let Some(tier) = &pilot.tier_override {
            self.effective_tier = tier.clone();
        }

        if let Some(limit) = pilot.agent_limit_override {
            self.agent_limit = limit;
        }

        if let Some(limit) = pilot.packet_limit_override {
            self.packet_limit = limit;
        }

        for feature in &pilot.features_override {
            if !self.features.contains(feature) {
                self.features.push(feature.clone());
            }
        }

        self.pilot_expires_at = Some(pilot.expires_at.clone());
        self.active_pilot = Some(pilot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pilot_grant_creation() {
        let pilot = PilotGrant::new(
            "cust_123".into(),
            "admin_456".into(),
            "2026-06-01T00:00:00Z".into(),
            Some("Enterprise".into()),
            Some(100),
            None,
            vec!["hipaa".into(), "soc2".into()],
            "Onboarding trial".into(),
        );

        assert!(pilot.grant_id.starts_with("pilot_"));
        assert_eq!(pilot.customer_id, "cust_123");
        assert_eq!(pilot.status, PilotStatus::Active);
        assert!(pilot.is_active());
    }

    #[test]
    fn test_effective_entitlement() {
        let mut ent = EffectiveEntitlement::from_base_tier("Indie");
        assert_eq!(ent.agent_limit, 5);
        assert_eq!(ent.effective_tier, "Indie");

        let pilot = PilotGrant::new(
            "cust_123".into(),
            "admin_456".into(),
            "2026-06-01T00:00:00Z".into(),
            Some("Enterprise".into()),
            Some(100),
            Some(10_000_000),
            vec!["hipaa".into()],
            "Trial".into(),
        );

        ent.apply_pilot(pilot);
        assert_eq!(ent.effective_tier, "Enterprise");
        assert_eq!(ent.agent_limit, 100);
        assert_eq!(ent.packet_limit, 10_000_000);
        assert!(ent.features.contains(&"hipaa".to_string()));
        assert!(ent.active_pilot.is_some());
    }
}
