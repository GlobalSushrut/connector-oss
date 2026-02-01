//! Evaluation context for MetaRules

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use aapi_core::Vakya;
use aapi_core::types::PrincipalId;

/// Context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    /// The VĀKYA being evaluated
    pub vakya: Vakya,
    /// Current timestamp
    pub timestamp: DateTime<Utc>,
    /// Request source IP
    pub source_ip: Option<String>,
    /// Geographic location
    pub geo: Option<GeoContext>,
    /// Session information
    pub session: Option<SessionContext>,
    /// Environment (production, staging, etc.)
    pub environment: String,
    /// Custom attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

impl EvaluationContext {
    pub fn new(vakya: Vakya) -> Self {
        Self {
            vakya,
            timestamp: Utc::now(),
            source_ip: None,
            geo: None,
            session: None,
            environment: "production".to_string(),
            attributes: HashMap::new(),
        }
    }

    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    pub fn with_geo(mut self, geo: GeoContext) -> Self {
        self.geo = Some(geo);
        self
    }

    pub fn with_session(mut self, session: SessionContext) -> Self {
        self.session = Some(session);
        self
    }

    pub fn with_environment(mut self, env: impl Into<String>) -> Self {
        self.environment = env.into();
        self
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Get the actor principal ID
    pub fn actor(&self) -> &PrincipalId {
        &self.vakya.v1_karta.pid
    }

    /// Get the action
    pub fn action(&self) -> &str {
        &self.vakya.v3_kriya.action
    }

    /// Get the resource
    pub fn resource(&self) -> &str {
        &self.vakya.v2_karma.rid.0
    }

    /// Get an attribute value
    pub fn get_attribute(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes.get(key)
    }

    /// Check if running in production
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}

/// Geographic context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoContext {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: Option<String>,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Timezone
    pub timezone: Option<String>,
}

impl GeoContext {
    pub fn new() -> Self {
        Self {
            country: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
        }
    }

    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    pub fn with_city(mut self, city: impl Into<String>) -> Self {
        self.city = Some(city.into());
        self
    }

    pub fn with_coordinates(mut self, lat: f64, lon: f64) -> Self {
        self.latitude = Some(lat);
        self.longitude = Some(lon);
        self
    }

    pub fn with_timezone(mut self, tz: impl Into<String>) -> Self {
        self.timezone = Some(tz.into());
        self
    }
}

impl Default for GeoContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Session context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    /// Session ID
    pub session_id: String,
    /// Session start time
    pub started_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Authentication method
    pub auth_method: Option<String>,
    /// MFA verified
    pub mfa_verified: bool,
    /// Session attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

impl SessionContext {
    pub fn new(session_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            session_id: session_id.into(),
            started_at: now,
            last_activity: now,
            auth_method: None,
            mfa_verified: false,
            attributes: HashMap::new(),
        }
    }

    pub fn with_auth_method(mut self, method: impl Into<String>) -> Self {
        self.auth_method = Some(method.into());
        self
    }

    pub fn with_mfa(mut self) -> Self {
        self.mfa_verified = true;
        self
    }

    /// Session duration in seconds
    pub fn duration_secs(&self) -> i64 {
        (Utc::now() - self.started_at).num_seconds()
    }

    /// Time since last activity in seconds
    pub fn idle_secs(&self) -> i64 {
        (Utc::now() - self.last_activity).num_seconds()
    }
}

/// Rate limit context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitContext {
    /// Key for rate limiting (e.g., actor ID, IP, etc.)
    pub key: String,
    /// Current count in window
    pub count: u64,
    /// Window start time
    pub window_start: DateTime<Utc>,
    /// Window duration in seconds
    pub window_secs: u64,
    /// Maximum allowed in window
    pub limit: u64,
}

impl RateLimitContext {
    pub fn new(key: impl Into<String>, limit: u64, window_secs: u64) -> Self {
        Self {
            key: key.into(),
            count: 0,
            window_start: Utc::now(),
            window_secs,
            limit,
        }
    }

    /// Check if rate limit is exceeded
    pub fn is_exceeded(&self) -> bool {
        self.count >= self.limit
    }

    /// Remaining requests in window
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.count)
    }

    /// Time until window resets
    pub fn reset_in_secs(&self) -> i64 {
        let elapsed = (Utc::now() - self.window_start).num_seconds();
        (self.window_secs as i64) - elapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aapi_core::*;

    fn create_test_vakya() -> Vakya {
        Vakya::builder()
            .karta(Karta {
                pid: PrincipalId::new("user:test"),
                role: None,
                realm: None,
                key_id: None,
                actor_type: ActorType::Human,
                delegation_chain: vec![],
            })
            .karma(Karma {
                rid: ResourceId::new("test:resource"),
                kind: None,
                ns: None,
                version: None,
                labels: std::collections::HashMap::new(),
            })
            .kriya(Kriya::new("test", "action"))
            .adhikarana(Adhikarana {
                cap: CapabilityRef::Reference { cap_ref: "cap:test".to_string() },
                policy_ref: None,
                ttl: Some(TtlConstraint {
                    expires_at: Timestamp(chrono::Utc::now() + chrono::Duration::hours(1)),
                    max_duration_ms: None,
                }),
                budgets: vec![],
                approval_lane: ApprovalLane::None,
                scopes: vec![],
                context: None,
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_evaluation_context() {
        let vakya = create_test_vakya();
        let ctx = EvaluationContext::new(vakya)
            .with_source_ip("192.168.1.1")
            .with_environment("staging");

        assert_eq!(ctx.actor().0, "user:test");
        assert_eq!(ctx.action(), "test.action");
        assert!(!ctx.is_production());
    }

    #[test]
    fn test_rate_limit_context() {
        let mut ctx = RateLimitContext::new("user:test", 100, 60);
        assert!(!ctx.is_exceeded());
        assert_eq!(ctx.remaining(), 100);

        ctx.count = 100;
        assert!(ctx.is_exceeded());
        assert_eq!(ctx.remaining(), 0);
    }
}
