//! Security configuration builder — progressive security from Level 0 to Level 7.

use serde::{Deserialize, Serialize};

/// Signing algorithm for cryptographic operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    Ed25519,
}

/// Security configuration — built via builder pattern.
///
/// Every level ADDS security. No level REMOVES it. The base is always secure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Signing algorithm (None = no signing, Ed25519 = sign all ops)
    pub signing: Option<SigningAlgorithm>,
    /// Enable SCITT transparency receipts
    pub scitt: bool,
    /// Data classification level (e.g., "PUBLIC", "PII", "PHI", "TOP_SECRET")
    pub data_classification: Option<String>,
    /// Jurisdiction (e.g., "US", "EU", "UK")
    pub jurisdiction: Option<String>,
    /// Data retention period in days (0 = indefinite)
    pub retention_days: u64,
    /// Key rotation period in days (0 = no rotation)
    pub key_rotation_days: u64,
    /// Audit export destination (e.g., "s3://bucket/path")
    pub audit_export: Option<String>,
    /// Maximum delegation depth
    pub max_delegation_depth: u8,
    /// Require MFA for specified actions
    pub require_mfa: bool,
    /// IP allowlist (empty = allow all)
    pub ip_allowlist: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            signing: None,
            scitt: false,
            data_classification: None,
            jurisdiction: None,
            retention_days: 0,
            key_rotation_days: 0,
            audit_export: None,
            max_delegation_depth: 3,
            require_mfa: false,
            ip_allowlist: Vec::new(),
        }
    }
}

/// Builder for SecurityConfig.
pub struct SecurityConfigBuilder {
    config: SecurityConfig,
}

impl SecurityConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: SecurityConfig::default(),
        }
    }

    pub fn signing(mut self, algo: SigningAlgorithm) -> Self {
        self.config.signing = Some(algo);
        self
    }

    pub fn scitt(mut self, enabled: bool) -> Self {
        self.config.scitt = enabled;
        self
    }

    pub fn data_classification(mut self, classification: &str) -> Self {
        self.config.data_classification = Some(classification.to_string());
        self
    }

    pub fn jurisdiction(mut self, jurisdiction: &str) -> Self {
        self.config.jurisdiction = Some(jurisdiction.to_string());
        self
    }

    pub fn retention_days(mut self, days: u64) -> Self {
        self.config.retention_days = days;
        self
    }

    pub fn key_rotation(mut self, days: u64) -> Self {
        self.config.key_rotation_days = days;
        self
    }

    pub fn audit_export(mut self, destination: &str) -> Self {
        self.config.audit_export = Some(destination.to_string());
        self
    }

    pub fn max_delegation_depth(mut self, depth: u8) -> Self {
        self.config.max_delegation_depth = depth;
        self
    }

    pub fn require_mfa(mut self, required: bool) -> Self {
        self.config.require_mfa = required;
        self
    }

    pub fn ip_allowlist(mut self, ips: &[&str]) -> Self {
        self.config.ip_allowlist = ips.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn build(self) -> SecurityConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_security() {
        let config = SecurityConfig::default();
        assert!(config.signing.is_none());
        assert!(!config.scitt);
        assert!(config.data_classification.is_none());
        assert_eq!(config.max_delegation_depth, 3);
    }

    #[test]
    fn test_military_grade_security() {
        let config = SecurityConfigBuilder::new()
            .signing(SigningAlgorithm::Ed25519)
            .scitt(true)
            .data_classification("TOP_SECRET")
            .jurisdiction("US")
            .retention_days(36500) // 100 years
            .key_rotation(30)
            .audit_export("s3://classified-audit/")
            .max_delegation_depth(2)
            .require_mfa(true)
            .ip_allowlist(&["10.0.0.0/8"])
            .build();

        assert!(config.signing.is_some());
        assert!(config.scitt);
        assert_eq!(config.data_classification.as_deref(), Some("TOP_SECRET"));
        assert_eq!(config.jurisdiction.as_deref(), Some("US"));
        assert_eq!(config.retention_days, 36500);
        assert_eq!(config.key_rotation_days, 30);
        assert!(config.require_mfa);
        assert_eq!(config.ip_allowlist.len(), 1);
    }
}
