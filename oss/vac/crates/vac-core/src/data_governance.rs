//! Data Governance — Residency, Encryption, Retention
//!
//! This module implements data governance controls:
//! - Data residency (region selection)
//! - Encryption at rest configuration
//! - Retention policies
//!
//! Design sources: GDPR, SOC2, HIPAA requirements

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Data Residency
// =============================================================================

/// Supported data regions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataRegion {
    /// United States
    Us,
    /// European Union (GDPR)
    Eu,
    /// Canada
    Ca,
    /// Asia Pacific (Singapore)
    Apac,
    /// Australia
    Au,
    /// United Kingdom
    Uk,
}

impl DataRegion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::Eu => "eu",
            Self::Ca => "ca",
            Self::Apac => "apac",
            Self::Au => "au",
            Self::Uk => "uk",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Us => "United States",
            Self::Eu => "European Union",
            Self::Ca => "Canada",
            Self::Apac => "Asia Pacific (Singapore)",
            Self::Au => "Australia",
            Self::Uk => "United Kingdom",
        }
    }

    pub fn gdpr_adequate(&self) -> bool {
        matches!(self, Self::Eu | Self::Uk | Self::Ca)
    }

    pub fn available_regions() -> Vec<Self> {
        vec![Self::Us, Self::Eu, Self::Ca, Self::Apac, Self::Au, Self::Uk]
    }
}

impl std::str::FromStr for DataRegion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "us" | "united_states" => Ok(Self::Us),
            "eu" | "european_union" => Ok(Self::Eu),
            "ca" | "canada" => Ok(Self::Ca),
            "apac" | "asia_pacific" | "singapore" => Ok(Self::Apac),
            "au" | "australia" => Ok(Self::Au),
            "uk" | "united_kingdom" => Ok(Self::Uk),
            _ => Err(format!("Unknown region: {}", s)),
        }
    }
}

/// Data residency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidencyConfig {
    /// Primary data region
    pub primary_region: DataRegion,
    /// Allowed regions for replication
    pub allowed_regions: Vec<DataRegion>,
    /// Require GDPR-adequate regions only
    pub gdpr_only: bool,
    /// Cross-region replication enabled
    pub cross_region_replication: bool,
    /// Data sovereignty requirements
    pub sovereignty: SovereigntyRequirements,
}

impl Default for ResidencyConfig {
    fn default() -> Self {
        Self {
            primary_region: DataRegion::Us,
            allowed_regions: vec![DataRegion::Us],
            gdpr_only: false,
            cross_region_replication: false,
            sovereignty: SovereigntyRequirements::default(),
        }
    }
}

impl ResidencyConfig {
    pub fn eu_compliant() -> Self {
        Self {
            primary_region: DataRegion::Eu,
            allowed_regions: vec![DataRegion::Eu],
            gdpr_only: true,
            cross_region_replication: false,
            sovereignty: SovereigntyRequirements {
                require_local_processing: true,
                require_local_storage: true,
                allow_cross_border_transfer: false,
            },
        }
    }

    pub fn is_region_allowed(&self, region: &DataRegion) -> bool {
        if self.gdpr_only && !region.gdpr_adequate() {
            return false;
        }
        self.allowed_regions.contains(region)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.allowed_regions.contains(&self.primary_region) {
            return Err("Primary region must be in allowed regions".into());
        }
        if self.gdpr_only {
            for region in &self.allowed_regions {
                if !region.gdpr_adequate() {
                    return Err(format!("Region {} is not GDPR-adequate", region.as_str()));
                }
            }
        }
        Ok(())
    }
}

/// Data sovereignty requirements
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SovereigntyRequirements {
    /// Require data to be processed locally
    pub require_local_processing: bool,
    /// Require data to be stored locally
    pub require_local_storage: bool,
    /// Allow cross-border data transfer
    pub allow_cross_border_transfer: bool,
}

// =============================================================================
// Encryption Configuration
// =============================================================================

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM (default)
    Aes256Gcm,
    /// AES-256-CBC
    Aes256Cbc,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

/// Key management mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyManagementMode {
    /// Platform-managed keys (default)
    PlatformManaged,
    /// Customer-managed keys (BYOK)
    CustomerManaged,
    /// Hardware Security Module
    Hsm,
}

impl Default for KeyManagementMode {
    fn default() -> Self {
        Self::PlatformManaged
    }
}

/// Encryption at rest configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Enable encryption at rest
    pub enabled: bool,
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Key management mode
    pub key_management: KeyManagementMode,
    /// Key rotation interval (days)
    pub key_rotation_days: u32,
    /// Customer KMS key ARN (for BYOK)
    pub customer_key_arn: Option<String>,
    /// Encrypt metadata
    pub encrypt_metadata: bool,
    /// Encrypt audit logs
    pub encrypt_audit_logs: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: EncryptionAlgorithm::default(),
            key_management: KeyManagementMode::default(),
            key_rotation_days: 90,
            customer_key_arn: None,
            encrypt_metadata: true,
            encrypt_audit_logs: true,
        }
    }
}

impl EncryptionConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    pub fn with_customer_key(mut self, key_arn: &str) -> Self {
        self.key_management = KeyManagementMode::CustomerManaged;
        self.customer_key_arn = Some(key_arn.into());
        self
    }

    pub fn with_hsm(mut self) -> Self {
        self.key_management = KeyManagementMode::Hsm;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.key_management == KeyManagementMode::CustomerManaged && self.customer_key_arn.is_none() {
            return Err("Customer key ARN required for BYOK".into());
        }
        if self.key_rotation_days < 1 {
            return Err("Key rotation interval must be at least 1 day".into());
        }
        Ok(())
    }
}

// =============================================================================
// Retention Policies
// =============================================================================

/// Retention action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionAction {
    /// Delete data permanently
    Delete,
    /// Archive to cold storage
    Archive,
    /// Anonymize data
    Anonymize,
    /// Mark for review
    Review,
}

/// Retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Data category
    pub data_category: DataCategory,
    /// Retention period (days)
    pub retention_days: u32,
    /// Action after retention period
    pub action: RetentionAction,
    /// Legal hold override
    pub legal_hold: bool,
    /// Enabled
    pub enabled: bool,
}

impl RetentionPolicy {
    pub fn new(id: &str, name: &str, category: DataCategory, days: u32) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            data_category: category,
            retention_days: days,
            action: RetentionAction::Delete,
            legal_hold: false,
            enabled: true,
        }
    }

    pub fn with_action(mut self, action: RetentionAction) -> Self {
        self.action = action;
        self
    }

    pub fn with_legal_hold(mut self) -> Self {
        self.legal_hold = true;
        self
    }
}

/// Data category for retention
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    /// Agent memory
    AgentMemory,
    /// Session data
    SessionData,
    /// Audit logs
    AuditLogs,
    /// User data (PII)
    UserData,
    /// System logs
    SystemLogs,
    /// Metrics
    Metrics,
    /// Backups
    Backups,
}

/// Default retention periods by category
pub fn default_retention_days(category: DataCategory) -> u32 {
    match category {
        DataCategory::AgentMemory => 90,
        DataCategory::SessionData => 30,
        DataCategory::AuditLogs => 365,
        DataCategory::UserData => 90,
        DataCategory::SystemLogs => 30,
        DataCategory::Metrics => 90,
        DataCategory::Backups => 30,
    }
}

// =============================================================================
// Data Governance Manager
// =============================================================================

/// Data governance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataGovernanceConfig {
    /// Data residency settings
    pub residency: ResidencyConfig,
    /// Encryption settings
    pub encryption: EncryptionConfig,
    /// Retention policies
    pub retention_policies: Vec<RetentionPolicy>,
    /// GDPR mode
    pub gdpr_mode: bool,
    /// HIPAA mode
    pub hipaa_mode: bool,
    /// SOC2 mode
    pub soc2_mode: bool,
}

impl Default for DataGovernanceConfig {
    fn default() -> Self {
        Self {
            residency: ResidencyConfig::default(),
            encryption: EncryptionConfig::default(),
            retention_policies: vec![
                RetentionPolicy::new("audit", "Audit Log Retention", DataCategory::AuditLogs, 365),
                RetentionPolicy::new("memory", "Agent Memory Retention", DataCategory::AgentMemory, 90),
                RetentionPolicy::new("session", "Session Data Retention", DataCategory::SessionData, 30),
            ],
            gdpr_mode: false,
            hipaa_mode: false,
            soc2_mode: false,
        }
    }
}

impl DataGovernanceConfig {
    pub fn gdpr_compliant() -> Self {
        Self {
            residency: ResidencyConfig::eu_compliant(),
            encryption: EncryptionConfig::default(),
            retention_policies: vec![
                RetentionPolicy::new("audit", "Audit Log Retention", DataCategory::AuditLogs, 365),
                RetentionPolicy::new("memory", "Agent Memory Retention", DataCategory::AgentMemory, 90)
                    .with_action(RetentionAction::Anonymize),
                RetentionPolicy::new("user", "User Data Retention", DataCategory::UserData, 30)
                    .with_action(RetentionAction::Delete),
            ],
            gdpr_mode: true,
            hipaa_mode: false,
            soc2_mode: true,
        }
    }

    pub fn hipaa_compliant() -> Self {
        Self {
            residency: ResidencyConfig {
                primary_region: DataRegion::Us,
                allowed_regions: vec![DataRegion::Us],
                gdpr_only: false,
                cross_region_replication: false,
                sovereignty: SovereigntyRequirements {
                    require_local_processing: true,
                    require_local_storage: true,
                    allow_cross_border_transfer: false,
                },
            },
            encryption: EncryptionConfig {
                enabled: true,
                algorithm: EncryptionAlgorithm::Aes256Gcm,
                key_management: KeyManagementMode::CustomerManaged,
                key_rotation_days: 90,
                customer_key_arn: None,
                encrypt_metadata: true,
                encrypt_audit_logs: true,
            },
            retention_policies: vec![
                RetentionPolicy::new("audit", "HIPAA Audit Retention", DataCategory::AuditLogs, 2190) // 6 years
                    .with_legal_hold(),
                RetentionPolicy::new("phi", "PHI Retention", DataCategory::UserData, 2190)
                    .with_legal_hold(),
            ],
            gdpr_mode: false,
            hipaa_mode: true,
            soc2_mode: true,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.residency.validate()?;
        self.encryption.validate()?;
        
        if self.gdpr_mode && !self.residency.primary_region.gdpr_adequate() {
            return Err("GDPR mode requires GDPR-adequate primary region".into());
        }
        
        Ok(())
    }

    pub fn get_retention_policy(&self, category: DataCategory) -> Option<&RetentionPolicy> {
        self.retention_policies.iter()
            .find(|p| p.data_category == category && p.enabled)
    }
}

/// Data governance manager
#[derive(Debug, Default)]
pub struct DataGovernanceManager {
    /// Configuration
    config: DataGovernanceConfig,
    /// Region endpoints
    region_endpoints: HashMap<DataRegion, String>,
}

impl DataGovernanceManager {
    pub fn new(config: DataGovernanceConfig) -> Self {
        let mut region_endpoints = HashMap::new();
        region_endpoints.insert(DataRegion::Us, "https://us.connector.dev".into());
        region_endpoints.insert(DataRegion::Eu, "https://eu.connector.dev".into());
        region_endpoints.insert(DataRegion::Ca, "https://ca.connector.dev".into());
        region_endpoints.insert(DataRegion::Apac, "https://apac.connector.dev".into());
        region_endpoints.insert(DataRegion::Au, "https://au.connector.dev".into());
        region_endpoints.insert(DataRegion::Uk, "https://uk.connector.dev".into());

        Self { config, region_endpoints }
    }

    pub fn config(&self) -> &DataGovernanceConfig {
        &self.config
    }

    pub fn primary_region(&self) -> DataRegion {
        self.config.residency.primary_region
    }

    pub fn get_endpoint(&self, region: &DataRegion) -> Option<&str> {
        self.region_endpoints.get(region).map(|s| s.as_str())
    }

    pub fn is_region_allowed(&self, region: &DataRegion) -> bool {
        self.config.residency.is_region_allowed(region)
    }

    pub fn encryption_enabled(&self) -> bool {
        self.config.encryption.enabled
    }

    pub fn should_delete(&self, category: DataCategory, age_days: u32) -> bool {
        if let Some(policy) = self.config.get_retention_policy(category) {
            if policy.legal_hold {
                return false;
            }
            age_days > policy.retention_days && policy.action == RetentionAction::Delete
        } else {
            false
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_region() {
        assert_eq!(DataRegion::Us.as_str(), "us");
        assert!(DataRegion::Eu.gdpr_adequate());
        assert!(!DataRegion::Us.gdpr_adequate());

        let region: DataRegion = "eu".parse().unwrap();
        assert_eq!(region, DataRegion::Eu);
    }

    #[test]
    fn test_residency_config() {
        let config = ResidencyConfig::eu_compliant();
        assert!(config.is_region_allowed(&DataRegion::Eu));
        assert!(!config.is_region_allowed(&DataRegion::Us));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_encryption_config() {
        let config = EncryptionConfig::default();
        assert!(config.enabled);
        assert!(config.validate().is_ok());

        let byok = EncryptionConfig::default().with_customer_key("arn:aws:kms:...");
        assert_eq!(byok.key_management, KeyManagementMode::CustomerManaged);
    }

    #[test]
    fn test_retention_policy() {
        let policy = RetentionPolicy::new("test", "Test Policy", DataCategory::AuditLogs, 365)
            .with_action(RetentionAction::Archive);
        
        assert_eq!(policy.retention_days, 365);
        assert_eq!(policy.action, RetentionAction::Archive);
    }

    #[test]
    fn test_governance_config() {
        let config = DataGovernanceConfig::gdpr_compliant();
        assert!(config.gdpr_mode);
        assert!(config.validate().is_ok());

        let hipaa = DataGovernanceConfig::hipaa_compliant();
        assert!(hipaa.hipaa_mode);
    }

    #[test]
    fn test_governance_manager() {
        let manager = DataGovernanceManager::new(DataGovernanceConfig::default());
        assert_eq!(manager.primary_region(), DataRegion::Us);
        assert!(manager.encryption_enabled());
        assert!(manager.get_endpoint(&DataRegion::Eu).is_some());
    }
}
