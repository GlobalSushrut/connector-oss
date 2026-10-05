//! Consent Registry — Per-Purpose Tracking and Consent Management
//!
//! FIX BUG-035/036/038: Consent infrastructure

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Consent Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub consent_id: String,
    pub subject_id: String,
    pub purpose: String,
    pub data_types: Vec<DataCategory>,
    pub granted: bool,
    pub granted_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub mechanism: ConsentMechanism,
    pub metadata: HashMap<String, String>,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataCategory {
    Identity,
    Contact,
    Financial,
    Health,
    Behavioral,
    Location,
    Biometric,
    Communication,
    Employment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentMechanism {
    ExplicitOptIn,
    Implicit,
    LegitimateInterest,
    Contractual,
    LegalObligation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurposeDefinition {
    pub purpose_id: String,
    pub name: String,
    pub description: String,
    pub legal_basis: LegalBasis,
    pub data_categories: Vec<DataCategory>,
    pub retention_days: u32,
    pub requires_explicit_consent: bool,
    pub third_party_sharing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegalBasis {
    Consent,
    Contract,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterests,
}

#[derive(Debug, Clone)]
pub struct ConsentCheck {
    pub subject_id: String,
    pub purpose: String,
    pub data_category: DataCategory,
    pub has_consent: bool,
    pub consent_record: Option<ConsentRecord>,
    pub expires_soon: bool,
}

// =============================================================================
// Consent Registry
// =============================================================================

pub struct ConsentRegistry {
    /// All consent records by ID
    records: Arc<RwLock<HashMap<String, ConsentRecord>>>,
    /// Index: subject_id -> consent_ids
    subject_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Index: purpose -> consent_ids
    purpose_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Purpose definitions
    purposes: Arc<RwLock<HashMap<String, PurposeDefinition>>>,
    /// Audit log
    audit_log: Arc<RwLock<Vec<ConsentAuditEvent>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentAuditEvent {
    pub timestamp: i64,
    pub event_type: ConsentEventType,
    pub consent_id: String,
    pub subject_id: String,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentEventType {
    Granted,
    Revoked,
    Expired,
    Checked,
    Denied,
    Updated,
}

impl ConsentRegistry {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            subject_index: Arc::new(RwLock::new(HashMap::new())),
            purpose_index: Arc::new(RwLock::new(HashMap::new())),
            purposes: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a purpose definition
    pub fn register_purpose(&self, purpose: PurposeDefinition) {
        self.purposes.write().unwrap().insert(purpose.purpose_id.clone(), purpose);
    }

    /// Record consent from subject
    pub fn record_consent(&self, subject_id: String, purpose: String, data_types: Vec<DataCategory>, mechanism: ConsentMechanism) -> Result<ConsentRecord, String> {
        // Validate purpose exists
        if !self.purposes.read().unwrap().contains_key(&purpose) {
            return Err("Purpose not registered".to_string());
        }

        let consent_id = format!("consent-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp_millis();

        let record = ConsentRecord {
            consent_id: consent_id.clone(),
            subject_id: subject_id.clone(),
            purpose: purpose.clone(),
            data_types,
            granted: true,
            granted_at: Some(now),
            expires_at: Some(now + (365 * 24 * 3600 * 1000)), // 1 year default
            revoked_at: None,
            mechanism,
            metadata: HashMap::new(),
            version: 1,
        };

        // Store
        self.records.write().unwrap().insert(consent_id.clone(), record.clone());

        // Update indexes
        self.subject_index.write().unwrap()
            .entry(subject_id.clone())
            .or_insert_with(HashSet::new)
            .insert(consent_id.clone());

        self.purpose_index.write().unwrap()
            .entry(purpose.clone())
            .or_insert_with(HashSet::new)
            .insert(consent_id.clone());

        // Audit
        self.audit(ConsentEventType::Granted, &record, "Consent granted");

        println!("[CONSENT] {} granted consent for {}", subject_id, purpose);
        Ok(record)
    }

    /// Revoke consent
    pub fn revoke_consent(&self, consent_id: &str, reason: &str) -> Result<(), String> {
        let mut records = self.records.write().unwrap();
        
        if let Some(record) = records.get_mut(consent_id) {
            record.granted = false;
            record.revoked_at = Some(chrono::Utc::now().timestamp_millis());
            
            self.audit(ConsentEventType::Revoked, record, reason);
            println!("[CONSENT] {} revoked for {} ({})", record.subject_id, record.purpose, reason);
            Ok(())
        } else {
            Err("Consent not found".to_string())
        }
    }

    /// Check if subject has consent for purpose and data category
    pub fn check_consent(&self, subject_id: &str, purpose: &str, data_category: DataCategory) -> ConsentCheck {
        let subject_consents = self.subject_index.read().unwrap()
            .get(subject_id)
            .cloned()
            .unwrap_or_default();

        let now = chrono::Utc::now().timestamp_millis();
        let mut found = None;
        let mut expires_soon = false;

        for consent_id in &subject_consents {
            if let Some(record) = self.records.read().unwrap().get(consent_id) {
                if record.purpose == purpose && record.data_types.contains(&data_category) {
                    if record.granted && !self.is_expired(record, now) {
                        found = Some(record.clone());
                        
                        // Check if expires within 30 days
                        if let Some(expires) = record.expires_at {
                            if expires - now < 30 * 24 * 3600 * 1000 {
                                expires_soon = true;
                            }
                        }
                        break;
                    }
                }
            }
        }

        let has_consent = found.is_some();
        let check = ConsentCheck {
            subject_id: subject_id.to_string(),
            purpose: purpose.to_string(),
            data_category,
            has_consent,
            consent_record: found,
            expires_soon,
        };

        // Audit
        if let Some(ref record) = check.consent_record {
            self.audit(ConsentEventType::Checked, record, "Consent check performed");
        } else {
            self.audit_log.write().unwrap().push(ConsentAuditEvent {
                timestamp: now,
                event_type: ConsentEventType::Denied,
                consent_id: "none".to_string(),
                subject_id: subject_id.to_string(),
                details: format!("No consent for {} / {:?}", purpose, data_category),
            });
        }

        check
    }

    /// Batch check consent for multiple subjects
    pub fn batch_check(&self, subject_ids: &[String], purpose: &str, data_category: DataCategory) -> Vec<ConsentCheck> {
        subject_ids.iter()
            .map(|id| self.check_consent(id, purpose, data_category))
            .collect()
    }

    /// Get all consents for subject
    pub fn get_subject_consents(&self, subject_id: &str) -> Vec<ConsentRecord> {
        let ids = self.subject_index.read().unwrap()
            .get(subject_id)
            .cloned()
            .unwrap_or_default();

        let records = self.records.read().unwrap();
        ids.iter()
            .filter_map(|id| records.get(id))
            .cloned()
            .collect()
    }

    /// Get consent statistics
    pub fn get_stats(&self) -> ConsentStats {
        let records = self.records.read().unwrap();
        let now = chrono::Utc::now().timestamp_millis();

        ConsentStats {
            total_consents: records.len(),
            active_consents: records.values().filter(|r| r.granted && !self.is_expired(r, now)).count(),
            revoked_consents: records.values().filter(|r| !r.granted).count(),
            expired_consents: records.values().filter(|r| self.is_expired(r, now)).count(),
            by_purpose: {
                let mut counts: HashMap<String, usize> = HashMap::new();
                for r in records.values() {
                    *counts.entry(r.purpose.clone()).or_insert(0) += 1;
                }
                counts
            },
        }
    }

    /// Clean up expired consents
    pub fn cleanup_expired(&self) -> usize {
        let now = chrono::Utc::now().timestamp_millis();
        let mut records = self.records.write().unwrap();
        let mut to_remove = Vec::new();

        for (id, record) in records.iter() {
            if self.is_expired(record, now) && record.granted {
                to_remove.push(id.clone());
            }
        }

        for id in &to_remove {
            if let Some(record) = records.get_mut(id) {
                record.granted = false;
                self.audit(ConsentEventType::Expired, record, "Consent expired");
            }
        }

        to_remove.len()
    }

    fn is_expired(&self, record: &ConsentRecord, now: i64) -> bool {
        if let Some(expires) = record.expires_at {
            now > expires
        } else {
            false
        }
    }

    fn audit(&self, event_type: ConsentEventType, record: &ConsentRecord, details: &str) {
        self.audit_log.write().unwrap().push(ConsentAuditEvent {
            timestamp: chrono::Utc::now().timestamp_millis(),
            event_type,
            consent_id: record.consent_id.clone(),
            subject_id: record.subject_id.clone(),
            details: details.to_string(),
        });
    }

    /// Get audit log for subject
    pub fn get_audit_log(&self, subject_id: &str, limit: usize) -> Vec<ConsentAuditEvent> {
        self.audit_log.read().unwrap()
            .iter()
            .filter(|e| e.subject_id == subject_id)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Create default purposes
    pub fn register_default_purposes(&self) {
        let purposes = vec![
            PurposeDefinition {
                purpose_id: "analytics".to_string(),
                name: "Analytics".to_string(),
                description: "Process data for analytics and insights".to_string(),
                legal_basis: LegalBasis::Consent,
                data_categories: vec![DataCategory::Behavioral, DataCategory::Identity],
                retention_days: 365,
                requires_explicit_consent: true,
                third_party_sharing: false,
            },
            PurposeDefinition {
                purpose_id: "service_delivery".to_string(),
                name: "Service Delivery".to_string(),
                description: "Provide core services".to_string(),
                legal_basis: LegalBasis::Contract,
                data_categories: vec![DataCategory::Identity, DataCategory::Contact],
                retention_days: 2555, // 7 years
                requires_explicit_consent: false,
                third_party_sharing: false,
            },
            PurposeDefinition {
                purpose_id: "marketing".to_string(),
                name: "Marketing".to_string(),
                description: "Send marketing communications".to_string(),
                legal_basis: LegalBasis::Consent,
                data_categories: vec![DataCategory::Contact, DataCategory::Behavioral],
                retention_days: 730,
                requires_explicit_consent: true,
                third_party_sharing: true,
            },
            PurposeDefinition {
                purpose_id: "fraud_prevention".to_string(),
                name: "Fraud Prevention".to_string(),
                description: "Detect and prevent fraud".to_string(),
                legal_basis: LegalBasis::LegitimateInterests,
                data_categories: vec![DataCategory::Financial, DataCategory::Behavioral],
                retention_days: 2555,
                requires_explicit_consent: false,
                third_party_sharing: false,
            },
        ];

        for p in purposes {
            self.register_purpose(p);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsentStats {
    pub total_consents: usize,
    pub active_consents: usize,
    pub revoked_consents: usize,
    pub expired_consents: usize,
    pub by_purpose: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_registry() -> ConsentRegistry {
        let reg = ConsentRegistry::new();
        reg.register_default_purposes();
        reg
    }

    #[test]
    fn test_record_and_check() {
        let reg = create_registry();
        
        let record = reg.record_consent(
            "user-123".to_string(),
            "analytics".to_string(),
            vec![DataCategory::Behavioral],
            ConsentMechanism::ExplicitOptIn,
        ).unwrap();
        
        assert!(record.granted);
        
        let check = reg.check_consent("user-123", "analytics", DataCategory::Behavioral);
        assert!(check.has_consent);
    }

    #[test]
    fn test_revoke() {
        let reg = create_registry();
        
        let record = reg.record_consent(
            "user-123".to_string(),
            "marketing".to_string(),
            vec![DataCategory::Contact],
            ConsentMechanism::ExplicitOptIn,
        ).unwrap();
        
        reg.revoke_consent(&record.consent_id, "User request").unwrap();
        
        let check = reg.check_consent("user-123", "marketing", DataCategory::Contact);
        assert!(!check.has_consent);
    }

    #[test]
    fn test_no_consent() {
        let reg = create_registry();
        
        let check = reg.check_consent("user-999", "analytics", DataCategory::Identity);
        assert!(!check.has_consent);
    }

    #[test]
    fn test_stats() {
        let reg = create_registry();
        
        reg.record_consent("user-1".to_string(), "analytics".to_string(), vec![DataCategory::Behavioral], ConsentMechanism::ExplicitOptIn).unwrap();
        reg.record_consent("user-2".to_string(), "analytics".to_string(), vec![DataCategory::Behavioral], ConsentMechanism::ExplicitOptIn).unwrap();
        reg.record_consent("user-3".to_string(), "marketing".to_string(), vec![DataCategory::Contact], ConsentMechanism::ExplicitOptIn).unwrap();
        
        let stats = reg.get_stats();
        assert_eq!(stats.total_consents, 3);
        assert_eq!(stats.by_purpose.get("analytics").copied().unwrap_or(0), 2);
    }
}
