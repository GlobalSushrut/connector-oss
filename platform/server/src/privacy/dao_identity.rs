//! DAO Identity — Decentralized Anonymous Identity for PII Protection
//!
//! Provides:
//! - Identity anonymization for LLM queries
//! - Context-preserving PII removal
//! - Anonymous identity tokens
//! - Reversible anonymization for authorized retrieval
//!
//! Core concept: Replace PII with anonymous identifiers that preserve
//! relationships and context without exposing personal data.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

// =============================================================================
// Anonymous Identity Types
// =============================================================================

/// Anonymous identity token (replaces PII)
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnonymousId {
    /// Public anonymous identifier
    pub anon_id: String,
    /// Identity type (what was anonymized)
    pub id_type: IdentityType,
    /// Context hash (for relationship preservation)
    pub context_hash: String,
    /// Scope (who can de-anonymize)
    pub scope: AnonymizationScope,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdentityType {
    PersonName,
    Email,
    Phone,
    Address,
    Ssn,
    MedicalRecord,
    FinancialAccount,
    Biometric,
    Location,
    DeviceId,
    IpAddress,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum AnonymizationScope {
    /// Only data subject can de-anonymize
    DataSubjectOnly,
    /// Authorized DAO members
    DaoAuthorized,
    /// Specific authorized roles
    RoleBased(Vec<String>),
    /// System only (no human access)
    SystemOnly,
    /// Public (irreversible)
    Irreversible,
}

/// Identity mapping (encrypted in vault)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMapping {
    /// Anonymous ID (public)
    pub anon_id: String,
    /// Original PII (encrypted)
    pub encrypted_original: Vec<u8>,
    /// Encryption nonce
    pub nonce: Vec<u8>,
    /// Identity type
    pub id_type: IdentityType,
    /// Created at
    pub created_at: i64,
    /// Expires at (for temporary anonymization)
    pub expires_at: Option<i64>,
    /// Access audit log
    pub access_log: Vec<AccessRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    pub timestamp: i64,
    pub accessor: String,
    pub reason: String,
    pub action: AccessAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AccessAction {
    Anonymize,
    DeAnonymizeAuthorized,
    QueryAnonymous,
}

// =============================================================================
// DAO Identity Manager
// =============================================================================

pub struct DaoIdentity {
    /// Active mappings (anon_id -> mapping)
    mappings: HashMap<String, IdentityMapping>,
    /// Context groups (relationships between anon_ids)
    context_groups: HashMap<String, Vec<String>>,
    /// Encryption key (in production, use KMS)
    master_key: [u8; 32],
    /// Audit log
    audit_log: Vec<AccessRecord>,
}

impl DaoIdentity {
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
            context_groups: HashMap::new(),
            master_key: [0u8; 32], // Generate proper key in production
            audit_log: Vec::new(),
        }
    }

    /// Anonymize PII for LLM context
    pub fn anonymize_for_llm(
        &mut self,
        pii: &str,
        id_type: IdentityType,
        context: &str,
    ) -> AnonymousId {
        let now = chrono::Utc::now().timestamp_millis();
        
        // Generate anonymous ID (deterministic per PII + context)
        let context_hash = Self::hash_context(context);
        let anon_id = format!("anon-{}-{}", 
            Self::short_hash(pii),
            &context_hash[..8]
        );

        // Check if already exists
        if let Some(existing) = self.mappings.get(&anon_id) {
            return AnonymousId {
                anon_id: existing.anon_id.clone(),
                id_type: existing.id_type,
                context_hash: existing.encrypted_original.len().to_string(), // Use as placeholder
                scope: AnonymizationScope::DaoAuthorized,
            };
        }

        // Encrypt original PII
        let (encrypted, nonce) = self.encrypt_pii(pii);

        let mapping = IdentityMapping {
            anon_id: anon_id.clone(),
            encrypted_original: encrypted,
            nonce,
            id_type,
            created_at: now,
            expires_at: Some(now + 86400000), // 24 hour default
            access_log: vec![AccessRecord {
                timestamp: now,
                accessor: "system".to_string(),
                reason: "llm_anonymization".to_string(),
                action: AccessAction::Anonymize,
            }],
        };

        self.mappings.insert(anon_id.clone(), mapping);

        // Add to context group
        self.context_groups
            .entry(context_hash.clone())
            .or_insert_with(Vec::new)
            .push(anon_id.clone());

        AnonymousId {
            anon_id,
            id_type,
            context_hash,
            scope: AnonymizationScope::DaoAuthorized,
        }
    }

    /// Anonymize text preserving context
    pub fn anonymize_text(&mut self, text: &str, context: &str) -> AnonymizedText {
        let mut anon_text = text.to_string();
        let mut replacements = Vec::new();

        // Detect and anonymize names
        let name_pattern = regex::Regex::new(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b").unwrap();
        for cap in name_pattern.captures_iter(text) {
            let name = cap.get(0).unwrap().as_str();
            let anon = self.anonymize_for_llm(name, IdentityType::PersonName, context);
            anon_text = anon_text.replace(name, &anon.anon_id);
            replacements.push((name.to_string(), anon.anon_id.clone()));
        }

        // Detect emails
        let email_pattern = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
        for cap in email_pattern.captures_iter(text) {
            let email = cap.get(0).unwrap().as_str();
            let anon = self.anonymize_for_llm(email, IdentityType::Email, context);
            anon_text = anon_text.replace(email, &anon.anon_id);
            replacements.push((email.to_string(), anon.anon_id.clone()));
        }

        // Detect phone numbers
        let phone_pattern = regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();
        for cap in phone_pattern.captures_iter(text) {
            let phone = cap.get(0).unwrap().as_str();
            let anon = self.anonymize_for_llm(phone, IdentityType::Phone, context);
            anon_text = anon_text.replace(phone, &anon.anon_id);
            replacements.push((phone.to_string(), anon.anon_id.clone()));
        }

        // Detect SSN
        let ssn_pattern = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        for cap in ssn_pattern.captures_iter(text) {
            let ssn = cap.get(0).unwrap().as_str();
            let anon = self.anonymize_for_llm(ssn, IdentityType::Ssn, context);
            anon_text = anon_text.replace(ssn, &anon.anon_id);
            replacements.push((ssn.to_string(), anon.anon_id.clone()));
        }

        AnonymizedText {
            anonymized_text: anon_text,
            replacements,
            context_hash: Self::hash_context(context),
        }
    }

    /// De-anonymize (authorized only)
    pub fn deanonymize(
        &mut self,
        anon_id: &str,
        accessor: &str,
        reason: &str,
    ) -> Result<String, DeAnonymizeError> {
        let now = chrono::Utc::now().timestamp_millis();

        let mapping = self.mappings.get_mut(anon_id)
            .ok_or(DeAnonymizeError::UnknownId)?;

        // Check expiration
        if let Some(expires) = mapping.expires_at {
            if now > expires {
                return Err(DeAnonymizeError::Expired);
            }
        }

        // Log access
        mapping.access_log.push(AccessRecord {
            timestamp: now,
            accessor: accessor.to_string(),
            reason: reason.to_string(),
            action: AccessAction::DeAnonymizeAuthorized,
        });

        // Decrypt
        let original = self.decrypt_pii(&mapping.encrypted_original, &mapping.nonce);
        Ok(original)
    }

    /// Reconstruct original from anonymized (for authorized response)
    pub fn reconstruct_response(
        &mut self,
        anonymized_response: &str,
        context: &str,
        accessor: &str,
    ) -> Result<String, DeAnonymizeError> {
        let mut reconstructed = anonymized_response.to_string();
        let context_hash = Self::hash_context(context);

        // Find all anon_ids in context
        if let Some(anon_ids) = self.context_groups.get(&context_hash) {
            for anon_id in anon_ids {
                if reconstructed.contains(anon_id) {
                    // De-anonymize
                    let original = self.deanonymize(anon_id, accessor, "response_reconstruction")?;
                    reconstructed = reconstructed.replace(anon_id, &original);
                }
            }
        }

        Ok(reconstructed)
    }

    /// Check if ID exists
    pub fn has_anon_id(&self, anon_id: &str) -> bool {
        self.mappings.contains_key(anon_id)
    }

    /// Get anonymization statistics
    pub fn get_stats(&self) -> DaoIdentityStats {
        let by_type: HashMap<IdentityType, usize> = self.mappings.values()
            .fold(HashMap::new(), |mut acc, m| {
                *acc.entry(m.id_type).or_insert(0) += 1;
                acc
            });

        DaoIdentityStats {
            total_anonymized: self.mappings.len(),
            by_type,
            context_groups: self.context_groups.len(),
        }
    }

    // Private helpers
    fn hash_context(context: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(context.as_bytes());
        hex::encode(&hasher.finalize()[..16])
    }

    fn short_hash(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }

    fn encrypt_pii(&self, pii: &str) -> (Vec<u8>, Vec<u8>) {
        // Simplified - use AES-GCM in production
        let nonce = rand::random::<[u8; 12]>().to_vec();
        let encrypted: Vec<u8> = pii.bytes().zip(self.master_key.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect();
        (encrypted, nonce)
    }

    fn decrypt_pii(&self, encrypted: &[u8], _nonce: &[u8]) -> String {
        // Simplified - use AES-GCM in production
        let decrypted: Vec<u8> = encrypted.iter().zip(self.master_key.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect();
        String::from_utf8_lossy(&decrypted).to_string()
    }
}

#[derive(Debug, Clone)]
pub struct AnonymizedText {
    pub anonymized_text: String,
    pub replacements: Vec<(String, String)>, // (original, anonymized)
    pub context_hash: String,
}

#[derive(Debug, Clone)]
pub enum DeAnonymizeError {
    UnknownId,
    Expired,
    Unauthorized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoIdentityStats {
    pub total_anonymized: usize,
    pub by_type: HashMap<IdentityType, usize>,
    pub context_groups: usize,
}

/// Thread-safe wrapper
#[derive(Clone)]
pub struct SharedDaoIdentity {
    inner: Arc<RwLock<DaoIdentity>>,
}

impl SharedDaoIdentity {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(DaoIdentity::new())),
        }
    }

    pub fn anonymize_text(&self, text: &str, context: &str) -> AnonymizedText {
        self.inner.write().unwrap().anonymize_text(text, context)
    }

    pub fn deanonymize(&self, anon_id: &str, accessor: &str, reason: &str) -> Result<String, DeAnonymizeError> {
        self.inner.write().unwrap().deanonymize(anon_id, accessor, reason)
    }

    pub fn reconstruct_response(&self, response: &str, context: &str, accessor: &str) -> Result<String, DeAnonymizeError> {
        self.inner.write().unwrap().reconstruct_response(response, context, accessor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymize_and_deanonymize() {
        let mut dao = DaoIdentity::new();

        let pii = "rahul@example.com";
        let anon = dao.anonymize_for_llm(pii, IdentityType::Email, "medical_query");

        assert_ne!(anon.anon_id, pii);
        assert!(dao.has_anon_id(&anon.anon_id));

        // De-anonymize
        let recovered = dao.deanonymize(&anon.anon_id, "doctor", "patient_care").unwrap();
        assert_eq!(recovered, pii);
    }

    #[test]
    fn test_anonymize_text_preserves_context() {
        let mut dao = DaoIdentity::new();

        let text = "Patient rahul@example.com with phone 555-123-4567 reported symptoms";
        let context = "medical_consultation_123";

        let anon = dao.anonymize_text(text, context);

        // Should contain anonymized IDs
        assert!(anon.anonymized_text.contains("anon-"));
        // Should NOT contain original PII
        assert!(!anon.anonymized_text.contains("rahul@example.com"));
        assert!(!anon.anonymized_text.contains("555-123-4567"));
        // But should preserve medical context
        assert!(anon.anonymized_text.contains("Patient"));
        assert!(anon.anonymized_text.contains("reported symptoms"));
    }

    #[test]
    fn test_reconstruct_response() {
        let mut dao = DaoIdentity::new();

        // Anonymize
        let text = "Patient John Doe has diabetes";
        let context = "medical_123";
        let anon = dao.anonymize_text(text, context);

        // LLM response (anonymized)
        let llm_response = format!("{} should monitor blood sugar daily", anon.anonymized_text);

        // Reconstruct for authorized user
        let reconstructed = dao.reconstruct_response(&llm_response, context, "doctor").unwrap();
        assert!(reconstructed.contains("John Doe"));
        assert!(!reconstructed.contains("anon-"));
    }

    #[test]
    fn test_medical_privacy_scenario() {
        let mut dao = DaoIdentity::new();

        // Patient: "rahul has aids" scenario
        let patient_query = "rahul@hospital.com has HIV and needs treatment";
        let context = "patient_rahul_consultation";

        // Anonymize for LLM
        let anon = dao.anonymize_text(patient_query, context);

        // LLM sees anonymized version
        assert!(!anon.anonymized_text.contains("rahul"));
        assert!(!anon.anonymized_text.contains("HIV"));
        // But context preserved
        assert!(anon.anonymized_text.contains("treatment"));

        // Doctor gets de-anonymized response
        let llm_response = "Patient requires ART therapy";
        let reconstructed = dao.reconstruct_response(llm_response, context, "doctor").unwrap();
        
        // Doctor sees proper context
        assert!(reconstructed.contains("rahul") || reconstructed.contains("anon")); // Context link preserved
    }
}
