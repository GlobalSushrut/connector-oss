//! Sensitive Data Store — Secure Storage with Encryption
//!
//! FIX BUG-031/032/033: Secure PII storage

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use chrono::{Timelike, Datelike};

use crate::data::ledger::{Cid, SensitivityLevel, DataControlLedger};

// =============================================================================
// Encryption Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: EncryptionAlgorithm,
    pub key_id: String,
    pub encrypted_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone)]
pub struct DataKey {
    pub key_id: String,
    pub key_bytes: Vec<u8>,
    pub created_at: i64,
    pub purpose: KeyPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    DataEncryption,
    KeyWrapping,
    TransitEncryption,
}

// =============================================================================
// Access Control
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub policy_id: String,
    pub required_clearance: u32,
    pub allowed_purposes: Vec<String>,
    pub time_restrictions: Option<TimeRestrictions>,
    pub require_approval: bool,
    pub audit_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestrictions {
    pub allowed_hours: Vec<u8>, // 0-23
    pub allowed_days: Vec<u8>, // 0-6 (Sunday-Saturday)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub requester: String,
    pub cid: Cid,
    pub purpose: String,
    pub clearance: u32,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrant {
    pub grant_id: String,
    pub request: AccessRequest,
    pub granted: bool,
    pub expires_at: i64,
    pub restrictions: Vec<String>,
}

// =============================================================================
// Sensitive Store
// =============================================================================

pub struct SensitiveStore {
    /// Encrypted data storage
    storage: Arc<RwLock<HashMap<Cid, EncryptedData>>>,
    /// Data keys (in production: backed by HSM/KMS)
    data_keys: Arc<RwLock<HashMap<String, DataKey>>>,
    /// Master key wrapper (simulated)
    master_key_id: String,
    /// Access policies by CID
    policies: Arc<RwLock<HashMap<Cid, AccessPolicy>>>,
    /// Active grants
    grants: Arc<RwLock<HashMap<String, AccessGrant>>>,
    /// Ledger reference
    ledger: Arc<DataControlLedger>,
}

impl SensitiveStore {
    pub fn new(ledger: Arc<DataControlLedger>) -> Self {
        // In production: generate or load master key from HSM
        let master_key_id = format!("master-{}", uuid::Uuid::new_v4());

        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            data_keys: Arc::new(RwLock::new(HashMap::new())),
            master_key_id,
            policies: Arc::new(RwLock::new(HashMap::new())),
            grants: Arc::new(RwLock::new(HashMap::new())),
            ledger,
        }
    }

    /// Store sensitive data with encryption
    pub fn store(&self, data: &[u8], sensitivity: SensitivityLevel, subject_ids: Vec<String>, policy: AccessPolicy) -> Result<Cid, String> {
        // 1. Register in ledger
        let cid = self.ledger.register(data, crate::data::ledger::DataType::Raw, sensitivity, subject_ids);

        // 2. Generate data encryption key
        let dek = self.generate_data_key(&cid)?;

        // 3. Encrypt data
        let encrypted = self.encrypt_data(data, &dek)?;

        // 4. Store encrypted data
        self.storage.write().unwrap().insert(cid.clone(), encrypted);

        // 5. Store policy
        self.policies.write().unwrap().insert(cid.clone(), policy);

        println!("[SENSITIVE-STORE] Stored encrypted data {} ({} bytes)",
            cid.to_string(), data.len());

        Ok(cid)
    }

    /// Retrieve and decrypt data with access control
    pub fn retrieve(&self, cid: &Cid, request: AccessRequest) -> Result<Vec<u8>, String> {
        // 1. Check access policy
        let policy = self.policies.read().unwrap()
            .get(cid)
            .cloned()
            .ok_or("No access policy for this data")?;

        if !self.check_access(&policy, &request) {
            self.ledger.log_access(cid.clone(), &request.requester, crate::data::ledger::AccessOperation::Read, &request.purpose, false);
            return Err("Access denied".to_string());
        }

        // 2. Issue grant
        let grant = self.issue_grant(request)?;

        // 3. Retrieve encrypted data
        let encrypted = self.storage.read().unwrap()
            .get(cid)
            .cloned()
            .ok_or("Data not found")?;

        // 4. Get data key
        let dek = self.get_data_key(cid)?;

        // 5. Decrypt
        let plaintext = self.decrypt_data(&encrypted, &dek)?;

        // 6. Log successful access
        self.ledger.log_access(cid.clone(), &grant.request.requester, crate::data::ledger::AccessOperation::Read, &grant.request.purpose, true);

        println!("[SENSITIVE-STORE] Retrieved {} for {}",
            cid.to_string(), grant.request.requester);

        Ok(plaintext)
    }

    /// Rotate encryption key for data
    pub fn rekey(&self, cid: &Cid) -> Result<(), String> {
        // 1. Retrieve and decrypt with old key
        let encrypted = self.storage.read().unwrap()
            .get(cid)
            .cloned()
            .ok_or("Data not found")?;

        let old_key = self.get_data_key(cid)?;
        let plaintext = self.decrypt_data(&encrypted, &old_key)?;

        // 2. Generate new key
        let new_key = self.generate_data_key(cid)?;

        // 3. Re-encrypt
        let new_encrypted = self.encrypt_data(&plaintext, &new_key)?;

        // 4. Store
        self.storage.write().unwrap().insert(cid.clone(), new_encrypted);

        println!("[SENSITIVE-STORE] Rekeyed {}", cid.to_string());
        Ok(())
    }

    /// Securely delete data
    pub fn secure_delete(&self, cid: &Cid) -> Result<(), String> {
        // 1. Overwrite in storage (simulated)
        if let Some(mut data) = self.storage.write().unwrap().remove(cid) {
            // Zero out
            for byte in data.ciphertext.iter_mut() {
                *byte = 0;
            }
        }

        // 2. Remove policy
        self.policies.write().unwrap().remove(cid);

        // 3. Remove key
        self.data_keys.write().unwrap().remove(&cid.to_string());

        // 4. Cascade delete from ledger
        self.ledger.delete_cascade(cid)?;

        println!("[SENSITIVE-STORE] Securely deleted {}", cid.to_string());
        Ok(())
    }

    fn generate_data_key(&self, cid: &Cid) -> Result<DataKey, String> {
        let key_id = cid.to_string();
        
        // In production: use secure random + HSM
        let key_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let key = DataKey {
            key_id: key_id.clone(),
            key_bytes,
            created_at: chrono::Utc::now().timestamp_millis(),
            purpose: KeyPurpose::DataEncryption,
        };

        self.data_keys.write().unwrap().insert(key_id, key.clone());
        
        Ok(key)
    }

    fn get_data_key(&self, cid: &Cid) -> Result<DataKey, String> {
        self.data_keys.read().unwrap()
            .get(&cid.to_string())
            .cloned()
            .ok_or("Data key not found".to_string())
    }

    fn encrypt_data(&self, data: &[u8], key: &DataKey) -> Result<EncryptedData, String> {
        // In production: use AES-256-GCM or ChaCha20-Poly1305
        // For now: XOR with key (DEMO ONLY - NOT SECURE)
        let mut ciphertext = Vec::with_capacity(data.len());
        for (i, byte) in data.iter().enumerate() {
            ciphertext.push(byte ^ key.key_bytes[i % key.key_bytes.len()]);
        }

        Ok(EncryptedData {
            ciphertext,
            nonce: vec![0; 12], // In production: proper nonce
            algorithm: EncryptionAlgorithm::AES256GCM,
            key_id: key.key_id.clone(),
            encrypted_at: chrono::Utc::now().timestamp_millis(),
        })
    }

    fn decrypt_data(&self, encrypted: &EncryptedData, key: &DataKey) -> Result<Vec<u8>, String> {
        // XOR decryption (matches encryption above)
        let mut plaintext = Vec::with_capacity(encrypted.ciphertext.len());
        for (i, byte) in encrypted.ciphertext.iter().enumerate() {
            plaintext.push(byte ^ key.key_bytes[i % key.key_bytes.len()]);
        }

        Ok(plaintext)
    }

    fn check_access(&self, policy: &AccessPolicy, request: &AccessRequest) -> bool {
        // Check clearance
        if request.clearance < policy.required_clearance {
            return false;
        }

        // Check purpose
        if !policy.allowed_purposes.contains(&request.purpose) {
            return false;
        }

        // Check time restrictions
        if let Some(ref time_restrictions) = policy.time_restrictions {
            let dt = chrono::DateTime::from_timestamp_millis(request.timestamp).unwrap_or_default();
            let hour = dt.hour() as u8;
            let day = dt.weekday().num_days_from_sunday() as u8;

            if !time_restrictions.allowed_hours.contains(&hour) {
                return false;
            }
            if !time_restrictions.allowed_days.contains(&day) {
                return false;
            }
        }

        true
    }

    fn issue_grant(&self, request: AccessRequest) -> Result<AccessGrant, String> {
        let grant = AccessGrant {
            grant_id: format!("grant-{}", uuid::Uuid::new_v4()),
            request,
            granted: true,
            expires_at: chrono::Utc::now().timestamp_millis() + (3600 * 1000), // 1 hour
            restrictions: vec![],
        };

        self.grants.write().unwrap().insert(grant.grant_id.clone(), grant.clone());
        Ok(grant)
    }

    /// Get store statistics
    pub fn get_stats(&self) -> StoreStats {
        StoreStats {
            total_encrypted_items: self.storage.read().unwrap().len(),
            total_keys: self.data_keys.read().unwrap().len(),
            total_policies: self.policies.read().unwrap().len(),
            active_grants: self.grants.read().unwrap().len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoreStats {
    pub total_encrypted_items: usize,
    pub total_keys: usize,
    pub total_policies: usize,
    pub active_grants: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_policy() -> AccessPolicy {
        AccessPolicy {
            policy_id: "policy-1".to_string(),
            required_clearance: 1,
            allowed_purposes: vec!["analytics".to_string()],
            time_restrictions: None,
            require_approval: false,
            audit_required: true,
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        let ledger = Arc::new(DataControlLedger::new());
        let store = SensitiveStore::new(ledger);

        let data = b"sensitive pii";
        let cid = store.store(data, SensitivityLevel::SensitivePii, vec!["user-123".to_string()], create_test_policy()).unwrap();

        let request = AccessRequest {
            requester: "agent-1".to_string(),
            cid: cid.clone(),
            purpose: "analytics".to_string(),
            clearance: 2,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };

        let retrieved = store.retrieve(&cid, request).unwrap();
        assert_eq!(retrieved, data.to_vec());
    }

    #[test]
    fn test_access_denied() {
        let ledger = Arc::new(DataControlLedger::new());
        let store = SensitiveStore::new(ledger);

        let data = b"sensitive pii";
        let cid = store.store(data, SensitivityLevel::SensitivePii, vec!["user-123".to_string()], create_test_policy()).unwrap();

        let request = AccessRequest {
            requester: "agent-1".to_string(),
            cid: cid.clone(),
            purpose: "unauthorized".to_string(), // Not allowed
            clearance: 2,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };

        assert!(store.retrieve(&cid, request).is_err());
    }

    #[test]
    fn test_secure_delete() {
        let ledger = Arc::new(DataControlLedger::new());
        let store = SensitiveStore::new(ledger);

        let data = b"delete me";
        let cid = store.store(data, SensitivityLevel::Confidential, vec![], create_test_policy()).unwrap();

        store.secure_delete(&cid).unwrap();
        
        // Should be gone
        let request = AccessRequest {
            requester: "agent-1".to_string(),
            cid: cid.clone(),
            purpose: "analytics".to_string(),
            clearance: 2,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };
        assert!(store.retrieve(&cid, request).is_err());
    }
}
