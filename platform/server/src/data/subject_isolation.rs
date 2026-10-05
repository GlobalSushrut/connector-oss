//! Subject Isolation — Per-Subject Namespaces and Encryption
//! FIX BUG-035/036/038: Subject isolation for privacy

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

use crate::data::ledger::{Cid, DataControlLedger, SensitivityLevel, DataType};
use crate::data::sensitive_store::{SensitiveStore, AccessPolicy, AccessRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub subject_id: String,
    pub subject_type: SubjectType,
    pub created_at: i64,
    pub namespace_key: String,
    pub metadata: HashMap<String, String>,
    pub isolation_level: IsolationLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectType { User, Customer, Employee, Device, Organization }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel { Shared, Logical, Physical, Dedicated }

#[derive(Debug, Clone)]
pub struct SubjectNamespace {
    pub subject_id: String,
    pub encryption_key: Vec<u8>,
    pub data_cids: Vec<Cid>,
    pub quota_bytes: u64,
    pub used_bytes: u64,
}

pub struct SubjectIsolationManager {
    subjects: Arc<RwLock<HashMap<String, Subject>>>,
    namespaces: Arc<RwLock<HashMap<String, SubjectNamespace>>>,
    subject_data_index: Arc<RwLock<HashMap<String, HashSet<Cid>>>>,
    ledger: Arc<DataControlLedger>,
    store: Arc<SensitiveStore>,
}

impl SubjectIsolationManager {
    pub fn new(ledger: Arc<DataControlLedger>, store: Arc<SensitiveStore>) -> Self {
        Self {
            subjects: Arc::new(RwLock::new(HashMap::new())),
            namespaces: Arc::new(RwLock::new(HashMap::new())),
            subject_data_index: Arc::new(RwLock::new(HashMap::new())),
            ledger,
            store,
        }
    }

    pub fn register_subject(&self, subject_id: String, subject_type: SubjectType, isolation: IsolationLevel) -> Result<Subject, String> {
        if self.subjects.read().unwrap().contains_key(&subject_id) {
            return Err("Subject already exists".to_string());
        }

        let namespace_key = self.generate_namespace_key(&subject_id);
        
        let subject = Subject {
            subject_id: subject_id.clone(),
            subject_type,
            created_at: chrono::Utc::now().timestamp_millis(),
            namespace_key: hex::encode(&namespace_key),
            metadata: HashMap::new(),
            isolation_level: isolation,
        };

        let namespace = SubjectNamespace {
            subject_id: subject_id.clone(),
            encryption_key: namespace_key,
            data_cids: Vec::new(),
            quota_bytes: 10 * 1024 * 1024 * 1024,
            used_bytes: 0,
        };

        self.subjects.write().unwrap().insert(subject_id.clone(), subject.clone());
        self.namespaces.write().unwrap().insert(subject_id.clone(), namespace);
        
        println!("[SUBJECT-ISOLATION] Registered {} with {:?} isolation", subject_id, isolation);
        Ok(subject)
    }

    pub fn store_subject_data(&self, subject_id: &str, data: &[u8], _data_type: DataType) -> Result<Cid, String> {
        let subject = self.subjects.read().unwrap().get(subject_id).cloned().ok_or("Subject not found")?;
        let mut namespace = self.namespaces.write().unwrap().get_mut(subject_id).ok_or("Namespace not found")?.clone();

        if namespace.used_bytes + data.len() as u64 > namespace.quota_bytes {
            return Err("Quota exceeded".to_string());
        }

        let encrypted = self.encrypt_with_subject_key(data, &namespace.encryption_key)?;

        let policy = AccessPolicy {
            policy_id: format!("subject-{}", subject_id),
            required_clearance: match subject.isolation_level {
                IsolationLevel::Shared => 1,
                IsolationLevel::Logical => 2,
                IsolationLevel::Physical => 3,
                IsolationLevel::Dedicated => 4,
            },
            allowed_purposes: vec!["subject_access".to_string()],
            time_restrictions: None,
            require_approval: subject.isolation_level == IsolationLevel::Dedicated,
            audit_required: true,
        };

        let cid = self.store.store(&encrypted, SensitivityLevel::Pii, vec![subject_id.to_string()], policy)?;

        namespace.data_cids.push(cid.clone());
        namespace.used_bytes += data.len() as u64;
        self.namespaces.write().unwrap().insert(subject_id.to_string(), namespace);

        self.subject_data_index.write().unwrap()
            .entry(subject_id.to_string()).or_insert_with(HashSet::new).insert(cid.clone());

        Ok(cid)
    }

    pub fn retrieve_subject_data(&self, subject_id: &str, cid: &Cid, requester: &str) -> Result<Vec<u8>, String> {
        let namespace = self.namespaces.read().unwrap().get(subject_id).cloned().ok_or("Namespace not found")?;
        
        if !namespace.data_cids.contains(cid) {
            return Err("Data not in subject namespace".to_string());
        }

        let request = AccessRequest {
            requester: requester.to_string(),
            cid: cid.clone(),
            purpose: "subject_access".to_string(),
            clearance: 5,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };

        let encrypted = self.store.retrieve(cid, request)?;
        self.decrypt_with_subject_key(&encrypted, &namespace.encryption_key)
    }

    /// Full GDPR erasure - cascade delete all subject data
    pub fn gdpr_erase(&self, subject_id: &str) -> Result<ErasureReport, String> {
        println!("[SUBJECT-ISOLATION] GDPR erasure for {}", subject_id);

        let data_cids: Vec<Cid> = self.subject_data_index.read().unwrap()
            .get(subject_id).cloned().unwrap_or_default().into_iter().collect();

        let mut deleted = Vec::new();
        let mut failed = Vec::new();

        for cid in &data_cids {
            match self.ledger.delete_cascade(cid) {
                Ok(count) => deleted.push((cid.clone(), count)),
                Err(e) => failed.push((cid.clone(), e)),
            }
        }

        self.namespaces.write().unwrap().remove(subject_id);
        self.subject_data_index.write().unwrap().remove(subject_id);
        self.subjects.write().unwrap().remove(subject_id);

        Ok(ErasureReport {
            subject_id: subject_id.to_string(),
            total_cids: data_cids.len(),
            deleted_cids: deleted.len(),
            failed_cids: failed.len(),
        })
    }

    fn generate_namespace_key(&self, subject_id: &str) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let secret = "system-secret";
        let input = format!("{}:{}", subject_id, secret);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher.finalize().to_vec()
    }

    fn encrypt_with_subject_key(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(data.len());
        for (i, b) in data.iter().enumerate() { out.push(b ^ key[i % key.len()]); }
        Ok(out)
    }

    fn decrypt_with_subject_key(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        self.encrypt_with_subject_key(data, key)
    }
}

#[derive(Debug, Clone)]
pub struct ErasureReport {
    pub subject_id: String,
    pub total_cids: usize,
    pub deleted_cids: usize,
    pub failed_cids: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn create_mgr() -> SubjectIsolationManager {
        let ledger = Arc::new(DataControlLedger::new());
        let store = Arc::new(SensitiveStore::new(ledger.clone()));
        SubjectIsolationManager::new(ledger, store)
    }

    #[test]
    fn test_register_and_store() {
        let mgr = create_mgr();
        mgr.register_subject("user-1".to_string(), SubjectType::User, IsolationLevel::Logical).unwrap();
        let cid = mgr.store_subject_data("user-1", b"secret", DataType::Raw).unwrap();
        assert!(!cid.to_string().is_empty());
    }

    #[test]
    fn test_gdpr_erase() {
        let mgr = create_mgr();
        mgr.register_subject("user-1".to_string(), SubjectType::User, IsolationLevel::Shared).unwrap();
        mgr.store_subject_data("user-1", b"data1", DataType::Raw).unwrap();
        mgr.store_subject_data("user-1", b"data2", DataType::Raw).unwrap();
        
        let report = mgr.gdpr_erase("user-1").unwrap();
        assert_eq!(report.total_cids, 2);
    }
}
