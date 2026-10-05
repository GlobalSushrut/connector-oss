//! Data Control Ledger — CID-based Data Separation and PII Lineage
//!
//! FIX BUG-031/032/033: Data control infrastructure

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// CID-based Data Types
// =============================================================================

/// Content Identifier - unique hash-based ID for data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid {
    pub hash: String,
    pub version: u8,
    pub codec: String,
}

impl Cid {
    pub fn new(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self {
            hash: hex::encode(hasher.finalize()),
            version: 1,
            codec: "raw".to_string(),
        }
    }

    pub fn to_string(&self) -> String {
        format!("cid-{}-v{}", &self.hash[..16], self.version)
    }
}

/// Data segment with lineage tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSegment {
    pub cid: Cid,
    pub parent_cids: Vec<Cid>,
    pub data_type: DataType,
    pub sensitivity_level: SensitivityLevel,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub subject_ids: Vec<String>, // PII subjects associated
    pub lineage: DataLineage,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    Raw,
    Processed,
    Aggregated,
    Anonymized,
    Derived,
    Temp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SensitivityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
    Pii = 4,
    SensitivePii = 5,
}

/// Data lineage - tracks transformations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLineage {
    pub source_cids: Vec<Cid>,
    pub transformations: Vec<Transformation>,
    pub processing_steps: Vec<ProcessingStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transformation {
    pub operation: String,
    pub timestamp: i64,
    pub processor: String,
    pub input_cids: Vec<Cid>,
    pub output_cid: Cid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStep {
    pub step_number: u32,
    pub operation: String,
    pub agent_id: String,
    pub timestamp: i64,
}

// =============================================================================
// Data Control Ledger
// =============================================================================

pub struct DataControlLedger {
    /// All data segments by CID
    segments: Arc<RwLock<HashMap<Cid, DataSegment>>>,
    /// Index by subject
    subject_index: Arc<RwLock<HashMap<String, HashSet<Cid>>>>,
    /// Index by sensitivity
    sensitivity_index: Arc<RwLock<HashMap<SensitivityLevel, HashSet<Cid>>>>,
    /// PII lineage graph
    lineage_graph: Arc<RwLock<HashMap<Cid, Vec<Cid>>>>, // cid -> parent cids
    /// Access log
    access_log: Arc<RwLock<VecDeque<AccessRecord>>>,
    /// Retention policies
    retention_policies: Arc<RwLock<HashMap<Cid, RetentionPolicy>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    pub timestamp: i64,
    pub cid: Cid,
    pub accessor: String,
    pub operation: AccessOperation,
    pub purpose: String,
    pub authorized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessOperation {
    Create,
    Read,
    Update,
    Delete,
    Transform,
    Export,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub cid: Cid,
    pub max_age_days: u32,
    pub legal_hold: bool,
    pub auto_delete: bool,
}

impl DataControlLedger {
    pub fn new() -> Self {
        Self {
            segments: Arc::new(RwLock::new(HashMap::new())),
            subject_index: Arc::new(RwLock::new(HashMap::new())),
            sensitivity_index: Arc::new(RwLock::new(HashMap::new())),
            lineage_graph: Arc::new(RwLock::new(HashMap::new())),
            access_log: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            retention_policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register new data segment with CID
    pub fn register(&self, data: &[u8], data_type: DataType, sensitivity: SensitivityLevel, subject_ids: Vec<String>) -> Cid {
        let cid = Cid::new(data);
        let now = chrono::Utc::now().timestamp_millis();

        let segment = DataSegment {
            cid: cid.clone(),
            parent_cids: vec![],
            data_type,
            sensitivity_level: sensitivity,
            created_at: now,
            expires_at: None,
            subject_ids: subject_ids.clone(),
            lineage: DataLineage {
                source_cids: vec![],
                transformations: vec![],
                processing_steps: vec![],
            },
            size_bytes: data.len() as u64,
        };

        // Store segment
        self.segments.write().unwrap().insert(cid.clone(), segment);

        // Update subject index
        {
            let mut subj_idx = self.subject_index.write().unwrap();
            for subject_id in subject_ids {
                subj_idx.entry(subject_id)
                    .or_insert_with(HashSet::new)
                    .insert(cid.clone());
            }
        }

        // Update sensitivity index
        self.sensitivity_index.write().unwrap()
            .entry(sensitivity)
            .or_insert_with(HashSet::new)
            .insert(cid.clone());

        // Log access
        self.log_access(cid.clone(), "system", AccessOperation::Create, "initial_ingest", true);

        println!("[DATA-LEDGER] Registered {} ({} bytes, {:?})",
            cid.to_string(), data.len(), sensitivity);

        cid
    }

    /// Create derived data with lineage tracking
    pub fn register_derived(&self, input_cids: Vec<Cid>, output_data: &[u8], operation: &str, processor: &str) -> Result<Cid, String> {
        let output_cid = Cid::new(output_data);
        let now = chrono::Utc::now().timestamp_millis();

        // Validate inputs exist
        let segments = self.segments.read().unwrap();
        let mut parents = Vec::new();
        let mut subject_ids = HashSet::new();
        let mut max_sensitivity = SensitivityLevel::Public;

        for cid in &input_cids {
            let seg = segments.get(cid).ok_or("Input CID not found")?;
            parents.push(cid.clone());
            subject_ids.extend(seg.subject_ids.iter().cloned());
            if seg.sensitivity_level > max_sensitivity {
                max_sensitivity = seg.sensitivity_level;
            }
        }

        // Create transformation record
        let transformation = Transformation {
            operation: operation.to_string(),
            timestamp: now,
            processor: processor.to_string(),
            input_cids: parents.clone(),
            output_cid: output_cid.clone(),
        };

        let segment = DataSegment {
            cid: output_cid.clone(),
            parent_cids: parents.clone(),
            data_type: DataType::Derived,
            sensitivity_level: max_sensitivity,
            created_at: now,
            expires_at: None,
            subject_ids: subject_ids.into_iter().collect(),
            lineage: DataLineage {
                source_cids: parents.clone(),
                transformations: vec![transformation],
                processing_steps: vec![ProcessingStep {
                    step_number: 1,
                    operation: operation.to_string(),
                    agent_id: processor.to_string(),
                    timestamp: now,
                }],
            },
            size_bytes: output_data.len() as u64,
        };

        // Store
        drop(segments);
        self.segments.write().unwrap().insert(output_cid.clone(), segment);

        // Update lineage graph
        self.lineage_graph.write().unwrap().insert(output_cid.clone(), parents);

        println!("[DATA-LEDGER] Registered derived {} from {} parents",
            output_cid.to_string(), input_cids.len());

        Ok(output_cid)
    }

    /// Get data segment by CID
    pub fn get(&self, cid: &Cid) -> Option<DataSegment> {
        self.segments.read().unwrap().get(cid).cloned()
    }

    /// Find all data for a subject (PII lineage)
    pub fn find_by_subject(&self, subject_id: &str) -> Vec<DataSegment> {
        let cids = self.subject_index.read().unwrap()
            .get(subject_id)
            .cloned()
            .unwrap_or_default();

        let segments = self.segments.read().unwrap();
        cids.iter()
            .filter_map(|cid| segments.get(cid))
            .cloned()
            .collect()
    }

    /// Get all derived data (downstream lineage)
    pub fn get_downstream(&self, cid: &Cid) -> Vec<Cid> {
        let graph = self.lineage_graph.read().unwrap();
        
        // Find all CIDs that have this CID as parent
        let mut downstream = Vec::new();
        for (child, parents) in graph.iter() {
            if parents.contains(cid) {
                downstream.push(child.clone());
            }
        }
        
        downstream
    }

    /// Get full lineage (upstream + downstream)
    pub fn get_full_lineage(&self, cid: &Cid) -> LineageResult {
        // Get upstream (parents)
        let mut upstream = Vec::new();
        let mut to_process = vec![cid.clone()];
        let mut visited = HashSet::new();
        
        while let Some(current) = to_process.pop() {
            if visited.insert(current.clone()) {
                if let Some(seg) = self.segments.read().unwrap().get(&current) {
                    for parent in &seg.parent_cids {
                        upstream.push(parent.clone());
                        to_process.push(parent.clone());
                    }
                }
            }
        }

        // Get downstream
        let downstream = self.get_downstream(cid);

        let mut all_related = upstream.clone();
        all_related.push(cid.clone());
        all_related.extend(downstream.iter().cloned());

        LineageResult {
            root: cid.clone(),
            upstream,
            downstream,
            all_related,
        }
    }

    /// Log data access
    pub fn log_access(&self, cid: Cid, accessor: &str, operation: AccessOperation, purpose: &str, authorized: bool) {
        let record = AccessRecord {
            timestamp: chrono::Utc::now().timestamp_millis(),
            cid,
            accessor: accessor.to_string(),
            operation,
            purpose: purpose.to_string(),
            authorized,
        };

        let mut log = self.access_log.write().unwrap();
        log.push_back(record);
        
        if log.len() > 10000 {
            log.pop_front();
        }
    }

    /// Query access log
    pub fn query_access(&self, cid: &Cid, since: i64) -> Vec<AccessRecord> {
        self.access_log.read().unwrap()
            .iter()
            .filter(|r| r.cid == *cid && r.timestamp >= since)
            .cloned()
            .collect()
    }

    /// Set retention policy
    pub fn set_retention(&self, cid: &Cid, policy: RetentionPolicy) -> Result<(), String> {
        if !self.segments.read().unwrap().contains_key(cid) {
            return Err("CID not found".to_string());
        }

        self.retention_policies.write().unwrap().insert(cid.clone(), policy);
        Ok(())
    }

    /// Apply retention policies (call periodically)
    pub fn apply_retention(&self) -> Vec<Cid> {
        let now = chrono::Utc::now().timestamp_millis();
        let policies = self.retention_policies.read().unwrap();
        let segments = self.segments.read().unwrap();
        
        let to_delete: Vec<Cid> = policies.iter()
            .filter(|(cid, policy)| {
                if policy.legal_hold {
                    return false;
                }
                
                if let Some(seg) = segments.get(cid) {
                    let age_days = (now - seg.created_at) / (24 * 3600 * 1000);
                    age_days > policy.max_age_days as i64
                } else {
                    false
                }
            })
            .map(|(cid, _)| cid.clone())
            .collect();

        to_delete
    }

    /// Delete data and all derivatives (cascade)
    pub fn delete_cascade(&self, cid: &Cid) -> Result<usize, String> {
        let lineage = self.get_full_lineage(cid);
        let count = lineage.all_related.len();
        
        let mut segments = self.segments.write().unwrap();
        let mut subj_idx = self.subject_index.write().unwrap();
        let mut sens_idx = self.sensitivity_index.write().unwrap();
        
        for c in &lineage.all_related {
            if let Some(seg) = segments.remove(c) {
                // Remove from subject index
                for subject_id in &seg.subject_ids {
                    if let Some(set) = subj_idx.get_mut(subject_id) {
                        set.remove(c);
                    }
                }
                
                // Remove from sensitivity index
                if let Some(set) = sens_idx.get_mut(&seg.sensitivity_level) {
                    set.remove(c);
                }
            }
        }

        println!("[DATA-LEDGER] Cascade deleted {} segments starting from {}",
            count, cid.to_string());

        Ok(count)
    }

    /// Get statistics
    pub fn get_stats(&self) -> LedgerStats {
        let segments = self.segments.read().unwrap();
        
        LedgerStats {
            total_segments: segments.len(),
            total_subjects: self.subject_index.read().unwrap().len(),
            total_size_bytes: segments.values().map(|s| s.size_bytes).sum(),
            by_sensitivity: {
                let mut counts = HashMap::new();
                for seg in segments.values() {
                    *counts.entry(seg.sensitivity_level).or_insert(0) += 1;
                }
                counts
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct LineageResult {
    pub root: Cid,
    pub upstream: Vec<Cid>,
    pub downstream: Vec<Cid>,
    pub all_related: Vec<Cid>,
}

#[derive(Debug, Clone)]
pub struct LedgerStats {
    pub total_segments: usize,
    pub total_subjects: usize,
    pub total_size_bytes: u64,
    pub by_sensitivity: HashMap<SensitivityLevel, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_generation() {
        let data = b"test data";
        let cid1 = Cid::new(data);
        let cid2 = Cid::new(data);
        
        assert_eq!(cid1, cid2); // Deterministic
        assert!(!cid1.hash.is_empty());
    }

    #[test]
    fn test_register_and_retrieve() {
        let ledger = DataControlLedger::new();
        
        let data = b"sensitive pii data";
        let cid = ledger.register(
            data,
            DataType::Raw,
            SensitivityLevel::Pii,
            vec!["user-123".to_string()],
        );
        
        let segment = ledger.get(&cid).unwrap();
        assert_eq!(segment.sensitivity_level, SensitivityLevel::Pii);
        assert_eq!(segment.subject_ids, vec!["user-123"]);
    }

    #[test]
    fn test_derived_data_lineage() {
        let ledger = DataControlLedger::new();
        
        // Register source
        let source = ledger.register(b"source", DataType::Raw, SensitivityLevel::Pii, vec!["user-1".to_string()]);
        
        // Create derived
        let derived = ledger.register_derived(
            vec![source.clone()],
            b"processed",
            "anonymize",
            "agent-1",
        ).unwrap();
        
        // Check lineage
        let seg = ledger.get(&derived).unwrap();
        assert!(seg.parent_cids.contains(&source));
        assert_eq!(seg.data_type, DataType::Derived);
    }

    #[test]
    fn test_find_by_subject() {
        let ledger = DataControlLedger::new();
        
        ledger.register(b"data1", DataType::Raw, SensitivityLevel::Pii, vec!["user-123".to_string()]);
        ledger.register(b"data2", DataType::Raw, SensitivityLevel::Pii, vec!["user-123".to_string()]);
        ledger.register(b"data3", DataType::Raw, SensitivityLevel::Pii, vec!["user-456".to_string()]);
        
        let user_data = ledger.find_by_subject("user-123");
        assert_eq!(user_data.len(), 2);
    }

    #[test]
    fn test_cascade_delete() {
        let ledger = DataControlLedger::new();
        
        let a = ledger.register(b"a", DataType::Raw, SensitivityLevel::Internal, vec![]);
        let b = ledger.register_derived(vec![a.clone()], b"b", "transform", "agent").unwrap();
        let c = ledger.register_derived(vec![b.clone()], b"c", "transform", "agent").unwrap();
        
        let deleted = ledger.delete_cascade(&a).unwrap();
        assert_eq!(deleted, 3); // a, b, c
        
        assert!(ledger.get(&a).is_none());
        assert!(ledger.get(&b).is_none());
        assert!(ledger.get(&c).is_none());
    }
}
