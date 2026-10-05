//! Compliance Custody — Chain of Custody for Evidence and Reports
//!
//! FIX BUG-056: Evidence custody tracking

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Custody Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyChain {
    pub chain_id: String,
    pub item_id: String,
    pub item_type: CustodyItemType,
    pub custody_events: Vec<CustodyEvent>,
    pub current_holder: String,
    pub current_location: String,
    pub status: CustodyStatus,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyItemType {
    Evidence,
    Report,
    Document,
    PhysicalMedia,
    DigitalAsset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEvent {
    pub event_id: String,
    pub timestamp: i64,
    pub event_type: CustodyEventType,
    pub from_holder: String,
    pub to_holder: String,
    pub from_location: String,
    pub to_location: String,
    pub authorized_by: String,
    pub reason: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyEventType {
    Creation,
    Transfer,
    Access,
    Copy,
    Destruction,
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyStatus {
    InCustody,
    CheckedOut,
    InTransit,
    Archived,
    Destroyed,
}

// =============================================================================
// Custody Manager
// =============================================================================

pub struct CustodyManager {
    chains: Arc<RwLock<HashMap<String, CustodyChain>>>,
    holders: Arc<RwLock<HashMap<String, Holder>>>,
    access_log: Arc<RwLock<VecDeque<AccessEntry>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Holder {
    pub holder_id: String,
    pub name: String,
    pub role: String,
    pub department: String,
    pub clearance_level: u32,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEntry {
    pub entry_id: String,
    pub chain_id: String,
    pub holder_id: String,
    pub timestamp: i64,
    pub access_type: AccessType,
    pub authorized: bool,
    pub purpose: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessType {
    View,
    Copy,
    Modify,
    Transfer,
    Destroy,
}

impl CustodyManager {
    pub fn new() -> Self {
        Self {
            chains: Arc::new(RwLock::new(HashMap::new())),
            holders: Arc::new(RwLock::new(HashMap::new())),
            access_log: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Register new holder
    pub fn register_holder(&self, holder: Holder) {
        self.holders.write().unwrap().insert(holder.holder_id.clone(), holder);
    }

    /// Create custody chain for item
    pub fn create_custody(
        &self,
        item_id: String,
        item_type: CustodyItemType,
        initial_holder: String,
        location: String,
    ) -> Result<String, String> {
        // Verify holder exists
        if !self.holders.read().unwrap().contains_key(&initial_holder) {
            return Err(format!("Holder {} not found", initial_holder));
        }

        let chain_id = format!("custody-{}", uuid::Uuid::new_v4());
        
        let creation_event = CustodyEvent {
            event_id: format!("evt-{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().timestamp_millis(),
            event_type: CustodyEventType::Creation,
            from_holder: "system".to_string(),
            to_holder: initial_holder.clone(),
            from_location: "none".to_string(),
            to_location: location.clone(),
            authorized_by: "system".to_string(),
            reason: "Initial custody creation".to_string(),
            signature: Self::sign_event(&initial_holder, &item_id),
        };

        let item_id_str = item_id.clone();
        let chain = CustodyChain {
            chain_id: chain_id.clone(),
            item_id,
            item_type,
            custody_events: vec![creation_event],
            current_holder: initial_holder,
            current_location: location,
            status: CustodyStatus::InCustody,
            created_at: chrono::Utc::now().timestamp_millis(),
        };

        self.chains.write().unwrap().insert(chain_id.clone(), chain);

        println!("[CUSTODY] Created chain {} for {}", chain_id, item_id_str);
        Ok(chain_id)
    }

    /// Transfer custody
    pub fn transfer(
        &self,
        chain_id: &str,
        to_holder: String,
        to_location: String,
        authorized_by: String,
        reason: String,
    ) -> Result<(), String> {
        let mut chains = self.chains.write().unwrap();
        
        let chain = chains.get_mut(chain_id)
            .ok_or("Custody chain not found")?;

        // Verify holders exist
        let holders = self.holders.read().unwrap();
        let from_holder = holders.get(&chain.current_holder)
            .ok_or("Current holder not found")?;
        let to_holder_ref = holders.get(&to_holder)
            .ok_or("Destination holder not found")?;

        // Verify authorization
        let auth_holder = holders.get(&authorized_by)
            .ok_or("Authorizer not found")?;

        if auth_holder.clearance_level < from_holder.clearance_level {
            return Err("Insufficient clearance to authorize".to_string());
        }

        // Create transfer event
        let event = CustodyEvent {
            event_id: format!("evt-{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().timestamp_millis(),
            event_type: CustodyEventType::Transfer,
            from_holder: chain.current_holder.clone(),
            to_holder: to_holder.clone(),
            from_location: chain.current_location.clone(),
            to_location: to_location.clone(),
            authorized_by: authorized_by.clone(),
            reason: reason.clone(),
            signature: Self::sign_event(&to_holder, &chain.item_id),
        };

        chain.custody_events.push(event);
        chain.current_holder = to_holder;
        chain.current_location = to_location;
        chain.status = CustodyStatus::InCustody;

        println!("[CUSTODY] Transferred {} to holder {}", chain_id, chain.current_holder);
        Ok(())
    }

    /// Access item (with logging)
    pub fn access(
        &self,
        chain_id: &str,
        holder_id: &str,
        access_type: AccessType,
        purpose: String,
    ) -> Result<bool, String> {
        let chains = self.chains.read().unwrap();
        
        let chain = chains.get(chain_id)
            .ok_or("Custody chain not found")?;

        // Check if holder is current custodian or authorized
        let authorized = chain.current_holder == holder_id;

        // Log access
        let entry = AccessEntry {
            entry_id: format!("access-{}", uuid::Uuid::new_v4()),
            chain_id: chain_id.to_string(),
            holder_id: holder_id.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            access_type,
            authorized,
            purpose,
        };

        self.access_log.write().unwrap().push_back(entry);

        if authorized {
            println!("[CUSTODY] Authorized access to {} by {}", chain_id, holder_id);
        } else {
            println!("[CUSTODY] DENIED access to {} by {}", chain_id, holder_id);
        }

        Ok(authorized)
    }

    /// Record destruction
    pub fn destroy(
        &self,
        chain_id: &str,
        authorized_by: String,
        reason: String,
        method: String,
    ) -> Result<(), String> {
        let mut chains = self.chains.write().unwrap();
        
        let chain = chains.get_mut(chain_id)
            .ok_or("Custody chain not found")?;

        let event = CustodyEvent {
            event_id: format!("evt-{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().timestamp_millis(),
            event_type: CustodyEventType::Destruction,
            from_holder: chain.current_holder.clone(),
            to_holder: "destroyed".to_string(),
            from_location: chain.current_location.clone(),
            to_location: "destroyed".to_string(),
            authorized_by,
            reason: format!("{} (method: {})", reason, method),
            signature: Self::sign_event("system", &chain.item_id),
        };

        chain.custody_events.push(event);
        chain.status = CustodyStatus::Destroyed;
        chain.current_holder = "destroyed".to_string();
        chain.current_location = "destroyed".to_string();

        println!("[CUSTODY] Destroyed {} (item {})", chain_id, chain.item_id);
        Ok(())
    }

    /// Verify custody chain integrity
    pub fn verify_chain(&self, chain_id: &str) -> Result<CustodyVerification, String> {
        let chains = self.chains.read().unwrap();
        
        let chain = chains.get(chain_id)
            .ok_or("Custody chain not found")?;

        let mut valid = true;
        let mut issues = Vec::new();

        // Verify each event signature
        for (i, event) in chain.custody_events.iter().enumerate() {
            let expected_sig = Self::sign_event(&event.to_holder, &chain.item_id);
            if event.signature != expected_sig {
                valid = false;
                issues.push(format!("Event {} has invalid signature", i));
            }
        }

        // Check for gaps in chain
        for i in 1..chain.custody_events.len() {
            let prev = &chain.custody_events[i-1];
            let curr = &chain.custody_events[i];
            
            if curr.from_holder != prev.to_holder {
                valid = false;
                issues.push(format!("Gap between events {} and {}", i-1, i));
            }
        }

        Ok(CustodyVerification {
            chain_id: chain_id.to_string(),
            valid,
            event_count: chain.custody_events.len(),
            issues,
            current_holder: chain.current_holder.clone(),
            current_status: chain.status,
        })
    }

    /// Get custody history
    pub fn get_history(&self, chain_id: &str) -> Option<Vec<CustodyEvent>> {
        self.chains.read().unwrap()
            .get(chain_id)
            .map(|c| c.custody_events.clone())
    }

    /// Get access log
    pub fn get_access_log(&self, chain_id: &str) -> Vec<AccessEntry> {
        self.access_log.read().unwrap()
            .iter()
            .filter(|e| e.chain_id == chain_id)
            .cloned()
            .collect()
    }

    fn sign_event(holder: &str, item: &str) -> String {
        use sha2::{Sha256, Digest};
        let input = format!("{}:{}", holder, item);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())[..16].to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CustodyVerification {
    pub chain_id: String,
    pub valid: bool,
    pub event_count: usize,
    pub issues: Vec<String>,
    pub current_holder: String,
    pub current_status: CustodyStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custody_creation() {
        let manager = CustodyManager::new();
        
        // Register holder
        manager.register_holder(Holder {
            holder_id: "holder-1".to_string(),
            name: "Alice".to_string(),
            role: "Auditor".to_string(),
            department: "Compliance".to_string(),
            clearance_level: 3,
            active: true,
        });

        // Create custody
        let chain_id = manager.create_custody(
            "evidence-1".to_string(),
            CustodyItemType::Evidence,
            "holder-1".to_string(),
            "Vault A".to_string(),
        ).unwrap();

        assert!(!chain_id.is_empty());

        // Verify chain
        let verification = manager.verify_chain(&chain_id).unwrap();
        assert!(verification.valid);
    }

    #[test]
    fn test_transfer() {
        let manager = CustodyManager::new();
        
        // Setup holders
        manager.register_holder(Holder {
            holder_id: "alice".to_string(),
            name: "Alice".to_string(),
            role: "Auditor".to_string(),
            department: "Compliance".to_string(),
            clearance_level: 3,
            active: true,
        });
        
        manager.register_holder(Holder {
            holder_id: "bob".to_string(),
            name: "Bob".to_string(),
            role: "Security".to_string(),
            department: "IT".to_string(),
            clearance_level: 4,
            active: true,
        });

        // Create and transfer
        let chain_id = manager.create_custody(
            "evidence-1".to_string(),
            CustodyItemType::Evidence,
            "alice".to_string(),
            "Vault A".to_string(),
        ).unwrap();

        manager.transfer(
            &chain_id,
            "bob".to_string(),
            "Vault B".to_string(),
            "alice".to_string(),
            "Handoff for review".to_string(),
        ).unwrap();

        let history = manager.get_history(&chain_id).unwrap();
        assert_eq!(history.len(), 2); // Creation + Transfer
    }

    #[test]
    fn test_access_denied() {
        let manager = CustodyManager::new();
        
        manager.register_holder(Holder {
            holder_id: "alice".to_string(),
            name: "Alice".to_string(),
            role: "Auditor".to_string(),
            department: "Compliance".to_string(),
            clearance_level: 3,
            active: true,
        });
        
        manager.register_holder(Holder {
            holder_id: "eve".to_string(),
            name: "Eve".to_string(),
            role: "Consultant".to_string(),
            department: "External".to_string(),
            clearance_level: 1,
            active: true,
        });

        let chain_id = manager.create_custody(
            "evidence-1".to_string(),
            CustodyItemType::Evidence,
            "alice".to_string(),
            "Vault A".to_string(),
        ).unwrap();

        // Eve tries to access (should be denied)
        let authorized = manager.access(
            &chain_id,
            "eve",
            AccessType::View,
            "Curiosity".to_string(),
        ).unwrap();

        assert!(!authorized);
    }
}
