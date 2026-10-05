//! Advanced Namespace Isolation — Virtualization Tree with MAC
//!
//! Provides:
//! - Mandatory Access Control (Bell-LaPadula + Biba hybrid)
//! - Virtualization tree (hierarchical isolation)
//! - Chain-controlled isolation (if compromised, chain breaks)
//! - Data leak prevention with automatic containment
//! - LLM misbehavior containment

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

// =============================================================================
// Security Levels (Bell-LaPadula)
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
}

impl SecurityLevel {
    /// Can read from lower level? (No read up - Simple Security Property)
    pub fn can_read_from(&self, source: SecurityLevel) -> bool {
        *self >= source // Can read same or lower
    }

    /// Can write to higher level? (No write down - *-Property)
    pub fn can_write_to(&self, target: SecurityLevel) -> bool {
        *self <= target // Can write same or higher
    }

    /// Check if access is allowed
    pub fn check_access(&self, obj_level: SecurityLevel, is_read: bool) -> bool {
        if is_read {
            self.can_read_from(obj_level)
        } else {
            self.can_write_to(obj_level)
        }
    }
}

// =============================================================================
// Integrity Levels (Biba)
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl IntegrityLevel {
    /// Can read from higher integrity? (No read down)
    pub fn can_read_from(&self, source: IntegrityLevel) -> bool {
        *self <= source // Can read same or higher
    }

    /// Can write to lower integrity? (No write up)
    pub fn can_write_to(&self, target: IntegrityLevel) -> bool {
        *self >= target // Can write same or lower
    }
}

// =============================================================================
// Namespace Node (Virtualization Tree)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceNode {
    /// Unique namespace ID
    pub namespace_id: String,
    /// Parent namespace (None for root)
    pub parent: Option<String>,
    /// Children namespaces
    pub children: Vec<String>,
    /// Security level
    pub security_level: SecurityLevel,
    /// Integrity level
    pub integrity_level: IntegrityLevel,
    /// Categories (compartments)
    pub categories: HashSet<String>,
    /// Agents in this namespace
    pub agents: HashSet<String>,
    /// Resources allocated
    pub resources: NamespaceResources,
    /// Isolation status
    pub isolation_status: IsolationStatus,
    /// Chain hash (for integrity verification)
    pub chain_hash: String,
    /// Created at
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceResources {
    pub memory_limit_mb: u64,
    pub cpu_limit_millicores: u32,
    pub max_agents: u32,
    pub network_bandwidth_mbps: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IsolationStatus {
    Secure,
    Compromised,
    Contained,
    Quarantined,
}

// =============================================================================
// Isolation Chain (Chain-controlled isolation)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationChain {
    /// Chain of trust (sequence of verified states)
    pub trust_chain: Vec<ChainLink>,
    /// Current chain hash
    pub current_hash: String,
    /// Is chain intact?
    pub is_intact: bool,
    /// Last verification
    pub last_verified: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    pub link_index: u64,
    pub namespace_id: String,
    /// Hash of previous link
    pub prev_hash: String,
    /// Current state hash
    pub state_hash: String,
    /// Timestamp
    pub timestamp: i64,
}

impl IsolationChain {
    /// Verify chain integrity
    pub fn verify(&self) -> bool {
        if self.trust_chain.is_empty() {
            return true; // Empty chain is valid
        }

        for i in 1..self.trust_chain.len() {
            let prev = &self.trust_chain[i - 1];
            let curr = &self.trust_chain[i];

            // Check chain continuity
            if curr.prev_hash != prev.state_hash {
                return false;
            }

            // Check sequence
            if curr.link_index != prev.link_index + 1 {
                return false;
            }
        }

        true
    }

    /// Add new link to chain
    pub fn append_link(&mut self, namespace_id: String, state_data: &str) -> String {
        let prev_hash = self
            .trust_chain
            .last()
            .map(|l| l.state_hash.clone())
            .unwrap_or_default();

        let link_index = self.trust_chain.len() as u64;
        let timestamp = chrono::Utc::now().timestamp_millis();

        // Calculate state hash
        let state_hash =
            Self::calculate_hash(&prev_hash, namespace_id.clone(), state_data, timestamp);

        let link = ChainLink {
            link_index,
            namespace_id,
            prev_hash,
            state_hash: state_hash.clone(),
            timestamp,
        };

        self.trust_chain.push(link);
        self.current_hash = state_hash.clone();
        self.last_verified = timestamp;

        // Verify chain still intact
        self.is_intact = self.verify();

        state_hash
    }

    fn calculate_hash(prev: &str, ns: String, data: &str, ts: i64) -> String {
        use sha2::{Digest, Sha256};
        let input = format!("{}:{}:{}:{}", prev, ns, data, ts);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// If chain broken, mark as compromised
    pub fn handle_breach(&mut self) {
        self.is_intact = false;
        // Chain is broken - trigger containment
    }
}

// =============================================================================
// Virtualization Tree Manager
// =============================================================================

pub struct NamespaceIsolation {
    /// All namespaces
    namespaces: HashMap<String, NamespaceNode>,
    /// Root namespaces
    roots: Vec<String>,
    /// Isolation chains per namespace
    chains: HashMap<String, IsolationChain>,
    /// Access audit log
    audit_log: Vec<AccessEvent>,
    /// Data leak detections
    leak_detections: Vec<LeakDetection>,
    /// Containment policies
    containment_policies: HashMap<String, ContainmentPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub timestamp: i64,
    pub namespace_id: String,
    pub agent_pid: String,
    pub operation: AccessOperation,
    pub target_namespace: Option<String>,
    pub success: bool,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessOperation {
    Read,
    Write,
    Execute,
    CreateAgent,
    DeleteAgent,
    CrossNamespaceAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakDetection {
    pub timestamp: i64,
    pub source_namespace: String,
    pub target_namespace: String,
    pub data_type: String,
    pub severity: LeakSeverity,
    pub chain_broken: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeakSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentPolicy {
    pub namespace_id: String,
    pub auto_contain_on_breach: bool,
    pub contain_children: bool,
    pub notify_admins: bool,
    pub preserve_evidence: bool,
}

impl NamespaceIsolation {
    pub fn new() -> Self {
        Self {
            namespaces: HashMap::new(),
            roots: Vec::new(),
            chains: HashMap::new(),
            audit_log: Vec::new(),
            leak_detections: Vec::new(),
            containment_policies: HashMap::new(),
        }
    }

    /// Create namespace in tree
    pub fn create_namespace(
        &mut self,
        namespace_id: String,
        parent: Option<String>,
        security_level: SecurityLevel,
        integrity_level: IntegrityLevel,
        categories: HashSet<String>,
    ) -> Result<(), IsolationError> {
        // Check parent exists if specified
        if let Some(ref parent_id) = parent {
            if !self.namespaces.contains_key(parent_id) {
                return Err(IsolationError::ParentNotFound);
            }
        }

        let resources = NamespaceResources {
            memory_limit_mb: 1024,
            cpu_limit_millicores: 1000,
            max_agents: 10,
            network_bandwidth_mbps: 100,
        };

        let node = NamespaceNode {
            namespace_id: namespace_id.clone(),
            parent: parent.clone(),
            children: Vec::new(),
            security_level,
            integrity_level,
            categories,
            agents: HashSet::new(),
            resources,
            isolation_status: IsolationStatus::Secure,
            chain_hash: String::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
        };

        // Link to parent
        if let Some(ref parent_id) = parent {
            if let Some(parent_node) = self.namespaces.get_mut(parent_id) {
                parent_node.children.push(namespace_id.clone());
            }
        } else {
            self.roots.push(namespace_id.clone());
        }

        // Create isolation chain
        let mut chain = IsolationChain {
            trust_chain: Vec::new(),
            current_hash: String::new(),
            is_intact: true,
            last_verified: 0,
        };
        chain.append_link(namespace_id.clone(), "namespace_created");

        self.chains.insert(namespace_id.clone(), chain);
        self.namespaces.insert(namespace_id.clone(), node);

        // Default containment policy
        self.containment_policies.insert(
            namespace_id.clone(),
            ContainmentPolicy {
                namespace_id: namespace_id.clone(),
                auto_contain_on_breach: true,
                contain_children: true,
                notify_admins: true,
                preserve_evidence: true,
            },
        );

        Ok(())
    }

    /// Check if cross-namespace access is allowed
    pub fn check_cross_namespace_access(
        &mut self,
        source_ns: &str,
        target_ns: &str,
        agent_pid: &str,
        is_read: bool,
    ) -> bool {
        let source = match self.namespaces.get(source_ns) {
            Some(ns) => ns,
            None => return false,
        };

        let target = match self.namespaces.get(target_ns) {
            Some(ns) => ns,
            None => return false,
        };

        // Check if source chain is intact
        if let Some(chain) = self.chains.get(source_ns) {
            if !chain.is_intact {
                // Chain broken - deny all access and trigger containment
                self.handle_chain_breach(source_ns, agent_pid);
                return false;
            }
        }

        // Check security levels (Bell-LaPadula)
        if !source
            .security_level
            .check_access(target.security_level, is_read)
        {
            self.log_access(
                source_ns,
                agent_pid,
                AccessOperation::CrossNamespaceAccess,
                Some(target_ns.to_string()),
                false,
            );
            return false;
        }

        // Check integrity levels (Biba)
        if is_read {
            // Reading: check Biba no-read-down
            if !source.integrity_level.can_read_from(target.integrity_level) {
                return false;
            }
        } else {
            // Writing: check Biba no-write-up
            if !source.integrity_level.can_write_to(target.integrity_level) {
                return false;
            }
        }

        // Check categories (compartments)
        let shared_categories: HashSet<_> =
            source.categories.intersection(&target.categories).collect();
        if shared_categories.is_empty()
            && !source.categories.is_empty()
            && !target.categories.is_empty()
        {
            // No shared categories - deny access
            return false;
        }

        // Check for data leak patterns
        if self.detect_data_leak(source_ns, target_ns, agent_pid) {
            self.handle_data_leak(source_ns, target_ns, agent_pid);
            return false;
        }

        // Log successful access
        self.log_access(
            source_ns,
            agent_pid,
            AccessOperation::CrossNamespaceAccess,
            Some(target_ns.to_string()),
            true,
        );

        true
    }

    /// Detect potential data leak
    fn detect_data_leak(&self, source_ns: &str, target_ns: &str, agent_pid: &str) -> bool {
        // Check if agent has history of suspicious access
        let suspicious_count = self
            .audit_log
            .iter()
            .filter(|e| {
                e.agent_pid == agent_pid
                    && e.operation == AccessOperation::CrossNamespaceAccess
                    && !e.success
            })
            .count();

        // More than 5 failed attempts = potential leak attempt
        suspicious_count > 5
    }

    /// Handle data leak detection
    fn handle_data_leak(&mut self, source_ns: &str, target_ns: &str, agent_pid: &str) {
        // Log detection
        let detection = LeakDetection {
            timestamp: chrono::Utc::now().timestamp_millis(),
            source_namespace: source_ns.to_string(),
            target_namespace: target_ns.to_string(),
            data_type: "cross_namespace".to_string(),
            severity: LeakSeverity::High,
            chain_broken: true,
        };

        self.leak_detections.push(detection);

        // Break chain for source namespace
        if let Some(chain) = self.chains.get_mut(source_ns) {
            chain.handle_breach();
        }

        // Trigger containment
        self.contain_namespace(source_ns);

        eprintln!(
            "[SECURITY] Data leak detected: {} -> {} by agent {}",
            source_ns, target_ns, agent_pid
        );
    }

    /// Handle chain breach
    fn handle_chain_breach(&mut self, namespace_id: &str, agent_pid: &str) {
        // Mark as compromised
        if let Some(ns) = self.namespaces.get_mut(namespace_id) {
            ns.isolation_status = IsolationStatus::Compromised;
        }

        // Contain the namespace
        self.contain_namespace(namespace_id);

        eprintln!(
            "[SECURITY] Chain breach in namespace {} by agent {}",
            namespace_id, agent_pid
        );
    }

    /// Contain namespace (isolate from others)
    fn contain_namespace(&mut self, namespace_id: &str) {
        if let Some(ns) = self.namespaces.get_mut(namespace_id) {
            ns.isolation_status = IsolationStatus::Contained;

            // Get containment policy
            if let Some(policy) = self.containment_policies.get(namespace_id) {
                if policy.contain_children {
                    // Recursively contain children
                    let children = ns.children.clone();
                    for child_id in children {
                        self.contain_namespace(&child_id);
                    }
                }
            }
        }
    }

    /// Log access event
    fn log_access(
        &mut self,
        namespace_id: &str,
        agent_pid: &str,
        operation: AccessOperation,
        target: Option<String>,
        success: bool,
    ) {
        let chain_hash = self
            .chains
            .get(namespace_id)
            .map(|c| c.current_hash.clone())
            .unwrap_or_default();

        let event = AccessEvent {
            timestamp: chrono::Utc::now().timestamp_millis(),
            namespace_id: namespace_id.to_string(),
            agent_pid: agent_pid.to_string(),
            operation,
            target_namespace: target,
            success,
            chain_hash,
        };

        self.audit_log.push(event);
    }

    /// Register agent in namespace
    pub fn register_agent(
        &mut self,
        namespace_id: &str,
        agent_pid: &str,
    ) -> Result<(), IsolationError> {
        let ns = self
            .namespaces
            .get_mut(namespace_id)
            .ok_or(IsolationError::NamespaceNotFound)?;

        if ns.isolation_status != IsolationStatus::Secure {
            return Err(IsolationError::NamespaceCompromised);
        }

        ns.agents.insert(agent_pid.to_string());

        // Update chain
        if let Some(chain) = self.chains.get_mut(namespace_id) {
            chain.append_link(
                namespace_id.to_string(),
                &format!("agent_registered:{}", agent_pid),
            );
        }

        Ok(())
    }

    /// Verify all chains
    pub fn verify_all_chains(&mut self) -> Vec<(String, bool)> {
        self.chains
            .iter_mut()
            .map(|(ns_id, chain)| {
                let is_intact = chain.verify();
                chain.is_intact = is_intact;
                (ns_id.clone(), is_intact)
            })
            .collect()
    }

    /// Get isolation status summary
    pub fn get_status_summary(&self) -> IsolationSummary {
        let total = self.namespaces.len();
        let secure = self
            .namespaces
            .values()
            .filter(|n| n.isolation_status == IsolationStatus::Secure)
            .count();
        let compromised = self
            .namespaces
            .values()
            .filter(|n| n.isolation_status == IsolationStatus::Compromised)
            .count();
        let contained = self
            .namespaces
            .values()
            .filter(|n| n.isolation_status == IsolationStatus::Contained)
            .count();

        IsolationSummary {
            total_namespaces: total,
            secure,
            compromised,
            contained,
            intact_chains: self.chains.values().filter(|c| c.is_intact).count(),
            broken_chains: self.chains.values().filter(|c| !c.is_intact).count(),
            leak_count: self.leak_detections.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IsolationError {
    ParentNotFound,
    NamespaceNotFound,
    NamespaceCompromised,
    AccessDenied,
    ChainBroken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationSummary {
    pub total_namespaces: usize,
    pub secure: usize,
    pub compromised: usize,
    pub contained: usize,
    pub intact_chains: usize,
    pub broken_chains: usize,
    pub leak_count: usize,
}

// =============================================================================
// Thread-safe wrapper
// =============================================================================

#[derive(Clone)]
pub struct SharedNamespaceIsolation {
    inner: Arc<RwLock<NamespaceIsolation>>,
}

impl SharedNamespaceIsolation {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(NamespaceIsolation::new())),
        }
    }

    pub fn create_namespace(
        &self,
        id: String,
        parent: Option<String>,
        sec: SecurityLevel,
        int: IntegrityLevel,
        cats: HashSet<String>,
    ) -> Result<(), IsolationError> {
        self.inner
            .write()
            .unwrap()
            .create_namespace(id, parent, sec, int, cats)
    }

    pub fn check_access(&self, source: &str, target: &str, agent: &str, read: bool) -> bool {
        self.inner
            .write()
            .unwrap()
            .check_cross_namespace_access(source, target, agent, read)
    }

    pub fn register_agent(&self, ns: &str, agent: &str) -> Result<(), IsolationError> {
        self.inner.write().unwrap().register_agent(ns, agent)
    }

    pub fn verify_chains(&self) -> Vec<(String, bool)> {
        self.inner.write().unwrap().verify_all_chains()
    }

    pub fn get_summary(&self) -> IsolationSummary {
        self.inner.read().unwrap().get_status_summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        // No read up
        assert!(SecurityLevel::Internal.can_read_from(SecurityLevel::Public));
        assert!(!SecurityLevel::Public.can_read_from(SecurityLevel::Secret));

        // No write down
        assert!(!SecurityLevel::Secret.can_write_to(SecurityLevel::Public));
        assert!(SecurityLevel::Public.can_write_to(SecurityLevel::Secret));
    }

    #[test]
    fn test_chain_integrity() {
        let mut chain = IsolationChain {
            trust_chain: Vec::new(),
            current_hash: String::new(),
            is_intact: true,
            last_verified: 0,
        };

        chain.append_link("ns1".to_string(), "state1");
        chain.append_link("ns1".to_string(), "state2");

        assert!(chain.verify());
        assert!(chain.is_intact);

        // Tamper with chain
        chain.trust_chain[0].state_hash = "tampered".to_string();
        assert!(!chain.verify());
    }

    #[test]
    fn test_namespace_isolation() {
        let mut isolation = NamespaceIsolation::new();

        // Create parent
        isolation
            .create_namespace(
                "parent".to_string(),
                None,
                SecurityLevel::Secret,
                IntegrityLevel::High,
                HashSet::new(),
            )
            .unwrap();

        // Create child
        isolation
            .create_namespace(
                "child".to_string(),
                Some("parent".to_string()),
                SecurityLevel::Confidential,
                IntegrityLevel::Medium,
                HashSet::new(),
            )
            .unwrap();

        // Child should not read from parent (no read up)
        assert!(!isolation.check_cross_namespace_access("child", "parent", "agent-1", true));

        // Parent can read from child
        assert!(isolation.check_cross_namespace_access("parent", "child", "agent-1", true));
    }

    #[test]
    fn test_data_leak_detection() {
        let mut isolation = NamespaceIsolation::new();

        isolation
            .create_namespace(
                "ns1".to_string(),
                None,
                SecurityLevel::Internal,
                IntegrityLevel::Medium,
                HashSet::new(),
            )
            .unwrap();

        isolation
            .create_namespace(
                "ns2".to_string(),
                None,
                SecurityLevel::Public,
                IntegrityLevel::Low,
                HashSet::new(),
            )
            .unwrap();

        // Simulate failed access attempts
        for _ in 0..6 {
            isolation.log_access(
                "ns1",
                "agent-1",
                AccessOperation::CrossNamespaceAccess,
                Some("ns2".to_string()),
                false,
            );
        }

        // Should detect leak
        assert!(isolation.detect_data_leak("ns1", "ns2", "agent-1"));
    }
}
