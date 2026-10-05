//! Agent Index Integration — Global Agent Discovery & Management
//!
//! Integrates agent index with distributed system:
//! - Single node: Local agent index
//! - Distributed: Global agent discovery across cells
//! - Automatic routing to agents by capability
//! - Health-aware agent selection

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// =============================================================================
// Agent Index Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIndexEntry {
    /// Agent ID
    pub agent_pid: String,
    /// Cell where agent runs (None for single-node)
    pub cell_id: Option<String>,
    /// Agent capabilities
    pub capabilities: Vec<String>,
    /// Agent role
    pub role: String,
    /// Agent health score
    pub health_score: f64,
    /// KECS score
    pub kecs: f64,
    /// Current load (0.0 - 1.0)
    pub load: f64,
    /// Resource requirements
    pub memory_mb: u64,
    pub cpu_cores: f32,
    /// Last heartbeat
    pub last_heartbeat: i64,
    /// Is local to this node?
    pub is_local: bool,
    /// Endpoint for remote access
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSelectionStrategy {
    LowestLoad,  // Select agent with lowest load
    HighestKECS, // Select agent with highest KECS
    Nearest,     // Select nearest agent (latency)
    RoundRobin,  // Rotate through agents
    Random,      // Random selection
    Sticky,      // Same agent for same session
}

// =============================================================================
// Agent Index Integration
// =============================================================================

pub struct AgentIndexIntegration {
    /// Mode: local-only or distributed
    distributed_mode: bool,
    /// Local agents (this node)
    local_agents: Arc<RwLock<HashMap<String, AgentIndexEntry>>>,
    /// Remote agents (other cells) - only in distributed mode
    remote_agents: Arc<RwLock<HashMap<String, AgentIndexEntry>>>,
    /// Capability index: capability -> agent_pids
    capability_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Role index: role -> agent_pids
    role_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Round-robin positions
    round_robin: Arc<RwLock<HashMap<String, usize>>>,
    /// Sticky sessions: session_id -> agent_pid
    sticky_sessions: Arc<RwLock<HashMap<String, String>>>,
    /// Last sync time (distributed mode)
    last_sync: Arc<RwLock<Instant>>,
}

impl AgentIndexIntegration {
    /// Create for single-node mode (default)
    pub fn single_node() -> Self {
        println!("[AGENT_INDEX] Initializing in single-node mode");
        Self {
            distributed_mode: false,
            local_agents: Arc::new(RwLock::new(HashMap::new())),
            remote_agents: Arc::new(RwLock::new(HashMap::new())),
            capability_index: Arc::new(RwLock::new(HashMap::new())),
            role_index: Arc::new(RwLock::new(HashMap::new())),
            round_robin: Arc::new(RwLock::new(HashMap::new())),
            sticky_sessions: Arc::new(RwLock::new(HashMap::new())),
            last_sync: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Create for distributed mode
    pub fn distributed() -> Self {
        println!("[AGENT_INDEX] Initializing in distributed mode");
        Self {
            distributed_mode: true,
            local_agents: Arc::new(RwLock::new(HashMap::new())),
            remote_agents: Arc::new(RwLock::new(HashMap::new())),
            capability_index: Arc::new(RwLock::new(HashMap::new())),
            role_index: Arc::new(RwLock::new(HashMap::new())),
            round_robin: Arc::new(RwLock::new(HashMap::new())),
            sticky_sessions: Arc::new(RwLock::new(HashMap::new())),
            last_sync: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Register local agent
    pub fn register_local_agent(&self, entry: AgentIndexEntry) {
        let agent_pid = entry.agent_pid.clone();

        // Add to local agents
        {
            let mut local = self.local_agents.write().unwrap();
            local.insert(agent_pid.clone(), entry.clone());
        }

        // Update indices
        self.update_indices(&entry);

        println!(
            "[AGENT_INDEX] Registered local agent {} with capabilities {:?}",
            agent_pid, entry.capabilities
        );
    }

    /// Register remote agent (distributed mode only)
    pub fn register_remote_agent(&self, entry: AgentIndexEntry) {
        if !self.distributed_mode {
            return; // Ignore in single-node mode
        }

        let agent_pid = entry.agent_pid.clone();

        {
            let mut remote = self.remote_agents.write().unwrap();
            remote.insert(agent_pid.clone(), entry.clone());
        }

        // Update indices
        self.update_indices(&entry);

        println!(
            "[AGENT_INDEX] Registered remote agent {} from cell {:?}",
            agent_pid, entry.cell_id
        );
    }

    /// Update capability and role indices
    fn update_indices(&self, entry: &AgentIndexEntry) {
        // Capability index
        {
            let mut cap_idx = self.capability_index.write().unwrap();
            for cap in &entry.capabilities {
                cap_idx
                    .entry(cap.clone())
                    .or_insert_with(Vec::new)
                    .push(entry.agent_pid.clone());
            }
        }

        // Role index
        {
            let mut role_idx = self.role_index.write().unwrap();
            role_idx
                .entry(entry.role.clone())
                .or_insert_with(Vec::new)
                .push(entry.agent_pid.clone());
        }
    }

    /// Deregister agent
    pub fn deregister_agent(&self, agent_pid: &str) {
        // Get capabilities and role before removing
        let (caps, role) = {
            let local = self.local_agents.read().unwrap();
            if let Some(entry) = local.get(agent_pid) {
                (entry.capabilities.clone(), entry.role.clone())
            } else {
                let remote = self.remote_agents.read().unwrap();
                if let Some(entry) = remote.get(agent_pid) {
                    (entry.capabilities.clone(), entry.role.clone())
                } else {
                    (vec![], String::new())
                }
            }
        };

        // Remove from local
        {
            let mut local = self.local_agents.write().unwrap();
            local.remove(agent_pid);
        }

        // Remove from remote
        {
            let mut remote = self.remote_agents.write().unwrap();
            remote.remove(agent_pid);
        }

        // Remove from indices
        {
            let mut cap_idx = self.capability_index.write().unwrap();
            for cap in &caps {
                if let Some(list) = cap_idx.get_mut(cap) {
                    list.retain(|pid| pid != agent_pid);
                }
            }
        }

        {
            let mut role_idx = self.role_index.write().unwrap();
            if let Some(list) = role_idx.get_mut(&role) {
                list.retain(|pid| pid != agent_pid);
            }
        }

        // Remove from sticky sessions
        {
            let mut sticky = self.sticky_sessions.write().unwrap();
            sticky.retain(|_, pid| pid != agent_pid);
        }

        println!("[AGENT_INDEX] Deregistered agent {}", agent_pid);
    }

    /// Find agent by capability
    pub fn find_by_capability(
        &self,
        capability: &str,
        strategy: AgentSelectionStrategy,
        session_id: Option<&str>,
    ) -> Option<AgentIndexEntry> {
        // Check sticky session first
        if strategy == AgentSelectionStrategy::Sticky {
            if let Some(session) = session_id {
                let sticky = self.sticky_sessions.read().unwrap();
                if let Some(agent_pid) = sticky.get(session) {
                    // Verify agent still exists and is healthy
                    if let Some(entry) = self.get_agent(agent_pid) {
                        if entry.health_score > 0.5 {
                            return Some(entry);
                        }
                    }
                }
            }
        }

        // Get candidates
        let candidates = {
            let cap_idx = self.capability_index.read().unwrap();
            cap_idx.get(capability).cloned().unwrap_or_default()
        };

        if candidates.is_empty() {
            return None;
        }

        // Filter healthy agents
        let healthy: Vec<AgentIndexEntry> = candidates
            .iter()
            .filter_map(|pid| self.get_agent(pid))
            .filter(|e| e.health_score > 0.5 && e.load < 0.9)
            .collect();

        if healthy.is_empty() {
            return None;
        }

        // Select based on strategy
        let selected = match strategy {
            AgentSelectionStrategy::LowestLoad => healthy
                .iter()
                .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap())
                .cloned(),
            AgentSelectionStrategy::HighestKECS => healthy
                .iter()
                .max_by(|a, b| a.kecs.partial_cmp(&b.kecs).unwrap())
                .cloned(),
            AgentSelectionStrategy::Nearest => {
                // In single-node: just pick local
                // In distributed: would use topology
                healthy
                    .iter()
                    .find(|e| e.is_local)
                    .cloned()
                    .or_else(|| healthy.first().cloned())
            }
            AgentSelectionStrategy::RoundRobin => {
                let mut rr = self.round_robin.write().unwrap();
                let pos = rr.entry(capability.to_string()).or_insert(0);
                let idx = *pos % healthy.len();
                *pos = (*pos + 1) % healthy.len().max(1);
                healthy.get(idx).cloned()
            }
            AgentSelectionStrategy::Random => {
                let idx = rand::random::<usize>() % healthy.len();
                healthy.get(idx).cloned()
            }
            AgentSelectionStrategy::Sticky => {
                // Default to lowest load if no sticky session
                healthy
                    .iter()
                    .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap())
                    .cloned()
            }
        };

        // Record sticky session
        if let Some(ref entry) = selected {
            if strategy == AgentSelectionStrategy::Sticky {
                if let Some(session) = session_id {
                    let mut sticky = self.sticky_sessions.write().unwrap();
                    sticky.insert(session.to_string(), entry.agent_pid.clone());
                }
            }
        }

        selected
    }

    /// Find agent by role
    pub fn find_by_role(
        &self,
        role: &str,
        strategy: AgentSelectionStrategy,
    ) -> Option<AgentIndexEntry> {
        let candidates = {
            let role_idx = self.role_index.read().unwrap();
            role_idx.get(role).cloned().unwrap_or_default()
        };

        let healthy: Vec<AgentIndexEntry> = candidates
            .iter()
            .filter_map(|pid| self.get_agent(pid))
            .filter(|e| e.health_score > 0.5)
            .collect();

        match strategy {
            AgentSelectionStrategy::LowestLoad => healthy
                .iter()
                .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap())
                .cloned(),
            _ => healthy.first().cloned(),
        }
    }

    /// Get agent by PID
    pub fn get_agent(&self, agent_pid: &str) -> Option<AgentIndexEntry> {
        // Check local first
        {
            let local = self.local_agents.read().unwrap();
            if let Some(entry) = local.get(agent_pid) {
                return Some(entry.clone());
            }
        }

        // Check remote
        if self.distributed_mode {
            let remote = self.remote_agents.read().unwrap();
            remote.get(agent_pid).cloned()
        } else {
            None
        }
    }

    /// Get all local agents
    pub fn get_local_agents(&self) -> Vec<AgentIndexEntry> {
        self.local_agents
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Get all agents (local + remote in distributed mode)
    pub fn get_all_agents(&self) -> Vec<AgentIndexEntry> {
        let mut agents = self.get_local_agents();

        if self.distributed_mode {
            let remote = self.remote_agents.read().unwrap();
            agents.extend(remote.values().cloned());
        }

        agents
    }

    /// Update agent heartbeat
    pub fn heartbeat(&self, agent_pid: &str) {
        let now = chrono::Utc::now().timestamp_millis();

        {
            let mut local = self.local_agents.write().unwrap();
            if let Some(entry) = local.get_mut(agent_pid) {
                entry.last_heartbeat = now;
                return;
            }
        }

        if self.distributed_mode {
            let mut remote = self.remote_agents.write().unwrap();
            if let Some(entry) = remote.get_mut(agent_pid) {
                entry.last_heartbeat = now;
            }
        }
    }

    /// Update agent load
    pub fn update_load(&self, agent_pid: &str, load: f64) {
        {
            let mut local = self.local_agents.write().unwrap();
            if let Some(entry) = local.get_mut(agent_pid) {
                entry.load = load.clamp(0.0, 1.0);
                return;
            }
        }

        if self.distributed_mode {
            let mut remote = self.remote_agents.write().unwrap();
            if let Some(entry) = remote.get_mut(agent_pid) {
                entry.load = load.clamp(0.0, 1.0);
            }
        }
    }

    /// Cleanup stale agents (no heartbeat for 5 minutes)
    pub fn cleanup_stale(&self) -> usize {
        let cutoff = chrono::Utc::now().timestamp_millis() - 300_000;
        let mut removed = 0;

        // Cleanup local
        {
            let local = self.local_agents.read().unwrap();
            let stale: Vec<String> = local
                .iter()
                .filter(|(_, e)| e.last_heartbeat < cutoff)
                .map(|(pid, _)| pid.clone())
                .collect();
            drop(local);

            for pid in stale {
                self.deregister_agent(&pid);
                removed += 1;
            }
        }

        // Cleanup remote
        if self.distributed_mode {
            let remote = self.remote_agents.read().unwrap();
            let stale: Vec<String> = remote
                .iter()
                .filter(|(_, e)| e.last_heartbeat < cutoff)
                .map(|(pid, _)| pid.clone())
                .collect();
            drop(remote);

            for pid in stale {
                self.deregister_agent(&pid);
                removed += 1;
            }
        }

        removed
    }

    /// Get statistics
    pub fn get_stats(&self) -> IndexStats {
        let local = self.local_agents.read().unwrap();
        let remote = self.remote_agents.read().unwrap();
        let cap_idx = self.capability_index.read().unwrap();

        IndexStats {
            mode: if self.distributed_mode {
                "distributed"
            } else {
                "single-node"
            },
            local_agents: local.len(),
            remote_agents: if self.distributed_mode {
                remote.len()
            } else {
                0
            },
            total_capabilities: cap_idx.len(),
            total_roles: self.role_index.read().unwrap().len(),
            avg_load: local
                .values()
                .chain(remote.values())
                .map(|e| e.load)
                .sum::<f64>()
                / (local.len() + remote.len()).max(1) as f64,
        }
    }

    /// Sync with remote cells (distributed mode)
    pub fn sync_remote(&self) -> Result<(), String> {
        if !self.distributed_mode {
            return Ok(()); // Nothing to sync in single-node
        }

        // In production: fetch agent list from remote cells via transport
        // For now: just update last sync time
        *self.last_sync.write().unwrap() = Instant::now();

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub mode: &'static str,
    pub local_agents: usize,
    pub remote_agents: usize,
    pub total_capabilities: usize,
    pub total_roles: usize,
    pub avg_load: f64,
}

#[derive(Clone)]
pub struct SharedAgentIndexIntegration {
    inner: Arc<AgentIndexIntegration>,
}

impl SharedAgentIndexIntegration {
    pub fn single_node() -> Self {
        Self {
            inner: Arc::new(AgentIndexIntegration::single_node()),
        }
    }

    pub fn distributed() -> Self {
        Self {
            inner: Arc::new(AgentIndexIntegration::distributed()),
        }
    }

    pub fn register_local_agent(&self, entry: AgentIndexEntry) {
        self.inner.register_local_agent(entry);
    }

    pub fn find_by_capability(
        &self,
        cap: &str,
        strategy: AgentSelectionStrategy,
        session: Option<&str>,
    ) -> Option<AgentIndexEntry> {
        self.inner.find_by_capability(cap, strategy, session)
    }

    pub fn get_local_agents(&self) -> Vec<AgentIndexEntry> {
        self.inner.get_local_agents()
    }

    pub fn update_load(&self, pid: &str, load: f64) {
        self.inner.update_load(pid, load);
    }

    pub fn heartbeat(&self, pid: &str) {
        self.inner.heartbeat(pid);
    }

    pub fn get_stats(&self) -> IndexStats {
        self.inner.get_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_node_mode() {
        let index = AgentIndexIntegration::single_node();

        let entry = AgentIndexEntry {
            agent_pid: "agent-1".to_string(),
            cell_id: None,
            capabilities: vec!["writer".to_string()],
            role: "writer".to_string(),
            health_score: 0.9,
            kecs: 0.8,
            load: 0.3,
            memory_mb: 256,
            cpu_cores: 0.25,
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            is_local: true,
            endpoint: None,
        };

        index.register_local_agent(entry);

        let found = index.find_by_capability("writer", AgentSelectionStrategy::LowestLoad, None);
        assert!(found.is_some());
    }

    #[test]
    fn test_capability_search() {
        let index = AgentIndexIntegration::single_node();

        // Register agents with different loads
        for i in 0..5 {
            let entry = AgentIndexEntry {
                agent_pid: format!("agent-{}", i),
                cell_id: None,
                capabilities: vec!["compute".to_string()],
                role: "worker".to_string(),
                health_score: 0.9,
                kecs: 0.8,
                load: i as f64 * 0.1,
                memory_mb: 256,
                cpu_cores: 0.25,
                last_heartbeat: chrono::Utc::now().timestamp_millis(),
                is_local: true,
                endpoint: None,
            };
            index.register_local_agent(entry);
        }

        // Should find lowest load (agent-0 with 0.0 load)
        let found = index.find_by_capability("compute", AgentSelectionStrategy::LowestLoad, None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().agent_pid, "agent-0");
    }
}
