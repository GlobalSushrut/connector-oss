//! Agent Index Integration — Real-time Index Sync with Kernel
//!
//! FIX BUG-069: Capability-based discovery and dynamic registration

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

use crate::distributed::cnp_stack::{CnpSession, Intent};

// =============================================================================
// Agent Index Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIndexEntry {
    pub agent_id: String,
    pub cell_id: String,
    pub capabilities: Vec<Capability>,
    pub role: AgentRole,
    pub status: AgentStatus,
    pub load_score: f32,        // 0.0 - 1.0
    pub last_heartbeat: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub version: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentRole {
    Worker,
    Coordinator,
    Gateway,
    Monitor,
    Specialized(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Registering,
    Active,
    Busy,
    Paused,
    Offline,
}

// =============================================================================
// Query Types
// =============================================================================

#[derive(Debug, Clone)]
pub struct AgentQuery {
    pub required_capabilities: Vec<String>,
    pub preferred_cell: Option<String>,
    pub max_load: f32,
    pub role: Option<AgentRole>,
    pub exclude_offline: bool,
}

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub agents: Vec<AgentIndexEntry>,
    pub total_matched: usize,
    pub selection_strategy: SelectionStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionStrategy {
    LeastLoaded,
    RoundRobin,
    StickySession(String),
    CapabilityScore,
    Random,
}

// =============================================================================
// Index Integration
// =============================================================================

pub struct AgentIndexIntegration {
    entries: Arc<RwLock<HashMap<String, AgentIndexEntry>>>,
    /// Capability index: capability -> agents with that capability
    capability_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Cell index: cell_id -> agents in cell
    cell_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Role index: role -> agents with that role
    role_index: Arc<RwLock<HashMap<AgentRole, HashSet<String>>>>,
    /// Recent changes for sync
    change_log: Arc<RwLock<VecDeque<IndexChange>>>,
    /// Sticky session routing: session_id -> agent_id
    sticky_sessions: Arc<RwLock<HashMap<String, String>>>,
}

#[derive(Debug, Clone)]
enum IndexChange {
    Added(String),
    Updated(String),
    Removed(String),
}

impl AgentIndexIntegration {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            capability_index: Arc::new(RwLock::new(HashMap::new())),
            cell_index: Arc::new(RwLock::new(HashMap::new())),
            role_index: Arc::new(RwLock::new(HashMap::new())),
            change_log: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            sticky_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register agent in index
    pub fn register(&self, entry: AgentIndexEntry) -> Result<(), String> {
        let agent_id = entry.agent_id.clone();
        
        // Add to entries
        self.entries.write().unwrap().insert(agent_id.clone(), entry.clone());
        
        // Update capability index
        {
            let mut cap_idx = self.capability_index.write().unwrap();
            for cap in &entry.capabilities {
                cap_idx.entry(cap.name.clone())
                    .or_insert_with(HashSet::new)
                    .insert(agent_id.clone());
            }
        }
        
        // Update cell index
        {
            let mut cell_idx = self.cell_index.write().unwrap();
            cell_idx.entry(entry.cell_id.clone())
                .or_insert_with(HashSet::new)
                .insert(agent_id.clone());
        }
        
        // Update role index
        {
            let mut role_idx = self.role_index.write().unwrap();
            role_idx.entry(entry.role)
                .or_insert_with(HashSet::new)
                .insert(agent_id.clone());
        }
        
        // Log change
        self.change_log.write().unwrap().push_back(IndexChange::Added(agent_id.clone()));
        
        println!("[AGENT-INDEX] Registered {} with {} capabilities",
            agent_id, entry.capabilities.len());
        
        Ok(())
    }

    /// Update agent status
    pub fn update_status(&self, agent_id: &str, status: AgentStatus, load_score: Option<f32>) -> Result<(), String> {
        let mut entries = self.entries.write().unwrap();
        
        if let Some(entry) = entries.get_mut(agent_id) {
            entry.status = status;
            if let Some(load) = load_score {
                entry.load_score = load;
            }
            entry.last_heartbeat = chrono::Utc::now().timestamp_millis();
            
            self.change_log.write().unwrap().push_back(IndexChange::Updated(agent_id.to_string()));
            
            println!("[AGENT-INDEX] Updated {}: status={:?}, load={}",
                agent_id, status, entry.load_score);
            Ok(())
        } else {
            Err("Agent not found".to_string())
        }
    }

    /// Heartbeat from agent
    pub fn heartbeat(&self, agent_id: &str) -> Result<(), String> {
        self.update_status(agent_id, AgentStatus::Active, None)
    }

    /// Unregister agent
    pub fn unregister(&self, agent_id: &str) -> Result<(), String> {
        let entry = self.entries.write().unwrap()
            .remove(agent_id)
            .ok_or("Agent not found")?;
        
        // Remove from capability index
        {
            let mut cap_idx = self.capability_index.write().unwrap();
            for cap in &entry.capabilities {
                if let Some(set) = cap_idx.get_mut(&cap.name) {
                    set.remove(agent_id);
                }
            }
        }
        
        // Remove from cell index
        {
            let mut cell_idx = self.cell_index.write().unwrap();
            if let Some(set) = cell_idx.get_mut(&entry.cell_id) {
                set.remove(agent_id);
            }
        }
        
        // Remove from role index
        {
            let mut role_idx = self.role_index.write().unwrap();
            if let Some(set) = role_idx.get_mut(&entry.role) {
                set.remove(agent_id);
            }
        }
        
        // Clean up sticky sessions
        {
            let mut sticky = self.sticky_sessions.write().unwrap();
            sticky.retain(|_, aid| aid != agent_id);
        }
        
        self.change_log.write().unwrap().push_back(IndexChange::Removed(agent_id.to_string()));
        
        println!("[AGENT-INDEX] Unregistered {}", agent_id);
        Ok(())
    }

    /// Find agents matching query
    pub fn find_agents(&self, query: &AgentQuery, strategy: SelectionStrategy) -> QueryResult {
        let entries = self.entries.read().unwrap();
        
        // Start with capability filter
        let mut candidates: Vec<&AgentIndexEntry> = if query.required_capabilities.is_empty() {
            entries.values().collect()
        } else {
            let cap_idx = self.capability_index.read().unwrap();
            
            // Find agents with ALL required capabilities
            let mut matching: Option<HashSet<String>> = None;
            for cap in &query.required_capabilities {
                if let Some(agents) = cap_idx.get(cap) {
                    match &mut matching {
                        None => matching = Some(agents.clone()),
                        Some(m) => {
                            m.retain(|a| agents.contains(a));
                        }
                    }
                } else {
                    return QueryResult {
                        agents: vec![],
                        total_matched: 0,
                        selection_strategy: strategy,
                    };
                }
            }
            
            matching.unwrap_or_default()
                .iter()
                .filter_map(|id| entries.get(id))
                .collect()
        };
        
        // Apply additional filters
        candidates.retain(|e| {
            if query.exclude_offline && e.status == AgentStatus::Offline {
                return false;
            }
            if e.load_score > query.max_load {
                return false;
            }
            if let Some(ref cell) = query.preferred_cell {
                if e.cell_id != *cell {
                    return false;
                }
            }
            if let Some(ref role) = query.role {
                if e.role != *role {
                    return false;
                }
            }
            true
        });
        
        let total_matched = candidates.len();
        
        // Sort by strategy
        let mut agents: Vec<AgentIndexEntry> = candidates.into_iter().cloned().collect();
        match strategy {
            SelectionStrategy::LeastLoaded => {
                agents.sort_by(|a, b| a.load_score.partial_cmp(&b.load_score).unwrap());
            }
            SelectionStrategy::RoundRobin => {
                // Random for now, in production use proper round-robin
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                chrono::Utc::now().timestamp_millis().hash(&mut hasher);
                let seed = hasher.finish();
                // Rotate by seed
                let offset = (seed as usize) % agents.len().max(1);
                agents.rotate_left(offset);
            }
            SelectionStrategy::CapabilityScore => {
                agents.sort_by(|a, b| {
                    let a_score: f32 = a.capabilities.iter().map(|c| c.confidence).sum();
                    let b_score: f32 = b.capabilities.iter().map(|c| c.confidence).sum();
                    b_score.partial_cmp(&a_score).unwrap()
                });
            }
            _ => {}
        }
        
        QueryResult {
            agents,
            total_matched,
            selection_strategy: strategy,
        }
    }

    /// "Find me an agent that can do X"
    pub fn find_agent_for_capability(&self, capability: &str, strategy: SelectionStrategy) -> Option<AgentIndexEntry> {
        let query = AgentQuery {
            required_capabilities: vec![capability.to_string()],
            preferred_cell: None,
            max_load: 0.9,
            role: None,
            exclude_offline: true,
        };
        
        let result = self.find_agents(&query, strategy);
        result.agents.into_iter().next()
    }

    /// Get or create sticky session
    pub fn get_sticky_agent(&self, session_id: &str, capability: &str) -> Option<AgentIndexEntry> {
        let sticky = self.sticky_sessions.read().unwrap();
        
        if let Some(agent_id) = sticky.get(session_id) {
            // Verify agent still active and has capability
            if let Some(entry) = self.entries.read().unwrap().get(agent_id) {
                if entry.status == AgentStatus::Active {
                    if entry.capabilities.iter().any(|c| c.name == capability) {
                        return Some(entry.clone());
                    }
                }
            }
        }
        
        drop(sticky);
        
        // Find new agent
        let agent = self.find_agent_for_capability(capability, SelectionStrategy::LeastLoaded)?;
        
        // Record sticky session
        self.sticky_sessions.write().unwrap()
            .insert(session_id.to_string(), agent.agent_id.clone());
        
        Some(agent)
    }

    /// Get changes since last sync
    pub fn get_changes(&self, since: i64) -> Vec<IndexChange> {
        self.change_log.read().unwrap()
            .iter()
            .filter(|_| true) // In production: filter by timestamp
            .cloned()
            .collect()
    }

    /// Get agents by cell
    pub fn get_cell_agents(&self, cell_id: &str) -> Vec<AgentIndexEntry> {
        let cell_idx = self.cell_index.read().unwrap();
        let entries = self.entries.read().unwrap();
        
        cell_idx.get(cell_id)
            .map(|agents| {
                agents.iter()
                    .filter_map(|id| entries.get(id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get agents by role
    pub fn get_role_agents(&self, role: AgentRole) -> Vec<AgentIndexEntry> {
        let role_idx = self.role_index.read().unwrap();
        let entries = self.entries.read().unwrap();
        
        role_idx.get(&role)
            .map(|agents| {
                agents.iter()
                    .filter_map(|id| entries.get(id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all active agents
    pub fn get_active_agents(&self) -> Vec<AgentIndexEntry> {
        self.entries.read().unwrap().values()
            .filter(|e| e.status == AgentStatus::Active)
            .cloned()
            .collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> IndexStats {
        let entries = self.entries.read().unwrap();
        
        IndexStats {
            total_agents: entries.len(),
            active_agents: entries.values().filter(|e| e.status == AgentStatus::Active).count(),
            busy_agents: entries.values().filter(|e| e.status == AgentStatus::Busy).count(),
            offline_agents: entries.values().filter(|e| e.status == AgentStatus::Offline).count(),
            total_capabilities: self.capability_index.read().unwrap().len(),
            total_cells: self.cell_index.read().unwrap().len(),
        }
    }

    /// Clean up stale entries
    pub fn cleanup_stale(&self, max_age_seconds: i64) -> Vec<String> {
        let now = chrono::Utc::now().timestamp_millis();
        let max_age_ms = max_age_seconds * 1000;
        
        let stale: Vec<String> = self.entries.read().unwrap()
            .values()
            .filter(|e| now - e.last_heartbeat > max_age_ms)
            .map(|e| e.agent_id.clone())
            .collect();
        
        for agent_id in &stale {
            let _ = self.update_status(agent_id, AgentStatus::Offline, None);
        }
        
        stale
    }
}

#[derive(Debug, Clone)]
pub struct IndexStats {
    pub total_agents: usize,
    pub active_agents: usize,
    pub busy_agents: usize,
    pub offline_agents: usize,
    pub total_capabilities: usize,
    pub total_cells: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_agent(id: &str, caps: Vec<&str>) -> AgentIndexEntry {
        AgentIndexEntry {
            agent_id: id.to_string(),
            cell_id: "cell-1".to_string(),
            capabilities: caps.into_iter().map(|c| Capability {
                name: c.to_string(),
                version: "1.0".to_string(),
                confidence: 0.9,
            }).collect(),
            role: AgentRole::Worker,
            status: AgentStatus::Active,
            load_score: 0.5,
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_registration() {
        let index = AgentIndexIntegration::new();
        
        let agent = create_test_agent("agent-1", vec!["compute", "storage"]);
        index.register(agent).unwrap();
        
        let stats = index.get_stats();
        assert_eq!(stats.total_agents, 1);
    }

    #[test]
    fn test_capability_query() {
        let index = AgentIndexIntegration::new();
        
        index.register(create_test_agent("agent-1", vec!["compute", "storage"])).unwrap();
        index.register(create_test_agent("agent-2", vec!["compute", "network"])).unwrap();
        index.register(create_test_agent("agent-3", vec!["storage"])).unwrap();
        
        let query = AgentQuery {
            required_capabilities: vec!["compute".to_string()],
            preferred_cell: None,
            max_load: 1.0,
            role: None,
            exclude_offline: true,
        };
        
        let result = index.find_agents(&query, SelectionStrategy::LeastLoaded);
        assert_eq!(result.total_matched, 2); // agent-1 and agent-2
    }

    #[test]
    fn test_find_agent_for_capability() {
        let index = AgentIndexIntegration::new();
        
        index.register(create_test_agent("agent-1", vec!["compute"])).unwrap();
        index.register(create_test_agent("agent-2", vec!["storage"])).unwrap();
        
        let agent = index.find_agent_for_capability("compute", SelectionStrategy::LeastLoaded);
        assert!(agent.is_some());
        assert_eq!(agent.unwrap().agent_id, "agent-1");
    }

    #[test]
    fn test_sticky_session() {
        let index = AgentIndexIntegration::new();
        
        index.register(create_test_agent("agent-1", vec!["compute"])).unwrap();
        
        let agent1 = index.get_sticky_agent("session-1", "compute");
        assert!(agent1.is_some());
        
        // Same session should return same agent
        let agent2 = index.get_sticky_agent("session-1", "compute");
        assert_eq!(agent1.unwrap().agent_id, agent2.unwrap().agent_id);
    }

    #[test]
    fn test_least_loaded_selection() {
        let index = AgentIndexIntegration::new();
        
        let mut a1 = create_test_agent("agent-1", vec!["compute"]);
        a1.load_score = 0.9;
        let mut a2 = create_test_agent("agent-2", vec!["compute"]);
        a2.load_score = 0.3;
        
        index.register(a1).unwrap();
        index.register(a2).unwrap();
        
        let query = AgentQuery {
            required_capabilities: vec!["compute".to_string()],
            preferred_cell: None,
            max_load: 1.0,
            role: None,
            exclude_offline: true,
        };
        
        let result = index.find_agents(&query, SelectionStrategy::LeastLoaded);
        assert_eq!(result.agents[0].agent_id, "agent-2"); // Least loaded first
    }
}
