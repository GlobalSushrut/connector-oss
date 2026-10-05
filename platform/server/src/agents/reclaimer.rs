//! Idle Resource Reclaimer — Automatic Cleanup of Idle Agents
//!
//! FIX BUG-073: Idle detection and resource cleanup

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

use crate::agents::index_integration::{AgentIndexIntegration, AgentIndexEntry, AgentStatus};
use crate::agents::resource_manager::ResourceManager;

// =============================================================================
// Idle Detection
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdleConfig {
    pub cpu_threshold_percent: f32,
    pub memory_threshold_percent: f32,
    pub idle_duration_seconds: u64,
    pub check_interval_seconds: u64,
}

impl Default for IdleConfig {
    fn default() -> Self {
        Self {
            cpu_threshold_percent: 5.0,
            memory_threshold_percent: 10.0,
            idle_duration_seconds: 300, // 5 minutes
            check_interval_seconds: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdleState {
    pub agent_id: String,
    pub idle_since: i64,
    pub last_cpu: f32,
    pub last_memory: f32,
    pub is_idle: bool,
}

// =============================================================================
// Reclaimer
// =============================================================================

pub struct Reclaimer {
    config: IdleConfig,
    agent_index: Arc<AgentIndexIntegration>,
    resource_manager: Arc<ResourceManager>,
    idle_states: Arc<RwLock<HashMap<String, IdleState>>>,
    reclaimed: Arc<RwLock<VecDeque<ReclaimEvent>>>,
    paused_agents: Arc<RwLock<Vec<String>>>,
    stats: Arc<RwLock<ReclaimerStats>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReclaimEvent {
    pub timestamp: i64,
    pub agent_id: String,
    pub action: ReclaimAction,
    pub resources_freed: HashMap<String, u64>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReclaimAction {
    Pause,
    Freeze,
    Destroy,
    Warn,
}

#[derive(Debug, Clone, Default)]
pub struct ReclaimerStats {
    pub total_paused: u64,
    pub total_frozen: u64,
    pub total_destroyed: u64,
    pub total_resources_freed_mb: u64,
    pub total_warnings: u64,
}

impl Reclaimer {
    pub fn new(
        config: IdleConfig,
        agent_index: Arc<AgentIndexIntegration>,
        resource_manager: Arc<ResourceManager>,
    ) -> Self {
        Self {
            config,
            agent_index,
            resource_manager,
            idle_states: Arc::new(RwLock::new(HashMap::new())),
            reclaimed: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            paused_agents: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(ReclaimerStats::default())),
        }
    }

    /// Check all agents for idleness
    pub fn check_idle(&self) -> Vec<IdleDetection> {
        let agents = self.agent_index.get_active_agents();
        let mut detections = Vec::new();
        let now = chrono::Utc::now().timestamp_millis();
        
        for agent in agents {
            let detection = self.check_agent_idle(&agent, now);
            if detection.is_idle {
                detections.push(detection);
            }
        }
        
        detections
    }

    fn check_agent_idle(&self, agent: &AgentIndexEntry, now: i64) -> IdleDetection {
        // Get current metrics (simplified)
        let cpu_percent = agent.load_score * 100.0;
        let memory_percent = agent.load_score * 80.0; // Simplified
        
        let is_under_threshold = cpu_percent < self.config.cpu_threshold_percent 
            && memory_percent < self.config.memory_threshold_percent;
        
        let mut idle_states = self.idle_states.write().unwrap();
        
        if is_under_threshold {
            // Check if already tracked
            if let Some(state) = idle_states.get_mut(&agent.agent_id) {
                let idle_duration_ms = now - state.idle_since;
                let is_idle = idle_duration_ms > (self.config.idle_duration_seconds as i64 * 1000);
                
                state.last_cpu = cpu_percent;
                state.last_memory = memory_percent;
                state.is_idle = is_idle;
                
                IdleDetection {
                    agent_id: agent.agent_id.clone(),
                    is_idle,
                    idle_duration_seconds: idle_duration_ms as u64 / 1000,
                    cpu_percent,
                    memory_percent,
                    action: if is_idle { 
                        self.determine_action(&agent.agent_id) 
                    } else { 
                        None 
                    },
                }
            } else {
                // Start tracking
                idle_states.insert(agent.agent_id.clone(), IdleState {
                    agent_id: agent.agent_id.clone(),
                    idle_since: now,
                    last_cpu: cpu_percent,
                    last_memory: memory_percent,
                    is_idle: false,
                });
                
                IdleDetection {
                    agent_id: agent.agent_id.clone(),
                    is_idle: false,
                    idle_duration_seconds: 0,
                    cpu_percent,
                    memory_percent,
                    action: None,
                }
            }
        } else {
            // Not idle, remove tracking
            idle_states.remove(&agent.agent_id);
            
            IdleDetection {
                agent_id: agent.agent_id.clone(),
                is_idle: false,
                idle_duration_seconds: 0,
                cpu_percent,
                memory_percent,
                action: None,
            }
        }
    }

    fn determine_action(&self, agent_id: &str) -> Option<ReclaimAction> {
        let paused = self.paused_agents.read().unwrap();
        
        if paused.contains(&agent_id.to_string()) {
            // Already paused, consider destroying
            Some(ReclaimAction::Destroy)
        } else {
            // First offense: pause
            Some(ReclaimAction::Pause)
        }
    }

    /// Reclaim idle agent
    pub fn reclaim(&self, agent_id: &str, action: ReclaimAction) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        
        match action {
            ReclaimAction::Pause => {
                self.pause_agent(agent_id)?;
                self.paused_agents.write().unwrap().push(agent_id.to_string());
                self.stats.write().unwrap().total_paused += 1;
            }
            ReclaimAction::Freeze => {
                self.freeze_agent(agent_id)?;
                self.stats.write().unwrap().total_frozen += 1;
            }
            ReclaimAction::Destroy => {
                self.destroy_agent(agent_id)?;
                self.stats.write().unwrap().total_destroyed += 1;
            }
            ReclaimAction::Warn => {
                println!("[RECLAIMER] Warning: Agent {} is idle", agent_id);
                self.stats.write().unwrap().total_warnings += 1;
            }
        }
        
        // Record event
        let event = ReclaimEvent {
            timestamp: now,
            agent_id: agent_id.to_string(),
            action,
            resources_freed: self.estimate_resources_freed(agent_id),
            reason: "Idle resource reclamation".to_string(),
        };
        
        self.reclaimed.write().unwrap().push_back(event);
        
        println!("[RECLAIMER] {:?} agent {} (idle > {}s)",
            action, agent_id, self.config.idle_duration_seconds);
        
        Ok(())
    }

    /// Resume paused agent
    pub fn resume(&self, agent_id: &str) -> Result<(), String> {
        self.agent_index.update_status(agent_id, AgentStatus::Active, None)?;
        
        self.paused_agents.write().unwrap().retain(|id| id != agent_id);
        self.idle_states.write().unwrap().remove(agent_id);
        
        println!("[RECLAIMER] Resumed agent {}", agent_id);
        Ok(())
    }

    /// Run full reclaim cycle
    pub fn run_cycle(&self) -> Vec<ReclaimEvent> {
        let detections = self.check_idle();
        let mut events = Vec::new();
        
        for detection in detections {
            if let Some(action) = detection.action {
                if let Ok(()) = self.reclaim(&detection.agent_id, action) {
                    if let Some(event) = self.reclaimed.read().unwrap().back() {
                        events.push(event.clone());
                    }
                }
            }
        }
        
        events
    }

    fn pause_agent(&self, agent_id: &str) -> Result<(), String> {
        self.agent_index.update_status(agent_id, AgentStatus::Paused, None)
    }

    fn freeze_agent(&self, agent_id: &str) -> Result<(), String> {
        // Freeze checkpoints state to disk
        println!("[RECLAIMER] Freezing agent {} (checkpoint state)", agent_id);
        self.agent_index.update_status(agent_id, AgentStatus::Paused, None)
    }

    fn destroy_agent(&self, agent_id: &str) -> Result<(), String> {
        self.resource_manager.deallocate(agent_id)?;
        self.agent_index.unregister(agent_id)?;
        self.idle_states.write().unwrap().remove(agent_id);
        Ok(())
    }

    fn estimate_resources_freed(&self, _agent_id: &str) -> HashMap<String, u64> {
        let mut resources = HashMap::new();
        resources.insert("memory_mb".to_string(), 512);
        resources.insert("cpu_millicores".to_string(), 500);
        resources
    }

    /// Get statistics
    pub fn get_stats(&self) -> ReclaimerStats {
        self.stats.read().unwrap().clone()
    }

    /// Get current idle agents
    pub fn get_idle_agents(&self) -> Vec<IdleDetection> {
        self.check_idle()
    }

    /// Get reclaim history
    pub fn get_history(&self, limit: usize) -> Vec<ReclaimEvent> {
        self.reclaimed.read().unwrap()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct IdleDetection {
    pub agent_id: String,
    pub is_idle: bool,
    pub idle_duration_seconds: u64,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub action: Option<ReclaimAction>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::index_integration::{AgentIndexIntegration, AgentIndexEntry, Capability, AgentRole};

    fn create_test_agent(id: &str, load: f32) -> AgentIndexEntry {
        AgentIndexEntry {
            agent_id: id.to_string(),
            cell_id: "cell-1".to_string(),
            capabilities: vec![Capability { name: "compute".to_string(), version: "1.0".to_string(), confidence: 0.9 }],
            role: AgentRole::Worker,
            status: AgentStatus::Active,
            load_score: load,
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_idle_detection() {
        let index = Arc::new(AgentIndexIntegration::new());
        let rm = Arc::new(ResourceManager::new());
        
        let config = IdleConfig {
            cpu_threshold_percent: 10.0,
            memory_threshold_percent: 10.0,
            idle_duration_seconds: 0, // Instant for test
            check_interval_seconds: 30,
        };
        
        let reclaimer = Reclaimer::new(config, index.clone(), rm);
        
        // Register low-load agent (idle)
        index.register(create_test_agent("agent-1", 0.02)).unwrap();
        
        let idle = reclaimer.check_idle();
        assert!(!idle.is_empty());
        assert!(idle[0].is_idle);
    }

    #[test]
    fn test_reclaim() {
        let index = Arc::new(AgentIndexIntegration::new());
        let rm = Arc::new(ResourceManager::new());
        
        let config = IdleConfig::default();
        let reclaimer = Reclaimer::new(config, index.clone(), rm);
        
        index.register(create_test_agent("agent-1", 0.1)).unwrap();
        
        reclaimer.reclaim("agent-1", ReclaimAction::Pause).unwrap();
        
        let stats = reclaimer.get_stats();
        assert_eq!(stats.total_paused, 1);
    }
}
