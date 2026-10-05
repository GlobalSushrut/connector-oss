//! Agent Auto-Allocator — Capability Matching & Load Balancing
//!
//! FIX BUG-070: "Find me an agent that can do X"

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

use crate::agents::index_integration::{AgentIndexIntegration, AgentQuery, SelectionStrategy, AgentIndexEntry, AgentStatus};
use crate::agents::resource_manager::{ResourceManager, ResourceType};

// =============================================================================
// Allocation Request
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationRequest {
    pub request_id: String,
    pub task_id: String,
    pub required_capabilities: Vec<String>,
    pub resource_requirements: HashMap<ResourceType, u64>,
    pub priority: AllocationPriority,
    pub preferred_cell: Option<String>,
    pub sticky_session: Option<String>,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AllocationPriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationResult {
    pub request_id: String,
    pub success: bool,
    pub agent_id: Option<String>,
    pub reason: Option<String>,
    pub wait_time_ms: u32,
    pub selection_method: SelectionMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionMethod {
    CapabilityMatch,
    LeastLoaded,
    RoundRobin,
    StickySession,
    ResourceAvailable,
    Random,
}

// =============================================================================
// Load Balancer
// =============================================================================

pub struct LoadBalancer {
    /// Recent selections for round-robin
    round_robin_cursor: Arc<RwLock<usize>>,
    /// Agent scores (higher = better)
    agent_scores: Arc<RwLock<HashMap<String, f32>>>,
    /// Selection history
    selection_history: Arc<RwLock<VecDeque<(String, String)>>>, // (task_id, agent_id)
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self {
            round_robin_cursor: Arc::new(RwLock::new(0)),
            agent_scores: Arc::new(RwLock::new(HashMap::new())),
            selection_history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
        }
    }

    /// Score agent based on multiple factors
    pub fn score_agent(&self, agent: &AgentIndexEntry, requirements: &AllocationRequest) -> f32 {
        let mut score = 0.0;
        
        // Capability match (up to 40 points)
        let matching_caps: usize = agent.capabilities.iter()
            .filter(|c| requirements.required_capabilities.contains(&c.name))
            .count();
        score += (matching_caps as f32 / requirements.required_capabilities.len().max(1) as f32) * 40.0;
        
        // Load score (inverse, up to 30 points)
        score += (1.0 - agent.load_score) * 30.0;
        
        // Recency bonus (agents not recently used, up to 20 points)
        let recently_used = self.selection_history.read().unwrap()
            .iter()
            .filter(|(_, aid)| aid == &agent.agent_id)
            .count();
        score += (1.0 / (recently_used as f32 + 1.0)) * 20.0;
        
        // Latency/proximity (up to 10 points)
        if requirements.preferred_cell.as_ref() == Some(&agent.cell_id) {
            score += 10.0;
        }
        
        score
    }

    /// Select best agent from candidates
    pub fn select_best(&self, candidates: &[AgentIndexEntry], requirements: &AllocationRequest) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }
        
        // Score all candidates
        let mut scored: Vec<(String, f32)> = candidates.iter()
            .map(|a| (a.agent_id.clone(), self.score_agent(a, requirements)))
            .collect();
        
        // Sort by score descending
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        Some(scored[0].0.clone())
    }

    /// Record selection
    pub fn record_selection(&self, task_id: &str, agent_id: &str) {
        let mut history = self.selection_history.write().unwrap();
        history.push_back((task_id.to_string(), agent_id.to_string()));
        
        // Keep bounded
        if history.len() > 1000 {
            history.pop_front();
        }
    }
}

// =============================================================================
// Auto-Allocator
// =============================================================================

pub struct AutoAllocator {
    index: Arc<AgentIndexIntegration>,
    resource_manager: Arc<ResourceManager>,
    load_balancer: LoadBalancer,
    /// Pending requests
    pending: Arc<RwLock<VecDeque<AllocationRequest>>>,
    /// Allocation statistics
    stats: Arc<RwLock<AllocatorStats>>,
}

#[derive(Debug, Clone, Default)]
pub struct AllocatorStats {
    pub total_requests: u64,
    pub successful_allocations: u64,
    pub failed_allocations: u64,
    pub queued_requests: u64,
    pub avg_wait_time_ms: u32,
}

impl AutoAllocator {
    pub fn new(index: Arc<AgentIndexIntegration>, resource_manager: Arc<ResourceManager>) -> Self {
        Self {
            index,
            resource_manager,
            load_balancer: LoadBalancer::new(),
            pending: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(AllocatorStats::default())),
        }
    }

    /// Allocate agent for task - "Find me an agent that can do X"
    pub fn allocate(&self, request: AllocationRequest) -> AllocationResult {
        let start_time = std::time::Instant::now();
        let request_id = request.request_id.clone();
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_requests += 1;
        }
        
        // Try sticky session first
        if let Some(ref session_id) = request.sticky_session {
            if let Some(agent) = self.index.get_sticky_agent(session_id, &request.required_capabilities[0]) {
                if self.check_resources(&agent.agent_id, &request.resource_requirements) {
                    self.load_balancer.record_selection(&request.task_id, &agent.agent_id);
                    
                    return AllocationResult {
                        request_id: request_id.clone(),
                        success: true,
                        agent_id: Some(agent.agent_id),
                        reason: None,
                        wait_time_ms: start_time.elapsed().as_millis() as u32,
                        selection_method: SelectionMethod::StickySession,
                    };
                }
            }
        }
        
        // Build query
        let query = AgentQuery {
            required_capabilities: request.required_capabilities.clone(),
            preferred_cell: request.preferred_cell.clone(),
            max_load: 0.9,
            role: None,
            exclude_offline: true,
        };
        
        // Find candidates
        let result = self.index.find_agents(&query, SelectionStrategy::CapabilityScore);
        
        if result.agents.is_empty() {
            // Queue for later if critical priority
            if request.priority <= AllocationPriority::High {
                self.pending.write().unwrap().push_back(request);
            }
            
            return AllocationResult {
                request_id: request_id.clone(),
                success: false,
                agent_id: None,
                reason: Some("No agents available with required capabilities".to_string()),
                wait_time_ms: start_time.elapsed().as_millis() as u32,
                selection_method: SelectionMethod::CapabilityMatch,
            };
        }
        
        // Check resource availability for top candidates
        let mut available_candidates: Vec<AgentIndexEntry> = result.agents.into_iter()
            .filter(|a| self.check_resources(&a.agent_id, &request.resource_requirements))
            .collect();
        
        if available_candidates.is_empty() {
            return AllocationResult {
                request_id: request_id.clone(),
                success: false,
                agent_id: None,
                reason: Some("No agents with sufficient resources".to_string()),
                wait_time_ms: start_time.elapsed().as_millis() as u32,
                selection_method: SelectionMethod::ResourceAvailable,
            };
        }
        
        // Select best agent using load balancer
        let selected = self.load_balancer.select_best(&available_candidates, &request)
            .ok_or_else(|| "Selection failed".to_string());
        
        match selected {
            Ok(agent_id) => {
                // Reserve resources
                if !request.resource_requirements.is_empty() {
                    let _ = self.resource_manager.reserve(
                        agent_id.clone(),
                        request.resource_requirements.clone(),
                        crate::agents::resource_manager::ReservationPriority::Normal,
                        3600,
                    );
                }
                
                // Record selection
                self.load_balancer.record_selection(&request.task_id, &agent_id);
                
                // Update stats
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.successful_allocations += 1;
                }
                
                println!("[AUTO-ALLOCATOR] Allocated {} to task {} (method: {:?})",
                    agent_id, request.task_id, SelectionMethod::CapabilityMatch);
                
                AllocationResult {
                    request_id: request_id.clone(),
                    success: true,
                    agent_id: Some(agent_id),
                    reason: None,
                    wait_time_ms: start_time.elapsed().as_millis() as u32,
                    selection_method: SelectionMethod::CapabilityMatch,
                }
            }
            Err(_) => {
                AllocationResult {
                    request_id: request_id.clone(),
                    success: false,
                    agent_id: None,
                    reason: Some("Agent selection failed".to_string()),
                    wait_time_ms: start_time.elapsed().as_millis() as u32,
                    selection_method: SelectionMethod::CapabilityMatch,
                }
            }
        }
    }

    /// Quick allocation - convenience method for simple cases
    pub fn quick_allocate(&self, task_id: &str, capability: &str) -> Option<String> {
        let request = AllocationRequest {
            request_id: format!("req-{}", uuid::Uuid::new_v4()),
            task_id: task_id.to_string(),
            required_capabilities: vec![capability.to_string()],
            resource_requirements: HashMap::new(),
            priority: AllocationPriority::Normal,
            preferred_cell: None,
            sticky_session: None,
            timeout_ms: 5000,
        };
        
        self.allocate(request).agent_id
    }

    /// Release allocation
    pub fn release(&self, task_id: &str, agent_id: &str) {
        // Clean up reservations
        // In production: notify agent, update state
        
        println!("[AUTO-ALLOCATOR] Released {} from task {}", agent_id, task_id);
    }

    /// Process pending queue
    pub fn process_pending(&self) -> Vec<AllocationResult> {
        let mut results = Vec::new();
        let mut pending = self.pending.write().unwrap();
        
        // Process up to 10 pending requests
        for _ in 0..10 {
            if let Some(request) = pending.pop_front() {
                // Check if timed out
                if request.timeout_ms > 0 {
                    // In production: check actual timeout
                }
                
                let result = self.allocate(request);
                results.push(result);
            } else {
                break;
            }
        }
        
        results
    }

    /// Get least busy agent
    pub fn get_least_busy(&self, capability: &str) -> Option<AgentIndexEntry> {
        let query = AgentQuery {
            required_capabilities: vec![capability.to_string()],
            preferred_cell: None,
            max_load: 1.0,
            role: None,
            exclude_offline: true,
        };
        
        let result = self.index.find_agents(&query, SelectionStrategy::LeastLoaded);
        result.agents.into_iter().next()
    }

    /// Check if agent has resources available
    fn check_resources(&self, agent_id: &str, requirements: &HashMap<ResourceType, u64>) -> bool {
        let available = self.resource_manager.get_available();
        
        for (rtype, required) in requirements {
            let avail = available.get(rtype).copied().unwrap_or(0);
            if *required > avail {
                return false;
            }
        }
        
        true
    }

    /// Get allocator statistics
    pub fn get_stats(&self) -> AllocatorStats {
        let mut stats = self.stats.read().unwrap().clone();
        stats.queued_requests = self.pending.read().unwrap().len() as u64;
        stats
    }

    /// Find agents matching specific criteria
    pub fn find_matching_agents(&self, capabilities: &[String], max_results: usize) -> Vec<AgentIndexEntry> {
        let query = AgentQuery {
            required_capabilities: capabilities.to_vec(),
            preferred_cell: None,
            max_load: 0.9,
            role: None,
            exclude_offline: true,
        };
        
        let result = self.index.find_agents(&query, SelectionStrategy::CapabilityScore);
        result.agents.into_iter().take(max_results).collect()
    }

    /// Check allocation health
    pub fn health_check(&self) -> HealthStatus {
        let stats = self.stats.read().unwrap();
        let pending = self.pending.read().unwrap().len();
        
        let success_rate = if stats.total_requests > 0 {
            stats.successful_allocations as f64 / stats.total_requests as f64
        } else {
            1.0
        };
        
        HealthStatus {
            healthy: success_rate > 0.8 && pending < 100,
            success_rate,
            pending_requests: pending,
            recommendation: if success_rate < 0.5 {
                "Consider adding more agents".to_string()
            } else {
                "Healthy".to_string()
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub healthy: bool,
    pub success_rate: f64,
    pub pending_requests: usize,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::index_integration::{AgentIndexIntegration, AgentIndexEntry, Capability, AgentRole, AgentStatus};

    fn create_test_entry(id: &str, caps: Vec<&str>, load: f32) -> AgentIndexEntry {
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
            load_score: load,
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_allocation() {
        let index = Arc::new(AgentIndexIntegration::new());
        let rm = Arc::new(ResourceManager::new());
        
        let allocator = AutoAllocator::new(index.clone(), rm);
        
        // Register agents
        index.register(create_test_entry("agent-1", vec!["compute"], 0.3)).unwrap();
        index.register(create_test_entry("agent-2", vec!["compute"], 0.8)).unwrap();
        
        let request = AllocationRequest {
            request_id: "req-1".to_string(),
            task_id: "task-1".to_string(),
            required_capabilities: vec!["compute".to_string()],
            resource_requirements: HashMap::new(),
            priority: AllocationPriority::Normal,
            preferred_cell: None,
            sticky_session: None,
            timeout_ms: 5000,
        };
        
        let result = allocator.allocate(request);
        assert!(result.success);
        assert!(result.agent_id.is_some());
        // Should pick agent-1 (less loaded)
        assert_eq!(result.agent_id.unwrap(), "agent-1");
    }

    #[test]
    fn test_quick_allocate() {
        let index = Arc::new(AgentIndexIntegration::new());
        let rm = Arc::new(ResourceManager::new());
        
        let allocator = AutoAllocator::new(index.clone(), rm);
        
        index.register(create_test_entry("agent-1", vec!["storage"], 0.5)).unwrap();
        
        let agent_id = allocator.quick_allocate("task-1", "storage");
        assert!(agent_id.is_some());
    }

    #[test]
    fn test_no_matching_agents() {
        let index = Arc::new(AgentIndexIntegration::new());
        let rm = Arc::new(ResourceManager::new());
        
        let allocator = AutoAllocator::new(index.clone(), rm);
        
        let request = AllocationRequest {
            request_id: "req-1".to_string(),
            task_id: "task-1".to_string(),
            required_capabilities: vec!["nonexistent".to_string()],
            resource_requirements: HashMap::new(),
            priority: AllocationPriority::Normal,
            preferred_cell: None,
            sticky_session: None,
            timeout_ms: 5000,
        };
        
        let result = allocator.allocate(request);
        assert!(!result.success);
    }
}
