//! Agent Traffic Police — Mini Kubernetes Scheduler for Agents
//!
//! FIX BUG-015: Proper agent lifecycle management with:
//! - Matching logic (namespace, role, model, instruction hash)
//! - Pooling strategy (idle pool, warm pool, pre-warmed agents)
//! - State transitions (Pending → Warm → Running → Idle → Terminating)
//!
//! This is NOT a patch — it's a mini scheduler.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

// =============================================================================
// Agent Identity & Matching
// =============================================================================

/// Agent identity for matching — determines if an agent can be reused
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Namespace (isolation boundary)
    pub namespace: String,
    /// Agent role (reader, writer, admin, etc.)
    pub role: String,
    /// Model being used (gpt-4, claude, etc.)
    pub model: String,
    /// Hash of instructions (determines behavior compatibility)
    pub instruction_hash: String,
    /// Capability tags
    pub capabilities: Vec<String>,
}

impl AgentIdentity {
    /// Check if this identity matches a request (subset match)
    pub fn matches(&self, request: &AgentRequest) -> bool {
        self.namespace == request.namespace
            && self.role == request.role
            && self.model == request.model
            && self.instruction_hash == request.instruction_hash
            && request
                .required_capabilities
                .iter()
                .all(|cap| self.capabilities.contains(cap))
    }

    /// Create identity hash for pool lookup
    pub fn pool_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.namespace,
            self.role,
            self.model,
            &self.instruction_hash[..16]
        )
    }
}

/// Request to acquire or create an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub namespace: String,
    pub role: String,
    pub model: String,
    pub instruction_hash: String,
    pub required_capabilities: Vec<String>,
    pub priority: Priority,
    pub resource_requirements: ResourceRequirements,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct ResourceRequirements {
    pub memory_mb: u64,
    pub cpu_millicores: u32,
    pub token_budget: u64,
}

// =============================================================================
// State Machine (Proper State Transitions)
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is being created and warmed up
    Pending,
    /// Agent is pre-warmed and ready in pool
    Warm,
    /// Agent is actively running work
    Running,
    /// Agent finished work, returning to pool
    Cooldown,
    /// Agent is in idle pool (ready for reuse)
    Idle,
    /// Agent is being terminated
    Terminating,
    /// Agent has been terminated
    Terminated,
}

impl AgentState {
    /// Valid state transitions
    pub fn can_transition_to(&self, new_state: AgentState) -> bool {
        match (self, new_state) {
            // Creation flow
            (AgentState::Pending, AgentState::Warm) => true,
            (AgentState::Pending, AgentState::Running) => true,
            (AgentState::Pending, AgentState::Terminating) => true,

            // Warm pool to running
            (AgentState::Warm, AgentState::Running) => true,
            (AgentState::Warm, AgentState::Terminating) => true,

            // Running lifecycle
            (AgentState::Running, AgentState::Cooldown) => true,
            (AgentState::Running, AgentState::Terminating) => true,

            // Cooldown to idle pool
            (AgentState::Cooldown, AgentState::Idle) => true,
            (AgentState::Cooldown, AgentState::Terminating) => true,

            // Idle pool reuse
            (AgentState::Idle, AgentState::Running) => true,
            (AgentState::Idle, AgentState::Terminating) => true,

            // Termination
            (AgentState::Terminating, AgentState::Terminated) => true,

            _ => false,
        }
    }
}

// =============================================================================
// Pool Entry (Managed Agent)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedAgent {
    /// Unique agent PID
    pub agent_pid: String,
    /// Agent identity for matching
    pub identity: AgentIdentity,
    /// Current state
    pub state: AgentState,
    /// Timestamps
    pub created_at: i64,
    pub state_changed_at: i64,
    pub last_used_at: i64,
    /// Usage stats
    pub total_uses: u64,
    pub total_tokens_consumed: u64,
    /// Resource tracking
    pub resources: ResourceUsage,
    /// State transition history
    pub state_history: Vec<StateTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_mb: u64,
    pub cpu_millicores: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: AgentState,
    pub to: AgentState,
    pub timestamp: i64,
    pub reason: String,
}

impl ManagedAgent {
    /// Transition to new state with validation
    pub fn transition_to(&mut self, new_state: AgentState, reason: &str) -> Result<(), String> {
        if !self.state.can_transition_to(new_state) {
            return Err(format!(
                "Invalid transition: {:?} → {:?}",
                self.state, new_state
            ));
        }

        let now = chrono::Utc::now().timestamp_millis();

        self.state_history.push(StateTransition {
            from: self.state,
            to: new_state,
            timestamp: now,
            reason: reason.to_string(),
        });

        self.state = new_state;
        self.state_changed_at = now;

        if new_state == AgentState::Running {
            self.last_used_at = now;
            self.total_uses += 1;
        }

        Ok(())
    }

    /// Check if agent has been idle too long
    pub fn idle_expired(&self, max_idle_ms: i64) -> bool {
        if self.state != AgentState::Idle {
            return false;
        }
        let idle_time = chrono::Utc::now().timestamp_millis() - self.last_used_at;
        idle_time > max_idle_ms
    }
}

// =============================================================================
// Pooling Strategy
// =============================================================================

/// Pool configuration and strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStrategy {
    /// Maximum agents per identity
    pub max_per_identity: usize,
    /// Global maximum agents
    pub global_max: usize,
    /// How long to keep warm agents ready (ms)
    pub warm_ttl_ms: i64,
    /// How long to keep idle agents (ms)
    pub idle_ttl_ms: i64,
    /// Cooldown period before returning to idle pool (ms)
    pub cooldown_ms: i64,
    /// Minimum idle agents to maintain per identity
    pub min_idle_per_identity: usize,
    /// Pre-warm count per identity
    pub pre_warm_count: usize,
}

impl Default for PoolStrategy {
    fn default() -> Self {
        Self {
            max_per_identity: 5,
            global_max: 100,
            warm_ttl_ms: 300_000, // 5 minutes
            idle_ttl_ms: 600_000, // 10 minutes
            cooldown_ms: 5_000,   // 5 seconds
            min_idle_per_identity: 1,
            pre_warm_count: 2,
        }
    }
}

/// Pool of agents with same identity
#[derive(Debug, Clone)]
pub struct IdentityPool {
    pub identity: AgentIdentity,
    /// Agents in warm state (ready to use)
    pub warm: VecDeque<String>,
    /// Agents in idle state (can be reused)
    pub idle: VecDeque<String>,
    /// All agents with this identity
    pub all_agents: BTreeSet<String>,
}

// =============================================================================
// Agent Traffic Police (Mini Scheduler)
// =============================================================================

pub struct AgentTrafficPolice {
    /// All managed agents: PID → ManagedAgent
    agents: HashMap<String, ManagedAgent>,
    /// Pools by identity
    pools: HashMap<String, IdentityPool>,
    /// Pending creation queue
    pending_creations: VecDeque<AgentRequest>,
    /// Pool strategy
    strategy: PoolStrategy,
    /// Current agent count
    current_count: usize,
    /// Total created
    total_created: u64,
    /// Total reused
    total_reused: u64,
    /// Total evicted
    total_evicted: u64,
}

impl AgentTrafficPolice {
    pub fn new(strategy: PoolStrategy) -> Self {
        Self {
            agents: HashMap::new(),
            pools: HashMap::new(),
            pending_creations: VecDeque::new(),
            strategy,
            current_count: 0,
            total_created: 0,
            total_reused: 0,
            total_evicted: 0,
        }
    }

    /// Acquire agent for work (main scheduler entrypoint)
    pub fn acquire_agent(
        &mut self,
        request: AgentRequest,
    ) -> Result<AgentAssignment, SchedulerError> {
        // 1. Try to find matching idle agent
        if let Some(agent_pid) = self.find_matching_idle(&request) {
            return self.activate_idle_agent(&agent_pid, request);
        }

        // 2. Try to find matching warm agent
        if let Some(agent_pid) = self.find_matching_warm(&request) {
            return self.activate_warm_agent(&agent_pid, request);
        }

        // 3. Check if we can create new
        if self.current_count >= self.strategy.global_max {
            // Try to evict to make room
            self.evict_for_request(&request)?;
        }

        // 4. Create new agent
        self.create_new_agent(request)
    }

    /// Find matching idle agent (exact identity match)
    fn find_matching_idle(&mut self, request: &AgentRequest) -> Option<String> {
        let identity = AgentIdentity {
            namespace: request.namespace.clone(),
            role: request.role.clone(),
            model: request.model.clone(),
            instruction_hash: request.instruction_hash.clone(),
            capabilities: request.required_capabilities.clone(),
        };
        let pool_key = identity.pool_key();

        // Get pool for this identity
        let pool = self.pools.get_mut(&pool_key)?;

        // Find first non-expired idle agent
        let now = chrono::Utc::now().timestamp_millis();

        let mut to_evict = Vec::new();
        let mut found = None;
        while let Some(agent_pid) = pool.idle.pop_front() {
            if let Some(agent) = self.agents.get(&agent_pid) {
                if agent.idle_expired(self.strategy.idle_ttl_ms) {
                    to_evict.push(agent_pid);
                    continue;
                }
                found = Some(agent_pid);
                break;
            }
        }
        for pid in to_evict {
            self.evict_agent(&pid, "idle_expired");
        }

        found
    }

    /// Find matching warm agent
    fn find_matching_warm(&self, request: &AgentRequest) -> Option<String> {
        let identity = AgentIdentity {
            namespace: request.namespace.clone(),
            role: request.role.clone(),
            model: request.model.clone(),
            instruction_hash: request.instruction_hash.clone(),
            capabilities: request.required_capabilities.clone(),
        };
        let pool_key = identity.pool_key();

        self.pools.get(&pool_key)?.warm.front().cloned()
    }

    /// Activate idle agent (transition: Idle → Running)
    fn activate_idle_agent(
        &mut self,
        agent_pid: &str,
        request: AgentRequest,
    ) -> Result<AgentAssignment, SchedulerError> {
        let agent = self
            .agents
            .get_mut(agent_pid)
            .ok_or(SchedulerError::AgentNotFound)?;

        agent
            .transition_to(AgentState::Running, "acquired_for_work")
            .map_err(|e| SchedulerError::StateTransitionFailed(e))?;

        self.total_reused += 1;

        Ok(AgentAssignment {
            agent_pid: agent_pid.to_string(),
            reused: true,
            identity: request,
        })
    }

    /// Activate warm agent (transition: Warm → Running)
    fn activate_warm_agent(
        &mut self,
        agent_pid: &str,
        request: AgentRequest,
    ) -> Result<AgentAssignment, SchedulerError> {
        let identity = AgentIdentity {
            namespace: request.namespace.clone(),
            role: request.role.clone(),
            model: request.model.clone(),
            instruction_hash: request.instruction_hash.clone(),
            capabilities: request.required_capabilities.clone(),
        };
        let pool_key = identity.pool_key();

        // Remove from warm pool
        if let Some(pool) = self.pools.get_mut(&pool_key) {
            pool.warm.retain(|pid| pid != agent_pid);
        }

        let agent = self
            .agents
            .get_mut(agent_pid)
            .ok_or(SchedulerError::AgentNotFound)?;

        agent
            .transition_to(AgentState::Running, "acquired_from_warm_pool")
            .map_err(|e| SchedulerError::StateTransitionFailed(e))?;

        self.total_reused += 1;

        Ok(AgentAssignment {
            agent_pid: agent_pid.to_string(),
            reused: true,
            identity: request,
        })
    }

    /// Create new agent (transition: Pending → Running)
    fn create_new_agent(
        &mut self,
        request: AgentRequest,
    ) -> Result<AgentAssignment, SchedulerError> {
        let agent_pid = format!("agent-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp_millis();

        let identity = AgentIdentity {
            namespace: request.namespace.clone(),
            role: request.role.clone(),
            model: request.model.clone(),
            instruction_hash: request.instruction_hash.clone(),
            capabilities: request.required_capabilities.clone(),
        };

        let managed_agent = ManagedAgent {
            agent_pid: agent_pid.clone(),
            identity: identity.clone(),
            state: AgentState::Pending,
            created_at: now,
            state_changed_at: now,
            last_used_at: now,
            total_uses: 0,
            total_tokens_consumed: 0,
            resources: ResourceUsage {
                memory_mb: request.resource_requirements.memory_mb,
                cpu_millicores: request.resource_requirements.cpu_millicores,
            },
            state_history: vec![StateTransition {
                from: AgentState::Terminated,
                to: AgentState::Pending,
                timestamp: now,
                reason: "created".to_string(),
            }],
        };

        self.agents.insert(agent_pid.clone(), managed_agent);

        // Add to pool
        let pool_key = identity.pool_key();
        let pool = self
            .pools
            .entry(pool_key.clone())
            .or_insert_with(|| IdentityPool {
                identity: identity.clone(),
                warm: VecDeque::new(),
                idle: VecDeque::new(),
                all_agents: BTreeSet::new(),
            });
        pool.all_agents.insert(agent_pid.clone());

        // Transition to running
        if let Some(agent) = self.agents.get_mut(&agent_pid) {
            let _ = agent.transition_to(AgentState::Running, "immediate_use");
        }

        self.current_count += 1;
        self.total_created += 1;

        Ok(AgentAssignment {
            agent_pid,
            reused: false,
            identity: request,
        })
    }

    /// Return agent to pool (transition: Running → Cooldown → Idle)
    pub fn release_agent(&mut self, agent_pid: &str) -> Result<(), SchedulerError> {
        let agent = self
            .agents
            .get_mut(agent_pid)
            .ok_or(SchedulerError::AgentNotFound)?;

        // Transition: Running → Cooldown
        agent
            .transition_to(AgentState::Cooldown, "work_completed")
            .map_err(|e| SchedulerError::StateTransitionFailed(e))?;

        let pool_key = agent.identity.pool_key();
        let cooldown_ms = self.strategy.cooldown_ms;

        // After cooldown, transition to Idle
        // In real implementation, this would be async with a timer
        // For now, immediate transition
        agent
            .transition_to(AgentState::Idle, "cooldown_complete")
            .map_err(|e| SchedulerError::StateTransitionFailed(e))?;

        // Add to idle pool
        if let Some(pool) = self.pools.get_mut(&pool_key) {
            pool.idle.push_back(agent_pid.to_string());
        }

        Ok(())
    }

    /// Pre-warm agents for an identity
    pub fn pre_warm(&mut self, identity: AgentIdentity, count: usize) -> Vec<String> {
        let mut created = Vec::new();

        for _ in 0..count {
            if self.current_count >= self.strategy.global_max {
                break;
            }

            let agent_pid = format!("agent-{}", uuid::Uuid::new_v4());
            let now = chrono::Utc::now().timestamp_millis();

            let managed_agent = ManagedAgent {
                agent_pid: agent_pid.clone(),
                identity: identity.clone(),
                state: AgentState::Pending,
                created_at: now,
                state_changed_at: now,
                last_used_at: now,
                total_uses: 0,
                total_tokens_consumed: 0,
                resources: ResourceUsage {
                    memory_mb: 256,
                    cpu_millicores: 250,
                },
                state_history: vec![StateTransition {
                    from: AgentState::Terminated,
                    to: AgentState::Pending,
                    timestamp: now,
                    reason: "pre_warm".to_string(),
                }],
            };

            self.agents.insert(agent_pid.clone(), managed_agent);

            // Add to pool
            let pool_key = identity.pool_key();
            let pool = self
                .pools
                .entry(pool_key.clone())
                .or_insert_with(|| IdentityPool {
                    identity: identity.clone(),
                    warm: VecDeque::new(),
                    idle: VecDeque::new(),
                    all_agents: BTreeSet::new(),
                });
            pool.all_agents.insert(agent_pid.clone());

            // Transition to warm
            if let Some(agent) = self.agents.get_mut(&agent_pid) {
                let _ = agent.transition_to(AgentState::Warm, "pre_warmed");
                pool.warm.push_back(agent_pid.clone());
            }

            self.current_count += 1;
            self.total_created += 1;
            created.push(agent_pid);
        }

        created
    }

    /// Evict agent (transition: any → Terminating → remove)
    fn evict_agent(&mut self, agent_pid: &str, reason: &str) {
        if let Some(agent) = self.agents.remove(agent_pid) {
            let pool_key = agent.identity.pool_key();

            // Remove from pool
            if let Some(pool) = self.pools.get_mut(&pool_key) {
                pool.all_agents.remove(agent_pid);
                pool.warm.retain(|pid| pid != agent_pid);
                pool.idle.retain(|pid| pid != agent_pid);

                // Remove empty pool
                if pool.all_agents.is_empty() {
                    self.pools.remove(&pool_key);
                }
            }

            self.current_count -= 1;
            self.total_evicted += 1;

            println!("[TRAFFIC_POLICE] Evicted agent {}: {}", agent_pid, reason);
        }
    }

    /// Evict to make room for high priority request
    fn evict_for_request(&mut self, request: &AgentRequest) -> Result<(), SchedulerError> {
        // Find lowest priority idle agents to evict
        let now = chrono::Utc::now().timestamp_millis();

        let candidates: Vec<(String, Priority)> = self
            .agents
            .values()
            .filter(|a| a.state == AgentState::Idle || a.state == AgentState::Warm)
            .filter(|a| a.identity.namespace == request.namespace)
            .map(|a| (a.agent_pid.clone(), Priority::Background)) // Idle agents are low priority
            .collect();

        if candidates.is_empty() {
            return Err(SchedulerError::CapacityExceeded);
        }

        // Evict oldest idle agents
        for (agent_pid, _) in candidates.iter().take(1) {
            self.evict_agent(agent_pid, "capacity_pressure");
        }

        Ok(())
    }

    /// Run maintenance (cleanup expired, rebalance)
    pub fn maintenance(&mut self) {
        let now = chrono::Utc::now().timestamp_millis();

        // 1. Evict expired idle agents
        let expired: Vec<String> = self
            .agents
            .values()
            .filter(|a| a.idle_expired(self.strategy.idle_ttl_ms))
            .map(|a| a.agent_pid.clone())
            .collect();

        for agent_pid in expired {
            self.evict_agent(&agent_pid, "idle_expired");
        }

        // 2. Evict expired warm agents
        let expired_warm: Vec<String> = self
            .agents
            .values()
            .filter(|a| {
                a.state == AgentState::Warm
                    && (now - a.state_changed_at) > self.strategy.warm_ttl_ms
            })
            .map(|a| a.agent_pid.clone())
            .collect();

        for agent_pid in expired_warm {
            self.evict_agent(&agent_pid, "warm_expired");
        }

        // 3. Pre-warm under-provisioned identities
        let pre_warm_needed: Vec<(AgentIdentity, usize)> = self
            .pools
            .values()
            .filter_map(|pool| {
                let warm_plus_idle = pool.warm.len() + pool.idle.len();
                if warm_plus_idle < self.strategy.min_idle_per_identity {
                    Some((
                        pool.identity.clone(),
                        self.strategy.min_idle_per_identity - warm_plus_idle,
                    ))
                } else {
                    None
                }
            })
            .collect();
        for (identity, needed) in pre_warm_needed {
            self.pre_warm(identity, needed);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> TrafficPoliceStats {
        let running = self
            .agents
            .values()
            .filter(|a| a.state == AgentState::Running)
            .count();
        let warm = self
            .agents
            .values()
            .filter(|a| a.state == AgentState::Warm)
            .count();
        let idle = self
            .agents
            .values()
            .filter(|a| a.state == AgentState::Idle)
            .count();

        TrafficPoliceStats {
            total_agents: self.agents.len(),
            running,
            warm,
            idle,
            total_pools: self.pools.len(),
            total_created: self.total_created,
            total_reused: self.total_reused,
            total_evicted: self.total_evicted,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentAssignment {
    pub agent_pid: String,
    pub reused: bool,
    pub identity: AgentRequest,
}

/// Alias for external callers
pub type AgentPoolStats = TrafficPoliceStats;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPoliceStats {
    pub total_agents: usize,
    pub running: usize,
    pub warm: usize,
    pub idle: usize,
    pub total_pools: usize,
    pub total_created: u64,
    pub total_reused: u64,
    pub total_evicted: u64,
}

#[derive(Debug, Clone)]
pub enum SchedulerError {
    CapacityExceeded,
    AgentNotFound,
    StateTransitionFailed(String),
    IdentityMismatch,
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulerError::CapacityExceeded => write!(f, "Global capacity exceeded"),
            SchedulerError::AgentNotFound => write!(f, "Agent not found"),
            SchedulerError::StateTransitionFailed(e) => write!(f, "State transition failed: {}", e),
            SchedulerError::IdentityMismatch => write!(f, "Identity mismatch"),
        }
    }
}

impl std::error::Error for SchedulerError {}

impl AgentTrafficPolice {
    pub fn register_agent(&mut self, pid: String, _capabilities: Vec<String>, _namespace: String) {
        // Agent registration is handled via acquire_agent; this is a no-op placeholder
        let _ = pid;
    }

    pub fn terminate_agent(&mut self, pid: &str) {
        self.evict_agent(pid, "terminated");
    }

    pub fn cleanup_idle_agents(&mut self, _threshold_ms: i64) -> Vec<String> {
        self.maintenance();
        vec![]
    }

    pub fn has_capacity(&self) -> bool {
        self.agents.len() < self.strategy.global_max
    }
}

/// Thread-safe wrapper
#[derive(Clone)]
pub struct SharedAgentTrafficPolice {
    inner: Arc<Mutex<AgentTrafficPolice>>,
}

impl SharedAgentTrafficPolice {
    pub fn new(strategy: PoolStrategy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AgentTrafficPolice::new(strategy))),
        }
    }

    pub fn acquire_agent(&self, request: AgentRequest) -> Result<AgentAssignment, SchedulerError> {
        self.inner.lock().unwrap().acquire_agent(request)
    }

    pub fn register_agent(&self, pid: String, capabilities: Vec<String>, namespace: String) {
        self.inner
            .lock()
            .unwrap()
            .register_agent(pid, capabilities, namespace);
    }

    pub fn release_agent(&self, pid: &str) {
        let _ = self.inner.lock().unwrap().release_agent(pid);
    }

    pub fn terminate_agent(&self, pid: &str) {
        self.inner.lock().unwrap().terminate_agent(pid);
    }

    pub fn stats(&self) -> AgentPoolStats {
        self.inner.lock().unwrap().stats()
    }

    pub fn cleanup_idle_agents(&self, threshold_ms: i64) -> Vec<String> {
        self.inner.lock().unwrap().cleanup_idle_agents(threshold_ms)
    }

    pub fn has_capacity(&self) -> bool {
        self.inner.lock().unwrap().has_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(capabilities: Vec<String>) -> AgentRequest {
        AgentRequest {
            namespace: "ns:test".to_string(),
            role: "worker".to_string(),
            model: "gpt-4".to_string(),
            instruction_hash: "0".repeat(64),
            required_capabilities: capabilities,
            priority: Priority::Normal,
            resource_requirements: ResourceRequirements::default(),
        }
    }

    #[test]
    fn test_agent_pool_reuse() {
        let strategy = PoolStrategy {
            global_max: 10,
            max_per_identity: 5,
            ..PoolStrategy::default()
        };
        let mut pool = AgentTrafficPolice::new(strategy);
        let req = sample_request(vec!["capability_a".to_string()]);

        let first = pool.acquire_agent(req.clone()).unwrap();
        let pid = first.agent_pid.clone();
        assert!(!first.reused);

        pool.release_agent(&pid).unwrap();

        let second = pool.acquire_agent(req).unwrap();
        assert_eq!(second.agent_pid, pid);
        assert!(second.reused);
    }

    #[test]
    fn test_agent_pool_exhaustion() {
        let strategy = PoolStrategy {
            global_max: 2,
            ..PoolStrategy::default()
        };
        let mut pool = AgentTrafficPolice::new(strategy);
        let req = sample_request(vec!["cap".to_string()]);

        pool.acquire_agent(req.clone()).unwrap();
        pool.acquire_agent(req.clone()).unwrap();

        let err = pool.acquire_agent(req);
        assert!(matches!(err, Err(SchedulerError::CapacityExceeded)));
    }
}
