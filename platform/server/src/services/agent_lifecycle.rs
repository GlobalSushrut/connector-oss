//! Agent Lifecycle Manager — Hard Enforcement & Tree Structure
//!
//! **Deprecated as source of truth.** Kernel progeny in `substrate/agent_progeny.rs` is the
//! authoritative parent/child tree (`parent_pid` / `child_pids` on VAC ACBs). This module's
//! in-memory `AgentRegistry` is not wired to `PlatformState` and must not be used for
//! enforcement or API responses until bridged or removed.
//!
//! Provides:
//! - Hard agent caps (cannot be exceeded under any circumstances)
//! - Agent tree (parent-child relationships)
//! - Auto-destruction (TTL-based cleanup)
//! - Replication (controlled cloning)
//! - Lifecycle scheduler (creation → active → idle → destruction)
//!
//! This is the HARD enforcement layer — no exceptions, no bypasses.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};
use std::time::{Duration, Instant};

// =============================================================================
// Hard Limits (Cannot be exceeded)
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HardAgentCaps {
    /// Global maximum agents (system-wide)
    pub global_max: u64,
    /// Maximum per namespace
    pub per_namespace_max: u64,
    /// Maximum depth of agent tree
    pub max_tree_depth: u32,
    /// Maximum children per agent
    pub max_children_per_agent: u32,
    /// Maximum agent lifetime (seconds)
    pub max_lifetime_seconds: u64,
    /// Maximum idle time before destruction (seconds)
    pub max_idle_seconds: u64,
}

impl Default for HardAgentCaps {
    fn default() -> Self {
        Self {
            global_max: 1000,
            per_namespace_max: 100,
            max_tree_depth: 10,
            max_children_per_agent: 20,
            max_lifetime_seconds: 86400, // 24 hours
            max_idle_seconds: 3600,      // 1 hour
        }
    }
}

// =============================================================================
// Agent States (Strict Lifecycle)
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentLifecycleState {
    /// Requested but not yet approved
    Pending,
    /// Creating resources
    Creating,
    /// Active and processing work
    Active,
    /// Idle but ready for work
    Idle,
    /// Paused (no new work)
    Paused,
    /// Marked for destruction
    Destroying,
    /// Destroyed (terminal state)
    Destroyed,
    /// Replicating (creating clone)
    Replicating,
}

impl AgentLifecycleState {
    /// Valid transitions (strict state machine)
    pub fn can_transition_to(&self, new_state: AgentLifecycleState) -> bool {
        match (self, new_state) {
            // Creation flow
            (AgentLifecycleState::Pending, AgentLifecycleState::Creating) => true,
            (AgentLifecycleState::Pending, AgentLifecycleState::Destroyed) => true, // Rejected
            (AgentLifecycleState::Creating, AgentLifecycleState::Active) => true,
            (AgentLifecycleState::Creating, AgentLifecycleState::Destroyed) => true, // Failed creation

            // Active lifecycle
            (AgentLifecycleState::Active, AgentLifecycleState::Idle) => true,
            (AgentLifecycleState::Active, AgentLifecycleState::Paused) => true,
            (AgentLifecycleState::Active, AgentLifecycleState::Destroying) => true,
            (AgentLifecycleState::Active, AgentLifecycleState::Replicating) => true,

            // Idle lifecycle
            (AgentLifecycleState::Idle, AgentLifecycleState::Active) => true,
            (AgentLifecycleState::Idle, AgentLifecycleState::Paused) => true,
            (AgentLifecycleState::Idle, AgentLifecycleState::Destroying) => true,

            // Paused lifecycle
            (AgentLifecycleState::Paused, AgentLifecycleState::Active) => true,
            (AgentLifecycleState::Paused, AgentLifecycleState::Destroying) => true,

            // Replication
            (AgentLifecycleState::Replicating, AgentLifecycleState::Active) => true,
            (AgentLifecycleState::Replicating, AgentLifecycleState::Destroying) => true,

            // Destruction (terminal)
            (AgentLifecycleState::Destroying, AgentLifecycleState::Destroyed) => true,

            _ => false,
        }
    }

    /// Is this a terminal state?
    pub fn is_terminal(&self) -> bool {
        matches!(self, AgentLifecycleState::Destroyed)
    }

    /// Does this state count against caps?
    pub fn counts_toward_cap(&self) -> bool {
        !matches!(
            self,
            AgentLifecycleState::Destroyed | AgentLifecycleState::Pending
        )
    }
}

// =============================================================================
// Agent Node (Tree Structure)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNode {
    /// Unique agent ID
    pub agent_pid: String,
    /// Parent agent (None for root)
    pub parent: Option<String>,
    /// Children (cloned/replicated agents)
    pub children: Vec<String>,
    /// Namespace
    pub namespace: String,
    /// Current state
    pub state: AgentLifecycleState,
    /// Hard caps applied to this agent
    pub caps: HardAgentCaps,
    /// Timestamps
    pub created_at: i64,
    pub expires_at: i64, // Hard deadline
    pub last_active_at: i64,
    pub state_changed_at: i64,
    /// Resource usage
    pub resources: AgentResources,
    /// Replication info
    pub replication: ReplicationInfo,
    /// State transition history
    pub state_history: Vec<StateTransition>,
    /// Reason for destruction (if destroyed)
    pub destruction_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct AgentResources {
    pub memory_mb: u64,
    pub cpu_percent: f32,
    pub tokens_consumed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplicationInfo {
    pub is_clone: bool,
    pub original_agent: Option<String>,
    pub generation: u32, // Clone of clone = generation 2
    pub max_replications: u32,
    pub replication_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: AgentLifecycleState,
    pub to: AgentLifecycleState,
    pub timestamp: i64,
    pub reason: String,
}

impl AgentNode {
    /// Calculate tree depth
    pub fn get_depth(&self, registry: &AgentRegistry) -> u32 {
        let mut depth = 0;
        let mut current = self.parent.clone();

        while let Some(parent_id) = current {
            depth += 1;
            if depth > 100 {
                return 100; // Break infinite loops
            }
            current = registry
                .agents
                .get(&parent_id)
                .and_then(|a| a.parent.clone());
        }

        depth
    }

    /// Check if this agent can have more children
    pub fn can_add_child(&self, caps: &HardAgentCaps) -> bool {
        self.children.len() < caps.max_children_per_agent as usize
    }

    /// Check if agent has expired
    pub fn is_expired(&self, now: i64) -> bool {
        now > self.expires_at
    }

    /// Check if agent has been idle too long
    pub fn is_idle_expired(&self, now: i64, caps: &HardAgentCaps) -> bool {
        let idle_time = now - self.last_active_at;
        idle_time > (caps.max_idle_seconds as i64 * 1000)
    }
}

// =============================================================================
// Agent Registry (Hard Enforcement)
// =============================================================================

pub struct AgentRegistry {
    /// All agents
    agents: HashMap<String, AgentNode>,
    /// Global count (atomic for thread safety)
    global_count: AtomicU64,
    /// Per-namespace counts
    namespace_counts: HashMap<String, u64>,
    /// Root agents (no parent)
    roots: HashSet<String>,
    /// Pending destruction queue
    destruction_queue: VecDeque<String>,
    /// Hard caps (enforced)
    hard_caps: HardAgentCaps,
    /// Creation denials (for monitoring)
    denial_log: Vec<DenialRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenialRecord {
    pub timestamp: i64,
    pub requested_namespace: String,
    pub requested_parent: Option<String>,
    pub reason: DenialReason,
    pub current_global_count: u64,
    pub namespace_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DenialReason {
    GlobalCapExceeded,
    NamespaceCapExceeded,
    TreeDepthExceeded,
    ParentChildrenCapExceeded,
    AgentNotFound,
    ParentNotActive,
    InvalidReplication,
}

impl AgentRegistry {
    pub fn new(caps: HardAgentCaps) -> Self {
        Self {
            agents: HashMap::new(),
            global_count: AtomicU64::new(0),
            namespace_counts: HashMap::new(),
            roots: HashSet::new(),
            destruction_queue: VecDeque::new(),
            hard_caps: caps,
            denial_log: Vec::new(),
        }
    }

    /// HARD CAP CHECK: Attempt to create agent
    /// Returns Ok(agent_pid) if successful, Err(reason) if cap would be exceeded
    pub fn request_agent_creation(
        &mut self,
        namespace: String,
        parent: Option<String>,
        is_replication: bool,
    ) -> Result<String, DenialReason> {
        let now = chrono::Utc::now().timestamp_millis();

        // CHECK 1: Global cap (absolute limit)
        let current_global = self.global_count.load(Ordering::SeqCst);
        if current_global >= self.hard_caps.global_max {
            self.log_denial(
                &namespace,
                parent.clone(),
                DenialReason::GlobalCapExceeded,
                current_global,
            );
            return Err(DenialReason::GlobalCapExceeded);
        }

        // CHECK 2: Namespace cap
        let ns_count = self.namespace_counts.get(&namespace).copied().unwrap_or(0);
        if ns_count >= self.hard_caps.per_namespace_max {
            self.log_denial(
                &namespace,
                parent.clone(),
                DenialReason::NamespaceCapExceeded,
                current_global,
            );
            return Err(DenialReason::NamespaceCapExceeded);
        }

        // CHECK 3: Parent validation
        if let Some(ref parent_id) = parent {
            if !self.agents.contains_key(parent_id) {
                self.log_denial(
                    &namespace,
                    Some(parent_id.clone()),
                    DenialReason::AgentNotFound,
                    current_global,
                );
                return Err(DenialReason::AgentNotFound);
            }
            let parent_agent = self.agents.get(parent_id).unwrap();

            // Parent must be active or idle (not destroying/destroyed)
            if !matches!(
                parent_agent.state,
                AgentLifecycleState::Active
                    | AgentLifecycleState::Idle
                    | AgentLifecycleState::Paused
            ) {
                self.log_denial(
                    &namespace,
                    Some(parent_id.clone()),
                    DenialReason::ParentNotActive,
                    current_global,
                );
                return Err(DenialReason::ParentNotActive);
            }

            // CHECK 4: Tree depth
            let parent_depth = parent_agent.get_depth(self);
            if parent_depth >= self.hard_caps.max_tree_depth {
                self.log_denial(
                    &namespace,
                    Some(parent_id.clone()),
                    DenialReason::TreeDepthExceeded,
                    current_global,
                );
                return Err(DenialReason::TreeDepthExceeded);
            }

            // CHECK 5: Parent children cap
            if !parent_agent.can_add_child(&self.hard_caps) {
                self.log_denial(
                    &namespace,
                    Some(parent_id.clone()),
                    DenialReason::ParentChildrenCapExceeded,
                    current_global,
                );
                return Err(DenialReason::ParentChildrenCapExceeded);
            }

            // CHECK 6: Replication limit
            if is_replication
                && parent_agent.replication.replication_count
                    >= parent_agent.replication.max_replications
            {
                self.log_denial(
                    &namespace,
                    Some(parent_id.clone()),
                    DenialReason::InvalidReplication,
                    current_global,
                );
                return Err(DenialReason::InvalidReplication);
            }
        }

        // ALL CHECKS PASSED - Grant provisional creation
        let agent_pid = format!(
            "agent-{}-{}",
            chrono::Utc::now().timestamp_millis(),
            uuid::Uuid::new_v4()
        );

        Ok(agent_pid)
    }

    /// Finalize agent creation (after provisional approval)
    pub fn finalize_agent_creation(
        &mut self,
        agent_pid: String,
        namespace: String,
        parent: Option<String>,
        is_replication: bool,
    ) -> Result<AgentNode, DenialReason> {
        let now = chrono::Utc::now().timestamp_millis();

        // Double-check caps (defense in depth)
        let current_global = self.global_count.load(Ordering::SeqCst);
        if current_global >= self.hard_caps.global_max {
            return Err(DenialReason::GlobalCapExceeded);
        }

        let ns_count = self.namespace_counts.get(&namespace).copied().unwrap_or(0);
        if ns_count >= self.hard_caps.per_namespace_max {
            return Err(DenialReason::NamespaceCapExceeded);
        }

        // Create replication info
        let replication = if let Some(ref parent_id) = parent {
            let parent_agent = self.agents.get(parent_id).unwrap();
            ReplicationInfo {
                is_clone: is_replication,
                original_agent: if is_replication {
                    Some(parent_id.clone())
                } else {
                    None
                },
                generation: parent_agent.replication.generation + 1,
                max_replications: self.hard_caps.max_children_per_agent,
                replication_count: 0,
            }
        } else {
            ReplicationInfo::default()
        };

        let node = AgentNode {
            agent_pid: agent_pid.clone(),
            parent: parent.clone(),
            children: Vec::new(),
            namespace: namespace.clone(),
            state: AgentLifecycleState::Creating,
            caps: self.hard_caps,
            created_at: now,
            expires_at: now + (self.hard_caps.max_lifetime_seconds as i64 * 1000),
            last_active_at: now,
            state_changed_at: now,
            resources: AgentResources::default(),
            replication,
            state_history: vec![StateTransition {
                from: AgentLifecycleState::Pending,
                to: AgentLifecycleState::Creating,
                timestamp: now,
                reason: if is_replication {
                    "replication".to_string()
                } else {
                    "creation".to_string()
                },
            }],
            destruction_reason: None,
        };

        // Link to parent
        if let Some(ref parent_id) = parent {
            if let Some(parent_node) = self.agents.get_mut(parent_id) {
                parent_node.children.push(agent_pid.clone());
                parent_node.replication.replication_count += 1;
            }
        } else {
            self.roots.insert(agent_pid.clone());
        }

        // Increment counts
        self.global_count.fetch_add(1, Ordering::SeqCst);
        *self.namespace_counts.entry(namespace).or_insert(0) += 1;

        self.agents.insert(agent_pid.clone(), node.clone());
        Ok(node)
    }

    /// Transition agent state (enforced)
    pub fn transition_state(
        &mut self,
        agent_pid: &str,
        new_state: AgentLifecycleState,
        reason: &str,
    ) -> Result<(), StateTransitionError> {
        let agent = self
            .agents
            .get_mut(agent_pid)
            .ok_or(StateTransitionError::AgentNotFound)?;

        if agent.state.is_terminal() {
            return Err(StateTransitionError::AlreadyDestroyed);
        }

        if !agent.state.can_transition_to(new_state) {
            return Err(StateTransitionError::InvalidTransition {
                from: agent.state,
                to: new_state,
            });
        }

        let now = chrono::Utc::now().timestamp_millis();
        let old_state = agent.state;

        agent.state = new_state;
        agent.state_changed_at = now;
        agent.last_active_at = now;

        agent.state_history.push(StateTransition {
            from: old_state,
            to: new_state,
            timestamp: now,
            reason: reason.to_string(),
        });

        // Handle special transitions
        if new_state == AgentLifecycleState::Destroying {
            self.destruction_queue.push_back(agent_pid.to_string());
        }

        // Update counts if transitioning to/from counting states
        if old_state.counts_toward_cap() && !new_state.counts_toward_cap() {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            if let Some(count) = self.namespace_counts.get_mut(&agent.namespace) {
                *count = count.saturating_sub(1);
            }
        }

        Ok(())
    }

    /// HARD DESTRUCTION: Destroy agent (irreversible)
    pub fn destroy_agent(
        &mut self,
        agent_pid: &str,
        reason: &str,
    ) -> Result<(), StateTransitionError> {
        if self
            .agents
            .get(agent_pid)
            .map(|a| a.state == AgentLifecycleState::Destroyed)
            .unwrap_or(false)
        {
            return Ok(()); // Already destroyed
        }

        // Extract needed data before more borrows
        let (children, parent_id_opt) = {
            let agent = self
                .agents
                .get(agent_pid)
                .ok_or(StateTransitionError::AgentNotFound)?;
            (agent.children.clone(), agent.parent.clone())
        };

        // Move children to orphaned state
        for child_id in children {
            let child_id_clone = child_id.clone();
            if let Some(child) = self.agents.get_mut(&child_id_clone) {
                child.parent = None;
            }
            self.roots.insert(child_id);
        }

        // Unlink from parent
        if let Some(ref parent_id) = parent_id_opt {
            if let Some(parent) = self.agents.get_mut(parent_id) {
                parent.children.retain(|c| c != agent_pid);
            }
        } else {
            self.roots.remove(agent_pid);
        }

        let now = chrono::Utc::now().timestamp_millis();
        let agent = self
            .agents
            .get_mut(agent_pid)
            .ok_or(StateTransitionError::AgentNotFound)?;
        let old_state = agent.state;

        agent.state = AgentLifecycleState::Destroyed;
        agent.destruction_reason = Some(reason.to_string());
        agent.state_changed_at = now;

        agent.state_history.push(StateTransition {
            from: old_state,
            to: AgentLifecycleState::Destroyed,
            timestamp: now,
            reason: reason.to_string(),
        });

        // Decrement counts if was counting
        if old_state.counts_toward_cap() {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            if let Some(count) = self.namespace_counts.get_mut(&agent.namespace) {
                *count = count.saturating_sub(1);
            }
        }

        // Schedule for removal from map (cleanup)
        self.destruction_queue.push_back(agent_pid.to_string());

        Ok(())
    }

    /// Auto-destruct expired agents (called by scheduler)
    pub fn auto_destruct_expired(&mut self) -> Vec<(String, String)> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut destroyed = Vec::new();

        // Find expired agents
        let expired: Vec<String> = self
            .agents
            .values()
            .filter(|a| {
                !a.state.is_terminal()
                    && (a.is_expired(now) || a.is_idle_expired(now, &self.hard_caps))
            })
            .map(|a| a.agent_pid.clone())
            .collect();

        for agent_pid in expired {
            let reason = if self
                .agents
                .get(&agent_pid)
                .map(|a| a.is_expired(now))
                .unwrap_or(false)
            {
                "lifetime_expired"
            } else {
                "idle_timeout"
            };

            if let Ok(()) = self.destroy_agent(&agent_pid, reason) {
                destroyed.push((agent_pid, reason.to_string()));
            }
        }

        destroyed
    }

    /// Cleanup destroyed agents from registry
    pub fn cleanup_destroyed(&mut self) -> usize {
        let to_remove: Vec<String> = self
            .agents
            .iter()
            .filter(|(_, a)| {
                a.state == AgentLifecycleState::Destroyed
                    && self.destruction_queue.contains(&a.agent_pid)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in &to_remove {
            self.agents.remove(id);
            self.destruction_queue.retain(|pid| pid != id);
        }

        to_remove.len()
    }

    /// Log denial for monitoring
    fn log_denial(
        &mut self,
        namespace: &str,
        parent: Option<String>,
        reason: DenialReason,
        global_count: u64,
    ) {
        let record = DenialRecord {
            timestamp: chrono::Utc::now().timestamp_millis(),
            requested_namespace: namespace.to_string(),
            requested_parent: parent,
            reason,
            current_global_count: global_count,
            namespace_count: self.namespace_counts.get(namespace).copied().unwrap_or(0),
        };

        self.denial_log.push(record);

        // Keep log manageable
        if self.denial_log.len() > 1000 {
            self.denial_log.remove(0);
        }
    }

    /// Get agent
    pub fn get_agent(&self, agent_pid: &str) -> Option<&AgentNode> {
        self.agents.get(agent_pid)
    }

    /// Get mutable agent
    pub fn get_agent_mut(&mut self, agent_pid: &str) -> Option<&mut AgentNode> {
        self.agents.get_mut(agent_pid)
    }

    /// Get current counts
    pub fn get_counts(&self) -> AgentCounts {
        AgentCounts {
            global: self.global_count.load(Ordering::SeqCst),
            per_namespace: self.namespace_counts.clone(),
            roots: self.roots.len() as u64,
            pending_destruction: self.destruction_queue.len() as u64,
            hard_caps: self.hard_caps,
        }
    }

    /// Get denial statistics
    pub fn get_denial_stats(&self) -> DenialStats {
        let total_denials = self.denial_log.len();
        let by_reason: HashMap<String, usize> =
            self.denial_log.iter().fold(HashMap::new(), |mut acc, r| {
                let key = format!("{:?}", r.reason);
                *acc.entry(key).or_insert(0) += 1;
                acc
            });

        DenialStats {
            total_denials,
            by_reason,
            last_denial: self.denial_log.last().cloned(),
        }
    }

    /// List all agents in tree structure
    pub fn list_tree(&self) -> Vec<AgentTreeView> {
        self.roots
            .iter()
            .filter_map(|root_id| self.build_tree_view(root_id, 0))
            .collect()
    }

    fn build_tree_view(&self, agent_pid: &str, depth: u32) -> Option<AgentTreeView> {
        let agent = self.agents.get(agent_pid)?;

        let children: Vec<AgentTreeView> = agent
            .children
            .iter()
            .filter_map(|child_id| self.build_tree_view(child_id, depth + 1))
            .collect();

        Some(AgentTreeView {
            agent_pid: agent_pid.to_string(),
            state: agent.state,
            namespace: agent.namespace.clone(),
            depth,
            children,
            is_expired: agent.is_expired(chrono::Utc::now().timestamp_millis()),
        })
    }

    /// Get namespace tree (agents grouped by namespace)
    pub fn get_namespace_tree(&self) -> HashMap<String, Vec<String>> {
        let mut tree: HashMap<String, Vec<String>> = HashMap::new();

        for (pid, agent) in &self.agents {
            tree.entry(agent.namespace.clone())
                .or_insert_with(Vec::new)
                .push(pid.clone());
        }

        tree
    }
}

#[derive(Debug, Clone)]
pub enum StateTransitionError {
    AgentNotFound,
    AlreadyDestroyed,
    InvalidTransition {
        from: AgentLifecycleState,
        to: AgentLifecycleState,
    },
    CapWouldBeExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCounts {
    pub global: u64,
    pub per_namespace: HashMap<String, u64>,
    pub roots: u64,
    pub pending_destruction: u64,
    pub hard_caps: HardAgentCaps,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenialStats {
    pub total_denials: usize,
    pub by_reason: HashMap<String, usize>,
    pub last_denial: Option<DenialRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTreeView {
    pub agent_pid: String,
    pub state: AgentLifecycleState,
    pub namespace: String,
    pub depth: u32,
    pub children: Vec<AgentTreeView>,
    pub is_expired: bool,
}

// =============================================================================
// Thread-safe wrapper
// =============================================================================

#[derive(Clone)]
pub struct SharedAgentRegistry {
    inner: Arc<RwLock<AgentRegistry>>,
}

impl SharedAgentRegistry {
    pub fn new(caps: HardAgentCaps) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AgentRegistry::new(caps))),
        }
    }

    pub fn request_creation(
        &self,
        ns: String,
        parent: Option<String>,
        is_rep: bool,
    ) -> Result<String, DenialReason> {
        self.inner
            .write()
            .unwrap()
            .request_agent_creation(ns, parent, is_rep)
    }

    pub fn finalize_creation(
        &self,
        pid: String,
        ns: String,
        parent: Option<String>,
        is_rep: bool,
    ) -> Result<AgentNode, DenialReason> {
        self.inner
            .write()
            .unwrap()
            .finalize_agent_creation(pid, ns, parent, is_rep)
    }

    pub fn transition_state(
        &self,
        pid: &str,
        state: AgentLifecycleState,
        reason: &str,
    ) -> Result<(), StateTransitionError> {
        self.inner
            .write()
            .unwrap()
            .transition_state(pid, state, reason)
    }

    pub fn destroy_agent(&self, pid: &str, reason: &str) -> Result<(), StateTransitionError> {
        self.inner.write().unwrap().destroy_agent(pid, reason)
    }

    pub fn auto_destruct(&self) -> Vec<(String, String)> {
        self.inner.write().unwrap().auto_destruct_expired()
    }

    pub fn cleanup(&self) -> usize {
        self.inner.write().unwrap().cleanup_destroyed()
    }

    pub fn get_agent(&self, pid: &str) -> Option<AgentNode> {
        self.inner.read().unwrap().get_agent(pid).cloned()
    }

    pub fn get_counts(&self) -> AgentCounts {
        self.inner.read().unwrap().get_counts()
    }

    pub fn get_tree(&self) -> Vec<AgentTreeView> {
        self.inner.read().unwrap().list_tree()
    }

    pub fn get_denial_stats(&self) -> DenialStats {
        self.inner.read().unwrap().get_denial_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_caps() -> HardAgentCaps {
        HardAgentCaps {
            global_max: 5,
            per_namespace_max: 3,
            max_tree_depth: 3,
            max_children_per_agent: 2,
            max_lifetime_seconds: 60,
            max_idle_seconds: 30,
        }
    }

    #[test]
    fn test_hard_global_cap() {
        let mut registry = AgentRegistry::new(test_caps());

        // Create up to cap
        for i in 0..5 {
            let pid = registry
                .request_agent_creation("ns1".to_string(), None, false)
                .unwrap();
            registry
                .finalize_agent_creation(pid, "ns1".to_string(), None, false)
                .unwrap();
        }

        // 6th should fail
        let result = registry.request_agent_creation("ns1".to_string(), None, false);
        assert!(matches!(result, Err(DenialReason::GlobalCapExceeded)));
    }

    #[test]
    fn test_namespace_cap() {
        let mut registry = AgentRegistry::new(test_caps());

        // Fill namespace 1
        for _ in 0..3 {
            let pid = registry
                .request_agent_creation("ns1".to_string(), None, false)
                .unwrap();
            registry
                .finalize_agent_creation(pid, "ns1".to_string(), None, false)
                .unwrap();
        }

        // 4th in ns1 should fail
        let result = registry.request_agent_creation("ns1".to_string(), None, false);
        assert!(matches!(result, Err(DenialReason::NamespaceCapExceeded)));

        // But ns2 should work
        let pid = registry
            .request_agent_creation("ns2".to_string(), None, false)
            .unwrap();
        registry
            .finalize_agent_creation(pid, "ns2".to_string(), None, false)
            .unwrap();
    }

    #[test]
    fn test_tree_depth_cap() {
        let mut registry = AgentRegistry::new(test_caps());

        // Create root
        let root = registry
            .request_agent_creation("ns1".to_string(), None, false)
            .unwrap();
        registry
            .finalize_agent_creation(root.clone(), "ns1".to_string(), None, false)
            .unwrap();

        // Create depth 1
        let d1 = registry
            .request_agent_creation("ns1".to_string(), Some(root.clone()), false)
            .unwrap();
        registry
            .finalize_agent_creation(d1.clone(), "ns1".to_string(), Some(root), false)
            .unwrap();

        // Create depth 2
        let d2 = registry
            .request_agent_creation("ns1".to_string(), Some(d1.clone()), false)
            .unwrap();
        registry
            .finalize_agent_creation(d2.clone(), "ns1".to_string(), Some(d1), false)
            .unwrap();

        // Depth 3 should fail (max is 3)
        let result = registry.request_agent_creation("ns1".to_string(), Some(d2), false);
        assert!(matches!(result, Err(DenialReason::TreeDepthExceeded)));
    }

    #[test]
    fn test_children_cap() {
        let mut registry = AgentRegistry::new(test_caps());

        // Create parent
        let parent = registry
            .request_agent_creation("ns1".to_string(), None, false)
            .unwrap();
        registry
            .finalize_agent_creation(parent.clone(), "ns1".to_string(), None, false)
            .unwrap();

        // Create 2 children (max is 2)
        for _ in 0..2 {
            let child = registry
                .request_agent_creation("ns1".to_string(), Some(parent.clone()), false)
                .unwrap();
            registry
                .finalize_agent_creation(child, "ns1".to_string(), Some(parent.clone()), false)
                .unwrap();
        }

        // 3rd child should fail
        let result = registry.request_agent_creation("ns1".to_string(), Some(parent), false);
        assert!(matches!(
            result,
            Err(DenialReason::ParentChildrenCapExceeded)
        ));
    }

    #[test]
    fn test_auto_destruction() {
        let mut registry = AgentRegistry::new(test_caps());

        // Create agent with very short lifetime
        let mut short_caps = test_caps();
        short_caps.max_lifetime_seconds = 0; // Already expired
        registry.hard_caps = short_caps;

        let pid = registry
            .request_agent_creation("ns1".to_string(), None, false)
            .unwrap();
        registry
            .finalize_agent_creation(pid.clone(), "ns1".to_string(), None, false)
            .unwrap();

        // Run auto-destruct
        let destroyed = registry.auto_destruct_expired();
        assert_eq!(destroyed.len(), 1);
        assert_eq!(destroyed[0].0, pid);

        // Verify destroyed
        let agent = registry.get_agent(&pid).unwrap();
        assert_eq!(agent.state, AgentLifecycleState::Destroyed);
    }

    #[test]
    fn test_state_machine_strict() {
        let mut registry = AgentRegistry::new(test_caps());

        let pid = registry
            .request_agent_creation("ns1".to_string(), None, false)
            .unwrap();
        registry
            .finalize_agent_creation(pid.clone(), "ns1".to_string(), None, false)
            .unwrap();

        // Valid: Creating → Active
        registry
            .transition_state(&pid, AgentLifecycleState::Active, "ready")
            .unwrap();

        // Valid: Active → Idle
        registry
            .transition_state(&pid, AgentLifecycleState::Idle, "no_work")
            .unwrap();

        // Invalid: Idle → Creating
        let result = registry.transition_state(&pid, AgentLifecycleState::Creating, "invalid");
        assert!(result.is_err());

        // Valid: Idle → Destroying → Destroyed
        registry
            .transition_state(&pid, AgentLifecycleState::Destroying, "cleanup")
            .unwrap();
        registry.destroy_agent(&pid, "test").unwrap();

        let agent = registry.get_agent(&pid).unwrap();
        assert_eq!(agent.state, AgentLifecycleState::Destroyed);
    }
}
