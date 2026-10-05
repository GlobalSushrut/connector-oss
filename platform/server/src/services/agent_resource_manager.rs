//! Agent Resource Manager — Fine-Grained Resource Control per Agent
//!
//! **Deprecated as HTTP SoT (U1.5).** Registration caps live in
//! `services::agents` + VAC kernel. This module is unwired from router paths.
//!
//! Manages individual agent resources to prevent crashes:
//! - Memory limits per agent
//! - CPU throttling
//! - I/O rate limiting
//! - Network quotas
//! - Resource reclamation

#![deprecated(note = "quota SoT is services::agents + VAC kernel; not wired to HTTP register")]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

// =============================================================================
// Resource Types
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory (MB)
    pub max_memory_mb: u64,
    /// Maximum CPU cores
    pub max_cpu: f32,
    /// Maximum IOPS
    pub max_iops: u32,
    /// Maximum network bandwidth (Mbps)
    pub max_network_mbps: u32,
    /// Maximum file descriptors
    pub max_fds: u32,
    /// Maximum threads
    pub max_threads: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            max_cpu: 0.5,
            max_iops: 1000,
            max_network_mbps: 100,
            max_fds: 1024,
            max_threads: 50,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Current memory usage (MB)
    pub memory_mb: u64,
    /// Current CPU usage (0.0 - 1.0 of allocated)
    pub cpu_percent: f32,
    /// Current IOPS
    pub iops: u32,
    /// Current network usage (Mbps)
    pub network_mbps: u32,
    /// Open file descriptors
    pub open_fds: u32,
    /// Active threads
    pub active_threads: u32,
    /// Last updated
    pub last_updated: i64,
}

// =============================================================================
// Agent Resource State
// =============================================================================

#[derive(Debug, Clone)]
pub struct AgentResourceState {
    pub agent_pid: String,
    pub limits: ResourceLimits,
    pub usage: ResourceUsage,
    pub throttled: bool,
    pub paused: bool,
    pub violations: u32,
    pub created_at: Instant,
    pub last_violation: Option<Instant>,
}

// =============================================================================
// Resource Manager
// =============================================================================

pub struct AgentResourceManager {
    /// Agent resource states
    agents: Arc<Mutex<HashMap<String, AgentResourceState>>>,
    /// Global memory pool (MB)
    global_memory_pool: AtomicU64,
    /// Global CPU pool (cores x 100)
    global_cpu_pool: AtomicU64,
    /// Throttling threshold (0.0 - 1.0)
    throttle_threshold: f32,
    /// Kill threshold (0.0 - 1.0)
    kill_threshold: f32,
    /// Check interval
    check_interval: Duration,
    /// Last check
    last_check: Arc<Mutex<Instant>>,
}

impl AgentResourceManager {
    pub fn new(total_memory_mb: u64, total_cpu_cores: f32) -> Self {
        println!(
            "[RESOURCE] Initializing with {} MB memory, {} CPU cores",
            total_memory_mb, total_cpu_cores
        );

        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            global_memory_pool: AtomicU64::new(total_memory_mb),
            global_cpu_pool: AtomicU64::new((total_cpu_cores * 100.0) as u64),
            throttle_threshold: 0.85,
            kill_threshold: 0.98,
            check_interval: Duration::from_secs(5),
            last_check: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Register agent with resource limits
    pub fn register_agent(
        &self,
        agent_pid: String,
        limits: ResourceLimits,
    ) -> Result<(), ResourceError> {
        // Check global pool
        let mem_needed = limits.max_memory_mb;
        let cpu_needed = (limits.max_cpu * 100.0) as u64;

        let available_mem = self.global_memory_pool.load(Ordering::Relaxed);
        let available_cpu = self.global_cpu_pool.load(Ordering::Relaxed);

        if mem_needed > available_mem {
            return Err(ResourceError::InsufficientGlobalMemory {
                needed: mem_needed,
                available: available_mem,
            });
        }

        if cpu_needed > available_cpu {
            return Err(ResourceError::InsufficientGlobalCpu {
                needed: cpu_needed as f32 / 100.0,
                available: available_cpu as f32 / 100.0,
            });
        }

        // Reserve resources
        self.global_memory_pool
            .fetch_sub(mem_needed, Ordering::Relaxed);
        self.global_cpu_pool
            .fetch_sub(cpu_needed, Ordering::Relaxed);

        // Create state
        let state = AgentResourceState {
            agent_pid: agent_pid.clone(),
            limits,
            usage: ResourceUsage {
                memory_mb: 0,
                cpu_percent: 0.0,
                iops: 0,
                network_mbps: 0,
                open_fds: 0,
                active_threads: 0,
                last_updated: chrono::Utc::now().timestamp_millis(),
            },
            throttled: false,
            paused: false,
            violations: 0,
            created_at: Instant::now(),
            last_violation: None,
        };

        self.agents.lock().unwrap().insert(agent_pid.clone(), state);

        println!(
            "[RESOURCE] Registered agent {} with limits: {} MB, {} CPU",
            agent_pid, limits.max_memory_mb, limits.max_cpu
        );

        Ok(())
    }

    /// Deregister agent and reclaim resources
    pub fn deregister_agent(&self, agent_pid: &str) -> Result<(), ResourceError> {
        let mut agents = self.agents.lock().unwrap();

        if let Some(state) = agents.remove(agent_pid) {
            // Return resources to global pool
            self.global_memory_pool
                .fetch_add(state.limits.max_memory_mb, Ordering::Relaxed);
            self.global_cpu_pool
                .fetch_add((state.limits.max_cpu * 100.0) as u64, Ordering::Relaxed);

            println!(
                "[RESOURCE] Deregistered agent {}, reclaimed {} MB",
                agent_pid, state.limits.max_memory_mb
            );
            Ok(())
        } else {
            Err(ResourceError::AgentNotFound)
        }
    }

    /// Update resource usage for agent
    pub fn update_usage(&self, agent_pid: &str, usage: ResourceUsage) -> ResourceAction {
        let mut agents = self.agents.lock().unwrap();

        if let Some(state) = agents.get_mut(agent_pid) {
            state.usage = usage;

            // Check memory limit
            let mem_ratio = usage.memory_mb as f32 / state.limits.max_memory_mb as f32;
            let cpu_ratio = usage.cpu_percent / 100.0;

            // Determine action
            if mem_ratio > self.kill_threshold || cpu_ratio > self.kill_threshold {
                state.violations += 1;
                state.last_violation = Some(Instant::now());

                if state.violations >= 3 {
                    println!("[RESOURCE] CRITICAL: Agent {} exceeded kill threshold (mem: {:.1}%, cpu: {:.1}%)",
                        agent_pid, mem_ratio * 100.0, cpu_ratio * 100.0);
                    return ResourceAction::Kill;
                }

                return ResourceAction::Throttle;
            }

            if mem_ratio > self.throttle_threshold || cpu_ratio > self.throttle_threshold {
                if !state.throttled {
                    state.throttled = true;
                    println!(
                        "[RESOURCE] Throttling agent {} (mem: {:.1}%, cpu: {:.1}%)",
                        agent_pid,
                        mem_ratio * 100.0,
                        cpu_ratio * 100.0
                    );
                }
                return ResourceAction::Throttle;
            }

            if state.throttled && mem_ratio < 0.7 && cpu_ratio < 0.7 {
                state.throttled = false;
                println!("[RESOURCE] Unthrottling agent {}", agent_pid);
                return ResourceAction::Unthrottle;
            }

            ResourceAction::None
        } else {
            ResourceAction::None
        }
    }

    /// Enforce resource limits (call periodically)
    pub fn enforce_limits(&self) -> Vec<(String, ResourceAction)> {
        let now = Instant::now();

        {
            let mut last_check = self.last_check.lock().unwrap();
            if now.duration_since(*last_check) < self.check_interval {
                return vec![];
            }
            *last_check = now;
        }

        let agents = self.agents.lock().unwrap();
        let mut actions = Vec::new();

        for (pid, state) in agents.iter() {
            // Check for violations
            let mem_ratio = state.usage.memory_mb as f32 / state.limits.max_memory_mb as f32;

            if mem_ratio > 1.0 {
                actions.push((pid.clone(), ResourceAction::Kill));
            } else if mem_ratio > self.throttle_threshold && !state.throttled {
                actions.push((pid.clone(), ResourceAction::Throttle));
            }
        }

        actions
    }

    /// Get resource stats for agent
    pub fn get_agent_stats(&self, agent_pid: &str) -> Option<AgentResourceStats> {
        let agents = self.agents.lock().unwrap();

        agents.get(agent_pid).map(|state| {
            let mem_ratio = state.usage.memory_mb as f32 / state.limits.max_memory_mb as f32;
            let cpu_ratio = state.usage.cpu_percent / 100.0;

            AgentResourceStats {
                agent_pid: agent_pid.to_string(),
                memory_used_mb: state.usage.memory_mb,
                memory_limit_mb: state.limits.max_memory_mb,
                memory_percent: mem_ratio * 100.0,
                cpu_percent: state.usage.cpu_percent,
                cpu_limit: state.limits.max_cpu,
                throttled: state.throttled,
                paused: state.paused,
                violations: state.violations,
                healthy: mem_ratio < self.throttle_threshold && cpu_ratio < self.throttle_threshold,
            }
        })
    }

    /// Get global stats
    pub fn get_global_stats(&self) -> GlobalResourceStats {
        let agents = self.agents.lock().unwrap();
        let total_memory = agents.values().map(|s| s.usage.memory_mb).sum();
        let total_cpu: f32 = agents.values().map(|s| s.usage.cpu_percent).sum();

        GlobalResourceStats {
            total_agents: agents.len(),
            active_agents: agents.values().filter(|s| !s.paused).count(),
            throttled_agents: agents.values().filter(|s| s.throttled).count(),
            total_memory_used_mb: total_memory,
            total_memory_available_mb: self.global_memory_pool.load(Ordering::Relaxed),
            total_cpu_used: total_cpu / 100.0,
            total_cpu_available: self.global_cpu_pool.load(Ordering::Relaxed) as f32 / 100.0,
        }
    }

    /// Pause agent (soft limit enforcement)
    pub fn pause_agent(&self, agent_pid: &str) -> Result<(), ResourceError> {
        let mut agents = self.agents.lock().unwrap();

        if let Some(state) = agents.get_mut(agent_pid) {
            state.paused = true;
            println!("[RESOURCE] Paused agent {}", agent_pid);
            Ok(())
        } else {
            Err(ResourceError::AgentNotFound)
        }
    }

    /// Resume agent
    pub fn resume_agent(&self, agent_pid: &str) -> Result<(), ResourceError> {
        let mut agents = self.agents.lock().unwrap();

        if let Some(state) = agents.get_mut(agent_pid) {
            state.paused = false;
            state.throttled = false;
            println!("[RESOURCE] Resumed agent {}", agent_pid);
            Ok(())
        } else {
            Err(ResourceError::AgentNotFound)
        }
    }

    /// Reclaim resources from low-priority agents
    pub fn reclaim_resources(&self, amount_mb: u64) -> Vec<String> {
        let agents = self.agents.lock().unwrap();

        // Find agents that can be paused (sorted by resource usage)
        let mut candidates: Vec<_> = agents
            .values()
            .filter(|s| !s.paused)
            .map(|s| (s.agent_pid.clone(), s.usage.memory_mb))
            .collect();

        candidates.sort_by(|a, b| b.1.cmp(&a.1)); // Highest usage first

        drop(agents);

        let mut reclaimed: Vec<String> = Vec::new();
        let mut total_reclaimed = 0u64;

        for (pid, mem) in candidates {
            if total_reclaimed >= amount_mb {
                break;
            }

            if let Ok(()) = self.pause_agent(&pid) {
                reclaimed.push(pid.clone());
                total_reclaimed += mem;
            }
        }

        if !reclaimed.is_empty() {
            println!(
                "[RESOURCE] Reclaimed {} MB from {} agents",
                total_reclaimed,
                reclaimed.len()
            );
        }

        reclaimed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceAction {
    None,
    Throttle,
    Unthrottle,
    Pause,
    Resume,
    Kill,
}

#[derive(Debug, Clone)]
pub enum ResourceError {
    AgentNotFound,
    InsufficientGlobalMemory { needed: u64, available: u64 },
    InsufficientGlobalCpu { needed: f32, available: f32 },
    LimitExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResourceStats {
    pub agent_pid: String,
    pub memory_used_mb: u64,
    pub memory_limit_mb: u64,
    pub memory_percent: f32,
    pub cpu_percent: f32,
    pub cpu_limit: f32,
    pub throttled: bool,
    pub paused: bool,
    pub violations: u32,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalResourceStats {
    pub total_agents: usize,
    pub active_agents: usize,
    pub throttled_agents: usize,
    pub total_memory_used_mb: u64,
    pub total_memory_available_mb: u64,
    pub total_cpu_used: f32,
    pub total_cpu_available: f32,
}

#[derive(Clone)]
pub struct SharedAgentResourceManager {
    inner: Arc<AgentResourceManager>,
}

impl SharedAgentResourceManager {
    pub fn new(total_memory_mb: u64, total_cpu_cores: f32) -> Self {
        Self {
            inner: Arc::new(AgentResourceManager::new(total_memory_mb, total_cpu_cores)),
        }
    }

    pub fn register_agent(&self, pid: String, limits: ResourceLimits) -> Result<(), ResourceError> {
        self.inner.register_agent(pid, limits)
    }

    pub fn deregister_agent(&self, pid: &str) -> Result<(), ResourceError> {
        self.inner.deregister_agent(pid)
    }

    pub fn update_usage(&self, pid: &str, usage: ResourceUsage) -> ResourceAction {
        self.inner.update_usage(pid, usage)
    }

    pub fn enforce_limits(&self) -> Vec<(String, ResourceAction)> {
        self.inner.enforce_limits()
    }

    pub fn get_agent_stats(&self, pid: &str) -> Option<AgentResourceStats> {
        self.inner.get_agent_stats(pid)
    }

    pub fn get_global_stats(&self) -> GlobalResourceStats {
        self.inner.get_global_stats()
    }

    pub fn reclaim_resources(&self, amount_mb: u64) -> Vec<String> {
        self.inner.reclaim_resources(amount_mb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_registration() {
        let manager = AgentResourceManager::new(8192, 8.0);

        let limits = ResourceLimits {
            max_memory_mb: 512,
            max_cpu: 1.0,
            ..Default::default()
        };

        let result = manager.register_agent("agent-1".to_string(), limits);
        assert!(result.is_ok());

        let stats = manager.get_global_stats();
        assert_eq!(stats.total_agents, 1);
    }

    #[test]
    fn test_resource_violation() {
        let manager = AgentResourceManager::new(8192, 8.0);

        let limits = ResourceLimits {
            max_memory_mb: 512,
            max_cpu: 1.0,
            ..Default::default()
        };

        manager
            .register_agent("agent-1".to_string(), limits)
            .unwrap();

        // Simulate high memory usage
        let usage = ResourceUsage {
            memory_mb: 600, // Exceeds 512 MB limit
            cpu_percent: 50.0,
            iops: 100,
            network_mbps: 10,
            open_fds: 10,
            active_threads: 5,
            last_updated: chrono::Utc::now().timestamp_millis(),
        };

        let action = manager.update_usage("agent-1", usage);
        assert_eq!(action, ResourceAction::Kill);
    }

    #[test]
    fn test_throttling() {
        let manager = AgentResourceManager::new(8192, 8.0);

        let limits = ResourceLimits {
            max_memory_mb: 512,
            max_cpu: 1.0,
            ..Default::default()
        };

        manager
            .register_agent("agent-1".to_string(), limits)
            .unwrap();

        // Simulate near-limit usage
        let usage = ResourceUsage {
            memory_mb: 450, // 88% of limit
            cpu_percent: 90.0,
            iops: 100,
            network_mbps: 10,
            open_fds: 10,
            active_threads: 5,
            last_updated: chrono::Utc::now().timestamp_millis(),
        };

        let action = manager.update_usage("agent-1", usage);
        assert_eq!(action, ResourceAction::Throttle);
    }

    #[test]
    fn test_resource_reclamation() {
        let manager = AgentResourceManager::new(8192, 8.0);

        // Register multiple agents
        for i in 0..5 {
            let limits = ResourceLimits {
                max_memory_mb: 512,
                max_cpu: 1.0,
                ..Default::default()
            };
            manager
                .register_agent(format!("agent-{}", i), limits)
                .unwrap();

            // Set usage
            let usage = ResourceUsage {
                memory_mb: 400,
                cpu_percent: 50.0,
                iops: 100,
                network_mbps: 10,
                open_fds: 10,
                active_threads: 5,
                last_updated: chrono::Utc::now().timestamp_millis(),
            };
            manager.update_usage(&format!("agent-{}", i), usage);
        }

        // Reclaim resources
        let reclaimed = manager.reclaim_resources(800);
        assert!(!reclaimed.is_empty());

        // Verify agents were paused
        for pid in &reclaimed {
            let stats = manager.get_agent_stats(pid).unwrap();
            assert!(stats.paused);
        }
    }
}
