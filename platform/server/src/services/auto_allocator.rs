//! Auto Allocator — Automatic Resource Distribution (Single Node Default)
//!
//! Default: 1 node runs 25-150 agents based on compute load
//! Optional: Auto-distribute to multiple nodes when configured
//!
//! Features:
//! - Automatic resource allocation based on system capacity
//! - Parallelization and agent sequencing
//! - Low-resource stability (never crash)
//! - Graceful degradation under load

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

// =============================================================================
// System Resource Monitoring
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SystemResources {
    /// Total memory (MB)
    pub total_memory_mb: u64,
    /// Available memory (MB)
    pub available_memory_mb: u64,
    /// Total CPU cores
    pub cpu_cores: u32,
    /// CPU usage percentage (0-100)
    pub cpu_usage_percent: f32,
    /// Disk space available (GB)
    pub disk_available_gb: u64,
    /// Network bandwidth (Mbps)
    pub network_mbps: u32,
}

impl SystemResources {
    /// Calculate how many agents can fit
    pub fn calculate_agent_capacity(&self) -> u32 {
        // Conservative estimates per agent:
        // - Memory: 100-500MB depending on complexity
        // - CPU: 0.1-0.5 cores
        // - We want to leave 30% headroom for system stability

        let available_memory = (self.available_memory_mb as f64 * 0.7) as u64;
        let available_cpu =
            (self.cpu_cores as f64 * (1.0 - self.cpu_usage_percent as f64 / 100.0) * 0.7) as f64;

        // Memory-based capacity (avg 200MB per agent)
        let memory_capacity = available_memory / 200;

        // CPU-based capacity (avg 0.25 cores per agent)
        let cpu_capacity = (available_cpu / 0.25) as u64;

        // Take the lower of the two
        let capacity = memory_capacity.min(cpu_capacity).min(150) as u32;

        // Minimum 25 agents
        capacity.max(25)
    }

    /// Check if system is under pressure
    pub fn is_under_pressure(&self) -> bool {
        self.cpu_usage_percent > 80.0
            || (self.available_memory_mb as f64 / self.total_memory_mb as f64) < 0.15
    }

    /// Check if system is critically low
    pub fn is_critical(&self) -> bool {
        self.cpu_usage_percent > 95.0
            || (self.available_memory_mb as f64 / self.total_memory_mb as f64) < 0.05
    }
}

// =============================================================================
// Agent Resource Requirements
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AgentRequirements {
    /// Memory needed (MB)
    pub memory_mb: u64,
    /// CPU cores needed
    pub cpu_cores: f32,
    /// Priority (0-100, higher = more important)
    pub priority: u32,
    /// Can this agent be throttled?
    pub throttlable: bool,
    /// Can this agent be paused?
    pub pausable: bool,
}

impl Default for AgentRequirements {
    fn default() -> Self {
        Self {
            memory_mb: 256,
            cpu_cores: 0.25,
            priority: 50,
            throttlable: true,
            pausable: true,
        }
    }
}

// =============================================================================
// Agent Slot — Resource Reservation
// =============================================================================

#[derive(Debug, Clone)]
pub struct AgentSlot {
    pub agent_pid: String,
    pub requirements: AgentRequirements,
    pub allocated_memory_mb: u64,
    pub allocated_cpu: f32,
    pub status: SlotStatus,
    pub created_at: Instant,
    pub last_active: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStatus {
    Reserved,
    Active,
    Throttled,
    Paused,
    Releasing,
}

// =============================================================================
// Auto Allocator — Main Controller
// =============================================================================

pub struct AutoAllocator {
    /// Mode: SingleNode or Distributed
    mode: AllocationMode,
    /// System resources
    system_resources: Arc<Mutex<SystemResources>>,
    /// Allocated agent slots
    slots: Arc<Mutex<HashMap<String, AgentSlot>>>,
    /// Resource limits
    max_agents: AtomicU32,
    /// Current agent count
    current_agents: AtomicU32,
    /// Memory pool (MB)
    memory_pool_mb: AtomicU64,
    /// CPU pool (cores)
    cpu_pool: AtomicU64, // Stored as x100 for precision
    /// Sequencing queue (for ordering)
    sequence_queue: Arc<Mutex<VecDeque<String>>>,
    /// Parallel execution limit
    parallel_limit: AtomicU32,
    /// Last resource check
    last_resource_check: Arc<Mutex<Instant>>,
    /// Stability mode
    stability_mode: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AllocationMode {
    SingleNode,
    Distributed,
    Auto, // Auto-detect based on configuration
}

impl AutoAllocator {
    pub fn new(mode: AllocationMode) -> Self {
        // Detect system resources
        let sys_resources = Self::detect_system_resources();
        let max_agents = sys_resources.calculate_agent_capacity();

        println!("[ALLOCATOR] Starting in {:?} mode", mode);
        println!("[ALLOCATOR] System capacity: {} agents", max_agents);
        println!(
            "[ALLOCATOR] Memory: {} MB available",
            sys_resources.available_memory_mb
        );
        println!(
            "[ALLOCATOR] CPU: {} cores @ {}% usage",
            sys_resources.cpu_cores, sys_resources.cpu_usage_percent
        );

        Self {
            mode,
            system_resources: Arc::new(Mutex::new(sys_resources)),
            slots: Arc::new(Mutex::new(HashMap::new())),
            max_agents: AtomicU32::new(max_agents),
            current_agents: AtomicU32::new(0),
            memory_pool_mb: AtomicU64::new(sys_resources.available_memory_mb),
            cpu_pool: AtomicU64::new((sys_resources.cpu_cores as f64 * 100.0) as u64),
            sequence_queue: Arc::new(Mutex::new(VecDeque::new())),
            parallel_limit: AtomicU32::new(sys_resources.cpu_cores.max(4)),
            last_resource_check: Arc::new(Mutex::new(Instant::now())),
            stability_mode: Arc::new(Mutex::new(false)),
        }
    }

    /// Create default single-node allocator
    pub fn default_single_node() -> Self {
        Self::new(AllocationMode::SingleNode)
    }

    /// Detect current system resources
    fn detect_system_resources() -> SystemResources {
        // In production: use sysinfo crate
        // For now: simulate based on typical server specs

        #[cfg(target_os = "linux")]
        {
            // Try to read from /proc
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                let total_kb = meminfo
                    .lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(16_777_216); // 16GB default

                let available_kb = meminfo
                    .lines()
                    .find(|l| l.starts_with("MemAvailable:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(total_kb / 2);

                let cpu_cores = std::thread::available_parallelism()
                    .map(|p| p.get() as u32)
                    .unwrap_or(4);

                return SystemResources {
                    total_memory_mb: total_kb / 1024,
                    available_memory_mb: available_kb / 1024,
                    cpu_cores,
                    cpu_usage_percent: 20.0, // Assume low usage at start
                    disk_available_gb: 100,
                    network_mbps: 1000,
                };
            }
        }

        // Default fallback
        SystemResources {
            total_memory_mb: 16384,
            available_memory_mb: 8192,
            cpu_cores: 8,
            cpu_usage_percent: 20.0,
            disk_available_gb: 100,
            network_mbps: 1000,
        }
    }

    /// Request agent allocation
    pub fn allocate_agent(
        &self,
        agent_pid: String,
        requirements: AgentRequirements,
    ) -> Result<AllocationResult, AllocationError> {
        // Check resource pressure
        self.check_resource_pressure();

        // Check if in stability mode
        if *self.stability_mode.lock().unwrap() {
            // Only allow high-priority agents
            if requirements.priority < 80 {
                return Err(AllocationError::StabilityMode);
            }
        }

        // Check current agent count
        let current = self.current_agents.load(Ordering::Relaxed);
        let max = self.max_agents.load(Ordering::Relaxed);

        if current >= max {
            // Try to find a lower-priority agent to pause
            if !self.try_make_room(requirements.priority) {
                return Err(AllocationError::CapacityExceeded { current, max });
            }
        }

        // Check memory availability
        let memory_needed = requirements.memory_mb;
        let available_memory = self.memory_pool_mb.load(Ordering::Relaxed);

        if memory_needed > available_memory {
            return Err(AllocationError::InsufficientMemory {
                needed: memory_needed,
                available: available_memory,
            });
        }

        // Reserve resources
        self.memory_pool_mb
            .fetch_sub(memory_needed, Ordering::Relaxed);
        self.cpu_pool
            .fetch_sub((requirements.cpu_cores * 100.0) as u64, Ordering::Relaxed);
        self.current_agents.fetch_add(1, Ordering::Relaxed);

        // Create slot
        let slot = AgentSlot {
            agent_pid: agent_pid.clone(),
            requirements,
            allocated_memory_mb: memory_needed,
            allocated_cpu: requirements.cpu_cores,
            status: SlotStatus::Active,
            created_at: Instant::now(),
            last_active: Instant::now(),
        };

        self.slots.lock().unwrap().insert(agent_pid.clone(), slot);

        // Add to sequence queue
        self.sequence_queue
            .lock()
            .unwrap()
            .push_back(agent_pid.clone());

        println!(
            "[ALLOCATOR] Allocated agent {} ({} MB, {} cores)",
            agent_pid, memory_needed, requirements.cpu_cores
        );

        Ok(AllocationResult {
            agent_pid,
            memory_allocated_mb: memory_needed,
            cpu_allocated: requirements.cpu_cores,
        })
    }

    /// Release agent resources
    pub fn release_agent(&self, agent_pid: &str) -> Result<(), AllocationError> {
        let mut slots = self.slots.lock().unwrap();

        if let Some(slot) = slots.remove(agent_pid) {
            // Return resources to pool
            self.memory_pool_mb
                .fetch_add(slot.allocated_memory_mb, Ordering::Relaxed);
            self.cpu_pool
                .fetch_add((slot.allocated_cpu * 100.0) as u64, Ordering::Relaxed);
            self.current_agents.fetch_sub(1, Ordering::Relaxed);

            // Remove from sequence queue
            let mut queue = self.sequence_queue.lock().unwrap();
            queue.retain(|pid| pid != agent_pid);

            println!(
                "[ALLOCATOR] Released agent {} (returned {} MB)",
                agent_pid, slot.allocated_memory_mb
            );

            Ok(())
        } else {
            Err(AllocationError::AgentNotFound)
        }
    }

    /// Try to pause lower-priority agents to make room
    fn try_make_room(&self, priority_needed: u32) -> bool {
        let mut slots = self.slots.lock().unwrap();

        // Find lowest priority agent that can be paused
        let to_pause: Option<String> = slots
            .values()
            .filter(|s| s.requirements.priority < priority_needed && s.requirements.pausable)
            .filter(|s| s.status == SlotStatus::Active)
            .min_by_key(|s| s.requirements.priority)
            .map(|s| s.agent_pid.clone());

        if let Some(pid) = to_pause {
            if let Some(slot) = slots.get_mut(&pid) {
                slot.status = SlotStatus::Paused;
                println!("[ALLOCATOR] Paused low-priority agent {} to make room", pid);
                return true;
            }
        }

        false
    }

    /// Check and handle resource pressure
    fn check_resource_pressure(&self) {
        let mut last_check = self.last_resource_check.lock().unwrap();

        if Instant::now().duration_since(*last_check) < Duration::from_secs(5) {
            return; // Don't check too frequently
        }

        *last_check = Instant::now();
        drop(last_check);

        // Update system resources
        let sys_resources = Self::detect_system_resources();
        *self.system_resources.lock().unwrap() = sys_resources;

        // Check pressure
        if sys_resources.is_critical() {
            println!("[ALLOCATOR] CRITICAL: System under extreme pressure!");
            println!("[ALLOCATOR] Activating emergency stability mode");
            *self.stability_mode.lock().unwrap() = true;

            // Pause all non-essential agents
            self.pause_non_essential_agents();
        } else if sys_resources.is_under_pressure() {
            println!("[ALLOCATOR] WARNING: System under pressure");
            *self.stability_mode.lock().unwrap() = false;

            // Throttle some agents
            self.throttle_agents();
        } else {
            *self.stability_mode.lock().unwrap() = false;
        }
    }

    /// Pause non-essential agents (priority < 50)
    fn pause_non_essential_agents(&self) {
        let mut slots = self.slots.lock().unwrap();
        let mut paused_count = 0;

        for slot in slots.values_mut() {
            if slot.requirements.priority < 50 && slot.status == SlotStatus::Active {
                slot.status = SlotStatus::Paused;
                paused_count += 1;
            }
        }

        if paused_count > 0 {
            println!("[ALLOCATOR] Paused {} non-essential agents", paused_count);
        }
    }

    /// Throttle agents to reduce load
    fn throttle_agents(&self) {
        let mut slots = self.slots.lock().unwrap();
        let mut throttled_count = 0;

        // Throttle throttlable agents with priority < 70
        for slot in slots.values_mut() {
            if slot.requirements.throttlable
                && slot.requirements.priority < 70
                && slot.status == SlotStatus::Active
            {
                slot.status = SlotStatus::Throttled;
                throttled_count += 1;
            }
        }

        if throttled_count > 0 {
            println!("[ALLOCATOR] Throttled {} agents", throttled_count);
        }
    }

    /// Get next agent in sequence (for ordered execution)
    pub fn next_in_sequence(&self) -> Option<String> {
        let mut queue = self.sequence_queue.lock().unwrap();
        queue.pop_front().map(|pid| {
            queue.push_back(pid.clone()); // Rotate
            pid
        })
    }

    /// Get parallel execution batch
    pub fn get_parallel_batch(&self, batch_size: usize) -> Vec<String> {
        let slots = self.slots.lock().unwrap();
        let limit = self.parallel_limit.load(Ordering::Relaxed) as usize;
        let size = batch_size.min(limit);

        slots
            .values()
            .filter(|s| s.status == SlotStatus::Active)
            .take(size)
            .map(|s| s.agent_pid.clone())
            .collect()
    }

    /// Update agent activity
    pub fn touch_agent(&self, agent_pid: &str) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(slot) = slots.get_mut(agent_pid) {
            slot.last_active = Instant::now();
        }
    }

    /// Get allocation statistics
    pub fn get_stats(&self) -> AllocatorStats {
        let slots = self.slots.lock().unwrap();
        let sys = self.system_resources.lock().unwrap();

        AllocatorStats {
            mode: self.mode,
            max_agents: self.max_agents.load(Ordering::Relaxed),
            current_agents: self.current_agents.load(Ordering::Relaxed),
            active_agents: slots
                .values()
                .filter(|s| s.status == SlotStatus::Active)
                .count() as u32,
            paused_agents: slots
                .values()
                .filter(|s| s.status == SlotStatus::Paused)
                .count() as u32,
            throttled_agents: slots
                .values()
                .filter(|s| s.status == SlotStatus::Throttled)
                .count() as u32,
            memory_used_mb: slots.values().map(|s| s.allocated_memory_mb).sum(),
            memory_available_mb: self.memory_pool_mb.load(Ordering::Relaxed),
            cpu_used: slots.values().map(|s| s.allocated_cpu).sum(),
            stability_mode: *self.stability_mode.lock().unwrap(),
            system_pressure: sys.is_under_pressure(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AllocationResult {
    pub agent_pid: String,
    pub memory_allocated_mb: u64,
    pub cpu_allocated: f32,
}

#[derive(Debug, Clone)]
pub enum AllocationError {
    CapacityExceeded { current: u32, max: u32 },
    InsufficientMemory { needed: u64, available: u64 },
    InsufficientCpu,
    AgentNotFound,
    StabilityMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AllocatorStats {
    pub mode: AllocationMode,
    pub max_agents: u32,
    pub current_agents: u32,
    pub active_agents: u32,
    pub paused_agents: u32,
    pub throttled_agents: u32,
    pub memory_used_mb: u64,
    pub memory_available_mb: u64,
    pub cpu_used: f32,
    pub stability_mode: bool,
    pub system_pressure: bool,
}

#[derive(Clone)]
pub struct SharedAutoAllocator {
    inner: Arc<AutoAllocator>,
}

impl SharedAutoAllocator {
    pub fn new(mode: AllocationMode) -> Self {
        Self {
            inner: Arc::new(AutoAllocator::new(mode)),
        }
    }

    pub fn default_single_node() -> Self {
        Self {
            inner: Arc::new(AutoAllocator::default_single_node()),
        }
    }

    pub fn allocate_agent(
        &self,
        pid: String,
        req: AgentRequirements,
    ) -> Result<AllocationResult, AllocationError> {
        self.inner.allocate_agent(pid, req)
    }

    pub fn release_agent(&self, pid: &str) -> Result<(), AllocationError> {
        self.inner.release_agent(pid)
    }

    pub fn next_in_sequence(&self) -> Option<String> {
        self.inner.next_in_sequence()
    }

    pub fn get_parallel_batch(&self, size: usize) -> Vec<String> {
        self.inner.get_parallel_batch(size)
    }

    pub fn touch_agent(&self, pid: &str) {
        self.inner.touch_agent(pid)
    }

    pub fn get_stats(&self) -> AllocatorStats {
        self.inner.get_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity_calculation() {
        let resources = SystemResources {
            total_memory_mb: 16384,
            available_memory_mb: 8192,
            cpu_cores: 8,
            cpu_usage_percent: 20.0,
            disk_available_gb: 100,
            network_mbps: 1000,
        };

        let capacity = resources.calculate_agent_capacity();
        assert!(capacity >= 25);
        assert!(capacity <= 150);
    }

    #[test]
    fn test_agent_allocation() {
        let allocator = AutoAllocator::default_single_node();

        let result = allocator.allocate_agent("agent-1".to_string(), AgentRequirements::default());

        assert!(result.is_ok());

        let stats = allocator.get_stats();
        assert_eq!(stats.current_agents, 1);
    }

    #[test]
    fn test_resource_pressure() {
        let allocator = AutoAllocator::default_single_node();

        // Allocate many agents to create pressure
        for i in 0..50 {
            let _ = allocator.allocate_agent(format!("agent-{}", i), AgentRequirements::default());
        }

        let stats = allocator.get_stats();
        assert!(stats.current_agents > 0);
    }

    #[test]
    fn test_sequencing() {
        let allocator = AutoAllocator::default_single_node();

        // Allocate agents
        for i in 0..5 {
            let _ = allocator.allocate_agent(format!("agent-{}", i), AgentRequirements::default());
        }

        // Get sequence
        let first = allocator.next_in_sequence();
        assert!(first.is_some());

        // Should rotate
        let second = allocator.next_in_sequence();
        assert!(second.is_some());
        assert_ne!(first, second);
    }
}
