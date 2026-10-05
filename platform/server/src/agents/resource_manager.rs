//! Agent Resource Manager — Multi-dimensional Resource Tracking & Enforcement
//!
//! FIX BUG-071: Multi-dimensional resource management

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

// =============================================================================
// Resource Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Cpu,           // millicores
    Memory,        // MB
    Storage,       // MB
    Network,       // Mbps
    Gpu,           // milligpu
    DiskIO,        // IOPS
    FileDescriptors,
    Threads,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub agent_id: String,
    pub resources: HashMap<ResourceType, u64>,
    pub limits: HashMap<ResourceType, u64>,
    pub thresholds: HashMap<ResourceType, f64>, // percentage for alerts
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub agent_id: String,
    pub timestamp: i64,
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub memory_percent: f32,
    pub storage_mb: u64,
    pub network_mbps: f32,
    pub gpu_percent: f32,
    pub disk_io_iops: u32,
    pub file_descriptors: u32,
    pub threads: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReservation {
    pub reservation_id: String,
    pub agent_id: String,
    pub resources: HashMap<ResourceType, u64>,
    pub expires_at: i64,
    pub priority: ReservationPriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReservationPriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
}

// =============================================================================
// Resource Manager
// =============================================================================

pub struct ResourceManager {
    /// Current allocations by agent
    allocations: Arc<RwLock<HashMap<String, ResourceAllocation>>>,
    /// Usage history
    usage_history: Arc<RwLock<Vec<ResourceUsage>>>,
    /// Active reservations
    reservations: Arc<RwLock<HashMap<String, ResourceReservation>>>,
    /// Total system capacity
    total_capacity: Arc<RwLock<HashMap<ResourceType, u64>>>,
    /// Contention handlers
    contention_handlers: Vec<Box<dyn Fn(&ResourceType, &HashMap<String, u64>) -> Resolution + Send + Sync>>,
}

#[derive(Debug, Clone)]
pub enum Resolution {
    Preempt(String),        // preempt this agent
    Throttle(String, f64),  // throttle this agent by factor
    Deny,
    Queue,
}

impl ResourceManager {
    pub fn new() -> Self {
        let mut capacity = HashMap::new();
        capacity.insert(ResourceType::Cpu, 100000);      // 100 cores in millicores
        capacity.insert(ResourceType::Memory, 256000); // 256 GB
        capacity.insert(ResourceType::Storage, 1000000); // 1 TB
        capacity.insert(ResourceType::Network, 10000);   // 10 Gbps
        capacity.insert(ResourceType::Gpu, 8000);        // 8 GPUs
        capacity.insert(ResourceType::DiskIO, 100000); // 100k IOPS
        capacity.insert(ResourceType::FileDescriptors, 1000000);
        capacity.insert(ResourceType::Threads, 10000);

        Self {
            allocations: Arc::new(RwLock::new(HashMap::new())),
            usage_history: Arc::new(RwLock::new(Vec::with_capacity(10000))),
            reservations: Arc::new(RwLock::new(HashMap::new())),
            total_capacity: Arc::new(RwLock::new(capacity)),
            contention_handlers: vec![],
        }
    }

    /// Register allocation for agent
    pub fn allocate(&self, agent_id: String, resources: HashMap<ResourceType, u64>, limits: HashMap<ResourceType, u64>) -> Result<ResourceAllocation, String> {
        // Check capacity
        let capacity = self.total_capacity.read().unwrap();
        let current = self.get_total_allocated();

        for (rtype, amount) in &resources {
            let total = current.get(rtype).copied().unwrap_or(0) + amount;
            let cap = capacity.get(rtype).copied().unwrap_or(0);
            if total > cap {
                return Err(format!(
                    "Insufficient {}: requested {}, available {}, capacity {}",
                    format!("{:?}", rtype),
                    amount,
                    cap.saturating_sub(current.get(rtype).copied().unwrap_or(0)),
                    cap
                ));
            }
        }

        let now = chrono::Utc::now().timestamp_millis();
        let allocation = ResourceAllocation {
            agent_id: agent_id.clone(),
            resources: resources.clone(),
            limits: limits.clone(),
            thresholds: self.default_thresholds(),
            created_at: now,
            updated_at: now,
        };

        let agent_id_str = agent_id.clone();
        self.allocations.write().unwrap().insert(agent_id, allocation.clone());

        println!("[RESOURCE-MGR] Allocated to {}: {:?}", agent_id_str, resources);
        Ok(allocation)
    }

    /// Update resource usage
    pub fn report_usage(&self, usage: ResourceUsage) -> Result<(), String> {
        // Validate against limits
        if let Some(allocation) = self.allocations.read().unwrap().get(&usage.agent_id) {
            for (rtype, limit) in &allocation.limits {
                let current = self.get_usage_value(&usage, rtype);
                if current > *limit {
                    // Trigger limit enforcement
                    self.enforce_limit(&usage.agent_id, rtype, current, *limit);
                }
            }
        }

        // Store in history
        let mut history = self.usage_history.write().unwrap();
        history.push(usage);
        
        // Keep history bounded
        if history.len() > 10000 {
            history.remove(0);
        }

        Ok(())
    }

    /// Reserve resources for future use
    pub fn reserve(&self, agent_id: String, resources: HashMap<ResourceType, u64>, priority: ReservationPriority, ttl_seconds: u32) -> Result<String, String> {
        let reservation_id = format!("res-{}", uuid::Uuid::new_v4());
        
        let reservation = ResourceReservation {
            reservation_id: reservation_id.clone(),
            agent_id,
            resources,
            expires_at: chrono::Utc::now().timestamp_millis() + (ttl_seconds as i64 * 1000),
            priority,
        };

        let agent_id_for_log = reservation.agent_id.clone();
        self.reservations.write().unwrap().insert(reservation_id.clone(), reservation);

        println!("[RESOURCE-MGR] Reserved {} for {} (priority: {:?})",
            reservation_id, agent_id_for_log, priority);
        
        Ok(reservation_id)
    }

    /// Release reservation
    pub fn release_reservation(&self, reservation_id: &str) -> Result<(), String> {
        self.reservations.write().unwrap()
            .remove(reservation_id)
            .ok_or("Reservation not found")?;
        
        println!("[RESOURCE-MGR] Released reservation {}", reservation_id);
        Ok(())
    }

    /// Deallocate all resources for agent
    pub fn deallocate(&self, agent_id: &str) -> Result<(), String> {
        self.allocations.write().unwrap()
            .remove(agent_id)
            .ok_or("Allocation not found")?;
        
        // Clean up reservations
        let mut reservations = self.reservations.write().unwrap();
        let to_remove: Vec<String> = reservations.values()
            .filter(|r| r.agent_id == agent_id)
            .map(|r| r.reservation_id.clone())
            .collect();
        
        for id in to_remove {
            reservations.remove(&id);
        }
        
        println!("[RESOURCE-MGR] Deallocated {}", agent_id);
        Ok(())
    }

    /// Handle resource contention
    pub fn handle_contention(&self, resource_type: ResourceType) -> Vec<Resolution> {
        let allocations = self.allocations.read().unwrap();
        let usage = self.get_current_usage();
        
        // Find agents using this resource
        let mut consumers: Vec<(String, u64)> = Vec::new();
        for (agent_id, alloc) in allocations.iter() {
            if let Some(amount) = usage.get(agent_id).and_then(|u| self.get_usage_value_opt(u, &resource_type)) {
                consumers.push((agent_id.clone(), amount));
            }
        }
        
        // Sort by priority (low first, for preemption)
        consumers.sort_by_key(|(_, amount)| *amount);

        let mut resolutions = Vec::new();
        for handler in &self.contention_handlers {
            resolutions.push(handler(&resource_type, &consumers.iter().cloned().collect()));
        }

        // Default: throttle lowest priority
        if resolutions.is_empty() && consumers.len() > 1 {
            resolutions.push(Resolution::Throttle(consumers[0].0.clone(), 0.5));
        }

        resolutions
    }

    /// Get available resources
    pub fn get_available(&self) -> HashMap<ResourceType, u64> {
        let capacity = self.total_capacity.read().unwrap();
        let allocated = self.get_total_allocated();
        let reserved = self.get_total_reserved();

        let mut available = HashMap::new();
        for (rtype, cap) in capacity.iter() {
            let used = allocated.get(rtype).copied().unwrap_or(0) 
                     + reserved.get(rtype).copied().unwrap_or(0);
            available.insert(*rtype, cap.saturating_sub(used));
        }

        available
    }

    /// Get usage statistics
    pub fn get_stats(&self) -> ResourceStats {
        let allocations = self.allocations.read().unwrap();
        let history = self.usage_history.read().unwrap();
        
        ResourceStats {
            total_agents: allocations.len(),
            total_allocations: allocations.len(),
            usage_samples: history.len(),
            available: self.get_available(),
            utilized: self.get_utilization(),
        }
    }

    fn get_total_allocated(&self) -> HashMap<ResourceType, u64> {
        let mut total = HashMap::new();
        for alloc in self.allocations.read().unwrap().values() {
            for (rtype, amount) in &alloc.resources {
                *total.entry(*rtype).or_insert(0) += amount;
            }
        }
        total
    }

    fn get_total_reserved(&self) -> HashMap<ResourceType, u64> {
        let mut total = HashMap::new();
        for res in self.reservations.read().unwrap().values() {
            for (rtype, amount) in &res.resources {
                *total.entry(*rtype).or_insert(0) += amount;
            }
        }
        total
    }

    fn get_current_usage(&self) -> HashMap<String, ResourceUsage> {
        let history = self.usage_history.read().unwrap();
        let mut latest: HashMap<String, ResourceUsage> = HashMap::new();
        
        for usage in history.iter() {
            latest.insert(usage.agent_id.clone(), usage.clone());
        }
        
        latest
    }

    fn get_usage_value(&self, usage: &ResourceUsage, rtype: &ResourceType) -> u64 {
        match rtype {
            ResourceType::Cpu => (usage.cpu_percent * 1000.0) as u64,
            ResourceType::Memory => usage.memory_mb,
            ResourceType::Storage => usage.storage_mb,
            ResourceType::Network => (usage.network_mbps * 1000.0) as u64,
            ResourceType::Gpu => (usage.gpu_percent * 1000.0) as u64,
            ResourceType::DiskIO => usage.disk_io_iops as u64,
            ResourceType::FileDescriptors => usage.file_descriptors as u64,
            ResourceType::Threads => usage.threads as u64,
        }
    }

    fn get_usage_value_opt(&self, usage: &ResourceUsage, rtype: &ResourceType) -> Option<u64> {
        Some(self.get_usage_value(usage, rtype))
    }

    fn enforce_limit(&self, agent_id: &str, rtype: &ResourceType, current: u64, limit: u64) {
        if current > limit {
            println!("[RESOURCE-MGR] LIMIT EXCEEDED: {} using {} of {} {:?}",
                agent_id, current, limit, rtype);
            
            // In production: trigger throttling, notify, or kill
        }
    }

    fn default_thresholds(&self) -> HashMap<ResourceType, f64> {
        let mut t = HashMap::new();
        t.insert(ResourceType::Cpu, 0.8);
        t.insert(ResourceType::Memory, 0.85);
        t.insert(ResourceType::Storage, 0.9);
        t.insert(ResourceType::Network, 0.8);
        t
    }

    fn get_utilization(&self) -> HashMap<ResourceType, f64> {
        let capacity = self.total_capacity.read().unwrap();
        let allocated = self.get_total_allocated();
        
        let mut util = HashMap::new();
        for (rtype, cap) in capacity.iter() {
            let alloc = allocated.get(rtype).copied().unwrap_or(0);
            util.insert(*rtype, alloc as f64 / *cap as f64);
        }
        util
    }

    pub fn add_contention_handler<F>(&mut self, handler: F)
    where
        F: Fn(&ResourceType, &HashMap<String, u64>) -> Resolution + Send + Sync + 'static,
    {
        self.contention_handlers.push(Box::new(handler));
    }
}

#[derive(Debug, Clone)]
pub struct ResourceStats {
    pub total_agents: usize,
    pub total_allocations: usize,
    pub usage_samples: usize,
    pub available: HashMap<ResourceType, u64>,
    pub utilized: HashMap<ResourceType, f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocation() {
        let manager = ResourceManager::new();
        
        let mut resources = HashMap::new();
        resources.insert(ResourceType::Cpu, 1000); // 1 core
        resources.insert(ResourceType::Memory, 1024); // 1 GB

        let allocation = manager.allocate(
            "agent-1".to_string(),
            resources,
            HashMap::new(),
        ).unwrap();

        assert_eq!(allocation.agent_id, "agent-1");
    }

    #[test]
    fn test_capacity_limit() {
        let manager = ResourceManager::new();
        
        // Try to allocate more than total CPU
        let mut resources = HashMap::new();
        resources.insert(ResourceType::Cpu, 200000); // 200 cores > 100 available

        let result = manager.allocate(
            "agent-1".to_string(),
            resources,
            HashMap::new(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_reservation() {
        let manager = ResourceManager::new();
        
        let mut resources = HashMap::new();
        resources.insert(ResourceType::Memory, 512);

        let res_id = manager.reserve(
            "agent-1".to_string(),
            resources,
            ReservationPriority::High,
            3600,
        ).unwrap();

        assert!(!res_id.is_empty());

        // Check available reduced
        let available = manager.get_available();
        let mem_cap = manager.total_capacity.read().unwrap().get(&ResourceType::Memory).copied().unwrap();
        assert!(available.get(&ResourceType::Memory).unwrap() < &mem_cap);
    }

    #[test]
    fn test_contention() {
        let mut manager = ResourceManager::new();
        
        // Allocate to multiple agents
        for i in 0..3 {
            let mut resources = HashMap::new();
            resources.insert(ResourceType::Cpu, 30000); // 30 cores each
            manager.allocate(format!("agent-{}", i), resources, HashMap::new()).unwrap();
        }

        // Simulate contention
        let resolutions = manager.handle_contention(ResourceType::Cpu);
        assert!(!resolutions.is_empty());
    }
}
