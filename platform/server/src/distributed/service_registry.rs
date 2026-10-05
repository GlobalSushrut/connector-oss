//! Service Registry — Real Cell Registry & Capability Discovery
//!
//! FIX: DNS-like service discovery with real cell registration
//!
//! Features:
//! - Cell self-registration
//! - Agent/capability registration
//! - Real endpoint resolution
//! - Health-based routing
//! - CDN-like edge routing

use std::collections::{HashMap, HashSet, BTreeMap};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

use crate::distributed::transport::{CellAddress, Endpoint, TransportProtocol, CellHealth};

// =============================================================================
// Service Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Service name (e.g., "llm-inference", "data-store")
    pub service_name: String,
    /// Cell providing this service
    pub cell_id: String,
    /// Service endpoints
    pub endpoints: Vec<ServiceEndpoint>,
    /// Service version
    pub version: String,
    /// Capabilities provided
    pub capabilities: Vec<String>,
    /// Load metrics
    pub load: LoadMetrics,
    /// Health status
    pub health: CellHealth,
    /// Registration timestamp
    pub registered_at: i64,
    /// Last heartbeat
    pub last_heartbeat: i64,
    /// TTL (time to live)
    pub ttl_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub protocol: TransportProtocol,
    pub address: SocketAddr,
    pub path: String, // API path
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadMetrics {
    /// Current load (0.0 - 1.0)
    pub load_factor: f64,
    /// Requests per second
    pub rps: f64,
    /// Average latency
    pub avg_latency_ms: u64,
    /// Available capacity
    pub available_slots: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistration {
    /// Agent ID
    pub agent_pid: String,
    /// Cell hosting agent
    pub cell_id: String,
    /// Agent capabilities
    pub capabilities: Vec<String>,
    /// Agent role
    pub role: String,
    /// KECS score
    pub kecs: f64,
    /// Current load
    pub load: f64,
    /// Registered at
    pub registered_at: i64,
    /// Last seen
    pub last_seen: i64,
    /// Status
    pub status: AgentStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Active,
    Idle,
    Busy,
    Offline,
}

// =============================================================================
// Service Registry
// =============================================================================

pub struct ServiceRegistry {
    /// Cell registry: cell_id -> CellAddress
    cells: Arc<RwLock<HashMap<String, CellAddress>>>,
    /// Service registry: service_name -> [ServiceEntry]
    services: Arc<RwLock<HashMap<String, Vec<ServiceEntry>>>>,
    /// Agent registry: agent_pid -> AgentRegistration
    agents: Arc<RwLock<HashMap<String, AgentRegistration>>>,
    /// Capability index: capability -> [agent_pid]
    capability_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Location-based routing: region -> [cell_id]
    region_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Service cache for fast lookups
    cache: Arc<RwLock<BTreeMap<String, (ServiceEntry, Instant)>>>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            cells: Arc::new(RwLock::new(HashMap::new())),
            services: Arc::new(RwLock::new(HashMap::new())),
            agents: Arc::new(RwLock::new(HashMap::new())),
            capability_index: Arc::new(RwLock::new(HashMap::new())),
            region_index: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(BTreeMap::new())),
            cache_ttl: Duration::from_secs(60),
        }
    }

    /// Register a cell
    pub fn register_cell(&self, cell: CellAddress) -> Result<(), RegistryError> {
        let cell_id = cell.cell_id.clone();
        
        // Update cells
        {
            let mut cells = self.cells.write().unwrap();
            cells.insert(cell_id.clone(), cell.clone());
        }

        // Update region index
        {
            let mut regions = self.region_index.write().unwrap();
            regions.entry(cell.region.clone())
                .or_insert_with(Vec::new)
                .push(cell_id.clone());
        }

        println!("[REGISTRY] Cell {} registered in region {}", 
            cell_id, cell.region);

        Ok(())
    }

    /// Deregister a cell
    pub fn deregister_cell(&self, cell_id: &str) {
        // Remove from cells
        {
            let mut cells = self.cells.write().unwrap();
            if let Some(cell) = cells.remove(cell_id) {
                // Remove from region index
                let mut regions = self.region_index.write().unwrap();
                if let Some(region_cells) = regions.get_mut(&cell.region) {
                    region_cells.retain(|id| id != cell_id);
                }
            }
        }

        // Remove associated services
        {
            let mut services = self.services.write().unwrap();
            for (_, entries) in services.iter_mut() {
                entries.retain(|e| e.cell_id != cell_id);
            }
        }

        // Remove associated agents
        {
            let mut agents = self.agents.write().unwrap();
            let to_remove: Vec<String> = agents.iter()
                .filter(|(_, a)| a.cell_id == cell_id)
                .map(|(pid, _)| pid.clone())
                .collect();
            
            for pid in to_remove {
                self.deregister_agent(&pid);
            }
        }

        println!("[REGISTRY] Cell {} deregistered", cell_id);
    }

    /// Register a service
    pub fn register_service(&self, entry: ServiceEntry) -> Result<(), RegistryError> {
        let service_name = entry.service_name.clone();
        
        let mut services = self.services.write().unwrap();
        let entries = services.entry(service_name.clone()).or_insert_with(Vec::new);
        
        // Remove old entry from same cell if exists
        entries.retain(|e| e.cell_id != entry.cell_id);
        
        // Add new entry
        entries.push(entry);

        println!("[REGISTRY] Service {} registered by cell {}", 
            service_name, entries.last().unwrap().cell_id);

        Ok(())
    }

    /// Update service health/heartbeat
    pub fn service_heartbeat(&self, cell_id: &str, service_name: &str) -> Result<(), RegistryError> {
        let mut services = self.services.write().unwrap();
        
        if let Some(entries) = services.get_mut(service_name) {
            for entry in entries.iter_mut() {
                if entry.cell_id == cell_id {
                    entry.last_heartbeat = chrono::Utc::now().timestamp_millis();
                    entry.health = CellHealth::Healthy;
                    return Ok(());
                }
            }
        }

        Err(RegistryError::ServiceNotFound)
    }

    /// Resolve service (return best endpoint)
    pub fn resolve_service(&self, service_name: &str) -> Option<ServiceEntry> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some((entry, timestamp)) = cache.get(service_name) {
                if Instant::now().duration_since(*timestamp) < self.cache_ttl {
                    return Some(entry.clone());
                }
            }
        }

        // Lookup in registry
        let services = self.services.read().unwrap();
        let entries = services.get(service_name)?;

        // Filter healthy entries
        let healthy: Vec<&ServiceEntry> = entries.iter()
            .filter(|e| e.health == CellHealth::Healthy)
            .collect();

        if healthy.is_empty() {
            return None;
        }

        // Choose best based on load (lowest load_factor)
        let best = healthy.iter()
            .min_by(|a, b| a.load.load_factor.partial_cmp(&b.load.load_factor).unwrap())?;

        // Cache result
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(service_name.to_string(), ((*best).clone(), Instant::now()));
        }

        Some((*best).clone())
    }

    /// Resolve service by region (CDN-like edge routing)
    pub fn resolve_service_by_region(
        &self, 
        service_name: &str, 
        region: &str
    ) -> Option<ServiceEntry> {
        let services = self.services.read().unwrap();
        let entries = services.get(service_name)?;

        // Get cells in region
        let regions = self.region_index.read().unwrap();
        let region_cells: HashSet<String> = regions.get(region)
            .map(|cells| cells.iter().cloned().collect())
            .unwrap_or_default();

        // Filter by region and health
        let candidates: Vec<&ServiceEntry> = entries.iter()
            .filter(|e| region_cells.contains(&e.cell_id) && e.health == CellHealth::Healthy)
            .collect();

        if candidates.is_empty() {
            // Fallback to global resolution
            return self.resolve_service(service_name);
        }

        // Choose best by load
        candidates.iter()
            .min_by(|a, b| a.load.load_factor.partial_cmp(&b.load.load_factor).unwrap())
            .map(|e| (*e).clone())
    }

    /// Register an agent
    pub fn register_agent(&self, agent: AgentRegistration) -> Result<(), RegistryError> {
        let agent_pid = agent.agent_pid.clone();
        
        // Update agents
        {
            let mut agents = self.agents.write().unwrap();
            agents.insert(agent_pid.clone(), agent.clone());
        }

        // Update capability index
        {
            let mut index = self.capability_index.write().unwrap();
            for cap in &agent.capabilities {
                index.entry(cap.clone())
                    .or_insert_with(Vec::new)
                    .push(agent_pid.clone());
            }
        }

        println!("[REGISTRY] Agent {} registered with capabilities {:?}",
            agent_pid, agent.capabilities);

        Ok(())
    }

    /// Deregister an agent
    pub fn deregister_agent(&self, agent_pid: &str) {
        // Get capabilities first
        let caps = {
            let agents = self.agents.read().unwrap();
            agents.get(agent_pid)
                .map(|a| a.capabilities.clone())
                .unwrap_or_default()
        };

        // Remove from capability index
        {
            let mut index = self.capability_index.write().unwrap();
            for cap in &caps {
                if let Some(pids) = index.get_mut(cap) {
                    pids.retain(|pid| pid != agent_pid);
                }
            }
        }

        // Remove from agents
        {
            let mut agents = self.agents.write().unwrap();
            agents.remove(agent_pid);
        }
    }

    /// Find agents by capability
    pub fn find_agents_by_capability(&self, capability: &str, limit: usize) -> Vec<AgentRegistration> {
        let index = self.capability_index.read().unwrap();
        let agents = self.agents.read().unwrap();

        index.get(capability)
            .map(|pids| {
                pids.iter()
                    .filter_map(|pid| agents.get(pid).cloned())
                    .filter(|a| a.status == AgentStatus::Active || a.status == AgentStatus::Idle)
                    .take(limit)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get cell by ID
    pub fn get_cell(&self, cell_id: &str) -> Option<CellAddress> {
        let cells = self.cells.read().unwrap();
        cells.get(cell_id).cloned()
    }

    /// Get all cells
    pub fn get_all_cells(&self) -> Vec<CellAddress> {
        let cells = self.cells.read().unwrap();
        cells.values().cloned().collect()
    }

    /// Get cells by region
    pub fn get_cells_by_region(&self, region: &str) -> Vec<CellAddress> {
        let regions = self.region_index.read().unwrap();
        let cells = self.cells.read().unwrap();

        regions.get(region)
            .map(|cell_ids| {
                cell_ids.iter()
                    .filter_map(|id| cells.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get healthy cells
    pub fn get_healthy_cells(&self) -> Vec<CellAddress> {
        let cells = self.cells.read().unwrap();
        cells.values()
            .filter(|c| c.health == CellHealth::Healthy)
            .cloned()
            .collect()
    }

    /// Update cell health
    pub fn update_cell_health(&self, cell_id: &str, health: CellHealth) {
        let mut cells = self.cells.write().unwrap();
        if let Some(cell) = cells.get_mut(cell_id) {
            cell.health = health;
            cell.last_seen = chrono::Utc::now().timestamp_millis();
        }
    }

    /// Cleanup expired entries
    pub fn cleanup_expired(&self) -> CleanupResult {
        let now = chrono::Utc::now().timestamp_millis();
        let mut removed_cells = 0;
        let mut removed_services = 0;
        let mut removed_agents = 0;

        // Cleanup expired cells (no heartbeat for 5 minutes)
        {
            let mut cells = self.cells.write().unwrap();
            let expired: Vec<String> = cells.iter()
                .filter(|(_, c)| now - c.last_seen > 300000)
                .map(|(id, _)| id.clone())
                .collect();
            
            for id in expired {
                cells.remove(&id);
                removed_cells += 1;
            }
        }

        // Cleanup expired services
        {
            let mut services = self.services.write().unwrap();
            for (_, entries) in services.iter_mut() {
                let before = entries.len();
                entries.retain(|e| now - e.last_heartbeat < (e.ttl_seconds as i64 * 1000));
                removed_services += before - entries.len();
            }
        }

        // Cleanup expired agents
        {
            let mut agents = self.agents.write().unwrap();
            let expired: Vec<String> = agents.iter()
                .filter(|(_, a)| now - a.last_seen > 300000)
                .map(|(pid, _)| pid.clone())
                .collect();
            
            for pid in expired {
                self.deregister_agent(&pid);
                removed_agents += 1;
            }
        }

        // Clear expired cache entries
        {
            let mut cache = self.cache.write().unwrap();
            let expired: Vec<String> = cache.iter()
                .filter(|(_, (_, ts))| Instant::now().duration_since(*ts) > self.cache_ttl)
                .map(|(k, _)| k.clone())
                .collect();
            
            for key in expired {
                cache.remove(&key);
            }
        }

        CleanupResult {
            removed_cells,
            removed_services,
            removed_agents,
        }
    }

    /// Get registry statistics
    pub fn get_stats(&self) -> RegistryStats {
        RegistryStats {
            total_cells: self.cells.read().unwrap().len(),
            total_services: self.services.read().unwrap().len(),
            total_agents: self.agents.read().unwrap().len(),
            total_capabilities: self.capability_index.read().unwrap().len(),
            cache_size: self.cache.read().unwrap().len(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RegistryError {
    CellNotFound,
    ServiceNotFound,
    AgentNotFound,
    DuplicateRegistration,
    InvalidEndpoint,
}

#[derive(Debug, Clone)]
pub struct CleanupResult {
    pub removed_cells: usize,
    pub removed_services: usize,
    pub removed_agents: usize,
}

#[derive(Debug, Clone)]
pub struct RegistryStats {
    pub total_cells: usize,
    pub total_services: usize,
    pub total_agents: usize,
    pub total_capabilities: usize,
    pub cache_size: usize,
}

// =============================================================================
// Thread-safe wrapper
// =============================================================================

#[derive(Clone)]
pub struct SharedServiceRegistry {
    inner: Arc<ServiceRegistry>,
}

impl SharedServiceRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ServiceRegistry::new()),
        }
    }

    pub fn register_cell(&self, cell: CellAddress) -> Result<(), RegistryError> {
        self.inner.register_cell(cell)
    }

    pub fn deregister_cell(&self, cell_id: &str) {
        self.inner.deregister_cell(cell_id);
    }

    pub fn register_service(&self, entry: ServiceEntry) -> Result<(), RegistryError> {
        self.inner.register_service(entry)
    }

    pub fn resolve_service(&self, service_name: &str) -> Option<ServiceEntry> {
        self.inner.resolve_service(service_name)
    }

    pub fn resolve_service_by_region(&self, service_name: &str, region: &str) -> Option<ServiceEntry> {
        self.inner.resolve_service_by_region(service_name, region)
    }

    pub fn register_agent(&self, agent: AgentRegistration) -> Result<(), RegistryError> {
        self.inner.register_agent(agent)
    }

    pub fn find_agents_by_capability(&self, capability: &str, limit: usize) -> Vec<AgentRegistration> {
        self.inner.find_agents_by_capability(capability, limit)
    }

    pub fn get_cell(&self, cell_id: &str) -> Option<CellAddress> {
        self.inner.get_cell(cell_id)
    }

    pub fn get_healthy_cells(&self) -> Vec<CellAddress> {
        self.inner.get_healthy_cells()
    }

    pub fn cleanup_expired(&self) -> CleanupResult {
        self.inner.cleanup_expired()
    }

    pub fn get_stats(&self) -> RegistryStats {
        self.inner.get_stats()
    }

    /// Phase R3: Gossip sync — mirror the registry into `InternalDns` so
    /// service discovery works across cell boundaries without extra RPC.
    ///
    /// Runs as a background tokio task. Interval defaults to 30 s, overridden
    /// by `CONNECTOR_INTERNAL_DNS_SYNC` (seconds).
    pub fn spawn_gossip_sync(&self) {
        let registry = self.clone();
        let interval_secs = std::env::var("CONNECTOR_INTERNAL_DNS_SYNC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs)
            );
            loop {
                ticker.tick().await;
                registry.sync_to_internal_dns();
            }
        });
    }

    /// Mirror all healthy cells and services into `crate::internal_dns`.
    ///
    /// Called by `spawn_gossip_sync` and can also be called manually after
    /// a cell registration event.
    pub fn sync_to_internal_dns(&self) {
        // Sync healthy cell QUIC endpoints: cell-{id}.connector.internal → :443
        let cells = self.inner.get_healthy_cells();
        let cell_count = cells.len();

        for cell in &cells {
            // Use the first QUIC endpoint if available
            let quic_addr = cell.endpoints.iter()
                .find(|e| e.protocol == crate::distributed::transport::TransportProtocol::Quic)
                .map(|e| e.address);

            if let Some(addr) = quic_addr {
                crate::internal_dns::register(
                    &format!("cell-{}.connector.internal", cell.cell_id),
                    addr,
                    &format!("region={}", cell.region),
                    &["cell", "quic", "distributed"],
                );
            }
        }

        let stats = self.inner.get_stats();
        tracing::debug!(
            services = stats.total_services,
            cells = cell_count,
            "InternalDns gossip sync complete"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cell(id: &str) -> CellAddress {
        CellAddress {
            cell_id: id.to_string(),
            endpoints: vec![],
            region: "us-east".to_string(),
            location_signature: "sig".to_string(),
            capabilities: vec!["compute".to_string()],
            health: CellHealth::Healthy,
            last_seen: chrono::Utc::now().timestamp_millis(),
        }
    }

    #[test]
    fn test_cell_registration() {
        let registry = ServiceRegistry::new();
        
        let cell = test_cell("cell-1");
        registry.register_cell(cell.clone()).unwrap();

        let resolved = registry.get_cell("cell-1");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().cell_id, "cell-1");
    }

    #[test]
    fn test_service_resolution() {
        let registry = ServiceRegistry::new();
        
        registry.register_cell(test_cell("cell-1")).unwrap();

        let service = ServiceEntry {
            service_name: "llm-inference".to_string(),
            cell_id: "cell-1".to_string(),
            endpoints: vec![],
            version: "1.0".to_string(),
            capabilities: vec!["gpt-4".to_string()],
            load: LoadMetrics {
                load_factor: 0.5,
                rps: 10.0,
                avg_latency_ms: 100,
                available_slots: 5,
            },
            health: CellHealth::Healthy,
            registered_at: chrono::Utc::now().timestamp_millis(),
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            ttl_seconds: 300,
        };

        registry.register_service(service).unwrap();

        let resolved = registry.resolve_service("llm-inference");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().cell_id, "cell-1");
    }

    #[test]
    fn test_capability_index() {
        let registry = ServiceRegistry::new();

        let agent = AgentRegistration {
            agent_pid: "agent-1".to_string(),
            cell_id: "cell-1".to_string(),
            capabilities: vec!["writer".to_string(), "reader".to_string()],
            role: "writer".to_string(),
            kecs: 0.8,
            load: 0.3,
            registered_at: chrono::Utc::now().timestamp_millis(),
            last_seen: chrono::Utc::now().timestamp_millis(),
            status: AgentStatus::Active,
        };

        registry.register_agent(agent).unwrap();

        let writers = registry.find_agents_by_capability("writer", 10);
        assert_eq!(writers.len(), 1);
        assert_eq!(writers[0].agent_pid, "agent-1");
    }

    #[test]
    fn test_region_routing() {
        let registry = ServiceRegistry::new();

        let cell1 = CellAddress {
            cell_id: "cell-us".to_string(),
            endpoints: vec![],
            region: "us-east".to_string(),
            location_signature: "sig".to_string(),
            capabilities: vec![],
            health: CellHealth::Healthy,
            last_seen: 0,
        };

        let cell2 = CellAddress {
            cell_id: "cell-eu".to_string(),
            endpoints: vec![],
            region: "eu-west".to_string(),
            location_signature: "sig".to_string(),
            capabilities: vec![],
            health: CellHealth::Healthy,
            last_seen: 0,
        };

        registry.register_cell(cell1).unwrap();
        registry.register_cell(cell2).unwrap();

        let us_cells = registry.get_cells_by_region("us-east");
        assert_eq!(us_cells.len(), 1);
        assert_eq!(us_cells[0].cell_id, "cell-us");
    }
}
