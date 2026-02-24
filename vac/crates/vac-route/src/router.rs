//! Cell router — routes agents and keys to cells using consistent hashing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{RouteError, RouteResult};
use crate::ring::ConsistentHashRing;

/// Status of a cell endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellStatus {
    Starting,
    Ready,
    Syncing,
    Degraded,
    ShuttingDown,
}

/// A cell endpoint with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellEndpoint {
    pub cell_id: String,
    pub address: String,
    pub status: CellStatus,
    pub load: u8,
}

impl CellEndpoint {
    pub fn new(cell_id: &str, address: &str) -> Self {
        Self {
            cell_id: cell_id.to_string(),
            address: address.to_string(),
            status: CellStatus::Starting,
            load: 0,
        }
    }

    /// Whether this cell can accept new work.
    pub fn is_available(&self) -> bool {
        matches!(self.status, CellStatus::Ready | CellStatus::Syncing)
    }
}

/// Routes agents and keys to cells using consistent hashing.
///
/// Maintains a hash ring for routing plus endpoint metadata for each cell.
#[derive(Debug)]
pub struct CellRouter {
    ring: ConsistentHashRing,
    endpoints: HashMap<String, CellEndpoint>,
}

impl CellRouter {
    pub fn new() -> Self {
        Self {
            ring: ConsistentHashRing::new(),
            endpoints: HashMap::new(),
        }
    }

    /// Add a cell to the router.
    pub fn add_cell(&mut self, endpoint: CellEndpoint) -> RouteResult<()> {
        if self.endpoints.contains_key(&endpoint.cell_id) {
            return Err(RouteError::CellAlreadyRegistered(endpoint.cell_id));
        }
        self.ring.add_cell(&endpoint.cell_id);
        self.endpoints.insert(endpoint.cell_id.clone(), endpoint);
        Ok(())
    }

    /// Remove a cell from the router. Its agents will be re-routed to neighbors.
    pub fn remove_cell(&mut self, cell_id: &str) -> RouteResult<CellEndpoint> {
        let endpoint = self
            .endpoints
            .remove(cell_id)
            .ok_or_else(|| RouteError::CellNotFound(cell_id.to_string()))?;
        self.ring.remove_cell(cell_id);
        Ok(endpoint)
    }

    /// Route an agent to a cell based on consistent hashing of agent_pid.
    pub fn route_agent(&self, agent_pid: &str) -> RouteResult<&CellEndpoint> {
        let cell_id = self
            .ring
            .get_node(agent_pid)
            .ok_or(RouteError::NoCells)?;
        self.endpoints
            .get(cell_id)
            .ok_or_else(|| RouteError::CellNotFound(cell_id.to_string()))
    }

    /// Route a key to N cells (for replication).
    pub fn route_replicas(&self, key: &str, n: usize) -> Vec<&CellEndpoint> {
        self.ring
            .get_n_nodes(key, n)
            .iter()
            .filter_map(|cell_id| self.endpoints.get(*cell_id))
            .collect()
    }

    /// Get a cell endpoint by ID.
    pub fn get_cell(&self, cell_id: &str) -> Option<&CellEndpoint> {
        self.endpoints.get(cell_id)
    }

    /// Get a mutable cell endpoint by ID.
    pub fn get_cell_mut(&mut self, cell_id: &str) -> Option<&mut CellEndpoint> {
        self.endpoints.get_mut(cell_id)
    }

    /// Update a cell's status.
    pub fn set_cell_status(&mut self, cell_id: &str, status: CellStatus) -> RouteResult<()> {
        let ep = self
            .endpoints
            .get_mut(cell_id)
            .ok_or_else(|| RouteError::CellNotFound(cell_id.to_string()))?;
        ep.status = status;
        Ok(())
    }

    /// Update a cell's load.
    pub fn set_cell_load(&mut self, cell_id: &str, load: u8) -> RouteResult<()> {
        let ep = self
            .endpoints
            .get_mut(cell_id)
            .ok_or_else(|| RouteError::CellNotFound(cell_id.to_string()))?;
        ep.load = load;
        Ok(())
    }

    /// Number of cells in the router.
    pub fn cell_count(&self) -> usize {
        self.endpoints.len()
    }

    /// All cell endpoints.
    pub fn all_cells(&self) -> impl Iterator<Item = &CellEndpoint> {
        self.endpoints.values()
    }

    /// Available cells (Ready or Syncing).
    pub fn available_cells(&self) -> Vec<&CellEndpoint> {
        self.endpoints.values().filter(|ep| ep.is_available()).collect()
    }

    /// Least-loaded available cell.
    pub fn least_loaded_cell(&self) -> Option<&CellEndpoint> {
        self.endpoints
            .values()
            .filter(|ep| ep.is_available())
            .min_by_key(|ep| ep.load)
    }
}

impl Default for CellRouter {
    fn default() -> Self {
        Self::new()
    }
}
