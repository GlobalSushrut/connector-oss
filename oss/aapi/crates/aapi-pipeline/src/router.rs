//! VAKYA Router — routes actions to local or remote cells.
//!
//! Routing priority:
//! 1. Adapter location: which cell has the adapter for this action domain?
//! 2. Agent location: which cell has the target agent?
//! 3. Fallback: execute locally.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

use aapi_core::Vakya;

// ============================================================================
// Route Target
// ============================================================================

/// Where a VAKYA should be executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteTarget {
    /// Execute on the local cell.
    Local,
    /// Forward to a remote cell.
    Remote { cell_id: String },
}

// ============================================================================
// VakyaRouter
// ============================================================================

/// Routes VAKYAs to the correct cell based on adapter and agent locations.
///
/// Routing priority:
/// 1. **Adapter location** — if the action domain (e.g. "database") is registered
///    on a specific cell, route there.
/// 2. **Agent location** — if the acting agent (v1_karta.pid) is known to be
///    on a specific cell, route there.
/// 3. **Local fallback** — execute on the current cell.
pub struct VakyaRouter {
    /// domain → cell_id (e.g. "database" → "cell-2")
    adapter_locations: HashMap<String, String>,
    /// agent_pid → cell_id (e.g. "pid:001" → "cell-3")
    agent_locations: HashMap<String, String>,
}

impl VakyaRouter {
    pub fn new() -> Self {
        Self {
            adapter_locations: HashMap::new(),
            agent_locations: HashMap::new(),
        }
    }

    /// Route a VAKYA to the correct cell.
    ///
    /// `local_cell_id` is the ID of the cell making the routing decision.
    pub fn route_vakya(&self, vakya: &Vakya, local_cell_id: &str) -> RouteTarget {
        // 1. Check adapter location by action domain
        if let Some((domain, _)) = vakya.v3_kriya.action.split_once('.') {
            if let Some(cell_id) = self.adapter_locations.get(domain) {
                if cell_id != local_cell_id && cell_id != "local" {
                    debug!(
                        action = %vakya.v3_kriya.action,
                        domain = %domain,
                        target_cell = %cell_id,
                        "Routing by adapter location"
                    );
                    return RouteTarget::Remote {
                        cell_id: cell_id.clone(),
                    };
                }
            }
        }

        // 2. Check agent location
        let agent_pid = &vakya.v1_karta.pid.0;
        if let Some(cell_id) = self.agent_locations.get(agent_pid) {
            if cell_id != local_cell_id && cell_id != "local" {
                debug!(
                    agent_pid = %agent_pid,
                    target_cell = %cell_id,
                    "Routing by agent location"
                );
                return RouteTarget::Remote {
                    cell_id: cell_id.clone(),
                };
            }
        }

        // 3. Fallback: local
        RouteTarget::Local
    }

    /// Register an adapter's domain on a cell.
    /// Called when adapters announce themselves via the event bus.
    pub fn register_adapter(&mut self, domain: &str, cell_id: &str) {
        self.adapter_locations
            .insert(domain.to_string(), cell_id.to_string());
    }

    /// Deregister an adapter domain.
    pub fn deregister_adapter(&mut self, domain: &str) {
        self.adapter_locations.remove(domain);
    }

    /// Register an agent's location.
    /// Called when agents migrate between cells.
    pub fn register_agent(&mut self, agent_pid: &str, cell_id: &str) {
        self.agent_locations
            .insert(agent_pid.to_string(), cell_id.to_string());
    }

    /// Deregister an agent location.
    pub fn deregister_agent(&mut self, agent_pid: &str) {
        self.agent_locations.remove(agent_pid);
    }

    /// Number of registered adapter locations.
    pub fn adapter_count(&self) -> usize {
        self.adapter_locations.len()
    }

    /// Number of registered agent locations.
    pub fn agent_count(&self) -> usize {
        self.agent_locations.len()
    }

    /// Check if a domain has a registered adapter location.
    pub fn has_adapter(&self, domain: &str) -> bool {
        self.adapter_locations.contains_key(domain)
    }

    /// Get the cell ID for a domain, if registered.
    pub fn adapter_cell(&self, domain: &str) -> Option<&str> {
        self.adapter_locations.get(domain).map(|s| s.as_str())
    }

    /// Get the cell ID for an agent, if registered.
    pub fn agent_cell(&self, agent_pid: &str) -> Option<&str> {
        self.agent_locations.get(agent_pid).map(|s| s.as_str())
    }
}

impl Default for VakyaRouter {
    fn default() -> Self {
        Self::new()
    }
}
