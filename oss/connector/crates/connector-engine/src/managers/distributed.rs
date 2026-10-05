//! DistributedManager — Cross-cell routing and distribution subsystem.
//!
//! Groups distributed systems engines:
//! - `CrossCellPortRouter` — Cross-cell message routing
//! - `AdaptiveRouter` — Workload-aware routing across cells
//! - `SessionRouter` — Session stickiness for routing

use crate::cross_cell_port::CrossCellPortRouter;
use crate::adaptive_router::AdaptiveRouter;
use crate::session_stickiness::SessionRouter;

/// DistributedManager — unified cross-cell routing layer.
///
/// Consolidates all distributed routing engines into a single manager,
/// providing a cohesive API for cross-cell communication and load balancing.
pub struct DistributedManager {
    /// CrossCellPortRouter — cross-cell message routing
    pub cross_cell: CrossCellPortRouter,
    /// AdaptiveRouter — workload-aware routing across cells
    pub adaptive_router: AdaptiveRouter,
    /// SessionRouter — session stickiness for routing
    pub session_router: SessionRouter,
}

impl DistributedManager {
    /// Create a new DistributedManager for a specific cell.
    pub fn new(cell_id: &str) -> Self {
        Self {
            cross_cell: CrossCellPortRouter::new(cell_id),
            adaptive_router: AdaptiveRouter::new(),
            session_router: SessionRouter::new(3_600_000), // 1 hour default
        }
    }

    /// Create with custom session timeout.
    pub fn with_session_timeout(mut self, timeout_ms: i64) -> Self {
        self.session_router = SessionRouter::new(timeout_ms);
        self
    }

    /// Update the cell ID for cross-cell routing.
    pub fn set_cell_id(&mut self, cell_id: &str) {
        self.cross_cell = CrossCellPortRouter::new(cell_id);
    }

    /// Register an agent's location for cross-cell routing.
    pub fn register_agent_location(&mut self, agent_pid: &str, cell_id: &str) {
        self.cross_cell.register_agent(agent_pid, cell_id);
    }

    /// Route a port message to target agent.
    pub fn route_port_message(
        &mut self,
        source_agent: &str,
        target_agent: &str,
        port_id: &str,
        payload: &str,
    ) -> crate::cross_cell_port::DeliveryResult {
        self.cross_cell.route_port_message(source_agent, target_agent, port_id, payload)
    }

    /// Bind a session to a cell for sticky routing.
    pub fn bind_session(&mut self, session_id: &str, cell_id: &str) {
        self.session_router.bind(session_id, cell_id);
    }

    /// Route a session to a cell (returns sticky or new decision).
    pub fn route_session(&mut self, session_id: &str, explicit_cell: Option<&str>) -> crate::session_stickiness::RouteDecision {
        self.session_router.route(session_id, explicit_cell)
    }

    /// Get cross-cell router reference.
    pub fn cross_cell(&self) -> &CrossCellPortRouter {
        &self.cross_cell
    }

    /// Get mutable cross-cell router reference.
    pub fn cross_cell_mut(&mut self) -> &mut CrossCellPortRouter {
        &mut self.cross_cell
    }

    /// Get adaptive router reference.
    pub fn adaptive_router(&self) -> &AdaptiveRouter {
        &self.adaptive_router
    }

    /// Get mutable adaptive router reference.
    pub fn adaptive_router_mut(&mut self) -> &mut AdaptiveRouter {
        &mut self.adaptive_router
    }

    /// Get session router reference.
    pub fn session_router(&self) -> &SessionRouter {
        &self.session_router
    }

    /// Get mutable session router reference.
    pub fn session_router_mut(&mut self) -> &mut SessionRouter {
        &mut self.session_router
    }
}

impl Default for DistributedManager {
    fn default() -> Self {
        Self::new("local")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distributed_manager_creation() {
        let manager = DistributedManager::new("cell-1");
        assert_eq!(manager.cross_cell().forward_count(), 0);
    }

    #[test]
    fn test_session_binding() {
        let mut manager = DistributedManager::new("cell-1");
        manager.bind_session("session-1", "cell-2");
        // Verify session was bound by routing
        let decision = manager.route_session("session-1", None);
        assert!(matches!(decision, crate::session_stickiness::RouteDecision::Sticky { .. }));
    }
}
